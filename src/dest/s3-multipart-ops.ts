import type { DestIo } from "./dest-io.ts";
import { classifyAbortFailure, type DestFaultLog, type DestOp } from "./fault-log.ts";
import { throttleError } from "./s3-multipart.ts";
import { drainResponseBounded } from "./s3-stream.ts";
import { EMPTY_BODY_MD5, stampObjectLockRefusal } from "./s3-worm.ts";
import { awsUriEncode } from "./sigv4.ts";
import { MAX_DEST_TEXT_BYTES } from "./types.ts";

/**
 * MultipartIO is the seam the S3 multipart wire ops need from S3Destination: the bound signedRequest
 * (signs + sends one S3 request, refusing redirects) and the two creation-only header builders (the
 * Object-Lock and storage-class headers, empty unless configured). Extracting these as free functions
 * over this seam keeps s3.ts small without changing any behaviour: every request is signed, sent and
 * classified exactly as it was when these were S3Destination methods.
 *
 * Narrower than ReadIO on purpose: the multipart ops never build a URL or sign a request themselves, so
 * they take only the bound signedRequest and cannot reach the credentials.
 */
export interface MultipartIO {
  signedRequest(method: string, key: string, query: string, body: Uint8Array | null, req: { label: string; op: DestOp }, extra?: Record<string, string>): Promise<Response>;
  objectLockHeaders(): Record<string, string>;
  storageClassHeader(): Record<string, string>;
  // faults is the destination's bounded, closed-vocabulary fault ring (G135). Every multipart step notes a
  // FAILURE into it before throwing, so an initiate/part/complete/abort fault carries its identity (the
  // closed S3 <Code>, the status, the classifier arm) rather than dying as a bare "status 403" -- the
  // multipart path is exactly where the single-shot PUT's s3WriteFailure diagnosis did not reach.
  readonly faults: DestFaultLog;
  // io is the destination's bounded DEGRADATION counter set (G186). throttleError notes into it when the
  // store sends a Retry-After the engine cannot read, so the backoff falls back to a guess. Diagnostic only.
  readonly io: DestIo;
}

// noteHttpFault reads the (already-failed) response's bounded error body ONCE and notes the fault identity
// under the given op. The body is consumed here and never leaves: only the closed <Code>, the status, the
// request-id PRESENCE and the Object-Lock-complaint boolean are recorded. Fail-safe: an unreadable body
// simply records s3Code "none".
// It RETURNS the body it read, because the response can only be drained once and the initiate's Object-Lock
// verdict is decided from that same body. Returning it keeps the single read: nothing re-reads a consumed
// response, and the body still never leaves this module.
async function noteHttpFault(io: MultipartIO, op: DestOp, resp: Response): Promise<string> {
  let body = "";
  try {
    body = new TextDecoder().decode(await drainResponseBounded(resp, MAX_DEST_TEXT_BYTES, "s3 error body"));
  } catch {
    body = "";
  }
  io.faults.noteResponse(op, resp, body);
  return body;
}

/**
 * initiateMultipart opens an S3 multipart upload (CreateMultipartUpload, a POST to ?uploads) and returns
 * the store's UploadId, the handle every later part, complete and abort is addressed by.
 *
 * This is the ONLY step that carries the creation-time headers: S3 binds Object-Lock retention and the
 * storage class to the object when the upload is created, not when it completes, so the lock and
 * storage-class headers ride here and the parts are unchanged. When WORM is armed the request also
 * carries the fixed empty-body Content-MD5, which AWS mandates on any Object-Lock request and without
 * which the seal fails with InvalidRequest.
 *
 * Throws on a non-2xx, tagged with the store's Retry-After when it signalled backpressure, and throws
 * separately when a 200 carries no UploadId at all (a stripping proxy or an off-brand store, recorded as
 * a conformance anomaly). The response body is read bounded and never retained.
 */
export async function initiateMultipart(io: MultipartIO, key: string): Promise<string> {
  // Object-Lock for a multipart object is set on CreateMultipartUpload (the initiate), NOT on the
  // individual UploadPart requests, S3 binds the retention to the object at create time. So the
  // lock headers (empty unless WORM is configured) ride only here; parts and complete are unchanged.
  const lock = io.objectLockHeaders();
  // AWS S3 mandates a Content-MD5 (or x-amz-checksum-*) header on a CreateMultipartUpload that carries
  // Object-Lock parameters, exactly as it does on a single-shot PutObject; without it the WORM multipart
  // seal fails with InvalidRequest. The initiate request body is ALWAYS empty, so the MD5 is the fixed
  // empty-body constant. It rides only when WORM is on (lock non-empty), so a non-WORM multipart (and every
  // R2 multipart) is byte-identical to before. signedRequest folds it into the signed + wire headers.
  const md5 = Object.keys(lock).length > 0 ? { "content-md5": EMPTY_BODY_MD5 } : {};
  const resp = await io.signedRequest("POST", key, "uploads=", new Uint8Array(0), { label: `initiate multipart ${key}`, op: "multipart-initiate" }, { ...lock, ...io.storageClassHeader(), ...md5 });
  if (!resp.ok) {
    // A WORM multipart that AWS refuses for a missing checksum lands here (InvalidRequest + the Object-Lock
    // complaint), as does an expired STS session and a bucket-policy denial. Note the identity, then throw
    // exactly as before.
    const body = await noteHttpFault(io, "multipart-initiate", resp);
    // The initiate is the ONLY multipart step that carries the Object-Lock headers, so it is the only one
    // that can be refused over them, and a large segment reaches the store through here rather than through
    // the single-shot PUT. Stamp the same verdict from the same function, or a WORM refusal on a multipart
    // seal reads as a plain 5xx and is retried like a store blip.
    throw stampObjectLockRefusal(throttleError(`initiate multipart ${key}`, resp, io.io), body, Object.keys(lock).length > 0);
  }
  // Bounded regardless of Content-Length (V12.3.1): the initiate response is always a tiny fixed-shape
  // document naming the new UploadId.
  const xml = new TextDecoder().decode(await drainResponseBounded(resp, MAX_DEST_TEXT_BYTES, `initiate multipart ${key}`));
  const m = /<UploadId>([^<]+)<\/UploadId>/.exec(xml);
  if (!m) {
    // G206: an off-brand store (or a stripping / namespacing proxy) answered the initiate 200 with no
    // <UploadId>. Every large-segment write then fails, and the run row shows only a coarse error. Record the
    // NON-CONFORMANCE as a closed class -- never the body, which can carry proxy or internal hostnames.
    io.faults.noteAnomaly("no-upload-id");
    throw new Error(`initiate multipart ${key}: response carried no UploadId`);
  }
  return m[1]!;
}

/**
 * uploadPart PUTs one part of an open multipart upload and returns its ETag, which completeMultipart
 * must name to assemble the object. partNumber is 1-based, as S3 requires.
 *
 * The part is a length-known buffer, so its real SHA-256 is signed into the request by signedRequest;
 * the caller holds one part in memory at a time. The query is built by hand in sorted order with the
 * upload id AWS-uri-encoded, because encodeURIComponent leaves !'()* alone and would break the
 * signature for an id containing them.
 *
 * Throws on a non-2xx (carrying the store's Retry-After on a 503/429), and separately when a 200 arrives
 * with no ETag, since without it the upload can never be completed.
 */
export async function uploadPart(io: MultipartIO, key: string, uploadId: string, partNumber: number, part: Uint8Array): Promise<string> {
  // Canonical query parameters in sorted order (partNumber before uploadId), values
  // AWS-uri-encoded, exactly as signV4 signs them (encodeURIComponent leaves !'()*
  // unencoded, which would break the signature for an UploadId containing them).
  const query = `partNumber=${partNumber}&uploadId=${awsUriEncode(uploadId)}`;
  const resp = await io.signedRequest("PUT", key, query, part, { label: `part ${partNumber} of ${key}`, op: "multipart-part" });
  if (!resp.ok) {
    await noteHttpFault(io, "multipart-part", resp);
    throw throttleError(`part ${partNumber} of ${key}`, resp, io.io);
  }
  const etag = resp.headers.get("etag");
  if (!etag) {
    io.faults.noteAnomaly("no-etag-on-part"); // G206: a 200 UploadPart with no ETag -- the store cannot complete a multipart
    throw new Error(`part ${partNumber} of ${key}: response carried no ETag`);
  }
  return etag;
}

/**
 * completeMultipart closes an open upload, POSTing the CompleteMultipartUpload document that names every
 * part in order so the store assembles them into the final object. etags must be in part order: the part
 * numbers are derived from the array index, not carried alongside, so a reordered array would assemble
 * the object wrongly rather than fail. Each ETag is XML-escaped for & and < before it is embedded.
 *
 * S3 answers this call with a 200 even when the assembly FAILED, putting an <Error> document in the body,
 * so a 2xx is not enough: the body is read (bounded) and any Error in it is treated as a failure. That is
 * the one status arm no classifier can reach, which is why it is recorded as a conformance anomaly as
 * well as a fault. A non-2xx throws with the store's Retry-After attached when it signalled backpressure.
 */
export async function completeMultipart(io: MultipartIO, key: string, uploadId: string, etags: string[]): Promise<void> {
  const partsXml = etags.map((etag, i) => `<Part><PartNumber>${i + 1}</PartNumber><ETag>${etag.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</ETag></Part>`).join("");
  const bodyXml = `<CompleteMultipartUpload>${partsXml}</CompleteMultipartUpload>`;
  const resp = await io.signedRequest("POST", key, `uploadId=${awsUriEncode(uploadId)}`, new TextEncoder().encode(bodyXml), { label: `complete multipart ${key}`, op: "multipart-complete" });
  if (!resp.ok) {
    await noteHttpFault(io, "multipart-complete", resp);
    throw throttleError(`complete multipart ${key}`, resp, io.io);
  }
  // Some stores return 200 with an error document; treat a body naming Error as failure. Bounded
  // regardless of Content-Length (V12.3.1): a conforming completion ack is always tiny.
  const text = new TextDecoder().decode(await drainResponseBounded(resp, MAX_DEST_TEXT_BYTES, `complete multipart ${key}`));
  if (/<Error>/.test(text)) {
    // A 2xx carrying an error document: no status arm can classify it, so it is EXACTLY the fault the
    // classifier defaults to permanent without being able to read it. noteBodyError records that honestly
    // (arm "default-permanent") along with the closed <Code> the document carried.
    io.faults.noteBodyError("multipart-complete", resp, text);
    io.faults.noteAnomaly("error-in-200-body"); // G206: the store's own conformance, separate from the fault identity
    throw new Error(`complete multipart ${key}: the store reported an error after a 200`);
  }
}

/**
 * abortMultipart cancels an open upload (AbortMultipartUpload) so a failed or empty write does not strand
 * part storage the customer keeps paying for until a bucket lifecycle rule reaps it.
 *
 * 204 is the success shape and 404 is also success (the upload never started, or is already gone), so a
 * repeated abort is safe. Every other outcome THROWS, including a transport failure that never reached
 * the store, after recording the stranding under its closed class. Callers treat the abort as
 * best-effort and swallow that throw: the original upload error is the one an operator needs, and the
 * stranded parts are tallied separately for the run row.
 */
export async function abortMultipart(io: MultipartIO, key: string, uploadId: string): Promise<void> {
  let resp: Response;
  try {
    resp = await io.signedRequest("DELETE", key, `uploadId=${awsUriEncode(uploadId)}`, null, { label: `abort multipart ${key}`, op: "multipart-abort" });
  } catch (e) {
    // G343: the abort request never got an answer at all (DNS / TLS / reset / timeout). This threw straight
    // past every sink -- noteHttpFault needs a RESPONSE -- so a network-stranded abort was the one failure
    // mode with NO record anywhere: not a fault row, not a class, nothing. Note the identity (a closed class,
    // never the endpoint/bucket/key/uploadId) and the stranding, then rethrow exactly as before: the caller
    // still treats the abort as best-effort and the ORIGINAL upload error is still what surfaces.
    io.faults.noteThrown("multipart-abort", e);
    io.faults.noteAbortFailure(classifyAbortFailure(e));
    throw e;
  }
  // 204 is the success shape; 404 means it never started or is already gone. Anything
  // else is reported (the caller treats abort as best-effort anyway).
  if (resp.status !== 204 && resp.status !== 404 && !resp.ok) {
    // A failed abort strands invisible part-storage the bucket lifecycle must reap; the count is already
    // tallied by the caller, but WHY it failed (403 policy vs 5xx store) was lost until now.
    await noteHttpFault(io, "multipart-abort", resp);
    // G343: the stranding itself, with its closed class -- so the pack can say "N aborts failed, denied" (fix
    // the bucket policy: the credential can write parts but not abort them) rather than a bare boolean.
    io.faults.noteAbortFailure(classifyAbortFailure(undefined, resp.status));
    throw new Error(`abort multipart ${key}: status ${resp.status}`);
  }
}
