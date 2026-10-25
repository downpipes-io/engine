import { base64Encode, hexDecode, sha256Hex } from "../crypto/bytes.ts";
import type { DestIo } from "./dest-io.ts";
import { classifyAbortFailure, type DestFaultLog, type DestOp } from "./fault-log.ts";
import { throttleError } from "./s3-multipart.ts";
import { drainResponseBounded } from "./s3-stream.ts";
import { EMPTY_BODY_MD5, isChecksumRequiredRefusal, S3_CHECKSUM_ALGORITHM, stampObjectLockRefusal } from "./s3-worm.ts";
import { awsUriEncode } from "./sigv4.ts";
import { MAX_DEST_TEXT_BYTES } from "./types.ts";

/**
 * MultipartIO is the seam the S3 multipart wire ops need from S3Destination: the bound signedRequest
 * (signs + sends one S3 request, refusing redirects) and the two creation-only header builders (the
 * Object-Lock and storage-class headers, empty unless configured). Every request goes through this seam
 * signed, sent and classified the same way.
 *
 * Narrower than ReadIO on purpose: the multipart ops never build a URL or sign a request themselves, so
 * they take only the bound signedRequest and cannot reach the credentials.
 */
export interface MultipartIO {
  // req.payloadHash lets a caller that has already hashed the body (uploadPart, when it sends the part's
  // checksum) hand the hex SHA-256 over, so a 32 MiB part is hashed once rather than twice.
  signedRequest(method: string, key: string, query: string, body: Uint8Array | null, req: { label: string; op: DestOp; payloadHash?: string }, extra?: Record<string, string>): Promise<Response>;
  objectLockHeaders(): Record<string, string>;
  storageClassHeader(): Record<string, string>;
  // checksumLearned reads, and learnChecksum sets, the destination's remembered fact that this bucket
  // refuses a write without an integrity header (see isChecksumRequiredRefusal). Once set it holds for the
  // life of the destination instance, so only the first refused request pays for the retry.
  checksumLearned(): boolean;
  learnChecksum(): void;
  // faults is the destination's bounded, closed-vocabulary fault ring. Every multipart step notes a
  // FAILURE into it before throwing, so an initiate/part/complete/abort fault carries its identity (the
  // closed S3 <Code>, the status, the classifier arm) rather than dying as a bare "status 403" -- the
  // multipart path is exactly where the single-shot PUT's s3WriteFailure diagnosis does not reach.
  readonly faults: DestFaultLog;
  // io is the destination's bounded DEGRADATION counter set. throttleError notes into it when the
  // store sends a Retry-After the engine cannot read, so the backoff falls back to a guess. Diagnostic only.
  readonly io: DestIo;
}

/**
 * MultipartUpload is one open upload: the store's UploadId, and whether it was CREATED checksummed (with
 * x-amz-checksum-algorithm). Every part and the completion must match how the upload was created, so the
 * flag travels with the id rather than being re-read from the destination, whose remembered fact can change
 * while the upload is open.
 */
export interface MultipartUpload {
  uploadId: string;
  checksum: boolean;
}

/** UploadedPart is one accepted part: its ETag, and its base64 SHA-256 when the upload is checksummed. */
export interface UploadedPart {
  etag: string;
  checksum?: string;
}

/**
 * ChecksumRequiredError is what uploadPart throws when AWS refuses the FIRST part of an upload that was
 * created without a checksum, because the bucket demands one. It is not a fault: the caller aborts that
 * upload, creates a checksummed one and sends the part again. It carries no store text.
 */
export class ChecksumRequiredError extends Error {
  constructor(label: string) {
    super(`${label}: status 400 (InvalidRequest: object lock write requires a checksum)`);
    this.name = "ChecksumRequiredError";
  }
}

// readErrorBody reads a failed response's bounded error body ONCE. The response can only be drained once,
// and the same body decides the checksum retry, the fault record and the initiate's Object-Lock verdict.
// Fail-safe: an unreadable body reads as "", which records s3Code "none" and never matches a retry.
async function readErrorBody(resp: Response): Promise<string> {
  try { // nosemgrep: incident-catch-returns-empty -- an unreadable error body is left out of the message and the failure it explains is already raised
    return new TextDecoder().decode(await drainResponseBounded(resp, MAX_DEST_TEXT_BYTES, "s3 error body"));
  } catch { // site-fault-waiver: src/dest/s3-multipart-ops.ts:readErrorBody:catch:1 -- an unreadable error body is left out of the message and the failure it explains is already raised
    return "";
  }
}

// noteHttpFault reads the (already-failed) response's bounded error body ONCE and notes the fault identity
// under the given op. The body is consumed here and never leaves: only the closed <Code>, the status, the
// request-id PRESENCE and the Object-Lock-complaint boolean are recorded.
async function noteHttpFault(io: MultipartIO, op: DestOp, resp: Response): Promise<void> {
  io.faults.noteResponse(op, resp, await readErrorBody(resp));
}

/**
 * initiateMultipart opens an S3 multipart upload (CreateMultipartUpload, a POST to ?uploads) and returns
 * the store's UploadId, the handle every later part, complete and abort is addressed by, with whether the
 * upload was created checksummed.
 *
 * This is the ONLY step that carries the creation-time headers: S3 binds Object-Lock retention and the
 * storage class to the object when the upload is created, not when it completes, so the lock and
 * storage-class headers ride here and the parts are unchanged. When WORM is armed the request also
 * carries the fixed empty-body Content-MD5, which AWS mandates on any Object-Lock request and without
 * which the seal fails with InvalidRequest.
 *
 * When the destination has learned that the bucket demands a checksum, the upload is created with
 * x-amz-checksum-algorithm: SHA256 and the empty-body Content-MD5, so every part can carry its own
 * x-amz-checksum-sha256. An initiate that sent no integrity header and gets AWS's missing-checksum refusal
 * learns that fact and is sent again once, checksummed.
 *
 * Throws on a non-2xx, tagged with the store's Retry-After when it signalled backpressure, and throws
 * separately when a 200 carries no UploadId at all (a stripping proxy or an off-brand store, recorded as
 * a conformance anomaly). The response body is read bounded and never retained.
 */
export async function initiateMultipart(io: MultipartIO, key: string): Promise<MultipartUpload> {
  // Object-Lock for a multipart object is set on CreateMultipartUpload (the initiate), NOT on the
  // individual UploadPart requests, S3 binds the retention to the object at create time. So the
  // lock headers (empty unless WORM is configured) ride only here; parts and complete are unchanged.
  const lock = io.objectLockHeaders();
  const checksum = io.checksumLearned();
  // AWS S3 mandates a Content-MD5 (or x-amz-checksum-*) header on a CreateMultipartUpload that carries
  // Object-Lock parameters, exactly as it does on a single-shot PutObject; without it the WORM multipart
  // seal fails with InvalidRequest. The initiate request body is ALWAYS empty, so the MD5 is the fixed
  // empty-body constant. It rides only when WORM is on (lock non-empty) or the bucket has been seen to demand
  // a checksum, so an ordinary multipart (and every R2 multipart) carries no extra header. signedRequest
  // folds it into the signed + wire headers.
  const sentIntegrity = Object.keys(lock).length > 0 || checksum;
  const md5 = sentIntegrity ? { "content-md5": EMPTY_BODY_MD5 } : {};
  const algorithm = checksum ? { "x-amz-checksum-algorithm": S3_CHECKSUM_ALGORITHM } : {};
  const resp = await io.signedRequest("POST", key, "uploads=", new Uint8Array(0), { label: `initiate multipart ${key}`, op: "multipart-initiate" }, { ...lock, ...io.storageClassHeader(), ...md5, ...algorithm });
  if (!resp.ok) {
    // A WORM multipart that AWS refuses for a missing checksum lands here (InvalidRequest + the Object-Lock
    // complaint), as does an expired STS session and a bucket-policy denial.
    const body = await readErrorBody(resp);
    // The bucket's default retention rule demands a checksum and this initiate sent none: remember it and
    // create the upload again, checksummed. The second call sends the header, so it cannot come back here.
    if (!sentIntegrity && isChecksumRequiredRefusal(resp.status, body)) {
      io.learnChecksum();
      io.io.note("checksumRetries");
      return initiateMultipart(io, key);
    }
    io.faults.noteResponse("multipart-initiate", resp, body);
    // The initiate is the ONLY multipart step that carries the Object-Lock headers, so it is the only one
    // that can be refused over them, and a large segment reaches the store through here rather than through
    // the single-shot PUT. Stamp the same verdict from the same function, or a WORM refusal on a multipart
    // seal reads as a plain 5xx and is retried like a store blip.
    throw stampObjectLockRefusal(throttleError(`initiate multipart ${key}`, resp, io.io), body, Object.keys(lock).length > 0);
  }
  // Bounded regardless of Content-Length: the initiate response is always a tiny fixed-shape
  // document naming the new UploadId.
  const xml = new TextDecoder().decode(await drainResponseBounded(resp, MAX_DEST_TEXT_BYTES, `initiate multipart ${key}`));
  const m = /<UploadId>([^<]+)<\/UploadId>/.exec(xml);
  if (!m) {
    // An off-brand store (or a stripping / namespacing proxy) answered the initiate 200 with no
    // <UploadId>. Every large-segment write then fails, and the run row shows only a coarse error. Record the
    // NON-CONFORMANCE as a closed class -- never the body, which can carry proxy or internal hostnames.
    io.faults.noteAnomaly("no-upload-id");
    throw new Error(`initiate multipart ${key}: response carried no UploadId`);
  }
  return { uploadId: m[1]!, checksum };
}

/**
 * uploadPart PUTs one part of an open multipart upload and returns its ETag, which completeMultipart
 * must name to assemble the object, with the part's base64 SHA-256 when the upload is checksummed.
 * partNumber is 1-based, as S3 requires.
 *
 * The part is a length-known buffer, so its real SHA-256 is signed into the request by signedRequest;
 * the caller holds one part in memory at a time. On a checksummed upload the same digest also rides as
 * x-amz-checksum-sha256, signed like every other header, and is hashed once for both. The query is built
 * by hand in sorted order with the upload id AWS-uri-encoded, because encodeURIComponent leaves !'()* alone
 * and would break the signature for an id containing them.
 *
 * Throws ChecksumRequiredError when AWS refuses the FIRST part of an upload created without a checksum
 * because the bucket demands one, so the caller can start a checksummed upload. Otherwise throws on a
 * non-2xx (carrying the store's Retry-After on a 503/429), and separately when a 200 arrives with no ETag,
 * since without it the upload can never be completed.
 */
export async function uploadPart(io: MultipartIO, key: string, upload: MultipartUpload, partNumber: number, part: Uint8Array): Promise<UploadedPart> {
  // Canonical query parameters in sorted order (partNumber before uploadId), values
  // AWS-uri-encoded, exactly as signV4 signs them (encodeURIComponent leaves !'()*
  // unencoded, which would break the signature for an UploadId containing them).
  const query = `partNumber=${partNumber}&uploadId=${awsUriEncode(upload.uploadId)}`;
  const label = `part ${partNumber} of ${key}`;
  const payloadHash = upload.checksum ? await sha256Hex(part) : undefined;
  const checksum = payloadHash !== undefined ? base64Encode(hexDecode(payloadHash)) : undefined;
  const resp = await io.signedRequest("PUT", key, query, part, { label, op: "multipart-part", ...(payloadHash !== undefined ? { payloadHash } : {}) }, checksum !== undefined ? { "x-amz-checksum-sha256": checksum } : undefined);
  if (!resp.ok) {
    const body = await readErrorBody(resp);
    // Only part 1 can be recovered: it is the one part the caller still holds when no part has been
    // accepted yet, so a fresh checksummed upload loses nothing.
    if (!upload.checksum && partNumber === 1 && isChecksumRequiredRefusal(resp.status, body)) throw new ChecksumRequiredError(label);
    io.faults.noteResponse("multipart-part", resp, body);
    throw throttleError(label, resp, io.io);
  }
  const etag = resp.headers.get("etag");
  if (!etag) {
    io.faults.noteAnomaly("no-etag-on-part"); // a 200 UploadPart with no ETag -- the store cannot complete a multipart
    throw new Error(`${label}: response carried no ETag`);
  }
  return checksum !== undefined ? { etag, checksum } : { etag };
}

/**
 * completeMultipart closes an open upload, POSTing the CompleteMultipartUpload document that names every
 * part in order so the store assembles them into the final object. parts must be in part order: the part
 * numbers are derived from the array index, not carried alongside, so a reordered array would assemble
 * the object wrongly rather than fail. Each ETag is XML-escaped for & and < before it is embedded. A part
 * with a checksum also names it as ChecksumSHA256, which AWS documents for an upload created with the
 * SHA256 algorithm; base64 carries neither character, so it needs no escaping.
 *
 * S3 answers this call with a 200 even when the assembly FAILED, putting an <Error> document in the body,
 * so a 2xx is not enough: the body is read (bounded) and any Error in it is treated as a failure. That is
 * the one status arm no classifier can reach, which is why it is recorded as a conformance anomaly as
 * well as a fault. A non-2xx throws with the store's Retry-After attached when it signalled backpressure.
 */
export async function completeMultipart(io: MultipartIO, key: string, uploadId: string, parts: UploadedPart[]): Promise<void> {
  const partsXml = parts
    .map((p, i) => `<Part><PartNumber>${i + 1}</PartNumber><ETag>${p.etag.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</ETag>${p.checksum !== undefined ? `<ChecksumSHA256>${p.checksum}</ChecksumSHA256>` : ""}</Part>`)
    .join("");
  const bodyXml = `<CompleteMultipartUpload>${partsXml}</CompleteMultipartUpload>`;
  const resp = await io.signedRequest("POST", key, `uploadId=${awsUriEncode(uploadId)}`, new TextEncoder().encode(bodyXml), { label: `complete multipart ${key}`, op: "multipart-complete" });
  if (!resp.ok) {
    await noteHttpFault(io, "multipart-complete", resp);
    throw throttleError(`complete multipart ${key}`, resp, io.io);
  }
  // Some stores return 200 with an error document; treat a body naming Error as failure. Bounded
  // regardless of Content-Length: a conforming completion ack is always tiny.
  const text = new TextDecoder().decode(await drainResponseBounded(resp, MAX_DEST_TEXT_BYTES, `complete multipart ${key}`));
  if (/<Error>/.test(text)) {
    // A 2xx carrying an error document: no status arm can classify it, so it is EXACTLY the fault the
    // classifier defaults to permanent without being able to read it. noteBodyError records that honestly
    // (arm "default-permanent") along with the closed <Code> the document carried.
    io.faults.noteBodyError("multipart-complete", resp, text);
    io.faults.noteAnomaly("error-in-200-body"); // the store's own conformance, separate from the fault identity
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
    // The abort request never got an answer at all (DNS / TLS / reset / timeout). This throws straight
    // past every sink -- noteHttpFault needs a RESPONSE -- so without this note a network-stranded abort
    // would leave no record anywhere: not a fault row, not a class, nothing. Note the identity (a closed
    // class, never the endpoint/bucket/key/uploadId) and the stranding, then rethrow: the caller still
    // treats the abort as best-effort and the ORIGINAL upload error is still what surfaces.
    io.faults.noteThrown("multipart-abort", e);
    io.faults.noteAbortFailure(classifyAbortFailure(e));
    throw e;
  }
  // 204 is the success shape; 404 means it never started or is already gone. Anything
  // else is reported (the caller treats abort as best-effort anyway).
  if (resp.status !== 204 && resp.status !== 404 && !resp.ok) {
    // A failed abort strands invisible part-storage the bucket lifecycle must reap; the count is tallied
    // by the caller, but this records WHY it failed (403 policy vs 5xx store) rather than leaving that unknown.
    await noteHttpFault(io, "multipart-abort", resp);
    // The stranding itself, with its closed class -- so the pack can say "N aborts failed, denied" (fix
    // the bucket policy: the credential can write parts but not abort them) rather than a bare boolean.
    io.faults.noteAbortFailure(classifyAbortFailure(undefined, resp.status));
    throw new Error(`abort multipart ${key}: status ${resp.status}`);
  }
}
