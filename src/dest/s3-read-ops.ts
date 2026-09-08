import type { DestIo } from "./dest-io.ts";
import { closedS3Code, type DestFaultLog, type DestOp } from "./fault-log.ts";
import { drainResponseBounded, xmlDecode } from "./s3-stream.ts";
import { parseObjectLockConfig } from "./s3-worm.ts";
import { awsUriEncode, type SigV4Creds, signV4 } from "./sigv4.ts";
import type { GetResult, ListPage, WormStatus, WormUnknownReason } from "./types.ts";
import { DestStatusError, MAX_DEST_TEXT_BYTES, MAX_LIST_PAGE_BYTES, MAX_STREAM_SEGMENT_BYTES } from "./types.ts";

/**
 * ReadIO is the seam the S3 read/probe ops need from S3Destination: the URL/date/hash primitives, the
 * metered fetch chokepoint, the STS session-token header builder, the bound signedRequest (for the
 * idempotent delete) and the signing credentials. Extracting get/exists/delete/list/objectLockStatus as
 * free functions over this seam keeps s3.ts small without changing any behaviour: every request is built,
 * signed, sent and classified exactly as it was when these were S3Destination methods.
 *
 * Implemented by S3Destination itself, and by the in-memory doubles the destination tests build, so a
 * caller of these ops never needs the whole destination class.
 */
export interface ReadIO {
  url(key: string): string;
  amzDate(): string;
  sha256Hex(b: Uint8Array): Promise<string>;
  metered(input: URL, init: RequestInit, op: DestOp): Promise<Response>;
  securityTokenHeader(): Record<string, string>;
  signedRequest(method: string, key: string, query: string, body: Uint8Array | null, req: { label: string; op: DestOp }, extra?: Record<string, string>): Promise<Response>;
  readonly creds: SigV4Creds;
  // faults is the destination's bounded, closed-vocabulary fault ring (G135). Every read/probe op notes a
  // FAILURE into it (op + HTTP status + closed S3 <Code> + fault class + classifier arm), so a GET/DELETE/
  // LIST/probe fault carries its identity instead of dying as a bare "status NNN". Diagnostic only: noting
  // never changes control flow.
  readonly faults: DestFaultLog;
  // io is the destination's bounded DEGRADATION counter set (G186). exists() notes into it when a HEAD
  // answers something other than 200/404 and is collapsed to "absent" -- the dedup-defeating fault that makes
  // a run re-upload an archive it already holds. Diagnostic only: noting never changes control flow.
  readonly io: DestIo;
}

// readS3ErrorBody reads a FAILED response's (tiny, fixed-shape) XML error document ONCE, bounded to a small
// cap regardless of what Content-Length claims (V12.3.1), so a misconfigured or hostile store cannot exhaust
// isolate memory on the error path. The body NEVER leaves this module's error path: it is consumed only to
// derive the closed S3 <Code> (closedS3Code, an allow-list) and the Object-Lock-complaint boolean the fault
// ring records. Fail-safe: any hiccup (including an over-cap body) yields "".
async function readS3ErrorBody(resp: Response): Promise<string> {
  try {
    const cl = resp.headers.get("content-length");
    if (cl !== null) {
      const advertised = Number(cl);
      if (Number.isFinite(advertised) && advertised > MAX_DEST_TEXT_BYTES) return ""; // an oversized/hostile error body -- do not buffer
    }
    return new TextDecoder().decode(await drainResponseBounded(resp, MAX_DEST_TEXT_BYTES, "s3 error body"));
  } catch {
    return "";
  }
}

/**
 * get fetches an object's bytes and ETag, or null if absent.
 *
 * A missing or empty ETag on a 200 response is treated as a hard error rather than a silent
 * default of "" (ENG-M14). The conditional-write guard in putConditional uses !== undefined,
 * so a caller that passes the empty string back as ifMatch would still send If-Match: "" to
 * the store (which returns a 412, triggering a retry). Throwing here instead is the cleaner
 * path: it surfaces a non-conformant store immediately on the read, before the caller constructs
 * the next write, so the RUNLOG retry loop never runs on a fabricated token and the problem is
 * visible rather than silently degraded into an unconditional overwrite. Any S3-compatible store
 * that serves a 200 GET without an ETag cannot satisfy the conditional-write contract and should
 * fail loudly at the earliest opportunity.
 *
 * Only a 404 returns null. A 3xx throws (a credentialed request must never be re-sent elsewhere), a
 * non-2xx whose error body carries InvalidObjectState (S3 usually sends it as a 403) throws the
 * distinct `thaw-needed` message so a cold-tiered archive reads as recoverable-but-not-now rather than
 * as an access outage, and every other non-2xx throws `GET <key>: status NNN`. The body is bounded to
 * MAX_STREAM_SEGMENT_BYTES as it streams in, so this is for small objects (the RUNLOG accumulation file
 * and manifests), never a sealed segment.
 */
export async function get(io: ReadIO, key: string): Promise<GetResult | null> {
  const u = new URL(io.url(key));
  const amzDate = io.amzDate();
  const headers: Record<string, string> = { host: u.host, "x-amz-date": amzDate, "x-amz-content-sha256": "UNSIGNED-PAYLOAD", ...io.securityTokenHeader() };
  const auth = await signV4("GET", u.pathname, "", headers, "UNSIGNED-PAYLOAD", amzDate, io.creds);
  // redirect:"manual" prevents the runtime from silently following a 3xx and re-sending
  // the credentialed SigV4 request to a third-party endpoint (V15.3.2).
  const resp = await io.metered(u, { method: "GET", headers: { "x-amz-date": amzDate, "x-amz-content-sha256": "UNSIGNED-PAYLOAD", Authorization: auth }, redirect: "manual" }, "get");
  if (resp.status >= 300 && resp.status < 400) {
    io.faults.noteResponse("get", resp, "");
    // G119: a 301/307 from an S3 endpoint almost always means the bucket lives in ANOTHER REGION, and the
    // Location header names it -- the one fact support needs and the one the run row never carried. noteRedirect
    // reads the Location ONLY to select the region token (or the closed unrecognised class when an appliance or
    // proxy is interposing); the URL, which embeds the bucket and the host, is never retained.
    io.faults.noteRedirect(resp);
    throw new Error(`GET ${key}: unexpected redirect (status ${resp.status}); a destination endpoint must not redirect a credentialed request`);
  }
  // A 404 is the NORMAL "absent" answer this method contracts to return as null, not a fault: it is not noted.
  if (resp.status === 404) return null;
  if (!resp.ok) {
    // A GLACIER / DEEP_ARCHIVE (COLD storage class) object cannot be read without a restore/thaw first: S3
    // answers the GET with a non-2xx (typically 403) carrying <Code>InvalidObjectState</Code>. A bucket
    // LIFECYCLE rule can silently transition an archive to a cold class after it was written, so a later
    // verify/restore GET fails on an object that IS present and IS recoverable, just not readable right now.
    // Discarding the S3 <Code> here (the old generic `status N`) made that indistinguishable from a real
    // access outage. Read the (already-failed) error body ONCE -- bounded, and used ONLY to extract the closed
    // <Code> token, never surfaced -- and throw a DISTINCT `thaw-needed` fault so the verify-at-seal coarse
    // mapper (and the restore path) render a legible "object is in a cold storage class" reason. This never
    // weakens the read: a genuine 403/5xx without that Code still throws the generic status error as before.
    const errBody = await readS3ErrorBody(resp);
    // Note the fault identity BEFORE the throw (G135): the op, the status, the closed <Code> and the
    // classifier arm, so a 403 InvalidObjectState (thaw) / AccessDenied (policy) / SignatureDoesNotMatch
    // (credential) are distinguishable in the pack. The body is never retained.
    io.faults.noteResponse("get", resp, errBody);
    if (closedS3Code(errBody) === "InvalidObjectState") {
      throw new Error(`GET ${key}: thaw-needed (object is in a cold storage class and must be restored/thawed before it can be read)`);
    }
    throw new Error(`GET ${key}: status ${resp.status}`);
  }
  const etag = resp.headers.get("etag");
  if (!etag) {
    io.faults.noteAnomaly("no-etag-on-get"); // G206: a 200 GET with no ETag -- the store cannot satisfy the conditional-write contract
    throw new Error(`GET ${key}: response carried no ETag; this store cannot satisfy the conditional-write contract`);
  }
  // get() is only ever used for small bounded objects (the RUNLOG accumulation file and manifests). The
  // advertised Content-Length, when present, is a CHEAP early exit (no need to even start reading a
  // declared-oversized body) -- but a store can omit it (chunked) or understate it, so the actual read
  // below is ALWAYS bounded to the same cap via drainResponseBounded, never trusting the header alone
  // (V12.3.1): a misconfigured or hostile store cannot exhaust isolate memory either way.
  const contentLength = resp.headers.get("content-length");
  if (contentLength !== null) {
    const advertised = Number(contentLength);
    if (Number.isFinite(advertised) && advertised > MAX_STREAM_SEGMENT_BYTES) {
      throw new Error(`GET ${key}: response Content-Length ${advertised} exceeds the ${MAX_STREAM_SEGMENT_BYTES}-byte read cap`);
    }
  }
  return { body: await drainResponseBounded(resp, MAX_STREAM_SEGMENT_BYTES, key), etag };
}

/**
 * exists reports whether an object is already present (for content-addressed dedup, so
 * an unchanged segment is not re-uploaded). It collapses every non-200 to false, which is correct for
 * the dedup callers (a 4xx/5xx is ridden by their withRetry) but WRONG for a probe that must tell "absent"
 * (404) from "unauthorised" (403) -- use headStatus for that.
 *
 * The collapse is counted, not corrected: a non-{200,404} answer bumps the headNon200CollapsedToAbsent
 * degradation counter so a run that quietly re-uploads everything it already holds is visible afterwards.
 */
export async function exists(io: ReadIO, key: string): Promise<boolean> {
  const status = await headStatus(io, key);
  // THE dedup-defeating fault (G186): a 403 (the credential lost s3:HeadObject) or a 5xx (the store is
  // wobbling) is collapsed to "absent" here, so the caller RE-UPLOADS a segment the bucket already holds --
  // every segment, every night, on a run that still reports success. A 404 is a genuine absence and is not a
  // degradation. Count only, never the status or the key; the collapse itself is deliberately unchanged (the
  // callers' withRetry rides it out, and a false re-upload is safe, if expensive).
  if (status !== 200 && status !== 404) io.io.note("headNon200CollapsedToAbsent");
  return status === 200;
}

/**
 * headStatus issues the SAME credentialed HEAD as exists() but returns the raw HTTP status instead of a
 * bool, so a PROBE can distinguish "object absent" (404) from "not authorised" (403) or "store unavailable"
 * (5xx/429). exists() collapsing every non-200 to false made the destination preflight a FALSE GREEN on a
 * 403/503; the preflight calls headStatus and classifies a non-{200,404} status as a failure. Read-only;
 * throws ONLY on a redirect (a credentialed request must never be silently re-sent to a third-party host).
 *
 * exists() is implemented on top of this, so the two never diverge in how the request is built or signed.
 */
export async function headStatus(io: ReadIO, key: string): Promise<number> {
  const u = new URL(io.url(key));
  const amzDate = io.amzDate();
  const headers: Record<string, string> = { host: u.host, "x-amz-date": amzDate, "x-amz-content-sha256": "UNSIGNED-PAYLOAD", ...io.securityTokenHeader() };
  const auth = await signV4("HEAD", u.pathname, "", headers, "UNSIGNED-PAYLOAD", amzDate, io.creds);
  // redirect:"manual" prevents the runtime from silently following a 3xx and re-sending
  // the credentialed SigV4 request to a third-party endpoint (V15.3.2).
  const resp = await io.metered(u, { method: "HEAD", headers: { "x-amz-date": amzDate, "x-amz-content-sha256": "UNSIGNED-PAYLOAD", Authorization: auth }, redirect: "manual" }, "head");
  if (resp.status >= 300 && resp.status < 400) {
    io.faults.noteResponse("head", resp, "");
    io.faults.noteRedirect(resp); // G119: the region hint / unrecognised-target class (never the Location URL)
    throw new Error(`HEAD ${key}: unexpected redirect (status ${resp.status}); a destination endpoint must not redirect a credentialed request`);
  }
  // 200 (present) and 404 (absent) are the two NORMAL answers a probe/dedup caller acts on; anything else
  // (403 not-authorised, 5xx/429 store-down) is the FALSE-GREEN this method exists to expose, so it is
  // noted in the fault ring (G135). A HEAD carries no body, so there is no <Code> to read.
  if (resp.status !== 200 && resp.status !== 404) io.faults.noteResponse("head", resp, "");
  return resp.status;
}

/**
 * del removes one object (S3 DeleteObject). It is the WRITE side of the retention prune
 * (seal/prune.ts), which only ever deletes an object the planner has proven unreferenced (a
 * superseded run's run/<runId>/ tree object, or a segment no retained run references). S3
 * DeleteObject is idempotent: deleting an absent key returns 204 (a no-op success), so a
 * re-run of an interrupted prune does not fail on an already-deleted object. Same SigV4 +
 * redirect:"manual" discipline as every other credentialed call here.
 *
 * A refusal throws DestStatusError, which carries the HTTP status alongside the byte-identical
 * message, so a caller can tell an Object-Lock retention refusal from a 403 policy denial without
 * parsing the string.
 */
export async function del(io: ReadIO, key: string): Promise<void> {
  const resp = await io.signedRequest("DELETE", key, "", null, { label: `DELETE ${key}`, op: "delete" });
  // 204 is the success shape; 404 is treated as success (the object is already gone, which
  // is the idempotent outcome the prune relies on). Anything else is a hard error.
  if (resp.status !== 204 && resp.status !== 404 && !resp.ok) {
    // Note the identity before throwing (G135): a delete refused by an Object-Lock retention window
    // (a locked bucket the prune can never reclaim) reads completely differently from a 403 policy denial,
    // and today both die as "DELETE key: status NNN".
    io.faults.noteResponse("delete", resp, await readS3ErrorBody(resp));
    // G246: TAGGED with the status (the message is byte-identical, so every existing catch and log line is
    // unchanged). The destination probe's cleanup delete used to call every one of these "denied" -- a
    // permission fact only a 401/403 establishes -- because the bare `catch` had nothing else to read.
    throw new DestStatusError(`DELETE ${key}: status ${resp.status}`, resp.status);
  }
}

/**
 * list enumerates the object keys under a prefix (S3 ListObjectsV2), following the
 * continuation token until the listing is complete so the caller sees the whole set in one
 * call. The prune uses it to find a superseded run's run/<runId>/ tree objects. The request
 * is a bucket-root GET with list-type=2: the canonical query is built in sorted order with
 * every value AWS-uri-encoded, exactly as signV4 signs it (a prefix or token carrying a
 * reserved character would otherwise break the signature). Paging is bounded only by the
 * store's own key count under the prefix; a run tree is a handful of objects.
 *
 * Because it accumulates every page in memory, use listPage instead for a keyspace whose size the
 * caller does not already know to be small.
 */
export async function list(io: ReadIO, prefix: string): Promise<string[]> {
  const keys: string[] = [];
  let token: string | undefined;
  let pages = 0;
  for (;;) {
    const page = await listPage(io, prefix, token, ++pages);
    for (const k of page.keys) keys.push(k);
    if (page.cursor === undefined) break;
    token = page.cursor;
  }
  return keys;
}

/**
 * listPage issues ONE ListObjectsV2 request and returns that page's keys plus the continuation
 * token for the next page (undefined when the store reports the listing is not truncated). It is
 * the bounded-memory primitive: a caller streaming a LARGE keyspace (the off-site replication seg/
 * sync, M6) walks page by page rather than accumulating the whole store like list() above. list()
 * is now just the accumulating loop over this. Every page is built, signed and classified exactly
 * as the old inline list did, so nothing about the request changes; only the result shape does.
 *
 * pageOrdinal is diagnostic only: it labels the fault ring entry raised when a store says the listing
 * IS truncated yet sends no continuation token, which stops the walk early and would otherwise look
 * like a complete listing. The page is still returned in that case, cursor absent, so the early stop
 * is recorded rather than corrected.
 */
export async function listPage(io: ReadIO, prefix: string, cursor?: string, pageOrdinal?: number): Promise<ListPage> {
  // A bucket-root request: io.url("") is endpoint/bucket/, so the signed path is the
  // bucket root and the listing is scoped by the prefix query parameter, not the path.
  const base = new URL(io.url(""));
  // Canonical query in sorted key order (continuation-token < list-type < prefix), values
  // AWS-uri-encoded. ListObjectsV2 is list-type=2.
  const parts = [`list-type=2`, `prefix=${awsUriEncode(prefix)}`];
  if (cursor !== undefined) parts.push(`continuation-token=${awsUriEncode(cursor)}`);
  const query = parts.sort().join("&");
  const amzDate = io.amzDate();
  const payloadHash = await io.sha256Hex(new Uint8Array(0));
  const headers: Record<string, string> = { host: base.host, "x-amz-date": amzDate, "x-amz-content-sha256": payloadHash, ...io.securityTokenHeader() };
  const auth = await signV4("GET", base.pathname, query, headers, payloadHash, amzDate, io.creds);
  const u = new URL(base.toString() + (query ? `?${query}` : ""));
  const resp = await io.metered(
    u,
    {
      method: "GET",
      headers: { "x-amz-date": amzDate, "x-amz-content-sha256": payloadHash, Authorization: auth },
      redirect: "manual",
    },
    "list",
  );
  if (resp.status >= 300 && resp.status < 400) {
    io.faults.noteResponse("list", resp, "");
    io.faults.noteRedirect(resp); // G119
    throw new Error(`LIST ${prefix}: unexpected redirect (status ${resp.status}); a destination endpoint must not redirect a credentialed request`);
  }
  if (!resp.ok) {
    io.faults.noteResponse("list", resp, await readS3ErrorBody(resp));
    throw new Error(`LIST ${prefix}: status ${resp.status}`);
  }
  // Bounded regardless of Content-Length (V12.3.1): every store pages a listing at 1000 keys, so a
  // conforming page never approaches MAX_LIST_PAGE_BYTES; a body that does is refused, not buffered whole.
  const xml = new TextDecoder().decode(await drainResponseBounded(resp, MAX_LIST_PAGE_BYTES, `list ${prefix}`));
  const keys: string[] = [];
  for (const m of xml.matchAll(/<Key>([^<]*)<\/Key>/g)) keys.push(xmlDecode(m[1]!));
  // IsTruncated true means more pages; NextContinuationToken carries the cursor.
  const truncated = /<IsTruncated>\s*true\s*<\/IsTruncated>/i.test(xml);
  const next = /<NextContinuationToken>([^<]+)<\/NextContinuationToken>/.exec(xml);
  // G085 (DATA LOSS, silent): the store said the listing IS truncated and gave NO continuation token. The walk
  // below then STOPS and every caller believes it saw the whole keyspace -- so a replication seg/ sync copies
  // only the pages it got, the replica records ok:true with a healthy holdsIndex, and the copy is discovered to
  // be non-restorable only when it is restored from. The early stop itself is unchanged (failing a live backup
  // on a non-conformant page would be worse); recording it is what makes the silent early stop diagnosable. The
  // page COUNT reached rides; never a key or the page XML.
  if (truncated && !next) io.faults.noteListTruncatedNoCursor(pageOrdinal ?? 1);
  return truncated && next ? { keys, cursor: xmlDecode(next[1]!) } : { keys };
}

/**
 * objectLockStatus is the WORM capability probe (S3 GetObjectLockConfiguration: a bucket-root GET
 * with the ?object-lock subresource). It reports what the BUCKET actually enforces, live, so the
 * posture can state REAL immutability rather than infer it from a refused delete:
 *   - HTTP 200 with <ObjectLockEnabled>Enabled</ObjectLockEnabled> => the bucket enforces
 *     Object-Lock. A <DefaultRetention> block, when present, carries the bucket's default rule,
 *     surfaced as defaultMode/defaultDays.
 *   - HTTP 404 (ObjectLockConfigurationNotFoundError) or a 200 whose body does NOT say Enabled =>
 *     the bucket was NOT created with Object-Lock; { enabled:false }. This is a NORMAL answer, not
 *     an error, so it does not throw.
 *   - any other status, an unparseable body, or a transport fault => { enabled:"unknown" } (the
 *     safe cannot-confirm reading the posture treats as a warning, never a green WORM claim).
 * The request is signed and refuses redirects exactly like every other credentialed call here. The
 * subresource query is the single canonical token "object-lock" (no value), as S3 signs it.
 *
 * It NEVER throws and never blocks a backup: every failure path degrades to "unknown", tagged with the
 * WORM_UNKNOWN_REASONS member that names the remedy, so a probe refused for a missing IAM permission is
 * not confused with a passing network blip or with a store that has no Object-Lock API at all.
 */
export async function objectLockStatus(io: ReadIO): Promise<WormStatus> {
  try {
    // A bucket-root GET (io.url("") is endpoint/bucket/), scoped by the ?object-lock subresource.
    const base = new URL(io.url(""));
    const query = "object-lock=";
    const amzDate = io.amzDate();
    const payloadHash = await io.sha256Hex(new Uint8Array(0));
    const headers: Record<string, string> = { host: base.host, "x-amz-date": amzDate, "x-amz-content-sha256": payloadHash, ...io.securityTokenHeader() };
    const auth = await signV4("GET", base.pathname, query, headers, payloadHash, amzDate, io.creds);
    const u = new URL(`${base.toString()}?${query}`);
    const resp = await io.metered(
      u,
      {
        method: "GET",
        headers: { "x-amz-date": amzDate, "x-amz-content-sha256": payloadHash, Authorization: auth },
        redirect: "manual",
      },
      "object-lock-probe",
    );
    // Every degradation to "unknown" below is a SWALLOWED fault: the posture then reports cannot-confirm and
    // the reason is lost. Note the identity in the fault ring first (G135) so a WORM claim that could not be
    // probed is diagnosable (a 403 on GetObjectLockConfiguration = the credential lacks s3:GetBucketObjectLock,
    // a 501/NotImplemented = the store has no Object-Lock API at all), while the swallow itself is unchanged:
    // a probe failure NEVER blocks a backup.
    if (resp.status >= 300 && resp.status < 400) {
      io.faults.noteResponse("object-lock-probe", resp, "");
      io.faults.noteRedirect(resp); // G119
      // G279: a credentialed probe that was REDIRECTED (a proxy interposing, or a bucket in another region).
      // The reason rides on the status itself; the redirect TARGET never does.
      return { enabled: "unknown", unknownReason: "redirect" };
    }
    // 404 = the bucket has no Object-Lock configuration (it was not created with lock): a definite,
    // honest "not enabled", not an error.
    if (resp.status === 404) return { enabled: false };
    if (!resp.ok) {
      io.faults.noteResponse("object-lock-probe", resp, await readS3ErrorBody(resp));
      // G279: the store ANSWERED and refused. A 401/403 is the one-line IAM fix (the credential lacks
      // s3:GetBucketObjectLockConfiguration); a 501 means the store has no Object-Lock API at all (nothing to
      // fix, and no immutability is possible there); a 5xx is the store, not the customer. The status CLASS is
      // the whole record: never the status detail beyond it, and never the error body.
      return { enabled: "unknown", unknownReason: wormUnknownReasonForStatus(resp.status) };
    }
    // Bounded regardless of Content-Length (V12.3.1): GetObjectLockConfiguration's response is always a
    // tiny fixed-shape document; the surrounding catch already treats a fault as the safe "unknown" reading.
    const xml = new TextDecoder().decode(await drainResponseBounded(resp, MAX_DEST_TEXT_BYTES, "object-lock status"));
    return parseObjectLockConfig(xml);
  } catch {
    // Transport/parse fault: cannot confirm, so report unknown (the posture treats it as a warning,
    // never a false "enforced"). A probe failure NEVER blocks a backup; it only affects reporting.
    // G279: name the cause. A transport fault is the SELF-HEALING one, and it used to read exactly like a
    // permanent permission denial -- so a compliance customer chased an IAM change for a passing blip.
    return { enabled: "unknown", unknownReason: "network" };
  }
}

/**
 * wormUnknownReasonForStatus maps the Object-Lock probe's REFUSED status to the closed WORM_UNKNOWN_REASONS
 * member that names the remedy (G279). PURE; the status is an integer, and nothing else about the response is
 * read. Exported so the validator can pin the mapping without a live store.
 *
 * @param status - the probe response's HTTP status.
 * @returns the closed reason.
 */
export function wormUnknownReasonForStatus(status: number): WormUnknownReason {
  if (status === 401 || status === 403) return "denied";
  if (status === 501) return "not-implemented"; // NotImplemented: the store has no Object-Lock API at all
  if (status >= 500 && status <= 599) return "server-error";
  return "other";
}
