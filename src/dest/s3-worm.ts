import { OBJECT_LOCK_REFUSAL_PROP } from "./classify.ts";
import type { WormMode, WormStatus } from "./types.ts";

/**
 * retainUntilISO derives the absolute S3 Object-Lock retain-until-date for an object written NOW,
 * as an RFC-3339 / ISO-8601 UTC instant (the form S3 requires for x-amz-object-lock-retain-until-date).
 * The window is policy.retentionDays whole days from the write instant; we floor the result to
 * whole seconds (no sub-second component) because S3 stores the retention to second granularity and
 * a fractional component is rejected by some stores. now is injectable so the signature is
 * deterministic under test.
 *
 * Days are fixed 24-hour spans, not calendar days, so a window spanning a daylight-saving change is
 * still exactly retentionDays * 86400 seconds. PURE: it reads nothing but its two arguments.
 */
export function retainUntilISO(now: Date, retentionDays: number): string {
  const ms = now.getTime() + retentionDays * 24 * 60 * 60 * 1000;
  // Floor to whole seconds, then format without milliseconds (e.g.).
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

/**
 * S3_OBJECT_LOCK_MODE maps our policy mode to the exact S3 header token (upper-case, as the S3 API
 * expects on x-amz-object-lock-mode).
 *
 * Total over WormMode, so it is the single place the internal lower-case vocabulary meets the wire
 * spelling. GOVERNANCE can be overridden by a principal holding s3:BypassGovernanceRetention;
 * COMPLIANCE cannot be overridden by anyone, including the account root, until the window expires.
 */
export const S3_OBJECT_LOCK_MODE: Record<WormMode, string> = { governance: "GOVERNANCE", compliance: "COMPLIANCE" };

/**
 * EMPTY_BODY_MD5 is the standard-base64 Content-MD5 of a ZERO-byte request body (base64(MD5("")) =
 * "1B2M2Y8AsgTpgAmY7PhCfg=="). AWS S3 mandates a Content-MD5 OR x-amz-checksum-* header on any request
 * that carries Object-Lock parameters, including CreateMultipartUpload, whose request body is always
 * empty. The eventual multipart object is NOT empty, but this header covers the (empty) CREATE request
 * body, which is what the Object-Lock rule checks. It is a compile-time constant (Web Crypto offers no
 * MD5), and the engine only ever sends it on the empty-body initiate, so there is nothing to compute.
 *
 * It is an S3 protocol requirement, not an integrity control: the archive's own hashes and the segment
 * AEAD are what a reader verifies. Sending it on any request with a non-empty body would be wrong.
 */
export const EMPTY_BODY_MD5 = "1B2M2Y8AsgTpgAmY7PhCfg==";

// S3_ERROR_CODE_RE extracts the S3 <Code> from an error response body. S3 error codes are a fixed,
// documented, PascalCase enum (InvalidRequest, AccessDenied, SignatureDoesNotMatch, ...): never secret,
// never customer data, so surfacing the code is safe under NC-5 where surfacing a raw message is not.
// The pattern is deliberately tight (a leading letter, then up to 63 letters/digits) so a malformed or
// adversarial body cannot smuggle arbitrary text through this seam.
const S3_ERROR_CODE_RE = /<Code>\s*([A-Za-z][A-Za-z0-9]{0,63})\s*<\/Code>/;

// OBJECT_LOCK_CHECKSUM_RE recognises AWS's specific complaint when an Object-Lock write omits the
// required integrity header, so the operator-facing reason can name the real cause instead of the
// generic "destination access error". Matched only as a boolean against the response body; no text from
// the body is ever forwarded.
const OBJECT_LOCK_CHECKSUM_RE = /Content-MD5|x-amz-checksum/i;

// OBJECT_LOCK_CODE_RE recognises the S3 error CODES that mean the bucket's own Object-Lock / retention
// policy refused the write, as distinct from the credential being wrong. It is matched against the
// already-sanitised <Code> token (a member of S3's fixed PascalCase enum), never against the body, so no
// provider text can reach a decision through it. AccessDenied is deliberately NOT here: it is the code a
// genuine credentials failure also carries, and a lock refusal that presents only as AccessDenied is
// recognised by the checksum complaint above instead.
const OBJECT_LOCK_CODE_RE = /^(?:InvalidRetentionPeriod|ObjectLockConfigurationNotFoundError|InvalidObjectState)$/;

// OBJECT_LOCK_UNSUPPORTED_CODE_RE recognises the code a store answers when it has no Object-Lock
// implementation to apply the request's lock headers with. R2 answers a lock-bearing PUT to a bucket that
// was not created Object-Lock enabled with "status 501 (NotImplemented)", and NotImplemented was in neither
// vocabulary above, so the whole worm-refused apparatus missed the store this product is built around: the
// refusal read as http-5xx, which sends an operator to wait out a Cloudflare incident that is not happening
// and will never clear.
//
// UNLIKE the two arms above this one is CONDITIONAL on the write having actually carried Object-Lock
// headers. NotImplemented is a general "this store does not do that" code, so on its own it says nothing
// about immutability; it only names the lock policy when the lock policy is the thing that was asked for.
// The condition is read from the headers the request put on the wire, not inferred from the response.
const OBJECT_LOCK_UNSUPPORTED_CODE_RE = /^NotImplemented$/;

/**
 * s3ErrorCode pulls the sanitised S3 <Code> from a response body, or undefined when the body carries no
 * recognisable code. Pure and side-effect free so it is trivially testable.
 *
 * The extraction is the REDACTION seam: S3_ERROR_CODE_RE admits only a leading letter followed by up to
 * 63 letters or digits, so what comes back is a token from S3's fixed error enum and never free text
 * from a malformed or hostile body. A code longer than 64 characters, or one carrying punctuation,
 * reads as absent rather than being truncated through.
 */
export function s3ErrorCode(body: string): string | undefined {
  return S3_ERROR_CODE_RE.exec(body)?.[1];
}

/**
 * s3WriteFailure builds the Error a failed object-creating write throws. It surfaces the REAL S3 <Code>
 * (sanitised) in the message -- "PUT seg/0001: status 400 (InvalidRequest)" -- so the next operator sees the
 * actionable cause rather than the engine's generic class. When the body is AWS's missing-checksum
 * complaint on an Object-Lock write, it appends a fixed, safe hint naming that exact cause. The status
 * number is always present (so the existing "status NNN" classifiers still fire); the code/hint are purely
 * additive. No raw message text is ever forwarded -- only the validated code and a constant hint string.
 *
 * It RETURNS the error rather than throwing it. The checksum hint is chosen by matching the body for
 * Content-MD5 or x-amz-checksum as a BOOLEAN only, so it can ride on any code, not just InvalidRequest.
 * A body with no recognisable code yields the bare "status NNN" message.
 *
 * @param verb - the HTTP verb, for the message ("PUT" / "conditional PUT").
 * @param key - the object key the write targeted.
 * @param status - the status the store answered with.
 * @param body - the store's error body, already read and bounded.
 * @param lockArmed - whether the write actually carried Object-Lock headers (see isObjectLockRefusal).
 * @returns the error to throw, stamped when the body is an Object-Lock refusal.
 */
export function s3WriteFailure(verb: string, key: string, status: number, body: string, lockArmed = false): Error {
  return stampObjectLockRefusal(s3WriteError(verb, key, status, body), body, lockArmed);
}

// isObjectLockRefusal is the ONE decision function for "did the store refuse this write because of
// Object-Lock". It reads the raw error body, which exists only at the throw site, and answers a boolean;
// nothing downstream ever sees the body. Both public entry points below go through it, so the two stores
// land in the same class from the same rules rather than from two spellings of them.
//
// lockArmed (whether the failed request actually carried Object-Lock headers) gates ONLY the NotImplemented
// arm, since NotImplemented names the lock policy only when the lock policy was what was asked for. The two
// older arms, the checksum complaint and the documented lock codes, stay unconditional exactly as they were.
function isObjectLockRefusal(body: string, lockArmed: boolean): boolean {
  const code = s3ErrorCode(body);
  if (OBJECT_LOCK_CHECKSUM_RE.test(body) || OBJECT_LOCK_CODE_RE.test(code ?? "")) return true;
  return lockArmed && OBJECT_LOCK_UNSUPPORTED_CODE_RE.test(code ?? "");
}

/**
 * stampObjectLockRefusal puts the boolean OBJECT_LOCK_REFUSAL_PROP on an already-built error when the
 * response body says the store refused the write over Object-Lock. It exists so the paths that build their
 * error somewhere else (the multipart initiate, which throws through throttleError to keep its Retry-After)
 * reach the SAME verdict from the SAME function as the single-shot PUT, rather than growing a second
 * spelling of the same idea.
 *
 * lockArmed is whether the request actually carried Object-Lock headers. It gates only the
 * NotImplemented arm; the checksum complaint and the documented lock codes are unconditional, as before.
 *
 * @param e - the error to stamp (returned unchanged when the body is not a lock refusal).
 * @param body - the store's error body, already read and bounded.
 * @param lockArmed - whether the failed request carried Object-Lock headers.
 * @returns the same error, stamped when the verdict is true.
 */
export function stampObjectLockRefusal(e: Error, body: string, lockArmed: boolean): Error {
  return isObjectLockRefusal(body, lockArmed) ? Object.assign(e, { [OBJECT_LOCK_REFUSAL_PROP]: true }) : e;
}

// s3WriteError builds the MESSAGE half, unchanged in every case, so every message-based consumer
// (destRejectionDetail, the "status NNN (Code)" classifiers, the fault-log shapes, the existing tests) sees
// exactly what it saw. The Object-Lock verdict is a separate, stamped BOOLEAN, because down-reason
// classification used to recover it by matching the sanitised MESSAGE and that lost twice: the redaction
// seam had already narrowed the body to a code plus a fixed hint, and a lock refusal that arrives as a 403
// was decided by the auth arm before the prose net was ever reached. The evidence is the raw body, which
// exists only at the throw site, so the fact goes on the object at the throw site (see
// OBJECT_LOCK_REFUSAL_PROP in dest/classify.ts). Booleans only: the body itself is never forwarded.
function s3WriteError(verb: string, key: string, status: number, body: string): Error {
  const code = s3ErrorCode(body);
  return code === undefined
    ? new Error(`${verb} ${key}: status ${status}`)
    : new Error(`${verb} ${key}: status ${status} (${OBJECT_LOCK_CHECKSUM_RE.test(body) ? `${code}: object lock write requires a checksum` : code})`);
}

/**
 * parseObjectLockConfig parses an S3 GetObjectLockConfiguration response body into a WormStatus.
 * Shape: <ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled>[<Rule>
 * <DefaultRetention><Mode>GOVERNANCE|COMPLIANCE</Mode><Days>N</Days>|<Years>N</Years>
 * </DefaultRetention></Rule>]</ObjectLockConfiguration>. Only when ObjectLockEnabled is exactly
 * "Enabled" do we report enabled:true; anything else (missing, "Disabled", garbage) is the honest
 * not-enabled. The default rule, when present, is surfaced; Years is normalised to days (×365) so a
 * single defaultDays field carries either. A body that does not parse as an ObjectLockConfiguration
 * at all is "unknown" (we cannot confirm enforcement), never silently treated as enabled.
 *
 * The three verdicts are asymmetric on purpose: an absent outer element reports unknown with the
 * body-unparseable reason (usually a proxy stripping the document), whereas a well-formed document that
 * does not say Enabled is a DEFINITE not-enabled. PURE regex matching, no XML parser: the outer element
 * may carry attributes (an xmlns is the common case), but a namespace-PREFIXED element name is not
 * recognised and reads as body-unparseable. Days wins over Years when both appear, and a default rule
 * carrying neither leaves defaultDays unset.
 */
export function parseObjectLockConfig(xml: string): WormStatus {
  // G279: a 200 whose body is NOT an ObjectLockConfiguration is a store (or, far more often, a PROXY) mangling
  // or stripping the document -- a completely different remedy from a permission denial or a network blip, and
  // until now they all collapsed into one bare "unknown". Name the cause; never carry a byte of the body.
  if (!/<ObjectLockConfiguration[\s>]/.test(xml)) return { enabled: "unknown", unknownReason: "body-unparseable" };
  const enabledMatch = /<ObjectLockEnabled>\s*([^<]*?)\s*<\/ObjectLockEnabled>/.exec(xml);
  const enabled = enabledMatch?.[1] === "Enabled";
  if (!enabled) return { enabled: false };
  const modeRaw = /<Mode>\s*([^<]*?)\s*<\/Mode>/.exec(xml)?.[1];
  const days = /<Days>\s*(\d+)\s*<\/Days>/.exec(xml)?.[1];
  const years = /<Years>\s*(\d+)\s*<\/Years>/.exec(xml)?.[1];
  const out: WormStatus = { enabled: true };
  if (modeRaw === "GOVERNANCE") out.defaultMode = "governance";
  else if (modeRaw === "COMPLIANCE") out.defaultMode = "compliance";
  if (days !== undefined) out.defaultDays = Number(days);
  else if (years !== undefined) out.defaultDays = Number(years) * 365;
  return out;
}
