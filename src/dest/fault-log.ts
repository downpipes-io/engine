// fault-log.ts -- the bounded, closed-vocabulary record of WHY a destination op failed (G135).
//
// The problem it solves: every destination op past the single-shot PUT collapses its fault to a bare
// "status 403" (or to a coarse run-error class), so a support pack cannot tell an expired STS session from
// a bucket-policy denial from a WORM InvalidRequest from a SignatureDoesNotMatch, and cannot tell a
// genuinely-permanent fault from one the classifier DEFAULTED to permanent because the message shape was
// unreadable. This module gives the S3 driver a per-instance ring that records the fault IDENTITY of every
// failing op in closed vocabularies, so the seal driver can stamp it on the run row and the pack can carry
// it.
//
// NO-CUSTODY REDACTION (binding): every field here is a closed enum, a boolean or a clamped int. The S3
// error <Code> is NOT surfaced as free text: it is matched against a CLOSED ALLOW-LIST of documented S3
// error codes, and anything outside that list records as "other". A raw error body, a key, an endpoint, a
// bucket, a header value, an x-amz-request-id or a message never enters a record (the request id is
// reduced to a PRESENCE boolean -- it is an opaque vendor token, and presence alone is what tells support
// whether the store even answered).
//
// LEAF module: it imports only classify.ts (itself import-free), so it can be shared across dest/* without
// a cycle.

import { classifyDestErrorArm, classifyDestStatus, type DestClassifierArm, type DestFault } from "./classify.ts";

/**
 * DEST_OPS is the closed vocabulary of destination operations that can fail. It names the WIRE op, never
 * the key/prefix/bucket it acted on. Every failing call site in the S3 driver maps to exactly one of these.
 */
export const DEST_OPS = [
  "put",
  "put-conditional",
  "multipart-initiate",
  "multipart-part",
  "multipart-complete",
  "multipart-abort",
  "get",
  "head",
  "delete",
  "list",
  "object-lock-probe",
] as const;
/**
 * The `op` field of a fault record: one member of DEST_OPS. The S3 driver's request helpers (s3.ts metered
 * and signedRequest, and the read / multipart op modules) take it as a REQUIRED argument, so a call site
 * cannot record a fault without naming which wire op produced it, and cannot name one outside the
 * vocabulary.
 */
export type DestOp = (typeof DEST_OPS)[number];

/**
 * S3_ERROR_CODES is the CLOSED allow-list of S3 error <Code> tokens we will record verbatim. They are a
 * documented, fixed, vendor-defined enum (never secret, never customer data), and each one names a
 * DIFFERENT operator action: InvalidAccessKeyId/SignatureDoesNotMatch = a broken credential; ExpiredToken/
 * TokenRefreshRequired/InvalidToken = a lapsed STS session; AccessDenied = a bucket/IAM policy; InvalidRequest
 * (+ the wormChecksumComplaint flag) = an Object-Lock write missing its checksum; InvalidObjectState = a
 * cold storage class needing a thaw; SlowDown = real backpressure. A body carrying anything OUTSIDE this
 * list records as "other" -- the allow-list is what makes this seam un-smugglable: no adversarial or
 * misconfigured store can push arbitrary text through it.
 */
export const S3_ERROR_CODES = [
  "AccessDenied",
  "AccountProblem",
  "AllAccessDisabled",
  "AuthorizationHeaderMalformed",
  "BadDigest",
  "BucketNotEmpty",
  "EntityTooLarge",
  "EntityTooSmall",
  "ExpiredToken",
  "InternalError",
  "InvalidAccessKeyId",
  "InvalidArgument",
  "InvalidBucketName",
  "InvalidBucketState",
  "InvalidDigest",
  "InvalidObjectState",
  "InvalidPart",
  "InvalidPartOrder",
  "InvalidRange",
  "InvalidRequest",
  "InvalidRetentionPeriod",
  "InvalidSecurity",
  "InvalidToken",
  "KeyTooLongError",
  "MalformedXML",
  "MethodNotAllowed",
  "MissingContentLength",
  "MissingSecurityHeader",
  "NoSuchBucket",
  "NoSuchKey",
  "NoSuchUpload",
  "NotImplemented",
  "ObjectLockConfigurationNotFoundError",
  "OperationAborted",
  "PermanentRedirect",
  "PreconditionFailed",
  "RequestTimeout",
  "RequestTimeTooSkewed",
  "ServiceUnavailable",
  "SignatureDoesNotMatch",
  "SlowDown",
  "TemporaryRedirect",
  "TokenRefreshRequired",
  "TooManyBuckets",
  "UnauthorizedAccess",
  "XAmzContentSHA256Mismatch",
] as const;
/**
 * The `s3Code` field of a fault record: an allow-listed token, "other" when the body carried a token the
 * allow-list does not hold, or "none" when it carried no parseable code at all. The two extra members are
 * what let the field stay closed while still distinguishing "the store said something we do not recognise"
 * from "the store said nothing", which are different diagnoses.
 */
export type S3ErrorCode = (typeof S3_ERROR_CODES)[number] | "other" | "none";

const S3_ERROR_CODE_SET: ReadonlySet<string> = new Set(S3_ERROR_CODES);

// CODE_RE is deliberately TIGHT (a leading letter, then up to 63 letters/digits, nothing else), matching
// the s3-worm.ts discipline, so a hostile body cannot even reach the allow-list check with punctuation or
// whitespace smuggled in. The extracted token is then required to be IN the allow-list.
const CODE_RE = /<Code>\s*([A-Za-z][A-Za-z0-9]{0,63})\s*<\/Code>/;

// OBJECT_LOCK_COMPLAINT_RE recognises AWS's specific complaint when an Object-Lock write omits its required
// integrity header. Matched as a BOOLEAN against the body only; no text from the body is ever forwarded.
// This is the one bit that separates "WORM refused the write" from a generic InvalidRequest.
const OBJECT_LOCK_COMPLAINT_RE = /Content-MD5|x-amz-checksum|object[- ]lock/i;

/**
 * Reduces a failed response's body to a CLOSED S3 error code: the documented token when the body carries
 * one from the allow-list, "other" when it carries an unrecognised token, "none" when it carries no
 * parseable code at all. The body itself is never retained.
 *
 * @param body - the (already-bounded) error body text.
 * @returns the closed code.
 */
export function closedS3Code(body: string): S3ErrorCode {
  const raw = CODE_RE.exec(body)?.[1];
  if (raw === undefined) return "none";
  return S3_ERROR_CODE_SET.has(raw) ? (raw as S3ErrorCode) : "other";
}

/**
 * DEST_ANOMALIES (gaps G085 / G119 / G206 / G207): the destination behaviours that are NOT a failed op with a
 * status -- so the fault ring above cannot hold them -- and that today either die as a coarse run-error class
 * or, worse, are SILENTLY TOLERATED. Each member names the BEHAVIOUR, never the key, page, header or size:
 *
 *   list-truncated-no-cursor      (G085, DATA LOSS) a ListObjectsV2 page said IsTruncated=true and gave NO
 *                                 NextContinuationToken. The walk STOPS believing it saw the whole keyspace,
 *                                 so a replication seg/ sync copies only the first page and the replica reads
 *                                 healthy (ok:true, a full holdsIndex) while being non-restorable. Recorded
 *                                 with the clamped page count reached (listPagesReached).
 *   no-upload-id                  (G206) a multipart-initiate 200 whose body carried no <UploadId> (a
 *                                 namespaced-XML or stripping proxy): every large-segment write fails.
 *   no-etag-on-part               (G206) a multipart UploadPart 200 with no ETag header.
 *   no-etag-on-get                (G206) a GET 200 with no ETag: the store cannot satisfy the conditional-write
 *                                 contract the RUNLOG depends on.
 *   no-etag-on-conditional-put    (G206) a conditional PUT 200 with no ETag. This one is SILENTLY TOLERATED
 *                                 today (the caller falls back to a body compare), so RUNLOG concurrency
 *                                 degrades with nothing recorded anywhere.
 *   error-in-200-body             (G206) the store answered 2xx and embedded an <Error> document.
 *   segment-over-limit            (G207) the engine's own segment ceiling refused a write. overBoundBytes
 *                                 carries the CLAMPED actual size, so support can tell an off-by-framing from a
 *                                 wildly wrong value.
 *   sealed-bound-exceeded         (G207) a sealed stream ran past its declared bound (an engine-side invariant).
 *   key-shape-refused             (G207) the key-traversal guard refused an object key's shape.
 *   redirect-wrong-region         (G119) a credentialed request was answered with a 3xx whose Location names an
 *                                 AWS REGIONAL endpoint: the bucket lives in another region. redirectRegionHint
 *                                 carries the REGION TOKEN ONLY (validated against the region shape) -- never the
 *                                 Location URL, which embeds the bucket and the host.
 *   redirect-target-unrecognised  (G119) a 3xx whose Location is NOT an AWS regional endpoint (a corporate proxy,
 *                                 a captive portal, an appliance interposing on the endpoint). The target is
 *                                 recorded ONLY as this class.
 */
export const DEST_ANOMALIES = [
  "list-truncated-no-cursor",
  "no-upload-id",
  "no-etag-on-part",
  "no-etag-on-get",
  "no-etag-on-conditional-put",
  "error-in-200-body",
  "segment-over-limit",
  "sealed-bound-exceeded",
  "key-shape-refused",
  "redirect-wrong-region",
  "redirect-target-unrecognised",
] as const;
/**
 * One member of DEST_ANOMALIES. It is the key space of the ring's anomaly tally, so that tally cannot grow
 * past the vocabulary above however many times a store misbehaves. noteGuardRefusal narrows it with Extract
 * to the three engine-guard members, so only those can be noted with a byte magnitude alongside the count.
 */
export type DestAnomaly = (typeof DEST_ANOMALIES)[number];

// AWS_REGION_RE is the REDACTION GATE on the one field of this record that is derived from a store-controlled
// header (the 301/307 Location). It is the AWS regional shape ONLY (us-east-1, ap-southeast-2, cn-northwest-1):
// a host, a bucket, a path, a query or any punctuation structurally cannot pass it, so the Location URL -- which
// embeds the customer's bucket name and endpoint -- can never ride. It mirrors sts.ts VALID_STS_REGION.
const AWS_REGION_RE = /^[a-z]{2}(?:-[a-z]+)+-\d{1,2}$/;
// REGION_ENDPOINT_RE extracts the region token from an AWS regional S3 endpoint host. It is applied to the
// Location's HOST only, and its capture is then re-gated by AWS_REGION_RE, so nothing but a region token can
// leave regionHintFromLocation.
const REGION_ENDPOINT_RE = /(?:^|\.)s3[.-]([a-z]{2}(?:-[a-z]+)+-\d{1,2})\.amazonaws\.com$/;

/**
 * regionHintFromLocation READS a redirect's Location header ONLY to SELECT the region token of an AWS regional
 * S3 endpoint, and RETURNS that token (or undefined when the target is not one). This is the G119 redaction
 * chokepoint: the Location can embed the customer's bucket name, a proxy host or a signed query, and NONE of
 * that can leave this function -- the return alphabet is exactly "a string matching AWS_REGION_RE, or nothing".
 *
 * @param location - the raw Location header value (never retained).
 * @returns the region token, or undefined when the target is not an AWS regional endpoint.
 */
export function regionHintFromLocation(location: string | null): string | undefined {
  if (location === null || location === "") return undefined;
  let host: string;
  try {
    host = new URL(location).host.toLowerCase();
  } catch {
    return undefined; // a relative / malformed Location names no region
  }
  const token = REGION_ENDPOINT_RE.exec(host)?.[1];
  return token !== undefined && AWS_REGION_RE.test(token) ? token : undefined;
}

/**
 * G343: THE STRANDED MULTIPART PARTS
 *
 * When a multipart upload fails, the driver aborts it best-effort so the store is not left accumulating
 * invisible part storage. When THAT abort ALSO fails, the parts are stranded: the customer is billed for
 * growing incomplete-multipart storage after a failed backup, and the only thing that survived was ONE
 * BOOLEAN on the run row (multipartAbortFailed). So support could not say whether the aborts were
 * PERMISSION-DENIED (fix the bucket policy: s3:AbortMultipartUpload) or the store ERRORED (set a lifecycle
 * rule to reap them) or the endpoint was simply UNREACHABLE at that moment (nothing to fix) -- three
 * different answers -- nor how much was stranded.
 *
 * ABORT_FAILURE_CLASSES is the closed WHY. The count rides alongside it. The seg/ keys and the uploadIds are
 * engine-generated and are deliberately NOT carried: the remedy does not need them.
 */
export const ABORT_FAILURE_CLASSES = [
  "denied", // 401/403: the credential may WRITE parts but not ABORT them (the classic narrow bucket policy)
  "server-error", // 5xx: the store failed the abort; a lifecycle / abort rule is the durable remedy
  "network", // the abort request never got an answer (DNS / TLS / reset / timeout): usually self-healing
  "other", // residual: never a message
] as const;
/**
 * The closed reason a multipart abort itself failed: what classifyAbortFailure returns and what rides on the
 * run row as strandedAborts.lastClass. sanitiseStrandedAborts re-checks a POSTED value against the same set
 * and drops the whole record when it is not a member, so the field can never arrive as free text.
 */
export type AbortFailureClass = (typeof ABORT_FAILURE_CLASSES)[number];
const ABORT_FAILURE_CLASS_SET: ReadonlySet<string> = new Set(ABORT_FAILURE_CLASSES);

/**
 * classifyAbortFailure coarsens a FAILED multipart abort into a closed AbortFailureClass. It reads the fault
 * ONLY to select a member (the status it carries, else the transport shape the shared classifier knows) and
 * RETURNS that member: the store's error body, the endpoint, the bucket, the object key and the uploadId
 * never leave the driver.
 *
 * @param e - the thrown abort fault.
 * @param status - the abort response's HTTP status, when the store answered at all.
 * @returns the closed class.
 */
export function classifyAbortFailure(e: unknown, status?: number): AbortFailureClass {
  const code = typeof status === "number" && Number.isFinite(status) ? Math.trunc(status) : 0;
  if (code === 401 || code === 403) return "denied";
  if (code >= 500 && code <= 599) return "server-error";
  if (code >= 400 && code <= 499) return "other";
  // No status: the request never completed. classifyDestStatus cannot help, so use the shared error-arm
  // classifier -- a timeout/reset/DNS fault is a `transient` transport class with a 0 status.
  const { status: derived } = classifyDestErrorArm(e);
  if (derived === 401 || derived === 403) return "denied";
  if (derived >= 500 && derived <= 599) return "server-error";
  if (derived === 0) return "network";
  return "other";
}

/** G343: how many multipart aborts FAILED on this destination instance, and the class of the most recent. */
export interface StrandedAborts {
  count: number;
  lastClass: AbortFailureClass;
}

/**
 * sanitiseStrandedAborts re-gates a posted strandedAborts record: the class must be a member and the count a
 * clamped positive int, else the whole record is dropped. PURE (a redaction chokepoint helper, so the DO-side
 * applier and the driver agree on exactly one shape).
 *
 * @param raw - the posted value (untrusted).
 * @returns the gated record, or undefined.
 */
export function sanitiseStrandedAborts(raw: unknown): StrandedAborts | undefined {
  if (typeof raw !== "object" || raw === null) return undefined;
  const r = raw as { count?: unknown; lastClass?: unknown };
  if (typeof r.lastClass !== "string" || !ABORT_FAILURE_CLASS_SET.has(r.lastClass)) return undefined;
  if (typeof r.count !== "number" || !Number.isFinite(r.count) || r.count <= 0) return undefined;
  return { count: Math.min(DEST_ANOMALY_COUNT_CAP, Math.floor(r.count)), lastClass: r.lastClass as AbortFailureClass };
}

/**
 * One recorded destination fault: the op, the clamped HTTP status (0 when the request never got a
 * response), the closed S3 code, the fault class the retry layer acted on, the classifier ARM that decided
 * that class (so support can see a fault the classifier DEFAULTED to permanent because it could not read
 * the message), whether the store even returned a request id, whether the store's complaint was the
 * Object-Lock checksum rule, and how many identical faults collapsed into this record.
 */
export interface DestFaultRecord {
  op: DestOp;
  httpStatus: number;
  s3Code: S3ErrorCode;
  fault: DestFault;
  arm: DestClassifierArm;
  requestIdPresent: boolean;
  wormChecksumComplaint: boolean;
  count: number;
}

/** The bounded snapshot the seal driver reads off a destination after a run. */
export interface DestFaultSnapshot {
  /** Total faults observed on this destination instance (every failing op, including retried ones). */
  total: number;
  /** Distinct fault SHAPES dropped because the ring was full (so a truncated view is never silently green). */
  overflow: number;
  /** Up to DEST_FAULT_SHAPES distinct fault shapes, most-recently-first, each with its own count. */
  faults: DestFaultRecord[];
  /** G085/G119/G206/G207: {closed anomaly -> count}. Absent when the store behaved conformantly. */
  anomalies?: Record<string, number>;
  /** G119: the region token of the redirect target, when it named an AWS regional endpoint. Never a URL. */
  redirectRegionHint?: string;
  /** G207: the CLAMPED size that tripped an engine guard (segment-over-limit / sealed-bound-exceeded). */
  overBoundBytes?: number;
  /** G085: how many list pages the walk reached before the store truncated it without a cursor. */
  listPagesReached?: number;
  /** G343: the multipart aborts that THEMSELVES failed, leaving stranded part-storage the customer is billed
   * for: how many, and the closed class of the most recent (denied = fix the policy; server-error = set a
   * lifecycle rule; network = it will likely heal). Absent when every abort landed. */
  strandedAborts?: StrandedAborts;
}

// The clamp on a byte magnitude carried on the ring: an int, bounded, non-negative. It is a SIZE, never a
// value; the ceiling only stops a malformed number bloating the record.
const DEST_BYTES_MAX = Number.MAX_SAFE_INTEGER;
const DEST_ANOMALY_COUNT_CAP = 1_000_000;

/**
 * The cap on DISTINCT fault shapes a destination instance retains. A run that fails 33 multipart parts the
 * same way collapses to ONE record with count 33, so 8 shapes is a generous ceiling for a real fault
 * pattern while keeping the run row (and the pack) bounded.
 */
export const DEST_FAULT_SHAPES = 8;

/** The HTTP-status clamp: a status is an int in 0..999 (0 = the request never received a response). */
function clampStatus(n: number): number {
  if (!Number.isFinite(n)) return 0;
  return Math.min(999, Math.max(0, Math.trunc(n)));
}

/**
 * DestFaultLog is the per-destination-instance, bounded, closed-vocabulary fault ring. The S3 driver holds
 * one and notes every failing op into it; the seal driver reads snapshot() after finalising a run and
 * stamps it on the run row, exactly as it already does for multipartAbortFailures().
 */
export class DestFaultLog {
  private records: DestFaultRecord[] = [];
  private totalCount = 0;
  private overflowCount = 0;
  // The G085/G119/G206/G207 anomaly counters: a bounded {closed member -> count} tally plus the three
  // magnitude fields. The key space is DEST_ANOMALIES (a closed set), so it can never grow.
  private anomalyCounts: Partial<Record<DestAnomaly, number>> = {};
  private regionHint: string | undefined;
  private overBytes = 0;
  private listPages = 0;
  // G343: the failed-abort tally + the class of the most recent one. Two integers and a closed enum.
  private abortFailures = 0;
  private lastAbortClass: AbortFailureClass | undefined;

  /**
   * Notes a multipart abort that ITSELF failed (G343), leaving stranded part storage. Counts only: the object
   * key, the uploadId and the store's error body never enter the record.
   *
   * @param cls - the closed failure class.
   */
  noteAbortFailure(cls: AbortFailureClass): void {
    this.abortFailures = Math.min(DEST_ANOMALY_COUNT_CAP, this.abortFailures + 1);
    this.lastAbortClass = cls;
  }

  /**
   * Notes ONE non-op anomaly (a store that is non-conformant, a walk the store truncated without a cursor,
   * an engine guard that refused a write). Counters only: nothing about the key, page, header or body enters.
   *
   * @param a - the closed anomaly member.
   */
  noteAnomaly(a: DestAnomaly): void {
    this.anomalyCounts[a] = Math.min(DEST_ANOMALY_COUNT_CAP, (this.anomalyCounts[a] ?? 0) + 1);
  }

  /**
   * Notes a credentialed request the store answered with a redirect (G119). The Location is READ only to
   * SELECT the region token of an AWS regional endpoint (regionHintFromLocation, the redaction chokepoint);
   * a target that is not one records ONLY the closed redirect-target-unrecognised class. The URL itself --
   * which embeds the bucket and the host -- is never retained.
   *
   * @param resp - the redirect response (its Location header is read, never stored).
   */
  noteRedirect(resp: Response): void {
    const region = regionHintFromLocation(resp.headers.get("location"));
    if (region === undefined) {
      this.noteAnomaly("redirect-target-unrecognised");
      return;
    }
    this.noteAnomaly("redirect-wrong-region");
    this.regionHint = region; // already gated to the region shape; a bucket/host/URL cannot be here
  }

  /**
   * Notes an engine GUARD refusal with its MAGNITUDE (G207): the size that tripped a ceiling, so support can
   * tell an off-by-framing overrun from a wildly wrong value without the message text (which is coarsened away
   * at the run row). The size is a clamped non-negative int; the offending key never rides.
   *
   * @param a - the closed guard class.
   * @param bytes - the observed size, clamped.
   */
  noteGuardRefusal(a: Extract<DestAnomaly, "segment-over-limit" | "sealed-bound-exceeded" | "key-shape-refused">, bytes?: number): void {
    this.noteAnomaly(a);
    if (typeof bytes === "number" && Number.isFinite(bytes) && bytes > 0) {
      this.overBytes = Math.max(this.overBytes, Math.min(DEST_BYTES_MAX, Math.floor(bytes)));
    }
  }

  /**
   * Notes a listing the store TRUNCATED WITHOUT A CURSOR (G085): the walk stops believing it enumerated the
   * whole keyspace, which is how a replica silently ends up holding only the first page of the segment store.
   * Records the page count reached; never a key or a page body.
   *
   * @param pagesReached - how many pages the walk had read when the store truncated it.
   */
  noteListTruncatedNoCursor(pagesReached: number): void {
    this.noteAnomaly("list-truncated-no-cursor");
    if (Number.isFinite(pagesReached) && pagesReached > 0) this.listPages = Math.max(this.listPages, Math.min(DEST_ANOMALY_COUNT_CAP, Math.floor(pagesReached)));
  }

  /**
   * Notes a fault decided by a REAL HTTP response: the status is the observed one (arm "matched-status"),
   * and the closed S3 code is read from the (already-bounded) error body.
   *
   * @param op - the closed destination op.
   * @param resp - the failed response (read for its status and the PRESENCE of a request id only).
   * @param body - the already-bounded error body text; never retained.
   */
  noteResponse(op: DestOp, resp: Response, body: string): void {
    this.push({
      op,
      httpStatus: clampStatus(resp.status),
      s3Code: closedS3Code(body),
      fault: classifyDestStatus(resp.status),
      arm: "matched-status",
      requestIdPresent: hasRequestId(resp),
      wormChecksumComplaint: OBJECT_LOCK_COMPLAINT_RE.test(body),
    });
  }

  /**
   * Notes a store that answered 2xx but embedded an error document (the multipart-complete case): the
   * status is a success, so no status arm can decide it -- it is a PERMANENT fault the classifier would
   * otherwise have defaulted to, and recording it as such is the point.
   *
   * @param op - the closed destination op.
   * @param resp - the (2xx) response.
   * @param body - the already-bounded body text; never retained.
   */
  noteBodyError(op: DestOp, resp: Response, body: string): void {
    this.push({
      op,
      httpStatus: clampStatus(resp.status),
      s3Code: closedS3Code(body),
      fault: "permanent",
      arm: "default-permanent",
      requestIdPresent: hasRequestId(resp),
      wormChecksumComplaint: OBJECT_LOCK_COMPLAINT_RE.test(body),
    });
  }

  /**
   * Notes a fault that arrived as a THROWN error (a transport failure, an abort/timeout, a rethrow from a
   * lower layer). The classifier arm records HOW the class was decided, so a "default-permanent" arm --
   * the fault we could not read at all -- is visible rather than indistinguishable from a real 4xx.
   *
   * @param op - the closed destination op.
   * @param e - the thrown value. Only its class/arm/status are derived; the message is never retained.
   */
  noteThrown(op: DestOp, e: unknown): void {
    const { fault, arm, status } = classifyDestErrorArm(e);
    this.push({
      op,
      httpStatus: clampStatus(status),
      s3Code: "none",
      fault,
      arm,
      requestIdPresent: false,
      wormChecksumComplaint: false,
    });
  }

  /**
   * The bounded snapshot: the total, the dropped-shape overflow, and up to DEST_FAULT_SHAPES distinct
   * shapes most-recently-first. Every field is a closed enum, a boolean or a clamped int.
   *
   * @returns the snapshot (a fresh copy; the caller cannot mutate the ring).
   */
  snapshot(): DestFaultSnapshot {
    const anomalies: Record<string, number> = {};
    for (const [k, n] of Object.entries(this.anomalyCounts)) {
      if (typeof n === "number" && n > 0) anomalies[k] = n;
    }
    return {
      total: this.totalCount,
      overflow: this.overflowCount,
      faults: this.records.map((r) => ({ ...r })),
      ...(Object.keys(anomalies).length > 0 ? { anomalies } : {}),
      ...(this.regionHint !== undefined ? { redirectRegionHint: this.regionHint } : {}),
      ...(this.overBytes > 0 ? { overBoundBytes: this.overBytes } : {}),
      ...(this.listPages > 0 ? { listPagesReached: this.listPages } : {}),
      ...(this.abortFailures > 0 && this.lastAbortClass !== undefined ? { strandedAborts: { count: this.abortFailures, lastClass: this.lastAbortClass } } : {}),
    };
  }

  /** Total faults observed, for a caller that only wants the count (mirrors multipartAbortFailures()). */
  total(): number {
    return this.totalCount;
  }

  /** Whether this destination recorded ANY evidence (a failing op, a non-op anomaly, or a stranded abort).
   * The run-fault reporter uses it so a clean destination still posts nothing while an anomaly-only run is
   * not lost. */
  hasEvidence(): boolean {
    return this.totalCount > 0 || Object.keys(this.anomalyCounts).length > 0 || this.abortFailures > 0;
  }

  // push folds an identical fault shape into its existing record (count++) and otherwise prepends a new
  // one, dropping (and TALLYING) the oldest shape past the cap so the ring is hard-bounded.
  private push(rec: Omit<DestFaultRecord, "count">): void {
    this.totalCount++;
    const hit = this.records.find((r) => r.op === rec.op && r.httpStatus === rec.httpStatus && r.s3Code === rec.s3Code && r.fault === rec.fault && r.arm === rec.arm && r.wormChecksumComplaint === rec.wormChecksumComplaint);
    if (hit) {
      hit.count++;
      // A repeat also refreshes recency: the shape that is still firing leads the snapshot.
      this.records = [hit, ...this.records.filter((r) => r !== hit)];
      return;
    }
    this.records.unshift({ ...rec, count: 1 });
    if (this.records.length > DEST_FAULT_SHAPES) {
      this.records.length = DEST_FAULT_SHAPES;
      this.overflowCount++;
    }
  }
}

// hasRequestId reports whether the store returned an x-amz-request-id / x-amz-id-2 at all. The VALUE is an
// opaque vendor token and is never recorded; its PRESENCE is what tells support the request reached a real
// S3-compatible store (rather than a proxy, a captive portal or an error page).
function hasRequestId(resp: Response): boolean {
  return resp.headers.get("x-amz-request-id") !== null || resp.headers.get("x-amz-id-2") !== null;
}
