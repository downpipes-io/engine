// DestIoSnapshot lives HERE, in the types module, rather than in dest-io.ts. It moved
// because types.ts importing it from dest-io.ts closed a circular dependency:
// dest-io.ts imports admin/diag-writer.ts, which reaches router-helpers.ts and from there the whole
// scheduler-do mixin web, so a types leaf was transitively pulling in the Durable Object.
// A pure interface belongs with the other types either way.
/**
 * The per-instance snapshot the seal driver can stamp on a run row: the six counters plus the pacer's WORST
 * effective rate over the instance's life. minEffectiveRatePerSec is the one non-counter: it is the floor the
 * adaptive pacer was driven down to (requests/second, clamped to a non-negative int), and it is what
 * separates "the store pushed back once" from "the store held us at 1 req/s all night". It is undefined when
 * no pacer was attached (the in-memory doubles, and any caller that builds a destination without one).
 */
export interface DestIoSnapshot {
  throttleObservations: number;
  retryAttemptsTotal: number;
  timeouts: number;
  conditionalPutConflicts: number;
  headNon200CollapsedToAbsent: number;
  retryAfterUnparseable: number;
  minEffectiveRatePerSec?: number;
}

import type { DestFaultSnapshot } from "./fault-log.ts";

// The destination abstraction the run pipeline writes to. S3Destination implements it
// over an S3-compatible bucket; a memory implementation backs the offline tests. The
// conditional put is the optimistic-concurrency primitive for the account-wide RUNLOG
// (design F10): concurrent downpipe runs read-append-resign and write with If-Match, so
// a lost update is detected and retried rather than silently dropping an entry.

/** The result of a destination get: the object's bytes and its (unquoted) ETag. */
export interface GetResult {
  body: Uint8Array;
  etag: string;
}

/**
 * One page of a streamed key listing (listPage): the keys in this page and the opaque cursor to
 * pass back for the NEXT page. cursor is undefined when this is the final page (the listing is
 * complete). Unlike list(), which materialises the WHOLE keyspace into one array, listPage exposes
 * the store's native pagination so a caller iterating a large prefix (the off-site replication seg/
 * sync) holds at most one page in memory at a time rather than the whole content-addressed store.
 * Keys within and across pages are in the store's native lexicographic order (S3 ListObjectsV2 / R2
 * list both page in sorted key order), which the replication merge-walk relies on.
 */
export interface ListPage {
  keys: string[];
  cursor?: string;
}

/** The result of a conditional put: ok is false when the precondition failed (a concurrent write
 * won, so the caller retries), and etag carries the new version when the write succeeded. */
export interface PutConditionalResult {
  ok: boolean; // false means the precondition failed (a concurrent write won); retry
  etag?: string;
}

/**
 * DestStatusError is the TYPED form of a store request that ANSWERED with a status the caller cannot use
 * (G246). The message is byte-identical to the plain Error it replaces, so every existing catch, log line and
 * operator response is unchanged; what is new is that the STATUS the wire op already read off the response is
 * carried rather than thrown away.
 *
 * WHY. probeDestination's cleanup delete classified its own failure from the bare fact of a throw and called
 * every one of them "denied" -- a PERMISSION fact it had not established. A 503 SlowDown, a 500, a 429 and a
 * dropped socket are not a denial, and telling support the customer's retention is permanently broken because
 * one request was unlucky is the same defect, inverted, as hiding a real least-privilege denial behind "the
 * store was flaky". The status was already in hand at the throw site; only the type was missing.
 *
 * A TRANSPORT fault (the request never reached a status) throws its own ordinary error, and destStatusOf
 * returns undefined for it -- which is exactly the fact "no status was ever seen".
 */
export class DestStatusError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "DestStatusError";
    this.status = status;
  }
}

/**
 * destStatusOf reads the store status off a thrown value, or undefined when the throw carried none (a
 * transport fault, or any other error). Type-tested, never text-matched.
 *
 * @param e - the thrown value.
 * @returns the HTTP status the store answered with, or undefined when the request never got one.
 */
export function destStatusOf(e: unknown): number | undefined {
  return e instanceof DestStatusError ? e.status : undefined;
}

/**
 * The SPEC 14.5 single-segment plaintext ceiling, 1 GiB. The source caps a value to this before
 * streaming and the destination asserts it as defence in depth.
 */
export const MAX_STREAM_SEGMENT_BYTES = 1024 * 1024 * 1024;

/**
 * The cap on a destination's small, fixed-shape response reads: S3 error documents, the WORM/Object-Lock
 * probe, and the multipart initiate/complete acknowledgements. Every one of these is a tiny, bounded body
 * in a conforming response (an error <Code>, an UploadId, a completion ack), so a body over this cap is a
 * misconfigured or hostile store and is refused before being buffered rather than trusted via an
 * omittable Content-Length header (V12.3.1).
 */
export const MAX_DEST_TEXT_BYTES = 64 * 1024;

/**
 * The cap on a single ListObjectsV2 page read (listPage). Every S3-compatible store bounds a page to
 * 1000 keys regardless of bucket size, so this is sized for the largest CONFORMING page this system's
 * own fixed ~75-byte seg/run key shapes could ever produce (well under 300 KiB) with generous headroom --
 * not MAX_DEST_TEXT_BYTES, which is too tight for a real large listing: the content-addressed seg/ store
 * is expected to reach 100,000+ keys (SEG_KEYSPACE_WARN_KEYS, seal/replicate.ts), and paging through it a
 * page at a time is exactly what listPage exists for, so its cap must not reject a legitimate full page.
 */
export const MAX_LIST_PAGE_BYTES = 1024 * 1024;

/**
 * The Cloudflare R2 single-PUT object-size ceiling, ~4.995 GiB. The native R2Bucket binding exposes
 * no multipart upload API (the binding's only write is .put), so a streamed in-account restore is
 * bounded by R2's single-PUT maximum, not by the 1 GiB per-segment plaintext ceiling: a value
 * chained across many >1 GiB segments still restores as ONE streamed PUT as long as the whole value
 * fits under this. A value past this ceiling cannot be written in a single PUT and is steered to the
 * offline downpipe CLI (which runs on a real machine with no Worker/binding limits). 4.995 GiB is
 * Cloudflare's documented R2 single-PUT max; the conservative .995 leaves headroom under the hard 5
 * GiB API limit.
 */
export const R2_MAX_SINGLE_PUT = Math.floor(4.995 * 1024 * 1024 * 1024);

// WORM (Write-Once-Read-Many) / Object-Lock. An OPT-IN, DEFAULT-OFF policy that, when set on a
// destination, adds S3 Object-Lock retention metadata to every archive-object creation so the
// store itself REFUSES to delete or overwrite the object until the retain-until date passes. This
// is real, store-enforced immutability (ransomware resilience): a compromised delete-credential
// cannot hard-delete an archive whose retention window is still open. It is purely ADDITIVE on top
// of the existing write path; with no policy the writes are byte-identical to before.
//
//   mode "governance": retention can be lifted/shortened by a principal holding the
//     s3:BypassGovernanceRetention permission (a privileged, auditable override). Protects against
//     accidental/ordinary-credential deletion.
//   mode "compliance": retention CANNOT be shortened or removed by ANYONE for the window, not even
//     the root account. This is the strong ransomware-resilience property: once written, the object
//     is undeletable until the retain-until date, full stop. Choose it deliberately, a wrong
//     retention window cannot be undone.
//
// CRITICAL PRECONDITION: the BUCKET MUST have been created with Object-Lock enabled. Object-Lock
// cannot be turned on for an existing bucket. If a WORM policy is configured but the bucket does
// not enforce Object-Lock, the store REFUSES the PUT rather than accepting it and dropping the
// headers: R2 answers 501 NotImplemented and AWS S3 answers ObjectLockConfigurationNotFoundError.
// So the destination holds NO objects at all, which is why the capability probe (objectLockStatus)
// exists and why validateAndProbeDestConfig now refuses the combination at add time.
// R2 CANNOT ENFORCE S3 OBJECT-LOCK on any bucket: it does not implement the Object-Lock
// configuration APIs and CreateBucket rejects the object-lock-enabled header, so no R2 bucket can
// be created with it. R2's own bucket-lock retention feature is a separate mechanism that this
// policy and this probe do not reach (see r2.ts; the native R2 binding does not expose object-lock
// on put either). MEASURED against a real R2 bucket over its S3 endpoint, with this
// repo's own signer: GET /<bucket>/?object-lock= answers 404 ObjectLockConfigurationNotFoundError,
// and a PUT carrying x-amz-object-lock-mode: COMPLIANCE answers 501 NotImplemented, "Header
// 'x-amz-object-lock-mode' with value 'COMPLIANCE' not implemented". The S3 endpoint is therefore
// NOT an escape hatch, and r2.ts said for a time that it was; four operator surfaces published that
// remedy, and following it means a 501 on every write and an archive holding nothing.
/**
 * The S3 Object-Lock retention mode: "governance" (a privileged principal can override) or
 * "compliance" (undeletable for the window by anyone, the strong ransomware-resilience property).
 */
export type WormMode = "governance" | "compliance";

/** An opt-in, default-off WORM/Object-Lock policy: the retention mode and the retain-until window
 * in whole days from the write instant (must be a positive integer, or the factory rejects it). */
export interface WormPolicy {
  mode: WormMode;
  // retentionDays is the retain-until window, in days, from the moment of the write. The
  // destination derives an absolute RFC-3339 retain-until-date per object at PUT time. Must be a
  // positive integer; a non-positive or non-finite value is a misconfiguration the factory rejects
  // (fail-safe: a WORM policy that cannot bind must surface as a posture warning, never write
  // unprotected while claiming protection).
  retentionDays: number;
}

// WormStatus is the typed result of the capability probe (objectLockStatus): what the BUCKET
// actually enforces, read live from the store (S3 GetObjectLockConfiguration), independent of any
// policy WE configured. This is what lets the engine report REAL WORM status instead of inferring
// it from whether a delete was refused.
//   enabled false                -> the bucket was NOT created with Object-Lock; no WORM is possible
//                                   here no matter what policy is set (the warning case).
//   enabled true                 -> the bucket enforces Object-Lock. defaultMode/defaultDays carry
//                                   the bucket's DEFAULT retention rule when one is configured
//                                   (absent when the bucket has lock on but no default rule).
//   enabled "unknown"            -> the probe could not determine the state (the store does not
//                                   support the API, returned an unparseable body, or a transport
//                                   fault). Treated as the SAFE (cannot-confirm) reading by posture.
/**
 * The typed result of the WORM capability probe (objectLockStatus): what the bucket actually
 * enforces, read live from the store, independent of any policy we configured. enabled is false
 * when the bucket was not created with Object-Lock and true when it enforces it (with the optional
 * default rule in defaultMode/defaultDays); the "unknown" reading means the probe could not
 * determine the state, the safe cannot-confirm result.
 */
export interface WormStatus {
  enabled: boolean | "unknown";
  defaultMode?: WormMode;
  defaultDays?: number;
  // unknownReason (G279) names WHY the probe could not confirm enforcement. A compliance customer's
  // immutability check that perpetually warns "cannot confirm" had FIVE indistinguishable causes behind one
  // bare "unknown", and they need OPPOSITE answers: a structural R2-binding limitation (this will never
  // confirm and no R2 route ever will), a missing s3:GetBucketObjectLockConfiguration permission (an IAM fix),
  // a proxy mangling the XML, a server error, or a flapping network fault (wait). Set ONLY when enabled is
  // "unknown"; it is a closed enum, never the probe's response body, status detail or redirect target.
  unknownReason?: WormUnknownReason;
}

/**
 * WORM_UNKNOWN_REASONS is the CLOSED vocabulary behind a "cannot confirm" WORM probe (G279).
 *   r2-binding-unsupported - the native R2 binding has no Object-Lock read API at all: this destination can
 *                            NEVER confirm. It names NO remedy, and it used to name the S3 endpoint: no R2
 *                            bucket enforces S3 Object-Lock by any route, and R2's S3 endpoint answers a
 *                            lock-bearing PUT 501 NotImplemented (measured). Not a fault.
 *   redirect               - the store answered the credentialed probe with a 3xx (a proxy, or the wrong region)
 *   denied                 - the store refused it (401/403): the credential lacks s3:GetBucketObjectLockConfiguration
 *   not-implemented        - the store answered 501: it has no Object-Lock API at all, so no bucket it holds can
 *                            enforce anything. R2's S3 endpoint is the measured member. Google Cloud Storage is
 *                            NOT: its S3-interoperable endpoint answers the probe, and a bucket created with
 *                            per-object retention reads as enabled.
 *   server-error           - the store errored (5xx)
 *   body-unparseable       - a 200 whose body is not an ObjectLockConfiguration (a proxy mangling the XML)
 *   network                - the probe threw before any answer (DNS / TLS / reset / timeout)
 *   other                  - residual: a refusal the classifier could not name (never the store's text). Last,
 *                            so an unrecognised status is never MISLABELLED -- a wrong reason is worse than an
 *                            honest unknown, because it sends a compliance customer to a remedy that cannot work.
 */
export const WORM_UNKNOWN_REASONS = ["r2-binding-unsupported", "redirect", "denied", "not-implemented", "server-error", "body-unparseable", "network", "other"] as const;
/**
 * One member of WORM_UNKNOWN_REASONS: WHY an Object-Lock probe could not confirm what the bucket enforces.
 * It rides on WormStatus only when enabled is "unknown", and the admin and scheduler paths each re-gate an
 * incoming value against WORM_UNKNOWN_REASONS before storing or reporting it, so a reason that is not a
 * member is dropped rather than shown on a row it cannot describe.
 */
export type WormUnknownReason = (typeof WORM_UNKNOWN_REASONS)[number];

/**
 * The destination abstraction the run pipeline and restore drill write to. It exposes
 * get/put/putStream/putConditional/exists/delete/list and an optional WORM capability probe.
 * S3Destination implements it over any S3-compatible bucket (Amazon S3, Google Cloud Storage's
 * S3-interoperable endpoint, R2's S3 endpoint, and the rest), R2Destination over a native in-account
 * R2 binding, AzureBlobDestination over Azure Blob Storage with its own Shared Key or bearer signer,
 * and a memory double backs the offline tests.
 */
export interface Destination {
  get(key: string): Promise<GetResult | null>;
  put(key: string, body: Uint8Array): Promise<void>;
  // putStream writes a streamed body (a large sealed segment) without buffering it whole.
  // size, when known, is the plaintext byte count; the destination rejects a segment over
  // MAX_STREAM_SEGMENT_BYTES, since no multipart path exists to split an oversized put.
  putStream(key: string, body: ReadableStream<Uint8Array>, size?: number): Promise<void>;
  putConditional(key: string, body: Uint8Array, opts: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult>;
  exists(key: string): Promise<boolean>;
  // headStatus returns the RAW HTTP status of a credentialed HEAD so a PROBE can distinguish "object
  // absent" (404) from "not authorised" (403) or "store unavailable" (5xx/429) -- exists() collapses every
  // non-200 to false, which made the destination preflight a FALSE GREEN on a broken/down credentialed
  // store. OPTIONAL: a binding-backed destination (R2) cannot return an auth error and need not implement
  // it; the preflight falls back to exists() when it is absent. Read-only, never a write.
  headStatus?(key: string): Promise<number>;
  // delete removes one object. It is the WRITE side of the retention prune (seal/prune.ts):
  // the prune deletes a superseded run's run/<runId>/ tree objects and then only the segments
  // no RETAINED run still references (manifest-driven GC, SPEC 10.1), so a delete only ever
  // touches an object the planner has already proven unreferenced. A delete of an absent key
  // is a no-op (success), so a re-run of an interrupted prune is idempotent.
  delete(key: string): Promise<void>;
  // list enumerates the object keys under a prefix, paging internally so the caller sees the
  // complete set in one call. The prune uses it to find a superseded run's run/<runId>/ tree
  // objects to delete. Order is not load-bearing (the caller treats the result as a set).
  // CONTRACT (r2.ts / s3-read-ops.ts): this is for SMALL, bounded prefix scans (a run/<runId>/
  // tree, a handful of objects); it materialises EVERY matching key into one in-memory array. A
  // caller iterating a LARGE keyspace (the whole content-addressed seg/ store across a fleet) must
  // use listPage instead, or it risks OOMing the isolate on a mature store.
  list(prefix: string): Promise<string[]>;
  // listPage returns ONE page of keys under a prefix plus the cursor for the next page (undefined
  // on the final page), exposing the store's native pagination so a caller can stream a large
  // keyspace in bounded memory rather than materialising it whole (the list() contract above). The
  // off-site 3-2-1 replication seg/ sync uses it to walk the content-addressed store page by page.
  // Keys are in the store's native lexicographic order, contiguous across pages. OPTIONAL on the
  // interface: an impl that cannot page natively omits it and the caller falls back to list(); the
  // real S3/R2 destinations implement it so production replication never lists a whole store at once.
  listPage?(prefix: string, cursor?: string): Promise<ListPage>;
  // objectLockStatus is the WORM capability probe: it queries the STORE for whether this bucket
  // actually ENFORCES S3 Object-Lock (and the bucket's default retention rule, if any), returning a
  // typed WormStatus. It is what lets the posture report REAL immutability instead of inferring it
  // from a refused delete. It is OPTIONAL on the interface (not every destination can answer): an
  // impl that cannot probe simply omits it, and the caller treats the absence as "unknown" (the safe
  // cannot-confirm reading). It MUST NOT throw for an ordinary not-enabled bucket, a bucket without
  // Object-Lock is a normal answer ({ enabled:false }), not an error; only an unreachable store or an
  // unparseable response degrades to { enabled:"unknown" }.
  objectLockStatus?(): Promise<WormStatus>;

  /**
   * sasExpiry reports when THIS destination's credential dies of its own accord, for the posture surface
   * that warns before the day comes. Optional, because only an Azure SAS has one: every other credential
   * this engine holds is valid until somebody rotates it.
   *
   * Declared here so the reading can be consumed. AzureBlobDestination has implemented it,
   * with tests, since the SAS credential landed, and it was absent from this interface, so no caller could
   * reach it without a cast and none did. Measured across src/ before wiring it: ZERO production callers.
   *
   * THREE RETURNS, NOT TWO, and collapsing any pair invents a fact:
   *   null                        this destination is not SAS-authenticated, so no expiry exists
   *   { expiresAtMs: number }     a SAS whose `se` parameter gives an absolute instant
   *   { expiresAtMs: null }       a SAS carrying no `se`: the expiry is NOT VISIBLE to us, which is
   *                               legal and is NOT the same as a token that never expires
   */
  sasExpiry?(): { expiresAtMs: number | null } | null;
  // multipartAbortFailures reports how many times a FAILED multipart upload's best-effort abort ALSO failed
  // over this destination instance's lifetime, leaving invisible stranded part-storage the bucket's own
  // lifecycle/abort policy must reap (multipart-abort-stranded-parts). It is a DIAGNOSTIC accessor only (an
  // integer, never a key/id/value): the seal driver reads it after finalising a run to stamp
  // `multipartAbortFailed` on the run-history row, so an otherwise-swallowed abort failure becomes visible.
  // OPTIONAL: only the multipart-capable S3 destination implements it; R2 (native binding, no multipart) and
  // the memory double omit it, and the seal driver treats an absent accessor as zero (nothing stranded).
  multipartAbortFailures?(): number;
  // destFaults reports the bounded, closed-vocabulary IDENTITY of every destination op that failed over this
  // destination instance's lifetime (G135): the op, the HTTP status, the closed S3 <Code>, the fault class,
  // the classifier ARM that decided it (so a fault the classifier DEFAULTED to permanent is distinguishable
  // from a real 4xx), whether the store returned a request id, and whether the complaint was the Object-Lock
  // checksum rule. Without it, every op past the single-shot PUT dies as a bare "status 403" and support
  // cannot tell an expired STS session from a bucket-policy denial from a WORM refusal.
  //
  // It is a DIAGNOSTIC accessor only, on the exact model of multipartAbortFailures(): the seal driver reads
  // it after finalising a run and stamps it on the run-history row. Every field is a closed enum, a boolean
  // or a clamped int -- never a key, a bucket, an endpoint, a header value or any error text.
  //
  // OPTIONAL: only the S3 destination implements it; R2 (native binding) and the memory double omit it, and
  // a caller treats an absent accessor as "no faults recorded".
  destFaults?(): DestFaultSnapshot;
  // destIo reports the bounded DEGRADATION counters of this destination instance (G186): the branches a
  // SUCCESSFUL run swallows, and which make it take ten times as long or cost ten times as much -- store
  // backpressure (503/429) driving the adaptive pacer down, multipart steps re-issued after transient faults,
  // requests aborted at the fetch bound against a black-holed endpoint, conditional-PUT conflicts (on the
  // RUNLOG, two engines fighting over one log), the dedup-defeating HEAD that collapses a 403/5xx to "absent"
  // and re-uploads the whole archive, and a Retry-After the engine could not parse. Plus the WORST effective
  // rate the pacer was driven to.
  //
  // It is the counterpart of destFaults(): that one says why an op FAILED, this one says how badly a run that
  // SUCCEEDED was degraded -- which today is visible only as an unattributable durationMs on the run row.
  // Same DIAGNOSTIC-accessor model: the seal driver reads it after finalising a run and stamps it on the run
  // row. Every field is a clamped non-negative integer; the shape has no string field at all.
  //
  // OPTIONAL: the S3 and R2 destinations implement it; the memory doubles omit it, and a caller treats an
  // absent accessor as "no degradation recorded".
  destIo?(): DestIoSnapshot;
}
