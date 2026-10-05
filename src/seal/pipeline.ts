import { noteSiteFault } from "../admin/site-faults.ts";
import { b64urlDecode, b64urlEncode, utf8 } from "../crypto/bytes.ts";
import { deriveMK, deriveNameMACKey } from "../crypto/derive.ts";
import { type HybridVerifier, hybridVerify } from "../crypto/sign.ts";
import type { Destination } from "../dest/types.ts";
import { detectChainAnomaly, runlogDigestField } from "../format/freshness.ts";
import { noteRunlogAnomaly } from "../format/integrity-fault-ledger.ts";
import { decodeULID } from "../format/ulid.ts";
import { buildArchive, parseRunlog, type RecipientEntry, type RunlogEntry, type Signer, signRunlog, type WriteRecord } from "../format/writer.ts";
import type { Selector, SourceAdapter } from "../sources/types.ts";
import { bytesEqual } from "../util/bytes-equal.ts";
import { addIncompleteId, type IncompleteByMarker, type IncompleteIds, MARKER_ATTRIBUTION_MAX_PER_KIND, safeMarkerAttribution } from "./marker.ts";
import { throttleRetry, withRetry } from "./retry.ts";
import { noteLockPlane, noteRunlogAbsent } from "./run-observations.ts";

// The run pipeline ties sources to the writer to the destination. It collects a run's
// records, builds the archive, writes every object (skipping content-addressed seg/
// objects that already exist), and then accumulates the run's entry onto the account-wide
// signed RUNLOG with an optimistic conditional write. A streaming, resumable, per-segment
// checkpointed form is a refinement; this is the v1 whole-run path used for
// small-to-moderate downpipes and for tests.

const RUNLOG_KEY = "_RECOVERY/RUNLOG";
const RUNLOG_SIG_KEY = "_RECOVERY/RUNLOG.sig";
// The signature of the body a writer is about to put, written BEFORE that body. The body and its .sig are two
// objects, so a crash between the two writes, or a slower writer whose stale .sig lands after a newer body,
// leaves a body the stored .sig does not cover. The pending copy is the engine's own signature over the body
// it wrote, so resolveRunlogSignature can promote it with no trust in the bucket. Readers never use it.
export const RUNLOG_SIG_PENDING_KEY = "_RECOVERY/RUNLOG.sig.pending";
const RUNLOG_MAX_ATTEMPTS = 6;
// RUNLOG CAS backoff: retrying a precondition failure with no delay lets contending finalisers thrash the
// conditional write in lockstep. A full-jitter exponential backoff (base * 2^attempt, capped) de-correlates
// the retries. Kept small so the bounded
// retries stay well inside the finalise wall budget; the lock already serialises most writers, this only
// smooths the residual race (a lock-free mirror, or lock contention).
const RUNLOG_CAS_BASE_MS = 25;
const RUNLOG_CAS_MAX_MS = 500;
const UINT32_MAX = 0xffffffff;

// Patient lock-acquire ladder. Barging a bare CAS with little or no backoff lets concurrently finalising
// runs fall through to the bare 6-attempt CAS all at once, so under load a share of them exhaust it and
// strike to terminal failure ("runlog write contended"), orphaning a committed run-tree. With
// PER-DESTINATION lock keying (scheduler-do.ts) the lock is held only by the finalisers racing for the
// SAME destination's one RUNLOG object, and each holder keeps it for just one read-modify-write; a patient
// ladder (a few attempts, full-jitter backoff between them, mirroring the handleThrottle park ladder) lets
// a waiter take its turn rather than barge into the CAS. The lock-free fallback is retained (correctness
// never depends on the lock; the CAS + sig-only-if-current are the backstops), but a CAS that still exhausts
// throws a typed RunlogContendedError so the sliced DO parks the run (checkpoint preserved, idempotent
// resume) instead of striking it dead -- bounded cross-invocation queueing, not a die-on-exhaustion.
const RUNLOG_LOCK_ACQUIRE_ATTEMPTS = 4;
const RUNLOG_LOCK_WAIT_BASE_MS = 10;
const RUNLOG_LOCK_WAIT_MAX_MS = 100;

// RunlogContendedError signals that the RUNLOG read-modify-write could not be committed because another
// finaliser is writing the SAME destination's RUNLOG (the lock was held for the whole patient window AND the
// lock-free CAS then exhausted). It is a TRANSIENT, retry-safe condition: the run-tree is already committed
// and the append is idempotent, so the caller should PARK and resume (the sliced DO's handleContention),
// never strike the run to terminal failure. Distinct from a hard fault so runseal-do.ts can route it to the
// patient park ladder rather than the MAX_SLICE_FAILURES strike ladder.
export class RunlogContendedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RunlogContendedError";
  }
}

// casJitterMs returns a full-jitter delay in [0, cap) for CAS backoff. It draws from
// crypto.getRandomValues rather than Math.random(); no security property depends on the value
// (it only de-correlates contending finalisers), but using the crypto source keeps the codebase
// free of Math.random() per the randomness guardrail.
function casJitterMs(cap: number): number {
  const buf = crypto.getRandomValues(new Uint8Array(4));
  const r = new DataView(buf.buffer).getUint32(0) / UINT32_MAX;
  return Math.floor(r * cap);
}

// destinationLocalPrev computes the per-downpipe prevRunId AS THE RUNLOG APPEND WILL RELINK IT: the runId
// of the highest-index entry already in THIS destination's RUNLOG for this downpipe whose index is below
// `index`, or null when this run is (or will be) the downpipe's first entry here. The SIGNED ROOT's
// freshness.prevRunId is seeded from this SAME source the append's relink reads, NOT from the scheduler
// DO's lastRunId (which only advances on a SUCCESSFUL completion and so lags under churn). That eliminates
// the trigger-time vs append-time divergence where a rapid re-trigger / crashed-run reclaim would otherwise
// sign a root with prevRunId=null while the RUNLOG links the real prior run, which the strict
// offline CLI reads as a rollback (rc=5) on an intact archive. Because it reads the SAME _RECOVERY/RUNLOG
// object relinkLocalPrev reads on THIS destination, the signed root and the relinked entry agree in the
// steady forward case and on the PRIMARY under 3-2-1 failover (both resolve to the same destination-local
// link computed here). RESIDUALS (both benign "disagrees with the signed root" notes, NOT chain-rewritten
// anomalies, cleared with --allow-stale -- see freshness.ts checkRunlogFreshness and RECOVER.md):
//   1. Out-of-order reclaim: a lower-index run finalising AFTER a higher-index run already signed its
//      immutable root can have the relink rewrite the higher run's stored prev to a value its frozen root
//      no longer matches; full closure needs finalisation ordering by index.
//   2. Replica restore under genuine failover: a replica's signed root is COPIED immutably from the
//      primary (replicate.ts mirrorRunToReplica), carrying the PRIMARY's local prev, while the replica
//      relinks its own entry to its OWN local chain (replicate.ts ~L559). When the replica skipped a run
//      the primary holds, root.prev (primary-local) and entry.prev (replica-local) legitimately diverge.
//      One signed-root prev cannot match every destination's independently-relinked chain; this is the
//      same fundamental tension as residual 1. Mitigated: replica verifyRunOnReplica is opts.verify
//      (default false) and runs attestKeyless allowStale, so mirroring never trips it; it surfaces only on
//      an operator restore/verify from the diverged replica, where --allow-stale is the documented path.
export async function destinationLocalPrev(dest: Destination, downpipeId: string, index: number): Promise<string | null> {
  const existing = await dest.get(RUNLOG_KEY);
  if (!existing) return null;
  const entries = parseRunlog(existing.body);
  let prev: string | null = null;
  let prevIndex = -1;
  for (const e of entries) {
    if (e.downpipeId !== downpipeId) continue;
    if (e.index >= index) continue;
    if (e.index > prevIndex) {
      prevIndex = e.index;
      prev = e.runId;
    }
  }
  return prev;
}

/**
 * noteHistoryChainRestart records this signal: the SCHEDULER says a prior run of this downpipe SUCCEEDED
 * (prevRunId is that run's id, and the scheduler's lastRunId only advances on a successful completion), and
 * yet THIS destination's RUNLOG has no entry to chain onto. The engine then normalises it silently: the signed
 * root goes out with freshness.prevRunId = null, the history chain RESTARTS, and a retention prune finds
 * nothing to supersede and returns 0. That is exactly what a downpipe repointed at a RE-CREATED or WRONG
 * bucket looks like, and remotely it was indistinguishable from a genuine first run.
 *
 * The PRECISION is the point. An absent RUNLOG on its own is NOT evidence: a brand-new downpipe's first run on
 * a fresh bucket is the identical read, and so is a run whose index merely advanced past failed attempts. Only
 * "a prior run SUCCEEDED, and its entry is not on this destination" is. The behaviour is unchanged (chaining
 * onto nothing is still correct); this only records that it happened, as a count and a boolean.
 *
 * @param localPrev - the prev this destination's own RUNLOG resolved to (null = nothing here to chain onto).
 * @param prevRunId - the scheduler's prev run id (null = this downpipe has no prior SUCCESSFUL run at all).
 * @param index - this run's RUNLOG index, recorded as priorRuns. Never a key, a bucket or a destination.
 */
export function noteHistoryChainRestart(localPrev: string | null, prevRunId: string | null, index: number): void {
  if (localPrev === null && prevRunId !== null) noteRunlogAbsent(index);
}

// patientAcquire takes the per-destination RUNLOG lock with a bounded, full-jitter-backed-off ladder
// (mirroring the handleThrottle park ladder, in miniature): a momentarily-held lock is AWAITED across a few
// short waits rather than abandoned after one barge, so concurrent finalisers to the same destination queue
// in the single-threaded DO instead of stampeding the CAS. Returns the lease token, or null if the lock was
// held for the WHOLE window (the caller then either falls back lock-free, append, or defers, prune). It never
// throws; an acquire round-trip that itself fails is treated as "not acquired" so a flaky lock plane degrades
// to the lock-free path rather than failing the run.
async function patientAcquire(lock: RunlogLock): Promise<string | null> {
  for (let i = 0; i < RUNLOG_LOCK_ACQUIRE_ATTEMPTS; i++) {
    let token: string | null = null;
    try {
      token = await lock.acquire();
    } catch {
      token = null; // a lock-plane error is not fatal: degrade to the lock-free CAS backstop
      // The fault is in the SCHEDULER plane (the DO that serves the lock), not the destination. It is
      // swallowed here by design, and the run then parks "runlog contended" or dies with a DESTINATION error
      // class -- which sends support to investigate a bucket that is perfectly healthy. Count it.
      noteLockPlane("acquireFaults");
    }
    if (token !== null) return token;
    if (i < RUNLOG_LOCK_ACQUIRE_ATTEMPTS - 1) {
      const cap = Math.min(RUNLOG_LOCK_WAIT_MAX_MS, RUNLOG_LOCK_WAIT_BASE_MS * 2 ** i);
      await new Promise((r) => setTimeout(r, casJitterMs(cap)));
    }
  }
  noteLockPlane("windowExhausted"); // the whole patient window elapsed with the lock held
  return null;
}

// releaseCounted releases the RUNLOG lock and counts a release fault before rethrowing it verbatim. The
// count is the evidence; the control flow is byte-unchanged.
async function releaseCounted(lock: RunlogLock, token: string): Promise<void> {
  try {
    await lock.release(token);
  } catch (e) {
    noteLockPlane("releaseFaults");
    throw e;
  }
}

export interface RunConfig {
  downpipeId: string;
  downpipeName: string;
  cadence: string;
  selector: Selector;
  recipients: RecipientEntry[]; // break-glass first
  // throttleRetry overrides the destination THROTTLE/transient retry budget for the buffered seal's
  // object writes (adaptive-dest-backpressure Layer 1e). Absent = the DEST_THROTTLE_RETRY default.
  throttleRetry?: { attempts?: number | undefined; baseMs?: number | undefined } | undefined;
}

export interface RunClock {
  runId: string; // a fresh ULID per run, allocated by the scheduler DO
  runlogIndex: number; // allocated by the scheduler DO (monotonic per account)
  prevRunId: string | null; // the previous run of this downpipe
  now: string; // RFC 3339 UTC millis
  randomNonce: () => Uint8Array;
  randomSalt: () => Uint8Array;
  master: Uint8Array; // 32 fresh random per run, in-memory only
}

export interface RunSummary {
  runId: string;
  records: number;
  bytes: number; // total plaintext bytes sealed this run (buffered value.length + streamed size)
  objectsWritten: number;
  objectsSkipped: number;
  runlogIndex: number;
  archiveBytesWritten: number; // sum of byte lengths of archive objects written (new stored bytes)
  durationMs: number; // wall-clock duration of runBackup, ms
  // recordsVanished is how many in-scope KV/R2 objects vanished (were deleted) mid-crawl between the list and
  // the value read. On the buffered path a vanish seals a _vanished MARKER record (crawl() forwards
  // it), so it is ALSO in recordsIncomplete + incompleteByMarker._vanished; this mirrors the sliced path's
  // dedicated CheckpointCounts.recordsVanished so the buffered completion posts the same distinct count.
  recordsVanished: number;
  recordsIncomplete: number; // sealed INCOMPLETENESS sentinels this run; mirrors CheckpointCounts.recordsIncomplete on the sliced path
  // incompleteByMarker is the PER-MARKER breakdown of recordsIncomplete (which kinds, for the support pack);
  // mirrors CheckpointCounts.incompleteByMarker on the sliced path. Only non-zero keys; {} when no markers.
  incompleteByMarker: IncompleteByMarker;
  // incompleteIds is the PER-KIND ATTRIBUTION companion: which surface/object was short, redaction-safe
  // ids only (cf-config surface ids today; see marker.ts safeMarkerAttribution). Mirrors CheckpointCounts.
  // incompleteIds on the sliced path; only non-empty kinds, {} when nothing was name-attributable.
  incompleteIds: IncompleteIds;
}

// RunlogLock serialises the account-wide RUNLOG read-modify-write across concurrent runs
// (backed by the scheduler DO). It is best-effort: correctness does not depend on it (the
// conditional write and the sig-only-if-current mitigation are the backstops), but holding
// it means the two-object RUNLOG+sig write does not interleave with another run.
export interface RunlogLock {
  acquire(): Promise<string | null>; // a lease token, or null if held by another run
  release(token: string): Promise<void>;
  // floor returns this destination's anti-rollback floor (sched/runlog-floor.ts): the highest RUNLOG index the
  // engine confirmed it appended here, or undefined when none is recorded or it could not be read.
  floor?(): Promise<number | undefined>;
}

// runBackup crawls the sources, seals an archive, writes it, and appends to the RUNLOG.
export async function runBackup(sources: SourceAdapter[], cfg: RunConfig, signer: Signer, dest: Destination, clock: RunClock, lock?: RunlogLock): Promise<RunSummary> {
  const runStart = Date.now();
  // This is the v1 whole-run BUFFERED path: every source record is held in this array until
  // buildArchive returns, so it is for small-to-moderate downpipes and tests only. The sliced path
  // (slice.ts) is the default and seals per slice without buffering. A deployment running with
  // SLICED_RUNS_DISABLED against a source that can produce unexpectedly large records should add a
  // hard cap at the sealRunBuffered/canary callers, since this path can exceed Workers memory.
  const records: WriteRecord[] = [];
  // Sum the plaintext bytes sealed this run as records are collected, so the run-history
  // ring can show a size without re-reading anything: a streamed record's size is known up
  // front (stream.size); a buffered record's is its value length.
  let plaintextBytes = 0;
  // Count incompleteness sentinels (markers a source emits in place of real bytes) as records
  // are collected, mirroring the sliced path (slice.ts sealOne), so the buffered seal surfaces the
  // same "N items not fully captured" signal. Markers are always small buffered values.
  let recordsIncomplete = 0;
  // The distinct mid-crawl-vanish count, derived from the _vanished marker records the KV/R2 adapters
  // seal in place of a silent skip (mirrors CheckpointCounts.recordsVanished on the sliced path). A vanish
  // is BOTH an incompleteness marker (counted above) and its own churn signal (counted here).
  let recordsVanished = 0;
  // The PER-MARKER breakdown (which kinds), mirroring CheckpointCounts.incompleteByMarker on the sliced
  // path: KEY identity + integer count only, never the marker payload (NO-CUSTODY). Only non-zero keys land.
  const incompleteByMarker: IncompleteByMarker = {};
  // The PER-KIND ATTRIBUTION: which surface/object was short, redaction-safe ids only (see
  // safeMarkerAttribution). Mirrors CheckpointCounts.incompleteIds on the sliced path.
  const incompleteIds: IncompleteIds = {};
  // The run's keyed-name MAC key (SPEC 6.4), the key buildArchive derives for the manifest's keyNameHash, so a
  // marker's handle matches its record's manifest line. Derived on the first marker only.
  let nameKey: Uint8Array | undefined;
  const runNameKey = async (): Promise<Uint8Array> => {
    if (nameKey === undefined) {
      const runIdBytes = decodeULID(clock.runId);
      nameKey = await deriveNameMACKey(await deriveMK(clock.master, runIdBytes), runIdBytes);
    }
    return nameKey;
  };
  for (const src of sources) {
    for await (const rec of src.crawl(cfg.selector)) {
      plaintextBytes += rec.stream ? rec.stream.size : (rec.value?.length ?? 0);
      // The marker KIND, when this record IS a marker, comes from the source adapter's OWN
      // markerKind assertion (set only where it built a substitute value in place of real bytes), never
      // from sniffing rec.value's content shape -- a real streamed value never carries one by construction,
      // and a real buffered value that merely LOOKS marker-shaped carries no markerKind either.
      const markerKind = rec.markerKind;
      if (markerKind !== undefined) {
        recordsIncomplete++;
        incompleteByMarker[markerKind] = (incompleteByMarker[markerKind] ?? 0) + 1;
        // A _vanished marker is also the distinct mid-crawl-deletion signal.
        if (markerKind === "_vanished") recordsVanished++;
        // Attribution (all source types): cf-config raw surface id, every custody source by a keyed
        // HANDLE (safeMarkerAttribution -- raw customer/operator names never leak). Compute the MAC only
        // while the per-kind bucket has room; addIncompleteId stays the dedup+cap authority.
        const idBucket = incompleteIds[markerKind];
        if (idBucket === undefined || idBucket.length < MARKER_ATTRIBUTION_MAX_PER_KIND) {
          const attribId = await safeMarkerAttribution(await runNameKey(), rec.sourceType, rec.name);
          if (attribId !== undefined) addIncompleteId(incompleteIds, markerKind, attribId);
        }
      }
      records.push({
        sourceType: rec.sourceType,
        name: rec.name,
        ...(rec.stream ? { stream: rec.stream } : { value: rec.value ?? new Uint8Array(0) }),
        ...(rec.namespace ? { namespace: rec.namespace } : {}),
        ...(rec.bucket ? { bucket: rec.bucket } : {}),
        // Identity self-annotations, mirroring the sliced path (slice.ts metaFor): the D1 database UUID rides
        // on the record; the account is the source adapter's own accountId (the API sources), so the archive
        // names which account it is a backup of. Both omitempty.
        ...(rec.database ? { database: rec.database } : {}),
        ...(src.accountId ? { account: src.accountId } : {}),
        // Carry the restore descriptor (KV TTL/metadata, R2 http/custom metadata, secrets wiring, D1
        // format) through the buffered path too. Without this the SLICED_RUNS_DISABLED fallback silently
        // dropped all descriptors, so a small run restored value-only (lost KV TTL/metadata, R2 metadata).
        // The sliced path already carries it (slice.ts sealOne); this keeps the two paths identical.
        ...(rec.descriptor ? { descriptor: rec.descriptor } : {}),
        // Carry the ALREADY-computed marker kind onto the record so buildRecordLine stamps
        // `incompleteMarker` into the shard line WITHOUT re-parsing the value (ONE parse, above). The sliced
        // path stamps it the same way (slice.ts sealOne), keeping the two seal paths byte-identical.
        ...(markerKind !== undefined ? { incompleteMarker: markerKind } : {}),
      });
    }
  }

  // Seed the signed root's freshness.prevRunId from the destination-local RUNLOG (the SAME source
  // the append's relink uses), not from the scheduler DO's clock.prevRunId (lastRunId at trigger time, which
  // lags under churn). This keeps the signed root and the relinked RUNLOG entry in agreement so the strict
  // offline CLI never reads an intact post-churn archive as a rollback.
  const localPrev = await destinationLocalPrev(dest, cfg.downpipeId, clock.runlogIndex);
  // Streaming records seal straight to the dest inside buildArchive; buffered segments and
  // the manifest come back in the map for us to write.
  const archive = await buildArchive(
    {
      downpipeId: cfg.downpipeId,
      downpipeName: cfg.downpipeName,
      cadence: cfg.cadence,
      runId: clock.runId,
      master: clock.master,
      recipients: cfg.recipients,
      signer,
      records,
      windowStart: clock.now,
      windowEnd: clock.now,
      createdAt: clock.now,
      runlogIndex: clock.runlogIndex,
      prevRunId: localPrev,
      skipRunlog: true, // the RUNLOG is accumulated and written conditionally below
      randomNonce: clock.randomNonce,
      randomSalt: clock.randomSalt,
    },
    { dest },
  );

  let written = 0;
  let skipped = 0;
  let archiveBytesWritten = 0;
  for (const [key, objBytes] of archive) {
    if (key.startsWith("seg/") && (await dest.exists(key))) {
      skipped++; // content-addressed, immutable, already present
      continue;
    }
    // Layer 1e: the buffered path previously wrote with a RAW dest.put (no retry at all) -- strictly worse
    // than the sliced path. Wrap it in the throttle retry so a deployment that opts into the buffered seal
    // (SLICED_RUNS_DISABLED) rides out a 503 wave instead of hard-failing on the first SlowDown.
    await withRetry(() => dest.put(key, objBytes), throttleRetry(cfg.throttleRetry));
    written++;
    archiveBytesWritten += objBytes.length;
  }

  const entry: RunlogEntry = { index: clock.runlogIndex, runId: clock.runId, downpipeId: cfg.downpipeId, time: clock.now, recordCount: records.length, prevRunId: localPrev, status: "active" };
  // Relink the per-destination RUNLOG chain locally; the signed root above already carries the SAME
  // destination-local prev (localPrev), so root and entry agree on this destination. Under
  // failover this run may have sealed to a destination missing the prior global run, and the local relink
  // keeps that destination's chain continuous.
  await appendRunlog(dest, signer, entry, lock, { relinkLocalPrev: true });

  const durationMs = Date.now() - runStart;
  return { runId: clock.runId, records: records.length, bytes: plaintextBytes, objectsWritten: written, objectsSkipped: skipped, runlogIndex: clock.runlogIndex, archiveBytesWritten, durationMs, recordsVanished, recordsIncomplete, incompleteByMarker, incompleteIds };
}

// RunlogSigState is what resolveRunlogSignature found for a stored RUNLOG body:
//   - "verified": the stored .sig verifies the body;
//   - "promoted": it did not, but the pending signature does, and it is now published as the .sig;
//   - "sig-absent": no .sig and no pending signature that verifies;
//   - "sig-invalid": a .sig that does not verify, and no pending signature that does.
export type RunlogSigState = "verified" | "promoted" | "sig-absent" | "sig-invalid";

function verifierOf(signer: Signer): HybridVerifier {
  return { ed: signer.edPublic, mldsa: signer.mldsaPublic };
}

export async function sigVerifies(obj: { body: Uint8Array } | null, body: Uint8Array, verifier: HybridVerifier): Promise<boolean> {
  if (!obj) return false;
  try {
    return await hybridVerify(verifier, body, b64urlDecode(new TextDecoder().decode(obj.body).trim()));
  } catch {
    // site-fault-waiver: src/seal/pipeline.ts:sigVerifies:catch:1 -- the .sig bytes come from the bucket, and one that does not decode is reported as not verifying by every caller
    return false; // a .sig that does not decode is a signature that does not verify
  }
}

// resolveRunlogSignature checks the stored RUNLOG.sig over `body` under the engine's own verifier. When it
// does not verify, it resumes the interrupted write: if the pending signature verifies these exact bytes, the
// engine signed them, so it publishes that signature as RUNLOG.sig. It never signs anything itself. A body
// neither signature covers is reported, not repaired.
export async function resolveRunlogSignature(dest: Destination, body: Uint8Array, verifier: HybridVerifier): Promise<RunlogSigState> {
  const sigObj = await withRetry(() => dest.get(RUNLOG_SIG_KEY), throttleRetry());
  if (await sigVerifies(sigObj, body, verifier)) return "verified";
  const pending = await withRetry(() => dest.get(RUNLOG_SIG_PENDING_KEY), throttleRetry());
  if (pending && (await sigVerifies(pending, body, verifier))) {
    await withRetry(() => dest.put(RUNLOG_SIG_KEY, pending.body), throttleRetry());
    return "promoted";
  }
  return sigObj ? "sig-invalid" : "sig-absent";
}

// RunlogIntegrityError: the stored RUNLOG did not pass verifyRunlogForWrite, so the engine refuses to modify or
// re-sign it. It is not contention (RunlogContendedError) and not transient: no retry clears it. The run, the
// prune or the replication pass that met it fails loudly, and an Owner decides the RUNLOG through the attended
// route (GET /admin/runlog/signature, POST /admin/runlog/resign). The message carries no customer id.
export type RunlogIntegrityReason = "sig-absent" | "sig-invalid" | "unparsable" | "chain-anomaly" | "below-floor" | "absent-above-floor";
export class RunlogIntegrityError extends Error {
  readonly reason: RunlogIntegrityReason;
  constructor(reason: RunlogIntegrityReason, detail: string) {
    super(`RUNLOG integrity: ${detail}; the engine will not modify or re-sign it (an Owner can review it at GET /admin/runlog/signature)`);
    this.name = "RunlogIntegrityError";
    this.reason = reason;
  }
}

// readFloor asks the lock for the destination's floor. A floor that cannot be read is no floor: the check is
// skipped, as it was before the floor existed, and never blocks a run on a scheduler-plane fault. The pack
// names the failed read (siteFaults).
export async function readFloor(lock?: RunlogLock): Promise<number | undefined> {
  try {
    const f = lock?.floor ? await lock.floor() : undefined;
    return typeof f === "number" && Number.isInteger(f) && f > 0 ? f : undefined;
  } catch (e) {
    noteSiteFault("runlog.floor-read", e);
    return undefined;
  }
}

/**
 * verifyRunlogForWrite is the check every RUNLOG writer runs on what it read BEFORE it changes or re-signs
 * anything, so a RUNLOG changed in the bucket is refused rather than laundered under the engine's key:
 *   - absent: allowed only when the destination's floor is 0 or unknown (a fresh destination);
 *   - the signature under the engine's own key, resuming an interrupted write from the pending signature;
 *   - the parse;
 *   - the chain the write is about to rewrite (format/freshness.ts detectChainAnomaly over chainOf's entries):
 *     the append's relink rewrites one downpipe's prevRunId chain, and it must never rewrite a chain that is
 *     already anomalous, because the rewrite would make the anomaly disappear. Other downpipes' chains are not
 *     rewritten by the write, so they are left to the reader. Writers that rewrite no chain pass no chainOf;
 *   - the highest index against the destination's floor (a replayed older signed RUNLOG).
 * Each refusal records an anomaly row with the existing vocabulary and throws RunlogIntegrityError.
 *
 * @returns the parsed entries of a RUNLOG that passed ([] for an allowed absent one).
 */
export async function verifyRunlogForWrite(dest: Destination, existing: { body: Uint8Array } | null, verifier: HybridVerifier, floor?: number, chainOf?: string): Promise<RunlogEntry[]> {
  if (!existing) {
    if (floor !== undefined && floor > 0) {
      noteRunlogAnomaly({ kind: "runlog-absent", indexB: floor });
      throw new RunlogIntegrityError("absent-above-floor", `the RUNLOG is absent while index ${floor} was confirmed at this destination, so a fresh RUNLOG would hide that history`);
    }
    return [];
  }
  const digest = await runlogDigestField(existing.body);
  const state = await resolveRunlogSignature(dest, existing.body, verifier);
  if (state === "sig-absent" || state === "sig-invalid") {
    noteRunlogAnomaly({ kind: "sig-invalid", ...digest });
    throw new RunlogIntegrityError(state, state === "sig-absent" ? "the RUNLOG has no signature" : "the RUNLOG signature does not verify under the engine's signer");
  }
  let entries: RunlogEntry[];
  try {
    entries = parseRunlog(existing.body);
  } catch {
    noteRunlogAnomaly({ kind: "parse-field", ...digest });
    throw new RunlogIntegrityError("unparsable", "the RUNLOG does not parse");
  }
  const anomaly = chainOf !== undefined ? detectChainAnomaly(entries.filter((e) => e.downpipeId === chainOf)) : null;
  if (anomaly) {
    noteRunlogAnomaly({ kind: anomaly.kind, entryCount: entries.length, ...digest, ...(anomaly.indexA !== undefined ? { indexA: anomaly.indexA } : {}), ...(anomaly.indexB !== undefined ? { indexB: anomaly.indexB } : {}) });
    const next =
      anomaly.kind === "duplicate-index"
        ? "two entries hold one index, which nothing in the product can repair without rewriting signed history; attach this downpipe to a fresh destination to keep backing up"
        : "an Owner can review it and relink this downpipe's chain once (see GET /admin/runlog/chain)";
    throw new RunlogIntegrityError("chain-anomaly", `the RUNLOG chain has an anomaly (${anomaly.kind}): ${next}`);
  }
  const max = entries.reduce((m, e) => Math.max(m, e.index), 0);
  if (floor !== undefined && max < floor) {
    noteRunlogAnomaly({ kind: "index-regression", indexA: max, indexB: floor, entryCount: entries.length, ...digest });
    throw new RunlogIntegrityError("below-floor", `the RUNLOG's highest index ${max} is below the ${floor} confirmed at this destination (a rollback)`);
  }
  return entries;
}

// appendRunlog reads the existing append-only RUNLOG, appends this run's entry, re-signs
// the whole log, and writes it back with an optimistic precondition (If-None-Match: * to
// create, If-Match: <etag> to extend). A concurrent run that wins the race returns a
// precondition failure, so we re-read and retry rather than dropping an entry. The append
// is idempotent on retry (a duplicate runId/index is not re-added).
//
// The RUNLOG and its detached .sig are two objects (the format keeps them separate), so
// after a successful conditional body write we write the matching .sig ONLY if our body
// is still the current one. If a concurrent run has already superseded it, that run owns
// the matching sig and we must not overwrite it with a stale one. This prevents a
// suspended writer from leaving a permanently stale sig as the terminal state. Each write
// also puts its signature at RUNLOG_SIG_PENDING_KEY BEFORE the body. If the final writer
// crashes between its body and sig write, or a slower writer's stale sig lands last, the
// offline reader fails closed until the next write, and resolveRunlogSignature then
// publishes the pending signature only if it verifies the stored body under the engine key.
// relinkLocalPrev (opts) recomputes the entry's prevRunId as the DESTINATION-LOCAL chain link at the
// moment of the winning write: the runId of the highest-index entry already in THIS destination for
// this downpipe, or null when it is the downpipe's first entry here. It is what keeps every
// destination's RUNLOG a locally-continuous chain under 3-2-1 FAILOVER, where a run may seal to (or be
// mirrored to) a destination that skipped the immediately-prior account-global run: the SIGNED root
// manifest carries the SAME destination-local prev (seeded from destinationLocalPrev at seal time on the
// primary), and this per-destination entry link is what the reader's detectChainAnomaly verifies, so
// failover never forges a dangling or forked chain. (On a copied-then-relinked replica the two can still
// differ -- see destinationLocalPrev residual 2.) Computing
// it HERE, inside the read the conditional write is based on, recomputed each retry, makes it atomic
// with the write (no precompute race two interleaving writers could turn into a fork).
export async function appendRunlog(dest: Destination, signer: Signer, entry: RunlogEntry, lock?: RunlogLock, opts?: { relinkLocalPrev?: boolean }): Promise<void> {
  // Serialise through the PER-DESTINATION RUNLOG write lock with the patient ladder: a waiter takes its
  // turn in the single-threaded DO rather than barging the CAS. If the lock is held for the whole
  // window we still proceed lock-free (correctness never depended on the lock; the conditional write +
  // sig-only-if-current are the backstops) -- but a CAS that then exhausts throws RunlogContendedError so the
  // sliced DO parks-and-resumes instead of striking the run dead.
  const floor = await readFloor(lock);
  const token: string | null = lock ? await patientAcquire(lock) : null;
  try {
    await appendRunlogBody(dest, signer, entry, opts?.relinkLocalPrev ?? false, floor);
  } finally {
    // A lock RELEASE fault is a SCHEDULER-plane fault, and by the time it can happen the archive AND the
    // RUNLOG entry are already committed -- yet it coarsens to the DESTINATION error class, so support is sent
    // to a bucket that is perfectly healthy. The throw is UNCHANGED (the caller's ladder is untouched); the
    // fault is COUNTED, so the pack can say the lock plane, not the destination, is flaking.
    if (lock && token) await releaseCounted(lock, token);
  }
}

// casBackoff sleeps a full-jitter, capped exponential interval before the next CAS attempt, and not at all after
// the last one.
async function casBackoff(attempt: number): Promise<void> {
  if (attempt >= RUNLOG_MAX_ATTEMPTS - 1) return;
  const cap = Math.min(RUNLOG_CAS_MAX_MS, RUNLOG_CAS_BASE_MS * 2 ** attempt);
  await new Promise((r) => setTimeout(r, casJitterMs(cap)));
}

async function appendRunlogBody(dest: Destination, signer: Signer, entry: RunlogEntry, relinkLocalPrev: boolean, floor?: number): Promise<void> {
  // lostCas: this writer's last conditional write lost to a concurrent winner. The winner writes its body,
  // then its .sig, and every writer puts its signature at the one pending key first, so for a moment after a
  // lost CAS the stored body can carry no .sig and a pending signature that is ours, not the winner's. That
  // is contention, not tampering: the writer backs off and re-reads, and records no anomaly. If the winner's
  // signature has still not landed when the attempts run out, the write ends as contention
  // (RunlogContendedError), so a sliced run parks and resumes. The resumed append reads afresh, and a signature
  // that is still bad then goes through verifyRunlogForWrite, which records the anomaly and refuses, exactly as
  // any first read that finds one does. A slow winner therefore costs a park, never a refusal.
  let lostCas = false;
  for (let attempt = 0; attempt < RUNLOG_MAX_ATTEMPTS; attempt++) {
    // Layer 1b: each INDIVIDUAL RUNLOG destination call rides out a THROTTLE on the hot object (a 503 on
    // _RECOVERY/RUNLOG), orthogonal to the outer CAS loop which rides out a concurrent WINNER (a 412,
    // returned as res.ok=false, NOT thrown -- so it never reaches this throttle retry). Conflating the two
    // would re-sign needlessly and could mask a real auth failure as contention.
    const existing = await withRetry(() => dest.get(RUNLOG_KEY), throttleRetry());
    if (lostCas && existing) {
      const state = await resolveRunlogSignature(dest, existing.body, verifierOf(signer));
      if (state === "sig-absent" || state === "sig-invalid") {
        await casBackoff(attempt);
        continue;
      }
    }
    // Verify BEFORE modifying: a RUNLOG this engine cannot vouch for is refused, never re-signed.
    const entries = await verifyRunlogForWrite(dest, existing, verifierOf(signer), floor, relinkLocalPrev ? entry.downpipeId : undefined);
    // A COPY so the relink below never mutates the caller's entry (the mirror reuses one entry across
    // several replica targets); push it only when this (runId,index) is not already present (idempotent).
    const toAppend = { ...entry };
    if (!entries.some((e) => e.runId === toAppend.runId && e.index === toAppend.index)) entries.push(toAppend);
    if (relinkLocalPrev) {
      // Relink THIS downpipe's ENTIRE chain into strict ascending-index order, recomputed each retry from
      // THIS read. Linking only the new entry to the current max-index tail is NOT enough: a lock-free
      // mirror racing the lock-holding seal on the SAME destination can append out of index order, and the
      // reader's per-downpipe prevRunId-linearity rule (freshness.ts detectChainAnomaly) would then read a
      // legitimately-interleaved chain as a "chain rewritten" rollback. Re-linking the whole chain by index
      // makes the STORED prevRunId chain linear regardless of arrival order, whichever writer lands LAST
      // (re-read under the CAS) leaves a clean chain, so failover never forges a false rollback. Other
      // downpipes' entries are untouched; the SIGNED root manifest carries the matching destination-local
      // prev seeded at seal time, so root and entry agree on the primary.
      const chain = entries.filter((e) => e.downpipeId === toAppend.downpipeId).sort((a, b) => a.index - b.index);
      let prev: string | null = null;
      for (const e of chain) {
        e.prevRunId = prev;
        prev = e.runId;
      }
    }
    // Canonical order: ascending index on every rewrite. Entries land at FINALISE time,
    // so concurrent runs interleave their appends; sorting keeps the stored document
    // deterministic and humanly scannable. Readers must not rely on it either way
    // (SPEC 10, amended: line order is not load-bearing; the signature is).
    entries.sort((a, b) => a.index - b.index);
    const { runlog, sig } = await signRunlog(entries, signer.edPrivate, signer.mldsaSecret);
    const sigText = utf8(b64urlEncode(sig));
    // The pending signature goes first, so a crash after the body write leaves a signature that resumes it.
    await withRetry(() => dest.put(RUNLOG_SIG_PENDING_KEY, sigText), throttleRetry());
    const res = existing
      ? await withRetry(() => dest.putConditional(RUNLOG_KEY, runlog, { ifMatch: existing.etag }), throttleRetry())
      : await withRetry(() => dest.putConditional(RUNLOG_KEY, runlog, { ifNoneMatch: "*" }), throttleRetry());
    if (res.ok) {
      // Only publish the sig if our body is still current (no concurrent winner since).
      const after = await withRetry(() => dest.get(RUNLOG_KEY), throttleRetry());
      const stillOurs = !!after && (res.etag ? after.etag === res.etag : bytesEqual(after.body, runlog));
      if (stillOurs) await withRetry(() => dest.put(RUNLOG_SIG_KEY, sigText), throttleRetry());
      else noteLockPlane("sigPublishSkipped"); // a concurrent winner moved the body, so OUR signature was not published
      return;
    }
    // Precondition failed: a concurrent run extended the log. Back off with FULL JITTER before re-reading
    // and retrying, so contending finalisers do not thrash the CAS in lockstep (runlog-cas-no-backoff-jitter).
    // No sleep after the final attempt (it falls through to the throw).
    lostCas = true;
    await casBackoff(attempt);
  }
  // The lock-free CAS exhausted under sustained same-destination contention. Throw the TYPED contended
  // error (not a generic one) so the sliced DO routes this to the patient PARK ladder (checkpoint preserved,
  // idempotent resume) instead of the MAX_SLICE_FAILURES strike ladder that used to shed ~1/3 of a storm.
  noteLockPlane("casExhausted");
  throw new RunlogContendedError(`RUNLOG write contended ${RUNLOG_MAX_ATTEMPTS} times for run ${entry.runId}`);
}

// supersedeRunlog is the WRITER side of the pruned/superseded RUNLOG (SPEC 10.1): under the same
// best-effort RUNLOG lock as appendRunlog, it reads the append-only RUNLOG, marks the given runIds
// status="superseded" IN PLACE (it NEVER removes an entry: removing one is a rollback the reader
// rejects), re-signs the WHOLE log with the existing signRunlog, and writes it back with the same
// optimistic precondition + sig-only-if-current mitigation appendRunlog uses. It returns the count
// of entries it transitioned active -> superseded (0 when there was nothing to do, which makes a
// re-run a no-op). The retention prune calls this FIRST, then deletes the run-tree + orphan
// segments, so an interrupted prune leaves a committed superseded RUNLOG plus some not-yet-deleted
// orphans (which a reader reports as orphan candidates, safe), never a referenced segment deleted
// ahead of its RUNLOG entry.
export async function supersedeRunlog(dest: Destination, signer: Signer, runIds: readonly string[], lock?: RunlogLock): Promise<number> {
  const target = new Set(runIds);
  if (target.size === 0) return 0;
  // Same per-destination patient acquire as appendRunlog: a prune racing concurrent seals to the
  // same destination's RUNLOG queues in the DO rather than stampeding the CAS, falling back lock-free if the
  // lock stays held for the whole window (the CAS is the backstop).
  const floor = await readFloor(lock);
  const token: string | null = lock ? await patientAcquire(lock) : null;
  try {
    return await supersedeRunlogBody(dest, signer, target, floor);
  } finally {
    // A lock RELEASE fault is a SCHEDULER-plane fault, and by the time it can happen the archive AND the
    // RUNLOG entry are already committed -- yet it coarsens to the DESTINATION error class, so support is sent
    // to a bucket that is perfectly healthy. The throw is UNCHANGED (the caller's ladder is untouched); the
    // fault is COUNTED, so the pack can say the lock plane, not the destination, is flaking.
    if (lock && token) await releaseCounted(lock, token);
  }
}

async function supersedeRunlogBody(dest: Destination, signer: Signer, target: Set<string>, floor?: number): Promise<number> {
  for (let attempt = 0; attempt < RUNLOG_MAX_ATTEMPTS; attempt++) {
    // Layer 1b: ride out a 503 on the hot RUNLOG object per individual call; the outer CAS loop still
    // handles a concurrent 412 winner (res.ok=false, not thrown).
    const existing = await withRetry(() => dest.get(RUNLOG_KEY), throttleRetry());
    // No RUNLOG to rewrite is a no-op success: there is nothing to supersede (and creating one here
    // would be wrong; superseding presupposes the runs exist in the log).
    // An absent RUNLOG where the floor says history was confirmed is refused (verifyRunlogForWrite throws).
    // Otherwise there is nothing to supersede.
    if (!existing) {
      await verifyRunlogForWrite(dest, null, verifierOf(signer), floor);
      return 0;
    }
    // Verify BEFORE deciding anything: a "nothing to change" answer read off an unverified RUNLOG would let
    // the prune go on to delete the runs a changed RUNLOG marks superseded.
    const entries = await verifyRunlogForWrite(dest, existing, verifierOf(signer), floor);
    let changed = 0;
    for (const e of entries) {
      // Only an ACTIVE entry transitions; an already-superseded one stays as it is (idempotent).
      if (target.has(e.runId) && e.status === "active") {
        e.status = "superseded";
        changed++;
      }
    }
    // Nothing to change (already superseded, or none of the targets present): no write, no-op.
    if (changed === 0) return 0;
    // Keep the canonical ascending-index order on rewrite, exactly like appendRunlog.
    entries.sort((a, b) => a.index - b.index);
    const { runlog, sig } = await signRunlog(entries, signer.edPrivate, signer.mldsaSecret);
    const sigText = utf8(b64urlEncode(sig));
    await withRetry(() => dest.put(RUNLOG_SIG_PENDING_KEY, sigText), throttleRetry());
    const res = await withRetry(() => dest.putConditional(RUNLOG_KEY, runlog, { ifMatch: existing.etag }), throttleRetry());
    if (res.ok) {
      // Publish the re-signed sig only if our body is still current (no concurrent winner since).
      const after = await withRetry(() => dest.get(RUNLOG_KEY), throttleRetry());
      const stillOurs = !!after && (res.etag ? after.etag === res.etag : bytesEqual(after.body, runlog));
      if (stillOurs) await withRetry(() => dest.put(RUNLOG_SIG_KEY, sigText), throttleRetry());
      return changed;
    }
    // Precondition failed: a concurrent run extended/rewrote the log. Back off with FULL JITTER before
    // re-reading and retrying, so a prune racing concurrent appends does not thrash the CAS in lockstep
    // (the same de-correlation appendRunlogBody applies; runlog-cas-no-backoff-jitter). No sleep after the
    // final attempt (it falls through to the throw).
    if (attempt < RUNLOG_MAX_ATTEMPTS - 1) {
      const cap = Math.min(RUNLOG_CAS_MAX_MS, RUNLOG_CAS_BASE_MS * 2 ** attempt);
      await new Promise((r) => setTimeout(r, casJitterMs(cap)));
    }
  }
  // The prune's RUNLOG re-sign exhausted the CAS under sustained same-destination contention. The retention
  // pass is fail-open per downpipe (it logs and retries next tick), so the typed contended error simply
  // routes there; the superseded marks are idempotent, so the deferred prune finishes on a later tick.
  noteLockPlane("casExhausted");
  throw new RunlogContendedError(`RUNLOG supersede contended ${RUNLOG_MAX_ATTEMPTS} times`);
}
