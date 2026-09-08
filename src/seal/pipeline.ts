import { b64urlEncode, utf8 } from "../crypto/bytes.ts";
import type { Destination } from "../dest/types.ts";
import { buildArchive, parseRunlog, type RecipientEntry, type RunlogEntry, type Signer, signRunlog, type WriteRecord } from "../format/writer.ts";
import type { Selector, SourceAdapter } from "../sources/types.ts";
import { bytesEqual } from "../util/bytes-equal.ts";
import { addIncompleteId, type IncompleteByMarker, type IncompleteIds, MARKER_ATTRIBUTION_MAX_PER_KIND, safeMarkerAttribution } from "./marker.ts";
import { throttleRetry, withRetry } from "./retry.ts";
import { noteLockPlane, noteRunlogAbsent } from "./run-observations.ts";

// The run pipeline ties sources to the writer to the destination. It collects a run's
// records, builds the archive, writes every object (skipping content-addressed seg/
// objects that already exist), and then accumulates the run's entry onto the account-wide
// signed RUNLOG with an optimistic conditional write (design F10). The streaming,
// resumable, per-segment checkpointed form (F11) is a refinement; this is the v1
// whole-run path used for small-to-moderate downpipes and for tests.

const RUNLOG_KEY = "_RECOVERY/RUNLOG";
const RUNLOG_SIG_KEY = "_RECOVERY/RUNLOG.sig";
const RUNLOG_MAX_ATTEMPTS = 6;
// RUNLOG CAS backoff (runlog-cas-no-backoff-jitter): a precondition failure re-reads and retries with a
// full-jitter exponential backoff (base * 2^attempt, capped) rather than no delay, so contending finalisers
// de-correlate instead of thrashing the conditional write in lockstep. Kept small so the bounded
// retries stay well inside the finalise wall budget; the lock already serialises most writers, this only
// smooths the residual race (a lock-free mirror, or lock contention).
const RUNLOG_CAS_BASE_MS = 25;
const RUNLOG_CAS_MAX_MS = 500;
const UINT32_MAX = 0xffffffff;

// SCALE-3: patient lock-acquire ladder. With PER-DESTINATION lock keying (scheduler-do.ts) the lock is
// held only by the finalisers racing for the SAME destination's one RUNLOG object, and each holder keeps it
// for just one read-modify-write; a patient ladder (a few attempts, full-jitter backoff between them,
// mirroring the handleThrottle park ladder) lets a waiter take its turn rather than barge into the CAS
// (avoiding a thundering herd of concurrent finalisers exhausting the bare CAS and striking to terminal
// failure, which would orphan a committed run-tree). The lock-free fallback is retained (correctness never
// depended on the lock; the CAS + sig-only-if-current are the backstops), but a CAS that STILL exhausts
// throws a typed RunlogContendedError so the sliced DO PARKS the run (checkpoint preserved, idempotent
// resume) instead of striking it dead -- bounded cross-invocation queueing, not a 6-try-and-die.
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
// the trigger-time vs append-time divergence behind RUNLOG-1: a rapid re-trigger / crashed-run reclaim no
// longer signs a root with prevRunId=null while the RUNLOG links the real prior run, which the strict
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
 * noteHistoryChainRestart records the G283 signal: the SCHEDULER says a prior run of this downpipe SUCCEEDED
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
      // G222: the fault is in the SCHEDULER plane (the DO that serves the lock), not the destination. It is
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
  noteLockPlane("windowExhausted"); // G222: the WHOLE patient window elapsed with the lock held
  return null;
}

// releaseCounted releases the RUNLOG lock and COUNTS a release fault (G222) before rethrowing it verbatim. The
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
  // the value read (WS-P2). On the buffered path a vanish seals a _vanished MARKER record (crawl() forwards
  // it), so it is ALSO in recordsIncomplete + incompleteByMarker._vanished; this mirrors the sliced path's
  // dedicated CheckpointCounts.recordsVanished so the buffered completion posts the same distinct count.
  recordsVanished: number;
  recordsIncomplete: number; // sealed INCOMPLETENESS sentinels this run (R1-1); mirrors CheckpointCounts.recordsIncomplete on the sliced path
  // incompleteByMarker is the PER-MARKER breakdown of recordsIncomplete (which kinds, for the support pack);
  // mirrors CheckpointCounts.incompleteByMarker on the sliced path. Only non-zero keys; {} when no markers.
  incompleteByMarker: IncompleteByMarker;
  // incompleteIds is the PER-KIND ATTRIBUTION companion (WS-P1): which surface/object was short, redaction-safe
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
  // R1-1: count incompleteness sentinels (markers a source emits in place of real bytes) as records
  // are collected, mirroring the sliced path (slice.ts sealOne), so the buffered seal surfaces the
  // same "N items not fully captured" signal. Markers are always small buffered values.
  let recordsIncomplete = 0;
  // WS-P2: the distinct mid-crawl-vanish count, derived from the _vanished marker records the KV/R2 adapters
  // now seal in place of a silent skip (mirrors CheckpointCounts.recordsVanished on the sliced path). A vanish
  // is BOTH an incompleteness marker (counted above) and its own churn signal (counted here).
  let recordsVanished = 0;
  // The PER-MARKER breakdown (which kinds), mirroring CheckpointCounts.incompleteByMarker on the sliced
  // path: KEY identity + integer count only, never the marker payload (NO-CUSTODY). Only non-zero keys land.
  const incompleteByMarker: IncompleteByMarker = {};
  // The PER-KIND ATTRIBUTION (WS-P1): which surface/object was short, redaction-safe ids only (see
  // safeMarkerAttribution). Mirrors CheckpointCounts.incompleteIds on the sliced path.
  const incompleteIds: IncompleteIds = {};
  for (const src of sources) {
    for await (const rec of src.crawl(cfg.selector)) {
      plaintextBytes += rec.stream ? rec.stream.size : (rec.value?.length ?? 0);
      // CR-04: the marker KIND, when this record IS a marker, comes from the source adapter's OWN
      // markerKind assertion (set only where it built a substitute value in place of real bytes), never
      // from sniffing rec.value's content shape -- a real streamed value never carries one by construction,
      // and a real buffered value that merely LOOKS marker-shaped carries no markerKind either.
      const markerKind = rec.markerKind;
      if (markerKind !== undefined) {
        recordsIncomplete++;
        incompleteByMarker[markerKind] = (incompleteByMarker[markerKind] ?? 0) + 1;
        // WS-P2: a _vanished marker is also the distinct mid-crawl-deletion signal.
        if (markerKind === "_vanished") recordsVanished++;
        // WS-P1 attribution (all source types): cf-config raw surface id, every custody source by a STABLE
        // one-way HANDLE (safeMarkerAttribution -- raw customer/operator names never leak). Compute the hash
        // only while the per-kind bucket has room; addIncompleteId stays the dedup+cap authority.
        const idBucket = incompleteIds[markerKind];
        if (idBucket === undefined || idBucket.length < MARKER_ATTRIBUTION_MAX_PER_KIND) {
          const attribId = await safeMarkerAttribution(rec.sourceType, rec.name);
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
        // RV-CLI-MARKER: carry the ALREADY-computed marker kind onto the record so buildRecordLine stamps
        // `incompleteMarker` into the shard line WITHOUT re-parsing the value (ONE parse, above). The sliced
        // path stamps it the same way (slice.ts sealOne), keeping the two seal paths byte-identical.
        ...(markerKind !== undefined ? { incompleteMarker: markerKind } : {}),
      });
    }
  }

  // RUNLOG-1: seed the signed root's freshness.prevRunId from the destination-local RUNLOG (the SAME source
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
    // Layer 1e: wrap the buffered path's object writes in the throttle retry (matching the sliced path)
    // so a deployment that opts into the buffered seal (SLICED_RUNS_DISABLED) rides out a 503 wave instead
    // of hard-failing on the first SlowDown.
    await withRetry(() => dest.put(key, objBytes), throttleRetry(cfg.throttleRetry));
    written++;
    archiveBytesWritten += objBytes.length;
  }

  const entry: RunlogEntry = { index: clock.runlogIndex, runId: clock.runId, downpipeId: cfg.downpipeId, time: clock.now, recordCount: records.length, prevRunId: localPrev, status: "active" };
  // Relink the per-destination RUNLOG chain locally; the signed root above already carries the SAME
  // destination-local prev (localPrev), so root and entry agree on this destination (RUNLOG-1). Under
  // failover this run may have sealed to a destination missing the prior global run, and the local relink
  // keeps that destination's chain continuous.
  await appendRunlog(dest, signer, entry, lock, { relinkLocalPrev: true });

  const durationMs = Date.now() - runStart;
  return { runId: clock.runId, records: records.length, bytes: plaintextBytes, objectsWritten: written, objectsSkipped: skipped, runlogIndex: clock.runlogIndex, archiveBytesWritten, durationMs, recordsVanished, recordsIncomplete, incompleteByMarker, incompleteIds };
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
// suspended writer from leaving a permanently stale sig as the terminal state. A narrow
// window remains only if the FINAL writer crashes between its body and sig write; the
// offline reader fails closed there and the next run repairs it. The single-writer RUNLOG
// (serialised through the scheduler DO) is the refinement that closes even that window.
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
  // turn in the single-threaded DO rather than barging the CAS (SCALE-3). If the lock is held for the whole
  // window we still proceed lock-free (correctness never depended on the lock; the conditional write +
  // sig-only-if-current are the backstops) -- but a CAS that then exhausts throws RunlogContendedError so the
  // sliced DO parks-and-resumes instead of striking the run dead.
  const token: string | null = lock ? await patientAcquire(lock) : null;
  try {
    await appendRunlogBody(dest, signer, entry, opts?.relinkLocalPrev ?? false);
  } finally {
    // G222: a lock RELEASE fault is a SCHEDULER-plane fault, and by the time it can happen the archive AND the
    // RUNLOG entry are already committed -- yet it coarsens to the DESTINATION error class, so support is sent
    // to a bucket that is perfectly healthy. The throw is UNCHANGED (the caller's ladder is untouched); the
    // fault is now COUNTED, so the pack can say the lock plane, not the destination, is flaking.
    if (lock && token) await releaseCounted(lock, token);
  }
}

async function appendRunlogBody(dest: Destination, signer: Signer, entry: RunlogEntry, relinkLocalPrev: boolean): Promise<void> {
  for (let attempt = 0; attempt < RUNLOG_MAX_ATTEMPTS; attempt++) {
    // Layer 1b: each INDIVIDUAL RUNLOG destination call rides out a THROTTLE on the hot object (a 503 on
    // _RECOVERY/RUNLOG), orthogonal to the outer CAS loop which rides out a concurrent WINNER (a 412,
    // returned as res.ok=false, NOT thrown -- so it never reaches this throttle retry). Conflating the two
    // would re-sign needlessly and could mask a real auth failure as contention.
    const existing = await withRetry(() => dest.get(RUNLOG_KEY), throttleRetry());
    const entries = existing ? parseRunlog(existing.body) : [];
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
      // prev seeded at seal time (RUNLOG-1), so root and entry agree on the primary.
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
    const res = existing
      ? await withRetry(() => dest.putConditional(RUNLOG_KEY, runlog, { ifMatch: existing.etag }), throttleRetry())
      : await withRetry(() => dest.putConditional(RUNLOG_KEY, runlog, { ifNoneMatch: "*" }), throttleRetry());
    if (res.ok) {
      // Only publish the sig if our body is still current (no concurrent winner since).
      const after = await withRetry(() => dest.get(RUNLOG_KEY), throttleRetry());
      const stillOurs = !!after && (res.etag ? after.etag === res.etag : bytesEqual(after.body, runlog));
      if (stillOurs) await withRetry(() => dest.put(RUNLOG_SIG_KEY, utf8(b64urlEncode(sig))), throttleRetry());
      else noteLockPlane("sigPublishSkipped"); // G222: a concurrent winner moved the body, so OUR signature was not published
      return;
    }
    // Precondition failed: a concurrent run extended the log. Back off with FULL JITTER before re-reading
    // and retrying, so contending finalisers do not thrash the CAS in lockstep (runlog-cas-no-backoff-jitter).
    // No sleep after the final attempt (it falls through to the throw).
    if (attempt < RUNLOG_MAX_ATTEMPTS - 1) {
      const cap = Math.min(RUNLOG_CAS_MAX_MS, RUNLOG_CAS_BASE_MS * 2 ** attempt);
      await new Promise((r) => setTimeout(r, casJitterMs(cap)));
    }
  }
  // The lock-free CAS exhausted under sustained same-destination contention. Throw the TYPED contended
  // error (not a generic one) so the sliced DO routes this to the patient PARK ladder (checkpoint preserved,
  // idempotent resume) instead of the MAX_SLICE_FAILURES strike ladder, which would shed a fraction of a
  // contention storm to terminal failure.
  noteLockPlane("casExhausted"); // G222
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
  // Same per-destination patient acquire as appendRunlog (SCALE-3): a prune racing concurrent seals to the
  // same destination's RUNLOG queues in the DO rather than stampeding the CAS, falling back lock-free if the
  // lock stays held for the whole window (the CAS is the backstop).
  const token: string | null = lock ? await patientAcquire(lock) : null;
  try {
    return await supersedeRunlogBody(dest, signer, target);
  } finally {
    // G222: a lock RELEASE fault is a SCHEDULER-plane fault, and by the time it can happen the archive AND the
    // RUNLOG entry are already committed -- yet it coarsens to the DESTINATION error class, so support is sent
    // to a bucket that is perfectly healthy. The throw is UNCHANGED (the caller's ladder is untouched); the
    // fault is now COUNTED, so the pack can say the lock plane, not the destination, is flaking.
    if (lock && token) await releaseCounted(lock, token);
  }
}

async function supersedeRunlogBody(dest: Destination, signer: Signer, target: Set<string>): Promise<number> {
  for (let attempt = 0; attempt < RUNLOG_MAX_ATTEMPTS; attempt++) {
    // Layer 1b: ride out a 503 on the hot RUNLOG object per individual call; the outer CAS loop still
    // handles a concurrent 412 winner (res.ok=false, not thrown).
    const existing = await withRetry(() => dest.get(RUNLOG_KEY), throttleRetry());
    // No RUNLOG to rewrite is a no-op success: there is nothing to supersede (and creating one here
    // would be wrong; superseding presupposes the runs exist in the log).
    if (!existing) return 0;
    const entries = parseRunlog(existing.body);
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
    const res = await withRetry(() => dest.putConditional(RUNLOG_KEY, runlog, { ifMatch: existing.etag }), throttleRetry());
    if (res.ok) {
      // Publish the re-signed sig only if our body is still current (no concurrent winner since).
      const after = await withRetry(() => dest.get(RUNLOG_KEY), throttleRetry());
      const stillOurs = !!after && (res.etag ? after.etag === res.etag : bytesEqual(after.body, runlog));
      if (stillOurs) await withRetry(() => dest.put(RUNLOG_SIG_KEY, utf8(b64urlEncode(sig))), throttleRetry());
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
  noteLockPlane("casExhausted"); // G222
  throw new RunlogContendedError(`RUNLOG supersede contended ${RUNLOG_MAX_ATTEMPTS} times`);
}
