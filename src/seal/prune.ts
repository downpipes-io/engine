import type { HybridRecipientPrivate } from "../crypto/kem.ts";
import type { HybridVerifier } from "../crypto/sign.ts";
import type { Destination } from "../dest/types.ts";
import type { ObjectStore } from "../format/reader.ts";
import { openRun } from "../format/reader.ts";
import type { RunlogEntry, Signer } from "../format/writer.ts";
import type { RunlogLock } from "./pipeline.ts";
import { supersedeRunlog } from "./pipeline.ts";
import { postSealFault, type SealFaultPost } from "./seal-fault-post.ts";
import { isWormRefusal, type PruneDeferClass, type SealFault } from "./seal-faults.ts";

// The retention PRUNE PLANNER (ASVS V14.2.7: classification-driven retention with automatic
// deletion). It closes the WRITER side of the pruned/superseded RUNLOG semantics the data format
// already defines (SPEC 10.1) and both readers already honour: a RUNLOG entry marked
// status="superseded" is RETAINED and is NOT a rollback, while a MISSING entry IS. This module
// only PLANS; it deletes nothing. The apply path (applyPrune, under the RUNLOG lock) is the one
// place that writes, and only when the per-downpipe enforce gate is set.
//
// SEGMENT GC SAFETY: deletion is MANIFEST-DRIVEN, never age-driven. A segment is deleted ONLY if it
// appears in a superseded run AND in no retained run, computed as a set difference over EXACT object
// keys (no heuristic, no ttl). The per-step invariant notes stay inside planPrune below.

// PrunePlan is what the planner computes for one downpipe: which runs are superseded, which run-tree
// objects to delete, which segments are now orphaned, and which runs are retained. It carries NO
// secret and NO plaintext: a run id, an object key and a byte count are the same redaction-safe
// surface the audit log and the run history already expose. reclaimableBytes is the summed byte size
// of the deletable objects when sizes are available (best-effort; absent sizes contribute 0).
export interface PrunePlan {
  readonly downpipeId: string;
  readonly retainedRunIds: readonly string[]; // the runs the policy keeps (most-recent keepRuns and/or within keepDays)
  readonly supersededRunIds: readonly string[]; // the active runs outside the window, to mark status="superseded"
  readonly runTreeObjects: readonly string[]; // the run/<runId>/ tree object keys to delete (across the superseded runs)
  readonly orphanSegs: readonly string[]; // seg/<aa>/<id>.seg keys referenced ONLY by superseded runs (the GC set)
  readonly reclaimableBytes: number; // summed size of the deletable objects, when sizes are known; else 0
  // deferred, when set, means the pass ABSTAINED: a retained run could not be enumerated, so the
  // protected reference set was incomplete and no deletion/supersede was safe. The plan's delete sets
  // are empty; a later pass retries. Present only on an abstaining plan.
  readonly deferred?: string;
  // deferredClass is the CLOSED, pack-bound coarsening of `deferred` (gap G190: "my retention never deletes
  // anything"). `deferred` is a sentence for the engine log; this is the enum the support pack + the bot reason
  // over, so a perpetual abstain is diagnosable without the customer's logs. Set exactly when `deferred` is.
  readonly deferredClass?: PruneDeferClass;
  // blockingRunId, on an abstaining plan, is the FIRST retained run that would not enumerate (the run that is
  // deferring every pass). It is the customer's own opaque run id, the same redaction class the reconcile
  // inventory + the run history already carry. Absent when nothing blocked.
  readonly blockingRunId?: string;
  // retainedUnreadableCount: how many RETAINED runs failed to enumerate this pass (>0 => the pass abstained).
  readonly retainedUnreadableCount: number;
  // supersededSkippedCount: how many over-cap runs were SILENTLY excluded from the prune this pass because they
  // could not be read (fail-safe: not superseded, nothing deleted).
  readonly supersededSkippedCount: number;
  // unparseableTimeCount: how many of this downpipe's RUNLOG entries carry a time that does not parse. Such an
  // entry can never be retained by the keepDays bound (it is treated as OUTSIDE the window), so a corrupt
  // timestamp silently changes eligibility; the count makes that visible.
  readonly unparseableTimeCount: number;
  // volumeRegression, when set, means the volume guard HELD one or more over-cap runs that the cap would
  // otherwise have superseded because they carry MORE records than any RETAINED run (an emptied/shrunken
  // source would else let smaller/empty runs evict the last FULL backup). The held runs are in
  // retainedRunIds; this is the redaction-safe signal the retention pass turns into an edge-triggered
  // backup-volume-regression alert. Absent on a plan where the cap dropped no volume high-water run.
  readonly volumeRegression?: VolumeRegression;
}

// PrunePolicy is the planner's view of DownpipeConfig.retention (kept local so prune.ts has no
// dependency on the scheduler DO module). enforce is NOT read here: the planner always plans; the
// gate lives at the apply site (applyPrune refuses without enforce===true).
export interface PrunePolicy {
  readonly keepRuns?: number;
  readonly keepDays?: number;
}

// ReplicaCoverage gates the prune on the 3-2-1 durability promise (M7). Retention prunes the PRIMARY
// archive (it deletes a superseded run-tree + its now-orphaned seg/ bytes), but a configured REPLICA
// that was briefly down or is still catching up may not yet hold a given run. Pruning that run from
// the primary before the replica receives it would leave it with FEWER than the configured copies (or
// zero off-site), silently dropping durability below the promise. The same-tick "replicate before
// prune" ordering (drive.ts) is not enough on its own: a replica down for a whole tick, or behind by
// more than one tick of backlog, is not caught up before the prune runs. So the planner additionally
// holds a run on the primary until EVERY configured replica is PROVEN to hold it.
//   minReplicaHoldsIndex is the MINIMUM holdsIndex across the downpipe's CONFIGURED replica
//   destinations (the most-behind replica's proven contiguous run index; -1 when a configured replica
//   holds nothing yet). A run is replica-covered iff its account-global RUNLOG index is <=
//   minReplicaHoldsIndex, i.e. the most-behind replica is caught up to it. A run with a higher index is
//   still owed to a lagging replica and is RETAINED on the primary even if it is over the retention cap.
//   The caller computes this from the repl: state the engine already tracks (per-destination
//   holdsIndex), exactly the proof uncoveredOriginRuns and the eviction-risk alert read.
//   maxReplicaHoldsFrom is the MAXIMUM holdsFrom across the configured replicas: the highest proven FLOOR,
//   i.e. the lowest run index every replica has CONTIGUOUSLY OBSERVED. A run is replica-covered only when
//   its index is at or ABOVE this floor AND at or below minReplicaHoldsIndex, i.e. it sits inside the run
//   window EVERY replica can actually PROVE it holds. This closes the ring-floor over-claim (BD-RETENTION-
//   HOLDSINDEX-RINGFLOOR-OVERCLAIM): keepRuns can far exceed the fixed 50-run history ring the replicate
//   pass walks, so a replica added after older runs aged out of that ring only ever observed from the ring
//   floor UPWARD. Without the floor bound, a pure index compare (index <= holdsIndex) would treat a
//   below-ring run the replica never held as covered and let retention delete the primary's ONLY copy of
//   it. A configured replica with no proven floor contributes +Infinity here (it can prove nothing below
//   its holdsIndex), so the covered window is empty until the replicate pass records a floor (the
//   conservative, retains-more direction). It self-heals on the next replicate tick.
// hasReplicas false means the downpipe fans out to NO replica (a single-destination downpipe): there is
// nothing off-site to wait for, so the gate is INERT and retention applies normally. This keeps the
// common single-destination case byte-for-byte unchanged.
export interface ReplicaCoverage {
  readonly hasReplicas: boolean;
  readonly minReplicaHoldsIndex: number;
  readonly maxReplicaHoldsFrom: number;
}

// MS_PER_DAY is the keepDays-to-millis factor; keepDays is validated as a positive integer upstream.
const MS_PER_DAY = 24 * 60 * 60 * 1000;

// VOLUME_REGRESSION_FACTOR is the volume guard's threshold (RL-PRUNE-VOLUME-REGRESSION-EVICTS-GOOD): a
// superseded run is pulled BACK into retained (held as the volume high-water) when its recordCount EXCEEDS
// the max recordCount among the retained runs by more than this factor. 1 = "strictly larger than every
// retained run", i.e. never drop the single largest backup for smaller or empty ones. It is a named
// constant so the policy is one obvious knob: a future tightening (e.g. 2 = only hold a run at least twice
// the retained max) changes the threshold without touching the guard logic.
const VOLUME_REGRESSION_FACTOR = 1;

// VolumeRegression reports that the volume guard HELD one or more over-cap runs the cap would otherwise
// have superseded, because they carry MORE records than any run the cap retained. It is the redaction-safe
// signal (counts only, never a value) the retention pass turns into an edge-triggered backup-volume-
// regression alert: after a source empties, a few green EMPTY runs sit within the keepRuns window and would
// evict the last FULL backup; the guard holds that high-water run so retention can never delete it.
export interface VolumeRegression {
  readonly heldRunIds: readonly string[]; // over-cap runs the guard pulled back into retained (never deleted)
  readonly heldMaxRecordCount: number; // the largest recordCount among the held runs (the volume high-water)
  readonly retainedMaxRecordCount: number; // the max recordCount among the runs the cap retained (the replacements)
}

// holdVolumeHighWater is the PURE volume guard: given the downpipe's active entries and the cap's initial
// retained/superseded split, it pulls back into retained ANY superseded run whose recordCount exceeds the
// retained max (x VOLUME_REGRESSION_FACTOR), so retention refuses to evict a downpipe's volume high-water
// run in favour of smaller/empty replacements. It ONLY ever moves a run from superseded -> retained (it
// retains MORE, deletes LESS) and NEVER supersedes a run the cap retained, so it cannot widen a delete.
// When the cap retained NOTHING (an all-expired keepDays window with no replacements to compare against) it
// is inert: there is no regression to guard, and holding an age-expired run would defeat an explicit
// keepDays policy. Returns the adjusted split plus a VolumeRegression signal when it held anything.
function holdVolumeHighWater(
  mine: RunlogEntry[],
  retainedRunIds: string[],
  supersededRunIds: string[],
): { retainedRunIds: string[]; supersededRunIds: string[]; volumeRegression?: VolumeRegression } {
  // Nothing retained (keepDays expired the whole window): the cap legitimately supersedes everything and
  // there are no smaller replacements to protect a high-water run against. Leave the split unchanged.
  if (retainedRunIds.length === 0) return { retainedRunIds, supersededRunIds };
  const countByRun = new Map<string, number>();
  for (const e of mine) countByRun.set(e.runId, e.recordCount);
  // The max recordCount among the runs the cap RETAINED (the runs that would remain after the prune).
  let retainedMax = 0;
  for (const id of retainedRunIds) retainedMax = Math.max(retainedMax, countByRun.get(id) ?? 0);
  const threshold = retainedMax * VOLUME_REGRESSION_FACTOR;
  // Any superseded run bigger than that threshold is the volume high-water: hold it (retained), never drop
  // it for smaller/empty runs. Everything at or below the threshold is a same-volume-or-smaller rollover
  // and supersedes exactly as before (normal retention unchanged).
  const heldRunIds: string[] = [];
  let heldMaxRecordCount = 0;
  const stillSuperseded: string[] = [];
  for (const id of supersededRunIds) {
    const c = countByRun.get(id) ?? 0;
    if (c > threshold) {
      heldRunIds.push(id);
      if (c > heldMaxRecordCount) heldMaxRecordCount = c;
    } else {
      stillSuperseded.push(id);
    }
  }
  if (heldRunIds.length === 0) return { retainedRunIds, supersededRunIds };
  return {
    retainedRunIds: [...retainedRunIds, ...heldRunIds],
    supersededRunIds: stillSuperseded,
    volumeRegression: { heldRunIds, heldMaxRecordCount, retainedMaxRecordCount: retainedMax },
  };
}

// partitionRuns is the pure core: given a downpipe's RUNLOG entries, the policy and now, it returns
// the retained and superseded run ids. Only entries for THIS downpipe that are currently
// status="active" are eligible to be superseded; an entry already marked "superseded" stays
// retained-in-place (it is kept in the RUNLOG, SPEC 10.1) and is NOT re-listed for deletion, which
// is what makes a second prune a no-op (idempotence). A run is RETAINED when it satisfies EITHER
// bound (the union): it is among the keepRuns most-recent by RUNLOG index, OR its RUNLOG time is
// within keepDays of now. A run outside BOTH is superseded. With neither bound set the planner keeps
// everything (validateConfig forbids that shape, but the planner is defensive).
//
// REPLICA-COVERAGE GATE (M7): when the optional `coverage` says the downpipe fans out to replicas, a
// run that the cap would otherwise supersede is RETAINED instead until EVERY configured replica is
// proven to hold it (coverage.maxReplicaHoldsFrom <= run.index <= coverage.minReplicaHoldsIndex, the
// window every replica can PROVE it holds). This stops the primary pruning a run out from under a
// lagging/down replica, or a below-ring run a newly-added replica never observed, which would silently
// drop the run below the 3-2-1 copy count. The retention cap semantics are otherwise unchanged: a run
// still inside the keepRuns/keepDays window is retained for the same reasons as before, and a
// replica-covered over-cap run is superseded exactly as before. Absent coverage (or a single-destination
// downpipe, hasReplicas=false) the gate is inert.
//
// VOLUME-REGRESSION GUARD (RL-PRUNE-VOLUME-REGRESSION-EVICTS-GOOD): after the cap (and the replica gate)
// have partitioned, holdVolumeHighWater pulls back into retained any superseded run whose recordCount
// EXCEEDS the max recordCount among the retained runs, so an emptied/shrunken source can never let a few
// green EMPTY runs evict the last FULL backup. It only ever retains MORE; a same-volume rollover prunes
// exactly as before. When it holds a run it returns a volumeRegression signal so the hold is alertable.
export function partitionRuns(
  entries: RunlogEntry[],
  downpipeId: string,
  policy: PrunePolicy,
  now: Date,
  coverage?: ReplicaCoverage,
): { retainedRunIds: string[]; supersededRunIds: string[]; unparseableTimeCount: number; volumeRegression?: VolumeRegression } {
  // This downpipe's entries, ascending by index (allocation order). Index is the stable ordering
  // key (line order is not load-bearing, SPEC 10), so "most recent" is highest index.
  const mine = entries.filter((e) => e.downpipeId === downpipeId).sort((a, b) => a.index - b.index);
  // Indices retained by the keepRuns bound: the top N by index. With keepRuns absent this bound
  // retains nothing on its own (the keepDays bound, if set, decides), matching the union semantics.
  const keepByRuns = new Set<string>();
  if (policy.keepRuns !== undefined) {
    for (const e of mine.slice(Math.max(0, mine.length - policy.keepRuns))) keepByRuns.add(e.runId);
  }
  // Run ids retained by the keepDays bound: RUNLOG time within keepDays of now. A run whose time is
  // unparseable is treated as OUTSIDE the day window (it can still be retained by keepRuns); it is
  // never silently kept by a parse failure, but a single bad timestamp cannot widen retention.
  const keepByDays = new Set<string>();
  // unparseableTimeCount (gap G190) counts the entries whose RUNLOG time does NOT parse. Such an entry is
  // treated as OUTSIDE the day window (never silently kept by a parse failure), so a corrupt timestamp
  // silently changes eligibility; counting it here makes that observable in the support pack. It is counted
  // over ALL of this downpipe's entries (not just the keepDays branch), so the signal survives a keepRuns-only
  // policy that would otherwise never look at the time field.
  let unparseableTimeCount = 0;
  for (const e of mine) {
    if (!Number.isFinite(Date.parse(e.time))) unparseableTimeCount++;
  }
  if (policy.keepDays !== undefined) {
    const cutoff = now.getTime() - policy.keepDays * MS_PER_DAY;
    for (const e of mine) {
      const t = Date.parse(e.time);
      if (Number.isFinite(t) && t >= cutoff) keepByDays.add(e.runId);
    }
  }
  // No bound set at all: keep everything (defensive; validateConfig requires at least one bound).
  const noBound = policy.keepRuns === undefined && policy.keepDays === undefined;

  const retainedRunIds: string[] = [];
  const supersededRunIds: string[] = [];
  for (const e of mine) {
    // A run already superseded by a PRIOR prune is DONE: it stays in the RUNLOG with its superseded
    // status (SPEC 10.1), but its run-tree was already deleted and its segments already GC'd. It must NOT
    // be treated as a retained PROTECTED reference (openRun would fail on the deleted tree and abstain the
    // whole pass forever after the first prune -- the prune-abstain bug), and it must NOT be superseded
    // again. Skip it entirely; protection of shared segments comes from the ACTIVE runs that reference
    // them. (A superseded run whose tree delete previously failed is left in place; the orphan-seg GC and
    // a future supersession of an overlapping run still reclaim its bytes.)
    if (e.status !== "active") continue;
    const withinCap = noBound || keepByRuns.has(e.runId) || keepByDays.has(e.runId);
    // REPLICA-COVERAGE GATE (M7): a run outside the cap is only superseded once every configured replica
    // is PROVEN to hold it (run.index <= the most-behind replica's holdsIndex). A run still owed to a
    // lagging/down replica is RETAINED on the primary even though it is over the cap, so retention can
    // never drop a run below its 3-2-1 copy count. Inert for a single-destination downpipe (hasReplicas
    // false) and when no coverage is supplied, so the common case is unchanged.
    const replicaCovered = coverage === undefined || !coverage.hasReplicas || (e.index >= coverage.maxReplicaHoldsFrom && e.index <= coverage.minReplicaHoldsIndex);
    const retained = withinCap || !replicaCovered;
    if (retained) retainedRunIds.push(e.runId);
    else supersededRunIds.push(e.runId);
  }
  // VOLUME-REGRESSION GUARD: never evict a downpipe's volume high-water run for smaller/empty ones. This
  // only ever pulls a run from superseded -> retained (retains MORE), so it cannot widen a delete.
  return { ...holdVolumeHighWater(mine, retainedRunIds, supersededRunIds), unparseableTimeCount };
}

// SegEnumerator reads a run's referenced segment object paths from its DECRYPTED shard manifests.
// The default implementation (openRunSegEnumerator) reuses the reader's openRun, which exposes
// records[].segments[].object. It is injected so the pure partition logic and the IO are separable
// and the validators can drive the planner with an in-memory enumerator.
export type SegEnumerator = (runId: string) => Promise<string[]>;

// RunTreeLister lists a run's run/<runId>/ tree object keys (root manifest, its sig, the shard
// manifests). The default implementation calls dest.list; injected for the same testability reason.
export type RunTreeLister = (runId: string) => Promise<string[]>;

// SizeLookup optionally reports an object's byte size, so the plan can sum reclaimableBytes. It is
// best-effort: an absent size (null) contributes nothing. Omitting the lookup yields reclaimableBytes
// 0 (the plan is still complete; the byte total is just not computed).
export type SizeLookup = (key: string) => Promise<number | null>;

// openRunSegEnumerator builds the production SegEnumerator: it opens each run with openRun under the
// operational identity (the same in-account read-back path the drill uses, admin/drill.ts) and
// collects every record's segment object keys. openRun verifies the whole chain as a side effect, so
// a run that does not open (tampered/missing) THROWS rather than returning a partial set, and the
// caller (planPrune) treats that run as un-enumerable and excludes it from the prune (fail-safe: an
// un-readable run is never superseded and its segments are never deleted).
export function openRunSegEnumerator(store: ObjectStore, identity: HybridRecipientPrivate, verifier: HybridVerifier): SegEnumerator {
  return async (runId: string): Promise<string[]> => {
    const run = await openRun(store, runId, identity, verifier);
    try {
      const segs: string[] = [];
      for (const rec of run.records) {
        for (const seg of rec.segments) segs.push(seg.object);
      }
      return segs;
    } finally {
      // This enumerator opens a run PURELY to read segment object names -- the prune holds a corpus-wide
      // decryption key only to read filenames (the "signed segment index, and the keyless prune" design
      // question). It should at least not leave the per-run master live after doing it.
      run.dispose();
    }
  };
}

// planPrune computes the full PrunePlan for one downpipe. It is the planner the cron drive loop and
// the validators call. It deletes NOTHING.
//
// The optional `coverage` (M7) is the 3-2-1 replica-coverage gate threaded into the partition: a run
// over the retention cap is NOT superseded until every configured replica is proven to hold it, so the
// prune can never drop a run below its off-site copy count. Absent (or a single-destination downpipe)
// the gate is inert and retention applies exactly as before.
//
// Steps:
//  1. Partition the downpipe's active runs into retained and superseded (partitionRuns, pure), with the
//     replica-coverage gate holding any over-cap run that a configured replica has not yet received.
//  2. For EACH retained and EACH superseded run, enumerate its referenced segment object paths from
//     the decrypted manifests. A SUPERSEDED run that fails to open is dropped from the prune (it is
//     NOT superseded this pass, so its tree and segments are untouched). A RETAINED run that fails to
//     open makes the protected reference set INCOMPLETE, which would let a shared segment fall into
//     the orphan set and be deleted, so the whole pass ABSTAINS (deletes and supersedes nothing) and
//     retries later. Either way an un-readable run can never cause a wrongful delete.
//  3. orphanSegs = supersededSegRefs MINUS retainedSegRefs (the core GC; see the file header).
//  4. runTreeObjects = the run/<runId>/ listing for each superseded run that survived step 2.
//  5. reclaimableBytes = summed size of the deletable objects, when a SizeLookup is supplied.
export async function planPrune(
  entries: RunlogEntry[],
  downpipeId: string,
  policy: PrunePolicy,
  now: Date,
  enumerateSegs: SegEnumerator,
  listRunTree: RunTreeLister,
  sizeOf?: SizeLookup,
  coverage?: ReplicaCoverage,
): Promise<PrunePlan> {
  const { retainedRunIds, supersededRunIds, unparseableTimeCount, volumeRegression } = partitionRuns(entries, downpipeId, policy, now, coverage);
  // The volume-regression signal (a held high-water run) is independent of segment enumeration, so surface
  // it on EVERY plan return below (including the abstain path): the hold already happened in the partition.
  const vr = volumeRegression ? { volumeRegression } : {};

  // Step 1: the COMPLETE protected reference set (with the abstain decision). If incomplete, abstain.
  const retained = await buildRetainedSegRefs(retainedRunIds, enumerateSegs);
  if (!retained.complete) {
    // Abstain entirely: supersede nothing, delete nothing. A run-tree delete is only ever paired with
    // its segment GC, and the segment GC is unsafe without a complete retained set, so we defer both.
    // The abstain now also carries its CLOSED class + the blocking (opaque) run id + the unreadable count
    // (gap G190), so a prune that defers forever is diagnosable from the support pack, not just the logs.
    return {
      downpipeId,
      retainedRunIds,
      supersededRunIds: [],
      runTreeObjects: [],
      orphanSegs: [],
      reclaimableBytes: 0,
      deferred: "a retained run could not be read; deferring the prune so segment GC stays safe",
      deferredClass: "retained-run-unreadable" as const,
      ...(retained.firstUnreadable !== undefined ? { blockingRunId: retained.firstUnreadable } : {}),
      retainedUnreadableCount: retained.unreadable,
      supersededSkippedCount: 0,
      unparseableTimeCount,
      ...vr,
    };
  }

  // Step 2: the superseded reference set, dropping any superseded run that cannot be read this pass.
  const superseded = await buildSupersededSegRefs(supersededRunIds, enumerateSegs);

  // Step 3: the orphan set = superseded segments referenced by NO retained run (the only deletable set).
  const orphanSegs = computeOrphanSegs(superseded.refs, retained.refs);

  // Step 4: the run-tree objects for the runs we are actually superseding (root + sig + shard manifests).
  // The RUNLOG entry itself is RETAINED marked superseded (it lives under _RECOVERY/, not run/<runId>/).
  const runTreeObjects: string[] = [];
  for (const runId of superseded.supersededOk) {
    for (const key of await listRunTree(runId)) runTreeObjects.push(key);
  }

  // Step 5: best-effort reclaimable-bytes sum over the deletable objects.
  const reclaimableBytes = await sumReclaimableBytes([...runTreeObjects, ...orphanSegs], sizeOf);

  return {
    downpipeId,
    retainedRunIds,
    supersededRunIds: superseded.supersededOk,
    runTreeObjects,
    orphanSegs,
    reclaimableBytes,
    retainedUnreadableCount: 0,
    supersededSkippedCount: superseded.skipped,
    unparseableTimeCount,
    ...vr,
  };
}

// buildRetainedSegRefs enumerates every RETAINED run's referenced segment objects into one set and
// reports whether it is COMPLETE. CRITICAL SAFETY: the set MUST be complete. orphanSegs =
// supersededSegRefs MINUS retainedSegRefs, so a MISSING retained reference (a retained run we could not
// read) does NOT shrink the orphan set, it GROWS it: a segment shared between an unreadable retained run
// and a superseded run would be absent from retainedSegRefs, fall into orphanSegs, and be deleted,
// BREAKING the retained run. So if ANY retained run fails to enumerate, complete is false and the caller
// abstains from all deletion this pass and retries when the run is readable again (idempotent).
// It additionally reports HOW MANY retained runs failed and WHICH one failed first (the opaque blocking run
// id), the evidence the abstain used to throw away (gap G190): a prune that defers forever is otherwise a
// generic log sentence with no way to name the one unreadable run behind it.
async function buildRetainedSegRefs(retainedRunIds: string[], enumerateSegs: SegEnumerator): Promise<{ refs: Set<string>; complete: boolean; unreadable: number; firstUnreadable?: string }> {
  const refs = new Set<string>();
  let complete = true;
  let unreadable = 0;
  let firstUnreadable: string | undefined;
  for (const runId of retainedRunIds) {
    try {
      for (const obj of await enumerateSegs(runId)) refs.add(obj);
    } catch {
      complete = false; // incomplete protected set: the caller abstains from all deletion this pass
      unreadable++;
      if (firstUnreadable === undefined) firstUnreadable = runId;
    }
  }
  return { refs, complete, unreadable, ...(firstUnreadable !== undefined ? { firstUnreadable } : {}) };
}

// buildSupersededSegRefs enumerates the SUPERSEDED runs' referenced segments, dropping any run that does
// not enumerate: a run we cannot read is NOT superseded this pass (its RUNLOG entry stays active and its
// tree + segments are left untouched), so a transient read failure can never delete data. Returns the
// segment reference set and the list of runs that actually enumerated (supersededOk).
// It also COUNTS the runs it dropped (gap G190): a permanently broken superseded run is excluded from every
// pass in silence today, so storage never shrinks and nothing anywhere says why.
async function buildSupersededSegRefs(supersededRunIds: string[], enumerateSegs: SegEnumerator): Promise<{ refs: Set<string>; supersededOk: string[]; skipped: number }> {
  const refs = new Set<string>();
  const supersededOk: string[] = [];
  let skipped = 0;
  for (const runId of supersededRunIds) {
    let segs: string[];
    try {
      segs = await enumerateSegs(runId);
    } catch {
      skipped++; // un-readable: skip superseding it this pass (fail-safe, idempotent retry next time)
      continue;
    }
    supersededOk.push(runId);
    for (const obj of segs) refs.add(obj);
  }
  return { refs, supersededOk, skipped };
}

// computeOrphanSegs is the core GC subtraction (pure): a segment referenced by a superseded run and by
// NO retained run. The subtraction is what guarantees a retained reference can never be in the orphan set.
function computeOrphanSegs(supersededRefs: Set<string>, retainedRefs: Set<string>): string[] {
  const orphanSegs: string[] = [];
  for (const obj of supersededRefs) {
    if (!retainedRefs.has(obj)) orphanSegs.push(obj);
  }
  return orphanSegs;
}

// sumReclaimableBytes is a best-effort sum over the deletable objects (run-tree + orphan segments). An
// absent size contributes 0; omitting sizeOf yields 0 overall (the plan is still complete either way).
async function sumReclaimableBytes(keys: string[], sizeOf?: SizeLookup): Promise<number> {
  if (!sizeOf) return 0;
  let total = 0;
  for (const key of keys) {
    const n = await sizeOf(key);
    if (typeof n === "number" && Number.isFinite(n) && n > 0) total += n;
  }
  return total;
}

// runTreePrefix is the listing prefix for a run's tree objects (the root manifest, its sig and the
// shard manifests all live under run/<runId>/). Kept here so the lister and any caller agree on the
// exact prefix string.
export function runTreePrefix(runId: string): string {
  return `run/${runId}/`;
}

// PruneApplyResult reports what an enforced prune actually did: the count of RUNLOG entries marked
// superseded, and the count of run-tree and segment objects deleted. Redaction-safe (counts only),
// it is what the cron records in the structured log and the audit event.
export interface PruneApplyResult {
  readonly superseded: number; // RUNLOG entries transitioned active -> superseded
  readonly runTreeDeleted: number; // run/<runId>/ tree objects deleted
  readonly orphansDeleted: number; // orphaned segment objects deleted
}

// applyPrune is the GATED apply path: it COMMITS the plan. It is the only function in the retention
// feature that writes or deletes, and the caller MUST have checked the enforce gate before calling
// it (the cron does: it only calls applyPrune when retention.enforce === true; dry-run never gets
// here). The ORDER is the crash-safety invariant:
//   1. Mark the superseded runs in the RUNLOG and re-sign (supersedeRunlog, under the RUNLOG lock).
//      Entries are RETAINED marked superseded, never removed (removing one is a rollback the reader
//      rejects, SPEC 10.1).
//   2. ONLY THEN delete the run-tree objects, then the orphan segments.
// If the process dies after step 1 but before/within step 2, the RUNLOG is already consistent (the
// runs are superseded) and the not-yet-deleted run-trees/orphans are simply objects a reader reports
// as orphan candidates: safe, and a later prune finishes the deletion (idempotent, since deleting an
// absent key is a no-op and supersedeRunlog skips already-superseded entries). A referenced segment
// is NEVER deleted because the planner already subtracted every retained reference from orphanSegs.
// Deletes are sequential and best-effort-ordered; a single delete failure throws so the caller's
// fail-open wrapper logs it and the next tick retries the remainder.
export async function applyPrune(dest: Destination, signer: Signer, plan: PrunePlan, lock?: RunlogLock): Promise<PruneApplyResult> {
  // Step 1: commit the superseded RUNLOG first (the rollback-safe ordering). supersedeRunlog only
  // transitions active entries and re-signs the whole log under the lock.
  const superseded = await supersedeRunlog(dest, signer, plan.supersededRunIds, lock);

  // Step 2: delete the run-tree objects, then the orphaned segments. Run-trees first so a crash mid
  // way leaves orphan segments (reader-reported, safe) rather than a half-deleted run tree whose
  // RUNLOG entry is gone (it never is: the entry is retained-superseded). delete is idempotent.
  let runTreeDeleted = 0;
  let orphansDeleted = 0;
  try {
    for (const key of plan.runTreeObjects) {
      await dest.delete(key);
      runTreeDeleted++;
    }
    for (const key of plan.orphanSegs) {
      await dest.delete(key);
      orphansDeleted++;
    }
  } catch (e) {
    // A HALF-APPLIED prune (gap G190): the supersede is committed but a delete failed partway. The throw is
    // UNCHANGED (the caller's fail-open wrapper still logs it and the next tick retries the remainder), and the
    // progress counts are carried on the typed error rather than lost with the bare exception, so support can
    // tell a WORM-refused delete (an irreducible remainder that will never drain, and the reason "storage keeps
    // growing") from a transient flake. PruneApplyError carries the counts + the WORM class ONLY; the raw
    // destination message is never read out of it (isWormRefusal is the same coarse classifier the orphan-root
    // reclaim already uses).
    throw new PruneApplyError(e, { superseded, runTreeDeleted, orphansDeleted }, isWormRefusal((e as Error)?.message ?? ""));
  }
  return { superseded, runTreeDeleted, orphansDeleted };
}

/**
 * PruneApplyError is the typed carrier for a HALF-APPLIED enforced prune (gap G190). It is thrown INSTEAD of
 * the bare destination error so the progress the apply had already made survives to the recording site, and it
 * re-exposes the original as `cause` so no existing handler loses information. It carries COUNTS + a WORM
 * boolean only: never a key, an endpoint or the destination's message (the message stays on `cause` for the
 * engine's own log, and is never sealed into the pack).
 */
export class PruneApplyError extends Error {
  readonly progress: PruneApplyResult;
  readonly wormBlocked: boolean;
  constructor(cause: unknown, progress: PruneApplyResult, wormBlocked: boolean) {
    super(`retention prune apply failed after superseding ${progress.superseded} run(s) and deleting ${progress.runTreeDeleted + progress.orphansDeleted} object(s)`, { cause });
    this.name = "PruneApplyError";
    this.progress = progress;
    this.wormBlocked = wormBlocked;
  }
}

/**
 * pruneObservations maps ONE downpipe's prune pass to the bounded, redaction-safe seal-fault OBSERVE rows the
 * support pack reads (gap G190: "retention never deletes anything / storage keeps growing"). PURE (no I/O), so
 * the recording site and the validator share one projection and the redaction can never drift.
 *
 * It emits at most three rows, all from the CLOSED SEAL_FAULT_KINDS vocabulary:
 *   - prune-deferred: the planner abstained (a retained run would not open). Carries the CLOSED deferredClass,
 *     the blocking opaque run id, the unreadable count and the unparseable-time count. The planner's free-text
 *     `deferred` sentence is NEVER carried.
 *   - prune-runs-skipped: over-cap runs silently excluded this pass because they could not be read.
 *   - prune-partial-apply: an enforced apply died mid-delete; carries what it had done + the WORM class.
 * A clean pass (no abstain, nothing skipped, an apply that finished) emits NOTHING, so the ring stays a
 * fault ring and a healthy fleet posts nothing at all.
 */
export function pruneObservations(plan: PrunePlan, at: number, failure?: PruneApplyError): SealFault[] {
  const out: SealFault[] = [];
  if (plan.deferredClass !== undefined) {
    out.push({
      kind: "prune-deferred",
      at,
      downpipeId: plan.downpipeId,
      ...(plan.blockingRunId !== undefined ? { runId: plan.blockingRunId } : {}),
      deferClass: plan.deferredClass,
      skipped: plan.retainedUnreadableCount,
      unparseableTime: plan.unparseableTimeCount,
    });
  }
  if (plan.supersededSkippedCount > 0) {
    out.push({
      kind: "prune-runs-skipped",
      at,
      downpipeId: plan.downpipeId,
      skipped: plan.supersededSkippedCount,
      unparseableTime: plan.unparseableTimeCount,
    });
  }
  if (failure !== undefined) {
    out.push({
      kind: "prune-partial-apply",
      at,
      downpipeId: plan.downpipeId,
      superseded: failure.progress.superseded,
      reclaimed: failure.progress.runTreeDeleted + failure.progress.orphansDeleted,
      partial: true,
      wormBlocked: failure.wormBlocked,
    });
  }
  return out;
}

/**
 * postPruneObservations records this pass's prune observations into the scheduler DO's bounded seal-fault ring
 * (POST /seal-fault, the SAME route + sanitiser the RunSealDO observe path already uses, so the vocabulary and
 * the clamping are shared). It is DIAGNOSTIC ONLY and STRICTLY BEST-EFFORT: the whole call is wrapped, so a DO
 * routing/persist hiccup degrades to "no observation" and can NEVER affect the prune (which has already
 * decided everything it is going to do by the time this runs). It reads and mutates no archive, RUNLOG or
 * destination object.
 *
 * Gap G326: it posts through the SHARED postSealFault chokepoint, so a retention observation lost to a
 * scheduler-DO outage (or to a drifted kind) is COUNTED and self-reported into the ring as an "observe-dropped"
 * record, rather than vanishing into an absence that reads exactly like a healthy retention pass.
 */
export async function postPruneObservations(scheduler: DurableObjectStub, plan: PrunePlan, at: number, failure?: PruneApplyError): Promise<void> {
  for (const fault of pruneObservations(plan, at, failure)) {
    await postSealFault(scheduler, fault as unknown as SealFaultPost);
  }
}
