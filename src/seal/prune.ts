import type { HybridRecipientPrivate } from "../crypto/kem.ts";
import type { HybridVerifier } from "../crypto/sign.ts";
import { type DeleteOutcome, type DestStatusError, type Destination, destStatusOf } from "../dest/types.ts";
import type { ObjectStore } from "../format/reader.ts";
import { openRun } from "../format/reader.ts";
import type { RunlogEntry, Signer } from "../format/writer.ts";
import type { RunlogLock } from "./pipeline.ts";
import { supersedeRunlog } from "./pipeline.ts";
import { postSealFault, type SealFaultPost } from "./seal-fault-post.ts";
import type { PruneDeferClass, SealFault, WormRefusalClass } from "./seal-faults.ts";

// The retention PRUNE PLANNER (ASVS V14.2.7: classification-driven retention with automatic
// deletion). It closes the WRITER side of the pruned/superseded RUNLOG semantics the data format
// already defines (SPEC 10.1) and both readers already honour: a RUNLOG entry marked
// status="superseded" is RETAINED and is NOT a rollback, while a MISSING entry IS. This module
// only PLANS; it deletes nothing. The apply path (applyPrune, under the RUNLOG lock) is the one
// place that writes, and only when the per-downpipe enforce gate is set.
//
// SEGMENT GC SAFETY: deletion is MANIFEST-DRIVEN, never age-driven. A segment is deleted ONLY if it
// appears in a superseded run AND in no retained run, computed as a set difference over EXACT object
// keys (no heuristic, no ttl); a retained run's segment can therefore never be deleted. The per-step
// invariant notes stay inside planPrune below.

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
  // runTrees is runTreeObjects grouped per run, in apply order, with the orphan segments each run references.
  // applyPrune deletes a run's tree only after every one of those segments is gone, because the tree is what
  // a later pass reads to find them again (see applyPrune). Absent on a plan built by hand; applyPrune then
  // treats every run-tree object as one run with no segment gate, the order the flat list gives.
  readonly runTrees?: readonly RunTreeStep[];
  // leftoverRunIds are runs an EARLIER pass already marked superseded whose objects are still in the
  // bucket (that pass was interrupted, or the store refused some deletes). This pass finishes them. They are
  // not in supersededRunIds, because the RUNLOG already says superseded and supersedeRunlog skips them.
  readonly leftoverRunIds?: readonly string[];
  // recheckSegs are the orphan segments that ONLY leftover runs reference. An earlier pass may already have
  // deleted them, so applyPrune checks each one is still there before it deletes it: a second delete of a
  // gone key would count as removed (or, on a versioned bucket, add another delete marker) when nothing was.
  readonly recheckSegs?: readonly string[];
  readonly reclaimableBytes: number; // summed size of the deletable objects, when sizes are known; else 0
  // deferred, when set, means the pass ABSTAINED: a retained run could not be enumerated, so the
  // protected reference set was incomplete and no deletion/supersede was safe. The plan's delete sets
  // are empty; a later pass retries. Present only on an abstaining plan.
  readonly deferred?: string;
  // deferredClass is the CLOSED, pack-bound coarsening of `deferred` ("my retention never deletes
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
  // could not be read (fail-safe: not superseded, nothing deleted), so the exclusion leaves a trace rather
  // than none at all.
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

// RunTreeStep is one superseded run's share of the delete plan. objects are its run/<runId>/ keys in the
// order applyPrune deletes them: the root signature first, the root manifest last (runTreeDeleteOrder).
// segs are the orphan segments this run references. They must all be gone before any of objects is
// deleted, because the tree is the only record of which segments the run used.
export interface RunTreeStep {
  readonly runId: string;
  readonly objects: readonly string[];
  readonly segs: readonly string[];
}

// PrunePolicy is the planner's view of DownpipeConfig.retention (kept local so prune.ts has no
// dependency on the scheduler DO module). enforce is NOT read here: the planner always plans; the
// gate lives at the apply site (applyPrune refuses without enforce===true).
export interface PrunePolicy {
  readonly keepRuns?: number;
  readonly keepDays?: number;
}

// ReplicaCoverage gates the prune on the 3-2-1 durability promise. Retention prunes the PRIMARY
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
//   window EVERY replica can actually PROVE it holds. This closes a ring-floor over-claim: keepRuns can far
//   exceed the fixed 50-run history ring the replicate
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

// VOLUME_REGRESSION_FACTOR is the volume guard's threshold: a
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
// REPLICA-COVERAGE GATE: when the optional `coverage` says the downpipe fans out to replicas, a
// run that the cap would otherwise supersede is RETAINED instead until EVERY configured replica is
// proven to hold it (coverage.maxReplicaHoldsFrom <= run.index <= coverage.minReplicaHoldsIndex, the
// window every replica can PROVE it holds). This stops the primary pruning a run out from under a
// lagging/down replica, or a below-ring run a newly-added replica never observed, which would silently
// drop the run below the 3-2-1 copy count. The retention cap semantics are otherwise unchanged: a run
// still inside the keepRuns/keepDays window is retained for the same reasons as before, and a
// replica-covered over-cap run is superseded exactly as before. Absent coverage (or a single-destination
// downpipe, hasReplicas=false) the gate is inert.
//
// VOLUME-REGRESSION GUARD: after the cap (and the replica gate)
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
  // unparseableTimeCount counts the entries whose RUNLOG time does NOT parse. Such an entry is
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
    // A run already superseded by a PRIOR prune is not a candidate here: it stays in the RUNLOG with its
    // superseded status (SPEC 10.1). It must NOT be treated as a retained PROTECTED reference (openRun would
    // fail on a deleted tree and abstain the whole pass forever after the first prune -- the prune-abstain
    // bug), and it must NOT be superseded again. Protection of shared segments comes from the ACTIVE runs
    // that reference them. If an earlier pass did not finish deleting such a run's objects, planPrune picks
    // them up as a LEFTOVER (planLeftovers), outside this partition.
    if (e.status !== "active") continue;
    const withinCap = noBound || keepByRuns.has(e.runId) || keepByDays.has(e.runId);
    // REPLICA-COVERAGE GATE: a run outside the cap is only superseded once every configured replica
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

// runTreeIndexLister builds the production RunTreeLister for one destination: ONE paged walk of the whole
// run/ prefix, memoised per destination instance, then every run's tree is a map lookup. The planner lists
// the tree of every superseded run of the downpipe, including every run an earlier pass already superseded
// (planLeftovers), and that set grows with every pass for the life of the downpipe. One list request per
// superseded run per 15-minute tick would grow without bound; one walk of what is actually still in the
// bucket costs one request per 1000 run-tree objects present, and a finished run contributes nothing.
// The memo is keyed on the Destination object, which the cron builds once per destination per pass and the
// attended route once per request, so a later pass never reads an earlier pass's listing. Downpipes that
// share a bucket share the walk; each one's plan reads only its own run ids. A failed walk is not memoised.
export function runTreeIndexLister(dest: Destination): RunTreeLister {
  return async (runId: string): Promise<string[]> => {
    let index = RUN_TREE_INDEX.get(dest);
    if (index === undefined) {
      index = buildRunTreeIndex(dest);
      RUN_TREE_INDEX.set(dest, index);
      index.catch(() => RUN_TREE_INDEX.delete(dest));
    }
    return [...((await index).get(runId) ?? [])];
  };
}

const RUN_TREE_INDEX = new WeakMap<Destination, Promise<Map<string, string[]>>>();

// buildRunTreeIndex walks run/ once, page by page where the destination can page (listPage), and groups
// the keys by run id (the path segment after run/).
async function buildRunTreeIndex(dest: Destination): Promise<Map<string, string[]>> {
  const byRun = new Map<string, string[]>();
  const add = (key: string): void => {
    const runId = key.slice("run/".length).split("/")[0] ?? "";
    if (runId === "" || !key.startsWith(runTreePrefix(runId))) return;
    const list = byRun.get(runId);
    if (list === undefined) byRun.set(runId, [key]);
    else list.push(key);
  };
  if (dest.listPage !== undefined) {
    let cursor: string | undefined;
    do {
      const page = await dest.listPage("run/", cursor);
      for (const k of page.keys) add(k);
      cursor = page.cursor;
    } while (cursor !== undefined);
  } else {
    for (const k of await dest.list("run/")) add(k);
  }
  return byRun;
}

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
      // This enumerator opens a run PURELY to read segment object names, holding a corpus-wide decryption
      // key for that purpose alone, so it must not leave the per-run master live after doing it.
      run.dispose();
    }
  };
}

// planPrune computes the full PrunePlan for one downpipe. It is the planner the cron drive loop and
// the validators call. It deletes NOTHING.
//
// The optional `coverage` is the 3-2-1 replica-coverage gate threaded into the partition: a run
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
//  3. LEFTOVERS: every run an EARLIER pass marked superseded whose run/<runId>/ tree is still listed
//     (planLeftovers). A leftover whose root signature is still there may still own segments, so it is
//     enumerated like a superseded run (and skipped this pass if it will not open). A leftover whose root
//     signature is gone had its segments deleted already (applyPrune deletes the signature only after the
//     run's segments), so only its remaining tree objects are planned.
//  4. orphanSegs = (supersededSegRefs + leftoverSegRefs) MINUS retainedSegRefs (the core GC; see the file
//     header). The subtraction is recomputed every pass, so a leftover segment a retained run now uses is
//     never deleted.
//  5. runTrees / runTreeObjects = the run/<runId>/ listing for each superseded run that survived step 2 and
//     each leftover, per run, in delete order, with the orphan segments each one references.
//  6. reclaimableBytes = summed size of the deletable objects, when a SizeLookup is supplied.
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
    // so a prune that defers forever is diagnosable from the support pack, not just the logs.
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

  // Step 3: the leftovers of runs an earlier pass superseded but did not finish deleting.
  const leftovers = await planLeftovers(entries, downpipeId, enumerateSegs, listRunTree);

  // Step 4: the orphan set = segments of superseded runs and leftovers referenced by NO retained run.
  const allSupersededRefs = new Set<string>([...superseded.refs, ...leftovers.refs]);
  const orphanSegs = computeOrphanSegs(allSupersededRefs, retained.refs);
  const orphanSet = new Set(orphanSegs);

  // Step 5: the run-tree objects for the runs we are superseding (root + sig + shard manifests), then the
  // leftovers' remaining objects, per run, in delete order. The RUNLOG entry itself is RETAINED marked
  // superseded (it lives under _RECOVERY/, not run/<runId>/).
  const runTrees: RunTreeStep[] = [];
  for (const runId of superseded.supersededOk) {
    const segs = (superseded.segsByRun.get(runId) ?? []).filter((k) => orphanSet.has(k));
    runTrees.push({ runId, objects: runTreeDeleteOrder(runId, await listRunTree(runId)), segs: [...new Set(segs)] });
  }
  for (const l of leftovers.steps) {
    runTrees.push({ runId: l.runId, objects: l.objects, segs: [...new Set(l.segs.filter((k) => orphanSet.has(k)))] });
  }
  const runTreeObjects = runTrees.flatMap((t) => t.objects);
  const recheckSegs = orphanSegs.filter((k) => !superseded.refs.has(k));

  // Step 6: best-effort reclaimable-bytes sum over the deletable objects.
  const reclaimableBytes = await sumReclaimableBytes([...runTreeObjects, ...orphanSegs], sizeOf);

  return {
    downpipeId,
    retainedRunIds,
    supersededRunIds: superseded.supersededOk,
    runTreeObjects,
    orphanSegs,
    runTrees,
    leftoverRunIds: leftovers.steps.map((l) => l.runId),
    recheckSegs,
    reclaimableBytes,
    retainedUnreadableCount: 0,
    // A leftover that still owns segments but would not open is skipped like an over-cap run that would
    // not open: nothing of it is deleted this pass, and the count says so.
    supersededSkippedCount: superseded.skipped + leftovers.skipped,
    unparseableTimeCount,
    ...vr,
  };
}

// runTreeDeleteOrder puts one run's tree keys in the order applyPrune deletes them. The root SIGNATURE goes
// first: once it is gone, no reader opens the run, and its absence is the marker a later pass reads to know
// that the run's segments were already deleted (applyPrune deletes it only after they are). The shard
// manifests follow. The root MANIFEST goes last, so a run that is only part deleted still names itself.
// Every other key keeps the listing's order. Pure.
export function runTreeDeleteOrder(runId: string, keys: readonly string[]): string[] {
  const sig = `${runTreePrefix(runId)}${ROOT_SIG_NAME}`;
  const root = `${runTreePrefix(runId)}${ROOT_MANIFEST_NAME}`;
  const rest = keys.filter((k) => k !== sig && k !== root);
  return [...(keys.includes(sig) ? [sig] : []), ...rest, ...(keys.includes(root) ? [root] : [])];
}

// The two root object names under run/<runId>/ (format/reader.ts openRun reads exactly these).
const ROOT_MANIFEST_NAME = "root.manifest.json";
const ROOT_SIG_NAME = "root.manifest.json.sig";

// planLeftovers finds the runs of THIS downpipe that an earlier pass already marked superseded but whose
// run/<runId>/ tree is still in the bucket, and plans what is left of each. It is what makes "a later pass
// finishes an interrupted prune" true: partitionRuns skips every non-active entry, so without this step a
// superseded run's remaining objects would never be planned again.
//   - An empty listing means the run is finished. Nothing is planned. This is the common case.
//   - The root signature still listed means the tree phase has not started, so the run may still own
//     segments. It is enumerated (openRun reads the root, the signature and the shard manifests, never a
//     segment body, so deleted segments do not stop it). One that will not open is SKIPPED this pass: its
//     tree is the only record of its segments, so deleting the tree blind could strand them.
//   - The root signature gone means applyPrune had already deleted the run's segments (it deletes the
//     signature only after them). The remaining tree objects are planned with no segments, and nothing is
//     opened.
// A leftover left by an engine that deleted the tree BEFORE the segments (the order before this change) and
// died partway has lost the shard manifests that name its segments. Its remaining tree objects are still
// finished here; its segments cannot be found by enumeration and stay in the bucket.
async function planLeftovers(
  entries: RunlogEntry[],
  downpipeId: string,
  enumerateSegs: SegEnumerator,
  listRunTree: RunTreeLister,
): Promise<{ steps: RunTreeStep[]; refs: Set<string>; skipped: number }> {
  const steps: RunTreeStep[] = [];
  const refs = new Set<string>();
  let skipped = 0;
  for (const e of entries) {
    if (e.downpipeId !== downpipeId || e.status !== "superseded") continue;
    const tree = await listRunTree(e.runId);
    if (tree.length === 0) continue;
    const objects = runTreeDeleteOrder(e.runId, tree);
    if (!tree.includes(`${runTreePrefix(e.runId)}${ROOT_SIG_NAME}`)) {
      steps.push({ runId: e.runId, objects, segs: [] });
      continue;
    }
    let segs: string[];
    try {
      segs = await enumerateSegs(e.runId);
    } catch {
      skipped++;
      continue;
    }
    for (const k of segs) refs.add(k);
    steps.push({ runId: e.runId, objects, segs });
  }
  return { steps, refs, skipped };
}

// buildRetainedSegRefs enumerates every RETAINED run's referenced segment objects into one set and
// reports whether it is COMPLETE. CRITICAL SAFETY: the set MUST be complete. orphanSegs =
// supersededSegRefs MINUS retainedSegRefs, so a MISSING retained reference (a retained run we could not
// read) does NOT shrink the orphan set, it GROWS it: a segment shared between an unreadable retained run
// and a superseded run would be absent from retainedSegRefs, fall into orphanSegs, and be deleted,
// BREAKING the retained run. So if ANY retained run fails to enumerate, complete is false and the caller
// abstains from all deletion this pass and retries when the run is readable again (idempotent).
// It additionally reports HOW MANY retained runs failed and WHICH one failed first (the opaque blocking run
// id), the evidence the abstain used to throw away: a prune that defers forever is otherwise a
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
// It also COUNTS the runs it dropped: a permanently broken superseded run is excluded from every
// pass in silence today, so storage never shrinks and nothing anywhere says why.
// segsByRun keeps each run's own segment list, so applyPrune can hold a run's tree until its segments are gone.
async function buildSupersededSegRefs(supersededRunIds: string[], enumerateSegs: SegEnumerator): Promise<{ refs: Set<string>; supersededOk: string[]; skipped: number; segsByRun: Map<string, string[]> }> {
  const refs = new Set<string>();
  const supersededOk: string[] = [];
  const segsByRun = new Map<string, string[]>();
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
    segsByRun.set(runId, segs);
    for (const obj of segs) refs.add(obj);
  }
  return { refs, supersededOk, skipped, segsByRun };
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

// PruneApplyResult reports what an enforced prune actually did, in counts only (redaction-safe): it is what
// the cron and the attended route record in the pass record, the fault ring and their responses.
//
// DELETED AND HIDDEN ARE COUNTED APART. A delete the store answered with a delete marker (a VERSIONED
// bucket, which every S3 Object Lock bucket is) removed the key from listings but not the bytes: they stay
// as a noncurrent version until the customer's own lifecycle rule expires them, and never while a retention
// lock holds them. Counting those as reclaimed told the customer storage had shrunk when it had not.
export interface PruneApplyResult {
  readonly superseded: number; // RUNLOG entries transitioned active -> superseded
  readonly runTreeDeleted: number; // run/<runId>/ tree objects the store removed
  readonly orphansDeleted: number; // orphaned segment objects the store removed
  readonly runTreeHidden: number; // run-tree objects the store only hid behind a delete marker (bytes kept)
  readonly orphansHidden: number; // orphaned segments the store only hid behind a delete marker (bytes kept)
  readonly refusedLocked: number; // deletes refused, and the object's own lock metadata shows a lock holding it
  readonly refusedDenied: number; // deletes refused with 401/403, and no lock holds the object: a permission to fix
  readonly refusedUnknown: number; // deletes refused where the lock could not be read or the readings disagree
  readonly failed: number; // a delete that got no usable answer (a transport fault, a 5xx, a 429): the loop stopped there
  readonly held: number; // planned objects NOT attempted: a run tree held because its segments did not all go, or the rest after a stop
  readonly alreadyGone: number; // objects that were already absent (a leftover segment checked first, or a delete the store answered 404): not a change
}

/**
 * pruneChanged reports whether an apply CHANGED the archive: it re-signed the RUNLOG with runs superseded,
 * or the store removed or hid at least one object. An already-absent object is not a change. It is the one
 * rule both audit producers use (cron/retention-pass.ts and admin/router-retention-prune.ts): a
 * retention-prune audit event is written for an apply that changed something, and for no other.
 */
export function pruneChanged(r: PruneApplyResult): boolean {
  return r.superseded > 0 || r.runTreeDeleted + r.orphansDeleted > 0 || hiddenCount(r) > 0;
}

/** refusedCount is the total number of deletes the store refused, over the three refusal classes. */
export function refusedCount(r: PruneApplyResult): number {
  return r.refusedLocked + r.refusedDenied + r.refusedUnknown;
}

/** hiddenCount is the total number of objects hidden behind a delete marker rather than removed. */
export function hiddenCount(r: PruneApplyResult): number {
  return r.runTreeHidden + r.orphansHidden;
}

/**
 * dominantRefusalClass names the ONE refusal class a row that has room for only one reports. The order is the
 * order of remedies: a permission denial first (a fixable credential), then could-not-tell (read the object's
 * lock to decide), then a lock (irreducible until it lapses), then a transient failure (it retries). Undefined
 * when nothing was refused or failed.
 */
export function dominantRefusalClass(r: PruneApplyResult): WormRefusalClass | undefined {
  if (r.refusedDenied > 0) return "access-denied";
  if (r.refusedUnknown > 0) return "could-not-tell";
  if (r.refusedLocked > 0) return "worm-locked";
  if (r.failed > 0) return "transient";
  return undefined;
}

/**
 * VERSIONED_BUCKET_RECLAIM_NOTE is the plain statement of what a hidden count means, for every surface that
 * reports one. It names no store feature the customer may not have, and promises no date.
 */
export const VERSIONED_BUCKET_RECLAIM_NOTE =
  "On a versioned bucket, and every Object Lock bucket is versioned, a delete adds a delete marker and the object's bytes stay as a noncurrent version. They are removed only by your bucket's own lifecycle rule for noncurrent versions, and not while a retention lock still holds them.";

// MAX_LOCK_READS caps how many refused deletes one apply reads the object's lock for (one HEAD each, plus at
// most one bucket configuration read). A credential that is denied every delete would otherwise double the
// request count of a pass that already refuses everything. A refusal past the cap is counted could-not-tell,
// because it was not read.
const MAX_LOCK_READS = 32;

// DeleteResult is one key's outcome inside applyPrune.
type DeleteResult = { gone: true; hidden: boolean; absent?: boolean } | { gone: false; refusal: "worm-locked" | "access-denied" | "could-not-tell" } | { gone: false; stop: true };

// applyPrune is the GATED apply path: it COMMITS the plan. It is the only function in the retention
// feature that writes or deletes, and the caller MUST have checked the enforce gate before calling
// it (the cron does: it only calls applyPrune when retention.enforce === true; dry-run never gets
// here). The ORDER is the crash-safety invariant:
//   1. Mark the superseded runs in the RUNLOG and re-sign (supersedeRunlog, under the RUNLOG lock).
//      Entries are RETAINED marked superseded, never removed (removing one is a rollback the reader
//      rejects, SPEC 10.1).
//   2. ONLY THEN delete the orphan segments.
//   3. Then each run's tree, and only for a run whose orphan segments are ALL gone: the root signature
//      first, the shard manifests next, the root manifest last (runTreeDeleteOrder).
// WHY SEGMENTS BEFORE THE TREE. The tree is the only record of which segments a run used: openRun reads
// the root, its signature and the shard manifests, never a segment body. So while the tree is intact a
// later pass can re-open the run and re-plan exactly the segments that remain. The earlier order (tree
// first) lost that record on the first interrupted delete, and the segments were never planned again.
// WHY THE SIGNATURE FIRST. It is deleted only after the run's segments, so its absence tells a later pass
// the segments are done and the rest of the tree can go without opening anything (planLeftovers).
// If the process dies after step 1, the RUNLOG is already consistent (the runs are superseded) and a later
// pass finishes the rest: planLeftovers plans every superseded run whose tree is still listed. Deleting an
// absent key is a no-op, and supersedeRunlog skips already-superseded entries. A referenced segment is
// NEVER deleted because the planner subtracts every retained reference from orphanSegs, every pass.
//
// A REFUSED delete does not stop the loop. The key is counted by class (classifyRefusal reads the object's
// own lock before it calls a refusal a lock) and the apply moves on, so one locked or denied object no
// longer strands everything planned after it. A run whose segment was refused keeps its tree for a later
// pass. A delete that got no usable answer (a transport fault, a 5xx, a 429) does stop the loop: the store is
// not answering, and the next pass retries. If anything was refused or failed, applyPrune throws a
// PruneApplyError carrying every count, so the caller records a partial apply rather than a clean one.
export async function applyPrune(dest: Destination, signer: Signer, plan: PrunePlan, lock?: RunlogLock): Promise<PruneApplyResult> {
  // Step 1: commit the superseded RUNLOG first (the rollback-safe ordering). supersedeRunlog only
  // transitions active entries and re-signs the whole log under the lock.
  const superseded = await supersedeRunlog(dest, signer, plan.supersededRunIds, lock);

  const n = { runTreeDeleted: 0, orphansDeleted: 0, runTreeHidden: 0, orphansHidden: 0, refusedLocked: 0, refusedDenied: 0, refusedUnknown: 0, failed: 0, held: 0, alreadyGone: 0 };
  let lockReads = 0;
  let stopped = false;
  let firstFault: unknown;
  const del = async (key: string): Promise<DeleteResult> => {
    try {
      const out = (await dest.delete(key)) as DeleteOutcome | undefined;
      if (out?.absent === true) return { gone: true, hidden: false, absent: true };
      return { gone: true, hidden: out?.deleteMarker === true };
    } catch (e) {
      firstFault ??= e;
      const status = destStatusOf(e);
      if (status === undefined || status >= 500 || status === 429 || status === 408) return { gone: false, stop: true };
      const readLock = lockReads < MAX_LOCK_READS;
      if (readLock) lockReads++;
      return { gone: false, refusal: await classifyRefusal(dest, key, e as DestStatusError, readLock) };
    }
  };
  const tally = (r: DeleteResult, kind: "tree" | "seg"): void => {
    if (r.gone && r.absent === true) n.alreadyGone++;
    else if (r.gone) {
      if (kind === "tree" && r.hidden) n.runTreeHidden++;
      else if (kind === "tree") n.runTreeDeleted++;
      else if (r.hidden) n.orphansHidden++;
      else n.orphansDeleted++;
    } else if ("stop" in r) {
      n.failed++;
      stopped = true;
    } else if (r.refusal === "worm-locked") n.refusedLocked++;
    else if (r.refusal === "access-denied") n.refusedDenied++;
    else n.refusedUnknown++;
  };

  // Step 2: the orphan segments. A segment's outcome gates the tree of every run that references it.
  // A segment only leftovers reference is checked first: if an earlier pass already deleted it, it is
  // counted alreadyGone and not deleted again.
  const segGone = new Set<string>();
  const recheck = new Set(plan.recheckSegs ?? []);
  for (const key of plan.orphanSegs) {
    if (stopped) {
      n.held++;
      continue;
    }
    if (recheck.has(key) && (await isAbsent(dest, key))) {
      n.alreadyGone++;
      segGone.add(key);
      continue;
    }
    const r = await del(key);
    tally(r, "seg");
    if (r.gone) segGone.add(key);
  }

  // Step 3: each run's tree, in delete order, only once its segments are gone. A plan built without
  // runTrees (a hand-built plan) is one step with no segment gate, in the flat list's order.
  const steps: readonly RunTreeStep[] = plan.runTrees ?? [{ runId: "", objects: plan.runTreeObjects, segs: [] }];
  for (const step of steps) {
    if (stopped || step.segs.some((k) => !segGone.has(k))) {
      n.held += step.objects.length;
      continue;
    }
    for (let i = 0; i < step.objects.length; i++) {
      if (stopped) {
        n.held += step.objects.length - i;
        break;
      }
      const key = step.objects[i]!;
      const r = await del(key);
      tally(r, "tree");
      // The signature is the "segments are done" marker. If it did not go, the rest of this tree stays, so
      // a later pass still sees the marker and opens the run rather than finishing it blind.
      if (!r.gone && key.endsWith(`/${ROOT_SIG_NAME}`)) {
        n.held += step.objects.length - i - 1;
        break;
      }
    }
  }

  const result: PruneApplyResult = { superseded, ...n };
  if (refusedCount(result) > 0 || result.failed > 0) throw new PruneApplyError(firstFault, result, plan.retainedRunIds.length);
  return result;
}

// isAbsent reports whether a key is definitely gone: a HEAD that answers 404 (on a versioned bucket, a key
// whose current version is a delete marker answers 404 too). Any other answer, or a fault, is NOT absent,
// so the caller deletes as planned and lets the delete's own answer decide.
async function isAbsent(dest: Destination, key: string): Promise<boolean> {
  try {
    if (dest.headStatus !== undefined) return (await dest.headStatus(key)) === 404;
    return !(await dest.exists(key));
  } catch {
    return false;
  }
}

// classifyRefusal decides why the store refused ONE delete, by READING rather than guessing. The status of a
// refusal cannot decide it: Amazon S3 answers a policy denial with 403 AccessDenied, and Google Cloud answers
// a delete inside a retention window with a 403 as well. So:
//   - where the destination can read the object's own lock (objectLockHold, the S3 HEAD of its Object Lock
//     headers): a lock that holds now is worm-locked; a read that fails, or that cannot say, is
//     could-not-tell, NEVER a lock; no lock holding, but a refusal whose own error named a lock, is
//     could-not-tell, because the two readings disagree; no lock and a 401/403 is access-denied;
//   - where it cannot (Azure, whose refusal code itself names an immutability policy or legal hold): a
//     refusal whose code names the lock is worm-locked, a 401/403 without one is access-denied;
//   - anything else is could-not-tell.
// readLock false means the per-apply read cap is spent, so the refusal is could-not-tell (it was not read).
async function classifyRefusal(dest: Destination, key: string, e: DestStatusError, readLock: boolean): Promise<"worm-locked" | "access-denied" | "could-not-tell"> {
  const auth = e.status === 401 || e.status === 403;
  if (dest.objectLockHold !== undefined) {
    if (!readLock) return "could-not-tell";
    let hold: Awaited<ReturnType<NonNullable<Destination["objectLockHold"]>>>;
    try {
      hold = await dest.objectLockHold(key);
    } catch {
      hold = "unknown";
    }
    if (hold === "held") return "worm-locked";
    if (hold === "unknown" || e.lockNamed === true) return "could-not-tell";
    return auth ? "access-denied" : "could-not-tell";
  }
  if (e.lockNamed === true) return "worm-locked";
  return auth ? "access-denied" : "could-not-tell";
}

/**
 * PruneApplyError is the typed carrier for an enforced prune that did NOT delete everything it planned: the
 * store refused some deletes, or stopped answering. The supersede is committed; progress carries every count
 * (removed, hidden, refused by class, failed, held). It re-exposes the first store error as `cause` so no
 * existing handler loses information. It carries COUNTS + a WORM boolean only: never a key, an endpoint or
 * the destination's message (the message stays on `cause` for the engine's own log, and is never sealed
 * into the pack).
 */
export class PruneApplyError extends Error {
  readonly progress: PruneApplyResult;
  // wormBlocked is true when at least one refusal was READ as a lock holding the object (refusedLocked > 0).
  readonly wormBlocked: boolean;
  // retainedRuns is the plan's retained-run count, carried so a recording site that catches this error
  // outside the planner's scope can still report it rather than a zero.
  readonly retainedRuns: number;
  constructor(cause: unknown, progress: PruneApplyResult, retainedRuns = 0) {
    super(
      `retention prune apply incomplete after superseding ${progress.superseded} run(s): ${progress.runTreeDeleted + progress.orphansDeleted} object(s) removed, ${hiddenCount(progress)} hidden behind a delete marker, ${refusedCount(progress)} refused, ${progress.failed} failed, ${progress.held} held for a later pass`,
      { cause },
    );
    this.name = "PruneApplyError";
    this.progress = progress;
    this.wormBlocked = progress.refusedLocked > 0;
    this.retainedRuns = retainedRuns;
  }
}

/**
 * pruneObservations maps ONE downpipe's prune pass to the bounded, redaction-safe seal-fault OBSERVE rows the
 * support pack reads ("retention never deletes anything / storage keeps growing"). PURE (no I/O), so
 * the recording site and the validator share one projection and the redaction can never drift.
 *
 * It emits at most three rows, all from the CLOSED SEAL_FAULT_KINDS vocabulary:
 *   - prune-deferred: the planner abstained (a retained run would not open). Carries the CLOSED deferredClass,
 *     the blocking opaque run id, the unreadable count and the unparseable-time count. The planner's free-text
 *     `deferred` sentence is NEVER carried.
 *   - prune-runs-skipped: over-cap runs silently excluded this pass because they could not be read.
 *   - prune-partial-apply: an enforced apply did not delete everything it planned; carries what it removed,
 *     what it only hid behind a delete marker, how many deletes were refused, and the refusal class.
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
    const cls = dominantRefusalClass(failure.progress);
    out.push({
      kind: "prune-partial-apply",
      at,
      downpipeId: plan.downpipeId,
      superseded: failure.progress.superseded,
      // reclaimed counts only what the store REMOVED; a delete marker is counted in hidden, not here.
      reclaimed: failure.progress.runTreeDeleted + failure.progress.orphansDeleted,
      hidden: hiddenCount(failure.progress),
      refused: refusedCount(failure.progress),
      partial: true,
      wormBlocked: failure.wormBlocked,
      ...(cls !== undefined ? { wormRefusalClass: cls } : {}),
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
 * It posts through the SHARED postSealFault chokepoint, so a retention observation lost to a
 * scheduler-DO outage (or to a drifted kind) is COUNTED and self-reported into the ring as an "observe-dropped"
 * record, rather than vanishing into an absence that reads exactly like a healthy retention pass.
 */
export async function postPruneObservations(scheduler: DurableObjectStub, plan: PrunePlan, at: number, failure?: PruneApplyError): Promise<void> {
  for (const fault of pruneObservations(plan, at, failure)) {
    await postSealFault(scheduler, fault as unknown as SealFaultPost);
  }
}
