// The per-destination retention-prune SIDECAR (B61): the destination-grain projection of a
// RetentionPassRecord, joined into the DestinationStatus view (DestStatusView.lastPrune) so a customer
// can see that pruning ran against a destination, what it last reclaimed, and why it last did nothing.
// Each row holds TWO halves so a deferral never erases the last reclaim: lastApplied (the most recent
// pass that actually deleted here) and lastOutcome (what the most recent pass concluded, whatever that
// was). Both callers of POST /retention-record feed it: the cron pass (cron/retention-pass.ts) and the
// Attended route (admin/router-retention-prune.ts).
//
// PURE (no I/O), like pruneObservations: the DO's write boundary and the validators share the one fold,
// so the projection can never drift between them. Vocabularies are REUSED, never minted: the outcome is
// RETENTION_OUTCOMES, the defer class is PruneDeferClass, and both are membership-checked again here
// (defence in depth on top of sanitiseRetentionPassRecord) with a drifted defer class coarsened to
// "other". Counts only, clamped under the record's own ceiling; no free text, no run ids, no object keys.

import { PRUNE_DEFER_CLASSES, type PruneDeferClass } from "../seal/seal-faults.ts";
import { clampRetentionAt, clampRetentionInt, RETENTION_OUTCOMES, type RetentionDownpipeOutcome, type RetentionOutcome, type RetentionPassRecord } from "./retention-record.ts";

// DestPruneApplied is the RECLAIM half: the most recent pass that actually applied deletions against
// this destination. reclaimed counts OBJECTS (run-tree objects + orphaned segments), never bytes: the
// planner deliberately reads no object bodies (prunePlannerInputs), so a byte total does not exist.
export interface DestPruneApplied {
  readonly at: number;
  readonly reclaimed: number;
  readonly supersededRuns: number;
}

// DestPruneOutcome is the OUTCOME half: what the most recent pass over this destination concluded.
// deferClass rides only on a deferred outcome; wormBlocked marks a pass in which WORM/Object-Lock
// refused the deletes (the same posture deleteProbe:"denied" reports from the other side).
export interface DestPruneOutcome {
  readonly at: number;
  readonly outcome: RetentionOutcome;
  readonly deferClass?: PruneDeferClass;
  readonly wormBlocked?: boolean;
}

// DestPruneState is one destination's sidecar row: both halves. A row with no lastApplied has never had
// an applied pass recorded (the field appears from the first pass after deploy; there is no backfill).
export interface DestPruneState {
  readonly lastApplied?: DestPruneApplied;
  readonly lastOutcome: DestPruneOutcome;
}

// DEST_PRUNE_MAP_MAX bounds the stored map (the RECONCILE_SIGNAL_MAX discipline): destination ids churn
// over an estate's life, so without a cap removed destinations' rows would accumulate unbounded.
export const DEST_PRUNE_MAP_MAX = 32;

// DEST_PRUNE_KEY_MAX mirrors the record sanitiser's own id bound (RETENTION_ID_MAX), re-applied here
// because the fold is exported pure and must bound its keys even off an unsanitised input.
const DEST_PRUNE_KEY_MAX = 128;

// DEST_PRUNE_SEVERITY orders the destination-grain coarsening of a pass's downpipe outcomes, most
// attention-needing first: a destination with one errored and one applied downpipe reads "error" (the
// reclaim is preserved in lastApplied, so nothing is hidden by the choice), and only a destination whose
// every retention downpipe is paused reads "paused".
const DEST_PRUNE_SEVERITY: readonly RetentionOutcome[] = ["error", "deferred", "dry-run", "applied", "no-op", "paused"];

// destOutcomeOf coarsens ONE destination's downpipe rows for one pass into the row's outcome half.
// deferClass is carried only when the coarsened outcome IS deferred; rows disagreeing on the class, and
// any class outside the closed PruneDeferClass vocabulary, coarsen to "other" rather than being carried.
function destOutcomeOf(at: number, rows: readonly RetentionDownpipeOutcome[]): DestPruneOutcome {
  const deferSet: ReadonlySet<string> = new Set(PRUNE_DEFER_CLASSES);
  const outcome = DEST_PRUNE_SEVERITY.find((o) => rows.some((r) => r.outcome === o)) ?? rows[0]!.outcome;
  let deferClass: PruneDeferClass | undefined;
  if (outcome === "deferred") {
    const classes = new Set<PruneDeferClass>(
      rows.filter((r) => r.outcome === "deferred").map((r) => (r.deferralClass !== undefined && deferSet.has(r.deferralClass) ? r.deferralClass : "other")),
    );
    deferClass = classes.size === 1 ? [...classes][0]! : "other";
  }
  const wormBlocked = rows.some((r) => r.wormBlocked === true);
  return { at, outcome, ...(deferClass !== undefined ? { deferClass } : {}), ...(wormBlocked ? { wormBlocked: true } : {}) };
}

// foldRetentionRecordIntoDestPrune folds ONE pass record into the sidecar rows, keyed by destination id.
// Aggregation is at DESTINATION grain per record: counts are summed across that destination's downpipe
// rows, so one downpipe's deferral can never overwrite a sibling downpipe's applied result within the
// same pass -- and across passes, lastApplied advances ONLY on a pass that carried an applied outcome,
// so a later deferral never erases the last reclaim.
//
// The default slot "" is resolved to defaultDestId (the CURRENT console default), so a pinned prune and a
// default-routed prune of the same bucket share one row; an estate with no console destination passes ""
// and the row stays under "" (the env-configured fallback the singular dest-status view joins). A row
// with no destKey at all (an older caller) cannot be attributed and is skipped, never guessed. A skipped
// destination (a record row with a skip code and no downpipe outcomes) updates nothing: its sidecar row
// keeps the last real outcome at its honest timestamp.
export function foldRetentionRecordIntoDestPrune(
  prior: Readonly<Record<string, DestPruneState>>,
  rec: RetentionPassRecord,
  defaultDestId: string,
): Record<string, DestPruneState> {
  const outcomeSet: ReadonlySet<string> = new Set(RETENTION_OUTCOMES);
  // The timestamp clamp, not the count clamp: both halves' `at` fields render as dates.
  const at = clampRetentionAt(rec.at);
  const byDest = new Map<string, RetentionDownpipeOutcome[]>();
  for (const d of rec.downpipes) {
    if (typeof d.destKey !== "string" || !outcomeSet.has(d.outcome)) continue;
    const key = (d.destKey === "" ? defaultDestId : d.destKey).slice(0, DEST_PRUNE_KEY_MAX);
    (byDest.get(key) ?? byDest.set(key, []).get(key)!).push(d);
  }
  const next: Record<string, DestPruneState> = { ...prior };
  for (const [key, rows] of byDest) {
    let reclaimed = 0;
    let superseded = 0;
    let appliedSeen = false;
    for (const r of rows) {
      if (r.outcome !== "applied") continue;
      appliedSeen = true;
      reclaimed += clampRetentionInt(r.runTreeObjects) + clampRetentionInt(r.orphanSegs);
      superseded += clampRetentionInt(r.supersededRuns);
    }
    const lastApplied = appliedSeen ? { at, reclaimed: clampRetentionInt(reclaimed), supersededRuns: clampRetentionInt(superseded) } : next[key]?.lastApplied;
    next[key] = { ...(lastApplied !== undefined ? { lastApplied } : {}), lastOutcome: destOutcomeOf(at, rows) };
  }
  return next;
}

// boundDestPruneMap keeps the DEST_PRUNE_MAP_MAX freshest rows (by lastOutcome.at, oldest evicted) and
// reports how many were dropped, so the DO write boundary can count the eviction (dest-prune-map) the
// way the reconcile signal map does. Pure; the caller owns the storage write.
export function boundDestPruneMap(map: Record<string, DestPruneState>): { map: Record<string, DestPruneState>; evicted: number } {
  const keys = Object.keys(map);
  if (keys.length <= DEST_PRUNE_MAP_MAX) return { map, evicted: 0 };
  const drop = keys.sort((a, b) => map[a]!.lastOutcome.at - map[b]!.lastOutcome.at).slice(0, keys.length - DEST_PRUNE_MAP_MAX);
  const out = { ...map };
  for (const k of drop) delete out[k];
  return { map: out, evicted: drop.length };
}
