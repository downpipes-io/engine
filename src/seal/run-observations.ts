// RUN OBSERVATIONS -- the isolate-local ledger for the seal-path evidence that is DETECTED deep inside pure
// code (a record seal, a slice, a fan-out plan, the RUNLOG lock ladder) where no scheduler DO stub exists
// (gaps G065, G066, G189, G222).
//
// WHY A LEDGER AND NOT A DIRECT POST. seal/record.ts, seal/slice.ts, seal/fanout.ts and seal/pipeline.ts are
// the hot, pure, injectable core of the seal: they take a Destination and a budget, not a DurableObjectStub,
// and threading one through them to observe a fault would be exactly the coupling their design refuses. So they
// NOTE into this module (a plain, bounded, in-memory tally), and the ONE place a crawl already ends -- the
// run-fault reporter (seal/run-fault-report.ts), which holds the scheduler stub and the downpipe id -- DRAINS
// it and posts it to the seal-fault ring. This is the source-fault-ledger seam, verbatim.
//
// The ledger is ISOLATE-LOCAL and RESET at every crawl start (beginRunObservations), for the same reason the
// source ledger is: a Workers isolate is warm and serves many runs, and a mis-attributed fault (this downpipe's
// evidence stamped on the next downpipe's run) is worse than a missing one.
//
// NO-CUSTODY (binding). Every field is a CLOSED enum, a COUNT or a one-way HANDLE:
//   - the skip CAUSE is a member of SKIP_CAUSES; a record NAME never enters -- the caller passes the
//     `h:<12 hex>` handle seal/marker.ts safeMarkerAttribution already produces (a SHA-384 prefix of the name),
//     and this module holds nothing else about the record;
//   - the stranding class is a member of STRAND_CLASSES and carries an integer count;
//   - the seal mode is a pair of SEAL_MODES members plus a small range count;
//   - the lock-plane fields are pure counters.
// No message, key, object name, bucket, endpoint or value can be stored here, because there is no field that
// could hold one.

import type { FanoutDowngradeReason, SealFaultKind, SealMode, SkipCause, StrandClass } from "./seal-faults.ts";

// The per-cause skip tally, the capped handle list, and the counters. Bounded in every dimension.
const HANDLES_MAX = 25;
const COUNT_CAP = 1_000_000_000;
// COMPLETENESS_MAX bounds the refuse-to-sign note list (G108). A run refuses ONCE (the guard throws), so one
// entry is the real case; the cap is the abuse ceiling.
const COMPLETENESS_MAX = 8;

// CompletenessKind is the subset of SEAL_FAULT_KINDS a REFUSE-TO-SIGN completeness guard raises (G108). Each
// carries the two integer counts the guard already computed, so a run that produced NO ARCHIVE can finally be
// sized: found-vs-expected shards, merged-vs-declared records, encountered-vs-counted keys.
export type CompletenessKind = Extract<
  SealFaultKind,
  "scratch-shard-missing" | "scratch-hash-mismatch" | "scratch-preamble-mismatch" | "merge-count-mismatch" | "under-crawl" | "open-shard-count-mismatch" | "open-batch-missing"
>;

/** One refuse-to-sign observation (G108): a closed kind, two counts, and (for a scratch-shard fault) the
 * shard's ORDINAL position in the merge order. Never a shard id, an object key or a message. */
export interface CompletenessNote {
  kind: CompletenessKind;
  found: number;
  expected: number;
  ordinal?: number;
}

/** The drained, redaction-safe snapshot of one crawl's observations. Enums, counts and hex handles only. */
export interface RunObservations {
  /** G065: {closed skip cause -> count} for records skipped as changed-mid-crawl. */
  skipsByCause: Partial<Record<SkipCause, number>>;
  /** G065: up to 25 one-way `h:<12 hex>` handles of the skipped records. Never an object name. */
  skipHandles: string[];
  /** G065: partial (mid-record) seals ABANDONED, whose already-written segments are orphaned. */
  partialsAbandoned: number;
  /** G066: {closed stranding class -> count} of destination objects/parts the engine stranded. */
  strandsByClass: Partial<Record<StrandClass, number>>;
  /** G189: the seal mode the downpipe REQUESTED and the mode the run actually ran in. */
  sealMode?: { requested: SealMode; effective: SealMode; ranges?: number; downgradeReason?: FanoutDowngradeReason; underCrawlChecked?: boolean; budgetOverrideForced?: boolean };
  /** G222: the RUNLOG lock / CAS plane counters. A blip here is a SCHEDULER-plane fault, not a destination one. */
  lock: { acquireFaults: number; windowExhausted: number; casExhausted: number; sigPublishSkipped: number; releaseFaults: number };
  /** G108: the REFUSE-TO-SIGN completeness guards' counts. A run that produced no archive at all: until now
   * these integers existed only inside a raw thrown message that coarsened to a generic failed run row. */
  completeness: CompletenessNote[];
  /** G283: the destination's RUNLOG was ABSENT while this downpipe has prior runs on it, so the signed root
   * chained onto nothing (prevRunId=null) and the history silently restarted. `priorRuns` is the run index
   * the engine expected to find. Absent = the RUNLOG was present (or this is a genuine first run). */
  runlogAbsent?: { priorRuns: number };
}

function empty(): RunObservations {
  return {
    skipsByCause: {},
    skipHandles: [],
    partialsAbandoned: 0,
    strandsByClass: {},
    lock: { acquireFaults: 0, windowExhausted: 0, casExhausted: 0, sigPublishSkipped: 0, releaseFaults: 0 },
    completeness: [],
  };
}

let ledger: RunObservations = empty();

/** beginRunObservations clears the ledger at the start of a crawl, so a warm isolate never attributes one
 * downpipe's skips, strandings or lock faults to the next downpipe's run. */
export function beginRunObservations(): void {
  ledger = empty();
}

/**
 * noteSkippedChanged records ONE record skipped as changed-mid-crawl (G065). The CAUSE is what makes a
 * persistent infra fault (a 403/timeout on the resume range-read, a short read) distinguishable from ordinary
 * content churn -- today they are the same aggregate counter, so "the restore is missing object X" has no
 * diagnosis at all.
 *
 * @param cause - the closed cause.
 * @param handle - the one-way `h:<12 hex>` attribution handle (seal/marker.ts safeMarkerAttribution). Omitted
 *   when the caller has none; a RAW record name must NEVER be passed here (the sanitiser would drop it, and the
 *   name must not even reach this process boundary).
 */
export function noteSkippedChanged(cause: SkipCause, handle?: string): void {
  ledger.skipsByCause[cause] = Math.min(COUNT_CAP, (ledger.skipsByCause[cause] ?? 0) + 1);
  if (handle !== undefined && /^h:[0-9a-f]{12}$/.test(handle) && ledger.skipHandles.length < HANDLES_MAX && !ledger.skipHandles.includes(handle)) {
    ledger.skipHandles.push(handle);
  }
}

/** notePartialAbandoned records a multi-GiB partial seal the slice ABANDONED (G065): its already-written
 * segments are orphaned, and nothing anywhere recorded that the abandonment happened. */
export function notePartialAbandoned(): void {
  ledger.partialsAbandoned = Math.min(COUNT_CAP, ledger.partialsAbandoned + 1);
}

/** noteStranded records destination bytes the engine stranded (G066): a scratch shard whose delete failed, a
 * leaked run-tree, unreclaimed multipart parts. A COUNT, never a boolean, and never a key. */
export function noteStranded(cls: StrandClass, n = 1): void {
  if (!Number.isFinite(n) || n <= 0) return;
  ledger.strandsByClass[cls] = Math.min(COUNT_CAP, (ledger.strandsByClass[cls] ?? 0) + Math.floor(n));
}

/** noteSealMode records the run's REQUESTED vs EFFECTIVE seal mode (G189): the silent fan-out-to-serial
 * downgrade that leaves a customer's "parallel" backup taking days with no evidence anywhere. */
export function noteSealMode(m: NonNullable<RunObservations["sealMode"]>): void {
  ledger.sealMode = m;
}

/** noteLockPlane bumps one RUNLOG lock / CAS plane counter (G222). These faults coarsen to the DESTINATION
 * error class today, so a scheduler-DO hiccup sends support to investigate a perfectly healthy bucket. */
export function noteLockPlane(k: keyof RunObservations["lock"], n = 1): void {
  if (!Number.isFinite(n) || n <= 0) return;
  ledger.lock[k] = Math.min(COUNT_CAP, ledger.lock[k] + Math.floor(n));
}

/**
 * noteCompleteness records ONE refuse-to-sign completeness guard (G108). The guard's DECISION is unchanged --
 * it still throws and the run still fails closed -- this only preserves the two counts it already computed, so
 * support can size the shortfall (found vs expected) and tell tamper (a hash mismatch) from lifecycle eviction
 * (a missing object) from a real under-crawl. Bounded; counts are clamped non-negative integers.
 *
 * @param kind - the closed guard kind.
 * @param found - what the guard actually got.
 * @param expected - what the run declared it should have.
 * @param ordinal - for a scratch-shard fault, its position in the merge order (never the shard id).
 */
export function noteCompleteness(kind: CompletenessKind, found: number, expected: number, ordinal?: number): void {
  if (ledger.completeness.length >= COMPLETENESS_MAX) return;
  const clamp = (n: number): number => (Number.isFinite(n) && n >= 0 ? Math.min(COUNT_CAP, Math.floor(n)) : 0);
  ledger.completeness.push({ kind, found: clamp(found), expected: clamp(expected), ...(ordinal !== undefined ? { ordinal: clamp(ordinal) } : {}) });
}

/** noteRunlogAbsent records that the destination's RUNLOG was ABSENT while this downpipe has PRIOR runs on it
 * (G283): the signed root then carries prevRunId=null and the history chain silently restarts, which is what a
 * downpipe repointed at a re-created or wrong bucket looks like. A single non-negative integer. */
export function noteRunlogAbsent(priorRuns: number): void {
  if (!Number.isFinite(priorRuns) || priorRuns <= 0) return; // index 0 IS a genuine first run: not evidence
  ledger.runlogAbsent = { priorRuns: Math.min(COUNT_CAP, Math.floor(priorRuns)) };
}

/** isEmptyRunObservations reports whether a crawl observed nothing at all: the healthy steady state, which
 * posts no record and costs no subrequest. A recorded seal MODE alone is not a fault, but it IS evidence (the
 * silent-downgrade case is exactly a run that otherwise looks clean), so it counts. */
export function isEmptyRunObservations(o: RunObservations): boolean {
  return (
    Object.keys(o.skipsByCause).length === 0 &&
    o.partialsAbandoned === 0 &&
    Object.keys(o.strandsByClass).length === 0 &&
    o.sealMode === undefined &&
    o.lock.acquireFaults === 0 &&
    o.lock.windowExhausted === 0 &&
    o.lock.casExhausted === 0 &&
    o.lock.sigPublishSkipped === 0 &&
    o.lock.releaseFaults === 0 &&
    o.completeness.length === 0 &&
    o.runlogAbsent === undefined
  );
}

/** drainRunObservations returns the ledger and RESETS it, so the reporter empties it exactly once per crawl. */
export function drainRunObservations(): RunObservations {
  const out = ledger;
  ledger = empty();
  return out;
}

/** runObservations is the read-only peek the validators use to assert a site recorded what it should. */
export function runObservations(): RunObservations {
  return ledger;
}
