// The retention-prune PASS RECORD: its closed vocabularies, its bounded record shape, the two classifiers
// that coarsen free text into an enum, and the pure sanitiser that is the single redaction chokepoint (gaps
// G071/G190).
//
// This is a LEAF module by design. The record is written by the cron (cron/retention-pass.ts), re-sanitised
// and persisted by the scheduler DO (sched/scheduler-do-observability.ts), and projected into the support pack
// (admin/support-sections-seal.ts). If the shape lived in the cron pass, the DO's type-only import of it would
// drag the cron's whole graph (which reaches admin/router.ts) into the DO base and close an import cycle. It
// imports nothing, so all three layers can agree on one vocabulary with no cycle.
//
// Everything here is a CLOSED ENUM, a COUNT or a boolean, plus the customer's own opaque downpipe/destination
// ids (the same class runs[]/replication already carry). The planner's deferral string and every caught
// exception are coarsened to an enum at the recording site: no message, object key, selector or value ever
// reaches the record.

// RETENTION_SKIP_CODES: why a prune did not even get to plan. The first two are WHOLE-PASS skips (no
// OPERATIONAL_PRIVATE; the pass keys would not load); the rest are per-destination.
export const RETENTION_SKIP_CODES = [
  "break-glass-only", // no in-account operational key: manifests cannot be decrypted, so the prune defers to the offline reader
  "keys-unavailable", // SIGNER_PRIVATE / the operational identity would not load this tick
  "dest-not-configured", // a downpipe pins a destination the DO holds no config for
  "dest-build-failed", // the destination config resolved but the client would not build (credentials, wrap key)
  "runlog-absent", // the bucket has no _RECOVERY/RUNLOG: nothing finalised here yet
  "runlog-unreadable", // the RUNLOG exists but would not read/parse (integrity-grade: prunes stop until it does)
] as const;
export type RetentionSkipCode = (typeof RETENTION_SKIP_CODES)[number];

// RETENTION_OUTCOMES: what happened to ONE downpipe's prune this tick.
export const RETENTION_OUTCOMES = [
  "applied", // enforce===true and the plan was committed (counts carried alongside)
  "dry-run", // a plan exists but retention.enforce is not true: nothing was written or deleted
  "no-op", // enforced, but no run falls outside the window (idempotent second pass)
  "deferred", // the planner ABSTAINED (see RETENTION_DEFERRAL_CLASSES): delete sets empty, retried next tick
  "error", // the per-downpipe prune threw and was swallowed by the fail-open guard
  // PAUSE MEANS PAUSE (RL-RETENTION-PRUNES-A-PAUSED-DOWNPIPE): the downpipe is PAUSED (config.enabled
  // false), so the cron pass did not plan and did not delete. The row exists rather than the downpipe
  // simply being absent, because "retention deliberately left this alone because you paused it" and
  // "retention silently did nothing" are two different sentences and support must be able to tell them
  // apart. An ATTENDED prune (the dual-controlled route) is unaffected and still deletes.
  "paused",
] as const;
export type RetentionOutcome = (typeof RETENTION_OUTCOMES)[number];

// RETENTION_DEFERRAL_CLASSES: the closed class of a planner abstention. The planner's own `deferred` field is
// operator-facing FREE TEXT and must never ride the pack; classifyDeferral maps it to a member here. A
// perpetually deferring downpipe (the "retention never deletes anything" ticket) is then visible as a class,
// not a string.
export const RETENTION_DEFERRAL_CLASSES = [
  "retained-run-unreadable", // a RETAINED run could not be enumerated, so segment GC would be unsafe
  "other", // an abstention this engine's classifier does not yet name (never the raw text)
] as const;
export type RetentionDeferralClass = (typeof RETENTION_DEFERRAL_CLASSES)[number];

// RETENTION_ERROR_CLASSES: the closed class of a per-downpipe prune throw (the fail-open guard's catch).
export const RETENTION_ERROR_CLASSES = [
  "lock-contention", // the RUNLOG lock was not acquired (a concurrent seal to the same destination)
  "runlog-unreadable", // the RUNLOG could not be read/verified during the apply
  "run-unreadable", // a run's manifest/segment could not be opened (a missing or corrupt object)
  "dest-write-failed", // a supersede re-sign or a delete was refused by the destination
  "other",
] as const;
export type RetentionErrorClass = (typeof RETENTION_ERROR_CLASSES)[number];

// RETENTION_INT_MAX / caps bound every posted count and array so a malformed value can never bloat the
// record (the same abuse ceiling the seal-fault ring uses).
const RETENTION_INT_MAX = 1_000_000_000;
const RETENTION_DEST_CAP = 16;
const RETENTION_DOWNPIPE_CAP = 64;
const RETENTION_ID_MAX = 128;

// RetentionDestOutcome is ONE destination bucket's pass outcome: the customer's own opaque destination key
// ("" = the default), how many retention downpipes write to it, and a closed skip code when the bucket was
// skipped whole.
export interface RetentionDestOutcome {
  readonly destKey: string;
  readonly downpipeCount: number;
  readonly skipCode?: RetentionSkipCode;
}

// RetentionDownpipeOutcome is ONE downpipe's prune outcome: a closed outcome, the closed deferral/error class
// when it deferred or threw, and clamped counts. Counts only, never an object key.
export interface RetentionDownpipeOutcome {
  readonly id: string;
  // destKey is the destination bucket this downpipe's prune ran against ("" = the default), the same
  // opaque id class destinations[] already carries. Without it the per-destination fold (B61,
  // retention-dest-prune.ts) could not attribute a downpipe row to its bucket: the record's downpipes[]
  // and destinations[] arrays carry no join between them.
  readonly destKey?: string;
  readonly outcome: RetentionOutcome;
  readonly deferralClass?: RetentionDeferralClass;
  readonly errorClass?: RetentionErrorClass;
  // wormBlocked marks an error outcome whose apply died because WORM/Object-Lock REFUSED the deletes (an
  // irreducible remainder, not a transient flake) -- the same boolean PruneApplyError already carries into
  // the fault ring; here it reaches the per-destination fold so the console can name the posture (B61).
  readonly wormBlocked?: boolean;
  readonly supersededRuns: number; // runs marked superseded (planned, or applied when outcome==="applied")
  readonly runTreeObjects: number; // run-tree objects planned/deleted
  readonly orphanSegs: number; // orphaned segments planned/deleted
  readonly retainedRuns: number; // runs the policy keeps
  readonly volumeHeld?: number; // runs the volume guard HELD from eviction (an emptied/shrunken source)
}

// RetentionPassRecord is the whole pass in one bounded record. auditWriteFailures makes a LOST prune audit
// (an applied prune whose audit write failed, so the chain never shows the deletion) reconstructable.
export interface RetentionPassRecord {
  readonly at: number;
  // attended marks a record posted by the attended prune route (admin/router-retention-prune.ts),
  // which prunes ONE downpipe on an operator's action rather than the whole fleet on the cron. The DO
  // folds an attended record into the per-destination sidecar (B61) exactly like a cron record, but never
  // lets it supersede the latest CRON pass slot: a single-downpipe pass must not read as a whole tick.
  readonly attended?: boolean;
  readonly downpipesWithRetention: number;
  // How many of those the pass did not touch because the downpipe is PAUSED. Reading
  // downpipesWithRetention alone made a pass that pruned nothing look identical whether it had nothing
  // to delete or had been told to stop; this is the difference, as a count.
  readonly downpipesPaused: number;
  readonly replicationUnreadable: boolean; // the M7 coverage gate ran on NO proof, so every replicated run was held
  readonly auditWriteFailures: number;
  readonly passSkipCode?: RetentionSkipCode; // set when the WHOLE pass skipped before any destination ran
  readonly destinations: readonly RetentionDestOutcome[];
  readonly downpipes: readonly RetentionDownpipeOutcome[];
}

// Exported so the per-destination fold (retention-dest-prune.ts) clamps with the SAME ceiling rather than
// a copy that could drift.
export function clampRetentionInt(v: number): number {
  return Number.isFinite(v) && v >= 0 ? Math.min(Math.floor(v), RETENTION_INT_MAX) : 0;
}

// clampRetentionAt bounds a TIMESTAMP: a non-negative integer up to MAX_SAFE_INTEGER. It is deliberately a
// SEPARATE clamp from clampRetentionInt: the count clamp's RETENTION_INT_MAX ceiling (1e9) sits far below
// epoch milliseconds, and running a timestamp through it would crush every stored pass record's `at` to a
// date near the epoch -- a fault that matters the moment a value renders as a date on a customer-readable
// surface (lastApplied.at).
export function clampRetentionAt(v: number): number {
  return Number.isFinite(v) && v >= 0 ? Math.min(Math.floor(v), Number.MAX_SAFE_INTEGER) : 0;
}

// classifyDeferral coarsens the planner's operator-facing deferral TEXT into a closed class. It matches the
// engine's own literal ("a retained run could not be read..."), and returns an enum member: the text itself
// is never returned, stored or posted.
export function classifyDeferral(reason: string): RetentionDeferralClass {
  return /^a retained run could not be read/.test(reason) ? "retained-run-unreadable" : "other";
}

// classifyPruneError coarsens a caught per-downpipe prune exception into a closed class. It reads the message
// ONLY to choose the class (the same idiom isWormRefusal uses on a destination-delete refusal) and returns an
// enum member; the message, the object key it names and any store error text never leave this function.
export function classifyPruneError(e: unknown): RetentionErrorClass {
  const m = e instanceof Error ? e.message : "";
  if (/lock|contend|contention/i.test(m)) return "lock-contention";
  if (/runlog/i.test(m)) return "runlog-unreadable";
  if (/is missing|could not be read|manifest|verif|decrypt|segment/i.test(m)) return "run-unreadable";
  // `\bput\b`, not `put ` with a trailing space. The literal space was doing two wrong things at once. It
  // MISSED the common shapes -- a native binding throws "put: <reason>" and an S3 leg writes "PUT seg/0001:
  // status 400", both of which fall past every branch to `other`, so a destination write failure was reported
  // as an unclassified fault and the retention pass lost the one label that says where to look. And it
  // MATCHED the substring in "input ", so a message like "invalid input value" classed as a destination write
  // failure that never happened. A word boundary on both sides fixes both directions: "input" no longer
  // matches (the p is preceded by a word character), while "put:", "put," and "PUT seg/0001" all do.
  if (/delete|\bput\b|write|refus|denied|forbidden/i.test(m)) return "dest-write-failed";
  return "other";
}

// sanitiseRetentionPassRecord bounds + clamps the accumulated pass into the posted record: closed enums are
// re-checked (defence in depth: a drifted internal value is DROPPED, never persisted), every count is clamped
// non-negative, ids are length-bounded, and the arrays are capped. PURE, exported, so the validator pins the
// exact redaction the pass posts.
export function sanitiseRetentionPassRecord(rec: RetentionPassRecord): RetentionPassRecord {
  const skipSet: ReadonlySet<string> = new Set(RETENTION_SKIP_CODES);
  const outcomeSet: ReadonlySet<string> = new Set(RETENTION_OUTCOMES);
  const deferralSet: ReadonlySet<string> = new Set(RETENTION_DEFERRAL_CLASSES);
  const errorSet: ReadonlySet<string> = new Set(RETENTION_ERROR_CLASSES);
  return {
    at: clampRetentionAt(rec.at),
    ...(rec.attended === true ? { attended: true } : {}),
    downpipesWithRetention: clampRetentionInt(rec.downpipesWithRetention),
    downpipesPaused: clampRetentionInt(rec.downpipesPaused),
    replicationUnreadable: rec.replicationUnreadable === true,
    auditWriteFailures: clampRetentionInt(rec.auditWriteFailures),
    ...(rec.passSkipCode !== undefined && skipSet.has(rec.passSkipCode) ? { passSkipCode: rec.passSkipCode } : {}),
    destinations: rec.destinations.slice(0, RETENTION_DEST_CAP).map((d) => ({
      destKey: d.destKey.slice(0, RETENTION_ID_MAX),
      downpipeCount: clampRetentionInt(d.downpipeCount),
      ...(d.skipCode !== undefined && skipSet.has(d.skipCode) ? { skipCode: d.skipCode } : {}),
    })),
    downpipes: rec.downpipes
      .filter((d) => outcomeSet.has(d.outcome))
      .slice(0, RETENTION_DOWNPIPE_CAP)
      .map((d) => ({
        id: d.id.slice(0, RETENTION_ID_MAX),
        ...(typeof d.destKey === "string" ? { destKey: d.destKey.slice(0, RETENTION_ID_MAX) } : {}),
        outcome: d.outcome,
        ...(d.deferralClass !== undefined && deferralSet.has(d.deferralClass) ? { deferralClass: d.deferralClass } : {}),
        ...(d.errorClass !== undefined && errorSet.has(d.errorClass) ? { errorClass: d.errorClass } : {}),
        ...(d.wormBlocked === true ? { wormBlocked: true } : {}),
        supersededRuns: clampRetentionInt(d.supersededRuns),
        runTreeObjects: clampRetentionInt(d.runTreeObjects),
        orphanSegs: clampRetentionInt(d.orphanSegs),
        retainedRuns: clampRetentionInt(d.retainedRuns),
        ...(d.volumeHeld !== undefined ? { volumeHeld: clampRetentionInt(d.volumeHeld) } : {}),
      })),
  };
}

