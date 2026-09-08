import { type CfOp, type Meter, type OpCounts, zeroOpCounts } from "../meter.ts";

export type { Meter, OpCounts } from "../meter.ts";

// SliceBudget bounds one invocation's share of the Workers platform limits so a large
// run yields cleanly instead of dying on them (design F13). The two limits that actually
// kill a seal are the per-invocation subrequest cap (every KV get, R2 get/put, S3 fetch
// and DO fetch counts toward it) and the CPU/wall clock. The budget is spent by the
// sources, the destination and the pipeline as they work; when it is low the slice
// checkpoints and hands the run to the next invocation, which starts a fresh budget.
//
// The defaults are deliberately conservative: the platform cap is 1000 subrequests on a
// paid plan, and a cron invocation also spends on the scheduler DO, the notification
// passes and any other due downpipes, so a slice never assumes it owns the whole cap.
// Finalisation (root manifest + signature + recovery bundle + RUNLOG read-append-write
// with retries) needs headroom, reserved via FINALISE_RESERVE.

export const DEFAULT_SLICE_SUBREQUESTS = 700;
export const DEFAULT_SLICE_WALL_MS = 20_000;

// FINALISE_RESERVE is the subrequest headroom finalisation needs, derived from the
// named worst-case sub-terms of the actual code paths so an edit to a retry count
// cannot silently break the arithmetic:
//  - the final empty-shard flush + root manifest + signature + 4 recovery-bundle
//    objects, each destination put retried up to 3 attempts (withRetry): 7 * 3 = 21;
//  - the RUNLOG append loop: up to 6 contended rounds of read + conditional put
//    (the re-read and the .sig put happen once, on the successful round): 6*2 + 2 = 14;
//  - the runlog lock: up to 3 contended acquire attempts + 1 release = 4;
//  - the /complete DO fetch: 1.
const FINALISE_DEST_PUTS = 7 * 3;
const FINALISE_RUNLOG_OPS = 6 * 2 + 2;
const FINALISE_LOCK_OPS = 4;
const FINALISE_COMPLETE = 1;
export const FINALISE_RESERVE = FINALISE_DEST_PUTS + FINALISE_RUNLOG_OPS + FINALISE_LOCK_OPS + FINALISE_COMPLETE;

// MAX_SLICE_SUBREQUESTS clamps the SCALE_SLICE_SUBREQUESTS knob: past ~940 the yield
// signal (remaining <= FINALISE_RESERVE) could fire only after the platform's 1000-cap
// had already killed the invocation, and a cap death persists NO checkpoint progress,
// so an over-set knob would convert "large run" into "permanently unfinishable run"
// (each alarm repeats the same slice until MAX_SLICE_FAILURES resolves it failed).
export const MAX_SLICE_SUBREQUESTS = 940;

// FREE_PLAN_SUBREQUEST_CEILING is Cloudflare's per-invocation subrequest cap on the FREE Workers plan
// (50), a well-documented platform limit. It is the OBSERVE-side anchor for SCHED free-plan-subrequest-cap:
// the plan TIER itself is not runtime-readable (a Worker cannot query its own account plan), but the engine's
// default slice budget (DEFAULT_SLICE_SUBREQUESTS 700) and ceiling (MAX_SLICE_SUBREQUESTS 940) both ASSUME a
// PAID plan (1000 cap). On a free plan a run is killed at this 50-subrequest ceiling -- before the slice budget
// can yield-and-checkpoint -- so "large backups never finish" with nothing in a run-history row to explain it.
// The pack cross-checks two runtime-readable facts against this constant (see support.ts planTier): whether the
// RESOLVED slice budget exceeds it (a free account would die at the cap), and whether any recorded cron tick has
// PROVABLY spent MORE than it and survived (a survived-past-50 tick can only happen on a paid plan → paid proof).
export const FREE_PLAN_SUBREQUEST_CEILING = 50;

// MAX_SLICE_WALL_MS clamps the SCALE_SLICE_WALL_MS knob well inside the deployed
// [limits] cpu_ms (300000): sealing hashes and encrypts every byte twice, and a CPU
// kill is not catchable (the alarm's catch never runs, the attempt counter never
// advances, and the run wedges until lease reclaim repeats the loop).
export const MAX_SLICE_WALL_MS = 120_000;

// LOW_SLICE_WALL_MS is the "unusually low" floor for the RESOLVED per-slice WALL budget (INFRA
// cpu-ms-misconfigured-low). A slice that yields after less than a QUARTER of the default (5s of a 20s
// default) can seal only a handful of records before checkpointing, so a large run makes almost no progress
// per slice -- the classic symptom of a typo'd SCALE_SLICE_WALL_MS (e.g. "200" meant as "20000") or a deployed
// [limits] cpu_ms set far below the platform default. It is a HINT, never a clamp: budgetFromEnv still honours
// the operator value; this only lets the pack FLAG a wall budget a run-history row alone cannot explain.
export const LOW_SLICE_WALL_MS = Math.floor(DEFAULT_SLICE_WALL_MS / 4);

// BYTE_RANGE_WINDOW_BYTES is duplicated as a literal here rather than imported from sources/byte-fetch.ts
// to avoid a seal -> sources import; the streamseal validator pins the two to the same value so they
// cannot drift.
const BYTE_RANGE_WINDOW_BYTES = 8 * 1024 * 1024; // mirrors sources/byte-fetch.ts BYTE_RANGE_WINDOW

// MAX_SINGLE_SLICE_RECORD_BYTES is the largest single streamed value that can be sealed WHOLE in ONE
// slice's subrequest budget (the no-resume bound). The two-pass chained seal range-reads every
// BYTE_RANGE_WINDOW window once per pass (address + seal = 2 fetches per window), so the byte fetches alone
// cost ~2 * ceil(size / BYTE_RANGE_WINDOW) subrequests, plus a per-segment exists()+putStream() and the
// finalise reserve. Taking HALF the subrequest cap as the window budget (the other half left for the
// per-segment puts, the source's listing/probe work, the finalise reserve, and the cron's shared spend on
// the scheduler DO and other due downpipes) gives (MAX_SLICE_SUBREQUESTS / 2 windows / 2 passes) *
// BYTE_RANGE_WINDOW. This is the ceiling for a value that CANNOT be mid-record-resumed: a source with no
// stable etag (resume would re-hash possibly-changed bytes and corrupt the record), or when
// SLICED_RUNS_DISABLED removes the resume path. Such a value must complete in one slice or be declined.
export const MAX_SINGLE_SLICE_RECORD_BYTES = Math.floor(MAX_SLICE_SUBREQUESTS / 2 / 2) * BYTE_RANGE_WINDOW_BYTES;

// MAX_SINGLE_RECORD_CONTENT_BYTES is the in-band capture ceiling for a value that CAN be mid-record-resumed
// (PR7): a streamed value with a STABLE ETAG, sealed one window at a time across as many slices as it
// needs. shouldYield() is now checked INSIDE the chained seal (after each window), so the per-invocation
// subrequest cap is no longer the bound (each slice seals only as many windows as fit, then checkpoints).
// The new bound is the prefix RE-HASH: a resume rebuilds the running whole-record SHA-384 by streaming the
// already-sealed prefix [0, offsetSealed) through SHA-384 in ONE subrequest, which is CPU/wall-bound, not
// subrequest-bound. The worst case is the last resume, which re-hashes nearly the whole value; it must
// finish inside one slice's wall budget while leaving room to seal at least one more window.
//
// Derivation (lockstep with the budget constants): give the prefix re-hash HALF of MAX_SLICE_WALL_MS (the
// other half covers sealing the remaining window(s), the source's listing/probe work, and the finalise
// reserve), at a CONSERVATIVE SHA-384 throughput floor. The streaming hash is the pure-JS @noble/hashes
// SHA-512/384 (Web Crypto has no streaming MAC/hash), which sustains well over 100 MiB/s on a Workers V8
// isolate; we floor it at 64 MiB/s (REHASH_BYTES_PER_MS) for a large safety margin against a cold isolate,
// GC pauses and the rest of the slice's CPU. That yields REHASH_BYTES_PER_MS * (MAX_SLICE_WALL_MS / 2) ~=
// 3.66 GiB. The result stays below R2_MAX_SINGLE_PUT (~4.995 GiB), so a captured object also remains
// restorable in-account as a single streamed PUT (the chain reassembles under that limit). An object past
// THIS ceiling, or any non-resumable (no-etag / unknown-size) value past MAX_SINGLE_SLICE_RECORD_BYTES, is
// SKIPPED with a loud incompleteness marker (recordsIncomplete surfaces it; the rest of the backup
// completes), recoverable out of band with the downpipe CLI, instead of wedging the run.
const REHASH_BYTES_PER_MS = 64 * 1024; // 64 MiB/s conservative SHA-384 streaming-hash throughput floor
export const MAX_SINGLE_RECORD_CONTENT_BYTES = REHASH_BYTES_PER_MS * Math.floor(MAX_SLICE_WALL_MS / 2);

export class SliceBudget implements Meter {
  private readonly maxSubrequests: number;
  private readonly maxWallMs: number;
  private readonly startedAt: number;
  private spent = 0;
  // ops is the per-resource subrequest tally (cost Phase 3); spend(n, op) accumulates it alongside the
  // plain subrequest budget, and opCounts() hands it to the slice to fold into the run's running counts.
  private readonly ops: OpCounts = zeroOpCounts();

  constructor(opts?: { subrequests?: number; wallMs?: number }) {
    this.maxSubrequests = opts?.subrequests ?? DEFAULT_SLICE_SUBREQUESTS;
    this.maxWallMs = opts?.wallMs ?? DEFAULT_SLICE_WALL_MS;
    this.startedAt = Date.now();
  }

  spend(n = 1, op?: CfOp): void {
    this.spent += n;
    this.ops.subrequests += n;
    if (op !== undefined) this.ops[op] += n;
  }

  get subrequestsSpent(): number {
    return this.spent;
  }

  // subrequestBudget is the resolved per-invocation subrequest cap this budget was built with (the pack's
  // per-tick outcome ring reports it alongside the spend, so a starved/overdrawn tick is visible).
  get subrequestBudget(): number {
    return this.maxSubrequests;
  }

  // opCounts returns this budget's per-resource subrequest tally (cost Phase 3). A slice merges it into
  // the run's running counts, so a completed run records an exact platform-operation breakdown for the
  // cost estimate. A copy, so the caller cannot mutate the live tally.
  opCounts(): OpCounts {
    return { ...this.ops };
  }

  remaining(): number {
    return Math.max(0, this.maxSubrequests - this.spent);
  }

  // shouldYield is the slice's checkpoint signal: subrequests low (keeping the finalise
  // reserve intact) or the wall clock consumed. It is a soft boundary checked between
  // records, never mid-record, so a record's segments and its manifest line are always
  // committed together.
  shouldYield(): boolean {
    return this.remaining() <= FINALISE_RESERVE || Date.now() - this.startedAt >= this.maxWallMs;
  }

  // canFinalise reports whether finalisation can safely run in THIS invocation.
  canFinalise(): boolean {
    return this.remaining() >= FINALISE_RESERVE;
  }
}

// scaleKnobNum parses one SCALE_* knob string exactly as budgetFromEnv does (a positive finite integer,
// else undefined = "use the default"). Shared by budgetFromEnv and resolveSliceScaleKnobs so the RESOLVED value
// the pack reports can never drift from the value a slice actually runs with.
function scaleKnobNum(v: unknown): number | undefined {
  if (typeof v !== "string" || v.trim() === "") return undefined;
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : undefined;
}

// budgetFromEnv builds a budget from the optional env knobs, falling back to the
// defaults. Invalid values fall back rather than throwing, and over-set values CLAMP
// to the platform-survivable ceilings: a typo'd or optimistic knob must never stop
// backups (the clamps keep the yield signal able to fire before the platform cap).
export function budgetFromEnv(env: { SCALE_SLICE_SUBREQUESTS?: unknown; SCALE_SLICE_WALL_MS?: unknown }, overrides?: { subrequests?: number; wallMs?: number }): SliceBudget {
  const subrequests = overrides?.subrequests ?? scaleKnobNum(env.SCALE_SLICE_SUBREQUESTS);
  const wallMs = overrides?.wallMs ?? scaleKnobNum(env.SCALE_SLICE_WALL_MS);
  return new SliceBudget({
    ...(subrequests !== undefined ? { subrequests: Math.min(subrequests, MAX_SLICE_SUBREQUESTS) } : {}),
    ...(wallMs !== undefined ? { wallMs: Math.min(wallMs, MAX_SLICE_WALL_MS) } : {}),
  });
}

// ResolvedKnob is one SCALE_* slice knob after resolution, for the support pack (INFRA slice-knobs-
// misconfigured / cpu-ms-misconfigured-low; SCHED free-plan-subrequest-cap). It is REDACTION-SAFE by
// construction (two ints + a closed source enum): `resolved` is the value a slice budget actually runs
// with, `ceiling` is the platform-survivable clamp, and `source` says how it was derived:
//   - "default"  : the knob was unset, the built-in default is used;
//   - "env"       : a valid operator value is used as-is;
//   - "clamped"  : an over-set value was clamped DOWN to the ceiling (a slice budget past the ceiling
//                  could be killed at the platform cap before it could yield-and-checkpoint);
//   - "invalid"  : a non-numeric / non-positive value was ignored and the default used (a typo).
// A diagnoser reads "backups silently stalling on this account" against these: an over-low resolved slice
// (e.g. a typo'd tiny SCALE_SLICE_SUBREQUESTS, or a wall budget set far below the deployed cpu_ms) makes
// large runs unable to make progress per slice, which no run-history row alone explains.
export interface ResolvedKnob {
  resolved: number;
  ceiling: number;
  source: KnobSource;
}

// KNOB_SOURCES is the CLOSED four-member vocabulary above, hoisted (gap G169) so EVERY env knob the engine
// resolves can report it -- not just the two SCALE_SLICE_* knobs that shipped with it. The point of the gap:
// an operator who typo'd SCALE_SEGMENT_TARGET_BYTES / DEST_THROTTLE_ATTEMPTS / SEAL_VERIFY_SAMPLE /
// REPL_VERIFY_SEGMENTS / SCALE_FANOUT_RANGES sees the pack report the running DEFAULT with no hint that the
// value they set was REJECTED -- "set but invalid" is indistinguishable from "never set". Never the raw string.
export const KNOB_SOURCES = ["default", "env", "clamped", "invalid"] as const;
export type KnobSource = (typeof KNOB_SOURCES)[number];

// KnobResolution is one env knob's pack-visible resolution: the closed source enum, and (for a numeric knob)
// the value in force plus the ceiling it was clamped against. REDACTION-SAFE by construction: an enum and
// bounded integers. The raw operator string is NEVER carried -- an invalid value is reported ONLY as
// source:"invalid" (the string could be anything, including a pasted secret).
export interface KnobResolution {
  source: KnobSource;
  resolved?: number;
  ceiling?: number;
}

// classifyEnvKnob is the ONE shared numeric-knob classifier (gap G169), mirroring the resolution every knob
// family already performs: unset/blank -> the default; a non-numeric / non-positive value -> "invalid" and the
// default runs; a value over the ceiling -> "clamped" to it; otherwise "env". `positiveOnly` distinguishes the
// SCALE_*/DEST_THROTTLE_* families (which require a POSITIVE value, so 0 is a typo) from the SEAL_VERIFY_*
// family (where 0 is meaningful: "no sample"). PURE: it reads the value's shape, never records or forwards it.
export function classifyEnvKnob(raw: unknown, defaultValue: number, ceiling: number, positiveOnly = true): KnobResolution {
  if (typeof raw !== "string" || raw.trim() === "") return { source: "default", resolved: defaultValue, ceiling };
  const n = Number(raw);
  const floor = positiveOnly ? 1 : 0;
  if (!Number.isFinite(n) || n < floor) return { source: "invalid", resolved: defaultValue, ceiling };
  const v = Math.floor(n);
  if (v > ceiling) return { source: "clamped", resolved: ceiling, ceiling };
  return { source: "env", resolved: v, ceiling };
}

// classifyFlagKnob classifies a BOOLEAN env flag (VERIFY_AT_SEAL / REPL_VERIFY_SEGMENTS / SLICED_RUNS_DISABLED).
// These parse any string, so they have no "invalid" arm: the only question the pack must answer is whether the
// running value came from the operator or from the built-in default. Never the raw string.
export function classifyFlagKnob(raw: unknown): KnobSource {
  return typeof raw === "string" && raw.trim() !== "" ? "env" : "default";
}
export interface ResolvedSliceScaleKnobs {
  sliceSubrequests: ResolvedKnob;
  sliceWallMs: ResolvedKnob;
}

// resolveKnob classifies one knob's raw env string into the ResolvedKnob the pack reports, mirroring
// budgetFromEnv's resolution EXACTLY (default on unset/invalid, clamp on over-set) so the reported value is
// the one a slice runs with.
function resolveKnob(raw: unknown, defaultValue: number, ceiling: number): ResolvedKnob {
  if (typeof raw !== "string" || raw.trim() === "") return { resolved: defaultValue, ceiling, source: "default" };
  const parsed = scaleKnobNum(raw);
  if (parsed === undefined) return { resolved: defaultValue, ceiling, source: "invalid" };
  if (parsed > ceiling) return { resolved: ceiling, ceiling, source: "clamped" };
  return { resolved: parsed, ceiling, source: "env" };
}

// resolveSliceScaleKnobs surfaces the RESOLVED per-slice subrequest + wall knobs (the effective per-invocation
// budgets) for the support pack, so a misconfigured knob (typo'd low, or over-set and clamped) is visible.
// No DO round-trip: the knobs live in env, which the bundle builder already holds.
export function resolveSliceScaleKnobs(env: { SCALE_SLICE_SUBREQUESTS?: unknown; SCALE_SLICE_WALL_MS?: unknown }): ResolvedSliceScaleKnobs {
  return {
    sliceSubrequests: resolveKnob(env.SCALE_SLICE_SUBREQUESTS, DEFAULT_SLICE_SUBREQUESTS, MAX_SLICE_SUBREQUESTS),
    sliceWallMs: resolveKnob(env.SCALE_SLICE_WALL_MS, DEFAULT_SLICE_WALL_MS, MAX_SLICE_WALL_MS),
  };
}

// numScaleKnob parses an optional positive-integer SCALE_* knob (a trimmed positive finite number,
// floored; undefined on absent/blank/non-positive), mirroring runstate-helpers.ts numKnob and the local
// `num` in budgetFromEnv. Duplicated as a pure local so the support pack can import the SCALE_* resolvers
// below from THIS leaf (which imports only meter.ts) instead of dragging the heavy runstate-helpers graph
// (sources / dest-factory / scheduler-do) into the admin support module.
function numScaleKnob(v: unknown): number | undefined {
  if (typeof v !== "string" || v.trim() === "") return undefined;
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : undefined;
}

// resolveSliceKnobs resolves the per-slice budget knobs to the EFFECTIVE values a slice runs with -- the
// SAME parse + clamp + default budgetFromEnv/SliceBudget apply (an over-set knob clamps to the platform-
// survivable ceiling; an unset knob reports the running default). For the support pack's diagnostic knobs
// block (support-pack mode scale-knobs-invisible + the cpu-kill/wedged-slice wall context). PURE: it
// records nothing, reads no destination, and touches no seal path; it only reflects the resolved budget.
export function resolveSliceKnobs(env: { SCALE_SLICE_SUBREQUESTS?: unknown; SCALE_SLICE_WALL_MS?: unknown }): { subrequests: number; wallMs: number } {
  const sub = numScaleKnob(env.SCALE_SLICE_SUBREQUESTS);
  const wall = numScaleKnob(env.SCALE_SLICE_WALL_MS);
  return {
    subrequests: sub !== undefined ? Math.min(sub, MAX_SLICE_SUBREQUESTS) : DEFAULT_SLICE_SUBREQUESTS,
    wallMs: wall !== undefined ? Math.min(wall, MAX_SLICE_WALL_MS) : DEFAULT_SLICE_WALL_MS,
  };
}

// resolveScaleKnobs resolves the remaining SCALE_* seal-shaping knobs for the support pack's diagnostic
// block: the manifest-shard record cap (SCALE_SHARD_MAX_RECORDS) and the per-segment plaintext target
// (SCALE_SEGMENT_TARGET_BYTES), each INCLUDED ONLY when the operator SET it (the engine's internal
// defaults are not the pack's to guess -- an unset knob is honest absence, and canonicalJSON rejects an
// explicit undefined); and the SLICED_RUNS_DISABLED flag (the v1 whole-run buffered path with no
// mid-record resume -- a large-value no-resume / OOM-risk signal). The truthy test mirrors truthyKnob /
// adapters.ts slicedRunsDisabled ("1"/"true"/"yes"/"on"). PURE; records nothing, touches no seal path.
export function resolveScaleKnobs(env: { SCALE_SHARD_MAX_RECORDS?: unknown; SCALE_SEGMENT_TARGET_BYTES?: unknown; SLICED_RUNS_DISABLED?: unknown }): { shardMaxRecords?: number; segmentTargetBytes?: number; slicedRunsDisabled: boolean } {
  const shardMaxRecords = numScaleKnob(env.SCALE_SHARD_MAX_RECORDS);
  const segmentTargetBytes = numScaleKnob(env.SCALE_SEGMENT_TARGET_BYTES);
  const slicedRunsDisabled = typeof env.SLICED_RUNS_DISABLED === "string" && /^(1|true|yes|on)$/i.test(env.SLICED_RUNS_DISABLED.trim());
  return {
    ...(shardMaxRecords !== undefined ? { shardMaxRecords } : {}),
    ...(segmentTargetBytes !== undefined ? { segmentTargetBytes } : {}),
    slicedRunsDisabled,
  };
}

// scaleKnobSources reports the SOURCE of the seal-shaping SCALE_* knobs (gap G169). resolveScaleKnobs above
// deliberately OMITS an unset knob (honest absence, since the engine's internal default is not the pack's to
// guess), which made a SET-BUT-INVALID knob indistinguishable from an unset one: both read as absent. This says
// which. The knobs have no clamp ceiling of their own (the seal path uses them as targets), so the classifier
// runs against MAX_SAFE_INTEGER and only the default/env/invalid arms can fire. PURE; never the raw string.
export function scaleKnobSources(env: { SCALE_SHARD_MAX_RECORDS?: unknown; SCALE_SEGMENT_TARGET_BYTES?: unknown; SLICED_RUNS_DISABLED?: unknown }): Record<string, KnobResolution> {
  return {
    shardMaxRecords: classifyEnvKnob(env.SCALE_SHARD_MAX_RECORDS, 0, Number.MAX_SAFE_INTEGER),
    segmentTargetBytes: classifyEnvKnob(env.SCALE_SEGMENT_TARGET_BYTES, 0, Number.MAX_SAFE_INTEGER),
    slicedRunsDisabled: { source: classifyFlagKnob(env.SLICED_RUNS_DISABLED) },
  };
}
