// RUN-PRESSURE EVIDENCE (gap G143, support-pack mode run-retry-pressure-invisible). A run that ultimately
// SUCCEEDS after riding out weeks of edge-of-budget 503/429 retries and throttle parks leaves no trace at all
// today: the retry counters live in a closure that returns, and the throttle/strike ladders live in the
// RunSealDO's transient doc, which cleanup() deletes the moment the run resolves. So "backups suddenly started
// failing" is diagnosed with no history of the pressure that preceded it, and on terminal failure the row
// cannot say whether the 8 strikes had ONE consistent cause or eight different ones, nor which subsystem was
// throttling.
//
// This leaf is the pure half of the fix: the CLOSED vocabularies, the pure classifiers that map a fault to a
// member of them, and the per-isolate RETRY METER that withRetry ticks (the retries happen deep inside the
// source and destination layers, so counting them at the ONE place every retry passes through is both the
// cheapest and the only complete place). The RunSealDO folds the meter into its run doc at each persist point,
// so the count survives an eviction between slices, and emits ONE bounded "run-pressure" observation when the
// run resolves (ok or failed).
//
// NO-CUSTODY: every field this produces is a COUNT or a member of a CLOSED enum. The classifiers below may
// READ an error message, but they return a closed enum member and NOTHING else -- no message, no key, no
// object name, no status text ever leaves them. Per-attempt raw causes stay where they already are: the
// causeDigest on the row and the customer's own Workers Logs.

import { isThrottleClass } from "../dest/classify.ts";
import { ConfigFaultError } from "./config-fault.ts";

// RETRY_SUBSYSTEMS is the CLOSED vocabulary for WHICH subsystem made the run wait. It answers the support
// question "who is throttling us": the destination (an S3-compatible store shedding load), the source API (the
// Cloudflare account API's shared ~1200 req / 5 min budget), or the scheduler (RUNLOG lock contention between
// finalisers). "unspecified" is the honest arm for a retry taken inside a layer that has not yet labelled its
// call site -- it is never guessed.
export const RETRY_SUBSYSTEMS = ["destination", "source-api", "scheduler", "unspecified"] as const;
export type RetrySubsystem = (typeof RETRY_SUBSYSTEMS)[number];
const RETRY_SUBSYSTEM_SET: ReadonlySet<string> = new Set(RETRY_SUBSYSTEMS);

// isRetrySubsystem gates a subsystem against the CLOSED vocabulary (used by the seal-fault sanitiser, which
// re-gates everything it persists rather than trusting an internal caller).
export function isRetrySubsystem(v: unknown): v is RetrySubsystem {
  return typeof v === "string" && RETRY_SUBSYSTEM_SET.has(v);
}

// SEAL_ATTEMPT_CLASSES is the CLOSED vocabulary for the coarse cause of ONE strike on the hard-fault ladder.
// The capped, ordered list of these is what turns "8 strikes" into "8 strikes, all auth" (a rotated credential)
// versus "3 transient, 2 source-missing, 3 destination" (a flapping estate). It is deliberately coarser than
// the run row's coarse error string and, unlike that string, is a strict enum: nothing interpolated, ever.
export const SEAL_ATTEMPT_CLASSES = ["throttle", "transient", "auth", "destination", "source-missing", "source-read", "config", "integrity", "contention", "other"] as const;
export type SealAttemptClass = (typeof SEAL_ATTEMPT_CLASSES)[number];
const SEAL_ATTEMPT_CLASS_SET: ReadonlySet<string> = new Set(SEAL_ATTEMPT_CLASSES);

// isSealAttemptClass gates one attempt class against the CLOSED vocabulary.
export function isSealAttemptClass(v: unknown): v is SealAttemptClass {
  return typeof v === "string" && SEAL_ATTEMPT_CLASS_SET.has(v);
}

// ATTEMPT_CLASSES_MAX caps the per-run ordered strike list at the strike ceiling (MAX_SLICE_FAILURES is 8), so
// the record is bounded by construction no matter how a future ladder is tuned.
export const ATTEMPT_CLASSES_MAX = 8;

// The message SHAPES the seal path itself authors (slice.ts coarseRunError classifies the same throws by the
// same shapes). Each regex exists ONLY to SELECT a closed enum member below; the matched text is never captured,
// returned or stored. Record data is encrypted before it can reach any of these paths, and a customer record
// NAME (the only customer string a seal error can embed) cannot pass any of these anchors into a wrong class in
// a way that carries the name itself: the output is always one of ten fixed strings.
const AUTH_RE = /(status|HTTP) (401|403)|AccessDenied|InvalidAccessKeyId|SignatureDoesNotMatch|ExpiredToken/i;
const CONTENTION_RE = /RUNLOG write contended|RUNLOG/;
const INTEGRITY_RE = /shard enumeration incomplete|open-shard enumeration incomplete|checkpoint|merkle|signature/i;
const SOURCE_MISSING_RE = /source resource missing/;
const SOURCE_READ_RE = /source read|cannot range-read|exceeds the .* limit|D1 export|unsupported source type/i;
const DEST_RE = /(status|HTTP) [45]\d\d|destination|PUT .* failed|GET .* failed/i;
const TRANSIENT_RE = /fetch failed|network|timed out|timeout|internal error/i;

/**
 * sealAttemptClass coarsens ONE caught slice fault into a CLOSED attempt class (gap G143). It is the ONLY thing
 * the strike list ever records. A typed ConfigFaultError short-circuits to "config" (a TYPE match, no text read
 * at all); everything else is matched against the seal path's own message shapes purely to SELECT a member, in
 * the same precedence coarseRunError uses (integrity and contention before the destination catch-all, so a
 * RUNLOG contention is never mislabelled a destination outage). PURE: it returns an enum member and nothing else.
 */
export function sealAttemptClass(e: unknown): SealAttemptClass {
  if (e instanceof ConfigFaultError) return "config";
  if (isThrottleClass(e)) return "throttle";
  const m = e instanceof Error ? e.message : typeof e === "string" ? e : "";
  if (SOURCE_MISSING_RE.test(m)) return "source-missing";
  if (INTEGRITY_RE.test(m)) return "integrity";
  if (CONTENTION_RE.test(m)) return "contention";
  if (AUTH_RE.test(m)) return "auth";
  if (SOURCE_READ_RE.test(m)) return "source-read";
  if (TRANSIENT_RE.test(m)) return "transient";
  if (DEST_RE.test(m)) return "destination";
  return "other";
}

/**
 * throttledSubsystemOf names WHICH subsystem asked the run to slow down, from the throttle message the park
 * ladder already holds (gap G143: "runs take 5 hours some days" is undiagnosable without it). Reads the message
 * ONLY to select a member of RETRY_SUBSYSTEMS; returns the enum, never the text. A throttle on the RUNLOG object
 * is attributed to the scheduler's lock path, a throttle from the rate-limited Cloudflare account API to the
 * source API, and everything else to the destination (the store that shed the write). PURE.
 */
export function throttledSubsystemOf(message: string): RetrySubsystem {
  if (/RUNLOG/.test(message)) return "scheduler";
  if (/Cloudflare API|cf api|api\.cloudflare\.com|account API/i.test(message)) return "source-api";
  return "destination";
}

// ---- the per-isolate RETRY METER -------------------------------------------------------------------------
//
// withRetry ticks this on every retry it actually takes. It is per-isolate by construction (a RunSealDO isolate
// runs exactly one run's slice at a time, and the source crawl + destination writes all happen inside it), so a
// slice's retries are unambiguously that slice's. The RunSealDO DRAINS it into the run doc at each persist point,
// which both makes the count durable across an eviction and clears it for the next slice. An isolate that is
// evicted mid-slice loses the un-drained tail: that is the honest bound of a zero-cost meter, and it can never
// affect a run.

// RETRY_METER_MAX bounds each counter so a pathological loop cannot grow the record (a real run's retries are
// in the tens).
const RETRY_METER_MAX = 1_000_000;

// RunPressure is the accumulated, bounded pressure evidence for ONE run. Counts and closed enums only.
export interface RunPressure {
  retries: number; // retries actually TAKEN (a first attempt is not a retry)
  bySubsystem: Partial<Record<RetrySubsystem, number>>; // which subsystem the retries were spent on
  probeFlaps: number; // resume-liveness probe faults SWALLOWED between slices (today: silent)
  attemptClasses: SealAttemptClass[]; // ordered, capped strike causes
  throttledSubsystem?: RetrySubsystem; // WHO parked the run on the patient throttle ladder (last park wins)
}

/** emptyRunPressure is the zero value (a fresh run has spent nothing). */
export function emptyRunPressure(): RunPressure {
  return { retries: 0, bySubsystem: {}, probeFlaps: 0, attemptClasses: [] };
}

let meter = { retries: 0, bySubsystem: {} as Partial<Record<RetrySubsystem, number>> };

/** noteRetry records ONE retry the data path actually took, against its (closed) subsystem. Called by withRetry. */
export function noteRetry(subsystem: RetrySubsystem = "unspecified"): void {
  const s: RetrySubsystem = isRetrySubsystem(subsystem) ? subsystem : "unspecified";
  meter.retries = Math.min(meter.retries + 1, RETRY_METER_MAX);
  meter.bySubsystem[s] = Math.min((meter.bySubsystem[s] ?? 0) + 1, RETRY_METER_MAX);
}

/** peekRetryMeter reports the un-drained retries (diagnostic + validator surface). */
export function peekRetryMeter(): { retries: number; bySubsystem: Partial<Record<RetrySubsystem, number>> } {
  return { retries: meter.retries, bySubsystem: { ...meter.bySubsystem } };
}

/** drainRetryMeter returns the retries taken since the last drain and CLEARS the meter. */
export function drainRetryMeter(): { retries: number; bySubsystem: Partial<Record<RetrySubsystem, number>> } {
  const out = peekRetryMeter();
  meter = { retries: 0, bySubsystem: {} };
  return out;
}

/** resetRetryMeter clears the meter without reading it (validators isolate cases with it). */
export function resetRetryMeter(): void {
  meter = { retries: 0, bySubsystem: {} };
}

/**
 * foldRetryMeter DRAINS the isolate meter into a run's accumulated pressure and returns the new total. PURE
 * apart from the drain (the meter is the only state). Every counter stays bounded.
 */
export function foldRetryMeter(prior: RunPressure | undefined): RunPressure {
  const base = prior ?? emptyRunPressure();
  const drained = drainRetryMeter();
  const bySubsystem: Partial<Record<RetrySubsystem, number>> = { ...base.bySubsystem };
  for (const [k, n] of Object.entries(drained.bySubsystem)) {
    if (!isRetrySubsystem(k)) continue;
    bySubsystem[k] = Math.min((bySubsystem[k] ?? 0) + n, RETRY_METER_MAX);
  }
  return {
    retries: Math.min(base.retries + drained.retries, RETRY_METER_MAX),
    bySubsystem,
    probeFlaps: Math.min(base.probeFlaps, RETRY_METER_MAX),
    attemptClasses: base.attemptClasses.slice(-ATTEMPT_CLASSES_MAX),
    ...(base.throttledSubsystem !== undefined ? { throttledSubsystem: base.throttledSubsystem } : {}),
  };
}

/**
 * withAttemptClass appends ONE strike's coarse class to the run's ordered, capped list (oldest dropped past
 * ATTEMPT_CLASSES_MAX). PURE: it returns a new RunPressure and reads the fault only through sealAttemptClass,
 * so nothing but a closed enum member can ever be appended.
 */
export function withAttemptClass(prior: RunPressure | undefined, e: unknown): RunPressure {
  const base = prior ?? emptyRunPressure();
  return { ...base, attemptClasses: [...base.attemptClasses, sealAttemptClass(e)].slice(-ATTEMPT_CLASSES_MAX) };
}

/** withProbeFlap counts one SWALLOWED resume-liveness probe fault (until now: entirely silent). PURE. */
export function withProbeFlap(prior: RunPressure | undefined): RunPressure {
  const base = prior ?? emptyRunPressure();
  return { ...base, probeFlaps: Math.min(base.probeFlaps + 1, RETRY_METER_MAX) };
}

/** withThrottledSubsystem records WHO parked the run on the patient throttle ladder (a closed enum). PURE. */
export function withThrottledSubsystem(prior: RunPressure | undefined, subsystem: RetrySubsystem): RunPressure {
  const base = prior ?? emptyRunPressure();
  return { ...base, throttledSubsystem: isRetrySubsystem(subsystem) ? subsystem : "unspecified" };
}

/**
 * dominantSubsystem names the subsystem that ate the MOST retries (the "who throttled us" answer), or
 * undefined when nothing was spent. Ties resolve in RETRY_SUBSYSTEMS order, so the answer is deterministic.
 * PURE.
 */
export function dominantSubsystem(p: RunPressure): RetrySubsystem | undefined {
  let best: RetrySubsystem | undefined;
  let bestN = 0;
  for (const s of RETRY_SUBSYSTEMS) {
    const n = p.bySubsystem[s] ?? 0;
    if (n > bestN) {
      best = s;
      bestN = n;
    }
  }
  return best;
}

/** hasPressure reports whether a run spent ANY pressure worth recording (a clean run records nothing). */
export function hasPressure(p: RunPressure | undefined, strikes: number, throttleParks: number, runlogParks: number): boolean {
  if (strikes > 0 || throttleParks > 0 || runlogParks > 0) return true;
  return p !== undefined && (p.retries > 0 || p.probeFlaps > 0 || p.attemptClasses.length > 0);
}
