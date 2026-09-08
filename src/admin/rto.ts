// RTO (Recovery Time Objective) estimate, the recovery-time companion to RPO (E4/C1 assessment finding:
// RTO is surfaced via the live GET /admin/rto route alongside the RPO/freshness signal). This is a PURE
// derivation: given a downpipe's observed
// recovery-test (drill/restore-test) DURATIONS and the bytes/records each one covered, plus the current
// archive size, it estimates how long a full recovery would take. It is unit-tested directly and reads
// only redaction-safe operational measurements (durations, byte counts), never a key, value or selector.
//
// HONEST ESTIMATE, NEVER A FABRICATED NUMBER (the load-bearing rule): with NO recovery-test history there
// is NO signal, so the estimate is "unknown", never a guessed constant. With history it is DERIVED from
// the measured throughput of the actual drills (bytes verified per millisecond), carries a "based on N
// drills" sample count so the consumer can weigh its confidence, and a low confidence when the sample is
// thin. The estimate is a derived projection, explicitly caveated; it is not a promise.
//
// WHY DRILL DURATION (not backup duration): a drill OPENS + VERIFIES the archive (decrypt + hash-check),
// which is the read-back work a recovery does, so its throughput is the honest proxy for recovery time. A
// backup's seal duration measures the write side, which is not what an RTO answers. The estimate scales
// the measured drill throughput up to the WHOLE archive size when the drill verified only a sample.

// RtoSample is one observed recovery-test measurement: the wall-clock the drill took (durationMs) and the
// work it covered (bytesVerified, recordsVerified). It is recorded by the engine when a drill / scheduled
// restore test runs and verifies at least one record. It carries only counts + a duration; no secret.
export interface RtoSample {
  at: number; // epoch ms the sample was taken (newest samples weigh the estimate; also the recency)
  durationMs: number; // wall-clock the drill/restore-test took
  bytesVerified: number; // plaintext bytes the drill decrypted-and-verified (the measured work)
  recordsVerified: number; // records the drill decrypted-and-verified
}

// RtoDownpipeInput is the per-downpipe slice estimateRto reads: the recent recovery-test samples (a
// bounded ring, newest-last) and the CURRENT archive size (bytes + records) the estimate scales to. The
// archive-size figures are the upper bound a full recovery would move; absent (0/undefined) when unknown,
// in which case the estimate reports the per-sample observed time without a whole-archive scale-up and
// says so. id/name are the downpipe's own redaction-safe config (for the per-downpipe estimate label).
export interface RtoDownpipeInput {
  id: string;
  name: string;
  samples: RtoSample[];
  archiveBytes?: number; // current total plaintext bytes the latest run holds (the recovery upper bound)
  archiveRecords?: number; // current total record count the latest run holds
}

// RtoConfidence is a coarse, honest confidence in the estimate: "none" (no samples, the estimate is
// unknown), "low" (1 sample, or a sample that verified a tiny fraction of the archive, thin signal),
// "medium" (a few consistent samples), "high" (several consistent samples covering a representative
// fraction). It is a hint for the consumer, never a precise probability.
export type RtoConfidence = "none" | "low" | "medium" | "high";

// RtoEstimate is the derived per-downpipe (or fleet) recovery-time estimate. When known is false the
// estimate is UNKNOWN (no drill history) and only the reason + sampleCount(0) are meaningful, there is no
// fabricated number. When known is true, estimateSeconds is the derived whole-archive recovery estimate,
// basedOnDrills is how many samples fed it (the "based on N drills" caveat), confidence is the coarse
// confidence, and observedThroughputBytesPerSec is the measured drill throughput the estimate scaled from
// (so the consumer can show the working). caveat is a fixed, redaction-safe sentence stating the estimate
// is derived and approximate. No field can carry a secret.
export interface RtoEstimate {
  id?: string; // the downpipe id (absent on the fleet roll-up)
  name?: string;
  known: boolean;
  estimateSeconds?: number; // the derived whole-archive recovery estimate (present iff known)
  basedOnDrills?: number; // sample count that fed the estimate (the honest "based on N drills")
  confidence: RtoConfidence;
  observedThroughputBytesPerSec?: number; // the measured drill throughput the estimate derived from
  reason?: string; // why the estimate is unknown (present iff !known), redaction-safe
  caveat?: string; // a fixed note that the estimate is derived/approximate (present iff known)
  // The samples the estimate excluded, and WHY the confidence is what it is: a sample with an unusable
  // duration or zero verified bytes is filtered out of the throughput maths (it carries no signal and
  // would corrupt the estimate), and this names how many and the last cause, so basedOnDrills and the raw
  // sample count can be reconciled.
  rejectedSamples?: { count: number; lastReason: RtoRejectReason }; // present iff at least one sample was excluded
  // The 3-value confidence enum on its own erases WHY confidence is degraded, and the three causes need
  // three different remedies ("we cannot size your archive" / "run more than one drill" / "your drills
  // only sample a sliver of the archive"). Present iff the estimate is degraded.
  degradationCause?: RtoDegradationCause;
}

// RTO_REJECT_REASONS: why a drill sample carries no throughput signal. Closed; never a value, never an id.
export const RTO_REJECT_REASONS = [
  "non-finite-duration", // the measured duration was NaN / Infinity / negative (a broken timer, a clock jump)
  "non-positive-bytes", // the drill verified ZERO bytes (an empty archive, or a drill that verified nothing)
] as const;
export type RtoRejectReason = (typeof RTO_REJECT_REASONS)[number];

// RTO_DEGRADATION_CAUSES: why the estimate is not a full-confidence one. Closed; each maps to ONE remedy.
export const RTO_DEGRADATION_CAUSES = [
  "archive-size-unknown", // no archive size, so the estimate is the longest OBSERVED drill, un-scaled: it cannot be projected to the whole archive at all
  "single-drill", // exactly one usable sample: one measurement is not a throughput distribution
  "thin-sample", // the drills covered only a sliver of the archive, so the scale-up is a large extrapolation
] as const;
export type RtoDegradationCause = (typeof RTO_DEGRADATION_CAUSES)[number];

// RTO_CAVEAT is the fixed, honest disclaimer attached to every KNOWN estimate: the number is derived from
// observed drill throughput and is approximate, not a guaranteed recovery time. Kept here so the engine
// and any consumer state it identically.
export const RTO_CAVEAT =
  "Derived from observed restore-test throughput, scaled to the current archive size; an approximate projection, not a guaranteed recovery time.";

// MIN_DRILL_MS floors a sample's duration when computing throughput, so a sub-millisecond drill (a tiny
// archive, or a fast in-memory test) cannot divide-by-zero or report an absurd throughput. 1 ms is the
// smallest meaningful wall-clock the timer resolves.
const MIN_DRILL_MS = 1;

// REPRESENTATIVE_FRACTION is the share of the archive a drill must have verified for the estimate to read
// as a fuller-confidence measurement rather than a thin extrapolation. A drill that verified only a tiny
// sample of a huge archive still yields an estimate, but at LOW confidence (the scale-up is a large
// extrapolation). 0.1 (10%) is a deliberately modest bar: most sampled drills verify a single record, so
// a representative-fraction drill is the exception that earns higher confidence.
const REPRESENTATIVE_FRACTION = 0.1;

// HIGH_CONFIDENCE_SAMPLE_COUNT is the usable-sample count at or above which a whole-archive-scaled,
// representative-fraction estimate reads as HIGH confidence (several drills average out one anomaly).
const HIGH_CONFIDENCE_SAMPLE_COUNT = 5;

// computeConfidence maps the usable-sample count, whether the estimate was scaled to the whole archive,
// and the fraction of the archive the drills covered into the coarse RtoConfidence ladder. Without a
// whole-archive scale, with a single sample, or with a tiny covered fraction the estimate is LOW; a few
// representative samples are MEDIUM; several are HIGH.
function computeConfidence(usableCount: number, archiveScaled: boolean, coveredFraction: number): RtoConfidence {
  if (!archiveScaled || usableCount === 1 || coveredFraction < REPRESENTATIVE_FRACTION) return "low";
  if (usableCount >= HIGH_CONFIDENCE_SAMPLE_COUNT) return "high";
  return "medium";
}

// estimateRto derives the recovery-time estimate for one downpipe from its recovery-test samples + archive
// size. The rule:
//   - NO samples (or none with a positive duration and positive bytes) -> known:false, confidence "none",
//     reason "no restore-test history yet", the HONEST unknown, never a fabricated number.
//   - one+ usable samples -> measure the AGGREGATE throughput (sum bytesVerified / sum durationMs across
//     the samples, so several drills average out a single anomalous one), then scale it to the current
//     archive size (archiveBytes) to estimate the whole-archive recovery time. When archiveBytes is
//     unknown/zero, fall back to the largest observed per-drill duration (the best evidence of how long a
//     recovery takes, un-scaled) and say so via low confidence.
//   - confidence rises with sample count AND the fraction of the archive the drills covered: 1 sample or a
//     tiny-fraction sample is "low"; a few representative samples "medium"; several "high".
// It NEVER throws. basedOnDrills counts only the USABLE samples that fed the estimate.
export function estimateRto(input: RtoDownpipeInput): RtoEstimate {
  const label = { id: input.id, name: input.name };
  // Usable samples: a positive duration AND positive verified bytes (a zero-byte or zero-duration sample
  // carries no throughput signal). Floor the duration at MIN_DRILL_MS for the throughput maths.
  const usable = input.samples.filter((s) => s.durationMs > 0 && s.bytesVerified > 0 && Number.isFinite(s.durationMs) && Number.isFinite(s.bytesVerified));
  // Count what the filter above threw away, and name the last cause: a sample with an unusable DURATION
  // and a sample that verified NOTHING are different faults with different fixes.
  let rejectedCount = 0;
  let lastRejectReason: RtoRejectReason | null = null;
  for (const s of input.samples) {
    if (s.durationMs > 0 && s.bytesVerified > 0 && Number.isFinite(s.durationMs) && Number.isFinite(s.bytesVerified)) continue;
    rejectedCount++;
    lastRejectReason = !Number.isFinite(s.durationMs) || s.durationMs <= 0 ? "non-finite-duration" : "non-positive-bytes";
  }
  const rejected = rejectedCount > 0 && lastRejectReason !== null ? { rejectedSamples: { count: rejectedCount, lastReason: lastRejectReason } } : {};
  if (usable.length === 0) {
    return {
      ...label,
      known: false,
      confidence: "none",
      reason: "no restore-test history yet; run a restore test (or enable scheduled restore tests) so a recovery-time estimate can be derived",
      // A fleet that has run 15 drills and has NO usable sample reads identically to one that has never drilled
      // at all -- unless the rejection count rides. It is the single most useful thing this branch can carry.
      ...rejected,
    };
  }

  // Aggregate measured throughput: total verified bytes over total drill time (flooring the summed time so
  // a batch of sub-ms drills cannot divide by zero). This averages several drills, damping one anomaly.
  const totalBytes = usable.reduce((n, s) => n + s.bytesVerified, 0);
  const totalMs = Math.max(MIN_DRILL_MS, usable.reduce((n, s) => n + s.durationMs, 0));
  const throughputBytesPerMs = totalBytes / totalMs;
  const observedThroughputBytesPerSec = Math.round(throughputBytesPerMs * 1000);

  // The recovery upper bound: the current archive size when known, else the bytes the drills themselves
  // covered (so the estimate still reflects real measured work rather than nothing). archiveScaled tracks
  // whether we scaled to the whole archive (higher-fidelity) or only reported the observed sample time.
  const archiveBytes = typeof input.archiveBytes === "number" && Number.isFinite(input.archiveBytes) && input.archiveBytes > 0 ? input.archiveBytes : 0;
  let estimateMs: number;
  let archiveScaled: boolean;
  let coveredFraction: number;
  if (archiveBytes > 0) {
    estimateMs = archiveBytes / throughputBytesPerMs;
    archiveScaled = true;
    // The fraction the AGGREGATE drills covered of the current archive (a thin fraction => big
    // extrapolation => lower confidence). Capped at 1 (a drill can cover the whole archive).
    coveredFraction = Math.min(1, totalBytes / archiveBytes);
  } else {
    // No known archive size: the best honest figure is the largest observed per-drill wall-clock (the
    // longest a measured recovery actually took), un-scaled. Confidence is capped low (we cannot project
    // to the whole archive).
    estimateMs = Math.max(...usable.map((s) => s.durationMs));
    archiveScaled = false;
    coveredFraction = 0;
  }
  const estimateSeconds = Math.max(1, Math.round(estimateMs / 1000));

  // Confidence: rises with the USABLE sample count and the covered fraction (see computeConfidence).
  const confidence = computeConfidence(usable.length, archiveScaled, coveredFraction);
  // Name the CAUSE of a degraded confidence. Ordered by which fact dominates the estimate's weakness:
  // an unknown archive size means the number cannot be projected AT ALL (the estimate is a raw observation);
  // one drill is no distribution; a thin covered fraction is a large extrapolation. A full-confidence estimate
  // carries no cause (there is nothing to explain).
  const degradationCause: RtoDegradationCause | null = !archiveScaled
    ? "archive-size-unknown"
    : usable.length < 2
      ? "single-drill"
      : coveredFraction < REPRESENTATIVE_FRACTION
        ? "thin-sample"
        : null;

  return {
    ...label,
    known: true,
    estimateSeconds,
    basedOnDrills: usable.length,
    confidence,
    observedThroughputBytesPerSec,
    caveat: RTO_CAVEAT,
    ...rejected,
    ...(degradationCause !== null ? { degradationCause } : {}),
  };
}

// estimateFleetRto rolls per-downpipe samples into ONE fleet-wide estimate (the account's overall
// recovery-time signal next to the fleet RPO). It pools EVERY usable sample across the downpipes (so the
// fleet throughput reflects all observed drills) and scales to the SUM of the archive sizes (the total
// bytes a full-account recovery would move). With no usable sample anywhere it is the honest unknown. The
// fleet estimate carries no id/name (it is the roll-up). It NEVER throws.
export function estimateFleetRto(inputs: RtoDownpipeInput[]): RtoEstimate {
  const pooledSamples: RtoSample[] = [];
  let archiveBytes = 0;
  let archiveRecords = 0;
  for (const dp of inputs) {
    for (const s of dp.samples) pooledSamples.push(s);
    if (typeof dp.archiveBytes === "number" && Number.isFinite(dp.archiveBytes) && dp.archiveBytes > 0) archiveBytes += dp.archiveBytes;
    if (typeof dp.archiveRecords === "number" && Number.isFinite(dp.archiveRecords) && dp.archiveRecords > 0) archiveRecords += dp.archiveRecords;
  }
  const est = estimateRto({ id: "", name: "", samples: pooledSamples, archiveBytes, archiveRecords });
  // Drop the per-downpipe label on the fleet roll-up (it is not one downpipe).
  const { id: _id, name: _name, ...fleet } = est;
  return fleet;
}

// RTO_SAMPLE_CAP bounds the per-downpipe recovery-sample ring so it cannot grow DO storage without limit
// (the same bounded-ring discipline RING_CAP applies to run history). The newest RTO_SAMPLE_CAP samples
// are kept; the oldest roll off. A small cap is right: the estimate weights recent throughput, and a long
// tail of stale samples would dilute a downpipe whose archive grew. 20 is generous (the last 20 drills).
export const RTO_SAMPLE_CAP = 20;

// appendRtoSample folds one new sample into the bounded ring (newest-last), rolling off the oldest beyond
// RTO_SAMPLE_CAP. Pure: it returns a new array, so the DO's read-modify-write stays explicit. A sample
// with a non-finite/negative duration or byte count is dropped (it carries no signal and would only
// corrupt the throughput maths), so a malformed measurement can never poison the estimate.
export function appendRtoSample(ring: RtoSample[] | undefined, sample: RtoSample): RtoSample[] {
  const base = Array.isArray(ring) ? ring : [];
  if (!(sample.durationMs >= 0) || !Number.isFinite(sample.durationMs) || !(sample.bytesVerified >= 0) || !Number.isFinite(sample.bytesVerified)) {
    return base.slice(-RTO_SAMPLE_CAP);
  }
  return [...base, sample].slice(-RTO_SAMPLE_CAP);
}
