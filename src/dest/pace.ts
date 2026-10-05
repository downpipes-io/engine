// DestPacer is an ADAPTIVE token-bucket throttle for writes to an S3-compatible archive destination.
// It is the PROACTIVE half of the destination-backpressure defence (T1-A): it paces a slice's outbound
// requests and, on observed pushback (a 503 SlowDown / 429 from the store), HALVES its effective rate so
// the next requests are spaced wider instead of hammering a destination that is already struggling. On a
// clean 2xx it recovers the rate additively back toward the configured steady rate. This is the inverse
// of CfPacer (cf-pace.ts), which is PROACTIVE-PRIMARY because the Cloudflare account API has a hard ~4/s
// shared ceiling; an S3 destination has no such fixed ceiling, so the pacer here is REACTIVE-PRIMARY: at
// the generous default rate it rarely blocks a healthy destination, and only clamps once the store pushes
// back. The REACTIVE retry half (seal/retry.ts withRetry, and s3.ts multipartStep) still rides out an
// individual 503 honouring Retry-After; this class reduces how many 503s happen in the first place.
//
// The "do not abandon the backup" half is the alarm's job, not this class: a 503 that still exhausts the
// retries surfaces as a thrown slice fault that the RunSealDO classifies as a THROTTLE and rides out on a
// patient, checkpoint-preserving ladder (it never charges the hard-fault strike counter). This class
// holds no such state; it is purely per-invocation pacing (one isolate / one slice), exactly like CfPacer.
//
// Default rate is deliberately generous (most S3-compatible stores handle far more than this): the point
// is to clamp UNDER pushback, not to throttle a healthy destination. Overridable via DEST_RATE_PER_SEC.

/**
 * The steady rate, in requests per second, a DestPacer paces to when DEST_RATE_PER_SEC is unset or
 * unreadable. With no knob set it is the pacer's ceiling: the adaptive rate only clamps BELOW it under
 * observed pushback, then recovers back to it. The support pack reports it as the effective rate whenever
 * the knob is absent or invalid, so the pack shows the rate that actually applied rather than the one the
 * operator thought they set.
 */
export const DEFAULT_DEST_RATE_PER_SEC = 50;
// MIN_DEST_RATE_PER_SEC is the floor the multiplicative decrease cannot go below: even a hard-throttling
// destination is still issued one request per second so a slice can make (slow) progress rather than stall.
const MIN_DEST_RATE_PER_SEC = 1;

/**
 * The adaptive token-bucket throttle described above, held for the life of ONE slice. Construct it with an
 * optional steady rate and burst, await take() before each destination request, and feed every observed
 * response status to observe(): a 503 or 429 HALVES the effective rate (floored at one request per second)
 * and a 2xx recovers it additively toward the steady rate. The bucket refills at the CURRENT effective rate,
 * so a clamp widens the spacing between requests with no explicit sleep bookkeeping.
 *
 * It holds no state beyond that (no persistence, nothing shared between isolates), so a clamp lasts only as
 * long as the slice that earned it. Riding out an individual 503 remains the retry layer's job.
 */
export class DestPacer {
  private tokens: number;
  private readonly capacity: number;
  private readonly baseRate: number;
  // effRate is the CURRENT effective rate (req/s). It starts at baseRate, halves on each observed 503/429
  // (multiplicative decrease, floored at MIN_DEST_RATE_PER_SEC) and climbs back toward baseRate on each 2xx
  // (additive increase). The token bucket refills at effRate, so a clamped rate naturally widens the gap
  // between requests without any explicit sleep bookkeeping.
  private effRate: number;
  private last: number;

  constructor(opts?: { ratePerSec?: number; burst?: number }) {
    this.baseRate = Math.max(MIN_DEST_RATE_PER_SEC, opts?.ratePerSec ?? DEFAULT_DEST_RATE_PER_SEC);
    // A small burst lets a short slice run unthrottled; default one second of tokens (at least 1).
    this.capacity = Math.max(1, opts?.burst ?? Math.ceil(this.baseRate));
    this.effRate = this.baseRate;
    this.tokens = this.capacity;
    this.last = Date.now();
  }

  // take resolves when a token is available, sleeping in bounded ~250 ms steps until the bucket refills
  // (at the CURRENT effRate), so a clamped pacer slows the slice without ever holding the isolate open
  // unboundedly per call. It never throws.
  async take(): Promise<void> {
    for (;;) {
      const now = Date.now();
      this.tokens = Math.min(this.capacity, this.tokens + ((now - this.last) * this.effRate) / 1000);
      this.last = now;
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }
      const waitMs = Math.min(250, Math.ceil(((1 - this.tokens) * 1000) / this.effRate));
      await new Promise((r) => setTimeout(r, Math.max(1, waitMs)));
    }
  }

  // observe folds one response status into the adaptive rate: a 503 SlowDown / 429 HALVES the effective
  // rate (multiplicative decrease, the AIMD response to congestion); a 2xx recovers it additively toward
  // the base rate. Every other status (3xx/4xx) is neutral: a redirect or an auth failure is not a
  // congestion signal, so it neither clamps nor recovers the rate.
  observe(status: number): void {
    if (status === 503 || status === 429) {
      this.effRate = Math.max(MIN_DEST_RATE_PER_SEC, this.effRate / 2);
    } else if (status >= 200 && status < 300) {
      this.effRate = Math.min(this.baseRate, this.effRate + Math.max(1, this.baseRate / 10));
    }
  }

  // effectiveRate exposes the current adaptive rate for tests and diagnostics. Not load-bearing.
  effectiveRate(): number {
    return this.effRate;
  }
}

/**
 * destPacerFromEnv builds a DestPacer from the optional DEST_RATE_PER_SEC / DEST_BURST knobs (positive
 * numbers), falling back to the generous default. An invalid value falls back rather than throwing,
 * exactly like budgetFromEnv / pacerFromEnv, so a typo'd knob never stops a backup.
 *
 * The fallback is silent by design, which is why config-anomalies.ts classifyEnvDestAnomalies mirrors this
 * same acceptance test: the pack names a knob that was set and then discarded here.
 */
export function destPacerFromEnv(env: { DEST_RATE_PER_SEC?: unknown; DEST_BURST?: unknown }): DestPacer {
  const num = (v: unknown): number | undefined => {
    if (typeof v !== "string" || v.trim() === "") return undefined;
    const n = Number(v);
    return Number.isFinite(n) && n > 0 ? n : undefined;
  };
  const ratePerSec = num(env.DEST_RATE_PER_SEC);
  const burst = num(env.DEST_BURST);
  return new DestPacer({ ...(ratePerSec !== undefined ? { ratePerSec } : {}), ...(burst !== undefined ? { burst } : {}) });
}
