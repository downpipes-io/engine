// Bounded retry with jittered backoff for the data path. A single transient fault on a
// source read or a destination write currently fails the whole run, which a large
// environment hits as a matter of course (a 5xx from an S3-compatible store, a blip on a
// binding call). Retrying a bounded number of times inside the slice turns those into a
// non-event, while persistent faults still fail the slice loudly (and the sliced run then
// resumes from its checkpoint rather than from zero).
//
// Only TRANSIENT faults retry. Conditional-put precondition failures are results, not
// throws, and never reach here; a validation or configuration error (missing binding,
// oversize record) throws a message that does not match the transient classes and fails
// immediately. The classifier is deliberately conservative: HTTP 5xx and 429 statuses in
// the error message (the dest layer throws "PUT <key> failed: status NNN"), and the
// fetch/network fault shapes the runtime throws (TypeError "fetch failed", "network",
// "timed out", "internal error").

import { isThrottleOrTransient } from "../dest/classify.ts";
import { classifyEnvKnob, type KnobResolution, type Meter } from "./budget.ts";
import { noteRetry, type RetrySubsystem } from "./run-pressure.ts";

export const DEFAULT_RETRY_ATTEMPTS = 3;

// DEST_THROTTLE_RETRY is the DEEPER backoff for the destination THROTTLE/transient class on the seal data
// path (adaptive-dest-backpressure Layer 1b). The default 3 attempts / 150 ms (≈ 600 ms total) cannot
// ride out a sustained 503 SlowDown wave from an S3-compatible store under a wide finalise burst; 6
// attempts / 500 ms base (≈ several seconds, still inside MAX_RETRY_SLEEP_MS and the slice wall) turns a
// multi-second throttle into a slow success instead of a loud false failure. It mirrors API_READ_RETRY's
// shape (the same problem on the rate-limited CF account API). An auth/permanent fault still fails on
// attempt 1 because the classifier (isThrottleOrTransient) returns false for it.
export const DEST_THROTTLE_RETRY = { attempts: 6, baseMs: 500 } as const;

// throttleRetry builds the withRetry options for a destination WRITE on the seal path: the shared
// throttle/transient classifier plus the deeper budget, with an optional per-deployment override
// (DEST_THROTTLE_ATTEMPTS / DEST_THROTTLE_BASE_MS, see throttleRetryFromEnv). The override exists so a
// store with a known-longer throttle window can ride deeper without a code change (fail-soft on a typo);
// it never weakens the verdict, only how patiently a throttle is retried.
export function throttleRetry(override?: { attempts?: number | undefined; baseMs?: number | undefined }): {
  classify: (e: unknown) => boolean;
  attempts: number;
  baseMs: number;
} {
  return {
    classify: isThrottleOrTransient,
    attempts: override?.attempts ?? DEST_THROTTLE_RETRY.attempts,
    baseMs: override?.baseMs ?? DEST_THROTTLE_RETRY.baseMs,
  };
}

// throttleRetryFromEnv parses the optional DEST_THROTTLE_ATTEMPTS / DEST_THROTTLE_BASE_MS knobs (positive
// numbers) into a throttleRetry override, falling back to the DEST_THROTTLE_RETRY defaults on absence or a
// typo (exactly like destPacerFromEnv / budgetFromEnv: a bad knob never stops or weakens a backup).
export function throttleRetryFromEnv(env: { DEST_THROTTLE_ATTEMPTS?: unknown; DEST_THROTTLE_BASE_MS?: unknown }): { attempts?: number; baseMs?: number } {
  const num = (v: unknown): number | undefined => {
    if (typeof v !== "string" || v.trim() === "") return undefined;
    const n = Number(v);
    return Number.isFinite(n) && n > 0 ? n : undefined;
  };
  const attempts = num(env.DEST_THROTTLE_ATTEMPTS);
  const baseMs = num(env.DEST_THROTTLE_BASE_MS);
  return { ...(attempts !== undefined ? { attempts } : {}), ...(baseMs !== undefined ? { baseMs } : {}) };
}

// throttleRetryKnobSources reports the SOURCE of the destination-throttle retry knobs (gap G169). The
// resolution above is fail-soft by design -- a typo'd DEST_THROTTLE_ATTEMPTS silently falls back to the
// DEST_THROTTLE_RETRY default -- so an operator who "tuned" the retry budget and saw no behaviour change had
// nothing in the pack to tell them the value was REJECTED rather than never read. These knobs have no clamp
// ceiling (they are budgets, not platform limits), so only the default/env/invalid arms can fire. The raw
// operator string is NEVER carried, only the closed source enum and the value in force.
export function throttleRetryKnobSources(env: { DEST_THROTTLE_ATTEMPTS?: unknown; DEST_THROTTLE_BASE_MS?: unknown }): Record<string, KnobResolution> {
  return {
    destThrottleAttempts: classifyEnvKnob(env.DEST_THROTTLE_ATTEMPTS, DEST_THROTTLE_RETRY.attempts, Number.MAX_SAFE_INTEGER),
    destThrottleBaseMs: classifyEnvKnob(env.DEST_THROTTLE_BASE_MS, DEST_THROTTLE_RETRY.baseMs, Number.MAX_SAFE_INTEGER),
  };
}

// API_READ_RETRY is the deeper backoff for CLOUDFLARE ACCOUNT-API reads (cf-config, workers, discovery).
// That API enforces a global ~1200 req / 5 min limit SHARED across the whole account, so a 429 on a large
// crawl must be ridden out with more attempts and a longer base than a one-off 5xx on a dest write: the
// default 3 attempts / 150 ms (max ~600 ms) cannot pace through a rate-limit window. Brief 429s ride out
// here (honouring Retry-After, see withRetry); a PERSISTENT rate limit still fails the slice loudly and the
// RunSealDO alarm's own 5 s -> 5 min backoff then spaces the resume across invocations.
export const API_READ_RETRY = { attempts: 6, baseMs: 500 } as const;

// API_WRITE_RETRY is the backoff profile for CLOUDFLARE ACCOUNT-API writes (the media re-upload path).
// Writes share the account's global ~1200 req / 5 min limit just as reads do, so it carries the same deeper
// attempts and longer base to ride out a 429; kept as its own constant (currently identical to
// API_READ_RETRY) so a write call site reads with write semantics and the write path can diverge from reads
// later without touching reads.
export const API_WRITE_RETRY = { attempts: 6, baseMs: 500 } as const;

// MAX_RETRY_SLEEP_MS caps a single in-slice backoff sleep so honouring a large Retry-After (or a deep
// exponential step) never blows the slice's wall-clock budget (DEFAULT_SLICE_WALL_MS). A rate limit that
// needs longer than this is handled across invocations by the DO alarm backoff, not by sleeping here.
export const MAX_RETRY_SLEEP_MS = 8_000;

// isTransient is the default withRetry predicate. It now DELEGATES to the shared destination-fault
// classifier (dest/classify.ts): isThrottleOrTransient returns true for a throttle (429/503), a transient
// fault (408/other 5xx), a Retry-After-tagged error, or a network shape, and false for auth/permanent --
// behaviourally equal to the historical regex it replaces (which retried "(status|HTTP) (5xx|429)", a
// Retry-After tag, or a network shape). Promoting the rule into one named classifier is the point of
// adaptive-dest-backpressure Layer 1a: which faults retry is decided in exactly one place.
export function isTransient(e: unknown): boolean {
  return isThrottleOrTransient(e);
}

// parseRetryAfter reads an HTTP Retry-After header value into milliseconds: either delta-seconds
// ("120") or an HTTP-date ("Wed, 21 Oct 2026 07:28:00 GMT"). Returns null when absent/unparseable, so
// the caller falls back to jittered exponential backoff. Clamped at 0 (a past date is "retry now").
export function parseRetryAfter(value: string | null | undefined): number | null {
  if (!value) return null;
  const secs = Number(value.trim());
  if (Number.isFinite(secs)) return Math.max(0, secs * 1000);
  const when = Date.parse(value);
  return Number.isFinite(when) ? Math.max(0, when - Date.now()) : null;
}

// retryAfterMsOf reads a server-requested delay an error carried (a 429 whose Retry-After the CF API
// client captured as err.retryAfterMs). Returns null when absent. Pure; used by withRetry.
export function retryAfterMsOf(e: unknown): number | null {
  const v = (e as { retryAfterMs?: unknown } | null)?.retryAfterMs;
  return typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : null;
}

// rateLimitError builds the error the CF API clients throw on a 429, carrying the parsed Retry-After (ms)
// so withRetry waits the server-requested time before the next attempt instead of a blind backoff.
export function rateLimitError(message: string, retryAfterMs: number | null): Error {
  const e = new Error(message) as Error & { retryAfterMs?: number };
  if (retryAfterMs !== null) e.retryAfterMs = retryAfterMs;
  return e;
}

// withRetry runs fn up to attempts times, sleeping base*2^k with full jitter between
// tries. METERING CONTRACT: every operation wrapped here must SELF-METER its real
// platform calls (the dest layers meter inside signedRequest/metered(), the sources
// meter their list/get/open calls), so withRetry itself spends nothing; charging per
// retry here would double-count each re-issued call. The final failure rethrows the
// last error unchanged so the caller's coarse-error mapping sees the original message.
//
// RETRY PRESSURE (gap G143): every retry this loop actually TAKES is ticked into the per-isolate retry meter
// (run-pressure.ts) before it sleeps. That is the one place a retry is visible: the source and destination
// layers each call withRetry from inside their own closures, so a run's whole retry cost passes through here
// and nowhere else. `subsystem` labels WHO the run waited on (a closed enum); an unlabelled call site tallies
// honestly as "unspecified" rather than being guessed at. Ticking the meter is a pure in-memory increment: it
// cannot throw, cannot slow the path and cannot change which faults retry.
export async function withRetry<T>(fn: () => Promise<T>, opts?: { attempts?: number | undefined; baseMs?: number | undefined; meter?: Meter | undefined; classify?: ((e: unknown) => boolean) | undefined; subsystem?: RetrySubsystem | undefined }): Promise<T> {
  const attempts = opts?.attempts ?? DEFAULT_RETRY_ATTEMPTS;
  const baseMs = opts?.baseMs ?? 150;
  const classify = opts?.classify ?? isTransient;
  let lastErr: unknown;
  for (let attempt = 0; attempt < attempts; attempt++) {
    if (attempt > 0) {
      // A retry is being TAKEN (the prior attempt threw a class this loop rides out). Count it against the
      // closed subsystem vocabulary so "the backups got slow, then started failing" has a history.
      noteRetry(opts?.subsystem ?? "unspecified");
      // Jittered exponential backoff, BUT honour a server Retry-After when the last error carried one (a
      // 429 from the CF account API): wait at least the server-requested time, never less. Capped at
      // MAX_RETRY_SLEEP_MS so a long Retry-After cannot blow the slice wall budget (the DO alarm backoff
      // covers a rate limit that needs longer than one slice).
      // Non-security timing jitter, but drawn from the CSPRNG so no reviewer has to reason about
      // whether Math.random() is used anywhere near a security boundary (GUARDRAILS section 15).
      const jitterBuf = new Uint32Array(1);
      crypto.getRandomValues(jitterBuf);
      const jitter = (jitterBuf[0] ?? 0) / 0x100000000;
      const expo = Math.floor(jitter * baseMs * 2 ** (attempt - 1));
      const ra = retryAfterMsOf(lastErr);
      const delay = Math.min(MAX_RETRY_SLEEP_MS, ra !== null ? Math.max(ra, expo) : expo);
      await new Promise((r) => setTimeout(r, delay));
    }
    try {
      return await fn();
    } catch (e) {
      lastErr = e;
      if (!classify(e)) throw e;
    }
  }
  throw lastErr;
}
