// The sweep of expired fixed-window rate counters.
//
// Every limiter that keys on a caller-typed or source-derived string stores one row per distinct key:
// `ratelimit:<key>` for the per-caller and per-source sign-in limiters, `recovery-rate:<key>` for the
// recovery-code sign-in. A row is read only inside its own window, so once `windowStart` plus the window
// has passed the row can never change a verdict and only occupies storage. The alarm deletes such rows, and
// any row that is not a window record.

import { RATE_LIMIT_PREFIX, RATE_LIMIT_WINDOW_MS, RECOVERY_RATE_PREFIX, RECOVERY_RATE_WINDOW_MS } from "./scheduler-do-limits.ts";

// RATE_SWEEP_PAGE is the number of rows one list call reads. RATE_SWEEP_PAGES_PER_PREFIX is how many pages one
// alarm reads under each prefix, so one alarm deletes at most 1,000 rows per prefix and leaves the rest for
// the next alarm.
const RATE_SWEEP_PAGE = 500;
const RATE_SWEEP_PAGES_PER_PREFIX = 2;
// A Durable Object storage delete call accepts at most 128 keys.
const DELETE_BATCH = 128;

// The slice of DurableObjectStorage this module uses, so a validator can drive it with a small double.
export interface RateWindowStore {
  list<T>(opts: { prefix: string; startAfter?: string; limit?: number }): Promise<Map<string, T>>;
  delete(keys: string[]): Promise<number>;
}

function isLive(raw: unknown, windowMs: number, nowMs: number): boolean {
  if (raw === null || typeof raw !== "object") return false;
  const start = (raw as { windowStart?: unknown }).windowStart;
  return typeof start === "number" && Number.isFinite(start) && start + windowMs > nowMs;
}

async function sweepPrefix(store: RateWindowStore, prefix: string, windowMs: number, nowMs: number): Promise<number> {
  let deleted = 0;
  let after: string | undefined;
  for (let page = 0; page < RATE_SWEEP_PAGES_PER_PREFIX; page++) {
    const rows = await store.list<unknown>(after === undefined ? { prefix, limit: RATE_SWEEP_PAGE } : { prefix, startAfter: after, limit: RATE_SWEEP_PAGE });
    if (rows.size === 0) break;
    const dead: string[] = [];
    for (const [key, raw] of rows) {
      after = key;
      if (!isLive(raw, windowMs, nowMs)) dead.push(key);
    }
    for (let i = 0; i < dead.length; i += DELETE_BATCH) deleted += await store.delete(dead.slice(i, i + DELETE_BATCH));
    if (rows.size < RATE_SWEEP_PAGE) break;
  }
  return deleted;
}

/**
 * sweepRateWindows deletes the rate-window rows whose window has ended, and any row under the two rate
 * prefixes that is not a window record. It reads at most RATE_SWEEP_PAGES_PER_PREFIX pages of
 * RATE_SWEEP_PAGE rows under each prefix, so one call deletes at most 1,000 rows per
 * prefix; the next alarm continues. It returns the number of rows deleted.
 */
export async function sweepRateWindows(store: RateWindowStore, nowMs: number): Promise<number> {
  const a = await sweepPrefix(store, RATE_LIMIT_PREFIX, RATE_LIMIT_WINDOW_MS, nowMs);
  const b = await sweepPrefix(store, RECOVERY_RATE_PREFIX, RECOVERY_RATE_WINDOW_MS, nowMs);
  return a + b;
}
