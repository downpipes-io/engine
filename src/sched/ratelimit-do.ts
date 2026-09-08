// RateLimitDO is the ACCOUNT-GLOBAL counterpart to CfPacer (src/cf-pace.ts). CfPacer bounds the burst of
// ONE isolate; this Durable Object holds the SAME token-bucket maths in DO storage, so every isolate that
// asks it for a token draws from one shared bucket. A single DO instance serialises its fetch() calls, so
// the read-modify-write of the bucket is race-free even under many concurrent crawls all naming the same
// singleton instance (env.RATELIMIT_DO.idFromName("account-cf-api")).
//
// The DO does NOT sleep: fetch() consumes a token if one is available (returning waitMs 0) and otherwise
// reports how long the caller must wait for the next refill (returning a positive waitMs WITHOUT consuming
// a token, so the caller is the one that sleeps and re-asks). Keeping the wait on the caller side means the
// DO never holds an isolate open and the bucket arithmetic stays a quick storage round-trip. DistributedPacer
// (src/cf-pace.ts) is the client that loops fetch()->sleep until it is granted a token.
//
// SCOPE (honest): this is the bucket-maths half. It is registered as a binding but the live cross-isolate
// go-live (every API caller wired through DistributedPacer in production, under real concurrent isolates) is
// not yet enabled; until the RATELIMIT_DO binding is present, accountPacer() falls back to the per-isolate
// CfPacer and the round-trip is never on the path. Under concurrent isolates the per-isolate pacing alone may
// not hold the account-global Cloudflare API limit. See accountPacer in src/cf-pace.ts.

import { DEFAULT_CF_API_RATE_PER_SEC } from "../cf-pace.ts";

// The persisted bucket: the fractional token count and the wall-clock ms it was last refilled to. Stored
// under one key so the whole bucket is one read and one write per call.
interface BucketState {
  tokens: number;
  last: number;
}

const BUCKET_KEY = "cf-api-bucket";

// ---- fail-open health ----
//
// This DO fails open by design (a broken limiter must never stop backups). Both a fail-open event and an
// invalid CF_API_RATE_PER_SEC knob are persisted as counts and a clamped timestamp, read back by GET /health
// for the support pack, so an operator can tell a degraded-to-no-throttle limiter from a healthy one. Counts
// only; the storage error text never rides.
const HEALTH_KEY = "ratelimit-health";
const FAIL_OPEN_COUNT_CAP = 1_000_000;

export interface RateLimitHealth {
  failOpenCount: number; // times take() threw and the caller was granted a free pass (the limiter was NOT throttling)
  lastFailOpenAt: number; // clamped epoch ms of the most recent fail-open; 0 when it has never happened
  knobInvalid: boolean; // CF_API_RATE_PER_SEC is SET but unparseable/non-positive, so the conservative default is silently in force
}

const EMPTY_HEALTH: RateLimitHealth = { failOpenCount: 0, lastFailOpenAt: 0, knobInvalid: false };

// knobIsInvalid is the PURE predicate behind knobInvalid: the knob is present (a non-empty string) but does not
// parse to a finite positive number, so rateFromEnv silently returns the default. An ABSENT knob is not a fault
// (the default is the intended value), so it reads false.
export function knobIsInvalid(env: { CF_API_RATE_PER_SEC?: unknown }): boolean {
  const raw = env.CF_API_RATE_PER_SEC;
  if (typeof raw !== "string" || raw.trim() === "") return false;
  const n = Number(raw);
  return !(Number.isFinite(n) && n > 0);
}

// The grant shape fetch() returns. waitMs 0 with granted true means a token was consumed; a positive waitMs
// with granted false means none was available and the caller should sleep waitMs then re-ask.
export interface RateGrant {
  granted: boolean;
  waitMs: number;
}

// rateFromEnv reads the SAME CF_API_RATE_PER_SEC knob CfPacer uses, so the shared bucket paces at the same
// configured rate (an invalid/absent value falls back to the conservative default rather than throwing).
function rateFromEnv(env: { CF_API_RATE_PER_SEC?: unknown }): number {
  const raw = env.CF_API_RATE_PER_SEC;
  if (typeof raw === "string" && raw.trim() !== "") {
    const n = Number(raw);
    if (Number.isFinite(n) && n > 0) return n;
  }
  return DEFAULT_CF_API_RATE_PER_SEC;
}

// burstFor matches CfPacer's capacity choice: one second's worth of tokens, at least 1, so a tiny crawl is
// never delayed but a long one is paced to the refill rate.
function burstFor(rate: number): number {
  return Math.max(1, Math.ceil(rate));
}

export class RateLimitDO {
  private state: DurableObjectState;
  private env: { CF_API_RATE_PER_SEC?: unknown };

  constructor(state: DurableObjectState, env: { CF_API_RATE_PER_SEC?: unknown }) {
    this.state = state;
    this.env = env;
  }

  // fetch is the only entrypoint: POST /take asks for one token. It never throws to the caller (a failure
  // returns a 0-wait grant so a broken limiter degrades to "no throttle" rather than stopping backups,
  // mirroring CfPacer's never-throw take()).
  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (req.method === "POST" && url.pathname === "/take") {
      // Fail open: a storage error inside take() degrades to a 0-wait grant rather than a 500, so a
      // broken limiter never stops backups. The DistributedPacer client also guards, this makes the
      // guarantee hold at the DO too.
      let grant: RateGrant;
      try {
        grant = await this.take(Date.now());
      } catch {
        grant = { granted: true, waitMs: 0 };
        // The fail-open is the whole point, but it must not be silent, so record it (count + time only) so the
        // pack can report how often the limiter has degraded to no-throttle. Best-effort: recording a fault
        // must never turn the fail-open into a failure, so a throwing recorder is swallowed too.
        await this.noteFailOpen(Date.now());
      }
      return new Response(JSON.stringify(grant), { status: 200, headers: { "content-type": "application/json" } });
    }
    // The support pack's read of this DO's own health (INTERNAL). Presence alone (infra.rateLimitDoConfigured)
    // could not distinguish a working limiter from one that has been failing open for weeks; this can.
    if (req.method === "GET" && url.pathname === "/health") {
      return new Response(JSON.stringify(await this.health()), { status: 200, headers: { "content-type": "application/json" } });
    }
    return new Response(JSON.stringify({ error: "not found" }), { status: 404, headers: { "content-type": "application/json" } });
  }

  // noteFailOpen persists the degraded-to-no-throttle counter. Never throws: the fail-open path is already the
  // "our store is broken" path, so a failed counter write is expected there and must change nothing.
  async noteFailOpen(now: number): Promise<void> {
    try {
      const prior = (await this.state.storage.get<RateLimitHealth>(HEALTH_KEY)) ?? EMPTY_HEALTH;
      const at = Number.isFinite(now) ? Math.max(0, Math.floor(now)) : 0;
      await this.state.storage.put<RateLimitHealth>(HEALTH_KEY, {
        failOpenCount: Math.min(FAIL_OPEN_COUNT_CAP, prior.failOpenCount + 1),
        lastFailOpenAt: at,
        knobInvalid: knobIsInvalid(this.env),
      });
    } catch {
      /* best-effort: the store that just failed take() may fail this too; the caller is unaffected */
    }
  }

  // health returns the persisted counters plus the LIVE knob verdict (re-evaluated on read, so a knob fixed by
  // a redeploy reads clean immediately rather than carrying a stale flag from the last fail-open).
  async health(): Promise<RateLimitHealth> {
    let stored: RateLimitHealth = EMPTY_HEALTH;
    try {
      stored = (await this.state.storage.get<RateLimitHealth>(HEALTH_KEY)) ?? EMPTY_HEALTH;
    } catch {
      /* best-effort: an unreadable health record reads as the zero counter, never a 500 */
    }
    return { ...stored, knobInvalid: knobIsInvalid(this.env) };
  }

  // take is the shared-bucket arithmetic, factored out of fetch() so the validator drives it directly with a
  // fake clock. It refills proportional to elapsed time (capped at the burst), and either consumes a token
  // (granted, waitMs 0) or reports the ms until the next token is available (not granted, no consume). It is
  // serialised by the single DO instance, so N concurrent callers are paced in aggregate against ONE bucket.
  async take(now: number): Promise<RateGrant> {
    const rate = rateFromEnv(this.env);
    const capacity = burstFor(rate);
    const refillPerMs = rate / 1000;

    const stored = await this.state.storage.get<BucketState>(BUCKET_KEY);
    // First call: start full (the burst is free), exactly like CfPacer's constructor.
    let tokens = stored ? stored.tokens : capacity;
    const last = stored ? stored.last : now;

    // Refill for the elapsed time (clamp elapsed at 0 so a backwards clock never drains the bucket).
    const elapsed = Math.max(0, now - last);
    tokens = Math.min(capacity, tokens + elapsed * refillPerMs);

    if (tokens >= 1) {
      tokens -= 1;
      await this.state.storage.put<BucketState>(BUCKET_KEY, { tokens, last: now });
      return { granted: true, waitMs: 0 };
    }

    // No token yet: persist the refilled count + timestamp (so the next caller's refill is measured from
    // here, not from the original last), and tell the caller how long until one token has accrued.
    await this.state.storage.put<BucketState>(BUCKET_KEY, { tokens, last: now });
    const waitMs = Math.max(1, Math.ceil((1 - tokens) / refillPerMs));
    return { granted: false, waitMs };
  }
}
