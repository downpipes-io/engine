// CfPacer is a token-bucket throttle for CLOUDFLARE ACCOUNT-API calls (cf-config, workers, discovery).
// It is the PROACTIVE half of the rate-limit defence: it paces a crawl's calls BELOW Cloudflare's global
// account-API limit (~1200 req / 5 min, i.e. ~4/s, SHARED with the customer's own Terraform/dashboard/
// tooling), so a large crawl does not burst into a wall of 429s in the first place. withRetry (seal/
// retry.ts) is the REACTIVE half that rides out a 429 that still happens, honouring Retry-After.
//
// SCOPE (honest): a Worker isolate has no shared in-memory state with other isolates/DOs, so this bucket
// bounds the burst of ONE crawl (one RunSealDO / one invocation), not the whole fleet. Cross-downpipe
// coordination is provided by two existing mechanisms, not this class: the cron driver spaces downpipe
// STARTS under one shared subrequest budget, and a slice that still trips a persistent rate limit fails
// and resumes on the RunSealDO alarm's 5 s -> 5 min backoff. A truly account-global limiter would need a
// shared rate-limit Durable Object every API caller checks; that is a deliberate future step, recorded so
// this is not mistaken for fleet-wide coordination.
//
// Default rate is deliberately conservative (well under the account ceiling, leaving headroom for the
// customer's other tooling) and is overridable via the CF_API_RATE_PER_SEC env knob.

export const DEFAULT_CF_API_RATE_PER_SEC = 3;

export class CfPacer {
  private tokens: number;
  private readonly capacity: number;
  private readonly refillPerMs: number;
  private last: number;

  constructor(opts?: { ratePerSec?: number; burst?: number }) {
    const rate = opts?.ratePerSec ?? DEFAULT_CF_API_RATE_PER_SEC;
    // A small burst lets a short crawl run unthrottled, then the refill rate paces a long one. Burst
    // defaults to one second's worth of tokens (at least 1), so a tiny crawl is never delayed.
    this.capacity = Math.max(1, opts?.burst ?? Math.ceil(rate));
    this.refillPerMs = rate / 1000;
    this.tokens = this.capacity;
    this.last = Date.now();
  }

  // take resolves when a token is available, sleeping in bounded steps until the bucket refills. It never
  // throws and never waits unboundedly per call (it re-checks each ~250 ms), so a paused crawl still makes
  // progress on the next alarm rather than holding an isolate open.
  async take(): Promise<void> {
    for (;;) {
      const now = Date.now();
      this.tokens = Math.min(this.capacity, this.tokens + (now - this.last) * this.refillPerMs);
      this.last = now;
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }
      const waitMs = Math.min(250, Math.ceil((1 - this.tokens) / this.refillPerMs));
      await new Promise((r) => setTimeout(r, waitMs));
    }
  }
}

// pacerFromEnv builds a CfPacer from the optional CF_API_RATE_PER_SEC knob (a positive number of
// requests/second), falling back to the conservative default. An invalid value falls back rather than
// throwing, exactly like budgetFromEnv, so a typo'd knob never stops backups.
export function pacerFromEnv(env: { CF_API_RATE_PER_SEC?: unknown }): CfPacer {
  const raw = env.CF_API_RATE_PER_SEC;
  if (typeof raw === "string" && raw.trim() !== "") {
    const n = Number(raw);
    if (Number.isFinite(n) && n > 0) return new CfPacer({ ratePerSec: n });
  }
  return new CfPacer();
}

// The minimal shape DistributedPacer needs from a RateLimitDO stub: a fetch() it can POST /take to. The
// stub is what env.RATELIMIT_DO.get(id) returns; we type only fetch so the validator can hand it an
// in-process double without a full DurableObjectStub.
interface RateLimitStub {
  fetch(input: Request | string, init?: RequestInit): Promise<Response>;
}

// The namespace shape: idFromName + get, the standard DurableObjectNamespace surface we use (the engine
// already names singletons this way, e.g. SCHEDULER.idFromName("account-scheduler")).
interface RateLimitNamespace {
  idFromName(name: string): unknown;
  get(id: unknown): RateLimitStub;
}

// The single account-global bucket instance name. Every isolate names the same instance so they all draw
// from one bucket.
const RATELIMIT_DO_NAME = "account-cf-api";

// DistributedPacer is the ACCOUNT-GLOBAL drop-in for CfPacer: its take() resolves once the shared
// RateLimitDO grants a token, sleeping the DO-reported wait between asks. It extends CfPacer purely so it
// is assignable everywhere a `pacer?: CfPacer` is expected (CfPacer carries private fields, so a bare
// structural object would not satisfy the type); the inherited bucket fields are unused because take() is
// fully overridden to consult the DO instead of the in-memory bucket.
//
// It never throws: a failed DO round-trip resolves immediately (fail-open, like CfPacer.take()), so a
// broken or unreachable limiter degrades to "no extra throttle" rather than stopping backups. withRetry
// (the reactive half) still rides out any 429 that slips through.
export class DistributedPacer extends CfPacer {
  private readonly stub: RateLimitStub;

  constructor(stub: RateLimitStub) {
    super();
    this.stub = stub;
  }

  override async take(): Promise<void> {
    for (;;) {
      let grant: { granted: boolean; waitMs: number };
      try {
        const res = await this.stub.fetch("https://ratelimit-do/take", { method: "POST" });
        grant = (await res.json()) as { granted: boolean; waitMs: number };
      } catch {
        return; // fail-open: never block a backup on a limiter outage.
      }
      if (grant.granted) return;
      // Bound the per-iteration sleep so a paused crawl still makes progress on the next alarm rather than
      // holding the isolate open for an unbounded wait (matches CfPacer's 250 ms re-check ceiling).
      const waitMs = Math.min(250, Math.max(0, grant.waitMs));
      await new Promise((r) => setTimeout(r, waitMs));
    }
  }
}

// accountPacer is the factory the adapter sites call. When the RATELIMIT_DO binding is present it returns a
// DistributedPacer fronting the shared singleton (account-global pacing); when it is absent it falls back to
// EXACTLY pacerFromEnv(env), so every site that was already paced per-isolate keeps byte-identical behaviour
// and the per-call DO round-trip is never on the default path. Go-live = setting the binding.
export function accountPacer(env: { CF_API_RATE_PER_SEC?: unknown; RATELIMIT_DO?: unknown }): CfPacer {
  const ns = env.RATELIMIT_DO as RateLimitNamespace | undefined;
  if (ns && typeof ns.idFromName === "function" && typeof ns.get === "function") {
    return new DistributedPacer(ns.get(ns.idFromName(RATELIMIT_DO_NAME)));
  }
  return pacerFromEnv(env);
}
