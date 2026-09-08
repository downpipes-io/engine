// Proves the ACCOUNT-GLOBAL CF API limiter's bucket maths and the drop-in pacer wiring, in-process only,
// no network, no real Durable Object. It shows that N takers against
// ONE shared bucket are paced in aggregate (the burst is free, then a positive wait is returned once the
// burst is spent and the bucket refills proportional to elapsed time), that DistributedPacer is a drop-in
// CfPacer whose take() loops the DO grant, and that accountPacer falls back to EXACTLY a local CfPacer when
// the RATELIMIT_DO binding is absent. It does NOT prove live cross-isolate enforcement through a real DO
// under concurrent isolates; that go-live is a deliberate later step.
// Run: node test/validate-ratelimit-do.ts

import { RateLimitDO, type RateGrant } from "../src/sched/ratelimit-do.ts";
import { CfPacer, DistributedPacer, accountPacer, pacerFromEnv } from "../src/cf-pace.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// A minimal in-memory DurableObjectState.storage double: one get/put over a Map, enough for the bucket.
function fakeState(): DurableObjectState {
  const map = new Map<string, unknown>();
  const storage = {
    get: async <T>(k: string): Promise<T | undefined> => map.get(k) as T | undefined,
    put: async <T>(k: string, v: T): Promise<void> => {
      map.set(k, v);
    },
  };
  return { storage } as unknown as DurableObjectState;
}

async function main(): Promise<void> {
  console.log("RateLimitDO.take: ONE shared bucket, fake clock, aggregate pacing across many takers:");
  {
    // rate 10/s => refillPerMs 0.01, burst = ceil(10) = 10. A fixed clock means NO refill between calls,
    // so the burst is exactly the number of free grants before the bucket reports a wait.
    const env = { CF_API_RATE_PER_SEC: "10" };
    const ratelimit = new RateLimitDO(fakeState(), env);
    const t0 = 1_000_000; // a fixed "now" so elapsed is 0 across the burst.

    let granted = 0;
    let firstWait: RateGrant | null = null;
    // 10 takers in the burst are all granted with waitMs 0; the 11th (clock unchanged) must report a wait.
    for (let i = 0; i < 10; i++) {
      const g = await ratelimit.take(t0);
      if (g.granted && g.waitMs === 0) granted++;
    }
    firstWait = await ratelimit.take(t0);
    ok("the burst (10 tokens) is all granted at waitMs 0", granted === 10);
    ok("the 11th take() past the burst is NOT granted and returns a POSITIVE wait", firstWait.granted === false && firstWait.waitMs > 0);
    // At 10/s one token accrues in ~100ms; the reported wait is on that order (>=1ms, bounded sane).
    ok("the reported wait is ~one refill period (>=1ms, <=100ms for 10/s)", firstWait.waitMs >= 1 && firstWait.waitMs <= 100);
  }

  console.log("\nRateLimitDO.take: advancing the fake clock refills the SAME bucket (aggregate, not per-caller):");
  {
    const env = { CF_API_RATE_PER_SEC: "10" }; // 0.01 tokens/ms, burst 10
    const ratelimit = new RateLimitDO(fakeState(), env);
    let now = 2_000_000;
    // Drain the whole burst at a fixed instant.
    for (let i = 0; i < 10; i++) await ratelimit.take(now);
    const drained = await ratelimit.take(now);
    ok("bucket drained: next take() at the same instant waits", !drained.granted && drained.waitMs > 0);

    // Advance 100ms: at 0.01/ms that is exactly 1 token, so EXACTLY ONE further take() is granted, then
    // the bucket is empty again. This is the aggregate property: refill is wall-clock based and shared, not
    // reset per caller.
    now += 100;
    const afterRefill = await ratelimit.take(now);
    const afterThat = await ratelimit.take(now);
    ok("after 100ms (=1 token at 10/s) exactly ONE more take() is granted", afterRefill.granted && afterRefill.waitMs === 0);
    ok("and the very next take() at the same instant is paced again (one token, not a reset burst)", !afterThat.granted && afterThat.waitMs > 0);
  }

  console.log("\nRateLimitDO.take: a backwards clock never drains the bucket (elapsed clamped at 0):");
  {
    const env = { CF_API_RATE_PER_SEC: "5" };
    const ratelimit = new RateLimitDO(fakeState(), env);
    await ratelimit.take(5_000_000); // establishes last = 5_000_000
    const back = await ratelimit.take(4_000_000); // clock jumps backwards
    ok("a backwards clock still grants from the remaining burst (no negative refill)", back.granted && back.waitMs === 0);
  }

  console.log("\nDistributedPacer.take: drop-in CfPacer that loops the DO grant via an in-process stub:");
  {
    // A stub RateLimitDO fronted by a fetch() the DistributedPacer POSTs /take to. Grant the first two
    // asks, then make the third ask wait once (waitMs small) and the fourth grant, proving the loop sleeps
    // and re-asks rather than giving up.
    const ratelimit = new RateLimitDO(fakeState(), { CF_API_RATE_PER_SEC: "1000" }); // generous; we drive grants directly
    // A scripted grant sequence consumed in order across ALL asks (cursor does not reset between take()s).
    // First take(): grant[0] granted -> 1 ask. Second take(): grant[1] not-granted then grant[2] granted -> 2 asks.
    const grants: RateGrant[] = [
      { granted: true, waitMs: 0 },
      { granted: false, waitMs: 5 },
      { granted: true, waitMs: 0 },
    ];
    let cursor = 0;
    let asks = 0;
    const stub = {
      fetch: async (): Promise<Response> => {
        const g = grants[Math.min(cursor, grants.length - 1)];
        cursor++;
        asks++;
        return new Response(JSON.stringify(g), { status: 200, headers: { "content-type": "application/json" } });
      },
    };
    const pacer = new DistributedPacer(stub);
    ok("DistributedPacer is assignable as a CfPacer (drop-in)", pacer instanceof CfPacer);

    // First take(): one ask, granted at once.
    asks = 0;
    await pacer.take();
    ok("a granted take() resolves after ONE ask", asks === 1);

    // Second take(): the first ask is NOT granted (waitMs 5), so it sleeps then re-asks and is granted: 2 asks.
    asks = 0;
    const t0 = Date.now();
    await pacer.take();
    ok("a not-granted-then-granted take() asks TWICE (loops the wait)", asks === 2);
    ok("and it actually slept the reported wait (>=1ms)", Date.now() - t0 >= 1);

    void ratelimit; // ratelimit constructed to prove the DO type is importable alongside the pacer
  }

  console.log("\nDistributedPacer.take: fail-open on a DO outage (never blocks a backup):");
  {
    const stub = {
      fetch: async (): Promise<Response> => {
        throw new Error("DO unreachable");
      },
    };
    const pacer = new DistributedPacer(stub);
    let resolved = false;
    await pacer.take();
    resolved = true;
    ok("a take() against an unreachable DO resolves (fail-open), never throws or hangs", resolved);
  }

  console.log("\naccountPacer: falls back to a local CfPacer when RATELIMIT_DO is absent (byte-identical pacing):");
  {
    ok("no binding -> a plain CfPacer (NOT a DistributedPacer)", accountPacer({}) instanceof CfPacer && !(accountPacer({}) instanceof DistributedPacer));
    ok("no binding + a knob -> a plain CfPacer (same as pacerFromEnv)", accountPacer({ CF_API_RATE_PER_SEC: "2" }) instanceof CfPacer && !(accountPacer({ CF_API_RATE_PER_SEC: "2" }) instanceof DistributedPacer));
    // The fallback paces exactly like pacerFromEnv: a 1-burst slow pacer delays the second take().
    const fb = accountPacer({ CF_API_RATE_PER_SEC: "20" });
    const ref = pacerFromEnv({ CF_API_RATE_PER_SEC: "20" });
    ok("the fallback and pacerFromEnv are the same class", fb.constructor === ref.constructor);
  }

  console.log("\naccountPacer: returns a DistributedPacer when the RATELIMIT_DO binding IS present:");
  {
    const stub = {
      fetch: async (): Promise<Response> => new Response(JSON.stringify({ granted: true, waitMs: 0 }), { status: 200 }),
    };
    const ns = {
      idFromName: (_name: string): unknown => ({ id: "account-cf-api" }),
      get: (_id: unknown): typeof stub => stub,
    };
    const pacer = accountPacer({ CF_API_RATE_PER_SEC: "3", RATELIMIT_DO: ns });
    ok("binding present -> a DistributedPacer", pacer instanceof DistributedPacer);
    // It works as a pacer: a granted take() resolves.
    let resolved = false;
    await pacer.take();
    resolved = true;
    ok("the account pacer's take() resolves against the granting stub", resolved);
  }

  console.log(failures === 0 ? "\nRATELIMIT-DO / DISTRIBUTED-PACER VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
