// Site fault 2 of 3: the rate limiter's health read (RateLimitDO.health, a DO other than the scheduler).
//
// The pack reads GET /health on the account rate limiter. When the limiter cannot read its own health record,
// the catch answers the zero counter, so the pack's rateLimitDoHealth reads clean while the store is failing.
// Before site faults nothing recorded the read fault.
//
// This proof exercises the cross-DO path: the catch notes the fault in the limiter's isolate, the limiter's
// fetch() drains it to the scheduler DO (POST /diag/site-faults) before it answers, and the same pack build
// that triggered the read then reads siteFaults from the scheduler. Two worlds: a healthy limiter store and one
// whose get() throws. The real SchedulerDO, the real RateLimitDO and the real buildSupportBundle serve both.
//
// Run: node test/validate-site-fault-ratelimit-health.ts

import { RateLimitDO } from "../src/sched/ratelimit-do.ts";
import { diffPaths, namespaceOver, normalise, ok, packOver, SENTINEL, sentinelError, siteFaultRows, storageText, stubOver, tally } from "./lib/site-fault-proof.ts";
import { makeScheduler } from "./validate-scheduler-shared.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

type Mode = "healthy" | "throws" | "overloaded";

async function world(mode: Mode): Promise<{ pack: Record<string, unknown>; stored: string; storedBeforePack: string }> {
  const { storage, stub: dobj } = makeScheduler();
  const scheduler = stubOver(dobj);
  const rlStorage = {
    async get(): Promise<unknown> {
      if (mode === "throws") throw sentinelError();
      if (mode === "overloaded") {
        const e = sentinelError();
        (e as unknown as { overloaded: boolean }).overloaded = true;
        throw e;
      }
      return undefined;
    },
    async put(): Promise<void> {},
  };
  const rl = new RateLimitDO({ storage: rlStorage } as unknown as DurableObjectState, { CF_API_RATE_PER_SEC: "10", SCHEDULER: namespaceOver(scheduler) } as unknown as { CF_API_RATE_PER_SEC?: unknown });
  // A health read before any pack (as a metrics scrape would make): the limiter's own fetch() drain must carry the
  // row to the scheduler DO's storage by itself.
  await rl.fetch(new Request("https://ratelimit.internal/health"));
  const storedBeforePack = storageText(storage);
  const pack = await packOver({ RATELIMIT_DO: namespaceOver(stubOver(rl)) }, scheduler);
  return { pack, stored: storageText(storage), storedBeforePack };
}

async function main(): Promise<void> {
  console.log("the limiter cannot read its health record; the pack must say so:");
  const healthy = await world("healthy");
  const faulty = await world("throws");
  const health = (p: Record<string, unknown>): unknown => (p.infra as Record<string, unknown> | undefined)?.rateLimitDoHealth;
  ok("the symptom: rateLimitDoHealth reads the same zero counter in both worlds", JSON.stringify(health(healthy.pack)) === JSON.stringify(health(faulty.pack)) && (health(faulty.pack) as { failOpenCount?: number } | undefined)?.failOpenCount === 0);
  ok("control: the healthy world's pack carries no siteFaults", siteFaultRows(healthy.pack).length === 0);
  const diff = diffPaths(normalise(healthy.pack), normalise(faulty.pack));
  console.log(`  pack paths that differ between the healthy and fault worlds: ${diff.length === 0 ? "none" : diff.join(", ")}`);
  ok("the fault world's pack differs from its healthy twin", diff.length > 0);
  ok("every differing path is under siteFaults or the section summary", diff.length > 0 && diff.every((p) => p.startsWith("$.siteFaults") || p.startsWith("$.sections") || p.startsWith("$.sectionsSummary")));
  const row = siteFaultRows(faulty.pack).find((r) => r.id === "ratelimit.health-read");
  ok("siteFaults names ratelimit.health-read", row !== undefined);
  ok("the limiter's own drain wrote the row to the scheduler DO before any pack was built", faulty.storedBeforePack.includes("ratelimit.health-read"));
  ok("the row carries class error and counts both reads (the earlier one and the pack's own)", row?.cls === "error" && row?.count === 2);
  ok("the row carries its legend line", row?.subsystem === "rate-limit" && row?.fixClass === "storage-health" && typeof row?.what === "string");

  console.log("the platform's overloaded flag is a class of its own:");
  const over = await world("overloaded");
  const orow = siteFaultRows(over.pack).find((r) => r.id === "ratelimit.health-read");
  ok("an error with overloaded: true is recorded as do-overloaded", orow?.cls === "do-overloaded");

  console.log("redaction:");
  for (const [label, w] of [["throws", faulty], ["overloaded", over]] as const) {
    ok(`${label}: the sentinel is not in the pack`, !JSON.stringify(w.pack).includes(SENTINEL));
    ok(`${label}: the sentinel is not in the scheduler DO's storage`, !w.stored.includes(SENTINEL));
  }

  const { failures, checks } = tally();
  console.log(`\n${failures === 0 ? "PASS" : "FAIL"} validate-site-fault-ratelimit-health (${failures} failure(s) of ${checks})`);
  verdictReached(failures, checks);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
