// Pins the /support/* DoS-ordering hardening: an ABSENT bearer is rejected 401 BEFORE
// any SchedulerDO round-trip, so an unauthenticated flood cannot make each rejected request cost one DO
// fetch (a softer DoS target than /metrics, which already short-circuits its empty bearer first). A present
// (even wrong) bearer still incurs exactly the one grant lookup a real credential check needs.
//
// Run: node test/validate-destsim-pull-dos.ts

import { handleSupportPull, resetAuthFailureThrottle, shouldRecordAuthFailure } from "../src/admin/support-ingest.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log((cond ? "  ok   " : "  FAIL ") + label);
  if (!cond) failures++;
}

// A scheduler stub that COUNTS fetches so we can prove the ordering: an empty-bearer request must issue zero.
function countingScheduler(): { stub: DurableObjectStub; count: () => number } {
  let n = 0;
  const stub = {
    fetch: async (input: RequestInfo | URL): Promise<Response> => {
      n++;
      const path = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url).pathname;
      if (path === "/ingest-credential") return new Response(JSON.stringify({ grant: null }), { headers: { "content-type": "application/json" } });
      return new Response("{}", { headers: { "content-type": "application/json" } });
    },
  } as unknown as DurableObjectStub;
  return { stub, count: () => n };
}

const env = {} as Env;

async function main(): Promise<void> {
  // 1. Empty bearer -> 401, and NOT a single DO fetch (the ordering fix).
  {
    const { stub, count } = countingScheduler();
    const resp = await handleSupportPull(new Request("https://engine.example/support/audit-feed"), env, stub);
    ok("empty bearer: 401", resp.status === 401);
    ok("empty bearer: ZERO DO round-trips (the ordering fix)", count() === 0);
  }
  // 2. No Authorization header at all -> same short-circuit.
  {
    const { stub, count } = countingScheduler();
    const resp = await handleSupportPull(new Request("https://engine.example/support/diagnostics"), env, stub);
    ok("absent Authorization: 401 with zero DO round-trips", resp.status === 401 && count() === 0);
  }
  // 3. A present (wrong) bearer DOES do the one grant lookup a real check needs, then 401s -- and a SUSTAINED
  //    storm of them must not scale DO WRITES with the attempt count. This branch is reachable by any
  //    unauthenticated caller, so an unthrottled diagnostic recorder on it would make the act of OBSERVING an
  //    attack a write amplifier for that attack, on the very route whose anti-DoS ordering (case 1 above: an
  //    absent/empty bearer is rejected with ZERO round-trips) exists to deny exactly that. The recorder is
  //    therefore throttled to one write per window per isolate.
  {
    const { stub, count } = countingScheduler();
    const resp = await handleSupportPull(
      new Request("https://engine.example/support/audit-feed", { headers: { Authorization: "Bearer not-a-real-credential" } }),
      env,
      stub,
    );
    ok("present-but-wrong bearer: 401", resp.status === 401);
    // A wrong bearer does the ONE grant lookup a real check needs, plus AT MOST one THROTTLED diagnostic write
    // (the rejected-pull counter, so "our SIEM stopped collecting" arrives with a cause). The
    // count is therefore 1 or 2, and the assertion below is the one that actually matters.
    ok("present-but-wrong bearer: one grant lookup, plus at most one throttled diagnostic write", count() === 1 || count() === 2);
  }
  // 3b. THE AMPLIFICATION PROPERTY, asserted directly rather than inferred from a round-trip count: a storm of
  //     rejected pulls must not drive a storage write per attempt. The counter still SEES the storm (it counts
  //     the distinct windows in which rejections occurred, and its lastAt stays exact), so support can say
  //     "you have had rejected pulls since Tuesday", but an attacker cannot
  //     turn it into a write multiplier.
  {
    resetAuthFailureThrottle();
    const t0 = 1_000_000;
    let allowed = 0;
    for (let i = 0; i < 5000; i++) if (shouldRecordAuthFailure(t0 + i)) allowed += 1; // 5,000 attempts in one window
    ok("a 5,000-request 401 storm inside one window drives ONE diagnostic write, not 5,000", allowed === 1);
    // The signal is not lost: a storm that persists into the next window records again, so "is this still
    // happening?" -- the question the counter exists to answer -- is still answerable.
    ok("a storm that PERSISTS into the next window is still recorded (the signal survives the throttle)", shouldRecordAuthFailure(t0 + 61_000) === true);
    resetAuthFailureThrottle();
  }

  // 4. A non-GET or unknown path still 404s (regression guard, unchanged).
  {
    const { stub } = countingScheduler();
    const post = await handleSupportPull(new Request("https://engine.example/support/audit-feed", { method: "POST" }), env, stub);
    ok("POST /support/audit-feed: 404 (unchanged)", post.status === 404);
  }

  console.log(failures === 0 ? "\nDESTSIM PULL DoS-ORDERING PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
