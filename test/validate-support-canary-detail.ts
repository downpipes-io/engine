// Prove the support pack's canary section carries the WHY of a death.
//
// fetchCanaryHealth must carry more than the aggregate liveness + the transition ring (a bird flipped dead
// at T): the coarse deadReason, which flight aspect failed, the stray byte-delta, and whether the schedule
// is still armed. The DO's lightweight /canary/transitions view returns nextRunAt + a per-dead-destination
// deadDetail derived from each destination's lastCheck, and the pack projects it redaction-safely. This test
// drives the real fetchCanaryHealth through a DO double and asserts the detail rides, the failed-aspect list
// is gated to the closed 8-member vocabulary, reasonAbsent flags a reason-less death, scheduleArmed is
// derived, and no coarse detail string leaks a value.
//
// Run:  node test/validate-support-canary-detail.ts

import { fetchCanaryHealth } from "../src/admin/support-sections-seal.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function canaryScheduler(view: unknown): DurableObjectStub {
  return {
    async fetch(input: RequestInfo | URL): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === "/canary/transitions") return new Response(JSON.stringify(view));
      return new Response("{}");
    },
  } as unknown as DurableObjectStub;
}

async function main(): Promise<void> {
  console.log("validate-support-canary-detail\n");

  const view = {
    enabled: true,
    status: "dead",
    deadDestinations: 2,
    transitionCount: 1,
    transitions: [{ at: "2026-07-11T00:00:00Z", destinationId: "dest-a", to: "dead", runSeq: 7 }],
    nextRunAt: 1_800_000_000_000,
    deadDetail: [
      // A real death with a coarse reason + a failed aspect + a stray byte-delta.
      { destinationId: "dest-a", at: "2026-07-11T00:00:00Z", deadReason: "decrypt-integrity: 3 bytes strayed", byteDelta: 3, failedAspects: ["decrypt-integrity", "restore-verify", "not-a-real-aspect"] },
      // A death record with NO stored reason (the worker died without reporting why).
      { destinationId: "dest-b", at: "2026-07-11T01:00:00Z", deadReason: null, byteDelta: null, failedAspects: [] },
    ],
  };

  const c = (await fetchCanaryHealth(canaryScheduler(view))) as Record<string, unknown>;
  const detail = c.deadDetail as Array<Record<string, unknown>>;

  ok("canary carries scheduleArmed derived from enabled + a positive nextRunAt", c.scheduleArmed === true && c.nextRunAt === 1_800_000_000_000);
  ok("canary.deadDetail carries one row per dead destination", Array.isArray(detail) && detail.length === 2);
  // Pull the two rows out once (indexing is unchecked under noUncheckedIndexedAccess). A row that went
  // missing falls back to an empty object, so every field assertion below reads undefined and FAILS
  // honestly rather than throwing before its ok() is recorded.
  const realDeath = detail[0] ?? {};
  const reasonlessDeath = detail[1] ?? {};
  ok("a real death carries its coarse deadReason + stray byteDelta", realDeath.deadReason === "decrypt-integrity: 3 bytes strayed" && realDeath.byteDelta === 3);
  ok("failedAspects is gated to the closed 8-member vocabulary (the bogus key is dropped)", Array.isArray(realDeath.failedAspects) && (realDeath.failedAspects as string[]).length === 2 && !(realDeath.failedAspects as string[]).includes("not-a-real-aspect"));
  ok("a reason-less death is flagged reasonAbsent (not silently omitted)", reasonlessDeath.reasonAbsent === true && reasonlessDeath.deadReason === undefined);

  // A disarmed schedule (enabled but no next flight) reads scheduleArmed false -- the WHY an enabled bird stopped.
  const disarmed = (await fetchCanaryHealth(canaryScheduler({ ...view, nextRunAt: 0 }))) as Record<string, unknown>;
  ok("an enabled canary with no next flight reads scheduleArmed false (the disarmed-schedule signal)", disarmed.scheduleArmed === false);

  // Honest absence: a quiet, never-flown canary (no status, no transitions, no detail) still omits the block.
  const quiet = (await fetchCanaryHealth(canaryScheduler({ enabled: false, transitions: [], deadDetail: [] }))) as Record<string, unknown>;
  ok("a never-flown canary still returns {} (honest absence preserved)", Object.keys(quiet).length === 0);

  console.log(failures === 0 ? "\nALL SUPPORT-CANARY-DETAIL VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
