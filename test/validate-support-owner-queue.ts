// Prove the support pack projects the dual-control owner-action queue aggregate.
//
// The configEvents excerpt carries individual propose/approve/reject events, but on a busy estate an old
// un-approved proposal rolls past the 40-event window and there was no live queue state, so "a high-blast-
// radius change is stuck waiting for a second owner" was undiagnosable. fetchOwnerActionQueue reads the new
// caller-independent DO aggregate and projects counts + oldest proposal + a closed-kind breakdown + the
// expired-undecided stall count. This drives the real gatherer through a DO double and asserts the counts
// ride, the kinds are gated to the closed vocabulary, and no id/summary/actor is echoed.
//
// Run:  node test/validate-support-owner-queue.ts

import { fetchOwnerActionQueue } from "../src/admin/support-sections-config.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function scheduler(stats: unknown): DurableObjectStub {
  return {
    async fetch(input: RequestInfo | URL): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === "/owner-actions/queue-stats") return new Response(JSON.stringify(stats));
      return new Response("{}");
    },
  } as unknown as DurableObjectStub;
}

async function main(): Promise<void> {
  console.log("validate-support-owner-queue\n");

  const q = (await fetchOwnerActionQueue(scheduler({
    pendingCount: 3,
    approvalsOutstanding: 2,
    expiredUndecidedCount: 1,
    oldestProposedAt: "2026-07-01T00:00:00.000Z",
    kinds: { "update-apply": 2, "dest-remove": 1, "totally-made-up-kind": 5 },
  }))) as Record<string, unknown>;

  ok("ownerActionQueue carries pendingCount + approvalsOutstanding + expiredUndecidedCount", q.pendingCount === 3 && q.approvalsOutstanding === 2 && q.expiredUndecidedCount === 1);
  ok("ownerActionQueue carries the oldest proposal timestamp (age is bot-side)", q.oldestProposedAt === "2026-07-01T00:00:00.000Z");
  ok("kinds are gated to the closed OwnerActionKind vocabulary (bogus kind dropped, real kinds kept)", (() => { const k = q.kinds as Record<string, number>; return k["totally-made-up-kind"] === undefined && k["update-apply"] === 2 && k["dest-remove"] === 1; })());
  ok("ownerActionQueue never echoes an id/summary/actor (counts + closed kinds + a timestamp only)", !JSON.stringify(q).includes("summary") && !JSON.stringify(q).includes("@"));

  // A quiet queue (nothing outstanding, nothing expired) returns {} so section() marks it "empty".
  const quiet = (await fetchOwnerActionQueue(scheduler({ pendingCount: 0, approvalsOutstanding: 0, expiredUndecidedCount: 0, oldestProposedAt: null, kinds: {} }))) as Record<string, unknown>;
  ok("a quiet owner-action queue returns {} (honest absence)", Object.keys(quiet).length === 0);

  // An expired-undecided-only queue still rides (a governance stall with no live pending is still a signal).
  const expiredOnly = (await fetchOwnerActionQueue(scheduler({ pendingCount: 0, expiredUndecidedCount: 2, kinds: {} }))) as Record<string, unknown>;
  ok("an expired-undecided-only queue still rides (governance stall visible)", expiredOnly.expiredUndecidedCount === 2);

  console.log(failures === 0 ? "\nALL SUPPORT-OWNER-QUEUE VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
