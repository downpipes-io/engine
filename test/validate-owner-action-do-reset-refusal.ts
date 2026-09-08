// validate-owner-action-do-reset-refusal.ts -- proves an owner-action fix: a FORESEEABLE plain-Error
// refusal from a replayed owner action (e.g. removeDest throwing "no such destination" when the target changed
// between propose and approve, scheduler-do-dest-config.ts:312) is now SENTINELLED inside approveOwnerAction's
// blockConcurrencyWhile, not re-thrown. A throw escaping the guard RESETS the Durable Object in workerd (wiping
// in-memory scheduler state -> 500); the fix makes it a clean 4xx with the DO intact. Before the fix the catch
// handled only AuthError and re-threw a plain Error inside the guard (guardThrows()===1). This is the
// non-AuthError sibling of the case already covered by validate-owner-action-dualcontrol-execstate.ts.

import { buildContext, ok, failureCount } from "./validate-owner-action-dualcontrol-harness.ts";

const ctx = await buildContext();
const { OWNER, OWNER2, call, doFetch, ownerCaller } = ctx;

// Two owners so a dest-remove auto-gates even with the toggle off.
await call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "owner" });

// Propose a dest-remove for a destination id that does NOT exist. gatedOwnerAction records the pending action
// without validating existence; the execute (removeDest) is where "no such destination" is thrown -- a PLAIN
// Error, not an AuthError. This models a target that was valid at propose time but is gone at approve time.
ctx.sched.resetGuardThrows();
const propose = await doFetch("/destinations/remove", ownerCaller(OWNER), { id: "no-such-destination", force: true });
ok("a dest-remove of a bogus id is auto-queued for a second owner (202)", propose.status === 202);
const pid = ((await propose.json()) as { id?: string }).id ?? "";

// A DISTINCT owner approves -> executeOwnerActionDO -> removeDest("no-such-destination") throws a plain Error.
const approve = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: pid });
ok("the plain-Error apply refusal is a clean 4xx, not a 5xx", approve.status >= 400 && approve.status < 500);
ok("the plain Error did NOT escape blockConcurrencyWhile (guardThrows()===0 -> no DO reset, so 4xx not 500)", ctx.sched.guardThrows() === 0);

// The record must be untouched (still pending, single-use preserved): a refused apply writes nothing.
const inbox = await ctx.inbox(OWNER);
ok("the refused action is still pending (nothing written on the refusal)", inbox.some((a) => a.id === pid && a.status === "pending"));

console.log(`\n${failureCount() === 0 ? "DO-RESET REFUSAL (owner-action, non-AuthError) PASS" : "DO-RESET REFUSAL: " + failureCount() + " FAIL"}`);
if (failureCount() > 0) process.exitCode = 1;
if (failureCount() > 0) process.exit(1);
