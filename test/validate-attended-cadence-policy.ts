// The attended-verification cadence as ESTATE STATE: the route, the owner gate, the audit record and the
// control-plane round trip.
//
// validate-attended-cadence.ts proves the pure oracle; this proves the plumbing that gives it a number to
// read, driven through the REAL admin router and the REAL Durable Object using the shared owner-action
// harness, so what is asserted is the wiring rather than a re-implementation of it.
//
// WHAT EARNS EACH ASSERTION:
//
//   The default. Absent must read 0 and mean NO CADENCE, not a cadence of zero. If this regressed, every
//   estate that never chose an interval would acquire a live obligation the moment the field shipped, which
//   is the reason the field is optional at all.
//
//   The owner gate. Lengthening a proof interval weakens the estate's stated assurance, so it is an owner
//   decision even though nothing gates on it. The DO re-resolves the caller from its own tables, so this
//   asserts the refusal at the DO rather than trusting the router's gate.
//
//   Clearing. 0 must stay reachable. An operator who set a cadence has to be able to stop stating a rhythm
//   they no longer keep, and forcing them to pick a long interval instead would leave a number in the
//   compliance record nobody intends to meet.
//
//   The audit record. Unlike the boolean policies, whose value is deliberately never written to the
//   immutable log, the interval IS recorded, because an integer of days is redaction-safe and a LONGER
//   interval is exactly the change a reviewer needs to see. So the assertion is that the number reaches the
//   log, not merely that an event did.
//
//   The control-plane round trip. The cadence rides the signed export so a reconciled estate restores the
//   rhythm its operator chose. That is only safe because due is computed per downpipe from proof history
//   that does NOT survive into a fresh account, so the recovered estate lands never-verified rather than
//   overdue. This asserts the carry; validate-attended-cadence.ts asserts the state.
//
// Run with `node test/validate-attended-cadence-policy.ts`.

import { ok, failureCount, buildContext } from "./validate-owner-action-dualcontrol-harness.ts";

async function main(): Promise<void> {
  const ctx = await buildContext();
  const { OWNER, OPERATOR, call, doFetch, ownerCaller, readLog, subjectOf } = ctx;

  console.log("\n-- the attended-verification cadence as estate state --\n");

  // ---- the default ---------------------------------------------------------------------------------------
  const initial = (await (await call(OWNER, "GET", "/admin/config/attended-cadence")).json()) as { attendedCadenceDays?: number };
  ok("an estate that never set a cadence reads 0, which means NO cadence rather than a zero-day one", initial.attendedCadenceDays === 0);

  // ---- setting it ----------------------------------------------------------------------------------------
  const setResp = await call(OWNER, "POST", "/admin/config/attended-cadence", { attendedCadenceDays: 90 });
  ok("the owner sets a 90-day cadence (200)", setResp.status === 200);
  const afterSet = (await (await call(OWNER, "GET", "/admin/config/attended-cadence")).json()) as { attendedCadenceDays?: number };
  ok("and it reads back", afterSet.attendedCadenceDays === 90);

  // ---- the bounds ----------------------------------------------------------------------------------------
  // A sub-day cadence cannot be met by a ceremony that needs a person present, and on split custody a quorum.
  // Beyond ten years an interval is indistinguishable from "never" while still reading as a stated rhythm.
  ok("a fractional interval is refused", (await call(OWNER, "POST", "/admin/config/attended-cadence", { attendedCadenceDays: 1.5 })).status === 400);
  ok("a negative interval is refused", (await call(OWNER, "POST", "/admin/config/attended-cadence", { attendedCadenceDays: -1 })).status === 400);
  ok("beyond ten years is refused", (await call(OWNER, "POST", "/admin/config/attended-cadence", { attendedCadenceDays: 3651 })).status === 400);
  ok("a non-number is refused", (await call(OWNER, "POST", "/admin/config/attended-cadence", { attendedCadenceDays: "90" })).status === 400);
  const stillNinety = (await (await call(OWNER, "GET", "/admin/config/attended-cadence")).json()) as { attendedCadenceDays?: number };
  ok("and none of those refusals disturbed the stored value", stillNinety.attendedCadenceDays === 90);

  // ---- the owner gate -----------------------------------------------------------------------------------
  // Lengthening a proof interval weakens the estate's stated assurance, so it is an owner decision even
  // though nothing gates on it. The router gates first, and the DO re-resolves the caller from its own tables
  // in setAttendedCadenceDays, so a router bug alone cannot let a non-owner move it.
  const asOperator = await call(OPERATOR, "POST", "/admin/config/attended-cadence", { attendedCadenceDays: 7 });
  ok("a non-owner cannot change the cadence", asOperator.status === 403);
  const afterDenied = (await (await call(OWNER, "GET", "/admin/config/attended-cadence")).json()) as { attendedCadenceDays?: number };
  ok("and the refused attempt left the stored interval untouched", afterDenied.attendedCadenceDays === 90);
  // Reading it is not an owner action: it is one integer, it names no run and carries no proof history.
  ok("a non-owner CAN read the interval", (await call(OPERATOR, "GET", "/admin/config/attended-cadence")).status === 200);

  // Defence in depth, and this is the assertion that makes the previous one more than a test of the router.
  // The DO re-resolves the caller's role from its OWN tables, so a FORGED owner header on an operator's
  // identity must still be refused: a router bug alone cannot move the cadence. Without this the router gate
  // could be deleted and every assertion above would still pass.
  const forged = await doFetch("/config/attended-cadence", { method: "access", email: OPERATOR, subject: subjectOf(OPERATOR), role: "owner", groups: [] }, { attendedCadenceDays: 7 });
  ok("the DO refuses a forged owner header on a non-owner identity", forged.status === 403);
  const afterForged = (await (await call(OWNER, "GET", "/admin/config/attended-cadence")).json()) as { attendedCadenceDays?: number };
  ok("and the forged attempt left the stored interval untouched", afterForged.attendedCadenceDays === 90);

  // ---- the audit record ----------------------------------------------------------------------------------
  // The number itself must reach the log: a reviewer needs to see an interval being LENGTHENED, which an
  // event with no value cannot show.
  const events = (await readLog()).events;
  const cadenceEvents = events.filter(
    (e) => e.action === "config-policy-change" && (e.target as { policyName?: string } | undefined)?.policyName === "attended-cadence",
  );
  ok("setting the cadence records a config-policy-change naming the policy", cadenceEvents.length >= 1);
  ok(
    "and the audit target carries the NEW INTERVAL, so a lengthening is visible to a reviewer",
    cadenceEvents.some((e) => (e.target as { newDays?: number } | undefined)?.newDays === 90),
  );

  // ---- clearing ------------------------------------------------------------------------------------------
  ok("0 is accepted and CLEARS the cadence", (await call(OWNER, "POST", "/admin/config/attended-cadence", { attendedCadenceDays: 0 })).status === 200);
  const cleared = (await (await call(OWNER, "GET", "/admin/config/attended-cadence")).json()) as { attendedCadenceDays?: number };
  ok("and the estate reads back as having no cadence", cleared.attendedCadenceDays === 0);

  // ---- the control-plane round trip ------------------------------------------------------------------------
  // The cadence rides the signed export so a reconciled estate restores the rhythm its operator chose. That is
  // only safe because due is computed per downpipe from proof history that does NOT survive into a fresh
  // account, so a recovered estate lands never-verified rather than overdue.
  await call(OWNER, "POST", "/admin/config/attended-cadence", { attendedCadenceDays: 180 });
  const slice = (await (await doFetch("/control-plane/export", ownerCaller(OWNER), undefined, "GET")).json()) as {
    orgPolicy?: Record<string, unknown>;
  };
  ok("and the no-custody export slice carries it, so a reconciled estate restores the chosen rhythm", slice.orgPolicy?.["attendedCadenceDays"] === 180);

  // An estate that CLEARED its cadence must export 0 rather than dropping the field, because dropping it
  // would make "the operator turned it off" indistinguishable from "this estate predates the field".
  await call(OWNER, "POST", "/admin/config/attended-cadence", { attendedCadenceDays: 0 });
  const slice2 = (await (await doFetch("/control-plane/export", ownerCaller(OWNER), undefined, "GET")).json()) as {
    orgPolicy?: Record<string, unknown>;
  };
  ok("a cleared cadence exports as 0, distinguishable from an estate that predates the field", slice2.orgPolicy?.["attendedCadenceDays"] === 0);

  console.log(`\n${failureCount() === 0 ? "ATTENDED-CADENCE-POLICY PASS" : `ATTENDED-CADENCE-POLICY: ${failureCount()} FAILED`}\n`);
  if (failureCount() > 0) process.exitCode = 1;
  process.exit(failureCount() === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
