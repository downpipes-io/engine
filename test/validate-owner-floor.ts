// validate-owner-floor: prove the single-owner dual-control DEADLOCK is impossible to ENTER, server-side.
// A solo owner arming dual control would then be unable to approve anything; this closes that gap by
// PREVENTION, raising the last-Owner floor to TWO while dual control is armed. No network, no deploy, no cost.
//   node test/validate-owner-floor.ts
//
// What it proves:
//   PURE (src/admin/owner-floor.ts): the floor arithmetic and its FAIL-SAFE (an ambiguous count refuses).
//   RULE A (enable): arming Require Approver with ONE Owner is refused (400), with two or more it is allowed,
//     and a refused enable never arms the gate.
//   RULE B (remove/demote): with dual control ON, removing OR demoting an Owner from a TWO-owner estate is
//     refused (the floor of two); from a THREE-owner estate it is allowed down to two (no over-block).
//   REGRESSION: the existing last-Owner guard still holds with dual control OFF, with its own
//     verbatim sentence.
//
// It reuses the production handleAdmin + in-memory SchedulerDO harness (buildContext), so every assertion is a
// real router -> DO outcome (an HTTP status, a persisted count read back, or the engine's own reason string).

import { buildContext } from "./validate-owner-action-dualcontrol-harness.ts";
import { checkOwnerRemoval, canRequireDualControl, ownerFloor, DUAL_CONTROL_ENABLE_REFUSAL, DUAL_CONTROL_FLOOR_REFUSAL, LAST_OWNER_REFUSAL } from "../src/admin/owner-floor.ts";
import type { Caller } from "../src/admin/identity.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
const errOf = async (r: Response): Promise<string> => ((await r.json()) as { error?: string }).error ?? "";
const jsonOf = async (r: Response): Promise<unknown> => r.json();
const ownerCountOf = (roster: unknown): number => (roster as Array<{ role: string }>).filter((r) => r.role === "owner").length;

async function main(): Promise<void> {
  // =============================================================================================
  // PART 1: the PURE floor invariant (src/admin/owner-floor.ts).
  // =============================================================================================
  console.log("-- pure owner-floor invariant --");
  ok("ownerFloor: off = 1", ownerFloor(false) === 1);
  ok("ownerFloor: on = 2", ownerFloor(true) === 2);

  ok("enable: refused with 0 Owners", canRequireDualControl(0) === false);
  ok("enable: refused with 1 Owner", canRequireDualControl(1) === false);
  ok("enable: allowed with 2 Owners", canRequireDualControl(2) === true);
  ok("enable: allowed with 3 Owners", canRequireDualControl(3) === true);
  ok("enable: fail-safe on NaN", canRequireDualControl(Number.NaN) === false);
  ok("enable: fail-safe on a non-integer", canRequireDualControl(1.5) === false);

  const rmVerdict = (n: number, on: boolean): string => { const v = checkOwnerRemoval(n, on); return v.ok ? "ok" : v.reason; };
  ok("remove: gate off, 1 Owner -> last-owner", rmVerdict(1, false) === "last-owner");
  ok("remove: gate off, 2 Owners -> allowed", rmVerdict(2, false) === "ok");
  ok("remove: gate on, 1 Owner -> last-owner", rmVerdict(1, true) === "last-owner");
  ok("remove: gate on, 2 Owners -> dual-control-floor", rmVerdict(2, true) === "dual-control-floor");
  ok("remove: gate on, 3 Owners -> allowed", rmVerdict(3, true) === "ok");
  ok("remove: fail-safe on NaN (gate on) refuses", checkOwnerRemoval(Number.NaN, true).ok === false);
  ok("remove: fail-safe on NaN (gate off) refuses", checkOwnerRemoval(Number.NaN, false).ok === false);
  ok("remove: fail-safe on a negative count refuses", checkOwnerRemoval(-1, true).ok === false);

  // =============================================================================================
  // PART 2: end to end through the production router + DO.
  // =============================================================================================
  console.log("\n-- server-side end to end --");
  const ctx = await buildContext();
  const { OWNER, OWNER2, call, doFetch } = ctx;
  const OWNER3 = "owner3-floor@acme.example";
  // The break-glass DO-direct caller: exempt from the owner-mint auto-gate, so it seeds extra Owners inline
  // while the gate is OFF (no propose/approve dance needed to reach a three-owner estate).
  const tokenCaller: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };

  // ---- RULE A (refuse): a lone Owner cannot arm dual control. ----
  const enable1 = await call(OWNER, "POST", "/admin/config/approval-policy", { requireConfigApproval: true });
  ok("rule a: enabling dual control with ONE Owner is refused (400)", enable1.status === 400);
  ok("rule a: the refusal names the two-Owner requirement", (await errOf(enable1)) === DUAL_CONTROL_ENABLE_REFUSAL);
  const pol1 = (await jsonOf(await call(OWNER, "GET", "/admin/config/approval-policy"))) as { requireConfigApproval: boolean };
  ok("rule a: the refused enable did NOT arm the gate (still off)", pol1.requireConfigApproval === false);

  // ---- REGRESSION: the last-Owner guard still holds with dual control OFF. ----
  const delOnly = await call(OWNER, "POST", "/admin/roles/delete", { email: OWNER });
  ok("regression: removing the only Owner (gate off) is refused (400)", delOnly.status === 400);
  ok("regression: the reason is the existing 'would remove the last Owner'", (await errOf(delOnly)) === LAST_OWNER_REFUSAL);

  // Seed a SECOND and THIRD Owner via the break-glass DO-direct path (gate off, so both apply inline).
  await doFetch("/roles", tokenCaller, { email: OWNER2, role: "owner" });
  await doFetch("/roles", tokenCaller, { email: OWNER3, role: "owner" });
  ok("seeded three Owners", ownerCountOf(await jsonOf(await call(OWNER, "GET", "/admin/roles"))) === 3);

  // ---- RULE A (allow): with >= 2 Owners, arming is allowed. ----
  const enable3 = await call(OWNER, "POST", "/admin/config/approval-policy", { requireConfigApproval: true });
  ok("rule a: enabling dual control with >= 2 Owners is allowed (200)", enable3.status === 200);
  const pol3 = (await jsonOf(await call(OWNER, "GET", "/admin/config/approval-policy"))) as { requireConfigApproval: boolean };
  ok("rule a: the gate is now armed", pol3.requireConfigApproval === true);

  // ---- RULE B (allow, no over-block): a THREE-owner dual-control estate can trim to two. ----
  // Under dual control the removal is a queued config change (202), not an immediate apply; a floor breach
  // would be refused at PROPOSE time (400), so a 202 here proves the guard did NOT over-block.
  const rm3 = await call(OWNER, "POST", "/admin/roles/delete", { email: OWNER3 });
  ok("rule b: removing an Owner from a 3-owner dual-control estate is ALLOWED (202 queued, not 400)", rm3.status === 202);
  const rm3id = ((await jsonOf(rm3)) as { id?: string }).id ?? "";
  const approve = await call(OWNER2, "POST", `/admin/config/changes/${rm3id}/approve`);
  ok("rule b: a DISTINCT Owner's approval applies the queued removal (200)", approve.status === 200);
  ok("rule b: the estate is now at two Owners", ownerCountOf(await jsonOf(await call(OWNER, "GET", "/admin/roles"))) === 2);

  // ---- RULE B (refuse): a TWO-owner dual-control estate cannot drop below two. ----
  const rm2 = await call(OWNER, "POST", "/admin/roles/delete", { email: OWNER2 });
  ok("rule b: removing an Owner from a 2-owner dual-control estate is refused (400)", rm2.status === 400);
  ok("rule b: the removal refusal names the dual-control floor", (await errOf(rm2)) === DUAL_CONTROL_FLOOR_REFUSAL);

  const demote2 = await call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "operator" });
  ok("rule b: DEMOTING an Owner from a 2-owner dual-control estate is refused (400)", demote2.status === 400);
  ok("rule b: the demotion refusal names the dual-control floor", (await errOf(demote2)) === DUAL_CONTROL_FLOOR_REFUSAL);

  ok("rule b: the refused changes left the estate at two Owners", ownerCountOf(await jsonOf(await call(OWNER, "GET", "/admin/roles"))) === 2);

  console.log(failures === 0 ? "\nAll owner-floor checks passed." : `\n${failures} owner-floor checks FAILED.`);
  if (failures > 0) process.exitCode = 1;
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
