// validate-restore-approval-optional: proves the RESTORE-apply dual-control gate is owner-opt-in and that
// BOTH directions of the switch are real.
//
// WHY THIS EXISTS. The gate used to be unconditional, and canApprove refuses a same-subject AND a same-email
// approval, so a one-identity estate could plan a restore and never apply it: the product's core promise was
// unreachable in a configuration the product itself calls valid (BASE_MIN_OWNERS is 1). The fix must not be
// graded by "a solo apply now proceeds" alone, because a dead gate would also pass that. So the ARMED case is
// asserted here too: with the policy on, an unapproved apply must still be refused. Only the two together
// distinguish "made optional" from "broken".
//
// Run: node test/validate-restore-approval-optional.ts
import { buildContext } from "./validate-owner-action-dualcontrol-harness.ts";
import { seedBoundRole } from "./testutil.ts";
import { canRequireDualControl, RESTORE_DUAL_CONTROL_ENABLE_REFUSAL } from "../src/admin/owner-floor.ts";
import { approvalKey, APPROVAL_TTL_MS, canApprove, type RestoreApproval } from "../src/admin/approvals.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  if (!cond) failures++;
  console.log(`${cond ? "ok  " : "FAIL"}  ${label}`);
}

//
// A NOTE ON THE CALL SHAPE: doFetch's planHash argument must actually reach the DO, or gateRestore
// refuses on a missing planHash before it ever looks for an approval, and the control that is supposed
// to separate "made optional" from "gate switched off" would measure neither.
const ctx = await buildContext();
const { call, OWNER, doFetch, ownerCaller } = ctx;
const PLAN = "plan-hash-for-the-optional-gate-proof";

try {
  // ---- 1. THE DEFAULT IS OFF, which is what makes a solo estate able to recover at all.
  const view = (await (await call(OWNER, "GET", "/admin/config/approval-policy")).json()) as {
    requireRestoreApproval?: boolean; requireConfigApproval?: boolean;
  };
  ok("the restore-approval policy defaults OFF", view.requireRestoreApproval === false);
  ok("it is a SEPARATE flag from the config gate (both readable)", typeof view.requireConfigApproval === "boolean");

  // ---- 2. POLICY OFF: the gate reports no approval required, so a lone operator's apply proceeds.
  const off = (await (await doFetch("/restore/gate", ownerCaller(OWNER), { planHash: PLAN })).json()) as {
    usable: boolean; required: boolean; approval: unknown;
  };
  ok("policy OFF -> the gate does not require an approval", off.required === false);
  ok("policy OFF -> the apply is not blocked", off.usable === true);
  ok("policy OFF -> there is no approval record to carry", off.approval === null);

  // ---- 3. THE ARM FLOOR FIRES FIRST, on the estate as it stands: ONE Owner.
  // This is not a setup step, it is the guard doing its job. Arming while solo would leave nobody able to
  // approve a restore, which is the exact lockout this policy was added to end, so it is refused on the way
  // in rather than discovered in an incident.
  const soloArm = await call(OWNER, "POST", "/admin/config/restore-approval-policy", { requireRestoreApproval: true });
  ok("a SOLO estate is refused when it tries to arm the gate", soloArm.status >= 400);
  const soloBody = await soloArm.text();
  ok("and the refusal explains the remedy", /second Owner or Approver/.test(soloBody));
  const stillOff = (await (await doFetch("/restore/gate", ownerCaller(OWNER), { planHash: PLAN })).json()) as { required: boolean };
  ok("a refused arm leaves the estate solo-capable, not half-armed", stillOff.required === false);

  // ---- 4. ARM IT PROPERLY. This is the control: if the gate were merely broken, the armed case would pass
  // too, and "made optional" would be indistinguishable from "switched off".
  await call(OWNER, "POST", "/admin/roles", { email: ctx.OWNER2, role: "owner" });
  const armed = await call(OWNER, "POST", "/admin/config/restore-approval-policy", { requireRestoreApproval: true });
  ok("an Owner CAN arm it once a second Owner exists", armed.status === 200);

  const on = (await (await doFetch("/restore/gate", ownerCaller(OWNER), { planHash: PLAN })).json()) as {
    usable: boolean; required: boolean;
  };
  ok("policy ON -> the gate requires an approval", on.required === true);
  ok("policy ON -> an UNAPPROVED apply is still refused", on.usable === false);

  // ---- 4a. THE POSITIVE CONTROL, and without it the armed assertions prove nothing. Every armed check
  // above is a REFUSAL, so a gate that refused unconditionally, or one that never received the plan hash
  // at all, would satisfy all of them. So the armed gate must be shown to SPEAK as well as refuse. A usable
  // approval is seeded at the plan's own key and the same call must flip.
  const now = Date.now();
  // BOTH IDENTITIES MUST BE IN THE DO'S OWN ROLE TABLE. The gate re-resolves maker and checker at SPEND
  // time (approvalSpendVerdict), so a record naming two identities the estate does not know is refused
  // however well-formed it is, and that refusal looks exactly like "no approval", which is the failure
  // this control exists to tell apart.
  await seedBoundRole(ctx.sched.storage, ctx.subjectOf("maker@acme.example"), "maker@acme.example", "operator");
  await seedBoundRole(ctx.sched.storage, ctx.subjectOf("checker@acme.example"), "checker@acme.example", "approver");
  await ctx.sched.storage.put(`planseen:${PLAN}`, { at: now });
  const iso = (ms: number): string => new Date(ms).toISOString();
  // Built as a REAL RestoreApproval rather than cast into one, so the compiler enforces every field the
  // gate's real read path expects.
  const seededRecord: RestoreApproval = {
    planHash: PLAN,
    runId: "run-positive-control",
    isLatest: true,
    plannedWrites: 1,
    bytes: 1024,
    redirectBinding: null,
    requesterSubject: ctx.subjectOf("maker@acme.example"),
    requestedBy: "maker@acme.example",
    requesterGroups: [],
    requestedAt: iso(now),
    reason: "the positive control",
    status: "approved",
    approverSubject: ctx.subjectOf("checker@acme.example"),
    approvedBy: "checker@acme.example",
    approverGroups: [],
    approvedAt: iso(now),
    expiresAt: iso(now + APPROVAL_TTL_MS),
  };
  await ctx.sched.storage.put(approvalKey(PLAN), seededRecord);
  const seeded = (await (await doFetch("/restore/gate", ownerCaller(OWNER), { planHash: PLAN })).json()) as { usable: boolean; required: boolean };
  ok("policy ON + a usable approval for THIS plan -> the gate OPENS (it reads the plan hash, it does not just refuse)",
    seeded.required === true && seeded.usable === true);
  const otherPlan = (await (await doFetch("/restore/gate", ownerCaller(OWNER), { planHash: `${PLAN}-a-different-plan` })).json()) as { usable: boolean };
  ok("...and a DIFFERENT plan hash is still refused, so the open above was about this plan and not a blanket yes",
    otherPlan.usable === false);

  // ---- 5. DISARM returns the estate to solo-capable.
  const disarmed = await call(OWNER, "POST", "/admin/config/restore-approval-policy", { requireRestoreApproval: false });
  ok("an Owner can disarm it again", disarmed.status === 200);
  const backOff = (await (await doFetch("/restore/gate", ownerCaller(OWNER), { planHash: PLAN })).json()) as { required: boolean };
  ok("after disarm the gate is optional again", backOff.required === false);

  // ---- 6. THE FLOOR AS PURE LOGIC. Arming while solo would re-create the very lockout this policy exists to end.
  ok("a one-identity estate may NOT arm the gate", canRequireDualControl(1) === false);
  ok("a two-identity estate may", canRequireDualControl(2) === true);
  ok("the refusal names the remedy, not just the refusal", /Appoint a second Owner or Approver/.test(RESTORE_DUAL_CONTROL_ENABLE_REFUSAL));

  // ---- 7. THE UNDERLYING REASON, pinned so nobody "simplifies" maker != checker away later.
  const rec = { planHash: PLAN, requestedBy: "solo@example.com", requesterSubject: "sub-solo", requestedAt: Date.now(), status: "requested", reason: "DR" } as never;
  ok("one identity still cannot approve its own restore when the gate IS armed",
    canApprove(rec, "solo@example.com", "sub-solo", Date.now()).ok === false);
  ok("a distinct second identity still can",
    canApprove(rec, "other@example.com", "sub-other", Date.now()).ok === true);
} finally {
  globalThis.fetch = ctx.realFetch;
}

if (failures > 0) process.exitCode = 1;
console.log(failures === 0 ? "\nPASS" : `\n${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
