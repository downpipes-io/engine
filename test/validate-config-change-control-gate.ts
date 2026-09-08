// PROOF 0/1/2 of the config change-control validator: the module invariants, the gate-OFF inline path,
// and the owner-only toggle. Split out of validate-config-change-control.ts for size; every assertion is
// byte-identical and runs in the same order against the shared live DO.

import type { Ctx } from "./validate-config-change-control-harness.ts";
import { OWNER, OPERATOR, ACCESS_ADMIN } from "./validate-config-change-control-harness.ts";
import {
  CHANGE_KINDS,
  CHANGE_WRITE_CAPABILITY,
  isConfigChangeKind,
} from "../src/admin/change-control.ts";

export async function runGate(ctx: Ctx): Promise<void> {
  const { ok, call, listDownpipes, pendingChanges, pendingKeyCount, setGate, dp } = ctx;

  // ===========================================================================================
  // PROOF 0: the change-control module is internally consistent (the closed-set + map invariants)
  // ===========================================================================================
  {
    ok("every change kind has a write capability mapping", CHANGE_KINDS.every((k) => CHANGE_WRITE_CAPABILITY[k] !== undefined));
    ok("isConfigChangeKind accepts every declared kind", CHANGE_KINDS.every((k) => isConfigChangeKind(k)));
    ok("isConfigChangeKind rejects an unknown kind", !isConfigChangeKind("not-a-kind") && !isConfigChangeKind(42));
  }

  // ===========================================================================================
  // PROOF 1: GATE OFF (default) == current behaviour - inline apply, NO pending record
  // ===========================================================================================
  {
    // The gate is OFF by default (no policy record set). A config mutation applies inline and changes
    // state immediately, with NO pending change created.
    const gateView = (await (await call(OWNER, "GET", "/admin/config/approval-policy")).json()) as { requireConfigApproval: boolean };
    ok("the gate is OFF by default", gateView.requireConfigApproval === false);

    const before = pendingKeyCount();
    const r = await call(OPERATOR, "POST", "/admin/downpipes", dp("dp_off", "off-pipe"));
    ok("a gate-off config mutation returns 200 (applied inline, not 202)", r.status === 200);
    const got = await listDownpipes();
    ok("the gate-off mutation changed state INLINE (the downpipe now exists)", got.some((d) => d.config.id === "dp_off"));
    ok("NO pending change record was created on the gate-off path", pendingKeyCount() === before);
    // The inbox is empty (nothing queued).
    ok("the pending-change inbox is empty with the gate off", (await pendingChanges(OWNER)).length === 0);
    // A config-history version was snapshotted (the gate-off path auto-snapshots, exactly as before).
    const hist = (await (await call(OWNER, "GET", "/admin/config/history")).json()) as { versions: Array<{ id: number }> };
    ok("the gate-off mutation auto-snapshotted into config history", hist.versions.length > 0);
    // Clean up so later proofs start tidy (delete is also a gate-off inline apply here).
    await call(OPERATOR, "POST", "/admin/downpipes/delete", { id: "dp_off" });
    ok("the gate-off delete also applied inline", !(await listDownpipes()).some((d) => d.config.id === "dp_off"));
  }

  // ===========================================================================================
  // PROOF 2: OWNER-ONLY toggle (and break-glass can always toggle); a non-owner cannot
  // ===========================================================================================
  {
    // An OPERATOR cannot flip the gate (not owner). access.policy is held by access-admin, but the toggle
    // is OWNER-ONLY (gated on keys.ceremony), so even an access-admin cannot flip it.
    const opTry = await setGate(OPERATOR, true);
    ok("an operator cannot toggle the gate (403)", opTry.status === 403);
    const aaTry = await setGate(ACCESS_ADMIN, true);
    ok("an access-admin cannot toggle the gate (403, it is owner-only not access.policy)", aaTry.status === 403);
    // The gate is still off (no unauthorised flip took effect).
    ok("the gate stayed OFF after the refused toggles", ((await (await call(OWNER, "GET", "/admin/config/approval-policy")).json()) as { requireConfigApproval: boolean }).requireConfigApproval === false);
    // The OWNER can turn it ON.
    const ownerOn = await setGate(OWNER, true);
    ok("the owner can toggle the gate ON (200)", ownerOn.status === 200 && ((await ownerOn.json()) as { requireConfigApproval: boolean }).requireConfigApproval === true);
    ok("the gate now reads ON", ((await (await call(OWNER, "GET", "/admin/config/approval-policy")).json()) as { requireConfigApproval: boolean }).requireConfigApproval === true);
  }
}
