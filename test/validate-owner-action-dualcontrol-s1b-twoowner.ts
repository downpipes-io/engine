// PROOF S1b (TWO OWNERS) of the OWNER-ACTION DUAL CONTROL suite, split out of
// validate-owner-action-dualcontrol.ts (behaviour-preserving). This group FIRST grants the second owner and a
// non-owner operator (so from here on the high-blast auto-apply engages), then proves the two-owner half of
// S1b: with the toggle OFF a high-blast op is auto-queued for a second owner; a non-high-blast op still
// applies inline; the bare-token break-glass is EXEMPT from the auto-apply (the bootstrap-deadlock fix).

import { ok, handleAdmin, TEAM, AUD } from "./validate-owner-action-dualcontrol-harness.ts";
import type { Ctx } from "./validate-owner-action-dualcontrol-harness.ts";
import type { Env } from "../src/env.d.ts";

export async function run(ctx: Ctx): Promise<void> {
  const { sched, OWNER, OWNER2, OPERATOR, call, doFetch, ownerCaller, destConfig, oidcProposal, listDestinations, listIdpConnections, inbox, ownerActionKeyCount } = ctx;

  // Now grant the SECOND owner (and a non-owner operator). From here on the high-blast auto-apply (S1b)
  // engages: a destination repoint/remove or an IdP change is dual-controlled regardless of the toggle.
  await call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "owner" });
  await call(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "operator" });

  // ===========================================================================================
  // PROOF S1b (TWO OWNERS): with the toggle OFF, a high-blast op (dest-remove / idp-conn-delete) is
  // AUTO-QUEUED for a second owner and CANNOT proceed on the proposer alone. This is the core S1b guarantee:
  // once a second owner exists the data/sign-in surfaces are dual-controlled even though requireConfigApproval
  // is off. A second owner approving then executes it; the toggle is confirmed OFF throughout.
  // ===========================================================================================
  {
    const toggleOff = async (): Promise<boolean> => !(((await (await call(OWNER, "GET", "/admin/config/approval-policy")).json()) as { requireConfigApproval: boolean }).requireConfigApproval);
    ok("[S1b 2-owner] the requireConfigApproval toggle is OFF for this proof", await toggleOff());

    // (a) dest-remove: AUTO-QUEUED despite the toggle being off. Seed a throwaway destination first (its add
    // is itself auto-gated with two owners, so run the dual-control dance to land it), then remove it. (off-dest
    // is left intact for the gate-ON PROOF 3(c) below.)
    {
      const addResp = await doFetch("/destinations", ownerCaller(OWNER), { label: "s1b-remove-me", config: destConfig("s1b-remove-bucket") });
      const addId = ((await addResp.json()) as { id?: string }).id ?? "";
      await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: addId });
      const seeded = (await listDestinations()).destinations.find((d) => d.label === "s1b-remove-me")!;
      ok("[S1b 2-owner] the throwaway destination was seeded via dual control", seeded !== undefined);
      const before = ownerActionKeyCount();
      const r = await doFetch("/destinations/remove", ownerCaller(OWNER), { id: seeded.id, force: true });
      ok("[S1b 2-owner] dest-remove returns 202 (auto-queued, toggle off)", r.status === 202);
      const pid = ((await r.json()) as { id?: string }).id ?? "";
      ok("[S1b 2-owner] the 202 carries an owner-action id", pid.length > 0);
      ok("[S1b 2-owner] a pending owner action was recorded for the auto-gated dest-remove", ownerActionKeyCount() === before + 1);
      ok("[S1b 2-owner] the dest-remove did NOT execute on the proposer alone (destination still present)", (await listDestinations()).destinations.some((d) => d.id === seeded.id));
      ok("[S1b 2-owner] the pending action is a dest-remove in the inbox", (await inbox(OWNER)).some((a) => a.id === pid && a.kind === "dest-remove"));
      // The toggle is STILL off (auto-apply is orthogonal to the opt-in toggle).
      ok("[S1b 2-owner] the requireConfigApproval toggle is STILL off (auto-apply is independent)", await toggleOff());
      // The maker cannot approve their own auto-gated action.
      const selfApprove = await doFetch("/owner-actions/approve", ownerCaller(OWNER), { id: pid });
      ok("[S1b 2-owner] the proposer cannot approve their own auto-gated dest-remove (400)", selfApprove.status === 400);
      // A second owner approves => it executes.
      const approve = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: pid });
      ok("[S1b 2-owner] a second owner approves the auto-gated dest-remove (200)", approve.status === 200);
      ok("[S1b 2-owner] the destination is removed after the second-owner approval", !(await listDestinations()).destinations.some((d) => d.id === seeded.id));
    }

    // (b) idp-conn-delete: seed an OIDC connection (also auto-gated, so seed via the dual-control flow), then
    // prove deleting it is AUTO-QUEUED with the toggle off.
    {
      // Create the connection: idp-conn-create is high-blast, so with two owners + toggle off it is queued too;
      // run the full dual-control dance to land the connection.
      const createResp = await doFetch("/idp/conn/create", ownerCaller(OWNER), oidcProposal("s1b-oidc"));
      ok("[S1b 2-owner] idp-conn-create is auto-queued with the toggle off (202)", createResp.status === 202);
      const createId = ((await createResp.json()) as { id?: string }).id ?? "";
      await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: createId });
      ok("[S1b 2-owner] the connection exists after the second-owner approval", (await listIdpConnections(OWNER)).connections?.some((c) => c.id === "s1b-oidc") === true);
      // Now delete it: AUTO-QUEUED with the toggle off.
      const before = ownerActionKeyCount();
      const delResp = await doFetch("/idp/conn/delete", ownerCaller(OWNER), { connId: "s1b-oidc" });
      ok("[S1b 2-owner] idp-conn-delete returns 202 (auto-queued, toggle off)", delResp.status === 202);
      const delId = ((await delResp.json()) as { id?: string }).id ?? "";
      ok("[S1b 2-owner] a pending owner action was recorded for the auto-gated idp-conn-delete", ownerActionKeyCount() === before + 1);
      ok("[S1b 2-owner] the connection is STILL present on the proposer alone", (await listIdpConnections(OWNER)).connections?.some((c) => c.id === "s1b-oidc") === true);
      ok("[S1b 2-owner] the pending action is an idp-conn-delete in the inbox", (await inbox(OWNER)).some((a) => a.id === delId && a.kind === "idp-conn-delete"));
      ok("[S1b 2-owner] the requireConfigApproval toggle is STILL off", await toggleOff());
      const approve = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: delId });
      ok("[S1b 2-owner] a second owner approves the auto-gated idp-conn-delete (200)", approve.status === 200);
      ok("[S1b 2-owner] the connection is gone after the second-owner approval", !(await listIdpConnections(OWNER)).connections?.some((c) => c.id === "s1b-oidc"));
    }

    // (c) a NON-high-blast DO-executed kind (dest-default) is NOT auto-gated with the toggle off: it applies
    // inline even with two owners, proving the auto-apply is scoped to the high-blast set, not all gated ops.
    {
      // Need two destinations so a non-default repoint is a genuine change. Seed two via the dual-control flow.
      for (const label of ["dd-a", "dd-b"]) {
        if (!(await listDestinations()).destinations.some((d) => d.label === label)) {
          const r = await doFetch("/destinations", ownerCaller(OWNER), { label, config: destConfig(`${label}-bucket`) });
          const pid = ((await r.json()) as { id?: string }).id ?? "";
          await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: pid });
        }
      }
      const ddTarget = (await listDestinations()).destinations.find((d) => d.label === "dd-b")!;
      const before = ownerActionKeyCount();
      const r = await doFetch("/destinations/default", ownerCaller(OWNER), { id: ddTarget.id });
      ok("[S1b 2-owner] dest-default (NOT high-blast) applies inline with the toggle off (200)", r.status === 200);
      ok("[S1b 2-owner] the dest-default change took effect inline", (await listDestinations()).defaultId === ddTarget.id);
      ok("[S1b 2-owner] dest-default queued NO owner action (not auto-gated)", ownerActionKeyCount() === before);
    }

    // (d) BREAK-GLASS EXEMPTION (the bootstrap-deadlock fix): the bare-token break-glass is EXEMPT from the
    // high-blast AUTO-apply (it is NOT exempt from the explicit opt-in toggle, proven ON in PROOF 3.6). With
    // two owners + the toggle off, a high-blast idp-conn-create runs INLINE for the break-glass (200, the
    // connection lands), where the SAME op via an attributable identity is auto-gated (202). Dual control
    // defends the realistic vector (a stolen attributable identity session); the break-glass is the
    // all-or-nothing override protected by the token secret (the same precedent requireStepUp sets by exempting
    // method === "token"). Without this exemption the DOCUMENTED first-Owner bootstrap deadlocks: the
    // break-glass cannot propose (no attributable maker) and there is no toggle to flip off, so it could never
    // wire the FIRST IdP connection (auto-enabled) before a second attributable owner exists to approve.
    {
      // A break-glass env (a bare ADMIN_TOKEN bearer) pointed at the SAME scheduler that now has two owners.
      const bgEnv = ({ ...sched.env, ADMIN_TOKEN: "bg-bootstrap-token", CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD }) as unknown as Env;
      const bgCall = (path: string, body: unknown): Promise<Response> =>
        handleAdmin(new Request(`https://engine.example${path}`, { method: "POST", headers: { authorization: "Bearer bg-bootstrap-token", "content-type": "application/json" }, body: JSON.stringify(body) }), bgEnv);

      // First confirm an ATTRIBUTABLE identity is STILL auto-gated for this exact high-blast op (the control).
      const idBefore = ownerActionKeyCount();
      const identityCreate = await call(OWNER, "POST", "/admin/idp/connections", oidcProposal("bg-control-oidc"));
      ok("[break-glass] an ATTRIBUTABLE owner's idp-conn-create is STILL auto-gated (202) with two owners", identityCreate.status === 202);
      const controlPid = ((await identityCreate.json()) as { id?: string }).id ?? "";
      ok("[break-glass] the attributable-owner create queued a pending action (auto-gate intact)", ownerActionKeyCount() === idBefore + 1);
      ok("[break-glass] the attributable-owner create did NOT land the connection on the proposer alone", !((await listIdpConnections(OWNER)).connections ?? []).some((c) => c.id === "bg-control-oidc"));
      // Clean it up via the dual-control flow so it is not mistaken for the break-glass result below.
      await doFetch("/owner-actions/reject", ownerCaller(OWNER2), { id: controlPid });

      // Now the break-glass: the SAME high-blast idp-conn-create runs INLINE (200), no pending action queued.
      const bgBefore = ownerActionKeyCount();
      const bgCreate = await bgCall("/admin/idp/connections", { presetId: "keycloak", vars: { host: "bg.acme.example", realm: "bootstrap" }, id: "bg-bootstrap-oidc", clientId: "bg-client", secret: "bg-secret" });
      ok("[break-glass] the bare-token break-glass idp-conn-create runs INLINE (200, not 202) despite two owners + auto-gate", bgCreate.status === 200);
      const bgBody = (await bgCreate.json()) as { ok?: boolean; conn?: { id?: string } };
      ok("[break-glass] the break-glass create reports ok and landed the connection (the first-IdP bootstrap)", bgBody.ok === true && bgBody.conn?.id === "bg-bootstrap-oidc");
      ok("[break-glass] the break-glass create queued NO owner action (exempt from the high-blast auto-apply)", ownerActionKeyCount() === bgBefore);
      ok("[break-glass] the break-glass connection is present in the management list (it actually wired)", ((await listIdpConnections(OWNER)).connections ?? []).some((c) => c.id === "bg-bootstrap-oidc"));
      // Clean up the break-glass connection (also via the break-glass, which is likewise exempt for delete).
      await bgCall("/admin/idp/connections/delete", { connId: "bg-bootstrap-oidc" });
    }
  }
}
