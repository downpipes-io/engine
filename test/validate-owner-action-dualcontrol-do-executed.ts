// PROOF 2 + PROOF 3 of the OWNER-ACTION DUAL CONTROL suite, split out of
// validate-owner-action-dualcontrol.ts (behaviour-preserving). PROOF 2 turns the shared gate ON (owner-only).
// PROOF 3 drives every DO-EXECUTED owner op through the DO stub (the router-bypass proof): one owner => 202 /
// pending, NOT executed; self-approval refused; a second owner approving executes it.

import { ok } from "./validate-owner-action-dualcontrol-harness.ts";
import type { Ctx } from "./validate-owner-action-dualcontrol-harness.ts";
import { type PendingOwnerAction } from "../src/admin/owner-action.ts";

export async function run(ctx: Ctx): Promise<void> {
  const { OWNER, OWNER2, OPERATOR, call, setGate, doFetch, ownerCaller, ownerActionKeyCount, destConfig, oidcProposal, listDestinations, listIdpConnections, discoveryStatus } = ctx;

  // ===========================================================================================
  // PROOF 2: turn the gate ON (owner-only; reuses the SAME requireConfigApproval toggle)
  // ===========================================================================================
  {
    const opTry = await setGate(OPERATOR, true);
    ok("a non-owner cannot toggle the (shared) dual-control gate (403)", opTry.status === 403);
    const ownerOn = await setGate(OWNER, true);
    ok("the owner turns the shared dual-control gate ON (200)", ownerOn.status === 200);
    ok("the gate now reads ON", ((await (await call(OWNER, "GET", "/admin/config/approval-policy")).json()) as { requireConfigApproval: boolean }).requireConfigApproval === true);
  }

  // ===========================================================================================
  // PROOF 3: every DO-EXECUTED owner op, ON: one owner => 202/pending NOT executed; self-approve refused;
  //          second owner => executes. Driven THROUGH THE DO (the router-bypass proof: the DO still gates).
  // ===========================================================================================

  // A reusable driver for a DO-executed op via the DO stub (router-bypass): propose as OWNER, assert queued +
  // not executed, assert OWNER self-approve refused, assert OWNER2 approve executes (the `executed` check is
  // the caller's). Returns the pending id.
  async function doExecutedGate(opPath: string, params: unknown, label: string, alreadyExecuted: () => Promise<boolean>): Promise<string> {
    const before = ownerActionKeyCount();
    const proposeResp = await doFetch(opPath, ownerCaller(OWNER), params);
    ok(`[${label}] one owner => 202 (queued at the DO, not executed)`, proposeResp.status === 202);
    const pid = ((await proposeResp.json()) as { id?: string }).id ?? "";
    ok(`[${label}] the 202 carries an owner-action id`, pid.length > 0);
    ok(`[${label}] a pending owner action was recorded`, ownerActionKeyCount() === before + 1);
    ok(`[${label}] the op did NOT execute on one owner`, !(await alreadyExecuted()));
    // Self-approval refused at the DO (defence in depth) — the maker cannot approve their own action.
    const selfResp = await doFetch("/owner-actions/approve", ownerCaller(OWNER), { id: pid });
    ok(`[${label}] the proposer cannot approve their OWN action (DO refuses, 400)`, selfResp.status === 400 && /cannot approve your own action/.test(((await selfResp.json()) as { error?: string }).error ?? ""));
    ok(`[${label}] still not executed after the self-approve attempt`, !(await alreadyExecuted()));
    // A DISTINCT owner approves => the op executes (DO-executed runs on approve).
    const approveResp = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: pid });
    ok(`[${label}] a SECOND distinct owner approves (200)`, approveResp.status === 200);
    const arec = (await approveResp.json()) as PendingOwnerAction;
    ok(`[${label}] the approved record is executed + records both actors (maker != checker)`, arec.status === "executed" && arec.proposedBy === OWNER && arec.approvedBy === OWNER2 && arec.proposedBy !== arec.approvedBy);
    ok(`[${label}] the op EXECUTED after the second owner approved`, await alreadyExecuted());
    return pid;
  }

  // (a) dest-put: add a destination.
  await doExecutedGate("/destinations", { label: "gated-dest", config: destConfig("gated-bucket") }, "dest-put", async () => (await listDestinations()).destinations.some((d) => d.label === "gated-dest"));

  // (b) dest-default: repoint the default to the just-added destination.
  {
    const dests = (await listDestinations()).destinations;
    const target = dests.find((d) => d.label === "gated-dest")!;
    await doExecutedGate("/destinations/default", { id: target.id }, "dest-default", async () => (await listDestinations()).defaultId === target.id);
  }

  // (c) dest-remove: remove the off-dest (force, so the orphan guard never blocks the proof).
  {
    const dests = (await listDestinations()).destinations;
    const offDest = dests.find((d) => d.label === "off-dest")!;
    await doExecutedGate("/destinations/remove", { id: offDest.id, force: true }, "dest-remove", async () => !(await listDestinations()).destinations.some((d) => d.id === offDest.id));
  }

  // (d) idp-conn-create: wire an OIDC connection.
  await doExecutedGate("/idp/conn/create", oidcProposal("gated-oidc"), "idp-conn-create", async () => {
    const l = await listIdpConnections(OWNER);
    return (l.connections ?? []).some((c) => c.id === "gated-oidc");
  });

  // (e) idp-conn-enabled: disable that connection.
  await doExecutedGate("/idp/conn/enabled", { connId: "gated-oidc", enabled: false }, "idp-conn-enabled", async () => {
    const l = await listIdpConnections(OWNER);
    return (l.connections ?? []).some((c) => c.id === "gated-oidc" && c.enabled === false);
  });

  // (f) idp-conn-delete: delete that connection.
  await doExecutedGate("/idp/conn/delete", { connId: "gated-oidc" }, "idp-conn-delete", async () => {
    const l = await listIdpConnections(OWNER);
    return !(l.connections ?? []).some((c) => c.id === "gated-oidc");
  });

  // (g) discovery-token-set: set the account-read token (the secret VALUE is never in the inbox/audit). Seed
  // TWO accounts seen so the default selection stays EMPTY (a single-account token would auto-select one),
  // leaving a genuine state change for the discovery-accounts-set proof (h) below.
  await doExecutedGate("/sources/discovery-token", { token: "cfat_discovery_token_value_1234567890", accountsSeen: [{ id: "acct-1", name: "Acct One" }, { id: "acct-2", name: "Acct Two" }] }, "discovery-token-set", async () => (await discoveryStatus()).present === true);
  ok("discovery-token-set with two accounts leaves the selection empty (no auto-pick)", ((await discoveryStatus()).selected ?? []).length === 0);

  // (h) discovery-accounts-set: choose acct-1 to browse (a genuine change from the empty default above).
  await doExecutedGate("/sources/discovery-accounts", { selected: ["acct-1"], engineAccountId: "acct-1" }, "discovery-accounts-set", async () => ((await discoveryStatus()).selected ?? []).includes("acct-1"));

  // (i) break-glass-retire: retire the ADMIN_TOKEN bearer (two owners satisfy the in-place precondition).
  await doExecutedGate("/policy/break-glass-retired", { retired: true }, "break-glass-retire", async () => ((await (await call(OWNER, "GET", "/admin/status")).json()) as { breakGlassTokenRetired?: boolean }).breakGlassTokenRetired === true);
}
