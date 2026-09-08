// PROOF 0 + PROOF 1 + PROOF S1b (one owner) of the OWNER-ACTION DUAL CONTROL suite. Split out of
// validate-owner-action-dualcontrol.ts; behaviour-preserving (every assertion is byte-faithful). These run in
// the SINGLE-OWNER phase: only the first owner is bootstrapped, so the high-blast auto-apply (S1b) does not yet
// engage. The orchestrator calls run() before granting the second owner.

import { ok } from "./validate-owner-action-dualcontrol-harness.ts";
import type { Ctx } from "./validate-owner-action-dualcontrol-harness.ts";
import {
  OWNER_ACTION_KINDS,
  HIGH_BLAST_ALWAYS_GATED,
  isOwnerActionKind,
  isRouterExecutedOwnerAction,
  isHighBlastAlwaysGated,
  ROUTER_EXECUTED_OWNER_ACTIONS,
} from "../src/admin/owner-action.ts";

export async function run(ctx: Ctx): Promise<void> {
  const { OWNER, ownerActionKeyCount, doFetch, ownerCaller, destConfig, listDestinations, inbox } = ctx;

  // ===========================================================================================
  // PROOF 0: the owner-action module is internally consistent (the closed set + the flow split)
  // ===========================================================================================
  {
    ok("every owner-action kind round-trips isOwnerActionKind", OWNER_ACTION_KINDS.every((k) => isOwnerActionKind(k)));
    ok("isOwnerActionKind rejects an unknown kind", !isOwnerActionKind("not-a-kind") && !isOwnerActionKind(42));
    ok("the router-executed set is a subset of the kinds", [...ROUTER_EXECUTED_OWNER_ACTIONS].every((k) => (OWNER_ACTION_KINDS as readonly string[]).includes(k)));
    ok("update/attach/mint are router-executed; destinations are NOT", isRouterExecutedOwnerAction("update-apply") && isRouterExecutedOwnerAction("sources-attach") && isRouterExecutedOwnerAction("support-credential-mint") && !isRouterExecutedOwnerAction("dest-put"));
    // The exact partition (a drift guard: a new kind must be classified as router- or DO-executed deliberately).
    const routerExecuted = OWNER_ACTION_KINDS.filter((k) => isRouterExecutedOwnerAction(k)).sort();
    const doExecuted = OWNER_ACTION_KINDS.filter((k) => !isRouterExecutedOwnerAction(k)).sort();
    ok("the router-executed kinds are exactly {update-apply, update-settle, sources-attach, support-credential-mint}", JSON.stringify(routerExecuted) === JSON.stringify(["sources-attach", "support-credential-mint", "update-apply", "update-settle"]));
    ok("the DO-executed kinds are exactly the destination/push/otlp-push/idp/break-glass/discovery/dual-control-disable set", JSON.stringify(doExecuted) === JSON.stringify(["break-glass-retire", "dest-default", "dest-put", "dest-remove", "dest-set", "discovery-accounts-set", "discovery-token-set", "dual-control-disable", "idp-conn-cert", "idp-conn-create", "idp-conn-delete", "idp-conn-enabled", "otlp-push-dest-set", "push-dest-set"]));
    ok("dual-control-disable is a DO-executed kind (the off switch runs on approve, not via a router token)", !isRouterExecutedOwnerAction("dual-control-disable") && (OWNER_ACTION_KINDS as readonly string[]).includes("dual-control-disable"));
  }

  // ===========================================================================================
  // PROOF 1: GATE OFF (default), ONE OWNER — a DO-executed owner op runs INLINE, no pending record (no
  // regression, and the S1b no-deadlock case: a high-blast op proceeds inline while there is only one owner
  // so the single-owner self-hosted bootstrap is never locked out, the step-up being the sole control).
  // ===========================================================================================
  {
    const before = ownerActionKeyCount();
    // Driving the DO directly with an owner caller, gate off: putDest runs inline and the destination exists.
    const r = await doFetch("/destinations", ownerCaller(OWNER), { label: "off-dest", config: destConfig("off-bucket") });
    ok("a gate-off destination add returns 200 (applied inline)", r.status === 200);
    ok("the gate-off add changed state INLINE (the destination exists)", (await listDestinations()).destinations.some((d) => d.label === "off-dest"));
    ok("NO pending owner action was recorded on the gate-off path", ownerActionKeyCount() === before);
    ok("the owner-action inbox is empty with the gate off", (await inbox(OWNER)).length === 0);
  }

  // ===========================================================================================
  // PROOF S1b (ONE OWNER): the high-blast auto-apply does NOT engage with a single owner. A high-blast
  // gate-check (dest-remove / idp-conn-delete) returns gate:'off' so the op proceeds inline; with one owner
  // there is no second owner to approve, so auto-gating would deadlock the bootstrap. This proves the
  // no-lone-owner-deadlock half of S1b at the DO gate decision itself.
  // ===========================================================================================
  {
    // Pure logic guards (the closed high-blast set), so a future kind is classified deliberately.
    ok("[S1b] the high-blast set is exactly {dest-set,dest-put,dest-remove,idp-conn-create,idp-conn-delete,idp-conn-enabled,idp-conn-cert,push-dest-set,otlp-push-dest-set}", JSON.stringify([...HIGH_BLAST_ALWAYS_GATED].sort()) === JSON.stringify(["dest-put", "dest-remove", "dest-set", "idp-conn-cert", "idp-conn-create", "idp-conn-delete", "idp-conn-enabled", "otlp-push-dest-set", "push-dest-set"]));
    ok("[S1b] dest-default is NOT auto-gated (lower blast than add/remove)", !isHighBlastAlwaysGated("dest-default"));
    ok("[S1b] discovery/break-glass kinds are NOT auto-gated", !isHighBlastAlwaysGated("discovery-token-set") && !isHighBlastAlwaysGated("break-glass-retire"));
    // The router gate-check rejects DO-executed kinds, so prove the gate DECISION via gatedOwnerAction: a
    // dest-remove of the off-dest with one owner and the toggle off APPLIES INLINE (200), not queued.
    const before = ownerActionKeyCount();
    const offDest = (await listDestinations()).destinations.find((d) => d.label === "off-dest")!;
    const r = await doFetch("/destinations/remove", ownerCaller(OWNER), { id: offDest.id, force: true });
    ok("[S1b] a dest-remove (high-blast) with ONE owner + toggle off applies INLINE (200)", r.status === 200);
    ok("[S1b] the one-owner dest-remove changed state inline (the destination is gone)", !(await listDestinations()).destinations.some((d) => d.id === offDest.id));
    ok("[S1b] NO pending owner action was queued for the one-owner high-blast op", ownerActionKeyCount() === before);
    // Re-add off-dest (gate off, one owner -> inline) so the later 2-owner proofs that expect it still find it.
    const re = await doFetch("/destinations", ownerCaller(OWNER), { label: "off-dest", config: destConfig("off-bucket") });
    ok("[S1b] re-adding off-dest with one owner applies inline (200)", re.status === 200);
  }
}
