// PROOF 3.5 + PROOF 3.6 + PROOF 5 + PROOF 6 + PROOF 6.5 of the OWNER-ACTION DUAL CONTROL suite, split out of
// validate-owner-action-dualcontrol.ts (behaviour-preserving). These cover the ROUTER end-to-end path, the
// asymmetric dual-control OFF SWITCH (FOLD 1, with the disarm alert), the router-executed gate (record / arm /
// single-use consume) for update/apply + the other router-executed ops, and the settle KEEP/ROLLBACK mapping.

import { ok, makeScheduler, handleAdmin, TEAM, AUD } from "./validate-owner-action-dualcontrol-harness.ts";
import type { Ctx } from "./validate-owner-action-dualcontrol-harness.ts";
import { type PendingOwnerAction, OWNER_ACTION_PREFIX, ownerActionHash } from "../src/admin/owner-action.ts";
import { decideKeep } from "../src/admin/update-apply.ts";
import type { CanaryLiveness } from "../src/canary/types.ts";
import type { Env } from "../src/env.d.ts";

export async function run(ctx: Ctx): Promise<void> {
  const { sched, webhookPosts, OWNER, OWNER2, OPERATOR, subjectOf, call, setGate, doFetch, ownerCaller, ownerActionKeyCount, listIdpConnections, inbox, applyOwnerOp, oidcProposal } = ctx;

  // ===========================================================================================
  // PROOF 3.5: END-TO-END THROUGH THE ROUTER (handleAdmin), not just the DO stub: a DO-executed op
  // returns 202 via the router, is NOT executed on one owner, and a second owner approving via the
  // router's dynamic approve route executes it. (idp-conn-enabled: the router forwards without a live probe.)
  // ===========================================================================================
  {
    // Seed an enabled OIDC connection so there is something to disable under the gate. idp-conn-create is
    // high-blast, so with two owners it is auto-gated (S1b) even with the toggle off; applyOwnerOp lands it
    // via the dual-control approve flow either way.
    await applyOwnerOp("/idp/conn/create", oidcProposal("router-oidc"));
    ok("the seed connection exists and is enabled", (await listIdpConnections(OWNER)).connections?.some((c) => c.id === "router-oidc" && c.enabled) === true);
    // Disable it THROUGH THE ROUTER under the gate -> 202 ownerActionQueued, NOT executed.
    const r = await call(OWNER, "POST", "/admin/idp/connections/enabled", { connId: "router-oidc", enabled: false });
    ok("a gated idp-conn-enabled via the ROUTER returns 202 (queued)", r.status === 202);
    const pid = ((await r.json()) as { ownerActionQueued?: boolean; id?: string }).id ?? "";
    ok("the router 202 carries an owner-action id", pid.length > 0);
    ok("the connection is STILL enabled (one owner could not disable it)", (await listIdpConnections(OWNER)).connections?.some((c) => c.id === "router-oidc" && c.enabled) === true);
    // The maker cannot approve via the router (maker != checker), and a non-owner cannot approve via the router.
    const selfRouter = await call(OWNER, "POST", `/admin/owner-actions/${pid}/approve`);
    ok("the proposer cannot approve via the router (4xx)", selfRouter.status >= 400);
    const opRouter = await call(OPERATOR, "POST", `/admin/owner-actions/${pid}/approve`);
    ok("a non-owner cannot approve via the router (403 at the keys.ceremony gate)", opRouter.status === 403);
    // It appears in the OWNER's inbox via the router.
    ok("the pending action is in the owner inbox via the router", (await inbox(OWNER)).some((a) => a.id === pid && a.kind === "idp-conn-enabled"));
    // A second owner approves via the ROUTER's dynamic approve route -> executes.
    const approveRouter = await call(OWNER2, "POST", `/admin/owner-actions/${pid}/approve`);
    ok("a second owner approves via the router (200)", approveRouter.status === 200);
    ok("the connection is now DISABLED (the approved op executed)", (await listIdpConnections(OWNER)).connections?.some((c) => c.id === "router-oidc" && c.enabled === false) === true);
    // Clean up: delete the connection via the dual-control approve flow (idp-conn-delete is gated here).
    await applyOwnerOp("/idp/conn/delete", { connId: "router-oidc" });
  }

  // ===========================================================================================
  // PROOF 3.6: the dual-control OFF SWITCH is itself ASYMMETRICALLY gated (+ disarm alert).
  //   - ARM (false->true) is IMMEDIATE (no second owner);
  //   - a non-break-glass owner DISARM (true->false) when ON => 202 pending, NOT disarmed;
  //   - a SECOND owner approving the dual-control-disable action => DISARMED;
  //   - the BARE-TOKEN break-glass owner DISARM is IMMEDIATE (the lockout escape);
  //   - EVERY true->false transition fires a dual-control-disabled notification.
  // No-deadlock: ARM is always immediate + break-glass can always disarm => never locked out of the off switch.
  // ===========================================================================================
  {
    const policyOn = async (): Promise<boolean> => ((await (await call(OWNER, "GET", "/admin/config/approval-policy")).json()) as { requireConfigApproval: boolean }).requireConfigApproval;
    // Set up a webhook channel + an all-events rule so a disarm alert has somewhere to land. Notify-config
    // writes go through the SAME gate, so configure them with the gate OFF first.
    await setGate(OWNER, false);
    const chResp = await call(OWNER, "POST", "/admin/notify/channels", { kind: "webhook", name: "disarm-sink", url: "https://hooks.example.com/alert" });
    const channel = (await chResp.json()) as { channel?: { id?: string }; id?: string };
    const channelId = channel.channel?.id ?? channel.id ?? "";
    ok("[disarm] a webhook channel was created for the alert", channelId.length > 0);
    await call(OWNER, "POST", "/admin/notify/rules", { scope: { kind: "global" }, minSeverity: "info", events: "all", channelIds: [channelId], enabled: true });

    // ARM is immediate (false -> true returns 200, gate reads ON, no pending action recorded).
    const armBefore = ownerActionKeyCount();
    const arm = await setGate(OWNER, true);
    ok("[disarm] ARM (false->true) is immediate (200)", arm.status === 200);
    ok("[disarm] ARM turned the gate ON", await policyOn());
    ok("[disarm] ARM queued NO owner action", ownerActionKeyCount() === armBefore);

    // A non-break-glass owner DISARM when ON => 202 pending, NOT disarmed.
    const postsBeforePending = webhookPosts.length;
    const disarmTry = await call(OWNER, "POST", "/admin/config/approval-policy", { requireConfigApproval: false });
    ok("[disarm] a non-break-glass owner disarm when ON => 202 (queued, not applied)", disarmTry.status === 202);
    const disarmId = ((await disarmTry.json()) as { ownerActionQueued?: boolean; id?: string }).id ?? "";
    ok("[disarm] the 202 carries an owner-action id", disarmId.length > 0);
    ok("[disarm] the gate is STILL ON (one owner could not disarm it)", await policyOn());
    ok("[disarm] the pending action is a dual-control-disable in the inbox", (await inbox(OWNER)).some((a) => a.id === disarmId && a.kind === "dual-control-disable"));
    ok("[disarm] NO disarm alert fired on the mere proposal (nothing disarmed yet)", webhookPosts.length === postsBeforePending);
    // The maker cannot approve their own disarm (maker != checker).
    const selfDisarm = await call(OWNER, "POST", `/admin/owner-actions/${disarmId}/approve`);
    ok("[disarm] the proposer cannot approve their own disarm (4xx)", selfDisarm.status >= 400);
    ok("[disarm] still ON after the self-approve attempt", await policyOn());

    // A SECOND owner approves => the gate flips OFF and a disarm alert fires.
    const postsBeforeApprove = webhookPosts.length;
    const approveDisarm = await call(OWNER2, "POST", `/admin/owner-actions/${disarmId}/approve`);
    ok("[disarm] a second owner approves the disarm (200)", approveDisarm.status === 200);
    const approveDisarmRec = (await approveDisarm.json()) as PendingOwnerAction;
    ok("[disarm] the approved disarm record is an executed dual-control-disable (maker != checker)", approveDisarmRec.kind === "dual-control-disable" && approveDisarmRec.status === "executed" && approveDisarmRec.proposedBy === OWNER && approveDisarmRec.approvedBy === OWNER2);
    ok("[disarm] the disarm action dropped out of the inbox (terminal)", ((await (await call(OWNER, "GET", "/admin/owner-actions")).json()) as PendingOwnerAction[]).every((a) => a.id !== disarmId));
    ok("[disarm] the gate is now OFF (a second owner disarmed it)", !(await policyOn()));
    ok("[disarm] an approved second-owner disarm fired a dual-control-disabled alert", webhookPosts.slice(postsBeforeApprove).some((p) => typeof (p as { detail?: unknown })?.detail === "string" && /dual control was turned off/i.test((p as { detail: string }).detail)));

    // A DIRECT owner disarm (immediate) also fires the alert: re-arm, then disarm as the SAME owner BUT with
    // the gate logic now OFF so the disarm is a no-op... instead, re-arm and disarm via the break-glass escape
    // below. First prove a DIRECT immediate disarm is impossible to reach for a non-break-glass owner (it is
    // always gated when ON), which the 202 above already showed. Re-arm for the break-glass proof.
    await setGate(OWNER, true);
    ok("[disarm] re-armed for the break-glass proof", await policyOn());

    // The BARE-TOKEN break-glass owner disarms IMMEDIATELY (the lockout escape), and that transition alerts.
    {
      const bsched = makeScheduler();
      const btokenEnv = ({ ...bsched.env, ADMIN_TOKEN: "bg-disarm-token", CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD }) as unknown as Env;
      async function bcall(method: "GET" | "POST", path: string, body?: unknown): Promise<Response> {
        const init: RequestInit = { method, headers: { authorization: "Bearer bg-disarm-token", ...(body !== undefined ? { "content-type": "application/json" } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) };
        return handleAdmin(new Request(`https://engine.example${path}`, init), btokenEnv);
      }
      // Set up a sink rule on THIS scheduler too (gate off), then ARM, then break-glass DISARM immediately.
      const bch = (await (await bcall("POST", "/admin/notify/channels", { kind: "webhook", name: "bg-sink", url: "https://hooks.example.com/alert" })).json()) as { channel?: { id?: string }; id?: string };
      const bchId = bch.channel?.id ?? bch.id ?? "";
      await bcall("POST", "/admin/notify/rules", { scope: { kind: "global" }, minSeverity: "info", events: "all", channelIds: [bchId], enabled: true });
      const bArm = await bcall("POST", "/admin/config/approval-policy", { requireConfigApproval: true });
      ok("[disarm] break-glass ARM is immediate (200)", bArm.status === 200);
      const postsBeforeBg = webhookPosts.length;
      const bDisarm = await bcall("POST", "/admin/config/approval-policy", { requireConfigApproval: false });
      ok("[disarm] the bare-token break-glass owner disarms IMMEDIATELY (200, not 202)", bDisarm.status === 200);
      ok("[disarm] the break-glass disarm reports disarmed:true", ((await bDisarm.json()) as { disarmed?: boolean }).disarmed === true);
      const bgOn = ((await (await bcall("GET", "/admin/config/approval-policy")).json()) as { requireConfigApproval: boolean }).requireConfigApproval;
      ok("[disarm] the gate is OFF after the break-glass disarm (no deadlock/lockout)", bgOn === false);
      ok("[disarm] the break-glass disarm fired a dual-control-disabled alert", webhookPosts.slice(postsBeforeBg).some((p) => typeof (p as { detail?: unknown })?.detail === "string" && /dual control was turned off/i.test((p as { detail: string }).detail)));
    }

    // Restore the main scheduler's gate ON for the proofs that follow (PROOF 4+ assume ON).
    await setGate(OWNER, true);
    ok("[disarm] main gate restored ON for the following proofs", await policyOn());
  }

  // ===========================================================================================
  // PROOF 5: ROUTER-EXECUTED ops cannot run on ONE owner when ON. update/apply (no token on the first call)
  //          returns 202 WITHOUT consuming a token or deploying; the DO gate-check records the pending.
  // ===========================================================================================
  {
    // Going live (dryRun:false) with NO token: under dual control ON this must NOT 400 for a missing token
    // (the first recording call carries none) and must NOT deploy — it must return 202 ownerActionQueued.
    // (loadVerifiedChannel will not be configured, so a real promote could not proceed anyway; the POINT is
    // the gate returns 202 BEFORE any token/deploy, proving a lone owner cannot ship code.)
    const before = ownerActionKeyCount();
    const r = await call(OWNER, "POST", "/admin/update/apply", { dryRun: false });
    // The router must NEVER let a lone owner ship code: the response is the dual-control 202 (the gate
    // recorded a pending action) when the update channel resolves, OR the documented 400/4xx for an
    // unconfigured channel (this network-free harness configures no real channel, so the route legitimately
    // stops at the channel step). What it must NOT be is a 200 (a deploy by one owner). Assert that explicitly
    // and assert the gate did not run the deploy: when it 400s at the channel step BEFORE the gate, no pending
    // action is recorded; when it 202s, exactly one is recorded. The direct DO gate-check below is the
    // robust, network-free enforcement proof.
    const r202 = r.status === 202;
    ok("update/apply via the router on one owner is 202 (queued) or the documented channel-unconfigured 4xx, never a 200 deploy", r202 || (r.status >= 400 && r.status < 500));
    ok("the router did not deploy on one owner (202 records exactly one pending action, the 4xx records none)", ownerActionKeyCount() === before + (r202 ? 1 : 0));
    // DIRECT DO gate-check (the router-bypass + enforcement proof): one owner => "pending" (records, no run).
    const beforeDirect = ownerActionKeyCount();
    const gc1 = await doFetch("/owner-actions/gate-check", ownerCaller(OWNER), { kind: "update-apply", params: { toVersion: "9.9.9", sha384: "sha384:deadbeef" }, summary: "promote to 9.9.9" });
    ok("update-apply gate-check by one owner => pending (recorded)", gc1.status === 200 && ((await gc1.json()) as { gate: string }).gate === "pending");
    ok("update-apply recorded a pending owner action (no deploy ran)", ownerActionKeyCount() === beforeDirect + 1);
    const pid = sched.storage.keysWithPrefix(OWNER_ACTION_PREFIX).map((k) => sched.storage.rawGet<PendingOwnerAction>(k)!).find((a) => a.kind === "update-apply" && a.status === "pending")!.id;
    // CONSUME before approval is refused (no second owner yet) — the router could not run the deploy.
    const hashFor = await ownerActionHash("update-apply", { toVersion: "9.9.9", sha384: "sha384:deadbeef" }, true, OWNER, subjectOf(OWNER), []);
    const earlyConsume = await doFetch("/owner-actions/consume", ownerCaller(OWNER), { id: pid, expectedActionHash: hashFor });
    ok("consuming update-apply BEFORE approval is refused (not approved)", earlyConsume.status === 400 && /not approved/.test(((await earlyConsume.json()) as { error?: string }).error ?? ""));
    // Self-approval refused.
    const selfA = await doFetch("/owner-actions/approve", ownerCaller(OWNER), { id: pid });
    ok("update-apply self-approval refused (maker != checker)", selfA.status === 400);
    // Second owner approves => ARMED (router-executed does NOT execute on approve; it waits for the consume).
    const approve = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: pid });
    const arec = (await approve.json()) as PendingOwnerAction;
    ok("a second owner ARMS the router-executed action (status approved, not executed)", approve.status === 200 && arec.status === "approved" && arec.approvedBy === OWNER2);
    // gate-check now reports "armed" for the SAME action+proposer (the re-submit path the router takes).
    const gc2 = await doFetch("/owner-actions/gate-check", ownerCaller(OWNER), { kind: "update-apply", params: { toVersion: "9.9.9", sha384: "sha384:deadbeef" }, summary: "promote to 9.9.9" });
    ok("update-apply gate-check now reports armed for the SAME action", gc2.status === 200 && ((await gc2.json()) as { gate: string }).gate === "armed");
    // CONSUME by a distinct owner succeeds exactly once; a SECOND consume is refused (single use).
    const consume1 = await doFetch("/owner-actions/consume", ownerCaller(OWNER), { id: pid, expectedActionHash: hashFor });
    ok("consuming the armed update-apply succeeds once (the router would now run the deploy)", consume1.status === 200 && ((await consume1.json()) as { ok?: boolean }).ok === true);
    const consume2 = await doFetch("/owner-actions/consume", ownerCaller(OWNER), { id: pid, expectedActionHash: hashFor });
    ok("a SECOND consume of the same approval is refused (single use)", consume2.status === 400);
    // A consume whose params don't match the approved action (re-arm-on-change) is refused.
    const otherHash = await ownerActionHash("update-apply", { toVersion: "1.2.3", sha384: "sha384:other" }, true, OWNER, subjectOf(OWNER), []);
    // Arm a fresh one then try to consume with a mismatched expected hash.
    const gcFresh = await doFetch("/owner-actions/gate-check", ownerCaller(OWNER), { kind: "update-apply", params: { toVersion: "5.5.5", sha384: "sha384:five" }, summary: "promote to 5.5.5" });
    const freshId = ((await gcFresh.json()) as { id: string }).id;
    await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: freshId });
    const mismatch = await doFetch("/owner-actions/consume", ownerCaller(OWNER), { id: freshId, expectedActionHash: otherHash });
    ok("a consume with a MISMATCHED action hash is refused (re-arm-on-change)", mismatch.status === 400 && /does not match/.test(((await mismatch.json()) as { error?: string }).error ?? ""));
    await doFetch("/owner-actions/reject", ownerCaller(OWNER2), { id: freshId });
  }

  // ===========================================================================================
  // PROOF 6: the other ROUTER-EXECUTED ops (sources-attach, support-credential-mint, update-settle) — one
  //          owner gate-check => pending (no privileged op runs); a second owner arms; consume is single-use.
  // ===========================================================================================
  async function routerExecutedGate(kind: string, params: unknown, label: string): Promise<void> {
    const before = ownerActionKeyCount();
    const gc = await doFetch("/owner-actions/gate-check", ownerCaller(OWNER), { kind, params, summary: `${label} summary` });
    ok(`[${label}] gate-check by one owner => pending (recorded, op not run)`, gc.status === 200 && ((await gc.json()) as { gate: string }).gate === "pending");
    ok(`[${label}] a pending owner action was recorded`, ownerActionKeyCount() === before + 1);
    const pid = sched.storage.keysWithPrefix(OWNER_ACTION_PREFIX).map((k) => sched.storage.rawGet<PendingOwnerAction>(k)!).find((a) => a.kind === kind && a.status === "pending")!.id;
    const selfA = await doFetch("/owner-actions/approve", ownerCaller(OWNER), { id: pid });
    ok(`[${label}] self-approval refused`, selfA.status === 400);
    const approve = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: pid });
    ok(`[${label}] a second owner ARMS it (approved, not executed)`, approve.status === 200 && ((await approve.json()) as PendingOwnerAction).status === "approved");
    const hashFor = await ownerActionHash(kind as never, params, true, OWNER, subjectOf(OWNER), []);
    const c1 = await doFetch("/owner-actions/consume", ownerCaller(OWNER), { id: pid, expectedActionHash: hashFor });
    ok(`[${label}] consume succeeds once`, c1.status === 200);
    const c2 = await doFetch("/owner-actions/consume", ownerCaller(OWNER), { id: pid, expectedActionHash: hashFor });
    ok(`[${label}] second consume refused (single use)`, c2.status === 400);
  }
  await routerExecutedGate("sources-attach", { sources: [{ type: "kv", binding: "KV_X", namespaceId: "ns1" }], remove: [] }, "sources-attach");
  await routerExecutedGate("support-credential-mint", { scope: "diagnostics", ttlSeconds: 3600 }, "support-credential-mint");
  await routerExecutedGate("update-settle", { fromVersion: "1.0.0", toVersion: "1.1.0", recommendedVersion: "1.1.0" }, "update-settle");

  // ===========================================================================================
  // PROOF 6.5: settle gates KEEP, NOT ROLLBACK. The settle route computes the keep/rollback decision
  // by flying the canary (no token) and invokes the update-settle gate ONLY when the decision is KEEP; the
  // ROLLBACK direction (back to the known-good fromVersion) is the SAFE recovery direction and proceeds inline
  // (gating it would impede incident response). The route's branch is decideKeep(...).keep, so this proves the
  // gate covers exactly the KEEP verdicts and NONE of the ROLLBACK verdicts. (The route itself needs a live CF
  // deploy + canary, so the gate-MECHANISM is proven in PROOF 6 above; here we prove the DIRECTION mapping the
  // route uses to decide whether to gate at all.)
  {
    // KEEP verdicts (these GATE in the route). Under the OPTIMISTIC settle a verified promote
    // is KEPT unless there is positive evidence of a bad build, so EVERY non-dead verdict keeps -- a singing
    // canary, OR an inconclusive flight whatever the baseline and whatever the self-check (a flight that
    // cannot COMPLETE in the post-swap window is not evidence of regression; only a dead canary is).
    const keepCases: Array<[CanaryLiveness, CanaryLiveness, boolean]> = [
      ["alive", "alive", false], // a singing canary
      ["alive", "ailing", true], ["alive", "ailing", false], // inconclusive + either self-check -> keep
      ["alive", "pending", true], ["alive", "pending", false],
      ["pending", "ailing", true], ["pending", "ailing", false], // no healthy baseline, still keeps
      ["pending", "pending", false],
    ];
    ok("[settle] every non-dead verdict => KEEP => gated (optimistic; self-check no longer forces a rollback)", keepCases.every(([b, v, sc]) => decideKeep(b, v, sc).keep === true));
    // ROLLBACK verdicts (NOT gated in the route -- safe recovery proceeds inline). The ONLY rollback is a
    // DEAD canary: a completed flight with a strayed byte, a data-integrity death, never excused by a
    // self-check and never reached by an incomplete flight.
    const rollbackCases: Array<[CanaryLiveness, CanaryLiveness, boolean]> = [
      ["alive", "dead", true], // a data-integrity death rolls back even with a passing self-check
      ["alive", "dead", false],
      ["pending", "dead", true], // dead always rolls back, any baseline, any self-check
    ];
    ok("[settle] every ROLLBACK verdict is NOT gated (proceeds inline as safe recovery)", rollbackCases.every(([b, v, sc]) => decideKeep(b, v, sc).keep === false));
  }
}
