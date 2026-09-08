// PROOF 8/9/10/11/12 of the config change-control validator: reject, the superseded-base + tamper
// refusals (TOCTOU), no-escalation-at-apply (the proposer's ceiling is re-checked on replay), the DO-side
// maker != checker + fail-closed defence in depth, and the gate-on across a non-downpipe family +
// bare-token-cannot-propose. Split out for size; byte-identical, runs in order against the shared live DO.

import type { Ctx } from "./validate-config-change-control-harness.ts";
import {
  OWNER,
  OPERATOR,
  OPERATOR2,
  VIEWER,
  ACCESS_ADMIN,
  ACCESS_ADMIN2,
  makeScheduler,
} from "./validate-config-change-control-harness.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { encodeCaller, type Caller } from "../src/admin/identity.ts";
import { type PendingConfigChange } from "../src/admin/change-control.ts";
import type { Env } from "../src/env.d.ts";

export async function runLifecycle(ctx: Ctx): Promise<void> {
  const { ok, call, readLog, listDownpipes, listRoles, pendingChanges, pendingKeyCount, setGate, sched, dp } = ctx;

  // ===========================================================================================
  // PROOF 8: REJECT discards a pending change (no apply; audited)
  // ===========================================================================================
  {
    // Queue a delete of dp_queued, then REJECT it: the downpipe must still exist (nothing applied).
    const q = await call(OPERATOR, "POST", "/admin/downpipes/delete", { id: "dp_queued" });
    ok("a delete is queued under the gate (202)", q.status === 202);
    const id = ((await q.json()) as { id: string }).id;
    const reject = await call(OPERATOR2, "POST", `/admin/config/changes/${id}/reject`);
    ok("a distinct holder of the write cap can reject (200)", reject.status === 200 && ((await reject.json()) as PendingConfigChange).status === "rejected");
    ok("the rejected change applied nothing (the downpipe still exists)", (await listDownpipes()).some((d) => d.config.id === "dp_queued"));
    ok("the rejected change is no longer pending", !(await pendingChanges(OWNER)).some((c) => c.id === id));
    // Approving a rejected change is refused.
    const approveRejected = await call(OPERATOR, "POST", `/admin/config/changes/${id}/approve`);
    ok("approving a rejected change is refused (4xx)", approveRejected.status >= 400);
    // A reject is audited.
    ok("the reject is audited", (await readLog("action=config-change-reject")).events.some((e) => (e.target as { id?: string }).id === id));
    // A VIEWER (no write cap) cannot reject a pending change.
    const q2 = await call(OPERATOR, "POST", "/admin/downpipes", dp("dp_tmp", "tmp"));
    const id2 = ((await q2.json()) as { id: string }).id;
    const viewerReject = await call(VIEWER, "POST", `/admin/config/changes/${id2}/reject`);
    ok("a viewer without the write cap cannot reject (4xx)", viewerReject.status >= 400);
    // Clean up: reject id2 as a privileged holder so it does not linger.
    await call(OPERATOR2, "POST", `/admin/config/changes/${id2}/reject`);
  }

  // ===========================================================================================
  // PROOF 9: SUPERSEDED BASE - a pending change whose base moved is rejected, does NOT apply stale
  // ===========================================================================================
  {
    // Queue change A (a downpipe upsert). Then COMMIT an unrelated config change B by approving it, which
    // moves the config-history head. Now approving A must be refused as SUPERSEDED (its reviewed diff was
    // against the old base), and A must NOT apply.
    const qa = await call(OPERATOR, "POST", "/admin/downpipes", dp("dp_super_a", "super-a"));
    const idA = ((await qa.json()) as { id: string }).id;
    const qb = await call(OPERATOR, "POST", "/admin/downpipes", dp("dp_super_b", "super-b"));
    const idB = ((await qb.json()) as { id: string }).id;
    // Approve B first -> the head moves.
    const headBefore = ((await (await call(OWNER, "GET", "/admin/config/history")).json()) as { headId: number }).headId;
    await call(OPERATOR2, "POST", `/admin/config/changes/${idB}/approve`);
    const headAfter = ((await (await call(OWNER, "GET", "/admin/config/history")).json()) as { headId: number }).headId;
    ok("approving change B moved the config-history head", headAfter > headBefore);
    // Now approve A: its base (headBefore) no longer matches the live head -> superseded, no apply.
    const approveA = await call(OPERATOR2, "POST", `/admin/config/changes/${idA}/approve`);
    ok("approving a change whose base MOVED is refused (4xx, superseded)", approveA.status >= 400);
    const ab = (await approveA.json()) as { error?: string };
    ok("the refusal says the change is superseded", /superseded|changed since/.test(ab.error ?? ""));
    ok("the superseded change did NOT apply (dp_super_a does not exist)", !(await listDownpipes()).some((d) => d.config.id === "dp_super_a"));
    // The record reads superseded (terminal) and is out of the pending inbox; a re-approve is still refused.
    const recA = sched.storage.rawGet<PendingConfigChange>("configchange:" + idA);
    ok("the superseded record is marked superseded", recA?.status === "superseded");
    ok("the superseded change is no longer pending", !(await pendingChanges(OWNER)).some((c) => c.id === idA));
    const reApprove = await call(OPERATOR2, "POST", `/admin/config/changes/${idA}/approve`);
    ok("a superseded change cannot be re-approved (4xx)", reApprove.status >= 400);
    // The supersede is audited.
    ok("the supersede is audited", (await readLog("action=config-change-supersede")).events.some((e) => (e.target as { id?: string }).id === idA));

    // TAMPER variant: a pending change whose stored params are tampered (so the contentHash no longer
    // matches) is refused at approve time and does not apply.
    const qc = await call(OPERATOR, "POST", "/admin/downpipes", dp("dp_tamper", "tamper"));
    const idC = ((await qc.json()) as { id: string }).id;
    const recC = sched.storage.rawGet<PendingConfigChange>("configchange:" + idC)!;
    (recC.params as { name: string }).name = "tampered-after-the-fact"; // mutate params, leave contentHash stale
    sched.storage.rawPut("configchange:" + idC, recC);
    const approveTampered = await call(OPERATOR2, "POST", `/admin/config/changes/${idC}/approve`);
    ok("a contentHash-mismatched (tampered) change is refused at approve (4xx)", approveTampered.status >= 400);
    ok("the tampered change applied nothing", !(await listDownpipes()).some((d) => d.config.id === "dp_tamper"));
    // Clean up the tampered record so it does not pollute later listings.
    await sched.storage.delete("configchange:" + idC);
  }

  // ===========================================================================================
  // PROOF 10: NO ESCALATION AT APPLY - a queued role change still obeys requireGrantWithinAuthority
  // ===========================================================================================
  {
    // The ESCALATION the apply must block: an ACCESS_ADMIN holds roles.write but NOT downpipe.write/
    // restore.apply, so it may NOT grant the "approver" built-in (which confers downpipe.write + apply) -
    // the inline setRole refuses this via requireGrantWithinAuthority. The gate must NOT become a bypass:
    // a queued role-set granting approver, even approved by a DISTINCT access-admin, must STILL be refused
    // at APPLY time because the PROPOSER's ceiling is re-checked when the change is replayed.
    //
    // First confirm the inline refusal still holds for an access-admin (sanity, gate ON so it would queue
    // only if it passed propose-time validation). Propose-time runs the real setRole as the proposer, which
    // throws on the escalation, so it is refused at PROPOSE time and nothing is queued.
    const before = pendingKeyCount();
    const escalateTry = await call(ACCESS_ADMIN, "POST", "/admin/roles", { email: "victim@acme.example", role: "approver" });
    ok("an access-admin proposing a grant ABOVE its authority is refused at propose time (4xx)", escalateTry.status >= 400);
    ok("the escalating proposal queued nothing", pendingKeyCount() === before);

    // Now the deeper apply-time check: queue a LEGITIMATE role grant the proposer MAY make (access-admin
    // granting "operator" is fine: operator's caps are a subset the access-admin... actually access-admin
    // lacks downpipe.write, so operator is ALSO above it). Use a grant that IS within authority: an
    // access-admin granting "viewer" (viewer's caps are a subset of access-admin's). That should queue and
    // apply cleanly, proving the within-authority path works through the queue.
    const legit = await call(ACCESS_ADMIN, "POST", "/admin/roles", { email: "newviewer@acme.example", role: "viewer" });
    ok("an access-admin can QUEUE a within-authority grant (viewer) under the gate (202)", legit.status === 202);
    const legitId = ((await legit.json()) as { id: string }).id;
    const legitApprove = await call(ACCESS_ADMIN2, "POST", `/admin/config/changes/${legitId}/approve`);
    ok("a distinct access-admin can approve the within-authority grant (200)", legitApprove.status === 200);
    ok("the within-authority grant applied (the new viewer exists)", (await listRoles()).some((r) => r.email === "newviewer@acme.example" && r.role === "viewer"));

    // THE APPLY-TIME CEILING TEETH, IN TWO ARMS. ARM 1 drives the DEMOTION route -- queue a change, demote
    // the proposer, approve -- but a demotion is itself a config mutation that auto-snapshots, so
    // approveChange's baseMoved check fires BEFORE the authority re-resolution ever runs: this route is
    // answered by SUPERSEDED, not by the ceiling. The route is real and worth pinning, so it asserts the
    // DISCRIMINATOR that says which guard actually answered.
    const grpQ = await call(ACCESS_ADMIN, "POST", "/admin/group-roles", { group: "platform-eng", role: "viewer" });
    ok("an access-admin queues a group-role mapping under the gate (202)", grpQ.status === 202);
    const grpId = ((await grpQ.json()) as { id: string }).id;
    // Demote the proposer to viewer (owner does this inline; gate is on, so it queues - approve it via a
    // second... owner is a single identity. Toggle the gate OFF to make the demotion immediate, then back
    // ON, since the owner-only toggle is always immediate).
    await setGate(OWNER, false);
    await call(OWNER, "POST", "/admin/roles", { email: ACCESS_ADMIN, role: "viewer" });
    await setGate(OWNER, true);
    ok("the proposer was demoted to viewer", (await listRoles()).some((r) => r.email === ACCESS_ADMIN && r.role === "viewer"));
    const grpApprove = await call(ACCESS_ADMIN2, "POST", `/admin/config/changes/${grpId}/approve`);
    ok("approving a change whose proposer was DEMOTED is refused at apply (4xx)", grpApprove.status >= 400);
    const grpRoles = (await (await call(OWNER, "GET", "/admin/group-roles")).json()) as Array<{ group: string }>;
    ok("the stale-authority group-role change did NOT apply", !grpRoles.some((g) => g.group === "platform-eng"));
    ok("and the record is SUPERSEDED, so the demotion route is answered by the BASE-MOVED guard and not by any authority check", sched.storage.rawGet<PendingConfigChange>(`configchange:${grpId}`)?.status === "superseded");
    // Restore ACCESS_ADMIN for any later assertions (gate toggled around the immediate write).
    await setGate(OWNER, false);
    await call(OWNER, "POST", "/admin/roles", { email: ACCESS_ADMIN, role: "access-admin" });
    await setGate(OWNER, true);

    // ARM 2: THE CEILING AXIS ITSELF, reached by the one kind of authority loss that moves NO config head.
    // A time-boxed grant lapsing is a CLOCK event: nothing is written when it happens, so the queued
    // change's base is untouched, baseMoved cannot answer, and the approve runs all the way to the proposer
    // re-resolution. Writing a past expiresAt straight onto the stored row reproduces exactly the state the
    // DO reads one second after a real grant expires (effectiveRole demotes it to viewer on read).
    const lapseGrant = (email: string, expired: boolean): void => {
      for (const k of sched.storage.keysWithPrefix("role:sub:")) {
        const row = sched.storage.rawGet<{ email: string; expiresAt?: string }>(k);
        if (row?.email !== email) continue;
        if (expired) sched.storage.rawPut(k, { ...row, expiresAt: new Date(Date.now() - 60_000).toISOString() });
        else {
          const { expiresAt: _drop, ...rest } = row;
          sched.storage.rawPut(k, rest);
        }
      }
    };
    const lapseQ = await call(ACCESS_ADMIN, "POST", "/admin/group-roles", { group: "platform-sre", role: "viewer" });
    ok("an access-admin queues a second group-role mapping under the gate (202)", lapseQ.status === 202);
    const lapseId = ((await lapseQ.json()) as { id: string }).id;
    lapseGrant(ACCESS_ADMIN, true);
    ok("the lapse is REAL: the proposer's own LIVE group-role write is now refused (403)", (await call(ACCESS_ADMIN, "POST", "/admin/group-roles", { group: "platform-probe", role: "viewer" })).status === 403);
    const lapseApprove = await call(ACCESS_ADMIN2, "POST", `/admin/config/changes/${lapseId}/approve`);
    ok("approving a change whose proposer's grant LAPSED is refused at apply (4xx, the ceiling re-checked)", lapseApprove.status >= 400);
    const lapseRoles = (await (await call(OWNER, "GET", "/admin/group-roles")).json()) as Array<{ group: string }>;
    ok("the lapsed-authority group-role change did NOT apply", !lapseRoles.some((g) => g.group === "platform-sre"));
    ok("and THIS record is still PENDING, not superseded, so the refusal is the AUTHORITY axis", sched.storage.rawGet<PendingConfigChange>(`configchange:${lapseId}`)?.status === "pending");
    lapseGrant(ACCESS_ADMIN, false);
    ok("the refusal SUSPENDS rather than voids: with the grant restored the SAME change applies (200)", (await call(ACCESS_ADMIN2, "POST", `/admin/config/changes/${lapseId}/approve`)).status === 200);
  }

  // ===========================================================================================
  // PROOF 11: DO-side maker != checker + no-caller fail-closed (defence in depth)
  // ===========================================================================================
  {
    // Drive the DO DIRECTLY (bypassing the router gate) to prove the dual-control rules live in the DO.
    // Propose a change as a maker through the DO, then have the SAME maker approve it at the DO -> refused.
    const maker: Caller = { method: "access", email: "do-maker@acme.example", subject: "sub-of-do-maker@acme.example", role: "operator", groups: [] };
    // The maker must hold downpipe.write; grant it via the role table (gate on, so toggle off for the seed).
    await setGate(OWNER, false);
    await call(OWNER, "POST", "/admin/roles", { email: "do-maker@acme.example", role: "operator" });
    await call(OWNER, "POST", "/admin/roles", { email: "do-checker@acme.example", role: "operator" });
    await setGate(OWNER, true);
    // Propose through the DO directly as the maker.
    const proposeResp = await sched.stub.fetch("https://scheduler.internal/downpipes", {
      method: "POST",
      headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(maker) },
      body: JSON.stringify(dp("dp_do", "do-pipe")),
    });
    ok("the DO queues the proposed change (202)", proposeResp.status === 202);
    const doId = ((await proposeResp.json()) as { id: string }).id;
    // The maker approves their OWN change at the DO -> refused 400.
    const selfAtDO = await sched.stub.fetch("https://scheduler.internal/config/changes/approve", {
      method: "POST",
      headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(maker) },
      body: JSON.stringify({ id: doId }),
    });
    const sb = (await selfAtDO.json()) as { error?: string };
    ok("the DO refuses a self-approval (defence in depth)", selfAtDO.status === 400 && /cannot approve your own change/.test(sb.error ?? ""));
    // A DO approve with NO caller header is refused (fail closed: no attributable checker).
    const noCaller = await sched.stub.fetch("https://scheduler.internal/config/changes/approve", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id: doId }),
    });
    ok("the DO refuses an approve with no caller header (fail closed)", noCaller.status === 400);
    // A DISTINCT approver at the DO succeeds.
    const checker: Caller = { method: "access", email: "do-checker@acme.example", subject: "sub-of-do-checker@acme.example", role: "operator", groups: [] };
    const okAtDO = await sched.stub.fetch("https://scheduler.internal/config/changes/approve", {
      method: "POST",
      headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(checker) },
      body: JSON.stringify({ id: doId }),
    });
    ok("the DO allows a DISTINCT approver", okAtDO.status === 200 && ((await okAtDO.json()) as PendingConfigChange).approvedBy === "do-checker@acme.example");
    ok("the DO-approved change applied (dp_do exists)", (await listDownpipes()).some((d) => d.config.id === "dp_do"));

    // SINGLE USE: the change is now APPLIED. A SECOND approve of
    // the SAME id, by the SAME distinct (maker != checker) approver, is REFUSED -- canApproveChange rejects a
    // non-pending record ("the change was already applied", 400), so a non-idempotent create-with-generated-id
    // kind cannot double-apply. This is the SERIAL proof of the re-read + re-assert inside approveChange's
    // blockConcurrencyWhile critical section: a losing concurrent approve finds status="applied" and is refused.
    // NOTE: the offline harness runs blockConcurrencyWhile's callback directly (serially), so this exercises the
    // single-use re-assert via a second serial approve; the TRUE concurrent input-gate race (two approvals in
    // flight at once, both past the outer fast-fail) needs a workerd runtime test, which is out of scope here.
    const secondAtDO = await sched.stub.fetch("https://scheduler.internal/config/changes/approve", {
      method: "POST",
      headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(checker) },
      body: JSON.stringify({ id: doId }),
    });
    const secondBody = (await secondAtDO.json()) as { error?: string };
    ok("a SECOND approve on the already-applied change is refused (single use, 400)", secondAtDO.status === 400 && /already applied/.test(secondBody.error ?? ""));
    ok("the second approve did NOT double-apply (dp_do exists exactly once)", (await listDownpipes()).filter((d) => d.config.id === "dp_do").length === 1);
  }

  // ===========================================================================================
  // PROOF 12: gate-on across a NON-downpipe family (posture risk-accept) + bare-token cannot propose
  // ===========================================================================================
  {
    // A posture risk-accept (owner-reserved posture.riskaccept) under the gate: the OWNER proposes it, a
    // DISTINCT owner-capable identity must approve. Owner is a single identity here, so prove the QUEUE +
    // the maker != checker refusal (owner cannot self-approve), then toggle off to apply for cleanup.
    const accept = await call(OWNER, "POST", "/admin/posture/accept", { checkId: "two-owners", reason: "accepted for the test" });
    // posture.riskaccept is owner-only; the owner holds it, so this queues (202) rather than applying.
    ok("an owner-only posture risk-accept queues under the gate (202)", accept.status === 202);
    const pid = ((await accept.json()) as { id: string }).id;
    const rec = (await pendingChanges(OWNER)).find((c) => c.id === pid);
    ok("the queued posture change carries a risk-accept diff", (rec?.diff ?? []).some((c) => c.area === "risk-accept"));
    // The owner (the proposer) cannot self-approve.
    const ownerSelf = await call(OWNER, "POST", `/admin/config/changes/${pid}/approve`);
    ok("the owner cannot approve their own queued posture change (maker != checker, 4xx)", ownerSelf.status >= 400);
    // Reject it to clean up (the owner holds the cap and may reject their own).
    await call(OWNER, "POST", `/admin/config/changes/${pid}/reject`);

    // The bare-token break-glass cannot PROPOSE a change (no attributable maker). With Access NOT
    // configured and only ADMIN_TOKEN set, the caller is the email-less owner break-glass: a config
    // mutation under the gate is refused (it could otherwise queue a change only it could not approve).
    const tsched = makeScheduler();
    const tokenEnv = ({ ...tsched.env, ADMIN_TOKEN: "shared-break-glass-token" }) as unknown as Env;
    async function tcall(method: "GET" | "POST", path: string, body?: unknown): Promise<Response> {
      const init: RequestInit = { method, headers: { authorization: "Bearer shared-break-glass-token", ...(body !== undefined ? { "content-type": "application/json" } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) };
      return handleAdmin(new Request(`https://engine.example${path}`, init), tokenEnv);
    }
    // The bare-token owner turns the gate ON (it is owner; the toggle is always available to break-glass).
    const tokenOn = await tcall("POST", "/admin/config/approval-policy", { requireConfigApproval: true });
    ok("the bare-token break-glass CAN toggle the gate (owner, no deadlock)", tokenOn.status === 200);
    // Now a config mutation from the bare token is refused (no attributable maker for dual control).
    const tokenMut = await tcall("POST", "/admin/downpipes", dp("dp_token", "token"));
    ok("the bare-token fallback cannot propose a config change under the gate (4xx, needs an attributable maker)", tokenMut.status >= 400);
    ok("the bare-token refusal is not a role 403 (it is owner; the bar is attributability)", tokenMut.status !== 403);
    // The break-glass can always disarm the gate again (no deadlock), restoring inline writes.
    const tokenOff = await tcall("POST", "/admin/config/approval-policy", { requireConfigApproval: false });
    ok("the bare-token break-glass can disarm the gate (no deadlock)", tokenOff.status === 200);
    const tokenMut2 = await tcall("POST", "/admin/downpipes", dp("dp_token", "token"));
    ok("with the gate disarmed the bare-token write applies inline again", tokenMut2.status === 200);
  }
}
