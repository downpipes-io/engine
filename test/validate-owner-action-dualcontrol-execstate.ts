// Two execute-time single-use / live-authority guards on the OWNER-ACTION APPROVE path itself (the existing
// groups exercise these guards only on SIBLING paths: the consume path and the config-change path):
//
//   SINGLE USE: a SECOND approve on an already-executed owner action is REFUSED. The owner-action approve path
//            runs canApproveOwnerAction at the top of approveOwnerAction; once the record's effective status is
//            "executed" the verdict is "the action was already carried out" (400), so the op cannot
//            double-execute. (The asymmetric blockConcurrencyWhile RE-ASSERT inside the critical section is the
//            CONCURRENT-double-approval guard; under the offline validator the DO's blockConcurrencyWhile falls
//            back to running fn() directly, so the closest faithful offline proof is the SERIAL
//            second-approve-on-executed refusal driven here.)
//
//   LIVE AUTHORITY CEILING: a proposer DEMOTED from owner between propose and approve is caught at EXECUTE.
//            approveOwnerAction runs the DO-executed method AS THE PROPOSER (proposerReplayCaller, re-resolved
//            live by subject); putDest re-checks roleForCaller(...).role === "owner", so a proposer who is no
//            longer an owner throws AuthError -> 403 and the op does NOT execute, even though the (distinct,
//            still-owner) approver's own approve verdict is valid. This is the apply-time authority ceiling on
//            the owner-action path (the sibling config-change path proves the same principle).
//
//   CONCURRENT-APPROVAL RACE + CONSUME RE-SUBMIT REFUSALS (ASVS V8.3.1): every OTHER in-guard refusal in
//            approveOwnerAction (the inner canApproveOwnerAction recheck) and in consumeOwnerAction (record
//            gone, wrong flow, hash mismatch, not-yet-armed/already-used/rejected) used to be a BARE throw
//            inside blockConcurrencyWhile -- resetting the DO for an ordinary, benign refusal. These prove every
//            one of those paths is now refused cleanly (the correct 400) WITHOUT resetting the DO
//            (guardThrows()===0).
//
// Driven THROUGH THE DO (router-bypass), reusing the shared harness. High-blast kinds (dest-put) are
// auto-gated once a second owner exists, so these proofs do not depend on the requireConfigApproval toggle.

import { ok } from "./validate-owner-action-dualcontrol-harness.ts";
import type { Ctx } from "./validate-owner-action-dualcontrol-harness.ts";
import { type PendingOwnerAction, OWNER_ACTION_PREFIX, ownerActionHash, ownerActionKey } from "../src/admin/owner-action.ts";

export async function run(ctx: Ctx): Promise<void> {
  const { OWNER, OWNER2, call, setGate, doFetch, ownerCaller, destConfig, listDestinations, inbox } = ctx;

  const labelCount = async (label: string): Promise<number> => (await listDestinations()).destinations.filter((d) => d.label === label).length;
  const roleOf = async (email: string): Promise<string> => ((await (await call(OWNER, "GET", "/admin/roles")).json()) as Array<{ email: string; role: string }>).find((e) => e.email === email)?.role ?? "none";

  // The suite leaves the requireConfigApproval toggle ON, which makes a /roles mutation a config-change-
  // controlled (queued) action. AUTH-46 needs the proposer demotion to land INLINE, so turn the toggle OFF
  // here. The high-blast dest-put auto-gate (S1b) is toggle-INDEPENDENT once a second owner exists, so the
  // AUTH-44/46 dest-put proposals below are still auto-gated regardless of this toggle.
  await setGate(OWNER, false);

  // ===========================================================================================
  // AUTH-44: a SECOND approve on an already-executed owner action is refused (single use).
  // ===========================================================================================
  {
    const LABEL = "auth44-single-use";
    // OWNER proposes a high-blast dest-put -> auto-gated (202, pending). OWNER2 (distinct owner) approves ->
    // it executes (single use). A SECOND approve on the SAME id must then be refused as already-carried-out.
    const propose = await doFetch("/destinations", ownerCaller(OWNER), { label: LABEL, config: destConfig("auth44-bucket") });
    ok("AUTH-44: a high-blast dest-put is auto-gated (202, pending)", propose.status === 202);
    const pid = ((await propose.json()) as { id?: string }).id ?? "";
    ok("AUTH-44: the 202 carries an owner-action id", pid.length > 0);

    const firstApprove = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: pid });
    const firstRec = (await firstApprove.json()) as PendingOwnerAction;
    ok("AUTH-44: the first distinct-owner approve executes the action (200, executed)", firstApprove.status === 200 && firstRec.status === "executed");
    ok("AUTH-44: the destination was added exactly once by the first approve", (await labelCount(LABEL)) === 1);

    // SECOND approve on the SAME (now executed) id, by the same distinct owner: refused, NOT re-executed.
    const secondApprove = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: pid });
    const secondBody = (await secondApprove.json()) as { error?: string };
    ok("AUTH-44: a SECOND approve on the already-executed action is refused (400)", secondApprove.status === 400);
    ok("AUTH-44: the refusal reason is 'the action was already carried out' (single use)", /already carried out/.test(secondBody.error ?? ""));
    ok("AUTH-44: the second approve did NOT double-execute (still exactly one destination)", (await labelCount(LABEL)) === 1);
  }

  // ===========================================================================================
  // AUTH-46: a proposer demoted from owner between propose and approve -> execute re-resolves live and refuses.
  // ===========================================================================================
  {
    const LABEL = "auth46-demoted-proposer";
    // PRECONDITION: OWNER and OWNER2 are both owners (the suite leaves them so). OWNER2 will be the proposer
    // and is demoted before the approve; OWNER (still an owner) is the distinct approver.
    ok("AUTH-46: precondition - OWNER2 is an owner before proposing", (await roleOf(OWNER2)) === "owner");

    // OWNER2 (an owner) proposes the high-blast dest-put -> auto-gated (202, pending). The pending record
    // captures OWNER2 as the proposer (proposedBySubject = OWNER2's stable subject).
    const propose = await doFetch("/destinations", ownerCaller(OWNER2), { label: LABEL, config: destConfig("auth46-bucket") });
    ok("AUTH-46: the owner proposer's high-blast dest-put is auto-gated (202, pending)", propose.status === 202);
    const pid = ((await propose.json()) as { id?: string }).id ?? "";
    ok("AUTH-46: the 202 carries an owner-action id", pid.length > 0);

    // DEMOTE the proposer from owner to viewer BETWEEN propose and approve (OWNER, still an owner, performs
    // the demotion; one owner remains so the last-Owner availability guard does not fire).
    const demote = await call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "viewer" });
    ok("AUTH-46: the proposer is demoted from owner to viewer between propose and approve (200)", demote.status === 200);
    ok("AUTH-46: the demotion took effect (proposer is now a viewer)", (await roleOf(OWNER2)) === "viewer");

    // Capture the pending state BEFORE the approve so we can prove it SURVIVES the refused approve.
    ok("AUTH-46: the proposed action is pending before the approve", (await inbox(OWNER)).some((r) => r.id === pid && r.status === "pending"));

    // OWNER (a distinct, still-owner approver) approves: the approve verdict (maker != checker, approver is an
    // owner, still pending) is itself valid, but executeOwnerActionDO runs putDest AS THE PROPOSER, which
    // re-resolves the proposer's role LIVE by subject (now viewer) and throws -> 403; the op does NOT execute.
    ctx.sched.resetGuardThrows(); // count only THIS approve's guard activity
    const approve = await doFetch("/owner-actions/approve", ownerCaller(OWNER), { id: pid });
    const approveBody = (await approve.json()) as { error?: string };
    ok("AUTH-46: approving a demoted proposer's action is refused at execute (403)", approve.status === 403);
    ok("AUTH-46: the refusal is the generic forbidden body (the proposer's owner ceiling re-checked live)", approveBody.error === "forbidden");
    ok("AUTH-46: the action did NOT execute (the destination was never added)", (await labelCount(LABEL)) === 0);
    // THE FIX: the FORESEEABLE proposer AuthError was caught INSIDE blockConcurrencyWhile
    // and surfaced OUTSIDE it, so nothing threw OUT of the guarded fn. In the REAL workerd runtime a throw there
    // RESETS the Durable Object (wiping its in-memory scheduler state) and returns 500 instead of the clean 403
    // an AuthError maps to; guardThrows()===0 proves the guard did NOT throw, i.e. a clean 403 with the DO
    // intact. RED before the fix: the old code let the proposer AuthError propagate out of blockConcurrencyWhile.
    ok("AUTH-46 (DO-reset): the proposer AuthError did NOT throw out of blockConcurrencyWhile (no DO reset -> 403, not 500)", ctx.sched.guardThrows() === 0);
    // The DO's in-memory state SURVIVES: the pending owner action is still pending (never wiped, never flipped).
    ok("AUTH-46 (DO-reset): the pending owner action SURVIVES the refused approve (still pending)", (await inbox(OWNER)).some((r) => r.id === pid && r.status === "pending"));

    // RESTORE OWNER2 to owner so any later assertions / a re-run of the suite see the original roster.
    await call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "owner" });
    ok("AUTH-46: cleanup - OWNER2 restored to owner", (await roleOf(OWNER2)) === "owner");
    // The SURVIVED pending action is still fully usable: with the proposer an owner again, re-approving the SAME
    // id now EXECUTES it, proving the earlier refusal left the record intact and actionable, not reset away.
    const reApprove = await doFetch("/owner-actions/approve", ownerCaller(OWNER), { id: pid });
    const reRec = (await reApprove.json()) as PendingOwnerAction;
    ok("AUTH-46 (DO-reset): re-approving the survived action after restore executes it (200, executed)", reApprove.status === 200 && reRec.status === "executed");
    ok("AUTH-46 (DO-reset): the destination is added exactly once by the re-approve", (await labelCount(LABEL)) === 1);
  }

  // ===========================================================================================
  // AUTH-46b: the proposer is OFFBOARDED and their ADDRESS is then
  // RE-ISSUED. AUTH-46 above proves the live re-resolution catches a DEMOTED proposer, which is the axis the
  // replay was built for. This is the axis it was blind to.
  //
  // proposerReplayCaller hands the recorded EMAIL to roleForCaller alongside the recorded subject, and
  // roleForCaller hands it to resolveBoundEntry, whose bind-on-first-auth defaults to ON for every non-native
  // subject. Step 2 of that function is a WRITE: it matches a pending grant BY EMAIL, binds it onto whichever
  // subject was presented, and deletes the pending row. So an ordinary invite issued at a departed proposer's
  // re-used address handed the DEPARTED subject a live owner grant at execute time, and the queued action ran.
  // The comment on proposerReplayCaller cited the ASVS V10.3.3 / V10.5.2 closure for this, and it was true of
  // the direction it was thinking about (a NEW subject at an old address inherits nothing, because
  // authorisation keys on the subject) and silent about its mirror image, which is the one that bites: the OLD
  // subject inherits the NEW person's grant. An owner action is the highest-privilege place that can happen.
  //
  // The pair below distinguishes a fixed build from a broken one by more than a status code: the broken build
  // EXECUTES at [AUTH-46b] the re-issue, and it also silently consumes the invitation the account issued to
  // somebody else, which no route anywhere reports.
  {
    const LABEL = "auth46b-reissued-address";
    const pendingKey = `role:pending:${OWNER2}`;
    ok("AUTH-46b: precondition - OWNER2 is an owner and proposes", (await roleOf(OWNER2)) === "owner");
    const propose = await doFetch("/destinations", ownerCaller(OWNER2), { label: LABEL, config: destConfig("auth46b-bucket") });
    ok("AUTH-46b: the proposal is auto-gated (202, pending)", propose.status === 202);
    const pid = ((await propose.json()) as { id?: string }).id ?? "";

    // OFFBOARD the proposer outright: the delete a SCIM leaver run posts, not a demotion. One owner remains,
    // so the availability floor does not fire.
    const off = await call(OWNER, "POST", "/admin/roles/delete", { email: OWNER2 });
    ok("AUTH-46b: the proposer is OFFBOARDED between propose and approve (200)", off.status === 200);
    ok("AUTH-46b: the offboard took effect (no role entry at all)", (await roleOf(OWNER2)) === "none");
    const offApprove = await doFetch("/owner-actions/approve", ownerCaller(OWNER), { id: pid });
    ok("AUTH-46b: approving an OFFBOARDED proposer's action is refused at execute (403)", offApprove.status === 403);
    ok("AUTH-46b: the action did NOT execute", (await labelCount(LABEL)) === 0);

    // THE ADDRESS IS RE-ISSUED to the next person: an ordinary grant, which for an address no subject has
    // claimed yet is written as an unclaimed `role:pending:<email>` row.
    const reissue = await call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "owner" });
    ok("AUTH-46b: the address is re-issued to the next person (200)", reissue.status === 200);
    ok("AUTH-46b: the re-issued grant is PENDING, claimed by no subject yet", ctx.sched.storage.rawGet(pendingKey) !== undefined);

    ctx.sched.resetGuardThrows();
    const reissuedApprove = await doFetch("/owner-actions/approve", ownerCaller(OWNER), { id: pid });
    ok("AUTH-46b: THE CLAIM UNDER TEST - re-issuing the departed proposer's ADDRESS does not re-arm their action (403)", reissuedApprove.status === 403);
    ok("AUTH-46b: THE ASSERTION THAT MATTERS - the action still did NOT execute", (await labelCount(LABEL)) === 0);
    ok("AUTH-46b: the NEW person's grant is untouched - the replay did not consume an invitation that is not its own", ctx.sched.storage.rawGet(pendingKey) !== undefined);
    ok("AUTH-46b: and the refusal is still the clean one, with the DO intact", ctx.sched.guardThrows() === 0);

    // NO STRANDING, and the arm that stops the fix being "refuse whenever the proposer has no bound row". The
    // address's real holder signs in, their OWN subject claims the grant through the same bind-on-first-auth
    // every live request performs, and the queued action becomes approvable again. In production that holder is
    // the new person and the departed proposer stays refused for ever; the harness's one identity per address
    // exercises the recovery half.
    await call(OWNER2, "GET", "/admin/whoami");
    ok("AUTH-46b: a real sign-in by the address's holder claims the pending grant, exactly as it always did", ctx.sched.storage.rawGet(pendingKey) === undefined);
    const reclaimApprove = await doFetch("/owner-actions/approve", ownerCaller(OWNER), { id: pid });
    const reclaimRec = (await reclaimApprove.json()) as PendingOwnerAction;
    ok("AUTH-46b: NO STRANDING - with the recorded SUBJECT authorised again the same action executes (200)", reclaimApprove.status === 200 && reclaimRec.status === "executed");
    ok("AUTH-46b: and it executed exactly once", (await labelCount(LABEL)) === 1);
    ok("AUTH-46b: cleanup - OWNER2 is an owner again for the proofs below", (await roleOf(OWNER2)) === "owner");
  }

  // ===========================================================================================
  // CONCURRENT-APPROVAL RACE: the guard's OWN re-read (inside approveOwnerAction's blockConcurrencyWhile) can
  // find the record no longer approvable even though the OUTER check just above saw it pending -- a genuine
  // concurrent distinct-owner approval landing in between is the real-world trigger (the same class of race
  // AUTH-44 proves at the OUTER check, serially). The offline validator's blockConcurrencyWhile has no real
  // concurrency to race (see the AUTH-44 comment above), so a single controlled stale read on the SAME storage
  // key deterministically reproduces exactly what the guard's re-read would observe from a concurrent winner,
  // without relying on non-deterministic microtask timing.
  // ===========================================================================================
  {
    const LABEL = "concurrent-approval-race";
    const propose = await doFetch("/destinations", ownerCaller(OWNER), { label: LABEL, config: destConfig("race-bucket") });
    ok("[race] the proposal is auto-gated (202, pending)", propose.status === 202);
    const pid = ((await propose.json()) as { id?: string }).id ?? "";

    // Make ONLY the guard's re-read of this exact record see it already "executed" (as a concurrent distinct-
    // owner winner would have left it); the outer check just above still sees the genuine pending record, so
    // this call reaches blockConcurrencyWhile exactly as the race's loser would. rawGet/put are unaffected --
    // only what get() RETURNS for the record's own key on its SECOND read is substituted, nothing is written.
    const key = ownerActionKey(pid);
    const origGet = ctx.sched.storage.get;
    let hits = 0;
    ctx.sched.storage.get = (async <T>(k: string): Promise<T | undefined> => {
      if (k === key) {
        hits++;
        if (hits === 2) {
          const real = ctx.sched.storage.rawGet<PendingOwnerAction>(k);
          return real ? ({ ...real, status: "executed" } as unknown as T) : undefined;
        }
      }
      return ctx.sched.storage.rawGet<T>(k);
    }) as typeof ctx.sched.storage.get;

    ctx.sched.resetGuardThrows();
    const approve = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: pid });
    ctx.sched.storage.get = origGet; // restore immediately, pass or fail
    const approveBody = (await approve.json()) as { error?: string };
    ok("[race] the guard's own re-read losing the race is refused cleanly (400)", approve.status === 400);
    ok("[race] the refusal is the same single-use verdict AUTH-44 proves at the outer check (already carried out)", /already carried out/.test(approveBody.error ?? ""));
    // THE FIX: before it, the inner canApproveOwnerAction recheck's failure threw a bare Error INSIDE
    // blockConcurrencyWhile, which resets the DO in real workerd; guardThrows()===0 proves it is now
    // sentinelled out cleanly instead, mirroring AUTH-46's own guardThrows()===0 proof above.
    ok("[race] the inner verdict failure did NOT throw out of blockConcurrencyWhile (no DO reset)", ctx.sched.guardThrows() === 0);
    // The REAL persisted record is untouched by the simulated stale read (only the SECOND get() call's return
    // value was substituted; no write ever happened) -- it is still genuinely pending and actionable.
    ok("[race] the underlying record survives untouched (still genuinely pending)", (await inbox(OWNER)).some((r) => r.id === pid && r.status === "pending"));
    await doFetch("/owner-actions/reject", ownerCaller(OWNER2), { id: pid }); // clean up
  }

  // ===========================================================================================
  // CONSUME RE-SUBMIT REFUSALS: consumeOwnerAction's guarded body had NO try/catch at all pre-fix -- every
  // refusal (record gone, wrong flow, hash mismatch, not-yet-armed/already-used/rejected) was a bare throw
  // INSIDE blockConcurrencyWhile, each one resetting the DO exactly like the CONCURRENT-APPROVAL RACE above.
  // These are all ORDINARY re-submit races (a maker double-submitting, or submitting against the wrong record/
  // flow), not faults -- reachable with NO manipulation at all, just an ordinary duplicate/mismatched re-submit.
  // ===========================================================================================
  {
    // Router-executed kinds (support-credential-mint et al) are NOT high-blast auto-gated (unlike dest-put
    // above) -- they gate only when the opt-in toggle is ON, which the AUTH-44/46 setup above turned OFF.
    await setGate(OWNER, true);
    const kind = "support-credential-mint";
    const params = { scope: "ml35-diagnostics", ttlSeconds: 3601 };
    const gc = await doFetch("/owner-actions/gate-check", ownerCaller(OWNER), { kind, params, summary: "consume-refusals" });
    ok("[consume] gate-check by one owner => pending", gc.status === 200 && ((await gc.json()) as { gate: string }).gate === "pending");
    const pid = ctx.sched.storage.keysWithPrefix(OWNER_ACTION_PREFIX).map((k) => ctx.sched.storage.rawGet<PendingOwnerAction>(k)!).find((a) => a.kind === kind && a.status === "pending")!.id;
    await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: pid }); // arms it
    const hashFor = await ownerActionHash(kind, params, true, OWNER, ctx.subjectOf(OWNER), []);

    // A first consume succeeds (single use spent). A SECOND consume on the SAME now-executed record hits the
    // "already used" bare throw -- reachable with no manipulation at all, just an ordinary double re-submit
    // (e.g. a page-refresh double-fire, exactly the scenario the finding calls out).
    const c1 = await doFetch("/owner-actions/consume", ownerCaller(OWNER), { id: pid, expectedActionHash: hashFor });
    ok("[consume] the first consume succeeds (200)", c1.status === 200);
    ctx.sched.resetGuardThrows();
    const c2 = await doFetch("/owner-actions/consume", ownerCaller(OWNER), { id: pid, expectedActionHash: hashFor });
    const c2Body = (await c2.json()) as { error?: string };
    ok("[consume] a second consume of the same approval is refused (400)", c2.status === 400);
    ok("[consume] the refusal reason is 'the approval was already used'", /already used/.test(c2Body.error ?? ""));
    // THE FIX: before it, this branch threw a bare Error INSIDE blockConcurrencyWhile (zero try/catch existed
    // anywhere in this function); guardThrows()===0 proves it is now sentinelled out cleanly.
    ok("[consume] the second consume did NOT throw out of blockConcurrencyWhile (no DO reset)", ctx.sched.guardThrows() === 0);

    // A consume on a WHOLLY UNKNOWN id hits the "no such owner action" bare throw the same way.
    ctx.sched.resetGuardThrows();
    const cNone = await doFetch("/owner-actions/consume", ownerCaller(OWNER), { id: "no-such-id", expectedActionHash: hashFor });
    const cNoneBody = (await cNone.json()) as { error?: string };
    ok("[consume] consuming an unknown id is refused (400)", cNone.status === 400 && /no such owner action/.test(cNoneBody.error ?? ""));
    ok("[consume] the unknown-id refusal did NOT throw out of blockConcurrencyWhile (no DO reset)", ctx.sched.guardThrows() === 0);

    // A consume on a DO-EXECUTED kind's record (never token-resubmit) hits the "wrong flow" bare throw.
    const doPropose = await doFetch("/destinations", ownerCaller(OWNER), { label: "consume-wrong-flow", config: destConfig("wrong-flow-bucket") });
    const doPid = ((await doPropose.json()) as { id?: string }).id ?? "";
    ctx.sched.resetGuardThrows();
    const wrongFlow = await doFetch("/owner-actions/consume", ownerCaller(OWNER), { id: doPid, expectedActionHash: "irrelevant" });
    const wrongFlowBody = (await wrongFlow.json()) as { error?: string };
    ok("[consume] consuming a DO-executed record via the token-resubmit flow is refused (400)", wrongFlow.status === 400 && /does not use the token-resubmit flow/.test(wrongFlowBody.error ?? ""));
    ok("[consume] the wrong-flow refusal did NOT throw out of blockConcurrencyWhile (no DO reset)", ctx.sched.guardThrows() === 0);
    await doFetch("/owner-actions/reject", ownerCaller(OWNER2), { id: doPid }); // clean up
  }
}
