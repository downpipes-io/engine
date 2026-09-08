// validate-cov-sched-scheduler-do-restore-approval: a focused branch-coverage validator for the
// RestoreApprovalMixin (src/sched/scheduler-do-restore-approval.ts), the restore dual-control
// approval state machine plus the drill-evidence log. It drives the REAL SchedulerDO over in-memory
// storage, router-bypassed via stub.fetch + an encoded x-downpipe-caller header (the documented
// "FROM THE ROUTER ONLY" trust these DO routes use), so every assertion checks a real outcome: an
// HTTP status, a returned record field, or a stored/audited effect. It walks each handler through its
// gate refusals (capability, attributable identity, validation), its success path, and its edge
// branches (re-request over an open vs approved vs in-flight-applying record, maker != checker
// self-approval, the lazy state rules, the atomic reserve-at-gate-time single-use consume, the
// drill-evidence cap rollover). The capability set branch and the non-finite-number fallbacks are
// exercised by one direct method call with a custom-role caller, since the wire header never carries a
// resolved capability set. No network is touched at all (the approval/drill handlers do no I/O beyond
// DO storage and the audit append).
//
// The reserve-at-gate-time fix: gateRestore now atomically RESERVES a usable approval
// ("applying") instead of only reading it; releaseRestore is the new release-on-failure path; and
// consumeApproval now requires the record to BE that reservation. Sections 6/6A/6B/6C cover the
// reserve, the release + retry, the closed-off re-approve/reject/re-request-during-applying bypasses
// (requestRestore's own guard is the sibling mutator that needed the SAME "applying" check as
// canApprove/canReject), and the stale-reservation self-heal; Section 7 covers the updated consume
// precondition.
//
// Run: node test/validate-cov-sched-scheduler-do-restore-approval.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { encodeCaller, CALLER_HEADER, type Caller, type Capability } from "../src/admin/identity.ts";
import { approvalKey, APPROVAL_TTL_MS, RESTORE_APPLY_LEASE_MS, type RestoreApproval } from "../src/admin/approvals.ts";
import { DRILL_EVIDENCE_CAP, DRILL_EVIDENCE_PREFIX, ORG_POLICY_KEY } from "../src/sched/scheduler-do-records.ts";
import { notePlanAnchor, seedBoundRole } from "./testutil.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

function makeScheduler(): { storage: MockStorage; stub: DurableObjectStub; dobj: SchedulerDO } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  return { storage, stub, dobj };
}

const planOf = (label: string): string => "sha384:" + label;

async function main(): Promise<void> {
  // THE RESTORE APPROVAL GATE IS OWNER-OPT-IN (OrgPolicy.requireRestoreApproval) AND OFF BY DEFAULT, because
  // an unconditional gate made restore-apply unreachable on a one-identity estate: canApprove refuses a
  // same-subject and a same-email approval, so no approval could ever exist there. This validator exercises
  // the gate MACHINERY, so it arms the policy explicitly. That the default is OFF, and that arming restores
  // the strict behaviour, is proved separately in validate-restore-approval-optional.ts.
  const s = makeScheduler();
  await s.storage.put(ORG_POLICY_KEY, { requireConfigApproval: false, requireRestoreApproval: true });
  // Plan hashes call() must NOT anchor for: the arms that drive a request against a plan the engine has no
  // recorded dry run for.
  const unanchored = new Set<string>();

  // call() drives a DO route bypassing the router, forwarding a Caller via the encoded header exactly as
  // the router does. POST always carries a body (the handler does req.json()); GET carries none.
  //
  // A REQUEST IS PRECEDED BY ITS DRY RUN'S PLAN ANCHOR, because requestRestore refuses a plan hash with no
  // recorded preview: the engine will not mint an approval against a plan it cannot date. Every operator
  // path reaches the request route through a dry run, so noting the anchor here is what makes these cases
  // the sequences the product permits rather than ones no console could produce. Skipped when the case has
  // already put an anchor of its own down (the stale-plan arm below), because a note SWEEPS before it puts
  // and would otherwise clear the very fixture that case planted, and skipped for the plan hashes the
  // absent-anchor arm needs to stay unanchored.
  async function call(path: string, caller: Caller | null, body?: unknown, method: "GET" | "POST" = "POST"): Promise<Response> {
    const headers: Record<string, string> = {};
    if (caller !== null) headers[CALLER_HEADER] = encodeCaller(caller);
    if (method === "POST") headers["content-type"] = "application/json";
    const init: RequestInit = { method, headers };
    if (method === "POST") init.body = JSON.stringify(body ?? {});
    const hash = (body as { planHash?: unknown } | undefined)?.planHash;
    if (path === "/restore/request" && typeof hash === "string" && !unanchored.has(hash) && !s.storage.has(`planseen:${hash}`)) await notePlanAnchor(s.stub.fetch, hash);
    return s.stub.fetch(`https://scheduler.internal${path}`, init);
  }
  const jbody = async (r: Response): Promise<Record<string, unknown>> => (await r.json()) as Record<string, unknown>;
  const errOf = async (r: Response): Promise<string> => ((await r.json()) as { error?: string }).error ?? "";

  // ---- Callers (the role on the header is the authority these routes trust FROM THE ROUTER ONLY). -----
  const viewer: Caller = { method: "access", email: "vw@x.example", subject: "sub|vw", role: "viewer", groups: [] };
  const operator: Caller = { method: "access", email: "op@x.example", subject: "sub|op", role: "operator", groups: [] };
  const approver: Caller = { method: "access", email: "ap@x.example", subject: "sub|ap", role: "approver", groups: [] };
  const approver2: Caller = { method: "access", email: "ap2@x.example", subject: "sub|ap2", role: "approver", groups: [] };
  const approverIp: Caller = { method: "access", email: "apip@x.example", subject: "sub|apip", role: "approver", groups: [], sourceIp: "203.0.113.9" };
  const approverNoEmail: Caller = { method: "access", email: null, subject: "sub|ap-noemail", role: "approver", groups: [] };
  const opNoEmail: Caller = { method: "access", email: null, subject: "sub|op-noemail", role: "operator", groups: [] };
  const opWithIp: Caller = { method: "access", email: "opip@x.example", subject: "sub|opip", role: "operator", groups: [], sourceIp: "203.0.113.7" };
  // The bare-token break-glass: owner role (so the capability gate passes) but NO stable subject.
  const tokenOwner: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };
  // A SECOND identity for the SAME human as `operator` -- same verified email, a genuinely distinct
  // IdP-bound subject (the shape a passkey identity plus a native-IdP identity, or two group-role-mapped SSO
  // connections, both produce for one person). Holds restore.approve so the capability gate is not what
  // refuses it; only the maker != checker email floor should.
  const operatorSameEmailApprover: Caller = { method: "access", email: "op@x.example", subject: "sub|op-second-identity", role: "approver", groups: [] };

  // The SAME authority, in the DO's OWN role table. The routes above trust the forwarded role; the
  // SPEND-TIME identity binding (approvals.ts approvalIdentitiesStillAuthorised) deliberately does not,
  // because at a reserve there is no caller and no header to trust -- it re-resolves the recorded maker and
  // checker from their immutable subjects against the live tables. Without these grants the fixture would
  // be asserting reserve/consume mechanics for a ceremony two people who hold nothing had performed, which
  // production cannot produce. See seedBoundRole's own comment.
  for (const c of [viewer, operator, approver, approver2, approverIp, approverNoEmail, opNoEmail, opWithIp, operatorSameEmailApprover]) {
    await seedBoundRole(s.storage, c.subject!, c.email, c.role);
  }

  const PH_MAIN = planOf("main-plan");
  const PH_SELF = planOf("self-plan");
  const PH_NOEMAIL_AP = planOf("noemail-ap-plan");
  const PH_REQONLY = planOf("reqonly-plan");
  const PH_REJ1 = planOf("rej1-plan");
  const PH_REJ2 = planOf("rej2-plan");
  const PH_NOEMAIL_REQ = planOf("noemail-req-plan");
  const PH_IP = planOf("ip-req-plan");
  const PH_CAP = planOf("cap-plan");
  const PH_UNRESERVED = planOf("unreserved-plan");
  const PH_SAMEEMAIL = planOf("same-email-plan");

  // ===========================================================================================
  // SECTION 1: requestRestore — the capability gate, every validation refusal, and the create path.
  // ===========================================================================================
  {
    const noCaller = await call("/restore/request", null, { planHash: PH_MAIN, runId: "r", reason: "x" });
    ok("[request] a caller-less request is refused at the DO capability re-check (403)", noCaller.status === 403);
    const vw = await call("/restore/request", viewer, { planHash: PH_MAIN, runId: "r", reason: "x" });
    ok("[request] a viewer (no restore.request) is refused (403, forbidden)", vw.status === 403 && (await jbody(vw)).error === "forbidden");

    const noPlan = await call("/restore/request", operator, { runId: "r", reason: "x" });
    ok("[request] a missing planHash is a 400 naming the sha384 binding", noPlan.status === 400 && /sha384/.test(await errOf(noPlan)));
    const badPlan = await call("/restore/request", operator, { planHash: "not-a-hash", runId: "r", reason: "x" });
    ok("[request] a planHash without the sha384 prefix is a 400", badPlan.status === 400 && /sha384/.test(await errOf(badPlan)));
    const noRun = await call("/restore/request", operator, { planHash: PH_MAIN, reason: "x" });
    ok("[request] a missing runId is a 400", noRun.status === 400 && /runId/.test(await errOf(noRun)));
    const emptyRun = await call("/restore/request", operator, { planHash: PH_MAIN, runId: "", reason: "x" });
    ok("[request] an empty runId is a 400", emptyRun.status === 400 && /runId/.test(await errOf(emptyRun)));
    const noReason = await call("/restore/request", operator, { planHash: PH_MAIN, runId: "r" });
    ok("[request] a missing reason is a 400", noReason.status === 400 && /reason/.test(await errOf(noReason)));
    const blankReason = await call("/restore/request", operator, { planHash: PH_MAIN, runId: "r", reason: "   " });
    ok("[request] a blank reason is a 400", blankReason.status === 400 && /reason/.test(await errOf(blankReason)));
    const longReason = await call("/restore/request", operator, { planHash: PH_MAIN, runId: "r", reason: "a".repeat(1001) });
    ok("[request] an over-length reason is a 400 (validateFreeText)", longReason.status === 400 && /reason/.test(await errOf(longReason)));
    const ctrlReason = await call("/restore/request", operator, { planHash: PH_MAIN, runId: "r", reason: "bad\x00reason" });
    ok("[request] a control-character reason is a 400 (validateFreeText)", ctrlReason.status === 400 && /reason/.test(await errOf(ctrlReason)));

    const tok = await call("/restore/request", tokenOwner, { planHash: PH_MAIN, runId: "r", reason: "token cannot make" });
    ok("[request] the bare-token caller (no subject) cannot raise a request (400, attributable identity)", tok.status === 400 && /attributable identity/.test(await errOf(tok)));

    // The create path: the full blast-radius cues are stored (not hashed); requestedBy + subject recorded.
    const created = await call("/restore/request", operator, { planHash: PH_MAIN, runId: "run-main", reason: "quarterly DR", isLatest: true, plannedWrites: 3, bytes: 42, redirectBinding: "KV_X" });
    const rec = (await created.json()) as RestoreApproval;
    ok("[request] a valid request is created (200, status requested)", created.status === 200 && rec.status === "requested" && rec.planHash === PH_MAIN);
    ok("[request] the stored cues are the request's (writes/bytes/redirect/isLatest)", rec.plannedWrites === 3 && rec.bytes === 42 && rec.redirectBinding === "KV_X" && rec.isLatest === true);
    ok("[request] the maker is recorded by email + stable subject", rec.requestedBy === "op@x.example" && rec.requesterSubject === "sub|op");
    const stored = await s.storage.get<RestoreApproval>(approvalKey(PH_MAIN));
    ok("[request] the record was persisted under approval:<planHash>", stored?.runId === "run-main");

    // A re-request for the SAME plan over a still-OPEN (requested) record overwrites it with a fresh one.
    const reReq = await call("/restore/request", operator, { planHash: PH_MAIN, runId: "run-main", reason: "raise it again" });
    const reRec = (await reReq.json()) as RestoreApproval;
    ok("[request] a re-request over an open record overwrites it (200, requested, new reason)", reReq.status === 200 && reRec.status === "requested" && reRec.reason === "raise it again");

    // requestedBy falls back to the subject when the verified email is null (an emailless verified caller).
    const noEmailReq = await call("/restore/request", opNoEmail, { planHash: PH_NOEMAIL_REQ, runId: "run-noemail", reason: "no email" });
    const neRec = (await noEmailReq.json()) as RestoreApproval;
    ok("[request] an emailless caller's requestedBy falls back to the subject", noEmailReq.status === 200 && neRec.requestedBy === "sub|op-noemail" && neRec.requesterSubject === "sub|op-noemail");

    // A request carrying a source IP: the IP rides into the restore-request audit event.
    const ipReq = await call("/restore/request", opWithIp, { planHash: PH_IP, runId: "run-ip", reason: "ip request" });
    ok("[request] a source-IP request succeeds (200)", ipReq.status === 200);
  }

  // ===========================================================================================
  // SECTION 2: approveRestore — the capability gate, attributable-identity gate, maker != checker, state.
  // ===========================================================================================
  {
    const opAp = await call("/restore/approve", operator, { planHash: PH_MAIN });
    ok("[approve] an operator (no restore.approve) is refused (403)", opAp.status === 403);
    const noPlan = await call("/restore/approve", approver, {});
    ok("[approve] a missing planHash is a 400", noPlan.status === 400 && /planHash/.test(await errOf(noPlan)));
    const noRec = await call("/restore/approve", approver, { planHash: planOf("does-not-exist") });
    ok("[approve] approving an unknown plan is a 400 (no such request)", noRec.status === 400 && /no such request/.test(await errOf(noRec)));
    const tok = await call("/restore/approve", tokenOwner, { planHash: PH_MAIN });
    ok("[approve] the bare-token caller (no subject) cannot approve (400, attributable identity)", tok.status === 400 && /attributable identity/.test(await errOf(tok)));

    // A distinct approver (with a source IP) approves the open PH_MAIN request -> approved, checker recorded.
    const apr = await call("/restore/approve", approverIp, { planHash: PH_MAIN });
    const ar = (await apr.json()) as RestoreApproval;
    ok("[approve] a distinct approver approves (200, status approved)", apr.status === 200 && ar.status === "approved");
    ok("[approve] the checker is recorded (email + subject), maker != checker by subject", ar.approvedBy === "apip@x.example" && ar.approverSubject === "sub|apip" && ar.approverSubject !== ar.requesterSubject);

    // Re-approving an already-approved record is refused (the state rule in canApprove).
    const reApr = await call("/restore/approve", approver2, { planHash: PH_MAIN });
    ok("[approve] re-approving an approved record is refused (400)", reApr.status === 400 && /already approved/.test(await errOf(reApr)));

    // maker != checker: the requester cannot approve their own request even holding the role.
    await call("/restore/request", approver, { planHash: PH_SELF, runId: "run-self", reason: "self" });
    const self = await call("/restore/approve", approver, { planHash: PH_SELF });
    ok("[approve] the maker cannot approve their own request (400, server-side maker != checker)", self.status === 400 && /cannot approve your own request/.test(await errOf(self)));

    // The SAME human, requesting under subject A and approving under subject B, sharing one verified
    // email, is refused too -- the subject-only check above would have missed this (the subjects genuinely
    // differ). This is the exact bypass the adversarial attack proved against origin/main.
    await call("/restore/request", operator, { planHash: PH_SAMEEMAIL, runId: "run-same-email", reason: "same-email bypass attempt" });
    const sameEmail = await call("/restore/approve", operatorSameEmailApprover, { planHash: PH_SAMEEMAIL });
    ok(
      "[approve] same email, DIFFERENT subject is STILL refused as a self-approval (400)",
      sameEmail.status === 400 && /cannot approve your own request/.test(await errOf(sameEmail)),
    );
    // Control: a genuinely distinct human (different email AND different subject) CAN still approve it --
    // proving the fix did not also break legitimate dual control.
    const sameEmailApr = await call("/restore/approve", approver2, { planHash: PH_SAMEEMAIL });
    const sameEmailAr = (await sameEmailApr.json()) as RestoreApproval;
    ok("[approve] CONTROL: a genuinely distinct approver still approves it (200)", sameEmailApr.status === 200 && sameEmailAr.status === "approved");

    // The checker's display email falls back to the subject when the verified email is null.
    await call("/restore/request", operator, { planHash: PH_NOEMAIL_AP, runId: "run-noemail-ap", reason: "for noemail approver" });
    const neAp = await call("/restore/approve", approverNoEmail, { planHash: PH_NOEMAIL_AP });
    const neAr = (await neAp.json()) as RestoreApproval;
    ok("[approve] an emailless checker's approvedBy falls back to the subject", neAp.status === 200 && neAr.approvedBy === "sub|ap-noemail" && neAr.approverSubject === "sub|ap-noemail");
  }

  // ===========================================================================================
  // SECTION 3: requestRestore refuses to clobber a still-usable APPROVED record.
  // ===========================================================================================
  {
    const reReq = await call("/restore/request", operator, { planHash: PH_MAIN, runId: "run-main", reason: "should not clobber the approval" });
    ok("[request] a re-request over an APPROVED record is refused (400, approval already exists)", reReq.status === 400 && /already exists/.test(await errOf(reReq)));
  }

  // ===========================================================================================
  // SECTION 4: rejectRestore — the capability gate, validation, the state rule, audit attribution.
  // ===========================================================================================
  {
    const opRj = await call("/restore/reject", operator, { planHash: PH_MAIN });
    ok("[reject] an operator (no restore.approve) is refused (403)", opRj.status === 403);
    const noPlan = await call("/restore/reject", approver, {});
    ok("[reject] a missing planHash is a 400", noPlan.status === 400 && /planHash/.test(await errOf(noPlan)));
    const noRec = await call("/restore/reject", approver, { planHash: planOf("nope-reject") });
    ok("[reject] rejecting an unknown plan is a 400 (no such request)", noRec.status === 400 && /no such request/.test(await errOf(noRec)));

    // The bare-token owner MAY reject (a reject needs no maker != checker), exercising the null subject/email
    // audit attribution arms without a refusal.
    await call("/restore/request", operator, { planHash: PH_REJ1, runId: "run-rej1", reason: "to reject by token" });
    const tokRj = await call("/restore/reject", tokenOwner, { planHash: PH_REJ1 });
    ok("[reject] the bare-token owner can reject an open request (200, rejected)", tokRj.status === 200 && ((await tokRj.json()) as RestoreApproval).status === "rejected");
    const reRj = await call("/restore/reject", tokenOwner, { planHash: PH_REJ1 });
    ok("[reject] re-rejecting a rejected record is refused (400, the state rule)", reRj.status === 400 && /already rejected/.test(await errOf(reRj)));

    // A normal approver (email + source IP) rejects another open request: the present subject/email/IP arms.
    await call("/restore/request", operator, { planHash: PH_REJ2, runId: "run-rej2", reason: "to reject by approver" });
    const apRj = await call("/restore/reject", approverIp, { planHash: PH_REJ2 });
    ok("[reject] a distinct approver rejects an open request (200, rejected)", apRj.status === 200 && ((await apRj.json()) as RestoreApproval).status === "rejected");
  }

  // ===========================================================================================
  // SECTION 5: listApprovals — the approver view, the requester-own view, the null-caller view, and the
  //            newest-first sort (including the equal-timestamp tie) over a fresh DO with seeded records.
  // ===========================================================================================
  {
    const apView = (await (await call("/restore/approvals?approver=1", approver, undefined, "GET")).json()) as RestoreApproval[];
    ok("[list] an approver sees the inbox (PH_MAIN + the self request among them)", Array.isArray(apView) && apView.some((r) => r.planHash === PH_MAIN) && apView.some((r) => r.planHash === PH_SELF));
    const opView = (await (await call("/restore/approvals", operator, undefined, "GET")).json()) as RestoreApproval[];
    ok("[list] a requesting operator (not approver) sees their OWN requests", Array.isArray(opView) && opView.some((r) => r.requesterSubject === "sub|op"));
    ok("[list] the operator view excludes the approver's own self request", !opView.some((r) => r.requesterSubject === "sub|ap"));
    const anonView = (await (await call("/restore/approvals", null, undefined, "GET")).json()) as RestoreApproval[];
    ok("[list] a caller-less, non-approver read sees nothing", Array.isArray(anonView) && !anonView.some((r) => r.requesterSubject === "sub|op"));

    // Sort coverage on a fresh DO: four seeded records, two with an IDENTICAL requestedAt (the tie), so the
    // comparator exercises the less-than, greater-than and equal arms; the result must be newest-first.
    const s2 = makeScheduler();
    await s2.storage.put(ORG_POLICY_KEY, { requireConfigApproval: false, requireRestoreApproval: true });
    const exp = new Date(Date.now() + APPROVAL_TTL_MS).toISOString();
    const seed = async (n: number, requestedAt: string): Promise<void> => {
      const rec: RestoreApproval = { planHash: planOf(`seed-${n}`), runId: `run-${n}`, isLatest: false, plannedWrites: 0, bytes: 0, redirectBinding: null, requesterSubject: `sub|seed-${n}`, requestedBy: `seed${n}@x`, requesterGroups: [], requestedAt, reason: "seed", status: "requested", expiresAt: exp };
      await s2.storage.put(approvalKey(rec.planHash), rec);
    };
    await seed(1, "2026-06-07T00:00:03.000Z");
    await seed(2, "2026-06-07T00:00:01.000Z");
    await seed(3, "2026-06-07T00:00:01.000Z");
    await seed(4, "2026-06-07T00:00:02.000Z");
    const sorted = (await (await s2.stub.fetch("https://scheduler.internal/restore/approvals?approver=1", { method: "GET", headers: { [CALLER_HEADER]: encodeCaller(approver) } })).json()) as RestoreApproval[];
    ok("[list] all four seeded records are visible to the approver", sorted.length === 4);
    ok("[list] the inbox is newest-first with the equal-timestamp pair last", sorted.map((r) => r.requestedAt).join(",") === "2026-06-07T00:00:03.000Z,2026-06-07T00:00:02.000Z,2026-06-07T00:00:01.000Z,2026-06-07T00:00:01.000Z");
  }

  // ===========================================================================================
  // SECTION 6: gateRestore — the read-only apply-time gate (no planHash, no record, usable, not-usable).
  //            The gate is READ-ONLY (it does NOT reserve); the actual atomic
  //            single-use reservation that closes the concurrent-apply TOCTOU is /restore/reserve,
  //            exercised in SECTION 6a below.
  // ===========================================================================================
  {
    const noPlan = (await (await call("/restore/gate", operator, {})).json()) as { usable: boolean; approval: RestoreApproval | null };
    ok("[gate] a missing planHash gates closed with no approval", noPlan.usable === false && noPlan.approval === null);
    const noRec = (await (await call("/restore/gate", operator, { planHash: planOf("never-requested") })).json()) as { usable: boolean; approval: RestoreApproval | null };
    ok("[gate] an unknown plan gates closed with no approval", noRec.usable === false && noRec.approval === null);
    const usable = (await (await call("/restore/gate", operator, { planHash: PH_MAIN })).json()) as { usable: boolean; approval: RestoreApproval | null };
    ok("[gate] the approved PH_MAIN plan gates OPEN and returns the record (read-only, still 'approved')", usable.usable === true && usable.approval?.status === "approved");
    // The read-only gate did NOT mutate the stored record: it stays "approved" (only /restore/reserve flips it).
    const afterGate = await s.storage.get<RestoreApproval>(approvalKey(PH_MAIN));
    ok("[gate] the read-only gate did not reserve or mutate the record (still 'approved', no appliedAt)", afterGate?.status === "approved" && afterGate?.appliedAt === undefined);
    // A requested-only record gates CLOSED but still returns the record (so the apply route can explain why).
    await call("/restore/request", operator, { planHash: PH_REQONLY, runId: "run-reqonly", reason: "requested only" });
    const notUsable = (await (await call("/restore/gate", operator, { planHash: PH_REQONLY })).json()) as { usable: boolean; approval: RestoreApproval | null };
    ok("[gate] a requested-only record gates CLOSED but surfaces the record", notUsable.usable === false && notUsable.approval?.status === "requested");
  }

  // ===========================================================================================
  // SECTION 6a: reserveRestore / releaseRestore — the atomic gate-to-write reservation: the
  //             single-use transition now happens at reserve time (approved -> applying), not at the
  //             post-write consume, so a concurrent second reserve for the SAME plan hash is refused
  //             while the first is genuinely in flight, and a crashed reservation self-heals via the lease.
  // ===========================================================================================
  {
    const noPlan = (await (await call("/restore/reserve", operator, {})).json()) as { reserved: boolean };
    ok("[reserve] a missing planHash does not reserve", noPlan.reserved === false);
    const noRec = (await (await call("/restore/reserve", operator, { planHash: planOf("never-reserved") })).json()) as { reserved: boolean };
    ok("[reserve] an unknown plan does not reserve", noRec.reserved === false);
    const notUsable = (await (await call("/restore/reserve", operator, { planHash: PH_REQONLY })).json()) as { reserved: boolean };
    ok("[reserve] a requested-only (not approved) record cannot be reserved", notUsable.reserved === false);

    // Seed a fresh request + approval for the reservation exercise, independent of PH_MAIN (section 7).
    const PH_RESV = planOf("reserve-plan");
    await call("/restore/request", operator, { planHash: PH_RESV, runId: "run-reserve", reason: "reservation exercise" });
    await call("/restore/approve", approver, { planHash: PH_RESV });

    // reserve succeeds once from "approved", stamping the lease start.
    const first = (await (await call("/restore/reserve", operator, { planHash: PH_RESV })).json()) as { reserved: boolean };
    ok("[reserve] a usable approval reserves (reserved:true)", first.reserved === true);
    const applying = await s.storage.get<RestoreApproval>(approvalKey(PH_RESV));
    ok("[reserve] the stored record flips to applying with a lease-start stamp", applying?.status === "applying" && typeof applying?.appliedAt === "string");

    // A second reserve while genuinely "applying" (within the lease) is refused: this closes the TOCTOU --
    // a concurrent second apply for the same plan hash cannot also reserve it.
    const second = (await (await call("/restore/reserve", operator, { planHash: PH_RESV })).json()) as { reserved: boolean };
    ok("[reserve] a concurrent second reserve while applying is refused", second.reserved === false);

    // Approve / reject / re-request must not be able to hijack a live reservation out from under it either
    // (each would otherwise overwrite "applying" and let a fresh reserve race in under the reserver).
    const reApprove = await call("/restore/approve", approver2, { planHash: PH_RESV });
    ok("[reserve] re-approving an applying record is refused (400)", reApprove.status === 400 && /currently being applied/.test(await errOf(reApprove)));
    const reReject = await call("/restore/reject", approver, { planHash: PH_RESV });
    ok("[reserve] rejecting an applying record is refused (400)", reReject.status === 400 && /currently being applied/.test(await errOf(reReject)));
    const reRequest = await call("/restore/request", operator, { planHash: PH_RESV, runId: "run-reserve", reason: "should not clobber the reservation" });
    ok("[reserve] re-requesting over an applying record is refused (400)", reRequest.status === 400 && /already exists/.test(await errOf(reRequest)));

    // release reverts applying -> approved (clearing appliedAt); a subsequent reserve then succeeds again.
    const rel = (await (await call("/restore/release", operator, { planHash: PH_RESV })).json()) as { released: boolean };
    ok("[release] releasing an applying reservation succeeds (released:true)", rel.released === true);
    const releasedRec = await s.storage.get<RestoreApproval>(approvalKey(PH_RESV));
    ok("[release] the stored record reverts to approved with appliedAt cleared", releasedRec?.status === "approved" && releasedRec?.appliedAt === undefined);
    const relAgain = (await (await call("/restore/release", operator, { planHash: PH_RESV })).json()) as { released: boolean };
    ok("[release] releasing an already-approved (not applying) record does nothing", relAgain.released === false);
    const third = (await (await call("/restore/reserve", operator, { planHash: PH_RESV })).json()) as { reserved: boolean };
    ok("[reserve] a fresh reserve after release succeeds again", third.reserved === true);

    // A lease-expired "applying" record (a crashed apply that never released) is lazily reclaimable: seed
    // one directly with appliedAt older than RESTORE_APPLY_LEASE_MS and confirm it reads back as approved
    // (gate) and is reservable again (reserve), the crash-reclaim mirroring the in-flight lease elsewhere.
    const PH_LEASE = planOf("lease-expired-plan");
    const staleApplying: RestoreApproval = {
      planHash: PH_LEASE,
      runId: "run-lease",
      isLatest: false,
      plannedWrites: 0,
      bytes: 0,
      redirectBinding: null,
      requesterSubject: "sub|lease-req",
      requestedBy: "lease-req@x.example",
      requesterGroups: [],
      requestedAt: new Date(Date.now() - RESTORE_APPLY_LEASE_MS * 3).toISOString(),
      reason: "crashed apply",
      status: "applying",
      approverSubject: "sub|lease-ap",
      approvedBy: "lease-ap@x.example",
      approvedAt: new Date(Date.now() - RESTORE_APPLY_LEASE_MS * 2).toISOString(),
      appliedAt: new Date(Date.now() - RESTORE_APPLY_LEASE_MS - 1000).toISOString(),
      expiresAt: new Date(Date.now() + APPROVAL_TTL_MS).toISOString(),
    };
    // The two identities on the seeded record hold their grants in the DO's own tables, so the crash-reclaim
    // is proved against a record the spend-time binding accepts -- the lease is what is under test here, not
    // the binding.
    await seedBoundRole(s.storage, "sub|lease-req", "lease-req@x.example", "operator");
    await seedBoundRole(s.storage, "sub|lease-ap", "lease-ap@x.example", "approver");
    await s.storage.put(approvalKey(PH_LEASE), staleApplying);
    const gateOnStale = (await (await call("/restore/gate", operator, { planHash: PH_LEASE })).json()) as { usable: boolean; approval: RestoreApproval | null };
    ok("[reserve] a lease-expired applying record reads back as approved/usable (crash reclaim)", gateOnStale.usable === true && gateOnStale.approval?.status === "approved");
    const reclaim = (await (await call("/restore/reserve", operator, { planHash: PH_LEASE })).json()) as { reserved: boolean };
    ok("[reserve] a lease-expired applying record is reclaimable by a fresh reserve", reclaim.reserved === true);
  }

  // ===========================================================================================
  // SECTION 7: consumeApproval — the atomic single-use consume (no planHash, not-reserved, the consume +
  //            reuse). consumeApproval flips THIS request's own RESERVATION (raw status "applying")
  //            rather than a merely-"approved" record, so the real flow reserves immediately before
  //            the write and consumes only after it succeeds, exactly as router-restore.ts now does.
  // ===========================================================================================
  {
    const noPlan = (await (await call("/restore/consume", operator, {})).json()) as { consumed: boolean };
    ok("[consume] a missing planHash does not consume", noPlan.consumed === false);
    const noRec = (await (await call("/restore/consume", operator, { planHash: planOf("never-here") })).json()) as { consumed: boolean };
    ok("[consume] an unknown plan does not consume", noRec.consumed === false);
    const notReserved = (await (await call("/restore/consume", operator, { planHash: PH_REQONLY })).json()) as { consumed: boolean };
    ok("[consume] a requested-only (never reserved) record is not consumed", notReserved.consumed === false);
    // PH_MAIN is still merely "approved" here (untouched since section 2): a bare consume, with no reserve
    // first, must NOT succeed.
    const stillApproved = (await (await call("/restore/consume", operator, { planHash: PH_MAIN })).json()) as { consumed: boolean };
    ok("[consume] a merely-approved (not yet reserved) record is not consumed by a bare consume call", stillApproved.consumed === false);

    // The real flow reserves immediately before the write; mirror that here before consuming PH_MAIN.
    const reserved = (await (await call("/restore/reserve", operator, { planHash: PH_MAIN })).json()) as { reserved: boolean };
    ok("[consume] PH_MAIN reserves cleanly ahead of the consume exercise", reserved.reserved === true);
    const done = (await (await call("/restore/consume", operator, { planHash: PH_MAIN })).json()) as { consumed: boolean; approval?: RestoreApproval };
    ok("[consume] a reserved (applying) approval is consumed exactly once (consumed:true)", done.consumed === true && done.approval?.status === "consumed");
    const persisted = await s.storage.get<RestoreApproval>(approvalKey(PH_MAIN));
    ok("[consume] the stored record is now consumed (single-use flip persisted)", persisted?.status === "consumed");
    const again = (await (await call("/restore/consume", operator, { planHash: PH_MAIN })).json()) as { consumed: boolean };
    ok("[consume] a second consume of the same approval does nothing (single use)", again.consumed === false);
  }

  // ===========================================================================================
  // SECTION 8: recordDrillEvidence — the capability gate, every validation refusal, the create path, and
  //            the cap rollover; plus listDrillEvidence.
  // ===========================================================================================
  {
    const vw = await call("/drill-evidence", viewer, { runId: "d1", kind: "in-account" });
    ok("[drill] a viewer (no drill.run) is refused (403)", vw.status === 403);
    const noRun = await call("/drill-evidence", operator, { kind: "in-account" });
    ok("[drill] a missing runId is a 400", noRun.status === 400 && /runId/.test(await errOf(noRun)));
    const blankRun = await call("/drill-evidence", operator, { runId: "   ", kind: "in-account" });
    ok("[drill] a blank runId is a 400", blankRun.status === 400 && /runId/.test(await errOf(blankRun)));
    const badKind = await call("/drill-evidence", operator, { runId: "d1", kind: "nonsense" });
    ok("[drill] an unknown kind is a 400", badKind.status === 400 && /kind/.test(await errOf(badKind)));
    const badNote = await call("/drill-evidence", operator, { runId: "d1", kind: "in-account", note: 123 });
    ok("[drill] a non-string note is a 400", badNote.status === 400 && /note/.test(await errOf(badNote)));
    const longNote = await call("/drill-evidence", operator, { runId: "d1", kind: "in-account", note: "a".repeat(1001) });
    ok("[drill] an over-length note is a 400 (validateFreeText)", longNote.status === 400 && /note/.test(await errOf(longNote)));

    const inAcct = await call("/drill-evidence", operator, { runId: "  drill-A  ", kind: "in-account" });
    const e1 = (await inAcct.json()) as { runId: string; kind: string; recordedBy: string | null; note?: string };
    ok("[drill] an in-account entry is recorded (200, trimmed runId, no note)", inAcct.status === 200 && e1.runId === "drill-A" && e1.kind === "in-account" && e1.note === undefined && e1.recordedBy === "op@x.example");
    const rehearsal = await call("/drill-evidence", operator, { runId: "drill-B", kind: "offline-rehearsal", note: "tabletop rehearsal" });
    const e2 = (await rehearsal.json()) as { kind: string; note?: string };
    ok("[drill] an offline-rehearsal entry with a note is recorded (200, note stored)", rehearsal.status === 200 && e2.kind === "offline-rehearsal" && e2.note === "tabletop rehearsal");
    const noEmail = await call("/drill-evidence", opNoEmail, { runId: "drill-C", kind: "in-account" });
    const e3 = (await noEmail.json()) as { recordedBy: string | null };
    ok("[drill] an emailless caller records recordedBy null (no attributable email)", noEmail.status === 200 && e3.recordedBy === null);

    const listed = (await (await call("/drill-evidence", operator, undefined, "GET")).json()) as Array<{ runId: string }>;
    ok("[drill] the evidence list returns the recorded entries newest-first", Array.isArray(listed) && listed.length === 3 && listed[0]!.runId === "drill-C");

    // Cap rollover on a fresh DO: seed DRILL_EVIDENCE_CAP rows (keys that sort before any real ULID, so they
    // are the oldest), then record one more so the count exceeds the cap and the oldest surplus is dropped.
    const s3 = makeScheduler();
    await s3.storage.put(ORG_POLICY_KEY, { requireConfigApproval: false, requireRestoreApproval: true });
    for (let i = 0; i < DRILL_EVIDENCE_CAP; i++) {
      await s3.storage.put(`${DRILL_EVIDENCE_PREFIX}${i.toString().padStart(26, "0")}`, { runId: `seed-${i}`, kind: "in-account", recordedBy: null, recordedAt: "2020-01-01T00:00:00.000Z" });
    }
    ok("[drill] the rollover DO is seeded exactly to the cap", s3.storage.countPrefix(DRILL_EVIDENCE_PREFIX) === DRILL_EVIDENCE_CAP);
    const overflow = await s3.stub.fetch("https://scheduler.internal/drill-evidence", { method: "POST", headers: { "content-type": "application/json", [CALLER_HEADER]: encodeCaller(operator) }, body: JSON.stringify({ runId: "the-newest", kind: "in-account" }) });
    ok("[drill] recording over the cap succeeds (200)", overflow.status === 200);
    ok("[drill] the rollover dropped the oldest surplus row back to the cap", s3.storage.countPrefix(DRILL_EVIDENCE_PREFIX) === DRILL_EVIDENCE_CAP);
    const afterList = (await (await s3.stub.fetch("https://scheduler.internal/drill-evidence", { method: "GET" })).json()) as Array<{ runId: string }>;
    ok("[drill] the newest entry survived the rollover (it is the head of the list)", afterList.length === DRILL_EVIDENCE_CAP && afterList[0]!.runId === "the-newest");
  }

  // ===========================================================================================
  // SECTION 9: callerHolds via a CUSTOM-ROLE caller (a resolved capability set) + the non-finite cue
  //            fallbacks. The wire header never carries a capability set, so this drives the real method
  //            directly with a custom-role caller whose set has() decides authority.
  // ===========================================================================================
  {
    const capCaller: Caller = { method: "access", email: "cap@x.example", subject: "sub|cap", role: "viewer", groups: [], capabilities: new Set<Capability>(["restore.request"]) };
    // The dry run this request is raised against, as call() does for the wire cases: requestRestore refuses
    // a plan hash with no recorded preview, and this section drives the method directly rather than through
    // the route, so it has to record the anchor for itself.
    await notePlanAnchor(s.stub.fetch, PH_CAP);
    const rec = await s.dobj.requestRestore({ planHash: PH_CAP, runId: "run-cap", reason: "custom-role caller", plannedWrites: Number.NaN, bytes: Number.POSITIVE_INFINITY, redirectBinding: null }, capCaller);
    ok("[caps] a custom-role caller whose set holds restore.request is authorised (record created)", rec.status === "requested" && rec.planHash === PH_CAP && rec.requestedBy === "cap@x.example");
    ok("[caps] non-finite plannedWrites/bytes cues fall back to 0; a null redirect stays null", rec.plannedWrites === 0 && rec.bytes === 0 && rec.redirectBinding === null);
    const persisted = await s.storage.get<RestoreApproval>(approvalKey(PH_CAP));
    ok("[caps] the custom-role request was persisted", persisted?.runId === "run-cap");

    // A custom-role caller whose set LACKS the capability is refused (the capability-set deny arm).
    const denyCaller: Caller = { method: "access", email: "deny@x.example", subject: "sub|deny", role: "viewer", groups: [], capabilities: new Set<Capability>(["downpipe.read"]) };
    let threw = false;
    try {
      await s.dobj.requestRestore({ planHash: planOf("deny-plan"), runId: "run-deny", reason: "lacks the cap" }, denyCaller);
    } catch (e) {
      threw = e instanceof Error && /restore\.request capability required/.test(e.message);
    }
    ok("[caps] a custom-role caller lacking restore.request is refused (AuthError)", threw);
  }

  // ===========================================================================================
  // SECTION 10: the audit trail captured the source IPs at the commit point (request / approve / reject).
  // ===========================================================================================
  {
    const log = (await (await call("/audit?limit=1000", operator, undefined, "GET")).json()) as { events: Array<{ action: string }> };
    const ev = log.events;
    const hasIp = (action: string, ip: string): boolean => ev.filter((e) => e.action === action).some((e) => JSON.stringify(e).includes(ip));
    ok("[audit] a restore-request event carries the request source IP", hasIp("restore-request", "203.0.113.7"));
    ok("[audit] a restore-approve event carries the approver source IP", hasIp("restore-approve", "203.0.113.9"));
    ok("[audit] a restore-reject event carries the rejecter source IP", hasIp("restore-reject", "203.0.113.9"));
  }

  // ===========================================================================================
  // SECTION 11: notePlanSeen / the PLAN ANCHOR — the put-if-absent record that makes an approval's TTL
  //             start at the plan the operator read rather than at the request they raised later. Its
  //             validation refusal, the put-if-absent rule, the sweep, the stale-plan refusal in
  //             requestRestore, and the drop on both terminal transitions.
  // ===========================================================================================
  {
    const PH_ANCHOR = planOf("anchor-plan");
    const bad = (await (await call("/restore/plan-seen", null, { planHash: "not-a-hash" })).json()) as { noted: boolean };
    ok("[plan-seen] a planHash that is not a sha384 binding hash is not recorded", bad.noted === false);
    const noHash = (await (await call("/restore/plan-seen", null, {})).json()) as { noted: boolean };
    ok("[plan-seen] an absent planHash is not recorded", noHash.noted === false);

    const t = Date.now();
    const first = (await (await call("/restore/plan-seen", null, { planHash: PH_ANCHOR, plannedAt: t - 5_000 })).json()) as { noted: boolean; anchoredAt: string | null };
    ok("[plan-seen] the first dry run for a plan records the anchor at the PLAN'S own instant, not at this call", first.noted === true && Date.parse(first.anchoredAt ?? "") === t - 5_000);
    // PUT-IF-ABSENT: a second preview must not move the deadline forward under an operator still holding
    // the first card.
    const second = (await (await call("/restore/plan-seen", null, { planHash: PH_ANCHOR, plannedAt: t })).json()) as { noted: boolean; anchoredAt: string | null };
    ok("[plan-seen] a second dry run does NOT move the anchor forward (the oldest card still in play is the one covered)", second.noted === false && Date.parse(second.anchoredAt ?? "") === t - 5_000);
    // A future plannedAt is clamped to now, so a caller-influenced value can only ever shorten its own
    // approval and never extend it.
    const PH_FUTURE = planOf("future-anchor-plan");
    const future = (await (await call("/restore/plan-seen", null, { planHash: PH_FUTURE, plannedAt: t + 86_400_000 })).json()) as { anchoredAt: string | null };
    ok("[plan-seen] a plan instant in the FUTURE is clamped to now, so it cannot extend an approval", Date.parse(future.anchoredAt ?? "") <= Date.now());

    // The approval's TTL is stamped from the anchor, so an approval requested later than the plan expires
    // 24 hours after the PLAN.
    const anchored = (await (await call("/restore/request", operator, { planHash: PH_ANCHOR, runId: "r-anchor", reason: "anchored" })).json()) as { expiresAt: string };
    ok("[request] expiresAt is APPROVAL_TTL_MS after the recorded plan anchor, not after this request", Date.parse(anchored.expiresAt) === t - 5_000 + APPROVAL_TTL_MS);

    // THE STALE PLAN. An anchor past its own deadline is refused rather than re-anchored to now: silently
    // re-anchoring is what would let the same displayed plan be re-requested after every expiry for ever,
    // since the plan hash carries no timestamp.
    const PH_STALE = planOf("stale-anchor-plan");
    await s.storage.put(`planseen:${PH_STALE}`, { at: Date.now() - (APPROVAL_TTL_MS + RESTORE_APPLY_LEASE_MS + 60_000) });
    const stale = await call("/restore/request", operator, { planHash: PH_STALE, runId: "r-stale", reason: "raised against yesterday's plan" });
    ok("[request] a request against a plan older than its own apply deadline is REFUSED", stale.status >= 400 && /run the dry run again/.test(await errOf(stale)));
    ok("[request] and no approval record was written by that refusal", (await s.storage.get(approvalKey(PH_STALE))) === undefined);
    // NO ANCHOR AT ALL is refused on the same terms, and it has to be: a swept anchor and one that never
    // existed are the same storage state, so accepting this arm would make the stale refusal above a
    // formality anybody could walk around by waiting for the next dry run to sweep.
    const PH_UNSEEN = planOf("never-previewed-plan");
    unanchored.add(PH_UNSEEN);
    const unseen = await call("/restore/request", operator, { planHash: PH_UNSEEN, runId: "r-unseen", reason: "no dry run was recorded" });
    ok("[request] a request against a plan with NO recorded dry run is REFUSED", unseen.status >= 400 && /run the dry run/.test(await errOf(unseen)));
    ok("[request] and no approval record was written by that refusal either", (await s.storage.get(approvalKey(PH_UNSEEN))) === undefined);

    // A corrupt anchor value reads as absent, so it refuses too -- and it does NOT wedge the plan, because
    // the next preview sweeps a non-finite row and re-anchors. Driven rather than argued: refused, then one
    // dry run, then accepted.
    const PH_CORRUPT = planOf("corrupt-anchor-plan");
    unanchored.add(PH_CORRUPT);
    await s.storage.put(`planseen:${PH_CORRUPT}`, { at: "not-a-number" });
    const corrupt = await call("/restore/request", operator, { planHash: PH_CORRUPT, runId: "r-corrupt", reason: "corrupt anchor" });
    ok("[request] an unparseable anchor reads as absent and is refused, not treated as a fresh preview", corrupt.status >= 400 && /run the dry run/.test(await errOf(corrupt)));
    await call("/restore/plan-seen", null, { planHash: PH_CORRUPT, plannedAt: Date.now() });
    const recovered = (await (await call("/restore/request", operator, { planHash: PH_CORRUPT, runId: "r-corrupt", reason: "corrupt anchor, re-planned" })).json()) as { expiresAt?: string };
    ok("[request] and one fresh dry run clears the corrupt row and unwedges the plan", typeof recovered.expiresAt === "string");

    // TERMINAL TRANSITIONS drop the anchor, so the next cycle anchors to a fresh preview.
    await call("/restore/reject", approver, { planHash: PH_ANCHOR, rejectReason: "stale-plan" });
    ok("[reject] the plan anchor is dropped when the approval is rejected", (await s.storage.get(`planseen:${PH_ANCHOR}`)) === undefined);
    const PH_CONSUME_ANCHOR = planOf("consume-anchor-plan");
    await call("/restore/plan-seen", null, { planHash: PH_CONSUME_ANCHOR, plannedAt: Date.now() });
    await call("/restore/request", operator, { planHash: PH_CONSUME_ANCHOR, runId: "r-consume", reason: "consume anchor" });
    await call("/restore/approve", approver, { planHash: PH_CONSUME_ANCHOR });
    await call("/restore/reserve", operator, { planHash: PH_CONSUME_ANCHOR });
    await call("/restore/consume", operator, { planHash: PH_CONSUME_ANCHOR });
    ok("[consume] the plan anchor is dropped when the approval is consumed", (await s.storage.get(`planseen:${PH_CONSUME_ANCHOR}`)) === undefined);

    // THE SWEEP. An anchor past its deadline is deleted by the next preview, which then re-anchors, so the
    // store cannot grow without bound and a genuinely fresh plan is never refused for an old one.
    const PH_SWEPT = planOf("swept-anchor-plan");
    await s.storage.put(`planseen:${PH_SWEPT}`, { at: Date.now() - (APPROVAL_TTL_MS + RESTORE_APPLY_LEASE_MS + 60_000) });
    const reNoted = (await (await call("/restore/plan-seen", null, { planHash: PH_SWEPT, plannedAt: Date.now() })).json()) as { noted: boolean };
    ok("[plan-seen] a stale anchor is swept and the fresh preview re-anchors", reNoted.noted === true);
  }

  console.log(failures === 0 ? "\nVALIDATE-COV-SCHED-SCHEDULER-DO-RESTORE-APPROVAL VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
