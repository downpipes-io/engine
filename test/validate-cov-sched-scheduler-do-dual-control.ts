// validate-cov-sched-scheduler-do-dual-control: a focused branch-coverage validator for the DualControlMixin
// (src/sched/scheduler-do-dual-control.ts), the OPT-IN dual control over the high-blast-radius OWNER ops. It
// drives the REAL Durable Object (router-bypassed via the shared owner-action harness) through every gate
// branch: the change-controlled vs exempt split in gatedOwnerAction, the inline gate-off path and the queued
// gate-on path, recordOwnerAction's attributable-maker refusal, the DO-executed approve+execute dispatch for
// every kind, the router-executed gate-check / arm / single-use consume flow with its precise refusals, the
// integrity recompute, the live proposer re-resolution, the reject lifecycle, the inbox projection and the
// audit source-IP attribution. Tampered/edge records are crafted at rest (with a correctly computed action
// hash) so the defensive branches run through the production code, never a stub. No network beyond the
// harness JWKS shim, no deploy, no cost.
//
// Run: node test/validate-cov-sched-scheduler-do-dual-control.ts

import { buildContext } from "./validate-owner-action-dualcontrol-harness.ts";
import { ownerActionHash, ownerActionKey, type PendingOwnerAction } from "../src/admin/owner-action.ts";
import { encodeCaller, type Caller } from "../src/admin/identity.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
const errOf = async (r: Response): Promise<string> => ((await r.json()) as { error?: string }).error ?? "";

async function main(): Promise<void> {
  const ctx = await buildContext();
  const { sched, OWNER, OWNER2, OPERATOR, subjectOf, call, readLog, setGate, doFetch, ownerCaller, ownerActionKeyCount, destConfig, oidcProposal, listDestinations, listIdpConnections, discoveryStatus } = ctx;

  try {
    // ---- Callers (router-bypass headers). The DO RE-RESOLVES role from its own tables, so the header role is
    //      only a label; the real authority is the bootstrapped/granted role table. -------------------------
    const ocIp = (email: string, ip: string): Caller => ({ ...ownerCaller(email), sourceIp: ip });
    const operatorCaller: Caller = { method: "access", email: OPERATOR, subject: subjectOf(OPERATOR), role: "operator", groups: [] };
    const tokenCaller: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };
    const doGet = (path: string, caller: Caller | null): Promise<Response> =>
      sched.stub.fetch(`https://scheduler.internal${path}`, { method: "GET", headers: caller !== null ? { "x-downpipe-caller": encodeCaller(caller) } : {} });
    const hashFor = (kind: string, params: unknown, proposer: string): Promise<string> =>
      ownerActionHash(kind as never, params, true, proposer, subjectOf(proposer), []);

    // Craft an at-rest owner-action record with a CORRECTLY computed action hash (normalised exactly as
    // verifyOwnerActionIntegrity recomputes it), so the defensive approve/consume branches run on a real record.
    let craftSeq = 0;
    async function putCrafted(o: {
      kind: string; params: unknown; status: PendingOwnerAction["status"]; routerExecuted?: boolean; proposedBy?: string;
      proposedBySubject?: string | null; proposedByGroups?: unknown; approverSubject?: string; approvedBy?: string;
      proposedAt?: string; expiresAtMs?: number; badHash?: boolean;
    }): Promise<{ id: string; actionHash: string }> {
      const id = `crafted-${craftSeq++}-${Date.now()}`;
      const routerExecuted = o.routerExecuted === true;
      const proposedBy = o.proposedBy ?? OWNER;
      const subj = o.proposedBySubject === undefined ? subjectOf(proposedBy) : o.proposedBySubject;
      const groups = Array.isArray(o.proposedByGroups) ? (o.proposedByGroups as string[]) : [];
      const actionHash = o.badHash === true ? "sha384:deliberately-wrong" : await ownerActionHash(o.kind as never, o.params, routerExecuted, proposedBy, subj, groups);
      const rec: Record<string, unknown> = {
        id, kind: o.kind, params: o.params, routerExecuted, proposedBy, proposedBySubject: subj,
        proposedByGroups: o.proposedByGroups, // may be undefined -> dropped by the storage clone (a non-array)
        proposedAt: o.proposedAt ?? new Date().toISOString(), summary: "crafted", actionHash, status: o.status,
        expiresAt: new Date(o.expiresAtMs ?? Date.now() + 3_600_000).toISOString(),
        ...(o.approverSubject !== undefined ? { approverSubject: o.approverSubject } : {}),
        ...(o.approvedBy !== undefined ? { approvedBy: o.approvedBy } : {}),
      };
      sched.storage.rawPut(ownerActionKey(id), rec);
      return { id, actionHash };
    }

    // ===========================================================================================
    // SETUP: grant a SECOND owner + a non-owner operator (gate OFF), then ARM the gate.
    // ===========================================================================================
    await call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "owner" });
    await call(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "operator" });
    const armed = await setGate(OWNER, true);
    ok("setup: an owner arms the dual-control gate (200)", armed.status === 200);

    // A DO-executed lifecycle driver: propose (202, queued), self-approve refused (maker != checker), a SECOND
    // owner approves and the op EXECUTES (single use). Returns the action id. verify() asserts the real state change.
    async function doExec(path: string, params: unknown, label: string, verify?: () => Promise<boolean>): Promise<string> {
      const before = ownerActionKeyCount();
      const p = await doFetch(path, ownerCaller(OWNER), params);
      ok(`[${label}] gate ON: a propose is queued (202)`, p.status === 202);
      const id = ((await p.json()) as { id?: string }).id ?? "";
      ok(`[${label}] the 202 carries an owner-action id + recorded one pending`, id.length > 0 && ownerActionKeyCount() === before + 1);
      const self = await doFetch("/owner-actions/approve", ownerCaller(OWNER), { id });
      ok(`[${label}] the proposer cannot approve their own action (400)`, self.status === 400 && /cannot approve your own action/.test(await errOf(self)));
      const ap = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id });
      ok(`[${label}] a distinct owner approves (200)`, ap.status === 200);
      const rec = (await ap.json()) as PendingOwnerAction;
      ok(`[${label}] the record is executed + attributes maker != checker`, rec.status === "executed" && rec.proposedBy === OWNER && rec.approvedBy === OWNER2);
      if (verify) ok(`[${label}] the approved action took effect`, await verify());
      return id;
    }

    // ===========================================================================================
    // SECTION A: every DO-EXECUTED kind dispatched through approveOwnerAction -> executeOwnerActionDO.
    // ===========================================================================================
    const execDestSetId = await doExec("/dest-config", { config: destConfig("ds-bucket") }, "dest-set");
    await doExec("/destinations", { label: "lpA", config: destConfig("lpa-bucket") }, "dest-put", async () => (await listDestinations()).destinations.some((d) => d.label === "lpA"));
    await doExec("/destinations", { label: "lpB", config: destConfig("lpb-bucket") }, "dest-put-2", async () => (await listDestinations()).destinations.some((d) => d.label === "lpB"));
    const lpB = (await listDestinations()).destinations.find((d) => d.label === "lpB")!;
    await doExec("/destinations/default", { id: lpB.id }, "dest-default", async () => (await listDestinations()).defaultId === lpB.id);
    const lpA = (await listDestinations()).destinations.find((d) => d.label === "lpA")!;
    await doExec("/destinations/remove", { id: lpA.id, force: true }, "dest-remove", async () => !(await listDestinations()).destinations.some((d) => d.id === lpA.id));
    await doExec("/idp/conn/create", oidcProposal("lc-oidc"), "idp-conn-create", async () => (await listIdpConnections(OWNER)).connections?.some((c) => c.id === "lc-oidc") === true);
    await doExec("/idp/conn/enabled", { connId: "lc-oidc", enabled: false }, "idp-conn-enabled", async () => (await listIdpConnections(OWNER)).connections?.some((c) => c.id === "lc-oidc" && c.enabled === false) === true);
    // idp-conn-cert: the dispatch reaches idpConnSamlCertUpdate, which soft-refuses a cert rollover on a NON-SAML
    // connection (returns {ok:false}); the owner action still executes (the arm + dispatch ran), proving the case.
    await doExec("/idp/conn/cert", { connId: "lc-oidc", addCerts: ["-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----"] }, "idp-conn-cert");
    await doExec("/idp/conn/delete", { connId: "lc-oidc" }, "idp-conn-delete", async () => !(await listIdpConnections(OWNER)).connections?.some((c) => c.id === "lc-oidc"));
    await doExec("/sources/discovery-token", { token: "cfat_cov_discovery_token_value_111", accountsSeen: [{ id: "acct-1", name: "One" }, { id: "acct-2", name: "Two" }] }, "discovery-token-set", async () => (await discoveryStatus()).present === true);
    await doExec("/sources/discovery-accounts", { selected: ["acct-1"], engineAccountId: "acct-1" }, "discovery-accounts-set", async () => ((await discoveryStatus()).selected ?? []).includes("acct-1"));
    await doExec("/policy/break-glass-retired", { retired: true }, "break-glass-retire", async () => ((await (await call(OWNER, "GET", "/admin/status")).json()) as { breakGlassTokenRetired?: boolean }).breakGlassTokenRetired === true);

    // A DO-executed lifecycle threaded with a source IP on BOTH the propose and the approve, so the
    // owner-action-propose + owner-action-approve audit events carry the IP (recordOwnerAction +
    // approveOwnerAction sourceIp attribution).
    {
      const p = await doFetch("/destinations", ocIp(OWNER, "198.51.100.11"), { label: "ip-dest", config: destConfig("ip-bucket") });
      ok("[ip] a propose with a source IP is queued (202)", p.status === 202);
      const id = ((await p.json()) as { id?: string }).id ?? "";
      const ap = await doFetch("/owner-actions/approve", ocIp(OWNER2, "198.51.100.12"), { id });
      ok("[ip] a distinct owner approves the IP-stamped action (200, executed)", ap.status === 200 && ((await ap.json()) as PendingOwnerAction).status === "executed");
      ok("[ip] the IP-stamped destination was added", (await listDestinations()).destinations.some((d) => d.label === "ip-dest"));
    }

    // ===========================================================================================
    // SECTION B: the ROUTER-EXECUTED flow end to end (gate-check -> arm -> single-use consume) + its refusals,
    // threaded with source IPs (record / arm-approve / consume audit attribution).
    // ===========================================================================================
    const UA = { toVersion: "9.9.9", sha384: "sha384:deadbeef" };
    const hashUA = await hashFor("update-apply", UA, OWNER);
    {
      const before = ownerActionKeyCount();
      const gc = await doFetch("/owner-actions/gate-check", ocIp(OWNER, "198.51.100.21"), { kind: "update-apply", params: UA, summary: "promote 9.9.9" });
      const gcb = (await gc.json()) as { gate: string; id: string };
      ok("[router] gate-check by one owner records a PENDING approval", gc.status === 200 && gcb.gate === "pending" && ownerActionKeyCount() === before + 1);
      const id = gcb.id;
      const early = await doFetch("/owner-actions/consume", ownerCaller(OWNER), { id, expectedActionHash: hashUA });
      ok("[router] consuming BEFORE approval is refused (not approved)", early.status === 400 && /not approved/.test(await errOf(early)));
      const self = await doFetch("/owner-actions/approve", ownerCaller(OWNER), { id });
      ok("[router] the proposer cannot approve their own router-executed action (400)", self.status === 400);
      const ap = await doFetch("/owner-actions/approve", ocIp(OWNER2, "198.51.100.22"), { id });
      const apb = (await ap.json()) as PendingOwnerAction;
      ok("[router] a distinct owner ARMS it (status approved, NOT executed)", ap.status === 200 && apb.status === "approved" && apb.approvedBy === OWNER2);
      const gc2 = await doFetch("/owner-actions/gate-check", ownerCaller(OWNER), { kind: "update-apply", params: UA, summary: "promote 9.9.9" });
      ok("[router] gate-check now reports the SAME action ARMED (the re-submit path)", gc2.status === 200 && ((await gc2.json()) as { gate: string }).gate === "armed");
      const mismatch = await doFetch("/owner-actions/consume", ownerCaller(OWNER), { id, expectedActionHash: "sha384:not-the-real-hash" });
      ok("[router] a consume with a MISMATCHED hash is refused (re-arm-on-change)", mismatch.status === 400 && /does not match/.test(await errOf(mismatch)));
      const noHash = await doFetch("/owner-actions/consume", ownerCaller(OWNER), { id });
      ok("[router] a consume with NO expected hash is refused", noHash.status === 400 && /does not match/.test(await errOf(noHash)));
      const c1 = await doFetch("/owner-actions/consume", ocIp(OWNER, "198.51.100.23"), { id, expectedActionHash: hashUA });
      ok("[router] consuming the armed approval succeeds exactly once (ok:true)", c1.status === 200 && ((await c1.json()) as { ok?: boolean }).ok === true);
      const c2 = await doFetch("/owner-actions/consume", ownerCaller(OWNER), { id, expectedActionHash: hashUA });
      ok("[router] a SECOND consume of the same approval is refused (single use, already used)", c2.status === 400 && /already used/.test(await errOf(c2)));
    }
    // sources-attach: a second router-executed kind through gate-check -> approve -> consume (lighter pass).
    {
      const SA = { sources: [{ type: "kv", binding: "KV_X", namespaceId: "ns1" }], remove: [] };
      const gc = await doFetch("/owner-actions/gate-check", ownerCaller(OWNER), { kind: "sources-attach", params: SA, summary: "attach kv" });
      const id = ((await gc.json()) as { id: string }).id;
      await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id });
      const c = await doFetch("/owner-actions/consume", ownerCaller(OWNER), { id, expectedActionHash: await hashFor("sources-attach", SA, OWNER) });
      ok("[router] sources-attach: arm + consume succeeds", c.status === 200 && ((await c.json()) as { ok?: boolean }).ok === true);
    }

    // ===========================================================================================
    // SECTION C: consume refusals that gate BEFORE the armed check.
    // ===========================================================================================
    {
      const noOwner = await doFetch("/owner-actions/consume", operatorCaller, { id: "anything", expectedActionHash: "x" });
      ok("[consume] a non-owner is refused (403, defence in depth over the router)", noOwner.status === 403);
      const noId = await doFetch("/owner-actions/consume", ownerCaller(OWNER), { id: 123, expectedActionHash: "x" });
      ok("[consume] a non-string id is refused (id required)", noId.status === 400 && /id required/.test(await errOf(noId)));
      const noRec = await doFetch("/owner-actions/consume", ownerCaller(OWNER), { id: "no-such-consume", expectedActionHash: "x" });
      ok("[consume] an unknown id is refused (no such owner action)", noRec.status === 400 && /no such owner action/.test(await errOf(noRec)));
      // A DO-executed (non-router) pending record cannot be consumed: it does not use the token-resubmit flow.
      const p = await doFetch("/destinations", ownerCaller(OWNER), { label: "consume-doexec", config: destConfig("ce-bucket") });
      const doExecId = ((await p.json()) as { id: string }).id;
      const wrongFlow = await doFetch("/owner-actions/consume", ownerCaller(OWNER), { id: doExecId, expectedActionHash: "x" });
      ok("[consume] a DO-executed record cannot be consumed (token-resubmit flow only)", wrongFlow.status === 400 && /does not use the token-resubmit flow/.test(await errOf(wrongFlow)));
      await doFetch("/owner-actions/reject", ownerCaller(OWNER2), { id: doExecId }); // tidy up
    }

    // ===========================================================================================
    // SECTION D: checkOwnerActionGate kind/role/maker refusals (gate ON).
    // ===========================================================================================
    {
      const bogus = await doFetch("/owner-actions/gate-check", ownerCaller(OWNER), { kind: "not-a-kind", params: {} });
      ok("[gate-check] an unknown kind is refused", bogus.status === 400 && /unknown owner action kind/.test(await errOf(bogus)));
      const nonRouter = await doFetch("/owner-actions/gate-check", ownerCaller(OWNER), { kind: "dest-put", params: {} });
      ok("[gate-check] a DO-executed kind is refused (not router-executed)", nonRouter.status === 400 && /not router-executed/.test(await errOf(nonRouter)));
      const nonOwner = await doFetch("/owner-actions/gate-check", operatorCaller, { kind: "update-apply", params: UA });
      ok("[gate-check] a non-owner is refused (403)", nonOwner.status === 403);
      const tokenGc = await doFetch("/owner-actions/gate-check", tokenCaller, { kind: "update-apply", params: UA });
      ok("[gate-check] the bare-token break-glass cannot be the maker (attributable identity required)", tokenGc.status === 400 && /attributable identity/.test(await errOf(tokenGc)));
      const nullGc = await doFetch("/owner-actions/gate-check", null, { kind: "update-apply", params: UA, summary: "x" });
      ok("[gate-check] a caller-less gate-check is refused at the owner gate (403)", nullGc.status === 403);
      // A gate-check with NO summary records a pending approval whose summary defaults to empty.
      const noSumGc = await doFetch("/owner-actions/gate-check", ownerCaller(OWNER), { kind: "update-settle", params: { v: "no-summary" } });
      const noSumBody = (await noSumGc.json()) as { gate: string; id: string };
      ok("[gate-check] an absent summary records a pending approval with an empty summary", noSumGc.status === 200 && noSumBody.gate === "pending" && sched.storage.rawGet<PendingOwnerAction>(ownerActionKey(noSumBody.id))!.summary === "");
    }

    // ===========================================================================================
    // SECTION E: the attributable-maker refusal at the two record sites + the null-caller gatedOwnerAction path.
    // ===========================================================================================
    {
      const tokenPropose = await doFetch("/destinations", tokenCaller, { label: "bg", config: destConfig("bg-bucket") });
      ok("[record] gate ON: a bare-token caller cannot propose a DO-executed owner action", tokenPropose.status === 400 && /attributable identity/.test(await errOf(tokenPropose)));
      const noCaller = await doFetch("/destinations/default", null, { id: "x" });
      ok("[record] gate ON: a caller-less gated op is refused (no attributable maker)", noCaller.status === 400 && /attributable identity/.test(await errOf(noCaller)));
    }

    // ===========================================================================================
    // SECTION F: approveOwnerAction + rejectOwnerAction edges.
    // ===========================================================================================
    {
      const apNoId = await doFetch("/owner-actions/approve", ownerCaller(OWNER), { id: 123 });
      ok("[approve] a non-string id is refused (id required)", apNoId.status === 400 && /id required/.test(await errOf(apNoId)));
      const apNoRec = await doFetch("/owner-actions/approve", ownerCaller(OWNER), { id: "no-such-approve" });
      ok("[approve] an unknown id is refused (no such owner action)", apNoRec.status === 400 && /no such owner action/.test(await errOf(apNoRec)));
      // A non-owner approve is refused at the owner gate (not the maker != checker rule).
      const p = await doFetch("/destinations", ownerCaller(OWNER), { label: "approve-edge", config: destConfig("ae-bucket") });
      const pid = ((await p.json()) as { id: string }).id;
      const opApprove = await doFetch("/owner-actions/approve", operatorCaller, { id: pid });
      ok("[approve] a non-owner cannot approve (only an Owner)", opApprove.status === 400 && /only an Owner/.test(await errOf(opApprove)));
      const nullApprove = await doFetch("/owner-actions/approve", null, { id: pid });
      ok("[approve] a caller-less approve fails closed (attributable identity required)", nullApprove.status === 400 && /attributable identity/.test(await errOf(nullApprove)));

      // reject edges, reusing the still-pending record above.
      const rjNoId = await doFetch("/owner-actions/reject", ownerCaller(OWNER), { id: 123 });
      ok("[reject] a non-string id is refused (id required)", rjNoId.status === 400 && /id required/.test(await errOf(rjNoId)));
      const rjNoRec = await doFetch("/owner-actions/reject", ownerCaller(OWNER), { id: "no-such-reject" });
      ok("[reject] an unknown id is refused (no such owner action)", rjNoRec.status === 400 && /no such owner action/.test(await errOf(rjNoRec)));
      const opReject = await doFetch("/owner-actions/reject", operatorCaller, { id: pid });
      ok("[reject] a non-owner cannot reject (403)", opReject.status === 403);
      const rjHappy = await doFetch("/owner-actions/reject", ocIp(OWNER2, "198.51.100.31"), { id: pid });
      ok("[reject] an owner rejects a pending action (200, status rejected, IP attributed)", rjHappy.status === 200 && ((await rjHappy.json()) as PendingOwnerAction).status === "rejected");
      const rjAgain = await doFetch("/owner-actions/reject", ownerCaller(OWNER), { id: pid });
      ok("[reject] re-rejecting a terminal record is refused (already rejected)", rjAgain.status === 400 && /already rejected/.test(await errOf(rjAgain)));
      // rejecting an already-EXECUTED record is refused too (canRejectOwnerAction terminal guard).
      const rjExecuted = await doFetch("/owner-actions/reject", ownerCaller(OWNER), { id: execDestSetId });
      ok("[reject] rejecting an executed record is refused (already carried out)", rjExecuted.status === 400 && /already carried out/.test(await errOf(rjExecuted)));
      // a record carrying an unknown kind is refused by BOTH the approve integrity recompute and the reject guard.
      const badKind = await putCrafted({ kind: "totally-unknown", params: {}, status: "pending" });
      const apBadKind = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: badKind.id });
      ok("[approve] an unknown-kind record fails the integrity kind guard", apBadKind.status === 400 && /unknown kind and cannot be carried out/.test(await errOf(apBadKind)));
      const rjBadKind = await doFetch("/owner-actions/reject", ownerCaller(OWNER), { id: badKind.id });
      ok("[reject] a record with an unknown kind is refused (unknown kind guard)", rjBadKind.status === 400 && /unknown kind/.test(await errOf(rjBadKind)));
    }

    // ===========================================================================================
    // SECTION G: crafted at-rest records exercise the defensive integrity / replay / consume-status branches.
    // ===========================================================================================
    {
      // (A) a record whose kind is router-executed but stored with routerExecuted:false reaches the DO-executed
      //     dispatch, which fails closed (a router-executed kind must never run in the DO).
      const a = await putCrafted({ kind: "update-apply", params: UA, status: "pending", routerExecuted: false });
      const apA = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: a.id });
      ok("[craft-A] a router-executed kind reaching the DO dispatch fails closed", apA.status === 400 && /router-executed and must not run in the DO/.test(await errOf(apA)));

      // (B) a record with a NULL proposer subject + a non-array groups field: the integrity recompute + the
      //     proposer replay normalise both (null subject, [] groups). The replay re-resolves to a NON-owner
      //     (no stable subject), so the execute is refused live (the proposer-ceiling re-check).
      const b = await putCrafted({ kind: "dest-default", params: { id: "no-such-dest" }, status: "pending", proposedBySubject: null, proposedByGroups: undefined });
      const apB = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: b.id });
      ok("[craft-B] a subjectless proposer is re-resolved live to a non-owner at execute (403)", apB.status === 403);

      // (C) consuming a REJECTED router-executed record gives the precise reason.
      const c = await putCrafted({ kind: "sources-attach", params: { x: 1 }, status: "rejected", routerExecuted: true });
      const cnC = await doFetch("/owner-actions/consume", ownerCaller(OWNER), { id: c.id, expectedActionHash: c.actionHash });
      ok("[craft-C] consuming a rejected record reports it was rejected", cnC.status === 400 && /was rejected/.test(await errOf(cnC)));

      // (D) consuming an APPROVED-but-EXPIRED record falls to the generic expired refusal.
      const d = await putCrafted({ kind: "sources-attach", params: { x: 2 }, status: "approved", routerExecuted: true, approverSubject: subjectOf(OWNER2), approvedBy: OWNER2, expiresAtMs: Date.now() - 1000 });
      const cnD = await doFetch("/owner-actions/consume", ownerCaller(OWNER), { id: d.id, expectedActionHash: d.actionHash });
      ok("[craft-D] consuming an expired armed record is refused (expired)", cnD.status === 400 && /expired/.test(await errOf(cnD)));

      // (E) an armed record with a checker SUBJECT but no display approvedBy still consumes (single use) and
      //     omits the approverEmail target field.
      const e = await putCrafted({ kind: "sources-attach", params: { x: 3 }, status: "approved", routerExecuted: true, approverSubject: subjectOf(OWNER2) });
      const cnE = await doFetch("/owner-actions/consume", ownerCaller(OWNER), { id: e.id, expectedActionHash: e.actionHash });
      ok("[craft-E] an armed record (subject only, no display email) consumes once", cnE.status === 200 && ((await cnE.json()) as { ok?: boolean }).ok === true);

      // (F) a tampered record (params changed, action hash now stale) is refused at approve by the integrity recompute.
      const p = await doFetch("/destinations", ownerCaller(OWNER), { label: "tamper", config: destConfig("tamper-bucket") });
      const tid = ((await p.json()) as { id: string }).id;
      const rec = sched.storage.rawGet<PendingOwnerAction>(ownerActionKey(tid))!;
      (rec.params as { label?: string }).label = "tampered";
      sched.storage.rawPut(ownerActionKey(tid), rec);
      const apF = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: tid });
      ok("[craft-F] a tampered record fails its integrity check at approve", apF.status === 400 && /integrity check/.test(await errOf(apF)));
      await sched.storage.delete(ownerActionKey(tid));

      // (G/H) the empty-id coercion in the DO dispatch: a dest-remove / dest-default whose stored params.id is
      //       NOT a string coerces to "" and the executed method then refuses (no such destination).
      const gRem = await putCrafted({ kind: "dest-remove", params: { id: 123, force: true }, status: "pending" });
      const apGRem = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: gRem.id });
      ok("[craft-G] a dest-remove with a non-string id coerces to empty and is refused", apGRem.status === 400 && /no such destination/.test(await errOf(apGRem)));
      const gDef = await putCrafted({ kind: "dest-default", params: { id: 123 }, status: "pending" });
      const apGDef = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: gDef.id });
      ok("[craft-H] a dest-default with a non-string id coerces to empty and is refused", apGDef.status === 400 && /no such destination/.test(await errOf(apGDef)));

      // (I) a bare-token owner consumes an armed approval (the consume audit attributes a null maker email).
      const tokArmed = await putCrafted({ kind: "sources-attach", params: { x: 7 }, status: "approved", routerExecuted: true, approverSubject: subjectOf(OWNER2), approvedBy: OWNER2 });
      const tokConsume = await doFetch("/owner-actions/consume", tokenCaller, { id: tokArmed.id, expectedActionHash: tokArmed.actionHash });
      ok("[craft-I] a bare-token owner consumes an armed approval once", tokConsume.status === 200 && ((await tokConsume.json()) as { ok?: boolean }).ok === true);

      // (J) a bare-token owner rejects a pending action (the reject audit attributes a null maker email).
      const tokPending = await putCrafted({ kind: "dest-put", params: { label: "tok-rej" }, status: "pending" });
      const tokReject = await doFetch("/owner-actions/reject", tokenCaller, { id: tokPending.id });
      ok("[craft-J] a bare-token owner rejects a pending action", tokReject.status === 200 && ((await tokReject.json()) as PendingOwnerAction).status === "rejected");
    }

    // ===========================================================================================
    // SECTION H: listPendingOwnerActions, the inbox projection + visibility + ordering.
    // ===========================================================================================
    {
      // Two pending records with KNOWN, distinct propose times prove the descending-by-proposedAt sort.
      const older = await putCrafted({ kind: "dest-put", params: { label: "older" }, status: "pending", proposedAt: "2020-01-01T00:00:00.000Z" });
      const newer = await putCrafted({ kind: "dest-put", params: { label: "newer" }, status: "pending", proposedAt: "2021-01-01T00:00:00.000Z" });
      const ownerInbox = (await (await doGet("/owner-actions", ownerCaller(OWNER))).json()) as PendingOwnerAction[];
      ok("[inbox] an owner sees the pending actions", Array.isArray(ownerInbox) && ownerInbox.some((a) => a.id === older.id) && ownerInbox.some((a) => a.id === newer.id));
      ok("[inbox] the inbox is sorted newest-first (proposedAt descending)", ownerInbox.findIndex((a) => a.id === newer.id) < ownerInbox.findIndex((a) => a.id === older.id));
      const opInbox = (await (await doGet("/owner-actions", operatorCaller)).json()) as PendingOwnerAction[];
      ok("[inbox] a non-owner (not the proposer) sees none of these owner-class actions", Array.isArray(opInbox) && !opInbox.some((a) => a.id === newer.id));
      const anonInbox = (await (await doGet("/owner-actions", null)).json()) as PendingOwnerAction[];
      ok("[inbox] a caller-less read resolves to viewer and sees nothing", Array.isArray(anonInbox) && anonInbox.length === 0);
    }

    // ===========================================================================================
    // SECTION I: dual-control-disable (the gate's own asymmetric off switch) + the gate-OFF gate-check.
    // ===========================================================================================
    {
      // setGate(.., false) when ON proposes a dual-control-disable and a DISTINCT owner approves it, flipping
      // the gate OFF (DO-executed approve -> executeOwnerActionDO 'dual-control-disable' -> setRequireConfigApproval).
      const disarmed = await setGate(OWNER, false);
      ok("[disarm] a second owner approving the dual-control-disable flips the gate OFF (200)", disarmed.status === 200);
      const policy = (await (await call(OWNER, "GET", "/admin/config/approval-policy")).json()) as { requireConfigApproval: boolean };
      ok("[disarm] the gate now reads OFF", policy.requireConfigApproval === false);
      // With the gate OFF, a non-high-blast DO-executed op runs INLINE through gatedOwnerAction (the
      // byte-identical pre-gate path): no pending action is queued and the change takes effect immediately.
      const inlineTarget = (await listDestinations()).destinations.find((d) => d.label === "ip-dest") ?? (await listDestinations()).destinations[0]!;
      const inlineBefore = ownerActionKeyCount();
      const inline = await doFetch("/destinations/default", ownerCaller(OWNER), { id: inlineTarget.id });
      ok("[disarm] gate OFF: a non-high-blast op runs inline (200, nothing queued)", inline.status === 200 && ownerActionKeyCount() === inlineBefore);
      ok("[disarm] the inline dest-default took effect immediately", (await listDestinations()).defaultId === inlineTarget.id);
      // With the gate OFF a router-executed gate-check returns 'off' (the router runs the op inline).
      const gcOff = await doFetch("/owner-actions/gate-check", ownerCaller(OWNER), { kind: "update-apply", params: UA, summary: "off-path" });
      ok("[disarm] gate-check returns off with the gate off", gcOff.status === 200 && ((await gcOff.json()) as { gate: string }).gate === "off");
    }

    // ===========================================================================================
    // SECTION J: the audit attribution, every owner-action event class is recorded with its source IP.
    // ===========================================================================================
    {
      const proposeLog = JSON.stringify((await readLog("action=owner-action-propose")).events);
      ok("[audit] propose events carry the proposer source IPs", proposeLog.includes("198.51.100.11") && proposeLog.includes("198.51.100.21"));
      const approveLog = JSON.stringify((await readLog("action=owner-action-approve")).events);
      ok("[audit] approve events carry the checker source IPs (DO-executed + router-arm)", approveLog.includes("198.51.100.12") && approveLog.includes("198.51.100.22"));
      const executeLog = JSON.stringify((await readLog("action=owner-action-execute")).events);
      ok("[audit] a consume execute event carries the re-submitter source IP", executeLog.includes("198.51.100.23"));
      const rejectLog = JSON.stringify((await readLog("action=owner-action-reject")).events);
      ok("[audit] a reject event carries the rejecter source IP", rejectLog.includes("198.51.100.31"));
      const verify = (await (await call(OWNER, "GET", "/admin/audit/verify")).json()) as { intact: boolean };
      ok("[audit] the tamper-evident chain still verifies intact after the whole flow", verify.intact === true);
    }
  } finally {
    globalThis.fetch = ctx.realFetch;
  }

  console.log(failures === 0 ? "\nVECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
