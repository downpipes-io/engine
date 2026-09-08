// PROOF 4 + PROOF 7 + PROOF 8 + PROOF 9 + PROOF 10 + PROOF 11 of the OWNER-ACTION DUAL CONTROL suite, split
// out of validate-owner-action-dualcontrol.ts (behaviour-preserving). These cover secret redaction in the
// summary/audit/listing, the break-glass propose/approve refusal, the non-owner approve refusal at the DO, the
// tampered-record integrity refusal, the gate-off regression, and the audit-chain verification.

import { ok, makeScheduler, handleAdmin } from "./validate-owner-action-dualcontrol-harness.ts";
import type { Ctx } from "./validate-owner-action-dualcontrol-harness.ts";
import { type Caller } from "../src/admin/identity.ts";
import { verifyChain } from "../src/admin/audit.ts";
import { type PendingOwnerAction, ownerActionKey } from "../src/admin/owner-action.ts";
import type { Env } from "../src/env.d.ts";

export async function run(ctx: Ctx): Promise<void> {
  const { sched, OWNER, OWNER2, OPERATOR, subjectOf, call, readLog, setGate, doFetch, ownerCaller, ownerActionKeyCount, destConfig, oidcProposal, listDestinations, inbox, applyOwnerOp } = ctx;

  // ===========================================================================================
  // PROOF 4: the SUMMARY + audit target carry NO secret (the dest secret key never leaks)
  // ===========================================================================================
  {
    // Queue a destination set whose config carries a recognisable secret; the inbox summary + the audit must
    // NEVER contain it (it lives only in the replay params, like the config-change webhook url).
    const SECRET = "DO-NOT-LOG-secret-access-key-XYZ";
    const cfg = { ...destConfig("redact-bucket"), secretAccessKey: SECRET };
    const r = await doFetch("/dest-config", ownerCaller(OWNER), { config: cfg });
    ok("a gated dest-set is queued (202)", r.status === 202);
    const pid = ((await r.json()) as { id: string }).id;
    const rec = (await inbox(OWNER)).find((a) => a.id === pid)!;
    ok("the inbox summary names the host/bucket but NOT the secret", /redact-bucket/.test(rec.summary) && !rec.summary.includes(SECRET));
    const logText = JSON.stringify(await readLog("action=owner-action-propose"));
    ok("the owner-action-propose audit carries NO secret (closed owneraction target)", !logText.includes(SECRET));
    // The inbox LISTING must also omit the secret from params (the redaction docstrings + the IdP
    // secret's write-only contract). The full params remain on the AT-REST record for byte-faithful replay,
    // but the read path strips the known secret fields (config.secretAccessKey / top-level secret / token).
    const listRec = (await inbox(OWNER)).find((a) => a.id === pid)!;
    ok("[redact] the LISTING params carry NO dest secret access key (dest-set)", !JSON.stringify(listRec.params).includes(SECRET));
    ok("[redact] the LISTING params still carry the non-secret bucket (dest-set)", JSON.stringify(listRec.params).includes("redact-bucket"));
    // Prove the AT-REST record STILL carries the secret (so the approved replay is byte-faithful) — read it
    // raw from storage, bypassing the listing projection.
    const atRest = sched.storage.rawGet<PendingOwnerAction>(ownerActionKey(pid))!;
    ok("[redact] the AT-REST record KEEPS the secret for replay (not the listing)", JSON.stringify(atRest.params).includes(SECRET));
    // Reject it to clean up (an owner may reject a pending action).
    await doFetch("/owner-actions/reject", ownerCaller(OWNER2), { id: pid });

    // dest-put: same redaction (the secret is nested under config).
    {
      const r2 = await doFetch("/destinations", ownerCaller(OWNER), { label: "redact-put", config: { ...destConfig("put-bucket"), secretAccessKey: SECRET } });
      const pid2 = ((await r2.json()) as { id: string }).id;
      const lr = (await inbox(OWNER)).find((a) => a.id === pid2)!;
      ok("[redact] the LISTING params carry NO secret (dest-put)", !JSON.stringify(lr.params).includes(SECRET) && JSON.stringify(lr.params).includes("put-bucket"));
      await doFetch("/owner-actions/reject", ownerCaller(OWNER2), { id: pid2 });
    }
    // dest-put with an AssumeRole policy: the externalId (config.assumeRole.externalId) is a live,
    // credential-class value (the STS cross-account confused-deputy guard) nested ONE LEVEL DEEPER than
    // secretAccessKey.
    {
      const EXTERNAL_ID = "DO-NOT-LOG-sts-external-id-CONFUSED-DEPUTY";
      const r5 = await doFetch("/destinations", ownerCaller(OWNER), {
        label: "redact-assumerole",
        config: { ...destConfig("assumerole-bucket"), assumeRole: { roleArn: "arn:aws:iam::123456789012:role/downpipes-write", externalId: EXTERNAL_ID } },
      });
      const pid5 = ((await r5.json()) as { id: string }).id;
      const lr = (await inbox(OWNER)).find((a) => a.id === pid5)!;
      ok("[redact] the LISTING params carry NO AssumeRole externalId (dest-put)", !JSON.stringify(lr.params).includes(EXTERNAL_ID));
      ok("[redact] the LISTING params still carry the non-secret role ARN + bucket (dest-put)", JSON.stringify(lr.params).includes("downpipes-write") && JSON.stringify(lr.params).includes("assumerole-bucket"));
      const atRest5 = sched.storage.rawGet<PendingOwnerAction>(ownerActionKey(pid5))!;
      ok("[redact] the AT-REST record KEEPS the externalId for replay (not the listing)", JSON.stringify(atRest5.params).includes(EXTERNAL_ID));
      // The redaction must not mutate the at-rest record's nested assumeRole object: a second listing read
      // still shows the same redacted view, and the at-rest externalId is still intact for replay.
      const lr2 = (await inbox(OWNER)).find((a) => a.id === pid5)!;
      ok("[redact] a REPEATED listing read still carries NO externalId (no in-place mutation leak)", !JSON.stringify(lr2.params).includes(EXTERNAL_ID));
      const atRest5b = sched.storage.rawGet<PendingOwnerAction>(ownerActionKey(pid5))!;
      ok("[redact] the AT-REST record's externalId SURVIVES a repeated listing read", JSON.stringify(atRest5b.params).includes(EXTERNAL_ID));
      // reject needs no maker != checker check (any Owner may veto a pending proposal), so its RESPONSE BODY
      // is the easiest second read path into the same live externalId the listing redacts. It must not echo
      // the raw at-rest record straight through this.json().
      const rejectResp = await doFetch("/owner-actions/reject", ownerCaller(OWNER2), { id: pid5 });
      const rejected = (await rejectResp.json()) as PendingOwnerAction;
      ok("[redact] the REJECT response carries NO AssumeRole externalId (sibling read path)", rejected.status === "rejected" && !JSON.stringify(rejected.params).includes(EXTERNAL_ID));
    }
    // The APPROVE response is the SAME kind of echo as reject, but via the OTHER dual-control
    // method (approveOwnerAction) for a DISTINCT owner who arms/executes the proposal. Proven independently
    // since approve and reject are two separate DO code paths that both read the raw record from storage.
    {
      const EXTERNAL_ID2 = "DO-NOT-LOG-sts-external-id-APPROVE-PATH";
      const r6 = await doFetch("/destinations", ownerCaller(OWNER), {
        label: "redact-assumerole-approve",
        config: { ...destConfig("assumerole-approve-bucket"), assumeRole: { roleArn: "arn:aws:iam::123456789012:role/downpipes-write", externalId: EXTERNAL_ID2 } },
      });
      const pid6 = ((await r6.json()) as { id: string }).id;
      const approveResp = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: pid6 });
      const approved = (await approveResp.json()) as PendingOwnerAction;
      ok("[redact] the APPROVE response carries NO AssumeRole externalId (sibling read path)", approved.status === "executed" && !JSON.stringify(approved.params).includes(EXTERNAL_ID2));
      ok("[redact] the APPROVE response still carries the non-secret role ARN + bucket", JSON.stringify(approved.params).includes("downpipes-write") && JSON.stringify(approved.params).includes("assumerole-approve-bucket"));
    }
    // discovery-token-set: the read-only API token is a top-level secret param.
    {
      const TOKEN = "cfat_REDACT_discovery_token_value_0987654321";
      const r3 = await doFetch("/sources/discovery-token", ownerCaller(OWNER), { token: TOKEN, accountsSeen: [{ id: "acct-redact", name: "Redact Acct" }] });
      const pid3 = ((await r3.json()) as { id: string }).id;
      const lr = (await inbox(OWNER)).find((a) => a.id === pid3)!;
      ok("[redact] the LISTING params carry NO discovery token (discovery-token-set)", !JSON.stringify(lr.params).includes(TOKEN));
      ok("[redact] the LISTING params still carry the non-secret account id (discovery-token-set)", JSON.stringify(lr.params).includes("acct-redact"));
      await doFetch("/owner-actions/reject", ownerCaller(OWNER2), { id: pid3 });
    }
    // idp-conn-create: the client secret is a top-level secret param.
    {
      const ISECRET = "REDACT-idp-client-secret-ABC";
      const proposal = oidcProposal("redact-oidc");
      const r4 = await doFetch("/idp/conn/create", ownerCaller(OWNER), { ...proposal, secret: ISECRET });
      const pid4 = ((await r4.json()) as { id: string }).id;
      const lr = (await inbox(OWNER)).find((a) => a.id === pid4)!;
      ok("[redact] the LISTING params carry NO IdP client secret (idp-conn-create)", !JSON.stringify(lr.params).includes(ISECRET));
      ok("[redact] the LISTING params still carry the non-secret connection id (idp-conn-create)", JSON.stringify(lr.params).includes("redact-oidc"));
      const atRest4 = sched.storage.rawGet<PendingOwnerAction>(ownerActionKey(pid4))!;
      ok("[redact] the AT-REST idp-conn-create record KEEPS the client secret for replay", JSON.stringify(atRest4.params).includes(ISECRET));
      await doFetch("/owner-actions/reject", ownerCaller(OWNER2), { id: pid4 });
    }
  }

  // ===========================================================================================
  // PROOF 7: BREAK-GLASS (bare token) cannot PROPOSE or APPROVE an owner action (needs an attributable id),
  //          but CAN toggle the gate (owner, no deadlock); the toggle is attributed.
  // ===========================================================================================
  {
    const tsched = makeScheduler();
    const tokenEnv = ({ ...tsched.env, ADMIN_TOKEN: "shared-break-glass-token" }) as unknown as Env;
    async function tcall(method: "GET" | "POST", path: string, body?: unknown): Promise<Response> {
      const init: RequestInit = { method, headers: { authorization: "Bearer shared-break-glass-token", ...(body !== undefined ? { "content-type": "application/json" } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) };
      return handleAdmin(new Request(`https://engine.example${path}`, init), tokenEnv);
    }
    // The bare-token owner turns the gate ON (always available to break-glass, no deadlock).
    const tokenOn = await tcall("POST", "/admin/config/approval-policy", { requireConfigApproval: true });
    ok("the bare-token break-glass CAN toggle the dual-control gate (owner, no deadlock)", tokenOn.status === 200);
    // Now a gated owner op from the bare token is refused (no attributable maker for dual control), NOT a 403.
    const tokenDest = await tcall("POST", "/admin/destinations", { label: "x", config: { endpoint: "https://acct.r2.cloudflarestorage.com", bucket: "b", region: "auto", accessKeyId: "AK", secretAccessKey: "sk" } });
    ok("the bare-token fallback cannot propose a gated owner action (4xx, needs an attributable maker)", tokenDest.status >= 400);
    ok("the bare-token refusal is not a role 403 (it is owner; the bar is attributability)", tokenDest.status !== 403);
    // Drive the DO directly with NO caller header: approve/consume/gate-check fail closed (no attributable id).
    const noCallerApprove = await tsched.stub.fetch("https://scheduler.internal/owner-actions/approve", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ id: "anything" }) });
    ok("a DO approve with no caller header fails closed (400)", noCallerApprove.status === 400);
  }

  // ===========================================================================================
  // PROOF 8: a NON-OWNER cannot approve a gated owner action even at the DO (every gated op is owner-class)
  // ===========================================================================================
  {
    // Queue a dest-put as OWNER (gate is ON from PROOF 2 on the main sched).
    const r = await doFetch("/destinations", ownerCaller(OWNER), { label: "nonowner-test", config: destConfig("nonowner-bucket") });
    const pid = ((await r.json()) as { id: string }).id;
    // The OPERATOR (non-owner) tries to approve at the DO -> refused (not the maker != checker rule; the owner
    // bar). The DO re-resolves the operator's role from its own tables.
    const opApprove = await doFetch("/owner-actions/approve", ownerCaller(OPERATOR) /* email operator, but DO re-resolves role */ , { id: pid });
    // ownerCaller asserts role "owner" in the header, but the DO RE-RESOLVES from its tables (operator), so
    // the asserted role is ignored and the owner re-check refuses it.
    const opCallerReal: Caller = { method: "access", email: OPERATOR, subject: subjectOf(OPERATOR), role: "operator", groups: [] };
    const opApproveReal = await doFetch("/owner-actions/approve", opCallerReal, { id: pid });
    ok("a non-owner cannot approve a gated owner action at the DO (4xx)", opApproveReal.status === 400 && /only an Owner/.test(((await opApproveReal.json()) as { error?: string }).error ?? ""));
    void opApprove;
    ok("the non-owner approve attempt did NOT execute the op", !(await listDestinations()).destinations.some((d) => d.label === "nonowner-test"));
    // A distinct owner can still approve it (proving the rule is owner + maker != checker, not "no one").
    const okApprove = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: pid });
    ok("a distinct owner approves the same action (executes)", okApprove.status === 200 && (await listDestinations()).destinations.some((d) => d.label === "nonowner-test"));
  }

  // ===========================================================================================
  // PROOF 9: a TAMPERED pending record (params changed, actionHash stale) is refused at approve (integrity)
  // ===========================================================================================
  {
    const r = await doFetch("/destinations", ownerCaller(OWNER), { label: "tamper-test", config: destConfig("tamper-bucket") });
    const pid = ((await r.json()) as { id: string }).id;
    const rec = sched.storage.rawGet<PendingOwnerAction>(ownerActionKey(pid))!;
    (rec.params as { label?: string }).label = "tampered-label"; // mutate params, leave actionHash stale
    sched.storage.rawPut(ownerActionKey(pid), rec);
    const approve = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: pid });
    ok("a tampered (hash-mismatched) owner action is refused at approve (4xx)", approve.status === 400 && /integrity/.test(((await approve.json()) as { error?: string }).error ?? ""));
    ok("the tampered action did NOT execute", !(await listDestinations()).destinations.some((d) => d.label === "tampered-label" || d.label === "tamper-test"));
    await sched.storage.delete(ownerActionKey(pid));
  }

  // ===========================================================================================
  // PROOF 10: GATE OFF again — a NON-high-blast DO-executed op runs inline (no regression after the ON
  // proofs). NB: a HIGH-BLAST op (dest add/remove, IdP change) is auto-gated here because two owners exist
  // (S1b), so this regression proof uses dest-default, which is NOT in the high-blast auto-apply set and so
  // genuinely applies inline with the toggle off. The auto-apply is scoped: it never gates the low-blast kinds.
  // ===========================================================================================
  {
    await setGate(OWNER, false);
    // Ensure two destinations exist so a non-default repoint is a genuine change (seed via the dual-control
    // flow; their adds are auto-gated). Then repoint the default away from whatever it currently is.
    for (const label of ["p10-a", "p10-b"]) {
      if (!(await listDestinations()).destinations.some((d) => d.label === label)) {
        await applyOwnerOp("/destinations", { label, config: destConfig(`${label}-bucket`) });
      }
    }
    const dests = (await listDestinations()).destinations;
    const currentDefault = (await listDestinations()).defaultId;
    const target = dests.find((d) => d.label === "p10-a" && d.id !== currentDefault) ?? dests.find((d) => d.label === "p10-b")!;
    const before = ownerActionKeyCount();
    const r = await doFetch("/destinations/default", ownerCaller(OWNER), { id: target.id });
    ok("with the gate OFF a non-high-blast op (dest-default) applies inline again (200)", r.status === 200);
    ok("the gate-off dest-default executed inline (the default repointed)", (await listDestinations()).defaultId === target.id);
    ok("the gate-off dest-default queued NOTHING", ownerActionKeyCount() === before);
    // A router-executed op's gate-check returns "off" so the router runs it inline (router-executed kinds are
    // not in the high-blast auto-apply set, so the toggle alone governs them).
    const gc = await doFetch("/owner-actions/gate-check", ownerCaller(OWNER), { kind: "sources-attach", params: { sources: [], remove: ["KV_X"] }, summary: "detach" });
    ok("a router-executed gate-check returns off with the gate off", gc.status === 200 && ((await gc.json()) as { gate: string }).gate === "off");
    await setGate(OWNER, true); // restore for the audit proof
  }

  // ===========================================================================================
  // PROOF 11: the audit chain VERIFIES over all the owner-action events, with BOTH actors attributed
  // ===========================================================================================
  {
    const verify = (await (await call(OWNER, "GET", "/admin/audit/verify")).json()) as { intact: boolean };
    ok("the chain verifies intact after the owner-action flow", verify.intact === true);
    const log = await readLog();
    const ascending = [...log.events].reverse();
    const independent = await verifyChain(ascending);
    ok("an independent re-verification agrees the chain is intact", independent.intact === true);
    const actions = new Set(log.events.map((e) => e.action));
    ok("owner-action-propose events are in the chain", actions.has("owner-action-propose"));
    ok("owner-action-approve events are in the chain", actions.has("owner-action-approve"));
    ok("owner-action-execute events are in the chain", actions.has("owner-action-execute"));
    ok("owner-action-reject events are in the chain", actions.has("owner-action-reject"));
    // A DO-executed approve attributes the checker; the paired execute attributes the maker (re-resolved).
    const approveEvt = (await readLog("action=owner-action-approve")).events[0];
    const executeEvt = (await readLog("action=owner-action-execute")).events[0];
    ok("an owner-action-approve attributes a checker email", typeof approveEvt?.actorEmail === "string" && approveEvt.actorEmail.length > 0);
    ok("an owner-action-execute exists with an actor", executeEvt !== undefined && executeEvt.actorEmail !== undefined);
  }
}
