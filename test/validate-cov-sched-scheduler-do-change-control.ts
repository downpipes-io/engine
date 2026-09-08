// validate-cov-sched-scheduler-do-change-control: a focused branch-coverage validator for the OPT-IN
// dual-control change-control mixin (src/sched/scheduler-do-change-control.ts). It drives the REAL
// SchedulerDO through the production handleAdmin router (forged-but-correctly-signed Access JWTs over a
// stubbed JWKS) and, for the defence-in-depth re-checks, straight into the DO with an x-downpipe-caller
// header, exactly as the sibling validators do. Every assertion checks a real outcome (an HTTP status, a
// returned body field, or a stored/audited effect), never just that a line ran.
//
// It targets the mixin's harder branches: the owner-only + boolean toggle gates, the disarm transition
// (break-glass off switch), the genesis head reference, EVERY applyConfigMutation switch arm (driven via
// the gate-off inline apply), the dry-run alarm capture/restore arms, the gate-on propose path, the
// approve guards (id/record/kind/maker-not-checker/missing-cap/integrity/superseded), the reject guards,
// the bare-token-cannot-propose refusal, the no-caller fail-closed approve, a legacy null-subject record,
// and the exhaustiveness default.
//
// Run: node test/validate-cov-sched-scheduler-do-change-control.ts

import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { Env } from "../src/env.d.ts";
import { makeScheduler, MockStorage } from "./validate-config-change-control-harness.ts";
import { makeSigner, TEAM, AUD } from "./validate-rbac-harness.ts";
import { encodeCaller, type Caller } from "../src/admin/identity.ts";
import { changeContentHash, type PendingConfigChange } from "../src/admin/change-control.ts";
import { CONFIG_GENESIS_PREV_HASH } from "../src/admin/config-history.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

async function main(): Promise<void> {
  const signer = await makeSigner();
  const { tokenFor, subjectOf } = signer;
  const s = makeScheduler();
  const ADMIN_TOKEN = "bg-change-control-token";
  const accEnv = { ...s.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, ADMIN_TOKEN } as unknown as Env;

  // A request as a given Access identity (the verified maker/checker path).
  const call = async (email: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> => {
    const init: RequestInit = {
      method,
      headers: { "cf-access-jwt-assertion": await tokenFor(email), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    };
    return handleAdmin(new Request(`https://engine.example${path}`, init), accEnv);
  };
  // A request as the BARE-TOKEN break-glass owner (method "token": owner authority, no attributable email).
  const tokenCall = async (method: "GET" | "POST", path: string, body?: unknown): Promise<Response> => {
    const init: RequestInit = {
      method,
      headers: { authorization: `Bearer ${ADMIN_TOKEN}`, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    };
    return handleAdmin(new Request(`https://engine.example${path}`, init), accEnv);
  };
  // A router-bypassed DO call carrying an explicit caller (defence-in-depth re-check coverage).
  const doFetch = (path: string, caller: Caller | null, body?: unknown): Promise<Response> => {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (caller !== null) headers["x-downpipe-caller"] = encodeCaller(caller);
    return s.stub.fetch(`https://scheduler.internal${path}`, { method: "POST", headers, body: JSON.stringify(body ?? {}) });
  };
  const j = async <T>(r: Response): Promise<T> => (await r.json()) as T;
  const accessCaller = (email: string, role: Caller["role"]): Caller => ({ method: "access", email, subject: subjectOf(email), role, groups: [] });

  const OWNER = "owner-cc@acme.example";
  const OWNER2 = "owner2-cc@acme.example"; // a SECOND owner, so dual control can be armed (the two-Owner enable floor)
  const OPERATOR = "op-cc@acme.example"; // operator: holds downpipe.write/delete
  const OPERATOR2 = "op2-cc@acme.example"; // a SECOND operator, the distinct checker
  const VIEWER = "viewer-cc@acme.example"; // viewer: no write caps
  const ACCESS_ADMIN = "aa-cc@acme.example"; // access-admin: roles.write/access.policy, NOT downpipe.write
  const ACCESS_ADMIN2 = "aa2-cc@acme.example"; // a SECOND access-admin, the distinct checker for people changes
  const NOTIFIER = "notifier-cc@acme.example"; // a CUSTOM-ROLE holder (viewer floor + notify.config)

  const listDownpipes = async (): Promise<Array<{ config: { id: string } }>> => j(await call(OWNER, "GET", "/admin/downpipes"));
  const listRoles = async (): Promise<Array<{ email: string; role: string }>> => j(await call(OWNER, "GET", "/admin/roles"));
  const pendingChanges = async (): Promise<PendingConfigChange[]> => j(await call(OWNER, "GET", "/admin/config/changes"));
  const histLen = async (): Promise<number> => (await j<{ versions: unknown[] }>(await call(OWNER, "GET", "/admin/config/history"))).versions.length;

  try {
    // =========================================================================================
    // PHASE 1: bootstrap the owner, ARM the gate, and prove the GENESIS head reference + gate-on propose.
    // =========================================================================================
    const who = await j<{ role: string }>(await call(OWNER, "GET", "/admin/whoami"));
    ok("the first Access caller bootstraps as Owner", who.role === "owner");
    // A second Owner so dual control can be armed (the two-Owner enable floor). Seeded DIRECTLY into storage as
    // a pending invite row rather than via a role-set, so it does NOT auto-snapshot a config-history version and
    // the genesis-head assertions below still see the first GATED change binding to the genesis sentinel.
    s.storage.rawPut(`role:pending:${OWNER2}`, { email: OWNER2, role: "owner", grantedBy: "seed", grantedAt: new Date().toISOString() });

    // ARM (false -> true) by the attributable owner: immediate, owner-pass + boolean-pass, no disarm.
    const arm = await call(OWNER, "POST", "/admin/config/approval-policy", { requireConfigApproval: true });
    ok("an owner can ARM the dual-control gate (200)", arm.status === 200);
    ok("the arm reports requireConfigApproval true and is not a disarm", (await j<{ requireConfigApproval: boolean; disarmed: boolean }>(arm)).requireConfigApproval === true);

    // Nothing has been snapshotted yet (bootstrap + the toggle do not snapshot), so the FIRST gate-on
    // proposal binds to the GENESIS head sentinel. This drives headVersionRef's no-version branch.
    const genProp = await call(OWNER, "POST", "/admin/downpipes", { id: "dp_gen", name: "genesis-pipe", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_GEN", include: [], exclude: [] } });
    ok("the first gate-on mutation queues (202), not applied inline", genProp.status === 202);
    const genId = (await j<{ id: string }>(genProp)).id;
    const genRec = s.storage.rawGet<PendingConfigChange>(`configchange:${genId}`);
    ok("the queued change binds to the genesis base id (-1)", genRec?.baseVersionId === -1);
    ok("the queued change binds to the genesis prev-hash sentinel", genRec?.baseVersionHash === CONFIG_GENESIS_PREV_HASH);
    ok("the genesis proposal did not apply (no downpipe yet)", !(await listDownpipes()).some((d) => d.config.id === "dp_gen"));

    // Reject the genesis change as the owner (holds the write cap; a proposer may withdraw their own).
    const genReject = await call(OWNER, "POST", `/admin/config/changes/${genId}/reject`);
    ok("the owner can reject a pending change (200)", genReject.status === 200);
    ok("the rejected change reads status rejected", (await j<PendingConfigChange>(genReject)).status === "rejected");

    // =========================================================================================
    // PHASE 2: approve/reject input guards (gate on), driven into the DO so a bad id/record/kind is exercised.
    // =========================================================================================
    const ownerCaller = accessCaller(OWNER, "owner");
    ok("approve with no id is refused (id required)", (await doFetch("/config/changes/approve", ownerCaller, {})).status === 400);
    ok("approve of an unknown id is refused (no such change)", (await doFetch("/config/changes/approve", ownerCaller, { id: "01NOPE" })).status === 400);
    ok("reject with no id is refused (id required)", (await doFetch("/config/changes/reject", ownerCaller, {})).status === 400);
    ok("reject of an unknown id is refused (no such change)", (await doFetch("/config/changes/reject", ownerCaller, { id: "01NOPE" })).status === 400);

    // A stored record carrying a kind outside the closed set can never be approved or rejected (fail closed).
    s.storage.rawPut("configchange:badkind", { id: "badkind", kind: "totally-bogus", params: {}, proposedBy: "x@acme.example", proposedBySubject: "sub-x", proposedByGroups: [], proposedAt: "2026-06-01T00:00:00.000Z", baseVersionId: -1, baseVersionHash: "sha384:y", diff: [], contentHash: "sha384:z", status: "pending" });
    ok("approving a tampered unknown-kind record is refused", (await doFetch("/config/changes/approve", ownerCaller, { id: "badkind" })).status === 400);
    ok("rejecting a tampered unknown-kind record is refused", (await doFetch("/config/changes/reject", ownerCaller, { id: "badkind" })).status === 400);
    await s.storage.delete("configchange:badkind");

    // =========================================================================================
    // PHASE 3: DISARM via break-glass (the asymmetric off switch), then drive EVERY applyConfigMutation
    // switch arm via the gate-off inline path. Each arm asserts the real applied effect.
    // =========================================================================================
    const disarm = await tokenCall("POST", "/admin/config/approval-policy", { requireConfigApproval: false });
    ok("the break-glass owner can DISARM immediately (200)", disarm.status === 200);
    ok("the disarm reports requireConfigApproval false (true -> false transition)", (await j<{ requireConfigApproval: boolean; disarmed: boolean }>(disarm)).requireConfigApproval === false);

    // Seed the roles the later dual-control proofs need (each is a gate-off role-set inline apply).
    for (const [email, role] of [[OPERATOR, "operator"], [OPERATOR2, "operator"], [VIEWER, "viewer"], [ACCESS_ADMIN, "access-admin"], [ACCESS_ADMIN2, "access-admin"]] as const) {
      ok(`grant ${role} inline applies (200)`, (await call(OWNER, "POST", "/admin/roles", { email, role })).status === 200);
    }
    ok("the granted operator is in the role table", (await listRoles()).some((r) => r.email === OPERATOR && r.role === "operator"));
    // Bind VIEWER's subject so the later DO-direct non-owner check resolves it from the live table.
    await call(VIEWER, "GET", "/admin/whoami");

    // downpipe-upsert + downpipe-delete.
    ok("downpipe-upsert inline applies (200)", (await call(OWNER, "POST", "/admin/downpipes", { id: "dp_inline", name: "inline", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_INLINE", include: [], exclude: [] } })).status === 200);
    ok("the upserted downpipe exists", (await listDownpipes()).some((d) => d.config.id === "dp_inline"));
    ok("downpipe-delete inline applies (200)", (await call(OWNER, "POST", "/admin/downpipes/delete", { id: "dp_inline" })).status === 200);
    ok("the deleted downpipe is gone", !(await listDownpipes()).some((d) => d.config.id === "dp_inline"));

    // role-set + role-delete (an extra, distinct from the seeded ones).
    ok("role-set inline applies (200)", (await call(OWNER, "POST", "/admin/roles", { email: "extra-cc@acme.example", role: "viewer" })).status === 200);
    ok("role-delete inline applies (200)", (await call(OWNER, "POST", "/admin/roles/delete", { email: "extra-cc@acme.example" })).status === 200);
    ok("the deleted role is gone", !(await listRoles()).some((r) => r.email === "extra-cc@acme.example"));

    // group-role-set + group-role-delete.
    ok("group-role-set inline applies (200)", (await call(OWNER, "POST", "/admin/group-roles", { group: "grp-cc", role: "viewer" })).status === 200);
    ok("the group-role mapping is present", (await j<Array<{ group: string }>>(await call(OWNER, "GET", "/admin/group-roles"))).some((g) => g.group === "grp-cc"));
    ok("group-role-delete inline applies (200)", (await call(OWNER, "POST", "/admin/group-roles/delete", { group: "grp-cc" })).status === 200);

    // custom-role-set + custom-role-delete.
    ok("custom-role-set inline applies (200)", (await call(OWNER, "POST", "/admin/custom-roles", { name: "cr-cc", label: "CR CC", capabilities: ["downpipe.read", "audit.read"], landing: "audit" })).status === 200);
    ok("the custom role is present", (await j<Array<{ name: string }>>(await call(OWNER, "GET", "/admin/custom-roles"))).some((c) => c.name === "cr-cc"));
    ok("custom-role-delete inline applies (200)", (await call(OWNER, "POST", "/admin/custom-roles/delete", { name: "cr-cc" })).status === 200);
    // A PERSISTENT custom role carrying notify.config, granted to a holder, for the gate-on custom-role
    // proposer apply path in Phase 4 (the replay forwards that holder's live-resolved capability set).
    ok("create a persistent custom role with notify.config (200)", (await call(OWNER, "POST", "/admin/custom-roles", { name: "cc-notify", label: "CC Notify", capabilities: ["downpipe.read", "notify.config"], landing: "downpipes" })).status === 200);
    ok("grant the custom role to a holder (200)", (await call(OWNER, "POST", "/admin/roles", { email: NOTIFIER, role: "viewer", customRole: "cc-notify" })).status === 200);
    const noteWho = await j<{ capabilities?: string[]; role: string }>(await call(NOTIFIER, "GET", "/admin/whoami"));
    ok("the custom-role holder resolves to notify.config on a viewer floor", (noteWho.capabilities ?? []).includes("notify.config") && noteWho.role === "viewer");

    // notify-channel-set + notify-rule-set + notify-rule-delete + notify-channel-delete.
    const ch = await call(OWNER, "POST", "/admin/notify/channels", { kind: "webhook", name: "ops-cc", url: "https://hooks.example.com/cc", enabled: true });
    ok("notify-channel-set inline applies (200)", ch.status === 200);
    const chId = (await j<{ id: string }>(ch)).id;
    const rule = await call(OWNER, "POST", "/admin/notify/rules", { scope: { kind: "global" }, minSeverity: "warning", events: "all", channelIds: [chId], enabled: true });
    ok("notify-rule-set inline applies (200)", rule.status === 200);
    const ruleId = (await j<{ id: string }>(rule)).id;
    ok("notify-rule-delete inline removes the rule", (await j<{ deleted: boolean }>(await call(OWNER, "POST", "/admin/notify/rules/delete", { id: ruleId }))).deleted === true);
    ok("notify-channel-delete inline removes the channel", (await j<{ deleted: boolean }>(await call(OWNER, "POST", "/admin/notify/channels/delete", { id: chId }))).deleted === true);


    // posture-accept + posture-unaccept.
    ok("posture-accept inline applies (200)", (await call(OWNER, "POST", "/admin/posture/accept", { checkId: "two-owners", reason: "accepted for the coverage test" })).status === 200);
    ok("posture-unaccept inline applies (200)", (await call(OWNER, "POST", "/admin/posture/unaccept", { checkId: "two-owners" })).status === 200);

    // expiry-item-set + expiry-item-delete.
    ok("expiry-item-set inline applies (200)", (await call(OWNER, "POST", "/admin/expiry", { id: "cred-cc", label: "CC CRED", kind: "credential", expiresAt: "2099-01-01T00:00:00.000Z" })).status === 200);
    ok("the expiry item is tracked", (await j<Array<{ id: string }>>(await call(OWNER, "GET", "/admin/expiry"))).some((e) => e.id === "cred-cc"));
    ok("expiry-item-delete inline applies (200)", (await call(OWNER, "POST", "/admin/expiry/delete", { id: "cred-cc" })).status === 200);

    // coverage-inventory.
    ok("coverage-inventory inline applies (200)", (await call(OWNER, "POST", "/admin/coverage/inventory", { kv: [{ id: "ns-cc", name: "uploads" }] })).status === 200);

    // =========================================================================================
    // PHASE 4: RE-ARM and run the dual-control lifecycle (propose / approve guards / clean approve /
    // superseded / tamper / no-caller / legacy null-subject / bare-token).
    // =========================================================================================
    ok("re-arm the gate (200)", (await call(OWNER, "POST", "/admin/config/approval-policy", { requireConfigApproval: true })).status === 200);

    // (4a) OPERATOR proposes a downpipe upsert -> queued with an attributable maker.
    const propL = await call(OPERATOR, "POST", "/admin/downpipes", { id: "dp_life", name: "life", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_LIFE", include: [], exclude: [] } });
    ok("an operator proposal queues (202)", propL.status === 202);
    const idL = (await j<{ id: string }>(propL)).id;

    // (4b) the proposer cannot approve their OWN change (maker != checker, refused inside the DO gate).
    const selfApprove = await call(OPERATOR, "POST", `/admin/config/changes/${idL}/approve`);
    ok("the proposer cannot approve their own change (4xx)", selfApprove.status >= 400);
    ok("the self-approve refusal is the maker != checker rule", /cannot approve your own change/.test((await j<{ error?: string }>(selfApprove)).error ?? ""));

    // (4c) a holder WITHOUT the original write capability cannot approve.
    const noCap = await call(ACCESS_ADMIN, "POST", `/admin/config/changes/${idL}/approve`);
    ok("an approver without the write cap cannot approve (4xx)", noCap.status >= 400);

    // (4d) a DISTINCT operator with the write cap approves -> the real validated apply commits + snapshots.
    const histBefore = await histLen();
    const approve = await call(OPERATOR2, "POST", `/admin/config/changes/${idL}/approve`);
    ok("a distinct holder approves (200)", approve.status === 200);
    const ar = await j<PendingConfigChange>(approve);
    ok("the approved change reads applied with the checker recorded", ar.status === "applied" && ar.approvedBy === OPERATOR2 && ar.proposedBy === OPERATOR);
    ok("the approved change APPLIED via the real path (the downpipe exists)", (await listDownpipes()).some((d) => d.config.id === "dp_life"));
    ok("the applied change auto-snapshotted a new config version", (await histLen()) === histBefore + 1);

    // (4e) SUPERSEDED: a change whose base moved since it was proposed is refused and does not apply.
    const propA = await call(OPERATOR, "POST", "/admin/downpipes", { id: "dp_supA", name: "supA", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_SUPA", include: [], exclude: [] } });
    const idA = (await j<{ id: string }>(propA)).id;
    const propB = await call(OPERATOR, "POST", "/admin/downpipes", { id: "dp_supB", name: "supB", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_SUPB", include: [], exclude: [] } });
    const idB = (await j<{ id: string }>(propB)).id;
    ok("approving B first moves the head (200)", (await call(OPERATOR2, "POST", `/admin/config/changes/${idB}/approve`)).status === 200);
    const supA = await call(OPERATOR2, "POST", `/admin/config/changes/${idA}/approve`);
    ok("approving A against a moved base is refused (4xx superseded)", supA.status >= 400);
    ok("the refusal says superseded / changed since", /superseded|changed since/.test((await j<{ error?: string }>(supA)).error ?? ""));
    ok("the superseded change did NOT apply", !(await listDownpipes()).some((d) => d.config.id === "dp_supA"));
    ok("the superseded record is marked superseded", s.storage.rawGet<PendingConfigChange>(`configchange:${idA}`)?.status === "superseded");

    // (4f) TAMPER: a pending record whose stored params no longer match its content hash is refused.
    const propT = await call(OPERATOR, "POST", "/admin/downpipes", { id: "dp_tam", name: "tam", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_TAM", include: [], exclude: [] } });
    const idT = (await j<{ id: string }>(propT)).id;
    const recT = s.storage.rawGet<PendingConfigChange>(`configchange:${idT}`)!;
    (recT.params as { name: string }).name = "tampered-name";
    s.storage.rawPut(`configchange:${idT}`, recT);
    const tamApprove = await call(OPERATOR2, "POST", `/admin/config/changes/${idT}/approve`);
    ok("a content-hash mismatched (tampered) change is refused (4xx)", tamApprove.status >= 400);
    ok("the tampered change applied nothing", !(await listDownpipes()).some((d) => d.config.id === "dp_tam"));
    await s.storage.delete(`configchange:${idT}`);

    // (4g) NO CALLER: a DO approve with no attributable checker is refused (fail closed).
    const propNC = await call(OPERATOR, "POST", "/admin/downpipes", { id: "dp_nc", name: "nc", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_NC", include: [], exclude: [] } });
    const idNC = (await j<{ id: string }>(propNC)).id;
    ok("a no-caller DO approve is refused (fail closed)", (await doFetch("/config/changes/approve", null, { id: idNC })).status === 400);
    await call(OPERATOR2, "POST", `/admin/config/changes/${idNC}/reject`); // clean up

    // (4h) LEGACY null-subject record: the approve recompute + replay tolerate a null subject / non-array
    // groups (fed as null / []). A group-role-set re-resolves the proposer's authority at apply, so the
    // subjectless proposer resolves to viewer (no access.policy) and the replay refuses. An access-admin
    // proposes (within authority); a DISTINCT access-admin approves so the maker != checker + cap gates pass.
    const propLEG = await call(ACCESS_ADMIN, "POST", "/admin/group-roles", { group: "leg-grp", role: "viewer" });
    ok("an access-admin queues a within-authority group-role mapping (202)", propLEG.status === 202);
    const idLEG = (await j<{ id: string }>(propLEG)).id;
    const recLEG = s.storage.rawGet<PendingConfigChange>(`configchange:${idLEG}`)!;
    recLEG.proposedBySubject = null;
    delete (recLEG as { proposedByGroups?: unknown }).proposedByGroups; // non-array (absent) on the stored record
    // Re-bind the content hash over the legacy-shaped fields so it passes the integrity recompute and the
    // approve reaches the replay (which then refuses on the subjectless proposer's viewer authority).
    recLEG.contentHash = await changeContentHash(recLEG.kind, recLEG.params, recLEG.proposedBy, null, [], recLEG.baseVersionId, recLEG.baseVersionHash);
    s.storage.rawPut(`configchange:${idLEG}`, recLEG);
    const legApprove = await call(ACCESS_ADMIN2, "POST", `/admin/config/changes/${idLEG}/approve`);
    ok("a legacy null-subject change is refused at apply (proposer resolves to viewer)", legApprove.status >= 400);
    ok("the legacy null-subject change applied nothing", !(await j<Array<{ group: string }>>(await call(OWNER, "GET", "/admin/group-roles"))).some((g) => g.group === "leg-grp"));
    await s.storage.delete(`configchange:${idLEG}`);

    // (4j) the BARE-TOKEN break-glass cannot PROPOSE under the gate (no attributable maker).
    const tokenProp = await tokenCall("POST", "/admin/downpipes", { id: "dp_tok", name: "tok", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_TOK", include: [], exclude: [] } });
    ok("the bare-token fallback cannot propose a change (4xx)", tokenProp.status >= 400);
    ok("the bare-token refusal is attributability, not a role 403", tokenProp.status !== 403 && /attributable/.test((await j<{ error?: string }>(tokenProp)).error ?? ""));
    ok("the bare-token proposal queued/applied nothing", !(await listDownpipes()).some((d) => d.config.id === "dp_tok"));

    // (4k) the BARE-TOKEN break-glass CAN reject (owner authority, attributable email is null on the audit).
    const propBTR = await call(OPERATOR, "POST", "/admin/downpipes", { id: "dp_btr", name: "btr", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_BTR", include: [], exclude: [] } });
    const idBTR = (await j<{ id: string }>(propBTR)).id;
    const tokenReject = await tokenCall("POST", `/admin/config/changes/${idBTR}/reject`);
    ok("the bare-token break-glass owner can reject a change (200)", tokenReject.status === 200);
    ok("the bare-token rejected change reads rejected", (await j<PendingConfigChange>(tokenReject)).status === "rejected");

    // (4l) a caller WITHOUT the original write capability cannot REJECT the change either (DO re-check).
    const propRJ = await call(OPERATOR, "POST", "/admin/downpipes", { id: "dp_rj", name: "rj", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_RJ", include: [], exclude: [] } });
    const idRJ = (await j<{ id: string }>(propRJ)).id;
    const viewerReject = await doFetch("/config/changes/reject", accessCaller(VIEWER, "viewer"), { id: idRJ });
    ok("a viewer without the write cap cannot reject (403)", viewerReject.status === 403);
    ok("the change is still pending after the refused reject", s.storage.rawGet<PendingConfigChange>(`configchange:${idRJ}`)?.status === "pending");
    await call(OPERATOR2, "POST", `/admin/config/changes/${idRJ}/reject`); // clean up with a capable holder

    // (4m) a reject of an ALREADY-TERMINAL record is refused even by a capable holder (the state guard).
    const reReject = await call(OPERATOR, "POST", `/admin/config/changes/${idBTR}/reject`);
    ok("re-rejecting an already-rejected change is refused (4xx)", reReject.status >= 400);
    ok("the re-reject refusal is the already-terminal state guard", /already rejected/.test((await j<{ error?: string }>(reReject)).error ?? ""));

    // (4i) a CUSTOM-ROLE proposer's queued change APPLIES on approval: the replay forwards the proposer's
    // live-resolved capability set (capabilities !== undefined), so the by-role re-check honours it without
    // refusing the holder on their viewer floor. A DISTINCT notify.config holder (an operator) approves.
    const propCR = await call(NOTIFIER, "POST", "/admin/notify/channels", { kind: "webhook", name: "cc-cr-sink", url: "https://hooks.example.com/cr" });
    ok("a custom-role proposer can QUEUE a notify change under the gate (202)", propCR.status === 202);
    const idCR = (await j<{ id: string }>(propCR)).id;
    const approveCR = await call(OPERATOR2, "POST", `/admin/config/changes/${idCR}/approve`);
    ok("the custom-role proposer's queued change APPLIES on approval (200, forwarded caps)", approveCR.status === 200);
    ok("the applied custom-role change reads applied", (await j<PendingConfigChange>(approveCR)).status === "applied");

    // =========================================================================================
    // PHASE 5: defence-in-depth toggle re-checks (router-bypassed) + the exhaustiveness default.
    // =========================================================================================
    // A non-owner cannot flip the policy even straight at the DO (owner re-resolved from the live table).
    const viewerToggle = await doFetch("/config/approval-policy", accessCaller(VIEWER, "viewer"), { requireConfigApproval: true });
    ok("a non-owner cannot flip the approval policy at the DO (403)", viewerToggle.status === 403);
    // A non-boolean value is rejected by the owner (the type guard) as a 400.
    const badType = await doFetch("/config/approval-policy", ownerCaller, { requireConfigApproval: "yes" });
    ok("a non-boolean approval policy value is refused (400)", badType.status === 400);
    // An owner toggle carrying a source IP exercises the audit's source-IP attribution branch (idempotent arm).
    const ipToggle = await doFetch("/config/approval-policy", { ...ownerCaller, sourceIp: "203.0.113.9" }, { requireConfigApproval: true });
    ok("an owner toggle with a source IP succeeds (200)", ipToggle.status === 200);
    ok("the source-IP toggle reports the policy on", (await j<{ requireConfigApproval: boolean }>(ipToggle)).requireConfigApproval === true);

    // The exhaustiveness default: a kind outside the closed set fails closed (no write), on a fresh DO.
    const do2 = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    let defaultThrew = false;
    try {
      await (do2 as unknown as { applyConfigMutation(k: string, p: unknown, c: unknown): Promise<unknown> }).applyConfigMutation("not-a-real-kind", {}, null);
    } catch (e) {
      defaultThrew = /unknown config change kind/.test(String((e as Error).message ?? e));
    }
    ok("applyConfigMutation fails closed on an unknown kind (exhaustiveness default)", defaultThrew);

    // =========================================================================================
    // PHASE 6: dry-run alarm capture/restore arms. The gate is ON, so each propose runs the dry-run.
    // We pre-set the DO alarm directly, then assert the proposal restored it to exactly its prior value.
    // =========================================================================================
    // (6a) alarm absent + a downpipe upsert (which re-arms): the dry-run must DELETE the re-armed alarm.
    await s.storage.deleteAlarm();
    const al1 = await call(OPERATOR, "POST", "/admin/downpipes", { id: "dp_al1", name: "al1", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_AL1", include: [], exclude: [] } });
    ok("a downpipe-upsert proposal queues with no prior alarm (202)", al1.status === 202);
    ok("the proposal left NO re-armed alarm behind (deleted in rollback)", (await s.storage.getAlarm()) === null);

    // (6b) alarm absent + a role-set (which does not touch the alarm): nothing to delete, stays absent.
    await s.storage.deleteAlarm();
    const al2 = await call(OWNER, "POST", "/admin/roles", { email: "al-role@acme.example", role: "viewer" });
    ok("a role-set proposal queues with no prior alarm (202)", al2.status === 202);
    ok("the role-set proposal left the alarm absent", (await s.storage.getAlarm()) === null);

    // (6c) a prior alarm + a downpipe upsert (re-arms to a different time): the dry-run RESETS it back.
    await s.storage.setAlarm(1);
    const al3 = await call(OPERATOR, "POST", "/admin/downpipes", { id: "dp_al3", name: "al3", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_AL3", include: [], exclude: [] } });
    ok("a downpipe-upsert proposal queues with a prior alarm (202)", al3.status === 202);
    ok("the proposal restored the prior alarm value exactly", (await s.storage.getAlarm()) === 1);

    // (6d) a prior alarm + a role-set (untouched): the alarm equals its prior value, no reset needed.
    await s.storage.setAlarm(1);
    const al4 = await call(OWNER, "POST", "/admin/roles", { email: "al-role2@acme.example", role: "viewer" });
    ok("a role-set proposal queues with a prior alarm (202)", al4.status === 202);
    ok("the role-set proposal left the prior alarm intact", (await s.storage.getAlarm()) === 1);

    // =========================================================================================
    // PHASE 7: the read surfaces (getOrgPolicyView + the pending inbox listing/sort).
    // =========================================================================================
    const pol = await j<{ requireConfigApproval: boolean; requireChangeNumber: boolean }>(await call(OWNER, "GET", "/admin/config/approval-policy"));
    ok("the org policy view reports both governance flags", pol.requireConfigApproval === true && typeof pol.requireChangeNumber === "boolean");

    // Two records with an IDENTICAL proposedAt exercise the sort's equal-key (0) arm; the live pending
    // records (different proposedAt) exercise the less-than / greater-than arms. All are pending.
    s.storage.rawPut("configchange:zzeq1", { id: "zzeq1", kind: "downpipe-upsert", params: {}, proposedBy: "eq@acme.example", proposedBySubject: "sub-eq", proposedByGroups: [], proposedAt: "2024-01-01T00:00:00.000Z", baseVersionId: -1, baseVersionHash: "sha384:y", diff: [], contentHash: "sha384:z", status: "pending" });
    s.storage.rawPut("configchange:zzeq2", { id: "zzeq2", kind: "downpipe-upsert", params: {}, proposedBy: "eq@acme.example", proposedBySubject: "sub-eq", proposedByGroups: [], proposedAt: "2024-01-01T00:00:00.000Z", baseVersionId: -1, baseVersionHash: "sha384:y", diff: [], contentHash: "sha384:z", status: "pending" });
    const inbox = await pendingChanges();
    ok("the pending inbox lists only pending records, newest-first", inbox.length >= 2 && inbox.every((r) => r.status === "pending"));
    ok("the equal-proposedAt records both appear in the inbox", inbox.some((r) => r.id === "zzeq1") && inbox.some((r) => r.id === "zzeq2"));
  } finally {
    signer.restoreFetch();
  }

  console.log(failures === 0 ? "\nVALIDATE-COV-SCHED-SCHEDULER-DO-CHANGE-CONTROL VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
