// validate-restore-approval-target-shown: a restore approver must be able to read WHERE and WHAT a restore
// writes before they approve it.
//
// The plan hash binds the write target: target.binding, target.namespaceId, target.bucketName, the cfConfig
// account and zone, the mediaRestore account, the D1 table subset and onExisting "skip" (approvals.ts
// restorePlanHash). The approver does not approve the hash; they approve what the inbox shows them. So every
// field the hash binds that moves the write away from the run's original bindings must also be readable in
// the approval record the approver lists. A record that names none of it reads as "Original bindings".
//
// Everything here goes through the real handleAdmin router and the real SchedulerDO on the in-memory
// storage: the dry run that anchors the plan, the request, the approver's inbox read, the approve and the
// apply. The run does not exist, so the dry run and the recomputed cues are the honest ok:false plan, and no
// apply can write anything.
//
// Run: node test/validate-restore-approval-target-shown.ts

import type { RestoreApproval } from "../src/admin/approvals.ts";
import { APPROVAL_MIN_DWELL_MS, approvalKey, planBindingHash, restorePlanBinding, restorePlanHash } from "../src/admin/approvals.ts";
import { type AuditEvent, toCSV } from "../src/admin/audit.ts";
import { type Caller, encodeCaller } from "../src/admin/identity.ts";
import type { RestoreRequest } from "../src/admin/restore-types.ts";
import { handleAdmin } from "../src/admin/router.ts";
import type { Env } from "../src/env.d.ts";
import { canonicalJSON } from "../src/format/canonjson.ts";
import { __advanceAuditFoldClockForTest, AUDIT_FOLD_WINDOW_MS } from "../src/sched/audit-fold.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { MockStorage } from "./mock-storage.ts";
import { ageRecord, notePlanAnchor } from "./testutil.ts";
import { AUD, makeSigner, TEAM } from "./validate-rbac-harness.ts";

// The SchedulerDO on test/mock-storage.ts, the storage whose rawGet/rawPut ageRecord needs to step past the
// approve dwell floor.
function makeScheduler(): { env: Pick<Env, "SCHEDULER">; storage: MockStorage; stub: DurableObjectStub } {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = { idFromName: (_n: string) => ({}) as unknown as DurableObjectId, get: (_id: DurableObjectId) => stub } as unknown as DurableObjectNamespace;
  return { env: { SCHEDULER: namespace }, storage, stub };
}

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const OWNER = "s17-owner@acme.example";
const OWNER2 = "s17-owner2@acme.example";
const OPERATOR = "s17-operator@acme.example";
const APPROVER = "s17-approver@acme.example";
const RUN_ID = "01JS17S17S17S17S17S17S17S1";

// Each case is a request that writes somewhere other than the run's original bindings, and the values the
// approver must be able to read to know where. The values are distinctive so a substring match on the
// approver's record cannot hit by accident.
interface Case {
  kind: string;
  extra: Partial<RestoreRequest>;
  mustName: string[];
}
const CASES: Case[] = [
  { kind: "target.binding (control: the one redirect the record carries)", extra: { target: { binding: "KV_S17_OTHER" } }, mustName: ["KV_S17_OTHER"] },
  { kind: "target.namespaceId", extra: { target: { namespaceId: "5170000000000000000000000000a17a" } }, mustName: ["5170000000000000000000000000a17a"] },
  { kind: "target.bucketName", extra: { target: { bucketName: "s17-foreign-bucket" } }, mustName: ["s17-foreign-bucket"] },
  {
    kind: "cfConfig account and zone",
    extra: { cfConfig: { token: "s17-cf-token-not-a-secret", accountId: "517acc00000000000000000000000c0f", zoneId: "517a0e00000000000000000000000c0f", confirmDifferentAccountId: "517acc00000000000000000000000c0f", confirmDifferentZoneId: "517a0e00000000000000000000000c0f" } },
    mustName: ["517acc00000000000000000000000c0f", "517a0e00000000000000000000000c0f"],
  },
  { kind: "mediaRestore account", extra: { mediaRestore: { token: "s17-media-token-not-a-secret", accountId: "517acc0000000000000000000000ed1a", confirmDifferentAccountId: "517acc0000000000000000000000ed1a" } }, mustName: ["517acc0000000000000000000000ed1a"] },
  { kind: "d1Tables subset", extra: { d1Tables: { database: "D1_S17_DB", tables: ["s17_orders", "s17_invoices"] } }, mustName: ["D1_S17_DB", "s17_orders", "s17_invoices"] },
  { kind: "onExisting skip", extra: { onExisting: "skip" }, mustName: ["skip"] },
];

async function main(): Promise<void> {
  const signer = await makeSigner();
  const sched = makeScheduler();
  const env = (): Env => ({ ...sched.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, WORKER_NAME: "downpipe-engine" }) as unknown as Env;
  const call = async (email: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> =>
    handleAdmin(
      new Request(`https://engine.example${path}`, {
        method,
        headers: { "cf-access-jwt-assertion": await signer.tokenFor(email), "content-type": "application/json" },
        ...(method === "GET" ? {} : { body: JSON.stringify(body ?? {}) }),
      }),
      env(),
    );

  console.log("-- setup through the router: two Owners, an Operator, an Approver, restore approval armed --");
  await call(OWNER, "GET", "/admin/whoami");
  for (const [email, role] of [
    [OWNER2, "owner"],
    [OPERATOR, "operator"],
    [APPROVER, "approver"],
  ] as const) {
    const r = await call(OWNER, "POST", "/admin/roles", { email, role });
    await r.text();
    ok(`grant ${role} ${email}: 200`, r.status === 200);
  }
  const arm = await call(OWNER, "POST", "/admin/config/restore-approval-policy", { requireRestoreApproval: true });
  const armText = await arm.text();
  ok(`arm requireRestoreApproval: 200 (${armText.slice(0, 80)})`, arm.status === 200);

  // raise: the operator's real path. Dry run first (it anchors the plan), then the request.
  const raise = async (extra: Partial<RestoreRequest>, reason: string): Promise<{ status: number; planHash: string; body: string }> => {
    const req = { runId: RUN_ID, ...extra } as RestoreRequest;
    const dry = await call(OPERATOR, "POST", "/admin/restore", { ...req, confirm: false });
    await dry.text();
    const r = await call(OPERATOR, "POST", "/admin/restore/request", { ...req, reason });
    return { status: r.status, planHash: await restorePlanHash(req), body: await r.text() };
  };

  console.log("\n-- negative control: a request with no redirect lists with redirectBinding null --");
  const plain = await raise({}, "s17 plain request");
  ok(`plain request accepted (${plain.status} ${plain.body.slice(0, 80)})`, plain.status === 200);

  const raised: Array<Case & { planHash: string }> = [];
  for (const c of CASES) {
    const r = await raise(c.extra, `s17 case ${c.kind}`);
    ok(`request [${c.kind}] accepted through the router (${r.status} ${r.body.slice(0, 80)})`, r.status === 200);
    raised.push({ ...c, planHash: r.planHash });
  }

  console.log("\n-- what the approver reads: GET /admin/restore/approvals --");
  const inboxResp = await call(APPROVER, "GET", "/admin/restore/approvals");
  const inbox = (await inboxResp.json()) as RestoreApproval[];
  ok(`approver inbox 200 with ${inbox.length} records`, inboxResp.status === 200 && inbox.length === CASES.length + 1);
  const plainRec = inbox.find((r) => r.planHash === plain.planHash);
  ok("plain request: redirectBinding null (Original bindings is true here)", plainRec !== undefined && plainRec.redirectBinding === null);

  // A per-record detail read, if the engine offers one. It does not today; record what it answers so the
  // report shows the list is the approver's only view.
  const detail = await call(APPROVER, "GET", `/admin/restore/approvals/${encodeURIComponent(plain.planHash)}`);
  console.log(`  info detail route GET /admin/restore/approvals/<planHash>: ${detail.status} ${(await detail.text()).slice(0, 60)}`);

  console.log("\n-- the safe behaviour: each redirected write names its target in the approver's record --");
  for (const c of raised) {
    const rec = inbox.find((r) => r.planHash === c.planHash);
    if (rec === undefined) {
      ok(`[${c.kind}] record present in the approver inbox`, false);
      continue;
    }
    // Everything the approver's record carries, minus the opaque hash (a hex digest could contain a hex id)
    // and minus the requester's free-text reason (the requester's claim, not an engine-attested fact; this
    // test's reasons also name each case). A value counts only as a whole JSON string.
    const { planHash: _hash, reason: _reason, ...shown } = rec;
    const text = JSON.stringify(shown);
    const missing = c.mustName.filter((v) => !text.includes(`"${v}"`));
    console.log(`  info [${c.kind}] redirectBinding=${JSON.stringify(rec.redirectBinding)} keys=${Object.keys(shown).sort().join(",")}`);
    ok(`[${c.kind}] the approver's record names ${c.mustName.join(" + ")}${missing.length ? ` (missing: ${missing.join(", ")})` : ""}`, missing.length === 0);
    // "Presents as original bindings": the console renders Original bindings when redirectBinding is null,
    // and nothing else in the record says otherwise.
    const presentsAsOriginal = rec.redirectBinding === null && missing.length === c.mustName.length;
    ok(`[${c.kind}] the record does not present as Original bindings`, !presentsAsOriginal);
  }

  console.log("\n-- the record's plan is the exact object the hash binds, and it carries no token --");
  const canonText = (v: unknown): string => new TextDecoder().decode(canonicalJSON(v));
  ok("plain request: plan present with target null (Original bindings is a fact the plan states)", plainRec?.plan !== undefined && plainRec.plan.target === null && plainRec.plan.cfConfig === undefined);
  for (const c of raised) {
    const rec = inbox.find((r) => r.planHash === c.planHash);
    const want = restorePlanBinding({ runId: RUN_ID, ...c.extra } as RestoreRequest);
    ok(`[${c.kind}] record.plan is restorePlanBinding of the request`, rec?.plan !== undefined && canonText(rec.plan) === canonText(want));
    ok(`[${c.kind}] record.plan hashes to the record's planHash`, rec?.plan !== undefined && (await planBindingHash(rec.plan)) === c.planHash);
  }
  const inboxText = JSON.stringify(inbox);
  ok("no token reaches the approver's inbox (value or key)", !inboxText.includes("token-not-a-secret") && !inboxText.includes('"token"'));

  console.log("\n-- the audit trail names the same targets: restore-request rows and their text render --");
  const readAudit = async (query: string): Promise<{ events: AuditEvent[]; headSeq: number; headHash: string }> =>
    (await (await call(OWNER, "GET", `/admin/audit?limit=500&${query}`)).json()) as { events: AuditEvent[]; headSeq: number; headHash: string };
  const reqLog = await readAudit("action=restore-request&outcome=success");
  const rowFor = (log: { events: AuditEvent[] }, hash: string): AuditEvent | undefined => log.events.find((e) => (e.target as { planHash?: string }).planHash === hash);
  const csvRow = (e: AuditEvent | undefined): string => (e === undefined ? "" : (toCSV([e], { headSeq: e.seq, headHash: e.hash }).split("\n")[1] ?? ""));
  const plainRow = rowFor(reqLog, plain.planHash);
  ok("plain request row renders as original bindings", csvRow(plainRow).includes("original bindings"));
  for (const c of raised) {
    const row = rowFor(reqLog, c.planHash);
    const targetText = JSON.stringify(row?.target ?? {});
    const missing = c.mustName.filter((v) => !targetText.includes(`"${v}"`));
    ok(`[${c.kind}] restore-request row names ${c.mustName.join(" + ")}${missing.length ? ` (missing: ${missing.join(", ")})` : ""}`, row !== undefined && missing.length === 0);
    const line = csvRow(row);
    const textMissing = c.mustName.filter((v) => !line.includes(v));
    ok(`[${c.kind}] the row's text render names the target and does not say original bindings${textMissing.length ? ` (missing: ${textMissing.join(", ")})` : ""}`, line !== "" && textMissing.length === 0 && (c.kind.startsWith("onExisting") ? line.includes("original bindings, skip existing") : !line.includes("original bindings")));
  }
  const allAudit = JSON.stringify((await readAudit("")).events);
  ok("no token reaches any audit row", !allAudit.includes("token-not-a-secret") && !allAudit.includes('"token"'));

  console.log("\n-- the DO stores a plan only when it hashes to the plan hash and names the run --");
  {
    const doCaller: Caller = { method: "access", email: "s17-do-maker@acme.example", subject: "s17-do-maker-subject", role: "operator", groups: [] };
    const DO_RUN = "01JS17D0D0D0D0D0D0D0D0D0D0";
    const req = { runId: DO_RUN, target: { namespaceId: "5170000000000000000000000000d0d0" } } as RestoreRequest;
    const hash = await restorePlanHash(req);
    await notePlanAnchor(sched.stub.fetch, hash);
    const doRequest = async (plan: unknown, label: string): Promise<{ status: number; body: { error?: string; plan?: unknown } }> => {
      const r = await sched.stub.fetch("https://scheduler.internal/restore/request", {
        method: "POST",
        headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(doCaller) },
        body: JSON.stringify({ planHash: hash, runId: DO_RUN, isLatest: false, reason: `s17 do ${label}`, ...(plan !== undefined ? { plan } : {}) }),
      });
      return { status: r.status, body: (await r.json()) as { error?: string; plan?: unknown } };
    };
    const moved = { ...restorePlanBinding(req), target: { namespaceId: "5170000000000000000000000000beef" } };
    const tampered = await doRequest(moved, "tampered");
    ok(`a plan whose target moved is refused 400 (${tampered.status} ${tampered.body.error ?? ""})`, tampered.status === 400 && /does not match the plan hash/.test(tampered.body.error ?? ""));
    const otherRun = await doRequest({ ...restorePlanBinding(req), runId: RUN_ID }, "other run");
    ok(`a plan naming another run is refused 400 (${otherRun.status})`, otherRun.status === 400 && /does not match the plan hash/.test(otherRun.body.error ?? ""));
    const notObject = await doRequest("not a plan", "string");
    ok(`a plan that is not an object is refused 400 (${notObject.status})`, notObject.status === 400);
    ok("no record was stored by a refused plan", sched.storage.rawGet(approvalKey(hash)) === undefined);
    const good = await doRequest(restorePlanBinding(req), "good");
    ok(`the matching plan is stored (${good.status})`, good.status === 200 && canonText(good.body.plan) === canonText(restorePlanBinding(req)));
    const none = await doRequest(undefined, "no plan");
    ok(`a request with no plan is still accepted and stores no plan (${none.status})`, none.status === 200 && none.body.plan === undefined);
  }

  console.log("\n-- positive control: the plan hash still refuses a change after approval --");
  for (const kind of ["target.namespaceId", "cfConfig account and zone", "d1Tables subset"]) {
    const c = raised.find((x) => x.kind === kind);
    if (c === undefined) continue;
    ageRecord(sched.storage, approvalKey(c.planHash), "requestedAt", APPROVAL_MIN_DWELL_MS + 1000);
    const ap = await call(APPROVER, "POST", "/admin/restore/approve", { planHash: c.planHash });
    const apText = await ap.text();
    ok(`[${kind}] approver approves (${ap.status} ${apText.slice(0, 60)})`, ap.status === 200);
    const approved = JSON.parse(apText) as RestoreApproval;
    ok(`[${kind}] the approve response carries the plan it approved`, approved.plan !== undefined && (await planBindingHash(approved.plan)) === c.planHash);
    const approveRow = rowFor(await readAudit("action=restore-approve&outcome=success"), c.planHash);
    const approveText = JSON.stringify(approveRow?.target ?? {});
    ok(`[${kind}] the restore-approve row names the target`, approveRow !== undefined && c.mustName.every((v) => approveText.includes(`"${v}"`)));
    // The same plan with its target moved.
    const moved: Partial<RestoreRequest> =
      kind === "target.namespaceId"
        ? { target: { namespaceId: "5170000000000000000000000000beef" } }
        : kind === "cfConfig account and zone"
          ? { cfConfig: { ...(c.extra.cfConfig as NonNullable<RestoreRequest["cfConfig"]>), zoneId: "517a0e0000000000000000000000beef", confirmDifferentZoneId: "517a0e0000000000000000000000beef" } }
          : { d1Tables: { database: "D1_S17_DB", tables: ["s17_orders", "s17_invoices", "s17_users"] } };
    const movedHash = await restorePlanHash({ runId: RUN_ID, ...moved } as RestoreRequest);
    ok(`[${kind}] the moved plan hashes differently`, movedHash !== c.planHash);
    // A quiet minute for the audit fold (src/sched/audit-fold.ts): this Owner's earlier refusal would
    // otherwise carry this one as a count, and this check reads the denied row itself.
    __advanceAuditFoldClockForTest(AUDIT_FOLD_WINDOW_MS);
    const apply = await call(OWNER, "POST", "/admin/restore", { runId: RUN_ID, confirm: true, ...moved });
    const applyBody = (await apply.json()) as { error?: string; planHash?: string };
    ok(`[${kind}] an apply with the moved target is refused 403 restore not approved`, apply.status === 403 && applyBody.error === "restore not approved" && applyBody.planHash === movedHash);
    const movedValue = kind === "target.namespaceId" ? "5170000000000000000000000000beef" : kind === "cfConfig account and zone" ? "517a0e0000000000000000000000beef" : "s17_users";
    const applyRow = rowFor(await readAudit("action=restore-apply&outcome=denied"), movedHash);
    ok(`[${kind}] the denied restore-apply row names the moved target ${movedValue}`, applyRow !== undefined && JSON.stringify(applyRow.target).includes(`"${movedValue}"`) && !csvRow(applyRow).includes("original bindings"));
    // The approved plan itself passes the dual-control gate (it then fails later for the missing run).
    const gate = await sched.stub.fetch("https://scheduler.internal/restore/gate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ planHash: c.planHash }) });
    const gateBody = (await gate.json()) as { usable?: boolean };
    ok(`[${kind}] the approved plan's own hash is usable at the gate`, gateBody.usable === true);
  }

  console.log("\n-- reject: the response and the restore-reject row carry the plan --");
  {
    const c = raised.find((x) => x.kind === "mediaRestore account");
    if (c !== undefined) {
      const rj = await call(APPROVER, "POST", "/admin/restore/reject", { planHash: c.planHash, rejectReason: "wrong-target" });
      const rjBody = (await rj.json()) as RestoreApproval;
      ok(`[${c.kind}] reject 200 and the response carries the plan (${rj.status})`, rj.status === 200 && rjBody.status === "rejected" && rjBody.plan?.mediaRestore?.accountId === "517acc0000000000000000000000ed1a");
      const rejectRow = rowFor(await readAudit("action=restore-reject&outcome=success"), c.planHash);
      ok(`[${c.kind}] the restore-reject row names the media account`, rejectRow !== undefined && (rejectRow.target as { mediaAccountId?: string }).mediaAccountId === "517acc0000000000000000000000ed1a");
    }
  }

  signer.restoreFetch();
  console.log(failures === 0 ? "\nRESTORE APPROVAL TARGET SHOWN PASS" : `\n${failures} FAILURE(S) of ${checks}`);
  verdictReached(failures, checks);
  if (failures > 0) process.exit(1);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
