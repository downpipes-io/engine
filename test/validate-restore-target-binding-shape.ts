// validate-restore-target-binding-shape: a restore's target.binding must be a binding NAME string that the
// engine looks up as an OWN binding, and the reserved-binding guard must refuse every value that reaches a
// reserved binding, whatever its JSON type.
//
// guardTarget (src/admin/restore-sinks.ts) asks RESERVED_BINDINGS.has(binding), a Set lookup that compares by
// identity, and resolveSink then reads env[binding], a property lookup that coerces its key to a string. A
// value that is not a string can therefore pass the Set check and still name a reserved binding once coerced,
// and a name that is not an own binding (for example "constructor") can resolve to something on the
// prototype chain.
//
// Everything here goes through the real handleAdmin router and the real SchedulerDO on the in-memory
// storage. The restore reads a real signed archive of three KV records from an R2 mock bound as DEST_R2,
// which is the engine's own archive destination and a reserved binding. The harm this test looks for is a
// restore record written INTO that bucket.
//
// Run: node test/validate-restore-target-binding-shape.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { APPROVAL_MIN_DWELL_MS, approvalKey, restorePlanBinding, restorePlanHash } from "../src/admin/approvals.ts";
import { guardTarget, RESERVED_REASON } from "../src/admin/restore-sinks.ts";
import type { RestorePlan, RestoreRequest, RestoreResult } from "../src/admin/restore-types.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import type { Env } from "../src/env.d.ts";
import { buildArchive, type RecipientEntry } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import { __advanceAuditFoldClockForTest, AUDIT_FOLD_WINDOW_MS } from "../src/sched/audit-fold.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { MockStorage } from "./mock-storage.ts";
import { ageRecord } from "./testutil.ts";
import { AUD, makeSigner, TEAM } from "./validate-rbac-harness.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const RUN_ID = "01JTBS0000000000000000000A";
const NS = "ns_tbs";
const RECORDS: Record<string, string> = { "tbs:a": "alpha", "tbs:b": "beta", "tbs:c": "gamma" };
const RECORD_KEYS = Object.keys(RECORDS);

const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));
const toAB = (b: Uint8Array): ArrayBuffer => {
  const out = new ArrayBuffer(b.byteLength);
  new Uint8Array(out).set(b);
  return out;
};

// The archive bucket. It counts every put so a write that lands in the reserved binding is visible.
class ArchiveR2 {
  store = new Map<string, Uint8Array>();
  puts: string[] = [];
  async get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer>; etag: string } | null> {
    const v = this.store.get(key);
    return v ? { arrayBuffer: async () => toAB(v), etag: `"${key.length}"` } : null;
  }
  async head(key: string): Promise<{ etag: string } | null> {
    return this.store.has(key) ? { etag: `"${key.length}"` } : null;
  }
  async put(key: string, body: ArrayBuffer | Uint8Array | string): Promise<{ etag: string }> {
    this.puts.push(key);
    this.store.set(key, typeof body === "string" ? utf8(body) : body instanceof Uint8Array ? body : new Uint8Array(body));
    return { etag: `"${key.length}"` };
  }
}

// The legitimate restore target, a KV namespace bound under an ordinary name.
class TargetKV {
  store = new Map<string, Uint8Array>();
  async put(k: string, v: ArrayBuffer | Uint8Array): Promise<void> {
    this.store.set(k, v instanceof Uint8Array ? v : new Uint8Array(v));
  }
  async get(k: string): Promise<ArrayBuffer | null> {
    const v = this.store.get(k);
    return v ? toAB(v) : null;
  }
}

function recipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

function makeScheduler(): { ns: DurableObjectNamespace; storage: MockStorage; dobj: SchedulerDO } {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const ns = { idFromName: (_n: string) => ({}) as unknown as DurableObjectId, get: (_id: DurableObjectId) => stub } as unknown as DurableObjectNamespace;
  return { ns, storage, dobj };
}

// Each malformed value, and the harmful reading it would get if it were coerced. "reaches" is the reserved
// binding the coerced key names, or null when the value names no reserved binding.
interface Case {
  label: string;
  binding: unknown;
  // malformed: not a non-empty string, so it can never be a binding name and must be refused as a request.
  malformed: boolean;
  reaches: string | null;
}
const CASES: Case[] = [
  { label: 'array ["DEST_R2"]', binding: ["DEST_R2"], malformed: true, reaches: "DEST_R2" },
  { label: 'nested array [["DEST_R2"]]', binding: [["DEST_R2"]], malformed: true, reaches: "DEST_R2" },
  { label: 'inherited name "constructor"', binding: "constructor", malformed: false, reaches: null },
  { label: 'inherited name "toString"', binding: "toString", malformed: false, reaches: null },
  { label: 'inherited name "__proto__"', binding: "__proto__", malformed: false, reaches: null },
  { label: 'empty string ""', binding: "", malformed: true, reaches: null },
  { label: "number 42", binding: 42, malformed: true, reaches: null },
  { label: "object {}", binding: {}, malformed: true, reaches: null },
  { label: "boolean true", binding: true, malformed: true, reaches: null },
];

async function main(): Promise<void> {
  const signer = await makeSigner();
  const sched = makeScheduler();

  // Seal the archive with a signer the engine also loads, so the restore verifies for real.
  const signerPrivateB64 = b64urlEncode(concat(rand(32), rand(32)));
  const archiveSigner = await loadSigner(signerPrivateB64);
  const breakGlass = recipient("break-glass");
  const op = recipient("operational");
  const r2 = new ArchiveR2();
  const archive = await buildArchive({
    downpipeId: "dp_tbs",
    downpipeName: "tbs",
    cadence: "3600s",
    runId: RUN_ID,
    master: rand(32),
    recipients: [breakGlass.entry, op.entry],
    signer: archiveSigner,
    records: Object.entries(RECORDS).map(([name, v]) => ({ sourceType: "kv", name, value: utf8(v), namespace: NS })),
    windowStart: "2026-09-01T00:00:00.000Z",
    windowEnd: "2026-09-01T00:00:01.000Z",
    createdAt: "2026-09-01T00:00:01.000Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });
  for (const [k, b] of archive) r2.store.set(k, b);
  const targetKV = new TargetKV();

  const env = (): Env =>
    ({
      SCHEDULER: sched.ns,
      CF_ACCESS_TEAM_DOMAIN: TEAM,
      CF_ACCESS_AUD: AUD,
      WORKER_NAME: "downpipe-engine",
      DEST_KIND: "r2",
      DEST_R2: r2 as unknown as R2Bucket,
      SIGNER_PRIVATE: signerPrivateB64,
      OPERATIONAL_PRIVATE: b64urlEncode(op.identity),
      KV_TBS_TARGET: targetKV as unknown as KVNamespace,
    }) as unknown as Env;

  const OWNER = "tbs-owner@acme.example";
  const OWNER2 = "tbs-owner2@acme.example";
  const OPERATOR = "tbs-operator@acme.example";
  const APPROVER = "tbs-approver@acme.example";
  const call = async (email: string, path: string, body: unknown): Promise<{ status: number; json: Record<string, unknown> }> => {
    const r = await handleAdmin(
      new Request(`https://engine.example${path}`, {
        method: path === "/admin/whoami" ? "GET" : "POST",
        headers: { "cf-access-jwt-assertion": await signer.tokenFor(email), "content-type": "application/json", origin: "https://engine.example" },
        ...(path === "/admin/whoami" ? {} : { body: JSON.stringify(body) }),
      }),
      env(),
    );
    const text = await r.text();
    let json: Record<string, unknown> = {};
    try {
      json = JSON.parse(text) as Record<string, unknown>;
    } catch {
      json = { raw: text };
    }
    return { status: r.status, json };
  };
  const recordPutsInArchive = (): string[] => r2.puts.filter((k) => RECORD_KEYS.includes(k));

  console.log("-- setup: two Owners, an Operator and an Approver, restore approval off --");
  await call(OWNER, "/admin/whoami", undefined);
  for (const [email, role] of [
    [OWNER2, "owner"],
    [OPERATOR, "operator"],
    [APPROVER, "approver"],
  ] as const) {
    const g = await call(OWNER, "/admin/roles", { email, role });
    ok(`grant ${role}: 200`, g.status === 200);
  }

  console.log("\n-- positive control: a restore to an ordinary binding writes the three records there --");
  {
    const dry = await call(OWNER, "/admin/restore", { runId: RUN_ID, target: { binding: "KV_TBS_TARGET" } });
    const plan = dry.json as unknown as RestorePlan;
    ok(`dry run 200 ok:true plannedWrites 3 (${dry.status} ok=${plan.ok} writes=${plan.plannedWrites})`, dry.status === 200 && plan.ok === true && plan.plannedWrites === 3);
    __advanceAuditFoldClockForTest(AUDIT_FOLD_WINDOW_MS);
    const apply = await call(OWNER, "/admin/restore", { runId: RUN_ID, confirm: true, target: { binding: "KV_TBS_TARGET" } });
    const res = apply.json as unknown as RestoreResult;
    ok(`apply 200 restored 3 (${apply.status} restored=${res.recordsRestored})`, apply.status === 200 && res.recordsRestored === 3);
    ok("the three records are in the target KV", RECORD_KEYS.every((k) => targetKV.store.has(k)));
    targetKV.store.clear();
  }

  console.log('\n-- negative control: the string "DEST_R2" is refused as reserved and writes nothing --');
  {
    const before = r2.puts.length;
    const dry = await call(OWNER, "/admin/restore", { runId: RUN_ID, target: { binding: "DEST_R2" } });
    const plan = dry.json as unknown as RestorePlan & { reason?: string };
    ok(`dry run refuses the reserved string (${dry.status} ok=${plan.ok} reason=${plan.reason})`, plan.ok === false && plan.reason === "target binding is reserved");
    __advanceAuditFoldClockForTest(AUDIT_FOLD_WINDOW_MS);
    const apply = await call(OWNER, "/admin/restore", { runId: RUN_ID, confirm: true, target: { binding: "DEST_R2" } });
    const res = apply.json as unknown as RestoreResult;
    ok(`apply refuses the reserved string (${apply.status} ok=${res.ok} reason=${res.reason})`, res.ok === false && res.reason === "target binding is reserved" && (res.recordsRestored ?? 0) === 0);
    ok("no put reached the archive bucket", r2.puts.length === before);
  }

  console.log("\n-- the malformed values, each through the router: dry run, then an Owner apply --");
  for (const c of CASES) {
    console.log(`\n  [${c.label}]`);
    const before = r2.puts.length;
    const body = { runId: RUN_ID, target: { binding: c.binding } };
    const dry = await call(OWNER, "/admin/restore", body);
    const plan = dry.json as unknown as RestorePlan & { reason?: string };
    const rows = Array.isArray(plan.sample) ? plan.sample : [];
    console.log(`  info dry run: ${dry.status} ok=${plan.ok} reason=${plan.reason ?? "-"} plannedWrites=${plan.plannedWrites} sampleBindings=${JSON.stringify(rows.map((r) => (r as { binding?: unknown }).binding))} skipped=${JSON.stringify((plan.skipped ?? []).map((s) => s.reason))}`);
    const dryRefused = dry.status >= 400 && dry.status < 500;
    // SAFE: the dry run never plans a write. A coerced reserved name must not show as a planned write, and
    // an inherited name is not a binding, so it must not show as one either.
    ok(`[${c.label}] dry run plans no write (4xx, or plannedWrites 0)`, dryRefused || plan.plannedWrites === 0);
    if (c.malformed) ok(`[${c.label}] a malformed binding is refused 4xx before any planning (${dry.status})`, dryRefused);

    __advanceAuditFoldClockForTest(AUDIT_FOLD_WINDOW_MS);
    let applyStatus = 0;
    let res: RestoreResult | undefined;
    let threw = "";
    try {
      const apply = await call(OWNER, "/admin/restore", { ...body, confirm: true });
      applyStatus = apply.status;
      res = apply.json as unknown as RestoreResult;
    } catch (e) {
      threw = (e as Error).message;
    }
    const newRecordPuts = r2.puts.slice(before).filter((k) => RECORD_KEYS.includes(k));
    console.log(`  info apply: ${applyStatus || "threw"} ok=${res?.ok} reason=${res?.reason ?? "-"} restored=${res?.recordsRestored} failures=${JSON.stringify((res?.failures ?? []).slice(0, 1))}${threw ? ` threw=${threw}` : ""} archivePuts=${JSON.stringify(r2.puts.slice(before))}`);
    ok(`[${c.label}] the apply writes NO restore record into the reserved archive bucket DEST_R2 (puts: ${JSON.stringify(newRecordPuts)})`, newRecordPuts.length === 0);
    ok(`[${c.label}] the apply restores nothing`, (res?.recordsRestored ?? 0) === 0);
    if (c.reaches !== null) ok(`[${c.label}] the apply does not report success`, res?.ok !== true);
    if (c.reaches !== null) ok(`[${c.label}] the apply is refused as reserved or as malformed (${applyStatus} ${res?.reason ?? ""})`, (applyStatus >= 400 && applyStatus < 500) || res?.reason === "target binding is reserved");
    if (c.malformed) ok(`[${c.label}] a malformed binding apply is refused 4xx (${applyStatus})`, applyStatus >= 400 && applyStatus < 500);
    // Put the archive back exactly as it was, so the next case reads a clean destination.
    for (const k of newRecordPuts) r2.store.delete(k);
  }

  console.log("\n-- plan hash and the approval path --");
  {
    const hArr = await restorePlanHash({ runId: RUN_ID, target: { binding: ["DEST_R2"] } } as unknown as RestoreRequest);
    const hStr = await restorePlanHash({ runId: RUN_ID, target: { binding: "DEST_R2" } } as unknown as RestoreRequest);
    const hNest = await restorePlanHash({ runId: RUN_ID, target: { binding: [["DEST_R2"]] } } as unknown as RestoreRequest);
    console.log(`  info planHash array=${hArr.slice(0, 16)} string=${hStr.slice(0, 16)} nested=${hNest.slice(0, 16)}`);
    ok("the plan hash separates the array from the string (no hash collision between the two)", hArr !== hStr && hArr !== hNest);

    const arm = await call(OWNER, "/admin/config/restore-approval-policy", { requireRestoreApproval: true });
    ok(`arm requireRestoreApproval: ${arm.status}`, arm.status === 200);
    const reqBody = { runId: RUN_ID, target: { binding: ["DEST_R2"] } };
    await call(OPERATOR, "/admin/restore", reqBody);
    const raised = await call(OPERATOR, "/admin/restore/request", { ...reqBody, reason: "tbs array target" });
    console.log(`  info request: ${raised.status} ${JSON.stringify(raised.json).slice(0, 160)}`);
    ok(`an approval request for a non-string binding is refused 4xx (${raised.status})`, raised.status >= 400 && raised.status < 500);
    if (raised.status === 200) {
      const inbox = await handleAdmin(
        new Request("https://engine.example/admin/restore/approvals", { headers: { "cf-access-jwt-assertion": await signer.tokenFor(APPROVER), origin: "https://engine.example" } }),
        env(),
      );
      const recs = (await inbox.json()) as Array<{ planHash: string; redirectBinding: unknown }>;
      const rec = recs.find((r) => r.planHash === hArr);
      console.log(`  info approver inbox record: redirectBinding=${JSON.stringify(rec?.redirectBinding)}`);
      ok("the approver's record does not present the array target as Original bindings (redirectBinding null)", rec !== undefined && rec.redirectBinding !== null);
      ageRecord(sched.storage, approvalKey(hArr), "requestedAt", APPROVAL_MIN_DWELL_MS + 1000);
      const ap = await call(APPROVER, "/admin/restore/approve", { planHash: hArr });
      console.log(`  info approve: ${ap.status} redirectBinding=${JSON.stringify(ap.json.redirectBinding)}`);
      const before = r2.puts.length;
      __advanceAuditFoldClockForTest(AUDIT_FOLD_WINDOW_MS);
      const apply = await call(OWNER, "/admin/restore", { ...reqBody, confirm: true });
      const res = apply.json as unknown as RestoreResult;
      const newRecordPuts = r2.puts.slice(before).filter((k) => RECORD_KEYS.includes(k));
      console.log(`  info approved apply: ${apply.status} ok=${res.ok} restored=${res.recordsRestored} archivePuts=${JSON.stringify(r2.puts.slice(before))}`);
      ok(`an APPROVED apply of the array target writes nothing into DEST_R2 (puts: ${JSON.stringify(newRecordPuts)})`, newRecordPuts.length === 0);
    }
  }

  console.log("\n-- a non-string target never reaches the approval inbox --");
  {
    const listInbox = async (): Promise<Array<{ planHash: string; redirectBinding: unknown; status: string }>> => {
      const r = await handleAdmin(
        new Request("https://engine.example/admin/restore/approvals", { headers: { "cf-access-jwt-assertion": await signer.tokenFor(APPROVER), origin: "https://engine.example" } }),
        env(),
      );
      return (await r.json()) as Array<{ planHash: string; redirectBinding: unknown; status: string }>;
    };
    const hArr = await restorePlanHash({ runId: RUN_ID, target: { binding: ["DEST_R2"] } } as unknown as RestoreRequest);
    ok("the refused array request left no record in the approver's inbox", !(await listInbox()).some((r) => r.planHash === hArr));

    // The other restore routes refuse the same shape.
    for (const path of ["/admin/restore/verify", "/admin/restore/attest"]) {
      const r = await call(OWNER, path, { runId: RUN_ID, target: { binding: ["DEST_R2"] } });
      ok(`${path} refuses an array target.binding 4xx (${r.status})`, r.status >= 400 && r.status < 500);
    }
    for (const field of ["namespaceId", "bucketName"]) {
      const r = await call(OWNER, "/admin/restore", { runId: RUN_ID, target: { [field]: ["ns"] } });
      ok(`/admin/restore refuses an array target.${field} 400 (${r.status})`, r.status === 400);
    }

    // The DO's own check, for a caller that reaches it without the router.
    const operatorCaller = { method: "access" as const, email: OPERATOR, subject: "tbs-operator-sub", role: "operator" as const };
    const doRequest = async (req: Record<string, unknown>): Promise<string> => {
      try {
        await sched.dobj.requestRestore(req as Parameters<SchedulerDO["requestRestore"]>[0], operatorCaller);
        return "accepted";
      } catch (e) {
        return (e as Error).message;
      }
    };
    // A plan hash with no record yet, so a refusal can only be the target check. Each refusal must name the
    // malformed target, not a later check such as the missing dry-run anchor.
    const nestReq = { runId: RUN_ID, target: { binding: [["DEST_R2"]] } } as unknown as RestoreRequest;
    const hNest = await restorePlanHash(nestReq);
    const r1 = await doRequest({ planHash: hNest, runId: RUN_ID, reason: "tbs do", redirectBinding: null, plan: restorePlanBinding(nestReq) });
    console.log(`  info DO request with a nested-array plan target: ${r1}`);
    ok("the DO refuses a plan whose target.binding is not a string, as a malformed target", r1.includes("malformed"));
    const r2 = await doRequest({ planHash: hNest, runId: RUN_ID, reason: "tbs do", redirectBinding: ["DEST_R2"] });
    console.log(`  info DO request with an array redirectBinding: ${r2}`);
    ok("the DO refuses a redirectBinding that is not a string, as a malformed target", r2.includes("malformed"));
    ok("neither DO request stored a record", sched.storage.rawGet(approvalKey(hNest)) === undefined);
    ok("the refused router request stored no record either", sched.storage.rawGet(approvalKey(hArr)) === undefined);

    // A record stored before the check: a valid request, then its stored plan rewritten to carry the array
    // with redirectBinding null, the shape the old DO stored.
    const strBody = { runId: RUN_ID, target: { binding: "KV_TBS_TARGET" } };
    await call(OPERATOR, "/admin/restore", strBody);
    const raised = await call(OPERATOR, "/admin/restore/request", { ...strBody, reason: "tbs legacy record" });
    ok(`a string target request is accepted (${raised.status})`, raised.status === 200);
    const hStr = await restorePlanHash(strBody as RestoreRequest);
    const stored = sched.storage.rawGet<{ redirectBinding: unknown; plan: { target: { binding: unknown } } }>(approvalKey(hStr));
    if (stored !== undefined) {
      stored.plan.target.binding = ["DEST_R2"];
      stored.redirectBinding = null;
      sched.storage.rawPut(approvalKey(hStr), stored);
    }
    const legacy = (await listInbox()).find((r) => r.planHash === hStr);
    console.log(`  info inbox view of the legacy record: redirectBinding=${JSON.stringify(legacy?.redirectBinding)}`);
    ok("the inbox does not show a legacy array target as no redirect (redirectBinding not null)", legacy !== undefined && legacy.redirectBinding !== null && String(legacy.redirectBinding).includes("DEST_R2"));
    ageRecord(sched.storage, approvalKey(hStr), "requestedAt", APPROVAL_MIN_DWELL_MS + 1000);
    const ap = await call(APPROVER, "/admin/restore/approve", { planHash: hStr });
    console.log(`  info approve of the legacy record: ${ap.status} ${JSON.stringify(ap.json).slice(0, 160)}`);
    ok(`the legacy record with an array target cannot be approved (${ap.status})`, ap.status >= 400 && ap.status < 500);
    ok("the legacy record is not approved", (await listInbox()).find((r) => r.planHash === hStr)?.status !== "approved");
  }

  console.log("\n-- guardTarget itself, behind the router check --");
  {
    const guard = (v: unknown): string => {
      try {
        return `returned ${guardTarget(v as string)}`;
      } catch (e) {
        return (e as Error).message;
      }
    };
    for (const v of [["DEST_R2"], [["DEST_R2"]], 42, {}, null]) ok(`guardTarget(${JSON.stringify(v)}) refuses as reserved`, guard(v) === RESERVED_REASON);
    ok('guardTarget("DEST_R2") refuses as reserved', guard("DEST_R2") === RESERVED_REASON);
    ok('guardTarget("KV-not-a-name") refuses as not present', /is not present in the environment/.test(guard("KV-not-a-name")));
    ok('guardTarget("KV_TBS_TARGET") returns the name', guard("KV_TBS_TARGET") === "returned KV_TBS_TARGET");
  }

  ok("over the whole run, no restore record was ever written into the archive bucket", recordPutsInArchive().length === 0);

  signer.restoreFetch();
  console.log(failures === 0 ? "\nRESTORE TARGET BINDING SHAPE PASS" : `\n${failures} FAILURE(S) of ${checks}`);
  verdictReached(failures, checks);
  if (failures > 0) process.exit(1);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
