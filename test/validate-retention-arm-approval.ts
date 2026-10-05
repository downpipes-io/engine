// validate-retention-arm-approval: a retention setting that one Operator arms alone must never make the
// unattended cron retention pass delete a run that the attended prune route would only delete after a
// dual-control approval.
//
// THE PROPERTY. The attended prune route (POST /admin/retention-prune/apply) needs restore.apply AND a
// usable prune approval from a distinct approver before it deletes. The cron pass (runRetentionPrunes)
// deletes whenever the stored retention.enforce is true. So the step that sets enforce to true must carry
// the same approval, or the cron must not act on an unapproved enforce. This file asserts the safe
// outcome only: either the Operator's arm is refused or queued (not 200), or the cron pass deletes no
// object. It does not care which of the two a fix picks.
//
// IT IS DRIVEN, NOT READ. The Operator is a real Access identity (a verified RS256 JWT against a stubbed
// JWKS) that the real handleAdmin router resolves against the real SchedulerDO over test/mock-storage.ts.
// The runs are real downpipe/0.1.0 archives sealed by the real writer into an R2-shaped store, and the
// cron pass is the real exported runRetentionPrunes. A cell passes or fails because bytes did or did not
// leave the store.
//
// THE POPULATION IS ASSERTED. "The cron deleted nothing" is also true of a fixture with nothing to delete,
// so a twin downpipe with the same runs, armed by the same Operator with enforce false (dry-run), must be
// planned by the same cron pass with 2 superseded runs. That twin never needs an approval, so it holds on
// the defect and on any fix.
//
// ARM.6 to ARM.9 pin the fix's shape: addDownpipe asks for restore.apply on an edit that lets the cron delete
// more (arming enforce, or lowering a bound, removing a bound or unpinning a replica while enforce is on),
// on the single, bulk and queued routes, and leaves narrowing edits on downpipe.write alone.
//
// Posture: operational-key (OPERATIONAL_PRIVATE is set), the only posture in which the cron can prune.
// Run: node test/validate-retention-arm-approval.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { APPROVAL_MIN_DWELL_MS } from "../src/admin/approvals.ts";
import { changeKey } from "../src/admin/change-control.ts";
import { ROLE_CAPABILITIES } from "../src/admin/identity-rbac.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { runRetentionPrunes } from "../src/cron/retention-pass.ts";
import type { RetentionPassRecord } from "../src/cron/retention-record.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import type { Env } from "../src/env.d.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { type RunlogEntry, signRunlog } from "../src/format/writer-runlog.ts";
import { loadSigner } from "../src/keys-env.ts";
import { retentionWidensPrune } from "../src/sched/destinations.ts";
import { type DownpipeConfig, SchedulerDO } from "../src/sched/scheduler-do.ts";
import { AuthError } from "../src/sched/scheduler-do-base.ts";
import { DESTINATIONS_KEY } from "../src/sched/scheduler-do-records.ts";
import { runTreePrefix } from "../src/seal/prune.ts";
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
function info(label: string): void {
  console.log(`  info ${label}`);
}

const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));

// The raw R2 binding surface buildDestination("r2") reads; the cron's deletes land here.
class R2Double {
  store = new Map<string, Uint8Array>();
  async get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer>; etag: string } | null> {
    const v = this.store.get(key);
    if (!v) return null;
    return { arrayBuffer: async () => v.slice().buffer as ArrayBuffer, etag: `"${key.length}:${v.length}"` };
  }
  async head(key: string): Promise<{ etag: string } | null> {
    const v = this.store.get(key);
    return v ? { etag: `"${key.length}:${v.length}"` } : null;
  }
  async put(key: string, body: ArrayBuffer | Uint8Array): Promise<{ etag: string }> {
    const b = body instanceof Uint8Array ? body : new Uint8Array(body);
    this.store.set(key, b);
    return { etag: `"${key.length}:${b.length}"` };
  }
  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }
  async list(opts: { prefix?: string }): Promise<{ objects: Array<{ key: string }>; truncated: boolean }> {
    const p = opts.prefix ?? "";
    return { objects: [...this.store.keys()].filter((k) => k.startsWith(p)).map((key) => ({ key })), truncated: false };
  }
}

function recipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

const OWNER = "owner-s16@acme.example";
const OWNER2 = "owner2-s16@acme.example";
const ROLE_EMAILS: Record<string, string> = {
  operator: "operator-s16@acme.example",
  approver: "approver-s16@acme.example",
  viewer: "viewer-s16@acme.example",
  "restore-operator": "restoreop-s16@acme.example",
  "access-admin": "accessadmin-s16@acme.example",
};
const OPERATOR = ROLE_EMAILS.operator!;
const APPROVER = ROLE_EMAILS.approver!;

interface Rig {
  storage: MockStorage;
  dobj: SchedulerDO;
  r2: R2Double;
  env: Env;
  stub: DurableObjectStub;
  call: (email: string, method: "GET" | "POST", path: string, body?: unknown) => Promise<Response>;
  sealRuns: (dpId: string, runIds: string[], startIndex?: number, prev?: string | null) => Promise<RunlogEntry[]>;
  writeRunlog: (entries: RunlogEntry[]) => Promise<void>;
}

type JwtSigner = Awaited<ReturnType<typeof makeSigner>>;

async function buildRig(jwt: JwtSigner): Promise<Rig> {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = { idFromName: () => ({}), get: () => stub } as unknown as DurableObjectNamespace;
  const signerB64 = b64urlEncode(concat(rand(32), rand(32)));
  const signer: Signer = await loadSigner(signerB64);
  const bg = recipient("break-glass");
  const op = recipient("operational");
  const r2 = new R2Double();
  const env = {
    SCHEDULER: namespace,
    CF_ACCESS_TEAM_DOMAIN: TEAM,
    CF_ACCESS_AUD: AUD,
    DEST_KIND: "r2",
    DEST_R2: r2 as unknown as R2Bucket,
    SIGNER_PRIVATE: signerB64,
    OPERATIONAL_PRIVATE: b64urlEncode(op.identity), // the operational-key posture
  } as unknown as Env;
  const call = async (email: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> =>
    handleAdmin(
      new Request(`https://engine.example${path}`, {
        method,
        headers: { "cf-access-jwt-assertion": await jwt.tokenFor(email), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      }),
      env,
    );
  const master = rand(32);
  // The RUNLOG is destination-wide, so index and prevRunId chain across downpipes in seal order.
  const sealRuns = async (dpId: string, runIds: string[], startIndex = 1, prev: string | null = null): Promise<RunlogEntry[]> => {
    const out: RunlogEntry[] = [];
    for (let i = 0; i < runIds.length; i++) {
      const index = startIndex + i;
      const prevRunId = i ? runIds[i - 1]! : prev;
      const at = `2026-06-0${i + 1}T00:00:00.000Z`;
      const arch = await buildArchive({
        downpipeId: dpId,
        downpipeName: dpId,
        cadence: "3600s",
        runId: runIds[i]!,
        master,
        recipients: [bg.entry, op.entry],
        signer,
        records: [{ sourceType: "kv", name: "k", value: utf8(`${dpId}-v${i}`), namespace: "ns" }],
        windowStart: at,
        windowEnd: at,
        createdAt: at,
        runlogIndex: index,
        prevRunId,
        skipRunlog: true,
        randomNonce: () => rand(16),
        randomSalt: () => rand(16),
      });
      for (const [k, b] of arch) r2.store.set(k, b);
      out.push({ index, runId: runIds[i]!, downpipeId: dpId, time: at, recordCount: 1, prevRunId, status: "active" });
    }
    return out;
  };
  const writeRunlog = async (entries: RunlogEntry[]): Promise<void> => {
    const { runlog, sig } = await signRunlog(entries, signer.edPrivate, signer.mldsaSecret);
    r2.store.set("_RECOVERY/RUNLOG", runlog);
    r2.store.set("_RECOVERY/RUNLOG.sig", utf8(b64urlEncode(sig)));
  };
  return { storage, dobj, r2, env, stub, call, sealRuns, writeRunlog };
}

function baseConfig(id: string): Record<string, unknown> {
  return { id, name: id, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: `KV_${id}`, include: [], exclude: [] } };
}

async function storedConfig(rig: Rig, id: string): Promise<DownpipeConfig | undefined> {
  const list = (await (await rig.call(OWNER, "GET", "/admin/downpipes")).json()) as Array<{ config: DownpipeConfig }>;
  return list.find((d) => d.config.id === id)?.config;
}

// seedDestinations writes a destination collection straight into the DO, so a downpipe can pin replicas.
// addDownpipe checks only that each pinned id names a live destination; nothing here is dialled.
function seedDestinations(rig: Rig, ids: string[]): void {
  const list = ids.map((id) => ({ id, label: id, endpoint: "https://acct.r2.cloudflarestorage.com", bucket: `b-${id}`, region: "auto", accessKeyId: "AK", secretAccessKey: "SK", setAt: 1, setBy: OWNER }));
  rig.storage.rawPut(DESTINATIONS_KEY, { list, defaultId: ids[0]! });
}

async function storedRetention(rig: Rig, id: string): Promise<{ keepRuns?: number; enforce?: boolean } | undefined> {
  const list = (await (await rig.call(OWNER, "GET", "/admin/downpipes")).json()) as Array<{ config: { id: string; retention?: { keepRuns?: number; enforce?: boolean } } }>;
  return list.find((d) => d.config.id === id)?.config.retention;
}

async function passRecord(rig: Rig): Promise<RetentionPassRecord | null> {
  const r = await rig.stub.fetch("https://do/retention-state", { method: "GET" });
  return ((await r.json()) as { record?: RetentionPassRecord | null }).record ?? null;
}

const treeCount = (rig: Rig, runId: string): number => [...rig.r2.store.keys()].filter((k) => k.startsWith(runTreePrefix(runId))).length;

const RUNS_A = ["01ARZ3NDEKTSV4RRFFQ69G5FA0", "01ARZ3NDEKTSV4RRFFQ69G5FA1", "01ARZ3NDEKTSV4RRFFQ69G5FA2"];
const RUNS_B = ["01ARZ3NDEKTSV4RRFFQ69G5FB0", "01ARZ3NDEKTSV4RRFFQ69G5FB1", "01ARZ3NDEKTSV4RRFFQ69G5FB2"];

async function main(): Promise<void> {
  console.log("validate-retention-arm-approval: an Operator's lone retention arm never drives an unapproved cron prune\n");
  const jwt = await makeSigner();
  try {
    // ---- ARM.0 setup: one Owner (first Access sign-in bootstraps it), one Operator, two downpipes with
    // three sealed runs each. dp_armed gets enforce true from the Operator; dp_twin gets enforce false. ----
    console.log("ARM.0 setup (operational-key posture, one Owner, one Operator)");
    const rig = await buildRig(jwt);
    const who = (await (await rig.call(OWNER, "GET", "/admin/whoami")).json()) as { role?: string };
    ok("the first Access caller is bootstrapped as Owner", who.role === "owner");
    ok("the Owner grants the Operator role (200)", (await rig.call(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "operator" })).status === 200);
    const whoOp = (await (await rig.call(OPERATOR, "GET", "/admin/whoami")).json()) as { role?: string };
    ok("the Operator resolves as operator", whoOp.role === "operator");
    ok("the Owner creates dp_armed with no retention (200)", (await rig.call(OWNER, "POST", "/admin/downpipes", baseConfig("dp_armed"))).status === 200);
    ok("the Owner creates dp_twin with no retention (200)", (await rig.call(OWNER, "POST", "/admin/downpipes", baseConfig("dp_twin"))).status === 200);
    const entries = [...(await rig.sealRuns("dp_armed", RUNS_A)), ...(await rig.sealRuns("dp_twin", RUNS_B, 4, RUNS_A[2]!))];
    await rig.writeRunlog(entries);
    ok("every run tree is populated before the pass", [...RUNS_A, ...RUNS_B].every((r) => treeCount(rig, r) > 0));

    // ---- ARM.1 the control: the Operator cannot prune through the attended route. ----
    console.log("\nARM.1 control: the attended prune route refuses the Operator");
    const att = await rig.call(OPERATOR, "POST", "/admin/retention-prune/apply", { downpipeId: "dp_armed", batch: [] });
    ok(`the Operator is refused at POST /admin/retention-prune/apply (${att.status})`, att.status === 403);

    // ---- ARM.2 the Operator arms retention alone. ----
    console.log("\nARM.2 the Operator arms retention on both downpipes, alone");
    const arm = await rig.call(OPERATOR, "POST", "/admin/downpipes", { ...baseConfig("dp_armed"), retention: { keepRuns: 1, enforce: true } });
    const armStatus = arm.status;
    info(`Operator upsert {keepRuns:1, enforce:true} on dp_armed answered ${armStatus}`);
    const twin = await rig.call(OPERATOR, "POST", "/admin/downpipes", { ...baseConfig("dp_twin"), retention: { keepRuns: 1, enforce: false } });
    ok(`the Operator's dry-run arm on dp_twin is accepted (${twin.status})`, twin.status === 200);
    const armed = await storedRetention(rig, "dp_armed");
    info(`stored retention on dp_armed after the Operator's arm: ${JSON.stringify(armed)}`);

    // ---- ARM.3 the unattended cron pass. ----
    console.log("\nARM.3 the cron retention pass runs with no prune approval on record");
    const before = RUNS_A.map((r) => treeCount(rig, r));
    await runRetentionPrunes(rig.env, rig.stub);
    const after = RUNS_A.map((r) => treeCount(rig, r));
    info(`dp_armed run-tree object counts before ${JSON.stringify(before)} after ${JSON.stringify(after)}`);
    const rec = await passRecord(rig);
    const armedRow = rec?.downpipes.find((d) => d.id === "dp_armed");
    const twinRow = rec?.downpipes.find((d) => d.id === "dp_twin");
    info(`pass record dp_armed row: ${JSON.stringify(armedRow)}`);

    // Population: the same pass planned real work for the twin, so a zero on dp_armed is not an empty fixture.
    ok("population: the pass planned the dry-run twin with 2 superseded runs", twinRow?.outcome === "dry-run" && twinRow?.supersededRuns === 2);
    ok("population: the dry-run twin kept every run tree", RUNS_B.every((r) => treeCount(rig, r) > 0));

    // THE SAFE BEHAVIOUR. Either the arm did not take effect alone, or the cron did not delete.
    const armTookEffect = armStatus === 200 && armed?.enforce === true;
    const cronDeleted = after.some((n, i) => n < before[i]!);
    ok(
      `SAFE: an Operator's lone arm is refused or queued, or the cron deletes nothing (arm ${armStatus}, enforce stored ${String(armed?.enforce)}, cron deleted ${cronDeleted ? "objects" : "nothing"})`,
      !armTookEffect || !cronDeleted,
    );
    ok("SAFE: the over-cap run tree 1 of dp_armed survives the unattended pass", after[0]! === before[0]!);
    ok("SAFE: the over-cap run tree 2 of dp_armed survives the unattended pass", after[1]! === before[1]!);

    // ---- ARM.4 the opt-in mitigation: with requireConfigApproval on, the Operator's arm is queued. ----
    console.log("\nARM.4 opt-in mitigation: requireConfigApproval on queues the Operator's arm");
    {
      const r2rig = await buildRig(jwt);
      await r2rig.call(OWNER, "GET", "/admin/whoami");
      await r2rig.call(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "operator" });
      // The gate refuses to arm with one Owner (a lone Owner cannot approve their own change), so a
      // single-Owner estate cannot use this mitigation at all. A second Owner is granted first.
      ok("a second Owner is granted (200)", (await r2rig.call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "owner" })).status === 200);
      await r2rig.call(OWNER, "POST", "/admin/downpipes", baseConfig("dp_armed"));
      await r2rig.writeRunlog(await r2rig.sealRuns("dp_armed", RUNS_A));
      ok("the Owner arms requireConfigApproval (200)", (await r2rig.call(OWNER, "POST", "/admin/config/approval-policy", { requireConfigApproval: true })).status === 200);
      const q = await r2rig.call(OPERATOR, "POST", "/admin/downpipes", { ...baseConfig("dp_armed"), retention: { keepRuns: 1, enforce: true } });
      ok(`the Operator's arm is not applied inline (${q.status})`, q.status !== 200);
      const b4 = RUNS_A.map((r) => treeCount(r2rig, r));
      await runRetentionPrunes(r2rig.env, r2rig.stub);
      ok("the cron deletes nothing while the arm waits for approval", RUNS_A.every((r, i) => treeCount(r2rig, r) === b4[i]));
    }

    // ---- ARM.5 report: which roles can arm enforce, and can one Owner alone. Information, not a verdict. ----
    console.log("\nARM.5 report: who can arm enforce, and what one Owner alone reaches");
    {
      const r3 = await buildRig(jwt);
      await r3.call(OWNER, "GET", "/admin/whoami");
      for (const [role, email] of Object.entries(ROLE_EMAILS)) {
        const g = await r3.call(OWNER, "POST", "/admin/roles", { email, role });
        const id = `dp_role_${role.replace("-", "_")}`;
        await r3.call(OWNER, "POST", "/admin/downpipes", baseConfig(id));
        const r = await r3.call(email, "POST", "/admin/downpipes", { ...baseConfig(id), retention: { keepRuns: 1, enforce: true } });
        const st = await storedRetention(r3, id);
        info(`role ${role} (grant ${g.status}): arm answered ${r.status}, stored enforce ${String(st?.enforce)}`);
      }
      // One Owner alone, default policy, no second identity at all.
      const r4 = await buildRig(jwt);
      await r4.call(OWNER, "GET", "/admin/whoami");
      await r4.call(OWNER, "POST", "/admin/downpipes", baseConfig("dp_owner"));
      await r4.writeRunlog(await r4.sealRuns("dp_owner", RUNS_A));
      const oa = await r4.call(OWNER, "POST", "/admin/downpipes", { ...baseConfig("dp_owner"), retention: { keepRuns: 1, enforce: true } });
      const ob = RUNS_A.map((r) => treeCount(r4, r));
      await runRetentionPrunes(r4.env, r4.stub);
      const oaft = RUNS_A.map((r) => treeCount(r4, r));
      info(`single Owner alone: arm answered ${oa.status}, run trees before ${JSON.stringify(ob)} after cron ${JSON.stringify(oaft)}`);
      // Two Owners, default policy: does a second Owner's existence change anything for a lone arm?
      const r5 = await buildRig(jwt);
      await r5.call(OWNER, "GET", "/admin/whoami");
      const g2 = await r5.call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "owner" });
      await r5.call(OWNER, "POST", "/admin/downpipes", baseConfig("dp_owner"));
      await r5.writeRunlog(await r5.sealRuns("dp_owner", RUNS_A));
      const oa2 = await r5.call(OWNER, "POST", "/admin/downpipes", { ...baseConfig("dp_owner"), retention: { keepRuns: 1, enforce: true } });
      const ob2 = RUNS_A.map((r) => treeCount(r5, r));
      await runRetentionPrunes(r5.env, r5.stub);
      info(`two Owners (grant ${g2.status}), one arms alone: arm answered ${oa2.status}, run trees before ${JSON.stringify(ob2)} after cron ${JSON.stringify(RUNS_A.map((r) => treeCount(r5, r)))}`);
    }

    // ---- ARM.6 the widening rule, edit by edit. An Owner arms dp_w with two bounds and one replica. The
    // Operator is refused on every edit that lets the cron delete more, and allowed on every edit that keeps
    // more or turns enforce off. An Approver (restore.apply) is not refused a widening edit, so the gate is the
    // capability and not a blanket refusal. Each refusal also leaves the stored config as it was. ----
    console.log("\nARM.6 widening edits need restore.apply; narrowing edits do not");
    {
      const r6 = await buildRig(jwt);
      await r6.call(OWNER, "GET", "/admin/whoami");
      await r6.call(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "operator" });
      seedDestinations(r6, ["d1", "d2", "d3"]);
      const dpW = (over: Record<string, unknown>): Record<string, unknown> => ({ ...baseConfig("dp_w"), destinationIds: ["d1", "d2"], ...over });
      const armed = { keepRuns: 5, keepDays: 30, enforce: true };
      // The Owner arms before the Approver is granted: with a second restore.approve holder the arm would queue
      // for their approval (validate-retention-arm-dualcontrol.ts), and this section is about the Operator.
      ok("the Owner arms dp_w with keepRuns 5, keepDays 30 and replica d2 (200)", (await r6.call(OWNER, "POST", "/admin/downpipes", dpW({ retention: armed }))).status === 200);
      await r6.call(OWNER, "POST", "/admin/roles", { email: APPROVER, role: "approver" });
      const snap = async (): Promise<string> => JSON.stringify(await storedConfig(r6, "dp_w").then((c) => ({ r: c?.retention, d: c?.destinationIds })));
      const widening: Array<[string, Record<string, unknown>]> = [
        ["lowers keepRuns 5 to 4", dpW({ retention: { ...armed, keepRuns: 4 } })],
        ["lowers keepDays 30 to 29", dpW({ retention: { ...armed, keepDays: 29 } })],
        ["removes the keepDays bound", dpW({ retention: { keepRuns: 5, enforce: true } })],
        ["removes the keepRuns bound", dpW({ retention: { keepDays: 30, enforce: true } })],
        ["unpins replica d2", dpW({ destinationIds: ["d1"], retention: armed })],
        ["makes replica d2 the primary", dpW({ destinationIds: ["d2", "d1"], retention: armed })],
      ];
      for (const [label, body] of widening) {
        const before = await snap();
        const r = await r6.call(OPERATOR, "POST", "/admin/downpipes", body);
        ok(`the Operator's edit that ${label} while enforce is on is refused (${r.status})`, r.status === 403);
        ok(`  and the stored config is unchanged after the refused edit that ${label}`, (await snap()) === before);
      }
      const narrowing: Array<[string, Record<string, unknown>, (c: DownpipeConfig | undefined) => boolean]> = [
        ["round-trips the stored config", dpW({ retention: armed }), (c) => c?.retention?.keepRuns === 5],
        ["raises keepRuns 5 to 6", dpW({ retention: { ...armed, keepRuns: 6 } }), (c) => c?.retention?.keepRuns === 6],
        ["raises keepDays 30 to 31", dpW({ retention: { keepRuns: 6, keepDays: 31, enforce: true } }), (c) => c?.retention?.keepDays === 31],
        ["adds replica d3", dpW({ destinationIds: ["d1", "d2", "d3"], retention: { keepRuns: 6, keepDays: 31, enforce: true } }), (c) => c?.destinationIds?.length === 3],
        ["turns enforce off and lowers keepRuns to 1", dpW({ destinationIds: ["d1"], retention: { keepRuns: 1, enforce: false } }), (c) => c?.retention?.enforce === false && c?.retention?.keepRuns === 1],
        ["removes retention", dpW({ destinationIds: ["d1"] }), (c) => c?.retention === undefined],
      ];
      for (const [label, body, check] of narrowing) {
        const r = await r6.call(OPERATOR, "POST", "/admin/downpipes", body);
        ok(`the Operator's edit that ${label} is applied (${r.status})`, r.status === 200 && check(await storedConfig(r6, "dp_w")));
      }
      const create = await r6.call(OPERATOR, "POST", "/admin/downpipes", { ...baseConfig("dp_new"), retention: { keepRuns: 3, enforce: true } });
      ok(`the Operator's create of a downpipe with enforce on is refused (${create.status})`, create.status === 403 && (await storedConfig(r6, "dp_new")) === undefined);
      const createDry = await r6.call(OPERATOR, "POST", "/admin/downpipes", { ...baseConfig("dp_new"), retention: { keepRuns: 3 } });
      ok(`the Operator's create of a downpipe with a dry-run retention is applied (${createDry.status})`, createDry.status === 200);
      const ap = await r6.call(APPROVER, "POST", "/admin/downpipes", dpW({ destinationIds: ["d1"], retention: { keepRuns: 1, enforce: true } }));
      // Not refused: the Approver holds restore.apply. The Owner holds restore.approve, so the arm queues for them.
      ok(`control: the Approver's (restore.apply) arm is not refused; it queues for the Owner (${ap.status})`, ap.status === 202 && (await storedConfig(r6, "dp_w"))?.retention === undefined);
    }

    // ---- ARM.7 the bulk route runs each item through the same apply path. ----
    console.log("\nARM.7 the bulk upsert refuses the Operator's arm per item");
    {
      const r7 = await buildRig(jwt);
      await r7.call(OWNER, "GET", "/admin/whoami");
      await r7.call(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "operator" });
      const bulk = await r7.call(OPERATOR, "POST", "/admin/downpipes/bulk", {
        downpipes: [
          { ...baseConfig("dp_b1"), retention: { keepRuns: 1, enforce: true } },
          { ...baseConfig("dp_b2"), retention: { keepRuns: 1, enforce: false } },
        ],
      });
      const out = (await bulk.json()) as { results?: Array<{ id: string; status: string; error?: string }> };
      const row = (id: string) => out.results?.find((x) => x.id === id);
      info(`bulk answered ${bulk.status}: ${JSON.stringify(out.results)}`);
      ok("the armed item is refused as forbidden", row("dp_b1")?.status === "error" && row("dp_b1")?.error === "forbidden");
      ok("  and nothing is stored for it", (await storedConfig(r7, "dp_b1")) === undefined);
      ok("the dry-run item in the same batch is applied", row("dp_b2")?.status === "applied");
    }

    // ---- ARM.8 the queued path. With requireConfigApproval on, the propose-time dry run and the approve
    // replay both run addDownpipe as the PROPOSER. An Operator cannot queue an arm. An Approver's arm is queued
    // and applies on a distinct Owner's approval. The replay caller is the proposer's live authority, so an
    // arm replayed as an operator is refused and one replayed as an approver is not. ----
    console.log("\nARM.8 the queued path checks the proposer");
    {
      const r8 = await buildRig(jwt);
      await r8.call(OWNER, "GET", "/admin/whoami");
      await r8.call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "owner" });
      await r8.call(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "operator" });
      await r8.call(OWNER, "POST", "/admin/roles", { email: APPROVER, role: "approver" });
      await r8.call(OWNER, "POST", "/admin/downpipes", baseConfig("dp_q"));
      ok("the Owner arms requireConfigApproval (200)", (await r8.call(OWNER, "POST", "/admin/config/approval-policy", { requireConfigApproval: true })).status === 200);
      const armBody = { ...baseConfig("dp_q"), retention: { keepRuns: 1, enforce: true } };
      const opq = await r8.call(OPERATOR, "POST", "/admin/downpipes", armBody);
      ok(`the Operator cannot queue an arm (${opq.status})`, opq.status === 403);
      const apq = await r8.call(APPROVER, "POST", "/admin/downpipes", armBody);
      const qid = apq.status === 202 ? ((await apq.json()) as { id: string }).id : "";
      ok(`the Approver's arm is queued (${apq.status})`, qid !== "");
      ok("  and is not applied while it waits", (await storedRetention(r8, "dp_q")) === undefined);
      ageRecord(r8.storage, changeKey(qid), "proposedAt", APPROVAL_MIN_DWELL_MS + 1000);
      const appr = await r8.call(OWNER2, "POST", `/admin/config/changes/${qid}/approve`);
      ok(`a distinct Owner approves the Approver's arm and it applies (${appr.status})`, appr.status === 200 && (await storedRetention(r8, "dp_q"))?.enforce === true);
      const replay = (role: "operator" | "approver", email: string) => ({ method: "access" as const, email, subject: `sub-of-${email}`, groups: [], role, capabilities: ROLE_CAPABILITIES[role], replay: true as const });
      const replayArm = { ...baseConfig("dp_r"), retention: { keepRuns: 1, enforce: true } };
      let refused: unknown = null;
      try {
        await r8.dobj.applyConfigMutation("downpipe-upsert", replayArm, replay("operator", OPERATOR));
      } catch (e) {
        refused = e;
      }
      ok("an arm replayed with an operator's authority is refused (AuthError)", refused instanceof AuthError && (await storedConfig(r8, "dp_r")) === undefined);
      await r8.dobj.applyConfigMutation("downpipe-upsert", replayArm, replay("approver", APPROVER));
      ok("the same arm replayed with an approver's authority applies", (await storedRetention(r8, "dp_r"))?.enforce === true);
    }

    // ---- ARM.9 the pure rule, including the cases the routes above do not reach. ----
    console.log("\nARM.9 retentionWidensPrune");
    {
      const c = (retention?: DownpipeConfig["retention"], destinationIds?: string[]): DownpipeConfig =>
        ({ ...baseConfig("dp_p"), ...(retention !== undefined ? { retention } : {}), ...(destinationIds !== undefined ? { destinationIds } : {}) }) as unknown as DownpipeConfig;
      const on = { keepRuns: 5, keepDays: 30, enforce: true };
      const cases: Array<[string, DownpipeConfig | undefined, DownpipeConfig, boolean]> = [
        ["a create with enforce on", undefined, c({ keepRuns: 5, enforce: true }), true],
        ["a create with enforce off", undefined, c({ keepRuns: 5, enforce: false }), false],
        ["a create with no retention", undefined, c(), false],
        ["arming over a dry-run policy", c({ keepRuns: 5 }), c({ keepRuns: 5, enforce: true }), true],
        ["arming over no policy", c(), c({ keepRuns: 5, enforce: true }), true],
        ["an unchanged armed policy", c(on), c(on), false],
        ["lowering keepRuns", c(on), c({ ...on, keepRuns: 1 }), true],
        ["lowering keepDays", c(on), c({ ...on, keepDays: 1 }), true],
        ["removing keepRuns", c(on), c({ keepDays: 30, enforce: true }), true],
        ["removing keepDays", c(on), c({ keepRuns: 5, enforce: true }), true],
        ["raising both bounds", c(on), c({ ...on, keepRuns: 9, keepDays: 90 }), false],
        ["adding a bound to a one-bound policy", c({ keepRuns: 5, enforce: true }), c(on), false],
        ["turning enforce off", c(on), c({ keepRuns: 1, enforce: false }), false],
        ["removing retention", c(on), c(), false],
        ["unpinning a replica", c(on, ["d1", "d2"]), c(on, ["d1"]), true],
        ["swapping primary and replica", c(on, ["d1", "d2"]), c(on, ["d2", "d1"]), true],
        ["adding a replica", c(on, ["d1"]), c(on, ["d1", "d2"]), false],
        ["unpinning a replica with enforce off", c({ keepRuns: 5 }, ["d1", "d2"]), c({ keepRuns: 5 }, ["d1"]), false],
      ];
      for (const [label, prior, next, want] of cases) ok(`${label}: ${want ? "widens" : "does not widen"}`, retentionWidensPrune(prior, next) === want);
    }
  } finally {
    jwt.restoreFetch();
  }

  console.log(failures === 0 ? `\nRETENTION-ARM-APPROVAL PASS (${checks} checks)` : `\n${failures} FAILURE(S) of ${checks} checks`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

await main();
