// validate-retention-arm-dualcontrol: one person must not be able to arm the scheduled retention prune alone
// while a second person could approve it.
//
// THE PROPERTY. The attended prune route (POST /admin/retention-prune/apply) deletes only after a holder of
// restore.approve who is not the requester approves the plan. The cron retention pass deletes whenever the
// stored retention.enforce is true, with no approval of its own. So an upsert that lets the pass delete more
// (retentionWidensPrune) must wait for that same kind of second person whenever one exists:
//   RA.1 with two people who hold restore.approve, an Owner's arm answers 202 and is not stored, and the cron
//        deletes nothing while it waits;
//   RA.2 the same Owner cannot approve their own arm, and an Operator (downpipe.write, no restore.approve)
//        cannot approve it either;
//   RA.3 after a different Owner approves, the arm is stored and the cron prunes;
//   RA.4 narrowing edits (raise a bound, turn enforce off, a rename) stay immediate (200);
//   RA.5 the bare-token break-glass arms at once (200), and that is alerted and audited;
//   RA.6 in an estate with one Owner and no other restore.approve holder, the Owner's arm applies at once
//        (no deadlock), raises the retention-armed-alone alert at warning to an all-events webhook, and
//        writes a retention-armed-alone audit row;
//   RA.7 the bulk route queues the same arm per item.
//
// IT IS DRIVEN, NOT READ. Real Access identities (RS256 JWTs against a stubbed JWKS) go through the real
// handleAdmin router to the real SchedulerDO over test/mock-storage.ts. The runs are real archives sealed by
// the real writer into an R2-shaped store, and the cron pass is the real exported runRetentionPrunes. A cell
// passes or fails because bytes did or did not leave the store, or because a webhook post did or did not
// arrive.
//
// THE POPULATION IS ASSERTED. "The cron deleted nothing" is also true of a fixture with nothing to delete, so
// a twin downpipe armed with enforce false (dry-run) must be planned by the same pass with 2 superseded runs.
//
// Posture: operational-key (OPERATIONAL_PRIVATE is set), the only posture in which the cron can prune.
// Run: node test/validate-retention-arm-dualcontrol.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { APPROVAL_MIN_DWELL_MS } from "../src/admin/approvals.ts";
import { changeKey } from "../src/admin/change-control.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { runRetentionPrunes } from "../src/cron/retention-pass.ts";
import type { RetentionPassRecord } from "../src/cron/retention-record.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import type { Env } from "../src/env.d.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { type RunlogEntry, signRunlog } from "../src/format/writer-runlog.ts";
import { loadSigner } from "../src/keys-env.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
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
const BG_TOKEN = "bg-retention-arm-token";
const SINK = "https://hooks.example.com/alert";

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

const OWNER = "owner-ra@acme.example";
const OWNER2 = "owner2-ra@acme.example";
const OPERATOR = "operator-ra@acme.example";

type JwtSigner = Awaited<ReturnType<typeof makeSigner>>;
interface Rig {
  storage: MockStorage;
  r2: R2Double;
  env: Env;
  stub: DurableObjectStub;
  call: (who: string, method: "GET" | "POST", path: string, body?: unknown) => Promise<Response>;
  sealRuns: (dpId: string, runIds: string[], startIndex?: number, prev?: string | null) => Promise<RunlogEntry[]>;
  writeRunlog: (entries: RunlogEntry[]) => Promise<void>;
}

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
    ADMIN_TOKEN: BG_TOKEN,
    DEST_KIND: "r2",
    DEST_R2: r2 as unknown as R2Bucket,
    SIGNER_PRIVATE: signerB64,
    OPERATIONAL_PRIVATE: b64urlEncode(op.identity),
  } as unknown as Env;
  // who is an email (a verified Access JWT) or "break-glass" (the bare admin token).
  const call = async (who: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> => {
    const auth = who === "break-glass" ? { authorization: `Bearer ${BG_TOKEN}` } : { "cf-access-jwt-assertion": await jwt.tokenFor(who) };
    return handleAdmin(
      new Request(`https://engine.example${path}`, {
        method,
        headers: { ...auth, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      }),
      env,
    );
  };
  const master = rand(32);
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
  return { storage, r2, env, stub, call, sealRuns, writeRunlog };
}

function baseConfig(id: string): Record<string, unknown> {
  return { id, name: id, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: `KV_${id}`, include: [], exclude: [] } };
}
const armBody = (id: string, keepRuns = 1): Record<string, unknown> => ({ ...baseConfig(id), retention: { keepRuns, enforce: true } });

async function storedRetention(rig: Rig, id: string): Promise<{ keepRuns?: number; enforce?: boolean } | undefined> {
  const list = (await (await rig.call(OWNER, "GET", "/admin/downpipes")).json()) as Array<{ config: { id: string; retention?: { keepRuns?: number; enforce?: boolean } } }>;
  return list.find((d) => d.config.id === id)?.config.retention;
}
async function passRecord(rig: Rig): Promise<RetentionPassRecord | null> {
  const r = await rig.stub.fetch("https://do/retention-state", { method: "GET" });
  return ((await r.json()) as { record?: RetentionPassRecord | null }).record ?? null;
}
async function auditHas(rig: Rig, action: string): Promise<boolean> {
  const text = await (await rig.call(OWNER, "GET", "/admin/audit?limit=1000")).text();
  return text.includes(`"action":"${action}"`);
}
async function wireSink(rig: Rig): Promise<boolean> {
  const ch = (await (await rig.call(OWNER, "POST", "/admin/notify/channels", { kind: "webhook", name: "arm-sink", url: SINK })).json()) as { channel?: { id?: string }; id?: string };
  const chId = ch.channel?.id ?? ch.id ?? "";
  const rule = await rig.call(OWNER, "POST", "/admin/notify/rules", { scope: { kind: "global" }, minSeverity: "warning", events: "all", channelIds: [chId], enabled: true });
  return chId !== "" && rule.status === 200;
}

const treeCount = (rig: Rig, runId: string): number => [...rig.r2.store.keys()].filter((k) => k.startsWith(runTreePrefix(runId))).length;
const RUNS_A = ["01ARZ3NDEKTSV4RRFFQ69G5RA0", "01ARZ3NDEKTSV4RRFFQ69G5RA1", "01ARZ3NDEKTSV4RRFFQ69G5RA2"];
const RUNS_B = ["01ARZ3NDEKTSV4RRFFQ69G5RB0", "01ARZ3NDEKTSV4RRFFQ69G5RB1", "01ARZ3NDEKTSV4RRFFQ69G5RB2"];

type Post = { event?: string; severity?: string; detail?: string };

async function main(): Promise<void> {
  console.log("validate-retention-arm-dualcontrol: arming the scheduled prune needs a second person when one exists\n");
  const jwt = await makeSigner();
  // Capture webhook posts; every other fetch goes to the JWKS stub, which throws on anything unexpected.
  const posts: Post[] = [];
  const jwksFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url === SINK) {
      try {
        posts.push(init && typeof init.body === "string" ? (JSON.parse(init.body) as Post) : {});
      } catch {
        posts.push({});
      }
      return new Response("ok", { status: 200 });
    }
    return jwksFetch(input, init);
  }) as typeof fetch;
  const armedAloneAlerts = (from: number): Post[] => posts.slice(from).filter((p) => p.event === "retention-armed-alone" && p.severity === "warning");

  try {
    // ---- RA.0 setup: two Owners (both hold restore.approve), one Operator, an all-events webhook rule, and
    // two downpipes with three sealed runs each. ----
    console.log("RA.0 setup (two Owners, one Operator, operational-key posture)");
    const rig = await buildRig(jwt);
    const who = (await (await rig.call(OWNER, "GET", "/admin/whoami")).json()) as { role?: string };
    ok("the first Access caller is bootstrapped as Owner", who.role === "owner");
    ok("a second Owner is granted (200)", (await rig.call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "owner" })).status === 200);
    ok("an Operator is granted (200)", (await rig.call(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "operator" })).status === 200);
    ok("a webhook channel and an all-events warning rule are wired", await wireSink(rig));
    ok("the Owner creates dp_a with no retention (200)", (await rig.call(OWNER, "POST", "/admin/downpipes", baseConfig("dp_a"))).status === 200);
    ok("the Owner creates dp_twin with no retention (200)", (await rig.call(OWNER, "POST", "/admin/downpipes", baseConfig("dp_twin"))).status === 200);
    await rig.writeRunlog([...(await rig.sealRuns("dp_a", RUNS_A)), ...(await rig.sealRuns("dp_twin", RUNS_B, 4, RUNS_A[2]!))]);
    ok("every run tree is populated before the pass", [...RUNS_A, ...RUNS_B].every((r) => treeCount(rig, r) > 0));

    // ---- RA.1 the Owner arms dp_a alone. ----
    console.log("\nRA.1 an Owner's arm with a second approver present is queued, and the cron prunes nothing");
    const postsBefore = posts.length;
    const arm = await rig.call(OWNER, "POST", "/admin/downpipes", armBody("dp_a"));
    const armText = await arm.text();
    info(`Owner upsert {keepRuns:1, enforce:true} on dp_a answered ${arm.status} ${armText.slice(0, 120)}`);
    const qid = arm.status === 202 ? ((JSON.parse(armText) as { id?: string }).id ?? "") : "";
    ok(`SAFE: the Owner's arm answers 202 queued (${arm.status})`, arm.status === 202 && qid !== "");
    ok("SAFE: enforce is not stored while the arm waits", (await storedRetention(rig, "dp_a"))?.enforce !== true);
    ok("the dry-run twin is applied at once (200)", (await rig.call(OWNER, "POST", "/admin/downpipes", { ...baseConfig("dp_twin"), retention: { keepRuns: 1, enforce: false } })).status === 200);
    const before = RUNS_A.map((r) => treeCount(rig, r));
    await runRetentionPrunes(rig.env, rig.stub);
    const after1 = RUNS_A.map((r) => treeCount(rig, r));
    const rec = await passRecord(rig);
    info(`dp_a run-tree counts before ${JSON.stringify(before)} after the pass ${JSON.stringify(after1)}`);
    const twinRow = rec?.downpipes.find((d) => d.id === "dp_twin");
    ok("population: the pass planned the dry-run twin with 2 superseded runs", twinRow?.outcome === "dry-run" && twinRow?.supersededRuns === 2);
    ok("SAFE: the cron deletes nothing from dp_a while the arm waits", after1.every((n, i) => n === before[i]));
    ok("the queued arm raised no armed-alone alert", armedAloneAlerts(postsBefore).length === 0);

    // ---- RA.2 maker is not checker, and the checker needs restore.approve. ----
    console.log("\nRA.2 the proposer and an Operator cannot approve the arm");
    if (qid !== "") ageRecord(rig.storage, changeKey(qid), "proposedAt", APPROVAL_MIN_DWELL_MS + 1000);
    const self = await rig.call(OWNER, "POST", `/admin/config/changes/${qid}/approve`);
    info(`the proposer's own approve answered ${self.status} ${(await self.text()).slice(0, 120)}`);
    ok(`SAFE: the same Owner cannot approve their own arm (${self.status})`, self.status >= 400 && (await storedRetention(rig, "dp_a"))?.enforce !== true);
    const opAppr = await rig.call(OPERATOR, "POST", `/admin/config/changes/${qid}/approve`);
    info(`the Operator's approve answered ${opAppr.status} ${(await opAppr.text()).slice(0, 140)}`);
    ok(`SAFE: an Operator (no restore.approve) cannot approve the arm (${opAppr.status})`, opAppr.status >= 400 && (await storedRetention(rig, "dp_a"))?.enforce !== true);

    // ---- RA.3 a different Owner approves, and the cron prunes. ----
    console.log("\nRA.3 after a different Owner approves, the cron prunes");
    const appr = await rig.call(OWNER2, "POST", `/admin/config/changes/${qid}/approve`);
    ok(`a different Owner approves the arm (${appr.status})`, appr.status === 200);
    ok("enforce is stored after the approval", (await storedRetention(rig, "dp_a"))?.enforce === true);
    await runRetentionPrunes(rig.env, rig.stub);
    const after2 = RUNS_A.map((r) => treeCount(rig, r));
    info(`dp_a run-tree counts after the approved pass ${JSON.stringify(after2)}`);
    ok("the approved arm prunes the two over-cap run trees", after2[0] === 0 && after2[1] === 0 && after2[2]! > 0);

    // ---- RA.4 narrowing edits stay immediate. ----
    console.log("\nRA.4 narrowing edits stay immediate");
    const raise = await rig.call(OWNER, "POST", "/admin/downpipes", armBody("dp_a", 3));
    ok(`raising keepRuns 1 to 3 applies at once (${raise.status})`, raise.status === 200 && (await storedRetention(rig, "dp_a"))?.keepRuns === 3);
    const rename = await rig.call(OPERATOR, "POST", "/admin/downpipes", { ...armBody("dp_a", 3), name: "renamed" });
    ok(`an Operator's rename of the armed downpipe applies at once (${rename.status})`, rename.status === 200);
    const off = await rig.call(OPERATOR, "POST", "/admin/downpipes", { ...baseConfig("dp_a"), retention: { keepRuns: 3, enforce: false } });
    ok(`turning enforce off applies at once (${off.status})`, off.status === 200 && (await storedRetention(rig, "dp_a"))?.enforce === false);
    const lower = await rig.call(OWNER, "POST", "/admin/downpipes", { ...baseConfig("dp_a"), retention: { keepRuns: 1, enforce: false } });
    ok(`lowering a bound with enforce off applies at once (${lower.status})`, lower.status === 200);

    // ---- RA.5 break-glass arms at once, and it is alerted and audited. ----
    console.log("\nRA.5 the break-glass token arms at once");
    const bgFrom = posts.length;
    const bg = await rig.call("break-glass", "POST", "/admin/downpipes", armBody("dp_twin"));
    ok(`the break-glass arm applies at once (${bg.status})`, bg.status === 200 && (await storedRetention(rig, "dp_twin"))?.enforce === true);
    const bgAlerts = armedAloneAlerts(bgFrom);
    info(`break-glass alerts: ${JSON.stringify(bgAlerts.map((a) => a.detail))}`);
    ok("the break-glass arm raised a retention-armed-alone warning naming the token", bgAlerts.some((a) => /break-glass/.test(a.detail ?? "")));

    // ---- RA.6 one Owner, no other restore.approve holder: today's behaviour plus an alert. ----
    console.log("\nRA.6 one Owner and an Operator: the arm applies at once and alerts");
    {
      const solo = await buildRig(jwt);
      await solo.call(OWNER, "GET", "/admin/whoami");
      await solo.call(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "operator" });
      ok("a webhook channel and an all-events warning rule are wired", await wireSink(solo));
      await solo.call(OWNER, "POST", "/admin/downpipes", baseConfig("dp_s"));
      await solo.writeRunlog(await solo.sealRuns("dp_s", RUNS_A));
      const from = posts.length;
      const s = await solo.call(OWNER, "POST", "/admin/downpipes", armBody("dp_s"));
      ok(`the lone Owner's arm applies at once (${s.status})`, s.status === 200 && (await storedRetention(solo, "dp_s"))?.enforce === true);
      const alerts = armedAloneAlerts(from);
      info(`one-approver alerts: ${JSON.stringify(alerts.map((a) => a.detail))}`);
      ok("the arm raised a retention-armed-alone warning to the all-events webhook", alerts.length === 1);
      ok("  and the alert names the Owner", alerts.some((a) => (a.detail ?? "").includes(OWNER)));
      ok("the arm wrote a retention-armed-alone audit row", await auditHas(solo, "retention-armed-alone"));
      const b4 = RUNS_A.map((r) => treeCount(solo, r));
      await runRetentionPrunes(solo.env, solo.stub);
      ok("the cron prunes as it does today", RUNS_A.some((r, i) => treeCount(solo, r) < b4[i]!));
      const nFrom = posts.length;
      const n = await solo.call(OWNER, "POST", "/admin/downpipes", armBody("dp_s", 2));
      ok(`a narrowing edit applies and does not alert (${n.status})`, n.status === 200 && armedAloneAlerts(nFrom).length === 0);
    }
    ok("the break-glass arm in RA.5 wrote a retention-armed-alone audit row", await auditHas(rig, "retention-armed-alone"));

    // ---- RA.7 the bulk route queues the same arm per item. ----
    console.log("\nRA.7 the bulk upsert queues the Owner's arm per item");
    const bulk = await rig.call(OWNER, "POST", "/admin/downpipes/bulk", {
      downpipes: [armBody("dp_c"), { ...baseConfig("dp_d"), retention: { keepRuns: 1, enforce: false } }],
    });
    const out = (await bulk.json()) as { results?: Array<{ id: string; status: string }> };
    info(`bulk answered ${bulk.status}: ${JSON.stringify(out.results)}`);
    const row = (id: string) => out.results?.find((x) => x.id === id);
    ok("SAFE: the armed item is queued, not applied", row("dp_c")?.status === "pending" && (await storedRetention(rig, "dp_c")) === undefined);
    ok("the dry-run item in the same batch is applied", row("dp_d")?.status === "applied");
  } finally {
    jwt.restoreFetch();
  }

  console.log(failures === 0 ? `\nRETENTION-ARM-DUALCONTROL PASS (${checks} checks)` : `\n${failures} FAILURE(S) of ${checks} checks`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

await main();
