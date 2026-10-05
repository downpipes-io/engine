// validate-retention-prune-failed-audit: a scheduled prune that CHANGED the archive leaves a first-class
// audit event, and a pass that changed nothing leaves none.
//
// THE RISK THIS GUARDS AGAINST. applyPrune (seal/prune.ts) commits the superseded RUNLOG first and only then
// deletes. When the store refuses or drops a delete it throws PruneApplyError, and by then the signed RUNLOG
// already marks runs superseded. The cron (cron/retention-pass.ts runOneRetentionPrune) used to write the
// retention-prune event only after a CLEAN apply, so a partial scheduled prune changed the archive and its
// only trace was one row in the fleet-wide 64-entry seal-fault ring.
//
// THE RULE UNDER TEST (stated at the cron's applyPrune call): one event per apply that changed the archive
// (seal/prune.ts pruneChanged: runs superseded, or an object removed or hidden), "success" when the apply
// finished its plan and "failed" when it threw after changing something; no event for an apply that changed
// nothing. A remainder the store keeps refusing is re-attempted every pass (planLeftovers), so the rule is
// proven over four ticks: one "failed" event when it first changes state, none while it only re-meets the
// lock, one "success" when the lock lapses and the pass clears it.
//
// IT IS DRIVEN, NOT READ. Every cell calls the REAL runRetentionPrunes over a REAL SchedulerDO and a REAL
// S3Destination (built by the engine from DEST_* env) whose fetch is answered by FakeS3 below, holding REAL
// downpipe/0.1.0 archives. A refused delete has the shape a store gives it: 403 with a body naming the
// retention, and a HEAD whose Object Lock headers show a retain-until in the future.
//
// An earlier rule said "a remainder is never re-attempted". That rule no longer holds, and FA.1 asserts the
// re-attempt.
//
// Run: node test/validate-retention-prune-failed-audit.ts

import { x25519 } from "@noble/curves/ed25519.js";
import type { AuditEvent } from "../src/admin/audit.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { runRetentionPrunes } from "../src/cron/retention-pass.ts";
import type { RetentionPassRecord } from "../src/cron/retention-record.ts";
import type { Env } from "../src/env.d.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { signRunlog, type RunlogEntry } from "../src/format/writer-runlog.ts";
import { loadSigner } from "../src/keys-env.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { DownpipeState } from "../src/sched/types.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

const ENDPOINT = "https://s3.example.com";
const BUCKET = "archive";
const NOW_MS = Date.now();
const RETENTION = `<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>Object is subject to object retention and cannot be deleted</Message></Error>`;

// FakeS3 answers the engine's S3Destination: GET/PUT (with If-Match / If-None-Match), HEAD with Object Lock
// headers, DELETE, ListObjectsV2 and the bucket's ?object-lock configuration.
//   locked      keys whose delete is refused (403, body names the retention) while their lock holds.
//   versioned   a versioned bucket: a delete answers 204 with x-amz-delete-marker and the key stops listing.
//   failDeletes answer every DELETE with 503 until cleared (a store that stops answering usefully).
//   pendingSwap models ANOTHER writer between this pass's RUNLOG read and its apply: on the first RUNLOG
//               read after a run was read it swaps in a RUNLOG with the over-cap runs already superseded,
//               and, when alsoDelete is set, removes the objects that writer already deleted.
class FakeS3 {
  store = new Map<string, { body: Uint8Array; etag: string }>();
  locked = new Set<string>();
  versioned = false;
  failDeletes = false;
  removed = 0;
  markers = 0;
  refused = 0;
  pendingSwap: { runlog: Uint8Array; sig: Uint8Array; alsoDelete: string[] } | null = null;
  private sawRunRead = false;
  private n = 0;

  put(key: string, body: Uint8Array): string {
    const etag = `"e${++this.n}"`;
    this.store.set(key, { body, etag });
    return etag;
  }

  async handle(req: Request): Promise<Response> {
    const u = new URL(req.url);
    const path = decodeURIComponent(u.pathname);
    const key = path.startsWith(`/${BUCKET}/`) ? path.slice(BUCKET.length + 2) : "";
    const method = req.method.toUpperCase();
    if (method === "GET" && u.searchParams.has("object-lock")) {
      return new Response(`<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`, { status: 200 });
    }
    if (method === "GET" && u.searchParams.get("list-type") === "2") {
      const prefix = u.searchParams.get("prefix") ?? "";
      const keys = [...this.store.keys()].filter((k) => k.startsWith(prefix)).sort();
      return new Response(`<ListBucketResult><IsTruncated>false</IsTruncated>${keys.map((k) => `<Contents><Key>${k}</Key></Contents>`).join("")}</ListBucketResult>`, { status: 200 });
    }
    if (method === "GET") {
      if (key.startsWith("run/")) this.sawRunRead = true;
      if (key === "_RECOVERY/RUNLOG" && this.sawRunRead && this.pendingSwap) {
        this.put("_RECOVERY/RUNLOG", this.pendingSwap.runlog);
        this.put("_RECOVERY/RUNLOG.sig", this.pendingSwap.sig);
        for (const k of this.pendingSwap.alsoDelete) this.store.delete(k);
        this.pendingSwap = null;
      }
      const v = this.store.get(key);
      if (!v) return new Response(null, { status: 404 });
      return new Response(v.body as Uint8Array<ArrayBuffer>, { status: 200, headers: { etag: v.etag } });
    }
    if (method === "HEAD") {
      if (!this.store.has(key)) return new Response(null, { status: 404 });
      if (this.locked.has(key)) {
        const until = new Date(NOW_MS + 30 * 86_400_000).toISOString().replace(/\.\d{3}Z$/, "Z");
        return new Response(null, { status: 200, headers: { "x-amz-object-lock-mode": "COMPLIANCE", "x-amz-object-lock-retain-until-date": until } });
      }
      return new Response(null, { status: 200 });
    }
    if (method === "PUT") {
      const body = new Uint8Array(await req.arrayBuffer());
      const cur = this.store.get(key);
      const ifMatch = req.headers.get("if-match");
      const ifNone = req.headers.get("if-none-match");
      if (ifNone === "*" && cur) return new Response(null, { status: 412 });
      if (ifMatch !== null && (!cur || cur.etag !== ifMatch)) return new Response(null, { status: 412 });
      return new Response(null, { status: 200, headers: { etag: this.put(key, body) } });
    }
    if (method === "DELETE") {
      if (this.failDeletes) return new Response(`<Error><Code>ServiceUnavailable</Code></Error>`, { status: 503 });
      if (!this.store.has(key)) return new Response(null, { status: 404 });
      if (this.locked.has(key)) {
        if (this.versioned) {
          // A versioned bucket does not refuse a delete with no versionId: it hides the object.
          this.store.delete(key);
          this.markers++;
          return new Response(null, { status: 204, headers: { "x-amz-delete-marker": "true" } });
        }
        this.refused++;
        return new Response(RETENTION, { status: 403 });
      }
      this.store.delete(key);
      if (this.versioned) {
        this.markers++;
        return new Response(null, { status: 204, headers: { "x-amz-delete-marker": "true" } });
      }
      this.removed++;
      return new Response(null, { status: 204 });
    }
    return new Response(null, { status: 400 });
  }
}

let current: FakeS3 | null = null;
const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
  const req = new Request(input as RequestInfo, init);
  if (current !== null && req.url.startsWith(ENDPOINT)) return current.handle(req);
  return realFetch(input as RequestInfo, init);
}) as typeof fetch;

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// makeScheduler wraps a REAL SchedulerDO. dropAuditWrites answers every POST /audit with a 500, so the
// lost-write cell can prove the loss is counted, not thrown. auditPosts counts every attempt.
function makeScheduler(dropAuditWrites: boolean): { storage: MockStorage; scheduler: DurableObjectStub; auditPosts: () => number } {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  let posts = 0;
  const scheduler = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (new URL(url).pathname === "/audit" && (init?.method ?? "GET") === "POST") {
        posts++;
        if (dropAuditWrites) return Promise.resolve(new Response("{}", { status: 500 }));
      }
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  return { storage, scheduler, auditPosts: () => posts };
}

const RUNS = ["01ARZ3NDEKTSV4RRFFQ69G5FA0", "01ARZ3NDEKTSV4RRFFQ69G5FA1", "01ARZ3NDEKTSV4RRFFQ69G5FA2"];
const DP = "dp_prune";

interface Rig {
  s3: FakeS3;
  env: Env;
  scheduler: DurableObjectStub;
  auditPosts: () => number;
  segOf: (runIndex: number) => string;
  sigOf: (runIndex: number) => string;
  treeOf: (runIndex: number) => string[];
}

// ONE downpipe with retention keepRuns:1 enforce:true and THREE sealed runs with distinct values: runs 1 and
// 2 are over the cap, each owns one orphan segment, and run 3 is retained.
async function buildRig(dropAuditWrites = false): Promise<Rig> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const bg = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const master = rand(32);
  const s3 = new FakeS3();
  const { storage, scheduler, auditPosts } = makeScheduler(dropAuditWrites);
  await storage.put(`dp:${DP}`, {
    config: { id: DP, name: `${DP}-name`, enabled: true, source: { type: "kv", binding: "SRC" }, schedule: { cadenceSeconds: 3600 }, retention: { keepRuns: 1, enforce: true } },
    nextRunAt: 0,
    lastRunId: null,
    inFlight: false,
  } as unknown as DownpipeState);
  const entries: RunlogEntry[] = [];
  const segs: string[] = [];
  for (let i = 0; i < 3; i++) {
    const at = `2026-06-0${i + 1}T00:00:00.000Z`;
    const prev = i === 0 ? null : RUNS[i - 1]!;
    const archive = await buildArchive({ downpipeId: DP, downpipeName: DP, cadence: "3600s", runId: RUNS[i]!, master, recipients: [bg.entry, op.entry], signer, records: [{ sourceType: "kv", name: "k", value: utf8(`value-${i}`), namespace: "ns" }], windowStart: at, windowEnd: at, createdAt: at, runlogIndex: i + 1, prevRunId: prev, skipRunlog: true, randomNonce: () => rand(16), randomSalt: () => rand(16) });
    const before = new Set(s3.store.keys());
    for (const [key, body] of archive) s3.put(key, body);
    segs.push([...s3.store.keys()].find((k) => k.startsWith("seg/") && !before.has(k))!);
    entries.push({ index: i + 1, runId: RUNS[i]!, downpipeId: DP, time: at, recordCount: 1, prevRunId: prev, status: "active" });
  }
  const { runlog, sig } = await signRunlog(entries, signer.edPrivate, signer.mldsaSecret);
  s3.put("_RECOVERY/RUNLOG", runlog);
  s3.put("_RECOVERY/RUNLOG.sig", utf8(b64urlEncode(sig)));
  // Pre-built for the concurrent-writer cells: the same RUNLOG with the two over-cap runs superseded.
  const done = entries.map((e, i) => (i < 2 ? { ...e, status: "superseded" as const } : e));
  const swapped = await signRunlog(done, signer.edPrivate, signer.mldsaSecret);
  const rig: Rig = {
    s3,
    env: {
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      DEST_KIND: "s3",
      DEST_ENDPOINT: ENDPOINT,
      DEST_BUCKET: BUCKET,
      DEST_REGION: "us-east-1",
      DEST_ACCESS_KEY_ID: "AKIDEXAMPLE",
      DEST_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
      SIGNER_PRIVATE: signerPrivateB64,
      OPERATIONAL_PRIVATE: b64urlEncode(op.identity),
    } as unknown as Env,
    scheduler,
    auditPosts,
    segOf: (i) => segs[i]!,
    sigOf: (i) => `run/${RUNS[i]!}/root.manifest.json.sig`,
    treeOf: (i) => [...s3.store.keys()].filter((k) => k.startsWith(`run/${RUNS[i]!}/`)),
  };
  (rig as unknown as { swap: () => void }).swap = () => {
    s3.pendingSwap = { runlog: swapped.runlog, sig: utf8(b64urlEncode(swapped.sig)), alsoDelete: [] };
  };
  return rig;
}

function armConcurrentSupersede(rig: Rig, alsoDelete: string[] = []): void {
  (rig as unknown as { swap: () => void }).swap();
  rig.s3.pendingSwap!.alsoDelete = alsoDelete;
}

async function tick(rig: Rig): Promise<{ threw: boolean; row: RetentionPassRecord["downpipes"][number] | undefined; rec: RetentionPassRecord | null }> {
  current = rig.s3;
  let threw = false;
  try {
    await runRetentionPrunes(rig.env, rig.scheduler);
  } catch {
    threw = true;
  } finally {
    current = null;
  }
  const r = await rig.scheduler.fetch("https://do/retention-state", { method: "GET" });
  const rec = ((await r.json()) as { record?: RetentionPassRecord | null }).record ?? null;
  return { threw, rec, row: rec?.downpipes.find((d) => d.id === DP) };
}

async function pruneEvents(scheduler: DurableObjectStub): Promise<AuditEvent[]> {
  const r = await scheduler.fetch("https://do/audit", { method: "GET" });
  // Oldest first by the chain's own sequence number, whatever order the list route returns.
  return ((await r.json()) as { events: AuditEvent[] }).events.filter((e) => e.action === "retention-prune").sort((a, b) => a.seq - b.seq);
}

function supersededInRunlog(s3: FakeS3): number {
  return (new TextDecoder().decode(s3.store.get("_RECOVERY/RUNLOG")!.body).match(/"superseded"/g) ?? []).length;
}

async function main(): Promise<void> {
  console.log("validate-retention-prune-failed-audit: a scheduled prune that changed the archive is audited, once\n");

  // ---- FA.0 THE CONTROL: a clean apply records exactly one success event. ------------------------------
  console.log("FA.0 the control: a clean scheduled prune records ONE success event");
  const clean = await buildRig();
  const c1 = await tick(clean);
  ok("the clean pass applied", c1.row?.outcome === "applied" && !c1.threw);
  const ce = await pruneEvents(clean.scheduler);
  ok(`exactly one retention-prune event (${ce.length})`, ce.length === 1);
  ok("it is outcome success, actorMethod engine, no human actor, targeting the downpipe by id and name", ce[0]?.outcome === "success" && ce[0]?.actorMethod === "engine" && ce[0]?.actorEmail === null && ce[0]?.target.kind === "downpipe" && (ce[0]?.target as { id?: string }).id === DP && (ce[0]?.target as { name?: string }).name === `${DP}-name`);
  await tick(clean);
  ok(`a second tick over a finished prune adds no event (${(await pruneEvents(clean.scheduler)).length} in total)`, (await pruneEvents(clean.scheduler)).length === 1);

  // ---- FA.1 A LOCKED REMAINDER ACROSS FOUR TICKS. ----------------------------------------------------------
  console.log("\nFA.1 a locked remainder across four ticks: failed once, nothing while locked, success when it clears");
  const lk = await buildRig();
  lk.s3.locked.add(lk.segOf(0)); // run 1's orphan segment is under a retention lock
  const t1 = await tick(lk);
  ok(`population: tick 1 superseded both over-cap runs in the RUNLOG (${supersededInRunlog(lk.s3)})`, supersededInRunlog(lk.s3) === 2);
  ok("population: tick 1 removed run 2's segment and tree, and kept run 1's tree (its segment is still there)", !lk.s3.store.has(lk.segOf(1)) && lk.treeOf(1).length === 0 && lk.treeOf(0).length > 0);
  ok("tick 1 row: error, refused 1, read as a lock (wormBlocked)", t1.row?.outcome === "error" && t1.row?.refused === 1 && t1.row?.wormBlocked === true);
  ok("tick 1: the pass does not report itself healthy", t1.threw);
  const e1 = await pruneEvents(lk.scheduler);
  ok(`tick 1 wrote ONE failed event (${e1.length})`, e1.length === 1 && e1[0]?.outcome === "failed");
  const runlogAfter1 = lk.s3.store.get("_RECOVERY/RUNLOG")!.etag;
  for (const n of [2, 3]) {
    const t = await tick(lk);
    ok(`tick ${n}: the remainder was RE-ATTEMPTED and refused again (${lk.s3.refused} refusals so far)`, lk.s3.refused === n);
    ok(`tick ${n}: nothing changed (RUNLOG not re-signed, run 1's tree still there)`, lk.s3.store.get("_RECOVERY/RUNLOG")!.etag === runlogAfter1 && lk.treeOf(0).length > 0);
    ok(`tick ${n}: the state is still reported on the row (error, wormBlocked)`, t.row?.outcome === "error" && t.row?.wormBlocked === true);
    ok(`tick ${n}: NO new audit event (${(await pruneEvents(lk.scheduler)).length} in total)`, (await pruneEvents(lk.scheduler)).length === 1);
  }
  lk.s3.locked.clear(); // the retention lapses
  const t4 = await tick(lk);
  ok("tick 4: the lock lapsed and the pass cleared the remainder", !lk.s3.store.has(lk.segOf(0)) && lk.treeOf(0).length === 0 && t4.row?.outcome === "applied" && !t4.threw);
  const e4 = await pruneEvents(lk.scheduler);
  ok(`across four ticks: exactly two events, failed then success (${e4.map((e) => e.outcome).join(", ")})`, e4.length === 2 && e4[0]?.outcome === "failed" && e4[1]?.outcome === "success");
  ok(`across four ticks: exactly two audit writes were attempted (${lk.auditPosts()})`, lk.auditPosts() === 2);

  // ---- FA.2 a store that stops answering after the RUNLOG commit. ---------------------------------------
  console.log("\nFA.2 a delete the store does not answer (503) after the RUNLOG commit records a FAILED event");
  const flake = await buildRig();
  flake.s3.failDeletes = true;
  const f1 = await tick(flake);
  ok("population: both runs superseded in the RUNLOG", supersededInRunlog(flake.s3) === 2);
  ok("the row is error with a transient failure, not a lock", f1.row?.outcome === "error" && f1.row?.wormBlocked === undefined && f1.row?.refusalClass === "transient");
  const fe = await pruneEvents(flake.scheduler);
  ok(`exactly one failed event (${fe.length})`, fe.length === 1 && fe[0]?.outcome === "failed");

  // ---- FA.3 the failed-event write is LOST: counted, never thrown over the prune's own error. -------------
  console.log("\nFA.3 a lost failed-event write is counted on auditWriteFailures, and the prune error still wins");
  const lost = await buildRig(true);
  lost.s3.locked.add(lost.segOf(0));
  const l1 = await tick(lost);
  ok(`the pass TRIED to write the audit event (${lost.auditPosts()} POST /audit)`, lost.auditPosts() === 1);
  ok("the lost write is counted (auditWriteFailures 1)", l1.rec?.auditWriteFailures === 1);
  ok("the row is still the classed error with wormBlocked", l1.row?.outcome === "error" && l1.row?.wormBlocked === true);

  // ---- FA.4 the pass after a transient failure finishes the job and records it. ----------------------------
  // Replaces the old FA.4 ("a retry plans nothing"): planLeftovers re-plans a superseded run's remainder, so
  // the retry DOES re-attempt it, and it records the change it makes.
  console.log("\nFA.4 the tick after a transient failure finishes the remainder and records ONE success event");
  flake.s3.failDeletes = false;
  const f2 = await tick(flake);
  ok("the retry cleared both runs' segments and trees", flake.treeOf(0).length === 0 && flake.treeOf(1).length === 0 && !flake.s3.store.has(flake.segOf(0)) && !flake.s3.store.has(flake.segOf(1)));
  ok("the retry row is applied", f2.row?.outcome === "applied" && !f2.threw);
  const fe2 = await pruneEvents(flake.scheduler);
  ok(`events across the two ticks: failed then success (${fe2.map((e) => e.outcome).join(", ")})`, fe2.length === 2 && fe2[0]?.outcome === "failed" && fe2[1]?.outcome === "success");

  // ---- FA.5 an apply that CHANGED NOTHING writes NO event. ---------------------------------------------------
  // Another writer superseded the same runs after this pass read the RUNLOG, so supersedeRunlog re-signs
  // nothing (superseded 0), and every delete is refused.
  console.log("\nFA.5 a partial apply that re-signed nothing and removed nothing records NO audit event");
  const idle = await buildRig();
  for (const i of [0, 1]) idle.s3.locked.add(idle.segOf(i));
  armConcurrentSupersede(idle);
  const i1 = await tick(idle);
  ok("population: the concurrent supersede landed before the apply", idle.s3.pendingSwap === null && supersededInRunlog(idle.s3) === 2);
  ok(`population: nothing was removed (${idle.s3.removed})`, idle.s3.removed === 0);
  ok("the apply threw and the row says so (error, wormBlocked, refused 2)", i1.row?.outcome === "error" && i1.row?.wormBlocked === true && i1.row?.refused === 2);
  ok(`NO retention-prune event for a pass that changed nothing (${(await pruneEvents(idle.scheduler)).length})`, (await pruneEvents(idle.scheduler)).length === 0);
  ok(`no audit write was attempted (${idle.auditPosts()} POST /audit)`, idle.auditPosts() === 0);

  // ---- FA.6 re-signed nothing, but ONLY ORPHAN deletes landed: that is a change. -----------------------------
  console.log("\nFA.6 a partial apply that re-signed nothing but removed orphan segments records a FAILED event");
  const some = await buildRig();
  for (const i of [0, 1]) some.s3.locked.add(some.sigOf(i)); // the trees cannot go; the segments can
  armConcurrentSupersede(some);
  const s1 = await tick(some);
  ok("population: the concurrent supersede landed before the apply", some.s3.pendingSwap === null);
  ok(`population: only the two orphan segments were removed (${some.s3.removed})`, some.s3.removed === 2 && !some.s3.store.has(some.segOf(0)) && !some.s3.store.has(some.segOf(1)));
  ok("the row records superseded 0 and 2 orphan segments removed", s1.row?.supersededRuns === 0 && s1.row?.orphanSegs === 2 && s1.row?.outcome === "error");
  const se = await pruneEvents(some.scheduler);
  ok(`exactly one failed event (${se.length})`, se.length === 1 && se[0]?.outcome === "failed");

  // ---- FA.7 every planned object was already gone (404): a clean apply that changed nothing. ----------------
  console.log("\nFA.7 an apply whose every delete finds the object already gone records NO event and a no-op row");
  const gone = await buildRig();
  armConcurrentSupersede(gone, [gone.segOf(0), gone.segOf(1), ...gone.treeOf(0), ...gone.treeOf(1)]);
  const g1 = await tick(gone);
  ok("population: the other writer superseded and deleted everything first", gone.s3.pendingSwap === null && gone.treeOf(0).length === 0 && gone.s3.removed === 0);
  ok("the pass finished cleanly and its row is a no-op, not applied", !g1.threw && g1.row?.outcome === "no-op");
  ok(`NO retention-prune event (${(await pruneEvents(gone.scheduler)).length})`, (await pruneEvents(gone.scheduler)).length === 0);

  // ---- FA.8 a versioned (Object Lock) bucket hides rather than removes: that is still a change. --------------
  console.log("\nFA.8 a versioned bucket's delete markers are a change: ONE success event, then silence");
  const ver = await buildRig();
  ver.s3.versioned = true;
  for (const i of [0, 1]) ver.s3.locked.add(ver.segOf(i));
  const v1 = await tick(ver);
  ok(`population: every delete was answered with a marker (${ver.s3.markers}) and none refused`, ver.s3.markers > 0 && ver.s3.refused === 0 && ver.s3.removed === 0);
  ok("the row is applied, with the objects counted hidden and none removed", v1.row?.outcome === "applied" && (v1.row?.hidden ?? 0) === ver.s3.markers && v1.row?.orphanSegs === 0 && v1.row?.runTreeObjects === 0);
  await tick(ver);
  const ve = await pruneEvents(ver.scheduler);
  ok(`exactly one success event across two ticks (${ve.map((e) => e.outcome).join(", ")})`, ve.length === 1 && ve[0]?.outcome === "success");

  console.log(failures === 0 ? `\nRETENTION-PRUNE-FAILED-AUDIT PASS (${checks} checks)` : `\n${failures} FAILURE(S) of ${checks} checks`);
  verdictReached(failures, checks);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
