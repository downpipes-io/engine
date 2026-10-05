// Prove the retention prune tells the truth about what it deleted, and finishes what it starts.
// No network, no deploy: real seals into an in-memory bucket, and the REAL S3 and Azure destinations over a
// scripted fetch, so every delete answer has the shape production sees. Run:
//   node test/validate-prune-apply-truth.ts
//
// PART 1  An interrupted apply is finished by the next pass, at EVERY crash point. Before, partitionRuns
//         skipped every superseded entry and the supersede had already committed, so a superseded run's
//         leftover tree objects and its orphan segments were never planned again.
// PART 2  A delete a versioned bucket answers with a delete marker is counted HIDDEN, not reclaimed, in the
//         apply result, the pass record and the per-destination fold.
// PART 3  A refused delete does not stop the loop, and a refusal is called a lock only when the object's own
//         lock metadata (S3) or the store's own immutability code (Azure) says so. DestStatusError carries the
//         sanitised code, never body text.
// PART 4  The scheduled pass records what a partial apply DID (not zeros) and does not report itself healthy;
//         the next scheduled pass finishes the job.
// PART 5  The pass record's refusal vocabulary is the fault ring's vocabulary.

import { x25519 } from "@noble/curves/ed25519.js";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { mlkemKeygen, mldsaKeygen } from "../src/crypto/pq.ts";
import { runRetentionPrunes } from "../src/cron/retention-pass.ts";
import { foldRetentionRecordIntoDestPrune } from "../src/cron/retention-dest-prune.ts";
import * as retentionRecord from "../src/cron/retention-record.ts";
import { sanitiseRetentionPassRecord, type RetentionPassRecord } from "../src/cron/retention-record.ts";
import { AzureBlobDestination } from "../src/dest/azure-blob.ts";
import { S3Destination } from "../src/dest/s3.ts";
import { DestStatusError, type Destination } from "../src/dest/types.ts";
import type { Env } from "../src/env.d.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { buildArchive, parseRunlog, type RecipientEntry, type RunlogEntry, type Signer } from "../src/format/writer.ts";
import { signRunlog } from "../src/format/writer-runlog.ts";
import { loadSigner } from "../src/keys-env.ts";
import { appendRunlog } from "../src/seal/pipeline.ts";
import { applyPrune, openRunSegEnumerator, planPrune, PruneApplyError, type RunTreeLister, runTreePrefix } from "../src/seal/prune.ts";
import { WORM_REFUSAL_CLASSES } from "../src/seal/seal-faults.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { DownpipeState } from "../src/sched/types.ts";
import { MemoryDestination } from "./memdest.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

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

const DP = "dp_truth";
const RUNS = ["01ARZ3NDEKTSV4RRFFQ69G5FB0", "01ARZ3NDEKTSV4RRFFQ69G5FB1", "01ARZ3NDEKTSV4RRFFQ69G5FB2", "01ARZ3NDEKTSV4RRFFQ69G5FB3"];

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// ---- PART 1: recovery at every crash point ----------------------------------------------------------

// CrashingDest passes every call through to the bucket, except that the delete numbered failAt (0-based)
// throws a transport fault, as a Worker that loses its socket or is evicted mid-loop does. A fault with no
// HTTP status is what stops the delete loop.
class CrashingDest extends MemoryDestination {
  deletes = 0;
  private readonly inner: MemoryDestination;
  private readonly failAt: number;
  constructor(inner: MemoryDestination, failAt: number) {
    super();
    this.inner = inner;
    this.failAt = failAt;
  }
  override get(k: string) {
    return this.inner.get(k);
  }
  override put(k: string, b: Uint8Array) {
    return this.inner.put(k, b);
  }
  override putConditional(k: string, b: Uint8Array, o: { ifMatch?: string; ifNoneMatch?: string }) {
    return this.inner.putConditional(k, b, o);
  }
  override exists(k: string) {
    return this.inner.exists(k);
  }
  override list(p: string) {
    return this.inner.list(p);
  }
  override listPage(p: string, c?: string) {
    return this.inner.listPage(p, c);
  }
  override async delete(k: string): Promise<void> {
    if (this.deletes++ === this.failAt) throw new Error("socket hang up");
    await this.inner.delete(k);
  }
}

interface SealedBucket {
  mem: MemoryDestination;
  store: ObjectStore;
  signer: Signer;
  identity: ReturnType<typeof parseIdentity>;
  verifier: { ed: Uint8Array; mldsa: Uint8Array };
  segOf: Map<string, string>;
}

// sealFour writes four real runs under one fixed master: A, B, C and C again, so runs 3 and 4 share one
// content-addressed segment. With keepRuns:1 runs 1-3 are over the cap: segments A and B are orphans, and
// segment C must survive because the retained run 4 still uses it.
async function sealFour(): Promise<SealedBucket> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  const signer: Signer = { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };
  const bg = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const mem = new MemoryDestination();
  const master = rand(32);
  const values = ["value-a", "value-b", "value-c", "value-c"];
  for (let i = 0; i < 4; i++) {
    const time = `2026-06-0${i + 1}T00:00:00.000Z`;
    const prevRunId = i === 0 ? null : RUNS[i - 1]!;
    const archive = await buildArchive({
      downpipeId: DP,
      downpipeName: "truth",
      cadence: "3600s",
      runId: RUNS[i]!,
      master,
      recipients: [bg.entry, op.entry],
      signer,
      records: [{ sourceType: "kv", name: "k", value: utf8(values[i]!), namespace: "ns" }],
      windowStart: time,
      windowEnd: time,
      createdAt: time,
      runlogIndex: i + 1,
      prevRunId,
      skipRunlog: true,
      randomNonce: () => rand(16),
      randomSalt: () => rand(16),
    });
    for (const [key, body] of archive) await mem.put(key, body);
    await appendRunlog(mem, signer, { index: i + 1, runId: RUNS[i]!, downpipeId: DP, time, recordCount: 1, prevRunId, status: "active" });
  }
  const store: ObjectStore = {
    get: async (k: string) => {
      const r = await mem.get(k);
      if (!r) throw new Error(`object ${k} is missing`);
      return r.body;
    },
  };
  const identity = parseIdentity(op.identity);
  const verifier = { ed: edPublic, mldsa: mldsa.publicKey };
  const enumerate = openRunSegEnumerator(store, identity, verifier);
  const segOf = new Map<string, string>();
  for (const r of RUNS) segOf.set(r, (await enumerate(r))[0]!);
  return { mem, store, signer, identity, verifier, segOf };
}

async function onePass(b: SealedBucket, dest: Destination): Promise<unknown> {
  const entries = parseRunlog((await b.mem.get("_RECOVERY/RUNLOG"))!.body);
  const lister: RunTreeLister = (runId) => b.mem.list(runTreePrefix(runId));
  const plan = await planPrune(entries, DP, { keepRuns: 1 }, new Date("2026-06-10T00:00:00.000Z"), openRunSegEnumerator(b.store, b.identity, b.verifier), lister);
  try {
    await applyPrune(dest, b.signer, plan);
    return undefined;
  } catch (e) {
    return e;
  }
}

async function part1(): Promise<void> {
  console.log("PART 1: an interrupted apply is finished by the next pass, at every crash point:");
  // The population: how many deletes one uninterrupted apply makes. Every crash point is below it.
  const probe = await sealFour();
  const counter = new CrashingDest(probe.mem, Number.POSITIVE_INFINITY);
  ok("control: an uninterrupted apply completes", (await onePass(probe, counter)) === undefined);
  const total = counter.deletes;
  ok(`control: the plan makes more than two deletes (${total}), so there are crash points inside it`, total > 2);

  let finishedEvery = true;
  let keptSharedEvery = true;
  let retainedOpensEvery = true;
  let crashedEvery = true;
  for (let k = 0; k < total; k++) {
    const b = await sealFour();
    const crash = await onePass(b, new CrashingDest(b.mem, k));
    if (!(crash instanceof PruneApplyError)) crashedEvery = false;
    // The next pass, against the healthy bucket.
    const second = await onePass(b, b.mem);
    const leftTrees = [...b.mem.entries().keys()].filter((key) => RUNS.slice(0, 3).some((r) => key.startsWith(runTreePrefix(r)))).length;
    const orphanA = await b.mem.exists(b.segOf.get(RUNS[0]!)!);
    const orphanB = await b.mem.exists(b.segOf.get(RUNS[1]!)!);
    const finished = second === undefined && leftTrees === 0 && !orphanA && !orphanB;
    if (!finished) {
      finishedEvery = false;
      console.log(`       crash at delete ${k}: second pass ${second === undefined ? "clean" : "threw"}, ${leftTrees} superseded tree object(s) left, orphan A ${orphanA ? "left" : "gone"}, orphan B ${orphanB ? "left" : "gone"}`);
    }
    if (!(await b.mem.exists(b.segOf.get(RUNS[3]!)!))) keptSharedEvery = false;
    try {
      const run = await openRun(b.store, RUNS[3]!, b.identity, b.verifier);
      run.dispose();
    } catch {
      retainedOpensEvery = false;
    }
  }
  ok(`every crash point (${total}) threw a PruneApplyError on the first pass`, crashedEvery);
  ok("at every crash point the NEXT pass removed every superseded run's tree and both orphan segments", finishedEvery);
  ok("at every crash point the segment the retained run shares was never deleted", keptSharedEvery);
  ok("at every crash point the retained run still opens and verifies", retainedOpensEvery);
}

// ---- scripted-fetch destinations --------------------------------------------------------------------

const NOW = new Date("2026-09-01T00:00:00.000Z");
const S3_BUCKET = "archive-bucket";
type Script = (method: string, key: string, search: string) => Response;

function withFetch<T>(script: Script, pathPrefix: string, run: () => Promise<T>): Promise<T> {
  const real = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url);
    const method = (init?.method ?? "GET").toUpperCase();
    return script(method, decodeURIComponent(url.pathname.slice(pathPrefix.length)), url.search);
  }) as typeof fetch;
  return run().finally(() => {
    globalThis.fetch = real;
  });
}

function s3(): S3Destination {
  return new S3Destination("https://s3.example.com", S3_BUCKET, "us-east-1", "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", { now: () => NOW });
}

const signerStub = {} as unknown as Signer;
function handPlan(segs: string[], runTrees: Array<{ runId: string; objects: string[]; segs: string[] }>) {
  return {
    downpipeId: DP,
    retainedRunIds: [RUNS[3]!],
    supersededRunIds: [] as string[],
    runTreeObjects: runTrees.flatMap((t) => t.objects),
    orphanSegs: segs,
    runTrees,
    reclaimableBytes: 0,
    retainedUnreadableCount: 0,
    supersededSkippedCount: 0,
    unparseableTimeCount: 0,
  };
}

// ---- PART 2: delete markers are hidden, not reclaimed -------------------------------------------------

async function part2(): Promise<void> {
  console.log("\nPART 2: a versioned bucket's delete marker is counted hidden, not reclaimed:");
  const tree = [`run/${RUNS[0]!}/root.manifest.json.sig`, `run/${RUNS[0]!}/root.manifest.json`];
  const plan = handPlan(["seg/aa/a.seg", "seg/bb/b.seg"], [{ runId: RUNS[0]!, objects: tree, segs: ["seg/aa/a.seg", "seg/bb/b.seg"] }]);
  // Every S3 Object Lock bucket is versioned: a DELETE with no versionId answers 204 and a delete marker.
  const result = await withFetch(
    (method) => (method === "DELETE" ? new Response(null, { status: 204, headers: { "x-amz-delete-marker": "true", "x-amz-version-id": "3HL4kqtJlcpXroDTDmJ" } }) : new Response(null, { status: 404 })),
    `/${S3_BUCKET}/`,
    () => applyPrune(s3(), signerStub, plan),
  );
  const r = result as unknown as Record<string, number>;
  ok("no object is counted as removed when every delete only added a marker", r.runTreeDeleted === 0 && r.orphansDeleted === 0);
  ok("all four are counted hidden behind a delete marker", r.runTreeHidden === 2 && r.orphansHidden === 2);

  // The same answer with no marker header (an unversioned bucket) is a real removal.
  const plain = await withFetch((method) => (method === "DELETE" ? new Response(null, { status: 204 }) : new Response(null, { status: 404 })), `/${S3_BUCKET}/`, () => applyPrune(s3(), signerStub, plan));
  ok("control: without the marker header the same four deletes are removals", plain.runTreeDeleted === 2 && plain.orphansDeleted === 2 && (plain as unknown as Record<string, number>).runTreeHidden === 0);

  // The count survives the pass record's sanitiser and the per-destination fold.
  const rec: RetentionPassRecord = {
    at: NOW.getTime(),
    downpipesWithRetention: 1,
    downpipesPaused: 0,
    replicationUnreadable: false,
    auditWriteFailures: 0,
    destinations: [{ destKey: "", downpipeCount: 1 }],
    downpipes: [{ id: DP, destKey: "", outcome: "applied", supersededRuns: 1, runTreeObjects: 0, orphanSegs: 0, hidden: 4, retainedRuns: 1 } as never],
  };
  const clean = sanitiseRetentionPassRecord(rec);
  ok("the pass record keeps the hidden count", (clean.downpipes[0] as unknown as Record<string, unknown>).hidden === 4);
  const folded = foldRetentionRecordIntoDestPrune({}, clean, "");
  const last = folded[""]?.lastApplied as unknown as Record<string, unknown> | undefined;
  ok("the per-destination fold reports 0 reclaimed and 4 hidden", last?.reclaimed === 0 && last?.hidden === 4);
}

// ---- PART 3: refusals are read, and the loop keeps going ---------------------------------------------

const ACCESS_DENIED = `<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>Access Denied for sk-live-SECRET</Message></Error>`;
const GCS_RETENTION = `<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>Object 'seg/aa/a.seg' is subject to object retention and cannot be deleted</Message></Error>`;

async function part3(): Promise<void> {
  console.log("\nPART 3: a refusal is read, counted, and does not stop the loop:");
  const future = new Date(NOW.getTime() + 30 * 86_400_000).toISOString().replace(/\.\d{3}Z$/, "Z");
  const segs = ["seg/01/locked.seg", "seg/02/fine.seg", "seg/03/denied.seg", "seg/04/marker.seg"];
  const script: Script = (method, key, search) => {
    if (search === "?object-lock=") return new Response(`<Error><Code>ObjectLockConfigurationNotFoundError</Code></Error>`, { status: 404 });
    if (method === "DELETE" && (key === segs[0] || key === segs[2])) return new Response(ACCESS_DENIED, { status: 403 });
    if (method === "DELETE" && key === segs[3]) return new Response(null, { status: 204, headers: { "x-amz-delete-marker": "true" } });
    if (method === "DELETE") return new Response(null, { status: 204 });
    if (method === "HEAD" && key === segs[0]) return new Response(null, { status: 200, headers: { "x-amz-object-lock-mode": "COMPLIANCE", "x-amz-object-lock-retain-until-date": future } });
    if (method === "HEAD") return new Response(null, { status: 200 });
    return new Response(null, { status: 404 });
  };
  let err: unknown;
  await withFetch(script, `/${S3_BUCKET}/`, async () => {
    try {
      await applyPrune(s3(), signerStub, handPlan(segs, []));
    } catch (e) {
      err = e;
    }
  });
  const p = (err as PruneApplyError | undefined)?.progress as unknown as Record<string, number> | undefined;
  ok("a partial apply throws PruneApplyError", err instanceof PruneApplyError);
  ok("the loop went PAST the first refusal: the next segment was removed", p?.orphansDeleted === 1);
  ok("and past the second: the last one was reached (and hidden by a marker)", p?.orphansHidden === 1);
  ok("the refusal whose object shows a future retain-until is counted as a lock", p?.refusedLocked === 1);
  ok("the refusal whose object shows no lock, on a bucket with no Object Lock, is access-denied", p?.refusedDenied === 1);
  ok("wormBlocked is set by the READ lock, not by the words of the refusal", (err as PruneApplyError).wormBlocked === true);

  // The error the S3 delete throws: the status, the sanitised <Code>, the lock-named boolean, no body text.
  let e1: unknown;
  let e2: unknown;
  await withFetch((m, k) => (m === "DELETE" && k.includes("a.seg") ? new Response(GCS_RETENTION, { status: 403 }) : new Response(ACCESS_DENIED, { status: 403 })), `/${S3_BUCKET}/`, async () => {
    const d = s3();
    e1 = await d.delete("seg/bb/b.seg").catch((e) => e);
    e2 = await d.delete("seg/aa/a.seg").catch((e) => e);
  });
  ok("a refused S3 delete throws DestStatusError with the status", e1 instanceof DestStatusError && e1.status === 403);
  ok("it carries the sanitised S3 <Code>", (e1 as DestStatusError).code === "AccessDenied");
  ok("its message is the production shape, with no body text", (e1 as Error).message === "DELETE seg/bb/b.seg: status 403");
  ok("a bare AccessDenied does not name a lock", (e1 as DestStatusError).lockNamed !== true);
  ok("a refusal whose body names the retention (Google Cloud's measured shape) sets lockNamed", (e2 as DestStatusError).lockNamed === true);

  // objectLockHold: the reading the classifier relies on, state by state.
  const reads: Record<string, string | undefined> = {};
  await withFetch(
    (_m, k, search) => {
      if (search === "?object-lock=") return new Response(`<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`, { status: 200 });
      if (k === "hold") return new Response(null, { status: 200, headers: { "x-amz-object-lock-legal-hold": "ON" } });
      if (k === "past") return new Response(null, { status: 200, headers: { "x-amz-object-lock-mode": "GOVERNANCE", "x-amz-object-lock-retain-until-date": "2020-01-01T00:00:00Z" } });
      if (k === "denied") return new Response(null, { status: 403 });
      if (k === "bare") return new Response(null, { status: 200 });
      return new Response(null, { status: 404 });
    },
    `/${S3_BUCKET}/`,
    async () => {
      const d = s3() as unknown as { objectLockHold?: (k: string) => Promise<string> };
      for (const k of ["hold", "past", "denied", "bare", "gone"]) reads[k] = await d.objectLockHold?.(k);
    },
  );
  ok("a legal hold that is ON is held", reads.hold === "held");
  ok("a retain-until in the past is not-held", reads.past === "not-held");
  ok("a HEAD that is itself refused is unknown, never held", reads.denied === "unknown");
  ok("no lock headers on a bucket WITH Object Lock is unknown (S3 hides them without s3:GetObjectRetention)", reads.bare === "unknown");
  ok("an absent object is unknown", reads.gone === "unknown");

  // Azure: the refusal code itself names the immutability policy, so it is read as a lock, and the loop goes on.
  const azure = new AzureBlobDestination("https://acct.blob.core.windows.net", "archive", "acct", "ZmFrZS1rZXktZm9yLXN0cmluZy10by1zaWduLW9ubHk=", { now: () => NOW });
  let az: unknown;
  await withFetch(
    (m, k) => (m === "DELETE" && k === "seg/01/locked.seg" ? new Response(null, { status: 409, headers: { "x-ms-error-code": "BlobImmutableDueToPolicy" } }) : new Response(null, { status: 202 })),
    "/archive/",
    async () => {
      try {
        await applyPrune(azure, signerStub, handPlan(["seg/01/locked.seg", "seg/02/fine.seg"], []));
      } catch (e) {
        az = e;
      }
    },
  );
  const azp = (az as PruneApplyError | undefined)?.progress as unknown as Record<string, number> | undefined;
  ok("Azure: BlobImmutableDueToPolicy is counted as a lock", azp?.refusedLocked === 1);
  ok("Azure: the loop kept going and removed the next blob", azp?.orphansDeleted === 1);
}

// ---- PART 4: the scheduled pass records progress and is not healthy -----------------------------------

class MockR2 {
  store = new Map<string, Uint8Array>();
  failKey: string | null = null;
  async get(key: string) {
    const v = this.store.get(key);
    if (!v) return null;
    return { arrayBuffer: async () => v.slice().buffer, etag: `"${key.length}:${v.length}"` };
  }
  async head(key: string) {
    const v = this.store.get(key);
    return v ? { etag: `"${key.length}:${v.length}"` } : null;
  }
  async put(key: string, body: ArrayBuffer | Uint8Array) {
    const b = body instanceof Uint8Array ? body : new Uint8Array(body);
    this.store.set(key, b);
    return { etag: `"${key.length}:${b.length}"` };
  }
  async delete(key: string): Promise<void> {
    if (key === this.failKey) throw new Error("simulated R2 fault on delete");
    this.store.delete(key);
  }
  async list(opts: { prefix?: string }) {
    const prefix = opts.prefix ?? "";
    return { objects: [...this.store.keys()].filter((k) => k.startsWith(prefix)).map((key) => ({ key })), truncated: false };
  }
}

async function part4(): Promise<void> {
  console.log("\nPART 4: the scheduled pass records what a partial apply did, and the next pass finishes it:");
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer = await loadSigner(signerPrivateB64);
  const bg = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const r2 = new MockR2();
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const scheduler = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(typeof input === "string" ? input : input.toString(), init)) } as unknown as DurableObjectStub;
  await storage.put(`dp:${DP}`, { config: { id: DP, name: DP, enabled: true, source: { type: "kv", binding: "SRC" }, schedule: { cadenceSeconds: 3600 }, retention: { keepRuns: 1, enforce: true } }, nextRunAt: 0, lastRunId: null, inFlight: false } as unknown as DownpipeState);
  const master = rand(32);
  const entries: RunlogEntry[] = [];
  for (let i = 0; i < 3; i++) {
    const at = `2026-06-0${i + 1}T00:00:00.000Z`;
    const prev = i === 0 ? null : RUNS[i - 1]!;
    const archive = await buildArchive({ downpipeId: DP, downpipeName: DP, cadence: "3600s", runId: RUNS[i]!, master, recipients: [bg.entry, op.entry], signer, records: [{ sourceType: "kv", name: "k", value: utf8(`v${i}`), namespace: "ns" }], windowStart: at, windowEnd: at, createdAt: at, runlogIndex: i + 1, prevRunId: prev, skipRunlog: true, randomNonce: () => rand(16), randomSalt: () => rand(16) });
    for (const [key, body] of archive) r2.store.set(key, body);
    entries.push({ index: i + 1, runId: RUNS[i]!, downpipeId: DP, time: at, recordCount: 1, prevRunId: prev, status: "active" });
  }
  const { runlog, sig } = await signRunlog(entries, signer.edPrivate, signer.mldsaSecret);
  r2.store.set("_RECOVERY/RUNLOG", runlog);
  r2.store.set("_RECOVERY/RUNLOG.sig", utf8(b64urlEncode(sig)));
  const env = { SCHEDULER: {} as unknown as DurableObjectNamespace, DEST_KIND: "r2", DEST_R2: r2 as unknown as R2Bucket, SIGNER_PRIVATE: signerPrivateB64, OPERATIONAL_PRIVATE: b64urlEncode(op.identity) } as unknown as Env;
  const treeLeft = (): number => [...r2.store.keys()].filter((k) => k.startsWith(runTreePrefix(RUNS[0]!)) || k.startsWith(runTreePrefix(RUNS[1]!))).length;
  const treeBefore = treeLeft();

  // The fault lands on the LAST object the apply deletes (run 2's root manifest), so everything before it
  // was really done and the row must say so.
  r2.failKey = `run/${RUNS[1]!}/root.manifest.json`;
  let passErr: unknown;
  try {
    await runRetentionPrunes(env, scheduler);
  } catch (e) {
    passErr = e;
  }
  ok("a pass whose enforced apply failed a delete does NOT resolve as a healthy pass", passErr instanceof Error && passErr.name === "RetentionApplyIncompleteError");
  const rec = ((await (await scheduler.fetch("https://do/retention-state", { method: "GET" })).json()) as { record?: RetentionPassRecord }).record;
  const row = rec?.downpipes.find((d) => d.id === DP);
  ok("the pass record carries an error row for the downpipe", row?.outcome === "error");
  ok("the row records the runs the apply superseded (2), not 0", row?.supersededRuns === 2);
  ok(`the row records the objects the apply removed (${(row?.runTreeObjects ?? 0) + (row?.orphanSegs ?? 0)}), not 0`, (row?.runTreeObjects ?? 0) + (row?.orphanSegs ?? 0) === treeBefore - 1 + 2);
  ok("the row records the retained run count, not 0", row?.retainedRuns === 1);
  ok("one tree object is left behind by the fault", treeLeft() === 1);

  // The next scheduled pass, with the fault gone, finishes the job.
  r2.failKey = null;
  let pass2Err: unknown;
  try {
    await runRetentionPrunes(env, scheduler);
  } catch (e) {
    pass2Err = e;
  }
  const rec2 = ((await (await scheduler.fetch("https://do/retention-state", { method: "GET" })).json()) as { record?: RetentionPassRecord }).record;
  ok("the next scheduled pass is healthy", pass2Err === undefined);
  ok("the next scheduled pass removed what was left", treeLeft() === 0);
  ok("and recorded it as applied", rec2?.downpipes.find((d) => d.id === DP)?.outcome === "applied");
}

// ---- PART 5: one refusal vocabulary --------------------------------------------------------------------

function part5(): void {
  console.log("\nPART 5: the pass record's refusal classes are the fault ring's:");
  const mine = (retentionRecord as unknown as { RETENTION_REFUSAL_CLASSES?: readonly string[] }).RETENTION_REFUSAL_CLASSES;
  ok("RETENTION_REFUSAL_CLASSES equals WORM_REFUSAL_CLASSES, member for member", Array.isArray(mine) && mine.join("|") === [...WORM_REFUSAL_CLASSES].join("|"));
  ok("the fault ring has a class for a lock that could not be read", (WORM_REFUSAL_CLASSES as readonly string[]).includes("could-not-tell"));
}

async function main(): Promise<void> {
  await part1();
  await part2();
  await part3();
  await part4();
  part5();
  console.log(failures === 0 ? "\nPRUNE APPLY TRUTH PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures, checks);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
