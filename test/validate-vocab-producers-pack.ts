// Producers of three support-pack vocabularies, proved end to end: for each member, the real fault (or the real
// resolution branch) runs through the real code, and the member is read back out of the support-pack section
// that carries it. A member the engine cannot produce is a promise the pack cannot keep.
//
//   R. RESTORE_FAILURE_CLASSES readback-failed, cf-config-surface and media-upload: one real runRestore apply
//      over a real sealed archive meets a sink that persists the wrong bytes, a Cloudflare surface that refuses
//      the write, and an images record whose bytes are a video. The failures are tallied by the router's own
//      restoreFailureTally onto the restore-verified anchor in a real SchedulerDO, and the pack's configEvents
//      section (fetchConfigEvents) carries failuresByClass.
//   P. REPLICA_FAULT_REASONS copy-failed and runlog-corrupt: the real replication pass (replicateBacklog) copies
//      a sealed run from the deploy-time R2 binding to a console S3 destination that refuses the object PUT,
//      that holds a RUNLOG signed by another key, or that holds a RUNLOG that does not parse. The pack's
//      sealFaults section (fetchSealFaults) and replication section (fetchReplication) carry the reason and its
//      next step. A clean target records no fault (the noise line). Every other reason, posted to the ring, is
//      read back with a next step too.
//   D. DEST_RESOLUTION_BRANCHES: every branch of resolveDestination, read out of the pack's destResolution
//      section (fetchDestResolution) over a real SchedulerDO.
//
// In-memory doubles only: no network, no deploy, no cost. Run: node test/validate-vocab-producers-pack.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { runRestore } from "../src/admin/restore.ts";
import { type RestoreResult, restoreFailureTally } from "../src/admin/restore-types.ts";
import { recordAudit } from "../src/admin/router-audit.ts";
import type { Caller } from "../src/admin/identity.ts";
import { fetchConfigEvents } from "../src/admin/support-sections-audit.ts";
import { fetchDestResolution } from "../src/admin/support-sections-config.ts";
import { fetchReplication, fetchSealFaults } from "../src/admin/support-sections-seal.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { R2Destination } from "../src/dest/r2.ts";
import { S3Destination } from "../src/dest/s3.ts";
import type { Env } from "../src/env.d.ts";
import { buildArchive, type RecipientEntry, type RunlogEntry, type Signer, type WriteRecord } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { DownpipeConfig, RunHistoryEntry } from "../src/sched/types.ts";
import { appendRunlog } from "../src/seal/pipeline.ts";
import { replicateBacklog } from "../src/seal/replicate.ts";
import { postSealFault } from "../src/seal/seal-fault-post.ts";
import { REPLICA_FAULT_REASONS } from "../src/seal/seal-faults.ts";
import type { CfApi, CfPage } from "../src/sources/cf-config-surfaces.ts";
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
function toAB(b: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(b.byteLength);
  new Uint8Array(out).set(b);
  return out;
}

const OWNER: Caller = { method: "token", email: "owner@acme.example", subject: null, groups: [], role: "owner" };

function makeDO(): { storage: MockStorage; scheduler: DurableObjectStub } {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const scheduler = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(input, init)) } as unknown as DurableObjectStub;
  return { storage, scheduler };
}

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// ---------------------------------------------------------------------------------------------------------
// R. Restore failure classes
// ---------------------------------------------------------------------------------------------------------
const RESTORE_RUN = "01BX5ZZKBKACTAV9WEVGEMMVV1";
const ACCT = "acct-vocab";
const BUCKET = "media";
// A real MP4 container header: an "images" record holding these bytes is a cross-type mismatch.
const REAL_MP4 = new Uint8Array([0, 0, 0, 0x18, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6f, 0x6d, 0, 0, 2, 0, 0x69, 0x73, 0x6f, 0x6d, 1, 2, 3, 4]);

class MockR2Archive {
  store = new Map<string, Uint8Array>();
  async get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer>; etag: string } | null> {
    const v = this.store.get(key);
    return v ? { arrayBuffer: async () => toAB(v), etag: `"${key.length}"` } : null;
  }
  async head(key: string): Promise<{ etag: string } | null> {
    return this.store.has(key) ? { etag: `"${key.length}"` } : null;
  }
}

// The live R2 sink. corrupt:true accepts every write and persists it with its first byte flipped, so the
// post-write readback reads back bytes that do not hash to the signed manifest.
class LiveR2 {
  stored = new Map<string, Uint8Array>();
  private corrupt: boolean;
  constructor(corrupt: boolean) {
    this.corrupt = corrupt;
  }
  async put(key: string, body: ReadableStream<Uint8Array> | ArrayBuffer | ArrayBufferView | string | null): Promise<{ etag: string }> {
    let bytes: Uint8Array;
    if (body instanceof ReadableStream) bytes = new Uint8Array(await new Response(body).arrayBuffer());
    else if (typeof body === "string") bytes = utf8(body);
    else if (body instanceof ArrayBuffer) bytes = new Uint8Array(body.slice(0));
    else if (body && ArrayBuffer.isView(body)) bytes = new Uint8Array(body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength));
    else bytes = new Uint8Array(0);
    if (this.corrupt && bytes.length > 0) {
      bytes = bytes.slice();
      bytes[0] = bytes[0]! ^ 0xff;
    }
    this.stored.set(key, bytes);
    return { etag: "etag" };
  }
  async get(key: string): Promise<{ body: ReadableStream<Uint8Array> } | null> {
    const v = this.stored.get(key);
    return v ? { body: new Response(v.slice()).body! } : null;
  }
}

// A Cloudflare API double over an empty live account: every snapshot item is a create. refuse:true throws the
// shape the real CfApi throws for a token without the edit scope.
function cfDouble(refuse: boolean): CfApi {
  return {
    get: async () => [],
    getPage: async (): Promise<CfPage> => ({ result: [] }),
    send: async (method, path) => {
      if (refuse) throw new Error(`Cloudflare API ${method} ${path}: Authentication error (403): the API token lacks the edit scope for this resource`);
      return {};
    },
  };
}

async function restoreSection(): Promise<void> {
  console.log("-- R. restore failure classes reach the pack's configEvents --");
  const signerB64 = b64urlEncode(concat(rand(32), rand(32)));
  const signer: Signer = await loadSigner(signerB64);
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const records: WriteRecord[] = [
    { sourceType: "r2", name: "r1", value: utf8("an object the sink will persist wrongly"), bucket: BUCKET },
    { sourceType: "cf-config", name: "dns", value: utf8(JSON.stringify([{ type: "A", name: "new.example.com", content: "3.3.3.3", proxied: false, ttl: 1 }])), account: ACCT },
    { sourceType: "images", name: "img-swap/blob", value: REAL_MP4, account: ACCT },
  ];
  const archive = await buildArchive({
    downpipeId: "dp_vocab_restore", downpipeName: "vocab-restore", cadence: "3600s", runId: RESTORE_RUN,
    master: rand(32), recipients: [breakGlass.entry, op.entry], signer, records,
    windowStart: "2026-10-01T00:00:00.000Z", windowEnd: "2026-10-01T00:00:01.000Z", createdAt: "2026-10-01T00:00:01.000Z",
    runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
  });
  const archiveR2 = new MockR2Archive();
  for (const [k, b] of archive) archiveR2.store.set(k, b);

  const apply = async (faulty: boolean): Promise<RestoreResult> => {
    const env = {
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      DEST_KIND: "r2",
      DEST_R2: archiveR2 as unknown as R2Bucket,
      SIGNER_PRIVATE: signerB64,
      OPERATIONAL_PRIVATE: b64urlEncode(op.identity),
      [`R2_${BUCKET}`]: new LiveR2(faulty) as unknown as R2Bucket,
    } as unknown as Env;
    return (await runRestore(env, { runId: RESTORE_RUN, confirm: true, cfConfig: { token: "tok", accountId: ACCT }, mediaRestore: { token: "tok", accountId: ACCT } }, null, {
      cfApiFactory: () => cfDouble(faulty),
      mediaUploaderFactory: () => ({
        uploadImage: async () => { throw new Error("the uploader must not be reached for a type-mismatched record"); },
        uploadStreamVideo: async () => { throw new Error("no stream record in this archive"); },
      }),
    })) as RestoreResult;
  };

  const res = await apply(true);
  const clsOf = (name: string) => res.failures.find((f) => f.name === name)?.cls;
  ok("the sink persisted the wrong bytes: r1 fails readback-failed", clsOf("r1") === "readback-failed");
  ok("the Cloudflare surface refused the write: dns fails cf-config-surface", clsOf("dns") === "cf-config-surface");
  ok("the images record holds a video: img-swap/blob fails media-upload", clsOf("img-swap/blob") === "media-upload");

  const tally = restoreFailureTally(res.failures);
  const { scheduler } = makeDO();
  await recordAudit(scheduler, OWNER, null, "restore-verified", "failed", {
    kind: "restore-receipt", runId: RESTORE_RUN, receiptSha384: res.receipt?.receiptSha384 ?? "", recordsRestored: res.receipt?.summary.recordsRestored ?? 0, allVerified: res.receipt?.summary.allVerified ?? false,
    failures: res.failures.length, ...(Object.keys(tally).length > 0 ? { failuresByClass: tally } : {}),
  });
  const { events } = await fetchConfigEvents(scheduler);
  const anchor = (events as Array<Record<string, unknown>>).find((e) => e.action === "restore-verified");
  const byClass = (anchor?.failuresByClass ?? {}) as Record<string, number>;
  ok("POPULATION: the pack carries the restore-verified anchor", anchor !== undefined);
  for (const m of ["readback-failed", "cf-config-surface", "media-upload"]) ok(`the pack's failuresByClass carries ${m}`, byClass[m] === 1);
  ok("the pack's classes sum to the failure count", Object.values(byClass).reduce((a, b) => a + b, 0) === res.failures.length);
  ok("no record name reaches the pack's anchor", !JSON.stringify(anchor ?? {}).includes("img-swap") && !JSON.stringify(anchor ?? {}).includes("\"r1\""));

  // NOISE: the same apply against a sink that keeps the bytes and an API that accepts the write fails only the
  // media record (its bytes are still a video), so the first two classes are not stamped on a clean apply.
  const clean = await apply(false);
  const cleanTally = restoreFailureTally(clean.failures);
  ok("NOISE: a sink that keeps the bytes produces no readback-failed", cleanTally["readback-failed"] === undefined);
  ok("NOISE: an API that accepts the write produces no cf-config-surface", cleanTally["cf-config-surface"] === undefined);
}

// ---------------------------------------------------------------------------------------------------------
// P. Replica fault reasons
// ---------------------------------------------------------------------------------------------------------
const DP = "dp-vocab-repl";
const S3_ID = "dest-s3vocab";
const S3_ENDPOINT = "https://s3-vocab.example.test";
const S3_BUCKET = "bkt";
const REPL_RUN = "01K5ZZKBKACTAV9WEVGEMMVV01";

// The deploy-time destination: an R2 binding with R2's precondition semantics.
class MockR2Bucket {
  store = new Map<string, { bytes: Uint8Array; etag: string }>();
  private seq = 0;
  async put(key: string, value: ArrayBuffer | ArrayBufferView | ReadableStream | string, options?: { onlyIf?: R2Conditional }): Promise<{ etag: string } | null> {
    const existing = this.store.get(key);
    const c = options?.onlyIf;
    if (c?.etagDoesNotMatch === "*" && existing) return null;
    if (c?.etagMatches !== undefined && (!existing || existing.etag !== c.etagMatches)) return null;
    let bytes: Uint8Array;
    if (value instanceof ReadableStream) bytes = new Uint8Array(await new Response(value).arrayBuffer());
    else if (typeof value === "string") bytes = utf8(value);
    else if (value instanceof ArrayBuffer) bytes = new Uint8Array(value.slice(0));
    else bytes = new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
    const etag = `r2-${++this.seq}`;
    this.store.set(key, { bytes, etag });
    return { etag };
  }
  async get(key: string): Promise<{ etag: string; httpEtag: string; arrayBuffer(): Promise<ArrayBuffer> } | null> {
    const r = this.store.get(key);
    if (!r) return null;
    const snap = r.bytes.slice();
    return { etag: r.etag, httpEtag: `"${r.etag}"`, arrayBuffer: async () => snap.buffer };
  }
  async head(key: string): Promise<{ etag: string; httpEtag: string } | null> {
    const r = this.store.get(key);
    return r ? { etag: r.etag, httpEtag: `"${r.etag}"` } : null;
  }
  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }
  async list(o?: { prefix?: string }): Promise<R2Objects> {
    const prefix = o?.prefix ?? "";
    const objects = [...this.store.keys()].filter((k) => k.startsWith(prefix)).sort().map((key) => ({ key }) as R2Object);
    return { objects, truncated: false, delimitedPrefixes: [] } as unknown as R2Objects;
  }
}

// The console destination: a path-style S3 wire over a map. refusePut makes every object PUT answer 403, the
// answer a bucket policy that denies writes gives; reads and lists still answer.
class S3Wire {
  store = new Map<string, { bytes: Uint8Array; etag: string }>();
  refusePut = false;
  private seq = 0;
  private realFetch = globalThis.fetch;
  install(): void {
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const u = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
      if (u.origin !== S3_ENDPOINT) return this.realFetch(input as RequestInfo, init);
      return this.handle(u, init ?? {});
    }) as typeof fetch;
  }
  uninstall(): void {
    globalThis.fetch = this.realFetch;
  }
  private async handle(u: URL, init: RequestInit): Promise<Response> {
    const method = (init.method ?? "GET").toUpperCase();
    const headers = new Headers(init.headers);
    const path = u.pathname.split("/").slice(2).map(decodeURIComponent).join("/");
    if (method === "GET" && u.searchParams.get("list-type") === "2") {
      const prefix = u.searchParams.get("prefix") ?? "";
      const keys = [...this.store.keys()].filter((k) => k.startsWith(prefix)).sort();
      const xml = `<ListBucketResult>${keys.map((k) => `<Contents><Key>${k.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</Key></Contents>`).join("")}<IsTruncated>false</IsTruncated></ListBucketResult>`;
      return new Response(xml, { status: 200 });
    }
    if (method === "PUT") {
      if (this.refusePut) return new Response("<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>", { status: 403 });
      const existing = this.store.get(path);
      if (headers.get("if-none-match") === "*" && existing) return new Response("", { status: 412 });
      const im = headers.get("if-match");
      if (im !== null && (!existing || existing.etag !== im)) return new Response("", { status: 412 });
      const body = new Uint8Array(await new Response(init.body as BodyInit).arrayBuffer());
      const etag = `"s3-${++this.seq}"`;
      this.store.set(path, { bytes: body, etag });
      return new Response("", { status: 200, headers: { etag } });
    }
    if (method === "GET" || method === "HEAD") {
      const r = this.store.get(path);
      if (!r) return new Response(method === "HEAD" ? null : "<Error><Code>NoSuchKey</Code></Error>", { status: 404 });
      return new Response(method === "HEAD" ? null : r.bytes.slice(), { status: 200, headers: { etag: r.etag, "content-length": String(r.bytes.length) } });
    }
    if (method === "DELETE") {
      this.store.delete(path);
      return new Response(null, { status: 204 });
    }
    return new Response("", { status: 400 });
  }
}

function storedRows(): Record<string, unknown> {
  return {
    list: [
      { id: "deploy", label: "Deploy-time destination", source: "deploy", endpoint: "", bucket: "", region: "", accessKeyId: "", secretAccessKey: "", setAt: 1, setBy: null, verifiedAt: 1, deleteProbe: "other" },
      { id: S3_ID, label: "S3", endpoint: S3_ENDPOINT, bucket: S3_BUCKET, region: "us-east-1", accessKeyId: "AKIDEXAMPLE", secretAccessKey: "not-a-real-secret", addressing: "path", setAt: 1, setBy: null, verifiedAt: 1, deleteProbe: "ok" },
    ],
    defaultId: "deploy",
  };
}

type TargetState = "clean" | "refuse-put" | "foreign-signed-runlog" | "unparsable-runlog";

// replicaPass seals one run to the deploy-time R2 binding, prepares the S3 target, runs the real replication
// pass against a real SchedulerDO, and returns what the pack's sections carry for the S3 target.
async function replicaPass(state: TargetState): Promise<{ faultReasons: string[]; replReason: unknown; faultSteps: string[]; replStep: unknown }> {
  const signerB64 = b64urlEncode(rand(64));
  const signer = await loadSigner(signerB64);
  const recipients = [makeRecipient("break-glass").entry, makeRecipient("operational").entry];
  const r2 = new MockR2Bucket();
  const archive = await buildArchive({
    downpipeId: DP, downpipeName: "vocab-repl", cadence: "3600s", runId: REPL_RUN, master: rand(32), recipients, signer,
    records: [{ sourceType: "kv" as const, name: "rec-1", namespace: "ns", value: utf8("value-1") }],
    windowStart: "2026-10-01T00:00:00.000Z", windowEnd: "2026-10-01T00:00:01.000Z", createdAt: "2026-10-01T00:00:01.000Z",
    runlogIndex: 1, prevRunId: null, skipRunlog: true, randomNonce: () => rand(16), randomSalt: () => rand(16),
  });
  for (const [k, v] of archive) await r2.put(k, v);
  const entry: RunlogEntry = { index: 1, runId: REPL_RUN, downpipeId: DP, time: "2026-10-01T01:00:00.000Z", recordCount: 1, prevRunId: null, status: "active" };
  await appendRunlog(new R2Destination(r2 as unknown as R2Bucket), signer, entry, undefined, { relinkLocalPrev: true });

  const s3 = new S3Wire();
  s3.install();
  try {
    const s3Dest = new S3Destination(S3_ENDPOINT, S3_BUCKET, "us-east-1", "AKIDEXAMPLE", "not-a-real-secret", { addressing: "path" });
    if (state === "foreign-signed-runlog") {
      // A RUNLOG that parses, signed by a key that is not this engine's: the append must refuse to re-sign it.
      const foreign = await loadSigner(b64urlEncode(rand(64)));
      await appendRunlog(s3Dest, foreign, { index: 7, runId: "01K5ZZKBKACTAV9WEVGEMMVV77", downpipeId: "dp-other", time: "2026-10-01T00:30:00.000Z", recordCount: 1, prevRunId: null, status: "active" }, undefined, { relinkLocalPrev: true });
    }
    if (state === "unparsable-runlog") await s3Dest.put("_RECOVERY/RUNLOG", utf8("this is not a RUNLOG"));
    s3.refusePut = state === "refuse-put";

    const { storage, scheduler } = makeDO();
    storage.seed("destinations", storedRows());
    const env = { DEST_R2: r2 as unknown as R2Bucket, SIGNER_PRIVATE: signerB64 } as unknown as Env;
    const config = { id: DP, name: "vocab-repl", enabled: true, cadenceSeconds: 3600, source: { type: "kv", namespaceId: "ns" }, destinationIds: ["deploy", S3_ID] } as unknown as DownpipeConfig;
    const history = [{ runId: REPL_RUN, index: 1, startedAt: "2026-10-01T01:00:00.000Z", status: "ok", destinationId: "deploy" }] as RunHistoryEntry[];
    await replicateBacklog(env, scheduler, config, history);

    const faults = (await fetchSealFaults(scheduler)) as Array<Record<string, unknown>>;
    const targetFaults = faults.filter((f) => f.kind === "replica-target-fault" && f.destinationId === S3_ID);
    const faultReasons = targetFaults.map((f) => String(f.replicaReason));
    const faultSteps = targetFaults.map((f) => (typeof f.nextStep === "string" ? f.nextStep : ""));
    const repl = await fetchReplication(scheduler);
    const replRow = (repl?.[DP] ?? []).find((r) => r.id === S3_ID);
    return { faultReasons, replReason: replRow?.reason, faultSteps, replStep: replRow?.nextStep };
  } finally {
    s3.uninstall();
  }
}

async function replicaSection(): Promise<void> {
  console.log("-- P. replica fault reasons reach the pack's sealFaults and replication sections --");
  const clean = await replicaPass("clean");
  ok("NOISE: a target that takes the copy records no replica-target-fault", clean.faultReasons.length === 0);
  ok("NOISE: and its replication row carries no reason", clean.replReason === undefined);
  ok("NOISE: and its replication row carries no next step", clean.replStep === undefined);

  const refused = await replicaPass("refuse-put");
  ok("a target that refuses the object PUT: sealFaults carries copy-failed", refused.faultReasons.includes("copy-failed"));
  ok("a target that refuses the object PUT: the replication row reason is copy-failed", refused.replReason === "copy-failed");
  // The pack names the next step itself. copy-failed is retried by the next pass; the evidence is a refused PUT,
  // not a network fault, so the step must not send support to networking.
  const copyStep = refused.faultSteps[0] ?? "";
  ok("copy-failed: the sealFaults row names re-copying as the remedy", /re-?copy/i.test(copyStep) && /next (replication )?pass/i.test(copyStep));
  ok("copy-failed: the next step does not point at networking", copyStep !== "" && !/network/i.test(copyStep));
  ok("copy-failed: the replication row carries the same next step", refused.replStep === copyStep);

  const foreign = await replicaPass("foreign-signed-runlog");
  ok("a target RUNLOG the engine cannot vouch for: sealFaults carries runlog-corrupt", foreign.faultReasons.includes("runlog-corrupt"));
  ok("a target RUNLOG the engine cannot vouch for: the replication row reason is runlog-corrupt", foreign.replReason === "runlog-corrupt");
  runlogCorruptStep("a target RUNLOG the engine cannot vouch for", foreign);

  const garbled = await replicaPass("unparsable-runlog");
  ok("a target RUNLOG that does not parse: sealFaults carries runlog-corrupt (not runlog-unreadable)", garbled.faultReasons.includes("runlog-corrupt") && !garbled.faultReasons.includes("runlog-unreadable"));
  ok("a target RUNLOG that does not parse: the replication row reason is runlog-corrupt", garbled.replReason === "runlog-corrupt");
  runlogCorruptStep("a target RUNLOG that does not parse", garbled);

  // Every other reason carries a next step too: one replica-target-fault per member, posted through the real
  // seal-fault post path and read back out of the pack.
  const { scheduler } = makeDO();
  for (const r of REPLICA_FAULT_REASONS) await postSealFault(scheduler, { kind: "replica-target-fault", at: 1, downpipeId: DP, destinationId: `t-${r}`, replicaReason: r });
  const rows = (await fetchSealFaults(scheduler)) as Array<Record<string, unknown>>;
  for (const r of REPLICA_FAULT_REASONS) {
    const row = rows.find((f) => f.replicaReason === r);
    ok(`${r}: the pack's sealFaults row carries a next step`, typeof row?.nextStep === "string" && (row.nextStep as string).length > 20);
  }
  ok("POPULATION: the ring holds one row per reason", rows.length === REPLICA_FAULT_REASONS.length);
}

// runlogCorruptStep: no retry clears runlog-corrupt. The step must say so, send an Owner to the RUNLOG signature
// review and its two attended repairs, and name the fresh destination for a duplicate index.
function runlogCorruptStep(label: string, p: { faultSteps: string[]; replStep: unknown }): void {
  const step = p.faultSteps[0] ?? "";
  ok(`${label}: the next step says no retry clears it`, /no retry/i.test(step));
  ok(`${label}: the next step sends an Owner to the RUNLOG signature review`, /Owner/.test(step) && /Keys > Posture > Destination RUNLOG signature/.test(step) && step.includes("/runlog/signature"));
  ok(`${label}: the next step names the attended re-sign and the chain relink`, step.includes("/runlog/resign") && step.includes("/runlog/relink"));
  ok(`${label}: the next step names a fresh destination for a duplicate index`, /duplicate index/i.test(step) && /fresh destination/i.test(step));
  ok(`${label}: the replication row carries the same next step`, p.replStep === step);
}

// ---------------------------------------------------------------------------------------------------------
// D. Destination resolution branches
// ---------------------------------------------------------------------------------------------------------
async function destSection(): Promise<void> {
  console.log("-- D. every resolution branch reaches the pack's destResolution section --");
  const R2_ENV = { DEST_R2: {} } as unknown as Env;
  const NO_ENV = {} as unknown as Env;
  const downpipes = [{ config: { id: "dp-a", destinationIds: ["deploy", S3_ID] } }, { config: { id: "dp-b", destinationIds: ["gone"] } }];

  const { storage, scheduler } = makeDO();
  storage.seed("destinations", storedRows());
  const dr = (await fetchDestResolution(R2_ENV, scheduler, downpipes)) as Record<string, unknown>;
  const rows = (dr.resolution ?? []) as Array<Record<string, unknown>>;
  const branchOf = (id: string) => rows.find((r) => r.id === id)?.branch;
  ok("a console row resolves console-stored", branchOf(S3_ID) === "console-stored");
  ok("\"deploy\" with the DEST_R2 binding resolves deploy-env-binding", branchOf("deploy") === "deploy-env-binding");
  ok("a named id with no row resolves missing", branchOf("gone") === "missing");

  const noEnv = (await fetchDestResolution(NO_ENV, scheduler, downpipes)) as Record<string, unknown>;
  const deployNoEnv = ((noEnv.resolution ?? []) as Array<Record<string, unknown>>).find((r) => r.id === "deploy");
  ok("\"deploy\" with no env destination resolves deploy-binding-missing", deployNoEnv?.branch === "deploy-binding-missing");

  const empty = makeDO();
  const bare = (await fetchDestResolution(R2_ENV, empty.scheduler, [])) as Record<string, unknown>;
  ok("the default on an estate with no stored destinations resolves env-no-collection", (bare.defaultResolution as Record<string, unknown> | undefined)?.branch === "env-no-collection");
}

async function main(): Promise<void> {
  await restoreSection();
  await replicaSection();
  await destSection();
  console.log(failures === 0 ? `\nVOCAB PRODUCERS PACK PASS (${checks} checks)\n` : `\nVOCAB PRODUCERS PACK FAIL (${failures} of ${checks})\n`);
  verdictReached(failures, checks);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
