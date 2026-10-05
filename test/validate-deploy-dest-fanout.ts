// Validates that the synthetic deploy-time destination (DEPLOY_DEST_ID, "deploy") is a real member of a
// downpipe's destinationIds on every path that resolves one: the seal choice, the fan-out failover, the 3-2-1
// replication pass (as a target AND as the origin of a stranded run), the canary, and the restore/drill read
// walk. "deploy" resolves to the env-backed destination (the DEST_R2 binding here). Where "deploy" is named but
// the deployment has no env destination at all, each path refuses with deploy-binding-missing, never with the
// generic not-configured that names a removed destination.
//
// The engine is driven over in-memory doubles only: an R2 binding double for "deploy", a stubbed S3 wire for
// the console destination "dest-s3", and a scheduler stub that answers /dest-config exactly as the DO does (a
// stored record by id, the default record without one, null for an unknown id). Real sealed archives, a real
// hybrid signature and the real post-copy attestation run end to end. No network, no deploy, no cost.
//
// The table at the bottom runs every consumer against ["deploy", "dest-s3"] and ["deploy"] alone, with the env
// binding present and absent. Run: node test/validate-deploy-dest-fanout.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { b64urlEncode, utf8 } from "../src/crypto/bytes.ts";
import { buildArchive, parseRunlog, type RecipientEntry, type RunlogEntry, type Signer } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import { appendRunlog } from "../src/seal/pipeline.ts";
import { R2Destination } from "../src/dest/r2.ts";
import { S3Destination } from "../src/dest/s3.ts";
import { replicateBacklog } from "../src/seal/replicate.ts";
import { resolveDestForState, sealDestErrorClassOf, selectSealDestination } from "../src/cron/seal-dispatch.ts";
import { withRunDestFallback } from "../src/admin/router-sources.ts";
import { REASON_OBJECT_MISSING, REASON_ORIGIN_REMOVED } from "../src/restore-reasons.ts";
import { runCanaryCycle } from "../src/canary/cycle.ts";
import { destResolutionRefusalOf } from "../src/dest/factory.ts";
import type { Env } from "../src/env.d.ts";
import type { DownpipeState, RunHistoryEntry } from "../src/sched/types.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

const DP = "dp-fanout";
const S3_ID = "dest-s3";
const S3_ENDPOINT = "https://s3.example.test";
const S3_BUCKET = "bkt";
const RUN1 = "01K5ZZKBKACTAV9WEVGEMMVR01";
const RUN2 = "01K5ZZKBKACTAV9WEVGEMMVR02";

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

// ---------------------------------------------------------------------------------------------------------
// The deploy-time destination: an in-memory R2 binding with R2's documented precondition semantics.
// ---------------------------------------------------------------------------------------------------------
class MockR2Bucket {
  store = new Map<string, { bytes: Uint8Array; etag: string }>();
  ops = 0;
  private seq = 0;
  async put(key: string, value: ArrayBuffer | ArrayBufferView | ReadableStream | string, options?: { onlyIf?: R2Conditional }): Promise<{ etag: string } | null> {
    this.ops++;
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
    this.ops++;
    const r = this.store.get(key);
    if (!r) return null;
    const snap = r.bytes.slice();
    return { etag: r.etag, httpEtag: `"${r.etag}"`, arrayBuffer: async () => snap.buffer };
  }
  async head(key: string): Promise<{ etag: string; httpEtag: string } | null> {
    this.ops++;
    const r = this.store.get(key);
    return r ? { etag: r.etag, httpEtag: `"${r.etag}"` } : null;
  }
  async delete(key: string): Promise<void> {
    this.ops++;
    this.store.delete(key);
  }
  async list(o?: { prefix?: string; cursor?: string }): Promise<R2Objects> {
    this.ops++;
    const prefix = o?.prefix ?? "";
    const objects = [...this.store.keys()].filter((k) => k.startsWith(prefix)).sort().map((key) => ({ key }) as R2Object);
    return { objects, truncated: false, delimitedPrefixes: [] } as unknown as R2Objects;
  }
}

// ---------------------------------------------------------------------------------------------------------
// The console destination: a path-style S3 wire over a map. GET/PUT/HEAD/DELETE an object, a conditional PUT
// (If-None-Match: * / If-Match), and a single-page ListObjectsV2. `down` makes every write answer 503.
// ---------------------------------------------------------------------------------------------------------
class S3Wire {
  store = new Map<string, { bytes: Uint8Array; etag: string }>();
  down = false;
  ops = 0;
  private seq = 0;
  private realFetch = globalThis.fetch;
  install(): void {
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const u = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
      if (u.origin !== S3_ENDPOINT) return this.realFetch(input as RequestInfo, init);
      this.ops++;
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
      if (this.down) return new Response("<Error><Code>ServiceUnavailable</Code></Error>", { status: 503 });
      const existing = this.store.get(path);
      if (headers.get("if-none-match") === "*" && existing) return new Response("", { status: 412 });
      const im = headers.get("if-match");
      if (im !== null && (!existing || existing.etag !== im)) return new Response("", { status: 412 });
      const body = init.body instanceof ReadableStream ? new Uint8Array(await new Response(init.body).arrayBuffer()) : new Uint8Array(await new Response(init.body as BodyInit).arrayBuffer());
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
      if (this.down) return new Response("", { status: 503 });
      this.store.delete(path);
      return new Response(null, { status: 204 });
    }
    return new Response("", { status: 400 });
  }
}

// ---------------------------------------------------------------------------------------------------------
// The scheduler stub. /dest-config answers exactly as the DO's getDestConfigById does: a stored record by id,
// the DEFAULT record without an id, null for an id with no record. Every POST is captured for assertions.
// ---------------------------------------------------------------------------------------------------------
interface Posted {
  path: string;
  body: Record<string, unknown>;
}
function storedS3(): Record<string, unknown> {
  return { id: S3_ID, label: "S3", endpoint: S3_ENDPOINT, bucket: S3_BUCKET, region: "us-east-1", accessKeyId: "AKIDEXAMPLE", secretAccessKey: "not-a-real-secret", addressing: "path", setAt: 1, setBy: null, verifiedAt: 1, deleteProbe: "ok" };
}
function storedDeploy(): Record<string, unknown> {
  return { id: "deploy", label: "Deploy-time destination", source: "deploy", endpoint: "", bucket: "", region: "", accessKeyId: "", secretAccessKey: "", setAt: 1, setBy: null, verifiedAt: 1, deleteProbe: "other" };
}
function makeScheduler(opts: { runDests?: Record<string, string[]> } = {}): { stub: DurableObjectStub; posts: Posted[] } {
  const list = [storedDeploy(), storedS3()];
  const defaultId = "deploy";
  const posts: Posted[] = [];
  const stub = {
    fetch: async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const u = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
      if (u.pathname === "/dest-config") {
        const id = u.searchParams.get("id");
        const config = id ? (list.find((d) => d.id === id) ?? null) : (list.find((d) => d.id === defaultId) ?? null);
        return Response.json({ config });
      }
      if (u.pathname === "/runlog-lock/acquire") return Response.json({ acquired: true, token: "t" });
      if (u.pathname === "/downpipes/dests-for-run") {
        const ids = opts.runDests?.[u.searchParams.get("runId") ?? ""] ?? [];
        return Response.json({ destinationIds: ids });
      }
      let body: Record<string, unknown> = {};
      try {
        body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
      } catch {
        body = {};
      }
      posts.push({ path: u.pathname, body });
      return Response.json({ ok: true });
    },
  } as unknown as DurableObjectStub;
  return { stub, posts };
}

function stateWith(destinationIds: string[]): DownpipeState {
  return { config: { id: DP, name: "fanout", enabled: true, cadenceSeconds: 3600, source: { type: "kv", namespaceId: "ns" }, destinationIds } } as unknown as DownpipeState;
}

// ---------------------------------------------------------------------------------------------------------
// Real sealed archives: run-1 sealed to "deploy" (the R2 binding), run-2 sealed to "dest-s3".
// ---------------------------------------------------------------------------------------------------------
interface Keys {
  signer: Signer;
  signerPrivateB64: string;
  recipients: RecipientEntry[];
}
async function makeKeys(): Promise<Keys> {
  const signerPrivateB64 = b64urlEncode(rand(64));
  const signer = await loadSigner(signerPrivateB64);
  const recipients = ["break-glass", "operational"].map((role) => {
    const xk = x25519.keygen();
    return { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(rand(64)).encapKey } };
  });
  return { signer, signerPrivateB64, recipients };
}
function entryFor(index: number, runId: string, prev: string | null): RunlogEntry {
  return { index, runId, downpipeId: DP, time: `2026-09-24T0${index}:00:00.000Z`, recordCount: 1, prevRunId: prev, status: "active" };
}
async function sealInto(put: (k: string, v: Uint8Array) => Promise<void>, k: Keys, index: number, runId: string, prev: string | null): Promise<void> {
  const archive = await buildArchive({
    downpipeId: DP, downpipeName: "fanout", cadence: "3600s", runId, master: rand(32), recipients: k.recipients, signer: k.signer,
    records: [{ sourceType: "kv" as const, name: `rec-${index}`, namespace: "ns", value: utf8(`value-${index}`) }],
    windowStart: "2026-09-24T00:00:00.000Z", windowEnd: "2026-09-24T00:00:01.000Z", createdAt: "2026-09-24T00:00:01.000Z",
    runlogIndex: index, prevRunId: prev, skipRunlog: true, randomNonce: () => rand(16), randomSalt: () => rand(16),
  });
  for (const [key, v] of archive) await put(key, v);
}

function envWith(k: Keys, r2: MockR2Bucket | null): Env {
  return { ...(r2 ? { DEST_R2: r2 as unknown as R2Bucket } : {}), SIGNER_PRIVATE: k.signerPrivateB64 } as unknown as Env;
}

function runlogIds(bytes: Uint8Array | undefined): string[] {
  return bytes ? parseRunlog(bytes).map((e) => e.runId) : [];
}

async function caught(fn: () => Promise<unknown>): Promise<Error | null> {
  try {
    await fn();
    return null;
  } catch (e) {
    return e as Error;
  }
}

// ---------------------------------------------------------------------------------------------------------
// 1. SEAL + FAN-OUT: the seal choice from destinationIds
// ---------------------------------------------------------------------------------------------------------
async function sealChoice(k: Keys, s3: S3Wire): Promise<void> {
  console.log("-- 1. seal choice: \"deploy\" is a destination the run can seal to --");
  const r2 = new MockR2Bucket();
  const { stub } = makeScheduler();
  const env = envWith(k, r2);

  const sel = await selectSealDestination(env, stub, stateWith(["deploy", S3_ID]));
  ok("[\"deploy\", S3]: the run seals to \"deploy\" (the first reachable destination), not past it", !("allDown" in sel) && sel.destinationId === "deploy");
  ok("[\"deploy\", S3]: the seal config is the env-backed one (null override)", !("allDown" in sel) && sel.destConfig === null);
  ok("[\"deploy\", S3]: the write probe reached the R2 binding", r2.ops > 0);

  s3.down = true;
  try {
    const failover = await selectSealDestination(env, stub, stateWith([S3_ID, "deploy"]));
    ok("[S3 down, \"deploy\"]: the run fails over to \"deploy\" instead of recording all destinations down", !("allDown" in failover) && failover.destinationId === "deploy");
  } finally {
    s3.down = false;
  }

  const single = await caught(() => resolveDestForState(env, stub, stateWith(["deploy"])));
  ok("[\"deploy\"] alone: the single-destination resolution does not throw", single === null);
  const singleCfg = single === null ? await resolveDestForState(env, stub, stateWith(["deploy"])) : undefined;
  ok("[\"deploy\"] alone: it resolves to the env-backed destination (null override)", singleCfg === null);
}

// ---------------------------------------------------------------------------------------------------------
// 2. REPLICATION: "deploy" as a target, and as the ORIGIN of runs another destination must receive
// ---------------------------------------------------------------------------------------------------------
async function replication(k: Keys, s3: S3Wire): Promise<void> {
  console.log("-- 2. replication: \"deploy\" receives copies and sources them --");
  const r2 = new MockR2Bucket();
  s3.store.clear();
  const { stub, posts } = makeScheduler();
  const env = envWith(k, r2);
  // run-1 sealed to "deploy" before the fan-out began; run-2 sealed to the S3 destination after it.
  await sealInto(async (key, v) => void (await r2.put(key, v)), k, 1, RUN1, null);
  await appendRunlog(new R2Destination(r2 as unknown as R2Bucket), k.signer, entryFor(1, RUN1, null), undefined, { relinkLocalPrev: true });
  const s3Dest = new S3Destination(S3_ENDPOINT, S3_BUCKET, "us-east-1", "AKIDEXAMPLE", "not-a-real-secret", { addressing: "path" });
  await sealInto((key, v) => s3Dest.put(key, v), k, 2, RUN2, RUN1);
  await appendRunlog(s3Dest, k.signer, entryFor(2, RUN2, RUN1), undefined, { relinkLocalPrev: true });

  const history = [
    { runId: RUN1, index: 1, startedAt: "2026-09-24T01:00:00.000Z", status: "ok", destinationId: "deploy" },
    { runId: RUN2, index: 2, startedAt: "2026-09-24T02:00:00.000Z", status: "ok", destinationId: S3_ID },
  ] as RunHistoryEntry[];
  await replicateBacklog(env, stub, stateWith(["deploy", S3_ID]).config, history);

  const rec = (id: string) => posts.filter((p) => p.path === "/replication/record" && p.body.destinationId === id);
  const deployRec = rec("deploy").at(-1)?.body;
  const s3Rec = rec(S3_ID).at(-1)?.body;
  ok("replication records \"deploy\" ok (not not-configured)", deployRec?.ok === true && deployRec?.reason === undefined);
  ok("\"deploy\" holds both runs (holdsIndex 2)", deployRec?.index === 2);
  ok("the S3 destination is ok and holds both runs", s3Rec?.ok === true && s3Rec?.index === 2);
  const faults = posts.filter((p) => p.path === "/seal-fault" && p.body.kind === "replica-target-fault");
  ok("no replica fault names not-configured", faults.every((f) => f.body.replicaReason !== "not-configured"));
  ok("no run is stranded as origin-dest-unconfigured (run-1's origin is \"deploy\")", faults.every((f) => f.body.replicaReason !== "origin-dest-unconfigured"));
  ok("the R2 binding's RUNLOG now holds run-2 (mirrored from S3)", runlogIds(r2.store.get("_RECOVERY/RUNLOG")?.bytes).includes(RUN2));
  ok("the S3 RUNLOG now holds run-1 (mirrored from \"deploy\")", runlogIds(s3.store.get("_RECOVERY/RUNLOG")?.bytes).includes(RUN1));
}

// ---------------------------------------------------------------------------------------------------------
// 3. RESTORE / DRILL READ WALK: a run whose recorded copy is on "deploy"
// ---------------------------------------------------------------------------------------------------------
async function restoreWalk(k: Keys): Promise<void> {
  console.log("-- 3. restore and drill reads: a copy on \"deploy\" is a configured copy --");
  const { stub } = makeScheduler({ runDests: { [RUN1]: ["deploy", S3_ID], [RUN2]: ["deploy"] } });
  const seen: Array<{ cfg: unknown; id: string | undefined }> = [];
  const missing = async (cfg: unknown, _fb: unknown, id: string | undefined): Promise<{ ok: boolean; reason: string }> => {
    seen.push({ cfg, id });
    return { ok: false, reason: REASON_OBJECT_MISSING };
  };
  await withRunDestFallback(envWith(k, new MockR2Bucket()), stub, RUN1, undefined, missing);
  ok("[\"deploy\", S3]: the walk offers \"deploy\" first, as the env-backed destination (null override)", seen[0]?.id === "deploy" && seen[0]?.cfg === null);
  ok("[\"deploy\", S3]: an availability refusal on \"deploy\" falls through to the S3 copy", seen.length === 2 && seen[1]?.id === S3_ID && seen[1]?.cfg !== null);
  const alone = await withRunDestFallback(envWith(k, new MockR2Bucket()), stub, RUN2, undefined, missing);
  ok("[\"deploy\"] alone: an exhausted walk keeps its real reason, never origin-removed (the deploy bucket is configured)", (alone as { reason?: string }).reason !== REASON_ORIGIN_REMOVED);
}

// ---------------------------------------------------------------------------------------------------------
// 4. CANARY: a canary pointed at "deploy" flies to the R2 binding
// ---------------------------------------------------------------------------------------------------------
async function canary(k: Keys): Promise<void> {
  console.log("-- 4. canary: pointed at \"deploy\", it probes the R2 binding --");
  const r2 = new MockR2Bucket();
  const { stub } = makeScheduler();
  const res = await runCanaryCycle(envWith(k, r2), stub, { runId: "c1", runSeq: 1, destinationId: "deploy", cleanupRunId: null });
  ok("the canary did not stop at resolution (status is not pending)", res.status !== "pending");
  ok("the canary's probe reached the R2 binding", r2.ops > 0);
}

// ---------------------------------------------------------------------------------------------------------
// 5. "deploy" NAMED, with NO env destination behind it: every path refuses with deploy-binding-missing
// ---------------------------------------------------------------------------------------------------------
async function deployBindingMissing(k: Keys, s3: S3Wire): Promise<void> {
  console.log("-- 5. \"deploy\" named with no env destination: refused as deploy-binding-missing --");
  const { stub, posts } = makeScheduler({ runDests: { [RUN1]: ["deploy"] } });
  const env = envWith(k, null);

  const sel = await selectSealDestination(env, stub, stateWith(["deploy", S3_ID]));
  ok("[\"deploy\", S3]: the run seals to the S3 destination, the one that can be served", !("allDown" in sel) && sel.destinationId === S3_ID);

  const thrown = await caught(() => resolveDestForState(env, stub, stateWith(["deploy"])));
  ok("[\"deploy\"] alone: the seal resolution refuses (throws)", thrown !== null);
  ok("[\"deploy\"] alone: the refusal carries the closed reason deploy-binding-missing", destResolutionRefusalOf(thrown) === "deploy-binding-missing");
  ok("[\"deploy\"] alone: the seal-error class is deploy-binding-missing, not dest-not-configured", sealDestErrorClassOf(thrown) === "deploy-binding-missing");

  s3.store.clear();
  const s3Dest = new S3Destination(S3_ENDPOINT, S3_BUCKET, "us-east-1", "AKIDEXAMPLE", "not-a-real-secret", { addressing: "path" });
  await sealInto((key, v) => s3Dest.put(key, v), k, 1, RUN1, null);
  await appendRunlog(s3Dest, k.signer, entryFor(1, RUN1, null), undefined, { relinkLocalPrev: true });
  await replicateBacklog(env, stub, stateWith(["deploy", S3_ID]).config, [{ runId: RUN1, index: 1, startedAt: "2026-09-24T01:00:00.000Z", status: "ok", destinationId: S3_ID }] as RunHistoryEntry[]);
  const deployRec = posts.filter((p) => p.path === "/replication/record" && p.body.destinationId === "deploy").at(-1)?.body;
  ok("replication records \"deploy\" down with reason deploy-binding-missing", deployRec?.ok === false && deployRec?.reason === "deploy-binding-missing");
  const fault = posts.find((p) => p.path === "/seal-fault" && p.body.destinationId === "deploy");
  ok("the replica fault names deploy-binding-missing, never not-configured", fault?.body.replicaReason === "deploy-binding-missing");

  const canaryRes = await runCanaryCycle(env, stub, { runId: "c2", runSeq: 2, destinationId: "deploy", cleanupRunId: null });
  ok("a canary pointed at \"deploy\" is pending, with a reason naming the deploy-time destination", canaryRes.status === "pending" && /deploy-time/.test(JSON.stringify(canaryRes)));
}

// ---------------------------------------------------------------------------------------------------------
// 6. CONTROL: an id with NO record is still not-configured, on the same paths
// ---------------------------------------------------------------------------------------------------------
async function missingIdControl(k: Keys): Promise<void> {
  console.log("-- 6. control: a removed destination id stays not-configured --");
  const r2 = new MockR2Bucket();
  const { stub, posts } = makeScheduler();
  const env = envWith(k, r2);

  const thrown = await caught(() => resolveDestForState(env, stub, stateWith(["gone"])));
  ok("[\"gone\"]: the seal resolution refuses with not-configured", destResolutionRefusalOf(thrown) === "not-configured");
  ok("[\"gone\"]: the seal-error class stays dest-not-configured", sealDestErrorClassOf(thrown) === "dest-not-configured");

  const sel = await selectSealDestination(env, stub, stateWith(["gone", S3_ID]));
  ok("[\"gone\", S3]: the run skips the removed id and seals to S3", !("allDown" in sel) && sel.destinationId === S3_ID);

  await replicateBacklog(env, stub, stateWith(["gone", S3_ID]).config, [{ runId: RUN1, index: 1, startedAt: "2026-09-24T01:00:00.000Z", status: "ok", destinationId: S3_ID }] as RunHistoryEntry[]);
  const goneRec = posts.filter((p) => p.path === "/replication/record" && p.body.destinationId === "gone").at(-1)?.body;
  ok("replication records the removed id as not-configured", goneRec?.ok === false && goneRec?.reason === "not-configured");

  const opsBefore = r2.ops;
  const canaryRes = await runCanaryCycle(env, stub, { runId: "c3", runSeq: 3, destinationId: "gone", cleanupRunId: null });
  ok("a canary pointed at a removed id is pending", canaryRes.status === "pending");
  ok("and it did not fly to the env default in its place (the R2 binding saw nothing)", r2.ops === opsBefore);
}

async function main(): Promise<void> {
  const k = await makeKeys();
  const s3 = new S3Wire();
  s3.install();
  try {
    await sealChoice(k, s3);
    await replication(k, s3);
    await restoreWalk(k);
    await canary(k);
    await deployBindingMissing(k, s3);
    await missingIdControl(k);
  } finally {
    s3.uninstall();
  }
  console.log(failures === 0 ? "\nDEPLOY DEST FANOUT PASS\n" : `\nDEPLOY DEST FANOUT FAIL (${failures})\n`);
  verdictReached(failures);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
