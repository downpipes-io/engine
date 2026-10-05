// Seal ONE released-generation fixture archive for the Go reader's read-them-all gate
// (a cross-repository compatibility rule). Run it from a checkout of the RELEASED engine
// tag, never from main: the fixture is a statement about what a released writer put on disk, so the bytes
// must come from that release's own writer. The fixture is sealed once and never regenerated.
//
// What the archive holds: one downpipe, two runs chained through the signed RUNLOG.
//   Run 1 is sealed by the buffered pipeline (runBackup, src/seal/pipeline.ts) over the real KV, R2, D1 and
//   Secrets source adapters driven against in-memory bindings, plus an account-scoped adapter for the five
//   API source types. It carries restore descriptors on every kind that has one, a single-segment streamed
//   R2 value, a salted secrets record and a _vanished incompleteness marker.
//   Run 2 is sealed by the sliced seal (runSlice and finaliseRun, src/seal/slice.ts), the production
//   default, over the real R2 source. Two records per shard gives a multi-shard run, and a lowered segment
//   target seals the large object as a chained multi-segment record. Its RUNLOG entry and signed root link
//   back to run 1.
//
// Beside the archive it writes the break-glass identity and the signer public key in the Go CLI's labelled
// format (the same shape test/write-archive.ts writes), and expected.json: every record's source type,
// name, size and plaintext SHA-384, taken from the source values before sealing. A reader grades itself
// against that file, not against anything it read out of the archive.
//
// The keys are throwaway, minted here for the fixture. They protect nothing.
//
// Run (from the released engine checkout): node test/seal-released-fixture.ts <out-dir>
// The out-dir must not exist yet: a generation directory is written once.

import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { x25519 } from "@noble/curves/ed25519.js";
import { b64urlEncode, concat, hexEncode, utf8 } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import { isValidRunId } from "../src/format/ulid.ts";
import { ENGINE_VERSION, VERSION as FORMAT_VERSION } from "../src/format/version.ts";
import type { RecipientEntry, Signer } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import { SliceBudget } from "../src/seal/budget.ts";
import { type RunCheckpoint, unwrapMaster, wrapMaster, zeroCounts } from "../src/seal/checkpoint.ts";
import { runBackup } from "../src/seal/pipeline.ts";
import { finaliseRun, runSlice, type ShardEntry, type SliceDeps } from "../src/seal/slice.ts";
import { D1Source } from "../src/sources/d1.ts";
import { KVSource } from "../src/sources/kv.ts";
import { R2Source } from "../src/sources/r2.ts";
import { SecretsSource } from "../src/sources/secrets.ts";
import type { Selector, SourceAdapter, SourceRecord } from "../src/sources/types.ts";

const outArg = process.argv[2];
if (!outArg) throw new Error("usage: node test/seal-released-fixture.ts <out-dir>");
const OUT: string = outArg;

const DOWNPIPE_ID = "dp_released";
const DOWNPIPE_NAME = "released-generation-fixture";
const ACCOUNT = "acct-released-fixture-0001";
const RUN_1 = "01K6400000FXTRGEN010000001";
const RUN_2 = "01K6400000FXTRGEN010000002";
const RUN_1_AT = "2026-09-26T00:00:00.000Z";
const RUN_2_AT = "2026-09-26T01:00:00.000Z";
const ALL: Selector = { include: [], exclude: [] };

// Deterministic content, so the expected hashes can be computed from a second crawl of the same doubles.
function patterned(n: number, seed: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (Math.imul(i + seed, 2654435761) >>> 24) & 0xff;
  return b;
}
function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}
function toAB(b: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(b.byteLength);
  new Uint8Array(out).set(b);
  return out;
}
function streamOf(bytes: Uint8Array, piece = 700): ReadableStream<Uint8Array> {
  let off = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (off >= bytes.length) {
        controller.close();
        return;
      }
      const n = Math.min(piece, bytes.length - off);
      controller.enqueue(bytes.subarray(off, off + n));
      off += n;
    },
  });
}

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// ---- in-memory bindings the real source adapters read -------------------------------------------------

interface KVSeed {
  name: string;
  value: Uint8Array;
  metadata?: unknown;
  expiration?: number;
  vanished?: boolean; // listed, then gone by the value read (the adapter seals a _vanished marker)
}
class MemKV {
  private seeds: KVSeed[];
  constructor(seeds: KVSeed[]) {
    this.seeds = [...seeds].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  }
  async list(options?: { prefix?: string; cursor?: string }): Promise<{ keys: { name: string; expiration?: number; metadata?: unknown }[]; list_complete: true; cacheStatus: null }> {
    const prefix = options?.prefix;
    const keys = this.seeds
      .filter((s) => prefix === undefined || s.name.startsWith(prefix))
      .map((s) => ({ name: s.name, ...(s.expiration !== undefined ? { expiration: s.expiration } : {}), ...(s.metadata !== undefined ? { metadata: s.metadata } : {}) }));
    return { keys, list_complete: true, cacheStatus: null };
  }
  async getWithMetadata(key: string, _type: "arrayBuffer"): Promise<{ value: ArrayBuffer | null; metadata: unknown; cacheStatus: null }> {
    const s = this.seeds.find((x) => x.name === key);
    if (!s || s.vanished) return { value: null, metadata: null, cacheStatus: null };
    return { value: toAB(s.value), metadata: s.metadata ?? null, cacheStatus: null };
  }
}

interface R2Obj {
  key: string;
  etag: string;
  bytes: Uint8Array;
  httpMetadata?: { contentType?: string; cacheControl?: string; cacheExpiry?: Date };
  customMetadata?: Record<string, string>;
}
class MemR2 {
  private objs: R2Obj[];
  constructor(objs: R2Obj[]) {
    this.objs = objs;
  }
  // biome-ignore lint/suspicious/noExplicitAny: the double implements only the slice of R2ListOptions the source uses.
  async list(opts: any): Promise<any> {
    const prefix: string | undefined = opts?.prefix;
    const startAfter: string | undefined = opts?.startAfter;
    const objects = this.objs
      .filter((o) => (prefix === undefined || o.key.startsWith(prefix)) && (startAfter === undefined || o.key > startAfter))
      .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
      .map((o) => ({ key: o.key, size: o.bytes.length, etag: o.etag, ...(o.httpMetadata ? { httpMetadata: o.httpMetadata } : {}), ...(o.customMetadata ? { customMetadata: o.customMetadata } : {}) }));
    return { objects, delimitedPrefixes: [], truncated: false };
  }
  // biome-ignore lint/suspicious/noExplicitAny: the double implements only the slice of R2GetOptions the source uses.
  async get(key: string, opts?: any): Promise<any> {
    const o = this.objs.find((x) => x.key === key);
    if (!o) return null;
    const meta = { ...(o.httpMetadata ? { httpMetadata: o.httpMetadata } : {}), ...(o.customMetadata ? { customMetadata: o.customMetadata } : {}) };
    const etagPin: string | undefined = opts?.onlyIf?.etagMatches;
    if (etagPin !== undefined && etagPin !== o.etag) return { key, size: o.bytes.length, etag: o.etag, ...meta };
    const range: { offset: number; length: number } | undefined = opts?.range;
    if (range) return { key, size: o.bytes.length, etag: o.etag, ...meta, body: streamOf(o.bytes.subarray(range.offset, range.offset + range.length)) };
    return { key, size: o.bytes.length, etag: o.etag, ...meta, body: streamOf(o.bytes), arrayBuffer: async () => toAB(o.bytes) };
  }
}

// MemD1 answers the queries D1Source issues: the sqlite_master listing, the column and rowid probes, and
// the keyset page over the integer-safe typed projection (a (typeof, value) pair per column).
interface MemD1Table {
  name: string;
  sql: string;
  columns: string[];
  rows: unknown[][];
}
function typedProjectionRow(row: unknown[]): unknown[] {
  const out: unknown[] = [];
  for (const v of row) {
    if (v === null || v === undefined) out.push("null", null);
    else if (typeof v === "string") out.push("text", v);
    else if (typeof v === "bigint") out.push("integer", v.toString());
    else if (typeof v === "number") {
      if (Number.isInteger(v)) out.push("integer", String(v));
      else out.push("real", v);
    } else out.push("blob", v);
  }
  return out;
}
class MemD1Stmt {
  private tables: MemD1Table[];
  private query: string;
  private binds: unknown[];
  constructor(tables: MemD1Table[], query: string, binds: unknown[]) {
    this.tables = tables;
    this.query = query;
    this.binds = binds;
  }
  bind(...values: unknown[]): MemD1Stmt {
    return new MemD1Stmt(this.tables, this.query, values);
  }
  private tableFor(): MemD1Table {
    const m = /FROM\s+"((?:[^"]|"")+)"/i.exec(this.query);
    const name = m?.[1]?.replace(/""/g, '"');
    const t = this.tables.find((x) => x.name === name);
    if (!t) throw new Error(`MemD1: unrecognised query: ${this.query}`);
    return t;
  }
  async all<T>(): Promise<{ results: T[]; success: true; meta: Record<string, unknown> }> {
    if (/FROM sqlite_master/i.test(this.query)) {
      return { results: this.tables.map((t) => ({ type: "table", name: t.name, tbl_name: t.name, sql: t.sql })) as T[], success: true, meta: {} };
    }
    throw new Error(`MemD1.all: unhandled: ${this.query}`);
  }
  async raw<T>(_opts: { columnNames: true }): Promise<[string[], ...T[]]> {
    if (/SELECT \* FROM .* LIMIT 0/i.test(this.query)) return [this.tableFor().columns] as unknown as [string[], ...T[]];
    if (/SELECT _rowid_ FROM .* LIMIT 0/i.test(this.query)) return [["_rowid_"]] as unknown as [string[], ...T[]];
    if (/WHERE _rowid_ > CAST\(\?1 AS INTEGER\) ORDER BY _rowid_ LIMIT \?2/i.test(this.query)) {
      const t = this.tableFor();
      const after = BigInt(String(this.binds[0]));
      const limit = Number(this.binds[1]);
      const out: unknown[][] = [];
      for (let i = 0; i < t.rows.length && out.length < limit; i++) {
        const rowid = BigInt(i + 1);
        if (rowid > after) out.push([...typedProjectionRow(t.rows[i]!), rowid.toString()]);
      }
      return [[...t.columns, "__dp_rowid"], ...out] as unknown as [string[], ...T[]];
    }
    throw new Error(`MemD1.raw: unhandled: ${this.query}`);
  }
}
class MemD1 {
  private tables: MemD1Table[];
  constructor(tables: MemD1Table[]) {
    this.tables = tables;
  }
  prepare(query: string): MemD1Stmt {
    return new MemD1Stmt(this.tables, query, []);
  }
  withSession(_constraint?: string): { prepare(q: string): MemD1Stmt; getBookmark(): string } {
    return { prepare: (q: string) => new MemD1Stmt(this.tables, q, []), getBookmark: () => "0000000a-0000000b-00000000-0123456789abcdef" };
  }
}

// ApiSource stands in for the five API-discovered source types. Their real adapters read the Cloudflare
// REST API; the seal treats every one of them the same way (buffered value, account annotation), which is
// what this reproduces.
class ApiSource implements SourceAdapter {
  readonly accountId = ACCOUNT;
  readonly sourceType: "cf-config" | "workers" | "stream" | "images" | "artifacts";
  private items: { name: string; value: Uint8Array }[];
  constructor(sourceType: "cf-config" | "workers" | "stream" | "images" | "artifacts", items: { name: string; value: Uint8Array }[]) {
    this.sourceType = sourceType;
    this.items = items;
  }
  async *crawl(_selector: Selector): AsyncIterable<SourceRecord> {
    for (const it of this.items) yield { sourceType: this.sourceType, name: it.name, value: it.value };
  }
  async estimate(_selector: Selector): Promise<{ records: number; bytes: number }> {
    return { records: this.items.length, bytes: this.items.reduce((n, it) => n + it.value.length, 0) };
  }
}

// MemDest is the destination both runs seal into, so run 2's RUNLOG append and signed root link to run 1.
class MemDest implements Destination {
  map = new Map<string, Uint8Array>();
  private tags = new Map<string, string>();
  private seq = 0;
  async get(key: string): Promise<GetResult | null> {
    const v = this.map.get(key);
    return v ? { body: v, etag: this.tags.get(key) ?? "e0" } : null;
  }
  async put(key: string, body: Uint8Array): Promise<void> {
    this.map.set(key, body);
    this.tags.set(key, `e${++this.seq}`);
  }
  async putStream(key: string, body: ReadableStream<Uint8Array>): Promise<void> {
    const parts: Uint8Array[] = [];
    const reader = body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      parts.push(value);
    }
    await this.put(key, concat(...parts));
  }
  async putConditional(key: string, body: Uint8Array, opts: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult> {
    const cur = this.tags.get(key);
    if (opts.ifNoneMatch === "*" && cur !== undefined) return { ok: false };
    if (opts.ifMatch !== undefined && cur !== opts.ifMatch) return { ok: false };
    await this.put(key, body);
    return { ok: true, etag: this.tags.get(key)! };
  }
  async exists(key: string): Promise<boolean> {
    return this.map.has(key);
  }
  async delete(key: string): Promise<void> {
    this.map.delete(key);
    this.tags.delete(key);
  }
  async list(prefix: string): Promise<string[]> {
    return [...this.map.keys()].filter((k) => k.startsWith(prefix));
  }
}

// ---- the source content ---------------------------------------------------------------------------------

const KV_SEEDS: KVSeed[] = [
  { name: "config/feature-flags", value: utf8('{"checkout":true,"search":"v2"}'), metadata: { owner: "web", revision: 14 }, expiration: 1893456000 },
  { name: "config/greeting", value: utf8("a released engine sealed this, and every later reader must open it"), metadata: { note: "quotes \" and unicode é" } },
  { name: "session/plain", value: utf8("a KV value with no metadata and no expiry") },
  { name: "session/raced", value: utf8("deleted between the list and the read"), vanished: true },
];
const R2_RUN1: R2Obj[] = [
  { key: "docs/report.txt", etag: '"r1a"', bytes: utf8("an R2 object with HTTP and custom metadata"), httpMetadata: { contentType: "text/plain", cacheControl: "max-age=3600", cacheExpiry: new Date("2030-01-01T00:00:00.000Z") }, customMetadata: { team: "ops", origin: "ingest" } },
  { key: "docs/plain.bin", etag: '"r1b"', bytes: patterned(900, 3) },
  // Over the lowered stream threshold, so the buffered pipeline seals it as a single streamed segment.
  { key: "media/clip.bin", etag: '"r1c"', bytes: patterned(6000, 11), httpMetadata: { contentType: "video/mp4" } },
];
const R2_RUN2: R2Obj[] = [
  { key: "archive/a.txt", etag: '"r2a"', bytes: utf8("run two, first small object") },
  { key: "archive/b.txt", etag: '"r2b"', bytes: utf8("run two, second small object"), customMetadata: { tier: "cold" } },
  { key: "archive/c.txt", etag: '"r2c"', bytes: utf8("run two, third small object") },
  // Over the stream threshold and three times the segment target: sealed as a chained multi-segment record.
  { key: "archive/large.bin", etag: '"r2d"', bytes: patterned(4096 * 3 + 517, 29), httpMetadata: { contentType: "application/octet-stream" } },
];
const STREAM_THRESHOLD = 1024;
const SEGMENT_TARGET = 4096;
const D1_TABLES: MemD1Table[] = [
  { name: "customers", sql: 'CREATE TABLE "customers" (id INTEGER PRIMARY KEY, name TEXT NOT NULL, balance REAL, note TEXT)', columns: ["id", "name", "balance", "note"], rows: [[1, "Ada", 12.5, null], [2, "Grace", -3.25, "o'brien"], [3, "Linus", 0, "unicode é"]] },
  { name: "events", sql: 'CREATE TABLE "events" (id INTEGER PRIMARY KEY, kind TEXT, big INTEGER)', columns: ["id", "kind", "big"], rows: [[1, "signup", 9007199254740993n], [2, "login", 42]] },
];
const API_ITEMS: Record<"cf-config" | "workers" | "stream" | "images" | "artifacts", { name: string; value: Uint8Array }[]> = {
  "cf-config": [{ name: "zone/example.test/settings", value: utf8('{"ssl":"strict","min_tls_version":"1.2"}') }],
  workers: [{ name: "script/api-worker/content", value: utf8("export default { fetch() { return new Response('ok'); } };") }],
  stream: [{ name: "video/0001/meta", value: utf8('{"uid":"0001","duration":12.5}') }],
  images: [{ name: "image/logo/meta", value: utf8('{"id":"logo","variants":["public"]}') }],
  artifacts: [{ name: "artifact/build-7/manifest", value: utf8('{"build":7,"files":2}') }],
};

// The secret's wiring. Engine 0.3.5 captures the scope, worker and comment too, and later engines stopped
// declaring them, so the list is held in a variable: the fields reach the released adapter either way.
const SECRETS = [{ name: "API_TOKEN", get: async () => "fixture-secret-value-not-a-real-token", store: "default", scope: "account", comment: "fixture secret", worker: "api-worker", bindingVar: "API_TOKEN" }];

function run1Sources(): SourceAdapter[] {
  return [
    new KVSource(new MemKV(KV_SEEDS) as unknown as KVNamespace, "ns_released"),
    new R2Source(new MemR2(R2_RUN1) as unknown as R2Bucket, "bucket_released", { resumable: false, streamThreshold: STREAM_THRESHOLD }),
    new D1Source(new MemD1(D1_TABLES) as unknown as D1Database, "appdb", undefined, 2, "4f9a2c1e-7b3d-4e82-9f10-6a5b8c3d2e91"),
    new SecretsSource(SECRETS),
    ...(Object.keys(API_ITEMS) as (keyof typeof API_ITEMS)[]).map((t) => new ApiSource(t, API_ITEMS[t])),
  ];
}
function run2Source(): SourceAdapter {
  return new R2Source(new MemR2(R2_RUN2) as unknown as R2Bucket, "bucket_released", { resumable: true, streamThreshold: STREAM_THRESHOLD });
}

// ---- expected records, taken from the source values, never from the archive ---------------------------

interface ExpectedRecord {
  sourceType: string;
  name: string;
  size: number;
  plaintextSha384: string;
  incompleteMarker?: string;
}
async function expectedOf(sources: SourceAdapter[]): Promise<ExpectedRecord[]> {
  const out: ExpectedRecord[] = [];
  for (const src of sources) {
    for await (const rec of src.crawl(ALL)) {
      let bytes: Uint8Array;
      if (rec.stream) {
        const parts: Uint8Array[] = [];
        for await (const c of rec.stream.open().chunks()) parts.push(c);
        bytes = concat(...parts);
      } else bytes = rec.value ?? new Uint8Array(0);
      out.push({ sourceType: rec.sourceType, name: rec.name, size: bytes.length, plaintextSha384: hexEncode(await sha384(bytes)), ...(rec.markerKind !== undefined ? { incompleteMarker: rec.markerKind } : {}) });
    }
  }
  return out;
}

async function main(): Promise<void> {
  if (existsSync(OUT)) throw new Error(`${OUT} already exists: a generation directory is written once and never regenerated`);
  for (const id of [RUN_1, RUN_2]) if (!isValidRunId(id)) throw new Error(`fixture run id ${id} is not a valid ULID`);

  const signerSeed = b64urlEncode(concat(rand(32), rand(32)));
  const signer: Signer = await loadSigner(signerSeed);
  const breakGlass = makeRecipient("break-glass");
  const operational = makeRecipient("operational");
  const recipients = [breakGlass.entry, operational.entry];
  const dest = new MemDest();

  // Run 1: the buffered pipeline.
  const s1 = await runBackup(run1Sources(), { downpipeId: DOWNPIPE_ID, downpipeName: DOWNPIPE_NAME, cadence: "0 * * * *", selector: ALL, recipients }, signer, dest, {
    runId: RUN_1,
    runlogIndex: 1,
    prevRunId: null,
    now: RUN_1_AT,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
    master: rand(32),
  });

  // Run 2: the sliced seal, checkpoint round-tripped through JSON between slices as the real owner does.
  const master2 = rand(32);
  let cp: RunCheckpoint = {
    v: 1, downpipeId: DOWNPIPE_ID, downpipeName: DOWNPIPE_NAME, cadence: "0 * * * *", sourceType: "r2",
    selector: ALL, runId: RUN_2, runlogIndex: 2, prevRunId: RUN_1,
    startedAt: RUN_2_AT, wrappedMaster: await wrapMaster(signerSeed, RUN_2, master2),
    cursor: null, sourceDone: false, nextRecordIndex: 0, nextShardIndex: 0,
    frontier: { count: 0, nodes: [] }, counts: zeroCounts(), sliceCount: 0, partialRecord: null,
  };
  const now2 = (): string => RUN_2_AT;
  const allShards: ShardEntry[] = [];
  let openBuffer: Record<string, unknown>[] = [];
  for (let s = 0; s < 50 && !cp.sourceDone; s++) {
    cp = JSON.parse(JSON.stringify(cp)) as RunCheckpoint;
    const m = await unwrapMaster(signerSeed, RUN_2, cp.wrappedMaster);
    const deps: SliceDeps = { source: run2Source(), dest, signer, recipients, budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }), segmentTargetBytes: SEGMENT_TARGET, shardMaxRecords: 2, nowIso: now2 };
    const r = await runSlice(deps, cp, m, openBuffer);
    m.fill(0);
    cp = r.checkpoint;
    allShards.push(...r.newShards);
    openBuffer = r.openReset ? r.openWrite : [...openBuffer, ...r.openWrite];
  }
  if (!cp.sourceDone) throw new Error("the sliced run did not complete");
  const m2 = await unwrapMaster(signerSeed, RUN_2, cp.wrappedMaster);
  const fin = await finaliseRun({ source: run2Source(), dest, signer, recipients, budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }), nowIso: now2 }, cp, m2, allShards, openBuffer);
  m2.fill(0);

  const expected = {
    generation: "downpipe-0.1.0",
    formatVersion: FORMAT_VERSION,
    engineVersion: ENGINE_VERSION,
    sealedAt: new Date().toISOString(),
    downpipeId: DOWNPIPE_ID,
    runs: [
      { runId: RUN_1, runlogIndex: 1, prevRunId: null, latest: false, sealPath: "buffered", records: await expectedOf(run1Sources()) },
      { runId: RUN_2, runlogIndex: 2, prevRunId: RUN_1, latest: true, sealPath: "sliced", shards: fin.shards, records: await expectedOf([run2Source()]) },
    ],
  };
  if (expected.runs[0]!.records.length !== s1.records) throw new Error(`run 1 sealed ${s1.records} records but the expected set holds ${expected.runs[0]!.records.length}`);

  for (const [key, bytes] of dest.map) {
    const p = join(OUT, "archive", key);
    await mkdir(dirname(p), { recursive: true });
    await writeFile(p, bytes);
  }
  await writeFile(join(OUT, "identity.key"), `downpipe-identity-v1 ${b64urlEncode(breakGlass.identity)}\n`);
  await writeFile(join(OUT, "signer.pub"), `downpipe-signer-public-v1 ${b64urlEncode(concat(signer.edPublic, signer.mldsaPublic))}\n`);
  await writeFile(join(OUT, "expected.json"), `${JSON.stringify(expected, null, 2)}\n`);
  console.log(`sealed ${FORMAT_VERSION} with engine ${ENGINE_VERSION}: run 1 ${s1.records} records (buffered), run 2 ${expected.runs[1]!.records.length} records in ${fin.shards} shards (sliced), ${dest.map.size} objects -> ${OUT}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
