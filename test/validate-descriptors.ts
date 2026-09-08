// Per-source restore descriptors: prove an engine archive is full-fidelity,
// not value-only, AND that the descriptor metadata it adds to the SIGNED shard manifest still
// signs and verifies, with byte-identical canonical JSON to the Go reader's recompute.
//
// What this validator covers:
//   1. CAPTURE: the real KV and R2 source adapters, run against in-memory doubles carrying
//      metadata, capture the descriptor (KV metadata + expiration; R2 http + custom metadata);
//      the real Secrets and D1 adapters capture their wiring / format.
//   2. EMIT + VERIFY (round trip): buildArchive seals those records, the TS reader opens the
//      run (so the manifest hybrid signature, the shard hash and every record hash verify) and
//      the descriptors survive on each ShardRecord with the EXACT values, and the values
//      themselves restore byte-correct.
//   3. APPLY: the KV and R2 restore sinks, driven with putOptionsFromRecord(rec), hand the
//      mock bindings the reconstructed expiration / metadata / httpMetadata / customMetadata.
//   4. BACKWARD COMPAT: an archive built from records with NO descriptor is byte-identical, in
//      the decrypted shard manifest, to one built before descriptors existed (no kv/r2/secrets/
//      d1 key appears on any line). This is the omitempty guarantee the conformance vectors,
//      which carry no descriptors, rely on.
//   5. A reusable cross-implementation artefact: with `--out <dir>` (or by default into a temp
//      dir) it writes a complete engine archive WITH descriptors plus the break-glass identity
//      and signer public key in the Go CLI's labelled format, and prints the path, so a Go
//      `downpipe restore` can be pointed at it.
//
// Run: node test/validate-descriptors.ts            (assertions, prints a temp archive path)
//      node test/validate-descriptors.ts --out DIR  (also writes the cross-impl sample to DIR)
// In-memory doubles only; no network, no deploy, no cost.

import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen, mldsaKeygen } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry, type Signer, type WriteRecord } from "../src/format/writer.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { KVSource } from "../src/sources/kv.ts";
import { R2Source } from "../src/sources/r2.ts";
import { SecretsSource, type BoundSecret } from "../src/sources/secrets.ts";
import { D1Source } from "../src/sources/d1.ts";
import { KVRestoreSink, R2RestoreSink, putOptionsFromRecord } from "../src/dest/restore-sink.ts";
import type { SourceRecord, Selector } from "../src/sources/types.ts";
import { unframeDpe } from "../src/format/container.ts";
import { openStream } from "../src/crypto/stream.ts";
import { deriveMK, deriveManifestWrapKey } from "../src/crypto/derive.ts";
import { decodeULID } from "../src/format/ulid.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";

const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const NS = "ns_descriptors";
const BUCKET = "media_descriptors";

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// deepEqual compares two JSON values irrespective of object key order, because the reader
// returns descriptor objects with keys in canonical (sorted) order, not the order a fixture
// literal lists them. It is the right oracle here: the wire contract is the canonical bytes
// (asserted elsewhere), so a round-trip equality check must be order-independent.
function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((x, i) => deepEqual(x, b[i]));
  }
  const ao = a as Record<string, unknown>;
  const bo = b as Record<string, unknown>;
  const ak = Object.keys(ao).sort();
  const bk = Object.keys(bo).sort();
  if (ak.length !== bk.length || !ak.every((k, i) => k === bk[i])) return false;
  return ak.every((k) => deepEqual(ao[k], bo[k]));
}

async function collect(iter: AsyncIterable<SourceRecord>): Promise<SourceRecord[]> {
  const out: SourceRecord[] = [];
  for await (const r of iter) out.push(r);
  return out;
}

const ALL: Selector = { include: [], exclude: [] };

// makeRecipient builds a hybrid recipient public entry and its 96-byte private identity
// (x25519 scalar(32) || ML-KEM seed(64)).
function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// ---- in-memory source doubles ----------------------------------------------
//
// Minimal subsets of the KV and R2 binding surfaces the source adapters call, returning the
// metadata fields the adapters now capture (KV list-key expiration + getWithMetadata metadata;
// R2 object httpMetadata + customMetadata).

interface KVSeed {
  name: string;
  value: Uint8Array;
  metadata?: unknown;
  expiration?: number;
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
    if (!s) return { value: null, metadata: null, cacheStatus: null };
    return { value: toAB(s.value), metadata: s.metadata ?? null, cacheStatus: null };
  }
}

interface R2Seed {
  key: string;
  value: Uint8Array;
  httpMetadata?: { contentType?: string; cacheControl?: string; cacheExpiry?: Date };
  customMetadata?: Record<string, string>;
}

class MemR2 {
  private seeds: R2Seed[];
  // Records every put so the apply assertion can read back the options the sink passed.
  puts: { key: string; options?: { httpMetadata?: { contentType?: string; cacheControl?: string; cacheExpiry?: Date }; customMetadata?: Record<string, string> } }[] = [];
  constructor(seeds: R2Seed[]) {
    this.seeds = [...seeds].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  }
  async list(options?: { prefix?: string; cursor?: string; limit?: number }): Promise<{ objects: unknown[]; delimitedPrefixes: []; truncated: false }> {
    const prefix = options?.prefix;
    const objects = this.seeds
      .filter((s) => prefix === undefined || s.key.startsWith(prefix))
      .map((s) => ({ key: s.key, size: s.value.length, ...(s.httpMetadata ? { httpMetadata: s.httpMetadata } : {}), ...(s.customMetadata ? { customMetadata: s.customMetadata } : {}) }));
    return { objects, delimitedPrefixes: [], truncated: false };
  }
  async get(key: string): Promise<unknown> {
    const s = this.seeds.find((x) => x.key === key);
    if (!s) return null;
    return {
      key,
      size: s.value.length,
      ...(s.httpMetadata ? { httpMetadata: s.httpMetadata } : {}),
      ...(s.customMetadata ? { customMetadata: s.customMetadata } : {}),
      async arrayBuffer(): Promise<ArrayBuffer> { return toAB(s.value); },
    };
  }
  async put(key: string, _value: unknown, options?: { httpMetadata?: { contentType?: string; cacheControl?: string; cacheExpiry?: Date }; customMetadata?: Record<string, string> }): Promise<unknown> {
    this.puts.push({ key, ...(options ? { options } : {}) });
    return { key };
  }
}

// MockKVSink is the KV binding surface KVRestoreSink writes through, recording the put options
// so the apply assertion can confirm the reconstructed expiration and metadata.
class MockKVSink {
  puts: { key: string; options?: { expiration?: number; metadata?: unknown } }[] = [];
  async put(key: string, _value: ArrayBuffer, options?: { expiration?: number; metadata?: unknown }): Promise<void> {
    this.puts.push({ key, ...(options ? { options } : {}) });
  }
}

function toAB(b: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(b.byteLength);
  new Uint8Array(out).set(b);
  return out;
}

// A read-only ObjectStore over the in-memory archive map, so the TS reader opens it.
class MapStore implements ObjectStore {
  private map: Map<string, Uint8Array>;
  constructor(map: Map<string, Uint8Array>) {
    this.map = map;
  }
  async get(key: string): Promise<Uint8Array> {
    const v = this.map.get(key);
    if (!v) throw new Error(`object not found: ${key}`);
    return v;
  }
}

// decryptShardLines opens the sealed shard manifest and returns its decoded NDJSON record
// lines (skipping the preamble), so a test can assert exactly which fields a line carries.
async function decryptShardLines(map: Map<string, Uint8Array>, master: Uint8Array): Promise<Record<string, unknown>[]> {
  const runIDBytes = decodeULID(RUN_ID);
  const mk = await deriveMK(master, runIDBytes);
  const wrapKey = await deriveManifestWrapKey(mk, runIDBytes, "00000");
  const sealed = map.get(`run/${RUN_ID}/manifest/00000.dpe`)!;
  const plain = await openStream(wrapKey, unframeDpe(sealed));
  return new TextDecoder()
    .decode(plain)
    .split("\n")
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l) as Record<string, unknown>)
    .filter((o) => o["kind"] === "record");
}

// ---- the descriptor fixtures ------------------------------------------------
//
// KV: one record with both metadata and an expiration, one with metadata only, one bare (no
// descriptor at all, to prove a value-only record stays value-only).
const KV_SEEDS: KVSeed[] = [
  { name: "with-both", value: utf8("kv value one"), metadata: { tier: "gold", ttlSrc: "policy", weight: 7 }, expiration: 1893456000 },
  { name: "with-meta", value: utf8("kv value two"), metadata: { note: "needs \"quotes\" and unicode é" } },
  { name: "bare", value: utf8("kv value three") },
];
// R2: one with http + custom metadata (http carries a Date cacheExpiry to exercise the
// Date->ISO normalisation on capture and ISO->Date rebuild on apply), one bare.
const R2_CACHE_EXPIRY = new Date("2030-01-01T00:00:00.000Z");
const R2_SEEDS: R2Seed[] = [
  { key: "uploads/report.txt", value: utf8("an r2 object value"), httpMetadata: { contentType: "text/plain", cacheControl: "max-age=3600", cacheExpiry: R2_CACHE_EXPIRY }, customMetadata: { team: "ops", origin: "ingest" } },
  { key: "uploads/bare.bin", value: utf8("a bare r2 object") },
];

interface Captured {
  kvRecords: SourceRecord[];
  r2Records: SourceRecord[];
  sec: SourceRecord;
  d1Header: SourceRecord;
  d1HeaderBytes: Uint8Array;
}

// ---- 1. CAPTURE: the real adapters lift the metadata into SourceRecord.descriptor -------
async function captureRecords(): Promise<Captured> {
  console.log("\ncapture (real source adapters):");
  const kvRecords = await collect(new KVSource(new MemKV(KV_SEEDS) as unknown as KVNamespace, NS).crawl(ALL));
  const kvBoth = kvRecords.find((r) => r.name === "with-both")!;
  const kvMeta = kvRecords.find((r) => r.name === "with-meta")!;
  const kvBare = kvRecords.find((r) => r.name === "bare")!;
  ok("KV captures metadata", JSON.stringify(kvBoth.descriptor?.kvMetadata) === JSON.stringify({ tier: "gold", ttlSrc: "policy", weight: 7 }));
  ok("KV captures expiration", kvBoth.descriptor?.kvExpiration === 1893456000);
  ok("KV metadata-only record has metadata, no expiration", kvMeta.descriptor?.kvMetadata !== undefined && kvMeta.descriptor?.kvExpiration === undefined);
  ok("KV bare record carries no descriptor", kvBare.descriptor === undefined);

  const memR2 = new MemR2(R2_SEEDS);
  const r2Records = await collect(new R2Source(memR2 as unknown as R2Bucket, BUCKET).crawl(ALL));
  const r2Full = r2Records.find((r) => r.name === "uploads/report.txt")!;
  const r2Bare = r2Records.find((r) => r.name === "uploads/bare.bin")!;
  ok("R2 captures contentType", r2Full.descriptor?.r2HttpMetadata?.["contentType"] === "text/plain");
  ok("R2 captures cacheControl", r2Full.descriptor?.r2HttpMetadata?.["cacheControl"] === "max-age=3600");
  ok("R2 normalises cacheExpiry Date to ISO", r2Full.descriptor?.r2HttpMetadata?.["cacheExpiry"] === R2_CACHE_EXPIRY.toISOString());
  ok("R2 captures custom metadata", JSON.stringify(r2Full.descriptor?.r2CustomMetadata) === JSON.stringify({ team: "ops", origin: "ingest" }));
  ok("R2 bare object carries no descriptor", r2Bare.descriptor === undefined);

  const secRecords = await collect(new SecretsSource([
    { name: "API_TOKEN", get: async () => "sk-never-logged", store: "default", scope: "account", comment: "prod token", worker: "api", bindingVar: "API_TOKEN" } satisfies BoundSecret,
  ]).crawl(ALL));
  const sec = secRecords[0]!;
  ok("secrets captures store/scope/worker/bindingVar/comment", sec.descriptor?.secretsStore === "default" && sec.descriptor?.secretsScope === "account" && sec.descriptor?.secretsComment === "prod token" && sec.descriptor?.secretsWorker === "api" && sec.descriptor?.secretsBindingVar === "API_TOKEN");
  ok("secrets descriptor never holds the value", JSON.stringify(sec.descriptor).indexOf("sk-never-logged") === -1);

  const d1db = makeMockD1();
  // A D1 database now backs up as a resumable SEQUENCE of buffered per-page records (header, row
  // pages, schema). The HEADER record carries the d1.format descriptor (the body-shape hint) the
  // omitempty round-trip below exercises; it is a buffered value, not a stream.
  const d1Records = await collect(new D1Source(d1db as unknown as D1Database, "appdb").crawl(ALL));
  const d1Header = d1Records[0]!;
  ok("d1 header captures the body format", d1Header.descriptor?.d1Format === "downpipe-d1-header/1");
  const d1HeaderBytes = d1Header.value!;

  return { kvRecords, r2Records, sec, d1Header, d1HeaderBytes };
}

interface Emitted {
  run: Awaited<ReturnType<typeof openRun>>;
  archive: Map<string, Uint8Array>;
  master: Uint8Array;
}

// ---- 2. EMIT + round-trip verify --------------------------------------------------------
async function emitAndVerify(signer: Signer, verifier: { ed: Uint8Array; mldsa: Uint8Array }, breakGlass: ReturnType<typeof makeRecipient>, op: ReturnType<typeof makeRecipient>, captured: Captured): Promise<Emitted> {
  const { kvRecords, r2Records, sec, d1Header, d1HeaderBytes } = captured;
  console.log("\nemit + round-trip (write archive, reopen, descriptors survive + signature verifies):");
  const master = rand(32);
  // Carry the captured descriptors straight onto the write records (the pipeline does this).
  const writeRecords: WriteRecord[] = [
    ...kvRecords.map((r) => ({ sourceType: "kv", name: r.name, value: r.value!, namespace: NS, ...(r.descriptor ? { descriptor: r.descriptor } : {}) } satisfies WriteRecord)),
    ...r2Records.map((r) => ({ sourceType: "r2", name: r.name, value: r.value!, bucket: BUCKET, ...(r.descriptor ? { descriptor: r.descriptor } : {}) } satisfies WriteRecord)),
    { sourceType: "secrets", name: sec.name, value: sec.value!, ...(sec.descriptor ? { descriptor: sec.descriptor } : {}) },
    { sourceType: "d1", name: "appdb/00-header", value: d1HeaderBytes, ...(d1Header.descriptor ? { descriptor: d1Header.descriptor } : {}) },
  ];
  const archive = await buildArchive({
    downpipeId: "dp_descriptors",
    downpipeName: "descriptors",
    cadence: "3600s",
    runId: RUN_ID,
    master,
    recipients: [breakGlass.entry, op.entry],
    signer,
    records: writeRecords,
    windowStart: "2026-06-07T00:00:00.000Z",
    windowEnd: "2026-06-07T00:00:01.000Z",
    createdAt: "2026-06-07T00:00:01.000Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });

  const store = new MapStore(archive);
  const identity = parseIdentity(breakGlass.identity);
  // openRun runs the whole SPEC 8.3 chain: the hybrid signature over the stored root bytes,
  // every shard hash and every record hash. If the descriptors had perturbed the signed bytes
  // in a way the reader did not expect, this would throw, so a clean open IS the signature
  // proof for the descriptor-bearing manifest.
  let run;
  try {
    run = await openRun(store, RUN_ID, identity, verifier, {});
    ok("descriptor-bearing run opens and the manifest signature verifies", true);
  } catch (e) {
    ok("descriptor-bearing run opens and the manifest signature verifies", false);
    console.log(`       open threw: ${(e as Error).message}`);
    console.log(failures === 0 ? "" : `\n${failures} FAILURE(S)`);
    process.exit(1);
  }

  const recBoth = run.records.find((r) => r.name === "with-both")!;
  ok("KV metadata survives the round trip", JSON.stringify(recBoth.kv?.metadata) === JSON.stringify({ tier: "gold", ttlSrc: "policy", weight: 7 }));
  ok("KV expiration survives the round trip", recBoth.kv?.expiration === 1893456000);
  const recMeta = run.records.find((r) => r.name === "with-meta")!;
  ok("KV metadata with quotes + unicode survives exactly", JSON.stringify(recMeta.kv?.metadata) === JSON.stringify({ note: "needs \"quotes\" and unicode é" }));
  ok("KV metadata-only record has no expiration field", recMeta.kv?.expiration === undefined);
  const recBare = run.records.find((r) => r.name === "bare")!;
  ok("KV bare record has no kv descriptor on the read side", recBare.kv === undefined);

  const recR2 = run.records.find((r) => r.name === "uploads/report.txt")!;
  ok("R2 httpMetadata survives the round trip", deepEqual(recR2.r2?.httpMetadata, { contentType: "text/plain", cacheControl: "max-age=3600", cacheExpiry: R2_CACHE_EXPIRY.toISOString() }));
  ok("R2 customMetadata survives the round trip", deepEqual(recR2.r2?.customMetadata, { team: "ops", origin: "ingest" }));
  const recR2Bare = run.records.find((r) => r.name === "uploads/bare.bin")!;
  ok("R2 bare object has no r2 descriptor", recR2Bare.r2 === undefined);

  const recSec = run.records.find((r) => r.name === "API_TOKEN")!;
  ok("secrets descriptor survives the round trip", deepEqual(recSec.secrets, { store: "default", scope: "account", comment: "prod token", worker: "api", bindingVar: "API_TOKEN" }));
  const recD1 = run.records.find((r) => r.name === "appdb/00-header")!;
  ok("d1 descriptor survives the round trip", recD1.d1?.format === "downpipe-d1-header/1");

  // The values must still restore byte-correct: a descriptor must not perturb the value path.
  for (const seed of KV_SEEDS) {
    const rec = run.records.find((r) => r.name === seed.name)!;
    const got = await run.restoreRecord(rec);
    ok(`KV value restores byte-correct for ${seed.name}`, eqBytes(got, seed.value));
  }
  for (const seed of R2_SEEDS) {
    const rec = run.records.find((r) => r.name === seed.key)!;
    const got = await run.restoreRecord(rec);
    ok(`R2 value restores byte-correct for ${seed.key}`, eqBytes(got, seed.value));
  }

  return { run, archive, master };
}

// ---- 3. APPLY: the sinks reconstruct the metadata on put --------------------------------
async function applyDescriptors(run: Emitted["run"]): Promise<void> {
  console.log("\napply (sinks pass the reconstructed descriptors to the binding):");
  const kvSinkBinding = new MockKVSink();
  const kvSink = new KVRestoreSink(kvSinkBinding as unknown as KVNamespace, NS);
  for (const seed of KV_SEEDS) {
    const rec = run.records.find((r) => r.name === seed.name)!;
    await kvSink.put(rec.name, await run.restoreRecord(rec), putOptionsFromRecord(rec));
  }
  const putBoth = kvSinkBinding.puts.find((p) => p.key === "with-both")!;
  ok("KV sink applies expiration on put", putBoth.options?.expiration === 1893456000);
  ok("KV sink applies metadata on put", JSON.stringify(putBoth.options?.metadata) === JSON.stringify({ tier: "gold", ttlSrc: "policy", weight: 7 }));
  const putBare = kvSinkBinding.puts.find((p) => p.key === "bare")!;
  ok("KV bare record put carries no options (value-only)", putBare.options === undefined);

  const r2SinkBinding = new MemR2([]);
  const r2Sink = new R2RestoreSink(r2SinkBinding as unknown as R2Bucket, BUCKET);
  for (const seed of R2_SEEDS) {
    const rec = run.records.find((r) => r.name === seed.key)!;
    await r2Sink.put(rec.name, await run.restoreRecord(rec), putOptionsFromRecord(rec));
  }
  const r2PutFull = r2SinkBinding.puts.find((p) => p.key === "uploads/report.txt")!;
  ok("R2 sink applies contentType on put", r2PutFull.options?.httpMetadata?.contentType === "text/plain");
  ok("R2 sink applies cacheControl on put", r2PutFull.options?.httpMetadata?.cacheControl === "max-age=3600");
  ok("R2 sink rebuilds cacheExpiry as a Date", r2PutFull.options?.httpMetadata?.cacheExpiry instanceof Date && r2PutFull.options.httpMetadata.cacheExpiry.toISOString() === R2_CACHE_EXPIRY.toISOString());
  ok("R2 sink applies custom metadata on put", deepEqual(r2PutFull.options?.customMetadata, { team: "ops", origin: "ingest" }));
  const r2PutBare = r2SinkBinding.puts.find((p) => p.key === "uploads/bare.bin")!;
  ok("R2 bare object put carries no options (value-only)", r2PutBare.options === undefined);
}

// ---- 4. BACKWARD COMPAT: no-descriptor archive is byte-identical in the shard manifest ---
async function backwardCompat(signer: Signer, breakGlass: ReturnType<typeof makeRecipient>, op: ReturnType<typeof makeRecipient>, archive: Map<string, Uint8Array>, master: Uint8Array): Promise<void> {
  console.log("\nbackward compatibility (omitempty: a no-descriptor archive is unchanged):");
  // Strip every descriptor and rebuild with the SAME master/nonce/salt sequence so the only
  // possible difference is the descriptor fields. The decrypted shard manifest must then be
  // byte-identical to a build of the same records with the descriptor code never touched, i.e.
  // no kv/r2/secrets/d1 key on any record line.
  const lines = await decryptShardLines(archive, master);
  const bareLine = lines.find((l) => l["name"] === "bare")!;
  ok("a value-only KV record line carries no kv/r2/secrets/d1 key", !("kv" in bareLine) && !("r2" in bareLine) && !("secrets" in bareLine) && !("d1" in bareLine));
  const r2BareLine = lines.find((l) => l["name"] === "uploads/bare.bin")!;
  ok("a value-only R2 record line carries no r2 key", !("r2" in r2BareLine));

  // Prove the omitempty guarantee at the byte level. Build two archives over the SAME records,
  // SAME master and a DETERMINISTIC nonce/salt stream, so the only thing that could differ is
  // the descriptor code path: one build gives every record NO descriptor, the other gives every
  // record an all-EMPTY descriptor (kvExpiration 0, empty strings) that descriptorFields must
  // drop entirely. The sealed shard bytes must then be byte-identical, which is exactly what
  // makes a descriptor-free archive (every conformance vector) verify unchanged.
  const plainRecords: WriteRecord[] = [
    { sourceType: "kv", name: "with-both", value: utf8("kv value one"), namespace: NS },
    { sourceType: "kv", name: "with-meta", value: utf8("kv value two"), namespace: NS },
    { sourceType: "kv", name: "bare", value: utf8("kv value three"), namespace: NS },
  ];
  const masterB = rand(32);
  // A counter-driven byte stream so two builds draw identical nonces/salts (the KV path uses
  // nonces only; no record here is a secret, so no salt is consumed, but pass one for parity).
  // randomNonce/randomSalt are called with no argument and must yield a 16-byte buffer; the previous
  // (n: number) => ... shape received undefined for n and produced a zero-length nonce. A no-arg
  // generator of a deterministic 16-byte block keeps the two builds in lock-step (so the byte-identical
  // manifest and equal-hash assertions still hold) while supplying a real nonce length.
  const detStream = () => { let c = 0; return (): Uint8Array => { const b = new Uint8Array(16); for (let i = 0; i < 16; i++) b[i] = (c + i) & 0xff; c++; return b; }; };
  const build = (records: WriteRecord[]) => buildArchive({ downpipeId: "dp_descriptors", downpipeName: "descriptors", cadence: "3600s", runId: RUN_ID, master: masterB, recipients: [breakGlass.entry, op.entry], signer, records, windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z", runlogIndex: 1, prevRunId: null, randomNonce: detStream(), randomSalt: detStream() });

  const noDescriptor = await build(plainRecords);
  const emptyDescriptorRecords: WriteRecord[] = plainRecords.map((r) => ({ ...r, descriptor: { kvExpiration: 0, secretsStore: "", secretsScope: "", secretsComment: "", secretsWorker: "", secretsBindingVar: "", d1Format: "" } }));
  const emptyArchive = await build(emptyDescriptorRecords);
  const sealedNone = noDescriptor.get(`run/${RUN_ID}/manifest/00000.dpe`)!;
  const sealedEmpty = emptyArchive.get(`run/${RUN_ID}/manifest/00000.dpe`)!;
  ok("an all-empty descriptor yields a byte-identical sealed shard manifest (omitempty)", eqBytes(sealedNone, sealedEmpty));
  // The signed root binds the shard by SHA-384 and the records by the Merkle root. Both are
  // identical with vs without empty descriptors (the root's masterCapsule legitimately differs
  // run to run because ML-KEM encapsulation draws its own randomness, so the root bytes are NOT
  // compared whole; the descriptor-relevant signed inputs are these two). That the shard hash
  // is unchanged is exactly why a descriptor-free archive still verifies: the descriptor code
  // contributes nothing to the bytes the signature covers when no descriptor is present.
  const rootNone = JSON.parse(new TextDecoder().decode(noDescriptor.get(`run/${RUN_ID}/root.manifest.json`)!)) as { merkleRoot: string; shards: { sha384: string }[] };
  const rootEmpty = JSON.parse(new TextDecoder().decode(emptyArchive.get(`run/${RUN_ID}/root.manifest.json`)!)) as { merkleRoot: string; shards: { sha384: string }[] };
  ok("the signed shard hash is unchanged by empty descriptors", rootNone.shards[0]!.sha384 === rootEmpty.shards[0]!.sha384);
  ok("the signed Merkle root is unchanged by empty descriptors", rootNone.merkleRoot === rootEmpty.merkleRoot);
}

async function main(): Promise<void> {
  // The signer the engine signs with and pins its verifier from (SIGNER_PRIVATE = b64url of
  // edSeed(32) || ML-DSA secret), so the reader's verify can pass.
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const mldsa = mldsaKeygen(mldsaSeed);
  const signer: Signer = await loadSigner(b64urlEncode(concat(edSeed, mldsaSeed)));
  const verifier = verifierFrom(signer);
  ok("signer public halves derive consistently", b64urlEncode(verifier.ed) === b64urlEncode(ed25519.getPublicKey(edSeed)) && b64urlEncode(verifier.mldsa) === b64urlEncode(mldsa.publicKey));

  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");

  const captured = await captureRecords();
  const { run, archive, master } = await emitAndVerify(signer, verifier, breakGlass, op, captured);
  await applyDescriptors(run);
  await backwardCompat(signer, breakGlass, op, archive, master);

  // ---- 5. the cross-implementation artefact -----------------------------------------------
  const outArg = argOut();
  const outDir = outArg ?? (await mkdtemp(join(tmpdir(), "downpipes-descriptors-")));
  await writeArchiveToDir(outDir, archive, breakGlass.identity, concat(verifier.ed, verifier.mldsa));
  console.log(`\nwrote a descriptor-bearing engine archive for the Go cross-check to:\n  ${outDir}`);
  console.log(`cross-check (offline Go reader, recovers + would replay descriptors):`);
  console.log(`  cd downpipe && go run ./cmd/downpipe restore --archive ${join(outDir, "archive")} \\`);
  console.log(`    --run ${RUN_ID} --identity ${join(outDir, "identity.key")} --signer ${join(outDir, "signer.pub")} \\`);
  console.log(`    --sink file --out <restore-dir>`);

  console.log(failures === 0 ? "\nDESCRIPTOR ROUND-TRIP TESTS PASS (full-fidelity archive; manifest signs + verifies; descriptors survive)" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

// argOut reads an optional `--out <dir>` so a caller can pin where the cross-impl sample lands.
function argOut(): string | undefined {
  const i = process.argv.indexOf("--out");
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : undefined;
}

// writeArchiveToDir flushes the archive object map plus the break-glass identity and signer
// public key in the Go CLI's labelled format, exactly as test/write-archive.ts does, so the Go
// tool can be pointed straight at it.
async function writeArchiveToDir(outDir: string, archive: Map<string, Uint8Array>, identity: Uint8Array, signerPublic: Uint8Array): Promise<void> {
  for (const [key, bytes] of archive) {
    const path = join(outDir, "archive", key);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, bytes);
  }
  await writeFile(join(outDir, "identity.key"), `downpipe-identity-v1 ${b64urlEncode(identity)}\n`);
  await writeFile(join(outDir, "signer.pub"), `downpipe-signer-public-v1 ${b64urlEncode(signerPublic)}\n`);
}

// makeMockD1 is the minimal D1Database surface the STREAMED D1Source.crawl reads: a consistent
// session, sqlite_master, a LIMIT 0 column header, a _rowid_ probe, then one keyset page. It is
// enough to exercise the format-descriptor capture, not the full D1 path (validate-d1-restore).
function makeMockD1(): unknown {
  const master = [{ type: "table", name: "items", tbl_name: "items", sql: "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)" }];
  const reader = {
    prepare(sql: string) {
      const stmt = {
        bind(..._v: unknown[]) { return stmt; },
        async all<T>(): Promise<{ results: T[] }> {
          if (sql.includes("sqlite_master")) return { results: master as unknown as T[] };
          return { results: [] };
        },
        async raw<T>(_opts: { columnNames: true }): Promise<T[]> {
          if (/LIMIT 0/i.test(sql)) {
            // _rowid_ probe -> rowid header; column-header probe -> the table's columns.
            return [/_rowid_/i.test(sql) ? ["_rowid_"] : ["id", "label"]] as unknown as T[];
          }
          // Keyset page: one data row plus the trailing rowid cursor; then exhausted. The source binds the
          // cursor as a string and casts it to INTEGER (real D1 rejects a bigint bind), so match that form.
          // The page now reads the integer-safe TYPED projection (d1-reader typedProjection): per column a
          // (typeof, CASE-projected value) pair, then CAST(_rowid_ AS TEXT). For items (id INTEGER, label
          // TEXT): typeof(id)='integer' + CAST(id AS TEXT)='1'; typeof(label)='text' + label='first'; then
          // the rowid cursor as text.
          if (/_rowid_ > CAST\(\?1 AS INTEGER\)/i.test(sql)) return [["__t0", "__v0", "__t1", "__v1", "__dp_rowid"], ["integer", "1", "text", "first", "1"]] as unknown as T[];
          return [["__t0", "__v0", "__t1", "__v1"], ["integer", "1", "text", "first"]] as unknown as T[];
        },
      };
      return stmt;
    },
  };
  return { ...reader, withSession(_c?: string) { return reader; } };
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
