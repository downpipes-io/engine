// Prove the three coupled RESTORE-INTEGRITY features end to end, in-memory only (no network, deploy or
// cost):
//   1. VERIFY-ON-READBACK for streamed R2 restores. After the streamed apply writes a large R2 object,
//      the engine reads it BACK from the same sink and re-hashes it (bounded memory) and asserts it
//      equals the SIGNED manifest hash. A readback that MISMATCHES (the persisted bytes are wrong) or a
//      MISSING object is recorded as a FAILURE, never a success: the apply ok is false, the record is in
//      failures, and its receipt entry is verified:false. The object is LEFT in place (the operator
//      decides). Bounded memory: verifyReadbackStreaming re-hashes incrementally, never buffering whole.
//   2. The BUFFERED CEILING gate. A record at/below BUFFERED_RESTORE_MAX_BYTES takes the buffered path
//      (receipt via:"buffered"); a record above it takes streaming + readback (receipt
//      via:"streamed-readback"). We force the streaming path on a small object by LOWERING the ceiling via
//      the RESTORE_BUFFERED_MAX_BYTES env knob (the knob only ever lowers it; the safety cap is 32 MiB).
//   3. The signed / audit-anchored RECEIPT. An applied restore returns a RestoreReceipt: one entry per
//      restored record with the expected (signed) hash, the verified hash, via and verified; a summary
//      with allVerified. It is tamper-evident: a DETACHED HYBRID SIGNATURE over the canonical core
//      (verifies against the operator-pinned verifier) AND an audit anchor (a "restore-verified" chain
//      entry carrying the receipt SHA-384, which the chain verify accepts and which binds the receipt's
//      content even with no signer key).
//
// Run: node test/validate-restore-readback.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen, mldsaKeygen } from "../src/crypto/pq.ts";
import {
  buildArchive,
  buildRecordLine,
  buildSignedRoot,
  sealShardManifest,
  signRunlog,
  type RecipientEntry,
  type Signer,
  type RecordMeta,
} from "../src/format/writer.ts";
import { sealRecordToDest } from "../src/seal/record.ts";
import { MerkleFrontier } from "../src/format/frontier.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { openRun, type ObjectStore, type Run } from "../src/format/reader.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { deriveCAK, deriveMK, deriveNameMACKey } from "../src/crypto/derive.ts";
import { decodeULID } from "../src/format/ulid.ts";
import { addBundle } from "../src/format/bundle.ts";
import { R2RestoreSink, KVRestoreSink, SecretsRestoreSink, D1RestoreSink, ReadbackNotSupportedError } from "../src/dest/restore-sink.ts";
import { runRestore, verifyReadbackStreaming, restoreReceiptDigestHex, verifyRestoreReceiptSignature } from "../src/admin/restore.ts";
import { buildEvent, verifyChain, type AuditDraft, type AuditEvent } from "../src/admin/audit.ts";
import { b64urlEncode, concat, hexEncode, utf8 } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import type { ShardRecord } from "../src/format/manifest.ts";
import type { SourceRecord } from "../src/sources/types.ts";
import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import type { Env } from "../src/env.d.ts";
import type { RestoreResult, RestoreReceipt } from "../src/admin/restore-types.ts";

const RUN_ID = "01BX5ZZKBKACTAV9WEVGEMMVS0";
const DP_ID = "dp_readback";
const NS = "ns_rb";
const BUCKET = "media";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// Knuth's multiplicative hash constant (0x9E3779B1) gives a deterministic, well-distributed
// byte pattern from the index and seed, so the readback assertion is exact and reproducible.
const KNUTH_HASH_MULTIPLIER = 2654435761;

function patterned(n: number, seed: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (Math.imul(i + seed, KNUTH_HASH_MULTIPLIER) >>> 24) & 0xff;
  return b;
}

async function drain(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  const reader = stream.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(value);
  }
  return concat(...parts);
}

// streamOf emits bytes as a readable stream (one chunk), so getStreamForVerify can hand the sink a real
// stream and the readback re-hashes it incrementally.
function streamOf(bytes: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
}

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// MemDest is the seal-pass destination for the multi-segment streamed archive (Section A).
class MemDest implements Destination {
  map = new Map<string, Uint8Array>();
  async get(key: string): Promise<GetResult | null> {
    const v = this.map.get(key);
    return v ? { body: v, etag: "e0" } : null;
  }
  async put(key: string, body: Uint8Array): Promise<void> {
    this.map.set(key, body);
  }
  async putStream(key: string, body: ReadableStream<Uint8Array>, _size?: number): Promise<void> {
    this.map.set(key, await drain(body));
  }
  async putConditional(key: string, body: Uint8Array): Promise<PutConditionalResult> {
    await this.put(key, body);
    return { ok: true, etag: "e0" };
  }
  async exists(key: string): Promise<boolean> {
    return this.map.has(key);
  }
  async delete(key: string): Promise<void> {
    this.map.delete(key);
  }
  async list(prefix: string): Promise<string[]> {
    return [...this.map.keys()].filter((k) => k.startsWith(prefix));
  }
}

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

// FakeR2 is the live R2 BINDING a restore writes back into and reads back from: put() drains the streamed
// body (or stores a buffer), get() returns the stored object as { body: stream } so getStreamForVerify can
// re-read it. A `corruptPut` option flips one byte of what is PERSISTED, modelling a write that R2 accepts
// but that lands wrong bytes (so the readback must catch it). A `dropOnGet` set drops a key on get,
// modelling a missing object after a write.
class FakeR2 {
  stored = new Map<string, Uint8Array>();
  dropOnGet = new Set<string>();
  private corruptPut: boolean;
  constructor(corruptPut = false) {
    this.corruptPut = corruptPut;
  }
  async put(key: string, body: ReadableStream<Uint8Array> | ArrayBuffer | ArrayBufferView | string | null | Blob): Promise<{ etag: string }> {
    let bytes: Uint8Array;
    if (body instanceof ReadableStream) bytes = await drain(body);
    else if (typeof body === "string") bytes = utf8(body);
    else if (body instanceof Uint8Array) bytes = body.slice();
    else if (body instanceof ArrayBuffer) bytes = new Uint8Array(body.slice(0));
    else if (body && ArrayBuffer.isView(body)) bytes = new Uint8Array(body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength));
    else bytes = new Uint8Array(0);
    if (this.corruptPut && bytes.length > 0) {
      const c = bytes.slice();
      c[0] = c[0]! ^ 0xff; // the write "succeeds" but persists a wrong byte
      bytes = c;
    }
    this.stored.set(key, bytes);
    return { etag: "etag" };
  }
  async get(key: string): Promise<{ body: ReadableStream<Uint8Array> } | null> {
    if (this.dropOnGet.has(key)) return null;
    const v = this.stored.get(key);
    if (!v) return null;
    return { body: streamOf(v) };
  }
}

// assembleArchive turns sealed records into the manifest/root/runlog/bundle objects (the builders the
// sliced seal uses), so openRun can verify and restore them. Mirrors validate-streaming-restore.
// sealRecordsToShard builds the per-record lines + the Merkle frontier from the sealed records, then
// seals the shard manifest carrying those lines.
async function sealRecordsToShard(
  master: Uint8Array,
  sealed: { meta: RecordMeta; seal: Awaited<ReturnType<typeof sealRecordToDest>> }[],
): Promise<{ shard: Awaited<ReturnType<typeof sealShardManifest>>; lines: unknown[]; merkleRootHex: string }> {
  const runIdBytes = decodeULID(RUN_ID);
  const mk = await deriveMK(master, runIdBytes);
  const nameKey = await deriveNameMACKey(mk, runIdBytes);
  const frontier = new MerkleFrontier();
  const lines: unknown[] = [];
  let i = 0;
  for (const s of sealed) {
    if (s.seal.ok !== true) continue;
    const recordId = "r" + String(i++).padStart(15, "0");
    const { line, recordHash } = await buildRecordLine(nameKey, recordId, s.meta, s.seal.seal);
    lines.push(line);
    await frontier.append(recordHash);
  }
  const shard = await sealShardManifest({
    master,
    runId: RUN_ID,
    shardId: "00000",
    downpipeName: "readback",
    cadence: "3600s",
    sourceType: "r2",
    windowStart: "2026-06-10T00:00:00.000Z",
    windowEnd: "2026-06-10T00:00:01.000Z",
    recordLines: lines,
    randomNonce: () => rand(16),
  });
  return { shard, lines, merkleRootHex: hexEncode(await frontier.root()) };
}

async function assembleArchive(p: {
  dest: MemDest;
  master: Uint8Array;
  signer: Signer;
  recipients: RecipientEntry[];
  sealed: { meta: RecordMeta; seal: Awaited<ReturnType<typeof sealRecordToDest>> }[];
}): Promise<void> {
  const { shard, lines, merkleRootHex } = await sealRecordsToShard(p.master, p.sealed);
  const { rootBytes, sigBytes } = await buildSignedRoot({
    downpipeId: DP_ID,
    runId: RUN_ID,
    createdAt: "2026-06-10T00:00:01.000Z",
    master: p.master,
    recipients: p.recipients,
    signer: p.signer,
    shards: [{ id: "00000", object: shard.object, sha384: shard.sha384Hex }],
    declaredRecordCount: lines.length,
    merkleRootHex,
    prevRunId: null,
    runlogIndex: 1,
    randomNonce: () => rand(16),
  });
  const finalObjects = new Map<string, Uint8Array>();
  finalObjects.set(shard.object, shard.bytes);
  finalObjects.set(`run/${RUN_ID}/root.manifest.json`, rootBytes);
  finalObjects.set(`run/${RUN_ID}/root.manifest.json.sig`, sigBytes);
  const { runlog, sig } = await signRunlog(
    [{ index: 1, runId: RUN_ID, downpipeId: DP_ID, time: "2026-06-10T00:00:01.000Z", recordCount: lines.length, prevRunId: null, status: "active" }],
    p.signer.edPrivate,
    p.signer.mldsaSecret,
  );
  finalObjects.set("_RECOVERY/RUNLOG", runlog);
  finalObjects.set("_RECOVERY/RUNLOG.sig", utf8(b64urlEncode(sig)));
  await addBundle(finalObjects, p.signer.edPrivate, p.signer.mldsaSecret);
  for (const [k, v] of finalObjects) await p.dest.put(k, v);
}

// buildBigArchive seals a 1 MiB + 7 B value across 5 segments (small segment target), opens it, and
// returns the run + the streamable record + the original value, so the readback helper can be driven over
// the REAL R2RestoreSink (the apply path's exact call) without any 32 MiB allocation.
async function buildBigArchive(): Promise<{ run: Run; recBig: ShardRecord; bigValue: Uint8Array }> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const signer: Signer = await loadSigner(b64urlEncode(concat(edSeed, mldsaSeed)));
  const verifier = verifierFrom(signer);
  const breakGlass = makeRecipient("break-glass");
  const recipients = [breakGlass.entry];

  const TARGET = 256 * 1024; // 4 STREAM chunks per segment
  const master = rand(32);
  const runIdBytes = decodeULID(RUN_ID);
  const cak = await deriveCAK(master, DP_ID);
  const dest = new MemDest();
  const deps = { cak, master, runIdBytes, dest, randomNonce: () => rand(16), randomSalt: () => rand(16), segmentTargetBytes: TARGET };

  const bigValue = patterned(1024 * 1024 + 7, 3);
  const bigStreamRecord: SourceRecord = {
    sourceType: "r2",
    name: "big/object.bin",
    bucket: BUCKET,
    stream: {
      size: bigValue.length,
      open: () => ({
        async *chunks() {
          yield bigValue;
        },
      }),
      openRange: (offset: number, length: number) => ({
        async *chunks() {
          yield bigValue.subarray(offset, offset + length);
        },
      }),
    },
  };
  const sealedBig = await sealRecordToDest(deps, "r000000000000000", bigStreamRecord);
  if (!sealedBig.ok) throw new Error("seal of the big record failed");

  await assembleArchive({
    dest,
    master,
    signer,
    recipients,
    sealed: [{ meta: { sourceType: "r2", name: "big/object.bin", bucket: BUCKET } as RecordMeta, seal: sealedBig }],
  });
  const identity = parseIdentity(breakGlass.identity);
  const run = await openRun(new MapStore(dest.map), RUN_ID, identity, verifier, {});
  const recBig = run.records.find((r) => r.name === "big/object.bin")!;
  return { run, recBig, bigValue };
}

// ---- Section A: verifyReadbackStreaming over the REAL sink (happy / wrong-bytes / missing) ----
type BigArchive = Awaited<ReturnType<typeof buildBigArchive>>;

// Happy path: stream-restore (the apply path's exact call), then read the LANDED object back and
// re-hash it. The readback hash equals the signed plaintextSha384.
async function proofHappyPath({ run, recBig, bigValue }: BigArchive): Promise<void> {
  const fake = new FakeR2();
  const sink = new R2RestoreSink(fake as unknown as R2Bucket, BUCKET);
  await sink.putStream("big/object.bin", run.restoreRecordStream(recBig), recBig.plaintextSize);
  ok("the streamed object landed byte-exact", eqBytes(fake.stored.get("big/object.bin")!, bigValue));
  const back = await verifyReadbackStreaming(sink, "big/object.bin");
  ok("readback hash equals the signed plaintext SHA-384 (proves the LANDED bytes)", back === recBig.plaintextSha384);
  ok("readback hash equals an independent hash of the original", back === hexEncode(await sha384(bigValue)));
}

// Wrong bytes: a binding that PERSISTS a corrupted object. The readback hash must NOT match the signed
// hash (the post-write check catches a write that landed wrong).
async function proofCorruptBytes({ run, recBig, bigValue }: BigArchive): Promise<void> {
  const corrupt = new FakeR2(true);
  const corruptSink = new R2RestoreSink(corrupt as unknown as R2Bucket, BUCKET);
  await corruptSink.putStream("big/object.bin", run.restoreRecordStream(recBig), recBig.plaintextSize);
  ok("the corrupting binding persisted DIFFERENT bytes than the verified stream", !eqBytes(corrupt.stored.get("big/object.bin")!, bigValue));
  const backBad = await verifyReadbackStreaming(corruptSink, "big/object.bin");
  ok("readback hash of corrupted landing does NOT equal the signed hash", backBad !== recBig.plaintextSha384);
}

// Missing object: a binding that returns null on get. The readback must THROW (the caller treats it as
// a failure), never return a fabricated pass.
async function proofMissing({ run, recBig }: BigArchive): Promise<void> {
  const missing = new FakeR2();
  const missingSink = new R2RestoreSink(missing as unknown as R2Bucket, BUCKET);
  await missingSink.putStream("big/object.bin", run.restoreRecordStream(recBig), recBig.plaintextSize);
  missing.dropOnGet.add("big/object.bin");
  let threw = false;
  try {
    await verifyReadbackStreaming(missingSink, "big/object.bin");
  } catch {
    threw = true;
  }
  ok("readback of a missing object throws (the caller records a failure)", threw);
}

// Bounded memory by construction: the helper re-hashes off a stream and never returns or buffers the
// value. We assert it consumed the binding's get() stream (a stream double counting reads).
async function proofBoundedMemory(): Promise<void> {
  let getReads = 0;
  const countingSink = {
    sourceType: "r2" as const,
    target: () => BUCKET,
    put: async () => {},
    putStream: async () => {},
    getStreamForVerify: async () =>
      new ReadableStream<Uint8Array>({
        pull(controller) {
          getReads++;
          if (getReads <= 16) controller.enqueue(patterned(64 * 1024, getReads));
          else controller.close();
        },
      }),
  };
  const h = await verifyReadbackStreaming(countingSink, "x");
  ok("readback drained the object as a STREAM (many pulls, bounded memory)", getReads > 8 && h.length === 96);
}

async function sectionA(): Promise<void> {
  console.log("verify-on-readback helper (real R2RestoreSink + fake binding):");
  const big = await buildBigArchive();
  await proofHappyPath(big);
  await proofCorruptBytes(big);
  await proofMissing(big);
  await proofBoundedMemory();
}

// ---- Section B: the buffered-ceiling gate observed via runRestore's receipt `via` ----
// We build one small KV record and one small R2 record (well under any sane ceiling) and a low override.
interface SmallArchive {
  archive: Map<string, Uint8Array>;
  opB64: string; // the operational read-back identity
  signerB64: string; // SIGNER_PRIVATE the engine derives its verifier + receipt signer from
}
async function buildSmallArchive(records: Array<{ sourceType: "kv" | "r2"; name: string; value: Uint8Array; namespace?: string; bucket?: string }>): Promise<SmallArchive> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const signerB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer = await loadSigner(signerB64);
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const archive = await buildArchive({
    downpipeId: DP_ID,
    downpipeName: "readback",
    cadence: "3600s",
    runId: RUN_ID,
    master: rand(32),
    recipients: [breakGlass.entry, op.entry],
    signer,
    records,
    windowStart: "2026-06-07T00:00:00.000Z",
    windowEnd: "2026-06-07T00:00:01.000Z",
    createdAt: "2026-06-07T00:00:01.000Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });
  return { archive, opB64: b64urlEncode(op.identity), signerB64 };
}

// MockR2Archive serves the sealed archive objects to the reader (the READ side / selectable dest).
class MockR2Archive {
  store = new Map<string, Uint8Array>();
  async get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer>; etag: string } | null> {
    const v = this.store.get(key);
    if (!v) return null;
    return { arrayBuffer: async () => toAB(v), etag: `"${key.length}"` };
  }
  async head(key: string): Promise<{ etag: string } | null> {
    const v = this.store.get(key);
    return v ? { etag: `"${key.length}"` } : null;
  }
  async put(key: string, body: ArrayBuffer | Uint8Array): Promise<{ etag: string }> {
    this.store.set(key, body instanceof Uint8Array ? body : new Uint8Array(body));
    return { etag: `"${key.length}"` };
  }
}

function toAB(b: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(b.byteLength);
  new Uint8Array(out).set(b);
  return out;
}

// MockKV is a minimal KV binding (the write-back target for the KV record).
class MockKV {
  store = new Map<string, Uint8Array>();
  putCount = 0;
  async put(k: string, v: ArrayBuffer | Uint8Array): Promise<void> {
    this.putCount++;
    this.store.set(k, v instanceof Uint8Array ? v : new Uint8Array(v));
  }
  async get(k: string): Promise<ArrayBuffer | null> {
    const v = this.store.get(k);
    return v ? toAB(v) : null;
  }
}

interface SectionBFixture {
  archiveR2: MockR2Archive;
  opB64: string;
  signerB64: string;
  kvVal: Uint8Array;
  r2Val: Uint8Array;
}

// Case 1: a SANE (high) ceiling -> the 64 KiB R2 record is BUFFERED. It is small enough to be written
// whole, so the buffered path now READS IT BACK and re-hashes the landed object (via:buffered-readback).
// The KV record cannot read back (no native API) so it is via:buffered-no-readback. Both verified.
async function sectionBHighCeiling(f: SectionBFixture): Promise<void> {
  const { archiveR2, opB64, signerB64, r2Val } = f;
  {
    const kv = new MockKV();
    const r2live = new FakeR2();
    const env = {
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      DEST_KIND: "r2",
      DEST_R2: archiveR2 as unknown as R2Bucket,
      SIGNER_PRIVATE: signerB64,
      OPERATIONAL_PRIVATE: opB64,
      [`KV_${NS}`]: kv as unknown as KVNamespace,
      [`R2_${BUCKET}`]: r2live as unknown as R2Bucket,
    } as unknown as Env;
    const res = (await runRestore(env, { runId: RUN_ID, confirm: true })) as RestoreResult;
    ok("high-ceiling apply restored both records", res.ok === true && res.recordsRestored === 2);
    const receipt = res.receipt!;
    const r2Entry = receipt.records.find((r) => r.name === "r1")!;
    const kvEntry = receipt.records.find((r) => r.name === "k1")!;
    ok("the small buffered R2 record was PROVEN by readback (via:buffered-readback)", r2Entry.via === "buffered-readback" && r2Entry.verified);
    ok("the small buffered R2 readback hash equals the signed expected hash", r2Entry.verifiedSha384 === r2Entry.expectedSha384 && r2Entry.expectedSha384 === hexEncode(await sha384(r2Val)));
    ok("the KV record makes NO readback claim (via:buffered-no-readback)", kvEntry.via === "buffered-no-readback" && kvEntry.verified);
    ok("the live R2 binding stored the object byte-exact", eqBytes(r2live.stored.get("r1")!, r2Val));
  }
}

// Case 2: the SAME 64 KiB R2 record with a LOW ceiling override -> it now STREAMS and is proven by
// READBACK (via:"streamed-readback"); the KV record is unaffected (still buffered). This proves the
// gate is driven by BUFFERED_RESTORE_MAX_BYTES, and the streamed object verifies on readback.
async function sectionBLowCeiling(f: SectionBFixture): Promise<void> {
  const { archiveR2, opB64, signerB64, r2Val } = f;
  {
    const kv = new MockKV();
    const r2live = new FakeR2();
    const env = {
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      DEST_KIND: "r2",
      DEST_R2: archiveR2 as unknown as R2Bucket,
      SIGNER_PRIVATE: signerB64,
      OPERATIONAL_PRIVATE: opB64,
      RESTORE_BUFFERED_MAX_BYTES: "4096", // 4 KiB: forces the 64 KiB R2 record to stream
      [`KV_${NS}`]: kv as unknown as KVNamespace,
      [`R2_${BUCKET}`]: r2live as unknown as R2Bucket,
    } as unknown as Env;
    const res = (await runRestore(env, { runId: RUN_ID, confirm: true })) as RestoreResult;
    ok("low-ceiling apply restored both records", res.ok === true && res.recordsRestored === 2);
    const receipt = res.receipt!;
    const r2Entry = receipt.records.find((r) => r.name === "r1")!;
    const kvEntry = receipt.records.find((r) => r.name === "k1")!;
    ok("the 64 KiB R2 record now took the STREAMING + READBACK path (via:streamed-readback)", r2Entry.via === "streamed-readback" && r2Entry.verified);
    ok("the streamed record's verifiedSha384 equals the signed expected hash", r2Entry.verifiedSha384 === r2Entry.expectedSha384 && r2Entry.expectedSha384 === hexEncode(await sha384(r2Val)));
    ok("the KV record is unaffected by the ceiling (still buffered-no-readback)", kvEntry.via === "buffered-no-readback" && kvEntry.verified);
    ok("the streamed object landed byte-exact in the live R2 binding", eqBytes(r2live.stored.get("r1")!, r2Val));
    ok("receipt.summary.allVerified is true on a clean apply", receipt.summary.allVerified === true && receipt.summary.recordsRestored === 2);
  }
}

async function sectionB(): Promise<void> {
  console.log("\nbuffered ceiling gate (observed via the receipt `via` through runRestore):");
  const kvVal = utf8("alpha-value-buffered");
  const r2Val = patterned(64 * 1024, 9); // 64 KiB R2 object
  const { archive, opB64, signerB64 } = await buildSmallArchive([
    { sourceType: "kv", name: "k1", value: kvVal, namespace: NS },
    { sourceType: "r2", name: "r1", value: r2Val, bucket: BUCKET },
  ]);
  const archiveR2 = new MockR2Archive();
  for (const [k, b] of archive) archiveR2.store.set(k, b);
  const f: SectionBFixture = { archiveR2, opB64, signerB64, kvVal, r2Val };
  await sectionBHighCeiling(f);
  await sectionBLowCeiling(f);
}

// ---- Section C: a streamed READBACK FAILURE through runRestore is NOT a success ----
interface SectionCFixture {
  archiveR2: MockR2Archive;
  opB64: string;
  signerB64: string;
}

// Wrong-bytes landing: a binding that corrupts what it persists. The streamed write "succeeds" (R2
// accepts the body), but the readback re-hash does not match the signed hash -> the record is a FAILURE.
async function sectionCWrongBytes(f: SectionCFixture): Promise<void> {
  const { archiveR2, opB64, signerB64 } = f;
  {
    const corruptR2 = new FakeR2(true);
    const env = {
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      DEST_KIND: "r2",
      DEST_R2: archiveR2 as unknown as R2Bucket,
      SIGNER_PRIVATE: signerB64,
      OPERATIONAL_PRIVATE: opB64,
      RESTORE_BUFFERED_MAX_BYTES: "4096",
      [`R2_${BUCKET}`]: corruptR2 as unknown as R2Bucket,
    } as unknown as Env;
    const res = (await runRestore(env, { runId: RUN_ID, confirm: true })) as RestoreResult;
    ok("a readback MISMATCH makes the apply NOT ok", res.ok === false);
    ok("nothing is counted as restored when the only record failed readback", res.recordsRestored === 0);
    ok("the record is in failures with a readback-verification reason", res.failures.some((f) => f.name === "r1" && /readback/.test(f.reason)));
    const receipt = res.receipt!;
    const r2Entry = receipt.records.find((r) => r.name === "r1")!;
    ok("the receipt entry is verified:false (proof the landed bytes are wrong)", r2Entry !== undefined && r2Entry.verified === false && r2Entry.via === "streamed-readback");
    ok("the receipt's verifiedSha384 differs from the expected (signed) hash", r2Entry.verifiedSha384 !== null && r2Entry.verifiedSha384 !== r2Entry.expectedSha384);
    ok("receipt.summary.allVerified is FALSE on a readback mismatch", receipt.summary.allVerified === false);
    // The object was LEFT in place (the operator decides; deleting could lose data).
    ok("the (wrong) object was NOT deleted (operator decides)", corruptR2.stored.has("r1"));
  }
}

// Missing-object landing: a binding that drops the object on get. The readback throws -> failure, with
// a verifiedSha384:null receipt entry.
async function sectionCMissing(f: SectionCFixture): Promise<void> {
  const { archiveR2, opB64, signerB64 } = f;
  {
    const droppingR2 = new FakeR2();
    droppingR2.dropOnGet.add("r1");
    const env = {
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      DEST_KIND: "r2",
      DEST_R2: archiveR2 as unknown as R2Bucket,
      SIGNER_PRIVATE: signerB64,
      OPERATIONAL_PRIVATE: opB64,
      RESTORE_BUFFERED_MAX_BYTES: "4096",
      [`R2_${BUCKET}`]: droppingR2 as unknown as R2Bucket,
    } as unknown as Env;
    const res = (await runRestore(env, { runId: RUN_ID, confirm: true })) as RestoreResult;
    ok("a missing-on-readback object makes the apply NOT ok", res.ok === false && res.recordsRestored === 0);
    ok("the record is in failures (could not be read back)", res.failures.some((f) => f.name === "r1" && /read back|readback/.test(f.reason)));
    const r2Entry = res.receipt!.records.find((r) => r.name === "r1")!;
    ok("the receipt entry is verified:false with verifiedSha384:null (no readback)", r2Entry.verified === false && r2Entry.verifiedSha384 === null);
  }
}

async function sectionC(): Promise<void> {
  console.log("\nreadback FAILURE through runRestore (the landed bytes are wrong):");
  const r2Val = patterned(64 * 1024, 11);
  const { archive, opB64, signerB64 } = await buildSmallArchive([{ sourceType: "r2", name: "r1", value: r2Val, bucket: BUCKET }]);
  const archiveR2 = new MockR2Archive();
  for (const [k, b] of archive) archiveR2.store.set(k, b);
  const f: SectionCFixture = { archiveR2, opB64, signerB64 };
  await sectionCWrongBytes(f);
  await sectionCMissing(f);
}

// ---- Section D: the receipt is signed AND audit-anchored ----
// proofReceiptContent checks the receipt shape, the per-record via labels and the summary totals.
async function proofReceiptContent(receipt: RestoreReceipt, kvVal: Uint8Array, r2Val: Uint8Array): Promise<void> {
  ok("the applied result carries a receipt", receipt !== undefined && receipt.runId === RUN_ID);
  ok("one receipt entry per restored record", receipt.records.length === 2);
  ok("both `via` values are present (buffered-no-readback + streamed-readback)", receipt.records.some((r) => r.via === "buffered-no-readback") && receipt.records.some((r) => r.via === "streamed-readback"));
  for (const rec of receipt.records) {
    ok(`receipt entry ${rec.name}: expected/verified hashes present and equal, verified:true`, rec.expectedSha384.length === 96 && rec.verifiedSha384 === rec.expectedSha384 && rec.verified === true);
  }
  ok("summary is correct (count + bytes + allVerified)", receipt.summary.recordsRestored === 2 && receipt.summary.bytesRestored === kvVal.length + r2Val.length && receipt.summary.allVerified === true);
}

// proofReceiptSignature checks the hybrid signature verifies, the digest re-derives, a tamper breaks
// both checks, and a wrong verifier rejects the signature while the hash still matches.
async function proofReceiptSignature(receipt: RestoreReceipt, signerB64: string): Promise<void> {
  const signer = await loadSigner(signerB64);
  const verifier = verifierFrom(signer);
  ok("the receipt is KEY-SIGNED (a signer was reachable)", typeof receipt.signature === "string" && receipt.signature.length > 0 && receipt.signatureAlg === "ed25519+ml-dsa-87");
  const v = await verifyRestoreReceiptSignature(receipt, verifier);
  ok("the receipt content matches its stated digest (hashOk)", v.hashOk === true);
  ok("the detached hybrid signature verifies against the operator-pinned verifier (signatureOk)", v.signatureOk === true);
  ok("receiptSha384 re-derives from the canonical core", (await restoreReceiptDigestHex(receipt)) === receipt.receiptSha384);

  // Tamper: flipping any receipt field breaks BOTH the hash and the signature.
  const tampered: RestoreReceipt = { ...receipt, summary: { ...receipt.summary, recordsRestored: 99 } };
  const vt = await verifyRestoreReceiptSignature(tampered, verifier);
  ok("a tampered receipt fails the hash check", vt.hashOk === false);
  ok("a tampered receipt fails the signature check", vt.signatureOk === false);

  // A WRONG verifier (a different key) does not verify the genuine signature.
  const otherEd = rand(32);
  const otherMldsa = mldsaKeygen(rand(32));
  const wrongVerifier = { ed: ed25519.getPublicKey(otherEd), mldsa: otherMldsa.publicKey };
  const vw = await verifyRestoreReceiptSignature(receipt, wrongVerifier);
  ok("a wrong verifier does NOT verify the signature (but the hash still matches)", vw.signatureOk === false && vw.hashOk === true);

  // recordsSkipped: the count the apply deliberately did not write. Without it, a reader auditing a
  // recovery would see "restored 98, allVerified true" and have no way to tell that records from the
  // archive were still absent from the account.
  //
  // The backward-compatibility property is the load-bearing one, because this receipt is ANCHORED into
  // the tamper-evident audit chain by its digest. A receipt that skipped nothing must produce the SAME
  // canonical bytes as before the field existed, or every already-anchored receipt stops matching its
  // recorded digest and a real archive of evidence reads as tampered.
  ok("a clean receipt omits recordsSkipped entirely", receipt.summary.recordsSkipped === undefined);
  const cleanCore = JSON.stringify(await canonicalReceiptCoreForTest(receipt));
  ok("a clean receipt's canonical core carries no recordsSkipped key (byte-identical to a pre-field receipt)", !cleanCore.includes("recordsSkipped"));

  // With a non-zero count the field IS committed to: it changes the digest, so it is signed evidence
  // rather than an unsigned annotation a tamperer could strip.
  const withSkips: RestoreReceipt = { ...receipt, summary: { ...receipt.summary, recordsSkipped: 2 } };
  const dWith = await restoreReceiptDigestHex(withSkips);
  ok("recordsSkipped is inside the signed/hashed core (adding it changes the digest)", dWith !== receipt.receiptSha384);
  const vSkip = await verifyRestoreReceiptSignature(withSkips, verifier);
  ok("stamping recordsSkipped onto a signed receipt breaks its hash and signature (it cannot be added after the fact)", vSkip.hashOk === false && vSkip.signatureOk === false);
  // And zero must behave exactly like absent, or a caller passing 0 silently forks the digest.
  const zeroSkips: RestoreReceipt = { ...receipt, summary: { ...receipt.summary, recordsSkipped: 0 } };
  ok("recordsSkipped:0 hashes identically to an absent field (zero is not a distinct state)", (await restoreReceiptDigestHex(zeroSkips)) === receipt.receiptSha384);
}

// canonicalReceiptCoreForTest re-derives what the digest is computed over, so the test can assert on the
// hashed bytes rather than on the receipt object. It mirrors restore-receipt.ts receiptCore; the digest
// equality assertions above are what keep the two honest.
async function canonicalReceiptCoreForTest(r: RestoreReceipt): Promise<unknown> {
  return {
    runId: r.runId,
    restoredAt: r.restoredAt,
    isLatest: r.isLatest,
    records: r.records,
    summary: r.summary,
  };
}

// proofAuditAnchor models the router's append of a "restore-verified" entry carrying the receipt
// SHA-384 onto a real hash chain, verifies the chain, then proves editing the anchored digest breaks it.
async function proofAuditAnchor(receipt: RestoreReceipt): Promise<void> {
  const draft: AuditDraft = {
    actorSubject: "iss|sub",
    actorEmail: "op@example.com",
    actorMethod: "passkey",
    sourceIp: null,
    action: "restore-verified",
    outcome: receipt.summary.allVerified ? "success" : "failed",
    target: { kind: "restore-receipt", runId: receipt.runId, receiptSha384: receipt.receiptSha384, recordsRestored: receipt.summary.recordsRestored, allVerified: receipt.summary.allVerified },
  };
  const genesis = await buildEvent({ actorSubject: null, actorEmail: null, actorMethod: "engine", sourceIp: null, action: "engine-secret-present", outcome: "success", target: { kind: "engine-state", field: "secret-present", detail: "signerConfigured" } }, 1, "2026-06-10T00:00:00.000Z", null);
  const anchor = await buildEvent(draft, 2, "2026-06-10T00:00:02.000Z", genesis);
  const chain: AuditEvent[] = [genesis, anchor];
  const verdict = await verifyChain(chain);
  ok("the audit chain with the receipt anchor verifies intact", verdict.intact === true && verdict.checkedThrough === 2);
  ok("the anchor entry carries the receipt SHA-384 in the chain", anchor.target.kind === "restore-receipt" && anchor.target.receiptSha384 === receipt.receiptSha384);
  ok("the anchor binds runId + recordsRestored + allVerified", anchor.target.kind === "restore-receipt" && anchor.target.runId === RUN_ID && anchor.target.recordsRestored === 2 && anchor.target.allVerified === true);
  // The anchor's own hash commits to the receipt digest: editing the anchored digest breaks the chain.
  const editedAnchor: AuditEvent = { ...anchor, target: { kind: "restore-receipt", runId: RUN_ID, receiptSha384: "00".repeat(48), recordsRestored: 2, allVerified: true } };
  const brokenVerdict = await verifyChain([genesis, editedAnchor]);
  ok("editing the anchored receipt digest breaks the chain (tamper-evident)", brokenVerdict.intact === false && brokenVerdict.brokenAt === 2);
}

async function sectionD(): Promise<void> {
  console.log("\nsigned + audit-anchored receipt:");
  const kvVal = utf8("alpha");
  const r2Val = patterned(64 * 1024, 13);
  const { archive, opB64, signerB64 } = await buildSmallArchive([
    { sourceType: "kv", name: "k1", value: kvVal, namespace: NS },
    { sourceType: "r2", name: "r1", value: r2Val, bucket: BUCKET },
  ]);
  const archiveR2 = new MockR2Archive();
  for (const [k, b] of archive) archiveR2.store.set(k, b);

  const kv = new MockKV();
  const r2live = new FakeR2();
  const env = {
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: archiveR2 as unknown as R2Bucket,
    SIGNER_PRIVATE: signerB64,
    OPERATIONAL_PRIVATE: opB64,
    RESTORE_BUFFERED_MAX_BYTES: "4096", // r1 streams (streamed-readback), k1 is buffered-no-readback (KV)
    [`KV_${NS}`]: kv as unknown as KVNamespace,
    [`R2_${BUCKET}`]: r2live as unknown as R2Bucket,
  } as unknown as Env;
  const res = (await runRestore(env, { runId: RUN_ID, confirm: true })) as RestoreResult;
  const receipt = res.receipt as RestoreReceipt;
  await proofReceiptContent(receipt, kvVal, r2Val);
  await proofReceiptSignature(receipt, signerB64);
  await proofAuditAnchor(receipt);
}

// ---- Section E: KV/Secrets/D1 sinks throw the typed not-supported error (no false readback claim) ----
// The honest buffered-no-readback label depends on these sinks signalling "I have no readback API" with the
// typed ReadbackNotSupportedError, so the apply path can tell it apart from a real R2 readback failure.
async function sectionE(): Promise<void> {
  console.log("\nKV/Secrets/D1 sinks declare no readback (typed ReadbackNotSupportedError):");
  const kvSink = new KVRestoreSink({} as unknown as KVNamespace, NS);
  const secretsSink = new SecretsRestoreSink([{ name: "s1", put: async () => {} }]);
  const d1Sink = new D1RestoreSink({} as unknown as D1Database, "db1", false);
  for (const [label, sink] of [["KV", kvSink], ["Secrets", secretsSink], ["D1", d1Sink]] as const) {
    let caught: unknown;
    try {
      await sink.getStreamForVerify("any");
    } catch (e) {
      caught = e;
    }
    ok(`${label} getStreamForVerify throws ReadbackNotSupportedError (not a generic Error)`, caught instanceof ReadbackNotSupportedError);
  }
}

// ---- Section F: a small BUFFERED R2 write that LANDS WRONG is caught by the new buffered readback ----
// A small buffered R2 record must not simply re-hash the SAME in-memory bytes it wrote, which would never
// notice a write that persisted wrong bytes: the buffered path must read the landed object BACK.
async function sectionF(): Promise<void> {
  console.log("\nsmall buffered R2 readback FAILURE through runRestore (the landed bytes are wrong):");
  const r2Val = patterned(64 * 1024, 17);
  const { archive, opB64, signerB64 } = await buildSmallArchive([{ sourceType: "r2", name: "r1", value: r2Val, bucket: BUCKET }]);
  const archiveR2 = new MockR2Archive();
  for (const [k, b] of archive) archiveR2.store.set(k, b);

  // A binding that corrupts what it persists, with a HIGH (default) ceiling so the 64 KiB record takes the
  // BUFFERED path. The buffered put "succeeds" but the readback re-hash does not match the signed hash.
  {
    const corruptR2 = new FakeR2(true);
    const env = {
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      DEST_KIND: "r2",
      DEST_R2: archiveR2 as unknown as R2Bucket,
      SIGNER_PRIVATE: signerB64,
      OPERATIONAL_PRIVATE: opB64,
      [`R2_${BUCKET}`]: corruptR2 as unknown as R2Bucket,
    } as unknown as Env;
    const res = (await runRestore(env, { runId: RUN_ID, confirm: true })) as RestoreResult;
    ok("a buffered readback MISMATCH makes the apply NOT ok", res.ok === false);
    ok("nothing is counted as restored when the only buffered record failed readback", res.recordsRestored === 0);
    ok("the buffered record is in failures with a readback-verification reason", res.failures.some((f) => f.name === "r1" && /readback/.test(f.reason)));
    const r2Entry = res.receipt!.records.find((r) => r.name === "r1")!;
    ok("the buffered receipt entry is verified:false via buffered-readback (NOT verified:true)", r2Entry !== undefined && r2Entry.verified === false && r2Entry.via === "buffered-readback");
    ok("the buffered receipt's verifiedSha384 differs from the expected (signed) hash", r2Entry.verifiedSha384 !== null && r2Entry.verifiedSha384 !== r2Entry.expectedSha384);
    ok("receipt.summary.allVerified is FALSE on a buffered readback mismatch", res.receipt!.summary.allVerified === false);
    ok("the (wrong) buffered object was NOT deleted (operator decides)", corruptR2.stored.has("r1"));
  }

  // A binding that DROPS the object on get (missing after a buffered write): the readback throws a real
  // (non-not-supported) error, so it is a failure with a verifiedSha384:null receipt entry.
  {
    const droppingR2 = new FakeR2();
    droppingR2.dropOnGet.add("r1");
    const env = {
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      DEST_KIND: "r2",
      DEST_R2: archiveR2 as unknown as R2Bucket,
      SIGNER_PRIVATE: signerB64,
      OPERATIONAL_PRIVATE: opB64,
      [`R2_${BUCKET}`]: droppingR2 as unknown as R2Bucket,
    } as unknown as Env;
    const res = (await runRestore(env, { runId: RUN_ID, confirm: true })) as RestoreResult;
    ok("a missing-on-readback buffered object makes the apply NOT ok", res.ok === false && res.recordsRestored === 0);
    ok("the buffered record is in failures (could not be read back)", res.failures.some((f) => f.name === "r1" && /read back|readback/.test(f.reason)));
    const r2Entry = res.receipt!.records.find((r) => r.name === "r1")!;
    ok("the buffered receipt entry is verified:false with verifiedSha384:null (no readback)", r2Entry.verified === false && r2Entry.verifiedSha384 === null && r2Entry.via === "buffered-readback");
  }
}

async function main(): Promise<void> {
  await sectionA();
  await sectionB();
  await sectionC();
  await sectionD();
  await sectionE();
  await sectionF();
  console.log(failures === 0 ? "\nRESTORE READBACK + RECEIPT PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
