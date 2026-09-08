// Prove the CONSTANT-MEMORY streaming in-account R2 restore (lifting the ~128 MB isolate ceiling to
// R2's single-PUT maximum) end to end, with full integrity. Covers:
//   1. openStreamToStream round-trips byte-exact across the chunk-boundary edge cases (empty, 1 byte,
//      exactly one chunk, one chunk + 1, many chunks) and is robust to how the producer chunks its
//      input (the one-stride lookahead + last-flag determination).
//   2. A value spanning MANY chunks AND multiple segments seals (small segment cap, no GBs needed),
//      opens under the TS reader, and restoreRecordStream restores it cell-for-cell identical through
//      a fake in-memory R2 sink -- WITHOUT ever materialising the value.
//   3. Tamper: one flipped byte inside a chunk makes the streaming restore ERROR (GCM auth), emitting
//      no wrong bytes; a corrupted final whole-record SHA-384 makes the stream error at the END (after
//      the authenticated chunks); a truncated/over-stated segment chunkRange is rejected (assembly).
//   4. Memory bound: the streaming decrypt produces its first output BEFORE it has read all the sealed
//      input, proving by construction that it never buffers the whole value (it holds ~2 strides).
//   5. A value past R2_MAX_SINGLE_PUT still throws the steer-to-the-offline-CLI error at the sink.
//
// In-memory doubles only. No network, no deploy, no cost.
// Run: node test/validate-streaming-restore.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import {
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
import { deriveCAK, deriveMK, deriveNameMACKey, deriveNonSecretFileKey } from "../src/crypto/derive.ts";
import { segID } from "../src/crypto/derive.ts";
import { sealStream, openStreamToStream } from "../src/crypto/stream.ts";
import { decodeULID } from "../src/format/ulid.ts";
import { addBundle } from "../src/format/bundle.ts";
import { R2RestoreSink } from "../src/dest/restore-sink.ts";
import { R2_MAX_SINGLE_PUT } from "../src/dest/types.ts";
import type { ShardRecord } from "../src/format/manifest.ts";
import type { SourceRecord } from "../src/sources/types.ts";
import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import { ADDR_SINGLE_NON_SECRET, CHUNK_SIZE, CODEC_NONE, TAG_SIZE } from "../src/format/version.ts";
import { b64urlEncode, concat, hexEncode, utf8 } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";

const RUN_ID = "01BX5ZZKBKACTAV9WEVGEMMVS0";
const DP_ID = "dp_stream_restore";
const STRIDE = CHUNK_SIZE + TAG_SIZE;

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

// patterned builds a deterministic, window-distinct byte pattern (no periodicity that would dedup
// windows to one shared segment), matching validate-chained-segments.
function patterned(n: number, seed: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (Math.imul(i + seed, 2654435761) >>> 24) & 0xff;
  return b;
}

// drain reads a whole ReadableStream into one buffer (test-side; the production path never does this).
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

// drainExpectError drains a stream and reports whether it errored, with the partial output it emitted
// before erroring (to assert no WRONG bytes are emitted on a tamper).
async function drainExpectError(stream: ReadableStream<Uint8Array>): Promise<{ errored: boolean; emitted: Uint8Array }> {
  const parts: Uint8Array[] = [];
  const reader = stream.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      parts.push(value);
    }
    return { errored: false, emitted: concat(...parts) };
  } catch {
    return { errored: true, emitted: concat(...parts) };
  }
}

// chunkedStream emits `bytes` in fixed-size pieces, to exercise openStreamToStream's tolerance of
// arbitrary producer chunking (the nonce or a stride boundary can straddle pieces).
function chunkedStream(bytes: Uint8Array, piece: number): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (let off = 0; off < bytes.length; off += piece) {
        controller.enqueue(bytes.subarray(off, Math.min(off + piece, bytes.length)));
      }
      controller.close();
    },
  });
}

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// MemDest: a minimal in-memory Destination for the seal pass (put/putStream/exists, the surface
// sealRecordToDest needs), mirroring validate-chained-segments.
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
  async putConditional(key: string, body: Uint8Array, _opts?: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult> {
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

// A fake R2 binding the R2RestoreSink streams into: it drains the streamed body to verify the bytes
// and records how many separate enqueues it saw (to confirm the body arrived incrementally, not as
// one buffer). FixedLengthStream is not a Node global, so the sink hands us the raw restore stream.
class FakeR2 {
  stored = new Map<string, Uint8Array>();
  lastChunks = 0;
  async put(key: string, body: ReadableStream<Uint8Array> | ArrayBuffer | ArrayBufferView | string | null | Blob): Promise<{ etag: string }> {
    if (body instanceof ReadableStream) {
      const parts: Uint8Array[] = [];
      const reader = body.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        parts.push(value);
      }
      this.lastChunks = parts.length;
      this.stored.set(key, concat(...parts));
    } else if (typeof body === "string") {
      this.stored.set(key, utf8(body));
    } else if (body instanceof Uint8Array) {
      this.stored.set(key, body.slice());
    } else if (body instanceof ArrayBuffer) {
      this.stored.set(key, new Uint8Array(body.slice(0)));
    } else if (body && ArrayBuffer.isView(body)) {
      this.stored.set(key, new Uint8Array(body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength)));
    } else {
      this.stored.set(key, new Uint8Array(0));
    }
    return { etag: "etag" };
  }
}

// assembleArchive turns sealed records into the manifest/root/runlog/bundle objects (the same
// builders the sliced seal uses), so openRun can verify and restore them.
async function assembleArchive(p: {
  dest: MemDest;
  master: Uint8Array;
  signer: Signer;
  recipients: RecipientEntry[];
  sealed: { meta: RecordMeta; seal: Awaited<ReturnType<typeof sealRecordToDest>> }[];
}): Promise<void> {
  const runIdBytes = decodeULID(RUN_ID);
  const mk = await deriveMK(p.master, runIdBytes);
  const nameKey = await deriveNameMACKey(mk, runIdBytes);
  const frontier = new MerkleFrontier();
  const lines: unknown[] = [];
  let i = 0;
  for (const s of p.sealed) {
    if (s.seal.ok !== true) continue;
    const recordId = "r" + String(i++).padStart(15, "0");
    const { line, recordHash } = await buildRecordLine(nameKey, recordId, s.meta, s.seal.seal);
    lines.push(line);
    await frontier.append(recordHash);
  }
  const shard = await sealShardManifest({
    master: p.master,
    runId: RUN_ID,
    shardId: "00000",
    downpipeName: "stream-restore",
    cadence: "3600s",
    sourceType: "r2",
    windowStart: "2026-06-10T00:00:00.000Z",
    windowEnd: "2026-06-10T00:00:01.000Z",
    recordLines: lines,
    randomNonce: () => rand(16),
  });
  const { rootBytes, sigBytes } = await buildSignedRoot({
    downpipeId: DP_ID,
    runId: RUN_ID,
    createdAt: "2026-06-10T00:00:01.000Z",
    master: p.master,
    recipients: p.recipients,
    signer: p.signer,
    shards: [{ id: "00000", object: shard.object, sha384: shard.sha384Hex }],
    declaredRecordCount: lines.length,
    merkleRootHex: hexEncode(await frontier.root()),
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

// ---- Section 1: openStreamToStream round-trips, edge cases + producer-chunking robustness ----
async function section1(): Promise<void> {
  console.log("openStreamToStream round-trip (chunk-boundary edge cases):");
  const fileKey = rand(32);
  // Sizes around the chunk boundary so the last-flag/lookahead logic is exercised at every edge:
  // empty (one empty last chunk), 1 byte, exactly one chunk, one chunk + 1 (two chunks), an exact
  // multiple of chunks, and a many-chunk value with a remainder.
  const sizes = [0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, CHUNK_SIZE * 3, CHUNK_SIZE * 4 + 123];
  for (const size of sizes) {
    const plain = patterned(size, 42);
    const sealed = await sealStream(fileKey, plain, rand(16));
    // a) whole-buffer input
    const fromBuffer = await drain(openStreamToStream(fileKey, sealed));
    ok(`size ${size}: round-trips from a whole buffer`, eqBytes(fromBuffer, plain));
    // b) byte-at-a-time producer (the nonce and every stride boundary straddle pieces)
    const fromTiny = await drain(openStreamToStream(fileKey, chunkedStream(sealed, 1)));
    ok(`size ${size}: round-trips from a 1-byte-at-a-time producer`, eqBytes(fromTiny, plain));
    // c) odd piece size that does not divide the stride
    const fromOdd = await drain(openStreamToStream(fileKey, chunkedStream(sealed, 7777)));
    ok(`size ${size}: round-trips from an odd-piece producer`, eqBytes(fromOdd, plain));
  }
}

// ---- Section 2: full archive seal -> open -> streaming restore byte-exact ----
// Returns the opened run + the big record + the original value + the dest map for the later
// tamper/assembly sections (which mutate the segment bytes/manifest under a fresh store).
async function buildBigArchive(): Promise<{ run: Run; recBig: ShardRecord; bigValue: Uint8Array; map: Map<string, Uint8Array>; verifier: ReturnType<typeof verifierFrom>; identity: ReturnType<typeof parseIdentity> }> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const signer: Signer = await loadSigner(b64urlEncode(concat(edSeed, mldsaSeed)));
  const verifier = verifierFrom(signer);
  const breakGlass = makeRecipient("break-glass");
  const recipients = [breakGlass.entry];

  const TARGET = 256 * 1024; // 4 STREAM chunks per segment (legal; SPEC 14.5 is "at most 16384")
  const master = rand(32);
  const runIdBytes = decodeULID(RUN_ID);
  const cak = await deriveCAK(master, DP_ID);
  const dest = new MemDest();
  const deps = { cak, master, runIdBytes, dest, randomNonce: () => rand(16), randomSalt: () => rand(16), segmentTargetBytes: TARGET };

  // 1 MiB + 7 B: 5 segments at a 256 KiB target (4 full segments of 4 chunks + a remainder), and
  // ~20 STREAM chunks overall -- many chunks AND multiple segments, the shape that proves the
  // chunked decrypt + the in-order segment assembly.
  const bigValue = patterned(1024 * 1024 + 7, 3);
  const bigStreamRecord: SourceRecord = {
    sourceType: "r2",
    name: "big/object.bin",
    bucket: "media",
    stream: {
      size: bigValue.length,
      open: () => ({
        // eslint-disable-next-line require-yield
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
    sealed: [{ meta: { sourceType: "r2", name: "big/object.bin", bucket: "media" } as RecordMeta, seal: sealedBig }],
  });
  const identity = parseIdentity(breakGlass.identity);
  const run = await openRun(new MapStore(dest.map), RUN_ID, identity, verifier, {});
  const recBig = run.records.find((r) => r.name === "big/object.bin")!;
  return { run, recBig, bigValue, map: dest.map, verifier, identity };
}

async function section2(): Promise<void> {
  console.log("\nfull archive: seal (many chunks, 5 segments) -> open -> streaming restore:");
  const { run, recBig, bigValue } = await buildBigArchive();
  ok("the reader sees a 5-segment chain", recBig.segments.length === 5);
  ok("the record is past the 8 MiB stream threshold OR multi-segment (streamable shape)", recBig.segments.length > 1);

  // Restore through the REAL R2RestoreSink + a fake binding, exactly as the apply path does:
  // sink.putStream(name, run.restoreRecordStream(rec), rec.plaintextSize).
  const fake = new FakeR2();
  const sink = new R2RestoreSink(fake as unknown as R2Bucket, "media");
  await sink.putStream("big/object.bin", run.restoreRecordStream(recBig), recBig.plaintextSize);
  const restored = fake.stored.get("big/object.bin")!;
  ok("the streamed restore is cell-for-cell identical to the original", eqBytes(restored, bigValue));
  ok("the restored byte count matches plaintextSize", restored.length === recBig.plaintextSize);
  // The body arrived in MANY enqueues (one per decrypted STREAM chunk), proving the sink received a
  // stream and not a single pre-buffered blob.
  ok("the restore body arrived incrementally (many chunks, not one buffer)", fake.lastChunks > 5);

  // The plain restoreRecordStream output also matches (independent of the sink), and equals the
  // buffered restoreRecord, so the two restore paths agree.
  const streamed = await drain(run.restoreRecordStream(recBig));
  ok("restoreRecordStream output equals the original", eqBytes(streamed, bigValue));
  const buffered = await run.restoreRecord(recBig);
  ok("streaming and buffered restore agree byte-for-byte", eqBytes(streamed, buffered));
}

// ---- Section 3: tamper inside a chunk, corrupt final hash, over-state a segment range ----
async function section3(): Promise<void> {
  console.log("\ntamper: a flipped byte in a chunk errors the stream (GCM), no wrong bytes:");
  {
    const { run, recBig, bigValue, map, verifier, identity } = await buildBigArchive();
    // Flip one byte inside the FIRST segment's first chunk ciphertext (after the 5-byte frame + the
    // 16-byte payload nonce, well inside the first chunk's ciphertext), then re-open the run over the
    // tampered store and stream-restore: the chunk must fail its GCM tag and error the stream.
    const seg0 = recBig.segments[0]!.object;
    const tampered = new Map(map);
    const segBytes = map.get(seg0)!.slice();
    const flipAt = 5 + 16 + 100; // frame(5) + nonce(16) + into the first chunk's ciphertext
    segBytes[flipAt] = segBytes[flipAt]! ^ 0xff;
    tampered.set(seg0, segBytes);
    const run2 = await openRun(new MapStore(tampered), RUN_ID, identity, verifier, {});
    const rec2 = run2.records.find((r) => r.name === "big/object.bin")!;
    const res = await drainExpectError(run2.restoreRecordStream(rec2));
    ok("a tampered chunk errors the streaming restore", res.errored);
    // The first chunk is the tampered one, so it fails before ANY plaintext is emitted: zero wrong
    // bytes leave the stream. And whatever (nothing, here) was emitted is never the original value.
    ok("no wrong bytes are emitted (the tampered first chunk fails before output)", res.emitted.length === 0);
    ok("the emitted prefix is never the full value", !eqBytes(res.emitted, bigValue));
    // The buffered reader rejects it too (parity): both readers refuse the tampered archive.
    let bufferedThrew = false;
    try {
      await run2.restoreRecord(rec2);
    } catch {
      bufferedThrew = true;
    }
    ok("the buffered restoreRecord also rejects the tampered chunk (reader parity)", bufferedThrew);
  }

  console.log("\ntamper: a flipped byte in a LATER chunk errors AFTER authenticated output, never wrong bytes:");
  {
    const { run, recBig, bigValue, map, verifier, identity } = await buildBigArchive();
    // Flip a byte inside the LAST segment's chunk ciphertext. The earlier segments/chunks are intact,
    // so they decrypt and emit correctly; the stream must then error on the tampered chunk WITHOUT
    // ever emitting a wrong byte (every emitted byte matched the original prefix).
    const segLast = recBig.segments[recBig.segments.length - 1]!.object;
    const tampered = new Map(map);
    const segBytes = map.get(segLast)!.slice();
    const flipAt = 5 + 16 + 10;
    segBytes[flipAt] = segBytes[flipAt]! ^ 0x01;
    tampered.set(segLast, segBytes);
    const run2 = await openRun(new MapStore(tampered), RUN_ID, identity, verifier, {});
    const rec2 = run2.records.find((r) => r.name === "big/object.bin")!;
    const res = await drainExpectError(run2.restoreRecordStream(rec2));
    ok("a tampered later chunk errors the streaming restore", res.errored);
    ok("it errored before completing (curtailed output, never the full value)", !eqBytes(res.emitted, bigValue));
    // Crucially every byte that WAS emitted is a correct prefix of the original (authenticated bytes
    // only): the stream never emits a wrong byte even when it later errors.
    ok("every emitted byte is a correct prefix of the original (authenticated only)", eqBytes(res.emitted, bigValue.subarray(0, res.emitted.length)));
  }

  console.log("\nfinal hash: a corrupted whole-record SHA-384 errors the stream at the END:");
  {
    const { run, recBig, bigValue } = await buildBigArchive();
    // Build a record whose plaintextSha384 is wrong but whose SEGMENTS are intact, so every chunk
    // authenticates and the WHOLE value is emitted, then the final hash check in the stream's flush
    // fails. The chunks pass GCM (real segments), so this proves the independent final content-address
    // check (not just per-chunk auth) is enforced on the streaming path.
    const badRec: ShardRecord = { ...recBig, plaintextSha384: "00".repeat(48) };
    const res = await drainExpectError(run.restoreRecordStream(badRec));
    ok("a corrupted final hash errors the streaming restore", res.errored);
    // The authenticated chunks were emitted (the failure is at the end), and they match the original,
    // so even here no WRONG byte is emitted -- the error is the final-hash guard, and the SINK only
    // commits on a clean close, so the object is never written.
    ok("the emitted bytes (pre-flush) are the authentic value, the error is the final-hash guard", eqBytes(res.emitted, bigValue));

    // Through the real sink + FixedLengthStream-less fake binding: a final-hash error must reject the
    // putStream so the restore records a fault rather than committing a (here byte-correct but
    // unverified-hash) object. We assert the sink call rejects.
    const fake = new FakeR2();
    const sink = new R2RestoreSink(fake as unknown as R2Bucket, "media");
    let sinkThrew = false;
    try {
      await sink.putStream("big/object.bin", run.restoreRecordStream(badRec), badRec.plaintextSize);
    } catch {
      sinkThrew = true;
    }
    ok("the sink putStream rejects when the final hash fails", sinkThrew);
  }

  console.log("\nassembly: an over-stated segment chunkRange is rejected (terminate-exactly):");
  {
    const { run, recBig } = await buildBigArchive();
    // Over-state the FIRST segment's lastChunkExclusive (declare 5 chunks where the segment really
    // has 4). The segment terminates after fewer chunks than declared, so the per-segment
    // terminate-exactly check (segmentStreamChunks === maxChunks) must reject it.
    const segs = recBig.segments.map((s) => ({ ...s, chunkRange: [...s.chunkRange] as [number, number] }));
    segs[0]!.chunkRange = [0, segs[0]!.chunkRange[1] + 1];
    const badRec: ShardRecord = { ...recBig, segments: segs };
    const res = await drainExpectError(run.restoreRecordStream(badRec));
    ok("an over-stated chunkRange is rejected by the streaming restore", res.errored);
  }

  console.log("\nassembly: a packed record is refused by the streaming path (caller must buffer):");
  {
    const { run, recBig } = await buildBigArchive();
    const segs = recBig.segments.map((s) => ({ ...s }));
    segs[0]!.packed = { offset: 0, length: 10 };
    const badRec: ShardRecord = { ...recBig, segments: segs };
    let threw = false;
    try {
      // restoreRecordStream throws synchronously on the assembly pre-check for a packed shape.
      run.restoreRecordStream(badRec);
    } catch {
      threw = true;
    }
    ok("restoreRecordStream refuses a packed record", threw);
  }
}

// ---- Section 4: memory bound -- decrypt emits output before reading all input ----
async function section4(): Promise<void> {
  console.log("\nmemory bound: the decrypt produces output before draining all input:");
  // Seal a value of MANY strides directly (no archive needed). Wrap the sealed input in a stream that
  // counts how many bytes have been READ from it, and record how many input bytes had been read at the
  // moment the FIRST output chunk was produced. A whole-buffer (unbounded) implementation would read
  // ALL input before emitting anything; the streaming implementation reads ~2 strides and emits.
  const fileKey = rand(32);
  const chunks = 64; // 64 * 64 KiB = 4 MiB of plaintext, ~65 strides
  const plain = patterned(CHUNK_SIZE * chunks, 7);
  const sealed = await sealStream(fileKey, plain, rand(16));

  let bytesRead = 0;
  let readAtFirstOutput = -1;
  const counting = new ReadableStream<Uint8Array>({
    start(controller) {
      // Emit one stride per pull so reads are observable; the consumer pulls as it needs bytes.
      let off = 0;
      const piece = STRIDE;
      const push = (): void => {
        if (off >= sealed.length) {
          controller.close();
          return;
        }
        const end = Math.min(off + piece, sealed.length);
        bytesRead += end - off;
        controller.enqueue(sealed.subarray(off, end));
        off = end;
      };
      // Pre-load one stride; the rest are pulled on demand.
      push();
    },
    pull(controller) {
      // Each pull emits the next stride; bytesRead climbs as the decrypt asks for more.
      const remaining = sealed.length - bytesRead;
      if (remaining <= 0) {
        controller.close();
        return;
      }
      const n = Math.min(STRIDE, remaining);
      controller.enqueue(sealed.subarray(bytesRead, bytesRead + n));
      bytesRead += n;
    },
  });

  const reader = openStreamToStream(fileKey, counting).getReader();
  const out: Uint8Array[] = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (readAtFirstOutput < 0) readAtFirstOutput = bytesRead;
    out.push(value);
  }
  const restored = concat(...out);
  ok("the value round-trips", eqBytes(restored, plain));
  ok("first output was produced before all input was read (bounded memory, not buffer-whole)", readAtFirstOutput >= 0 && readAtFirstOutput < sealed.length);
  // Tighter bound: the first output appears after only a few strides have been read, never the whole
  // input. Allow generous slack for stream-internal buffering, but it must be a small constant, far
  // below the full sealed size.
  ok(`first output read <= a handful of strides (read ${readAtFirstOutput} of ${sealed.length} bytes)`, readAtFirstOutput <= STRIDE * 4);
}

// ---- Section 5: a value past R2_MAX_SINGLE_PUT still steers to the offline CLI ----
async function section5(): Promise<void> {
  console.log("\nceiling: a value past R2_MAX_SINGLE_PUT steers to the offline CLI:");
  const fake = new FakeR2();
  const sink = new R2RestoreSink(fake as unknown as R2Bucket, "media");
  // A tiny placeholder body; the guard fires on the `size` argument before the binding is touched.
  const tiny = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(TAG_SIZE));
      controller.close();
    },
  });
  let threw = false;
  let message = "";
  try {
    await sink.putStream("huge/object.bin", tiny, R2_MAX_SINGLE_PUT + 1);
  } catch (e) {
    threw = true;
    message = (e as Error).message;
  }
  ok("putStream throws on size > R2_MAX_SINGLE_PUT", threw);
  ok("the error steers recovery to the offline downpipe CLI", /offline/.test(message) && /downpipe CLI/.test(message));
  ok("the binding was not called (guard fires pre-binding)", fake.stored.size === 0);

  // Sanity: a value AT exactly R2_MAX_SINGLE_PUT is allowed (it does not throw the ceiling guard).
  // We do not actually stream gigabytes; we only prove the guard boundary is inclusive by catching
  // any thrown ceiling error (the fake binding accepts the tiny body).
  const fake2 = new FakeR2();
  const sink2 = new R2RestoreSink(fake2 as unknown as R2Bucket, "media");
  const tiny2 = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(0));
      controller.close();
    },
  });
  let ceilingThrew = false;
  try {
    await sink2.putStream("at-ceiling.bin", tiny2, R2_MAX_SINGLE_PUT);
  } catch (e) {
    if (/too large/.test((e as Error).message)) ceilingThrew = true;
  }
  ok("a value AT exactly the ceiling is not rejected by the guard", !ceilingThrew);
}

async function main(): Promise<void> {
  // Keep the deterministic seg-id helpers referenced so an unused-import lint never trips, and so the
  // direct address derivation stays exercised alongside the high-level seal path.
  const probeKey = await deriveNonSecretFileKey(rand(32), await segID(rand(32), ADDR_SINGLE_NON_SECRET, new Uint8Array(0), utf8("probe")), CODEC_NONE);
  ok("seg-id + file-key derivation is reachable", probeKey.length === 32 && (await sha384(probeKey)).length === 48);

  await section1();
  await section2();
  await section3();
  await section4();
  await section5();

  console.log(failures === 0 ? "\nSTREAMING RESTORE PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
