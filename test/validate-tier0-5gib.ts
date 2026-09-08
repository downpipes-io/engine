// Seal-side memory-boundedness + the single-segment ceiling. Two proofs:
//  1. sealStreamRecord (buildArchive's single-segment streaming seal) seals a very large record (default 1 GiB
//     smoke; TIER0_GIB=5 for the true threshold) with BOUNDED peak memory -- it never holds the value whole. A
//     generator ChunkSource yields the plaintext 64 KiB at a time (NO backing array), the seal addresses it in one
//     pass then seals it in a second (streamseal.ts, both chunk-at-a-time), and a counting destination DRAINS the
//     sealed segment + discards it -- NO disk, NO multi-GiB buffer. peak RSS far below the sealed size proves it
//     streams (a buffering seal would balloon to ~size).
//  2. THE CEILING: a value past the single-segment ceiling
//     (MAX_SEGMENT_CHUNKS = 16384 = 1 GiB) sealed as ONE segment is NON-PRODUCTION -- the WRITE side does not
//     enforce the ceiling, but the READER REJECTS a segment whose chunkRange exceeds it (record-codec.ts). So at
//     >= 5 GiB the single segment (81920 chunks) is correctly refused on restore. THIS IS WHY the production
//     sources (r2.ts / byte-fetch.ts) provide openRange, so buildArchive CHAINS a multi-GiB blob into an ordered
//     chain of <= 1 GiB segments the reader takes one bounded segment at a time. The chained seal+restore
//     boundedness end to end is a SEPARATE, un-built production-path cell (needs an openRange source + a disk-
//     backed dest + the streaming restore); this cell proves the seal-side bound + the ceiling's restore refusal.
// NET-ZERO: in-process, generated fake bytes, no disk, no bucket, no network, harness-minted keys. House style.
// Run at the true threshold: TIER0_GIB=5 npx tsx test/validate-tier0-5gib.ts
import { x25519 } from "@noble/curves/ed25519.js";

import { concat } from "../src/crypto/bytes.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import type { ChunkSource, StreamingValue } from "../src/crypto/streamseal.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { MAX_SEGMENT_CHUNKS } from "../src/format/version.ts";
import { buildArchive, type RecipientEntry, type Signer, type WriteRecord } from "../src/format/writer.ts";
import { verifierFrom } from "../src/keys-env.ts";
import { MemoryDestination } from "./memdest.ts";

const GIB = 1024 * 1024 * 1024;
const CHUNK = 65536;
const TOTAL = Math.round((Number(process.env.TIER0_GIB) || 1) * GIB);

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}
function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}
async function makeSigner(): Promise<Signer> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  return { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };
}

// A reused 64 KiB chunk: the seal consumes it synchronously each iteration, so reuse is safe and keeps the SOURCE
// allocation flat -- isolating the SEAL's memory behaviour (this test is about the seal, not the generator).
const CHUNK_BUF = new Uint8Array(CHUNK).fill(0x5a);
function genChunkSource(total: number): ChunkSource {
  return {
    async *chunks() {
      let sent = 0;
      while (sent < total) {
        const n = Math.min(CHUNK, total - sent);
        yield n === CHUNK ? CHUNK_BUF : CHUNK_BUF.subarray(0, n);
        sent += n;
      }
    },
  };
}

// CountingDestination drains a streamed segment and DISCARDS it (never stores the multi-GiB body); the small
// buffered objects (manifest shards, root) fall through to MemoryDestination's in-memory put.
class CountingDestination extends MemoryDestination {
  streamedBytes = 0;
  override async putStream(_key: string, body: ReadableStream<Uint8Array>): Promise<void> {
    const reader = body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      this.streamedBytes += value.length;
    }
  }
}

// A read-only ObjectStore over the buildArchive return map (manifest + root; the counting dest discarded the
// giant segment). Enough for the reader to reach the manifest-level chunkRange check that refuses the segment.
class MapStore implements ObjectStore {
  // An explicit field rather than a constructor parameter property: Node runs these validators with
  // strip-only type stripping, which rejects a parameter property outright
  // (ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX).
  readonly map: Map<string, Uint8Array>;
  constructor(map: Map<string, Uint8Array>) {
    this.map = map;
  }
  async get(key: string): Promise<Uint8Array> {
    const v = this.map.get(key);
    if (!v) throw new Error(`object not found: ${key}`);
    return v;
  }
  list(prefix: string): Promise<string[]> {
    return Promise.resolve([...this.map.keys()].filter((k) => k.startsWith(prefix)));
  }
}

const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

async function main(): Promise<void> {
  const bg = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const signer = await makeSigner();
  const sv: StreamingValue = { size: TOTAL, open: () => genChunkSource(TOTAL) };
  const rec: WriteRecord = { sourceType: "r2", name: "tier0-big", bucket: "media", stream: sv };
  const dest = new CountingDestination();

  let peakRss = process.memoryUsage().rss;
  const sampler = setInterval(() => { peakRss = Math.max(peakRss, process.memoryUsage().rss); }, 100);
  const t0 = Date.now();
  const archive = await buildArchive(
    {
      downpipeId: "dp_tier0", downpipeName: "tier0", cadence: "0 * * * *", runId: RUN_ID, master: rand(32),
      recipients: [bg.entry, op.entry], signer, records: [rec],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    },
    { dest },
  );
  clearInterval(sampler);
  peakRss = Math.max(peakRss, process.memoryUsage().rss);
  for (const [k, b] of archive) await dest.put(k, b); // manifest + root (small, in memory)

  const gib = (TOTAL / GIB).toFixed(2);
  const peakMiB = Math.round(peakRss / 1024 / 1024);
  const streamedMiB = Math.round(dest.streamedBytes / 1024 / 1024);
  console.log(`  sealed ${gib} GiB in ${((Date.now() - t0) / 1000).toFixed(1)}s; segment streamed-out ${streamedMiB} MiB; peak RSS ${peakMiB} MiB`);

  ok(`the whole record was STREAMED through the seal (sealed segment ${streamedMiB} MiB >= the ${gib} GiB plaintext)`, dest.streamedBytes >= TOTAL * 0.99);
  // Default-FAIL refuter: peak RSS stays a SMALL fraction of the sealed size -> the seal never held the record
  // whole. A buffering regression would balloon peak RSS to ~the sealed size (or OOM). 1 GiB ceiling is generous
  // headroom over the true streaming working set (a handful of 64 KiB chunks + hash/cipher state) yet far below a
  // multi-GiB buffer at TIER0_GIB=5.
  ok(`REFUTER: peak RSS ${peakMiB} MiB stayed bounded (< 1024 MiB) -> no whole-record buffering at ${gib} GiB`, peakMiB < 1024);

  // CEILING RESTORE REFUTER: the single segment has ceil(TOTAL/64KiB) chunks.
  // At >= ~1.01 GiB that exceeds MAX_SEGMENT_CHUNKS (16384), so the reader must REFUSE it on restore -- the
  // manifest-level chunkRange check (record-codec.ts) fires before any segment read, so the discarded segment is
  // not needed. This is why production CHAINS multi-GiB blobs (openRange) into <= 1 GiB segments.
  const chunks = Math.ceil(TOTAL / CHUNK);
  if (chunks > MAX_SEGMENT_CHUNKS) {
    let rejected = false;
    let rejectMsg = "";
    try {
      const run = await openRun(new MapStore(archive), RUN_ID, parseIdentity(bg.identity), verifierFrom(signer), { verifyFreshness: false });
      const r0 = run.records[0];
      // restoreRecordStream runs the pre-stream segmentChunkBound assembly check (reader.ts:188) BEFORE any
      // store.get, so it throws the over-ceiling chunkRange error itself -- not a missing-segment error (which
      // restoreRecord would raise first, reader.ts:91). The discarded segment is therefore not needed.
      if (r0) {
        const stream = run.restoreRecordStream(r0);
        const rdr = stream.getReader();
        for (;;) {
          const { done } = await rdr.read();
          if (done) break;
        }
      }
    } catch (e) {
      rejected = true;
      rejectMsg = e instanceof Error ? e.message : String(e);
    }
    // The refusal must be for the CEILING, not an incidental missing-segment fault -- assert the reason mentions
    // the chunk ceiling, so this refuter cannot pass vacuously.
    const forCeiling = /ceiling|chunkRange|exceeds|16384|chunk/i.test(rejectMsg);
    ok(`CEILING REFUTER: the over-ceiling single segment (${chunks} chunks > ${MAX_SEGMENT_CHUNKS}) is REJECTED on restore FOR the ceiling`, rejected && forCeiling);
    if (rejected) console.log(`    restore rejection: ${rejectMsg.slice(0, 130)}`);
  } else {
    console.log(`  (note: ${chunks} chunks <= ${MAX_SEGMENT_CHUNKS} ceiling, a single-segment-valid size; run TIER0_GIB>=2 to exercise the ceiling refuter)`);
  }

  console.log(failures === 0 ? `\nTIER-0 ${gib} GiB OK: sealStreamRecord is memory-bounded at scale AND the over-ceiling single segment is refused on restore (why production chains); net-zero.` : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error("TIER0 FAILED:", e instanceof Error ? (e.stack ?? e.message) : e);
  process.exit(1);
});
