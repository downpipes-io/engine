// Reader-parity for the per-segment chunkRange gate. The TS reader
// (src/format/reader.ts) must enforce each segment's signed chunkRange exactly as the Go
// reference reader (internal/format/reader.go openSegment/segmentChunkBound) does, or the
// in-account drill/canary/restore reader verifies LESS than the offline reader, a
// reader-parity break in the core integrity story.
//
// This is the byte-for-byte TS analogue of the Go suite's
// TestRestoreRecordBoundsSegmentByChunkRange (downpipe/internal/format/reader_test.go): it
// builds a real archive whose one record spans two STREAM chunks (the true whole-segment
// chunkRange is [0, 2)), opens it under the TS reader, then mutates ONLY the manifest's
// declared chunkRange on the returned record (the stored bytes are untouched) and asserts
// the reader's restoreRecord:
//   - restores under the true range [0, 2)                              (positive control)
//   - REJECTS an under-declared range [0, 1) (the read is bounded, the 2nd chunk refused)
//   - REJECTS an over-declared range [0, 5) (the segment terminates after 2 chunks)
//   - REJECTS firstChunk != 0 ([1, 2)), an empty range [0, 0), and a range over the
//     16384-chunk per-segment ceiling
// Each rejected case is exactly the case the Go reader rejects, so a `downpipe verify` of
// the same mutation would agree: the two readers apply the identical segmentChunkBound and
// exact-termination checks. Run: node test/validate-reader-chunkrange.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { CHUNK_SIZE, MAX_SEGMENT_CHUNKS } from "../src/format/version.ts";
import type { HybridVerifier } from "../src/crypto/sign.ts";
import type { ShardRecord } from "../src/format/manifest.ts";

const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const DP_ID = "dp_chunkrange";

// DeepMutable drops readonly recursively (through nested objects, arrays and tuples). ShardRecord and
// its Segment are shipped readonly so the production write path assembles them only through Mutable<T>
// locals; this test, by contrast, copies a real record and mutates ONLY the manifest's declared
// chunkRange to drive the per-segment bound controls. withChunkRange returns DeepMutable<ShardRecord>
// so that one mutation type-checks without loosening the shipped readonly shape; the result is still
// assignable wherever the readonly ShardRecord is wanted (restoreRecord).
type DeepMutable<T> = T extends readonly unknown[]
  ? { -readonly [K in keyof T]: DeepMutable<T[K]> }
  : T extends object
    ? { -readonly [K in keyof T]: DeepMutable<T[K]> }
    : T;

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

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
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

// A deep-enough copy that mutating the segment's chunkRange does not touch the original
// record (mirrors the Go withChunkRange helper, which copies the segments slice).
function withChunkRange(rec: ShardRecord, cr: [number, number]): DeepMutable<ShardRecord> {
  const cp: DeepMutable<ShardRecord> = { ...rec, segments: rec.segments.map((s) => ({ ...s })) };
  cp.segments[0]!.chunkRange = cr;
  return cp;
}

// restoreThrows reports whether restoreRecord rejects the record (a thrown error). The
// rejection class is the same structural-error path the reader already uses for its other
// verification failures; the parity claim is about accept-vs-reject, not the message text.
async function restoreThrows(run: Awaited<ReturnType<typeof openRun>>, rec: ShardRecord): Promise<boolean> {
  try {
    await run.restoreRecord(rec);
    return false;
  } catch {
    return true;
  }
}

async function main(): Promise<void> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const signer: Signer = await loadSigner(b64urlEncode(concat(edSeed, mldsaSeed)));
  const verifier: HybridVerifier = verifierFrom(signer);
  const breakGlass = makeRecipient("break-glass");
  const recipients = [breakGlass.entry];

  // CHUNK_SIZE+1 bytes seal into two STREAM chunks (one full chunk plus a 1-byte
  // remainder), so the true whole-segment chunkRange is [0, 2), exactly the Go fixture.
  const value = new Uint8Array(CHUNK_SIZE + 1).fill(0x41);
  const objects = await buildArchive({
    downpipeId: DP_ID,
    downpipeName: "chunkrange",
    cadence: "3600s",
    runId: RUN_ID,
    master: rand(32),
    recipients,
    signer,
    records: [{ sourceType: "kv", name: "two-chunk", namespace: "ns", value }],
    windowStart: "2026-06-10T00:00:00.000Z",
    windowEnd: "2026-06-10T00:00:01.000Z",
    createdAt: "2026-06-10T00:00:01.000Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });

  const store = new MapStore(objects);
  const identity = parseIdentity(breakGlass.identity);
  const run = await openRun(store, RUN_ID, identity, verifier, {});
  const rec = run.records.find((r) => r.name === "two-chunk")!;
  ok("the fixture record opens", !!rec);
  ok("the fixture spans two STREAM chunks (true chunkRange is [0,2))", rec.segments.length === 1 && rec.segments[0]!.chunkRange[0] === 0 && rec.segments[0]!.chunkRange[1] === 2);

  // Positive control: the true range [0, 2) restores the value byte-exact.
  {
    const restored = await run.restoreRecord(withChunkRange(rec, [0, 2]));
    ok("the true chunkRange [0,2) restores byte-exact", eqBytes(restored, value));
  }

  // (a) firstChunk != 0: a sub-segment offset is not a shape this major emits (Go rejects).
  ok("rejects firstChunk != 0 ([1,2))", await restoreThrows(run, withChunkRange(rec, [1, 2])));

  // (b) lastChunkExclusive over the per-segment ceiling (Go rejects at segmentChunkBound).
  ok(`rejects lastChunkExclusive over the ${MAX_SEGMENT_CHUNKS}-chunk ceiling`, await restoreThrows(run, withChunkRange(rec, [0, MAX_SEGMENT_CHUNKS + 1])));

  // (c) a chunkRange that OVER-states the real chunk count: [0,5) declares 5 but the segment
  // terminates after 2 chunks (Go rejects at the exact-termination check).
  ok("rejects a chunkRange over-stating the chunk count ([0,5))", await restoreThrows(run, withChunkRange(rec, [0, 5])));

  // Extra parity cases the Go test also pins: an under-declared range cannot read past its
  // bound, and an empty range is rejected.
  ok("rejects an under-declared range that cannot read its 2nd chunk ([0,1))", await restoreThrows(run, withChunkRange(rec, [0, 1])));
  ok("rejects an empty range ([0,0))", await restoreThrows(run, withChunkRange(rec, [0, 0])));

  // And, to make the parity explicit: the unmutated record still restores, so the gate only
  // ever rejects a manifest that disagrees with the sealed bytes, never a sound archive.
  {
    const restored = await run.restoreRecord(rec);
    ok("the unmutated (sound) record still restores: the gate rejects only disagreeing ranges", eqBytes(restored, value));
  }

  console.log(failures === 0 ? "\nREADER CHUNKRANGE PARITY PASS (the TS reader enforces chunkRange like the Go reader)" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
