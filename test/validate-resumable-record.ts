// Prove MID-RECORD RESUMABLE SEAL: a SINGLE streamed content value too large to seal in one slice
// is sealed across MULTIPLE slices, one window at a time, and the result is BYTE-IDENTICAL to sealing the
// same value in ONE shot. This is the load-bearing safety property: a wrong whole-record digest is an
// UNRECOVERABLE archive, so the test FAILS unless the multi-slice archive reproduces the one-shot's
// ordered segment object keys, record line (recordHash + plaintextSha384 + segments), and Merkle root,
// AND the TS reader opens the multi-slice archive and restores the record byte-exact.
//
// Then: CHANGE-DETECTION (the object's etag moves between slices -> the resume SKIPS the record, no corrupt
// line committed); PROGRESS (a value needing K slices completes in about K slices, >=1 new window each, no
// stall); and REGRESSION (a value that fits one slice still seals in one slice unchanged; a no-etag value
// never mid-record-yields). The BACKSTOP (an over-ceiling / no-etag-over-one-slice object skips with a
// marker) lives in validate-byte-fetch.ts; this file proves the resume itself.
// Run: node test/validate-resumable-record.ts

import { sha384 as nobleSha384 } from "@noble/hashes/sha2.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import type { RecipientEntry, Signer } from "../src/format/writer.ts";
import { runSlice, finaliseRun, type ShardEntry, type SliceDeps } from "../src/seal/slice.ts";
import { sealRecordToDest, type RecordSealDeps, type ResumeFrom } from "../src/seal/record.ts";
import { wrapMaster, unwrapMaster, zeroCounts, type RunCheckpoint } from "../src/seal/checkpoint.ts";
import { SliceBudget } from "../src/seal/budget.ts";
import { deriveCAK } from "../src/crypto/derive.ts";
import { decodeULID } from "../src/format/ulid.ts";
import type { StreamingValue, ChunkSource } from "../src/crypto/streamseal.ts";
import type { SourceAdapter, SourceRecord, Selector, CrawlEvent, Meter } from "../src/sources/types.ts";
import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import { b64urlEncode, concat, hexEncode } from "../src/crypto/bytes.ts";

const RUN_ID = "01BX5ZZKBKACTAV9WEVGEMMVR7";
const DP_ID = "dp_resumable";
const ALL: Selector = { include: [], exclude: [] };

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
// patterned: a deterministic byte pattern whose every window is distinct (a periodic pattern would dedup
// windows to one shared segment and confound the segment-key comparison).
function patterned(n: number, seed: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (Math.imul(i + seed, 2654435761) >>> 24) & 0xff;
  return b;
}
function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// MemDest: the full Destination contract over a map, with content-counter etags. range/streamed reads are
// not on this surface (this is the ARCHIVE sink); the source-side bytes are served by memStreamingValue.
class MemDest implements Destination {
  map = new Map<string, Uint8Array>();
  private tags = new Map<string, string>();
  private seq = 0;
  putStreams = 0;
  async get(key: string): Promise<GetResult | null> {
    const v = this.map.get(key);
    return v ? { body: v, etag: this.tags.get(key) ?? "e0" } : null;
  }
  async put(key: string, body: Uint8Array): Promise<void> {
    this.map.set(key, body);
    this.tags.set(key, `e${++this.seq}`);
  }
  async putStream(key: string, body: ReadableStream<Uint8Array>): Promise<void> {
    this.putStreams++;
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

// memStreamingValue presents an in-memory byte array as a StreamingValue with a stable etag, exactly the
// shape sources/byte-fetch.ts httpStreamingValue exposes: open() over the whole value, openRange() over a
// window (in BYTE-WINDOW pieces to exercise re-chunking), and openStreamedRange() over an extent (the
// prefix re-hash entry, one logical read). `holder.etag` and `holder.bytes` are mutable so a test can
// REPLACE the object between slices (the change-detection edge). reads is a per-extent read counter, so a
// test can assert a resume did not re-read the prefix windows it already sealed.
interface BlobHolder {
  etag: string;
  bytes: Uint8Array;
}
function memStreamingValue(holder: BlobHolder, opts?: { piece?: number; counters?: { ranged: number; streamed: number } }): StreamingValue {
  const piece = opts?.piece ?? 9_000; // uneven, so the re-chunker is exercised
  const counters = opts?.counters;
  const windowed = (start: number, total: number): ChunkSource => ({
    async *chunks(): AsyncIterable<Uint8Array> {
      if (counters) counters.ranged++;
      // Pin to the etag captured when the StreamingValue was built: a changed holder.etag means the object
      // was replaced underneath the seal, which the production source surfaces as a 412; here we throw the
      // same way so the seal treats it as changed-mid-crawl rather than yielding wrong bytes.
      if (holder.etag !== boundEtag) throw new Error("precondition failed (etag changed)");
      let off = start;
      const end = start + total;
      while (off < end) {
        const n = Math.min(piece, end - off);
        yield holder.bytes.subarray(off, off + n);
        off += n;
      }
    },
  });
  const streamed = (start: number, total: number): ChunkSource => ({
    async *chunks(): AsyncIterable<Uint8Array> {
      if (counters) counters.streamed++;
      if (holder.etag !== boundEtag) throw new Error("precondition failed (etag changed)");
      let off = start;
      const end = start + total;
      while (off < end) {
        const n = Math.min(piece, end - off);
        yield holder.bytes.subarray(off, off + n);
        off += n;
      }
    },
  });
  const boundEtag = holder.etag;
  return {
    size: holder.bytes.length,
    etag: boundEtag,
    open: () => windowed(0, holder.bytes.length),
    openRange: (offset, length) => windowed(offset, length),
    openStreamedRange: (offset, length) => streamed(offset, length),
  };
}

// OneRecordSource is a resumable source that yields EXACTLY ONE streamed record then a mark. It re-yields
// the SAME record whenever the crawl resumes from the null cursor (the partial record's cursor stays null
// because no mark precedes it), so the partial is always the FIRST re-yielded record on resume; once the
// mark is consumed (cursor "after") the crawl is exhausted. A fresh StreamingValue is built per crawl
// (every slice re-opens the object), all pinned to the holder's CURRENT etag, so a replaced object is seen.
class OneRecordSource implements SourceAdapter {
  readonly sourceType = "r2" as const;
  private holder: BlobHolder;
  private name: string;
  private counters: { ranged: number; streamed: number } | undefined;
  constructor(holder: BlobHolder, name: string, counters?: { ranged: number; streamed: number }) {
    this.holder = holder;
    this.name = name;
    this.counters = counters;
  }
  async *crawl(_selector: Selector, _meter?: Meter): AsyncIterable<SourceRecord> {
    yield this.record();
  }
  async *crawlFrom(_selector: Selector, token: string | null, _meter?: Meter): AsyncIterable<CrawlEvent> {
    if (token === "after") return; // exhausted
    yield { kind: "record", record: this.record() };
    yield { kind: "mark", token: "after" };
  }
  private record(): SourceRecord {
    return {
      sourceType: "r2",
      name: this.name,
      bucket: "media",
      stream: memStreamingValue(this.holder, { ...(this.counters ? { counters: this.counters } : {}) }),
    };
  }
  async estimate(): Promise<{ records: number; bytes: number }> {
    return { records: 1, bytes: this.holder.bytes.length };
  }
}

// sealRunToCompletion drives runSlice repeatedly (checkpoint round-tripped through JSON each time, the
// real eviction discipline) until the source is exhausted, then finalises. Returns the archive dest and
// how many slices it took. budget is rebuilt fresh each slice (a per-invocation budget). A guard caps the
// loop so a stall (a resume that never advances) fails the test loudly rather than hanging.
async function sealRunToCompletion(
  source: () => SourceAdapter,
  dest: MemDest,
  signer: Signer,
  recipients: RecipientEntry[],
  signerPrivateB64: string,
  budgetOpts: { subrequests: number; wallMs: number },
  segmentTargetBytes: number,
  master: Uint8Array, // the run master, held FIXED so a one-shot and a multi-slice run are comparable
  maxSlices = 200,
): Promise<{ slices: number; checkpoint: RunCheckpoint }> {
  // Wrap a COPY of the master: the caller holds the same master constant across two runs (one-shot and
  // multi-slice) to compare them, so this function must not zero it. From here every slice unwraps the
  // wrapped master from the (serialised) checkpoint, never the local copy.
  let cp: RunCheckpoint = {
    v: 1, downpipeId: DP_ID, downpipeName: "resumable", cadence: "3600s", sourceType: "r2",
    selector: ALL, runId: RUN_ID, runlogIndex: 1, prevRunId: null,
    startedAt: "2026-06-10T00:00:00.000Z", wrappedMaster: await wrapMaster(signerPrivateB64, RUN_ID, new Uint8Array(master)),
    cursor: null, sourceDone: false, nextRecordIndex: 0, nextShardIndex: 0,
    frontier: { count: 0, nodes: [] }, counts: zeroCounts(), sliceCount: 0, partialRecord: null,
  };
  const allShards: ShardEntry[] = [];
  let openBuffer: Record<string, unknown>[] = []; // carry the open-shard buffer across slices (models the DO's persisted batches)
  let slices = 0;
  for (; slices < maxSlices && !cp.sourceDone; slices++) {
    cp = JSON.parse(JSON.stringify(cp)) as RunCheckpoint; // eviction: only the serialised checkpoint survives
    const m = await unwrapMaster(signerPrivateB64, RUN_ID, cp.wrappedMaster);
    const deps: SliceDeps = { source: source(), dest, signer, recipients, budget: new SliceBudget(budgetOpts), segmentTargetBytes };
    const r = await runSlice(deps, cp, m, openBuffer);
    m.fill(0);
    cp = r.checkpoint;
    allShards.push(...r.newShards);
    openBuffer = r.openReset ? r.openWrite : [...openBuffer, ...r.openWrite];
  }
  if (!cp.sourceDone) throw new Error(`run did not complete within ${maxSlices} slices (a mid-record resume stalled)`);
  const m = await unwrapMaster(signerPrivateB64, RUN_ID, cp.wrappedMaster);
  await finaliseRun({ source: source(), dest, signer, recipients, budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) }, cp, m, allShards, openBuffer);
  m.fill(0);
  return { slices, checkpoint: cp };
}

function segKeys(dest: MemDest): string[] {
  return [...dest.map.keys()].filter((k) => k.startsWith("seg/")).sort();
}
function rootMerkleRoot(dest: MemDest): string {
  const raw = dest.map.get(`run/${RUN_ID}/root.manifest.json`)!;
  return (JSON.parse(new TextDecoder().decode(raw)) as { merkleRoot: string }).merkleRoot;
}

async function main(): Promise<void> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const verifier = verifierFrom(signer);
  const breakGlass = makeRecipient("break-glass");
  const recipients = [breakGlass.entry];
  const identity = parseIdentity(breakGlass.identity);

  // A value of 5 windows at a 64 KiB target (so a tiny budget forces the ONE record across several slices
  // without a gigabyte fixture). 64 KiB == CHUNK_SIZE, so each window is exactly one STREAM chunk.
  const TARGET = 64 * 1024;
  const VALUE = patterned(TARGET * 5 + 1234, 17); // 5 full windows + a remainder => 6 segments
  const wantSha = hexEncode(await nobleSha384(VALUE));

  console.log("FORMAT-EQUIVALENCE: one record sealed across many slices == sealed in one shot:");

  // The SAME run master drives both runs: content addressing is HMAC(deriveCAK(master, downpipeId), ...)
  // and the name MAC is master-derived, so a byte-identity comparison is only meaningful under a fixed
  // master (which is exactly the real invariant: a resumed run unwraps the SAME wrapped master each slice).
  const FIXED_MASTER = rand(32);

  // (A) ONE-SHOT: a budget large enough to seal the whole record in a single slice.
  const destOne = new MemDest();
  const holderOne: BlobHolder = { etag: '"v1"', bytes: VALUE };
  const one = await sealRunToCompletion(() => new OneRecordSource(holderOne, "big/object.bin"), destOne, signer, recipients, signerPrivateB64, { subrequests: 700, wallMs: 60_000 }, TARGET, FIXED_MASTER);
  ok("the one-shot run sealed in a single slice", one.slices === 1);

  // (B) MULTI-SLICE: a TINY subrequest budget so the slice yields mid-record after roughly one window each,
  // forcing the SAME one record across many slices, UNDER THE SAME MASTER. The wall budget stays generous
  // so only the subrequest pressure drives the yield.
  const destMany = new MemDest();
  const holderMany: BlobHolder = { etag: '"v1"', bytes: VALUE };
  const many = await sealRunToCompletion(() => new OneRecordSource(holderMany, "big/object.bin"), destMany, signer, recipients, signerPrivateB64, { subrequests: 1, wallMs: 60_000 }, TARGET, FIXED_MASTER);
  ok(`the same record spanned MULTIPLE slices (took ${many.slices}, >= 2)`, many.slices >= 2);

  // THE BYTE-IDENTITY PROOF: the multi-slice archive's content-addressed segment objects, the signed
  // Merkle root, and (via the reader) the record's whole-record SHA-384, recordHash (the Merkle leaf) and
  // segment list must ALL equal the one-shot's. Any divergence in the resumed digest or the segment set
  // fails here.
  const keysOne = segKeys(destOne);
  const keysMany = segKeys(destMany);
  ok(`the same ordered set of segment objects was written (${keysOne.length} segments)`, keysOne.length > 1 && JSON.stringify(keysOne) === JSON.stringify(keysMany));
  ok("the signed Merkle root is byte-identical to the one-shot", rootMerkleRoot(destOne) === rootMerkleRoot(destMany));

  const runOne = await openRun(new MapStore(destOne.map), RUN_ID, identity, verifier, {});
  const runMany = await openRun(new MapStore(destMany.map), RUN_ID, identity, verifier, {});
  ok("the multi-slice archive OPENS under the reader (signature, shard + record hashes, Merkle root)", true);
  ok("both archives declare exactly one record", runOne.records.length === 1 && runMany.records.length === 1);
  const recOne = runOne.records[0]!;
  const recMany = runMany.records[0]!;
  ok("the whole-record plaintext SHA-384 is the value's, identical across both", recMany.plaintextSha384 === wantSha && recOne.plaintextSha384 === wantSha);
  ok("the record line's recordHash (the Merkle leaf) is byte-identical", recOne.recordHash === recMany.recordHash);
  ok("the ordered segment list is byte-identical", JSON.stringify(recOne.segments) === JSON.stringify(recMany.segments));
  ok("the record chained into >1 segment (a real chain, not a single segment)", recMany.segments.length > 1);
  const restored = await runMany.restoreRecord(recMany);
  ok("the multi-slice record restores BYTE-EXACT (reassembled plaintext SHA matches)", eqBytes(restored, VALUE));

  console.log("\nPROGRESS: a value needing K slices completes in about K slices (>=1 new window each, no stall):");
  // 6 segments over a 1-subrequest budget: each slice seals one or two windows then yields, so the run
  // completes in O(segments) slices, never stalling (a stall would re-read the prefix without advancing and
  // the loop guard in sealRunToCompletion would have thrown). The bound is generous (<= 2x the segment
  // count) to tolerate the exact per-window subrequest accounting.
  ok(`completed in O(segments) slices: ${many.slices} slices for ${keysMany.length} segments`, many.slices >= 2 && many.slices <= keysMany.length * 2 + 2);

  console.log("\nCHANGE-DETECTION: the object's etag moves between slices -> resume SKIPS, never a corrupt record:");
  {
    const dest = new MemDest();
    const holder: BlobHolder = { etag: '"v1"', bytes: patterned(TARGET * 4 + 77, 23) };
    // Seal slice 1 (which leaves the record partial), then REPLACE the object (new etag + new bytes), then
    // resume. The resumed seal must find the etag changed and SKIP the record (changed-mid-crawl): no
    // record line is ever committed for it, the run completes with ZERO records, and recordsSkippedChanged
    // counts the one skip. A digest over the NEW prefix bytes must NEVER be sealed against the OLD segments.
    const master = rand(32);
    let cp: RunCheckpoint = {
      v: 1, downpipeId: DP_ID, downpipeName: "resumable", cadence: "3600s", sourceType: "r2",
      selector: ALL, runId: RUN_ID, runlogIndex: 2, prevRunId: null,
      startedAt: "2026-06-10T00:00:00.000Z", wrappedMaster: await wrapMaster(signerPrivateB64, RUN_ID, master),
      cursor: null, sourceDone: false, nextRecordIndex: 0, nextShardIndex: 0,
      frontier: { count: 0, nodes: [] }, counts: zeroCounts(), sliceCount: 0, partialRecord: null,
    };
    master.fill(0);
    const allShards: ShardEntry[] = [];
    // Slice 1: tiny budget -> partial.
    {
      const m = await unwrapMaster(signerPrivateB64, RUN_ID, cp.wrappedMaster);
      const r = await runSlice({ source: new OneRecordSource(holder, "mut/object.bin"), dest, signer, recipients, budget: new SliceBudget({ subrequests: 1, wallMs: 60_000 }), segmentTargetBytes: TARGET }, cp, m);
      m.fill(0);
      cp = JSON.parse(JSON.stringify(r.checkpoint)) as RunCheckpoint;
      allShards.push(...r.newShards);
    }
    ok("slice 1 left the record PARTIAL (a partialRecord is checkpointed, source not done)", cp.partialRecord !== null && cp.sourceDone === false);
    // The object is REPLACED underneath the run.
    holder.etag = '"v2"';
    holder.bytes = patterned(holder.bytes.length, 99); // same length, different bytes
    // Resume slices to completion.
    let openBuffer: Record<string, unknown>[] = [];
    let guard = 0;
    for (; guard < 50 && !cp.sourceDone; guard++) {
      const m = await unwrapMaster(signerPrivateB64, RUN_ID, cp.wrappedMaster);
      const r = await runSlice({ source: new OneRecordSource(holder, "mut/object.bin"), dest, signer, recipients, budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }), segmentTargetBytes: TARGET }, cp, m, openBuffer);
      m.fill(0);
      cp = JSON.parse(JSON.stringify(r.checkpoint)) as RunCheckpoint;
      allShards.push(...r.newShards);
      openBuffer = r.openReset ? r.openWrite : [...openBuffer, ...r.openWrite];
    }
    ok("the run completes after the change (no wedge)", cp.sourceDone);
    ok("the changed record was SKIPPED, never committed (records == 0)", cp.counts.records === 0);
    ok("recordsSkippedChanged counted the one changed-mid-crawl skip", cp.counts.recordsSkippedChanged === 1);
    ok("the outbound partialRecord was cleared (the partial is abandoned)", cp.partialRecord === null);
    const m = await unwrapMaster(signerPrivateB64, RUN_ID, cp.wrappedMaster);
    await finaliseRun({ source: new OneRecordSource(holder, "mut/object.bin"), dest, signer, recipients, budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) }, cp, m, allShards, openBuffer);
    m.fill(0);
    const run = await openRun(new MapStore(dest.map), RUN_ID, identity, verifier, {});
    ok("the archive opens and has NO record (no corrupt record line was produced)", run.records.length === 0);
  }

  console.log("\nCHANGE-DETECTION at the seal level: a resume with a mismatched etag refuses, never re-hashes:");
  {
    // Drive sealChainedStreamRecord directly: seal a prefix (yield), then resume with a stream whose etag
    // differs from the partial's etag. The resume must refuse (changed-mid-crawl) WITHOUT calling the
    // streamed re-hash (the counter stays 0), because the etag mismatch is checked first.
    const master = rand(32);
    const cak = await deriveCAK(master, DP_ID);
    const dest = new MemDest();
    const counters = { ranged: 0, streamed: 0 };
    const holder: BlobHolder = { etag: '"v1"', bytes: patterned(TARGET * 3, 31) };
    const deps: RecordSealDeps = {
      cak, master, runIdBytes: decodeULID(RUN_ID), dest,
      randomNonce: () => rand(16), randomSalt: () => rand(16),
      segmentTargetBytes: TARGET,
      yieldCheck: () => true, // force a yield after the first window
    };
    const rec1: SourceRecord = { sourceType: "r2", name: "x", bucket: "media", stream: memStreamingValue(holder, { counters }) };
    const out1 = await sealRecordToDest(deps, "r000000000000000", rec1);
    ok("the seal yielded a partial after one window", out1.ok === "partial");
    if (out1.ok === "partial") {
      // Resume with an etag that does NOT match the partial's etag.
      const resume: ResumeFrom = { offsetSealed: out1.offsetSealed, segments: out1.segments, etag: '"STALE"' };
      const before = counters.streamed;
      const out2 = await sealRecordToDest({ ...deps, yieldCheck: () => false }, "r000000000000000", rec1, resume);
      ok("a resume with a mismatched etag is REFUSED as changed-mid-crawl", out2.ok === false);
      ok("the refusal happened BEFORE any prefix re-hash (no streamed read issued)", counters.streamed === before);
    }
  }

  console.log("\nREGRESSION: a value that fits one slice still seals in ONE slice; a no-etag value never mid-yields:");
  {
    // A value that fits the budget in one slice: same archive, one slice, regardless of mid-record support.
    const dest = new MemDest();
    const holder: BlobHolder = { etag: '"v1"', bytes: patterned(TARGET * 2 + 9, 41) };
    const r = await sealRunToCompletion(() => new OneRecordSource(holder, "ok/object.bin"), dest, signer, recipients, signerPrivateB64, { subrequests: 700, wallMs: 60_000 }, TARGET, rand(32));
    ok("an under-budget record seals in exactly one slice", r.slices === 1);
    const run = await openRun(new MapStore(dest.map), RUN_ID, identity, verifier, {});
    ok("it restores byte-exact", run.records.length === 1 && eqBytes(await run.restoreRecord(run.records[0]!), holder.bytes));
  }
  {
    // A NO-ETAG stream never yields mid-record even under budget pressure (it cannot be safely resumed), so
    // it seals WHOLE in one slice. Drive the seal directly with a no-etag StreamingValue and a yieldCheck
    // that always fires: the seal must still return ok (whole), never partial.
    const master = rand(32);
    const cak = await deriveCAK(master, DP_ID);
    const dest = new MemDest();
    const bytes = patterned(TARGET * 3, 53);
    const noEtag: StreamingValue = {
      size: bytes.length,
      open: () => ({ async *chunks() { yield bytes; } }),
      openRange: (o, l) => ({ async *chunks() { yield bytes.subarray(o, o + l); } }),
      // no etag, no openStreamedRange: not resumable
    };
    const deps: RecordSealDeps = {
      cak, master, runIdBytes: decodeULID(RUN_ID), dest,
      randomNonce: () => rand(16), randomSalt: () => rand(16),
      segmentTargetBytes: TARGET,
      yieldCheck: () => true, // would yield if it could
    };
    const out = await sealRecordToDest(deps, "r000000000000000", { sourceType: "r2", name: "noetag", bucket: "media", stream: noEtag });
    ok("a NO-ETAG streamed value never yields mid-record (seals whole, never partial)", out.ok === true);
    if (out.ok === true) {
      ok("the no-etag whole seal chains and its whole-record SHA-384 is correct", out.seal.segments.length > 1 && out.seal.plaintextSha384 === hexEncode(await nobleSha384(bytes)));
    }
  }

  console.log(failures === 0 ? "\nMID-RECORD RESUMABLE SEAL PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
