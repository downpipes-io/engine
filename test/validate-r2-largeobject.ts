// Prove the R2 large-object fix (no archive format change): the REAL R2Source (not a mock
// stand-in) now (1) exposes etag + openStreamedRange on a large object's stream so the seal RESUMES it
// MID-RECORD ACROSS SLICES via an etag-pinned ranged prefix re-hash, (2) FAILS SOFT over the in-band
// ceiling -- a single object too large to seal safely is yielded as a LOUD incompleteness marker and the
// crawl CONTINUES (the rest of the bucket still archives) instead of the chained seal THROWING and
// terminal-failing the whole run with zero archive, and (3) detects an ETAG CHANGE between slices and
// ABANDONS the resume (never stitches two object versions).
//
// SAFETY: no large objects are ever materialised. The over-ceiling object reports a multi-GiB size as a
// METADATA NUMBER with NO backing bytes (the mock THROWS if anything tries to GET it, proving the skip is
// decided from the cheap list page before any value read). Every real fixture is a few KiB; the streamed
// path is forced on a tiny object via the R2Source streamThreshold test seam and a tiny segment target.
// Run: node test/validate-r2-largeobject.ts

import { sha384 as nobleSha384 } from "@noble/hashes/sha2.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import type { RecipientEntry, Signer } from "../src/format/writer.ts";
import { runSlice, finaliseRun, type ShardEntry, type SliceDeps } from "../src/seal/slice.ts";
import { wrapMaster, unwrapMaster, zeroCounts, type RunCheckpoint } from "../src/seal/checkpoint.ts";
import { SliceBudget, MAX_SINGLE_RECORD_CONTENT_BYTES } from "../src/seal/budget.ts";
import type { Selector, CrawlEvent, SourceAdapter } from "../src/sources/types.ts";
import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import { b64urlEncode, concat, hexEncode } from "../src/crypto/bytes.ts";
import { R2Source } from "../src/sources/r2.ts";
import { isIncompleteMarkerValue } from "../src/seal/marker.ts";

const RUN_ID = "01BX5ZZKBKACTAV9WEVGEMMVR7";
const DP_ID = "dp_r2large";
const ALL: Selector = { include: [], exclude: [] };
const TARGET = 4096; // tiny segment target so a few-KiB object chains into several segments
const SMALL_THRESHOLD = 1024; // tiny buffer/stream boundary so a few-KiB object takes the streamed path

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
// streamOf turns bytes into a ReadableStream that yields uneven small pieces (exercises the seal's
// re-chunker), exactly the shape an R2 object body has.
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

// MockObj models one R2 object. `bytes` is the (tiny) backing content; it is ABSENT for an over-ceiling
// object that must be skipped from the list page alone, so any GET of it throws. etag/bytes are mutable so
// a test can REPLACE the object between slices (the etag-change edge).
interface MockObj {
  key: string;
  size: number;
  etag: string;
  bytes?: Uint8Array;
  httpMetadata?: { contentType?: string };
  customMetadata?: Record<string, string>;
}

// MockR2Bucket is the subset of the R2Bucket binding the R2Source touches: list() (prefix + startAfter,
// single page), get() whole (the buffered path; arrayBuffer + metadata) and get() ranged+etag-pinned (the
// streamed path; a body ReadableStream, or a body-less object when the etag pin fails -- exactly how the
// real binding signals a version change). It records every get so a test can assert which objects were
// (and were NOT) fetched.
class MockR2Bucket {
  objs: MockObj[];
  getCalls: { key: string; range?: { offset: number; length: number }; etagPin?: string }[] = [];
  listCalls = 0;
  constructor(objs: MockObj[]) {
    this.objs = objs;
  }
  // biome-ignore lint/suspicious/noExplicitAny: the mock implements only the slice of R2ListOptions/result the source uses.
  async list(opts: any): Promise<any> {
    this.listCalls++;
    const prefix: string | undefined = opts?.prefix;
    const startAfter: string | undefined = opts?.startAfter;
    const objects = this.objs
      .filter((o) => (prefix === undefined || o.key.startsWith(prefix)) && (startAfter === undefined || o.key > startAfter))
      .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
      .map((o) => ({
        key: o.key,
        size: o.size,
        etag: o.etag,
        ...(o.httpMetadata ? { httpMetadata: o.httpMetadata } : {}),
        ...(o.customMetadata ? { customMetadata: o.customMetadata } : {}),
      }));
    return { objects, truncated: false };
  }
  // biome-ignore lint/suspicious/noExplicitAny: the mock implements only the slice of R2GetOptions/result the source uses.
  async get(key: string, opts?: any): Promise<any> {
    const o = this.objs.find((x) => x.key === key);
    if (!o) return null;
    const etagPin: string | undefined = opts?.onlyIf?.etagMatches;
    const range: { offset: number; length: number } | undefined = opts?.range;
    this.getCalls.push({ key, ...(range ? { range } : {}), ...(etagPin !== undefined ? { etagPin } : {}) });
    const meta = {
      ...(o.httpMetadata ? { httpMetadata: o.httpMetadata } : {}),
      ...(o.customMetadata ? { customMetadata: o.customMetadata } : {}),
    };
    // etag pin failed: the real binding returns the object WITHOUT a body (a mid-crawl replacement).
    if (etagPin !== undefined && etagPin !== o.etag) return { key, size: o.size, etag: o.etag, ...meta };
    if (o.bytes === undefined) throw new Error(`MockR2Bucket.get fetched bytes for ${key}, which has none: an over-ceiling object must be skipped from the list page, never GET'd`);
    if (range) return { key, size: o.size, etag: o.etag, ...meta, body: streamOf(o.bytes.subarray(range.offset, range.offset + range.length)) };
    return { key, size: o.size, etag: o.etag, ...meta, body: streamOf(o.bytes), arrayBuffer: async () => o.bytes!.slice().buffer };
  }
}
function asBucket(b: MockR2Bucket): R2Bucket {
  return b as unknown as R2Bucket;
}

// MemDest: the full Destination contract over a map (the ARCHIVE sink), copied from validate-resumable-record.ts.
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

function freshCheckpoint(wrappedMaster: { iv: string; ct: string }, runlogIndex: number): RunCheckpoint {
  return {
    v: 1, downpipeId: DP_ID, downpipeName: "r2large", cadence: "3600s", sourceType: "r2",
    selector: ALL, runId: RUN_ID, runlogIndex, prevRunId: null,
    startedAt: "2026-06-10T00:00:00.000Z", wrappedMaster,
    cursor: null, sourceDone: false, nextRecordIndex: 0, nextShardIndex: 0,
    frontier: { count: 0, nodes: [] }, counts: zeroCounts(), sliceCount: 0, partialRecord: null,
  };
}

// sealRunToCompletion drives runSlice (checkpoint round-tripped through JSON each slice, the real eviction
// discipline) until the source is exhausted, then finalises. budget is rebuilt fresh each slice. A guard
// caps the loop so a stalled resume fails loudly rather than hanging. Returns the final checkpoint + slice
// count. Adapted from validate-resumable-record.ts to take a source factory (the REAL R2Source here).
async function sealRunToCompletion(
  source: () => SourceAdapter, dest: MemDest, signer: Signer, recipients: RecipientEntry[], signerPrivateB64: string,
  budgetOpts: { subrequests: number; wallMs: number }, segmentTargetBytes: number, master: Uint8Array, maxSlices = 200,
): Promise<{ slices: number; checkpoint: RunCheckpoint }> {
  let cp = freshCheckpoint(await wrapMaster(signerPrivateB64, RUN_ID, new Uint8Array(master)), 1);
  const allShards: ShardEntry[] = [];
  // Shard-spanning: the open shard buffer carries ACROSS slices and is sealed by finaliseRun,
  // so the owner persists+re-seeds it just like allShards. Thread it through every runSlice and hand the
  // accumulated buffer to finaliseRun; dropping it would lose the carried manifest lines of a large object.
  let openBuffer: Record<string, unknown>[] = [];
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
  const signerPrivateB64 = b64urlEncode(concat(rand(32), rand(32)));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const verifier = verifierFrom(signer);
  const breakGlass = makeRecipient("break-glass");
  const recipients = [breakGlass.entry];
  const identity = parseIdentity(breakGlass.identity);

  // ============================================================================================
  console.log("WIRING: a large R2 object's stream exposes etag + openStreamedRange + openRange (the resume inputs):");
  {
    const bytes = patterned(TARGET * 3 + 7, 5); // a few KiB, streamed under the tiny threshold
    const obj: MockObj = { key: "vid/clip.bin", size: bytes.length, etag: '"v1"', bytes, httpMetadata: { contentType: "video/mp4" }, customMetadata: { take: "3" } };
    const src = new R2Source(asBucket(new MockR2Bucket([obj])), "media", { resumable: true, streamThreshold: SMALL_THRESHOLD });
    const events: CrawlEvent[] = [];
    for await (const ev of src.crawlFrom(ALL, null)) events.push(ev);
    const recEv = events.find((e) => e.kind === "record");
    ok("the large object yielded a STREAMED record (not buffered)", recEv?.kind === "record" && recEv.record.stream !== undefined && recEv.record.value === undefined);
    if (recEv?.kind === "record" && recEv.record.stream) {
      const st = recEv.record.stream;
      ok("the stream carries the object's etag (the resume version pin)", st.etag === '"v1"');
      ok("the stream exposes openStreamedRange (the one-subrequest prefix re-hash entry)", typeof st.openStreamedRange === "function");
      ok("the stream exposes openRange (the chained-window read)", typeof st.openRange === "function");
      ok("size equals the object's declared size", st.size === bytes.length);
      ok("the restore descriptor captured the HTTP + custom metadata", JSON.stringify(recEv.record.descriptor) === JSON.stringify({ r2HttpMetadata: { contentType: "video/mp4" }, r2CustomMetadata: { take: "3" } }));
      // openStreamedRange and openRange must return the EXACT etag-pinned bytes for a sub-extent.
      const collect = async (cs: { chunks(): AsyncIterable<Uint8Array> }): Promise<Uint8Array> => {
        const parts: Uint8Array[] = [];
        for await (const c of cs.chunks()) parts.push(c);
        return concat(...parts);
      };
      ok("openStreamedRange(0, 100) returns the exact prefix bytes", eqBytes(await collect(st.openStreamedRange!(0, 100)), bytes.subarray(0, 100)));
      ok("openRange(64, 200) returns the exact window bytes", eqBytes(await collect(st.openRange!(64, 200)), bytes.subarray(64, 264)));
    }
    ok("a resume mark follows the record (the crawl can checkpoint after it)", events.some((e) => e.kind === "mark"));
  }

  // ============================================================================================
  console.log("\nRESUME ACROSS SLICES: the REAL R2Source seals one large object over MANY slices, BYTE-IDENTICAL to one shot:");
  {
    const VALUE = patterned(TARGET * 4 + 1234, 17); // 5 segments (4 windows + a remainder)
    const wantSha = hexEncode(await nobleSha384(VALUE));
    const FIXED_MASTER = rand(32);
    const mkSrc = () => new R2Source(asBucket(new MockR2Bucket([{ key: "vid/movie.bin", size: VALUE.length, etag: '"v1"', bytes: VALUE }])), "media", { resumable: true, streamThreshold: SMALL_THRESHOLD });

    // (A) one-shot: a generous budget seals the whole object in one slice.
    const destOne = new MemDest();
    const one = await sealRunToCompletion(mkSrc, destOne, signer, recipients, signerPrivateB64, { subrequests: 700, wallMs: 60_000 }, TARGET, FIXED_MASTER);
    ok("the one-shot run sealed in a single slice", one.slices === 1);

    // (B) multi-slice: a 1-subrequest budget forces a yield after each window, so the SAME object spans
    // many slices, resumed each time via etag + openStreamedRange. Same master so the comparison is meaningful.
    const destMany = new MemDest();
    const many = await sealRunToCompletion(mkSrc, destMany, signer, recipients, signerPrivateB64, { subrequests: 1, wallMs: 60_000 }, TARGET, FIXED_MASTER);
    ok(`the object spanned MULTIPLE slices (took ${many.slices}, >= 2)`, many.slices >= 2);

    const keysOne = segKeys(destOne);
    const keysMany = segKeys(destMany);
    ok(`the same ordered set of segment objects was written (${keysOne.length} segments, a real chain)`, keysOne.length > 1 && JSON.stringify(keysOne) === JSON.stringify(keysMany));
    ok("the signed Merkle root is byte-identical to the one-shot", rootMerkleRoot(destOne) === rootMerkleRoot(destMany));
    const run = await openRun(new MapStore(destMany.map), RUN_ID, identity, verifier, {});
    ok("the multi-slice archive opens and declares exactly one record", run.records.length === 1);
    ok("the whole-record plaintext SHA-384 is the value's", run.records[0]!.plaintextSha384 === wantSha);
    ok("the record chained into >1 segment", run.records[0]!.segments.length > 1);
    ok("the multi-slice record restores BYTE-EXACT", eqBytes(await run.restoreRecord(run.records[0]!), VALUE));
  }

  // ============================================================================================
  console.log("\nFAIL-SOFT OVER CEILING: an oversized object is skipped with a LOUD marker and the run keeps archiving the rest:");
  {
    const small = patterned(96, 3);
    const HUGE = 4 * 1024 * 1024 * 1024; // ~4 GiB reported as a NUMBER; no bytes are ever allocated or fetched
    const bucket = new MockR2Bucket([
      { key: "aaa/small.txt", size: small.length, etag: '"s1"', bytes: small },
      { key: "zzz/huge.bin", size: HUGE, etag: '"h1"' }, // > MAX_SINGLE_RECORD_CONTENT_BYTES; no `bytes`
    ]);
    ok("the fixture's huge size is genuinely over the in-band ceiling", HUGE > MAX_SINGLE_RECORD_CONTENT_BYTES);
    const mkSrc = () => new R2Source(asBucket(bucket), "media", { resumable: true });
    const dest = new MemDest();
    const run = await sealRunToCompletion(mkSrc, dest, signer, recipients, signerPrivateB64, { subrequests: 700, wallMs: 60_000 }, TARGET, rand(32));
    ok("the run COMPLETED (not a terminal-fail / wedge)", run.checkpoint.sourceDone === true);
    ok("both objects produced a record (the small one + the skip marker)", run.checkpoint.counts.records === 2);
    ok("exactly one record was counted as not-fully-captured (recordsIncomplete == 1)", run.checkpoint.counts.recordsIncomplete === 1);
    ok("the oversized object's bytes were NEVER fetched (no GET issued for it)", !bucket.getCalls.some((c) => c.key === "zzz/huge.bin"));

    const opened = await openRun(new MapStore(dest.map), RUN_ID, identity, verifier, {});
    ok("the archive opens with both records", opened.records.length === 2);
    const restored = await Promise.all(opened.records.map((r) => opened.restoreRecord(r)));
    const markers = restored.filter((b) => isIncompleteMarkerValue(b));
    const reals = restored.filter((b) => !isIncompleteMarkerValue(b));
    ok("exactly one record is an incompleteness marker", markers.length === 1);
    ok("the OTHER record is the small object, restored byte-exact", reals.length === 1 && eqBytes(reals[0]!, small));
    if (markers.length === 1) {
      const m = JSON.parse(new TextDecoder().decode(markers[0]!)) as { _skipped?: string; size?: number };
      ok("the marker is a _skipped sentinel naming the over-ceiling skip", typeof m._skipped === "string" && /exceeds the .* single-invocation in-band capture limit/.test(m._skipped));
      ok("the marker records the true (huge) object size for out-of-band recovery", m.size === HUGE);
    }
  }

  // ============================================================================================
  console.log("\nNON-RESUMABLE CEILING: with sliced runs OFF the lower one-slice ceiling applies, still a skip not a throw:");
  {
    // SLICED_RUNS_DISABLED => resumable:false => ceiling drops to MAX_SINGLE_SLICE_RECORD_BYTES (~1.84 GiB).
    // An object between the two ceilings (~2.5 GiB) must be SKIPPED here (it could not resume across slices),
    // where a resumable run would have streamed it. Reported as a number; never allocated.
    const BETWEEN = 2_500_000_000; // > MAX_SINGLE_SLICE_RECORD_BYTES, < MAX_SINGLE_RECORD_CONTENT_BYTES
    const bucket = new MockR2Bucket([{ key: "vm/image.qcow2", size: BETWEEN, etag: '"i1"' }]);
    const src = new R2Source(asBucket(bucket), "media", { resumable: false });
    const events: CrawlEvent[] = [];
    for await (const ev of src.crawlFrom(ALL, null)) events.push(ev);
    const rec = events.find((e) => e.kind === "record");
    ok("the between-ceilings object is skipped as a marker under the non-resumable ceiling", rec?.kind === "record" && isIncompleteMarkerValue(rec.record.value));
    ok("its bytes were never fetched", bucket.getCalls.length === 0);
  }

  // ============================================================================================
  console.log("\nETAG CHANGE MID-CRAWL: the object is replaced between slices -> the resume ABANDONS it, never stitches two versions:");
  {
    const bucket = new MockR2Bucket([{ key: "mut/object.bin", size: TARGET * 4, etag: '"v1"', bytes: patterned(TARGET * 4, 23) }]);
    const mkSrc = () => new R2Source(asBucket(bucket), "media", { resumable: true, streamThreshold: SMALL_THRESHOLD });
    const master = rand(32);
    let cp = freshCheckpoint(await wrapMaster(signerPrivateB64, RUN_ID, master), 2);
    master.fill(0);
    const dest = new MemDest();
    const allShards: ShardEntry[] = [];
    let openBuffer: Record<string, unknown>[] = []; // shard-spanning: carried open buffer (see sealRunToCompletion)
    // Slice 1: tiny budget -> the object is left PARTIAL (sealed under etag "v1").
    {
      const m = await unwrapMaster(signerPrivateB64, RUN_ID, cp.wrappedMaster);
      const r = await runSlice({ source: mkSrc(), dest, signer, recipients, budget: new SliceBudget({ subrequests: 1, wallMs: 60_000 }), segmentTargetBytes: TARGET }, cp, m, openBuffer);
      m.fill(0);
      cp = JSON.parse(JSON.stringify(r.checkpoint)) as RunCheckpoint;
      allShards.push(...r.newShards);
      openBuffer = r.openReset ? r.openWrite : [...openBuffer, ...r.openWrite];
    }
    ok("slice 1 left the object PARTIAL (a partialRecord is checkpointed, source not done)", cp.partialRecord !== null && cp.sourceDone === false);
    // REPLACE the object underneath the run (new etag + new bytes, same length).
    bucket.objs[0]!.etag = '"v2"';
    bucket.objs[0]!.bytes = patterned(TARGET * 4, 99);
    // Resume to completion.
    let guard = 0;
    for (; guard < 50 && !cp.sourceDone; guard++) {
      const m = await unwrapMaster(signerPrivateB64, RUN_ID, cp.wrappedMaster);
      const r = await runSlice({ source: mkSrc(), dest, signer, recipients, budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }), segmentTargetBytes: TARGET }, cp, m, openBuffer);
      m.fill(0);
      cp = JSON.parse(JSON.stringify(r.checkpoint)) as RunCheckpoint;
      allShards.push(...r.newShards);
      openBuffer = r.openReset ? r.openWrite : [...openBuffer, ...r.openWrite];
    }
    ok("the run completes after the change (no wedge)", cp.sourceDone);
    ok("the changed object was SKIPPED, never committed (records == 0)", cp.counts.records === 0);
    ok("recordsSkippedChanged counted the one changed-mid-crawl skip", cp.counts.recordsSkippedChanged === 1);
    ok("the outbound partialRecord was cleared (the partial is abandoned)", cp.partialRecord === null);
    const m = await unwrapMaster(signerPrivateB64, RUN_ID, cp.wrappedMaster);
    await finaliseRun({ source: mkSrc(), dest, signer, recipients, budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) }, cp, m, allShards, openBuffer);
    m.fill(0);
    const opened = await openRun(new MapStore(dest.map), RUN_ID, identity, verifier, {});
    ok("the archive opens and has NO record (no corrupt, version-stitched record line was produced)", opened.records.length === 0);
  }

  console.log(failures === 0 ? "\nR2 LARGE-OBJECT PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
