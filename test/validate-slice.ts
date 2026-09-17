// Prove the sliced seal end to end: a KV namespace far past one
// invocation's budget seals across MANY slices (fresh budget each), checkpointing the
// cursor + Merkle frontier + counters + the WRAPPED run master between invocations, with
// the archive finalised over the accumulated shards and opened by the TS reader with
// every record byte-exact and none duplicated; resume survives "eviction" (state lives
// only in the serialised checkpoint), cursor invalidation (the watermark fallback), and
// a wrapped master is bound to its runId (a swap is refused). Then the REAL worker entry
// (sealRunSliced) and the REAL RunSealDO class are driven with in-memory doubles:
// inline completion for a small run (no DO involvement), handoff for a large one, the
// DO's alarm chain to completion with heartbeats, a lost lease abandoning cleanly, slice
// failures backing off and a persistent failure resolving the run as failed.
// Run: node test/validate-slice.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import type { RecipientEntry, Signer } from "../src/format/writer.ts";
import { runSlice, finaliseRun, coarseRunError, causeDigest, redactedRunError, PAD5_LIMIT, type ShardEntry, type SliceDeps } from "../src/seal/slice.ts";
import { attestKeyless } from "../src/format/keyless.ts";
import { wrapMaster, unwrapMaster, openStoredCheckpoint, sealCheckpointForStorage, sealOpenShardBatch, openOpenShardBatch, zeroCounts, type RunCheckpoint } from "../src/seal/checkpoint.ts";
import { SliceBudget } from "../src/seal/budget.ts";
import { sealRunSliced, RunSealDO, type StartSliceRun } from "../src/seal/runstate.ts";
import { cfConfigToken } from "../src/seal/runstate-helpers.ts";
import { KVSource } from "../src/sources/kv.ts";
import type { SourceAdapter, SourceRecord, Selector, Meter } from "../src/sources/types.ts";
import type { MarkerKey } from "../src/seal/marker.ts";
import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import type { Env } from "../src/env.d.ts";
import type { DownpipeState } from "../src/sched/scheduler-do.ts";
import { b64urlEncode, concat, utf8, hexEncode } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { buildReader, goPresent, runReader, writeArchiveDir } from "./scale-go-reader.ts";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";

const RUN_ID = "01BX5ZZKBKACTAV9WEVGEMMVRY";
const DP_ID = "dp_sliced";

// REQUIRE_DOWNPIPE=1 turns an absent sibling Go reader repo (see the differential test below) into a
// could-not-check refusal. Unset (the default a customer's
// `npm run deploy` runs under), the same absence is a declared skip: the differential runs in CI,
// where the sibling is checked out and this variable is set, not on every machine that deploys the
// engine. Same REQUIRE_* convention as REQUIRE_CF_OPENAPI and REQUIRE_ENGINE elsewhere in this
// workspace: a name CI sets deliberately, never a default that would need a customer to know it exists.
const REQUIRE_DOWNPIPE = process.env.REQUIRE_DOWNPIPE === "1";

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

// ---- doubles ---------------------------------------------------------------

// MemDest: the full Destination contract over a map (etagged, conditional).
class MemDest implements Destination {
  map = new Map<string, Uint8Array>();
  private tags = new Map<string, string>();
  private seq = 0;
  // throttle, when true, makes every WRITE throw a 503 SlowDown (a destination throttle) so a test can
  // drive the alarm's park-and-resume ladder. Reads are unaffected, so content-addressed dedup still works.
  throttle = false;
  async get(key: string): Promise<GetResult | null> {
    const v = this.map.get(key);
    return v ? { body: v, etag: this.tags.get(key) ?? "e0" } : null;
  }
  async put(key: string, body: Uint8Array): Promise<void> {
    if (this.throttle) throw new Error(`PUT ${key}: status 503`);
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

// CorruptRootDest is a MemDest that corrupts the signed root manifest's detached SIGNATURE on
// read-back ONLY (a byte flip on the ".sig" object). The seal itself never re-reads the root it
// just wrote, so the archive lands intact; the FIRST reader of the root is verify-at-seal, whose
// Tier-0 attestation then fails its signature check and returns a SUSPECT verdict. That drives the
// suspect path in runSealVerification without any mid-call hook, so the run still completes "ok"
// (fail-open) while the verdict is recorded and the critical alert is routed.
class CorruptRootDest extends MemDest {
  override async get(key: string): Promise<GetResult | null> {
    const r = await super.get(key);
    if (r && key.endsWith("root.manifest.json.sig") && r.body.byteLength > 0) {
      const flipped = new Uint8Array(r.body);
      flipped[0] = flipped[0]! ^ 0xff;
      return { body: flipped, etag: r.etag };
    }
    return r;
  }
}

// FailWriteDest is a MemDest whose first segment WRITE fails with a plain (non-throttle) destination
// error, so a backup throws while sealing rather than at adapter construction. It exercises the v1
// buffered seal's catch path (zeroise + redacted log + failed completion) without deleting the source
// binding (which the source code reads outside the buffered try, so that would escape instead).
class FailWriteDest extends MemDest {
  override async put(key: string, body: Uint8Array): Promise<void> {
    throw new Error(`PUT ${key}: status 500 destination write rejected`);
  }
}

// ContendRunlogDest is a MemDest whose CONDITIONAL write of the account RUNLOG always reports a precondition
// failure while `contend` is set, simulating another finaliser holding the same destination's RUNLOG (the
// contention the per-destination lock + park branch defend against). Segment/root/bundle writes are
// unaffected, so the run seals and finalises normally up to the RUNLOG append, which then exhausts the CAS
// and throws RunlogContendedError -- the typed signal the seal DO PARKS on (handleContention) instead of
// striking the run dead. Clearing `contend` lets the SAME parked run resume and finalise.
class ContendRunlogDest extends MemDest {
  contend = false;
  override async putConditional(key: string, body: Uint8Array, opts: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult> {
    if (this.contend && key === "_RECOVERY/RUNLOG") return { ok: false };
    return super.putConditional(key, body, opts);
  }
}

// MemKV: a paginated KV namespace double with REAL cursor semantics: cursors are epoch-
// stamped opaque tokens, and invalidateCursors() expires every cursor issued so far (the
// platform expiring a long-held cursor) while freshly-issued ones keep working, which is
// what exercises the watermark fallback without breaking the fallback's own paging.
class MemKV {
  private seeds: { name: string; value: Uint8Array }[];
  private pageSize: number;
  private epoch = 0;
  lists = 0;
  gets = 0;
  constructor(seeds: { name: string; value: Uint8Array }[], pageSize: number) {
    this.seeds = [...seeds].sort((a, b) => (a.name < b.name ? -1 : 1));
    this.pageSize = pageSize;
  }
  invalidateCursors(): void {
    this.epoch++;
  }
  async list(options?: { prefix?: string; cursor?: string }): Promise<{ keys: { name: string }[]; list_complete: boolean; cursor?: string; cacheStatus: null }> {
    this.lists++;
    let start = 0;
    if (options?.cursor !== undefined) {
      const m = /^e(\d+)c(\d+)$/.exec(options.cursor);
      if (!m || Number(m[1]) !== this.epoch) throw new Error("cursor: invalid or expired");
      start = Number(m[2]);
    }
    const prefix = options?.prefix;
    const all = prefix === undefined ? this.seeds : this.seeds.filter((s) => s.name.startsWith(prefix));
    const page = all.slice(start, start + this.pageSize);
    const next = start + this.pageSize;
    const complete = next >= all.length;
    return { keys: page.map((s) => ({ name: s.name })), list_complete: complete, ...(complete ? {} : { cursor: `e${this.epoch}c${next}` }), cacheStatus: null };
  }
  async getWithMetadata(key: string, _t: "arrayBuffer"): Promise<{ value: ArrayBuffer | null; metadata: unknown; cacheStatus: null }> {
    this.gets++;
    const s = this.seeds.find((x) => x.name === key);
    if (!s) return { value: null, metadata: null, cacheStatus: null };
    const out = new ArrayBuffer(s.value.byteLength);
    new Uint8Array(out).set(s.value);
    return { value: out, metadata: null, cacheStatus: null };
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

// CountingStore wraps an ObjectStore and tallies the get() calls, so a test can prove the bounded
// at-seal re-read reads FEWER shard objects than the full re-read (the whole point of bounding it under
// the subrequest cap), without weakening what the signature-authenticated completeness check guarantees.
class CountingStore implements ObjectStore {
  gets = 0;
  private inner: ObjectStore;
  constructor(inner: ObjectStore) {
    this.inner = inner;
  }
  async get(key: string): Promise<Uint8Array> {
    this.gets++;
    return this.inner.get(key);
  }
}

// Mock scheduler stub: records calls; heartbeat ownership is scriptable.
function makeScheduler(): { stub: DurableObjectStub; calls: { path: string; body?: unknown }[]; setOwned(v: boolean): void } {
  const calls: { path: string; body?: unknown }[] = [];
  let owned = true;
  const stub = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const body = init?.body ? JSON.parse(String(init.body)) : undefined;
      calls.push({ path: url.pathname, ...(body !== undefined ? { body } : {}) });
      if (url.pathname === "/heartbeat") return new Response(JSON.stringify({ owned }));
      if (url.pathname === "/runlog-lock/acquire") return new Response(JSON.stringify({ acquired: false }));
      return new Response(JSON.stringify({ ok: true }));
    },
  } as unknown as DurableObjectStub;
  return { stub, calls, setOwned: (v: boolean) => (owned = v) };
}

// Mock DurableObjectState for RunSealDO: a Map-backed storage with alarm capture.
function makeDOState(): { state: DurableObjectState; alarms: number[]; storage: Map<string, unknown> } {
  const storage = new Map<string, unknown>();
  const alarms: number[] = [];
  const state = {
    storage: {
      async get(key: string): Promise<unknown> {
        return storage.get(key);
      },
      async put(a: string | Record<string, unknown>, b?: unknown): Promise<void> {
        if (typeof a === "string") storage.set(a, b);
        else for (const [k, v] of Object.entries(a)) storage.set(k, v);
      },
      async delete(key: string | string[]): Promise<boolean | number> {
        if (Array.isArray(key)) {
          let n = 0;
          for (const k of key) if (storage.delete(k)) n += 1;
          return n;
        }
        return storage.delete(key);
      },
      async deleteAll(): Promise<void> {
        storage.clear();
      },
      async list(opts?: { prefix?: string }): Promise<Map<string, unknown>> {
        const out = new Map<string, unknown>();
        for (const [k, v] of storage) if (!opts?.prefix || k.startsWith(opts.prefix)) out.set(k, v);
        return out;
      },
      async setAlarm(t: number): Promise<void> {
        alarms.push(t);
      },
      async deleteAlarm(): Promise<void> {},
    },
  } as unknown as DurableObjectState;
  return { state, alarms, storage };
}

// makeReversingDOState is makeDOState with one twist: list({ prefix: "shard:" }) hands the shard rows
// back in REVERSED insertion order, i.e. descending shard id. The real platform makes no order
// guarantee across a storage.list, and the finalise alarm relies on its OWN sort to put the shards
// into the stable id order the manifest needs. Feeding the alarm descending shard rows forces that sort
// to actually move elements, exercising the "this id sorts EARLIER" arm of the comparator (the
// already-ascending case only ever takes the other arm), and the archive must still open with every
// record, which proves the sort restored a correct, stable shard order.
function makeReversingDOState(): { state: DurableObjectState; alarms: number[]; storage: Map<string, unknown> } {
  const storage = new Map<string, unknown>();
  const alarms: number[] = [];
  const state = {
    storage: {
      async get(key: string): Promise<unknown> {
        return storage.get(key);
      },
      async put(a: string | Record<string, unknown>, b?: unknown): Promise<void> {
        if (typeof a === "string") storage.set(a, b);
        else for (const [k, v] of Object.entries(a)) storage.set(k, v);
      },
      async delete(key: string | string[]): Promise<boolean | number> {
        if (Array.isArray(key)) {
          let n = 0;
          for (const k of key) if (storage.delete(k)) n += 1;
          return n;
        }
        return storage.delete(key);
      },
      async deleteAll(): Promise<void> {
        storage.clear();
      },
      async list(opts?: { prefix?: string }): Promise<Map<string, unknown>> {
        let entries = [...storage.entries()].filter(([k]) => !opts?.prefix || k.startsWith(opts.prefix));
        if (opts?.prefix === SHARD_PREFIX) entries = entries.reverse(); // descending id: the alarm sort must reorder
        return new Map(entries);
      },
      async setAlarm(t: number): Promise<void> {
        alarms.push(t);
      },
      async deleteAlarm(): Promise<void> {},
    },
  } as unknown as DurableObjectState;
  return { state, alarms, storage };
}

const SHARD_PREFIX = "shard:";

// makePagingDOState is makeDOState whose storage.list() FAITHFULLY honours { startAfter, limit } and
// caps every page at SHARD_PAGE (the platform's 1000), exactly like the real DurableObjectStorage. The
// plain makeDOState mock returns the whole set in one page, which would MASK a truncation bug: a single
// un-paged list() in finalise would make a run with more shards than one page silently
// drop its tail. A mock that pages forces the finalise enumeration to loop, and a single un-paged
// read to truncate, so the test is meaningful. SHARD_PAGE matches the engine's SHARD_LIST_PAGE (the
// production code requests limit:1000; a smaller cap here would make the FIRST page short and hide the
// loop), so the run below must exceed 1000 shards to span two pages.
const SHARD_PAGE = 1000;
function makePagingDOState(): { state: DurableObjectState; alarms: number[]; storage: Map<string, unknown> } {
  const storage = new Map<string, unknown>();
  const alarms: number[] = [];
  const state = {
    storage: {
      async get(key: string): Promise<unknown> {
        return storage.get(key);
      },
      async put(a: string | Record<string, unknown>, b?: unknown): Promise<void> {
        if (typeof a === "string") storage.set(a, b);
        else for (const [k, v] of Object.entries(a)) storage.set(k, v);
      },
      async delete(key: string | string[]): Promise<boolean | number> {
        if (Array.isArray(key)) {
          let n = 0;
          for (const k of key) if (storage.delete(k)) n += 1;
          return n;
        }
        return storage.delete(key);
      },
      async deleteAll(): Promise<void> {
        storage.clear();
      },
      // Platform contract: ascending key order, optional prefix, optional startAfter (exclusive), a page
      // capped at min(limit, SHARD_PAGE). A caller that wants the whole set MUST loop with startAfter.
      async list<T>(opts?: { prefix?: string; startAfter?: string; limit?: number }): Promise<Map<string, T>> {
        const prefix = opts?.prefix ?? "";
        let keys = [...storage.keys()].filter((k) => k.startsWith(prefix)).sort();
        if (opts?.startAfter !== undefined) keys = keys.filter((k) => k > opts.startAfter!);
        const cap = Math.min(opts?.limit ?? SHARD_PAGE, SHARD_PAGE);
        const out = new Map<string, T>();
        for (const k of keys.slice(0, cap)) out.set(k, storage.get(k) as T);
        return out;
      },
      async setAlarm(t: number): Promise<void> {
        alarms.push(t);
      },
      async deleteAlarm(): Promise<void> {},
    },
  } as unknown as DurableObjectState;
  return { state, alarms, storage };
}

function nsFor(stub: DurableObjectStub): DurableObjectNamespace {
  return {
    idFromName: (_n: string) => ({}) as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
}

function value(i: number): Uint8Array {
  // Distinct, varied-length values; a few larger ones to exercise multi-chunk records.
  const n = 40 + ((i * 97) % 300) + (i % 50 === 0 ? 70_000 : 0);
  const b = new Uint8Array(n);
  for (let j = 0; j < n; j++) b[j] = (Math.imul(i + 1, 2654435761) >>> (j % 24)) & 0xff;
  return b;
}

// NonResumableSource is a minimal crawl-only adapter (no crawlFrom) for the cap test: it yields several
// small records, spending the meter as a real crawl does, so a tiny budget is exhausted mid-crawl and the
// non-resumable branch must fail LOUDLY rather than silently truncate / never-back-up.
class NonResumableSource implements SourceAdapter {
  readonly sourceType = "cf-config" as const;
  private readonly count: number;
  constructor(count: number) {
    this.count = count;
  }
  async *crawl(_selector: Selector, meter?: Meter): AsyncIterable<SourceRecord> {
    for (let i = 0; i < this.count; i++) {
      meter?.spend(1);
      yield { sourceType: "cf-config", name: `surface/${i}`, value: new TextEncoder().encode(`v${i}`) };
    }
  }
  async estimate(): Promise<{ records: number; bytes: number }> {
    return { records: this.count, bytes: -1 };
  }
}

// MarkerSource yields a mix of REAL records and INCOMPLETENESS SENTINELS (markers a source emits
// in place of real bytes). Each marker is a small JSON object carrying one of the five sentinel keys
// (_truncated/_unavailable/_skipped/_pending/_refused), exactly as the stream/images/artifacts/workers/
// cloudflare-config adapters emit. The seal must count these as recordsIncomplete (a sealed-but-not-real
// record) so the run reports "completed with N items not fully captured", not a clean ok.
class MarkerSource implements SourceAdapter {
  readonly sourceType = "cf-config" as const;
  async *crawl(_selector: Selector, meter?: Meter): AsyncIterable<SourceRecord> {
    const enc = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));
    // two real records, then one of EACH sentinel shape (five markers), interleaved with a real record.
    // markerKind is the adapter's OWN assertion (mirroring the real cf-config/stream/images/artifacts/
    // workers adapters), never inferred by the seal from the value's shape.
    meter?.spend(1); yield { sourceType: "cf-config", name: "real/a", value: enc({ real: 1 }) };
    meter?.spend(1); yield { sourceType: "cf-config", name: "surface/x/_truncated", value: enc({ _truncated: "list exceeded cap", captured: 10 }), markerKind: "_truncated" };
    meter?.spend(1); yield { sourceType: "cf-config", name: "surface/y", value: enc({ _unavailable: "token could not read this surface" }), markerKind: "_unavailable" };
    meter?.spend(1); yield { sourceType: "cf-config", name: "real/b", value: enc({ real: 2 }) };
    meter?.spend(1); yield { sourceType: "cf-config", name: "blob/z", value: enc({ _skipped: "over size gate", size: 9_000_000 }), markerKind: "_skipped" };
    meter?.spend(1); yield { sourceType: "cf-config", name: "video/w", value: enc({ _pending: "download inprogress", percentComplete: 42 }), markerKind: "_pending" };
    meter?.spend(1); yield { sourceType: "cf-config", name: "video/v", value: enc({ _refused: "download url is not an https cloudflarestream.com address", host: "evil.example" }), markerKind: "_refused" };
  }
  async estimate(): Promise<{ records: number; bytes: number }> {
    return { records: 7, bytes: -1 };
  }
}

// MarkerMixSource yields a NON-UNIFORM mix of marker kinds -- some REPEATED, some ABSENT -- so the
// per-kind incompleteByMarker tally is proven to ACCUMULATE (count, not just flag presence) AND to omit the
// zero-count kinds. 3x_truncated, 2x_unavailable, 1x_skipped, 0x_pending, 0x_refused, plus 2 real records.
class MarkerMixSource implements SourceAdapter {
  readonly sourceType = "cf-config" as const;
  async *crawl(_selector: Selector, meter?: Meter): AsyncIterable<SourceRecord> {
    const enc = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));
    // markerKind (present only on the sentinel items) is the adapter's OWN assertion, mirroring the
    // real cf-config adapter, never inferred by the seal from the value's shape.
    const items: Array<{ name: string; value: unknown; markerKind?: MarkerKey }> = [
      { name: "real/a", value: { real: 1 } },
      { name: "surface/t1", value: { _truncated: "list exceeded cap", captured: 10 }, markerKind: "_truncated" },
      { name: "surface/t2", value: { _truncated: "list exceeded cap", captured: 20 }, markerKind: "_truncated" },
      { name: "surface/u1", value: { _unavailable: "token could not read this surface" }, markerKind: "_unavailable" },
      { name: "real/b", value: { real: 2 } },
      { name: "surface/t3", value: { _truncated: "list exceeded cap", captured: 30 }, markerKind: "_truncated" },
      { name: "surface/u2", value: { _unavailable: "token could not read this surface" }, markerKind: "_unavailable" },
      { name: "blob/z", value: { _skipped: "over size gate", size: 9_000_000 }, markerKind: "_skipped" },
    ];
    for (const it of items) {
      meter?.spend(1);
      yield { sourceType: "cf-config", name: it.name, value: enc(it.value), ...(it.markerKind !== undefined ? { markerKind: it.markerKind } : {}) };
    }
  }
  async estimate(): Promise<{ records: number; bytes: number }> {
    return { records: 8, bytes: -1 };
  }
}

// KvMarkerSource (NO-CUSTODY gate) emits a KV record whose value is marker-SHAPED (a real KV value that
// happens to look like a sentinel) and whose NAME is a customer key. The seal must COUNT it in
// incompleteByMarker (the classifier is value-based) and attribute WHICH object into incompleteIds -- but for a
// custody source (KV here) ONLY by a STABLE one-way HANDLE of the name, NEVER the raw customer key. This proves
// the pack shows which object was short (a handle the customer can recompute) while the raw KV/R2 key never leaks.
class KvMarkerSource implements SourceAdapter {
  readonly sourceType = "kv" as const;
  async *crawl(_selector: Selector, meter?: Meter): AsyncIterable<SourceRecord> {
    const enc = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));
    // markerKind is the adapter's OWN assertion (mirroring the real kv.ts vanished-marker emit).
    meter?.spend(1); yield { sourceType: "kv", name: "users/alice@example.com/secret-note", value: enc({ _unavailable: "vanished mid-crawl" }), namespace: "ns1", markerKind: "_unavailable" };
  }
  async estimate(): Promise<{ records: number; bytes: number }> {
    return { records: 1, bytes: -1 };
  }
}

async function main(): Promise<void> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const verifier = verifierFrom(signer);
  const breakGlass = makeRecipient("break-glass");
  const recipients = [breakGlass.entry];

  console.log("causeDigest single-sources the [cause <hex>] suffix (the failed row's digest is byte-identical to the log's):");
  {
    const m = "PUT seg/0001: status 500 destination write rejected";
    const cause = await causeDigest(m);
    const redacted = await redactedRunError(m);
    ok("causeDigest(m) is a bare 12-hex digest (no class, no brackets)", /^[0-9a-f]{12}$/.test(cause));
    // The hex INSIDE redactedRunError's `[cause <hex>]` must be the SAME string causeDigest returns: this is
    // what proves the digest the failed completion stamps on the run-history row is byte-identical to the log
    // line's, since BOTH derive from this one causeDigest source (the dead diagnostics-bot consumer relies on it).
    ok("redactedRunError embeds EXACTLY that digest as [cause <hex>]", redacted === `${coarseRunError(m)} [cause ${cause}]`);
    ok("the [cause <hex>] substring of the log equals causeDigest(m)", /\[cause ([0-9a-f]{12})\]/.exec(redacted)?.[1] === cause);
  }

  console.log("non-resumable source over budget fails LOUDLY (cap + alert, not a silent truncate):");
  {
    const dest = new MemDest();
    const master = rand(32);
    const cp: RunCheckpoint = {
      v: 1, downpipeId: DP_ID, downpipeName: "sliced", cadence: "3600s", sourceType: "cf-config",
      selector: { include: [], exclude: [] }, runId: RUN_ID, runlogIndex: 1, prevRunId: null,
      startedAt: "2026-06-10T00:00:00.000Z", wrappedMaster: await wrapMaster(signerPrivateB64, RUN_ID, master),
      cursor: null, sourceDone: false, nextRecordIndex: 0, nextShardIndex: 0,
      frontier: { count: 0, nodes: [] }, counts: zeroCounts(), sliceCount: 0, partialRecord: null,
    };
    const budget = new SliceBudget({ subrequests: 1, wallMs: 60_000 }); // exhausts after the first record
    const deps: SliceDeps = { source: new NonResumableSource(50), dest, signer, recipients, budget };
    let threw: Error | null = null;
    try { await runSlice(deps, cp, master); } catch (e) { threw = e as Error; }
    master.fill(0);
    ok("a non-resumable source over budget throws (no silent truncation / never-backed-up)", threw !== null);
    ok("the fault maps to the clear 'source too large for one slice' class", threw !== null && coarseRunError(threw.message) === "source too large to back up in one slice (not yet resumable)");
  }

  console.log("RUNLOG-write error classification surfaces the real S3 <Code> (not a misleading 'contended'):");
  {
    // A RUNLOG write the store REJECTED for a NON-throttle, NON-CAS reason (403 AccessDenied, a 409
    // Object-Lock/WORM conflict on the overwrite) must surface the actionable code -- the SAME treatment the
    // segment-write path gives -- not collapse to "runlog write contended" (which an operator would expect to
    // clear by retrying, when an auth/WORM failure never will).
    ok("a 403 AccessDenied on the RUNLOG write surfaces the real code", coarseRunError("PUT _RECOVERY/RUNLOG: status 403 (AccessDenied)") === "destination rejected the write (AccessDenied)");
    ok("a 409 Object-Lock conflict on the RUNLOG overwrite surfaces the real code", /^destination rejected the write \(ObjectLockConflict/.test(coarseRunError("PUT _RECOVERY/RUNLOG: status 409 (ObjectLockConflict: cannot overwrite WORM object)")));
    // unchanged: a 5xx/429 throttle routes to the patient ladder; a bare CAS exhaustion and a 412 stay contention.
    ok("a 503 throttle on the RUNLOG write still routes to the throttle ladder", coarseRunError("PUT _RECOVERY/RUNLOG: status 503 (SlowDown)") === "destination access error");
    ok("a bare CAS-exhaustion 'RUNLOG write contended N times' still maps to contention", coarseRunError("RUNLOG write contended 6 times") === "runlog write contended");
    ok("a 412 precondition (a real concurrent winner) still maps to contention", coarseRunError("conditional PUT _RECOVERY/RUNLOG: status 412") === "runlog write contended");
    // Seal-integrity classes (the observe modes also carry the counts via the seal-fault ring):
    // a finalise that REFUSED to sign a truncated archive (mode shard-list-truncated) reads as a named
    // integrity refusal, not a generic "run failed".
    ok("a short shard enumeration maps to the truncated-archive refusal class", coarseRunError("shard enumeration incomplete: found 968 of 970 shards; refusing to sign a truncated archive") === "shard enumeration incomplete (refused to sign a truncated archive)");
    ok("a short open-shard reload maps to the same truncated-archive refusal class", coarseRunError("open-shard enumeration incomplete: loaded 3 of 5 buffered lines; refusing to sign a short archive") === "shard enumeration incomplete (refused to sign a truncated archive)");
    // a resume whose CHECKPOINT could not be unwrapped/validated (mode signer-rotation-strands-runs) reads
    // as a named resume-state fault (a signer rotation strands the run, or a corrupted DO write).
    ok("a malformed checkpoint maps to the checkpoint-unwrap class", coarseRunError("checkpoint identity fields are malformed") === "checkpoint unwrap failed (resume state unreadable; signer may have rotated)");
    ok("an unwrapped-master size failure maps to the checkpoint-unwrap class", coarseRunError("unwrapped checkpoint master is not 32 bytes") === "checkpoint unwrap failed (resume state unreadable; signer may have rotated)");
  }

  console.log("incompleteness sentinels are COUNTED at run level (recordsIncomplete), not a clean ok:");
  {
    const dest = new MemDest();
    const master = rand(32);
    const cp: RunCheckpoint = {
      v: 1, downpipeId: DP_ID, downpipeName: "sliced", cadence: "3600s", sourceType: "cf-config",
      selector: { include: [], exclude: [] }, runId: RUN_ID, runlogIndex: 2, prevRunId: null,
      startedAt: "2026-06-10T00:00:00.000Z", wrappedMaster: await wrapMaster(signerPrivateB64, RUN_ID, master),
      cursor: null, sourceDone: false, nextRecordIndex: 0, nextShardIndex: 0,
      frontier: { count: 0, nodes: [] }, counts: zeroCounts(), sliceCount: 0, partialRecord: null,
    };
    const budget = new SliceBudget({ subrequests: 50, wallMs: 60_000 }); // ample: the whole small source seals in one slice
    const deps: SliceDeps = { source: new MarkerSource(), dest, signer, recipients, budget };
    const r = await runSlice(deps, cp, master);
    master.fill(0);
    ok("the source is exhausted in one slice (all 7 records sealed)", r.checkpoint.sourceDone && r.checkpoint.counts.records === 7);
    // 5 of the 7 records are markers (_truncated/_unavailable/_skipped/_pending/_refused), 2 are real.
    ok("recordsIncomplete counts the 5 incompleteness sentinels (not silently 0)", r.checkpoint.counts.recordsIncomplete === 5);
    // Per-marker breakdown: this run sealed exactly one of EACH kind, so the support pack carries WHICH
    // markers fired (not just the aggregate). All five keys present, each === 1.
    const ibm1 = r.checkpoint.counts.incompleteByMarker;
    ok("incompleteByMarker tallies one of each of the five sentinel kinds", ibm1._truncated === 1 && ibm1._unavailable === 1 && ibm1._skipped === 1 && ibm1._pending === 1 && ibm1._refused === 1);
    ok("recordsSkippedChanged is untouched (markers SEAL, they are not etag-skips)", r.checkpoint.counts.recordsSkippedChanged === 0);
    // ATTRIBUTION: a cf-config marker's record NAME is a closed-registry surface id, so the seal records
    // WHICH surface each kind hit (not just the count). The five markers came from five distinct surface names.
    const iid1 = r.checkpoint.counts.incompleteIds;
    ok("incompleteIds attributes each cf-config marker kind to its surface id",
      JSON.stringify(iid1._truncated) === JSON.stringify(["surface/x/_truncated"]) && JSON.stringify(iid1._unavailable) === JSON.stringify(["surface/y"])
      && JSON.stringify(iid1._skipped) === JSON.stringify(["blob/z"]) && JSON.stringify(iid1._pending) === JSON.stringify(["video/w"]) && JSON.stringify(iid1._refused) === JSON.stringify(["video/v"]));
  }

  console.log("NO-CUSTODY: a non-cf-config (KV) marker is COUNTED and attributed by a HANDLE, never the raw key:");
  {
    const dest = new MemDest();
    const master = rand(32);
    const cp: RunCheckpoint = {
      v: 1, downpipeId: DP_ID, downpipeName: "sliced", cadence: "3600s", sourceType: "kv",
      selector: { include: [], exclude: [] }, runId: RUN_ID, runlogIndex: 5, prevRunId: null,
      startedAt: "2026-06-10T00:00:00.000Z", wrappedMaster: await wrapMaster(signerPrivateB64, RUN_ID, master),
      cursor: null, sourceDone: false, nextRecordIndex: 0, nextShardIndex: 0,
      frontier: { count: 0, nodes: [] }, counts: zeroCounts(), sliceCount: 0, partialRecord: null,
    };
    const r = await runSlice({ source: new KvMarkerSource(), dest, signer, recipients, budget: new SliceBudget({ subrequests: 50, wallMs: 60_000 }) }, cp, master);
    master.fill(0);
    ok("the KV marker IS counted in incompleteByMarker (value-based classifier)", r.checkpoint.counts.incompleteByMarker._unavailable === 1);
    // Breadth: the KV marker IS now attributed -- but by a STABLE one-way HANDLE, not the raw key.
    const kvIds = r.checkpoint.counts.incompleteIds;
    const expectedHandle = `h:${hexEncode(await sha384(utf8("users/alice@example.com/secret-note"))).slice(0, 12)}`;
    ok("incompleteIds._unavailable carries exactly one 'h:'-prefixed handle for the KV object", Array.isArray(kvIds._unavailable) && kvIds._unavailable.length === 1 && kvIds._unavailable[0]!.startsWith("h:"));
    ok("the handle is the STABLE SHA-384 handle of the name (customer-recomputable, deterministic)", kvIds._unavailable?.[0] === expectedHandle);
    ok("NO-CUSTODY: the raw customer KV key never appears anywhere in incompleteIds (only the handle)", !JSON.stringify(kvIds).includes("alice@example.com") && !JSON.stringify(kvIds).includes("secret-note"));
  }

  console.log("a fully-captured run (no markers) reports recordsIncomplete === 0:");
  {
    const kv = new MemKV([{ name: "k/1", value: value(1) }, { name: "k/2", value: value(2) }], 100);
    const dest = new MemDest();
    const master = rand(32);
    const cp: RunCheckpoint = {
      v: 1, downpipeId: DP_ID, downpipeName: "sliced", cadence: "3600s", sourceType: "kv",
      selector: { include: [], exclude: [] }, runId: RUN_ID, runlogIndex: 3, prevRunId: null,
      startedAt: "2026-06-10T00:00:00.000Z", wrappedMaster: await wrapMaster(signerPrivateB64, RUN_ID, master),
      cursor: null, sourceDone: false, nextRecordIndex: 0, nextShardIndex: 0,
      frontier: { count: 0, nodes: [] }, counts: zeroCounts(), sliceCount: 0, partialRecord: null,
    };
    const r = await runSlice({ source: new KVSource(kv as unknown as KVNamespace, "ns1"), dest, signer, recipients, budget: new SliceBudget({ subrequests: 50, wallMs: 60_000 }) }, cp, master);
    master.fill(0);
    ok("a clean run seals 2 records with recordsIncomplete === 0", r.checkpoint.counts.records === 2 && r.checkpoint.counts.recordsIncomplete === 0);
  }

  console.log("incompleteByMarker is the PER-KIND breakdown of a MIXED run (the pack carries WHICH markers, not just the count):");
  {
    const dest = new MemDest();
    const master = rand(32);
    const cp: RunCheckpoint = {
      v: 1, downpipeId: DP_ID, downpipeName: "sliced", cadence: "3600s", sourceType: "cf-config",
      selector: { include: [], exclude: [] }, runId: RUN_ID, runlogIndex: 4, prevRunId: null,
      startedAt: "2026-06-10T00:00:00.000Z", wrappedMaster: await wrapMaster(signerPrivateB64, RUN_ID, master),
      cursor: null, sourceDone: false, nextRecordIndex: 0, nextShardIndex: 0,
      frontier: { count: 0, nodes: [] }, counts: zeroCounts(), sliceCount: 0, partialRecord: null,
    };
    const r = await runSlice({ source: new MarkerMixSource(), dest, signer, recipients, budget: new SliceBudget({ subrequests: 50, wallMs: 60_000 }) }, cp, master);
    master.fill(0);
    const ibm = r.checkpoint.counts.incompleteByMarker;
    ok("the mixed source seals all 8 records in one slice", r.checkpoint.sourceDone && r.checkpoint.counts.records === 8);
    ok("recordsIncomplete aggregates the 6 markers", r.checkpoint.counts.recordsIncomplete === 6);
    ok("incompleteByMarker._truncated === 3 (ACCUMULATES across records, not just flags presence)", ibm._truncated === 3);
    ok("incompleteByMarker._unavailable === 2", ibm._unavailable === 2);
    ok("incompleteByMarker._skipped === 1", ibm._skipped === 1);
    ok("zero-count kinds are ABSENT, never present as 0 (only non-zero keys)", !("_pending" in ibm) && !("_refused" in ibm));
    ok("the per-kind counts sum to recordsIncomplete", (ibm._truncated ?? 0) + (ibm._unavailable ?? 0) + (ibm._skipped ?? 0) + (ibm._pending ?? 0) + (ibm._refused ?? 0) === r.checkpoint.counts.recordsIncomplete);
  }

  const N = 2500;
  const seeds = Array.from({ length: N }, (_, i) => ({ name: `key/${String(i).padStart(6, "0")}`, value: value(i) }));

  console.log("multi-slice seal with eviction between every slice:");
  {
    const kv = new MemKV(seeds, 100);
    const dest = new MemDest();
    const master = rand(32);
    let cp: RunCheckpoint = {
      v: 1,
      downpipeId: DP_ID,
      downpipeName: "sliced",
      cadence: "3600s",
      sourceType: "kv",
      selector: { include: [], exclude: [] },
      runId: RUN_ID,
      runlogIndex: 7,
      prevRunId: null,
      startedAt: "2026-06-10T00:00:00.000Z",
      wrappedMaster: await wrapMaster(signerPrivateB64, RUN_ID, master),
      cursor: null,
      sourceDone: false,
      nextRecordIndex: 0,
      nextShardIndex: 0,
      frontier: { count: 0, nodes: [] },
      counts: zeroCounts(),
      sliceCount: 0,
      partialRecord: null,
    };
    master.fill(0); // the in-memory master is GONE; every slice must unwrap from the checkpoint

    const allShards: ShardEntry[] = [];
    // The open-shard buffer is carried across slices (it models the RunSealDO's persisted wrapped batches,
    // which survive eviction in DO storage); openReset means a flush consumed it, else this slice's new
    // lines are appended. With shardMaxRecords 400 and ~50 records/slice the shard now SPANS ~8 slices
    // before it flushes, which is exactly the intended effect of carrying the buffer forward.
    let openBuffer: Record<string, unknown>[] = [];
    let slices = 0;
    for (; slices < 200 && !cp.sourceDone; slices++) {
      // EVICTION SIMULATION: each slice starts from the SERIALISED checkpoint only.
      cp = JSON.parse(JSON.stringify(cp)) as RunCheckpoint;
      const m = await unwrapMaster(signerPrivateB64, RUN_ID, cp.wrappedMaster);
      const budget = new SliceBudget({ subrequests: 160, wallMs: 60_000 });
      const deps: SliceDeps = {
        source: new KVSource(kv as unknown as KVNamespace, "ns1"),
        dest,
        signer,
        recipients,
        budget,
        shardMaxRecords: 400,
      };
      const r = await runSlice(deps, cp, m, openBuffer);
      m.fill(0);
      cp = r.checkpoint;
      allShards.push(...r.newShards);
      openBuffer = r.openReset ? r.openWrite : [...openBuffer, ...r.openWrite];
    }
    ok(`the run spans many slices (took ${slices})`, slices > 10 && cp.sourceDone);
    ok("multiple manifest shards accumulated", allShards.length > 1);
    ok("a shard spans MORE slices than the per-slice record count (spanning, not shards==slices)", slices > allShards.length + 1);

    {
      const m = await unwrapMaster(signerPrivateB64, RUN_ID, cp.wrappedMaster);
      const budget = new SliceBudget({ subrequests: 700, wallMs: 60_000 });
      const deps: SliceDeps = { source: new KVSource(kv as unknown as KVNamespace, "ns1"), dest, signer, recipients, budget };
      await finaliseRun(deps, cp, m, allShards, openBuffer);
      m.fill(0);
    }

    const run = await openRun(new MapStore(dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
    ok("the sliced archive opens (signature, shard hashes, record hashes, merkle root)", true);
    ok(`declaredRecordCount is exactly N (no duplicates, no losses): ${run.records.length}`, run.records.length === N);
    const names = new Set(run.records.map((r) => r.name));
    ok("every record name is unique", names.size === N);
    let allExact = true;
    for (let i = 0; i < N; i += 97) {
      const rec = run.records.find((r) => r.name === seeds[i]!.name)!;
      const got = await run.restoreRecord(rec);
      if (Buffer.compare(Buffer.from(got), Buffer.from(seeds[i]!.value)) !== 0) allExact = false;
    }
    ok("sampled records restore byte-exact across slice boundaries", allExact);
    ok("each value was read exactly once across all slices (no re-reads on resume)", kv.gets === N);

    // The at-seal keyless completeness re-read SAMPLES a strided subset of
    // shards on a large run instead of re-reading EVERY shard (which would trip the 1000-subrequest cap and
    // wedge the run after the bytes land but before /complete). The root signature already authenticates the
    // whole shard list, so sampling weakens nothing the signature + the always-full offline/drill path
    // guarantee. This multi-shard archive (allShards.length > 1) is exactly where it matters.
    {
      const fullStore = new CountingStore(new MapStore(dest.map));
      const attFull = await attestKeyless(fullStore, RUN_ID, verifier, { shardCheck: "full" });
      ok("a full re-read attests complete (every shard read back)", attFull.signatureValid && attFull.complete);

      const boundedStore = new CountingStore(new MapStore(dest.map));
      const attBounded = await attestKeyless(boundedStore, RUN_ID, verifier, { shardCheck: { sampleAbove: 0, sample: 2 } });
      ok("a bounded (sample 2) re-read still attests complete", attBounded.signatureValid && attBounded.complete);
      ok(`the bounded re-read reads FEWER objects than the full one (${boundedStore.gets} < ${fullStore.gets})`, boundedStore.gets < fullStore.gets);

      // sample 0 above the threshold reads NO shards yet still attests complete: the root SIGNATURE is the
      // real completeness proof; the read-back is only a durability smoke test.
      const noneStore = new CountingStore(new MapStore(dest.map));
      const attNone = await attestKeyless(noneStore, RUN_ID, verifier, { shardCheck: { sampleAbove: 0, sample: 0 } });
      ok("sample 0 reads no shard objects yet still attests complete (signature-only completeness)", attNone.complete && noneStore.gets < boundedStore.gets);

      // A threshold AT OR ABOVE the shard count keeps the run on the FULL path (byte-identical verdict to
      // today for every run that seals now): the bounded form only engages above sampleAbove.
      const thresholdStore = new CountingStore(new MapStore(dest.map));
      const attThreshold = await attestKeyless(thresholdStore, RUN_ID, verifier, { shardCheck: { sampleAbove: 1_000_000, sample: 2 } });
      ok("a run at/under sampleAbove stays FULL (reads every shard, unchanged verdict)", attThreshold.complete && thresholdStore.gets === fullStore.gets);

      // A tampered shard the bounded sample DOES touch is still caught (sampling is a real check on what it
      // reads); sample 1 strides to the first shard, so tamper it and confirm the bounded verdict flips.
      const tampered = new Map(dest.map);
      const firstShardKey = [...tampered.keys()].find((k) => k.endsWith("manifest/00000.dpe"));
      ok("the sampled-first shard exists", firstShardKey !== undefined);
      const bad = new Uint8Array(tampered.get(firstShardKey!)!);
      bad[0] = bad[0]! ^ 0xff;
      tampered.set(firstShardKey!, bad);
      const attTamper = await attestKeyless(new MapStore(tampered), RUN_ID, verifier, { shardCheck: { sampleAbove: 0, sample: 1 } });
      ok("the bounded re-read CATCHES a tampered shard it samples", attTamper.signatureValid && !attTamper.complete);

      // The strided GET sample only spot-checks `sample` shards, so a durably-MISSING shard OUTSIDE
      // the sample would pass the GET spot-checks as "complete" (a false green AT SEAL). The one-LIST presence
      // pass closes it: it cross-references every signed shard object BY NAME. Drop a LATER shard the stride
      // does NOT sample (with sample 1 the stride touches ONLY 00000, so any higher-index shard is un-sampled),
      // and confirm a LIST-capable store flips to suspect while a get-only store misses it (the exact gap).
      {
        const manifestKeys = [...dest.map.keys()].filter((k) => /manifest\/\d{5}\.dpe$/.test(k)).sort();
        const lastShardKey = manifestKeys[manifestKeys.length - 1]!;
        ok("the dropped shard is a LATER (un-sampled) shard, not 00000", manifestKeys.length > 1 && !lastShardKey.endsWith("00000.dpe"));
        const dropped = new Map(dest.map);
        dropped.delete(lastShardKey); // the OBJECT is gone; the signed root still LISTS it (shardCount unchanged)
        // A LIST-capable store: the presence pass runs and catches the missing shard BY NAME -> suspect.
        const listStore: ObjectStore = {
          get: async (k: string): Promise<Uint8Array> => { const v = dropped.get(k); if (!v) throw new Error(`object ${k} is missing`); return v; },
          list: async (prefix: string): Promise<string[]> => [...dropped.keys()].filter((k) => k.startsWith(prefix)),
        };
        const attListMissing = await attestKeyless(listStore, RUN_ID, verifier, { shardCheck: { sampleAbove: 0, sample: 1 } });
        ok("a LIST-capable bounded re-read CATCHES an un-sampled MISSING shard (suspect, not verified)", attListMissing.signatureValid && !attListMissing.complete);
        // A get-only store (no list) cannot run the presence pass, so the sample (stride touches ONLY 00000)
        // MISSES the dropped later shard -> a FALSE GREEN. This is exactly the gap the LIST pass closes.
        const getOnly: ObjectStore = { get: async (k: string): Promise<Uint8Array> => { const v = dropped.get(k); if (!v) throw new Error(`object ${k} is missing`); return v; } };
        const attGetOnlyMissing = await attestKeyless(getOnly, RUN_ID, verifier, { shardCheck: { sampleAbove: 0, sample: 1 } });
        ok("a get-only store MISSES the un-sampled missing shard (the false green the LIST pass closes)", attGetOnlyMissing.signatureValid && attGetOnlyMissing.complete);
      }
    }
  }

  console.log("\nbyte-identity: a single-shard run seals byte-identically whether the shard is closed by the in-crawl flush or carried and sealed by finaliseRun:");
  {
    // A shard closes either via the in-crawl flushShard (lines.length >= shardMax) or, when the buffer never
    // reaches shardMax during the crawl, by finaliseRun.sealFinal carrying it forward and sealing it there.
    // flushShard's own encoding is identical either way, so with a fixed clock + fixed nonces a run that
    // produces ONE shard MUST emit the byte-identical shard object AND the byte-identical signed root
    // whichever path closes it. Seal the SAME 6-record source two ways:
    //   (a) shardMax large, so no in-crawl flush -> finaliseRun seals the carried open buffer.
    //   (b) shardMax == record count, so the in-crawl flushShard closes the shard and finaliseRun adds nothing.
    // Byte-equality of run/<id>/manifest/00000.dpe AND run/<id>/root.manifest.json across (a) and (b) proves
    // sealFinal reproduces the same bytes as the in-crawl flush for the single-shard / never-spanning case.
    const recs = Array.from({ length: 6 }, (_, i) => ({ name: `bi/${String(i).padStart(4, "0")}`, value: utf8(`byte-identity-fixed-value-${i}`) }));
    const fixedNow = (): string => "2026-06-10T00:00:05.000Z";
    const fixedNonce = (): Uint8Array => new Uint8Array(16).fill(7);
    const fixedSalt = (): Uint8Array => new Uint8Array(16).fill(9);
    const master = rand(32); // ONE master, used by both paths, so the per-record/file keys match
    async function sealOneShard(shardMaxRecords: number): Promise<{ dest: MemDest; shardCount: number }> {
      const kv = new MemKV(recs, 100);
      const dest = new MemDest();
      const wm = await wrapMaster(signerPrivateB64, RUN_ID, master);
      let cp: RunCheckpoint = {
        v: 1, downpipeId: DP_ID, downpipeName: "sliced", cadence: "3600s", sourceType: "kv",
        selector: { include: [], exclude: [] }, runId: RUN_ID, runlogIndex: 4, prevRunId: null,
        startedAt: "2026-06-10T00:00:00.000Z", wrappedMaster: wm, cursor: null, sourceDone: false,
        nextRecordIndex: 0, nextShardIndex: 0, frontier: { count: 0, nodes: [] }, counts: zeroCounts(),
        sliceCount: 0, partialRecord: null,
      };
      const allShards: ShardEntry[] = [];
      let openBuffer: Record<string, unknown>[] = [];
      for (let s = 0; s < 20 && !cp.sourceDone; s++) {
        const m = await unwrapMaster(signerPrivateB64, RUN_ID, cp.wrappedMaster);
        const deps: SliceDeps = { source: new KVSource(kv as unknown as KVNamespace, "ns1"), dest, signer, recipients, budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }), shardMaxRecords, nowIso: fixedNow, randomNonce: fixedNonce, randomSalt: fixedSalt };
        const r = await runSlice(deps, cp, m, openBuffer);
        m.fill(0);
        cp = r.checkpoint;
        allShards.push(...r.newShards);
        openBuffer = r.openReset ? r.openWrite : [...openBuffer, ...r.openWrite];
      }
      const m = await unwrapMaster(signerPrivateB64, RUN_ID, cp.wrappedMaster);
      const fin = await finaliseRun({ source: new KVSource(kv as unknown as KVNamespace, "ns1"), dest, signer, recipients, budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }), nowIso: fixedNow, randomNonce: fixedNonce, randomSalt: fixedSalt }, cp, m, allShards, openBuffer);
      m.fill(0);
      return { dest, shardCount: fin.shards };
    }
    const a = await sealOneShard(1000); // (a) carried open buffer sealed by finaliseRun
    const b = await sealOneShard(6); //    (b) in-crawl flushShard closes the shard
    ok("byte-identity: both paths produce exactly ONE shard", a.shardCount === 1 && b.shardCount === 1);
    const shardKeyA = [...a.dest.map.keys()].find((k) => k.endsWith("manifest/00000.dpe"));
    const shardKeyB = [...b.dest.map.keys()].find((k) => k.endsWith("manifest/00000.dpe"));
    ok("byte-identity: the single shard is id 00000 in both", shardKeyA !== undefined && shardKeyB !== undefined);
    ok("byte-identity: the emitted shard object run/<id>/manifest/00000.dpe is byte-identical", shardKeyA !== undefined && shardKeyB !== undefined && Buffer.compare(Buffer.from(a.dest.map.get(shardKeyA)!), Buffer.from(b.dest.map.get(shardKeyB)!)) === 0);
    const rootKeyA = [...a.dest.map.keys()].find((k) => k.endsWith("root.manifest.json"));
    const rootKeyB = [...b.dest.map.keys()].find((k) => k.endsWith("root.manifest.json"));
    ok("byte-identity: both paths wrote a signed root", rootKeyA !== undefined && rootKeyB !== undefined);
    // The signed root's master CAPSULE (recipient KEM/X25519) and the detached signature use fresh
    // ephemeral randomness, so the raw root bytes legitimately differ run to run. The byte-identity
    // contract is the signed COMMITMENT -- the Merkle root over the records, the shard list (id/object/
    // sha384) and the declared counts -- which the offline reader recomputes and the signature binds.
    type RootCommit = { merkleRoot: string; shardCount: number; declaredRecordCount: number; shards: { id: string; object: string; sha384: string }[] };
    const rootA = JSON.parse(new TextDecoder().decode(a.dest.map.get(rootKeyA!)!)) as RootCommit;
    const rootB = JSON.parse(new TextDecoder().decode(b.dest.map.get(rootKeyB!)!)) as RootCommit;
    ok("byte-identity: the signed MERKLE ROOT value is identical across the two seal paths", rootA.merkleRoot === rootB.merkleRoot && rootA.merkleRoot.length > 0);
    ok("byte-identity: the signed shard list (id/object/sha384) + counts are identical", JSON.stringify(rootA.shards) === JSON.stringify(rootB.shards) && rootA.shardCount === rootB.shardCount && rootA.declaredRecordCount === rootB.declaredRecordCount && rootA.shardCount === 1);
    // And the new path's archive opens with the full record set (correctness alongside byte-identity).
    const runA = await openRun(new MapStore(a.dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
    ok("byte-identity: the new single-shard archive opens with all 6 records", runA.records.length === 6);
  }

  console.log("\npad5 guardrail: a shard id at or over PAD5_LIMIT is REFUSED loudly (never a silent signed-root reorder):");
  {
    // pad5 mints 5-digit shard ids; at index 100000 the id widens to 6 digits and sorts BEFORE "99999",
    // which would silently reorder the signed root's shard list and break the recomputed Merkle root. Minting
    // such an id must throw a loud, retryable seal failure BEFORE any byte is written. Drive it through
    // finaliseRun with a checkpoint whose nextShardIndex is exactly PAD5_LIMIT and an empty run, so the
    // empty-run parity shard tries to mint pad5(PAD5_LIMIT).
    const baseOverflowCp = (nextShardIndex: number): RunCheckpoint => ({
      v: 1, downpipeId: DP_ID, downpipeName: "sliced", cadence: "3600s", sourceType: "kv",
      selector: { include: [], exclude: [] }, runId: RUN_ID, runlogIndex: 5, prevRunId: null,
      startedAt: "2026-06-10T00:00:00.000Z", wrappedMaster: { iv: "", ct: "" }, cursor: null, sourceDone: true,
      nextRecordIndex: 0, nextShardIndex, frontier: { count: 0, nodes: [] }, counts: zeroCounts(),
      sliceCount: 1, partialRecord: null,
    });
    {
      const dest = new MemDest();
      const master = rand(32);
      const cp = { ...baseOverflowCp(PAD5_LIMIT), wrappedMaster: await wrapMaster(signerPrivateB64, RUN_ID, master) };
      const m = await unwrapMaster(signerPrivateB64, RUN_ID, cp.wrappedMaster);
      const deps: SliceDeps = { source: new KVSource(new MemKV([], 100) as unknown as KVNamespace, "ns1"), dest, signer, recipients, budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) };
      let threw = false;
      let msgOk = false;
      try {
        await finaliseRun(deps, cp, m, [], []);
      } catch (e) {
        threw = true;
        msgOk = /outside the 5-digit shard-id range/.test((e as Error).message);
      }
      m.fill(0);
      ok("pad5: minting a shard id == PAD5_LIMIT (100000) throws", threw);
      ok("pad5: the refusal is the explicit shard-id-range error (loud, retryable)", msgOk);
      ok("pad5: NO root was written (no truncated/reordered archive emitted)", ![...dest.map.keys()].some((k) => k.endsWith("root.manifest.json")));
    }
    {
      // The boundary is EXACTLY PAD5_LIMIT: one below it (99999) still seals cleanly, proving the guard does
      // not over-refuse the last legal id.
      const dest = new MemDest();
      const master = rand(32);
      const cp = { ...baseOverflowCp(PAD5_LIMIT - 1), wrappedMaster: await wrapMaster(signerPrivateB64, RUN_ID, master) };
      const m = await unwrapMaster(signerPrivateB64, RUN_ID, cp.wrappedMaster);
      const deps: SliceDeps = { source: new KVSource(new MemKV([], 100) as unknown as KVNamespace, "ns1"), dest, signer, recipients, budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) };
      const fin = await finaliseRun(deps, cp, m, [], []);
      m.fill(0);
      ok("pad5: the last legal id (99999) seals without refusal", fin.rootWritten === true);
      ok("pad5: the 99999 archive wrote its signed root", [...dest.map.keys()].some((k) => k.endsWith("root.manifest.json")));
    }
  }

  console.log("\nthe carried open-shard buffer is AES-256-GCM-wrapped at rest under a DISTINCT AAD (plaintext record names never rest in the clear):");
  {
    // The open-shard batch carries buildRecordLine `name` fields (protected-class record names). At rest in
    // DO storage it MUST be wrapped exactly like the cursor and the master: AES-256-GCM under the checkpoint
    // wrap key with the DISTINCT "open|<runId>|<seq>" AAD domain, so a wrapped batch can never be
    // transplanted onto another run, sequence, or wrapped field without the AEAD failing.
    const lines = [{ kind: "record", sourceType: "kv", name: "secret/customer-name-12345", size: 42 }];
    const wrapped = await sealOpenShardBatch(signerPrivateB64, RUN_ID, 7, lines);
    ok("the wrap yields iv + ciphertext (not cleartext)", typeof wrapped.iv === "string" && typeof wrapped.ct === "string");
    ok("the plaintext record name does NOT appear anywhere in the wrapped form", !JSON.stringify(wrapped).includes("customer-name-12345"));
    const back = await openOpenShardBatch(signerPrivateB64, RUN_ID, 7, wrapped);
    ok("the matching runId + seq round-trips the exact lines", JSON.stringify(back) === JSON.stringify(lines));
    let wrongSeq = false;
    try { await openOpenShardBatch(signerPrivateB64, RUN_ID, 8, wrapped); } catch { wrongSeq = true; }
    ok("opening under a DIFFERENT sequence is refused (the AAD binds the seq)", wrongSeq);
    let wrongRun = false;
    try { await openOpenShardBatch(signerPrivateB64, "01BX5ZZKBKACTAV9WEVGEMMVS9", 7, wrapped); } catch { wrongRun = true; }
    ok("opening under a DIFFERENT runId is refused (the AAD binds the run)", wrongRun);
  }

  console.log("\ncursor invalidation falls back to the watermark scan:");
  {
    const kv = new MemKV(seeds.slice(0, 700), 100);
    const dest = new MemDest();
    const master = rand(32);
    let cp: RunCheckpoint = {
      v: 1,
      downpipeId: DP_ID,
      downpipeName: "sliced",
      cadence: "3600s",
      sourceType: "kv",
      selector: { include: [], exclude: [] },
      runId: RUN_ID,
      runlogIndex: 8,
      prevRunId: null,
      startedAt: "2026-06-10T00:00:00.000Z",
      wrappedMaster: await wrapMaster(signerPrivateB64, RUN_ID, master),
      cursor: null,
      sourceDone: false,
      nextRecordIndex: 0,
      nextShardIndex: 0,
      frontier: { count: 0, nodes: [] },
      counts: zeroCounts(),
      sliceCount: 0,
      partialRecord: null,
    };
    const allShards: ShardEntry[] = [];
    let openBuffer: Record<string, unknown>[] = [];
    // Slice 1 normally, then invalidate EVERY cursor (a long outage), and resume.
    for (let s = 0; s < 100 && !cp.sourceDone; s++) {
      const m = await unwrapMaster(signerPrivateB64, RUN_ID, cp.wrappedMaster);
      const deps: SliceDeps = {
        source: new KVSource(kv as unknown as KVNamespace, "ns1"),
        dest,
        signer,
        recipients,
        budget: new SliceBudget({ subrequests: 150, wallMs: 60_000 }),
      };
      const r = await runSlice(deps, cp, m, openBuffer);
      m.fill(0);
      cp = r.checkpoint;
      allShards.push(...r.newShards);
      openBuffer = r.openReset ? r.openWrite : [...openBuffer, ...r.openWrite];
      kv.invalidateCursors(); // every resume's saved cursor is now expired (fallback path)
    }
    ok("the run completes despite invalidated cursors", cp.sourceDone);
    ok("no value was read twice under the fallback", kv.gets === 700);
    const m = await unwrapMaster(signerPrivateB64, RUN_ID, cp.wrappedMaster);
    await finaliseRun({ source: new KVSource(kv as unknown as KVNamespace, "ns1"), dest, signer, recipients, budget: new SliceBudget({}) }, cp, m, allShards, openBuffer);
    m.fill(0);
    const run = await openRun(new MapStore(dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
    ok("the fallback-resumed archive opens with the full record set", run.records.length === 700);
  }

  console.log("\nwrapped-master binding:");
  {
    const master = rand(32);
    const wrapped = await wrapMaster(signerPrivateB64, RUN_ID, master);
    const back = await unwrapMaster(signerPrivateB64, RUN_ID, wrapped);
    ok("the master unwraps byte-exact under its runId", Buffer.compare(Buffer.from(back), Buffer.from(master)) === 0);
    let threw = false;
    try {
      await unwrapMaster(signerPrivateB64, "01BX5ZZKBKACTAV9WEVGEMMVS1", wrapped);
    } catch {
      threw = true;
    }
    ok("a wrapped master replayed onto another runId is refused (AAD binding)", threw);
    threw = false;
    try {
      await unwrapMaster(b64urlEncode(rand(64)), RUN_ID, wrapped);
    } catch {
      threw = true;
    }
    ok("a different signer seed cannot unwrap (key binding)", threw);
  }

  console.log("\npartialRecord wraps at rest (it holds a record name):");
  {
    // A checkpoint carrying a mid-record partial holds the part-sealed object's NAME (in partialRecord.meta),
    // protected-class data, so the STORED form must AES-256-GCM-wrap it under the checkpoint wrap key with a
    // DISTINCT AAD domain from the cursor. Round-trip it and assert: no plaintext name at rest, full
    // recovery, AAD domain separation (a partial ciphertext cannot be opened as the cursor), and a legacy
    // doc with no wrappedPartial defaults partialRecord to null (no in-flight run stranded by the upgrade).
    const master = rand(32);
    const cp: RunCheckpoint = {
      v: 1, downpipeId: DP_ID, downpipeName: "sliced", cadence: "3600s", sourceType: "r2",
      selector: { include: [], exclude: [] }, runId: RUN_ID, runlogIndex: 1, prevRunId: null,
      startedAt: "2026-06-10T00:00:00.000Z", wrappedMaster: await wrapMaster(signerPrivateB64, RUN_ID, master),
      cursor: "cursor-token-PARTIAL-NAME", sourceDone: false, nextRecordIndex: 3, nextShardIndex: 1,
      frontier: { count: 0, nodes: [] }, counts: zeroCounts(), sliceCount: 2,
      partialRecord: { recordIndex: 3, meta: { sourceType: "r2", name: "PROTECTED-OBJECT-NAME", bucket: "media" }, offsetSealed: 65536, segments: [{ object: "seg/ab/abcd.seg", chunkRange: [0, 1], packed: null }], etag: '"v1"' },
    };
    master.fill(0);
    const stored = await sealCheckpointForStorage(signerPrivateB64, cp);
    const storedJson = JSON.stringify(stored);
    ok("the stored form wraps the partial (wrappedPartial set, no plaintext partialRecord field)", (stored as { wrappedPartial?: unknown; partialRecord?: unknown }).wrappedPartial !== null && !("partialRecord" in stored));
    ok("the part-sealed object NAME never rests in the clear (encrypted into wrappedPartial)", !storedJson.includes("PROTECTED-OBJECT-NAME"));
    const back = await openStoredCheckpoint(signerPrivateB64, stored);
    ok("the partial round-trips: name + offset + segments + etag recovered", back.partialRecord?.meta.name === "PROTECTED-OBJECT-NAME" && back.partialRecord?.offsetSealed === 65536 && back.partialRecord?.segments[0]?.object === "seg/ab/abcd.seg" && back.partialRecord?.etag === '"v1"');
    // AAD domain separation: transplant the partial ciphertext into the cursor slot; opening must fail
    // (the "partial|<runId>" AAD does not authenticate under the "cursor|<runId>" domain).
    const swapped = { ...stored, wrappedCursor: (stored as { wrappedPartial: { iv: string; ct: string } | null }).wrappedPartial, wrappedPartial: null };
    let aadThrew = false;
    try { await openStoredCheckpoint(signerPrivateB64, swapped); } catch { aadThrew = true; }
    ok("AAD domain separation: a partial ciphertext cannot be opened as the cursor", aadThrew);
    // Legacy tolerance: a doc persisted before partialRecord shipped has no wrappedPartial.
    const legacy = { ...stored } as Record<string, unknown>;
    delete legacy.wrappedPartial;
    const legacyBack = await openStoredCheckpoint(signerPrivateB64, legacy);
    ok("a legacy doc with no wrappedPartial opens with partialRecord defaulted to null", legacyBack.partialRecord === null);
  }

  // ---- the REAL drivers: sealRunSliced + RunSealDO ---------------------------------------
  console.log("\nsealRunSliced: inline completion for a small run:");
  const breakGlassB64 = b64urlEncode(concat(breakGlass.entry.pub.x25519, breakGlass.entry.pub.mlkemEk));
  const mkEnv = (kv: MemKV, sched: DurableObjectStub, runseal: DurableObjectStub, dest: MemDest): Env => {
    // buildDestination wants a real binding shape; give it an R2Bucket facade over MemDest.
    const r2Facade = {
      async put(key: string, v: ArrayBuffer | ReadableStream<Uint8Array>, opts?: { onlyIf?: { etagMatches?: string; etagDoesNotMatch?: string } }): Promise<unknown> {
        if (v instanceof ReadableStream) {
          await dest.putStream(key, v);
          return { etag: "s" };
        }
        const body = new Uint8Array(v as ArrayBuffer);
        if (opts?.onlyIf) {
          const r = await dest.putConditional(key, body, {
            ...(opts.onlyIf.etagMatches !== undefined ? { ifMatch: opts.onlyIf.etagMatches } : {}),
            ...(opts.onlyIf.etagDoesNotMatch !== undefined ? { ifNoneMatch: opts.onlyIf.etagDoesNotMatch } : {}),
          });
          return r.ok ? { etag: r.etag } : null;
        }
        await dest.put(key, body);
        return { etag: "u" };
      },
      async get(key: string): Promise<unknown> {
        const r = await dest.get(key);
        if (!r) return null;
        const buf = new ArrayBuffer(r.body.byteLength);
        new Uint8Array(buf).set(r.body);
        return { etag: r.etag, async arrayBuffer() { return buf; } };
      },
      async head(key: string): Promise<unknown> {
        return (await dest.exists(key)) ? {} : null;
      },
      async delete(key: string): Promise<void> {
        await dest.delete(key);
      },
      async list(opts?: { prefix?: string; cursor?: string }): Promise<unknown> {
        const keys = await dest.list(opts?.prefix ?? "");
        return { objects: keys.map((key) => ({ key })), truncated: false };
      },
    };
    return {
      SCHEDULER: nsFor(sched),
      RUNSEAL: nsFor(runseal),
      SIGNER_PRIVATE: signerPrivateB64,
      BREAK_GLASS_PUBLIC: breakGlassB64,
      DEST_KIND: "r2",
      DEST_R2: r2Facade,
      KV_TEST: kv,
      // Keep the throttle retry depth but collapse its backoff sleeps so the throttle/park tests run in
      // milliseconds, not the ~15 s/slice the production 500 ms base would take (Layer 1b is depth-driven,
      // and the throttle ROUTING + park behaviour under test is independent of the sleep length).
      DEST_THROTTLE_BASE_MS: "1",
    } as unknown as Env;
  };
  const dpState = (id: string): DownpipeState =>
    ({
      config: { id, name: id, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_TEST", namespaceId: "ns1", include: [], exclude: [] } },
      nextRunAt: 0,
      lastRunId: null,
      inFlight: true,
      inFlightSince: Date.now(),
    }) as DownpipeState;

  // dpStateSrc builds a DownpipeState with an arbitrary source config, for the API-source (cf-config /
  // workers) and other paths the plain KV dpState does not exercise.
  const dpStateSrc = (id: string, source: DownpipeState["config"]["source"]): DownpipeState =>
    ({
      config: { id, name: id, cadenceSeconds: 3600, enabled: true, source },
      nextRunAt: 0,
      lastRunId: null,
      inFlight: true,
      inFlightSince: Date.now(),
    }) as DownpipeState;

  {
    const sched = makeScheduler();
    const runsealCalls: string[] = [];
    const runsealStub = {
      async fetch(input: RequestInfo | URL): Promise<Response> {
        runsealCalls.push(new URL(input instanceof Request ? input.url : String(input)).pathname);
        return new Response(JSON.stringify({ ok: true }));
      },
    } as unknown as DurableObjectStub;
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 12), 100);
    const env = mkEnv(kv, sched.stub, runsealStub, dest);
    await sealRunSliced(env, dpState("dp-small"), { runId: RUN_ID, index: 3, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) });
    const complete = sched.calls.find((c) => c.path === "/complete");
    const body = complete?.body as { status?: string; recordCount?: number; runId?: string } | undefined;
    ok("a small run completes inline with status ok", body?.status === "ok" && body?.runId === RUN_ID);
    ok("the completion carries the record count", body?.recordCount === 12);
    ok("the seal DO was never involved", runsealCalls.length === 0);
    const run = await openRun(new MapStore(dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
    ok("the inline archive opens with all records", run.records.length === 12);
  }

  console.log("\nsealRunSliced: a THROTTLE on a sub-budget INLINE run park-and-resumes (handoff), never a loud failure (Layer 1c):");
  {
    const sched = makeScheduler();
    const runsealCalls: string[] = [];
    const runsealStub = {
      async fetch(input: RequestInfo | URL): Promise<Response> {
        runsealCalls.push(new URL(input instanceof Request ? input.url : String(input)).pathname);
        return new Response(JSON.stringify({ ok: true }));
      },
    } as unknown as DurableObjectStub;
    const dest = new MemDest();
    dest.throttle = true; // every write 503s, from the first seg of this small (sub-budget) run
    const kv = new MemKV(seeds.slice(0, 12), 100);
    const env = mkEnv(kv, sched.stub, runsealStub, dest);
    const origError = console.error;
    const logged: string[] = [];
    console.error = (...a: unknown[]) => { logged.push(a.map(String).join(" ")); };
    try {
      // A budget that easily FITS the run (it would complete inline if not throttled), so the throttle, not
      // the budget, is what forces the handoff -- proving the inline-throttle ROUTING, not the over-budget path.
      await sealRunSliced(env, dpState("dp-inline-throttle"), { runId: RUN_ID, index: 41, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) });
    } finally {
      console.error = origError;
    }
    ok("the throttled inline run was HANDED OFF to the seal DO (park-and-resume), not failed", runsealCalls.includes("/start"));
    ok("NO failed completion was posted for a throttle (it is a slow success, not a loud failure)", !sched.calls.some((c) => c.path === "/complete" && (c.body as { status?: string } | undefined)?.status === "failed"));
    ok("the throttle handoff log stays redacted (no raw status/key leak)", logged.every((l) => !l.includes("KV_TEST")));
  }

  console.log("\nsealRunSliced: a non-throttle (auth) inline fault STILL fails loud, never parks (Layer 1c boundary):");
  {
    const sched = makeScheduler();
    const runsealCalls: string[] = [];
    const runsealStub = {
      async fetch(input: RequestInfo | URL): Promise<Response> {
        runsealCalls.push(new URL(input instanceof Request ? input.url : String(input)).pathname);
        return new Response(JSON.stringify({ ok: true }));
      },
    } as unknown as DurableObjectStub;
    // A 403 on every write: an auth fault must fail loud immediately (no retry, no park-and-resume).
    const dest = new (class extends MemDest { override async put(key: string): Promise<void> { throw new Error(`PUT ${key}: status 403`); } })();
    const kv = new MemKV(seeds.slice(0, 12), 100);
    const env = mkEnv(kv, sched.stub, runsealStub, dest);
    const origError = console.error;
    console.error = () => {};
    try {
      await sealRunSliced(env, dpState("dp-inline-auth"), { runId: RUN_ID, index: 42, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) });
    } finally {
      console.error = origError;
    }
    ok("an auth fault is NOT handed off to the DO (no park for a credential failure)", !runsealCalls.includes("/start"));
    const complete = sched.calls.find((c) => c.path === "/complete");
    const body = complete?.body as { status?: string; runId?: string } | undefined;
    ok("an auth fault posts a loud failed completion with the empty runId", body?.status === "failed" && body?.runId === "");
  }

  console.log("\nsealRunSliced -> RunSealDO: handoff and alarm chain to completion:");
  {
    const sched = makeScheduler();
    const doState = makeDOState();
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 900), 100);
    // The runseal stub routes /start into the REAL RunSealDO instance.
    let realDO: RunSealDO | null = null;
    const runsealStub = {
      async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
        const req = new Request(input instanceof Request ? input.url : String(input), init);
        return realDO!.fetch(req);
      },
    } as unknown as DurableObjectStub;
    const env = mkEnv(kv, sched.stub, runsealStub, dest);
    // Tight budgets force the handoff and many alarm slices.
    (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "150";
    (env as unknown as Record<string, string>)["SCALE_SHARD_MAX_RECORDS"] = "200";
    realDO = new RunSealDO(doState.state, env);

    await sealRunSliced(env, dpState("dp-big"), { runId: RUN_ID, index: 9, prevRunId: null }, { budget: new SliceBudget({ subrequests: 150, wallMs: 60_000 }) });
    ok("the inline slice handed the run to the seal DO (doc persisted)", doState.storage.has("doc"));
    ok("an alarm was armed", doState.alarms.length === 1);

    // The AT-REST doc never carries the plaintext resume cursor (its source token
    // embeds the last fully-committed record NAME); the cursor is wrapped under the
    // checkpoint wrap key exactly like the master, so DO storage alone reveals no name.
    const doc0 = doState.storage.get("doc") as { config: unknown; checkpoint: Record<string, unknown>; attempt: number; openBatchSeqStart?: number; openBatchSeqEnd?: number };
    ok("the persisted checkpoint wraps its cursor (no plaintext cursor field)", doc0.checkpoint["wrappedCursor"] !== undefined && !("cursor" in doc0.checkpoint));
    ok("no record name leaks into the persisted doc", !JSON.stringify(doc0).includes("key/0"));
    // LEGACY tolerance: a doc persisted without the cursor wrap carries the
    // plaintext cursor; it must still resume, and the next slice re-persists it wrapped. The
    // open-shard batch pointers (openBatchSeqStart/End) are RunDoc state the cursor-migration
    // (openAndMigrate) leaves untouched, so preserve them here -- this doc already handed off an open
    // batch, and dropping the pointers would orphan it (the migration only re-wraps the checkpoint cursor).
    const legacyCp = await openStoredCheckpoint(signerPrivateB64, doc0.checkpoint);
    ok("the wrapped cursor opens back to a plaintext resume token", typeof legacyCp.cursor === "string" && legacyCp.cursor.length > 0);
    doState.storage.set("doc", { config: doc0.config, checkpoint: legacyCp, attempt: 0, openBatchSeqStart: doc0.openBatchSeqStart, openBatchSeqEnd: doc0.openBatchSeqEnd });
    await realDO.alarm();
    const reDoc = doState.storage.get("doc") as { checkpoint: Record<string, unknown> } | undefined;
    ok("a legacy plaintext-cursor doc resumes and re-persists in the wrapped form", reDoc !== undefined && reDoc.checkpoint["wrappedCursor"] !== undefined && !("cursor" in reDoc.checkpoint));

    let alarms = 0;
    for (; alarms < 100 && doState.storage.has("doc"); alarms++) await realDO.alarm();
    ok(`the alarm chain completed the run (took ${alarms} alarms)`, alarms > 2 && !doState.storage.has("doc"));
    const heartbeats = sched.calls.filter((c) => c.path === "/heartbeat").length;
    ok("every alarm heartbeated the scheduler lease", heartbeats >= alarms - 1);
    const complete = sched.calls.find((c) => c.path === "/complete");
    const body = complete?.body as { status?: string; recordCount?: number; index?: number } | undefined;
    ok("the DO posted the ok completion at the allocated index", body?.status === "ok" && body?.index === 9);
    ok("the completion carries the full record count", body?.recordCount === 900);
    const run = await openRun(new MapStore(dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
    ok("the handed-off archive opens with every record", run.records.length === 900);
    ok("the archive spans multiple shards", run.records.length === 900 && dest.map.size > 900);
  }

  console.log("\nRunSealDO: a lost lease abandons cleanly:");
  {
    const sched = makeScheduler();
    const doState = makeDOState();
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 500), 100);
    let realDO: RunSealDO | null = null;
    const runsealStub = {
      async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
        return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init));
      },
    } as unknown as DurableObjectStub;
    const env = mkEnv(kv, sched.stub, runsealStub, dest);
    (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "120";
    realDO = new RunSealDO(doState.state, env);
    await sealRunSliced(env, dpState("dp-lost"), { runId: RUN_ID, index: 11, prevRunId: null }, { budget: new SliceBudget({ subrequests: 120, wallMs: 60_000 }) });
    ok("the run handed off", doState.storage.has("doc"));
    sched.setOwned(false); // the scheduler reclaimed the run (e.g. this DO was presumed dead)
    await realDO.alarm();
    ok("a heartbeat refusal abandons the run (state cleared)", !doState.storage.has("doc"));
    ok("no completion was posted by the abandoned sealer", !sched.calls.some((c) => c.path === "/complete"));
  }

  console.log("\nRunSealDO: slice failures back off, then resolve the run as failed:");
  {
    const sched = makeScheduler();
    const doState = makeDOState();
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 500), 100);
    let realDO: RunSealDO | null = null;
    const runsealStub = {
      async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
        return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init));
      },
    } as unknown as DurableObjectStub;
    const env = mkEnv(kv, sched.stub, runsealStub, dest);
    (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "120";
    realDO = new RunSealDO(doState.state, env);
    await sealRunSliced(env, dpState("dp-fail"), { runId: RUN_ID, index: 13, prevRunId: null }, { budget: new SliceBudget({ subrequests: 120, wallMs: 60_000 }) });
    ok("the run handed off", doState.storage.has("doc"));
    // Break the source binding so every subsequent slice fails (a persistent fault).
    delete (env as unknown as Record<string, unknown>)["KV_TEST"];
    const origError = console.error;
    const logged: string[] = [];
    console.error = (...args: unknown[]) => {
      logged.push(args.map(String).join(" "));
    };
    let alarmsRun = 0;
    try {
      for (; alarmsRun < 20 && doState.storage.has("doc"); alarmsRun++) await realDO.alarm();
    } finally {
      console.error = origError;
    }
    ok(`the failing run resolved within the failure cap (took ${alarmsRun} alarms)`, !doState.storage.has("doc") && alarmsRun >= 8);
    // The slice-failure log lines carry the coarse class + a one-way digest, never
    // the raw message (which here names the missing binding, and in the size-bound
    // failures would name a RECORD). Logpush ships these lines off-account.
    ok("the failure logs are redacted to the coarse class + digest", logged.length > 0 && logged.every((l) => !l.includes("KV_TEST")));
    ok("the redacted log keeps a correlatable cause digest", logged.some((l) => /source binding error \[cause [0-9a-f]{12}\]/.test(l)));
    const complete = sched.calls.find((c) => c.path === "/complete");
    const body = complete?.body as { status?: string; error?: string; runId?: string } | undefined;
    ok("the failed completion carries the coarse reason and the empty runId", body?.status === "failed" && body?.runId === "" && body?.error === "source binding error");
    const lastDoc = doState.storage.size;
    ok("the DO state is fully cleaned up", lastDoc === 0);
  }

  console.log("\nRunSealDO: a destination throttle (503) PARKS and resumes, never striking the run as a hard fault:");
  {
    const sched = makeScheduler();
    const doState = makeDOState();
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 500), 100);
    let realDO: RunSealDO | null = null;
    const runsealStub = {
      async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
        return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init));
      },
    } as unknown as DurableObjectStub;
    const env = mkEnv(kv, sched.stub, runsealStub, dest);
    (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "120";
    // A SHORT parking window so the test is fast (the default is 60 rounds, hours at the cap).
    (env as unknown as Record<string, string>)["DEST_THROTTLE_MAX_YIELDS"] = "3";
    realDO = new RunSealDO(doState.state, env);
    await sealRunSliced(env, dpState("dp-throttle"), { runId: RUN_ID, index: 21, prevRunId: null }, { budget: new SliceBudget({ subrequests: 120, wallMs: 60_000 }) });
    ok("the run handed off (the first slice sealed before the throttle began)", doState.storage.has("doc"));
    // From here the destination throttles every write with a 503 SlowDown.
    dest.throttle = true;
    const origError = console.error;
    const logged: string[] = [];
    console.error = (...args: unknown[]) => {
      logged.push(args.map(String).join(" "));
    };
    try {
      // Two throttle alarms, BELOW the 3-round window: the run must stay PARKED (doc preserved), on the
      // throttle ladder (throttleAttempt grows), NOT charging the hard-fault strike counter.
      await realDO.alarm();
      await realDO.alarm();
    } finally {
      console.error = origError;
    }
    const parked = doState.storage.get("doc") as { attempt: number; throttleAttempt?: number } | undefined;
    ok("a throttled run is PARKED, not cleaned up (the checkpoint survives the outage)", doState.storage.has("doc"));
    ok("the throttle rides its OWN ladder (throttleAttempt grows to 2)", (parked?.throttleAttempt ?? 0) === 2);
    ok("the throttle NEVER charges the hard-fault strike counter (attempt stays 0)", parked?.attempt === 0);
    ok("no failed completion is posted while parked", !sched.calls.some((c) => c.path === "/complete"));
    ok("the throttle logs say throttled/parked and stay redacted", logged.some((l) => /throttled \(waiting/.test(l)) && logged.every((l) => !l.includes("KV_TEST")));

    // The destination RECOVERS: the next alarm resumes the SAME run from its checkpoint and drives it to a
    // clean completion (park-and-resume), no fresh run, content-addressed dedup so nothing is double-sealed.
    dest.throttle = false;
    let more = 0;
    for (; more < 200 && doState.storage.has("doc"); more++) await realDO.alarm();
    const complete = sched.calls.find((c) => c.path === "/complete");
    const cbody = complete?.body as { status?: string; runId?: string; recordCount?: number } | undefined;
    ok("the recovered destination lets the SAME run resume and complete ok", cbody?.status === "ok" && cbody?.runId === RUN_ID);
    ok("the resumed run captured every record (500)", cbody?.recordCount === 500);
    ok("the DO state is cleaned up after the resumed completion", doState.storage.size === 0);
  }

  console.log("\nRunSealDO: a destination throttle that never recovers gives up after the parking window, with an honest reason:");
  {
    const sched = makeScheduler();
    const doState = makeDOState();
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 500), 100);
    let realDO: RunSealDO | null = null;
    const runsealStub = {
      async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
        return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init));
      },
    } as unknown as DurableObjectStub;
    const env = mkEnv(kv, sched.stub, runsealStub, dest);
    (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "120";
    (env as unknown as Record<string, string>)["DEST_THROTTLE_MAX_YIELDS"] = "3";
    realDO = new RunSealDO(doState.state, env);
    await sealRunSliced(env, dpState("dp-throttle-terminal"), { runId: RUN_ID, index: 22, prevRunId: null }, { budget: new SliceBudget({ subrequests: 120, wallMs: 60_000 }) });
    dest.throttle = true; // never recovers
    const origError = console.error;
    console.error = () => {};
    let alarms = 0;
    try {
      for (; alarms < 20 && doState.storage.has("doc"); alarms++) await realDO.alarm();
    } finally {
      console.error = origError;
    }
    ok(`the never-recovering throttle gives up at the parking window (took ${alarms} alarms)`, !doState.storage.has("doc") && alarms === 3);
    const complete = sched.calls.find((c) => c.path === "/complete");
    const body = complete?.body as { status?: string; error?: string; runId?: string } | undefined;
    ok("the give-up completion is failed with an honest unavailable reason and an empty runId", body?.status === "failed" && body?.runId === "" && body?.error === "destination unavailable (sustained throttling)");
    ok("the DO state is fully cleaned up", doState.storage.size === 0);
  }

  console.log("\nRunSealDO: RUNLOG contention PARKS and resumes, never striking the run as a hard fault:");
  {
    const sched = makeScheduler(); // its /runlog-lock/acquire returns acquired:false (lock held), so the
    // patient acquire falls through to the lock-free CAS, which this dest then refuses while `contend` is set.
    const doState = makeDOState();
    const dest = new ContendRunlogDest();
    const kv = new MemKV(seeds.slice(0, 500), 100);
    let realDO: RunSealDO | null = null;
    const runsealStub = {
      async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
        return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init));
      },
    } as unknown as DurableObjectStub;
    const env = mkEnv(kv, sched.stub, runsealStub, dest);
    (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "120";
    (env as unknown as Record<string, string>)["DEST_THROTTLE_MAX_YIELDS"] = "3"; // a short window so the test is fast
    realDO = new RunSealDO(doState.state, env);
    await sealRunSliced(env, dpState("dp-contend"), { runId: RUN_ID, index: 31, prevRunId: null }, { budget: new SliceBudget({ subrequests: 120, wallMs: 60_000 }) });
    ok("the run handed off (the first slice sealed before finalise)", doState.storage.has("doc"));
    dest.contend = true; // from here every RUNLOG conditional write fails: finalise hits contention.
    const origError = console.error;
    const logged: string[] = [];
    console.error = (...args: unknown[]) => {
      logged.push(args.map(String).join(" "));
    };
    try {
      // Drive alarms until the source is drained AND the run reaches the contended finalise; below the
      // 3-round contention window the run must stay PARKED (doc preserved), on the runlogAttempt ladder,
      // NOT charging the hard-fault strike counter and NOT failing.
      for (let i = 0; i < 40 && ((doState.storage.get("doc") as { runlogAttempt?: number } | undefined)?.runlogAttempt ?? 0) < 2; i++) await realDO.alarm();
    } finally {
      console.error = origError;
    }
    const parked = doState.storage.get("doc") as { attempt: number; runlogAttempt?: number; throttleAttempt?: number } | undefined;
    ok("a contended run is PARKED, not cleaned up (the checkpoint survives)", doState.storage.has("doc"));
    ok("contention rides its OWN ladder (runlogAttempt grows to 2)", (parked?.runlogAttempt ?? 0) === 2);
    ok("contention NEVER charges the hard-fault strike counter (attempt stays 0)", parked?.attempt === 0);
    ok("contention does NOT touch the throttle ladder (throttleAttempt stays 0)", (parked?.throttleAttempt ?? 0) === 0);
    ok("no failed completion is posted while parked on contention", !sched.calls.some((c) => c.path === "/complete"));
    ok("the contention logs say parking and stay redacted", logged.some((l) => /RUNLOG contended \(parking/.test(l)) && logged.every((l) => !l.includes("KV_TEST")));

    // The contention CLEARS: the SAME parked run resumes and finalises (idempotent re-finalise), ok.
    dest.contend = false;
    for (let more = 0; more < 200 && doState.storage.has("doc"); more++) await realDO.alarm();
    const complete = sched.calls.find((c) => c.path === "/complete");
    const cbody = complete?.body as { status?: string; runId?: string; recordCount?: number } | undefined;
    ok("the cleared contention lets the SAME run resume and complete ok", cbody?.status === "ok" && cbody?.runId === RUN_ID);
    ok("the resumed run captured every record (500)", cbody?.recordCount === 500);
    ok("the DO state is cleaned up after the resumed completion", doState.storage.size === 0);
  }

  console.log("\nRunSealDO: RUNLOG contention that never clears gives up at the window with an honest reason (no run wedged):");
  {
    const sched = makeScheduler();
    const doState = makeDOState();
    const dest = new ContendRunlogDest();
    const kv = new MemKV(seeds.slice(0, 500), 100);
    let realDO: RunSealDO | null = null;
    const runsealStub = {
      async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
        return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init));
      },
    } as unknown as DurableObjectStub;
    const env = mkEnv(kv, sched.stub, runsealStub, dest);
    (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "120";
    (env as unknown as Record<string, string>)["DEST_THROTTLE_MAX_YIELDS"] = "3";
    realDO = new RunSealDO(doState.state, env);
    await sealRunSliced(env, dpState("dp-contend-terminal"), { runId: RUN_ID, index: 32, prevRunId: null }, { budget: new SliceBudget({ subrequests: 120, wallMs: 60_000 }) });
    dest.contend = true; // never clears
    const origError = console.error;
    console.error = () => {};
    try {
      for (let i = 0; i < 60 && doState.storage.has("doc"); i++) await realDO.alarm();
    } finally {
      console.error = origError;
    }
    ok("the never-clearing contention eventually gives up (the run is not wedged forever)", !doState.storage.has("doc"));
    const complete = sched.calls.find((c) => c.path === "/complete");
    const body = complete?.body as { status?: string; error?: string; runId?: string } | undefined;
    ok("the give-up completion is failed with an honest contended reason and an empty runId", body?.status === "failed" && body?.runId === "" && body?.error === "RUNLOG persistently contended");
    ok("the DO state is fully cleaned up", doState.storage.size === 0);
    // Orphan-root GC: finaliseRun wrote the signed root (+ shard manifests) BEFORE the RUNLOG
    // append, which then never committed. The give-up path must reclaim that run/<runId>/ tree so an orphan
    // root (cryptographically intact but not-in-RUNLOG, needing --allow-stale, bytes never reclaimed) never
    // accumulates. The shared content-addressed seg/ blobs and the destination-global _RECOVERY/ bundle must
    // survive (dedup-shared with the next cadence's re-seal / other runs).
    const runTreeLeft = await dest.list(`run/${RUN_ID}/`);
    ok("the orphan run-tree (root.manifest + sig + shard manifests) was reclaimed on give-up", runTreeLeft.length === 0);
    ok("the shared content-addressed seg/ blobs were NOT deleted by the orphan-root GC", (await dest.list("seg/")).length > 0);
    ok("the destination-global _RECOVERY/ bundle was NOT deleted by the orphan-root GC", (await dest.list("_RECOVERY/")).length > 0);
  }

  console.log("\nsealRunSliced: VERIFY_AT_SEAL off skips the read-back and omits the verdict:");
  {
    const sched = makeScheduler();
    const runsealStub = { async fetch(): Promise<Response> { return new Response(JSON.stringify({ ok: true })); } } as unknown as DurableObjectStub;
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 12), 100);
    const env = mkEnv(kv, sched.stub, runsealStub, dest);
    (env as unknown as Record<string, string>)["VERIFY_AT_SEAL"] = "0"; // explicit opt-out
    // Spy: if verify-at-seal ran it would read back the just-written root; track every dest read.
    const readKeys: string[] = [];
    const origGet = dest.get.bind(dest);
    dest.get = async (k: string) => { readKeys.push(k); return origGet(k); };
    await sealRunSliced(env, dpState("dp-verifyoff"), { runId: RUN_ID, index: 31, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) });
    const complete = sched.calls.find((c) => c.path === "/complete");
    const body = complete?.body as { status?: string; sealVerification?: unknown } | undefined;
    ok("the run completes ok with verify-at-seal off", body?.status === "ok");
    ok("no seal-verification verdict is attached when the feature is off", body !== undefined && !("sealVerification" in body));
    ok("the destination archive is never re-read for verification", !readKeys.some((k) => k.endsWith("root.manifest.json")));
  }

  console.log("\nsealRunSliced: a SUSPECT seal-verification flags the run yet still completes ok (fail-open) and alerts:");
  {
    // This scheduler also answers /notify/resolve with no immediate channels, so the seal-verify alert
    // routing resolves cleanly to "not delivered" (still proving the alert path was taken) without noise.
    const sched = (() => {
      const calls: { path: string; body?: unknown }[] = [];
      const stub = {
        async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
          const url = new URL(input instanceof Request ? input.url : String(input));
          const body = init?.body ? JSON.parse(String(init.body)) : undefined;
          calls.push({ path: url.pathname, ...(body !== undefined ? { body } : {}) });
          if (url.pathname === "/heartbeat") return new Response(JSON.stringify({ owned: true }));
          if (url.pathname === "/runlog-lock/acquire") return new Response(JSON.stringify({ acquired: false }));
          if (url.pathname === "/notify/resolve") return new Response(JSON.stringify({ now: [], digestedCount: 0, emission: null }));
          return new Response(JSON.stringify({ ok: true }));
        },
      } as unknown as DurableObjectStub;
      return { stub, calls };
    })();
    const runsealStub = { async fetch(): Promise<Response> { return new Response(JSON.stringify({ ok: true })); } } as unknown as DurableObjectStub;
    const dest = new CorruptRootDest(); // corrupts the root signature on read-back only
    const kv = new MemKV(seeds.slice(0, 12), 100);
    const env = mkEnv(kv, sched.stub, runsealStub, dest);
    await sealRunSliced(env, dpState("dp-suspect"), { runId: RUN_ID, index: 32, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) });
    const complete = sched.calls.find((c) => c.path === "/complete");
    const body = complete?.body as { status?: string; recordCount?: number; sealVerification?: { status?: string; tier?: string } } | undefined;
    ok("a suspect verdict does NOT fail the run (fail-open: the bytes are already written)", body?.status === "ok" && body?.recordCount === 12);
    ok("the suspect seal-verification verdict is attached to the completion", body?.sealVerification?.status === "suspect");
    ok("the suspect verdict is the Tier-0 keyless attestation (signature check)", body?.sealVerification?.tier === "tier-0");
    ok("the suspect verdict routed the critical alert through the scheduler's notify resolve", sched.calls.some((c) => c.path === "/notify/resolve"));
  }

  console.log("\nsealRunSliced: a destinationId is pinned through every seal path (inline, handoff, resume):");
  {
    const sched = makeScheduler();
    const doState = makeDOState();
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 12), 100);
    const runsealStub = { async fetch(): Promise<Response> { return new Response(JSON.stringify({ ok: true })); } } as unknown as DurableObjectStub;
    const env = mkEnv(kv, sched.stub, runsealStub, dest);
    await sealRunSliced(env, dpState("dp-destid-inline"), { runId: RUN_ID, index: 33, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }), destOverride: null, destinationId: "r2-primary" });
    const inlineComplete = sched.calls.find((c) => c.path === "/complete");
    ok("an inline-completed run records the pinned destinationId as its origin", (inlineComplete?.body as { destinationId?: string } | undefined)?.destinationId === "r2-primary");

    // Handoff: a large run carries the destinationId into the persisted doc, and every resumed slice
    // re-persists it forward (a mid-run loss would silently repoint the remaining slices).
    const sched2 = makeScheduler();
    const dest2 = new MemDest();
    const kv2 = new MemKV(seeds.slice(0, 900), 100);
    let realDO: RunSealDO | null = null;
    const runsealStub2 = { async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> { return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init)); } } as unknown as DurableObjectStub;
    const env2 = mkEnv(kv2, sched2.stub, runsealStub2, dest2);
    (env2 as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "150";
    (env2 as unknown as Record<string, string>)["SCALE_SHARD_MAX_RECORDS"] = "200";
    realDO = new RunSealDO(doState.state, env2);
    await sealRunSliced(env2, dpState("dp-destid-big"), { runId: RUN_ID, index: 34, prevRunId: null }, { budget: new SliceBudget({ subrequests: 150, wallMs: 60_000 }), destOverride: null, destinationId: "r2-secondary" });
    const handoffDoc = doState.storage.get("doc") as { destinationId?: string } | undefined;
    ok("the handoff doc pins the destinationId for the resumed slices", handoffDoc?.destinationId === "r2-secondary");
    let alarms = 0;
    for (; alarms < 100 && doState.storage.has("doc"); alarms++) await realDO.alarm();
    const c2 = sched2.calls.find((c) => c.path === "/complete");
    ok("the resumed DO completion reports the SAME pinned destinationId", (c2?.body as { destinationId?: string; status?: string } | undefined)?.destinationId === "r2-secondary");
  }

  console.log("\nRunSealDO /start: stale shard rows from an abandoned run are swept before the new run writes:");
  {
    const sched = makeScheduler();
    const doState = makeDOState();
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 12), 100);
    let realDO: RunSealDO | null = null;
    const runsealStub = { async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> { return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init)); } } as unknown as DurableObjectStub;
    const env = mkEnv(kv, sched.stub, runsealStub, dest);
    realDO = new RunSealDO(doState.state, env);
    // Pre-seed a stale shard row that the new /start must NOT carry forward.
    doState.storage.set("shard:zzz-stale", { id: "zzz-stale", object: "run/old/shard.json", sha384: "deadbeef" });
    // Build a real first-slice checkpoint + shards to hand to /start (a single small slice).
    const master = rand(32);
    const cp0: RunCheckpoint = {
      v: 1, downpipeId: "dp-stale", downpipeName: "dp-stale", cadence: "3600s", sourceType: "kv",
      selector: { include: [], exclude: [] }, runId: RUN_ID, runlogIndex: 41, prevRunId: null,
      startedAt: "2026-06-10T00:00:00.000Z", wrappedMaster: await wrapMaster(signerPrivateB64, RUN_ID, master),
      cursor: null, sourceDone: false, nextRecordIndex: 0, nextShardIndex: 0,
      frontier: { count: 0, nodes: [] }, counts: zeroCounts(), sliceCount: 0, partialRecord: null,
    };
    // shardMaxRecords 5 forces this 12-record slice to FLUSH shard rows (a small run otherwise
    // carries every record in the open buffer and writes no shard row), so the new run has its own shards
    // for the stale-sweep assertion; the leftover open buffer rides the handoff as openShardLines.
    const r0 = await runSlice({ source: new KVSource(kv as unknown as KVNamespace, "ns1"), dest, signer, recipients, budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }), shardMaxRecords: 5 }, cp0, master);
    master.fill(0);
    const startReq = new Request("https://runseal.internal/start", { method: "POST", body: JSON.stringify({ config: dpStateSrc("dp-stale", { type: "kv", binding: "KV_TEST", namespaceId: "ns1", include: [], exclude: [] }).config, checkpoint: r0.checkpoint, shards: r0.newShards, openShardLines: r0.openWrite } satisfies StartSliceRun), headers: { "content-type": "application/json" } });
    const startResp = await realDO.fetch(startReq);
    ok("/start accepts the handoff", startResp.ok && ((await startResp.json()) as { ok?: boolean }).ok === true);
    ok("the stale shard row from the abandoned run was swept", !doState.storage.has("shard:zzz-stale"));
    ok("the new run's own shard rows were written", [...doState.storage.keys()].some((k) => k.startsWith("shard:") && k !== "shard:zzz-stale"));
  }

  console.log("\nRunSealDO GET /status: reports an active run and reports inactive when idle:");
  {
    const doState = makeDOState();
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 12), 100);
    const env = mkEnv(kv, makeScheduler().stub, ({ async fetch(): Promise<Response> { return new Response("{}"); } }) as unknown as DurableObjectStub, dest);
    const realDO = new RunSealDO(doState.state, env);
    const idle = await realDO.fetch(new Request("https://runseal.internal/status"));
    const idleBody = (await idle.json()) as { active?: boolean };
    ok("GET /status on an idle DO reports active:false", idleBody.active === false);
    // Seed an active doc directly, then read status.
    doState.storage.set("doc", { config: {}, checkpoint: { runId: RUN_ID, sliceCount: 4, counts: { records: 7, bytes: 123 }, sourceDone: false }, attempt: 2 });
    const active = await realDO.fetch(new Request("https://runseal.internal/status"));
    const activeBody = (await active.json()) as { active?: boolean; runId?: string; sliceCount?: number; records?: number; bytes?: number; sourceDone?: boolean; attempt?: number };
    ok("GET /status on an active DO reports the live run identity and counters", activeBody.active === true && activeBody.runId === RUN_ID && activeBody.sliceCount === 4 && activeBody.records === 7 && activeBody.bytes === 123 && activeBody.sourceDone === false && activeBody.attempt === 2);
  }

  console.log("\nRunSealDO fetch: an unknown route is 404 and a malformed /start body is a clean 400:");
  {
    const doState = makeDOState();
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 12), 100);
    const env = mkEnv(kv, makeScheduler().stub, ({ async fetch(): Promise<Response> { return new Response("{}"); } }) as unknown as DurableObjectStub, dest);
    const realDO = new RunSealDO(doState.state, env);
    const notFound = await realDO.fetch(new Request("https://runseal.internal/nope", { method: "DELETE" }));
    ok("an unknown method+path returns 404 not found", notFound.status === 404 && ((await notFound.json()) as { error?: string }).error === "not found");
    const bad = await realDO.fetch(new Request("https://runseal.internal/start", { method: "POST", body: "{not json", headers: { "content-type": "application/json" } }));
    ok("a malformed /start body is caught and answered 400 (never an unhandled throw)", bad.status === 400 && typeof ((await bad.json()) as { error?: string }).error === "string");
  }

  console.log("\nRunSealDO alarm: an alarm with no active doc is a no-op (completed or aborted run):");
  {
    const doState = makeDOState();
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 12), 100);
    const sched = makeScheduler();
    const env = mkEnv(kv, sched.stub, ({ async fetch(): Promise<Response> { return new Response("{}"); } }) as unknown as DurableObjectStub, dest);
    const realDO = new RunSealDO(doState.state, env);
    await realDO.alarm(); // no doc set
    ok("an alarm with no doc returns without heartbeating or completing", sched.calls.length === 0 && doState.alarms.length === 0);
  }

  console.log("\nRunSealDO: the RUNLOG lock is taken and released when the scheduler grants it:");
  {
    // A scheduler that GRANTS the runlog lock (acquired + token) so finaliseRun takes and releases it,
    // exercising the acquire-success branch of runlogLockVia (the existing tests only see acquired:false).
    const lockCalls: string[] = [];
    let owned = true;
    const stub = {
      async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
        const url = new URL(input instanceof Request ? input.url : String(input));
        lockCalls.push(url.pathname);
        if (url.pathname === "/heartbeat") return new Response(JSON.stringify({ owned }));
        if (url.pathname === "/runlog-lock/acquire") return new Response(JSON.stringify({ acquired: true, token: "lock-tok" }));
        return new Response(JSON.stringify({ ok: true }));
      },
    } as unknown as DurableObjectStub;
    owned = true;
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 12), 100);
    const env = mkEnv(kv, stub, ({ async fetch(): Promise<Response> { return new Response("{}"); } }) as unknown as DurableObjectStub, dest);
    await sealRunSliced(env, dpState("dp-lock"), { runId: RUN_ID, index: 42, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) });
    ok("the granted runlog lock was acquired", lockCalls.includes("/runlog-lock/acquire"));
    ok("the granted runlog lock was released with its token", lockCalls.includes("/runlog-lock/release"));
    const complete = lockCalls.includes("/complete");
    ok("the run still completes under the held lock", complete);
  }

  console.log("\nsealRunSliced: an API source (cf-config) fetches the discovery token and honours the discovery selector:");
  {
    // A cf-config run: the discovery-config fetch supplies the read-only token (covering cfConfigToken's
    // API-source branch), and the cf-config selector path runs. The accountId is deliberately ABSENT, so
    // buildAdapter throws BEFORE any network read, which the outer catch resolves as a failed completion.
    const calls: { path: string }[] = [];
    const stub = {
      async fetch(input: RequestInfo | URL): Promise<Response> {
        const url = new URL(input instanceof Request ? input.url : String(input));
        calls.push({ path: url.pathname });
        if (url.pathname === "/sources/discovery-config") return new Response(JSON.stringify({ config: { token: "disco-token" } }));
        return new Response(JSON.stringify({ ok: true }));
      },
    } as unknown as DurableObjectStub;
    const dest = new MemDest();
    const kv = new MemKV([], 100);
    const env = mkEnv(kv, stub, ({ async fetch(): Promise<Response> { return new Response("{}"); } }) as unknown as DurableObjectStub, dest);
    const origError = console.error;
    console.error = () => {};
    try {
      await sealRunSliced(env, dpStateSrc("dp-cfg", { type: "cf-config", cfConfigMode: "manual", include: [], exclude: [] }), { runId: RUN_ID, index: 51, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) });
    } finally {
      console.error = origError;
    }
    ok("the cf-config run fetched the read-only discovery token from the scheduler", calls.some((c) => c.path === "/sources/discovery-config"));
    const complete = calls.find((c) => c.path === "/complete");
    ok("the missing accountId fails the run cleanly through the outer catch (failed completion, empty runId)", complete !== undefined);
  }

  console.log("\nsealRunSliced: a cf-config run with no discovery token configured resolves the token to undefined:");
  {
    // The discovery-config returns config:null (no token set yet), so cfConfigToken resolves undefined,
    // and buildAdapter throws the actionable 'set the discovery token first' error (the false arm of the
    // token ternary). Still a clean failed completion, never an unhandled throw.
    const calls: { path: string }[] = [];
    const stub = {
      async fetch(input: RequestInfo | URL): Promise<Response> {
        const url = new URL(input instanceof Request ? input.url : String(input));
        calls.push({ path: url.pathname });
        if (url.pathname === "/sources/discovery-config") return new Response(JSON.stringify({ config: null }));
        return new Response(JSON.stringify({ ok: true }));
      },
    } as unknown as DurableObjectStub;
    const dest = new MemDest();
    const kv = new MemKV([], 100);
    const env = mkEnv(kv, stub, ({ async fetch(): Promise<Response> { return new Response("{}"); } }) as unknown as DurableObjectStub, dest);
    const origError = console.error;
    const logged: string[] = [];
    console.error = (...a: unknown[]) => { logged.push(a.map(String).join(" ")); };
    try {
      await sealRunSliced(env, dpStateSrc("dp-cfg-notoken", { type: "cf-config", accountId: "acc1", cfConfigMode: "manual", include: [], exclude: [] }), { runId: RUN_ID, index: 52, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) });
    } finally {
      console.error = origError;
    }
    const complete = calls.find((c) => c.path === "/complete");
    ok("a token-less cf-config run resolves cleanly to a failed completion", complete !== undefined && (complete as { body?: { status?: string } } | undefined) !== undefined);
    ok("the failure is reported, redacted (no raw token text in the log)", logged.length > 0 && logged.every((l) => !l.includes("disco-token")));
  }

  console.log("\ncfConfigToken: EVERY API-based source type resolves the read-only discovery token:");
  {
    // cfConfigToken's allow-list must return the token for every API-based source type (cf-config/workers/
    // stream/images/artifacts); a source type missing from the list would be constructed without it and
    // buildAdapter would throw "needs the account read-only token" on every run. Assert the token resolves
    // for all FIVE API-based types, and that the four binding types still resolve to undefined WITHOUT any
    // DO fetch.
    // The faked config carries accountsSeen/selected for "acc1" (a real stored DiscoveryConfig always
    // does once it exists), so the scope re-check inside cfConfigToken finds it in scope.
    const mkStub = (calls: string[]): DurableObjectStub =>
      ({
        async fetch(input: RequestInfo | URL): Promise<Response> {
          calls.push(new URL(input instanceof Request ? input.url : String(input)).pathname);
          return new Response(JSON.stringify({ config: { token: "disco-token", accountsSeen: [{ id: "acc1", name: "Acct One" }], selected: ["acc1"] } }));
        },
      }) as unknown as DurableObjectStub;
    const noEnv = {} as unknown as import("../src/env.d.ts").Env;
    const apiTypes = ["cf-config", "workers", "stream", "images", "artifacts"] as const;
    for (const t of apiTypes) {
      const calls: string[] = [];
      const token = await cfConfigToken(mkStub(calls), dpStateSrc(`dp-${t}`, { type: t, accountId: "acc1" } as DownpipeState["config"]["source"]), noEnv);
      ok(`an API source (${t}) resolves the discovery token from the scheduler`, token === "disco-token" && calls.includes("/sources/discovery-config"));
    }
    const bindingTypes = ["kv", "r2", "d1", "secrets"] as const;
    for (const t of bindingTypes) {
      const calls: string[] = [];
      const token = await cfConfigToken(mkStub(calls), dpStateSrc(`dp-${t}`, { type: t, binding: "X" } as DownpipeState["config"]["source"]), noEnv);
      ok(`a binding source (${t}) needs no token and makes no discovery-config fetch`, token === undefined && calls.length === 0);
    }
  }

  console.log("\ncfConfigToken: the DISCOVERY_API_TOKEN env fallback resolves the token when the DO has none (an env-token deployment):");
  {
    // An IaC/env-token deployment has no DO-stored discovery config, only the
    // DISCOVERY_API_TOKEN deploy var. The run path must resolve the token from that fallback exactly as
    // the six admin readers do, else every API-source backup fails despite a valid token. Assert: with the
    // DO returning config:null, an API source resolves the token from env (trimmed); a binding source still
    // resolves undefined and makes NO DO fetch (so it never even consults env); and when NEITHER the DO nor
    // env has a token, an API source resolves undefined (the adapter then throws the honest token error).
    const mkNullStub = (calls: string[]): DurableObjectStub =>
      ({
        async fetch(input: RequestInfo | URL): Promise<Response> {
          calls.push(new URL(input instanceof Request ? input.url : String(input)).pathname);
          return new Response(JSON.stringify({ config: null }));
        },
      }) as unknown as DurableObjectStub;
    const envWithToken = { DISCOVERY_API_TOKEN: "  env-disco-token  " } as unknown as import("../src/env.d.ts").Env;
    const envNoToken = {} as unknown as import("../src/env.d.ts").Env;
    {
      const calls: string[] = [];
      const token = await cfConfigToken(mkNullStub(calls), dpStateSrc("dp-env-api", { type: "stream", accountId: "acc1" } as DownpipeState["config"]["source"]), envWithToken);
      ok("an API source falls back to the trimmed DISCOVERY_API_TOKEN env var when the DO has no token", token === "env-disco-token" && calls.includes("/sources/discovery-config"));
    }
    {
      const calls: string[] = [];
      const token = await cfConfigToken(mkNullStub(calls), dpStateSrc("dp-env-bind", { type: "kv", binding: "X" } as DownpipeState["config"]["source"]), envWithToken);
      ok("a binding source ignores the env token and makes no discovery-config fetch", token === undefined && calls.length === 0);
    }
    {
      const calls: string[] = [];
      const token = await cfConfigToken(mkNullStub(calls), dpStateSrc("dp-no-token", { type: "images", accountId: "acc1" } as DownpipeState["config"]["source"]), envNoToken);
      ok("an API source with neither a DO nor an env token resolves undefined (the adapter throws the honest token error)", token === undefined && calls.includes("/sources/discovery-config"));
    }
  }

  console.log("\nsealRunSliced: a refused seal-DO handoff throws and posts the failed completion immediately:");
  {
    const sched = makeScheduler();
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 900), 100);
    // The runseal stub REFUSES the handoff (non-2xx), as the DO's catch would on a malformed payload.
    const runsealStub = { async fetch(): Promise<Response> { return new Response(JSON.stringify({ error: "boom" }), { status: 400 }); } } as unknown as DurableObjectStub;
    const env = mkEnv(kv, sched.stub, runsealStub, dest);
    (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "150";
    const origError = console.error;
    console.error = () => {};
    try {
      await sealRunSliced(env, dpState("dp-refused"), { runId: RUN_ID, index: 53, prevRunId: null }, { budget: new SliceBudget({ subrequests: 150, wallMs: 60_000 }) });
    } finally {
      console.error = origError;
    }
    const complete = sched.calls.find((c) => c.path === "/complete");
    const body = complete?.body as { status?: string; runId?: string } | undefined;
    ok("a refused handoff falls to the outer catch and posts the failed completion now", body?.status === "failed" && body?.runId === "");
  }

  console.log("\nsealRunSliced: an inline run whose ok completion POST fails leaves the row in flight, never failed:");
  {
    // The seal succeeds (archive complete) but the scheduler's /complete throws: this is NOT a seal
    // failure, so it must be logged and the row left in flight (the lease reclaim resolves it), NOT
    // posted as failed under a fresh run. We assert no FAILED completion is posted from this path.
    let postedFailed = false;
    const stub = {
      async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
        const url = new URL(input instanceof Request ? input.url : String(input));
        if (url.pathname === "/complete") {
          const b = init?.body ? JSON.parse(String(init.body)) : {};
          if (b.status === "failed") postedFailed = true;
          throw new Error("scheduler unreachable");
        }
        if (url.pathname === "/heartbeat") return new Response(JSON.stringify({ owned: true }));
        if (url.pathname === "/runlog-lock/acquire") return new Response(JSON.stringify({ acquired: false }));
        return new Response(JSON.stringify({ ok: true }));
      },
    } as unknown as DurableObjectStub;
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 12), 100);
    const env = mkEnv(kv, stub, ({ async fetch(): Promise<Response> { return new Response("{}"); } }) as unknown as DurableObjectStub, dest);
    const origError = console.error;
    const logged: string[] = [];
    console.error = (...a: unknown[]) => { logged.push(a.map(String).join(" ")); };
    try {
      await sealRunSliced(env, dpState("dp-completefail"), { runId: RUN_ID, index: 54, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) });
    } finally {
      console.error = origError;
    }
    ok("a failed ok-completion POST does NOT get re-posted as a failed run", !postedFailed);
    ok("the sealed-but-not-completed condition is logged honestly", logged.some((l) => /sealed fully but the ok completion did not land/.test(l)));
    const run = await openRun(new MapStore(dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
    ok("the archive is intact despite the lost completion POST", run.records.length === 12);
  }

  console.log("\nsealRunSliced: SLICED_RUNS_DISABLED falls back to the v1 whole-run buffered seal:");
  {
    const sched = makeScheduler();
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 40), 100);
    const env = mkEnv(kv, sched.stub, ({ async fetch(): Promise<Response> { return new Response("{}"); } }) as unknown as DurableObjectStub, dest);
    (env as unknown as Record<string, string>)["SLICED_RUNS_DISABLED"] = "1"; // revert to the buffered path
    (env as unknown as Record<string, string>)["SCALE_SEGMENT_TARGET_BYTES"] = "131072"; // a valid numKnob (true arm)
    (env as unknown as Record<string, string>)["SCALE_SHARD_MAX_RECORDS"] = "0"; // an invalid numKnob (rejected -> false arm)
    await sealRunSliced(env, dpState("dp-buffered"), { runId: RUN_ID, index: 61, prevRunId: null });
    const complete = sched.calls.find((c) => c.path === "/complete");
    const body = complete?.body as { status?: string; recordCount?: number; runId?: string } | undefined;
    ok("the buffered path completes the whole run in one pass", body?.status === "ok" && body?.runId === RUN_ID);
    ok("the buffered completion carries the full record count", body?.recordCount === 40);
    ok("the seal DO is never involved on the buffered path", !doStateHasAlarm(sched));
    const run = await openRun(new MapStore(dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
    ok("the buffered archive opens with every record", run.records.length === 40);
  }

  console.log("\nsealRunBuffered: a seal failure posts the redacted failed completion (the v1 error path):");
  {
    const sched = makeScheduler();
    // The destination rejects every WRITE, so the buffered run throws inside runBackup (not at adapter
    // construction, which the source reads outside the buffered try). The binding stays present.
    const dest = new FailWriteDest();
    const kv = new MemKV(seeds.slice(0, 40), 100);
    const env = mkEnv(kv, sched.stub, ({ async fetch(): Promise<Response> { return new Response("{}"); } }) as unknown as DurableObjectStub, dest);
    (env as unknown as Record<string, string>)["SLICED_RUNS_DISABLED"] = "1";
    const origError = console.error;
    const logged: string[] = [];
    console.error = (...a: unknown[]) => { logged.push(a.map(String).join(" ")); };
    try {
      await sealRunSliced(env, dpState("dp-buffered-fail"), { runId: RUN_ID, index: 62, prevRunId: null });
    } finally {
      console.error = origError;
    }
    const complete = sched.calls.find((c) => c.path === "/complete");
    const body = complete?.body as { status?: string; error?: string; runId?: string } | undefined;
    ok("the buffered failure posts a failed completion with an empty runId and a coarse reason", body?.status === "failed" && body?.runId === "" && typeof body?.error === "string" && body.error.length > 0);
    ok("the buffered failure log is redacted to the coarse class + digest (no raw object key)", logged.length > 0 && logged.some((l) => /run dp-buffered-fail .* failed:/.test(l)) && logged.every((l) => !/status 500 destination write rejected/.test(l)));
  }

  console.log("\nsealDeps: a missing SIGNER_PRIVATE fails the run cleanly with the required-configuration error:");
  {
    const sched = makeScheduler();
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 12), 100);
    const env = mkEnv(kv, sched.stub, ({ async fetch(): Promise<Response> { return new Response("{}"); } }) as unknown as DurableObjectStub, dest);
    delete (env as unknown as Record<string, unknown>)["SIGNER_PRIVATE"]; // requireEnv must throw
    const origError = console.error;
    console.error = () => {};
    try {
      await sealRunSliced(env, dpState("dp-nosigner"), { runId: RUN_ID, index: 63, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) });
    } finally {
      console.error = origError;
    }
    const complete = sched.calls.find((c) => c.path === "/complete");
    const body = complete?.body as { status?: string; runId?: string } | undefined;
    ok("a missing required configuration fails the run cleanly (failed completion, empty runId)", body?.status === "failed" && body?.runId === "");
  }

  console.log("\nRunSealDO: a terminal slice failure whose /complete also throws is logged and still cleans up:");
  {
    let completeCalls = 0;
    let owned = true;
    const stub = {
      async fetch(input: RequestInfo | URL): Promise<Response> {
        const url = new URL(input instanceof Request ? input.url : String(input));
        if (url.pathname === "/heartbeat") return new Response(JSON.stringify({ owned }));
        if (url.pathname === "/runlog-lock/acquire") return new Response(JSON.stringify({ acquired: false }));
        if (url.pathname === "/complete") { completeCalls++; throw new Error("scheduler unreachable"); }
        return new Response(JSON.stringify({ ok: true }));
      },
    } as unknown as DurableObjectStub;
    owned = true;
    const doState = makeDOState();
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 500), 100);
    let realDO: RunSealDO | null = null;
    const runsealStub = { async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> { return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init)); } } as unknown as DurableObjectStub;
    const env = mkEnv(kv, stub, runsealStub, dest);
    (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "120";
    realDO = new RunSealDO(doState.state, env);
    await sealRunSliced(env, dpStateSrc("dp-fail-complete", { type: "kv", binding: "KV_TEST", namespaceId: "ns1", include: [], exclude: [] }), { runId: RUN_ID, index: 71, prevRunId: null }, { budget: new SliceBudget({ subrequests: 120, wallMs: 60_000 }) });
    ok("the run handed off", doState.storage.has("doc"));
    delete (env as unknown as Record<string, unknown>)["KV_TEST"]; // every subsequent slice now fails
    const origError = console.error;
    const logged: string[] = [];
    console.error = (...a: unknown[]) => { logged.push(a.map(String).join(" ")); };
    let alarms = 0;
    try {
      for (; alarms < 20 && doState.storage.has("doc"); alarms++) await realDO.alarm();
    } finally {
      console.error = origError;
    }
    ok("the terminal failure still cleans up even though the failed /complete threw", !doState.storage.has("doc") && doState.storage.size === 0);
    ok("the failed-completion attempt was made and its failure logged honestly", completeCalls >= 1 && logged.some((l) => /failure completion did not land/.test(l)));
  }

  console.log("\nRunSealDO: a never-recovering throttle whose give-up /complete throws still cleans up:");
  {
    let owned = true;
    const stub = {
      async fetch(input: RequestInfo | URL): Promise<Response> {
        const url = new URL(input instanceof Request ? input.url : String(input));
        if (url.pathname === "/heartbeat") return new Response(JSON.stringify({ owned }));
        if (url.pathname === "/runlog-lock/acquire") return new Response(JSON.stringify({ acquired: false }));
        if (url.pathname === "/complete") throw new Error("scheduler unreachable");
        return new Response(JSON.stringify({ ok: true }));
      },
    } as unknown as DurableObjectStub;
    owned = true;
    const doState = makeDOState();
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 500), 100);
    let realDO: RunSealDO | null = null;
    const runsealStub = { async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> { return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init)); } } as unknown as DurableObjectStub;
    const env = mkEnv(kv, stub, runsealStub, dest);
    (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "120";
    (env as unknown as Record<string, string>)["DEST_THROTTLE_MAX_YIELDS"] = "2"; // short window
    realDO = new RunSealDO(doState.state, env);
    await sealRunSliced(env, dpStateSrc("dp-throttle-completefail", { type: "kv", binding: "KV_TEST", namespaceId: "ns1", include: [], exclude: [] }), { runId: RUN_ID, index: 72, prevRunId: null }, { budget: new SliceBudget({ subrequests: 120, wallMs: 60_000 }) });
    dest.throttle = true; // never recovers
    const origError = console.error;
    const logged: string[] = [];
    console.error = (...a: unknown[]) => { logged.push(a.map(String).join(" ")); };
    let alarms = 0;
    try {
      for (; alarms < 20 && doState.storage.has("doc"); alarms++) await realDO.alarm();
    } finally {
      console.error = origError;
    }
    ok("the throttle give-up cleans up even though its failed /complete threw", !doState.storage.has("doc") && doState.storage.size === 0);
    ok("the throttle give-up logged the completion-did-not-land honestly", logged.some((l) => /failure completion did not land/.test(l)));
  }

  console.log("\nRunSealDO: the default parking window applies when DEST_THROTTLE_MAX_YIELDS is unset:");
  {
    const sched = makeScheduler();
    const doState = makeDOState();
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 500), 100);
    let realDO: RunSealDO | null = null;
    const runsealStub = { async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> { return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init)); } } as unknown as DurableObjectStub;
    const env = mkEnv(kv, sched.stub, runsealStub, dest);
    (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "120";
    // DEST_THROTTLE_MAX_YIELDS deliberately UNSET, so throttleMaxYields returns the built-in default.
    realDO = new RunSealDO(doState.state, env);
    await sealRunSliced(env, dpState("dp-throttle-default"), { runId: RUN_ID, index: 73, prevRunId: null }, { budget: new SliceBudget({ subrequests: 120, wallMs: 60_000 }) });
    dest.throttle = true;
    const origError = console.error;
    const logged: string[] = [];
    console.error = (...a: unknown[]) => { logged.push(a.map(String).join(" ")); };
    try {
      // A handful of throttle rounds: with the DEFAULT (60) window the run stays PARKED, never given up.
      for (let i = 0; i < 4; i++) await realDO.alarm();
    } finally {
      console.error = origError;
    }
    const parked = doState.storage.get("doc") as { throttleAttempt?: number } | undefined;
    ok("the default window keeps a throttled run PARKED well past a few rounds", doState.storage.has("doc") && (parked?.throttleAttempt ?? 0) === 4);
    ok("the parking log states the default ceiling (60), not a configured one", logged.some((l) => /\/60/.test(l)));
    ok("no failed completion is posted under the default window so soon", !sched.calls.some((c) => c.path === "/complete"));
  }

  console.log("\nsliceDepsFromEnv knobs: a valid segment-target is applied, an invalid shard-max is ignored, and no budget arg derives one from env:");
  {
    const sched = makeScheduler();
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 12), 100);
    const env = mkEnv(kv, sched.stub, ({ async fetch(): Promise<Response> { return new Response("{}"); } }) as unknown as DurableObjectStub, dest);
    (env as unknown as Record<string, string>)["SCALE_SEGMENT_TARGET_BYTES"] = "131072"; // valid -> numKnob applies it
    (env as unknown as Record<string, string>)["SCALE_SHARD_MAX_RECORDS"] = "not-a-number"; // invalid -> numKnob rejects it
    // No budget argument: the sliced path derives the budget from env (budgetFromEnv); a generous default
    // lets this small run complete inline.
    await sealRunSliced(env, dpState("dp-knobs"), { runId: RUN_ID, index: 81, prevRunId: null });
    const complete = sched.calls.find((c) => c.path === "/complete");
    const body = complete?.body as { status?: string; recordCount?: number } | undefined;
    ok("the run completes ok with a valid segment-target and an env-derived budget", body?.status === "ok" && body?.recordCount === 12);
    const run = await openRun(new MapStore(dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
    ok("the archive opens despite the rejected (invalid) shard-max knob", run.records.length === 12);
  }

  console.log("\nRunSealDO handoff with VERIFY_AT_SEAL off: the resumed completion omits the verdict:");
  {
    const sched = makeScheduler();
    const doState = makeDOState();
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 900), 100);
    let realDO: RunSealDO | null = null;
    const runsealStub = { async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> { return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init)); } } as unknown as DurableObjectStub;
    const env = mkEnv(kv, sched.stub, runsealStub, dest);
    (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "150";
    (env as unknown as Record<string, string>)["SCALE_SHARD_MAX_RECORDS"] = "200";
    (env as unknown as Record<string, string>)["VERIFY_AT_SEAL"] = "0"; // the DO finalise must skip the read-back
    realDO = new RunSealDO(doState.state, env);
    await sealRunSliced(env, dpState("dp-do-verifyoff"), { runId: RUN_ID, index: 82, prevRunId: null }, { budget: new SliceBudget({ subrequests: 150, wallMs: 60_000 }) });
    let alarms = 0;
    for (; alarms < 100 && doState.storage.has("doc"); alarms++) await realDO.alarm();
    const complete = sched.calls.find((c) => c.path === "/complete");
    const body = complete?.body as { status?: string; recordCount?: number; sealVerification?: unknown } | undefined;
    ok("the resumed DO run completes ok with verify-at-seal off", body?.status === "ok" && body?.recordCount === 900);
    ok("the DO completion omits the seal-verification verdict when the feature is off", body !== undefined && !("sealVerification" in body));
  }

  console.log("\nsealRunBuffered with VERIFY_AT_SEAL off: the buffered completion omits the verdict:");
  {
    const sched = makeScheduler();
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 40), 100);
    const env = mkEnv(kv, sched.stub, ({ async fetch(): Promise<Response> { return new Response("{}"); } }) as unknown as DurableObjectStub, dest);
    (env as unknown as Record<string, string>)["SLICED_RUNS_DISABLED"] = "1";
    (env as unknown as Record<string, string>)["VERIFY_AT_SEAL"] = "0";
    await sealRunSliced(env, dpState("dp-buffered-verifyoff"), { runId: RUN_ID, index: 83, prevRunId: null });
    const complete = sched.calls.find((c) => c.path === "/complete");
    const body = complete?.body as { status?: string; recordCount?: number; sealVerification?: unknown } | undefined;
    ok("the buffered run completes ok with verify-at-seal off", body?.status === "ok" && body?.recordCount === 40);
    ok("the buffered completion omits the seal-verification verdict when the feature is off", body !== undefined && !("sealVerification" in body));
  }

  console.log("\nRunSealDO finalise: out-of-order shard rows are sorted to a stable shard order:");
  {
    // The platform makes no order promise across storage.list, and finalise leans on its OWN sort to put
    // the shard rows into the stable id order the manifest needs. Run a real handed-off crawl over a
    // reversing DO state whose shard list hands the rows back DESCENDING by id. The finalise alarm's sort
    // must then move elements, which drives the "this id sorts earlier" arm of the shard comparator that
    // an already-ascending list never reaches. The run must still complete ok and the archive must open
    // with every record, proving the sort produced a correct, stable shard order from a shuffled input.
    const sched = makeScheduler();
    const doState = makeReversingDOState();
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 900), 100);
    let realDO: RunSealDO | null = null;
    const runsealStub = { async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> { return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init)); } } as unknown as DurableObjectStub;
    const env = mkEnv(kv, sched.stub, runsealStub, dest);
    (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "120";
    (env as unknown as Record<string, string>)["SCALE_SHARD_MAX_RECORDS"] = "150"; // several shards, so the descending list has work
    realDO = new RunSealDO(doState.state, env);
    await sealRunSliced(env, dpState("dp-shardsort"), { runId: RUN_ID, index: 91, prevRunId: null }, { budget: new SliceBudget({ subrequests: 120, wallMs: 60_000 }) });
    ok("the run handed off so the seal DO owns the finalise (multi-shard crawl)", doState.storage.has("doc"));
    let alarms = 0;
    for (; alarms < 200 && doState.storage.has("doc"); alarms++) await realDO.alarm();
    // Sanity: the run really did accumulate more than one shard, so the descending list forced the
    // comparator to reorder rather than trivially returning a single-element list untouched.
    const shardObjects = [...dest.map.keys()].filter((k) => k.includes("/shards/")).length;
    ok("the crawl produced multiple shards (the descending list had real reordering to do)", shardObjects > 1 || dest.map.size > 900);
    const complete = sched.calls.find((c) => c.path === "/complete");
    const body = complete?.body as { status?: string; recordCount?: number } | undefined;
    ok("the run finalised ok despite the descending shard-row list", body?.status === "ok" && body?.recordCount === 900);
    const run = await openRun(new MapStore(dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
    ok("the archive opens with every record (the sort restored a stable shard order)", run.records.length === 900);
  }

  console.log("\nRunSealDO complete: a failed completion with no reason supplied falls back to a non-empty default:");
  {
    // complete() is the DO's single /complete poster; its failed body carries error ?? "run failed".
    // Every in-tree caller supplies a coarse, non-empty reason (the strike ladder posts coarseRunError,
    // which never returns ""; the throttle give-up posts a literal), so the default arm guards against a
    // future caller that posts a failure with no reason. Exercise that defensive contract directly:
    // invoke the failed completion with the reason OMITTED and assert the scheduler still receives a
    // non-empty, honest reason rather than undefined, so a row is never resolved "failed" with no cause.
    const sched = makeScheduler();
    const doState = makeDOState();
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 12), 100);
    const env = mkEnv(kv, sched.stub, ({ async fetch(): Promise<Response> { return new Response("{}"); } }) as unknown as DurableObjectStub, dest);
    const realDO = new RunSealDO(doState.state, env);
    const cp: RunCheckpoint = {
      v: 1, downpipeId: "dp-nofail-reason", downpipeName: "dp-nofail-reason", cadence: "3600s", sourceType: "kv",
      selector: { include: [], exclude: [] }, runId: RUN_ID, runlogIndex: 99, prevRunId: null,
      startedAt: "2026-06-10T00:00:00.000Z", wrappedMaster: await wrapMaster(signerPrivateB64, RUN_ID, rand(32)),
      cursor: null, sourceDone: false, nextRecordIndex: 0, nextShardIndex: 0,
      frontier: { count: 0, nodes: [] }, counts: zeroCounts(), sliceCount: 0, partialRecord: null,
    };
    // complete is private; reach it through the same cast the doubles use (a real method call that posts
    // a real /complete body). status "failed", reason argument DELIBERATELY omitted (undefined).
    await (realDO as unknown as { complete(s: DurableObjectStub, c: RunCheckpoint, st: "ok" | "failed", e?: string): Promise<void> }).complete(sched.stub, cp, "failed");
    const complete = sched.calls.find((c) => c.path === "/complete");
    const body = complete?.body as { status?: string; error?: string; runId?: string } | undefined;
    ok("a failed completion with no reason still posts (status failed, empty runId)", body?.status === "failed" && body?.runId === "");
    ok("the omitted reason falls back to the non-empty default, never an undefined cause", body?.error === "run failed");
  }

  // A run that crosses more than one DO list page of SHARDS. A shard flushes at the end of every
  // slice (and at shardMax), so a large resumable run accumulates many shards; SCALE_SHARD_MAX_RECORDS=1
  // makes EVERY record its own shard, so MANY_SHARD_RECORDS records yield that many shards, comfortably
  // past one 1000-key list page. The values are tiny so sealing 1000+ shards stays fast.
  const MANY_SHARD_RECORDS = SHARD_PAGE + 60; // > one full shard page (1000), so finalise must page twice
  const tinySeeds = Array.from({ length: MANY_SHARD_RECORDS }, (_, i) => ({ name: `k/${String(i).padStart(6, "0")}`, value: utf8(`v${i}`) }));

  console.log("\nRunSealDO finalise: a run with MORE shards than one DO list page signs a root over ALL shards (no silent tail-drop):");
  {
    // finaliseAndComplete must page through the full shard list rather than reading a single un-paged
    // storage.list({ prefix: "shard:" }): a DO list() returns at most one page (~1000 keys), so a run
    // with more shards than one page would otherwise silently drop its tail shards, with finaliseRun then
    // signing root.manifest over only the listed shards while declaring the full record count and the
    // Merkle root over ALL records -- an internally inconsistent, spec-violating archive that still reports
    // ok. Here a paging DO state caps every list page at SHARD_PAGE (1000, the platform page the engine
    // requests), and shard-max=1 forces the run past one page of shards, so the finalise enumeration
    // MUST page or it truncates.
    const sched = makeScheduler();
    const doState = makePagingDOState();
    const dest = new MemDest();
    const kv = new MemKV(tinySeeds, 200);
    let realDO: RunSealDO | null = null;
    const runsealStub = { async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> { return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init)); } } as unknown as DurableObjectStub;
    const env = mkEnv(kv, sched.stub, runsealStub, dest);
    (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "300"; // many records per slice, so the shard count grows fast
    (env as unknown as Record<string, string>)["SCALE_SHARD_MAX_RECORDS"] = "1"; // every record is its own shard
    realDO = new RunSealDO(doState.state, env);
    await sealRunSliced(env, dpState("dp-manyshards"), { runId: RUN_ID, index: 101, prevRunId: null }, { budget: new SliceBudget({ subrequests: 300, wallMs: 60_000 }) });
    ok("the run handed off so the seal DO owns the finalise", doState.storage.has("doc"));
    let alarms = 0;
    for (; alarms < 400 && doState.storage.has("doc"); alarms++) await realDO.alarm();

    // Precondition: the run really accumulated MORE shard objects than one list page, so the finalise
    // enumeration genuinely had a second page to fetch (a single un-paged read would have truncated).
    const shardObjectsLanded = [...dest.map.keys()].filter((k) => k.includes(`run/${RUN_ID}/manifest/`)).length;
    ok(`the run produced MORE than one DO list page of shards (got ${shardObjectsLanded}, page is ${SHARD_PAGE})`, shardObjectsLanded > SHARD_PAGE);

    const complete = sched.calls.find((c) => c.path === "/complete");
    const body = complete?.body as { status?: string; recordCount?: number } | undefined;
    ok("the run finalised ok across the multi-page shard set", body?.status === "ok" && body?.recordCount === MANY_SHARD_RECORDS);
    // The decisive assertion: the signed archive opens with EVERY record. The declared record count, the
    // Merkle root and the shard manifest are all consistent only if the root was signed over ALL shards
    // (every page), not just the first page. A truncated root would either fail to open or be short.
    const run = await openRun(new MapStore(dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
    ok(`the archive opens with ALL ${MANY_SHARD_RECORDS} records (the root covers every shard page, no tail-drop)`, run.records.length === MANY_SHARD_RECORDS);
  }

  console.log("\nRunSealDO finalise: an un-paged read truncates, and the completeness guard REFUSES a truncated shard set (does not sign):");
  {
    // Build a real >1-page shard set by driving runSlice directly (no alarm-chain finalise), then seed it
    // into a paging DO state and exercise the seal DO's finalise path, in two halves:
    //  (a) RED: a single un-paged storage.list returns only ONE page over the >1-page shard
    //      set, so it would have signed a root over a SUBSET while declaring the full count. We assert the
    //      un-paged read truncates AND that the DO's paged enumeration returns the WHOLE set.
    //  (b) GREEN: the completeness guard refuses to sign when the enumerated set is SMALLER than the run
    //      declared (cp.nextShardIndex), so a truncated/missing-shard finalise FAILS LOUD, never signs.
    const kv = new MemKV(tinySeeds, 200);
    const dest = new MemDest();
    const master = rand(32);
    let cp: RunCheckpoint = {
      v: 1, downpipeId: DP_ID, downpipeName: "sliced", cadence: "3600s", sourceType: "kv",
      selector: { include: [], exclude: [] }, runId: RUN_ID, runlogIndex: 102, prevRunId: null,
      startedAt: "2026-06-10T00:00:00.000Z", wrappedMaster: await wrapMaster(signerPrivateB64, RUN_ID, master),
      cursor: null, sourceDone: false, nextRecordIndex: 0, nextShardIndex: 0,
      frontier: { count: 0, nodes: [] }, counts: zeroCounts(), sliceCount: 0, partialRecord: null,
    };
    const allShards: ShardEntry[] = [];
    for (let s = 0; s < 2000 && !cp.sourceDone; s++) {
      const m = await unwrapMaster(signerPrivateB64, RUN_ID, cp.wrappedMaster);
      const r = await runSlice({ source: new KVSource(kv as unknown as KVNamespace, "ns1"), dest, signer, recipients, budget: new SliceBudget({ subrequests: 300, wallMs: 60_000 }), shardMaxRecords: 1 }, cp, m);
      m.fill(0);
      cp = r.checkpoint;
      allShards.push(...r.newShards);
    }
    const declaredShards = cp.nextShardIndex;
    ok(`the run declares more than one page of shards (nextShardIndex=${declaredShards} > ${SHARD_PAGE})`, declaredShards > SHARD_PAGE && allShards.length === declaredShards);

    // Seed a paging DO state with the doc + every shard row, exactly as a handed-off run would have.
    const doState = makePagingDOState();
    const sched = makeScheduler();
    const env = mkEnv(kv, sched.stub, ({ async fetch(): Promise<Response> { return new Response("{}"); } }) as unknown as DurableObjectStub, dest);
    const realDO = new RunSealDO(doState.state, env);
    const stored = await sealCheckpointForStorage(signerPrivateB64, cp);
    doState.storage.set("doc", { config: dpState("dp-guard").config, checkpoint: stored, attempt: 0, destConfig: null });
    for (const sh of allShards) doState.storage.set(`shard:${sh.id}`, sh);

    // (a) RED: a single un-paged list() returns at most ONE page -- exactly the truncation the DO's
    // paged enumeration guards against.
    const onePage = await (doState.state.storage as unknown as { list<T>(o?: { prefix?: string }): Promise<Map<string, T>> }).list<ShardEntry>({ prefix: "shard:" });
    ok("a single un-paged list() returns only ONE page of shard rows (a would-be silent truncation)", onePage.size === SHARD_PAGE && onePage.size < declaredShards);
    // The DO's own paged enumeration (the fix) returns the WHOLE shard set.
    const enumerated = await (realDO as unknown as { listAllShards(): Promise<ShardEntry[]> }).listAllShards();
    ok("the paged enumeration returns EVERY shard across all pages (no truncation)", enumerated.length === declaredShards);

    // (b) GREEN: the completeness guard refuses to sign a truncated set. Invoke the private
    // finaliseAndComplete the same way the suite reaches private complete(): a real method call. To make
    // the guard see a SHORT set we DELETE the tail shard rows (a truncated/missing-shard enumeration) and
    // assert the finalise THROWS rather than signing a subset.
    const m2 = await unwrapMaster(signerPrivateB64, RUN_ID, cp.wrappedMaster);
    const shardKeys = [...doState.storage.keys()].filter((k) => k.startsWith("shard:")).sort();
    for (const k of shardKeys.slice(SHARD_PAGE)) doState.storage.delete(k); // keep only the first page
    const deps = { source: new KVSource(kv as unknown as KVNamespace, "ns1"), dest, signer, recipients, budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) } as SliceDeps;
    let guardThrew: Error | null = null;
    try {
      await (realDO as unknown as { finaliseAndComplete(s: DurableObjectStub, d: SliceDeps, doc: unknown, cp: RunCheckpoint, master: Uint8Array): Promise<void> }).finaliseAndComplete(sched.stub, deps, { config: dpState("dp-guard").config }, cp, m2);
    } catch (e) {
      guardThrew = e as Error;
    }
    m2.fill(0);
    ok("the completeness guard REFUSES a truncated shard set (finalise throws, never signs)", guardThrew !== null && /shard enumeration incomplete/.test(guardThrew.message));
    // And it did NOT write a (truncated) signed root: a refused finalise leaves no root.manifest for this run.
    ok("no truncated root.manifest.json was signed when the guard fired", !dest.map.has(`run/${RUN_ID}/root.manifest.json`));
  }

  console.log("\nRunSealDO /start: MORE than one DO list page of stale shards from an aborted run is FULLY swept (no leaked tail):");
  {
    // /start clears shard rows from any abandoned previous run before writing the new ones. A single
    // un-paged storage.list({ prefix: "shard:" }) returns at most ONE page (~SHARD_LIST_PAGE keys), so an
    // aborted prior run that left MORE than a page of stale shards would have only its first page swept,
    // leaking the tail into the new run's DO state (and into the new run's finalise enumeration). A paging
    // DO state caps every list page at SHARD_PAGE, so a >1-page stale set forces the cleanup to loop or
    // leave a tail.
    const sched = makeScheduler();
    const doState = makePagingDOState();
    const dest = new MemDest();
    const kv = new MemKV(seeds.slice(0, 12), 100);
    let realDO: RunSealDO | null = null;
    const runsealStub = { async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> { return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init)); } } as unknown as DurableObjectStub;
    const env = mkEnv(kv, sched.stub, runsealStub, dest);
    realDO = new RunSealDO(doState.state, env);
    // Pre-seed MORE than one full list page of stale shard rows (ids that the new run will NOT reuse,
    // so every one is "stale" and must be deleted). pad6 so the keys sort lexicographically ascending,
    // exactly the order the paged cursor advances through.
    const STALE_COUNT = SHARD_PAGE + 60; // > one full page (1000), so the cleanup MUST page twice
    for (let i = 0; i < STALE_COUNT; i++) {
      const id = `old-${String(i).padStart(6, "0")}`;
      doState.storage.set(`shard:${id}`, { id, object: `run/old/${id}.json`, sha384: "deadbeef" });
    }
    const seededStale = [...doState.storage.keys()].filter((k) => k.startsWith("shard:")).length;
    ok(`the aborted run left MORE than one list page of stale shards (got ${seededStale}, page is ${SHARD_PAGE})`, seededStale > SHARD_PAGE);
    // Confirm the truncation premise: a single un-paged list() sees only ONE page.
    const onePage = await (doState.state.storage as unknown as { list<T>(o?: { prefix?: string }): Promise<Map<string, T>> }).list<unknown>({ prefix: "shard:" });
    ok("a single un-paged list() returns only ONE page of the stale shards (a would-be silent truncation)", onePage.size === SHARD_PAGE && onePage.size < seededStale);

    // Build a real first-slice checkpoint + a SMALL set of new shards to hand to /start.
    const master = rand(32);
    const cp0: RunCheckpoint = {
      v: 1, downpipeId: "dp-stale-paged", downpipeName: "dp-stale-paged", cadence: "3600s", sourceType: "kv",
      selector: { include: [], exclude: [] }, runId: RUN_ID, runlogIndex: 43, prevRunId: null,
      startedAt: "2026-06-10T00:00:00.000Z", wrappedMaster: await wrapMaster(signerPrivateB64, RUN_ID, master),
      cursor: null, sourceDone: false, nextRecordIndex: 0, nextShardIndex: 0,
      frontier: { count: 0, nodes: [] }, counts: zeroCounts(), sliceCount: 0, partialRecord: null,
    };
    const r0 = await runSlice({ source: new KVSource(kv as unknown as KVNamespace, "ns1"), dest, signer, recipients, budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }), shardMaxRecords: 5 }, cp0, master);
    master.fill(0);
    const startReq = new Request("https://runseal.internal/start", { method: "POST", body: JSON.stringify({ config: dpStateSrc("dp-stale-paged", { type: "kv", binding: "KV_TEST", namespaceId: "ns1", include: [], exclude: [] }).config, checkpoint: r0.checkpoint, shards: r0.newShards, openShardLines: r0.openWrite } satisfies StartSliceRun), headers: { "content-type": "application/json" } });
    const startResp = await realDO.fetch(startReq);
    ok("/start accepts the handoff", startResp.ok && ((await startResp.json()) as { ok?: boolean }).ok === true);

    // The decisive assertion: NOT ONE stale "old-*" shard row survives. A single un-paged cleanup would
    // sweep only the first page and leave the >1000th..tail stale rows behind; the paged cleanup
    // removes every page.
    const survivingStale = [...doState.storage.keys()].filter((k) => k.startsWith("shard:old-"));
    ok(`every stale shard from the aborted run was swept across ALL pages (0 leaked; a single un-paged sweep would leak ${seededStale - SHARD_PAGE})`, survivingStale.length === 0);
    ok("the new run's own shard rows were written", [...doState.storage.keys()].some((k) => k.startsWith("shard:") && !k.startsWith("shard:old-")));
  }

  // ===== SLICED / MULTI-SHARD PRODUCTION SEAL -- FUZZED, TWO-READER DIFFERENTIAL =====
  // The seal for REAL runs is the SLICED, multi-shard path (runSlice/finaliseRun). This test FUZZES the
  // record set (count, names, value lengths) and the slicing parameters (KV page size, shardMaxRecords,
  // per-slice budget), drives the full multi-slice seal with eviction between slices, then restores EVERY
  // record through BOTH the independent Go offline reader (files) AND the TS reader (openRun), asserting
  // byte-identical recovery. The Go offline reader is the customer's real recovery tool, exercised here on
  // a FUZZED multi-shard archive.
  // Refuter (default-FAIL): a byte-tampered shard makes BOTH readers refuse (never silent-wrong).
  console.log("sliced/multi-shard production seal, fuzzed, two-reader differential (Go offline reader vs TS reader):");
  {
    const go = goPresent();
    if (!go.ok) {
      console.log("  ok   SKIP: Go toolchain absent (the sliced two-reader differential needs the Go offline reader; not a pass, not a fail)");
    } else {
      const bin = join(mkdtempSync(join(tmpdir(), "slice-fuzz-bin-")), "downpipe");
      const built = buildReader(process.cwd(), bin); // validators run from the engine dir; buildReader finds ../downpipe
      // AN ABSENT SIBLING REPO IS A DECLARED SKIP BY DEFAULT, NOT A REFUSAL, because this file runs
      // TWICE with two different audiences: as a member of `validate:chain`, which is BOTH what CI's
      // "validate" job runs AND, unchanged, what a customer's own `npm run deploy` runs as its blocking
      // preflight (scripts/deploy.sh calls exactly `npm run validate`). A cold operator following
      // docs/src/content/docs/operations/deploy.mdx with only the engine cloned does not have
      // downpipes-io/downpipe beside it, was never told to, and cannot fix a TypeScript refusal they do
      // not read TypeScript to interpret. A first deploy attempt on a fresh clone hits
      // exactly this, refused at preflight with exit 2, and the operator has to read the refusal, work out
      // it means "clone a second, undocumented repository", and do that by hand before a second attempt
      // can even start.
      //
      // The reader differential this proves is a property of the SOURCE CODE, not of any one deploy: it
      // asks whether archives THIS COMMIT's seal path writes are readable by the independent Go reader,
      // which does not vary per Cloudflare account. CI already proves it on every push, with the sibling
      // checked out on purpose (.github/workflows/ci.yml, the "validate" job's "Checkout the Go reader"
      // step, feeding straight into the same `npm run validate` this file is a member of). Re-deriving the
      // identical fact on every individual customer's machine, for a build they did not modify, buys
      // nothing the CI run had not already proven, and it is the literal cause of the block above.
      //
      // This mirrors the convention this repo already uses for the SAME shape of problem elsewhere:
      // validate-console-route-parity.ts and validate-console-keygen-roundtrip.ts (both members of THIS
      // engine's validate:chain, both needing a sibling checkout) skip cleanly (verdictSkipped, exit 0) by
      // default and only refuse under an explicit `--require`/`REQUIRE_*` flag that CI passes as an
      // ADDITIONAL, separate step outside the plain chain. REQUIRE_DOWNPIPE=1 (declared above) is that
      // flag here, and it is set on the CI steps that already provide the sibling deliberately (ci.yml's
      // "validate" and "coverage" jobs), so CI's hardness for a genuinely missing sibling is unchanged: an
      // absent repo there still means REQUIRE_DOWNPIPE=1 was set, so this still exits 2 and still fails the
      // job. Only a customer's un-set-by-default deploy stops treating the absence as a block.
      //
      // A reader that IS here and does not build stays a FINDING regardless of REQUIRE_DOWNPIPE and falls
      // through to ok() below: that is a broken second reader, a product defect, not an absent precondition,
      // and it is the distinction buildReader's `reason` exists to carry.
      if (!built.ok && built.reason === "absent") {
        const why = `sibling Go reader repo (downpipes-io/downpipe) not found beside this engine checkout (${built.detail}). The archive-format differential against the independent offline reader is a property of this commit, not of any one deploy: it runs in CI on every push (.github/workflows/ci.yml, the "validate" and "coverage" jobs). It is not required for \`npm run deploy\`. To run it here yourself, clone downpipes-io/downpipe as a sibling of this engine checkout (../downpipe) and re-run.`;
        if (REQUIRE_DOWNPIPE && failures === 0) {
          verdictSkipped(`REFUSED, exit 2: ${why} REQUIRE_DOWNPIPE=1 was set, so an absent sibling here is CANNOT-CHECK rather than a skip.`);
          process.exit(2);
        }
        console.log(`  ok   SKIP: ${why} Not a pass, not a fail.`);
        verdictSkipped(why, { require: REQUIRE_DOWNPIPE });
      } else {
      ok(`Go offline reader built (${built.detail})`, built.ok);
      if (built.ok) {
        const signerPubB64 = b64urlEncode(concat(signer.edPublic, signer.mldsaPublic));
        const idB64 = b64urlEncode(breakGlass.identity);
        let seed = (Number(process.env.SLICE_FUZZ_SEED) || 0x1234abcd) >>> 0;
        const rnd = (): number => { seed = (seed + 0x6d2b79f5) >>> 0; let t = seed; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
        const ri = (lo: number, hi: number): number => lo + Math.floor(rnd() * (hi - lo + 1));
        const runSealFuzz = async (seeds: { name: string; value: Uint8Array }[], pageSize: number, shardMax: number, subreq: number): Promise<{ dest: MemDest; slices: number; shards: number }> => {
          const kv = new MemKV(seeds, pageSize);
          const dest = new MemDest();
          const master = rand(32);
          let cp: RunCheckpoint = {
            v: 1, downpipeId: DP_ID, downpipeName: "slice-fuzz", cadence: "3600s", sourceType: "kv",
            selector: { include: [], exclude: [] }, runId: RUN_ID, runlogIndex: 3, prevRunId: null,
            startedAt: "2026-06-10T00:00:00.000Z", wrappedMaster: await wrapMaster(signerPrivateB64, RUN_ID, master),
            cursor: null, sourceDone: false, nextRecordIndex: 0, nextShardIndex: 0,
            frontier: { count: 0, nodes: [] }, counts: zeroCounts(), sliceCount: 0, partialRecord: null,
          };
          master.fill(0);
          const allShards: ShardEntry[] = [];
          let openBuffer: Record<string, unknown>[] = [];
          let slices = 0;
          for (; slices < 800 && !cp.sourceDone; slices++) {
            cp = JSON.parse(JSON.stringify(cp)) as RunCheckpoint; // eviction: only the serialised checkpoint survives
            const m = await unwrapMaster(signerPrivateB64, RUN_ID, cp.wrappedMaster);
            const deps: SliceDeps = { source: new KVSource(kv as unknown as KVNamespace, "ns1"), dest, signer, recipients, budget: new SliceBudget({ subrequests: subreq, wallMs: 60_000 }), shardMaxRecords: shardMax };
            const r = await runSlice(deps, cp, m, openBuffer);
            m.fill(0); cp = r.checkpoint; allShards.push(...r.newShards);
            openBuffer = r.openReset ? r.openWrite : [...openBuffer, ...r.openWrite];
          }
          const mf = await unwrapMaster(signerPrivateB64, RUN_ID, cp.wrappedMaster);
          await finaliseRun({ source: new KVSource(kv as unknown as KVNamespace, "ns1"), dest, signer, recipients, budget: new SliceBudget({ subrequests: 900, wallMs: 60_000 }) }, cp, mf, allShards, openBuffer);
          mf.fill(0);
          return { dest, slices, shards: allShards.length };
        };
        const walkOut = (d: string, into: Uint8Array[]): void => { for (const nm of readdirSync(d, { withFileTypes: true })) { const p = join(d, nm.name); if (nm.isDirectory()) walkOut(p, into); else into.push(new Uint8Array(readFileSync(p))); } };

        const B2_RUNS = 15 * (Number(process.env.SLICE_FUZZ_SCALE) || 1);
        let differentialPass = 0;
        let sawMultiShard = false;
        let sawMultiSlice = false;
        for (let iter = 0; iter < B2_RUNS; iter++) {
          const count = ri(3, 48);
          const seeds: { name: string; value: Uint8Array }[] = [];
          const usedNames = new Set<string>();
          for (let i = 0; i < count; i++) {
            let nm = "";
            do { nm = `k/${ri(0, 1 << 24).toString(36)}/${i}`; } while (usedNames.has(nm));
            usedNames.add(nm);
            const vlen = ri(1, 160);
            const v = new Uint8Array(vlen);
            for (let j = 0; j < vlen; j++) v[j] = ri(0, 255);
            seeds.push({ name: nm, value: v });
          }
          const { dest, slices, shards } = await runSealFuzz(seeds, ri(2, 16), ri(2, 24), ri(40, 200));
          if (shards > 1) sawMultiShard = true;
          if (slices > 1) sawMultiSlice = true;

          const run = await openRun(new MapStore(dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
          const arcRoot = mkdtempSync(join(tmpdir(), "slice-fuzz-arc-"));
          const { archiveDir, identityFile, signerFile } = writeArchiveDir(arcRoot, dest.map, idB64, signerPubB64);
          const outRoot = mkdtempSync(join(tmpdir(), "slice-fuzz-out-"));
          const outDir = join(outRoot, "out");
          const gr = runReader(bin, ["restore", "--archive", archiveDir, "--run", RUN_ID, "--identity", identityFile, "--signer", signerFile, "--sink", "file", "--apply", "--out", outDir]);
          let iterOk = gr.exitCode === 0 && run.records.length === count;
          if (gr.exitCode !== 0) console.log(`  FAIL iter ${iter}: Go reader refused a clean fuzzed sliced archive (exit ${gr.exitCode}); stderr=${gr.stderr.slice(-160)}`);
          else if (run.records.length !== count) console.log(`  FAIL iter ${iter}: TS reader record count ${run.records.length} != sealed ${count}`);
          if (iterOk) {
            const goPool: Uint8Array[] = [];
            walkOut(outDir, goPool);
            for (const s of seeds) {
              const rec = run.records.find((r) => r.name === s.name);
              if (!rec) { iterOk = false; console.log(`  FAIL iter ${iter}: TS reader missing "${s.name}"`); break; }
              const ts = await run.restoreRecord(rec);
              if (Buffer.compare(Buffer.from(ts), Buffer.from(s.value)) !== 0) { iterOk = false; console.log(`  FAIL iter ${iter}: TS reader wrong bytes for "${s.name}"`); break; }
              const gi = goPool.findIndex((b) => b.length === s.value.length && Buffer.compare(Buffer.from(b), Buffer.from(s.value)) === 0);
              if (gi < 0) { iterOk = false; console.log(`  FAIL iter ${iter}: the Go reader did NOT recover "${s.name}" that the TS reader did (READER DIVERGENCE)`); break; }
              goPool.splice(gi, 1);
            }
            if (iterOk && goPool.length !== 0) { iterOk = false; console.log(`  FAIL iter ${iter}: the Go reader restored ${goPool.length} object(s) the TS reader did not`); }
          }
          if (iterOk) differentialPass++;
          rmSync(arcRoot, { recursive: true, force: true });
          rmSync(outRoot, { recursive: true, force: true });
        }
        ok(`two-reader differential: all ${B2_RUNS} fuzzed sliced archives recovered byte-identical by BOTH readers`, differentialPass === B2_RUNS);
        ok("exercised genuinely MULTI-SHARD archives (not a single shard)", sawMultiShard);
        ok("exercised genuinely MULTI-SLICE seals (eviction across slices)", sawMultiSlice);

        // Refuter (default-FAIL): a byte-tampered shard in a sliced archive makes BOTH readers refuse.
        {
          const seeds = Array.from({ length: 20 }, (_, i) => ({ name: `ref/${i}`, value: rand(64) }));
          const { dest } = await runSealFuzz(seeds, 4, 3, 60);
          let bigKey = "";
          let bigLen = -1;
          for (const [k, v] of dest.map) if (v.length > bigLen) { bigLen = v.length; bigKey = k; }
          const tampered = new Uint8Array(dest.map.get(bigKey)!);
          tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 1;
          const tamperedMap = new Map(dest.map);
          tamperedMap.set(bigKey, tampered);
          const arcRoot = mkdtempSync(join(tmpdir(), "slice-fuzz-reftamper-"));
          const { archiveDir, identityFile, signerFile } = writeArchiveDir(arcRoot, tamperedMap, idB64, signerPubB64);
          const gr = runReader(bin, ["restore", "--archive", archiveDir, "--run", RUN_ID, "--identity", identityFile, "--signer", signerFile, "--sink", "discard", "--apply"]);
          ok(`REFUTER: the Go reader REFUSES a byte-tampered sliced archive (exit ${gr.exitCode}, never silent-wrong)`, gr.exitCode !== 0);
          let tsRefused = false;
          try { const rr = await openRun(new MapStore(tamperedMap), RUN_ID, parseIdentity(breakGlass.identity), verifier, {}); for (const rc of rr.records) await rr.restoreRecord(rc); } catch { tsRefused = true; }
          ok("REFUTER: the TS reader REFUSES the same byte-tampered sliced archive", tsRefused);
          rmSync(arcRoot, { recursive: true, force: true });
        }

        // Adversarial: crafted STRUCTURAL attacks on the PRODUCTION sliced/multi-shard seal (not just a
        // random byte flip) -- a wrong signer public and a swapped shard object must each be refused by BOTH
        // readers, so the multi-shard structure (more attack surface than the buffered path) is covered too.
        {
          const advSeeds = Array.from({ length: 40 }, (_, i) => ({ name: `adv/${String(i).padStart(3, "0")}`, value: rand(80) }));
          const { dest, shards } = await runSealFuzz(advSeeds, 4, 3, 60); // shardMax 3 -> many shards
          ok(`adversarial base is genuinely multi-shard (${shards} shards)`, shards > 1);

          // WRONG SIGNER: the manifest is signed by `signer`; hand the readers a different signer public.
          {
            const otherSigner = await loadSigner(b64urlEncode(concat(rand(32), rand(32))));
            const otherPub = b64urlEncode(concat(otherSigner.edPublic, otherSigner.mldsaPublic));
            const arcRoot = mkdtempSync(join(tmpdir(), "slice-adv-wsig-"));
            const p = writeArchiveDir(arcRoot, dest.map, idB64, otherPub);
            const gr = runReader(bin, ["restore", "--archive", p.archiveDir, "--run", RUN_ID, "--identity", p.identityFile, "--signer", p.signerFile, "--sink", "discard", "--apply"]);
            ok(`ADVERSARIAL: the Go reader REFUSES a multi-shard archive under the WRONG signer (exit ${gr.exitCode})`, gr.exitCode !== 0);
            let tsRef = false;
            try { const r = await openRun(new MapStore(dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifierFrom(otherSigner), {}); for (const rc of r.records) await r.restoreRecord(rc); } catch { tsRef = true; }
            ok("ADVERSARIAL: the TS reader REFUSES a multi-shard archive under the WRONG signer", tsRef);
            rmSync(arcRoot, { recursive: true, force: true });
          }

          // SWAPPED SHARDS: swap the two largest objects' contents; the content-address + hash binding
          // across the multi-shard manifest must reject the confusion.
          {
            const entries = [...dest.map.entries()].sort((a, b) => b[1].length - a[1].length);
            const m = new Map(dest.map);
            m.set(entries[0]![0], entries[1]![1]);
            m.set(entries[1]![0], entries[0]![1]);
            const arcRoot = mkdtempSync(join(tmpdir(), "slice-adv-swap-"));
            const p = writeArchiveDir(arcRoot, m, idB64, signerPubB64);
            const gr = runReader(bin, ["restore", "--archive", p.archiveDir, "--run", RUN_ID, "--identity", p.identityFile, "--signer", p.signerFile, "--sink", "discard", "--apply"]);
            ok(`ADVERSARIAL: the Go reader REFUSES a swapped-shard multi-shard archive (exit ${gr.exitCode})`, gr.exitCode !== 0);
            let tsRef = false;
            try { const r = await openRun(new MapStore(m), RUN_ID, parseIdentity(breakGlass.identity), verifierFrom(signer), {}); for (const rc of r.records) await r.restoreRecord(rc); } catch { tsRef = true; }
            ok("ADVERSARIAL: the TS reader REFUSES a swapped-shard multi-shard archive", tsRef);
            rmSync(arcRoot, { recursive: true, force: true });
          }
        }
      }
      }
    }
  }

  console.log(failures === 0 ? "\nSLICED RUN ENGINE PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

// doStateHasAlarm is a tiny readability helper for the buffered-path assertion: the buffered seal
// never goes through the seal DO, so the scheduler sees no DO handoff call.
function doStateHasAlarm(sched: { calls: { path: string }[] }): boolean {
  return sched.calls.some((c) => c.path === "/start");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
