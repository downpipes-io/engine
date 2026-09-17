// The chaos test suite's axis-scale coverage (Tier 1, deploy-free net-zero LOGIC). This validator proves large-run scale
// CORRECTNESS in-process over the REAL engine, to in-memory doubles: no estate, no bucket, no network, no
// seed, no deploy, no load, no spend. It is the net-zero core of the axis-scale design, covering
// cells (a)-(e) plus the default-FAIL refuters. It EXTENDS the shipped scale coverage
// (validate-fanout.ts byte-identity + merge, validate-slice.ts checkpoint/resume + the REAL RunSealDO alarm
// chain, validate-fleet-scale.ts pagination + bounded rings, validate-verify-at-seal.ts the three sampling
// bounds) with the DELTA the design names, elevated to the corpus discipline at the scale boundary:
//
//   (a) an INDEPENDENT oracle over a LARGE fanned-out archive: the harness-owned PLAINTEXT-SET oracle (the
//       restored plaintext multiset == the seeded multiset, a metamorphic invariant that never trusts the
//       engine's self-report and, per the feasibility review, never asserts byte-identity across the per-run
//       entropy) PLUS the sibling Go offline reader (../downpipe cmd/downpipe, a DIFFERENT codebase)
//       re-verifying the same fanned-out archive;
//   (b) the metered IN-BAND subrequest SLI (OpCounts off the budget fold, slice.ts:489) asserted at or below
//       the resolved slice budget every slice, WITH the yield firing before FINALISE_RESERVE -- the honest
//       measurable SLI, never the unmeasurable DO-CPU-vs-30s (meter.ts:14); plus the honest verify tier;
//   (c) a throttle / RUNLOG-contention park-and-resume that is LOSS-FREE and DUP-FREE against the plaintext-set
//       oracle across the park boundary (the delta over validate-slice, which only checks the self-reported
//       count);
//   (d) the ring-vs-archive-authority split: the bounded 50-entry run-history RING drops oldest under pressure
//       WHILE the append-only signed archive RUNLOG chain is the authority and NEVER drops a sealed run, with
//       the run-at-risk-eviction detector and the honest point-in-time bound;
//   (e) the AXIS4 sampling bound RESTATED at the scale boundary as an honest limit, never a false CLEAN.
//
// NET-ZERO by construction: harness-minted keys (x25519.keygen() + a random ML-KEM seed, never a customer
// key), fake records, in-memory MemDest / DO-storage doubles, a local hermetic `go run` over a temp dir.
// Teardown is process exit (+ os.tmpdir cleanup). ~/Desktop/downpipes-live-keys is never read.
//
// Run: node test/validate-scale-tier1.ts
//
// House style: Australian English, no em dashes, no rule-of-three.

import { createHash } from "node:crypto";
import { rmSync } from "node:fs";

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { buildArchive, parseRunlog, type RecipientEntry, type RunlogEntry, type Signer, signRunlog, type WriteRecord } from "../src/format/writer.ts";
import { finaliseRun, runSlice, type ShardEntry, type SliceDeps } from "../src/seal/slice.ts";
import { zeroCounts, type RunCheckpoint } from "../src/seal/checkpoint.ts";
import { budgetFromEnv, DEFAULT_SLICE_SUBREQUESTS, FINALISE_RESERVE, MAX_SLICE_SUBREQUESTS, SliceBudget } from "../src/seal/budget.ts";
import { countPage, deleteScratchShards, FANOUT_MAX_RANGE_KEYS, FANOUT_MAX_RANGES, type FanoutRange, finishCount, mergeStep, newMergeState, newPlanScan, planFanout, rangesFromSplitKeys, sealRangeOpenShard, stridePage } from "../src/seal/fanout.ts";
import { RunSealDO, sealRunSliced } from "../src/seal/runstate.ts";
import { appendRunlog } from "../src/seal/pipeline.ts";
import { verifyAtSeal } from "../src/seal/verify-at-seal.ts";
import { isRunEvictionRisk } from "../src/notify/types.ts";
import { resolveRunAt } from "../src/admin/point-in-time.ts";
import type { RunHistoryEntry } from "../src/sched/types.ts";
import { KVSource } from "../src/sources/kv.ts";
import type { Selector } from "../src/sources/types.ts";
import type { DownpipeState } from "../src/sched/scheduler-do.ts";
import type { Env } from "../src/env.d.ts";
import type { Destination, GetResult, ListPage, PutConditionalResult } from "../src/dest/types.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { makeScheduler as makeSchedulerDO, makeConfig, stubFetch } from "./validate-scheduler-shared.ts";
import { buildReader, copyArchiveRoot, flipLastByte, goPresent, newTmpRoot, restoreDiscardArgs, runReader, writeArchiveDir } from "./scale-go-reader.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

// A fixed valid ULID for the non-orchestrated cells (the seal is per-run non-deterministic regardless).
const RUN_ID = "01BX5ZZKBKACTAV9WEVGEMMVRY";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
function section(title: string): void {
  console.log(`\n${title}`);
}

function rand(n: number): Uint8Array {
  // crypto.getRandomValues caps at 65 536 bytes per call, so fill a large buffer in chunks (the one large
  // multi-segment value in cell (a) exceeds it).
  const out = new Uint8Array(n);
  for (let off = 0; off < n; off += 65_536) crypto.getRandomValues(out.subarray(off, Math.min(off + 65_536, n)));
  return out;
}

// sha384Hex is the INDEPENDENT oracle hash: node's own crypto, never the engine's sha384 or the Go reader's,
// so a shared crypto bug in both ports cannot hide from the plaintext-set oracle (write-corpus-archive.ts
// uses the same node-crypto idiom for exactly this reason).
function sha384Hex(bytes: Uint8Array): string {
  return createHash("sha384").update(Buffer.from(bytes)).digest("hex");
}

interface Recipient {
  entry: RecipientEntry;
  identity: Uint8Array; // downpipe-identity-v1 body: x25519 scalar(32) || ML-KEM seed(64)
}
function makeRecipient(role: string): Recipient {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// ---- the harness-owned PLAINTEXT-SET oracle (the metamorphic invariant) --------------------------------
// The harness KNOWS the fake record set it fed in, so it asserts the engine's output against THAT truth,
// never the engine's self-report. A "pair" is name|node-crypto-SHA-384(plaintext); the multiset is the
// SORTED join of the pairs, so equality means the restored plaintext set == the seeded plaintext set
// EXACTLY (no loss, no duplicate, no substitution). Per the feasibility review the oracle compares the
// PLAINTEXT SET, never archive bytes (per-run entropy makes the bytes non-deterministic by design).
interface Rec {
  name: string;
  value: Uint8Array;
}
function fedMultiset(recs: Rec[]): string {
  return JSON.stringify(recs.map((r) => `${r.name}|${sha384Hex(r.value)}`).sort());
}
async function restoredMultiset<R extends { name: string }>(run: { records: R[]; restoreRecord: (r: R) => Promise<Uint8Array> }): Promise<string> {
  const pairs: string[] = [];
  for (const rec of run.records) pairs.push(`${rec.name}|${sha384Hex(await run.restoreRecord(rec))}`);
  return JSON.stringify(pairs.sort());
}

// ---- in-memory doubles (modelled on validate-fanout.ts / validate-slice.ts MemDest+MemKV+MapStore) -----

// MemDest: the full Destination contract over a map (etagged, conditional). `throttle` makes every WRITE
// throw a 503 SlowDown; `contend` makes the RUNLOG conditional write report a precondition failure; both
// clear to let the SAME parked run resume (the validate-slice fault-double pattern, unified here).
class MemDest implements Destination {
  map = new Map<string, Uint8Array>();
  private tags = new Map<string, string>();
  private seq = 0;
  throttle = false;
  contend = false;
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
    if (this.throttle) throw new Error(`PUT ${key}: status 503`);
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
    if (this.contend && key === "_RECOVERY/RUNLOG") return { ok: false };
    if (this.throttle) throw new Error(`PUT ${key}: status 503`);
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
  async listPage(prefix: string): Promise<ListPage> {
    return { keys: await this.list(prefix) };
  }
}

// MemKV: a paginated KVNamespace double (list + getWithMetadata), keys kept in sorted order.
class MemKV {
  private seeds: { name: string; value: Uint8Array }[];
  private pageSize: number;
  constructor(seeds: { name: string; value: Uint8Array }[], pageSize: number) {
    this.seeds = [...seeds].sort((a, b) => (a.name < b.name ? -1 : 1));
    this.pageSize = pageSize;
  }
  async list(options?: { prefix?: string; cursor?: string }): Promise<{ keys: { name: string }[]; list_complete: boolean; cursor?: string; cacheStatus: null }> {
    const start = options?.cursor !== undefined ? Number(options.cursor) : 0;
    const prefix = options?.prefix;
    const all = prefix === undefined ? this.seeds : this.seeds.filter((s) => s.name.startsWith(prefix));
    const page = all.slice(start, start + this.pageSize);
    const next = start + this.pageSize;
    const complete = next >= all.length;
    return { keys: page.map((s) => ({ name: s.name })), list_complete: complete, ...(complete ? {} : { cursor: String(next) }), cacheStatus: null };
  }
  async getWithMetadata(key: string, _t: "arrayBuffer"): Promise<{ value: ArrayBuffer | null; metadata: unknown; cacheStatus: null }> {
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
  list(prefix: string): Promise<string[]> {
    return Promise.resolve([...this.map.keys()].filter((k) => k.startsWith(prefix)));
  }
}

// ---- the REAL RunSealDO serial alarm chain wiring (validate-slice.ts mkEnv pattern) --------------------
// nsFor wraps a stub into a DurableObjectNamespace; makeSealScheduler is the scheduler double (heartbeat
// owns the lease, the RUNLOG lock returns not-acquired so the lock-free CAS is exercised); makeDOState is
// the Map-backed DurableObjectState with alarm capture; mkEnv wires an R2Bucket facade over a MemDest so a
// throttle/contention fault on the MemDest reaches the REAL seal path.
function nsFor(stub: DurableObjectStub): DurableObjectNamespace {
  return { idFromName: (_n: string) => ({}) as DurableObjectId, get: (_id: DurableObjectId) => stub } as unknown as DurableObjectNamespace;
}
function makeSealScheduler(): { stub: DurableObjectStub; calls: { path: string; body?: unknown }[] } {
  const calls: { path: string; body?: unknown }[] = [];
  const stub = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const body = init?.body ? JSON.parse(String(init.body)) : undefined;
      calls.push({ path: url.pathname, ...(body !== undefined ? { body } : {}) });
      if (url.pathname === "/heartbeat") return new Response(JSON.stringify({ owned: true }));
      if (url.pathname === "/runlog-lock/acquire") return new Response(JSON.stringify({ acquired: false }));
      return new Response(JSON.stringify({ ok: true }));
    },
  } as unknown as DurableObjectStub;
  return { stub, calls };
}
function makeDOState(): { state: DurableObjectState; storage: Map<string, unknown> } {
  const storage = new Map<string, unknown>();
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
      async setAlarm(_t: number): Promise<void> {},
      async deleteAlarm(): Promise<void> {},
    },
  } as unknown as DurableObjectState;
  return { state, storage };
}
function mkEnv(kv: MemKV, sched: DurableObjectStub, dest: MemDest, signerB64: string, breakGlassB64: string, knobs: Record<string, string>): { env: Env; setDO(d: RunSealDO): void } {
  let realDO: RunSealDO | null = null;
  const runsealStub = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init));
    },
  } as unknown as DurableObjectStub;
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
  const env = {
    SCHEDULER: nsFor(sched),
    RUNSEAL: nsFor(runsealStub),
    SIGNER_PRIVATE: signerB64,
    BREAK_GLASS_PUBLIC: breakGlassB64,
    DEST_KIND: "r2",
    DEST_R2: r2Facade,
    KV_TEST: kv,
    VERIFY_AT_SEAL: "0",
    DEST_THROTTLE_BASE_MS: "1",
    ...knobs,
  } as unknown as Env;
  return { env, setDO: (d) => (realDO = d) };
}
const dpState = (id: string): DownpipeState =>
  ({
    config: { id, name: id, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_TEST", namespaceId: "ns1", include: [], exclude: [] } },
    nextRunAt: 0,
    lastRunId: null,
    inFlight: true,
    inFlightSince: Date.now(),
  }) as DownpipeState;

// ============================ main ============================
async function main(): Promise<void> {
  const signerPrivateB64 = b64urlEncode(concat(rand(32), rand(32)));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const verifier = verifierFrom(signer);
  const breakGlass = makeRecipient("break-glass");
  const operational = makeRecipient("operational");
  const recipients = [breakGlass.entry, operational.entry]; // break-glass first (loadRecipients contract)
  const breakGlassB64 = b64urlEncode(concat(breakGlass.entry.pub.x25519, breakGlass.entry.pub.mlkemEk));
  const operationalIdB64 = b64urlEncode(operational.identity); // OPERATIONAL_PRIVATE for the verify-at-seal decrypt tier

  // Shared seal knobs for the non-DO fan-out drive (small pages/shards so range boundaries do not align to
  // shard boundaries, forcing the merge to re-group across seams, exactly as validate-fanout.ts does).
  const pageSize = 4;
  const shardMax = 8;
  const segTarget = 65_536; // a small segment target so the one large value chains into several segments

  function baseCp(extra: Partial<RunCheckpoint>): RunCheckpoint {
    return {
      v: 1, downpipeId: "dp_scale", downpipeName: "scale", cadence: "3600s", sourceType: "kv",
      selector: { include: [], exclude: [] }, runId: RUN_ID, runlogIndex: 1, prevRunId: null,
      startedAt: "2026-06-10T00:00:00.000Z", wrappedMaster: { iv: "", ct: "" }, cursor: null, sourceDone: false,
      nextRecordIndex: 0, nextShardIndex: 0, frontier: { count: 0, nodes: [] }, counts: zeroCounts(),
      sliceCount: 0, partialRecord: null, ...extra,
    };
  }
  function depsFor(recs: Rec[], dest: MemDest, master: Uint8Array, subrequests: number): SliceDeps {
    return {
      source: new KVSource(new MemKV(recs, pageSize) as unknown as KVNamespace, "ns1"),
      dest, signer, recipients, budget: new SliceBudget({ subrequests, wallMs: 60_000 }),
      segmentTargetBytes: segTarget, shardMaxRecords: shardMax,
      nowIso: () => "2026-06-10T00:00:05.000Z", randomNonce: () => rand(16), randomSalt: () => rand(16),
    };
  }
  // sealRange: one WORKER sealing its half-open range with composite scratch ids.
  async function sealRange(recs: Rec[], dest: MemDest, master: Uint8Array, rangeIndex: number, range: FanoutRange): Promise<{ shards: ShardEntry[]; records: number }> {
    let cp = baseCp({ selector: { include: [], exclude: [], range }, rangeIndex });
    const allShards: ShardEntry[] = [];
    let openBuffer: Record<string, unknown>[] = [];
    for (let s = 0; s < 2000 && !cp.sourceDone; s++) {
      const r = await runSlice(depsFor(recs, dest, master, 200), cp, master, openBuffer);
      cp = r.checkpoint;
      allShards.push(...r.newShards);
      openBuffer = r.openReset ? r.openWrite : [...openBuffer, ...r.openWrite];
    }
    const open = await sealRangeOpenShard(depsFor(recs, dest, master, 700), cp, master, openBuffer);
    if (open !== null) allShards.push(open);
    return { shards: allShards, records: cp.counts.records };
  }
  // sealWithRanges seals each range as a worker then merges into ONE archive with a per-step merge budget.
  async function sealWithRanges(recs: Rec[], master: Uint8Array, ranges: FanoutRange[], mergeSubreq: number): Promise<{ dest: MemDest; steps: number; scratch: number }> {
    const dest = new MemDest();
    const allScratch: ShardEntry[] = [];
    let total = 0;
    for (let i = 0; i < ranges.length; i++) {
      const { shards, records } = await sealRange(recs, dest, master, i, ranges[i]!);
      allScratch.push(...shards);
      total += records;
    }
    const mergeCp = baseCp({ counts: { ...zeroCounts(), records: total } });
    let st = newMergeState(allScratch);
    let carried: Record<string, unknown>[] = [];
    let done = false;
    let steps = 0;
    for (; steps < 5000 && !done; steps++) {
      const r = await mergeStep(depsFor(recs, dest, master, mergeSubreq), mergeCp, master, st, carried);
      st = r.state;
      carried = r.carriedLines;
      done = r.done;
    }
    await deleteScratchShards(depsFor(recs, dest, master, 700), st.scratchShards);
    return { dest, steps, scratch: allScratch.length };
  }
  // planByScan drives the SLICED keys-only count+stride scan to completion (the coordinator's real planTick).
  async function planByScan(src: KVSource, selector: Selector, n: number): Promise<{ ranges: FanoutRange[]; total: number }> {
    const scan = newPlanScan();
    for await (const ev of src.listKeysFrom(selector, null)) countPage(scan, ev.keys.length);
    finishCount(scan, n, FANOUT_MAX_RANGE_KEYS, FANOUT_MAX_RANGES);
    for await (const ev of src.listKeysFrom(selector, null)) stridePage(scan, ev.keys);
    return { ranges: rangesFromSplitKeys(scan.splits), total: scan.total };
  }

  // ======================================================================================================
  // CELL (a): a large fanned-out run seals a correct archive an INDEPENDENT oracle verifies.
  // ======================================================================================================
  section("CELL (a): a large SCAN-planned fan-out seal is verified by the harness plaintext-set oracle AND the independent Go reader");
  const goArchiveRoots: string[] = []; // temp dirs to sweep at teardown
  {
    // A large keyspace (300 keys) with one large multi-segment value, so the run FORCES the sliced count+
    // stride SCAN plan and a many-step checkpointed merge, and the assembly spans the streaming segment path.
    const N = 300;
    const recs: Rec[] = Array.from({ length: N }, (_, i) => ({ name: `key/${String(i).padStart(5, "0")}`, value: utf8(`scale-value-${i}-${"x".repeat(i % 11)}`) }));
    const bigIdx = 137;
    recs[bigIdx] = { name: `key/${String(bigIdx).padStart(5, "0")}`, value: rand(300_000) }; // ~5 segments at segTarget
    const master = rand(32);
    const src = () => new KVSource(new MemKV(recs, pageSize) as unknown as KVNamespace, "ns1");

    // The coordinator's REAL gate picks the SCAN plan when the keyspace exceeds the front sample.
    const plan = await planFanout(src(), { include: [], exclude: [] }, { ranges: 4, minRecords: 1, sampleCap: 3 });
    ok(`planFanout picks the SCAN plan for the ${N}-key keyspace (not the front sample)`, plan.mode === "scan");
    const scan = await planByScan(src(), { include: [], exclude: [] }, 4);
    ok(`the sliced scan COUNTED the whole keyspace (${scan.total} == ${N}) into balanced ranges`, scan.total === N && scan.ranges.length >= 2);

    // Drive the REAL sliced fan-out + the REAL checkpointed merge with a small per-step merge budget.
    const fan = await sealWithRanges(recs, master, scan.ranges, 44);
    ok(`the merge ran MANY checkpointed steps (${fan.steps}) over ${fan.scratch} scratch shards`, fan.steps > 3 && fan.scratch > scan.ranges.length);
    ok("the merge reclaimed every scratch shard (no composite-id shard left under manifest/)", ![...fan.dest.map.keys()].some((k) => /manifest\/\d{10}\.dpe$/.test(k)));

    // Oracle 1: the harness-owned PLAINTEXT-SET oracle over the engine's own openRun read path.
    const run = await openRun(new MapStore(fan.dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
    ok(`the fanned-out archive opens with all ${N} records (declaredRecordCount == fed count)`, run.records.length === N);
    const fed = fedMultiset(recs);
    ok("the restored PLAINTEXT MULTISET equals the seeded plaintext multiset EXACTLY (no loss, no dup, no substitution)", (await restoredMultiset(run)) === fed);

    // Oracle 2: the sibling Go offline reader (a DIFFERENT codebase) re-verifies the SAME fanned-out archive.
    const go = goPresent();
    if (!go.ok) {
      ok("Go cross-check DEGRADED to a named GAP (no Go toolchain on PATH; the plaintext-set oracle still ran)", true);
    } else {
      const root = newTmpRoot();
      goArchiveRoots.push(root);
      const built = buildReader(process.cwd(), `${root}/downpipe`);
      if (!built.ok) {
        ok(`Go cross-check DEGRADED to a named GAP (reader build unavailable: ${built.detail})`, true);
      } else {
        const { archiveDir, identityFile, signerFile } = writeArchiveDir(root, fan.dest.map, b64urlEncode(breakGlass.identity), b64urlEncode(concat(verifier.ed, verifier.mldsa)));
        const res = runReader(`${root}/downpipe`, restoreDiscardArgs(archiveDir, RUN_ID, identityFile, signerFile));
        ok(`the INDEPENDENT Go reader verified the fanned-out archive (exit 0 = ExitVerified; a different codebase recomputed the root)${res.exitCode !== 0 ? ` [exit ${res.exitCode}: ${res.stderr.slice(-160)}]` : ""}`, res.exitCode === 0);
        const verified = /verified\s+(\d+)/.exec(res.stderr);
        ok(`the Go reader independently decrypted + hash-checked all ${N} records`, verified !== null && Number(verified[1]) === N);

        // ---- Refuter (a) keystone: a large-run seal that drops or corrupts a shard MUST fail ----
        // In-process: flip one byte of a FINAL shard object; its sha384 is in the signed root, so openRun
        // fails closed. The clean archive greens above, so the oracle is not a stuck no-op (two-sided).
        const shardKey = [...fan.dest.map.keys()].find((k) => /manifest\/\d{5}\.dpe$/.test(k))!;
        const tampered = new Map(fan.dest.map);
        const bad = new Uint8Array(tampered.get(shardKey)!);
        bad[bad.length - 1] = bad[bad.length - 1]! ^ 0xff;
        tampered.set(shardKey, bad);
        let openThrew = false;
        try {
          const badRun = await openRun(new MapStore(tampered), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
          // If open somehow succeeds, the plaintext multiset MUST still diverge (a broken shard cannot restore clean).
          openThrew = (await restoredMultiset(badRun)) !== fed;
        } catch {
          openThrew = true;
        }
        ok("REFUTER (a): a corrupted final shard is caught by the in-process oracle (open fails closed OR the multiset diverges)", openThrew);

        // Go reader: the SAME corruption on a copy of the archive dir makes the independent reader REFUSE.
        const badRoot = `${root}-tamper`;
        copyArchiveRoot(root, badRoot);
        goArchiveRoots.push(badRoot);
        flipLastByte(`${badRoot}/archive/${shardKey}`);
        const badRes = runReader(`${root}/downpipe`, restoreDiscardArgs(`${badRoot}/archive`, RUN_ID, `${badRoot}/identity.key`, `${badRoot}/signer.pub`));
        ok(`REFUTER (a): the independent Go reader REFUSES the corrupted large archive (non-zero exit ${badRes.exitCode})`, badRes.exitCode !== 0);
      }
    }
  }

  // ======================================================================================================
  // CELL (b): the subrequest cap and the strided-sampling bounds are honoured at scale.
  // ======================================================================================================
  section("CELL (b): the metered IN-BAND subrequest SLI is honoured every slice, and the verify tier is surfaced honestly");
  {
    // A many-record run sliced with a SMALL fresh budget each invocation, so the run yields many times. The
    // metered OpCounts.subrequests off each slice's budget fold (slice.ts:489) is the in-band SLI.
    const N = 240;
    const recs: Rec[] = Array.from({ length: N }, (_, i) => ({ name: `k/${String(i).padStart(5, "0")}`, value: utf8(`b-value-${i}-${"y".repeat(i % 7)}`) }));
    const master = rand(32);
    const budgetKnob = 60; // the resolved per-slice subrequest budget (well below the 1000 platform cap)
    let cp = baseCp({ counts: zeroCounts() });
    const allShards: ShardEntry[] = [];
    let openBuffer: Record<string, unknown>[] = [];
    const dest = new MemDest();
    let slices = 0;
    let yields = 0;
    let capHonouredEverySlice = true;
    let yieldFiredBeforeReserve = true;
    let lastFoldedSubreq = 0;
    for (let s = 0; s < 2000 && !cp.sourceDone; s++) {
      const deps = depsFor(recs, dest, master, budgetKnob);
      const r = await runSlice(deps, cp, master, openBuffer);
      cp = r.checkpoint;
      allShards.push(...r.newShards);
      openBuffer = r.openReset ? r.openWrite : [...openBuffer, ...r.openWrite];
      slices++;
      // NO cap breach: this slice's metered spend never exceeded the resolved budget.
      if (deps.budget.subrequestsSpent > deps.budget.subrequestBudget) capHonouredEverySlice = false;
      // When the slice yielded (the source is not yet exhausted), the yield MUST have fired: the remaining
      // budget fell to or below FINALISE_RESERVE (budget.ts:154), so the slice checkpointed BEFORE the cap.
      if (!cp.sourceDone) {
        yields++;
        if (!(deps.budget.shouldYield() && deps.budget.remaining() <= FINALISE_RESERVE)) yieldFiredBeforeReserve = false;
      }
      lastFoldedSubreq = cp.counts.opCounts.subrequests;
    }
    ok(`the run SLICED many times under the small budget (${slices} slices, ${yields} yields)`, slices > 3 && yields > 2);
    ok(`NO cap breach: every slice's metered OpCounts.subrequests stayed at or below the resolved budget (${budgetKnob})`, capHonouredEverySlice);
    ok("the yield fired BEFORE FINALISE_RESERVE was crossed on every yielding slice (the slice checkpointed, never raced the cap)", yieldFiredBeforeReserve);
    ok(`the metered OpCounts folded across the checkpoint into the run row's running total (${lastFoldedSubreq} subrequests)`, lastFoldedSubreq > 0);

    // The resolved-budget clamp (budget.ts:36-41): an over-set knob CLAMPS to the platform-survivable ceiling
    // rather than risking a cap death that persists no checkpoint.
    ok(`an over-set SCALE_SLICE_SUBREQUESTS clamps to MAX_SLICE_SUBREQUESTS (${MAX_SLICE_SUBREQUESTS})`, budgetFromEnv({ SCALE_SLICE_SUBREQUESTS: "99999" }).subrequestBudget === MAX_SLICE_SUBREQUESTS);
    ok(`a valid SCALE_SLICE_SUBREQUESTS is honoured as-is; an unset one uses the default (${DEFAULT_SLICE_SUBREQUESTS})`, budgetFromEnv({ SCALE_SLICE_SUBREQUESTS: "500" }).subrequestBudget === 500 && budgetFromEnv({}).subrequestBudget === DEFAULT_SLICE_SUBREQUESTS);

    await finaliseRun(depsFor(recs, dest, master, 700), cp, master, allShards, openBuffer);
    const runB = await openRun(new MapStore(dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
    ok(`the sliced run still sealed a correct archive (${runB.records.length} records) with the budget honoured`, runB.records.length === N && (await restoredMultiset(runB)) === fedMultiset(recs));

    // ---- The verify tier is surfaced HONESTLY at the scale boundary (the REAL multi-shard sliced archive) ----
    // Drive the REAL verifyAtSeal over the 240-record sliced archive just sealed (many real shards), with the
    // thresholds lowered so this modest run crosses each boundary. This is the honest Tier-1 method: the tier
    // BRANCH is what matters, not the absolute size (the genuine 1M-key/multi-GB run is the owner-gated Tier 2).
    const shardCount = [...dest.map.keys()].filter((k) => /manifest\/\d{5}\.dpe$/.test(k)).length;
    ok(`the verify-boundary archive has MANY real shards (${shardCount}) so the strided shard sample is a genuine subset`, shardCount >= 4);

    const bytesTotal = recs.reduce((s, r) => s + r.value.length, 0); // > the lowered byte thresholds below
    const envFull = { SIGNER_PRIVATE: signerPrivateB64, OPERATIONAL_PRIVATE: operationalIdB64, SEAL_VERIFY_FULL_BYTES: String(bytesTotal + 1_000_000), SEAL_VERIFY_FULL_SHARDS: "1000" } as unknown as Env;
    const vFull = await verifyAtSeal(envFull, dest, RUN_ID, bytesTotal);
    ok("a SMALL run (plaintext <= SEAL_VERIFY_FULL_BYTES) verifies at tier FULL (the control that above-threshold is not spuriously full)", vFull.status === "verified" && vFull.tier === "full");

    const envSampled = { SIGNER_PRIVATE: signerPrivateB64, OPERATIONAL_PRIVATE: operationalIdB64, SEAL_VERIFY_FULL_BYTES: "1", SEAL_VERIFY_FULL_SHARDS: "2", SEAL_VERIFY_SHARD_SAMPLE: "2" } as unknown as Env;
    const vSampled = await verifyAtSeal(envSampled, dest, RUN_ID, bytesTotal);
    ok("above SEAL_VERIFY_FULL_BYTES the verdict carries tier 'sampled-decrypt', HONESTLY bounded (never silently upgraded to full)", vSampled.status === "verified" && vSampled.tier === "sampled-decrypt");

    const envTier0 = { SIGNER_PRIVATE: signerPrivateB64, OPERATIONAL_PRIVATE: operationalIdB64, SEAL_VERIFY_MAX_BYTES: "1" } as unknown as Env;
    const vTier0 = await verifyAtSeal(envTier0, dest, RUN_ID, bytesTotal);
    ok("above SEAL_VERIFY_MAX_BYTES the verdict is tier-0 only with tier0Cause 'too-large' (the cost ceiling, honestly named)", vTier0.status === "verified" && vTier0.tier === "tier-0" && vTier0.tier0Cause === "too-large");
    ok("NO false-complete: not one bounded verdict claimed tier 'full' above the threshold", vSampled.tier !== "full" && vTier0.tier !== "full");

    // ---- Refuter (b): a cap breach MUST be caught (a slice that overran the budget without yielding) ----
    // The cell (b) oracle is: for every slice, subrequestsSpent <= subrequestBudget AND (source done OR
    // shouldYield fired). Feed the oracle a BREACH (spent past the budget, not yet yielded) and require it to
    // report a breach; the honoured readings above green, so the detector is not a stuck no-op (two-sided).
    const capHonoured = (spent: number, budget: number, sourceDone: boolean, yielded: boolean): boolean => spent <= budget && (sourceDone || yielded);
    const breach = new SliceBudget({ subrequests: budgetKnob, wallMs: 60_000 });
    breach.spend(budgetKnob + 5); // a slice that spent PAST the resolved budget in one record (no mid-record yield)
    ok("REFUTER (b): a slice that spent PAST the budget without yielding is CAUGHT by the cap-honoured oracle", capHonoured(breach.subrequestsSpent, breach.subrequestBudget, false, false) === false);
    ok("REFUTER (b) two-sided: an honoured slice (spent within budget, yielded) passes the same oracle", capHonoured(budgetKnob, budgetKnob, false, true) === true);
  }

  // ======================================================================================================
  // CELL (c): a contended or throttled large run resumes without loss or duplication.
  // ======================================================================================================
  section("CELL (c): a throttled / RUNLOG-contended run PARKS and resumes LOSS-FREE and DUP-FREE (the plaintext-set oracle over the park boundary)");
  {
    const N = 120;
    const seeds: Rec[] = Array.from({ length: N }, (_, i) => ({ name: `key/${String(i).padStart(5, "0")}`, value: utf8(`c-value-${i}-${"z".repeat(i % 9)}`) }));
    const fed = fedMultiset(seeds);
    const knobs = { SCALE_SLICE_SUBREQUESTS: "70", DEST_THROTTLE_MAX_YIELDS: "3", DEST_THROTTLE_ATTEMPTS: "1", DEST_THROTTLE_BASE_MS: "1" };

    // --- Sub-drive 1: a destination THROTTLE (503) parks on throttleAttempt, then recovers and completes ---
    {
      const sched = makeSealScheduler();
      const doState = makeDOState();
      const dest = new MemDest();
      const kv = new MemKV(seeds, 40);
      const { env, setDO } = mkEnv(kv, sched.stub, dest, signerPrivateB64, breakGlassB64, knobs);
      const realDO = new RunSealDO(doState.state, env);
      setDO(realDO);
      const origError = console.error;
      console.error = () => {};
      try {
        await sealRunSliced(env, dpState("dp-c-throttle"), { runId: RUN_ID, index: 21, prevRunId: null }, { budget: new SliceBudget({ subrequests: 70, wallMs: 60_000 }) });
        ok("throttle: the run handed off to the seal DO (the first slice sealed before the throttle)", doState.storage.has("doc"));
        dest.throttle = true; // from here every write 503s
        await realDO.alarm();
        await realDO.alarm();
        const parked = doState.storage.get("doc") as { attempt?: number; throttleAttempt?: number } | undefined;
        ok("throttle: the run PARKS on its own ladder (throttleAttempt advanced) and NEVER charges the hard-fault strike counter (attempt stays 0)", (parked?.throttleAttempt ?? 0) >= 1 && (parked?.attempt ?? 0) === 0);
        ok("throttle: the checkpoint is preserved while parked (the doc survives the outage)", doState.storage.has("doc"));
        dest.throttle = false; // the destination recovers
        for (let i = 0; i < 400 && doState.storage.has("doc"); i++) await realDO.alarm();
      } finally {
        console.error = origError;
      }
      const complete = sched.calls.find((c) => c.path === "/complete");
      const body = complete?.body as { status?: string; runId?: string; recordCount?: number } | undefined;
      ok("throttle: the recovered destination let the SAME run resume and complete ok", body?.status === "ok" && body?.runId === RUN_ID);
      const run = await openRun(new MapStore(dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
      ok("throttle: the resumed archive restores the FED plaintext multiset EXACTLY (no record lost, none duplicated across the park boundary)", (await restoredMultiset(run)) === fed);
    }

    // --- Sub-drive 2: a RUNLOG CONTENTION parks on runlogAttempt, then clears and finalises to ONE entry ---
    {
      const sched = makeSealScheduler();
      const doState = makeDOState();
      const dest = new MemDest();
      const kv = new MemKV(seeds, 40);
      const { env, setDO } = mkEnv(kv, sched.stub, dest, signerPrivateB64, breakGlassB64, knobs);
      const realDO = new RunSealDO(doState.state, env);
      setDO(realDO);
      const origError = console.error;
      console.error = () => {};
      try {
        await sealRunSliced(env, dpState("dp-c-contend"), { runId: RUN_ID, index: 31, prevRunId: null }, { budget: new SliceBudget({ subrequests: 70, wallMs: 60_000 }) });
        dest.contend = true; // from here the RUNLOG conditional write always reports a precondition failure
        for (let i = 0; i < 60 && ((doState.storage.get("doc") as { runlogAttempt?: number } | undefined)?.runlogAttempt ?? 0) < 1; i++) await realDO.alarm();
        const parked = doState.storage.get("doc") as { attempt?: number; runlogAttempt?: number; throttleAttempt?: number } | undefined;
        ok("contention: the run PARKS on runlogAttempt, NEVER charging the hard-fault strike counter (attempt 0) and NEVER the throttle ladder (throttleAttempt 0)", (parked?.runlogAttempt ?? 0) >= 1 && (parked?.attempt ?? 0) === 0 && (parked?.throttleAttempt ?? 0) === 0);
        dest.contend = false; // the contention clears
        for (let i = 0; i < 400 && doState.storage.has("doc"); i++) await realDO.alarm();
      } finally {
        console.error = origError;
      }
      const complete = sched.calls.find((c) => c.path === "/complete");
      const body = complete?.body as { status?: string; runId?: string } | undefined;
      ok("contention: the cleared contention let the SAME run resume and finalise ok", body?.status === "ok" && body?.runId === RUN_ID);
      const run = await openRun(new MapStore(dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
      ok("contention: the resumed archive restores the FED plaintext multiset EXACTLY (loss-free and dup-free across the park boundary)", (await restoredMultiset(run)) === fed);
      const entries = parseRunlog((await dest.get("_RECOVERY/RUNLOG"))!.body);
      const mine = entries.filter((e) => e.runId === RUN_ID);
      ok("contention: the idempotent RUNLOG append committed EXACTLY ONE entry for the run (a park never double-appends)", mine.length === 1);
    }

    // --- Positive control: a clean large run completes with NO park recorded ---
    {
      const sched = makeSealScheduler();
      const doState = makeDOState();
      const dest = new MemDest();
      const kv = new MemKV(seeds, 40);
      const { env, setDO } = mkEnv(kv, sched.stub, dest, signerPrivateB64, breakGlassB64, knobs);
      const realDO = new RunSealDO(doState.state, env);
      setDO(realDO);
      await sealRunSliced(env, dpState("dp-c-clean"), { runId: RUN_ID, index: 41, prevRunId: null }, { budget: new SliceBudget({ subrequests: 70, wallMs: 60_000 }) });
      let sawPark = false;
      for (let i = 0; i < 400 && doState.storage.has("doc"); i++) {
        const d = doState.storage.get("doc") as { throttleAttempt?: number; runlogAttempt?: number } | undefined;
        if ((d?.throttleAttempt ?? 0) > 0 || (d?.runlogAttempt ?? 0) > 0) sawPark = true;
        await realDO.alarm();
      }
      const body = sched.calls.find((c) => c.path === "/complete")?.body as { status?: string } | undefined;
      const run = await openRun(new MapStore(dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
      ok("control: a clean large run completes ok with NO park recorded and the FED multiset restored (catches a stuck-on-park oracle)", body?.status === "ok" && !sawPark && (await restoredMultiset(run)) === fed);
    }

    // ---- Refuter (c): a resumed run that DUPLICATES or LOSES a record MUST be caught by the oracle ----
    // The multiset oracle is fed a synthetic dup / loss relative to the fed set and MUST report a mismatch;
    // the real resumes above match exactly, so the oracle is not a stuck pass (two-sided).
    const restoredClean = seeds.map((r) => `${r.name}|${sha384Hex(r.value)}`).sort();
    const dupSet = JSON.stringify([...restoredClean, restoredClean[0]!].sort()); // a duplicated record
    const lossSet = JSON.stringify(restoredClean.slice(1).sort()); // a lost record
    ok("REFUTER (c): a DUPLICATED record on resume is caught (the restored multiset differs from the fed set)", dupSet !== fed);
    ok("REFUTER (c): a LOST record on resume is caught (the restored multiset differs from the fed set)", lossSet !== fed);
  }

  // ======================================================================================================
  // CELL (d): a sealed run evicted from the run-history RING is not a lost run.
  // ======================================================================================================
  section("CELL (d): the bounded run-history RING drops oldest under pressure WHILE the append-only archive RUNLOG is the authority that never drops a sealed run");
  {
    // Drive the REAL SchedulerDO past RING_CAP (50) with 51 trigger+complete cycles; capture every runId.
    const { stub, storage } = makeSchedulerDO();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-ring"));
    const CYCLES = 51;
    const runIds: string[] = [];
    for (let i = 0; i < CYCLES; i++) {
      const trig = (await (await stubFetch(stub, "POST", "/trigger", { id: "dp-ring" })).json()) as { runId: string; index: number };
      runIds.push(trig.runId);
      await stubFetch(stub, "POST", "/complete", { id: "dp-ring", runId: trig.runId, index: trig.index, status: "ok", recordCount: 1, bytes: 1 });
    }
    const ring = storage.rawGet<RunHistoryEntry[]>("hist:dp-ring") ?? [];
    const headIndex = Math.min(...ring.map((r) => r.index));
    ok(`the REAL run-history ring is bounded to RING_CAP (${ring.length} == 50), dropping oldest under ${CYCLES} completions`, ring.length === 50);
    ok("the OLDEST run (index 1) was SHIFTED OFF the ring (its row is gone; the ring is a recent-activity VIEW)", headIndex === 2 && !ring.some((r) => r.runId === runIds[0]));

    // The archive RUNLOG authority: seal run #1 as a REAL openable archive, then append the other 50 runs'
    // entries via the REAL appendRunlog to the SAME destination. The chain is append-only and never drops.
    const adest = new MemDest();
    const arecs: WriteRecord[] = Array.from({ length: 5 }, (_, i) => ({ sourceType: "kv", name: `d/${i}`, value: utf8(`d-run1-${i}`) }));
    const amaster = rand(32);
    const run1Id = runIds[0]!;
    const a1 = await buildArchive({ downpipeId: "dp-ring", downpipeName: "dp-ring", cadence: "3600s", runId: run1Id, master: amaster, recipients, signer, records: arecs, windowStart: "2026-06-10T00:00:00.000Z", windowEnd: "2026-06-10T00:00:01.000Z", createdAt: "2026-06-10T00:00:01.000Z", runlogIndex: 1, prevRunId: null, skipRunlog: true, randomNonce: () => rand(16), randomSalt: () => rand(16) }, { dest: adest });
    for (const [k, v] of a1) await adest.put(k, v);
    await appendRunlog(adest, signer, { index: 1, runId: run1Id, downpipeId: "dp-ring", time: "2026-06-10T00:00:01.000Z", recordCount: arecs.length, prevRunId: null, status: "active" } as RunlogEntry);
    for (let i = 1; i < CYCLES; i++) {
      await appendRunlog(adest, signer, { index: i + 1, runId: runIds[i]!, downpipeId: "dp-ring", time: "2026-06-10T00:00:01.000Z", recordCount: 1, prevRunId: runIds[i - 1]!, status: "active" } as RunlogEntry);
    }
    const authorityHas = (id: string): boolean => parseRunlog((adest.map.get("_RECOVERY/RUNLOG"))!).some((e) => e.runId === id);
    ok("the append-only archive RUNLOG chain retained ALL 51 sealed runs (it NEVER drops a sealed run)", parseRunlog(adest.map.get("_RECOVERY/RUNLOG")!).length === CYCLES);
    ok("the run EVICTED from the ring (index 1) is STILL in the archive RUNLOG authority", authorityHas(run1Id));
    const restored1 = await openRun(new MapStore(adest.map), run1Id, parseIdentity(breakGlass.identity), verifier, { allowStale: true });
    ok("the evicted run is STILL restorable BY ITS runId from the archive (the durable authority retained it)", restored1.records.length === arecs.length && (await restoredMultiset(restored1)) === fedMultiset(arecs.map((r) => ({ name: r.name, value: r.value as Uint8Array }))));

    // The honest point-in-time bound (admin/point-in-time.ts): a T older than the oldest RETAINED ring run
    // resolves NOT-FOUND with its retainedFrom bound, rather than silently returning the oldest run.
    const ringTimed: RunHistoryEntry[] = ring.map((r, i) => ({ ...r, startedAt: new Date(1_000_000 + i * 1000).toISOString(), status: "ok" }));
    const oldestRetained = Date.parse(ringTimed[0]!.startedAt);
    const missBelow = resolveRunAt("dp-ring", ringTimed, oldestRetained - 5000);
    ok("point-in-time: a T older than the oldest RETAINED ring run resolves NOT-FOUND with a retainedFrom bound (never a silently-wrong oldest run)", missBelow.found === false && missBelow.retainedFrom !== undefined);
    const hitWithin = resolveRunAt("dp-ring", ringTimed, Date.parse(ringTimed[ringTimed.length - 1]!.startedAt) + 1000);
    ok("point-in-time: a T within the retained window resolves to a run (the ring convenience still works inside its bound)", hitWithin.found === true);

    // Eviction under replication lag is SURFACED, not silent: the pure run-at-risk-eviction detector.
    ok("run-at-risk-eviction FIRES when the ring is at cap AND a replica's holdsIndex is below the head (the closing reconcile window is surfaced)", isRunEvictionRisk({ ringAtCap: true, headIndex: headIndex, holdsIndex: headIndex - 1 }).atRisk === true);
    ok("run-at-risk-eviction is SILENT when the ring is not at capacity (nothing is being evicted yet)", isRunEvictionRisk({ ringAtCap: false, headIndex: headIndex, holdsIndex: -1 }).atRisk === false);

    // ---- Refuter (d): a dropped RUNLOG entry MUST fail; an always-false eviction detector MUST fail ----
    // Delete the evicted run's entry from the archive RUNLOG out of band (re-sign the truncated chain). The
    // authority oracle MUST then report the run unresolvable; it reported it PRESENT above (two-sided).
    const kept = parseRunlog(adest.map.get("_RECOVERY/RUNLOG")!).filter((e) => e.runId !== run1Id);
    const resigned = await signRunlog(kept, signer.edPrivate, signer.mldsaSecret);
    adest.map.set("_RECOVERY/RUNLOG", resigned.runlog);
    ok("REFUTER (d): after the evicted run's RUNLOG entry is destroyed out of band, the authority oracle reports it UNRESOLVABLE (the detector can see a destroyed authority)", authorityHas(run1Id) === false);
    const alwaysFalse = (_in: { ringAtCap: boolean; headIndex: number; holdsIndex: number }): { atRisk: boolean } => ({ atRisk: false });
    ok("REFUTER (d): a detector that returned atRisk:false on the at-cap lagging-replica input would FAIL the cell (the at-risk arm is live)", isRunEvictionRisk({ ringAtCap: true, headIndex: 2, holdsIndex: 1 }).atRisk === true && alwaysFalse({ ringAtCap: true, headIndex: 2, holdsIndex: 1 }).atRisk === false);
  }

  // ======================================================================================================
  // CELL (e): the scale sampling bound is surfaced honestly at the scale boundary (the AXIS4 limit, restated).
  // ======================================================================================================
  section("CELL (e): the AXIS4 sampling bound RESTATED at the scale boundary as an honest limit, never a false CLEAN");
  {
    // A real archive with a streamed segment (a record body). Corrupt one segment byte OUTSIDE the shard
    // (the shard hash is unaffected, so Tier-0 completeness passes; only the decrypt tier reads the body).
    const edest = new MemDest();
    const eStreamVal = rand(40_000); // a FIXED buffer, so every seal read pass hashes the SAME bytes
    const erecs: WriteRecord[] = [
      { sourceType: "kv", name: "e/a", value: utf8("verify-e-a") },
      { sourceType: "kv", name: "e/b", value: utf8("verify-e-b") },
      { sourceType: "r2", name: "e/streamed", bucket: "media", stream: { size: eStreamVal.length, open: () => ({ async *chunks() { yield eStreamVal; } }) } },
    ];
    const eplain = eStreamVal.length + 20;
    const earchive = await buildArchive({ downpipeId: "dp_scale", downpipeName: "scale", cadence: "3600s", runId: RUN_ID, master: rand(32), recipients, signer, records: erecs, windowStart: "2026-06-10T00:00:00.000Z", windowEnd: "2026-06-10T00:00:01.000Z", createdAt: "2026-06-10T00:00:01.000Z", runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16) }, { dest: edest });
    for (const [k, v] of earchive) await edest.put(k, v);
    // Corrupt a byte of the streamed SEGMENT object (a record body, NOT a shard): Tier-0 stays clean.
    const segKey = [...edest.map.keys()].find((k) => k.startsWith("seg/") && k.endsWith(".seg"))!;
    const seg = new Uint8Array(edest.map.get(segKey)!);
    seg[Math.floor(seg.length / 2)] = seg[Math.floor(seg.length / 2)]! ^ 0xff;
    edest.map.set(segKey, seg);

    // At FULL coverage the decrypt tier reads every record body and CATCHES the corruption (the two-sided
    // control: the same corruption IS caught when coverage is total, i.e. for small runs).
    const envFull = { SIGNER_PRIVATE: signerPrivateB64, OPERATIONAL_PRIVATE: operationalIdB64, SEAL_VERIFY_FULL_BYTES: String(eplain + 1_000_000), SEAL_VERIFY_MAX_BYTES: String(eplain + 1_000_000) } as unknown as Env;
    const eFull = await verifyAtSeal(envFull, edest, RUN_ID, eplain);
    ok("full coverage CATCHES the record-body corruption (suspect at tier 'full') -- the catch is total for a small run", eFull.status === "suspect" && eFull.tier === "full");

    // Forced Tier-0 (a LARGE run over SEAL_VERIFY_MAX_BYTES): the decrypt sample is SKIPPED, so the same
    // non-sampled record-body corruption is NOT caught at seal. The verdict is recorded at its BOUNDED tier
    // with tier0Cause 'too-large' -- an honest BOUND handed to the drill / offline reader, NEVER a false full
    // CLEAN. The Tier-0 completeness / signature / freshness checks still run at any tier.
    const envTier0 = { SIGNER_PRIVATE: signerPrivateB64, OPERATIONAL_PRIVATE: operationalIdB64, SEAL_VERIFY_MAX_BYTES: "1" } as unknown as Env;
    const eTier0 = await verifyAtSeal(envTier0, edest, RUN_ID, eplain);
    ok("forced Tier-0 (large run) records the verdict at its BOUNDED tier with tier0Cause 'too-large' -- the non-sampled corruption is honestly handed off, NEVER reported as a full clean verify", eTier0.tier === "tier-0" && eTier0.tier0Cause === "too-large");
    ok("the honest BOUND: a Tier-0 verdict on a large run NEVER claims tier 'full' (no scale cell over-claims verify-at-seal as a complete at-seal integrity gate)", (eTier0.tier as string) !== "full");

    // ---- Refuter (e): a false CLEAN on a large run's non-sampled corruption MUST fail ----
    // The over-claim the cell guards against is a verdict claiming FULL coverage on an above-threshold run.
    // Assert the bounded verdict's tier is never 'full'; the small-run control legitimately IS 'full' (two-sided).
    ok("REFUTER (e): a verdict claiming tier 'full' on the above-threshold run would FAIL the cell (the bounded verdict is honestly tier-0, the full-coverage control is honestly full)", (eTier0.tier as string) !== "full" && eFull.tier === "full");
  }

  // Teardown: sweep any Go cross-check temp dirs (belt-and-suspenders; the OS reclaims them regardless).
  for (const root of goArchiveRoots) {
    try {
      rmSync(root, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
  }

  console.log(failures === 0 ? "\nSCALE TIER 1 PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
