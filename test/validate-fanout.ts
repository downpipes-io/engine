// Prove fan-out: a high-cardinality LEX-ORDERED KV run split across N parallel WORKER ranges and
// merged into ONE signed archive is BYTE-IDENTICAL to a single-DO SERIAL seal of the same data. This is
// the correctness keystone AND the safety net: the signed Merkle root is folded over per-record leaf
// hashes that BIND the recordId, so the merge must renumber every record to the serial global id and
// re-group shards into the global shardMax grouping; any divergence makes the independently-recomputed
// root mismatch the signature and FAILS CLOSED. The test seals the SAME fixed dataset two ways -- serial
// (N=1) and fan-out (N=2,3,4) -- and asserts the signed merkleRoot, the shard list (id/object/sha384),
// the shard objects byte-for-byte, and the restored record set are IDENTICAL. It also drives a SLICED
// merge (tiny per-step budget, frontier checkpointed) to the identical archive, the half-open range-seam
// (each boundary key covered exactly once), and the merge completeness guard (a missing scratch shard
// FAILS LOUD). Run: node test/validate-fanout.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import type { RecipientEntry, Signer } from "../src/format/writer.ts";
import { finaliseRun, runSlice, type ShardEntry, type SliceDeps } from "../src/seal/slice.ts";
import { zeroCounts, type CheckpointCounts, type RunCheckpoint } from "../src/seal/checkpoint.ts";
import { DEFAULT_SLICE_SUBREQUESTS, SliceBudget } from "../src/seal/budget.ts";
import { countPage, deleteScratchShards, FANOUT_MAX_RANGE_KEYS, FANOUT_MAX_RANGES, finishCount, KV_LIST_PAGE_KEYS, mergeStep, newMergeState, newPlanScan, partitionKeyRange, planFanout, planRangeCount, rangesFromSplitKeys, renumberLine, sealRangeOpenShard, strideBoundaryIndices, stridePage, type FanoutRange } from "../src/seal/fanout.ts";
import { MAX_SLICE_FAILURES } from "../src/seal/runstate-helpers.ts";
import { RunSealDO, sealRunSliced } from "../src/seal/runstate.ts";
import type { CoordinatorDoc } from "../src/seal/runseal-do.ts";
import { KVSource } from "../src/sources/kv.ts";
import type { Selector, SourceAdapter } from "../src/sources/types.ts";
import type { DownpipeState } from "../src/sched/scheduler-do.ts";
import type { Env } from "../src/env.d.ts";
import type { Destination, GetResult, ListPage, PutConditionalResult } from "../src/dest/types.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";

const RUN_ID = "01BX5ZZKBKACTAV9WEVGEMMVRY";
const DP_ID = "dp_fanout";

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

// MemDest: a minimal in-memory Destination exposing `.map` for read-back (the slice-validator pattern).
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
  async listPage(prefix: string): Promise<ListPage> {
    return { keys: await this.list(prefix) };
  }
}

// MemKV: a paginated KVNamespace double (list + getWithMetadata), keys kept in sorted order.
class MemKV {
  private seeds: { name: string; value: Uint8Array }[];
  private pageSize: number;
  lists = 0;
  gets = 0;
  constructor(seeds: { name: string; value: Uint8Array }[], pageSize: number) {
    this.seeds = [...seeds].sort((a, b) => (a.name < b.name ? -1 : 1));
    this.pageSize = pageSize;
  }
  async list(options?: { prefix?: string; cursor?: string }): Promise<{ keys: { name: string }[]; list_complete: boolean; cursor?: string; cacheStatus: null }> {
    this.lists++;
    const start = options?.cursor !== undefined ? Number(options.cursor) : 0;
    const prefix = options?.prefix;
    const all = prefix === undefined ? this.seeds : this.seeds.filter((s) => s.name.startsWith(prefix));
    const page = all.slice(start, start + this.pageSize);
    const next = start + this.pageSize;
    const complete = next >= all.length;
    return { keys: page.map((s) => ({ name: s.name })), list_complete: complete, ...(complete ? {} : { cursor: String(next) }), cacheStatus: null };
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

// makeDOState: a Map-backed DurableObjectState with alarm capture and faithful { prefix, startAfter, limit }
// list paging (the RunSealDO's listAllShards / collectStaleKeys page with startAfter).
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
      async list<T>(opts?: { prefix?: string; startAfter?: string; limit?: number }): Promise<Map<string, T>> {
        const prefix = opts?.prefix ?? "";
        let keys = [...storage.keys()].filter((k) => k.startsWith(prefix)).sort();
        if (opts?.startAfter !== undefined) keys = keys.filter((k) => k > opts.startAfter!);
        const out = new Map<string, T>();
        for (const k of keys.slice(0, opts?.limit ?? keys.length)) out.set(k, storage.get(k) as T);
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

// makeScheduler: a DurableObjectStub double that records calls; the lease is always owned, the runlog lock
// is uncontended, and /complete + /notify routes answer ok.
function makeScheduler(): { stub: DurableObjectStub; calls: { path: string; body?: unknown }[] } {
  const calls: { path: string; body?: unknown }[] = [];
  const stub = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const body = init?.body ? JSON.parse(String(init.body)) : undefined;
      calls.push({ path: url.pathname, ...(body !== undefined ? { body } : {}) });
      if (url.pathname === "/heartbeat") return new Response(JSON.stringify({ owned: true }));
      if (url.pathname === "/runlog-lock/acquire") return new Response(JSON.stringify({ acquired: true, token: "t" }));
      if (url.pathname === "/notify/resolve") return new Response(JSON.stringify({ now: [], digestedCount: 0, emission: null }));
      return new Response(JSON.stringify({ ok: true }));
    },
  } as unknown as DurableObjectStub;
  return { stub, calls };
}

// FleetInst is one DO in the fan-out fleet (its storage state + the lazily-built RunSealDO).
interface FleetInst {
  state: DurableObjectState;
  alarms: number[];
  storage: Map<string, unknown>;
  obj?: RunSealDO;
}

// makeFleet wires a fleet of REAL RunSealDO instances by a RUNSEAL namespace double (idFromName(name) ->
// per-name instance) + a scheduler double + an R2 facade over a shared MemDest, all driven in Node. knobs
// override env (the fan-out + budget + fault knobs). Used to run the whole fan-out lifecycle and its fault
// ladders end to end.
function makeFleet(opts: { dest: MemDest; kv: MemKV; sched: DurableObjectStub; signerPrivateB64: string; breakGlassB64: string; knobs?: Record<string, string> }): { env: Env; instances: Map<string, FleetInst>; instFor: (name: string) => FleetInst } {
  const { dest, kv, sched } = opts;
  const instances = new Map<string, FleetInst>();
  let env!: Env;
  const instFor = (name: string): FleetInst => {
    let inst = instances.get(name);
    if (!inst) { inst = makeDOState() as FleetInst; instances.set(name, inst); }
    if (!inst.obj) inst.obj = new RunSealDO(inst.state, env);
    return inst;
  };
  const runseal = {
    idFromName: (name: string) => ({ name }),
    get: (id: { name: string }) => ({
      async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
        const req = input instanceof Request ? input : new Request(String(input), init);
        return instFor(id.name).obj!.fetch(req);
      },
    }),
  } as unknown as DurableObjectNamespace;
  const r2Facade = {
    async put(key: string, v: ArrayBuffer | ReadableStream<Uint8Array>): Promise<unknown> {
      if (v instanceof ReadableStream) { await dest.putStream(key, v); return { etag: "s" }; }
      await dest.put(key, new Uint8Array(v as ArrayBuffer));
      return { etag: "u" };
    },
    async get(key: string): Promise<unknown> {
      const r = await dest.get(key);
      if (!r) return null;
      const buf = new ArrayBuffer(r.body.byteLength);
      new Uint8Array(buf).set(r.body);
      return { etag: r.etag, async arrayBuffer() { return buf; } };
    },
    async head(key: string): Promise<unknown> { return (await dest.exists(key)) ? {} : null; },
    async delete(key: string): Promise<void> { await dest.delete(key); },
    async list(o?: { prefix?: string }): Promise<unknown> { return { objects: (await dest.list(o?.prefix ?? "")).map((key) => ({ key })), truncated: false }; },
  };
  env = {
    SCHEDULER: { idFromName: () => ({}), get: () => sched } as unknown as DurableObjectNamespace,
    RUNSEAL: runseal,
    SIGNER_PRIVATE: opts.signerPrivateB64,
    BREAK_GLASS_PUBLIC: opts.breakGlassB64,
    DEST_KIND: "r2",
    DEST_R2: r2Facade,
    KV_TEST: kv,
    VERIFY_AT_SEAL: "0",
    ...(opts.knobs ?? {}),
  } as unknown as Env;
  return { env, instances, instFor };
}

// driveFleet steps every instance's alarm in rounds until the run completes (a /complete is posted) or no
// instance has work left. Returns the rounds taken.
async function driveFleet(instances: Map<string, FleetInst>, calls: { path: string; body?: unknown }[], maxRounds = 400): Promise<number> {
  let rounds = 0;
  for (; rounds < maxRounds; rounds++) {
    if (calls.some((c) => c.path === "/complete")) break;
    let drove = false;
    for (const inst of [...instances.values()]) {
      if (inst.storage.has("doc")) { await inst.obj!.alarm(); drove = true; }
    }
    if (!drove) break;
  }
  return rounds;
}

const dpStateKv = (): DownpipeState => ({
  config: { id: DP_ID, name: "fanout", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_TEST", namespaceId: "ns1", include: [], exclude: [] } },
  nextRunAt: 0, lastRunId: null, inFlight: true, inFlightSince: Date.now(),
} as unknown as DownpipeState);

const fixedNow = (): string => "2026-06-10T00:00:05.000Z";
const fixedNonce = (): Uint8Array => new Uint8Array(16).fill(7);
const fixedSalt = (): Uint8Array => new Uint8Array(16).fill(9);

// The signed-root commitment the byte-identity contract compares (the raw root bytes legitimately vary:
// the master capsule + detached signature use fresh ephemeral randomness, see validate-slice byte-identity).
type RootCommit = { merkleRoot: string; shardCount: number; declaredRecordCount: number; shards: { id: string; object: string; sha384: string }[] };

async function main(): Promise<void> {
  const signerPrivateB64 = b64urlEncode(concat(rand(32), rand(32)));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const verifier = verifierFrom(signer);
  const breakGlass = makeRecipient("break-glass");
  const recipients = [breakGlass.entry];

  // ONE master shared by the serial seal, every fan-out worker, and the merge, so the derived CAK/MK/file
  // keys + name MACs match and the content addresses + leaf hashes line up. Kept alive across all paths.
  const master = rand(32);
  const pageSize = 4; // small, so a range crawl spans multiple KV pages (range + paging interaction)
  const shardMax = 3; // small, so range boundaries do NOT align to shard boundaries (exercises re-grouping)

  function baseCp(extra: Partial<RunCheckpoint>): RunCheckpoint {
    return {
      v: 1, downpipeId: DP_ID, downpipeName: "fanout", cadence: "3600s", sourceType: "kv",
      selector: { include: [], exclude: [] }, runId: RUN_ID, runlogIndex: 1, prevRunId: null,
      startedAt: "2026-06-10T00:00:00.000Z", wrappedMaster: { iv: "", ct: "" }, cursor: null, sourceDone: false,
      nextRecordIndex: 0, nextShardIndex: 0, frontier: { count: 0, nodes: [] }, counts: zeroCounts(),
      sliceCount: 0, partialRecord: null, ...extra,
    };
  }

  function depsFor(recs: { name: string; value: Uint8Array }[], dest: MemDest, subrequests: number): SliceDeps {
    return { source: new KVSource(new MemKV(recs, pageSize) as unknown as KVNamespace, "ns1"), dest, signer, recipients, budget: new SliceBudget({ subrequests, wallMs: 60_000 }), shardMaxRecords: shardMax, nowIso: fixedNow, randomNonce: fixedNonce, randomSalt: fixedSalt };
  }

  // sealSerial: today's single-DO sliced path (rangeIndex undefined). Returns the parsed root commitment.
  async function sealSerial(recs: { name: string; value: Uint8Array }[]): Promise<{ dest: MemDest; root: RootCommit }> {
    const dest = new MemDest();
    let cp = baseCp({});
    const allShards: ShardEntry[] = [];
    let openBuffer: Record<string, unknown>[] = [];
    for (let s = 0; s < 200 && !cp.sourceDone; s++) {
      const r = await runSlice(depsFor(recs, dest, 50), cp, master, openBuffer);
      cp = r.checkpoint;
      allShards.push(...r.newShards);
      openBuffer = r.openReset ? r.openWrite : [...openBuffer, ...r.openWrite];
    }
    await finaliseRun(depsFor(recs, dest, 700), cp, master, allShards, openBuffer);
    return { dest, root: parseRoot(dest) };
  }

  // sealRange: one WORKER sealing its half-open range with composite scratch ids (cp.rangeIndex set).
  async function sealRange(recs: { name: string; value: Uint8Array }[], dest: MemDest, rangeIndex: number, range: FanoutRange): Promise<{ shards: ShardEntry[]; counts: CheckpointCounts }> {
    const selector: Selector = { include: [], exclude: [], range };
    let cp = baseCp({ selector, rangeIndex });
    const allShards: ShardEntry[] = [];
    let openBuffer: Record<string, unknown>[] = [];
    for (let s = 0; s < 200 && !cp.sourceDone; s++) {
      const r = await runSlice(depsFor(recs, dest, 30), cp, master, openBuffer);
      cp = r.checkpoint;
      allShards.push(...r.newShards);
      openBuffer = r.openReset ? r.openWrite : [...openBuffer, ...r.openWrite];
    }
    const open = await sealRangeOpenShard(depsFor(recs, dest, 700), cp, master, openBuffer);
    if (open !== null) allShards.push(open);
    return { shards: allShards, counts: cp.counts };
  }

  // sealFanout: partition into N ranges, seal each worker, then merge into ONE archive. mergeSubreq tunes
  // the merge slicing (a big budget = one-shot; a small budget = many sliced steps, frontier checkpointed).
  async function sealFanout(recs: { name: string; value: Uint8Array }[], n: number, mergeSubreq: number): Promise<{ dest: MemDest; root: RootCommit; steps: number; scratchCount: number }> {
    const dest = new MemDest();
    const sortedKeys = recs.map((r) => r.name).sort();
    const ranges = partitionKeyRange(sortedKeys, n);
    const allScratch: ShardEntry[] = [];
    let totalRecords = 0;
    for (let i = 0; i < ranges.length; i++) {
      const { shards, counts } = await sealRange(recs, dest, i, ranges[i]!);
      allScratch.push(...shards);
      totalRecords += counts.records;
    }
    const mergeCp = baseCp({ counts: { ...zeroCounts(), records: totalRecords } });
    let st = newMergeState(allScratch);
    let carried: Record<string, unknown>[] = [];
    let done = false;
    let steps = 0;
    for (; steps < 500 && !done; steps++) {
      const r = await mergeStep(depsFor(recs, dest, mergeSubreq), mergeCp, master, st, carried);
      st = r.state;
      carried = r.carriedLines;
      done = r.done;
    }
    await deleteScratchShards(depsFor(recs, dest, 700), st.scratchShards);
    return { dest, root: parseRoot(dest), steps, scratchCount: allScratch.length };
  }

  function parseRoot(dest: MemDest): RootCommit {
    const key = [...dest.map.keys()].find((k) => k.endsWith("root.manifest.json"));
    if (key === undefined) throw new Error("no signed root was written");
    return JSON.parse(new TextDecoder().decode(dest.map.get(key)!)) as RootCommit;
  }

  // planByScan drives the SLICED keys-only scan + the pure count/stride steppers to completion (mirroring
  // the coordinator's planTick), returning the BALANCED ranges, the counted total and the range count M.
  async function planByScan(src: KVSource, selector: Selector, n: number, maxRangeKeys: number, maxRanges: number): Promise<{ ranges: FanoutRange[]; total: number; rangeCount: number }> {
    const scan = newPlanScan();
    for await (const ev of src.listKeysFrom(selector, null)) countPage(scan, ev.keys.length);
    finishCount(scan, n, maxRangeKeys, maxRanges);
    for await (const ev of src.listKeysFrom(selector, null)) stridePage(scan, ev.keys);
    return { ranges: rangesFromSplitKeys(scan.splits), total: scan.total, rangeCount: scan.rangeCount };
  }

  // sealWithRanges seals each given range as a worker then merges into ONE archive (the fixed-master path
  // sealFanout uses, but over caller-supplied ranges -- so a scan-planned partition can be byte-compared).
  async function sealWithRanges(records: { name: string; value: Uint8Array }[], ranges: FanoutRange[], mergeSubreq: number): Promise<{ dest: MemDest; root: RootCommit }> {
    const dest = new MemDest();
    const allScratch: ShardEntry[] = [];
    let totalRecords = 0;
    for (let i = 0; i < ranges.length; i++) {
      const { shards, counts } = await sealRange(records, dest, i, ranges[i]!);
      allScratch.push(...shards);
      totalRecords += counts.records;
    }
    const mergeCp = baseCp({ counts: { ...zeroCounts(), records: totalRecords } });
    let st = newMergeState(allScratch);
    let carried: Record<string, unknown>[] = [];
    let done = false;
    for (let steps = 0; steps < 500 && !done; steps++) {
      const r = await mergeStep(depsFor(records, dest, mergeSubreq), mergeCp, master, st, carried);
      st = r.state;
      carried = r.carriedLines;
      done = r.done;
    }
    await deleteScratchShards(depsFor(records, dest, 700), st.scratchShards);
    return { dest, root: parseRoot(dest) };
  }

  // The fixed dataset: 14 distinct keys, varied small values. With shardMax 3 the serial seal makes 5
  // shards (3,3,3,3,2), so range boundaries (which fall on arbitrary keys) cannot align to shard boundaries
  // -- the merge MUST re-group across range seams to stay byte-identical.
  const recs = Array.from({ length: 14 }, (_, i) => ({ name: `key/${String(i).padStart(4, "0")}`, value: utf8(`fan-out-fixed-value-${i}-${"x".repeat(i % 5)}`) }));

  console.log("byte-identity: serial (N=1) vs fan-out (N=2,3,4) produce the IDENTICAL signed archive:");
  const serial = await sealSerial(recs);
  ok("serial seal wrote a signed root", serial.root.merkleRoot.length > 0);
  ok("serial seal grouped 14 records into 5 shards (shardMax 3)", serial.root.shardCount === 5 && serial.root.declaredRecordCount === 14);

  for (const n of [2, 3, 4]) {
    const fan = await sealFanout(recs, n, 700);
    ok(`N=${n}: fan-out partitioned into ${n} ranges and produced ${fan.scratchCount} scratch shards (> ${n})`, fan.scratchCount >= n);
    ok(`N=${n}: the signed MERKLE ROOT is byte-identical to the serial seal`, fan.root.merkleRoot === serial.root.merkleRoot);
    ok(`N=${n}: the signed shard list (id/object/sha384) + counts are identical`, JSON.stringify(fan.root.shards) === JSON.stringify(serial.root.shards) && fan.root.shardCount === serial.root.shardCount && fan.root.declaredRecordCount === serial.root.declaredRecordCount);
    // Each FINAL shard object is byte-for-byte identical (deterministic nonce + clock).
    let shardBytesEqual = true;
    for (const s of serial.root.shards) {
      const a = serial.dest.map.get(s.object);
      const b = fan.dest.map.get(s.object);
      if (!a || !b || Buffer.compare(Buffer.from(a), Buffer.from(b)) !== 0) shardBytesEqual = false;
    }
    ok(`N=${n}: every final shard object run/<id>/manifest/NNNNN.dpe is byte-identical`, shardBytesEqual);
    // The fan-out archive contains ONLY the final shards (scratch deleted): no 10-digit composite ids left.
    const leftoverScratch = [...fan.dest.map.keys()].filter((k) => /manifest\/\d{10}\.dpe$/.test(k));
    ok(`N=${n}: the merge reclaimed every scratch shard (no composite-id shard left under manifest/)`, leftoverScratch.length === 0);
    // Both archives open and restore the SAME record set byte-exact.
    const runFan = await openRun(new MapStore(fan.dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
    ok(`N=${n}: the fan-out archive opens (signature, shard hashes, record hashes, merkle root) with all 14 records`, runFan.records.length === 14);
    let restoredExact = true;
    for (const rec of runFan.records) {
      const want = recs.find((x) => x.name === rec.name);
      if (!want) { restoredExact = false; continue; }
      const got = await runFan.restoreRecord(rec);
      if (Buffer.compare(Buffer.from(got), Buffer.from(want.value)) !== 0) restoredExact = false;
    }
    ok(`N=${n}: every record restores byte-exact (by name, not recordId)`, restoredExact);
  }

  console.log("\nsliced merge: a tiny per-step budget (frontier checkpointed across many steps) yields the IDENTICAL archive:");
  {
    // subrequests just above FINALISE_RESERVE so each step consumes only a few scratch shards, forcing many
    // merge slices; the forward-progress guard guarantees >=1 scratch shard per step (no wedge).
    const sliced = await sealFanout(recs, 4, 44);
    ok(`the sliced merge took multiple steps (${sliced.steps})`, sliced.steps > 1);
    ok("the sliced merge's signed merkle root matches the serial seal", sliced.root.merkleRoot === serial.root.merkleRoot);
    ok("the sliced merge's shard list matches the serial seal", JSON.stringify(sliced.root.shards) === JSON.stringify(serial.root.shards));
    const runSliced = await openRun(new MapStore(sliced.dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
    ok("the sliced-merge archive opens with all 14 records", runSliced.records.length === 14);
  }

  console.log("\npartitionKeyRange: the half-open seam covers every key EXACTLY ONCE (no drop, no double):");
  {
    const keys = recs.map((r) => r.name).sort();
    for (const n of [2, 3, 4, 5]) {
      const ranges = partitionKeyRange(keys, n);
      // Every key must fall into exactly one range under (startAfter EXCLUSIVE, stopAt INCLUSIVE].
      let coveredOnce = true;
      for (const k of keys) {
        let hits = 0;
        for (const r of ranges) {
          const aboveStart = r.startAfter === undefined || k > r.startAfter;
          const belowStop = r.stopAt === undefined || k <= r.stopAt;
          if (aboveStart && belowStop) hits++;
        }
        if (hits !== 1) coveredOnce = false;
      }
      ok(`N=${n}: every key is covered by exactly one range`, coveredOnce);
      ok(`N=${n}: range 0 has no startAfter and the last has no stopAt (cover the whole keyspace)`, ranges[0]!.startAfter === undefined && ranges[ranges.length - 1]!.stopAt === undefined);
    }
    // A boundary key equal to a split goes to the LOWER range (inclusive stopAt), never the next.
    const ranges = partitionKeyRange(keys, 2);
    const split = ranges[0]!.stopAt!;
    ok("a key equal to a split point belongs to its lower range only (inclusive stopAt / exclusive startAfter)", split === ranges[1]!.startAfter && keys.includes(split));
  }

  console.log("\nrange cap: planned ranges are sized strictly below the KV watermark-rescan ceiling:");
  {
    const keys = recs.map((r) => r.name).sort(); // 14 distinct keys
    // The production cap is STRICTLY below the rescan ceiling (slice subrequest budget * KV list page), so a
    // single range can never fast-forward past the slice budget on a cursor-refused resume and wedge.
    const rescanCeiling = DEFAULT_SLICE_SUBREQUESTS * KV_LIST_PAGE_KEYS;
    ok(`FANOUT_MAX_RANGE_KEYS (${FANOUT_MAX_RANGE_KEYS}) is strictly below the rescan ceiling (${rescanCeiling})`, FANOUT_MAX_RANGE_KEYS > 0 && FANOUT_MAX_RANGE_KEYS < rescanCeiling);
    // A tiny cap forces partitionKeyRange to SPLIT FURTHER so no range spans more than the cap, while the
    // half-open seam still covers every key exactly once (the production 175k cap over a <=10k sample is a
    // no-op; this proves the capping mechanism the production constant relies on).
    const spanOf = (r: FanoutRange): number => keys.filter((k) => (r.startAfter === undefined || k > r.startAfter) && (r.stopAt === undefined || k <= r.stopAt)).length;
    for (const cap of [2, 3, 5]) {
      const capped = partitionKeyRange(keys, 2, cap);
      const maxSpan = Math.max(...capped.map(spanOf));
      let coveredOnce = true;
      for (const k of keys) {
        let hits = 0;
        for (const r of capped) if ((r.startAfter === undefined || k > r.startAfter) && (r.stopAt === undefined || k <= r.stopAt)) hits++;
        if (hits !== 1) coveredOnce = false;
      }
      ok(`cap ${cap}: every planned range spans <= ${cap} keys (max ${maxSpan}) and still covers each key exactly once`, maxSpan <= cap && coveredOnce);
    }
    // The cap is a NO-OP when the sample is within it, so a capped partition (no bite) is byte-identical to
    // the uncapped even-N partition -- the byte-identity seal contract seals over partitionKeyRange(keys, n).
    for (const n of [2, 3, 4, 5]) {
      ok(`cap is a no-op within the sample: partitionKeyRange(keys, ${n}, HUGE) === partitionKeyRange(keys, ${n})`, JSON.stringify(partitionKeyRange(keys, n, 1_000_000)) === JSON.stringify(partitionKeyRange(keys, n)));
    }
  }

  console.log("\nKV range crawl: startAfter EXCLUSIVE + stopAt INCLUSIVE yield exactly the in-range keys:");
  {
    const kv = new MemKV(recs, pageSize);
    const src = new KVSource(kv as unknown as KVNamespace, "ns1");
    async function namesIn(range: FanoutRange): Promise<string[]> {
      const out: string[] = [];
      for await (const ev of src.crawlFrom({ include: [], exclude: [], range }, null)) {
        if (ev.kind === "record") out.push(ev.record.name);
      }
      return out;
    }
    const got = await namesIn({ startAfter: "key/0003", stopAt: "key/0009" });
    const want = recs.map((r) => r.name).filter((k) => k > "key/0003" && k <= "key/0009");
    ok("crawlFrom over a range yields exactly the keys in (startAfter, stopAt]", JSON.stringify(got) === JSON.stringify(want) && got.length === 6);
    ok("the EXCLUSIVE startAfter key (key/0003) is NOT yielded", !got.includes("key/0003"));
    ok("the INCLUSIVE stopAt key (key/0009) IS yielded", got.includes("key/0009"));
    // Concatenating all ranges' crawls reproduces the whole keyspace in order, exactly once.
    const ranges = partitionKeyRange(recs.map((r) => r.name).sort(), 3);
    const concatenated: string[] = [];
    for (const r of ranges) concatenated.push(...(await namesIn(r)));
    ok("the N ranges concatenate to the full keyspace in key order (no gap, no overlap)", JSON.stringify(concatenated) === JSON.stringify(recs.map((r) => r.name).sort()));
  }

  console.log("\ncompleteness guard: a merge missing a scratch shard FAILS LOUD (never signs a short archive):");
  {
    const dest = new MemDest();
    const sortedKeys = recs.map((r) => r.name).sort();
    const ranges = partitionKeyRange(sortedKeys, 3);
    const allScratch: ShardEntry[] = [];
    let totalRecords = 0;
    for (let i = 0; i < ranges.length; i++) {
      const { shards, counts } = await sealRange(recs, dest, i, ranges[i]!);
      allScratch.push(...shards);
      totalRecords += counts.records;
    }
    // Drop the bytes of one scratch shard from the destination: the merge must refuse rather than sign a
    // root that declares more records than the shards hold.
    const victim = allScratch[allScratch.length - 1]!;
    dest.map.delete(victim.object);
    const mergeCp = baseCp({ counts: { ...zeroCounts(), records: totalRecords } });
    let threw = false;
    let loud = false;
    try {
      await mergeStep(depsFor(recs, dest, 700), mergeCp, master, newMergeState(allScratch), []);
    } catch (e) {
      threw = true;
      loud = /scratch shard .* is missing|truncated archive/.test((e as Error).message);
    }
    ok("a missing scratch shard makes the merge throw (no truncated archive signed)", threw && loud);
    ok("no signed root was written for the incomplete merge", ![...dest.map.keys()].some((k) => k.endsWith("root.manifest.json")));
  }

  console.log("\nplanFanout: DIRECT plan when the keyspace fits the front sample, SCAN when larger, SERIAL otherwise:");
  {
    const kvSrc = (): KVSource => new KVSource(new MemKV(recs, pageSize) as unknown as KVNamespace, "ns1");
    const direct = await planFanout(kvSrc(), { include: [], exclude: [] }, { ranges: 4, minRecords: 1 });
    ok("DIRECT plan with 4 ranges when ranges>=2, big enough, and the whole keyspace fit the sample", direct.mode === "direct" && direct.ranges.length === 4);
    const scan = await planFanout(kvSrc(), { include: [], exclude: [] }, { ranges: 4, minRecords: 1, sampleCap: 3 });
    ok("SCAN plan when the keyspace is LARGER than the front sample (more:true): the coordinator plans balanced", scan.mode === "scan");
    ok("SCAN plan IGNORES min-records at probe time (the coordinator applies it against the real count -- un-clamp)", (await planFanout(kvSrc(), { include: [], exclude: [] }, { ranges: 4, minRecords: 1_000_000, sampleCap: 3 })).mode === "scan");
    ok("SERIAL when fan-out is OFF (ranges<2, the default)", (await planFanout(kvSrc(), { include: [], exclude: [] }, { ranges: 1, minRecords: 1 })).mode === "serial");
    ok("SERIAL below min-records when the whole keyspace fit the sample (exact gate, no clamp)", (await planFanout(kvSrc(), { include: [], exclude: [] }, { ranges: 4, minRecords: 1_000_000 })).mode === "serial");
    const nonKv = { sourceType: "d1", crawl: async function* () {}, estimate: async () => ({ records: 0, bytes: 0 }) } as unknown as SourceAdapter;
    ok("SERIAL for a non-key-sampler source (D1/secrets/API never fan out)", (await planFanout(nonKv, { include: [], exclude: [] }, { ranges: 4, minRecords: 1 })).mode === "serial");
    const emptyKv = new KVSource(new MemKV([], pageSize) as unknown as KVNamespace, "ns1");
    ok("SERIAL for an empty source (nothing to split)", (await planFanout(emptyKv, { include: [], exclude: [] }, { ranges: 4, minRecords: 1 })).mode === "serial");
    // sampleKeys reports more:true once the cap is hit (the planner's bounded scan).
    const capped = await kvSrc().sampleKeys({ include: [], exclude: [] }, 3);
    ok("sampleKeys caps the scan and reports more:true", capped.keys.length === 3 && capped.more === true);
  }

  console.log("\nbranch coverage: partitionKeyRange edges, renumberLine guard, mergeStep empty parity, scratch-shard integrity:");
  {
    let threw = false;
    try { partitionKeyRange([], 0); } catch { threw = true; }
    ok("partitionKeyRange throws on a non-positive N", threw);
    ok("partitionKeyRange(keys, 1) is the whole keyspace", JSON.stringify(partitionKeyRange(["a", "b"], 1)) === JSON.stringify([{}]));
    ok("partitionKeyRange on fewer than 2 keys is the whole keyspace", JSON.stringify(partitionKeyRange(["only"], 4)) === JSON.stringify([{}]));
    ok("partitionKeyRange collapses duplicate split points (no empty range)", partitionKeyRange(["a", "a", "a", "a"], 4).length < 4);

    let rThrew = false;
    try { await renumberLine({ kind: "record", recordId: "r00000_0000000000" }, "r000000000000000"); } catch { rThrew = true; }
    ok("renumberLine refuses a line missing its hash/size fields (fails loud)", rThrew);

    ok("sealRangeOpenShard returns null for an empty open buffer", (await sealRangeOpenShard(depsFor(recs, new MemDest(), 700), baseCp({ rangeIndex: 0 }), master, [])) === null);

    // An empty run (0 records, 0 scratch shards) merges to ONE empty parity shard (finaliseRun's parity).
    const emptyDest = new MemDest();
    const emptyMergeCp = baseCp({ counts: { ...zeroCounts(), records: 0 } });
    const er = await mergeStep(depsFor(recs, emptyDest, 700), emptyMergeCp, master, newMergeState([]), []);
    ok("an empty fan-out run merges to one empty parity shard + a signed root", er.done && er.recordCount === 0 && er.state.finalShards.length === 1);

    // A scratch shard whose BYTES were corrupted (sha384 != the worker report) is refused by the merge.
    const corruptDest = new MemDest();
    const sortedKeys = recs.map((r) => r.name).sort();
    const ranges = partitionKeyRange(sortedKeys, 2);
    const scratch: ShardEntry[] = [];
    for (let i = 0; i < ranges.length; i++) scratch.push(...(await sealRange(recs, corruptDest, i, ranges[i]!)).shards);
    const victim = scratch[0]!;
    const bad = new Uint8Array(corruptDest.map.get(victim.object)!);
    bad[bad.length - 1] = bad[bad.length - 1]! ^ 0xff;
    corruptDest.map.set(victim.object, bad);
    let hashThrew = false;
    let hashLoud = false;
    try { await mergeStep(depsFor(recs, corruptDest, 700), baseCp({ counts: { ...zeroCounts(), records: recs.length } }), master, newMergeState(scratch), []); } catch (e) { hashThrew = true; hashLoud = /hash does not match the worker report/.test((e as Error).message); }
    ok("a corrupted scratch shard (sha384 mismatch) FAILS the merge loud", hashThrew && hashLoud);

    // Fan-out UNDER-CRAWL cross-check (defense-in-depth): the globalRecordIndex===counts.records guard above
    // only proves the merge is INTERNALLY consistent -- it re-read exactly as many records as the workers
    // REPORTED -- so a UNIFORM under-crawl (every worker honestly reporting a range it silently crawled short)
    // satisfies it. So the merge ALSO cross-checks the workers' summed reports against the COUNT-pass
    // authoritative total carried on MergeState.expectedRecordTotal: a SHORTFALL fails loud. runUnderCrawlMerge
    // seals a real 2-range fan-out into a FRESH dest (so each case merges independently) and drives the merge
    // to completion with a given expectedRecordTotal, returning whether it finished or failed loud.
    const runUnderCrawlMerge = async (expectedRecordTotal: number | undefined): Promise<{ done: boolean; threw: boolean; loud: boolean }> => {
      const dest = new MemDest();
      const ranges2 = partitionKeyRange(recs.map((r) => r.name).sort(), 2);
      const scratch: ShardEntry[] = [];
      let total = 0;
      for (let i = 0; i < ranges2.length; i++) { const { shards, counts } = await sealRange(recs, dest, i, ranges2[i]!); scratch.push(...shards); total += counts.records; }
      const cp = baseCp({ counts: { ...zeroCounts(), records: total } }); // the summed worker reports
      let st = expectedRecordTotal === undefined ? newMergeState(scratch) : newMergeState(scratch, expectedRecordTotal);
      let carried: Record<string, unknown>[] = [];
      let done = false;
      try {
        for (let steps = 0; steps < 500 && !done; steps++) { const r = await mergeStep(depsFor(recs, dest, 700), cp, master, st, carried); st = r.state; carried = r.carriedLines; done = r.done; }
      } catch (e) { return { done: false, threw: true, loud: /under-crawl|short of its authoritative key count/.test((e as Error).message) }; }
      return { done, threw: false, loud: false };
    };
    // (a) expectedRecordTotal HIGHER than the sealed total = a uniform under-crawl (the workers encountered
    //     FEWER keys than the count pass found) -> FAIL LOUD, even though globalRecordIndex===counts.records holds.
    const ucShort = await runUnderCrawlMerge(recs.length + 3);
    ok("under-crawl: workers reporting FEWER records than the count-pass total FAIL the merge loud", ucShort.threw && ucShort.loud);
    // (b) expectedRecordTotal EQUAL to the sealed total = a clean run -> merges cleanly (no false positive).
    ok("under-crawl: an EXACT count-pass match merges cleanly (no false positive)", (await runUnderCrawlMerge(recs.length)).done);
    // (c) expectedRecordTotal LOWER than the sealed total = keys ADDED since the count -> merges cleanly (an
    //     over-count is not a shortfall / not data loss).
    ok("under-crawl: an OVER-count (keys added since the count pass) merges cleanly (not a shortfall)", (await runUnderCrawlMerge(recs.length - 2)).done);
    // (d) expectedRecordTotal ABSENT (a DIRECT-planned run, no count pass) -> the cross-check is SKIPPED.
    ok("under-crawl: a DIRECT-planned run (no count pass) skips the cross-check and merges cleanly", (await runUnderCrawlMerge(undefined)).done);

    // deleteScratchShards is best-effort: a delete that throws is swallowed (a WORM/transient orphan is harmless).
    const throwingDest = new (class extends MemDest { override async delete(): Promise<void> { throw new Error("status 403 immutable"); } })();
    let delThrew = false;
    try { await deleteScratchShards(depsFor(recs, throwingDest, 700), [{ id: "0000000000", object: "x", sha384: "y" }]); } catch { delThrew = true; }
    ok("deleteScratchShards swallows a refused delete (best-effort GC)", !delThrew);
  }

  console.log("\nmulti-DO orchestration: sealRunSliced -> COORDINATOR spawns WORKERS -> /range-done -> sliced merge -> ok /complete:");
  {
    // A fleet of REAL RunSealDO instances (the coordinator idFromName(dp) + a worker idFromName(dp#rN) per
    // range), wired by a RUNSEAL namespace double, all driven in Node. The whole fan-out lifecycle runs:
    // sealRunSliced plans + hands off, the coordinator spawns workers, each worker seals its range across
    // slices and posts /range-done, and the coordinator runs the sliced merge to the ok completion.
    const dest = new MemDest();
    const sched = makeScheduler();
    const breakGlassB64 = b64urlEncode(concat(breakGlass.entry.pub.x25519, breakGlass.entry.pub.mlkemEk));
    const { env, instances } = makeFleet({ dest, kv: new MemKV(recs, pageSize), sched: sched.stub, signerPrivateB64, breakGlassB64, knobs: { SCALE_FANOUT_RANGES: "4", SCALE_FANOUT_MIN_RECORDS: "1", SCALE_SHARD_MAX_RECORDS: "3", SCALE_SLICE_SUBREQUESTS: "44" } });

    await sealRunSliced(env, dpStateKv(), { runId: RUN_ID, index: 9, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) });
    ok("sealRunSliced fanned the run out (coordinator doc persisted, no inline serial run)", (instances.get(DP_ID)?.storage.get("doc") as { kind?: string } | undefined)?.kind === "coordinator");
    ok("the coordinator spawned 4 worker DOs", [0, 1, 2, 3].every((i) => instances.has(`${DP_ID}#r${i}`)));

    const rounds = await driveFleet(instances, sched.calls);
    const complete = sched.calls.find((c) => c.path === "/complete");
    const body = complete?.body as { status?: string; recordCount?: number; index?: number } | undefined;
    ok(`the fan-out run posted the ok completion (after ${rounds} alarm rounds)`, body?.status === "ok" && body?.index === 9);
    ok("the completion declares the full global record count (14)", body?.recordCount === 14);
    ok("every DO cleaned up its state (coordinator + workers)", [...instances.values()].every((inst) => !inst.storage.has("doc")));
    // The orchestrated archive opens and restores every record byte-exact (a correct, verifiable single archive).
    const runDo = await openRun(new MapStore(dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
    ok("the orchestrated archive opens (signature, completeness, merkle root) with all 14 records", runDo.records.length === 14);
    let exact = true;
    for (const rec of runDo.records) {
      const want = recs.find((x) => x.name === rec.name);
      if (!want || Buffer.compare(Buffer.from(await runDo.restoreRecord(rec)), Buffer.from(want.value)) !== 0) exact = false;
    }
    ok("every orchestrated record restores byte-exact", exact);
    const leftoverScratch = [...dest.map.keys()].filter((k) => /manifest\/\d{10}\.dpe$/.test(k));
    ok("the orchestrated merge reclaimed every scratch shard", leftoverScratch.length === 0);
  }

  console.log("\nfan-out fault ladders: a WORKER hard fault / throttle and a COORDINATOR merge fault all FAIL CLOSED:");
  {
    // A worker whose segment write hard-faults (403) strikes to MAX_SLICE_FAILURES, reports /range-failed,
    // and the coordinator fails the whole run honestly (handleRangeFailed -> failed /complete).
    const dest = new (class extends MemDest { override async put(key: string, body: Uint8Array): Promise<void> { if (key.startsWith("seg/")) throw new Error(`PUT ${key}: status 403 AccessDenied`); return super.put(key, body); } })();
    const sched = makeScheduler();
    const breakGlassB64 = b64urlEncode(concat(breakGlass.entry.pub.x25519, breakGlass.entry.pub.mlkemEk));
    const { env, instances } = makeFleet({ dest, kv: new MemKV(recs, pageSize), sched: sched.stub, signerPrivateB64, breakGlassB64, knobs: { SCALE_FANOUT_RANGES: "3", SCALE_FANOUT_MIN_RECORDS: "1", SCALE_SHARD_MAX_RECORDS: "3", DEST_THROTTLE_BASE_MS: "1" } });
    await sealRunSliced(env, dpStateKv(), { runId: RUN_ID, index: 10, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) });
    await driveFleet(instances, sched.calls);
    const c = sched.calls.find((x) => x.path === "/complete");
    ok("a worker hard fault fails the run closed (failed /complete, empty runId)", (c?.body as { status?: string; runId?: string } | undefined)?.status === "failed" && (c?.body as { runId?: string } | undefined)?.runId === "");
    ok("no signed root was written for the failed fan-out run", ![...dest.map.keys()].some((k) => k.endsWith("root.manifest.json")));
  }
  {
    // A worker throttled (503) for the whole parking window (DEST_THROTTLE_MAX_YIELDS=2) parks then fails
    // the range (workerFault throttle ladder: park -> sustained-throttle terminal), failing the run closed.
    const dest = new (class extends MemDest { override async put(key: string, body: Uint8Array): Promise<void> { if (key.startsWith("seg/")) throw new Error(`PUT ${key}: status 503 SlowDown`); return super.put(key, body); } })();
    const sched = makeScheduler();
    const breakGlassB64 = b64urlEncode(concat(breakGlass.entry.pub.x25519, breakGlass.entry.pub.mlkemEk));
    const { env, instances } = makeFleet({ dest, kv: new MemKV(recs, pageSize), sched: sched.stub, signerPrivateB64, breakGlassB64, knobs: { SCALE_FANOUT_RANGES: "2", SCALE_FANOUT_MIN_RECORDS: "1", SCALE_SHARD_MAX_RECORDS: "3", DEST_THROTTLE_BASE_MS: "1", DEST_THROTTLE_ATTEMPTS: "1", DEST_THROTTLE_MAX_YIELDS: "2" } });
    await sealRunSliced(env, dpStateKv(), { runId: RUN_ID, index: 11, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) });
    // observe a PARK first (throttleAttempt set, no strike) before the terminal
    let parked = false;
    for (let i = 0; i < 60; i++) {
      if (sched.calls.some((x) => x.path === "/complete")) break;
      for (const inst of [...instances.values()]) {
        if (inst.storage.has("doc")) {
          await inst.obj!.alarm();
          const d = inst.storage.get("doc") as { throttleAttempt?: number } | undefined;
          if (d && (d.throttleAttempt ?? 0) > 0) parked = true;
        }
      }
    }
    const c = sched.calls.find((x) => x.path === "/complete");
    ok("a throttled worker PARKS (throttleAttempt advanced, no strike) before giving up", parked);
    ok("a worker throttled for the whole window fails the run closed", (c?.body as { status?: string } | undefined)?.status === "failed");
  }
  {
    // The workers succeed, but the COORDINATOR's signed-root write hard-faults (500): the merge strikes to
    // MAX and fails the run closed (coordinatorFault hard ladder), never a partial archive reported ok.
    const dest = new (class extends MemDest { override async put(key: string, body: Uint8Array): Promise<void> { if (key.endsWith("root.manifest.json")) throw new Error(`PUT ${key}: status 500 internal`); return super.put(key, body); } })();
    const sched = makeScheduler();
    const breakGlassB64 = b64urlEncode(concat(breakGlass.entry.pub.x25519, breakGlass.entry.pub.mlkemEk));
    const { env, instances } = makeFleet({ dest, kv: new MemKV(recs, pageSize), sched: sched.stub, signerPrivateB64, breakGlassB64, knobs: { SCALE_FANOUT_RANGES: "2", SCALE_FANOUT_MIN_RECORDS: "1", SCALE_SHARD_MAX_RECORDS: "3", DEST_THROTTLE_BASE_MS: "1" } });
    await sealRunSliced(env, dpStateKv(), { runId: RUN_ID, index: 12, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) });
    await driveFleet(instances, sched.calls, 200);
    const c = sched.calls.find((x) => x.path === "/complete");
    ok("a coordinator merge fault (root write 500) fails the run closed after striking", (c?.body as { status?: string } | undefined)?.status === "failed");
  }
  {
    // A coordinator whose signed-root write is THROTTLED (503) parks on its patient ladder (no strike) and,
    // after the whole parking window (DEST_THROTTLE_MAX_YIELDS=2), fails the run closed -- so a destination
    // down through the merge can never park the lease-holding coordinator forever.
    const dest = new (class extends MemDest { override async put(key: string, body: Uint8Array): Promise<void> { if (key.endsWith("root.manifest.json")) throw new Error(`PUT ${key}: status 503 SlowDown`); return super.put(key, body); } })();
    const sched = makeScheduler();
    const breakGlassB64 = b64urlEncode(concat(breakGlass.entry.pub.x25519, breakGlass.entry.pub.mlkemEk));
    const { env, instances } = makeFleet({ dest, kv: new MemKV(recs, pageSize), sched: sched.stub, signerPrivateB64, breakGlassB64, knobs: { SCALE_FANOUT_RANGES: "2", SCALE_FANOUT_MIN_RECORDS: "1", SCALE_SHARD_MAX_RECORDS: "3", DEST_THROTTLE_BASE_MS: "1", DEST_THROTTLE_ATTEMPTS: "1", DEST_THROTTLE_MAX_YIELDS: "2" } });
    await sealRunSliced(env, dpStateKv(), { runId: RUN_ID, index: 14, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) });
    let coordParked = false;
    for (let i = 0; i < 80; i++) {
      if (sched.calls.some((x) => x.path === "/complete")) break;
      for (const inst of [...instances.values()]) {
        if (inst.storage.has("doc")) {
          await inst.obj!.alarm();
          const d = inst.storage.get("doc") as { kind?: string; throttleAttempt?: number } | undefined;
          if (d?.kind === "coordinator" && (d.throttleAttempt ?? 0) > 0) coordParked = true;
        }
      }
    }
    const c = sched.calls.find((x) => x.path === "/complete");
    ok("a coordinator merge THROTTLE parks the merge (no strike) before giving up", coordParked);
    ok("a coordinator throttled through the whole window fails the run closed", (c?.body as { status?: string } | undefined)?.status === "failed");
  }

  console.log("\nsilent stall: a worker that never progresses (the uncatchable wedge) is STRUCK OUT, fails closed + releases the lease:");
  {
    // Unlike the loud worker-fault test above (which THROWS and rides the worker's own strike ladder), this
    // is the SILENT stall: a worker that never reports /range-done and never advances its checkpoint -- the
    // KV watermark-rescan / CPU hard-kill wedge that no JS catch sees, so the worker's own ladder never
    // fires. We model it faithfully by NEVER driving the workers' alarms (an uncatchable kill persists
    // nothing and never re-fires usefully): the workers sit frozen at their slice-0 baseline. The
    // coordinator's no-progress ladder must strike them and fail the run CLOSED within a bounded number of
    // ticks (NOT await forever), write no signed root, and RELEASE the lease so the run becomes reclaimable.
    const dest = new MemDest();
    const sched = makeScheduler();
    const breakGlassB64 = b64urlEncode(concat(breakGlass.entry.pub.x25519, breakGlass.entry.pub.mlkemEk));
    const { env, instances } = makeFleet({ dest, kv: new MemKV(recs, pageSize), sched: sched.stub, signerPrivateB64, breakGlassB64, knobs: { SCALE_FANOUT_RANGES: "2", SCALE_FANOUT_MIN_RECORDS: "1", SCALE_SHARD_MAX_RECORDS: "3" } });
    await sealRunSliced(env, dpStateKv(), { runId: RUN_ID, index: 20, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) });
    const coord = instances.get(DP_ID)!;
    ok("the run fanned out (coordinator awaiting two workers)", (coord.storage.get("doc") as { kind?: string; phase?: string } | undefined)?.phase === "await");
    // Cover both stall modes: range 0's worker is frozen-but-PRESENT (the rescan wedge --
    // /status keeps returning the same fingerprint), and range 1's worker has VANISHED (the partial-spawn
    // orphan / "alarm never re-fires" -- its doc is gone, so /status reports active:false). Both must strike.
    instances.get(`${DP_ID}#r1`)!.storage.delete("doc");
    // Drive ONLY the coordinator (both workers silently stalled), counting ticks until it fails closed.
    let coordTicks = 0;
    for (let i = 0; i < 50; i++) {
      if (sched.calls.some((x) => x.path === "/complete")) break;
      if (!coord.storage.has("doc")) break;
      await coord.obj!.alarm();
      coordTicks++;
    }
    const c = sched.calls.find((x) => x.path === "/complete");
    const cb = c?.body as { status?: string; runId?: string } | undefined;
    ok(`a silently stalled worker is struck out and the run fails CLOSED within the bounded ladder (${coordTicks} ticks, <= ${MAX_SLICE_FAILURES + 2})`, cb?.status === "failed" && cb?.runId === "" && coordTicks <= MAX_SLICE_FAILURES + 2);
    ok("the stalled run did NOT await forever (it terminated within the ladder, not maxRounds)", coordTicks < 50);
    ok("the stalled fan-out run wrote NO signed root", ![...dest.map.keys()].some((k) => k.endsWith("root.manifest.json")));
    ok("the coordinator RELEASED the lease: its doc + alarm are cleaned up (the run is now reclaimable)", !coord.storage.has("doc"));
    // It STOPS heartbeating owned:true: driving the now-doc-less coordinator records no further heartbeat,
    // so the scheduler's stuck-lease reclaim is restored (the backstop fan-out had removed).
    const hbBefore = sched.calls.filter((x) => x.path === "/heartbeat").length;
    await coord.obj!.alarm();
    const hbAfter = sched.calls.filter((x) => x.path === "/heartbeat").length;
    ok("the struck-out coordinator no longer heartbeats owned:true (lease reclaim restored)", hbAfter === hbBefore);
  }
  {
    // A worker that PROGRESSES (advancing fingerprint) is NEVER struck by the no-progress ladder: the happy
    // path completes ok even though the coordinator now polls liveness each await tick (no false strike).
    const dest = new MemDest();
    const sched = makeScheduler();
    const breakGlassB64 = b64urlEncode(concat(breakGlass.entry.pub.x25519, breakGlass.entry.pub.mlkemEk));
    const { env, instances } = makeFleet({ dest, kv: new MemKV(recs, pageSize), sched: sched.stub, signerPrivateB64, breakGlassB64, knobs: { SCALE_FANOUT_RANGES: "3", SCALE_FANOUT_MIN_RECORDS: "1", SCALE_SHARD_MAX_RECORDS: "3", SCALE_SLICE_SUBREQUESTS: "44" } });
    await sealRunSliced(env, dpStateKv(), { runId: RUN_ID, index: 21, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) });
    await driveFleet(instances, sched.calls);
    const c = sched.calls.find((x) => x.path === "/complete");
    ok("a progressing fan-out run still completes OK (the liveness poll never false-strikes a live worker)", (c?.body as { status?: string; recordCount?: number } | undefined)?.status === "ok" && (c?.body as { recordCount?: number } | undefined)?.recordCount === 14);
  }

  console.log("\na /range-done that lands WHILE awaitTick's own fetches are in flight is not reverted by its stale write-back:");
  {
    // awaitTick's poll loop (and coordinatorAlarm's earlier heartbeatBase) each fetch() a worker DO, which
    // releases the coordinator DO's automatic input gate for that round trip (runtime.input-gate-probe.test.mjs
    // pins this rule down). A genuinely concurrent handleRangeDone() is admitted during that window, records
    // its range, and the reporting worker then cleans itself up -- so a blind write-back of the `doc` this
    // tick STARTED with would silently revert that completion forever (the worker that reported it is gone).
    // Reproduce the interleaving deterministically: gate range 0's /status poll open, call awaitTick()
    // directly so it suspends there, drive a REAL /range-done for a DIFFERENT range (1) to completion while
    // it is suspended, then release the gate and assert the completion SURVIVES the tick's persist.
    const dest = new MemDest();
    const sched = makeScheduler();
    const breakGlassB64 = b64urlEncode(concat(breakGlass.entry.pub.x25519, breakGlass.entry.pub.mlkemEk));
    const { env, instances } = makeFleet({ dest, kv: new MemKV(recs, pageSize), sched: sched.stub, signerPrivateB64, breakGlassB64, knobs: { SCALE_FANOUT_RANGES: "3", SCALE_FANOUT_MIN_RECORDS: "1", SCALE_SHARD_MAX_RECORDS: "3", SCALE_SLICE_SUBREQUESTS: "44" } });
    await sealRunSliced(env, dpStateKv(), { runId: RUN_ID, index: 30, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) });
    const coord = instances.get(DP_ID)!;
    ok("the run fanned out to 3 awaited ranges", (coord.storage.get("doc") as { kind?: string; phase?: string } | undefined)?.phase === "await");

    // Wrap the RUNSEAL namespace double so range 0's /status poll is held open until the test releases it;
    // every other call (including range 1/2's polls and the coordinator's own routes) is unaffected.
    type FakeNS = { idFromName(name: string): { name: string }; get(id: { name: string }): { fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> } };
    const realRunseal = env.RUNSEAL as unknown as FakeNS;
    let releaseR0: (() => void) | null = null;
    const r0Gate = new Promise<void>((resolve) => { releaseR0 = resolve; });
    const gated: FakeNS = {
      idFromName: (name) => realRunseal.idFromName(name),
      get: (id) => {
        if (id.name !== `${DP_ID}#r0`) return realRunseal.get(id);
        return {
          async fetch(input, init) {
            const url = new URL(input instanceof Request ? input.url : String(input));
            if (url.pathname !== "/status") return realRunseal.get(id).fetch(input, init);
            await r0Gate; // hold the gate open; the coordinator's input gate is released for exactly this long
            return new Response(JSON.stringify({ active: false })); // the (fictional) worker already cleaned itself up
          },
        };
      },
    };
    env.RUNSEAL = gated as unknown as DurableObjectNamespace;

    // structuredClone: this fake storage's Map hands back the SAME live object on every get(), unlike real DO
    // storage (which deserializes a fresh copy each call). Snapshot it so the concurrent handleRangeDone
    // below mutates an INDEPENDENT copy in the Map -- faithfully modelling awaitTick's `doc` param as the
    // frozen-in-time read coordinatorAlarm took before this tick's fetches opened the gate.
    const doc = structuredClone(coord.storage.get("doc")) as CoordinatorDoc;
    const internal = coord.obj as unknown as { awaitTick(scheduler: DurableObjectStub, doc: CoordinatorDoc): Promise<void> };
    const tickDone = internal.awaitTick(sched.stub, doc); // suspends mid-tick, blocked on range 0's poll

    // While the tick is suspended, drive a REAL /range-done for range 1 (not range 0) straight through the
    // coordinator's own route -- exactly the concurrent worker-initiated call described above.
    const rd = await coord.obj!.fetch(new Request("https://runseal.internal/range-done", { method: "POST", body: JSON.stringify({ rangeIndex: 1, shards: [], recordCount: 0, counts: zeroCounts() }), headers: { "content-type": "application/json" } }));
    ok("the concurrent /range-done for range 1 is admitted while the tick is suspended", rd.status === 200);
    const midDoc = coord.storage.get("doc") as { doneRanges?: unknown[] } | undefined;
    ok("range 1 is recorded done in storage before the suspended tick resolves", midDoc?.doneRanges?.[1] != null);

    releaseR0!(); // let the deferred poll -- and the tick's tail persist -- proceed
    await tickDone;

    const finalDoc = coord.storage.get("doc") as { doneRanges?: unknown[]; phase?: string } | undefined;
    ok("range 1's concurrently-recorded completion SURVIVES the tick's persist (fails pre-fix: reverted to null)", finalDoc?.doneRanges?.[1] != null);
    ok("the coordinator is still awaiting ranges 0 and 2 (untouched by the merge)", finalDoc?.phase === "await" && finalDoc?.doneRanges?.[0] === null && finalDoc?.doneRanges?.[2] === null);
  }

  console.log("\na /range-failed arriving after the coordinator has already flipped to MERGE no longer wipes it:");
  {
    // handleRangeFailed used to check only doc?.kind !== "coordinator" (unlike handleRangeDone, which also
    // requires phase === "await"), so a straggling worker's /range-failed retry landing after every range
    // has already reported done -- and the coordinator has moved on to merging -- would run cleanup() and
    // destroy the in-progress merge state (plus the coordinator's storage + alarm) out from under it.
    const dest = new MemDest();
    const sched = makeScheduler();
    const breakGlassB64 = b64urlEncode(concat(breakGlass.entry.pub.x25519, breakGlass.entry.pub.mlkemEk));
    const { env, instFor } = makeFleet({ dest, kv: new MemKV(recs, pageSize), sched: sched.stub, signerPrivateB64, breakGlassB64 });
    void env;
    const co = instFor(DP_ID).obj!;
    await co.fetch(new Request("https://runseal.internal/start-fanout", { method: "POST", body: JSON.stringify({ config: dpStateKv().config, base: { runId: RUN_ID, runlogIndex: 40, prevRunId: null, downpipeId: DP_ID, downpipeName: "fanout", cadence: "3600s", sourceType: "kv", startedAt: "2026-06-10T00:00:00.000Z" }, selector: { include: [], exclude: [] }, wrappedMaster: { iv: "", ct: "" }, ranges: [{ stopAt: "key/0006" }, { startAfter: "key/0006" }], destConfig: null }), headers: { "content-type": "application/json" } }));
    await co.fetch(new Request("https://runseal.internal/range-done", { method: "POST", body: JSON.stringify({ rangeIndex: 0, shards: [], recordCount: 0, counts: zeroCounts() }), headers: { "content-type": "application/json" } }));
    await co.fetch(new Request("https://runseal.internal/range-done", { method: "POST", body: JSON.stringify({ rangeIndex: 1, shards: [], recordCount: 0, counts: zeroCounts() }), headers: { "content-type": "application/json" } }));
    const afterMerge = instFor(DP_ID).storage.get("doc") as { phase?: string; merge?: unknown } | undefined;
    ok("both ranges done flips the coordinator to phase merge", afterMerge?.phase === "merge");
    const mergeSnapshot = JSON.stringify(afterMerge?.merge);
    const completesBefore = sched.calls.filter((x) => x.path === "/complete").length;

    const failedResp = await co.fetch(new Request("https://runseal.internal/range-failed", { method: "POST", body: JSON.stringify({ reason: "a straggling worker retry" }), headers: { "content-type": "application/json" } }));
    ok("a /range-failed arriving after the merge has started is a no-op (200, ignored)", failedResp.status === 200);
    const afterFailed = instFor(DP_ID).storage.get("doc") as { phase?: string; merge?: unknown } | undefined;
    ok("the coordinator doc SURVIVES (fails pre-fix: cleanup() wipes it)", afterFailed !== undefined);
    ok("the in-progress MERGE state is byte-identical (untouched)", JSON.stringify(afterFailed?.merge) === mergeSnapshot);
    ok("no spurious failed /complete was posted for the already-merging run", sched.calls.filter((x) => x.path === "/complete").length === completesBefore);
  }

  console.log("\na range that finishes one tick before its OWN strike ceiling does not strike out an otherwise-healthy run:");
  {
    // The re-read-and-merge above protects the FINAL PERSIST, but the STRIKE-OUT KILL DECISION a few lines
    // earlier in the same tick used to be evaluated from strikes[] computed off the STALE doc/doneRanges --
    // before that re-read ran. A range that has genuinely made no observable progress for MAX_SLICE_FAILURES-1
    // ticks (an honest straggler; exactly what the ladder exists to tolerate for up to MAX_SLICE_FAILURES
    // ticks) and then finishes-and-self-destructs during THIS tick is indistinguishable, to the stale view,
    // from a real 8th stall: without merging the fresh doneRanges in before strikes.some(...) is evaluated,
    // the coordinator would strike the run out and cleanup() would wipe the completion just honestly recorded
    // -- the same net harm described above, just reached via a straggler instead of a fresh range.
    const dest = new MemDest();
    const sched = makeScheduler();
    const breakGlassB64 = b64urlEncode(concat(breakGlass.entry.pub.x25519, breakGlass.entry.pub.mlkemEk));
    const { env, instances } = makeFleet({ dest, kv: new MemKV(recs, pageSize), sched: sched.stub, signerPrivateB64, breakGlassB64, knobs: { SCALE_FANOUT_RANGES: "3", SCALE_FANOUT_MIN_RECORDS: "1", SCALE_SHARD_MAX_RECORDS: "3", SCALE_SLICE_SUBREQUESTS: "44" } });
    await sealRunSliced(env, dpStateKv(), { runId: RUN_ID, index: 31, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) });
    const coord = instances.get(DP_ID)!;
    ok("the run fanned out to 3 awaited ranges", (coord.storage.get("doc") as { kind?: string; phase?: string } | undefined)?.phase === "await");

    // From now on, range 1's /status always reports gone (as it will be for real once rangeFinalise's
    // resp.ok -> cleanup() runs right after its /range-done below); every other route is unaffected.
    type FakeNS = { idFromName(name: string): { name: string }; get(id: { name: string }): { fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> } };
    const realRunseal = env.RUNSEAL as unknown as FakeNS;
    const gated: FakeNS = {
      idFromName: (name) => realRunseal.idFromName(name),
      get: (id) => {
        if (id.name !== `${DP_ID}#r1`) return realRunseal.get(id);
        return {
          async fetch(input, init) {
            const url = new URL(input instanceof Request ? input.url : String(input));
            if (url.pathname === "/status") return new Response(JSON.stringify({ active: false }));
            return realRunseal.get(id).fetch(input, init);
          },
        };
      },
    };
    env.RUNSEAL = gated as unknown as DurableObjectNamespace;

    // Simulate range 1 having honestly struck MAX_SLICE_FAILURES-1 times already, then snapshot the doc --
    // modelling awaitTick's `doc` parameter as the frozen-in-time read coordinatorAlarm took at the top of
    // THIS tick, before range 1's real completion (below) lands.
    const seeded = coord.storage.get("doc") as CoordinatorDoc;
    seeded.rangeStrikes = (seeded.rangeStrikes ?? seeded.ranges.map(() => 0)).slice();
    seeded.rangeStrikes[1] = MAX_SLICE_FAILURES - 1;
    coord.storage.set("doc", seeded);
    const doc = structuredClone(coord.storage.get("doc")) as CoordinatorDoc;

    // Range 1 finishes and reports for real, straight through the coordinator's own route -- exactly the
    // concurrent worker-initiated call described above (its worker is now "gone" per the gate above).
    const rd = await coord.obj!.fetch(new Request("https://runseal.internal/range-done", { method: "POST", body: JSON.stringify({ rangeIndex: 1, shards: [], recordCount: 0, counts: zeroCounts() }), headers: { "content-type": "application/json" } }));
    ok("range 1's real completion is admitted", rd.status === 200);

    // Run the tick with the STALE doc (doneRanges[1] still null, rangeStrikes[1] === MAX_SLICE_FAILURES - 1):
    // its own poll of range 1 returns null (worker gone), which -- pre-fix -- pushes strikes[1] to
    // MAX_SLICE_FAILURES and strikes the whole run out before the fresh re-read ever runs.
    const internal = coord.obj as unknown as { awaitTick(scheduler: DurableObjectStub, doc: CoordinatorDoc): Promise<void> };
    await internal.awaitTick(sched.stub, doc);

    const finalDoc = coord.storage.get("doc") as { kind?: string; phase?: string; doneRanges?: unknown[] } | undefined;
    ok("the run is NOT struck out (fails pre-fix: the stale view's strikes[1] hits MAX_SLICE_FAILURES and cleanup() wipes the whole coordinator, including range 1's just-recorded completion)", finalDoc?.kind === "coordinator");
    ok("range 1's completion survives", finalDoc?.doneRanges?.[1] != null);
    ok("the coordinator is still awaiting range 0 and 2 (untouched)", finalDoc?.phase === "await" && finalDoc?.doneRanges?.[0] === null && finalDoc?.doneRanges?.[2] === null);
    ok("no spurious failed /complete was posted", sched.calls.filter((x) => x.path === "/complete").length === 0);
  }

  console.log("\nfan-out route guards: malformed bodies are 400; a stale / out-of-bounds /range-done is ignored:");
  {
    const dest = new MemDest();
    const sched = makeScheduler();
    const breakGlassB64 = b64urlEncode(concat(breakGlass.entry.pub.x25519, breakGlass.entry.pub.mlkemEk));
    const { env, instFor } = makeFleet({ dest, kv: new MemKV(recs, pageSize), sched: sched.stub, signerPrivateB64, breakGlassB64 });
    void env;
    const co = instFor(DP_ID).obj!;
    const bad = (path: string): Request => new Request(`https://runseal.internal${path}`, { method: "POST", body: "{not json", headers: { "content-type": "application/json" } });
    ok("/start-fanout rejects a malformed body (400)", (await co.fetch(bad("/start-fanout"))).status === 400);
    ok("/start-range rejects a malformed body (400)", (await co.fetch(bad("/start-range"))).status === 400);
    ok("/range-done rejects a malformed body (400)", (await co.fetch(bad("/range-done"))).status === 400);
    ok("/range-failed rejects a malformed body (400)", (await co.fetch(bad("/range-failed"))).status === 400);
    // /range-done with no coordinator doc present is a stale no-op (ok, ignored).
    const stale = await co.fetch(new Request("https://runseal.internal/range-done", { method: "POST", body: JSON.stringify({ rangeIndex: 0, shards: [], recordCount: 0, counts: zeroCounts() }), headers: { "content-type": "application/json" } }));
    ok("/range-done is a no-op when there is no coordinator doc (stale)", stale.status === 200);
    // /range-failed with no coordinator doc is also a stale no-op.
    ok("/range-failed is a no-op when there is no coordinator doc (stale)", (await co.fetch(new Request("https://runseal.internal/range-failed", { method: "POST", body: JSON.stringify({ reason: "x" }), headers: { "content-type": "application/json" } }))).status === 200);
    // Seed a coordinator doc, then a /range-done with an out-of-bounds rangeIndex is 400.
    await co.fetch(new Request("https://runseal.internal/start-fanout", { method: "POST", body: JSON.stringify({ config: dpStateKv().config, base: { runId: RUN_ID, runlogIndex: 13, prevRunId: null, downpipeId: DP_ID, downpipeName: "fanout", cadence: "3600s", sourceType: "kv", startedAt: "2026-06-10T00:00:00.000Z" }, selector: { include: [], exclude: [] }, wrappedMaster: { iv: "", ct: "" }, ranges: [{ stopAt: "key/0006" }, { startAfter: "key/0006" }], destConfig: null }), headers: { "content-type": "application/json" } }));
    ok("a coordinator doc is seeded with phase await", (instFor(DP_ID).storage.get("doc") as { phase?: string } | undefined)?.phase === "await");
    const oob = await co.fetch(new Request("https://runseal.internal/range-done", { method: "POST", body: JSON.stringify({ rangeIndex: 9, shards: [], recordCount: 0, counts: zeroCounts() }), headers: { "content-type": "application/json" } }));
    ok("/range-done with an out-of-bounds range index is rejected (400)", oob.status === 400);
  }

  console.log("\nbalanced planner: count+stride sizes BALANCED ranges over the WHOLE keyspace, not a front sample:");
  {
    // 60 keys clustered into a dense "aa/" prefix (50) then a sparse "zz/" tail (10). With a tiny front
    // sample the OLD planner sampled only the first few "aa/" keys, so every split landed in the front and the
    // LAST range absorbed the whole tail -- a severe skew (~weeks for 50M). The new count+stride scan sizes 4
    // balanced ranges of ~15 keys instead.
    const skewKeys = [...Array.from({ length: 50 }, (_, i) => `aa/${String(i).padStart(4, "0")}`), ...Array.from({ length: 10 }, (_, i) => `zz/${String(i).padStart(4, "0")}`)];
    const skewRecs = skewKeys.map((name) => ({ name, value: utf8(name) }));
    const sorted = [...skewKeys].sort();
    const sel: Selector = { include: [], exclude: [] };
    const span = (r: FanoutRange): number => sorted.filter((k) => (r.startAfter === undefined || k > r.startAfter) && (r.stopAt === undefined || k <= r.stopAt)).length;
    // The OLD front-sample planner: partition only the first 4 sampled keys -> the last range is the tail.
    const oldRanges = partitionKeyRange(sorted.slice(0, 4), 4);
    const oldMax = Math.max(...oldRanges.map(span));
    ok(`OLD front-sample planner SKEWS: one range holds ${oldMax} of 60 keys (the whole tail)`, oldMax >= 50);
    // The NEW count+stride scan over the WHOLE keyspace.
    const plan = await planByScan(new KVSource(new MemKV(skewRecs, pageSize) as unknown as KVNamespace, "ns1"), sel, 4, FANOUT_MAX_RANGE_KEYS, FANOUT_MAX_RANGES);
    ok("the scan COUNTED all 60 keys (not the 4-key front sample)", plan.total === 60);
    ok("the scan produced 4 balanced ranges", plan.ranges.length === 4 && plan.rangeCount === 4);
    const spans = plan.ranges.map(span);
    const newMax = Math.max(...spans);
    ok(`every balanced range is within tolerance of 60/4=15 (spans ${spans.join(",")}, max ${newMax})`, newMax <= Math.ceil(60 / 4) + 1 && newMax - Math.min(...spans) <= 2);
    ok(`no range holds the lion's share: new max ${newMax} << old max ${oldMax}`, newMax < oldMax && newMax < 20);
    let coveredOnce = true;
    for (const k of sorted) {
      let hits = 0;
      for (const r of plan.ranges) if ((r.startAfter === undefined || k > r.startAfter) && (r.stopAt === undefined || k <= r.stopAt)) hits++;
      if (hits !== 1) coveredOnce = false;
    }
    ok("the balanced ranges still cover every key EXACTLY ONCE (no drop, no overlap)", coveredOnce);
  }

  console.log("\nbalanced planner cap interaction: total/N over the per-range cap splits into MORE ranges, each <= cap:");
  {
    ok("planRangeCount: N ranges when total/N is within the cap", planRangeCount(60, 4, 1000, 512) === 4);
    ok("planRangeCount: floor(total/cap)+1 ranges when total/N exceeds the cap (strict <= cap)", planRangeCount(60, 2, 10, 512) === 7);
    ok("planRangeCount: clamped to maxRanges when the cap would demand more (the documented over-cap residual)", planRangeCount(60, 2, 10, 3) === 3);
    ok("planRangeCount: 1 range for an un-splittable keyspace (<2 keys)", planRangeCount(1, 4, 1000, 512) === 1);
    ok("strideBoundaryIndices: floor(i*total/M)", JSON.stringify(strideBoundaryIndices(60, 4)) === JSON.stringify([15, 30, 45]));
    ok("strideBoundaryIndices: dedupes when M exceeds total", strideBoundaryIndices(4, 8).length < 7);
    ok("strideBoundaryIndices: none for M<2 (the whole keyspace is one range)", strideBoundaryIndices(60, 1).length === 0);
    // End to end: a per-range cap below total/N forces the scan to emit MORE balanced ranges, each <= cap.
    const keys = Array.from({ length: 60 }, (_, i) => ({ name: `k/${String(i).padStart(4, "0")}`, value: utf8(`v${i}`) }));
    const sorted = keys.map((k) => k.name).sort();
    const span = (r: FanoutRange): number => sorted.filter((k) => (r.startAfter === undefined || k > r.startAfter) && (r.stopAt === undefined || k <= r.stopAt)).length;
    const plan = await planByScan(new KVSource(new MemKV(keys, pageSize) as unknown as KVNamespace, "ns1"), { include: [], exclude: [] }, 2, 10, 512); // N=2 but cap=10 over 60 keys
    ok("the cap forced 7 ranges (floor(60/10)+1) instead of N=2", plan.ranges.length === 7 && plan.rangeCount === 7);
    ok("every capped range spans <= 10 keys (no range can reach the watermark-rescan wedge)", Math.max(...plan.ranges.map(span)) <= 10);
  }

  console.log("\nsliced planning resume: the keys-only scan spans >1 invocation and resumes after the last persisted page:");
  {
    const keys = Array.from({ length: 30 }, (_, i) => ({ name: `s/${String(i).padStart(4, "0")}`, value: utf8(`v${i}`) }));
    const src = new KVSource(new MemKV(keys, pageSize) as unknown as KVNamespace, "ns1");
    const sel: Selector = { include: [], exclude: [] };
    const wantAll = keys.map((k) => k.name).sort();
    // Consume the scan in two halves: take 2 pages (a budget yield), save the token, then re-open with the
    // token (a fresh "invocation") and finish. The concatenation must be the whole keyspace exactly once.
    const collected: string[] = [];
    let token: string | null = null;
    let pagesFirst = 0;
    for await (const ev of src.listKeysFrom(sel, token)) {
      collected.push(...ev.keys);
      token = ev.token;
      if (++pagesFirst >= 2) break;
    }
    ok("the first invocation listed a prefix of the keyspace and saved a resume token", collected.length > 0 && collected.length < 30 && token !== null);
    for await (const ev of src.listKeysFrom(sel, token)) collected.push(...ev.keys);
    ok("the resumed scan completes: every key seen EXACTLY once across the two invocations", JSON.stringify(collected) === JSON.stringify(wantAll));
    // A REFUSED resume cursor (KV cursors are opaque + not contractually long-lived) falls back to the
    // watermark scan: re-list from the start, skip whole pages by the `after` watermark, yield only the rest.
    const refusingKv = new (class extends MemKV {
      override async list(o?: { prefix?: string; cursor?: string }): Promise<{ keys: { name: string }[]; list_complete: boolean; cursor?: string; cacheStatus: null }> {
        if (o?.cursor === "STALE") throw new Error("KV refused the opaque cursor");
        return super.list(o);
      }
    })(keys, pageSize);
    const refused: string[] = [];
    for await (const ev of new KVSource(refusingKv as unknown as KVNamespace, "ns1").listKeysFrom(sel, JSON.stringify({ cursor: "STALE", after: "s/0007" }))) refused.push(...ev.keys);
    ok("a refused resume cursor falls back to the watermark scan and yields the rest of the keyspace exactly once", JSON.stringify(refused) === JSON.stringify(wantAll.filter((k) => k > "s/0007")));
    // Drive the COUNT pass exactly as the coordinator does (2 pages per "alarm", persisting scan + token).
    const scan = newPlanScan();
    let tk: string | null = null;
    let alarms = 0;
    for (;;) {
      alarms++;
      let p = 0;
      let last = false;
      let broke = false;
      for await (const ev of src.listKeysFrom(sel, tk)) {
        countPage(scan, ev.keys.length);
        tk = ev.token;
        if (ev.last) {
          last = true;
          broke = true;
          break;
        }
        if (++p >= 2) {
          broke = true;
          break;
        }
      }
      if (last || !broke) break;
    }
    ok(`the COUNT pass resumed across multiple alarms (${alarms}) to the right total (30)`, scan.scanned === 30 && alarms > 1);
  }

  console.log("\nbyte-identity via the BALANCED scan planner: scan-derived ranges seal the IDENTICAL archive as serial:");
  {
    // Plan the 14-key dataset with the SLICED scan (tiny cap forces the scan path), then seal those balanced
    // ranges + merge with the fixed master -- the signed root must be byte-identical to the serial seal.
    const plan = await planByScan(new KVSource(new MemKV(recs, pageSize) as unknown as KVNamespace, "ns1"), { include: [], exclude: [] }, 3, FANOUT_MAX_RANGE_KEYS, FANOUT_MAX_RANGES);
    ok(`the scan planned ${plan.ranges.length} balanced ranges over the 14-key set`, plan.ranges.length >= 2 && plan.total === 14);
    const fan = await sealWithRanges(recs, plan.ranges, 700);
    ok("the scan-planner fan-out MERKLE ROOT is byte-identical to the serial seal", fan.root.merkleRoot === serial.root.merkleRoot);
    ok("the scan-planner fan-out shard list is identical to the serial seal", JSON.stringify(fan.root.shards) === JSON.stringify(serial.root.shards));
    const run = await openRun(new MapStore(fan.dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
    ok("the scan-planner archive opens + restores all 14 records", run.records.length === 14);
  }

  console.log("\nmulti-DO orchestration via the SLICED balanced planner (scan path): plan across alarms -> spawn -> merge -> ok:");
  {
    // 40 keys + SCALE_FANOUT_SAMPLE_CAP=2 so the run takes the SCAN path; a tiny slice budget so the plan SLICES.
    const scanRecs = Array.from({ length: 40 }, (_, i) => ({ name: `key/${String(i).padStart(4, "0")}`, value: utf8(`scan-value-${i}-${"y".repeat(i % 4)}`) }));
    const dest = new MemDest();
    const sched = makeScheduler();
    const breakGlassB64 = b64urlEncode(concat(breakGlass.entry.pub.x25519, breakGlass.entry.pub.mlkemEk));
    const { env, instances } = makeFleet({ dest, kv: new MemKV(scanRecs, pageSize), sched: sched.stub, signerPrivateB64, breakGlassB64, knobs: { SCALE_FANOUT_RANGES: "3", SCALE_FANOUT_MIN_RECORDS: "1", SCALE_FANOUT_SAMPLE_CAP: "2", SCALE_SHARD_MAX_RECORDS: "3", SCALE_SLICE_SUBREQUESTS: "44" } });
    await sealRunSliced(env, dpStateKv(), { runId: RUN_ID, index: 30, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) });
    const coord = instances.get(DP_ID)!;
    ok("the run took the SCAN path (coordinator doc in the PLAN phase, no ranges yet)", (coord.storage.get("doc") as { phase?: string } | undefined)?.phase === "plan");
    // Drive ONLY the coordinator and watch the keys-only plan SLICE (scanned advances while still phase=plan).
    let sawSlicedPlan = false;
    for (let i = 0; i < 12; i++) {
      const d = coord.storage.get("doc") as { kind?: string; phase?: string; planScan?: { scanned: number } } | undefined;
      if (d?.kind === "coordinator" && d.phase === "plan" && (d.planScan?.scanned ?? 0) > 0) sawSlicedPlan = true;
      if (d?.phase !== "plan") break; // plan done (spawned or downgraded)
      await coord.obj!.alarm();
    }
    ok("the keys-only plan SLICED across multiple alarms (scanned advanced while still in the plan phase)", sawSlicedPlan);
    const rounds = await driveFleet(instances, sched.calls);
    const body = sched.calls.find((c) => c.path === "/complete")?.body as { status?: string; recordCount?: number; index?: number } | undefined;
    ok(`the scan-path run posted the ok completion (40 records, ${rounds} more rounds)`, body?.status === "ok" && body?.index === 30 && body?.recordCount === 40);
    ok("the coordinator spawned balanced worker DOs", [0, 1, 2].every((i) => instances.has(`${DP_ID}#r${i}`)));
    const run = await openRun(new MapStore(dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
    ok("the scan-path archive opens + restores all 40 records byte-exact", run.records.length === 40);
    let exact = true;
    for (const rec of run.records) {
      const want = scanRecs.find((x) => x.name === rec.name);
      if (!want || Buffer.compare(Buffer.from(await run.restoreRecord(rec)), Buffer.from(want.value)) !== 0) exact = false;
    }
    ok("every scan-path record restores byte-exact", exact);
  }

  console.log("\nmin-records un-clamp: a SCAN-path run below the now-KNOWN threshold DOWNGRADES to serial:");
  {
    // 14 keys, SAMPLE_CAP=2 (more:true -> SCAN path, where the OLD clamp would have fanned out regardless),
    // but MIN_RECORDS=1000 (> 14). The coordinator counts the REAL 14 keys, sees 14 < 1000, downgrades to serial.
    const dest = new MemDest();
    const sched = makeScheduler();
    const breakGlassB64 = b64urlEncode(concat(breakGlass.entry.pub.x25519, breakGlass.entry.pub.mlkemEk));
    const { env, instances } = makeFleet({ dest, kv: new MemKV(recs, pageSize), sched: sched.stub, signerPrivateB64, breakGlassB64, knobs: { SCALE_FANOUT_RANGES: "4", SCALE_FANOUT_MIN_RECORDS: "1000", SCALE_FANOUT_SAMPLE_CAP: "2", SCALE_SHARD_MAX_RECORDS: "3" } });
    await sealRunSliced(env, dpStateKv(), { runId: RUN_ID, index: 31, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) });
    ok("the run took the SCAN path (more:true bypassed the old front-sample clamp)", (instances.get(DP_ID)?.storage.get("doc") as { phase?: string } | undefined)?.phase === "plan");
    const rounds = await driveFleet(instances, sched.calls);
    const body = sched.calls.find((c) => c.path === "/complete")?.body as { status?: string; recordCount?: number } | undefined;
    ok(`the sub-threshold run DOWNGRADED to serial and completed ok (14 records, ${rounds} rounds)`, body?.status === "ok" && body?.recordCount === 14);
    ok("NO fan-out worker DOs were spawned (it stayed serial, honoring MIN_RECORDS exactly)", !instances.has(`${DP_ID}#r0`));
    const run = await openRun(new MapStore(dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {});
    ok("the downgraded serial archive opens + restores all 14 records", run.records.length === 14);
  }

  master.fill(0);
  console.log(failures === 0 ? "\nFAN-OUT ENGINE PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
