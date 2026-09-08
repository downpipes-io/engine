// Source-side chaos validators.
//
// The chaos network-fault proxy faults DESTINATION writes; this drives the OTHER half -- a fault on a
// SOURCE read -- through a REAL seal run via the fault injector (test/source-fault-injector.ts), and
// asserts the engine's behaviour. The headline question is the "KV cursor-refusal wedge": under a
// refused cursor, does a run WEDGE, LOSE keys, or fail closed? Plus mid-crawl key deletion, a
// throttle/transient that recovers, an R2 etag change, and a D1 page error mid-stream.
//
// The invariant every scenario asserts: a source fault may DELAY or FAIL a run, but must NEVER silently
// lose data or leave a verifiable-but-incomplete archive. A run either completes with EVERY key the
// source enumerated (the archive opens and the Merkle root recomputes), or it fails closed with NO
// signed root (a reader can never mistake the partial bytes for a complete backup).
//
// Run: node test/validate-source-faults.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import type { RecipientEntry, Signer } from "../src/format/writer.ts";
import { runSlice, finaliseRun, coarseRunError, type ShardEntry, type SliceDeps } from "../src/seal/slice.ts";
import { wrapMaster, unwrapMaster, zeroCounts, type RunCheckpoint } from "../src/seal/checkpoint.ts";
import { isIncompleteMarkerValue } from "../src/seal/marker.ts";
import { SliceBudget } from "../src/seal/budget.ts";
import { sealRunSliced, RunSealDO } from "../src/seal/runstate.ts";
import { KVSource } from "../src/sources/kv.ts";
import { R2Source } from "../src/sources/r2.ts";
import { D1Source, D1_PAGE_BYTE_LIMIT } from "../src/sources/d1.ts";
import type { SourceAdapter } from "../src/sources/types.ts";
import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import type { Env } from "../src/env.d.ts";
import type { DownpipeState } from "../src/sched/scheduler-do.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { InjectableKV, InjectableR2, InjectableD1, kvSeeds, type KVSeed } from "./source-fault-injector.ts";

const RUN_ID = "01BX5ZZKBKACTAV9WEVGEMMVRY";
const DP_ID = "dp_srcfault";

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

// ---- destination + store doubles (the same contract validate-slice.ts uses) -------------------------

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
  async putStream(key: string, body: ReadableStream<Uint8Array>, _size?: number): Promise<void> {
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

function hasRoot(dest: MemDest): boolean {
  return [...dest.map.keys()].some((k) => k.endsWith("root.manifest.json"));
}

// ---- DO + scheduler doubles (mirrors validate-slice.ts) ---------------------------------------------

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
        let keys = [...storage.keys()].filter((k) => !opts?.prefix || k.startsWith(opts.prefix)).sort();
        if (opts?.startAfter !== undefined) keys = keys.filter((k) => k > opts.startAfter!);
        const cap = Math.min(opts?.limit ?? 1000, 1000);
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

// ---- signer / recipients (built once in main) -------------------------------------------------------

let signer: Signer;
let signerB64: string;
let verifier: ReturnType<typeof verifierFrom>;
let breakGlass: { entry: RecipientEntry; identity: Uint8Array };
let recipients: RecipientEntry[];

async function freshCheckpoint(sourceType: RunCheckpoint["sourceType"], runlogIndex: number, master: Uint8Array): Promise<RunCheckpoint> {
  return {
    v: 1,
    downpipeId: DP_ID,
    downpipeName: "srcfault",
    cadence: "3600s",
    sourceType,
    selector: { include: [], exclude: [] },
    runId: RUN_ID,
    runlogIndex,
    prevRunId: null,
    startedAt: "2026-06-30T00:00:00.000Z",
    wrappedMaster: await wrapMaster(signerB64, RUN_ID, master),
    cursor: null,
    sourceDone: false,
    nextRecordIndex: 0,
    nextShardIndex: 0,
    frontier: { count: 0, nodes: [] },
    counts: zeroCounts(),
    sliceCount: 0,
    partialRecord: null,
  };
}

// driveSlicesToDone runs a real multi-slice seal with EVICTION between every slice (only the serialised
// checkpoint survives, exactly as the DO persists it), carrying the open-shard buffer forward, until the
// source is exhausted. beforeSlice runs before each slice (used to expire cursors on a resume). It does
// NOT catch -- a scenario that expects a throw drives runSlice directly.
async function driveSlicesToDone(
  makeSource: () => SourceAdapter,
  dest: MemDest,
  cp0: RunCheckpoint,
  budgetOpts: { subrequests: number; wallMs: number },
  beforeSlice?: (cp: RunCheckpoint) => void,
  cap = 300,
): Promise<{ cp: RunCheckpoint; allShards: ShardEntry[]; openBuffer: Record<string, unknown>[]; slices: number }> {
  let cp = cp0;
  const allShards: ShardEntry[] = [];
  let openBuffer: Record<string, unknown>[] = [];
  let slices = 0;
  for (; slices < cap && !cp.sourceDone; slices++) {
    beforeSlice?.(cp);
    cp = JSON.parse(JSON.stringify(cp)) as RunCheckpoint;
    const m = await unwrapMaster(signerB64, RUN_ID, cp.wrappedMaster);
    const deps: SliceDeps = { source: makeSource(), dest, signer, recipients, budget: new SliceBudget(budgetOpts) };
    const r = await runSlice(deps, cp, m, openBuffer);
    m.fill(0);
    cp = r.checkpoint;
    allShards.push(...r.newShards);
    openBuffer = r.openReset ? r.openWrite : [...openBuffer, ...r.openWrite];
  }
  return { cp, allShards, openBuffer, slices };
}

async function finalise(makeSource: () => SourceAdapter, dest: MemDest, cp: RunCheckpoint, allShards: ShardEntry[], openBuffer: Record<string, unknown>[]): Promise<void> {
  const m = await unwrapMaster(signerB64, RUN_ID, cp.wrappedMaster);
  await finaliseRun({ source: makeSource(), dest, signer, recipients, budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) }, cp, m, allShards, openBuffer);
  m.fill(0);
}

async function openArchive(dest: MemDest): Promise<{ records: { name: string }[]; restoreRecord(r: { name: string }): Promise<Uint8Array> }> {
  return openRun(new MapStore(dest.map), RUN_ID, parseIdentity(breakGlass.identity), verifier, {}) as unknown as { records: { name: string }[]; restoreRecord(r: { name: string }): Promise<Uint8Array> };
}

// ---- env / dpState for the REAL inline + DO drivers (mirrors validate-slice.ts) ----------------------

function mkEnv(kv: unknown, sched: DurableObjectStub, runseal: DurableObjectStub, dest: MemDest): Env {
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
    async list(opts?: { prefix?: string }): Promise<unknown> {
      const keys = await dest.list(opts?.prefix ?? "");
      return { objects: keys.map((key) => ({ key })), truncated: false };
    },
  };
  const breakGlassB64 = b64urlEncode(concat(breakGlass.entry.pub.x25519, breakGlass.entry.pub.mlkemEk));
  return {
    SCHEDULER: nsFor(sched),
    RUNSEAL: nsFor(runseal),
    SIGNER_PRIVATE: signerB64,
    BREAK_GLASS_PUBLIC: breakGlassB64,
    DEST_KIND: "r2",
    DEST_R2: r2Facade,
    KV_TEST: kv,
    DEST_THROTTLE_BASE_MS: "1",
  } as unknown as Env;
}

function dpState(id: string): DownpipeState {
  return {
    config: { id, name: id, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_TEST", namespaceId: "ns1", include: [], exclude: [] } },
    nextRunAt: 0,
    lastRunId: null,
    inFlight: true,
    inFlightSince: Date.now(),
  } as DownpipeState;
}

// captureErrors swaps console.error for the duration of fn, returning the lines logged (so a scenario can
// assert a redacted slice-failure strike happened) without spamming the validator output.
async function captureErrors(fn: () => Promise<void>): Promise<string[]> {
  const logged: string[] = [];
  const orig = console.error;
  console.error = (...a: unknown[]) => {
    logged.push(a.map(String).join(" "));
  };
  try {
    await fn();
  } finally {
    console.error = orig;
  }
  return logged;
}

// ---- scenarios --------------------------------------------------------------------------------------

// A: a STALE resume cursor (the realistic case: a cursor expired between slices) falls back to the
// watermark re-scan and the run completes with EVERY key, none lost, none re-read. REFUTES "cursor
// refusal loses keys" for the resume path.
async function scenarioStaleCursorFallback(): Promise<void> {
  console.log("\nA) KV stale resume-cursor -> watermark fallback -> COMPLETE, no key lost, no re-read:");
  const N = 40;
  const seeds = kvSeeds(N);
  const kv = new InjectableKV(seeds, { pageSize: 10, cursorMode: "epoch" });
  const dest = new MemDest();
  const master = rand(32);
  const cp0 = await freshCheckpoint("kv", 1, master);
  master.fill(0);
  const makeSource = (): SourceAdapter => new KVSource(kv as unknown as KVNamespace, "ns1");
  // Expire the resume cursor before EVERY resume slice, so every resume must take the fallback. The
  // budget (just above the FINALISE_RESERVE of 40, well under the ~44 the whole crawl needs) forces the
  // run to span several slices, so the stale-cursor fallback is exercised on every one.
  const driven = await driveSlicesToDone(makeSource, dest, cp0, { subrequests: 52, wallMs: 60_000 }, (cp) => {
    if (cp.cursor !== null) kv.invalidateCursors();
  });
  ok(`the run spanned multiple slices, every resume hitting the fallback (took ${driven.slices})`, driven.slices > 2 && driven.cp.sourceDone);
  await finalise(makeSource, dest, driven.cp, driven.allShards, driven.openBuffer);
  const run = await openArchive(dest);
  ok("the archive opens (signature, shard hashes, Merkle root) despite every cursor being refused", true);
  ok(`every key is present: ${run.records.length} === ${N} (no loss, no duplication)`, run.records.length === N);
  ok("every record name is unique", new Set(run.records.map((r) => r.name)).size === N);
  // The watermark skips already-yielded keys, so a value is read EXACTLY once even across the fallback.
  ok(`each value was read exactly once (kv.gets ${kv.gets} === ${N}; the fallback re-LISTS, never re-GETS)`, kv.gets === N);
  ok(`the fallback added list calls (kv.lists ${kv.lists} > slices ${driven.slices})`, kv.lists > driven.slices);
  // Spot-check bytes round-trip across the fallback boundaries.
  let exact = true;
  for (let i = 0; i < N; i += 7) {
    const rec = run.records.find((r) => r.name === seeds[i]!.name);
    if (!rec) { exact = false; continue; }
    const got = await run.restoreRecord(rec);
    if (Buffer.compare(Buffer.from(got), Buffer.from(seeds[i]!.value)) !== 0) exact = false;
  }
  ok("sampled values restore byte-exact across the fallback boundaries", exact);
}

// B: a DETERMINISTIC forward-cursor refusal (a re-list cannot escape it) does NOT wedge forever and does
// NOT silently complete: the run fails CLOSED. Driven through the REAL RunSealDO strike ladder.
async function scenarioDeterministicRefusalFailsClosed(): Promise<void> {
  console.log("\nB) KV deterministic forward-cursor refusal -> bounded strikes -> FAILED, no root (no wedge, no loss):");
  const seeds = kvSeeds(30);
  const kv = new InjectableKV(seeds, { pageSize: 10, cursorMode: "refuse-all" });
  const sched = makeScheduler();
  const doState = makeDOState();
  const dest = new MemDest();
  let realDO: RunSealDO | null = null;
  const runsealStub = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init));
    },
  } as unknown as DurableObjectStub;
  const env = mkEnv(kv, sched.stub, runsealStub, dest);
  (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "120";
  realDO = new RunSealDO(doState.state, env);

  let alarmsRun = 0;
  const logged = await captureErrors(async () => {
    // A small inline budget forces a handoff within page 0 (before the refused forward list), so the DO
    // resume path -- where the cursor is actually refused -- is what is under test.
    await sealRunSliced(env, dpState("dp-refuse"), { runId: RUN_ID, index: 13, prevRunId: null }, { budget: new SliceBudget({ subrequests: 5, wallMs: 60_000 }) });
    ok("B: the inline slice handed the run off to the seal DO", doState.storage.has("doc"));
    for (; alarmsRun < 20 && doState.storage.has("doc"); alarmsRun++) await realDO.alarm();
  });
  ok(`B: the run resolved within the strike cap, never wedging (took ${alarmsRun} alarms, cap 8)`, !doState.storage.has("doc") && alarmsRun >= 8 && alarmsRun <= 12);
  const complete = sched.calls.find((c) => c.path === "/complete");
  const body = complete?.body as { status?: string; runId?: string; error?: string } | undefined;
  ok("B: a FAILED completion was posted with the empty runId (fail-closed, no green)", body?.status === "failed" && body?.runId === "");
  // A raw KV cursor refusal carries no recognised token, so coarseRunError yields the generic class --
  // the operator gets no actionable "the source cursor was refused" hint.
  ok("B: the failure classifies as the generic 'run failed' (a cursor refusal is NOT specifically named)", body?.error === "run failed");
  // THE DATA-LOSS INVARIANT: no signed root was written, so the partial bytes can never be read back as a
  // complete archive. Fail-closed, not verifiable-but-incomplete.
  ok("B: NO signed root was written (the partial run is not a verifiable archive)", !hasRoot(dest));
  ok("B: the strike logs stay redacted (no raw binding/cursor leak via Logpush)", logged.length > 0 && logged.every((l) => !l.includes("KV_TEST")));
}

// C: a key DELETED between the list and the get is skipped (SPEC 12.5) and the archive of the SURVIVORS
// is intact and verifiable. No corruption of the Merkle root, no torn record.
async function scenarioMidCrawlDeletion(): Promise<void> {
  console.log("\nC) KV key deleted between list and get -> skipped, archive of survivors intact + verifiable:");
  const N = 12;
  const seeds = kvSeeds(N);
  const gone = seeds[5]!.name;
  const kv = new InjectableKV(seeds, { pageSize: 100, vanishOnGet: [gone] });
  const dest = new MemDest();
  const master = rand(32);
  const cp0 = await freshCheckpoint("kv", 2, master);
  master.fill(0);
  const makeSource = (): SourceAdapter => new KVSource(kv as unknown as KVNamespace, "ns1");
  const driven = await driveSlicesToDone(makeSource, dest, cp0, { subrequests: 200, wallMs: 60_000 });
  ok("C: the run completed in one pass", driven.cp.sourceDone);
  await finalise(makeSource, dest, driven.cp, driven.allShards, driven.openBuffer);
  const run = await openArchive(dest);
  // A mid-crawl-vanished key seals an honest _vanished MARKER record in its place,
  // so the archive carries N records (the N-1 survivors + one sentinel NAMED after the vanished key). The
  // sentinel is a tiny JSON marker, NOT the deleted object's real bytes, and the RESTORE side skips it
  // (isMarkerValue), so a restore never re-creates the deleted key with sentinel content.
  ok(`C: the archive carries N records: N-1 survivors + 1 _vanished sentinel (${run.records.length} === ${N})`, run.records.length === N);
  const goneRec = run.records.find((r) => r.name === gone);
  ok("C: the vanished key is present as a record NAMED after it (the honest per-object sentinel)", goneRec !== undefined);
  ok("C: that record's value is a _vanished MARKER (isMarkerValue), not the deleted object's real bytes", goneRec !== undefined && isIncompleteMarkerValue(await run.restoreRecord(goneRec)));
  ok("C: every surviving key IS in the archive", seeds.filter((s) => s.name !== gone).every((s) => run.records.some((r) => r.name === s.name)));
  ok("C: the archive opens and the Merkle root recomputes (no corruption from the sentinel)", true);
  ok(`C: all ${N} keys were attempted (kv.gets ${kv.gets} === ${N}); the vanished one returned null`, kv.gets === N);
  // The vanished key seals a _vanished marker, so it counts BOTH as an incompleteness marker
  // (recordsIncomplete + incompleteByMarker._vanished) AND as the distinct mid-crawl-deletion signal
  // (recordsVanished) -- exactly once each (the marker is a real record sealed once; no double-count).
  ok("C: recordsIncomplete === 1 (the _vanished sentinel sealed as an incompleteness marker)", driven.cp.counts.recordsIncomplete === 1);
  ok("C: incompleteByMarker._vanished === 1 (the per-kind breakdown names the vanish kind)", driven.cp.counts.incompleteByMarker._vanished === 1);
  ok("C: recordsVanished === 1 (the mid-crawl deletion is COUNTED distinctly, exactly once, no double-count)", driven.cp.counts.recordsVanished === 1);
}

// D: a TRANSIENT source error (a one-shot list throw, e.g. a 5xx blip) is recovered by the DO's
// slice-level retry from the last checkpoint, and the run completes with every key. Back off and
// complete, NOT wedge.
async function scenarioTransientRecovers(): Promise<void> {
  console.log("\nD) transient source-read fault -> DO slice retry recovers -> COMPLETE with every key:");
  const N = 30;
  const seeds = kvSeeds(N);
  const kv = new InjectableKV(seeds, { pageSize: 10, cursorMode: "ok" });
  const sched = makeScheduler();
  const doState = makeDOState();
  const dest = new MemDest();
  let realDO: RunSealDO | null = null;
  const runsealStub = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init));
    },
  } as unknown as DurableObjectStub;
  const env = mkEnv(kv, sched.stub, runsealStub, dest);
  (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "120";
  realDO = new RunSealDO(doState.state, env);

  let alarmsRun = 0;
  const logged = await captureErrors(async () => {
    await sealRunSliced(env, dpState("dp-transient"), { runId: RUN_ID, index: 14, prevRunId: null }, { budget: new SliceBudget({ subrequests: 5, wallMs: 60_000 }) });
    ok("D: the run handed off to the seal DO", doState.storage.has("doc"));
    // Arm a ONE-SHOT transient read fault on the next CRAWL list (not the liveness probe). The first DO
    // alarm strikes once; the retry, from the same checkpoint, recovers.
    kv.armListFault("KV list failed: status 500 transient backend error", false);
    for (; alarmsRun < 30 && doState.storage.has("doc"); alarmsRun++) await realDO.alarm();
  });
  ok("D: a hard-fault strike WAS logged (the transient really fired), redacted", logged.some((l) => /\[cause [0-9a-f]{12}\]/.test(l)));
  ok("D: the run recovered and completed (it did NOT fail or wedge)", !doState.storage.has("doc"));
  const complete = sched.calls.find((c) => c.path === "/complete");
  const body = complete?.body as { status?: string; recordCount?: number } | undefined;
  ok("D: the completion is OK at the full record count (every key captured after recovery)", body?.status === "ok" && body?.recordCount === N);
  const run = await openArchive(dest);
  ok(`D: the recovered archive opens with all ${N} keys`, run.records.length === N);
}

// E: an R2 object CHANGED behind its etag pin mid-crawl is skipped cleanly (recordsSkippedChanged), the
// other objects seal, and the archive is verifiable. The etag pin never seals bytes that disagree with
// the recorded address.
async function scenarioR2EtagChange(): Promise<void> {
  console.log("\nE) R2 object changed behind its etag pin mid-crawl -> clean skip, survivors sealed + verifiable:");
  const small = (k: string, n: number): KVSeed => ({ name: k, value: utf8(`r2-${k}-${"y".repeat(n)}`) });
  const entries = [
    { key: "obj/a", body: small("a", 3).value },
    { key: "obj/big", body: utf8("Z".repeat(200)) }, // > streamThreshold -> the streamed (etag-pinned) path
    { key: "obj/c", body: small("c", 4).value },
  ];
  const r2 = new InjectableR2(entries, { pageSize: 100, etagChangeOnGet: ["obj/big"] });
  const dest = new MemDest();
  const master = rand(32);
  const cp0 = await freshCheckpoint("r2", 3, master);
  master.fill(0);
  // streamThreshold 32 makes obj/big (200 B) take the streamed path without a multi-MiB fixture.
  const makeSource = (): SourceAdapter => new R2Source(r2 as unknown as R2Bucket, "bkt", { streamThreshold: 32 });
  const driven = await driveSlicesToDone(makeSource, dest, cp0, { subrequests: 200, wallMs: 60_000 });
  ok("E: the run completed in one pass", driven.cp.sourceDone);
  await finalise(makeSource, dest, driven.cp, driven.allShards, driven.openBuffer);
  const run = await openArchive(dest);
  ok("E: the changed object was counted as a clean changed-mid-crawl skip", driven.cp.counts.recordsSkippedChanged === 1);
  ok("E: the changed object is ABSENT from the archive (never sealed corrupt)", !run.records.some((r) => r.name === "obj/big"));
  ok("E: the two unchanged objects sealed and the archive opens", run.records.length === 2 && run.records.every((r) => r.name === "obj/a" || r.name === "obj/c"));
}

// F: a D1 row page that errors MID-STREAM fails the slice closed (no root). D1 is resumable, but a
// deterministic page error re-throws on every resume, so it strikes out rather than wedging or
// half-writing a verifiable archive.
async function scenarioD1PageErrorFailsClosed(): Promise<void> {
  console.log("\nF) D1 row page errors mid-stream -> slice fails closed, classified, no root:");
  const rows = Array.from({ length: 6 }, (_, i) => [i + 1, `row-${i}`]);
  const db = new InjectableD1([{ name: "t", sql: 'CREATE TABLE "t" (id INTEGER PRIMARY KEY, v TEXT)', columns: ["id", "v"], rows }]);
  db.armKeysetFault(2); // the 2nd keyset page throws mid-stream
  const dest = new MemDest();
  const master = rand(32);
  const cp0 = await freshCheckpoint("d1", 4, master);
  const makeSource = (): SourceAdapter => new D1Source(db as unknown as D1Database, "faultdb", D1_PAGE_BYTE_LIMIT, 2);
  let threw: Error | null = null;
  try {
    const m = await unwrapMaster(signerB64, RUN_ID, cp0.wrappedMaster);
    await runSlice({ source: makeSource(), dest, signer, recipients, budget: new SliceBudget({ subrequests: 200, wallMs: 60_000 }) }, cp0, m);
    m.fill(0);
  } catch (e) {
    threw = e as Error;
  }
  master.fill(0);
  ok("F: the slice threw on the mid-stream page error (no silent truncation)", threw !== null);
  ok("F: the fault classifies as a source read error (D1_ has a named branch)", threw !== null && coarseRunError(threw.message) === "source read error");
  ok("F: NO signed root was written (fail-closed, the DO would strike this out to FAILED)", !hasRoot(dest));
  ok("F: at least the header + first page sealed durably before the error (content-addressed, orphaned without a root)", dest.map.size > 0);
}

// H: the D1 native database UUID (the `database` identity annotation) must survive a REAL multi-slice resume
// -- it rides on every record through eviction + resume + finalise into the signed manifest, not just on the
// record NAME. Guards the sliced-path/partial-match identity carry for a completing (not fail-closed) run.
async function scenarioD1IdentitySurvivesResume(): Promise<void> {
  console.log("\nH) D1 database UUID (identity annotation) survives a real multi-slice resume:");
  const rows = Array.from({ length: 8 }, (_, i) => [i + 1, `row-${i}`]);
  const db = new InjectableD1([{ name: "t", sql: 'CREATE TABLE "t" (id INTEGER PRIMARY KEY, v TEXT)', columns: ["id", "v"], rows }]);
  const dest = new MemDest();
  const master = rand(32);
  const cp0 = await freshCheckpoint("d1", 6, master);
  master.fill(0);
  const DBID = "db-uuid-resume-9f8e7d6c";
  // rowsPerPage 2 (8 rows -> multiple pages) + a tiny per-slice budget -> the crawl checkpoints + resumes.
  const makeSource = (): SourceAdapter => new D1Source(db as unknown as D1Database, "resumedb", D1_PAGE_BYTE_LIMIT, 2, DBID);
  const driven = await driveSlicesToDone(makeSource, dest, cp0, { subrequests: 3, wallMs: 60_000 });
  await finalise(makeSource, dest, driven.cp, driven.allShards, driven.openBuffer);
  const arch = await openArchive(dest);
  const d1recs = arch.records.filter((r) => (r as { sourceType?: string }).sourceType === "d1");
  ok("H: the run actually spanned multiple slices (a real resume, not one shot)", driven.slices > 1);
  ok("H: at least the header + a row page + schema sealed", d1recs.length >= 3);
  ok("H: EVERY D1 record carries the native database UUID across the resume (identity annotation preserved)", d1recs.length > 0 && d1recs.every((r) => (r as { database?: string }).database === DBID));
}

// G: pin how coarseRunError classifies representative SOURCE-side read faults. Deterministic, no platform
// dependency. A KV/R2 binding read throttle/5xx is named a SOURCE read.
function scenarioClassificationPins(): void {
  console.log("\nG) classification of source-read faults (a KV/R2 status fault is a SOURCE read, not a destination):");
  // A KV/R2 binding read throttle/5xx whose message carries 'status NNN' is caught by a source-side
  // branch BEFORE the destination catch-all, so a SOURCE outage is attributed to the SOURCE (the right
  // system) instead of the destination. (The DO's throttle ROUTING keys off its own 503/429 regex and
  // parks correctly; this is only the final coarse LABEL on a struck-out run.)
  ok("G: a KV list throttle ('status 429') is classified as 'source read error'", coarseRunError("KV list failed: status 429") === "source read error");
  ok("G: a KV get 5xx ('status 500') is classified as 'source read error'", coarseRunError("KV GET key/0001: status 500") === "source read error");
  ok("G: an R2 list throttle ('status 503') is classified as 'source read error'", coarseRunError("R2 list: status 503 SlowDown") === "source read error");
  // A source status fault must not be attributed to the destination.
  ok("G: a KV get 5xx no longer classifies as 'destination access error'", coarseRunError("KV GET key/0001: status 500") !== "destination access error");
  // D1 read faults are named by the D1_-prefixed branch.
  ok("G: a D1 read error is named 'source read error' (the D1_ branch wins)", coarseRunError("D1_ERROR: read failed: status 500") === "source read error");
  // The DESTINATION path is UNDISTURBED: a real destination WRITE fault ('PUT seg/... status NNN', a bare
  // verb with no KV/R2 token) still maps to the destination class; the source branch must not eat it.
  ok("G: a destination write 'status 400' still classifies as 'destination access error' (dest path undisturbed)", coarseRunError("PUT seg/x: status 400") === "destination access error");
  ok("G: a destination write with an S3 code still surfaces the code (dest path undisturbed)", coarseRunError("PUT seg/0001: status 403 (AccessDenied)") === "destination rejected the write (AccessDenied)");
  // A destination READ/LIST fault ('GET/LIST <key>: status NNN', also no KV/R2 token) stays destination.
  ok("G: a destination LIST 'status 503' stays 'destination access error' (bare verb, no KV/R2 token)", coarseRunError("LIST _RECOVERY/: status 503") === "destination access error");
  // A bare cursor refusal / not-found (no KV/R2 token, no status) still falls through to the generic class.
  ok("G: a KV cursor refusal falls through to the generic 'run failed'", coarseRunError("cursor: invalid or expired") === "run failed");
}

// H: a source that UNDER-REPORTS yet claims its listing is complete. The engine seals exactly what the
// source enumerated and the archive is fully verifiable over THAT set. The completeness guarantee is, by
// construction, relative to the source's own enumeration (KV/R2 give no independent count oracle): this
// is the honest residual, not an engine integrity failure.
async function scenarioSourceUnderReports(): Promise<void> {
  console.log("\nH) source under-reports + claims complete -> engine seals exactly that, fully verifiable (honest residual):");
  const N = 20;
  const seeds = kvSeeds(N);
  const kv = new InjectableKV(seeds, { pageSize: 10, truncateAndClaimCompleteAfter: 10 });
  const dest = new MemDest();
  const master = rand(32);
  const cp0 = await freshCheckpoint("kv", 5, master);
  master.fill(0);
  const makeSource = (): SourceAdapter => new KVSource(kv as unknown as KVNamespace, "ns1");
  const driven = await driveSlicesToDone(makeSource, dest, cp0, { subrequests: 200, wallMs: 60_000 });
  await finalise(makeSource, dest, driven.cp, driven.allShards, driven.openBuffer);
  const run = await openArchive(dest);
  ok("H: the archive is fully verifiable (it opens, the Merkle root recomputes)", true);
  ok(`H: it contains exactly the keys the source enumerated (${run.records.length}), NOT a torn subset`, run.records.length === 10);
  ok("H: the run reported done without error (a lying list_complete is undetectable at this layer -- residual)", driven.cp.sourceDone && driven.cp.counts.recordsIncomplete === 0);
}

async function main(): Promise<void> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  signerB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  signer = await loadSigner(signerB64);
  verifier = verifierFrom(signer);
  breakGlass = makeRecipient("break-glass");
  recipients = [breakGlass.entry];

  await scenarioStaleCursorFallback();
  await scenarioDeterministicRefusalFailsClosed();
  await scenarioMidCrawlDeletion();
  await scenarioTransientRecovers();
  await scenarioR2EtagChange();
  await scenarioD1PageErrorFailsClosed();
  await scenarioD1IdentitySurvivesResume();
  scenarioClassificationPins();
  await scenarioSourceUnderReports();

  console.log(failures === 0 ? "\nSOURCE FAULT CHAOS VALIDATORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
