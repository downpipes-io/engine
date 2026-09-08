// validate-deploy-rollback (DEP): chaos validators for the DEPLOY / ROLLBACK / MIGRATION class, an
// un-run failure mode for the backup engine. The invariant under any deploy, rollback or migration:
// NEVER lose data, NEVER corrupt or mis-read an archive, NEVER silently stop backups without a
// detectable signal, and a rollback must leave already-sealed runs READABLE + recoverable (or fail
// LOUD, never mis-read). Each scenario drives the REAL DOs / seal / version state over in-memory
// doubles (no network, no deploy) and asserts the invariant, either confirming the engine holds or
// surfacing a concrete finding.
//
//   DEP-01 redeploy-mid-run resume: an in-flight run with a persisted checkpoint is resumed by a FRESH
//          RunSealDO instance over the SAME durable storage (a "redeploy": new isolate, same persisted
//          DO state). It must finish byte-correct from the checkpoint alone; a CORRUPTED checkpoint
//          must fail CLOSED (the run resolves failed, never seals a mis-read archive).
//   DEP-02 schema-ahead-of-code: a persisted checkpoint at a NEWER version than the running code expects
//          (a rollback reading a migrated store). The pure guard rejects it, and the RunSealDO degrades
//          GRACEFULLY (strike ladder -> failed completion), never a crash or a silent mis-read. (The
//          config-side dp:<id> guard is owned by validate-config-schema-version; cited, not re-proven.)
//   DEP-03 rollback-precedes-format-bump: a run sealed under a NEWER archive formatVersion read by OLDER
//          code. Both readers (keyed openRun + keyless attestKeyless) reject it LOUD ("not implemented by
//          this reader"), never mis-parse; a newer PATCH is accepted (the archive stays readable
//          across a patch bump); the archive bytes are untouched, so a correct-version reader recovers.
//   DEP-04 cron-removed dead-man: whether ANY staleness/dead-man signal survives the cron being removed.
//          FINDING: the staleness detector runs ONLY inside the cron-driven pass; the timer that
//          survives cron removal (the DO alarm) does NOT run it -> silent-stop-no-alert is CONFIRMED for
//          the cron-removed case. (Refuted for a per-downpipe stop while the fleet cron still fires.)
//   DEP-05 duplicate-cron double-drive: two triggers for the same downpipe close together. The in-flight
//          lease serialises them (the second coalesces), so no duplicate RUNLOG index and no second run
//          (hence no double archive); a duplicate completion is idempotent.
//   DEP-06 partial-deploy version skew: the cleanly-reachable subset -- the forward/backward-compatible
//          checkpoint field defaults that let a checkpoint cross a deploy in either direction, plus the
//          version gate that rejects an incompatible skew. A true mixed-binary run is out of this layer
//          (one compiled codebase); documented.
//
// Run: node test/validate-deploy-rollback.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { openRun, attestKeyless, type ObjectStore, type KeylessAttestation } from "../src/format/reader.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { hybridSign } from "../src/crypto/sign.ts";
import { canonicalJSON } from "../src/format/canonjson.ts";
import { integrityCategoryOf } from "../src/format/integrity-error.ts";
import { checkFormatVersion } from "../src/format/structural-gates.ts";
import type { RootManifest } from "../src/format/manifest.ts";
import type { RecipientEntry, Signer } from "../src/format/writer.ts";
import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import type { Env } from "../src/env.d.ts";
import type { DownpipeState } from "../src/sched/scheduler-do.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { sealRunSliced, RunSealDO } from "../src/seal/runstate.ts";
import { SliceBudget } from "../src/seal/budget.ts";
import { MAX_SLICE_FAILURES } from "../src/seal/runstate-helpers.ts";
import { type RunCheckpoint, validateCheckpoint, openStoredCheckpoint } from "../src/seal/checkpoint.ts";
import type { SchedulerDOSurface } from "../src/sched/scheduler-do-base.ts";
import { ALERT_COOLDOWN_PREFIX } from "../src/sched/scheduler-do-records.ts";
import { CRON_ALERT_SWEEP_AT_KEY, CRON_DEADMAN_STALL_MS } from "../src/sched/scheduler-do-limits.ts";
import { NOTIFY_CHANNEL_PREFIX } from "../src/notify.ts";
import { ALERTING_HEALTH_KEY } from "../src/sched/sched-fault-ledger.ts";
// DEP-04 drives the SchedulerDO's staleness detector + alarm; DEP-05 drives its scheduling state machine.
// The two suites use different storage doubles (the scheduler-shared mock implements getAlarm, which
// completeRun needs); import each makeScheduler/makeConfig under an alias.
import { makeScheduler as makeNotifyDO, makeConfig as makeNotifyConfig, staleStart, STALE_THRESHOLD_MS } from "./validate-notify-shared.ts";
import { makeScheduler as makeSchedDO, makeConfig as makeSchedConfig } from "./validate-scheduler-shared.ts";

const RUN_ID = "01BX5ZZKBKACTAV9WEVGEMMVRY";
const DP_ID = "dp_dep";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// surf casts a real DO to its public testable surface so the production methods are driven directly,
// the same seam validate-config-schema-version uses.
const surf = (dobj: unknown): SchedulerDOSurface => dobj as unknown as SchedulerDOSurface;

// installFetchMock swaps the global fetch for a capturing double so the DEP-04 alarm backstop is proven
// NETWORK-FREE: the env-free DO reaches no channel adapter, so it must make no outbound call at all.
// Restore in a finally so the swap never leaks past the case that installs it.
function installFetchMock(): { captured: Array<{ url: string }>; restore: () => void } {
  const captured: Array<{ url: string }> = [];
  const original = globalThis.fetch;
  (globalThis as { fetch: unknown }).fetch = async (url: unknown): Promise<unknown> => {
    captured.push({ url: String(url) });
    return { ok: true, status: 200, body: null };
  };
  return { captured, restore: () => { (globalThis as { fetch: unknown }).fetch = original; } };
}

// health reads one counter off the alerting-health ledger: the backstop's only observable output.
function health(storage: { rawGet<T>(k: string): T | undefined }, event: string): number {
  const agg = storage.rawGet<Record<string, { count: number; lastAt: string }>>(ALERTING_HEALTH_KEY);
  return agg?.[event]?.count ?? 0;
}

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// smallValue mints a tiny, distinct, varied-length record value (no large allocations: the harness keeps
// only synthetic state). Distinct bytes per index make a mis-ordered or duplicated record detectable.
function smallValue(i: number): Uint8Array {
  const n = 24 + ((i * 31) % 200);
  const b = new Uint8Array(n);
  for (let j = 0; j < n; j++) b[j] = (Math.imul(i + 1, 2654435761) >>> (j % 24)) & 0xff;
  return b;
}

// ---- doubles ---------------------------------------------------------------

// MemDest: the full Destination contract over a map (etagged, conditional), the same shape the slice
// validator uses. The map IS the archive; a reader opens it via MapStore.
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

// MemKV: a paginated KV namespace double with real cursor semantics (epoch-stamped opaque tokens).
class MemKV {
  private seeds: { name: string; value: Uint8Array }[];
  private pageSize: number;
  private epoch = 0;
  gets = 0;
  constructor(seeds: { name: string; value: Uint8Array }[], pageSize: number) {
    this.seeds = [...seeds].sort((a, b) => (a.name < b.name ? -1 : 1));
    this.pageSize = pageSize;
  }
  async list(options?: { prefix?: string; cursor?: string }): Promise<{ keys: { name: string }[]; list_complete: boolean; cursor?: string; cacheStatus: null }> {
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

// MapStore is an ObjectStore over a key->bytes map, so the TS reader opens the archive MemDest accreted.
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

// makeDOState is a Map-backed DurableObjectState double with alarm capture. The RunSealDO keeps NO
// in-memory run state, so a fresh RunSealDO over the SAME storage Map is exactly a redeploy/eviction.
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

// localScheduler is the seal DO's view of the scheduler: it heartbeats (ownership scriptable), reports no
// runlog lock (so finalise takes the lock-free CAS path) and captures /complete so a test reads the outcome.
function localScheduler(): { stub: DurableObjectStub; calls: { path: string; body?: unknown }[]; setOwned(v: boolean): void } {
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

function nsFor(stub: DurableObjectStub): DurableObjectNamespace {
  return {
    idFromName: (_n: string) => ({}) as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
}

// mkEnv assembles the seal Worker env: an R2Bucket facade over MemDest, the KV binding, the signer and the
// break-glass recipient, plus tight slice/shard budgets so a small run still HANDS OFF and spans many alarms.
function mkEnv(signerPrivateB64: string, breakGlassB64: string, kv: MemKV, sched: DurableObjectStub, runseal: DurableObjectStub, dest: MemDest): Env {
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
    SCALE_SLICE_SUBREQUESTS: "150",
    SCALE_SHARD_MAX_RECORDS: "200",
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

// HandoffRun is a run that has been handed off to a seal DO mid-flight: the durable storage Map holds the
// persisted checkpoint doc, and a factory mints a FRESH RunSealDO over that SAME storage (a "redeploy").
interface HandoffRun {
  doState: ReturnType<typeof makeDOState>;
  dest: MemDest;
  kv: MemKV;
  sched: ReturnType<typeof localScheduler>;
  seeds: { name: string; value: Uint8Array }[];
  freshDO: () => RunSealDO;
}

// startHandoff seals the inline first slice of an N-record KV run and hands the remainder to the seal DO,
// leaving the persisted checkpoint in durable storage. It returns the storage + a freshDO() factory so a
// test can resume the run under a NEW RunSealDO instance (the redeploy).
async function startHandoff(signerPrivateB64: string, breakGlassB64: string, n: number, index: number): Promise<HandoffRun> {
  const seeds = Array.from({ length: n }, (_, i) => ({ name: `key/${String(i).padStart(6, "0")}`, value: smallValue(i) }));
  const kv = new MemKV(seeds, 100);
  const dest = new MemDest();
  const sched = localScheduler();
  const doState = makeDOState();
  let currentDO: RunSealDO | null = null;
  const runsealStub = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      return currentDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init));
    },
  } as unknown as DurableObjectStub;
  const env = mkEnv(signerPrivateB64, breakGlassB64, kv, sched.stub, runsealStub, dest);
  const freshDO = (): RunSealDO => {
    // A fresh isolate's env (new R2/KV facades over the SAME underlying stores) plus a NEW RunSealDO over
    // the SAME durable storage Map: the redeploy. The seal DO holds no in-memory run state, so the only
    // thing carrying the run across the boundary is the persisted checkpoint.
    const env2 = mkEnv(signerPrivateB64, breakGlassB64, kv, sched.stub, runsealStub, dest);
    currentDO = new RunSealDO(doState.state, env2);
    return currentDO;
  };
  currentDO = freshDO();
  // The inline first slice runs under a tight budget and hands the rest off to the (real) seal DO.
  await sealRunSliced(env, dpState(DP_ID), { runId: RUN_ID, index, prevRunId: null }, { budget: new SliceBudget({ subrequests: 150, wallMs: 60_000 }) });
  return { doState, dest, kv, sched, seeds, freshDO };
}

// drainAlarms fires the seal DO's alarm until the run completes (the doc is cleaned up) or the bound is hit.
async function drainAlarms(run: HandoffRun, max: number): Promise<number> {
  let fired = 0;
  for (; fired < max && run.doState.storage.has("doc"); fired++) {
    await run.freshDO().alarm();
  }
  return fired;
}

async function main(): Promise<void> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const verifier = verifierFrom(signer);
  const breakGlass = makeRecipient("break-glass");
  const breakGlassB64 = b64urlEncode(concat(breakGlass.entry.pub.x25519, breakGlass.entry.pub.mlkemEk));
  const identity = parseIdentity(breakGlass.identity);

  const N = 900;

  // ============================================================================================
  // DEP-01: a run is handed off mid-flight, then RESUMED by a fresh RunSealDO over the same durable
  // storage (a redeploy). It must finish byte-correct from the persisted checkpoint alone.
  // ============================================================================================
  console.log("DEP-01 redeploy-mid-run resume: a fresh seal DO finishes the run byte-correct from the persisted checkpoint:");
  let archiveMap: Map<string, Uint8Array> | null = null;
  {
    const run = await startHandoff(signerPrivateB64, breakGlassB64, N, 9);
    ok("the inline slice handed the run to the seal DO (checkpoint persisted)", run.doState.storage.has("doc"));

    // Run two alarms on the ORIGINAL instance, then assert the run is still MID-FLIGHT (the checkpoint
    // outlives any single invocation). This is the state a redeploy interrupts.
    await run.freshDO().alarm();
    await run.freshDO().alarm();
    ok("after two alarms the run is still in flight (a redeploy will interrupt it mid-run)", run.doState.storage.has("doc"));
    const statusResp = await run.freshDO().fetch(new Request("https://do/status", { method: "GET" }));
    const status = (await statusResp.json()) as { records?: number; sourceDone?: boolean };
    const midRecords = status.records ?? 0;
    ok(`the persisted checkpoint records partial progress (0 < ${midRecords} < ${N})`, midRecords > 0 && midRecords < N);

    // REDEPLOY: every subsequent alarm is fired through freshDO() -- a NEW RunSealDO instance over the SAME
    // storage, modelling a fresh isolate per wakeup. The run must resume from the checkpoint and complete.
    const alarms = await drainAlarms(run, 100);
    ok(`the run resumed under fresh DO instances and completed (took ${alarms} more alarms)`, alarms > 2 && !run.doState.storage.has("doc"));

    const complete = run.sched.calls.find((c) => c.path === "/complete");
    const body = complete?.body as { status?: string; recordCount?: number; index?: number } | undefined;
    ok("the resumed run posted an OK completion at the allocated index", body?.status === "ok" && body?.index === 9);
    ok(`the completion declares the full record count (${N})`, body?.recordCount === N);

    // The decisive proof the checkpoint was read correctly: the accreted archive opens and EVERY record is
    // present exactly once and byte-exact across the redeploy boundary (no loss, no duplication, no mis-read).
    const opened = await openRun(new MapStore(run.dest.map), RUN_ID, identity, verifier, {});
    ok(`the redeployed archive opens with exactly N records (${opened.records.length})`, opened.records.length === N);
    const names = new Set(opened.records.map((r) => r.name));
    ok("every record name is unique (no checkpoint double-count on resume)", names.size === N);
    let allExact = true;
    for (let i = 0; i < N; i += 53) {
      const rec = opened.records.find((r) => r.name === run.seeds[i]!.name);
      if (!rec) { allExact = false; continue; }
      const got = await opened.restoreRecord(rec);
      if (Buffer.compare(Buffer.from(got), Buffer.from(run.seeds[i]!.value)) !== 0) allExact = false;
    }
    ok("sampled records restore byte-exact across the redeploy boundary", allExact);
    ok("each source value was read exactly once across the whole run (no re-reads on resume)", run.kv.gets === N);
    // Keep this validly-sealed archive for the DEP-03 format-bump scenario.
    archiveMap = run.dest.map;
  }

  console.log("\nDEP-01 fail-closed: a CORRUPTED persisted checkpoint resolves the run FAILED, never seals a mis-read archive:");
  {
    const run = await startHandoff(signerPrivateB64, breakGlassB64, N, 10);
    ok("the run handed off (checkpoint persisted)", run.doState.storage.has("doc"));
    // Corrupt the wrapped run master in the persisted doc (flip a ciphertext byte). On resume the AEAD unwrap
    // must fail, so the run can derive NO content keys -- the only safe outcome is to fail, never to seal
    // something under a guessed/garbage key.
    const doc = run.doState.storage.get("doc") as { checkpoint: { wrappedMaster: { iv: string; ct: string } } };
    const ct = doc.checkpoint.wrappedMaster.ct;
    doc.checkpoint.wrappedMaster.ct = (ct[0] === "A" ? "B" : "A") + ct.slice(1);
    run.doState.storage.set("doc", doc);

    let threw = false;
    try {
      // The strike ladder needs up to MAX_SLICE_FAILURES alarms to give up; bound generously.
      await drainAlarms(run, MAX_SLICE_FAILURES + 4);
    } catch {
      threw = true; // the DO alarm() must NEVER throw out; it absorbs faults onto the strike ladder.
    }
    ok("the seal DO alarm never threw out of the run loop (faults ride the strike ladder)", !threw);
    ok("the corrupted run was cleaned up (not wedged in flight forever)", !run.doState.storage.has("doc"));
    const completes = run.sched.calls.filter((c) => c.path === "/complete").map((c) => c.body as { status?: string });
    ok("the corrupted run resolved FAILED (fail-closed)", completes.some((b) => b?.status === "failed"));
    ok("the corrupted run NEVER reported an OK completion (no silent mis-read)", !completes.some((b) => b?.status === "ok"));
    // No signed root was sealed: a mis-read must never produce a readable-looking archive.
    ok("no signed root manifest was written for the corrupted run", ![...run.dest.map.keys()].some((k) => k.endsWith("root.manifest.json")));
  }

  // ============================================================================================
  // DEP-02: a persisted checkpoint at a NEWER version than the running code expects (a rollback reading
  // a migrated store). The pure guard rejects it; the seal DO degrades gracefully (never a crash/mis-read).
  // ============================================================================================
  console.log("\nDEP-02 schema-ahead-of-code (checkpoint side): a newer checkpoint version is REJECTED, the run fails CLOSED:");
  {
    // The pure guard, both arms: v:1 is the only accepted version; a NEWER v is rejected loudly. validateCheckpoint
    // mirrors the dp:<id> migrateOrRejectConfig gate (config side, owned by validate-config-schema-version).
    let guardThrew = false;
    try {
      validateCheckpoint({ v: 2 } as unknown);
    } catch {
      guardThrew = true;
    }
    ok("guard: a checkpoint at a NEWER version (v:2) is rejected (validateCheckpoint throws)", guardThrew);

    const run = await startHandoff(signerPrivateB64, breakGlassB64, N, 12);
    ok("the run handed off (checkpoint persisted)", run.doState.storage.has("doc"));
    // The at-rest stored checkpoint is migrated to a NEWER schema version (v:2) by a hypothetical newer
    // engine; this OLDER code is then rolled back onto it. openStoredCheckpoint must refuse it.
    const stored = (run.doState.storage.get("doc") as { checkpoint: Record<string, unknown> }).checkpoint;
    const ahead = { ...stored, v: 2 };
    let openThrew = false;
    try {
      await openStoredCheckpoint(signerPrivateB64, ahead);
    } catch {
      openThrew = true;
    }
    ok("openStoredCheckpoint refuses a v:2 at-rest checkpoint (no mis-read of new-shape state)", openThrew);

    // Drive the REAL seal DO over the schema-ahead doc: it must degrade gracefully (strike ladder ->
    // failed completion), never crash and never seal under mis-read state.
    const doc = run.doState.storage.get("doc") as { checkpoint: { v: number } };
    doc.checkpoint.v = 2;
    run.doState.storage.set("doc", doc);
    let crashed = false;
    try {
      await drainAlarms(run, MAX_SLICE_FAILURES + 4);
    } catch {
      crashed = true;
    }
    ok("the seal DO did NOT crash on a schema-ahead checkpoint (graceful)", !crashed);
    ok("the schema-ahead run was cleaned up (not wedged)", !run.doState.storage.has("doc"));
    const completes = run.sched.calls.filter((c) => c.path === "/complete").map((c) => c.body as { status?: string });
    ok("the schema-ahead run resolved FAILED (migrate-or-reject: rejected, fail-closed)", completes.some((b) => b?.status === "failed"));
    ok("the schema-ahead run NEVER reported OK (no silent mis-read under newer-shape state)", !completes.some((b) => b?.status === "ok"));
  }

  // ============================================================================================
  // DEP-03: a run sealed under a NEWER archive formatVersion (major), read by OLDER code. The reader must
  // reject it LOUD, never mis-parse, and the archive must stay recoverable by a correct-version reader.
  // ============================================================================================
  console.log("\nDEP-03 rollback-precedes-format-bump: an older reader rejects a NEWER-MAJOR archive LOUD (never mis-parses):");
  {
    if (archiveMap === null) {
      ok("DEP-03 precondition: a sealed archive from DEP-01 is available", false);
    } else {
      const rootKey = `run/${RUN_ID}/root.manifest.json`;
      const sigKey = `${rootKey}.sig`;
      const origRootBytes = archiveMap.get(rootKey)!;
      const origRoot = JSON.parse(new TextDecoder().decode(origRootBytes)) as RootManifest;
      ok("the DEP-01 archive is at the current format version (downpipe/0.1.x)", typeof origRoot.formatVersion === "string" && origRoot.formatVersion.startsWith("downpipe/0.1."));

      // resignedAt re-serialises the signed root with a substituted formatVersion and RE-SIGNS it with the
      // SAME signer, so the new root is a GENUINELY (validly) signed archive at that version -- not a
      // corruption. The reader verifies the signature FIRST, so without re-signing a bumped version would
      // fail the signature check, not the version gate; re-signing isolates the gate under test.
      const resignedAt = async (version: string): Promise<Map<string, Uint8Array>> => {
        const root = { ...origRoot, formatVersion: version } as unknown as Record<string, unknown>;
        const bytes = canonicalJSON(root);
        const sig = await hybridSign(signer.edPrivate, signer.mldsaSecret, bytes);
        const m = new Map(archiveMap!);
        m.set(rootKey, bytes);
        m.set(sigKey, utf8(b64urlEncode(sig)));
        return m;
      };

      // downpipe/1.0.0: a well-formed semver label at a NEWER major than the reader implements. It must be
      // three components, or it trips the SHAPE branch of the gate (missing major.minor.patch) instead of the
      // unimplemented-version branch this case exists to exercise.
      const newerMajor = await resignedAt("downpipe/1.0.0");

      // KEYED reader: openRun must THROW the explicit unimplemented-version rejection (the coded
      // usage/rejection path), reached BEFORE any shard is parsed, so the archive can never be mis-decoded.
      let openErr: Error | null = null;
      try {
        await openRun(new MapStore(newerMajor), RUN_ID, identity, verifier, {});
      } catch (e) {
        openErr = e as Error;
      }
      ok("openRun (keyed) REJECTS a downpipe/1.0.0 archive", openErr !== null);
      ok("the rejection names the unimplemented version (loud, not a generic parse error)", openErr !== null && /implements downpipe\/0\.1\.x and does not implement 1\.0/i.test(openErr.message));
      // It must also tell the operator the bytes are FINE. This is the half the old message dropped, and
      // dropping it is what let the console render an unreadable-by-this-build archive as a possible
      // corruption. Asserted separately so a future reword cannot quietly lose the remedy again.
      ok("the rejection says nothing is wrong with the bytes", openErr !== null && /Nothing is wrong with the bytes/.test(openErr.message));
      ok("the rejection points at where the format-to-release mapping is published", openErr !== null && /CHANGELOG\.md/.test(openErr.message));
      ok("the version refusal is NOT categorised as an integrity failure", openErr !== null && integrityCategoryOf(openErr) === "format-unsupported");

      // KEYLESS reader: attestKeyless reports signatureValid:true (the archive IS authentically newer, not
      // tampered) but complete:false with a structure reason -- a loud refusal that still tells a recovery
      // operator the bytes are genuine and need a newer reader.
      const att: KeylessAttestation = await attestKeyless(new MapStore(newerMajor), RUN_ID, verifier, { allowStale: true });
      ok("attestKeyless confirms the newer-major archive is AUTHENTIC (signatureValid:true)", att.signatureValid === true);
      ok("attestKeyless REFUSES to attest the newer-major archive complete (complete:false)", att.complete === false);

      // The gate pins MAJOR.MINOR (downpipe/0.1.x): the forward-compatible unit is the PATCH, so a 0.1.x
      // archive stays readable across a patch bump, while a newer MINOR or MAJOR is a loud rejection. Under
      // the pre-cutover downpipe/1.0 label the tolerated unit was the minor; the 0.x semver identity is
      // deliberately tighter, because a 0.x minor is allowed to break compatibility.
      ok("checkFormatVersion accepts the current version (downpipe/0.1.0)", (() => { try { checkFormatVersion("downpipe/0.1.0"); return true; } catch { return false; } })());
      ok("checkFormatVersion accepts a newer PATCH (downpipe/0.1.9 -> readable across a patch bump)", (() => { try { checkFormatVersion("downpipe/0.1.9"); return true; } catch { return false; } })());
      ok("checkFormatVersion REJECTS a newer MINOR (downpipe/0.2.0)", (() => { try { checkFormatVersion("downpipe/0.2.0"); return false; } catch { return true; } })());
      ok("checkFormatVersion REJECTS a newer MAJOR (downpipe/1.0.0)", (() => { try { checkFormatVersion("downpipe/1.0.0"); return false; } catch { return true; } })());
      // A label that is not full major.minor.patch is refused on SHAPE, before any version comparison.
      ok("checkFormatVersion REJECTS a non-semver label (downpipe/2.0, no patch component)", (() => { try { checkFormatVersion("downpipe/2.0"); return false; } catch { return true; } })());

      // ---- three labels this gate USED TO ACCEPT, each a version it does not implement ------------------
      // The split was unbounded and the components were only checked for non-emptiness, so anything whose
      // first two components read "0" and "1" was opened whatever followed. A gate that accepts a label it
      // does not implement is the failure this whole function exists to prevent, and it is the direction
      // that loses data rather than the one that merely says the wrong thing.
      const refuses = (v: string): boolean => { try { checkFormatVersion(v); return false; } catch { return true; } };
      ok("checkFormatVersion REJECTS a FOURTH component (downpipe/0.1.0.0) -- was accepted", refuses("downpipe/0.1.0.0"));
      ok("checkFormatVersion REJECTS a non-decimal patch (downpipe/0.1.x) -- was accepted", refuses("downpipe/0.1.x"));
      ok("checkFormatVersion REJECTS a trailing space (downpipe/0.1.0 ) -- was accepted", refuses("downpipe/0.1.0 "));
      // POSITIVE CONTROLS of the same kind, so the three above cannot pass by the gate refusing everything.
      ok("CONTROL: the exact current label is still accepted", !refuses("downpipe/0.1.0"));
      ok("CONTROL: a multi-digit patch is still accepted (downpipe/0.1.10)", !refuses("downpipe/0.1.10"));

      // ---- the two-component label, retired rather than served -------------------------------
      // It used to be refused as a FORMAT MISMATCH, on the ground that a released engine of ours wrote it
      // and the bytes were intact. That ground is gone: the 1.x lineage was retired rather than carried,
      // nothing implementing it was published, no reader for it is obtainable, and the update channel no
      // longer offers a writer that stamps one. So all three components are part of the version, and a
      // two-component label is an anomaly in a manifest we provably signed. Softening it would close by
      // naming a reader build to go and fetch, and that build will not exist.
      ok("checkFormatVersion REJECTS a two-component label (downpipe/1.0)", refuses("downpipe/1.0"));
      const twoComponent = (() => { try { checkFormatVersion("downpipe/1.0"); return null; } catch (e) { return e as Error; } })();
      ok("downpipe/1.0 is categorised integrity, NOT format-unsupported", twoComponent !== null && integrityCategoryOf(twoComponent) !== "format-unsupported");
      ok("downpipe/1.0 does NOT close by naming a reader to go and fetch", twoComponent !== null && !/Get a downpipe reader/.test(twoComponent.message));
      ok("downpipe/1.0 names the MAJOR.MINOR.PATCH shape, since it is refused on ARITY and every component of it IS a decimal number", twoComponent !== null && /MAJOR\.MINOR\.PATCH/.test(twoComponent.message) && /all three components present/.test(twoComponent.message));
      // POSITIVE CONTROL for the format-unsupported category, so the three assertions above cannot pass by
      // the gate having stopped producing that category at all. A WELL-FORMED version outside the
      // implemented set is the only route to it now, and it is the route a future minor bump takes.
      const unimplemented = (() => { try { checkFormatVersion("downpipe/0.2.0"); return null; } catch (e) { return e as Error; } })();
      ok("CONTROL: downpipe/0.2.0 IS categorised format-unsupported, so that category still has a producer", unimplemented !== null && integrityCategoryOf(unimplemented) === "format-unsupported");
      ok("CONTROL: downpipe/0.2.0 DOES name a reader to go and fetch, and says nothing was lost", unimplemented !== null && /Get a downpipe reader/.test(unimplemented.message) && /nothing has been lost/.test(unimplemented.message));
      // And "downpipe/0.1", whose two numbers MATCH the implemented set, must still be refused: its
      // derivation labels would read "downpipe/0.1 <purpose>" and derive every key to different bytes.
      ok("checkFormatVersion REJECTS downpipe/0.1 even though its numbers match the implemented set", refuses("downpipe/0.1"));
      // A label that is not a version at all stays on the strict side: no reader implements it, so there is
      // nothing for the holder to go and fetch, and the true statement is that the manifest is damaged.
      const malformed = (() => { try { checkFormatVersion("downpipe/0.1.x"); return null; } catch (e) { return e as Error; } })();
      ok("a MALFORMED label stays categorised integrity (no reader implements it)", malformed !== null && integrityCategoryOf(malformed) === "integrity");

      // RECOVERABILITY: the bump changed only the root's version label + signature; every shard and segment
      // byte is untouched, and the ORIGINAL (0.1.x) archive still opens with every record. The data is never
      // lost or corrupted by the rollback -- a correct-version reader recovers it in full.
      const shardKeysSame = [...archiveMap.keys()].filter((k) => k !== rootKey && k !== sigKey).every((k) => {
        const a = archiveMap!.get(k)!;
        const b = newerMajor.get(k);
        return b !== undefined && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
      });
      ok("the format bump left every shard/segment object byte-identical (no data corruption)", shardKeysSame);
      const reopened = await openRun(new MapStore(archiveMap), RUN_ID, identity, verifier, {});
      ok(`the original (downpipe/0.1.x) archive still opens with every record (${reopened.records.length} === ${N})`, reopened.records.length === N);
    }
  }

  // ============================================================================================
  // DEP-04: cron-removed dead-man. Does ANY staleness signal survive the cron being removed?
  // ============================================================================================
  console.log("\nDEP-04 cron-removed dead-man: whether a staleness signal survives the cron trigger being removed:");
  {
    // A downpipe whose last SUCCESS is past the staleness budget (the cron has not run it in a long time),
    // with a delivery destination configured so the detector is armed.
    const STALE_ID = "dp-stale";
    const seedStale = async (storage: { put(k: string, v: unknown): Promise<void> }): Promise<void> => {
      await storage.put(`dp:${STALE_ID}`, { config: makeNotifyConfig(STALE_ID), nextRunAt: Date.now() + 3_600_000, lastRunId: null, inFlight: false });
      // Newest-last ring with a single OK run whose start is just past the staleness budget.
      await storage.put(`hist:${STALE_ID}`, [{ runId: "01OLDOLDOLDOLDOLDOLDOLDOLD", index: 1, startedAt: staleStart(), status: "ok" }]);
      await storage.put(`${NOTIFY_CHANNEL_PREFIX}c1`, { id: "c1", kind: "webhook", name: "SRE", url: "https://hook.example.com/sre", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" });
    };

    // ---- Case A (REFUTE): while the fleet cron STILL fires, the staleness dead-man works -------------
    // reconcileAlerts() is exactly what the cron-driven drive() pass calls each tick. It fires the "stale"
    // alert and records the cooldown, so a per-downpipe stop (its schedule removed but the fleet cron alive)
    // IS detected. The dead-man exists and works -- as long as its driver keeps running.
    {
      const { storage, stub } = makeNotifyDO();
      await seedStale(storage);
      const r = await surf(stub).reconcileAlerts();
      const staleAlert = r.alerts.find((a) => a.id === STALE_ID);
      ok("Case A: the staleness budget is a finite multiple of cadence (a real bound exists)", STALE_THRESHOLD_MS > 0);
      ok("Case A: while the cron pass runs, reconcileAlerts FIRES a 'stale' dead-man alert", staleAlert?.state === "stale");
      ok("Case A: the alert is recorded (cooldown written), so the signal is real, not a no-op", storage.rawGet(`${ALERT_COOLDOWN_PREFIX}${STALE_ID}`) !== undefined);
    }

    // ---- Case B (FIXED, DEP-04): the timer that SURVIVES cron removal now BACKSTOPS the DETECTION -------
    // A deploy that removes the cron trigger stops scheduled() -> drive() -> reconcileAlerts(), so the
    // cron-driven staleness sweep goes silent. The SchedulerDO's own platform alarm() is the ONE timer that
    // survives, and the DO alarm now runs runCronDeadManSweep() AFTER re-arm: when the
    // cron heartbeat (CRON_ALERT_SWEEP_AT_KEY) has gone stale it runs the SAME sweep. What it CANNOT do is
    // deliver: the DO constructor takes only `state` (no env), so it reaches no notify-channel adapter. It
    // therefore records the trip and the undeliverable batch and rolls the optimistic transition cooldown
    // back, so the eventual cron-driven alert is not suppressed. (This CLOSES the earlier gap where the
    // alarm re-armed but never swept, so a cron-removed deploy silenced the backups AND their detector; the
    // delivery half is the residual that keeps an EXTERNAL monitor the primary control.)
    {
      const { storage, stub } = makeNotifyDO();
      await seedStale(storage); // seedStale configures a notify channel, so detection is armed
      // The cron looks dead: its last sweep is older than the stall threshold (the removed-trigger case).
      await storage.put(CRON_ALERT_SWEEP_AT_KEY, Date.now() - CRON_DEADMAN_STALL_MS - 60_000);
      const fx = installFetchMock();
      try {
        await surf(stub).alarm(); // the surviving DO wakeup now backstops the sweep
      } finally {
        fx.restore();
      }
      ok("Case B (FIXED): the DO alarm() -- the only timer that survives cron removal -- now RUNS the staleness sweep", health(storage, "cron-deadman-tripped") === 1);
      ok("Case B: the batch it detected reached NO sink, and the ledger records that rather than going quiet", health(storage, "undeliverable-alert-batch") === 1);
      ok("Case B: the env-free backstop made no outbound call at all", fx.captured.length === 0);
      ok("Case B: the optimistic cooldown is rolled back, so the cron-driven alert is not suppressed once it resumes", storage.rawGet(`${ALERT_COOLDOWN_PREFIX}${STALE_ID}`) === undefined);
      // The state WAS stale: the cron path (which the Worker drives WITH env) still fires and would deliver.
      const r = await surf(stub).reconcileAlerts();
      ok("Case B: the cron path still detects the same stale downpipe (the silence is the delivery limit, not a healthy pipe)", r.alerts.some((a) => a.id === STALE_ID && a.state === "stale"));
    }
  }

  // ============================================================================================
  // DEP-05: duplicate-cron double-drive. Two triggers for the same downpipe close together must be
  // serialised by the in-flight lease: no duplicate RUNLOG index, no second run, idempotent completion.
  // ============================================================================================
  console.log("\nDEP-05 duplicate-cron double-drive: the in-flight lease serialises two near-simultaneous triggers:");
  {
    const { storage, stub } = makeSchedDO();
    const ID = "dp-double";
    await surf(stub).addDownpipe(makeSchedConfig(ID));

    // Two triggers fire close together (a duplicate cron tick, or two drivers racing). The first allocates a
    // run; the second finds a fresh lease and COALESCES.
    const t1 = await surf(stub).trigger({ id: ID });
    const t2 = await surf(stub).trigger({ id: ID });
    ok("the first trigger allocated a run (runId + index)", "runId" in t1 && "index" in t1);
    ok("the second (duplicate) trigger COALESCED (skipped), never allocated a second run", "skipped" in t2);

    const idx1 = "index" in t1 ? t1.index : -1;
    ok("exactly ONE runlog index was allocated (the counter advanced by one)", storage.rawGet<number>("runlogCounter") === idx1 && idx1 === 1);
    const ring = storage.rawGet<{ index: number; status: string }[]>(`hist:${ID}`) ?? [];
    const inFlight = ring.filter((h) => h.status === "in-flight");
    ok("the history ring holds exactly ONE in-flight row (no duplicate run row)", inFlight.length === 1 && ring.length === 1);

    // Completion is idempotent: a retried/duplicate /complete for the same index must not double-resolve the
    // row or re-open the lease (so the run, and its single archive, are accounted exactly once).
    const runId1 = "runId" in t1 ? t1.runId : "";
    await surf(stub).completeRun({ id: ID, runId: runId1, index: idx1, status: "ok", recordCount: 5, bytes: 100 });
    await surf(stub).completeRun({ id: ID, runId: runId1, index: idx1, status: "ok", recordCount: 5, bytes: 100 });
    const ringAfter = storage.rawGet<{ index: number; status: string; recordCount?: number }[]>(`hist:${ID}`) ?? [];
    const okRows = ringAfter.filter((h) => h.index === idx1 && h.status === "ok");
    ok("the duplicate completion is idempotent: still exactly ONE resolved row at the index (no double archive)", okRows.length === 1 && ringAfter.length === 1);
    ok("no extra runlog index was minted by the double-drive (counter unchanged at 1)", storage.rawGet<number>("runlogCounter") === 1);
    const dsAfter = storage.rawGet<{ inFlight: boolean }>(`dp:${ID}`);
    ok("the lease is released after completion (inFlight cleared, not re-opened by the duplicate)", dsAfter?.inFlight === false);
  }

  // ============================================================================================
  // DEP-06: partial-deploy version skew. The cleanly-reachable subset is the checkpoint's forward/backward
  // compatible field handling that lets a checkpoint cross a deploy in EITHER direction, plus the version
  // gate for an incompatible skew. A true mixed-binary run (slice A by build X, slice B by build Y) is not
  // reachable with one compiled codebase; it is documented here, and the mechanisms that make it safe are
  // the same ones asserted below + the version gates in DEP-02.
  // ============================================================================================
  console.log("\nDEP-06 partial-deploy version skew (reachable subset): forward/backward-compatible checkpoint defaults + the version gate:");
  {
    // A base v:1 checkpoint as a NEWER build would persist it: it carries optional fields an OLDER build
    // does not model (openShard / recordsIncomplete / partialRecord). Reading it under the older shape must
    // accept it (default/ignore the unknown-but-optional fields), so a run's checkpoint survives a forward
    // deploy. validateCheckpoint is the read-time gate both builds funnel through.
    const base = (): Record<string, unknown> => ({
      v: 1, downpipeId: DP_ID, downpipeName: "skew", cadence: "3600s", sourceType: "kv",
      selector: { include: [], exclude: [] }, runId: RUN_ID, runlogIndex: 1, prevRunId: null,
      startedAt: "2026-06-10T00:00:00.000Z", wrappedMaster: { iv: "x", ct: "y" }, cursor: null,
      sourceDone: false, nextRecordIndex: 0, nextShardIndex: 0, frontier: { count: 0, nodes: [] },
      counts: { records: 0, bytes: 0, objectsWritten: 0, objectsSkipped: 0, archiveBytesWritten: 0, recordsSkippedChanged: 0, durationMs: 0 },
      sliceCount: 0, partialRecord: null,
    });

    // NEW->OLD: a checkpoint carrying newer optional fields validates and the new fields round-trip.
    const fromNewer = { ...base(), recordsIncomplete: 4, openShard: { count: 7 }, counts: { ...(base().counts as Record<string, unknown>), recordsIncomplete: 4 } };
    let newToOld: RunCheckpoint | null = null;
    try {
      newToOld = validateCheckpoint(fromNewer);
    } catch {
      newToOld = null;
    }
    ok("NEW->OLD: a checkpoint with newer optional fields validates (a forward deploy never strands a run)", newToOld !== null);
    ok("NEW->OLD: the openShard buffered-count is preserved (not silently dropped on resume)", newToOld?.openShard?.count === 7);

    // OLD->NEW: a checkpoint written by an OLDER build LACKS those fields; the newer read-time guard must
    // DEFAULT them (openShard -> {count:0}, recordsIncomplete -> 0, partialRecord -> null) rather than
    // reject, so a run's checkpoint survives a backward read too.
    const fromOlder = base(); // no openShard, no recordsIncomplete on counts
    let oldToNew: RunCheckpoint | null = null;
    try {
      oldToNew = validateCheckpoint(fromOlder);
    } catch {
      oldToNew = null;
    }
    ok("OLD->NEW: a legacy checkpoint missing the newer optional fields validates (a rollback/upgrade never strands a run)", oldToNew !== null);
    ok("OLD->NEW: the absent open-shard buffer defaults to {count:0} (resume starts spanning fresh)", oldToNew?.openShard?.count === 0);
    ok("OLD->NEW: the absent recordsIncomplete defaults to 0 (counts accrue from a clean base)", oldToNew?.counts.recordsIncomplete === 0);
    ok("OLD->NEW: the absent partialRecord defaults to null (no half-record is resumed under inconsistent state)", oldToNew?.partialRecord === null);

    // The INCOMPATIBLE skew (a load-bearing version bump) is the fail-closed gate proven in DEP-02: a
    // strictly-newer version is rejected, never mis-read. Re-stated here to close the DEP-06 narrative.
    ok("INCOMPATIBLE skew: a strictly-newer checkpoint version still fails closed (see DEP-02)", (() => { try { validateCheckpoint({ v: 2 } as unknown); return false; } catch { return true; } })());
  }

  console.log(failures === 0 ? "\nvalidate-deploy-rollback: ALL PASS" : `\nvalidate-deploy-rollback: ${failures} FAILED`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exitCode = 1;
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
