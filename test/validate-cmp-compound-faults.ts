// CMP — COMPOUND / CONCURRENT-fault chaos for the backup engine. The single-fault cases are exercised
// elsewhere (validate-slice, validate-runlog-contention, validate-heal-dests, and the chaos test sweeps);
// this validator injects TWO+ faults at the SAME tick and asserts the ONE invariant that must survive
// every compound fault: a fault (or two) may DELAY or FAIL a run, but must NEVER (a) silently lose data,
// (b) leave a verifiable-but-incomplete/duplicated archive, (c) corrupt the control plane (audit chain,
// config, lease) or (d) double-apply a restore. Integrity >= availability. Every block drives the REAL
// DO(s)/seal (RunSealDO, SchedulerDO, the restore-approval state machine) over in-memory bindings, exactly
// as validate-slice does, and asserts on concrete observed behaviour (a root written or not, the archive
// opening or refusing, the lease flipping, the completion status, the approval state).
//
//   CMP-01  DO-wipe-mid-run: the SchedulerDO storage is wiped while a run is in flight on its RunSealDO.
//   CMP-05  source-gone AND failover-down at the same tick: the run must fail CLOSED, no partial archive.
//   CMP-09  removeDest-during-seal: a destination is removed/reconfigured mid-seal; no split, no partial.
//   CMP-10  signer-rotate-during-failover: a consistent-key archive that verifies, or fail closed.
//   CMP-04  partition-during-apply: a lost-response retry must not double-apply (single-use consume).
//
// Run: node test/validate-cmp-compound-faults.ts

import { ORG_POLICY_KEY } from "../src/sched/scheduler-do-records.ts";
import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import type { RecipientEntry, Signer } from "../src/format/writer.ts";
import { type RunCheckpoint, wrapMaster, zeroCounts } from "../src/seal/checkpoint.ts";
import { SliceBudget } from "../src/seal/budget.ts";
import { runSlice, type SliceDeps } from "../src/seal/slice.ts";
import { RunSealDO, sealRunSliced } from "../src/seal/runstate.ts";
import type { Meter, Selector, SourceAdapter, SourceRecord } from "../src/sources/types.ts";
import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { DownpipeConfig, DownpipeState } from "../src/sched/scheduler-do.ts";
import { newULID } from "../src/sched/scheduler-helpers.ts";
import { destinationReachable } from "../src/cron/seal-dispatch.ts";
import { restorePlanHash } from "../src/admin/approvals.ts";
import type { RestoreRequest } from "../src/admin/restore-types.ts";
import type { Caller } from "../src/admin/identity.ts";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { notePlanAnchor } from "./testutil.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

// value(i) is a tiny (16..39 byte) deterministic record value: enough variety to seal distinct records,
// small enough that a 900-record run is well under 40 KiB total (the "never allocate large data" floor).
function value(i: number): Uint8Array {
  const n = 16 + (i % 24);
  const b = new Uint8Array(n);
  for (let j = 0; j < n; j++) b[j] = (Math.imul(i + 1, 2654435761) >>> (j % 24)) & 0xff;
  return b;
}

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// freshSigner mints an independent 64-byte signer seed + its verifier, so CMP-10 can ROTATE the engine's
// SIGNER_PRIVATE to a genuinely different key (the checkpoint wrap key is HKDF-derived from this seed, so
// a rotation makes a mid-run unwrap fail closed, and the root signature changes verifier).
async function freshSigner(): Promise<{ b64: string; signer: Signer; verifier: ReturnType<typeof verifierFrom> }> {
  const b64 = b64urlEncode(concat(rand(32), rand(32)));
  const signer = await loadSigner(b64);
  return { b64, signer, verifier: verifierFrom(signer) };
}

// ---- destination + source doubles (the validate-slice contract, plus a `down` fault toggle) -----------

// MemDest is the full Destination contract over a Map. `down`, when set, makes every WRITE throw a plain
// (non-throttle) 500 — a destination that has been removed / gone unwritable mid-seal. Reads stay live so
// the archive can be opened/verified after the fault (proving what did or did not land).
class MemDest implements Destination {
  map = new Map<string, Uint8Array>();
  private tags = new Map<string, string>();
  private seq = 0;
  down = false;
  async get(key: string): Promise<GetResult | null> {
    const v = this.map.get(key);
    return v ? { body: v, etag: this.tags.get(key) ?? "e0" } : null;
  }
  async put(key: string, body: Uint8Array): Promise<void> {
    if (this.down) throw new Error(`PUT ${key}: status 500 destination write rejected`);
    this.map.set(key, body);
    this.tags.set(key, `e${++this.seq}`);
  }
  async putStream(key: string, body: ReadableStream<Uint8Array>): Promise<void> {
    const parts: Uint8Array[] = [];
    const reader = body.getReader();
    for (;;) {
      const { done, value: v } = await reader.read();
      if (done) break;
      parts.push(v);
    }
    await this.put(key, concat(...parts));
  }
  async putConditional(key: string, body: Uint8Array, opts: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult> {
    if (this.down) throw new Error(`PUT ${key}: status 500 destination write rejected`);
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

// MemKV is a paginated KV namespace double. `vanishAfterGets`, when set, makes the namespace THROW once
// that many values have been read — a source resource DELETED mid-crawl (the owner-named "deleted
// mid-process" case), so the seal hits a real source fault partway through a multi-slice run.
class MemKV {
  private seeds: { name: string; value: Uint8Array }[];
  private pageSize: number;
  gets = 0;
  vanishAfterGets = Number.POSITIVE_INFINITY;
  constructor(seeds: { name: string; value: Uint8Array }[], pageSize: number) {
    this.seeds = [...seeds].sort((a, b) => (a.name < b.name ? -1 : 1));
    this.pageSize = pageSize;
  }
  async list(options?: { prefix?: string; cursor?: string }): Promise<{ keys: { name: string }[]; list_complete: boolean; cursor?: string; cacheStatus: null }> {
    let start = 0;
    if (options?.cursor !== undefined) start = Number(options.cursor);
    const prefix = options?.prefix;
    const all = prefix === undefined ? this.seeds : this.seeds.filter((s) => s.name.startsWith(prefix));
    const page = all.slice(start, start + this.pageSize);
    const next = start + this.pageSize;
    const complete = next >= all.length;
    return { keys: page.map((s) => ({ name: s.name })), list_complete: complete, ...(complete ? {} : { cursor: String(next) }), cacheStatus: null };
  }
  async getWithMetadata(key: string, _t: "arrayBuffer"): Promise<{ value: ArrayBuffer | null; metadata: unknown; cacheStatus: null }> {
    this.gets++;
    if (this.gets > this.vanishAfterGets) throw new Error("KV namespace not found: the bound namespace was deleted");
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

// VanishingSource is a crawl-only adapter (NO probeLiveness, so the seal does not preflight it away) that
// yields `live` real records then THROWS — a source that disappears mid-crawl. It lets CMP-05 drive the
// seal core with a source-gone fault that fires DURING the crawl, alongside a down destination.
class VanishingSource implements SourceAdapter {
  readonly sourceType = "cf-config" as const;
  private live: number;
  constructor(live: number) {
    this.live = live;
  }
  async *crawl(_selector: Selector, meter?: Meter): AsyncIterable<SourceRecord> {
    for (let i = 0; i < this.live; i++) {
      meter?.spend(1);
      yield { sourceType: "cf-config", name: `surface/${i}`, value: value(i) };
    }
    throw new Error("source resource missing: the bound resource was deleted mid-crawl");
  }
  async estimate(): Promise<{ records: number; bytes: number }> {
    return { records: this.live, bytes: -1 };
  }
}

// ---- DO storage doubles ------------------------------------------------------------------------------

// makeDOState is the RunSealDO storage double (Map-backed, alarm capture), identical in shape to
// validate-slice's so the REAL RunSealDO drives against real persisted state.
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
      async list(opts?: { prefix?: string; startAfter?: string; limit?: number }): Promise<Map<string, unknown>> {
        let keys = [...storage.keys()].filter((k) => !opts?.prefix || k.startsWith(opts.prefix)).sort();
        if (opts?.startAfter !== undefined) keys = keys.filter((k) => k > opts.startAfter!);
        if (typeof opts?.limit === "number") keys = keys.slice(0, opts.limit);
        const out = new Map<string, unknown>();
        for (const k of keys) out.set(k, storage.get(k));
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

// WipeableStorage is the SchedulerDO storage double: a Map-backed DurableObjectStorage that HONOURS
// prefix/startAfter/limit paging (so listAllByPrefix behaves), with a wipe() that clears it whole — the
// authentic "the DO lost its storage" event a chaos script reproduces with rm -rf.
class WipeableStorage {
  readonly map = new Map<string, unknown>();
  private alarm: number | null = null;
  async get<T>(key: string): Promise<T | undefined> {
    return this.map.get(key) as T | undefined;
  }
  async put<T>(a: string | Record<string, unknown>, b?: T): Promise<void> {
    if (typeof a === "string") this.map.set(a, b);
    else for (const [k, v] of Object.entries(a)) this.map.set(k, v);
  }
  async delete(key: string | string[]): Promise<boolean | number> {
    if (Array.isArray(key)) {
      let n = 0;
      for (const k of key) if (this.map.delete(k)) n += 1;
      return n;
    }
    return this.map.delete(key);
  }
  async deleteAll(): Promise<void> {
    this.map.clear();
  }
  async list<T>(opts?: { prefix?: string; start?: string; startAfter?: string; limit?: number }): Promise<Map<string, T>> {
    const prefix = opts?.prefix ?? "";
    let keys = [...this.map.keys()].filter((k) => k.startsWith(prefix)).sort();
    if (opts?.startAfter !== undefined) keys = keys.filter((k) => k > opts.startAfter!);
    if (opts?.start !== undefined) keys = keys.filter((k) => k >= opts.start!);
    if (typeof opts?.limit === "number") keys = keys.slice(0, opts.limit);
    const out = new Map<string, T>();
    for (const k of keys) out.set(k, this.map.get(k) as T);
    return out;
  }
  async getAlarm(): Promise<number | null> {
    return this.alarm;
  }
  async setAlarm(t: number): Promise<void> {
    this.alarm = t;
  }
  async deleteAlarm(): Promise<void> {
    this.alarm = null;
  }
  wipe(): void {
    this.map.clear();
    this.alarm = null;
  }
}

function nsFor(stub: DurableObjectStub): DurableObjectNamespace {
  return {
    idFromName: (_n: string) => ({}) as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
}

// ---- the engine Env (an R2Bucket facade over MemDest), mirroring validate-slice's mkEnv ---------------

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
    DEST_THROTTLE_BASE_MS: "1",
  } as unknown as Env;
}

function dpConfig(id: string): DownpipeConfig {
  return { id, name: id, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_TEST", namespaceId: "ns1", include: [], exclude: [] } } as DownpipeConfig;
}

function dpState(id: string): DownpipeState {
  return { config: dpConfig(id), nextRunAt: 0, lastRunId: null, inFlight: true, inFlightSince: Date.now() } as DownpipeState;
}

// makeMockScheduler is the scriptable scheduler stub the seal heartbeats/finalises against (CMP-05/09/10).
// It records every path called (so a test can prove the seal NEVER re-resolves the destination mid-run),
// scripts lease ownership, and refuses the runlog lock so finalise takes the lock-free CAS path.
function makeMockScheduler(): { stub: DurableObjectStub; calls: { path: string; body?: unknown }[]; setOwned(v: boolean): void } {
  const calls: { path: string; body?: unknown }[] = [];
  let owned = true;
  const stub = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const body = init?.body ? JSON.parse(String(init.body)) : undefined;
      calls.push({ path: url.pathname, ...(body !== undefined ? { body } : {}) });
      if (url.pathname === "/heartbeat") return new Response(JSON.stringify({ owned }));
      if (url.pathname === "/runlog-lock/acquire") return new Response(JSON.stringify({ acquired: false }));
      if (url.pathname === "/notify/resolve") return new Response(JSON.stringify({ now: [], digestedCount: 0, emission: null }));
      return new Response(JSON.stringify({ ok: true }));
    },
  } as unknown as DurableObjectStub;
  return { stub, calls, setOwned: (v: boolean) => (owned = v) };
}

// makeRealScheduler builds a REAL SchedulerDO over WipeableStorage, so CMP-01 drives the genuine lease
// (heartbeat/completeRun ownership) and re-bootstrap and CMP-04 drives the genuine restore-approval state
// machine. The returned stub is what the RunSealDO heartbeats against.
function makeRealScheduler(): { dobj: SchedulerDO; storage: WipeableStorage; stub: DurableObjectStub } {
  const storage = new WipeableStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  return { dobj, storage, stub };
}

const SEEDS = Array.from({ length: 900 }, (_, i) => ({ name: `key/${String(i).padStart(6, "0")}`, value: value(i) }));

// silence reroutes console.error around a fault-driving block (the engine logs redacted faults there) and
// returns the captured lines so a test can still assert the redaction held.
async function silence(fn: () => Promise<void>): Promise<string[]> {
  const orig = console.error;
  const lines: string[] = [];
  console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
  try {
    await fn();
  } finally {
    console.error = orig;
  }
  return lines;
}

// archiveOpensComplete returns true iff the destination holds a COMPLETE, verifiable archive for runId
// (root present, signature + shard hashes + Merkle root all check, every record opens). A partial archive
// (shards but no signed root) makes openRun throw, so this returns false — exactly the "not readable as
// complete" property each fail-closed assertion needs.
async function archiveOpensComplete(dest: MemDest, runId: string, identity: Uint8Array, verifier: ReturnType<typeof verifierFrom>): Promise<{ opened: boolean; records: number }> {
  try {
    const run = await openRun(new MapStore(dest.map), runId, parseIdentity(identity), verifier, {});
    return { opened: true, records: run.records.length };
  } catch {
    return { opened: false, records: 0 };
  }
}

function hasRoot(dest: MemDest, runId: string): boolean {
  return [...dest.map.keys()].some((k) => k.includes(`run/${runId}/`) && k.endsWith("root.manifest.json"));
}

// =====================================================================================================
// CMP-01 — DO-wipe-mid-run. The whole control plane (config, schedules, lease, audit, dest creds) lives
// in ONE singleton SchedulerDO. Wipe it while a run is in flight on its (separate) RunSealDO and assert:
//   (a) mid-crawl: the next alarm heartbeats the wiped scheduler, gets owned:false (the lease re-bootstrap
//       is loud), and ABANDONS the run — no finalise into an amnesiac control plane, no signed root, the
//       partial shards are NOT readable as complete;
//   (b) finalise-window: a wipe that lands AFTER the finalising alarm's heartbeat but in the
//       finalise->/complete window still leaves a COMPLETE, verifiable archive on the destination (the
//       bytes + RUNLOG are on the bucket, independent of the scheduler) — the run completed correctly; the
//       control plane merely forgot it (amnesia), data survives. Never a partial-as-complete.
// =====================================================================================================
async function cmp01(signerB64: string, breakGlassB64: string, breakGlass: { identity: Uint8Array }, verifier: ReturnType<typeof verifierFrom>): Promise<void> {
  console.log("\nCMP-01 DO-wipe-mid-run:");

  // ---- (a) wipe mid-crawl -> abandon, no signed root --------------------------------------------------
  {
    const sched = makeRealScheduler();
    const doState = makeDOState();
    const dest = new MemDest();
    const kv = new MemKV(SEEDS, 100);
    sched.storage.map.set("dp:dp-wipe", { config: dpConfig("dp-wipe"), nextRunAt: 0, lastRunId: null, inFlight: false });
    const trig = (await (await sched.stub.fetch("https://s/trigger", { method: "POST", body: JSON.stringify({ id: "dp-wipe" }) })).json()) as { runId: string; index: number; prevRunId: string | null };
    let realDO: RunSealDO | null = null;
    const runsealStub = { async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> { return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init)); } } as unknown as DurableObjectStub;
    const env = mkEnv(signerB64, breakGlassB64, kv, sched.stub, runsealStub, dest);
    (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "150";
    (env as unknown as Record<string, string>)["SCALE_SHARD_MAX_RECORDS"] = "200";
    realDO = new RunSealDO(doState.state, env);

    await sealRunSliced(env, dpState("dp-wipe"), trig, { budget: new SliceBudget({ subrequests: 150, wallMs: 60_000 }) });
    ok("(a) a large run handed off to the seal DO (in flight)", doState.storage.has("doc"));
    await realDO.alarm(); // one good slice against the intact scheduler (the lease is valid)
    ok("(a) the in-flight run is mid-crawl (some shards landed, NO signed root yet)", !hasRoot(dest, trig.runId) && doState.storage.has("doc"));
    const ownedPre = ((await (await sched.stub.fetch("https://s/heartbeat", { method: "POST", body: JSON.stringify({ id: "dp-wipe", runId: trig.runId, index: trig.index }) })).json()) as { owned: boolean }).owned;
    ok("(a) PRE-wipe the real lease reports owned:true", ownedPre === true);

    sched.storage.wipe(); // the SchedulerDO loses ALL its storage (rm -rf the DO)
    const downpipesGone = !sched.storage.map.has("dp:dp-wipe");
    ok("(a) the wipe is total amnesia: the downpipe row is gone", downpipesGone);
    const ownedPost = ((await (await sched.stub.fetch("https://s/heartbeat", { method: "POST", body: JSON.stringify({ id: "dp-wipe", runId: trig.runId, index: trig.index }) })).json()) as { owned: boolean }).owned;
    ok("(a) POST-wipe the real lease reports owned:false (the amnesia is LOUD to the in-flight sealer)", ownedPost === false);

    const log = await silence(async () => { await realDO!.alarm(); }); // the next slice heartbeats -> owned:false
    ok("(a) the in-flight run ABANDONS cleanly (the seal DO state is cleared)", doState.storage.size === 0);
    ok("(a) the abandon log names a lost lease, redacted (no record name leak)", log.some((l) => /lost its lease/.test(l)) && log.every((l) => !l.includes("key/0")));
    ok("(a) no signed root was written into the amnesiac control plane", !hasRoot(dest, trig.runId));
    const a = await archiveOpensComplete(dest, trig.runId, breakGlass.identity, verifier);
    ok("(a) INVARIANT: the partial archive is NOT readable as complete (openRun refuses it)", a.opened === false);
  }

  // ---- (b) wipe in the finalise->/complete window -> complete archive survives ------------------------
  {
    const sched = makeRealScheduler();
    const doState = makeDOState();
    const dest = new MemDest();
    const kv = new MemKV(SEEDS, 100);
    sched.storage.map.set("dp:dp-fin", { config: dpConfig("dp-fin"), nextRunAt: 0, lastRunId: null, inFlight: false });
    const trig = (await (await sched.stub.fetch("https://s/trigger", { method: "POST", body: JSON.stringify({ id: "dp-fin" }) })).json()) as { runId: string; index: number; prevRunId: string | null };
    // A scheduler facade that WIPES the real DO storage the instant /complete is called — i.e. the amnesia
    // lands AFTER finaliseRun has written the root + RUNLOG to the bucket and AFTER the finalising alarm's
    // heartbeat passed, but before the completion is recorded. The worst interleaving for "completes
    // correctly". Heartbeat + runlog-lock earlier in the alarm run against intact storage.
    let wipedAtComplete = false;
    const wipeStub = {
      fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (new URL(url).pathname === "/complete") {
          sched.storage.wipe();
          wipedAtComplete = true;
        }
        return sched.dobj.fetch(new Request(url, init));
      },
    } as unknown as DurableObjectStub;
    let realDO: RunSealDO | null = null;
    const runsealStub = { async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> { return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init)); } } as unknown as DurableObjectStub;
    const env = mkEnv(signerB64, breakGlassB64, kv, wipeStub, runsealStub, dest);
    (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "150";
    (env as unknown as Record<string, string>)["SCALE_SHARD_MAX_RECORDS"] = "200";
    realDO = new RunSealDO(doState.state, env);

    await sealRunSliced(env, dpState("dp-fin"), trig, { budget: new SliceBudget({ subrequests: 150, wallMs: 60_000 }), destinationId: "r2-primary" });
    let alarms = 0;
    await silence(async () => { for (; alarms < 200 && doState.storage.has("doc"); alarms++) await realDO!.alarm(); });
    ok("(b) the run finalised and the wipe landed exactly at /complete (worst interleaving)", wipedAtComplete && doState.storage.size === 0);
    ok("(b) the control plane has amnesia (no history row recorded for the run)", !sched.storage.map.has("hist:dp-fin") && !sched.storage.map.has("dp:dp-fin"));
    const b = await archiveOpensComplete(dest, trig.runId, breakGlass.identity, verifier);
    ok(`(b) INVARIANT: the archive on the bucket is COMPLETE + verifiable despite the wipe (${b.records} records)`, b.opened && b.records === 900);
    ok("(b) the destination-global RUNLOG survived the control-plane wipe (recoverable offline)", dest.map.has("_RECOVERY/RUNLOG"));
  }
}

// =====================================================================================================
// CMP-05 — source-gone AND failover-down at the same tick. Two faults: the source vanishes AND there is
// nowhere healthy to write. Assert the run fails CLOSED — no partial/incomplete archive that verifies.
// =====================================================================================================
async function cmp05(signerB64: string, breakGlassB64: string, breakGlass: { identity: Uint8Array; entry: RecipientEntry }, signer: Signer, verifier: ReturnType<typeof verifierFrom>): Promise<void> {
  console.log("\nCMP-05 source-gone AND failover-down (same tick):");

  // The failover GATE: a down destination probes UNWRITABLE (so 3-2-1 failover excludes it); when EVERY
  // destination is down the dispatcher has nowhere to write (the allDown path records a failed run and
  // never seals). Prove the gate verdict directly on the real probe.
  const downDest = new MemDest();
  downDest.down = true;
  const upDest = new MemDest();
  ok("the failover write-probe marks a down destination UNWRITABLE (excluded from failover)", (await destinationReachable(downDest)) === false);
  ok("the failover write-probe marks a healthy destination writable", (await destinationReachable(upDest)) === true);

  // Compound at the SEAL: a real KV run whose source vanishes mid-crawl AND whose destination is down.
  // Drive the REAL RunSealDO to its terminal strike and assert a failed completion with NO partial archive.
  {
    const sched = makeMockScheduler();
    const doState = makeDOState();
    const dest = new MemDest();
    const runId = newULID(Date.now());
    const kv = new MemKV(SEEDS.slice(0, 500), 100);
    kv.vanishAfterGets = 600; // the namespace is deleted late in the crawl (the second fault is armed)
    let realDO: RunSealDO | null = null;
    const runsealStub = { async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> { return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init)); } } as unknown as DurableObjectStub;
    const env = mkEnv(signerB64, breakGlassB64, kv, sched.stub, runsealStub, dest);
    (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "120";
    realDO = new RunSealDO(doState.state, env);
    await sealRunSliced(env, dpState("dp-cmp05"), { runId, index: 5, prevRunId: null }, { budget: new SliceBudget({ subrequests: 120, wallMs: 60_000 }), destinationId: "r2-primary" });
    ok("the run handed off (a first slice sealed before the faults bite)", doState.storage.has("doc"));
    dest.down = true; // the destination goes unwritable (failover would have nowhere to go)
    const log = await silence(async () => { for (let i = 0; i < 30 && doState.storage.has("doc"); i++) await realDO!.alarm(); });
    ok("the compound-faulted run resolves (never wedged in flight)", doState.storage.size === 0);
    const complete = sched.calls.find((c) => c.path === "/complete");
    const body = complete?.body as { status?: string; runId?: string } | undefined;
    ok("INVARIANT: the run fails CLOSED (a failed completion with the empty runId)", body?.status === "failed" && body?.runId === "");
    ok("the failure logs stay redacted (no source binding / record name leak)", log.length > 0 && log.every((l) => !l.includes("KV_TEST") && !l.includes("key/0")));
    const r = await archiveOpensComplete(dest, runId, breakGlass.identity, verifier);
    ok("INVARIANT: no partial archive verifies after the compound fault (openRun refuses)", r.opened === false);
  }

  // The source-gone arm in isolation, at the seal CORE: a slice whose source throws mid-crawl writes some
  // content segments but NEVER a signed root, so the half-archive is not readable as complete (the bytes
  // are not a verifiable, declared-complete run).
  {
    const dest = new MemDest();
    const runId = newULID(Date.now());
    const master = rand(32);
    const cp: RunCheckpoint = {
      v: 1, downpipeId: "dp-core", downpipeName: "core", cadence: "3600s", sourceType: "cf-config",
      selector: { include: [], exclude: [] }, runId, runlogIndex: 1, prevRunId: null,
      startedAt: "2026-06-30T00:00:00.000Z", wrappedMaster: await wrapMaster(signerB64, runId, master),
      cursor: null, sourceDone: false, nextRecordIndex: 0, nextShardIndex: 0,
      frontier: { count: 0, nodes: [] }, counts: zeroCounts(), sliceCount: 0, partialRecord: null,
    };
    const deps: SliceDeps = { source: new VanishingSource(3), dest, signer, recipients: [breakGlass.entry], budget: new SliceBudget({ subrequests: 200, wallMs: 60_000 }) };
    let threw = false;
    await silence(async () => { try { await runSlice(deps, cp, master); } catch { threw = true; } });
    master.fill(0);
    ok("the seal core throws when the source vanishes mid-crawl (no silent truncation)", threw);
    ok("INVARIANT: no signed root was written for the vanished-source run", !hasRoot(dest, runId));
    const r = await archiveOpensComplete(dest, runId, breakGlass.identity, verifier);
    ok("INVARIANT: the half-written archive (segments, no root) is NOT readable as complete", r.opened === false);
  }
}

// =====================================================================================================
// CMP-09 — removeDest-during-seal. A destination is removed/reconfigured while a run is actively sealing
// to it. The correctness rule is that a run NEVER re-resolves its destination mid-flight (a mid-run change
// must not split one run across two stores). Assert: (a) the pinned origin survives every resumed slice
// and the seal makes ZERO destination-config lookups, so a console removeDest cannot repoint or split it,
// and the run completes to the ONE store it started with; (b) if the pinned store itself dies mid-seal the
// run fails CLOSED — no corrupt/partial archive readable as complete.
// =====================================================================================================
async function cmp09(signerB64: string, breakGlassB64: string, breakGlass: { identity: Uint8Array }, verifier: ReturnType<typeof verifierFrom>): Promise<void> {
  console.log("\nCMP-09 removeDest-during-seal:");

  // ---- (a) the pin survives a mid-run dest change: no re-resolution, no split ------------------------
  {
    const sched = makeMockScheduler();
    const doState = makeDOState();
    const dest = new MemDest();
    const runId = newULID(Date.now());
    const kv = new MemKV(SEEDS, 100);
    let realDO: RunSealDO | null = null;
    const runsealStub = { async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> { return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init)); } } as unknown as DurableObjectStub;
    const env = mkEnv(signerB64, breakGlassB64, kv, sched.stub, runsealStub, dest);
    (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "150";
    (env as unknown as Record<string, string>)["SCALE_SHARD_MAX_RECORDS"] = "200";
    realDO = new RunSealDO(doState.state, env);
    await sealRunSliced(env, dpState("dp-cmp09a"), { runId, index: 9, prevRunId: null }, { budget: new SliceBudget({ subrequests: 150, wallMs: 60_000 }), destinationId: "r2-primary" });
    ok("(a) the run pinned its failover-chosen origin at handoff", (doState.storage.get("doc") as { destinationId?: string }).destinationId === "r2-primary");

    // Drive to completion, snapshotting the pinned origin each alarm; a "console removeDest/reconfigure"
    // happening concurrently would change the scheduler's dest collection, but the in-flight run never
    // asks for it, so it cannot be repointed.
    const pinnedSeen = new Set<string | undefined>();
    let alarms = 0;
    for (; alarms < 200 && doState.storage.has("doc"); alarms++) {
      pinnedSeen.add((doState.storage.get("doc") as { destinationId?: string }).destinationId);
      await realDO.alarm();
    }
    ok("(a) every resumed slice re-persisted the SAME pinned origin (no mid-run repoint)", pinnedSeen.size === 1 && pinnedSeen.has("r2-primary"));
    ok("(a) the seal made ZERO destination-config lookups (a removeDest cannot repoint an in-flight run)", !sched.calls.some((c) => c.path === "/dest-config" || c.path.startsWith("/destinations")));
    const complete = sched.calls.find((c) => c.path === "/complete");
    ok("(a) the completion reports the SAME pinned origin it started with", (complete?.body as { destinationId?: string; status?: string } | undefined)?.destinationId === "r2-primary");
    const r = await archiveOpensComplete(dest, runId, breakGlass.identity, verifier);
    ok(`(a) INVARIANT: exactly one store holds the COMPLETE run, no split (${r.records} records)`, r.opened && r.records === 900);
  }

  // ---- (b) the pinned store dies mid-seal -> fail closed, no partial-as-complete ---------------------
  {
    const sched = makeMockScheduler();
    const doState = makeDOState();
    const dest = new MemDest();
    const runId = newULID(Date.now());
    const kv = new MemKV(SEEDS.slice(0, 500), 100);
    let realDO: RunSealDO | null = null;
    const runsealStub = { async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> { return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init)); } } as unknown as DurableObjectStub;
    const env = mkEnv(signerB64, breakGlassB64, kv, sched.stub, runsealStub, dest);
    (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "120";
    realDO = new RunSealDO(doState.state, env);
    await sealRunSliced(env, dpState("dp-cmp09b"), { runId, index: 19, prevRunId: null }, { budget: new SliceBudget({ subrequests: 120, wallMs: 60_000 }), destinationId: "r2-primary" });
    ok("(b) the run handed off and sealed a first slice to its pinned store", doState.storage.has("doc"));
    dest.down = true; // the pinned destination is removed / its bucket goes unwritable mid-seal
    await silence(async () => { for (let i = 0; i < 30 && doState.storage.has("doc"); i++) await realDO!.alarm(); });
    ok("(b) the run resolves (never wedged) once its destination dies", doState.storage.size === 0);
    const complete = sched.calls.find((c) => c.path === "/complete");
    ok("(b) INVARIANT: the run fails CLOSED (failed completion, empty runId)", (complete?.body as { status?: string; runId?: string } | undefined)?.status === "failed" && (complete?.body as { runId?: string } | undefined)?.runId === "");
    dest.down = false; // the store recovers for reads; the question is only whether a complete archive exists
    ok("(b) INVARIANT: no signed root was left over the dead destination", !hasRoot(dest, runId));
    const r = await archiveOpensComplete(dest, runId, breakGlass.identity, verifier);
    ok("(b) INVARIANT: the partial archive is NOT readable as complete (openRun refuses)", r.opened === false);
  }
}

// =====================================================================================================
// CMP-10 — signer-rotate-during-failover. The signer key rotates while a run (sealing to its
// failover-chosen origin) is resuming on the seal DO. Assert: the archive is signed with a CONSISTENT key
// and verifies, OR the run fails closed — never a mixed/unverifiable root. The checkpoint wrap key is
// HKDF-derived from SIGNER_PRIVATE, so a mid-run rotation makes the resume unwrap fail closed BEFORE any
// byte is sealed under the new key; a run that completed wholly under the old key verifies under the old
// verifier ONLY.
// =====================================================================================================
async function cmp10(oldSigner: { b64: string; verifier: ReturnType<typeof verifierFrom> }, breakGlassB64: string, breakGlass: { identity: Uint8Array }): Promise<void> {
  console.log("\nCMP-10 signer-rotate-during-failover:");
  const rotated = await freshSigner();

  // ---- rotation MID-RESUME -> fail closed (no mixed root) --------------------------------------------
  {
    const sched = makeMockScheduler();
    const doState = makeDOState();
    const dest = new MemDest();
    const runId = newULID(Date.now());
    const kv = new MemKV(SEEDS, 100);
    let realDO: RunSealDO | null = null;
    const runsealStub = { async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> { return realDO!.fetch(new Request(input instanceof Request ? input.url : String(input), init)); } } as unknown as DurableObjectStub;
    const env = mkEnv(oldSigner.b64, breakGlassB64, kv, sched.stub, runsealStub, dest);
    (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "150";
    (env as unknown as Record<string, string>)["SCALE_SHARD_MAX_RECORDS"] = "200";
    realDO = new RunSealDO(doState.state, env);
    await sealRunSliced(env, dpState("dp-cmp10"), { runId, index: 10, prevRunId: null }, { budget: new SliceBudget({ subrequests: 150, wallMs: 60_000 }), destinationId: "r2-secondary" });
    ok("the run handed off (wrappedMaster sealed under the OLD signer), pinned to its failover origin", doState.storage.has("doc") && (doState.storage.get("doc") as { destinationId?: string }).destinationId === "r2-secondary");
    await realDO.alarm(); // one good slice still under the old key
    ok("a slice advanced under the old signer (still mid-run)", doState.storage.has("doc"));

    (env as unknown as Record<string, string>)["SIGNER_PRIVATE"] = rotated.b64; // ROTATE the engine signer mid-run
    const log = await silence(async () => { for (let i = 0; i < 25 && doState.storage.has("doc"); i++) await realDO!.alarm(); });
    ok("INVARIANT: the rotated-signer resume FAILS CLOSED (the checkpoint cannot be unwrapped under the new key)", doState.storage.size === 0);
    const complete = sched.calls.find((c) => c.path === "/complete");
    ok("a failed completion was posted (empty runId), never an ok over a mixed-key root", (complete?.body as { status?: string; runId?: string } | undefined)?.status === "failed" && (complete?.body as { runId?: string } | undefined)?.runId === "");
    ok("the rotation failure stays redacted (no key material / record name leak)", log.every((l) => !l.includes(rotated.b64) && !l.includes(oldSigner.b64) && !l.includes("key/0")));
    ok("INVARIANT: NO signed root was produced under the rotated key over old-key records", !hasRoot(dest, runId));
    const underOld = await archiveOpensComplete(dest, runId, breakGlass.identity, oldSigner.verifier);
    const underNew = await archiveOpensComplete(dest, runId, breakGlass.identity, rotated.verifier);
    ok("INVARIANT: the half-archive is unreadable as complete under EITHER key (no mixed/partial run)", underOld.opened === false && underNew.opened === false);
  }

  // ---- a run that completed wholly under one key verifies under that key ONLY (consistent root) ------
  {
    const sched = makeMockScheduler();
    const dest = new MemDest();
    const runId = newULID(Date.now());
    const kv = new MemKV(SEEDS.slice(0, 12), 100);
    const runsealStub = { async fetch(): Promise<Response> { return new Response(JSON.stringify({ ok: true })); } } as unknown as DurableObjectStub;
    const env = mkEnv(oldSigner.b64, breakGlassB64, kv, sched.stub, runsealStub, dest);
    await sealRunSliced(env, dpState("dp-cmp10ok"), { runId, index: 11, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }), destinationId: "r2-primary" });
    const complete = sched.calls.find((c) => c.path === "/complete");
    ok("a no-rotation run completes ok", (complete?.body as { status?: string } | undefined)?.status === "ok");
    const underOld = await archiveOpensComplete(dest, runId, breakGlass.identity, oldSigner.verifier);
    const underNew = await archiveOpensComplete(dest, runId, breakGlass.identity, rotated.verifier);
    ok("INVARIANT: the completed archive verifies under its CONSISTENT (old) key", underOld.opened && underOld.records === 12);
    ok("INVARIANT: the same archive does NOT verify under a different (rotated) key (single-key root, no ambiguity)", underNew.opened === false);
  }
}

// =====================================================================================================
// CMP-04 — partition-during-apply. A console<->engine partition during a restore APPLY (the engine applied
// but the response was lost, so the console retries). With no idempotency receipt in the apply body
// itself, the no-double-apply guard is the restore-approval state machine: a SINGLE-USE consume + the
// plan-binding hash + the atomic read-modify-write. Drive the REAL approval DO and assert a retried apply
// after a partition cannot re-authorise, a changed plan is refused, and a concurrent double-consume races
// to exactly one winner.
// =====================================================================================================
async function cmp04(): Promise<void> {
  console.log("\nCMP-04 partition-during-apply (no double-apply / no clobber of a changed target):");
  // The restore-approval gate is OWNER-OPT-IN and OFF by default (an unconditional gate locked
  // one-identity estates out of restore entirely). cmp04 exercises the gate, so it arms it.
  const sched = makeRealScheduler();
  await sched.storage.put(ORG_POLICY_KEY, { requireConfigApproval: false, requireRestoreApproval: true });
  // BOTH principals are approvers, and that is deliberate rather than lazy: the self-approval invariant at
  // the end of this section is only worth anything if the maker is a person who COULD have approved. Give
  // the maker only restore.request and their self-approval is refused by the capability gate before the
  // maker != checker rule is ever consulted, so the invariant reads green while grading nothing.
  const maker: Caller = { method: "access", email: "maker@acme.example", subject: "sub|maker", role: "approver", groups: [] };
  const checker: Caller = { method: "access", email: "checker@acme.example", subject: "sub|checker", role: "approver", groups: [] };

  // The two principals must exist in the DO's OWN role table, not merely be asserted on the forwarded
  // caller header. requestRestore/approveRestore trust the router-resolved role (the documented FROM THE
  // ROUTER ONLY trust), but the SPEND is bound to the two identities the record rests on: gateRestore and
  // reserveRestore re-resolve BOTH subjects LIVE from these tables (approvalSpendVerdict ->
  // resolveStoredIdentityAuthority) and refuse an approval whose maker no longer holds restore.request or
  // whose checker no longer holds restore.approve. A fixture that only asserted the role on the header
  // therefore drove an estate where neither principal existed at all: every spend read
  // maker-authority-lapsed, the positive path failed, and the single-use INVARIANTS below passed
  // VACUOUSLY because a refused reserve and a spent reserve both return false. Grant through the real
  // setRole (an owner-token break-glass caller, the engine's own internal owner authority) and then bind
  // each grant to its subject the way a first authentication does, so the spend-time re-resolution finds
  // the same authority the request was made under.
  const bootstrap: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };
  await sched.dobj.setRole({ email: maker.email!, role: "approver" }, bootstrap);
  await sched.dobj.setRole({ email: checker.email!, role: "approver" }, bootstrap);
  const makerBound = await sched.dobj.roleForCaller({ method: "access", email: maker.email, subject: maker.subject, groups: [] });
  const checkerBound = await sched.dobj.roleForCaller({ method: "access", email: checker.email, subject: checker.subject, groups: [] });
  ok("the maker and checker are BOUND in the DO's own role table (the spend-time re-resolution has something to resolve)", makerBound.role === "approver" && checkerBound.role === "approver");

  const planA = await restorePlanHash({ runId: "RUN-A" } as RestoreRequest);
  const planB = await restorePlanHash({ runId: "RUN-B" } as RestoreRequest); // a DIFFERENT plan (changed target)
  ok("two distinct restore plans hash to two distinct binding keys", planA !== planB && planA.startsWith("sha384:") && planB.startsWith("sha384:"));

  await notePlanAnchor(sched.dobj, planA);
  await sched.dobj.requestRestore({ planHash: planA, runId: "RUN-A", reason: "dr drill apply" }, maker);
  await sched.dobj.approveRestore({ planHash: planA }, checker);
  ok("the apply-time gate reports the approval usable BEFORE the apply", (await sched.dobj.gateRestore({ planHash: planA })).usable === true);

  // APPLY #1 succeeds on the engine -> the router RESERVES the approval immediately before the write
  // (HI-03: the atomic gate-to-write reservation, not the read-only gate above), then consumes it on
  // success (single use).
  const firstReserve = await sched.dobj.reserveRestore({ planHash: planA });
  ok("apply #1 reserves the approval immediately before the write", firstReserve.reserved === true);
  const firstConsume = await sched.dobj.consumeApproval({ planHash: planA });
  ok("apply #1 consumes the single-use approval", firstConsume.consumed === true);

  // PARTITION: the apply response is lost; the console retries the SAME apply.
  ok("INVARIANT: the retried apply's gate now reports NOT usable (a consumed approval cannot authorise a second apply)", (await sched.dobj.gateRestore({ planHash: planA })).usable === false);
  const secondReserve = await sched.dobj.reserveRestore({ planHash: planA });
  ok("INVARIANT: the retried apply cannot even reserve a consumed approval (reserved:false)", secondReserve.reserved === false);
  const secondConsume = await sched.dobj.consumeApproval({ planHash: planA });
  ok("INVARIANT: a retried consume after the partition returns consumed:false (atomic single use, no double-apply)", secondConsume.consumed === false);

  // CHANGED TARGET between approval and apply: an apply whose plan differs from what was approved finds no
  // usable approval for its (different) plan hash -> refused. No clobber of a target nobody approved.
  ok("INVARIANT: an apply for a CHANGED plan (different runId/target) is refused (its plan hash has no approval)", (await sched.dobj.gateRestore({ planHash: planB })).usable === false);

  // A FAILED apply does NOT consume, so its approval stays usable for the legitimate retry — that retry is
  // the FIRST real apply, not a double-apply.
  const planC = await restorePlanHash({ runId: "RUN-C" } as RestoreRequest);
  await notePlanAnchor(sched.dobj, planC);
  await sched.dobj.requestRestore({ planHash: planC, runId: "RUN-C", reason: "fails first time" }, maker);
  await sched.dobj.approveRestore({ planHash: planC }, checker);
  ok("a failed apply (never consumed) leaves the approval usable for the legitimate retry", (await sched.dobj.gateRestore({ planHash: planC })).usable === true);

  // A concurrent double-consume (two engine invocations of the same retried apply racing) must produce
  // EXACTLY ONE winner: the DO is single-threaded, so the second read-modify-write sees `consumed`. The
  // reservation (HI-03) is taken once first, mirroring the router's reserve-immediately-before-the-write,
  // then both consume calls race against that SAME reservation.
  const reserveC = await sched.dobj.reserveRestore({ planHash: planC });
  ok("the retry's apply reserves the approval before racing the consume", reserveC.reserved === true);
  const [c1, c2] = await Promise.all([sched.dobj.consumeApproval({ planHash: planC }), sched.dobj.consumeApproval({ planHash: planC })]);
  ok("INVARIANT: a concurrent double-consume yields exactly ONE winner (atomic RMW, no double-apply)", [c1.consumed, c2.consumed].filter(Boolean).length === 1);

  // The two-identity guard underneath it all: a self-approval (maker == checker by SUBJECT) is refused, so
  // a single party can never both authorise and apply a restore.
  const planD = await restorePlanHash({ runId: "RUN-D" } as RestoreRequest);
  await notePlanAnchor(sched.dobj, planD);
  await sched.dobj.requestRestore({ planHash: planD, runId: "RUN-D", reason: "self-approval attempt" }, maker);
  let selfApproveRefused = false;
  try {
    await sched.dobj.approveRestore({ planHash: planD }, maker);
  } catch (e) {
    selfApproveRefused = e instanceof Error && /cannot approve your own request/.test(e.message);
  }
  ok("INVARIANT: a self-approval (maker == checker) is refused (no single-party apply)", selfApproveRefused);

  // THE CONTROL ON EVERY "usable === true" ABOVE. A gate that answered `usable` for the wrong reason, or a
  // spend-time binding that had quietly stopped resolving anything, would leave this whole section reading
  // green: a refused reserve and an already-spent reserve are the same `false`, so the single-use invariants
  // would pass identically against an estate where nobody can spend anything at all. Drive the
  // discriminator: approve a plan, confirm it is usable, then OFFBOARD the checker and confirm the SAME
  // plan flips to not usable, classified as the checker's authority lapsing rather than the flat
  // not-approved every other cause collapses into.
  const planE = await restorePlanHash({ runId: "RUN-E" } as RestoreRequest);
  await notePlanAnchor(sched.dobj, planE);
  await sched.dobj.requestRestore({ planHash: planE, runId: "RUN-E", reason: "spend-time binding control" }, maker);
  await sched.dobj.approveRestore({ planHash: planE }, checker);
  ok("the control plan is usable while both identities still hold their authority", (await sched.dobj.gateRestore({ planHash: planE })).usable === true);
  await sched.dobj.deleteRole({ email: checker.email! }, bootstrap);
  ok("INVARIANT: offboarding the CHECKER makes their already-approved plan unusable (spend-time identity binding is live)", (await sched.dobj.gateRestore({ planHash: planE })).usable === false);
  ok("INVARIANT: offboarding the CHECKER also refuses the reserve, the authoritative gate adjacent to the write", (await sched.dobj.reserveRestore({ planHash: planE })).reserved === false);
  const refusals = (await sched.storage.get<Record<string, { count: number }>>("diag:governancerefusals")) ?? {};
  ok("the refusal is classified as the checker's lapse, not a flat not-approved", (refusals["restore-apply|checker-authority-lapsed"]?.count ?? 0) >= 1);

  // The audit chain is intact across all of the above (the control plane is not corrupted by the churn).
  ok("the control plane is intact: the approval records persisted under their binding keys", sched.storage.map.has(`approval:${planA}`) && sched.storage.map.has(`approval:${planC}`) && sched.storage.map.has(`approval:${planD}`));
}

async function main(): Promise<void> {
  const old = await freshSigner();
  const breakGlass = makeRecipient("break-glass");
  const breakGlassB64 = b64urlEncode(concat(breakGlass.entry.pub.x25519, breakGlass.entry.pub.mlkemEk));

  await cmp01(old.b64, breakGlassB64, breakGlass, old.verifier);
  await cmp05(old.b64, breakGlassB64, breakGlass, old.signer, old.verifier);
  await cmp09(old.b64, breakGlassB64, breakGlass, old.verifier);
  await cmp10({ b64: old.b64, verifier: old.verifier }, breakGlassB64, breakGlass);
  await cmp04();

  console.log(failures === 0 ? "\nCMP COMPOUND-FAULT ENGINE PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
