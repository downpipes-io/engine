// Prove the contended single-RUNLOG path no longer SHEDS runs under a concurrent trigger storm.
// In-memory doubles only, no network/deploy/cost. Run:
//   node test/validate-runlog-contention.ts
//
// Why this exists: a ~30-way concurrent finaliser storm exhausted
// the account-global RUNLOG's 6-attempt CAS and STRUCK ~1/3 of the runs to terminal failure ("runlog write
// contended"), orphaning committed run-trees. The fix turns that loud shed into bounded cross-invocation
// QUEUEING:
//   - PER-DESTINATION lock keying (scheduler-do.ts): finalisers writing different destinations take
//     different lock slots and never serialise on each other, so a storm spreads across slots.
//   - a PATIENT lock acquire (pipeline.ts patientAcquire): a waiter takes its turn in the single-threaded
//     DO rather than barging the CAS; the lock-free CAS remains the backstop.
//   - a TYPED RunlogContendedError on CAS exhaustion so the sliced DO PARKS the run (checkpoint preserved,
//     idempotent resume) instead of striking it dead (the park branch is proven in validate-slice.ts).
//
// What this proves (each via a NEGATIVE control, not a vacuous assert):
//  - per-destination independence: a lock held on destination A does NOT block destination B (they take
//    different DO slots), while a SECOND acquire on A is still refused (same-destination serialisation);
//  - the per-destination key reaches storage (the lease lands under runlogLock:<dest>, the default slot
//    stays free) and the wire carries the key on acquire AND release;
//  - the per-slot lease bounds a CRASHED holder: an expired destination-A lease is reclaimable without a
//    release, the reclaimed token differs, and destination B is untouched throughout;
//  - the PATIENT acquire is patient: appendRunlog waits across a briefly-held lock and still commits (it
//    does not abandon the write after one barge);
//  - DETERMINISTIC CAS-fail: a RUNLOG whose conditional write can never land throws the TYPED
//    RunlogContendedError (the park signal) — both when the lock is held the whole window AND lock-free;
//  - supersede (the prune writer) raises the SAME typed error on sustained contention;
//  - a LARGE pre-seeded RUNLOG appends cleanly with exactly ONE lock acquire and ONE conditional write (no
//    CAS storm at scale).

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { appendRunlog, supersedeRunlog, RunlogContendedError, type RunlogLock } from "../src/seal/pipeline.ts";
import { runlogLockVia } from "../src/seal/runstate-helpers.ts";
import { signRunlog, parseRunlog, type RunlogEntry, type Signer } from "../src/format/writer.ts";
import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import { mldsaKeygen } from "../src/crypto/pq.ts";
import { b64urlEncode, utf8 } from "../src/crypto/bytes.ts";

const RUNLOG_KEY = "_RECOVERY/RUNLOG";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

interface StoredLock {
  token: string;
  expiresAt: number;
}

function makeScheduler(): { storage: MockStorage; stub: DurableObjectStub } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  // A DurableObjectStub facade that routes fetch() at the real SchedulerDO (so runlogLockVia drives the
  // real acquire/release handlers, including the per-destination slot keying, with no network).
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => dobj.fetch(new Request(input instanceof Request ? input.url : String(input), init)),
  } as unknown as DurableObjectStub;
  return { storage, stub };
}

// ---- An in-memory Destination with ETag optimistic concurrency (pipeline-runlog.ts shape) -
class MemoryDestination implements Destination {
  private mapStore = new Map<string, { body: Uint8Array; etag: string }>();
  private counter = 0;
  // When failConditional is set, EVERY putConditional reports a precondition failure (ok:false) so a test
  // can drive the CAS to exhaustion deterministically (no real concurrency needed).
  failConditional = false;
  putConditionalCalls = 0;
  private nextEtag(): string {
    return `"${++this.counter}"`;
  }
  async get(key: string): Promise<GetResult | null> {
    const v = this.mapStore.get(key);
    return v ? { body: v.body, etag: v.etag } : null;
  }
  async put(key: string, body: Uint8Array): Promise<void> {
    this.mapStore.set(key, { body, etag: this.nextEtag() });
  }
  async putStream(_key: string, _body: ReadableStream<Uint8Array>): Promise<void> {
    throw new Error("not used");
  }
  async putConditional(key: string, body: Uint8Array, opts: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult> {
    this.putConditionalCalls++;
    if (this.failConditional) return { ok: false };
    const cur = this.mapStore.get(key);
    if (opts.ifNoneMatch === "*" && cur) return { ok: false };
    if (opts.ifMatch && (!cur || cur.etag !== opts.ifMatch)) return { ok: false };
    const etag = this.nextEtag();
    this.mapStore.set(key, { body, etag });
    return { ok: true, etag };
  }
  async exists(key: string): Promise<boolean> {
    return this.mapStore.has(key);
  }
  async delete(key: string): Promise<void> {
    this.mapStore.delete(key);
  }
  async list(prefix: string): Promise<string[]> {
    return [...this.mapStore.keys()].filter((k) => k.startsWith(prefix));
  }
}

async function realSigner(): Promise<Signer> {
  const ed = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  return { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };
}

function entryFor(dp: string, index: number, prev: string | null): RunlogEntry {
  return { index, runId: `R${dp}-${index}`, downpipeId: dp, time: "2026-06-28T00:00:00.000Z", recordCount: 1, prevRunId: prev, status: "active" };
}

// ---- TC-1: per-destination independence + same-destination serialisation -----------------
async function testPerDestIndependence(): Promise<void> {
  console.log("\nindependent destinations take independent lock slots (no cross-destination serialisation):");
  const { stub, storage } = makeScheduler();
  const lockA = runlogLockVia(stub, "destA");
  const lockB = runlogLockVia(stub, "destB");

  const tokA = await lockA.acquire();
  const tokB = await lockB.acquire();
  ok("destination A acquires its lock", typeof tokA === "string" && (tokA as string).length > 0);
  ok("destination B acquires CONCURRENTLY while A is held (different slot, not serialised)", typeof tokB === "string" && (tokB as string).length > 0);
  ok("the two destinations hold DIFFERENT tokens", tokA !== tokB);

  // Same-destination serialisation is the negative control: a SECOND acquire on A while held is refused.
  const tokA2 = await lockA.acquire();
  ok("a second acquire on destination A while held is refused (same-destination serialisation)", tokA2 === null);

  // The keying reaches storage: A's lease is under its own slot, B's under its own, the default slot free.
  ok("destination A's lease persists under runlogLock:destA", storage.has("runlogLock:destA"));
  ok("destination B's lease persists under runlogLock:destB", storage.has("runlogLock:destB"));
  ok("the default (unkeyed) slot is untouched by the keyed locks", !storage.has("runlogLock"));

  await lockA.release(tokA as string);
  ok("releasing destination A frees ONLY its slot (B still held)", !storage.has("runlogLock:destA") && storage.has("runlogLock:destB"));
  // After A is freed it is acquirable again; B is unaffected.
  const tokA3 = await lockA.acquire();
  ok("destination A is re-acquirable once released", typeof tokA3 === "string");
  await lockA.release(tokA3 as string);
  await lockB.release(tokB as string);
}

// ---- TC-2: the per-slot lease bounds a crashed holder, per destination -------------------
async function testPerSlotLeaseReclaim(): Promise<void> {
  console.log("\na crashed holder's per-destination lease is reclaimable without leaking across destinations:");
  const { stub, storage } = makeScheduler();
  const lockA = runlogLockVia(stub, "destA");
  const lockB = runlogLockVia(stub, "destB");

  const heldA = await lockA.acquire();
  ok("destination A is held", typeof heldA === "string");
  // While A's lease is fresh, a re-acquire is refused (the lock really is held).
  ok("a fresh destination-A lease refuses a re-acquire", (await lockA.acquire()) === null);

  // Backdate A's lease into the past (a crashed holder that never released), exactly as validate-runlog-lock
  // ages the default slot; then a new acquire reclaims A. B was never touched.
  const cur = storage.rawGet<StoredLock>("runlogLock:destA");
  if (!cur) throw new Error("test bug: expected destA lease");
  cur.expiresAt = Date.now() - 1000;
  storage.rawPut("runlogLock:destA", cur);

  const reclaimed = await lockA.acquire();
  ok("an expired destination-A lease is reclaimable by a new acquire (crashed holder)", typeof reclaimed === "string");
  ok("the reclaimed token differs from the abandoned one", reclaimed !== heldA);
  ok("destination B was never created by destination A's churn", !storage.has("runlogLock:destB"));
  // B is independently acquirable throughout.
  const tokB = await lockB.acquire();
  ok("destination B acquires cleanly despite destination A's reclaim churn", typeof tokB === "string");
  await lockA.release(reclaimed as string);
  await lockB.release(tokB as string);
}

// ---- TC-3: the patient acquire waits across a briefly-held lock and still commits --------
async function testPatientAcquireWaitsThenWins(): Promise<void> {
  console.log("\nthe patient acquire waits for a briefly-held lock rather than abandoning the write:");
  const signer = await realSigner();
  const dest = new MemoryDestination();
  // A lock that is "held" for the first two acquire attempts (returns null), then frees (returns a token):
  // the patient ladder must keep trying and TAKE it, not give up after one barge.
  let attempts = 0;
  let released = false;
  const lock: RunlogLock = {
    acquire: async () => {
      attempts++;
      return attempts <= 2 ? null : "tok";
    },
    release: async (_t: string) => {
      released = true;
    },
  };
  await appendRunlog(dest, signer, entryFor("dp", 1, null), lock, { relinkLocalPrev: true });
  ok("the patient acquire retried past the briefly-held lock (>=3 attempts)", attempts >= 3);
  ok("the RUNLOG was written once the lock freed", (await dest.get(RUNLOG_KEY)) !== null);
  ok("the taken lock was released after the write", released);
}

// ---- TC-4: deterministic CAS-fail raises the TYPED RunlogContendedError (the park signal) -
async function testDeterministicCasFail(): Promise<void> {
  console.log("\na RUNLOG whose conditional write can never land throws the TYPED contended error (park signal):");
  const signer = await realSigner();

  // (a) lock held the WHOLE window (acquire always null) + a dest that always fails the CAS -> the lock-free
  // backstop runs and exhausts, throwing RunlogContendedError (NOT a generic Error, so the DO parks it).
  {
    const dest = new MemoryDestination();
    dest.failConditional = true;
    const heldLock: RunlogLock = { acquire: async () => null, release: async () => {} };
    let caught: unknown;
    try {
      await appendRunlog(dest, signer, entryFor("dp", 1, null), heldLock, { relinkLocalPrev: true });
    } catch (e) {
      caught = e;
    }
    ok("a lock-held + un-committable CAS throws RunlogContendedError (typed park signal)", caught instanceof RunlogContendedError);
    ok("the CAS was actually attempted multiple times before giving up", dest.putConditionalCalls >= 2);
  }

  // (b) NO lock at all (the buffered/canary path) + always-fail CAS -> still the TYPED contended error.
  {
    const dest = new MemoryDestination();
    dest.failConditional = true;
    let caught: unknown;
    try {
      await appendRunlog(dest, signer, entryFor("dp", 1, null), undefined, { relinkLocalPrev: true });
    } catch (e) {
      caught = e;
    }
    ok("a lock-FREE un-committable CAS also throws RunlogContendedError", caught instanceof RunlogContendedError);
  }
}

// ---- TC-5: supersede (the prune writer) raises the same typed error on sustained contention
async function testSupersedeContended(): Promise<void> {
  console.log("\nthe prune RUNLOG re-sign raises the TYPED contended error under sustained contention:");
  const signer = await realSigner();
  const dest = new MemoryDestination();
  // Seed a real RUNLOG with one active entry so supersede has something to mark (an empty RUNLOG is a no-op).
  const { runlog, sig } = await signRunlog([entryFor("dp", 1, null)], signer.edPrivate, signer.mldsaSecret);
  await dest.put(RUNLOG_KEY, runlog);
  await dest.put(`${RUNLOG_KEY}.sig`, utf8(b64urlEncode(sig)));
  // Now make every conditional re-sign fail: supersede's CAS exhausts -> typed contended error.
  dest.failConditional = true;
  let caught: unknown;
  try {
    await supersedeRunlog(dest, signer, ["Rdp-1"], undefined);
  } catch (e) {
    caught = e;
  }
  ok("supersede throws RunlogContendedError on sustained contention (prune retries next tick, idempotent)", caught instanceof RunlogContendedError);
}

// ---- TC-6: a LARGE pre-seeded RUNLOG appends cleanly with ONE acquire and ONE write ------
async function testLargePreseededRunlog(): Promise<void> {
  console.log("\na large pre-seeded RUNLOG appends with a single lock acquire and a single conditional write (no CAS storm):");
  const signer = await realSigner();
  const dest = new MemoryDestination();
  // Pre-seed 1500 entries for OTHER downpipes (relinkLocalPrev only touches the appended downpipe's chain,
  // so the pre-seeded chain is left intact) to model a busy account whose RUNLOG is already large.
  const N = 1500;
  const seeded: RunlogEntry[] = [];
  for (let i = 1; i <= N; i++) seeded.push(entryFor(`other${i % 7}`, i, null));
  const { runlog, sig } = await signRunlog(seeded, signer.edPrivate, signer.mldsaSecret);
  await dest.put(RUNLOG_KEY, runlog);
  await dest.put(`${RUNLOG_KEY}.sig`, utf8(b64urlEncode(sig)));

  // A simple in-memory granted lock (acquire succeeds first try) to prove the steady-state cost: exactly
  // one acquire + one conditional write, no CAS retry loop, even with a 1500-entry RUNLOG.
  let acquires = 0;
  let held = false;
  const lock: RunlogLock = {
    acquire: async () => {
      if (held) return null;
      held = true;
      acquires++;
      return "tok";
    },
    release: async (_t: string) => {
      held = false;
    },
  };
  const before = dest.putConditionalCalls;
  await appendRunlog(dest, signer, entryFor("dpNew", N + 1, null), lock, { relinkLocalPrev: true });
  const after = await dest.get(RUNLOG_KEY);
  const entries = after ? parseRunlog(after.body) : [];
  ok("the append landed with EXACTLY one lock acquire (no acquire storm)", acquires === 1);
  ok("the append committed in EXACTLY one conditional write (no CAS retry loop at scale)", dest.putConditionalCalls - before === 1);
  ok("the large RUNLOG now carries all 1501 entries", entries.length === N + 1);
  ok("the newly-appended run is present", entries.some((e) => e.runId === `RdpNew-${N + 1}`));
  ok("every pre-seeded entry survived the append", entries.filter((e) => e.downpipeId.startsWith("other")).length === N);
}

async function main(): Promise<void> {
  await testPerDestIndependence();
  await testPerSlotLeaseReclaim();
  await testPatientAcquireWaitsThenWins();
  await testDeterministicCasFail();
  await testSupersedeContended();
  await testLargePreseededRunlog();

  console.log(failures === 0 ? "\nRUNLOG-CONTENTION VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
