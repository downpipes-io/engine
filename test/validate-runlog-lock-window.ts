// validate-runlog-lock-window: the patient RUNLOG lock-acquire ladder (src/seal/pipeline.ts
// patientAcquire) is sized to outlast a real append's hold, not just a CAS backoff gap.
//
// THE DEFECT (a known issue for 0.3.8). A holder keeps the per-destination RUNLOG lock for one append: a
// read plus a conditional write, 4 to 5 destination round-trips, hundreds of milliseconds. The ladder slept
// at most RUNLOG_LOCK_WAIT_BASE_MS*(2^0+2^1+2^2) = 10+20+40 = 70ms across its (then) 4 attempts, so any
// overlap with a real append sent the waiter lock-free into the CAS before the holder had released
// (measured: lockWindowExhausted counted once in a clean round, with no other fault).
//
// THE FIX, WITHOUT SPENDING EXTRA SUBREQUESTS. The attempt count stays at 4 (FINALISE_LOCK_OPS in
// budget.ts stays 4, FINALISE_RESERVE stays 40), but each wait is longer AND equal-jittered (a guaranteed
// floor, not full jitter's chance of a near-zero draw): base 200ms, cap 800ms. The 3 waits are then at
// LEAST 100+200+400 = 700ms and at MOST 200+400+800 = 1400ms, comfortably past a worst-case append hold on
// every draw. This file proves it against the real exported appendRunlog, with a RunlogLock stub held for a
// FIXED 600ms (inside the new minimum, outside the old maximum) and a simulated clock + setTimeout so the
// test runs instantly rather than actually sleeping:
//   1. The waiter ACQUIRES the lock (the stub's release is called with the token it issued), not lock-free.
//   2. noteLockPlane("windowExhausted") is NOT counted for this append (src/seal/run-observations.ts).
//
// SECOND SCENARIO: a lock held for the WHOLE waiter window (longer than the 1400ms maximum), on a finalise
// whose slice wall budget is nearly spent. patientAcquire takes an optional SliceBudget (threaded from
// appendRunlog's opts) and stops waiting once the budget's remaining wall time falls to or below
// LOCK_WAIT_WALL_FLOOR_MS, rather than sleeping through it: the waiter goes lock-free at once, the append
// still completes (or would park cleanly under real contention), and the wait never pushes the finalise
// past its wall budget.
//
// Run: node test/validate-runlog-lock-window.ts

import { mldsaKeygen } from "../src/crypto/pq.ts";
import { parseRunlog, type RunlogEntry, type Signer } from "../src/format/writer.ts";
import { appendRunlog, type RunlogLock } from "../src/seal/pipeline.ts";
import { SliceBudget } from "../src/seal/budget.ts";
import { beginRunObservations, runObservations } from "../src/seal/run-observations.ts";
import { MemoryDestination } from "./memdest.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- a simulated clock: Date.now() and setTimeout both run off `skew`, advanced by setTimeout's own
// requested delay, so the ladder's real sleeps resolve INSTANTLY but the delay values it asked for still
// move the clock the ladder itself reads (Date.now() inside the stub's acquire()). ----
const realNow = Date.now.bind(Date);
const realSetTimeout = globalThis.setTimeout;
let skew = 0;
function install(): void {
  Date.now = () => realNow() + skew;
  globalThis.setTimeout = ((cb: () => void, ms?: number) => {
    skew += ms ?? 0;
    queueMicrotask(cb);
    return 0 as unknown as ReturnType<typeof setTimeout>;
  }) as typeof setTimeout;
}
function uninstall(): void {
  Date.now = realNow;
  globalThis.setTimeout = realSetTimeout;
}

// HeldLock is held by another "writer" for exactly HOLD_MS from construction: acquire() refuses
// (acquired:false -> null) until the simulated clock passes heldUntil, then grants a fresh token. release()
// just records the token it was given, so the test can tell a real acquire (release called) from a
// lock-free fallback (release never called, because appendRunlog only releases what it acquired).
const HOLD_MS = 600;
class HeldLock implements RunlogLock {
  private readonly heldUntil: number;
  acquireCalls = 0;
  releasedWith: string | undefined;
  constructor() {
    this.heldUntil = Date.now() + HOLD_MS;
  }
  async acquire(): Promise<string | null> {
    this.acquireCalls++;
    if (Date.now() < this.heldUntil) return null; // another writer still holds it
    return `tok-${this.acquireCalls}`;
  }
  async release(token: string): Promise<void> {
    this.releasedWith = token;
  }
}

function entry(runId: string): RunlogEntry {
  return { index: 1, runId, downpipeId: "dp-lockwindow", time: "2026-09-27T08:00:00.000Z", recordCount: 1, prevRunId: null, status: "active" };
}

// NeverLock is held for the WHOLE run: acquire() always refuses. It models a lock that outlasts the entire
// waiter window (longer than the 1400ms maximum), the scenario the wall-budget floor exists for.
class NeverLock implements RunlogLock {
  acquireCalls = 0;
  async acquire(): Promise<string | null> {
    this.acquireCalls++;
    return null;
  }
  async release(): Promise<void> {
    throw new Error("release must never be called: appendRunlog only releases a token it acquired");
  }
}

async function main(): Promise<void> {
  console.log("-- the patient ladder outlasts a fixed 600ms lock hold: the waiter acquires, not lock-free --");

  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  const signer: Signer = { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };

  install();
  try {
    beginRunObservations();
    const dest = new MemoryDestination();
    const lock = new HeldLock();
    await appendRunlog(dest, signer, entry("run-lockwindow-1"), lock);

    ok("the waiter's acquire() was eventually called past the 600ms hold (sanity: the stub did grant a token)", lock.acquireCalls > 0);
    ok("the waiter ACQUIRED the lock (release was called with the token the stub issued), not lock-free", lock.releasedWith !== undefined && lock.releasedWith === `tok-${lock.acquireCalls}`);
    const obs = runObservations();
    ok("windowExhausted was NOT counted for this append (the ladder did not exhaust its window)", obs.lock.windowExhausted === 0);
    ok("acquireFaults stayed at 0 (the stub never threw)", obs.lock.acquireFaults === 0);
  } finally {
    uninstall();
  }

  console.log("-- a lock held for the WHOLE window, on a slice whose wall budget is nearly spent: no extra wait, no hang --");
  install();
  try {
    beginRunObservations();
    const dest = new MemoryDestination();
    const lock = new NeverLock();
    // A slice budget with 1000ms of wall allowance, already 600ms spent by the time this append runs (the
    // seal work before finalisation): 400ms left, BELOW LOCK_WAIT_WALL_FLOOR_MS (500ms). patientAcquire
    // must see this on its very first check and go lock-free at once, never sleeping at all.
    const budget = new SliceBudget({ wallMs: 1000 });
    skew += 600;
    const skewBefore = skew;

    let threw: unknown;
    try {
      await appendRunlog(dest, signer, entry("run-lockwindow-2"), lock, { budget });
    } catch (e) {
      threw = e;
    }

    ok("the append did not throw: it completed lock-free rather than hanging or striking the run", threw === undefined);
    ok("the waiter stopped BEFORE exhausting the ladder's attempts (the wall floor cut it short, not the attempt count)", lock.acquireCalls > 0 && lock.acquireCalls < 4);
    ok("NO extra wait was added: the simulated clock did not advance (patientAcquire never slept)", skew === skewBefore);
    const obs = runObservations();
    ok("windowExhausted WAS counted (the ladder stopped itself on the wall floor)", obs.lock.windowExhausted === 1);
    const rl = await dest.get("_RECOVERY/RUNLOG");
    const entries = rl ? parseRunlog(rl.body) : [];
    ok("the append still landed (lock-free CAS completed the write)", entries.some((e) => e.runId === "run-lockwindow-2"));
  } finally {
    uninstall();
  }

  console.log(failures === 0 ? "\nRUNLOG LOCK WINDOW PASS\n" : `\nRUNLOG LOCK WINDOW FAIL (${failures})\n`);
  verdictReached(failures);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
