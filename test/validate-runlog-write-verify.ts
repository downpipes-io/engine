// Every RUNLOG writer verifies what it read before it changes or re-signs anything (seal/pipeline.ts
// verifyRunlogForWrite): the signature under the engine's own key, the chain the write rewrites, and the
// destination's anti-rollback floor, which the writers read from their per-destination lock.
// test/validate-runlog-resign-verify.ts holds the refuter's cases (a changed or removed entry on the seal,
// prune and mirror paths). This validator adds:
//   - POSITIVE CONTROL: an unaltered RUNLOG with its floor seals, prunes and mirrors as before;
//   - the crash window: a write that stopped after the body resumes from the pending signature; with the
//     pending signature also lost, the next write refuses (RunlogIntegrityError sig-invalid), never re-signs;
//   - a deleted RUNLOG where the floor is above 0: the seal and the prune refuse to start a fresh log; with
//     floor 0 (a fresh destination) the first seal creates it as before;
//   - a replayed older signed RUNLOG (rollback): below the floor, the seal and the prune refuse;
//   - the prune's no-op hole: entries pre-flipped to superseded in an unverified body are refused before the
//     prune can read "nothing to change" and go on to delete;
//   - the chain rule: the append refuses to relink a chain that is already anomalous, and leaves another
//     downpipe's chain to the reader;
//   - the index rule: the append refuses an index that another run in the destination's RUNLOG already holds,
//     whichever downpipe holds it, and records a duplicate-index anomaly instead of writing the duplicate;
//   - the floor rule: a floor the lock returns that is not a whole number above zero is refused, never skipped;
//   - the lost-write rule: a winner whose signature has not yet landed is contention, so the writer backs off
//     and appends, and ends as RunlogContendedError (never an integrity refusal) if it never lands;
//   - the relink rule: it orders one downpipe's chain by index, leaves other downpipes alone, and a writer
//     that does not relink keeps the entry's own prev;
//   - replication: a mirror refuses an entry whose index disagrees with the run's signed root;
//   - the run row names the refusal (coarseRunError), not contention;
//   - the refusal text: each signature refusal and the index refusal say what is wrong, and the two signature
//     refusals say different things;
//   - a correctly signed RUNLOG whose body does not parse is refused as "unparsable" (never a raw parse error),
//     with a parse-field anomaly that carries the digest;
//   - a floor read that throws is no floor, and the failed read reaches the site-fault ledger as runlog.floor-read.
//
// Run: node test/validate-runlog-write-verify.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { peekSiteFaults } from "../src/admin/site-faults.ts";
import { b64urlDecode, b64urlEncode, utf8 } from "../src/crypto/bytes.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import { type HybridVerifier, hybridSign, hybridVerify } from "../src/crypto/sign.ts";
import { drainIntegrityFaultLedger, resetIntegrityFaultLedger } from "../src/format/integrity-fault-ledger.ts";
import { parseRunlog, type RecipientEntry, type RunlogEntry, type Signer, signRunlog } from "../src/format/writer.ts";
import { appendRunlog, type RunClock, type RunConfig, RunlogContendedError, RunlogIntegrityError, type RunlogLock, readFloor, runBackup, supersedeRunlog, verifyRunlogForWrite } from "../src/seal/pipeline.ts";
import { applyPrune, type PrunePlan } from "../src/seal/prune.ts";
import { mirrorRunToReplica } from "../src/seal/replicate.ts";
import { coarseRunError } from "../src/seal/slice.ts";
import type { Selector, SourceAdapter, SourceRecord } from "../src/sources/types.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { MemoryDestination } from "./memdest.ts";

const RUNLOG = "_RECOVERY/RUNLOG";
const RUNLOG_SIG = "_RECOVERY/RUNLOG.sig";
const RUNLOG_PENDING = "_RECOVERY/RUNLOG.sig.pending";
const DP = "dp_write_verify";
const R = (n: number): string => `01ARZ3NDEKTSV4RRFFQ69G5FF${n}`;

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean, detail?: unknown): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) {
    failures++;
    if (detail !== undefined) console.log(`         ${JSON.stringify(detail).slice(0, 300)}`);
  }
}
const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));

class OneRecordSource implements SourceAdapter {
  readonly sourceType = "kv" as const;
  async *crawl(_sel: Selector): AsyncIterable<SourceRecord> {
    yield { sourceType: "kv", name: "k", value: utf8("v"), namespace: "ns" };
  }
  async estimate(): Promise<{ records: number; bytes: number }> {
    return { records: 1, bytes: -1 };
  }
}
class CrashingDestination extends MemoryDestination {
  failNextPutOf: string | null = null;
  override async put(key: string, body: Uint8Array): Promise<void> {
    if (this.failNextPutOf === key) {
      this.failNextPutOf = null;
      throw new Error(`simulated crash before PUT ${key}`);
    }
    return super.put(key, body);
  }
}

// A destination where a concurrent winner takes the RUNLOG between this writer's read and its conditional write.
// The winner's body lands at once. Its signature lands only after `sigLandsAfterReads` further reads of the body
// (Infinity: never), and until then the stored .sig is absent or the stale one for the previous body.
class WinnerDestination extends MemoryDestination {
  winner: { body: Uint8Array; sig: Uint8Array } | null = null;
  sigMode: "absent" | "stale" = "absent";
  sigLandsAfterReads = 2;
  private readsSinceLoss = -1;
  override async get(key: string) {
    if (key === RUNLOG && this.readsSinceLoss >= 0) {
      this.readsSinceLoss++;
      if (this.winner && this.readsSinceLoss === this.sigLandsAfterReads) await super.put(RUNLOG_SIG, this.winner.sig);
    }
    return super.get(key);
  }
  override async putConditional(key: string, body: Uint8Array, opts: { ifMatch?: string; ifNoneMatch?: string }) {
    if (key === RUNLOG && this.winner && this.readsSinceLoss < 0) {
      await super.put(RUNLOG, this.winner.body);
      if (this.sigMode === "absent") await super.delete(RUNLOG_SIG);
      this.readsSinceLoss = 0;
      return { ok: false as const };
    }
    return super.putConditional(key, body, opts);
  }
}

async function makeSigner(): Promise<Signer> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const m = mldsaKeygen();
  return { edPrivate: ed.privateKey, edPublic: new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey)), mldsaSecret: m.secretKey, mldsaPublic: m.publicKey };
}
function recipient(role: string): RecipientEntry {
  const xk = x25519.keygen();
  return { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(rand(64)).encapKey } };
}
// A per-destination lock whose floor is set by the test, as runlogLockVia reads it from the scheduler DO.
function lockWithFloor(floor: number | undefined): RunlogLock {
  return { acquire: async () => "tok", release: async () => {}, floor: async () => floor };
}

async function sigVerifies(dest: MemoryDestination, v: HybridVerifier): Promise<boolean> {
  const body = await dest.get(RUNLOG);
  const sig = await dest.get(RUNLOG_SIG);
  if (!body || !sig) return false;
  try {
    return await hybridVerify(v, body.body, b64urlDecode(new TextDecoder().decode(sig.body).trim()));
  } catch {
    return false;
  }
}
async function throwsIntegrity(fn: () => Promise<unknown>, reason: string): Promise<{ ok: boolean; got: string }> {
  try {
    await fn();
    return { ok: false, got: "no throw" };
  } catch (e) {
    return { ok: e instanceof RunlogIntegrityError && e.reason === reason, got: e instanceof RunlogIntegrityError ? `RunlogIntegrityError ${e.reason}` : String((e as Error).message).slice(0, 120) };
  }
}

async function main(): Promise<void> {
  const signer = await makeSigner();
  const v: HybridVerifier = { ed: signer.edPublic, mldsa: signer.mldsaPublic };
  const cfg: RunConfig = { downpipeId: DP, downpipeName: "wv", cadence: "3600s", selector: { include: [], exclude: [] }, recipients: [recipient("break-glass"), recipient("operational")] };
  const seal = (dest: MemoryDestination, n: number, prev: string | null, lock?: RunlogLock) =>
    runBackup([new OneRecordSource()], cfg, signer, dest, { randomNonce: () => rand(16), randomSalt: () => rand(16), runId: R(n), runlogIndex: n, prevRunId: prev, now: `2026-10-01T0${n}:00:00.000Z`, master: rand(32) } as RunClock, lock);
  const threeRuns = async (): Promise<MemoryDestination> => {
    const d = new CrashingDestination();
    await seal(d, 1, null, lockWithFloor(undefined));
    await seal(d, 2, R(1), lockWithFloor(1));
    await seal(d, 3, R(2), lockWithFloor(2));
    return d;
  };

  console.log("-- POSITIVE CONTROL: an unaltered RUNLOG with its floor seals, prunes and mirrors as before --");
  {
    const d = await threeRuns();
    let threw: unknown = null;
    try {
      await seal(d, 4, R(3), lockWithFloor(3));
    } catch (e) {
      threw = e;
    }
    ok("a fresh destination (floor 0) created the RUNLOG, and three more seals appended under their floors", threw === null && parseRunlog((await d.get(RUNLOG))!.body).length === 4, threw);
    ok("the RUNLOG verifies under the engine key", await sigVerifies(d, v));
    const plan: PrunePlan = { downpipeId: DP, retainedRunIds: [R(2), R(3), R(4)], supersededRunIds: [R(1)], runTreeObjects: [], orphanSegs: [], reclaimableBytes: 0, retainedUnreadableCount: 0, supersededSkippedCount: 0, unparseableTimeCount: 0 };
    const pr = await applyPrune(d, signer, plan, lockWithFloor(4));
    ok("the prune under the floor supersedes run 1", pr.superseded === 1 && parseRunlog((await d.get(RUNLOG))!.body).some((e) => e.runId === R(1) && e.status === "superseded"));
    const replica = new MemoryDestination();
    await seal(replica, 1, null, lockWithFloor(undefined));
    const entry = parseRunlog((await d.get(RUNLOG))!.body).find((e) => e.runId === R(2))!;
    const m = await mirrorRunToReplica(d, replica, signer, entry, { verify: true, verifySegments: false, lock: lockWithFloor(1) });
    ok("the mirror (verify on) appends run 2 to the replica", !m.alreadyDone && parseRunlog((await replica.get(RUNLOG))!.body).some((e) => e.runId === R(2)) && (await sigVerifies(replica, v)));
  }

  console.log("\n-- the crash window --");
  {
    const d = (await threeRuns()) as CrashingDestination;
    d.failNextPutOf = RUNLOG_SIG;
    try {
      await seal(d, 4, R(3), lockWithFloor(3));
    } catch {
      /* the crash between the body and the .sig */
    }
    ok("CONTROL: the crash left a body the stored .sig does not cover", !(await sigVerifies(d, v)));
    let threw: unknown = null;
    try {
      await seal(d, 5, R(4), lockWithFloor(3));
    } catch (e) {
      threw = e;
    }
    ok("the next seal resumes from the pending signature and appends", threw === null && parseRunlog((await d.get(RUNLOG))!.body).some((e) => e.runId === R(5)) && (await sigVerifies(d, v)), threw);

    const lost = (await threeRuns()) as CrashingDestination;
    lost.failNextPutOf = RUNLOG_SIG;
    try {
      await seal(lost, 4, R(3), lockWithFloor(3));
    } catch {
      /* the crash */
    }
    await lost.delete(RUNLOG_PENDING); // the pending signature is lost too
    const body = (await lost.get(RUNLOG))!.body.slice();
    const r = await throwsIntegrity(() => seal(lost, 5, R(4), lockWithFloor(3)), "sig-invalid");
    ok(`with the pending signature also lost, the next seal refuses (${r.got})`, r.ok);
    const after = (await lost.get(RUNLOG))!.body;
    ok("...and re-signs nothing: the body is as the crash left it and still does not verify", after.length === body.length && after.every((b, i) => b === body[i]) && !(await sigVerifies(lost, v)));
    ok("the run row names the refusal, not contention", coarseRunError(new RunlogIntegrityError("sig-invalid", "x").message) === "runlog integrity refused (an Owner must review the destination RUNLOG)");
  }

  console.log("\n-- a deleted RUNLOG where the floor is above 0 --");
  {
    const d = await threeRuns();
    await d.delete(RUNLOG);
    await d.delete(RUNLOG_SIG);
    await d.delete(RUNLOG_PENDING);
    const s = await throwsIntegrity(() => seal(d, 4, R(3), lockWithFloor(3)), "absent-above-floor");
    ok(`the seal refuses to start a fresh RUNLOG (${s.got})`, s.ok && (await d.get(RUNLOG)) === null);
    const p = await throwsIntegrity(() => supersedeRunlog(d, signer, [R(1)], lockWithFloor(3)), "absent-above-floor");
    ok(`the prune refuses too (${p.got})`, p.ok);
    const fresh = new MemoryDestination();
    let threw: unknown = null;
    try {
      await seal(fresh, 1, null, lockWithFloor(undefined));
    } catch (e) {
      threw = e;
    }
    ok("CONTROL: a fresh destination with no floor creates its first RUNLOG as before", threw === null && (await sigVerifies(fresh, v)), threw);
  }

  console.log("\n-- a replayed older signed RUNLOG (rollback) --");
  {
    const d = await threeRuns();
    const oldBody = (await d.get(RUNLOG))!.body.slice();
    const oldSig = (await d.get(RUNLOG_SIG))!.body.slice();
    await seal(d, 4, R(3), lockWithFloor(3));
    await seal(d, 5, R(4), lockWithFloor(4));
    await d.put(RUNLOG, oldBody); // put back the validly signed RUNLOG of three runs
    await d.put(RUNLOG_SIG, oldSig);
    ok("CONTROL: the replayed RUNLOG verifies under the engine key (only the floor can see it)", await sigVerifies(d, v));
    const s = await throwsIntegrity(() => seal(d, 6, R(5), lockWithFloor(5)), "below-floor");
    ok(`the seal refuses the replayed RUNLOG (${s.got})`, s.ok);
    ok("...and leaves it as it was (three entries)", parseRunlog((await d.get(RUNLOG))!.body).length === 3);
    const p = await throwsIntegrity(() => supersedeRunlog(d, signer, [R(1)], lockWithFloor(5)), "below-floor");
    ok(`the prune refuses it too (${p.got})`, p.ok);
  }

  console.log("\n-- the prune's no-op hole --");
  {
    const d = await threeRuns();
    // Every entry flipped to superseded in the body, with the old .sig left: an unverified "nothing to change".
    const flipped = parseRunlog((await d.get(RUNLOG))!.body).map((e) => ({ ...e, status: "superseded" as const }));
    await d.put(RUNLOG, (await signRunlog(flipped, signer.edPrivate, signer.mldsaSecret)).runlog);
    await d.delete(RUNLOG_PENDING);
    const victim = `run/${R(2)}/root.manifest.json`;
    const plan: PrunePlan = { downpipeId: DP, retainedRunIds: [R(3)], supersededRunIds: [R(1), R(2)], runTreeObjects: [victim], orphanSegs: [], reclaimableBytes: 0, retainedUnreadableCount: 0, supersededSkippedCount: 0, unparseableTimeCount: 0 };
    const r = await throwsIntegrity(() => applyPrune(d, signer, plan, lockWithFloor(3)), "sig-invalid");
    ok(`the prune refuses before reading "nothing to change" (${r.got})`, r.ok);
    ok("...so no run tree is deleted", (await d.get(victim)) !== null);
  }

  console.log("\n-- the chain rule --");
  {
    const d = new MemoryDestination();
    // A validly signed RUNLOG whose own chain for DP dangles, and a second downpipe whose chain is broken.
    const entries: RunlogEntry[] = [
      { index: 1, runId: R(1), downpipeId: DP, time: "2026-10-01T01:00:00.000Z", recordCount: 1, prevRunId: R(9), status: "active" },
      { index: 2, runId: "01ARZ3NDEKTSV4RRFFQ69G5FG1", downpipeId: "dp_other", time: "2026-10-01T02:00:00.000Z", recordCount: 1, prevRunId: null, status: "active" },
      { index: 3, runId: "01ARZ3NDEKTSV4RRFFQ69G5FG2", downpipeId: "dp_other", time: "2026-10-01T03:00:00.000Z", recordCount: 1, prevRunId: null, status: "active" },
    ];
    const signed = await signRunlog(entries, signer.edPrivate, signer.mldsaSecret);
    await d.put(RUNLOG, signed.runlog);
    await d.put(RUNLOG_SIG, utf8(b64urlEncode(signed.sig)));
    const own = await throwsIntegrity(() => appendRunlog(d, signer, { index: 4, runId: R(4), downpipeId: DP, time: "2026-10-01T04:00:00.000Z", recordCount: 1, prevRunId: R(1), status: "active" }, undefined, { relinkLocalPrev: true }), "chain-anomaly");
    ok(`the append refuses to relink its own downpipe's anomalous chain (${own.got})`, own.ok && parseRunlog((await d.get(RUNLOG))!.body).length === 3);
    let threw: unknown = null;
    try {
      await appendRunlog(d, signer, { index: 5, runId: "01ARZ3NDEKTSV4RRFFQ69G5FH1", downpipeId: "dp_new", time: "2026-10-01T05:00:00.000Z", recordCount: 1, prevRunId: null, status: "active" }, undefined, { relinkLocalPrev: true });
    } catch (e) {
      threw = e;
    }
    ok("a different downpipe still appends: another chain is left to the reader", threw === null && parseRunlog((await d.get(RUNLOG))!.body).length === 4, threw);
  }

  console.log("\n-- the index rule: one index, one run, in every destination's RUNLOG --");
  {
    // A destination whose signed RUNLOG holds indices 1 to 3 (downpipe dp_other owns 2), as a second destination
    // does while the engine's counter restarts after a control-plane recovery.
    const d = new MemoryDestination();
    const held: RunlogEntry[] = [
      { index: 1, runId: R(1), downpipeId: DP, time: "2026-10-01T01:00:00.000Z", recordCount: 1, prevRunId: null, status: "active" },
      { index: 2, runId: "01ARZ3NDEKTSV4RRFFQ69G5FG1", downpipeId: "dp_other", time: "2026-10-01T02:00:00.000Z", recordCount: 1, prevRunId: null, status: "active" },
      { index: 3, runId: R(3), downpipeId: DP, time: "2026-10-01T03:00:00.000Z", recordCount: 1, prevRunId: R(1), status: "active" },
    ];
    const signed = await signRunlog(held, signer.edPrivate, signer.mldsaSecret);
    await d.put(RUNLOG, signed.runlog);
    await d.put(RUNLOG_SIG, utf8(b64urlEncode(signed.sig)));
    const entryAt = (index: number, runId: string, downpipeId: string, prev: string | null): RunlogEntry => ({ index, runId, downpipeId, time: "2026-10-02T04:00:00.000Z", recordCount: 1, prevRunId: prev, status: "active" });

    // CONTROL: an index nobody holds appends.
    let ctl: unknown = null;
    try {
      await appendRunlog(d, signer, entryAt(4, R(4), DP, R(3)), undefined, { relinkLocalPrev: true });
    } catch (e) {
      ctl = e;
    }
    ok("control: an index no entry holds appends", ctl === null && parseRunlog((await d.get(RUNLOG))!.body).length === 4, ctl);
    // CONTROL: the same (runId, index) again is the idempotent retry, not a refusal.
    let again: unknown = null;
    try {
      await appendRunlog(d, signer, entryAt(4, R(4), DP, R(3)), undefined, { relinkLocalPrev: true });
    } catch (e) {
      again = e;
    }
    ok("control: the same run and index again is an idempotent retry", again === null && parseRunlog((await d.get(RUNLOG))!.body).length === 4, again);

    // THE FORK: another downpipe's run takes index 2, which dp_other holds.
    const afterControls = (await d.get(RUNLOG))!.body;
    resetIntegrityFaultLedger();
    const fork = await throwsIntegrity(() => appendRunlog(d, signer, entryAt(2, R(5), "dp_new", null), undefined, { relinkLocalPrev: true }), "index-held");
    ok(`an index another downpipe holds is refused (${fork.got})`, fork.ok);
    const entries = parseRunlog((await d.get(RUNLOG))!.body);
    ok("...and the RUNLOG still holds each index once", entries.length === 4 && new Set(entries.map((e) => e.index)).size === 4, entries.map((e) => e.index));
    ok("...byte for byte as it was", Buffer.compare(Buffer.from((await d.get(RUNLOG))!.body), Buffer.from(afterControls)) === 0);
    const snap = drainIntegrityFaultLedger();
    const row = snap.runlogAnomalies.find((a) => a.kind === "duplicate-index");
    ok("...and a duplicate-index anomaly names the index", row !== undefined && row.indexA === 2 && row.indexB === 2, snap.runlogAnomalies);
    // The same refusal for the downpipe's own earlier index, and for a writer that does not relink.
    const own = await throwsIntegrity(() => appendRunlog(d, signer, entryAt(3, R(6), DP, R(1)), undefined, { relinkLocalPrev: true }), "index-held");
    ok(`an index the same downpipe holds under another run is refused (${own.got})`, own.ok);
    const plain = await throwsIntegrity(() => appendRunlog(d, signer, entryAt(1, R(7), "dp_other", null)), "index-held");
    ok(`a writer that does not relink refuses it too (${plain.got})`, plain.ok);

    // THE LOCK REPORT: a refused index is reported through the lock so the counter can move past it.
    const reports: Array<{ index: number; downpipeId: string }> = [];
    const spy: RunlogLock = { acquire: async () => "t", release: async () => {}, indexHeld: async (e) => void reports.push(e) };
    await throwsIntegrity(() => appendRunlog(d, signer, entryAt(2, R(8), "dp_new", null), spy, { relinkLocalPrev: true }), "index-held");
    ok("a refusal is reported through the lock with the index and downpipe", reports.length === 1 && reports[0]!.index === 2 && reports[0]!.downpipeId === "dp_new", reports);
    let retryErr: unknown = null;
    try {
      await appendRunlog(d, signer, entryAt(4, R(4), DP, R(3)), spy, { relinkLocalPrev: true });
    } catch (e) {
      retryErr = e;
    }
    ok("control: the same run and index again still appends and reports nothing", retryErr === null && reports.length === 1, retryErr);
    const broken: RunlogLock = { acquire: async () => "t", release: async () => {}, indexHeld: async () => { throw new Error("lock plane down"); } };
    const stillIntegrity = await throwsIntegrity(() => appendRunlog(d, signer, entryAt(2, R(9), "dp_new", null), broken, { relinkLocalPrev: true }), "index-held");
    ok(`a report that fails does not change the refusal (${stillIntegrity.got})`, stillIntegrity.ok);
  }

  console.log("\n-- a floor the lock returns that is not a whole number above zero is refused --");
  {
    const d = await threeRuns();
    const before = Buffer.from((await d.get(RUNLOG))!.body);
    const rawLock = (f: unknown): RunlogLock => ({ acquire: async () => "tok", release: async () => {}, floor: async () => f as number | undefined });
    const entry4 = (): RunlogEntry => ({ index: 4, runId: R(4), downpipeId: DP, time: "2026-10-02T04:00:00.000Z", recordCount: 1, prevRunId: R(3), status: "active" });
    ok("control, an integer floor of 3 reads as 3", (await readFloor(rawLock(3))) === 3);
    ok("control, no floor and a floor of 0 read as no floor", (await readFloor(rawLock(undefined))) === undefined && (await readFloor(rawLock(0))) === undefined);
    for (const [name, bad] of [["1.5", 1.5], ["-1", -1], ["NaN", Number.NaN], ['the string "3"', "3"], ["null", null]] as Array<[string, unknown]>) {
      const r = await throwsIntegrity(() => readFloor(rawLock(bad)), "floor-invalid");
      ok(`readFloor refuses a floor of ${name} (${r.got})`, r.ok);
      const a = await throwsIntegrity(() => appendRunlog(d, signer, entry4(), rawLock(bad)), "floor-invalid");
      ok(`an append under a floor of ${name} is refused (${a.got})`, a.ok);
    }
    ok("...and the RUNLOG is byte for byte as it was", Buffer.compare(Buffer.from((await d.get(RUNLOG))!.body), before) === 0);
    let threw: unknown = null;
    try {
      await appendRunlog(d, signer, entry4(), rawLock(3));
    } catch (e) {
      threw = e;
    }
    ok("control, the same append at an integer floor of 3 lands", threw === null && parseRunlog((await d.get(RUNLOG))!.body).length === 4, threw);
  }

  const entryOf = (index: number, runId: string, downpipeId: string, prev: string | null): RunlogEntry => ({ index, runId, downpipeId, time: "2026-10-02T04:00:00.000Z", recordCount: 1, prevRunId: prev, status: "active" });
  const seed = async (d: MemoryDestination, entries: RunlogEntry[]): Promise<void> => {
    const { runlog, sig } = await signRunlog(entries, signer.edPrivate, signer.mldsaSecret);
    await d.put(RUNLOG, runlog);
    await d.put(RUNLOG_SIG, utf8(b64urlEncode(sig)));
  };
  const chainOfDest = async (d: MemoryDestination): Promise<Map<string, { index: number; prev: string | null; dp: string }>> =>
    new Map(parseRunlog((await d.get(RUNLOG))!.body).map((e) => [e.runId, { index: e.index, prev: e.prevRunId ?? null, dp: e.downpipeId }]));

  console.log("\n-- a lost write whose winner's signature has not landed is contention, not a refusal --");
  for (const mode of ["absent", "stale"] as const) {
    const d = new WinnerDestination();
    await seed(d, [entryOf(1, R(1), DP, null)]);
    const won = [entryOf(1, R(1), DP, null), entryOf(2, R(2), DP, R(1))];
    const w = await signRunlog(won, signer.edPrivate, signer.mldsaSecret);
    d.winner = { body: w.runlog, sig: utf8(b64urlEncode(w.sig)) };
    d.sigMode = mode;
    d.sigLandsAfterReads = 2;
    resetIntegrityFaultLedger();
    let threw: unknown = null;
    try {
      await appendRunlog(d, signer, entryOf(3, R(3), DP, R(2)));
    } catch (e) {
      threw = e;
    }
    const idx = parseRunlog((await d.get(RUNLOG))!.body).map((e) => e.index);
    ok(`winner's .sig ${mode} for one re-read: the writer backs off and appends (indexes ${idx.join(",")})`, threw === null && idx.join(",") === "1,2,3", threw instanceof Error ? threw.message : threw);
    ok(`...and records no anomaly (${mode})`, drainIntegrityFaultLedger().runlogAnomalies.length === 0);
    ok(`...and the RUNLOG verifies (${mode})`, await sigVerifies(d, v));
  }
  {
    const d = new WinnerDestination();
    await seed(d, [entryOf(1, R(1), DP, null)]);
    const w = await signRunlog([entryOf(1, R(1), DP, null), entryOf(2, R(2), DP, R(1))], signer.edPrivate, signer.mldsaSecret);
    d.winner = { body: w.runlog, sig: utf8(b64urlEncode(w.sig)) };
    d.sigLandsAfterReads = Number.POSITIVE_INFINITY;
    let threw: unknown = null;
    try {
      await appendRunlog(d, signer, entryOf(3, R(3), DP, R(2)));
    } catch (e) {
      threw = e;
    }
    ok(`a winner's .sig that never lands ends as contention, not integrity (${threw instanceof Error ? threw.name : "no throw"})`, threw instanceof RunlogContendedError && !(threw instanceof RunlogIntegrityError));
  }

  console.log("\n-- the relink orders one downpipe's chain by index and leaves other downpipes alone --");
  {
    const d = new MemoryDestination();
    await seed(d, [entryOf(1, R(1), DP, null), entryOf(3, R(3), DP, R(1))]);
    await appendRunlog(d, signer, entryOf(2, R(2), DP, null), undefined, { relinkLocalPrev: true });
    const c = await chainOfDest(d);
    ok("an entry that arrives below the tail is linked between its neighbours by index", c.get(R(1))?.prev === null && c.get(R(2))?.prev === R(1) && c.get(R(3))?.prev === R(2), [...c]);
  }
  {
    const d = new MemoryDestination();
    await seed(d, [entryOf(1, R(1), DP, null), entryOf(2, R(2), "dp_other", null)]);
    await appendRunlog(d, signer, entryOf(3, R(3), DP, null), undefined, { relinkLocalPrev: true });
    const c = await chainOfDest(d);
    ok("the new entry links to its own downpipe's tail, not to another downpipe's entry", c.get(R(3))?.prev === R(1), [...c]);
    ok("another downpipe's entry keeps no prev", c.get(R(2))?.prev === null && c.get(R(1))?.prev === null, [...c]);
  }
  {
    const d = new MemoryDestination();
    await seed(d, [entryOf(1, R(1), DP, null), entryOf(3, R(3), DP, R(1))]);
    await appendRunlog(d, signer, entryOf(2, R(2), DP, null));
    const c = await chainOfDest(d);
    ok("control, a writer that does not relink stores the entry's own prev and leaves the chain as it was", c.get(R(2))?.prev === null && c.get(R(3))?.prev === R(1), [...c]);
  }

  console.log("\n-- the refusal text, the unparsable refusal and the floor-read fault --");
  {
    const entryAt = (index: number, runId: string): RunlogEntry => ({ index, runId, downpipeId: DP, time: "2026-10-02T04:00:00.000Z", recordCount: 1, prevRunId: null, status: "active" });
    const messageOf = async (fn: () => Promise<unknown>): Promise<{ reason: string; message: string }> => {
      try {
        await fn();
        return { reason: "no throw", message: "" };
      } catch (e) {
        return e instanceof RunlogIntegrityError ? { reason: e.reason, message: e.message } : { reason: "other", message: String((e as Error).message) };
      }
    };
    const signedAt = async (d: MemoryDestination, body: Uint8Array): Promise<void> => {
      await d.put(RUNLOG, body);
      await d.put(RUNLOG_SIG, utf8(b64urlEncode(await hybridSign(signer.edPrivate, signer.mldsaSecret, body))));
    };

    // sig-absent and sig-invalid: two reasons, two different texts.
    const good = await signRunlog([entryAt(1, R(1))], signer.edPrivate, signer.mldsaSecret);
    const noSig = new MemoryDestination();
    await noSig.put(RUNLOG, good.runlog);
    const a = await messageOf(() => appendRunlog(noSig, signer, entryAt(2, R(2))));
    ok(`a RUNLOG with no signature is refused as sig-absent (${a.reason})`, a.reason === "sig-absent");
    ok("...and the text says it has no signature", a.message.includes("the RUNLOG has no signature") && !a.message.includes("does not verify"), a.message);
    const badSig = new MemoryDestination();
    await badSig.put(RUNLOG, good.runlog);
    await badSig.put(RUNLOG_SIG, utf8(b64urlEncode(rand(good.sig.length))));
    const b = await messageOf(() => appendRunlog(badSig, signer, entryAt(2, R(2))));
    ok(`a RUNLOG whose signature does not verify is refused as sig-invalid (${b.reason})`, b.reason === "sig-invalid");
    ok("...and the text says the signature does not verify under the engine's signer", b.message.includes("the RUNLOG signature does not verify under the engine's signer") && !b.message.includes("no signature"), b.message);

    // unparsable: a body the engine key signed that is not a RUNLOG.
    const junk = new MemoryDestination();
    await signedAt(junk, utf8("this is not a runlog\n"));
    resetIntegrityFaultLedger();
    const u = await messageOf(() => appendRunlog(junk, signer, entryAt(1, R(1))));
    ok(`a correctly signed RUNLOG that does not parse is refused as unparsable, not as a raw parse error (${u.reason}: ${u.message.slice(0, 80)})`, u.reason === "unparsable");
    ok("...and the text says it does not parse", u.message.includes("the RUNLOG does not parse"), u.message);
    ok("...and the write changed nothing", Buffer.compare(Buffer.from((await junk.get(RUNLOG))!.body), Buffer.from(utf8("this is not a runlog\n"))) === 0);
    const snap = drainIntegrityFaultLedger();
    ok("...and a parse-field anomaly carries the body digest", snap.runlogAnomalies.some((x) => x.kind === "parse-field" && x.digest !== undefined), snap.runlogAnomalies);
    // The verify entry point every writer shares gives the same answer.
    const junkBody = await junk.get(RUNLOG);
    const direct = await messageOf(() => verifyRunlogForWrite(junk, junkBody, v));
    ok(`verifyRunlogForWrite refuses it the same way (${direct.reason})`, direct.reason === "unparsable");
    // CONTROL: a signed, parsable one passes.
    const okd = new MemoryDestination();
    await signedAt(okd, good.runlog);
    ok("control: the same writer appends to a signed RUNLOG that parses", (await messageOf(() => appendRunlog(okd, signer, entryAt(2, R(2))))).reason === "no throw");

    // index-held: the text names the index and says it is refused.
    const held = await messageOf(() => appendRunlog(okd, signer, entryAt(1, R(7))));
    ok(`an index another run holds is refused as index-held (${held.reason})`, held.reason === "index-held");
    ok("...and the text names the index and the refusal", held.message.includes("index 1 is already held by another run in this RUNLOG, so the run is refused rather than written as a duplicate"), held.message);

    // The floor read.
    const lock = (floor: () => Promise<number | undefined>): RunlogLock => ({ acquire: async () => null, release: async () => {}, floor });
    ok("a floor of 3 is read as 3", (await readFloor(lock(async () => 3))) === 3);
    const before = peekSiteFaults()["runlog.floor-read"]?.count ?? 0;
    const thrown = await readFloor(lock(async () => Promise.reject(new Error("planted"))));
    const rowAfter = peekSiteFaults()["runlog.floor-read"];
    ok("a floor read that throws is no floor", thrown === undefined);
    ok("...and names the failed read as runlog.floor-read with its class", rowAfter !== undefined && rowAfter.count === before + 1 && rowAfter.lastCls === "error", rowAfter);
  }

  console.log("\n-- replication: the entry must match the run's signed root --");
  {
    const d = await threeRuns();
    const replica = new MemoryDestination();
    await seal(replica, 1, null, lockWithFloor(undefined));
    const real = parseRunlog((await d.get(RUNLOG))!.body).find((e) => e.runId === R(2))!;
    let msg = "no throw";
    try {
      await mirrorRunToReplica(d, replica, signer, { ...real, index: 7 }, { verify: true, verifySegments: false, lock: lockWithFloor(1) });
    } catch (e) {
      msg = (e as Error).message;
    }
    ok(`a mirror refuses an entry whose index disagrees with the signed root (${msg.slice(0, 90)})`, /does not match the run's signed root/.test(msg));
    ok("...and appends nothing to the replica", !parseRunlog((await replica.get(RUNLOG))!.body).some((e) => e.runId === R(2)));
  }

  console.log(failures === 0 ? "\nRUNLOG WRITE VERIFY PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures, checks);
  if (failures > 0) process.exitCode = 1;
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
  verdictReached(failures + 1, checks);
});
