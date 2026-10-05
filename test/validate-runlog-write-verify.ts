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
//   - replication: a mirror refuses an entry whose index disagrees with the run's signed root;
//   - the run row names the refusal (coarseRunError), not contention.
//
// Run: node test/validate-runlog-write-verify.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { b64urlDecode, b64urlEncode, utf8 } from "../src/crypto/bytes.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import { type HybridVerifier, hybridVerify } from "../src/crypto/sign.ts";
import { parseRunlog, type RecipientEntry, type RunlogEntry, type Signer, signRunlog } from "../src/format/writer.ts";
import { appendRunlog, type RunClock, type RunConfig, type RunlogLock, RunlogIntegrityError, runBackup, supersedeRunlog } from "../src/seal/pipeline.ts";
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
