// The RUNLOG body and its detached .sig are two objects, so a crash between the two writes, or a slower
// writer whose stale .sig lands after a newer body, leaves a body the stored .sig does not cover. Each RUNLOG
// write therefore puts its signature at _RECOVERY/RUNLOG.sig.pending BEFORE the body, and the next write
// resumes by publishing that pending signature, but only when it verifies the stored body under the engine
// key (seal/pipeline.ts resolveRunlogSignature).
//
// This validator drives the real appendRunlog, supersedeRunlog and resolveRunlogSignature on an in-memory
// bucket:
//   - a normal append and supersede leave the pending signature equal to the published one;
//   - a crash after the body write (the .sig put fails) is resumed by the next write, and by the resolver;
//   - the stale-.sig race (body 2 with sig 1 and pending 2) is resumed;
//   - NEGATIVE: a body changed in the bucket is never promoted, by a stale pending, a junk pending or a
//     pending the attacker copied from the old .sig; an absent .sig with no usable pending stays absent;
//   - the reader (openRun with freshness on) reads past a pending object, and fails closed in the crash
//     window, as it did before this object existed.
//
// Run: node test/validate-runlog-sig-pending.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { b64urlDecode, b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import { type HybridVerifier, hybridVerify } from "../src/crypto/sign.ts";
import { drainIntegrityFaultLedger, resetIntegrityFaultLedger } from "../src/format/integrity-fault-ledger.ts";
import { type ObjectStore, openRun } from "../src/format/reader.ts";
import { parseRunlog, type RecipientEntry, type RunlogEntry, type Signer, signRunlog } from "../src/format/writer.ts";
import { appendRunlog, RUNLOG_SIG_PENDING_KEY, type RunClock, type RunConfig, RunlogContendedError, RunlogIntegrityError, resolveRunlogSignature, runBackup, supersedeRunlog } from "../src/seal/pipeline.ts";
import type { Selector, SourceAdapter, SourceRecord } from "../src/sources/types.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { MemoryDestination } from "./memdest.ts";

const RUNLOG = "_RECOVERY/RUNLOG";
const RUNLOG_SIG = "_RECOVERY/RUNLOG.sig";
const DP = "dp_pending";
const R1 = "01ARZ3NDEKTSV4RRFFQ69G5FC1";
const R2 = "01ARZ3NDEKTSV4RRFFQ69G5FC2";
const R3 = "01ARZ3NDEKTSV4RRFFQ69G5FC3";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));

// CrashingDestination fails the next put of one key once: the crash between the body and the .sig write.
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

class OneRecordSource implements SourceAdapter {
  readonly sourceType = "kv" as const;
  async *crawl(_sel: Selector): AsyncIterable<SourceRecord> {
    yield { sourceType: "kv", name: "k", value: utf8("v"), namespace: "ns" };
  }
  async estimate(): Promise<{ records: number; bytes: number }> {
    return { records: 1, bytes: -1 };
  }
}

async function makeSigner(): Promise<Signer> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const m = mldsaKeygen();
  return { edPrivate: ed.privateKey, edPublic: new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey)), mldsaSecret: m.secretKey, mldsaPublic: m.publicKey };
}

function recipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

const entry = (runId: string, index: number, prev: string | null): RunlogEntry => ({ index, runId, downpipeId: DP, time: `2026-10-01T0${index}:00:00.000Z`, recordCount: 1, prevRunId: prev, status: "active" });

async function sigOver(dest: MemoryDestination, key: string, v: HybridVerifier): Promise<boolean> {
  const body = await dest.get(RUNLOG);
  const sig = await dest.get(key);
  if (!body || !sig) return false;
  try {
    return await hybridVerify(v, body.body, b64urlDecode(new TextDecoder().decode(sig.body).trim()));
  } catch {
    return false;
  }
}

async function bytesOf(dest: MemoryDestination, key: string): Promise<string> {
  const o = await dest.get(key);
  return o ? new TextDecoder().decode(o.body) : "";
}

// RaceDestination reproduces the first-run race deterministically. The RUNLOG starts empty. When the writer
// under test makes its conditional CREATE, a concurrent winner is let in first: the winner's signed body is
// stored WITHOUT its .sig, and the writer's create fails. The winner's .sig is published only after the writer
// has re-read the body `sigAfterReads` times (never, when it is Infinity). By then the pending signature is the
// writer's own, which does not cover the winner's body: exactly the state the race leaves.
class RaceDestination extends MemoryDestination {
  winnerBody: Uint8Array | null = null;
  winnerSig: Uint8Array | null = null;
  sigAfterReads = 2;
  private armed = true;
  private reReads = 0;
  override async putConditional(key: string, body: Uint8Array, opts: { ifMatch?: string; ifNoneMatch?: string }) {
    if (key === RUNLOG && opts.ifNoneMatch && this.armed && this.winnerBody) {
      this.armed = false;
      await super.put(RUNLOG, this.winnerBody);
      return { ok: false as const };
    }
    return super.putConditional(key, body, opts);
  }
  override async get(key: string) {
    if (key === RUNLOG && !this.armed) {
      this.reReads++;
      if (this.reReads > this.sigAfterReads && this.winnerSig && !(await super.exists(RUNLOG_SIG))) await super.put(RUNLOG_SIG, this.winnerSig);
    }
    return super.get(key);
  }
}

const firstEntry = (runId: string, index: number, downpipeId: string): RunlogEntry => ({ index, runId, downpipeId, time: `2026-10-01T0${index}:00:00.000Z`, recordCount: 1, prevRunId: null, status: "active" });

const sigInvalidRows = (): number => drainIntegrityFaultLedger().runlogAnomalies.filter((a) => a.kind === "sig-invalid").length;

async function main(): Promise<void> {
  const signer = await makeSigner();
  const v: HybridVerifier = { ed: signer.edPublic, mldsa: signer.mldsaPublic };

  console.log("\nnormal writes:");
  {
    const dest = new MemoryDestination();
    await appendRunlog(dest, signer, entry(R1, 1, null));
    await appendRunlog(dest, signer, entry(R2, 2, R1));
    ok("append: the published .sig verifies the body", await sigOver(dest, RUNLOG_SIG, v));
    ok("append: the pending signature equals the published .sig", (await bytesOf(dest, RUNLOG_SIG_PENDING_KEY)) === (await bytesOf(dest, RUNLOG_SIG)));
    const n = await supersedeRunlog(dest, signer, [R1]);
    ok("supersede: one entry changed and the published .sig verifies", n === 1 && (await sigOver(dest, RUNLOG_SIG, v)));
    ok("supersede: the pending signature equals the published .sig", (await bytesOf(dest, RUNLOG_SIG_PENDING_KEY)) === (await bytesOf(dest, RUNLOG_SIG)));
    ok("resolver on a clean RUNLOG: verified", (await resolveRunlogSignature(dest, (await dest.get(RUNLOG))!.body, v)) === "verified");
  }

  console.log("\ncrash after the body write (append):");
  {
    const dest = new CrashingDestination();
    await appendRunlog(dest, signer, entry(R1, 1, null));
    dest.failNextPutOf = RUNLOG_SIG;
    let threw = false;
    try {
      await appendRunlog(dest, signer, entry(R2, 2, R1));
    } catch {
      threw = true;
    }
    ok("the simulated crash stops the write after the body", threw);
    ok("crash window: the body holds run 2", parseRunlog((await dest.get(RUNLOG))!.body).some((e) => e.runId === R2));
    ok("crash window: the stored .sig does NOT verify the body", !(await sigOver(dest, RUNLOG_SIG, v)));
    ok("crash window: the pending signature verifies the body", await sigOver(dest, RUNLOG_SIG_PENDING_KEY, v));
    const state = await resolveRunlogSignature(dest, (await dest.get(RUNLOG))!.body, v);
    ok(`the resolver promotes the pending signature (${state})`, state === "promoted");
    ok("after the resume the stored .sig verifies the body", await sigOver(dest, RUNLOG_SIG, v));
    dest.failNextPutOf = RUNLOG_SIG;
    try {
      await appendRunlog(dest, signer, entry(R3, 3, R2));
    } catch {
      /* second crash, resumed by the next write below */
    }
    await supersedeRunlog(dest, signer, [R1]);
    const entries = parseRunlog((await dest.get(RUNLOG))!.body);
    ok("the next write resumes it: run 3 kept, run 1 superseded, .sig verifies", entries.some((e) => e.runId === R3) && entries.some((e) => e.runId === R1 && e.status === "superseded") && (await sigOver(dest, RUNLOG_SIG, v)));
  }

  console.log("\ncrash after the body write (supersede):");
  {
    const dest = new CrashingDestination();
    await appendRunlog(dest, signer, entry(R1, 1, null));
    await appendRunlog(dest, signer, entry(R2, 2, R1));
    dest.failNextPutOf = RUNLOG_SIG;
    try {
      await supersedeRunlog(dest, signer, [R1]);
    } catch {
      /* the crash */
    }
    ok("crash window: the stored .sig does NOT verify the superseded body", !(await sigOver(dest, RUNLOG_SIG, v)));
    ok("the resolver promotes the pending signature", (await resolveRunlogSignature(dest, (await dest.get(RUNLOG))!.body, v)) === "promoted" && (await sigOver(dest, RUNLOG_SIG, v)));
  }

  console.log("\nstale .sig race (body 2, sig 1, pending 2):");
  {
    const dest = new MemoryDestination();
    await appendRunlog(dest, signer, entry(R1, 1, null));
    const sig1 = (await dest.get(RUNLOG_SIG))!.body;
    await appendRunlog(dest, signer, entry(R2, 2, R1));
    await dest.put(RUNLOG_SIG, sig1); // the slower writer's stale .sig lands last
    ok("race: the stored .sig does NOT verify the body", !(await sigOver(dest, RUNLOG_SIG, v)));
    ok("race: the resolver promotes the pending signature and the .sig verifies", (await resolveRunlogSignature(dest, (await dest.get(RUNLOG))!.body, v)) === "promoted" && (await sigOver(dest, RUNLOG_SIG, v)));
  }

  console.log("\nnegative controls (a changed body is never promoted):");
  for (const how of ["stale-pending", "junk-pending", "pending-copied-from-old-sig", "no-pending"] as const) {
    const dest = new MemoryDestination();
    await appendRunlog(dest, signer, entry(R1, 1, null));
    await appendRunlog(dest, signer, entry(R2, 2, R1));
    const oldSig = await bytesOf(dest, RUNLOG_SIG);
    const changed = parseRunlog((await dest.get(RUNLOG))!.body).map((e) => (e.runId === R1 ? { ...e, recordCount: 999 } : e));
    await dest.put(RUNLOG, (await signRunlog(changed, signer.edPrivate, signer.mldsaSecret)).runlog); // serialiser only
    if (how === "junk-pending") await dest.put(RUNLOG_SIG_PENDING_KEY, utf8("junk"));
    if (how === "pending-copied-from-old-sig") await dest.put(RUNLOG_SIG_PENDING_KEY, utf8(oldSig));
    if (how === "no-pending") await dest.delete(RUNLOG_SIG_PENDING_KEY);
    const state = await resolveRunlogSignature(dest, (await dest.get(RUNLOG))!.body, v);
    ok(`[${how}] a changed body reads sig-invalid (${state}) and the .sig is left as it was`, state === "sig-invalid" && (await bytesOf(dest, RUNLOG_SIG)) === oldSig);
  }
  {
    const dest = new MemoryDestination();
    await appendRunlog(dest, signer, entry(R1, 1, null));
    await dest.delete(RUNLOG_SIG);
    await dest.put(RUNLOG_SIG_PENDING_KEY, utf8("junk"));
    ok("a deleted .sig with no usable pending reads sig-absent", (await resolveRunlogSignature(dest, (await dest.get(RUNLOG))!.body, v)) === "sig-absent" && (await dest.get(RUNLOG_SIG)) === null);
  }
  {
    // A .sig deleted after a completed write: the pending signature still verifies the body, so the resolver
    // publishes it again. That restore is recorded as a sig-restored anomaly row, so the pack names it.
    const dest = new MemoryDestination();
    await appendRunlog(dest, signer, entry(R1, 1, null));
    await dest.delete(RUNLOG_SIG);
    drainIntegrityFaultLedger();
    const state = await resolveRunlogSignature(dest, (await dest.get(RUNLOG))!.body, v);
    const rows = drainIntegrityFaultLedger().runlogAnomalies.filter((a) => a.kind === "sig-restored");
    ok(`a deleted .sig with a verifying pending is published again (${state})`, state === "promoted" && (await sigOver(dest, RUNLOG_SIG, v)));
    ok("the restore over an absent .sig records one sig-restored anomaly row", rows.length === 1);
    ok("the sig-restored row carries the 12-hex digest of the RUNLOG bytes", rows.length === 1 && typeof rows[0]?.digest === "string" && /^[0-9a-f]{12}$/.test(rows[0].digest));
  }
  {
    // CONTROL: the crash window (a stale .sig is present) resumes with no sig-restored row. That is an
    // interrupted write, and the .sig was never absent.
    const dest = new CrashingDestination();
    await appendRunlog(dest, signer, entry(R1, 1, null));
    dest.failNextPutOf = RUNLOG_SIG;
    try {
      await appendRunlog(dest, signer, entry(R2, 2, R1));
    } catch {
      // the simulated crash
    }
    drainIntegrityFaultLedger();
    const state = await resolveRunlogSignature(dest, (await dest.get(RUNLOG))!.body, v);
    const rows = drainIntegrityFaultLedger().runlogAnomalies.filter((a) => a.kind === "sig-restored");
    ok(`control: the crash-window resume promotes (${state}) and records no sig-restored row`, state === "promoted" && rows.length === 0);
  }
  {
    const other = await makeSigner();
    const dest = new MemoryDestination();
    await appendRunlog(dest, other, entry(R1, 1, null));
    ok("a RUNLOG signed under another key reads sig-invalid, even with its own pending present", (await resolveRunlogSignature(dest, (await dest.get(RUNLOG))!.body, v)) === "sig-invalid");
  }

  console.log("\nthe reader and the pending object:");
  {
    const bg = recipient("break-glass");
    const op = recipient("operational");
    const cfg: RunConfig = { downpipeId: DP, downpipeName: "pending", cadence: "3600s", selector: { include: [], exclude: [] }, recipients: [bg.entry, op.entry] };
    const dest = new CrashingDestination();
    const seal = (runId: string, index: number, prev: string | null) => runBackup([new OneRecordSource()], cfg, signer, dest, { randomNonce: () => rand(16), randomSalt: () => rand(16), runId, runlogIndex: index, prevRunId: prev, now: `2026-10-01T0${index}:00:00.000Z`, master: rand(32) } as RunClock);
    await seal(R1, 1, null);
    const store: ObjectStore = {
      get: async (k: string) => {
        const r = await dest.get(k);
        if (!r) throw new Error(`object ${k} is missing`);
        return r.body;
      },
    };
    const identity = parseIdentity(op.identity);
    const opens = async (runId: string, allowStale = false): Promise<boolean> => {
      try {
        (await openRun(store, runId, identity, v, { verifyFreshness: true, allowStale })).dispose();
        return true;
      } catch {
        return false;
      }
    };
    ok("the reader opens the latest run with a pending object beside the RUNLOG", (await dest.exists(RUNLOG_SIG_PENDING_KEY)) && (await opens(R1)));
    await dest.put(RUNLOG_SIG_PENDING_KEY, utf8("junk"));
    ok("the reader opens it with a junk pending object too", await opens(R1));
    dest.failNextPutOf = RUNLOG_SIG;
    try {
      await seal(R2, 2, R1);
    } catch {
      /* the crash */
    }
    ok("in the crash window the reader fails closed (it never reads the pending signature)", !(await opens(R2, true)));
    await supersedeRunlog(dest, signer, [R1]);
    ok("after the next write resumes the signature the reader opens run 2", await opens(R2, true));
  }

  console.log("\nfirst-run race: the loser of the create re-reads while the winner's .sig is still in flight:");
  {
    const winner = await signRunlog([firstEntry(R1, 1, "dp_d1")], signer.edPrivate, signer.mldsaSecret);
    const dest = new RaceDestination();
    dest.winnerBody = winner.runlog;
    dest.winnerSig = utf8(b64urlEncode(winner.sig));
    resetIntegrityFaultLedger();
    let err: unknown = null;
    try {
      await appendRunlog(dest, signer, firstEntry(R2, 2, "dp_r2"), undefined, { relinkLocalPrev: true });
    } catch (e) {
      err = e;
    }
    ok(`the loser's append succeeds once the winner's .sig lands (no refusal: ${err ? String(err) : "none"})`, err === null);
    const after = parseRunlog((await dest.get(RUNLOG))!.body);
    ok("the RUNLOG holds both first entries", after.length === 2 && after.some((e) => e.runId === R1) && after.some((e) => e.runId === R2));
    ok("the published .sig verifies the final body", await sigOver(dest, RUNLOG_SIG, v));
    ok("no sig-invalid anomaly is recorded for the contention", sigInvalidRows() === 0);
  }

  console.log("\na slow winner: its .sig lands after the loser's attempts run out, so the loser parks, then succeeds:");
  {
    const winner = await signRunlog([firstEntry(R1, 1, "dp_d1")], signer.edPrivate, signer.mldsaSecret);
    const dest = new RaceDestination();
    dest.winnerBody = winner.runlog;
    dest.winnerSig = utf8(b64urlEncode(winner.sig));
    // One append makes 5 re-reads after its lost create, so the .sig lands on the 6th read: after the first call
    // has run out of attempts, and before the resumed call reads (a winner slower than the whole retry window).
    dest.sigAfterReads = 5;
    resetIntegrityFaultLedger();
    let first: unknown = null;
    try {
      await appendRunlog(dest, signer, firstEntry(R2, 2, "dp_r2"), undefined, { relinkLocalPrev: true });
    } catch (e) {
      first = e;
    }
    ok("the first call ends as contention (RunlogContendedError), not a refusal", first instanceof RunlogContendedError);
    ok("and records no sig-invalid anomaly", sigInvalidRows() === 0);
    let resumed: unknown = null;
    try {
      await appendRunlog(dest, signer, firstEntry(R2, 2, "dp_r2"), undefined, { relinkLocalPrev: true });
    } catch (e) {
      resumed = e;
    }
    ok(`the resumed call succeeds once the winner's .sig is there (error: ${resumed ? String(resumed) : "none"})`, resumed === null);
    ok("the RUNLOG then holds both first entries under a verifying .sig", parseRunlog((await dest.get(RUNLOG))!.body).length === 2 && (await sigOver(dest, RUNLOG_SIG, v)));
  }

  console.log("\na signature that stays bad after a lost CAS is refused when the run resumes:");
  {
    const winner = await signRunlog([firstEntry(R1, 1, "dp_d1")], signer.edPrivate, signer.mldsaSecret);
    const dest = new RaceDestination();
    dest.winnerBody = winner.runlog;
    dest.winnerSig = utf8(b64urlEncode(winner.sig));
    dest.sigAfterReads = Number.POSITIVE_INFINITY; // the winner's .sig never arrives
    resetIntegrityFaultLedger();
    let first: unknown = null;
    try {
      await appendRunlog(dest, signer, firstEntry(R2, 2, "dp_r2"), undefined, { relinkLocalPrev: true });
    } catch (e) {
      first = e;
    }
    ok("the first call parks as contention with no anomaly", first instanceof RunlogContendedError && sigInvalidRows() === 0);
    let resumed: unknown = null;
    try {
      await appendRunlog(dest, signer, firstEntry(R2, 2, "dp_r2"), undefined, { relinkLocalPrev: true });
    } catch (e) {
      resumed = e;
    }
    ok("the resumed call refuses with RunlogIntegrityError (the signature is still bad on a fresh read)", resumed instanceof RunlogIntegrityError);
    ok("and records a sig-invalid anomaly", sigInvalidRows() >= 1);
  }

  console.log("\na bad signature on the first read refuses at once, as before:");
  {
    const dest = new MemoryDestination();
    await appendRunlog(dest, signer, entry(R1, 1, null));
    await dest.put(RUNLOG_SIG, utf8("junk"));
    await dest.put(RUNLOG_SIG_PENDING_KEY, utf8("junk"));
    resetIntegrityFaultLedger();
    let err: unknown = null;
    try {
      await appendRunlog(dest, signer, entry(R2, 2, R1));
    } catch (e) {
      err = e;
    }
    ok("a RUNLOG whose signature does not verify is refused on the first read (no contention wait)", err instanceof RunlogIntegrityError);
    ok("and it records a sig-invalid anomaly", sigInvalidRows() === 1);
  }

  console.log(failures === 0 ? "\nRUNLOG SIG PENDING PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures, checks);
  if (failures > 0) process.exitCode = 1;
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
  verdictReached(failures + 1, checks);
});
