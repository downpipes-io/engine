// Every engine path that rewrites the destination RUNLOG reads the stored RUNLOG, edits it, and
// signs the result with the engine key. If a path signs WITHOUT first checking the stored
// signature, a RUNLOG that someone changed in the bucket comes back with a valid signature, and
// the change can no longer be detected.
//
// This validator drives each re-sign path on the real engine code, against an in-memory bucket:
//   - SEAL: runBackup -> appendRunlog (finaliseRun and mergeStep call the same appendRunlog);
//   - PRUNE: applyPrune -> supersedeRunlog (the cron retention pass and the admin prune both call it);
//   - MIRROR: mirrorRunToReplica -> appendRunlog on the replica, with verify:true as the replication
//     pass calls it.
//
// For each path it plants two changes in the stored RUNLOG body and leaves the old .sig in place:
//   - "changed": the recordCount of run 2 is changed;
//   - "removed": the entry of run 2 is removed.
// The SAFE outcome: the path refuses (throws), or it does not leave a valid signature over the
// changed content. A positive control drives each path on an unchanged RUNLOG and expects a normal,
// validly signed result. A negative control checks that the planted change is detectable before the
// path runs (the stored signature does not verify).
//
// Run: node test/validate-runlog-resign-verify.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { b64urlDecode, concat, utf8 } from "../src/crypto/bytes.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import { type HybridVerifier, hybridVerify } from "../src/crypto/sign.ts";
import { type ObjectStore, openRun } from "../src/format/reader.ts";
import { parseRunlog, type RecipientEntry, type RunlogEntry, type Signer, signRunlog } from "../src/format/writer.ts";
import { type RunClock, type RunConfig, runBackup } from "../src/seal/pipeline.ts";
import { applyPrune, type PrunePlan } from "../src/seal/prune.ts";
import { mirrorRunToReplica } from "../src/seal/replicate.ts";
import type { Selector, SourceAdapter, SourceRecord } from "../src/sources/types.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { MemoryDestination } from "./memdest.ts";

const RUNLOG = "_RECOVERY/RUNLOG";
const RUNLOG_SIG = "_RECOVERY/RUNLOG.sig";
const DP = "dp_resign";
const R1 = "01ARZ3NDEKTSV4RRFFQ69G5FA1";
const R2 = "01ARZ3NDEKTSV4RRFFQ69G5FA2";
const R3 = "01ARZ3NDEKTSV4RRFFQ69G5FA3";
const R4 = "01ARZ3NDEKTSV4RRFFQ69G5FA4";
const TAMPER_COUNT = 999;

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
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

class OneRecordSource implements SourceAdapter {
  readonly sourceType = "kv" as const;
  private readonly value: string;
  constructor(value: string) {
    this.value = value;
  }
  async *crawl(_sel: Selector): AsyncIterable<SourceRecord> {
    yield { sourceType: "kv", name: "k", value: utf8(this.value), namespace: "ns" };
  }
  async estimate(): Promise<{ records: number; bytes: number }> {
    return { records: 1, bytes: -1 };
  }
}

interface Keys {
  signer: Signer;
  verifier: HybridVerifier;
  recipients: RecipientEntry[];
  identity: ReturnType<typeof parseIdentity>;
}

async function makeKeys(): Promise<Keys> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  const signer: Signer = { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };
  const bg = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  return { signer, verifier: { ed: edPublic, mldsa: mldsa.publicKey }, recipients: [bg.entry, op.entry], identity: parseIdentity(op.identity) };
}

async function seal(k: Keys, dest: MemoryDestination, runId: string, index: number, prev: string | null): Promise<void> {
  const cfg: RunConfig = { downpipeId: DP, downpipeName: "resign", cadence: "3600s", selector: { include: [], exclude: [] }, recipients: k.recipients };
  const clock = { randomNonce: () => rand(16), randomSalt: () => rand(16), runId, runlogIndex: index, prevRunId: prev, now: `2026-10-01T0${index}:00:00.000Z`, master: rand(32) } as RunClock;
  await runBackup([new OneRecordSource(`value ${runId}`)], cfg, k.signer, dest, clock);
}

// A bucket with three real sealed runs (R1, R2, R3) and their real signed RUNLOG.
async function bucketWithThreeRuns(k: Keys): Promise<MemoryDestination> {
  const dest = new MemoryDestination();
  await seal(k, dest, R1, 1, null);
  await seal(k, dest, R2, 2, R1);
  await seal(k, dest, R3, 3, R2);
  return dest;
}

type Tamper = "none" | "changed" | "removed";

// plant rewrites ONLY the RUNLOG body; the old .sig stays, as an attacker without the engine key leaves it.
async function plant(k: Keys, dest: MemoryDestination, tamper: Tamper): Promise<void> {
  if (tamper === "none") return;
  const cur = await dest.get(RUNLOG);
  if (!cur) throw new Error("no RUNLOG to tamper");
  let entries = parseRunlog(cur.body);
  if (tamper === "changed") entries = entries.map((e) => (e.runId === R2 ? { ...e, recordCount: TAMPER_COUNT } : e));
  if (tamper === "removed") entries = entries.filter((e) => e.runId !== R2);
  // signRunlog is used only as the NDJSON serialiser; its signature is thrown away.
  const { runlog } = await signRunlog(entries, k.signer.edPrivate, k.signer.mldsaSecret);
  await dest.put(RUNLOG, runlog);
}

async function storedSigValid(k: Keys, dest: MemoryDestination): Promise<boolean> {
  const body = await dest.get(RUNLOG);
  const sig = await dest.get(RUNLOG_SIG);
  if (!body || !sig) return false;
  try {
    return await hybridVerify(k.verifier, body.body, b64urlDecode(new TextDecoder().decode(sig.body).trim()));
  } catch {
    return false;
  }
}

async function storedEntries(dest: MemoryDestination): Promise<RunlogEntry[]> {
  const body = await dest.get(RUNLOG);
  return body ? parseRunlog(body.body) : [];
}

function tamperPersists(entries: RunlogEntry[], tamper: Tamper): boolean {
  if (tamper === "changed") return entries.some((e) => e.runId === R2 && e.recordCount === TAMPER_COUNT);
  if (tamper === "removed") return !entries.some((e) => e.runId === R2);
  return false;
}

function storeOf(dest: MemoryDestination): ObjectStore {
  return {
    get: async (key: string) => {
      const r = await dest.get(key);
      if (!r) throw new Error(`object ${key} is missing`);
      return r.body;
    },
  };
}

// readerAccepts: does the engine's own reader open R2 with the RUNLOG freshness check on?
async function readerAccepts(k: Keys, dest: MemoryDestination, runId: string): Promise<boolean> {
  try {
    const run = await openRun(storeOf(dest), runId, k.identity, k.verifier, { verifyFreshness: true, allowStale: true });
    run.dispose();
    return true;
  } catch {
    return false;
  }
}

type PathName = "seal" | "prune" | "mirror";

// drive runs one re-sign path against `dest`. It returns whether it threw, and the destination whose
// RUNLOG the path rewrote (the replica for mirror).
async function drive(k: Keys, path: PathName, dest: MemoryDestination): Promise<{ threw: string | null }> {
  try {
    if (path === "seal") {
      await seal(k, dest, R4, 4, R3);
    } else if (path === "prune") {
      const plan: PrunePlan = { downpipeId: DP, retainedRunIds: [R2, R3], supersededRunIds: [R1], runTreeObjects: [], orphanSegs: [], reclaimableBytes: 0, retainedUnreadableCount: 0, supersededSkippedCount: 0, unparseableTimeCount: 0 };
      await applyPrune(dest, k.signer, plan);
    } else {
      // `dest` is the REPLICA here. The primary holds a real sealed R4; mirror it onto the replica with
      // the options the replication pass uses (verify:true).
      const primary = new MemoryDestination();
      await seal(k, primary, R4, 4, R3);
      const entry: RunlogEntry = { index: 4, runId: R4, downpipeId: DP, time: "2026-10-01T04:00:00.000Z", recordCount: 1, prevRunId: R3, status: "active" };
      await mirrorRunToReplica(primary, dest, k.signer, entry, { verify: true, verifySegments: false });
    }
    return { threw: null };
  } catch (e) {
    return { threw: (e as Error).message };
  }
}

function effectPresent(path: PathName, entries: RunlogEntry[]): boolean {
  if (path === "prune") return entries.some((e) => e.runId === R1 && e.status === "superseded");
  return entries.some((e) => e.runId === R4);
}

async function main(): Promise<void> {
  const k = await makeKeys();
  const paths: PathName[] = ["seal", "prune", "mirror"];

  for (const path of paths) {
    console.log(`\nPATH ${path}:`);

    // Positive control: an unchanged RUNLOG re-signs fine.
    {
      const dest = await bucketWithThreeRuns(k);
      ok(`[${path}/control] the stored RUNLOG signature verifies before the path runs`, await storedSigValid(k, dest));
      const r = await drive(k, path, dest);
      const entries = await storedEntries(dest);
      ok(`[${path}/control] the path completes without a refusal`, r.threw === null);
      ok(`[${path}/control] the rewritten RUNLOG carries the path's change`, effectPresent(path, entries));
      ok(`[${path}/control] the rewritten RUNLOG signature verifies`, await storedSigValid(k, dest));
    }

    for (const tamper of ["changed", "removed"] as const) {
      const dest = await bucketWithThreeRuns(k);
      await plant(k, dest, tamper);
      // Negative control: the planted change is detectable before the path runs.
      ok(`[${path}/${tamper}] before: the stored RUNLOG signature does NOT verify (the change is detectable)`, !(await storedSigValid(k, dest)));
      const readerBefore = await readerAccepts(k, dest, R3);
      ok(`[${path}/${tamper}] before: the reader refuses run 3 on this RUNLOG`, !readerBefore);

      const r = await drive(k, path, dest);
      const entries = await storedEntries(dest);
      const sigValid = await storedSigValid(k, dest);
      const persists = tamperPersists(entries, tamper);
      const laundered = sigValid && persists;
      console.log(`       observed: threw=${r.threw === null ? "no" : `yes (${r.threw.slice(0, 80)})`} sigValidAfter=${sigValid} tamperStillInBody=${persists} pathChangeWritten=${effectPresent(path, entries)}`);
      // The SAFE assertion: RED while the path launders the change, GREEN once it verifies before it re-signs.
      ok(`[${path}/${tamper}] SAFE: the path refuses, or leaves no valid signature over the changed RUNLOG`, r.threw !== null || !laundered);
      const readerAfter = await readerAccepts(k, dest, R3);
      ok(`[${path}/${tamper}] SAFE: the reader still refuses run 3 after the path ran`, !readerAfter);
    }
  }

  console.log(failures === 0 ? "\nRUNLOG RESIGN VERIFY PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures, checks);
  if (failures > 0) process.exitCode = 1;
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
  verdictReached(failures + 1, checks);
});
