// Prove the in-console break-glass restore's engine half: a break-glass-only estate, which
// holds NO operational read-back key and today refuses restore outright, can restore when the operator's
// browser supplies a valid per-run MASTER it decapsulated locally (the break-glass PRIVATE never leaves the
// browser). The proofs, all against real code with in-memory doubles (no network, no deploy, no cost):
//   1) readRestoreCapsule serves a chosen run's master capsule + key commitment, the browser recovers the
//      per-run master from it (openCapsule), and openRunFromMaster opens+verifies the SAME run from that
//      master alone and every record decrypts to the original bytes;
//   2) a WRONG 32-byte master fails closed at the key commitment BEFORE any record is read;
//   3) a CROSS-RUN master (run A's master on run B) fails closed the same way (a master opens its own run and
//      nothing else), while run B's own master opens run B;
//   4) a break-glass-only runRestore (no OPERATIONAL_PRIVATE) REFUSES with no master (the honest break-glass
//      reason, nothing written) and SUCCEEDS with a valid master (writes the verified bytes back), while the
//      operational path is unchanged (still restores with no master);
//   5) the master NEVER appears in the plan hash, the RestoreResult, or the signed receipt (a restore driven
//      with a master is greppable-clean of the master bytes, while the same shapes still carry real content).
// Run with `node test/validate-restore-from-master.ts`.

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen, mldsaKeygen } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import { runRestore } from "../src/admin/restore.ts";
import { openRunFromMaster, readRestoreCapsule } from "../src/admin/restore-open.ts";
import { restorePlanHash } from "../src/admin/approvals.ts";
import { openCapsule, parseWraps } from "../src/crypto/capsule.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { b64urlEncode, concat, hexDecode, hexEncode, utf8 } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";
import type { RestorePlan, RestoreResult } from "../src/admin/restore-types.ts";

const RUN_A = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const RUN_B = "01BX5ZZKBKACTAV9WEVGEMMVRY";
const NS = "ns_throwaway";
const KVSET: Record<string, string> = { "a": "alpha-value", "b": "beta-value", "user:42": "gamma-value-longer" };

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// MockKV / MockR2: the same in-memory doubles validate-restore.ts uses. MockKV tracks putCount so a
// "wrote nothing" assertion is exact; MockR2 serves the sealed archive to the R2 destination the factory builds.
class MockKV {
  store = new Map<string, Uint8Array>();
  putCount = 0;
  async put(k: string, v: ArrayBuffer | Uint8Array): Promise<void> {
    this.putCount++;
    this.store.set(k, v instanceof Uint8Array ? v : new Uint8Array(v));
  }
  async get(k: string): Promise<ArrayBuffer | null> {
    const v = this.store.get(k);
    return v ? toAB(v) : null;
  }
}
class MockR2 {
  store = new Map<string, Uint8Array>();
  async get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer>; etag: string } | null> {
    const v = this.store.get(key);
    if (!v) return null;
    return { arrayBuffer: async () => toAB(v), etag: `"${key.length}"` };
  }
  async head(key: string): Promise<{ etag: string } | null> {
    const v = this.store.get(key);
    return v ? { etag: `"${key.length}"` } : null;
  }
  async put(key: string, body: ArrayBuffer | Uint8Array): Promise<{ etag: string }> {
    this.store.set(key, body instanceof Uint8Array ? body : new Uint8Array(body));
    return { etag: `"${key.length}"` };
  }
}
function toAB(b: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(b.byteLength);
  new Uint8Array(out).set(b);
  return out;
}

async function sealRun(runId: string, master: Uint8Array, signer: Signer, breakGlass: RecipientEntry, op: RecipientEntry): Promise<MockR2> {
  const archive = await buildArchive({
    downpipeId: "dp_restore",
    downpipeName: "restore",
    cadence: "3600s",
    runId,
    master,
    recipients: [breakGlass, op],
    signer,
    records: Object.entries(KVSET).map(([name, v]) => ({ sourceType: "kv" as const, name, value: utf8(v), namespace: NS })),
    windowStart: "2026-06-07T00:00:00.000Z",
    windowEnd: "2026-06-07T00:00:01.000Z",
    createdAt: "2026-06-07T00:00:01.000Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });
  const r2 = new MockR2();
  for (const [k, b] of archive) r2.store.set(k, b);
  return r2;
}

// throwsKeyCommitment runs an open that must fail CLOSED at the signed key-commitment check (a wrong or
// cross-run master), returning true only when it threw with the commitment reason. The commitment check runs
// inside openRunWith BEFORE the shard/segment reads (deriveMK + openShards), so a throw here is by construction
// before any record is decrypted.
async function throwsKeyCommitment(fn: () => Promise<unknown>): Promise<boolean> {
  try {
    await fn();
    return false;
  } catch (e) {
    return /key commitment/.test((e as Error).message ?? "");
  }
}

async function main(): Promise<void> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  mldsaKeygen(mldsaSeed);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");

  // Two runs sealed under DIFFERENT per-run masters (captured here so the cross-run proof can use A's master
  // on B). Each is sealed to the SAME break-glass + operational recipients, exactly as a real pair of runs is.
  const masterA = rand(32);
  const masterB = rand(32);
  const r2A = await sealRun(RUN_A, masterA, signer, breakGlass.entry, op.entry);
  const r2B = await sealRun(RUN_B, masterB, signer, breakGlass.entry, op.entry);

  const operationalPrivateB64 = b64urlEncode(op.identity);
  const restoreKV = new MockKV();
  // The operational estate: holds OPERATIONAL_PRIVATE (the in-account read-back key). The break-glass-only
  // estate: the SAME wiring MINUS the operational key, so it has only the signer + destination + live binding.
  const opEnv = (r2: MockR2, kv: MockKV): Env => ({
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: r2 as unknown as R2Bucket,
    SIGNER_PRIVATE: signerPrivateB64,
    OPERATIONAL_PRIVATE: operationalPrivateB64,
    [`KV_${NS}`]: kv as unknown as KVNamespace,
  } as unknown as Env);
  const bgEnv = (r2: MockR2, kv: MockKV): Env => ({
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: r2 as unknown as R2Bucket,
    SIGNER_PRIVATE: signerPrivateB64,
    [`KV_${NS}`]: kv as unknown as KVNamespace,
  } as unknown as Env);
  const expectBytes = Object.values(KVSET).reduce((n, v) => n + utf8(v).length, 0);

  // ===== PROOF 1: the browser-decap -> engine-open loop, from the capsule the engine serves =====
  {
    // The engine serves the NON-SECRET capsule for run A (readRestoreCapsule; signature-verifies the manifest).
    const cap = await readRestoreCapsule(bgEnv(r2A, restoreKV), RUN_A);
    ok("readRestoreCapsule returns the master-capsule wraps + key commitment for the signed run", cap.masterCapsule.length >= 1 && cap.keyCommitment.length > 0 && cap.declaredRecordCount === 3);
    // The browser recovers run A's per-run master from that capsule with the break-glass private (stays local).
    const recovered = await openCapsule(parseWraps(cap.masterCapsule), parseIdentity(breakGlass.identity), hexDecode(cap.keyCommitment));
    ok("openCapsule recovers a 32-byte per-run master", recovered.length === 32);
    ok("the recovered master equals the run's seal-time master", b64urlEncode(recovered) === b64urlEncode(masterA));
    // openRunFromMaster opens+verifies run A from the recovered master ALONE (no operational key in bgEnv).
    const run = await openRunFromMaster(bgEnv(r2A, restoreKV), RUN_A, recovered);
    ok("openRunFromMaster opens the run from the browser-supplied master (break-glass-only env, no op key)", run.records.length === 3);
    let bytesMatch = true;
    for (const rec of run.records) {
      const pt = new TextDecoder().decode(await run.restoreRecord(rec));
      if (KVSET[rec.name] !== pt) bytesMatch = false;
    }
    ok("every record decrypts to the original plaintext under the supplied master", bytesMatch);
  }

  // ===== PROOF 2: a WRONG master fails closed at the key commitment, before any record =====
  {
    const wrong = new Uint8Array(32).fill(7);
    ok("a wrong 32-byte master fails closed at the key commitment (nothing decrypted)", await throwsKeyCommitment(() => openRunFromMaster(bgEnv(r2A, restoreKV), RUN_A, wrong)));
  }

  // ===== PROOF 3: a CROSS-RUN master (A's master on B) fails closed; B's own master opens B =====
  {
    ok("run A's master on run B fails closed at the key commitment (a master opens ONLY its own run)", await throwsKeyCommitment(() => openRunFromMaster(bgEnv(r2B, restoreKV), RUN_B, masterA)));
    const runB = await openRunFromMaster(bgEnv(r2B, restoreKV), RUN_B, masterB);
    ok("run B opens with its OWN master (positive control: B itself is recoverable)", runB.records.length === 3);
  }

  // ===== PROOF 4: break-glass-only REFUSES without a master, SUCCEEDS with a valid one =====
  {
    // Dry-run, no master, no operational key: the honest break-glass refusal, nothing verified.
    const noMasterDryKV = new MockKV();
    const dryRefuse = (await runRestore(bgEnv(r2A, noMasterDryKV), { runId: RUN_A })) as RestorePlan;
    ok("break-glass-only dry-run with NO master refuses (ok:false, break-glass reason)", dryRefuse.ok === false && /break-glass-only posture/.test(dryRefuse.reason ?? ""));
    // Dry-run, valid master: plans every record, writes nothing.
    const dryOkKV = new MockKV();
    const dryOk = (await runRestore(bgEnv(r2A, dryOkKV), { runId: RUN_A }, null, { master: masterA })) as RestorePlan;
    ok("break-glass-only dry-run WITH a valid master plans every record and writes nothing", dryOk.ok === true && dryOk.plannedWrites === 3 && dryOkKV.putCount === 0);

    // Apply, no master, no operational key: refuse, nothing written.
    const applyRefuseKV = new MockKV();
    const applyRefuse = (await runRestore(bgEnv(r2A, applyRefuseKV), { runId: RUN_A, confirm: true })) as RestoreResult;
    ok("break-glass-only apply with NO master refuses (ok:false, nothing written)", applyRefuse.ok === false && applyRefuse.recordsRestored === 0 && applyRefuseKV.putCount === 0 && /break-glass-only posture/.test(applyRefuse.reason ?? ""));
    // Apply, valid master: the verified bytes are written back.
    const applyOkKV = new MockKV();
    const applyOk = (await runRestore(bgEnv(r2A, applyOkKV), { runId: RUN_A, confirm: true }, null, { master: masterA })) as RestoreResult;
    let bytesMatch = applyOkKV.store.size === 3;
    for (const [name, v] of Object.entries(KVSET)) {
      const got = applyOkKV.store.get(name);
      if (!got || new TextDecoder().decode(got) !== v) bytesMatch = false;
    }
    ok("break-glass-only apply WITH a valid master restores every record, bytes matching", applyOk.ok === true && applyOk.recordsRestored === 3 && applyOk.bytesRestored === expectBytes && bytesMatch);

    // Apply, WRONG master, no operational key: opens, then fails closed at the commitment (nothing written).
    const applyWrongKV = new MockKV();
    const applyWrong = (await runRestore(bgEnv(r2A, applyWrongKV), { runId: RUN_A, confirm: true }, null, { master: new Uint8Array(32).fill(9) })) as RestoreResult;
    ok("break-glass-only apply with a WRONG master fails closed, nothing written", applyWrong.ok === false && applyWrong.recordsRestored === 0 && applyWrongKV.putCount === 0);

    // The operational path is UNCHANGED: an estate that holds the operational key still restores with no master.
    const opKV = new MockKV();
    const opApply = (await runRestore(opEnv(r2A, opKV), { runId: RUN_A, confirm: true })) as RestoreResult;
    ok("the operational path is unchanged: restores with NO master when it holds the operational key", opApply.ok === true && opApply.recordsRestored === 3 && opKV.store.size === 3);
  }

  // ===== PROOF 5: the master is absent from the plan hash, the result and the receipt =====
  {
    const masterB64 = b64urlEncode(masterA);
    const masterHex = hexEncode(masterA);
    // The plan hash is computed from a RestoreRequest, which carries NO master field, so it cannot depend on
    // the master: the SAME request hashes identically whether or not a master rode the restore, and the master
    // string is not in the hash.
    const planHash = await restorePlanHash({ runId: RUN_A, confirm: true });
    ok("restorePlanHash is deterministic and independent of any master (no master field on RestoreRequest)", planHash === (await restorePlanHash({ runId: RUN_A, confirm: true })) && !planHash.includes(masterB64) && !planHash.includes(masterHex));

    // Drive a real master-restore and grep the whole returned shape (result + signed receipt) for the master.
    const grepKV = new MockKV();
    const res = (await runRestore(bgEnv(r2A, grepKV), { runId: RUN_A, confirm: true }, null, { master: masterA })) as RestoreResult;
    const serialised = JSON.stringify(res);
    ok("the restore actually ran with the master (a receipt was produced), proving this is not a vacuous grep", res.ok === true && res.receipt !== undefined && serialised.includes(RUN_A));
    ok("the master (base64url) does NOT appear anywhere in the RestoreResult or its receipt", !serialised.includes(masterB64));
    ok("the master (hex) does NOT appear anywhere in the RestoreResult or its receipt", !serialised.includes(masterHex));
  }

  console.log(failures === 0 ? "\nRESTORE-FROM-MASTER VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
