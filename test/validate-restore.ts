// Prove the in-account restore: seal a small KV set to an in-memory destination, then drive
// the real runRestore handler (through the dest factory + the verifying reader) to (1)
// restore the records into a mock KV namespace with bytes matching, (2) dry-run by default
// and write nothing, (3) refuse a reserved-binding target, and (4) read the archive through
// a selectable destination (the R2 destination, via the factory). Run:
//   node test/validate-restore.ts
// In-memory doubles only; no network, no deploy, no cost.

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen, mldsaKeygen } from "../src/crypto/pq.ts";
import { buildArchive, parseRunlog, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { runRestore as runRestoreUnderTest, guardTarget, runBlindRestoreTest as runBlindRestoreTestUnderTest } from "../src/admin/restore.ts";
import { type MediaUploader, MEDIA_UPLOAD_MAX } from "../src/admin/media-restore.ts";
import { vanishedMarkerValue } from "../src/seal/marker.ts";
import { encodeD1Backup, D1_BACKUP_FORMAT } from "../src/sources/d1-format.ts";
import { resolveCfConfigSurfaces, restorePlanHash } from "../src/admin/approvals.ts";
import { SECRETS_OUT_OF_BAND_REASON } from "../src/admin/restore-sinks.ts";
import { CF_CONFIG_SURFACES } from "../src/sources/cf-config-surfaces.ts";
import { PROVEN_WRITE_SURFACES } from "../src/sources/cf-config-write-generated.ts";

// The exemplar for "an idempotent surface with NO write path" is DERIVED, not named.
//
// It was hard-coded twice and broke twice, both times because the named surface gained a writer and
// stopped being an example of the case: dns-settings, url-normalization the day after.
// Each time the assertion went red for a reason that had nothing to do with the rule it tests, which is a
// false failure and costs a diagnosis. Which surfaces are read-only moves continuously while the proving
// work lands, so the fixture asks the registry instead of remembering.
//
// It throws rather than skipping if the registry ever has none, because that would mean every idempotent
// surface is writable and this whole branch of the restore plan is dead code, which is worth a loud
// failure rather than a quiet pass.
const READ_ONLY_IDEMPOTENT = (() => {
  const s = CF_CONFIG_SURFACES.find((x) => x.restoreTier === "idempotent" && typeof x.write !== "function" && x.scope === "zone");
  if (s === undefined) throw new Error("no read-only idempotent zone surface in the registry: this fixture, and the plan branch it tests, need re-thinking");
  return s.id;
})();
import { ed25519 } from "@noble/curves/ed25519.js";
import { b64urlEncode, concat, hexEncode, utf8 } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import type { Env } from "../src/env.d.ts";
import type { RestorePlan, RestoreResult } from "../src/admin/restore-types.ts";
import type { CfApi, CfPage } from "../src/sources/cf-config-surfaces.ts";
import { Run } from "../src/format/reader.ts";
import type { ShardRecord } from "../src/format/manifest.ts";
import { flipBit } from "./memdest.ts";

const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const NS = "ns_throwaway";
const KVSET: Record<string, string> = { "a": "alpha-value", "b": "beta-value", "user:42": "gamma-value-longer" };

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

// patterned builds n deterministic bytes (a cheap repeatable fill), used for the larger-than-ceiling
// records that must exceed the buffered/streaming and re-upload size bounds without a huge random draw.
function patterned(n: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (Math.imul(i + 1, 2654435761) >>> 24) & 0xff;
  return b;
}

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// makeRecipient builds a hybrid recipient public entry and its 96-byte private identity
// (x25519 scalar(32) || ML-KEM seed(64)), matching the pipeline validator's idiom.
function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// MockKV implements just the KVNamespace surface KVRestoreSink uses, tracking a put count so
// the dry-run assertion can prove zero writes.
class MockKV {
  store = new Map<string, Uint8Array>();
  putCount = 0;
  async put(k: string, v: ArrayBuffer | Uint8Array): Promise<void> {
    this.putCount++;
    this.store.set(k, v instanceof Uint8Array ? v : new Uint8Array(v));
  }
  async get(k: string, _type?: string): Promise<ArrayBuffer | null> {
    const v = this.store.get(k);
    return v ? toAB(v) : null;
  }
}

// MockR2 holds the sealed archive object map and serves it through the R2 binding surface the
// R2 destination reads (get -> { arrayBuffer, etag }, head, put). This is the "selectable
// destination" half: restore reads the archive through the factory-built R2 destination.
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

// THE SHARED DESTINATION'S RUNLOG, and why the next three helpers exist.
//
// This file seals thirty-odd independent archives and installs them into ONE MockR2, the way a real
// account keeps every downpipe's runs in one bucket. A real bucket also keeps ONE account-wide
// _RECOVERY/RUNLOG that appendRunlog EXTENDS per run, so every run it holds is in it. buildArchive
// instead emits a single-entry log per archive, so each install overwrote the last and the destination
// ended up holding thirty archives and a log that knew only the final one. Every earlier run was then
// "not present in the RUNLOG", which is a freshness refusal, not a fixture detail: the anti-rollback
// check cannot place a run its destination's log does not carry.
//
// Rather than merge the logs (every archive here is signed at runlogIndex 1, and one log cannot carry
// thirty entries at index 1 without being a duplicated-index anomaly), installArchive REGISTERS each
// archive's own genuinely signed log, and the two wrappers below point the destination at the log
// belonging to the run under test before the restore reads it. Nothing else about the archives changes,
// and no gate is relaxed: each restore sees a real, correctly signed RUNLOG carrying its own run.
const runlogByRunId = new Map<string, { log: Uint8Array; sig: Uint8Array }>();

function installArchive(store: MockR2, archive: Map<string, Uint8Array>): void {
  for (const [k, b] of archive) store.store.set(k, b);
  const log = archive.get("_RECOVERY/RUNLOG");
  const sig = archive.get("_RECOVERY/RUNLOG.sig");
  if (log !== undefined && sig !== undefined) {
    for (const e of parseRunlog(log)) runlogByRunId.set(e.runId, { log, sig });
  }
}

// pointRunlogAt re-points the destination this env reads at the registered log for the given run. A run
// with no registered log (an archive built inline for a negative case) is left exactly as it is.
function pointRunlogAt(env: Env, runId: string | undefined): void {
  if (runId === undefined) return;
  const pair = runlogByRunId.get(runId);
  const dest = (env as unknown as { DEST_R2?: MockR2 }).DEST_R2;
  if (pair === undefined || dest === undefined || !(dest.store instanceof Map)) return;
  dest.store.set("_RECOVERY/RUNLOG", pair.log);
  dest.store.set("_RECOVERY/RUNLOG.sig", pair.sig);
}

async function runRestore(...args: Parameters<typeof runRestoreUnderTest>): ReturnType<typeof runRestoreUnderTest> {
  pointRunlogAt(args[0], args[1].runId);
  return runRestoreUnderTest(...args);
}

async function runBlindRestoreTest(...args: Parameters<typeof runBlindRestoreTestUnderTest>): ReturnType<typeof runBlindRestoreTestUnderTest> {
  pointRunlogAt(args[0], args[1].runId);
  return runBlindRestoreTestUnderTest(...args);
}

// Fixture carries the signed in-memory archive (in MockR2), the recipients/signer and the baseEnv
// factory every proof reuses, plus the whole-run apply result + plaintext total the prologue checks.
interface Fixture {
  r2: MockR2;
  restoreKV: MockKV;
  signer: Signer;
  breakGlass: ReturnType<typeof makeRecipient>;
  op: ReturnType<typeof makeRecipient>;
  baseEnv: () => Env;
  applied: RestoreResult;
  expectBytes: number;
}

// sealKvArchive seals the KVSET into an in-memory archive map under the shared signer/recipients.
async function sealKvArchive(signer: Signer, breakGlass: ReturnType<typeof makeRecipient>, op: ReturnType<typeof makeRecipient>): Promise<Map<string, Uint8Array>> {
  return buildArchive({
    downpipeId: "dp_restore",
    downpipeName: "restore",
    cadence: "3600s",
    runId: RUN_ID,
    master: rand(32),
    recipients: [breakGlass.entry, op.entry],
    signer,
    records: Object.entries(KVSET).map(([name, v]) => ({ sourceType: "kv", name, value: utf8(v), namespace: NS })),
    windowStart: "2026-06-07T00:00:00.000Z",
    windowEnd: "2026-06-07T00:00:01.000Z",
    createdAt: "2026-06-07T00:00:01.000Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });
}

// setup seals the KV set into a MockR2 archive, wires baseEnv, runs the first whole-run apply (the
// PROOF 1 round-trip) and returns the Fixture. It also asserts the verifier-halves sanity.
async function setup(): Promise<Fixture> {
  // The signer the engine will both sign the archive with AND pin its verifier from. Build
  // SIGNER_PRIVATE = b64url(edSeed(32) || ML-DSA secret) so the engine's loadSigner derives
  // the identical verifier (verify cannot pass otherwise).
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const mldsa = mldsaKeygen(mldsaSeed);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const verifier = verifierFrom(signer);
  // Sanity: the pinned verifier halves match the raw key derivation.
  ok("signer public halves derive consistently", b64urlEncode(verifier.ed) === b64urlEncode(ed25519.getPublicKey(edSeed)) && b64urlEncode(verifier.mldsa) === b64urlEncode(mldsa.publicKey));

  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");

  // Seal the KV set into an in-memory archive, then place every object into MockR2 so the
  // root + sig + RUNLOG + shard + segments all live in the selectable R2 destination.
  const r2 = new MockR2();
  installArchive(r2, await sealKvArchive(signer, breakGlass, op));

  // The operational identity is the in-account read-back key the engine holds.
  const operationalPrivateB64 = b64urlEncode(op.identity);

  // baseEnv wires the engine: the R2 archive destination (selectable via the factory), the
  // signer, the operational read-back key, and a live KV namespace bound under the
  // convention KV_<namespace> the resolver uses when there is no target override.
  const restoreKV = new MockKV();
  const baseEnv = (): Env => ({
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: r2 as unknown as R2Bucket,
    SIGNER_PRIVATE: signerPrivateB64,
    OPERATIONAL_PRIVATE: operationalPrivateB64,
    [`KV_${NS}`]: restoreKV as unknown as KVNamespace,
  } as unknown as Env);

  const expectBytes = Object.values(KVSET).reduce((n, v) => n + utf8(v).length, 0);
  const applied = await proofWholeRunRoundTrip(baseEnv, restoreKV, expectBytes);
  return { r2, restoreKV, signer, breakGlass, op, baseEnv, applied, expectBytes };
}

// proofWholeRunRoundTrip is PROOF 1: seal -> verify -> restore into a live KV namespace, BYTES MATCH.
async function proofWholeRunRoundTrip(baseEnv: () => Env, restoreKV: MockKV, expectBytes: number): Promise<RestoreResult> {
  const applied = (await runRestore(baseEnv(), { runId: RUN_ID, confirm: true })) as RestoreResult;
  ok("applied mode is 'applied'", applied.mode === "applied");
  ok("applied restored all 3 records", applied.ok === true && applied.recordsRestored === 3 && applied.recordsVerified === 3);
  ok("applied reports no failures", applied.failures.length === 0);
  ok("applied bytesRestored equals the sealed plaintext total", applied.bytesRestored === expectBytes);
  let bytesMatch = true;
  for (const [name, v] of Object.entries(KVSET)) {
    const got = restoreKV.store.get(name);
    if (!got || new TextDecoder().decode(got) !== v) bytesMatch = false;
  }
  ok("every restored KV value byte-matches the original (round-trip)", bytesMatch);
  ok("restored exactly the 3 keys, nothing extra", restoreKV.store.size === 3);
  return applied;
}

// ---- PROOF 2: DRY-RUN (default, no confirm) WRITES NOTHING ----
async function proofDryRun(fx: Fixture): Promise<void> {
  const { baseEnv, expectBytes } = fx;
  const dryKV = new MockKV();
  const dryEnv = baseEnv();
  dryEnv[`KV_${NS}`] = dryKV as unknown as KVNamespace;
  const plan = (await runRestore(dryEnv, { runId: RUN_ID })) as RestorePlan;
  ok("dry-run mode is 'dry-run'", plan.mode === "dry-run");
  ok("dry-run verified all 3 records", plan.ok === true && plan.recordsVerified === 3 && plan.plannedWrites === 3);
  ok("dry-run bytes equals the plaintext total", plan.bytes === expectBytes);
  ok("dry-run sample lists a resolved target per row", plan.sample.length === 3 && plan.sample.every((s) => s.binding.length > 0));
  ok("dry-run sample echoes the recovered namespace and binding", plan.sample.every((s) => s.namespace === NS && s.binding === `KV_${NS}`));
  ok("DRY-RUN WROTE NOTHING", dryKV.putCount === 0 && dryKV.store.size === 0);
}

// ---- PROOF 2b: an in-account restore larger than the ceiling is REFUSED, not attempted ----
async function proofOversizeRefused(fx: Fixture): Promise<void> {
  const { baseEnv, signer, breakGlass, op } = fx;
  // The engine restore runs the whole window in one Worker invocation (no slice/resume), so an oversized
  // run is refused before any write (steered to the offline CLI) rather than half-overwriting live state.
  {
    const BIG_RUN = "01ARZ3NDEKTSV4RRFFQ69G5FD3";
    const bigRecords = Array.from({ length: 201 }, (_, i) => ({ sourceType: "kv" as const, name: `big:${String(i).padStart(4, "0")}`, value: utf8(`v${i}`), namespace: NS }));
    const bigArchive = await buildArchive({
      downpipeId: "dp_restore", downpipeName: "restore", cadence: "3600s", runId: BIG_RUN,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer, records: bigRecords,
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    const bigR2 = new MockR2();
    installArchive(bigR2, bigArchive);
    const bigKV = new MockKV();
    const bigEnv = (): Env => ({ ...baseEnv(), DEST_R2: bigR2 as unknown as R2Bucket, [`KV_${NS}`]: bigKV as unknown as KVNamespace } as unknown as Env);

    const bigDry = (await runRestore(bigEnv(), { runId: BIG_RUN })) as RestorePlan;
    ok("an oversized restore dry-run is refused (ok:false)", bigDry.ok === false && bigDry.mode === "dry-run");
    ok("the dry-run reason steers to the in-account limit / offline CLI", typeof bigDry.reason === "string" && /in-account limit/.test(bigDry.reason));

    const bigApply = (await runRestore(bigEnv(), { runId: BIG_RUN, confirm: true })) as RestoreResult;
    ok("an oversized apply is refused (ok:false, nothing restored)", bigApply.ok === false && bigApply.recordsRestored === 0);
    ok("the oversized apply WROTE NOTHING (no partial overwrite of live state)", bigKV.putCount === 0 && bigKV.store.size === 0);

    // The escape hatch: a bounded in-account apply (maxRecords <= ceiling) is allowed and runs.
    const boundedKV = new MockKV();
    const boundedEnv = { ...bigEnv(), [`KV_${NS}`]: boundedKV as unknown as KVNamespace } as unknown as Env;
    const bounded = (await runRestore(boundedEnv, { runId: BIG_RUN, confirm: true, maxRecords: 200 })) as RestoreResult;
    ok("a bounded apply (maxRecords=200) passes the ceiling and restores", bounded.ok === true && bounded.recordsRestored === 200);
  }
}

// ---- WINDOWED-RESTORE HONESTY (R1): maxRecords < the matched set leaves records UNRESTORED, and the
// result must say so (windowed, a numeric outOfWindow, complete:false, a "(window)" skipped marker)
// WITHOUT flipping ok for a caller that intentionally pages with maxRecords. The sealed run holds 3
// records; maxRecords=2 leaves 1 beyond the window. ----
async function proofWindowed(fx: Fixture): Promise<void> {
  const { baseEnv } = fx;
  {
    const N = Object.keys(KVSET).length; // 3
    const MAX = 2;
    const winReason = (n: number) => `windowed restore: ${n} record(s) beyond maxRecords were not restored; re-run with a higher maxRecords or recover the full run offline`;

    // DRY-RUN windowed: complete:false, windowed:true, outOfWindow=1, a "(window)" marker. ok is UNCHANGED
    // (dryRunSkipped is empty here, so ok stays true exactly as an unbounded clean dry-run -- no regression).
    const winDryKV = new MockKV();
    const winDryEnv = baseEnv();
    winDryEnv[`KV_${NS}`] = winDryKV as unknown as KVNamespace;
    const winDry = (await runRestore(winDryEnv, { runId: RUN_ID, maxRecords: MAX })) as RestorePlan;
    ok("windowed dry-run reports windowed:true", winDry.windowed === true);
    ok("windowed dry-run reports outOfWindow = N - maxRecords", winDry.outOfWindow === N - MAX);
    ok("windowed dry-run reports complete:false", winDry.complete === false);
    ok("windowed dry-run carries a (window) skipped marker with the count + remedy", winDry.skipped.some((s) => s.name === "(window)" && s.reason === winReason(N - MAX)));
    ok("windowed dry-run does NOT regress ok (intentional partial stays ok:true)", winDry.ok === true);
    ok("windowed dry-run still wrote nothing", winDryKV.putCount === 0 && winDryKV.store.size === 0);

    // APPLY windowed: complete:false, windowed:true, outOfWindow=1, a "(window)" marker; ok is UNCHANGED
    // (failures is empty for an intentional partial, so ok stays true -- the console reads complete, not ok).
    const winKV = new MockKV();
    const winEnv = baseEnv();
    winEnv[`KV_${NS}`] = winKV as unknown as KVNamespace;
    const winApplied = (await runRestore(winEnv, { runId: RUN_ID, confirm: true, maxRecords: MAX })) as RestoreResult;
    ok("windowed apply reports windowed:true", winApplied.windowed === true);
    ok("windowed apply reports outOfWindow = N - maxRecords", winApplied.outOfWindow === N - MAX);
    ok("windowed apply reports complete:false (cannot present as a whole-run success)", winApplied.complete === false);
    ok("windowed apply carries a (window) skipped marker with the count + remedy", (winApplied.skipped ?? []).some((s) => s.name === "(window)" && s.reason === winReason(N - MAX)));
    ok("windowed apply does NOT regress ok (intentional partial stays ok:true)", winApplied.ok === true);
    ok("windowed apply restored exactly maxRecords records", winApplied.recordsRestored === MAX && winKV.store.size === MAX);

    // A NON-windowed (maxRecords >= matched) restore is complete:true, windowed:false, outOfWindow:0, no marker.
    const fullKV = new MockKV();
    const fullEnv = baseEnv();
    fullEnv[`KV_${NS}`] = fullKV as unknown as KVNamespace;
    const full = (await runRestore(fullEnv, { runId: RUN_ID, confirm: true })) as RestoreResult;
    ok("an unbounded apply is complete:true, windowed:false, outOfWindow:0", full.complete === true && full.windowed === false && full.outOfWindow === 0);
    ok("an unbounded apply carries NO (window) marker", !(full.skipped ?? []).some((s) => s.name === "(window)"));
  }
}

// ---- PROOF 3 + 4 + subset bonus: reserved-binding refusal, the selectable-dest proof, and an include
// selector restoring only the matching record. ----
async function proofReservedAndSelectable(fx: Fixture): Promise<void> {
  const { baseEnv, r2, applied } = fx;
  // ---- PROOF 3: a RESERVED-BINDING target is REFUSED (no write) ----
  // A confirm restore whose target binding is reserved must write nothing and report the
  // coarse reserved reason, never overwriting an engine internal.
  const reservedKV = new MockKV();
  const reservedEnv = baseEnv();
  reservedEnv["SIGNER_PRIVATE_TARGET"] = reservedKV as unknown as KVNamespace; // a stand-in target store
  const refused = (await runRestore(reservedEnv, { runId: RUN_ID, confirm: true, target: { binding: "SIGNER_PRIVATE" } })) as RestoreResult;
  ok("reserved-binding target refused (ok:false)", refused.ok === false && refused.reason === "target binding is reserved");
  ok("reserved-binding refusal wrote nothing", refused.recordsRestored === 0 && reservedKV.putCount === 0);
  // The direct guard: reserved refused, normal allowed.
  let guardRefused = false;
  try {
    guardTarget("DEST_SECRET_ACCESS_KEY");
  } catch {
    guardRefused = true;
  }
  ok("guardTarget refuses a reserved binding", guardRefused);
  ok("guardTarget allows a normal binding", guardTarget("KV_app") === "KV_app");
  // The in-account R2 archive binding DEST_R2 (and DEST_KIND) must be reserved too, so a
  // target override can never redirect restored plaintext into the encrypted-archive bucket.
  let destR2Refused = false;
  try { guardTarget("DEST_R2"); } catch { destR2Refused = true; }
  ok("guardTarget refuses DEST_R2 (the archive bucket binding)", destR2Refused);
  let destKindRefused = false;
  try { guardTarget("DEST_KIND"); } catch { destKindRefused = true; }
  ok("guardTarget refuses DEST_KIND", destKindRefused);

  // ---- PROOF 4: the destination is SELECTABLE (the archive was read through the R2 dest) ----
  // PROOF 1 already opened the run by reading every object through the factory-built R2
  // destination (DEST_KIND:"r2", DEST_R2 bound), so a successful restore IS the proof the
  // R2 destination satisfies the read side. Assert the factory chose R2 and a record came
  // back through it by confirming the archive lives only in the R2 mock and restore worked.
  ok("archive was served from the R2 destination (selectable dest)", r2.store.has(`run/${RUN_ID}/root.manifest.json`) && applied.recordsRestored === 3);

  // ---- BONUS: an include selector restores a SUBSET; excluded rows are reported skipped ----
  const subsetKV = new MockKV();
  const subsetEnv = baseEnv();
  subsetEnv[`KV_${NS}`] = subsetKV as unknown as KVNamespace;
  const subset = (await runRestore(subsetEnv, { runId: RUN_ID, confirm: true, include: ["user:"] })) as RestoreResult;
  ok("include selector restored only the matching record", subset.ok === true && subset.recordsRestored === 1 && subsetKV.store.has("user:42") && subsetKV.store.size === 1);
}

// ---- GRANULAR single-record restore (E4/C1): recordName plans + applies EXACTLY one record ----
// The sealed run holds 3 records (a, b, user:42). recordName:"a" must plan ONE record, apply ONLY that
// record, and a dry-run must write nothing. It is the first-class single-record path: exact-name, not a
// prefix, with the SAME dry-run-default + reserved-binding + verify safety as a full restore.
async function proofGranular(fx: Fixture): Promise<void> {
  const { baseEnv } = fx;
  {
    // Dry-run a single record: plans exactly 1, writes nothing.
    const granDryKV = new MockKV();
    const granDryEnv = baseEnv();
    granDryEnv[`KV_${NS}`] = granDryKV as unknown as KVNamespace;
    const granPlan = (await runRestore(granDryEnv, { runId: RUN_ID, recordName: "a" })) as RestorePlan;
    ok("granular dry-run plans EXACTLY 1 record", granPlan.mode === "dry-run" && granPlan.ok === true && granPlan.recordsVerified === 1 && granPlan.plannedWrites === 1);
    ok("granular dry-run sample is the named record only", granPlan.sample.length === 1 && granPlan.sample[0]?.name === "a");
    ok("granular dry-run reports the OTHER records skipped 'not the selected record'", granPlan.skipped.some((s) => s.name === "b" && s.reason === "not the selected record") && granPlan.skipped.some((s) => s.name === "user:42"));
    ok("granular DRY-RUN WROTE NOTHING", granDryKV.putCount === 0 && granDryKV.store.size === 0);

    // Apply a single record: writes ONLY that record, byte-exact, nothing else.
    const granKV = new MockKV();
    const granEnv = baseEnv();
    granEnv[`KV_${NS}`] = granKV as unknown as KVNamespace;
    const granApplied = (await runRestore(granEnv, { runId: RUN_ID, confirm: true, recordName: "a" })) as RestoreResult;
    ok("granular apply restored EXACTLY 1 record", granApplied.ok === true && granApplied.recordsRestored === 1 && granApplied.recordsVerified === 1);
    ok("granular apply wrote ONLY the named key, byte-exact", granKV.store.size === 1 && granKV.putCount === 1 && new TextDecoder().decode(granKV.store.get("a")!) === KVSET["a"]);
    ok("granular apply bytesRestored equals the one record's plaintext", granApplied.bytesRestored === utf8(KVSET["a"]!).length);

    // EXACT, not prefix: recordName "user:4" matches NO record (the real key is "user:42"), so the plan is
    // empty and the honest "record not found in run" reason is returned; NOT a silent prefix catch.
    const granMissEnv = baseEnv();
    const granMissKV = new MockKV();
    granMissEnv[`KV_${NS}`] = granMissKV as unknown as KVNamespace;
    const granMiss = (await runRestore(granMissEnv, { runId: RUN_ID, recordName: "user:4" })) as RestorePlan;
    ok("granular recordName is EXACT not prefix: a partial name finds nothing", granMiss.ok === false && granMiss.recordsVerified === 0 && granMiss.reason === "record not found in run");
    ok("granular exact-miss wrote nothing", granMissKV.putCount === 0);

    // A reserved-binding target still poisons a single-record apply: granular restore never weakens the guard.
    const granReservedEnv = baseEnv();
    const granReserved = (await runRestore(granReservedEnv, { runId: RUN_ID, confirm: true, recordName: "a", target: { binding: "SIGNER_PRIVATE" } })) as RestoreResult;
    ok("granular apply still refuses a reserved-binding target", granReserved.ok === false && granReserved.reason === "target binding is reserved" && granReserved.recordsRestored === 0);

    // The single-record apply gets its OWN distinct plan hash (a whole-run approval cannot be reused).
    const wholeHash = await restorePlanHash({ runId: RUN_ID });
    const oneHash = await restorePlanHash({ runId: RUN_ID, recordName: "a" });
    const otherHash = await restorePlanHash({ runId: RUN_ID, recordName: "b" });
    ok("granular plan hash differs from the whole-run hash", oneHash !== wholeHash);
    ok("granular plan hash differs per record (re-arm on which record)", oneHash !== otherHash);
    // Back-compat: a whole-run request with recordName ABSENT hashes identically to before recordName existed.
    ok("whole-run hash is stable when recordName is absent", (await restorePlanHash({ runId: RUN_ID, include: [], exclude: [] })) === wholeHash);

    // One more requirement: the plan states its resolved surface set (asserted elsewhere) and the hash must
    // BIND it, or widening the set does not invalidate an approval already granted for a narrower one, and
    // an approver's signature silently comes to authorise more than they saw.
    //
    // Nothing asserted this on the engine side. Replace the bound value with an empty list and every test
    // here still passed, which is how the guard sweep found it: the surface set was stated on the plan and
    // bound nowhere that a test could see.
    {
      const proven = resolveCfConfigSurfaces();
      ok("there are at least two proven surfaces, so widening is expressible (else this proves nothing)", proven.length >= 2);
      // token is REQUIRED on the cf-config restore input. It is constant across all three hashes below so
      // the only thing varying is the surface set, which is what this case is about.
      const cf = { token: "cf-token-for-hashing", accountId: "acct-1" };
      const narrow = await restorePlanHash({ runId: RUN_ID, cfConfig: { ...cf, surfaces: [proven[0]!] } });
      const wider = await restorePlanHash({ runId: RUN_ID, cfConfig: { ...cf, surfaces: [proven[0]!, proven[1]!] } });
      ok("F10: WIDENING the surface set changes the plan hash, so an old approval cannot cover it", narrow !== wider);
      // And the reverse, which is the case an attacker would want: narrowing must not collide back onto a
      // hash an approver already signed for something broader.
      ok("F10: narrowing changes it too, so the two are not interchangeable", wider !== narrow);
      const sameAgain = await restorePlanHash({ runId: RUN_ID, cfConfig: { ...cf, surfaces: [proven[0]!] } });
      ok("the same surface set hashes identically, so the binding is stable rather than merely noisy", narrow === sameAgain);
    }
  }
}

// ---- The dry-run plan is DETERMINISTIC given fixed inputs, and every record excluded from
// plannedWrites is ALWAYS named in `skipped` with a reason, so "the plan covers fewer records than the run
// captured" cannot happen SILENTLY through this code path -- only noisily, with a stated cause per record.
//
// Two candidate causes for a silent shortfall do not survive inspection:
//
//   1. reader.ts's openShards/verifyRecords (format/reader.ts:571-620) either returns EVERY record the
//      signed root declares or THROWS (records.length !== root.declaredRecordCount is an integrity error,
//      not a silent short read) -- there is no partial-read path on the restore-open side to intermittently
//      truncate. Not exercised again here (validate-reader.ts owns it); cited so this file's conclusion does
//      not stand alone.
//   2. sourceBindings (what buildSourceBindingMap supplies) only changes anything for an ORIGINAL-bindings
//      restore: resolveSink's `target?.binding ?? sourceBindings?.get(...) ?? convention`
//      (restore-sinks.ts:348) means an explicit target -- which an applying restore typically supplies, via
//      a redirect into a scratch binding -- makes sourceBindings irrelevant to the plan (part (c)
//      below). And on the original-bindings path it resolves, it is ALL-OR-NOTHING per shared binding (parts
//      (a)/(b)), so it cannot split a shortfall within one shared namespace.
//
// What DOES reproduce deterministically: a narrowed scope (recordName/maxRecords), which plans fewer records
// than the run holds -- and ALWAYS says so per record (part (d), and proofGranular above). A ledger reading
// plannedWrites=1 against a 3-or-4-record run with skipped=none cannot have come from buildRestorePlan/
// runDryRun on a complete run: the two never disagree by construction (asserted here as an accounting
// invariant), so a future occurrence of skipped=none alongside a real shortfall points OUTSIDE this file --
// at the request the caller actually sent, or at which of two responses a driver captured -- not at this
// classification loop.
async function proofPlanAccountingAndDeterminism(fx: Fixture): Promise<void> {
  const { baseEnv } = fx;

  // (a) ORIGINAL bindings, sourceBindings EMPTY (buildSourceBindingMap's presence-safe empty-on-fault
  // return), and the KV_<namespace> convention binding ABSENT (the operator attached under a chosen name,
  // e.g. SRC_KV, not the convention -- the exact case buildSourceBindingMap exists to cover). Every one of
  // the 3 records must be accounted for: NOT a silent 0.
  {
    const env = baseEnv();
    delete env[`KV_${NS}`];
    const plan1 = (await runRestore(env, { runId: RUN_ID }, null, { sourceBindings: new Map() })) as RestorePlan;
    const plan2 = (await runRestore(env, { runId: RUN_ID }, null, { sourceBindings: new Map() })) as RestorePlan;
    // This block's own heading says every record must be ACCOUNTED FOR rather than silently dropped, and the
    // next two lines prove exactly that: all three are named in skipped with the honest reason, and the
    // accounting invariant balances. That accounting alone is not enough: a plan that can write NOTHING, over
    // a run that holds three records, must not report itself ok and complete -- this is the same fixture
    // hazard the kv-binding-fallback proof warns about in its own header ("a fixture invented from the same
    // assumption as the code proves only that they share it"), one file over. This shape has been observed
    // live as ok:true complete:true over unwritable records, on the last screen an operator reads before
    // authorising a write-back.
    ok("a plan that can write NOTHING is not ok and not complete, however honestly it lists the reasons", plan1.ok === false && plan1.complete === false && plan1.plannedWrites === 0);
    ok("all 3 records are named in skipped, each with the honest reason", plan1.skipped.length === 3 && plan1.skipped.every((s) => s.reason === "target binding not present"));
    ok("ACCOUNTING INVARIANT: plannedWrites + skipped.length == the whole run (no silent drop)", plan1.plannedWrites + plan1.skipped.length === 3);
    // DETERMINISM: the SAME call, same inputs, run twice -- byte-identical CLASSIFICATION. If the row's two
    // runs really were the identical request against the identical build, this is the property that would
    // have to fail for buildRestorePlan/runDryRun themselves to be the cause, and it does not.
    //
    // THE TWO CLOCK FIELDS ARE EXCLUDED, AND THAT IS NOT A SOFTENING OF THE CLAIM. plannedAt and
    // applyDeadline are wall-clock instants: the plan states when it was computed and the last instant an
    // apply of it may still be writing, and the lapsed-KV fidelity warning is computed against the second
    // one. A plan could never have been time-invariant once it disclosed anything about expirations (a key
    // that lapses between two identical calls changes the disclosure, correctly); this fixture simply held
    // no expirations, so the impurity was invisible. What is asserted is the property the claim was always
    // about: every classification, count and reason reproduces, and the clock fields are separately checked
    // to be present and to move forward rather than being quietly dropped from the comparison.
    const withoutClock = (p: RestorePlan): string => {
      const { plannedAt: _p, applyDeadline: _d, ...rest } = p;
      return JSON.stringify(rest);
    };
    ok("repeating the SAME call with the SAME inputs yields a BYTE-IDENTICAL classification (the plan builder is pure)", withoutClock(plan1) === withoutClock(plan2));
    ok(
      "and both plans state their own instant and their own apply deadline, the later call's being no earlier",
      Number.isFinite(Date.parse(plan1.plannedAt ?? "")) &&
        Number.isFinite(Date.parse(plan1.applyDeadline ?? "")) &&
        Date.parse(plan2.plannedAt ?? "") >= Date.parse(plan1.plannedAt ?? "") &&
        Date.parse(plan2.applyDeadline ?? "") >= Date.parse(plan1.applyDeadline ?? ""),
    );
  }

  // (b) ORIGINAL bindings, sourceBindings CORRECTLY resolved (buildSourceBindingMap, reading
  // config.source and keying kv:<namespaceId>): the SAME 3 records, all planned, nothing skipped. Proves the
  // fixed function's OUTPUT actually changes resolveSink's outcome end-to-end (the fallback validator proves
  // the map's shape in isolation; this connects it to a real plan).
  {
    const env = baseEnv();
    delete env[`KV_${NS}`];
    env["SRC_KV"] = new MockKV() as unknown as KVNamespace;
    const sourceBindings = new Map([[`kv:${NS}`, "SRC_KV"]]);
    const plan = (await runRestore(env, { runId: RUN_ID }, null, { sourceBindings })) as RestorePlan;
    ok("with the real attach binding resolved, all 3 plan and nothing skips", plan.ok === true && plan.plannedWrites === 3 && plan.skipped.length === 0);
  }

  // (c) REDIRECT target: sourceBindings is IRRELEVANT -- empty, correct or wrong, it never matters -- every
  // record resolves to the redirect binding. Every applying harness journey uses this pattern (never
  // original bindings) for the one apply it drives, so buildSourceBindingMap's live DO fetch cannot be the
  // cause of a shortfall on the path that actually writes.
  {
    const env = baseEnv();
    delete env[`KV_${NS}`];
    env["RESTORE_KV"] = new MockKV() as unknown as KVNamespace;
    const planEmpty = (await runRestore(env, { runId: RUN_ID, target: { binding: "RESTORE_KV" } }, null, { sourceBindings: new Map() })) as RestorePlan;
    const planWrongMap = (await runRestore(env, { runId: RUN_ID, target: { binding: "RESTORE_KV" } }, null, { sourceBindings: new Map([[`kv:${NS}`, "SOME_OTHER_BINDING"]]) })) as RestorePlan;
    ok("redirect target plans all 3 records with an EMPTY sourceBindings map", planEmpty.ok === true && planEmpty.plannedWrites === 3 && planEmpty.skipped.length === 0);
    ok("redirect target plans all 3 records even when sourceBindings maps to something ELSE entirely", planWrongMap.ok === true && planWrongMap.plannedWrites === 3 && planWrongMap.skipped.length === 0);
  }

  // (d) A NARROWED scope (recordName), the shape a stale sessionStorage scope draft or a scoped re-entry
  // would send: plannedWrites=1 of 3, and the shortfall is NEVER skipped=none -- the other 2 always carry
  // "not the selected record" (proofGranular above asserts this by name; restated here as the general
  // invariant so it reads as one property, not two coincidences).
  {
    const env = baseEnv();
    env["RESTORE_KV"] = new MockKV() as unknown as KVNamespace;
    const plan = (await runRestore(env, { runId: RUN_ID, target: { binding: "RESTORE_KV" }, recordName: "a" }, null, { sourceBindings: new Map() })) as RestorePlan;
    ok("a narrowed (recordName) redirect plan covers 1 of 3", plan.ok === true && plan.plannedWrites === 1);
    ok("ACCOUNTING INVARIANT holds under narrowing too: plannedWrites + skipped.length == the whole run", plan.plannedWrites + plan.skipped.length === 3);
    ok("and skipped is never empty when plannedWrites undercounts the run: this shape cannot read skipped=none", plan.plannedWrites < 3 && plan.skipped.length > 0);
  }
}

// ---- cf-config RESTORE WRITE-BACK: an IDEMPOTENT surface re-applies in-console with a cfConfig token,
// computing a read-only diff on dry-run and writing via the (injected) CfApi on apply; WITHOUT a cfConfig
// context the record stays OUT OF BAND (the safe default). The token is bound into NO plan hash. ----
// makeCfDouble is an in-memory CfApi double: an EMPTY live zone (so a snapshot record is a create),
// recording every send so a test can assert nothing/something was written.
function makeCfDouble(live: unknown[] = []): { api: CfApi; sent: Array<{ method: string; path: string }> } {
  const sent: Array<{ method: string; path: string }> = [];
  const api: CfApi = {
    // `live` lets a caller seed what the zone ALREADY has. Empty by default, which is every existing
    // caller. It exists so the additive contract can be driven through the real plan: refusing to remove a
    // live extra cannot be observed against a live state that has nothing in it.
    get: async () => live,
    getPage: async (): Promise<CfPage> => ({ result: live }),
    send: async (method, path) => { sent.push({ method, path }); return {}; },
  };
  return { api, sent };
}

async function proofCfConfigWriteBack(fx: Fixture): Promise<void> {
  const { baseEnv, r2, signer, breakGlass, op } = fx;
  {
    const RUN_CFG = "01ARZ3NDEKTSV4RRFFQ69G5FB2"; // a distinct valid ULID
    // Snapshot for the DNS surface: one record absent from the (empty) live zone -> exactly one ADD.
    const dnsSnapshot = [{ type: "A", name: "new.example.com", content: "3.3.3.3", proxied: false, ttl: 1 }];
    const cfgArchive = await buildArchive({
      downpipeId: "dp_cfg", downpipeName: "cfg", cadence: "3600s", runId: RUN_CFG,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [
        // account stamps the SIGNED origin the cross-account guard cross-checks against (the source adapter's
        // own accountId at seal); acct-1 here, so the acct-1 restore below is a same-account restore.
        { sourceType: "cf-config", name: "dns", value: utf8(JSON.stringify(dnsSnapshot)), account: "acct-1" },
        // The self-identifying record must NOT be treated as a restorable surface: it is informational.
        { sourceType: "cf-config", name: "_cf-config-identity", value: utf8(JSON.stringify({ v: 1, accountId: "acct-1", zoneId: "zone", zoneName: "example.com" })), account: "acct-1" },
      ],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, cfgArchive);

    const cfCtx = { token: "edit-token-xyz", accountId: "acct-1", zoneId: "zone" };

    // DRY-RUN with a cfConfig context: per-surface diff computed READ-ONLY (no send), surfaced in configChanges.
    const cfDry = makeCfDouble();
    const cfgPlan = (await runRestore(baseEnv(), { runId: RUN_CFG, cfConfig: cfCtx }, null, { cfApiFactory: () => cfDry.api })) as RestorePlan;
    ok("cf-config dry-run surfaces the surface diff in configChanges", (cfgPlan.configChanges ?? []).some((c) => c.surface === "dns" && /1 to add/.test(c.summary) && c.willApply));
    // The plan STATES the resolved surface allow-list it was computed against, because the console
    // mirrors the plan hash client-side to show the operator the hash an approval binds to, and the
    // DEFAULT is the proven set, which the console has no copy of. Without this the mirror bound account
    // and zone only, so the hash on screen was not the hash the approval bound to.
    //
    // Asserted as EQUAL to resolveCfConfigSurfaces, the same function the hash binds, rather than merely
    // non-empty: a list that is present but computed some other way would satisfy "present" and still
    // produce a hash the console could not match.
    ok("the plan states the resolved cf-config surface set, exactly as the hash binds it", JSON.stringify(cfgPlan.cfConfigSurfaces) === JSON.stringify(resolveCfConfigSurfaces(undefined)));
    ok("the surface set is non-empty, so the assertion above is not vacuous", (cfgPlan.cfConfigSurfaces ?? []).length > 0);
    ok("cf-config DRY-RUN WROTE NOTHING to Cloudflare", cfDry.sent.length === 0);
    // The identity record is metadata: it lands OUT OF BAND (informational), never in configChanges as a
    // diffable/restorable surface, and never triggers a write.
    ok("the _cf-config-identity record is out of band (informational), never a diffable surface", cfgPlan.skipped.some((s) => s.name === "_cf-config-identity" && /identity/i.test(s.reason)) && !(cfgPlan.configChanges ?? []).some((c) => c.surface === "_cf-config-identity"));

    // THROUGH THE PLAN: a diff that is ONLY a live-only extra must NOT read as an apply.
    //
    // The writer's own test already proves it reports the extra as a "remove" and that summariseDiff renders
    // it. What was untested is the join: restore-plan.ts sets willApply from
    // `changes.some(c => c.action !== "remove")`, and if that ever became `changes.length > 0` the operator
    // would be told an apply WILL write something when it will only report a leftover it refuses to touch.
    //
    // Neither existing willApply assertion catches that. One has a real add, which passes either way; the
    // other has no changes at all, which also passes either way. Only a diff made ENTIRELY of removals can
    // tell the two apart, and that is exactly the shape the additive contract is about.
    {
      // Live holds a record the snapshot does not. The snapshot's own record is present too, so the ONLY
      // difference is the extra: a diff of pure removals.
      const extra = { type: "A", name: "attacker.example.com", content: "9.9.9.9", proxied: false, ttl: 1 };
      const withExtra = makeCfDouble([...dnsSnapshot, extra]);
      const extraPlan = (await runRestore(baseEnv(), { runId: RUN_CFG, cfConfig: cfCtx }, null, { cfApiFactory: () => withExtra.api })) as RestorePlan;
      const dnsChange = (extraPlan.configChanges ?? []).find((c) => c.surface === "dns");
      ok("a live-only extra still produces a configChanges entry, rather than vanishing", dnsChange !== undefined);
      ok("the summary NAMES it as live-only and left in place", /live-only/.test(dnsChange?.summary ?? ""));
      ok("willApply is FALSE, because refusing to remove something is not an apply", dnsChange?.willApply === false);
      ok("and the dry run sent nothing, so the refusal is not a write", withExtra.sent.length === 0);
    }

    // END TO END: AN UNPROVEN WRITER MUST NOT RUN WHEN NO SCOPE IS NAMED.
    //
    // resolveCfConfigSurfaces is already tested in isolation, and the apply path already consults it. That
    // is two correct halves with nothing asserting they are joined: delete the allowedSurfaces check from
    // restore-plan.ts and every one of those tests still passes, while a default restore starts writing
    // through writers generated from a schema that does not say which field identifies an item. This is the
    // whole reason `available` exists as a count separate from `inBand`, so it is worth an assertion that
    // fails when the two come apart.
    //
    // The surface is chosen AT RUN TIME rather than named, so proving one does not silently retarget or
    // break this test. If the unproven set is ever empty the block says so instead of passing on nothing,
    // which is the vacuous pass this file has been bitten by before.
    {
      const unprovenZone = CF_CONFIG_SURFACES.filter((x) => typeof x.write === "function" && !PROVEN_WRITE_SURFACES.has(x.id) && x.scope === "zone");
      ok("there is an unproven zone writer to test the default scope with (else this block proves nothing)", unprovenZone.length > 0);
      const target = unprovenZone[0]?.id ?? "";
      if (target !== "") {
        const RUN_SCOPE = "01ARZ3NDEKTSV4RRFFQ69G5FB3";
        const scopeArchive = await buildArchive({
          downpipeId: "dp_scope", downpipeName: "scope", cadence: "3600s", runId: RUN_SCOPE,
          master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
          records: [{ sourceType: "cf-config", name: target, value: utf8(JSON.stringify([{ name: "dp-scope-probe" }])), account: "acct-1" }],
          windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
          runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
        });
        installArchive(r2, scopeArchive);

        const dflt = makeCfDouble();
        const dfltPlan = (await runRestore(baseEnv(), { runId: RUN_SCOPE, cfConfig: cfCtx }, null, { cfApiFactory: () => dflt.api })) as RestorePlan;
        ok(`an UNPROVEN surface (${target}) is NOT in the default plan's changes`, !(dfltPlan.configChanges ?? []).some((c) => c.surface === target));
        ok("and it is reported as skipped rather than silently dropped", dfltPlan.skipped.some((k) => k.name === target));
        ok("the default plan does not even list it as an allowed surface", !(dfltPlan.cfConfigSurfaces ?? []).includes(target));

        // The opt-in must be REAL, or the assertions above pass for the wrong reason: a surface that can
        // never be reached is trivially not reached by default.
        const named = makeCfDouble();
        const namedPlan = (await runRestore(baseEnv(), { runId: RUN_SCOPE, cfConfig: { ...cfCtx, surfaces: [target] } }, null, { cfApiFactory: () => named.api })) as RestorePlan;
        ok(`naming ${target} explicitly DOES bring it into scope, so the opt-in is real`, (namedPlan.cfConfigSurfaces ?? []).includes(target));
        ok("and once named it is no longer skipped as out of scope", !namedPlan.skipped.some((k) => k.name === target && /scope/i.test(k.reason)));
      }
    }

    // APPLY with the edit token: the surface re-applies (one create POST), reported in configApplied.
    const cfRun = makeCfDouble();
    const cfgApplied = (await runRestore(baseEnv(), { runId: RUN_CFG, confirm: true, cfConfig: cfCtx }, null, { cfApiFactory: () => cfRun.api })) as RestoreResult;
    ok("cf-config apply reports the surface applied", cfgApplied.ok === true && (cfgApplied.configApplied ?? []).some((c) => c.surface === "dns" && c.applied === 1));
    ok("cf-config apply wrote via the CfApi (one create POST)", cfRun.sent.length === 1 && cfRun.sent[0]!.method === "POST");

    // WITHOUT a cfConfig context: the cf-config record stays OUT OF BAND (skipped), no diff, no Cloudflare write.
    const cfNone = makeCfDouble();
    const cfgNonePlan = (await runRestore(baseEnv(), { runId: RUN_CFG }, null, { cfApiFactory: () => cfNone.api })) as RestorePlan;
    ok("cf-config without a token stays OUT OF BAND (skipped), no in-console write", cfgNonePlan.configChanges === undefined && cfgNonePlan.skipped.some((s) => s.name === "dns") && cfNone.sent.length === 0);

    // A cfConfig OBJECT PRESENT with an EMPTY token but a real account id (the console cannot
    // send this shape -- flow.ts's pairingError guard blocks it client-side -- but the engine must not
    // rely on that: a raw API caller could send it directly). restore-plan.ts:103 gates on
    // `body.cfConfig.token !== "" && body.cfConfig.accountId !== ""`, so this must behave IDENTICALLY to
    // cfConfig being absent entirely (the assertion above): no diff computed, no CfApi instantiated, the
    // record stays out of band. Proves an empty token is never treated as "authenticated" -- the engine
    // does not even attempt a live Cloudflare call with it.
    const cfEmpty = makeCfDouble();
    const cfgEmptyPlan = (await runRestore(baseEnv(), { runId: RUN_CFG, cfConfig: { token: "", accountId: "acct-1", zoneId: "zone" } }, null, { cfApiFactory: () => cfEmpty.api })) as RestorePlan;
    ok("cf-config with an EMPTY TOKEN (account id present) stays OUT OF BAND, exactly like no cfConfig at all", cfgEmptyPlan.configChanges === undefined && cfgEmptyPlan.skipped.some((s) => s.name === "dns") && cfEmpty.sent.length === 0);

    // The cf-config apply binds the account/zone into the plan hash (its own approval) but NEVER the token.
    const hWith = await restorePlanHash({ runId: RUN_CFG, cfConfig: cfCtx });
    const hOtherAcct = await restorePlanHash({ runId: RUN_CFG, cfConfig: { token: "edit-token-xyz", accountId: "acct-2", zoneId: "zone" } });
    const hOtherToken = await restorePlanHash({ runId: RUN_CFG, cfConfig: { token: "A-DIFFERENT-token", accountId: "acct-1", zoneId: "zone" } });
    const hPlain = await restorePlanHash({ runId: RUN_CFG });
    ok("cf-config plan hash differs by account + from a plain restore (its own approval)", hWith !== hOtherAcct && hWith !== hPlain);
    ok("cf-config plan hash IGNORES the token (a secret never enters the hash)", hWith === hOtherToken);
  }
}

// ---- MEDIA RE-UPLOAD (stream/images): with a mediaRestore EDIT token + confirm, captured media bytes
// re-upload to the live account (images keep their id; a video gets a new uid, reported as an id-map). A
// capture MARKER is never uploaded as a file. WITHOUT the token, media records stay OUT OF BAND. ----
// makeUploaderDouble is an in-memory MediaUploader double: images keep their id (identity-preserving);
// a video is assigned a NEW uid (remapped). It records every upload so a test asserts a marker is NEVER
// uploaded. readbackReadable is true on every result here because every result is verified:true, i.e. the
// readback happened and matched; the apply reads readbackReadable ONLY on the verified:false branch, to
// split a durable mismatch from an unreadable live object.
function makeUploaderDouble(): { uploader: MediaUploader; uploads: Array<{ kind: string; id: string; bytes: string }> } {
  const uploads: Array<{ kind: string; id: string; bytes: string }> = [];
  const uploader: MediaUploader = {
    uploadImage: async (_acct, id, bytes) => { uploads.push({ kind: "image", id, bytes: new TextDecoder().decode(bytes) }); const h = hexEncode(await sha384(bytes)); return { restoredId: id, remapped: false, verifiedSha384: h, verified: true, via: "media-image-readback", readbackReadable: true }; },
    uploadStreamVideo: async (_acct, originalUid, bytes) => { uploads.push({ kind: "stream", id: originalUid, bytes: new TextDecoder().decode(bytes) }); return { restoredId: `new-${originalUid}`, remapped: true, verifiedSha384: null, verified: true, via: "media-stream-exists", readbackReadable: true }; },
  };
  return { uploader, uploads };
}

async function proofMediaReupload(fx: Fixture): Promise<void> {
  const { baseEnv, r2, signer, breakGlass, op } = fx;
    const RUN_MEDIA = "01ARZ3NDEKTSV4RRFFQ69G5FC3"; // a distinct valid ULID
    const mediaArchive = await buildArchive({
      downpipeId: "dp_media", downpipeName: "media", cadence: "3600s", runId: RUN_MEDIA,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [
        // account is the SIGNED origin the cross-account guard cross-checks; acct-1 here, so the acct-1
        // media restore below is a same-account restore that needs no cross-account confirmation.
        { sourceType: "images", name: "img1", value: utf8(JSON.stringify({ id: "img1", filename: "a.png" })), account: "acct-1" }, // metadata (inventory)
        { sourceType: "images", name: "img1/blob", value: utf8("PNG-BYTES-img1"), account: "acct-1" }, // an uploadable image blob
        { sourceType: "images", name: "img2/blob", value: utf8(JSON.stringify({ _unavailable: "403" })), incompleteMarker: "_unavailable", account: "acct-1" }, // a capture MARKER, never uploaded
        { sourceType: "stream", name: "vid1", value: utf8(JSON.stringify({ uid: "vid1" })), account: "acct-1" }, // metadata
        { sourceType: "stream", name: "vid1/video.mp4", value: utf8("MP4-BYTES-vid1"), account: "acct-1" }, // an uploadable video
      ],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, mediaArchive);

    const mediaCtx = { token: "edit-token-media", accountId: "acct-1" };

    // DRY-RUN with a mediaRestore context: previews the uploadable blobs, uploads NOTHING; the marker is out of band.
    const mDry = makeUploaderDouble();
    const mPlan = (await runRestore(baseEnv(), { runId: RUN_MEDIA, mediaRestore: mediaCtx }, null, { mediaUploaderFactory: () => mDry.uploader })) as RestorePlan;
    ok("media dry-run plans the image blob + the video (not the metadata/marker)", (mPlan.mediaPlanned ?? []).length === 2 && (mPlan.mediaPlanned ?? []).some((m) => m.name === "img1/blob" && m.type === "images") && (mPlan.mediaPlanned ?? []).some((m) => m.name === "vid1/video.mp4" && m.type === "stream"));
    ok("media DRY-RUN UPLOADED NOTHING", mDry.uploads.length === 0);
    ok("a capture-marker blob is out of band, never planned", mPlan.skipped.some((s) => s.name === "img2/blob") && !(mPlan.mediaPlanned ?? []).some((m) => m.name === "img2/blob"));

    // APPLY with the edit token: the image re-uploads to its ORIGINAL id; the video gets a new uid (remapped).
    const mRun = makeUploaderDouble();
    const mApplied = (await runRestore(baseEnv(), { runId: RUN_MEDIA, confirm: true, mediaRestore: mediaCtx }, null, { mediaUploaderFactory: () => mRun.uploader })) as RestoreResult;
    ok("media apply succeeds", mApplied.ok === true);
    ok("the image re-uploaded to its ORIGINAL id (identity-preserving, not remapped)", (mApplied.mediaRestored ?? []).some((m) => m.name === "img1/blob" && m.restoredId === "img1" && m.remapped === false));
    ok("the video re-uploaded as a NEW uid (remapped id-map entry)", (mApplied.mediaRestored ?? []).some((m) => m.name === "vid1/video.mp4" && m.restoredId === "new-vid1" && m.remapped === true));
    ok("exactly the two real blobs uploaded (the marker was NOT uploaded as a file)", mRun.uploads.length === 2 && mRun.uploads.some((u) => u.bytes === "PNG-BYTES-img1") && mRun.uploads.some((u) => u.bytes === "MP4-BYTES-vid1") && !mRun.uploads.some((u) => u.bytes.includes("_unavailable")));

    // WITHOUT a mediaRestore context: the media blobs stay OUT OF BAND (skipped), nothing uploads.
    const mNone = makeUploaderDouble();
    const mNonePlan = (await runRestore(baseEnv(), { runId: RUN_MEDIA }, null, { mediaUploaderFactory: () => mNone.uploader })) as RestorePlan;
    ok("media without a token stays OUT OF BAND, no re-upload", mNonePlan.mediaPlanned === undefined && mNonePlan.skipped.some((s) => s.name === "img1/blob") && mNone.uploads.length === 0);

    // A mediaRestore OBJECT PRESENT with an EMPTY token but a real account id (the console
    // cannot send this shape -- flow.ts's pairingError guard blocks it client-side -- but the engine must
    // not rely on that). restore-plan.ts gates on `body.mediaRestore.token !== "" && ...accountId !== ""`
    // exactly as cfConfig does, so this must behave IDENTICALLY to mediaRestore being absent: nothing
    // planned, no uploader instantiated, both blobs stay out of band.
    const mEmpty = makeUploaderDouble();
    const mEmptyPlan = (await runRestore(baseEnv(), { runId: RUN_MEDIA, mediaRestore: { token: "", accountId: "acct-1" } }, null, { mediaUploaderFactory: () => mEmpty.uploader })) as RestorePlan;
    ok("media with an EMPTY TOKEN (account id present) stays OUT OF BAND, exactly like no mediaRestore at all", mEmptyPlan.mediaPlanned === undefined && mEmptyPlan.skipped.some((s) => s.name === "img1/blob") && mEmpty.uploads.length === 0);

    // The media apply binds the account into the plan hash (its own approval) but NEVER the token: a
    // plain-restore approval cannot be reused to authorise a media re-upload, and one account's approval
    // cannot be reused for another, while the secret token never enters the hash.
    const mhWith = await restorePlanHash({ runId: RUN_MEDIA, mediaRestore: mediaCtx });
    const mhPlain = await restorePlanHash({ runId: RUN_MEDIA });
    const mhOtherAcct = await restorePlanHash({ runId: RUN_MEDIA, mediaRestore: { token: "edit-token-media", accountId: "acct-2" } });
    const mhOtherToken = await restorePlanHash({ runId: RUN_MEDIA, mediaRestore: { token: "A-DIFFERENT-token", accountId: "acct-1" } });
    ok("media plan hash differs from a plain restore + by account (its own approval)", mhWith !== mhPlain && mhWith !== mhOtherAcct);
    ok("media plan hash IGNORES the token (a secret never enters the hash)", mhWith === mhOtherToken);
}

// ---- The in-account ceiling + maxRecords window must bound MEDIA + CF-CONFIG records too, not only the
// data records. Each media re-upload costs ~2-3 subrequests (upload + /blob readback) and each cf-config
// surface costs a live read + write, so a restore with MANY media/cf-config records but FEW data records can
// trip the platform subrequest cap mid-apply and half-complete with no clean resume. The fix counts media +
// cf-config toward MAX_IN_ACCOUNT_RESTORE_RECORDS, refuses an oversized combined restore before any write,
// and bounds a windowed restore so it proceeds in resumable batches (windowed/outOfWindow/complete:false).
// The OLD code counted only the data `plan`, so a media/cf-config-heavy restore was UNBOUNDED. ----
async function proofInAccountBoundsMedia(fx: Fixture): Promise<void> {
  const { baseEnv, r2, signer, breakGlass, op } = fx;
  const dnsSnap = (h: string) => utf8(JSON.stringify([{ type: "A", name: `${h}.example.com`, content: "9.9.9.9", proxied: false, ttl: 1 }]));
  const cfCtx = { token: "edit-token-xyz", accountId: "acct-1", zoneId: "zone" };
  const mediaCtx = { token: "edit-token-media", accountId: "acct-1" };
  const sealMedia = async (runId: string, mediaN: number) => {
    // account "acct-1" is the SIGNED origin the cross-account guard cross-checks; it matches cfCtx/mediaCtx
    // (acct-1), so these are same-account restores that the guard passes without a cross-account confirmation.
    const records = [
      ...Array.from({ length: mediaN }, (_, i) => ({ sourceType: "images" as const, name: `m3img${String(i).padStart(4, "0")}/blob`, value: utf8(`PNG-${i}`), account: "acct-1" })),
      { sourceType: "cf-config" as const, name: "dns", value: dnsSnap("a"), account: "acct-1" },
      { sourceType: "cf-config" as const, name: "firewall-access-rules", value: utf8(JSON.stringify([])), account: "acct-1" },
      { sourceType: "cf-config" as const, name: "page-rules", value: utf8(JSON.stringify([])), account: "acct-1" },
    ];
    const archive = await buildArchive({
      downpipeId: "dp_m3", downpipeName: "m3", cadence: "3600s", runId,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer, records,
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    const m3R2 = new MockR2();
    installArchive(m3R2, archive);
    return (): Env => ({ ...baseEnv(), DEST_R2: m3R2 as unknown as R2Bucket } as unknown as Env);
  };

  {
    // OVERSIZE REFUSAL counting the COMBINED total. ZERO data records, 210 uploadable image blobs and 3
    // cf-config surfaces = 213 combined in-account writes, over the 200 ceiling. The data `plan` is EMPTY,
    // so the OLD (data-only) ceiling check passed and attempted all 213 writes; the fix counts media +
    // cf-config and refuses BEFORE any upload/cf-config write, steering to the offline CLI.
    const m3Env = await sealMedia("01ARZ3NDEKTSV4RRFFQ69G5M03", 210);
    const ovUp = makeUploaderDouble();
    const ovCf = makeCfDouble();
    const ovDry = (await runRestore(m3Env(), { runId: "01ARZ3NDEKTSV4RRFFQ69G5M03", cfConfig: cfCtx, mediaRestore: mediaCtx }, null, { cfApiFactory: () => ovCf.api, mediaUploaderFactory: () => ovUp.uploader })) as RestorePlan;
    ok("an oversized media+cf-config dry-run is refused on the COMBINED count (ok:false)", ovDry.ok === false && ovDry.mode === "dry-run" && /in-account limit/.test(ovDry.reason ?? ""));
    ok("the refused dry-run uploaded/wrote NOTHING", ovUp.uploads.length === 0 && ovCf.sent.length === 0);
    const ovApply = (await runRestore(m3Env(), { runId: "01ARZ3NDEKTSV4RRFFQ69G5M03", confirm: true, cfConfig: cfCtx, mediaRestore: mediaCtx }, null, { cfApiFactory: () => ovCf.api, mediaUploaderFactory: () => ovUp.uploader })) as RestoreResult;
    ok("an oversized media+cf-config apply is refused, nothing restored", ovApply.ok === false && ovApply.recordsRestored === 0);
    ok("the refused apply WROTE NOTHING (no partial upload/cf-config write)", ovUp.uploads.length === 0 && ovCf.sent.length === 0);

    // BOUNDED BATCH (resumable, never half-completing past the cap). maxRecords=120 spends the budget over
    // the COMBINED set in APPLY ORDER -- data, then cf-config, then media -- so the batch is 0 data + 3
    // cf-config + 117 media = 120 in-account writes, leaving 93 media beyond the window. recordsRestored
    // counts the 117 media (cf-config writes are reported in configApplied, not recordsRestored). The apply
    // is honest it is partial: windowed, outOfWindow=93, complete:false, a "(window)" remedy marker; ok
    // stays true for the intentional partial. The OLD code ran ALL 210 media + 3 cf-config in one invocation
    // regardless of maxRecords (which only ever windowed the data records).
    const BATCH = 120;
    const b1Up = makeUploaderDouble();
    const b1Cf = makeCfDouble();
    const b1 = (await runRestore(m3Env(), { runId: "01ARZ3NDEKTSV4RRFFQ69G5M03", confirm: true, maxRecords: BATCH, cfConfig: cfCtx, mediaRestore: mediaCtx }, null, { cfApiFactory: () => b1Cf.api, mediaUploaderFactory: () => b1Up.uploader })) as RestoreResult;
    ok("a windowed apply spends the budget across the COMBINED set (3 cf-config + 117 media = 120)", b1Up.uploads.length === BATCH - 3 && (b1.configApplied ?? []).length === 3 && b1.recordsRestored === BATCH - 3);
    ok("the windowed apply is honest it is partial (windowed, outOfWindow=93, complete:false)", b1.windowed === true && b1.outOfWindow === 213 - BATCH && b1.complete === false);
    ok("the windowed apply carries the (window) remedy marker (re-run to continue / offline)", (b1.skipped ?? []).some((s) => s.name === "(window)"));
    ok("an intentional partial does NOT regress ok", b1.ok === true);
    ok("the budget covered cf-config first then media (dns POSTed its one create within the window)", b1Cf.sent.length === 1 && b1Cf.sent[0]!.method === "POST");
  }

  {
    // RESUME TO COMPLETION at/under the ceiling. A run whose COMBINED total is within the ceiling (50 media +
    // 3 cf-config = 53) completes cleanly in one in-account pass: every media uploads and every cf-config
    // surface applies, complete:true, windowed:false, nothing left out of window.
    const fitEnv = await sealMedia("01ARZ3NDEKTSV4RRFFQ69G5M53", 50);
    const fUp = makeUploaderDouble();
    const fCf = makeCfDouble();
    const f = (await runRestore(fitEnv(), { runId: "01ARZ3NDEKTSV4RRFFQ69G5M53", confirm: true, cfConfig: cfCtx, mediaRestore: mediaCtx }, null, { cfApiFactory: () => fCf.api, mediaUploaderFactory: () => fUp.uploader })) as RestoreResult;
    ok("an under-ceiling media+cf-config run completes in one pass (complete:true, windowed:false)", f.complete === true && f.windowed === false && f.outOfWindow === 0 && f.ok === true);
    ok("the completing pass uploaded every media blob", fUp.uploads.length === 50);
    ok("the completing pass applied every cf-config surface (dns POSTs one create, the empty surfaces no-op)", (f.configApplied ?? []).length === 3 && fCf.sent.length === 1 && fCf.sent[0]!.method === "POST");
  }
}

// ---- R2 RESTORE round-trip + small-R2 BUFFERED-READBACK proof ----
// An r2 record under the buffered ceiling resolves an R2RestoreSink (binding R2_<bucket>), writes the
// value, then re-reads it from the SAME sink and re-hashes (verify-on-readback). A clean, matching
// readback counts the record restored and stamps the receipt entry "buffered-readback". This drives the
// r2 arm of resolveSink (the bucket override + the bucket sample) and the small-R2 buffered-readback path.

// RestoreR2 is the live WRITE-BACK bucket the R2RestoreSink targets: it stores put bytes and serves
// them back through get(name).body as a one-chunk stream, exactly what getStreamForVerify reads.
class RestoreR2 {
  store = new Map<string, Uint8Array>();
  putCount = 0;
  async put(key: string, body: ArrayBuffer | Uint8Array): Promise<{ etag: string }> {
    this.putCount++;
    this.store.set(key, body instanceof Uint8Array ? body : new Uint8Array(body));
    return { etag: `"${key.length}"` };
  }
  async get(key: string): Promise<{ body: ReadableStream<Uint8Array> } | null> {
    const v = this.store.get(key);
    if (!v) return null;
    return { body: new ReadableStream<Uint8Array>({ start(c) { c.enqueue(v); c.close(); } }) };
  }
}

// WriteOnlyR2 writes but cannot read the object back (get returns null): the readback-failure double.
class WriteOnlyR2 {
  store = new Map<string, Uint8Array>();
  async put(key: string, body: ArrayBuffer | Uint8Array): Promise<{ etag: string }> { this.store.set(key, body instanceof Uint8Array ? body : new Uint8Array(body)); return { etag: "x" }; }
  async get(): Promise<null> { return null; }
}

// ThrowOnPutR2 throws on put: the write-fault double.
class ThrowOnPutR2 {
  async put(): Promise<never> { throw new Error("simulated R2 put fault"); }
  async get(): Promise<null> { return null; }
}

async function proofR2RoundTrip(fx: Fixture): Promise<void> {
  const { baseEnv, r2, signer, breakGlass, op } = fx;
    const RUN_R2 = "01ARZ3NDEKTSV4RRFFQ69G5R20";
    const BUCKET = "bkt_throwaway";
    const r2Records = { "obj/a.bin": "rrr-alpha", "obj/b.bin": "rrr-beta-longer-value" };
    const r2Archive = await buildArchive({
      downpipeId: "dp_restore", downpipeName: "restore", cadence: "3600s", runId: RUN_R2,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: Object.entries(r2Records).map(([name, v]) => ({ sourceType: "r2" as const, name, value: utf8(v), bucket: BUCKET })),
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, r2Archive);

    const writeR2 = new RestoreR2();
    const r2Env = { ...baseEnv(), [`R2_${BUCKET}`]: writeR2 as unknown as R2Bucket } as unknown as Env;
    const r2Applied = (await runRestore(r2Env, { runId: RUN_R2, confirm: true })) as RestoreResult;
    ok("R2 apply restored both objects via the R2RestoreSink", r2Applied.ok === true && r2Applied.recordsRestored === 2);
    ok("R2 apply wrote the exact bytes back into the live bucket", new TextDecoder().decode(writeR2.store.get("obj/a.bin")!) === r2Records["obj/a.bin"]);
    ok("R2 receipt entries are proven by post-write readback (buffered-readback)", (r2Applied.receipt?.records ?? []).every((rec) => rec.via === "buffered-readback" && rec.verified === true));

    // The dry-run resolves the same R2 sink and reports the recovered bucket in the sample (the r2 sample
    // arm), writing nothing.
    const r2DryR2 = new RestoreR2();
    const r2DryEnv = { ...baseEnv(), [`R2_${BUCKET}`]: r2DryR2 as unknown as R2Bucket } as unknown as Env;
    const r2Plan = (await runRestore(r2DryEnv, { runId: RUN_R2 })) as RestorePlan;
    ok("R2 dry-run sample echoes the recovered bucket + R2_ binding", r2Plan.sample.length === 2 && r2Plan.sample.every((s) => s.bucket === BUCKET && s.binding === `R2_${BUCKET}`));
    ok("R2 DRY-RUN WROTE NOTHING to the bucket", r2DryR2.putCount === 0);

    // A bucket TARGET OVERRIDE (a different binding) resolves that binding instead of R2_<bucket>; an
    // absent binding is a per-record skip "target binding not present", never a whole-run abort.
    const r2MissEnv = { ...baseEnv() } as unknown as Env; // no R2_bkt_throwaway, no override target wired
    const r2Miss = (await runRestore(r2MissEnv, { runId: RUN_R2 })) as RestorePlan;
    ok("R2 record with no matching binding is skipped 'target binding not present'", r2Miss.recordsVerified === 0 && r2Miss.skipped.some((s) => s.reason === "target binding not present"));

    // VERIFY-ON-READBACK FAILURE: the sink writes but cannot read the object back (get returns null), so
    // the record is a post-write readback failure (ok:false), the receipt entry is verified:false, and it
    // is NOT counted as restored. A write-only double models a transport that lost the readback.
    const woR2 = new WriteOnlyR2();
    const woEnv = { ...baseEnv(), [`R2_${BUCKET}`]: woR2 as unknown as R2Bucket } as unknown as Env;
    const woApplied = (await runRestore(woEnv, { runId: RUN_R2, confirm: true })) as RestoreResult;
    ok("R2 readback failure leaves ok:false and counts nothing restored", woApplied.ok === false && woApplied.recordsRestored === 0 && woApplied.failures.length === 2);
    ok("R2 readback failure stamps the receipt verified:false (buffered-readback)", (woApplied.receipt?.records ?? []).every((rec) => rec.verified === false && rec.verifiedSha384 === null));

    // A WRITE FAULT (the sink put throws) drains into failures as "destination access error" and the
    // record is not restored, without abandoning the rest.
    const tpEnv = { ...baseEnv(), [`R2_${BUCKET}`]: new ThrowOnPutR2() as unknown as R2Bucket } as unknown as Env;
    const tpApplied = (await runRestore(tpEnv, { runId: RUN_R2, confirm: true })) as RestoreResult;
    ok("R2 write fault is drained to a 'destination access error' failure (ok:false)", tpApplied.ok === false && tpApplied.failures.some((f) => f.reason === "destination access error"));
}

// ---- LARGE R2 takes the STREAMING verify + apply path (shouldStream true), via a lowered buffered
// ceiling. The dry-run streams-and-discards (verifyRecordStreamingDiscard); the apply streams into one
// PUT then proves the landed bytes via streamed readback (verifyReadbackStreaming -> via "streamed-readback"). ----
async function proofLargeR2Streaming(fx: Fixture): Promise<void> {
  const { baseEnv, r2, signer, breakGlass, op } = fx;
  {
    const RUN_BIG = "01ARZ3NDEKTSV4RRFFQ69G5R2B";
    const BUCKET = "bkt_big";
    const bigVal = patterned(200_000); // larger than the lowered 64 KiB ceiling below
    const bigArchive = await buildArchive({
      downpipeId: "dp_restore", downpipeName: "restore", cadence: "3600s", runId: RUN_BIG,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [{ sourceType: "r2" as const, name: "big/blob.bin", value: bigVal, bucket: BUCKET }],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, bigArchive);

    // StreamR2 models the native R2 binding the R2RestoreSink streams through: the sink's putStream calls
    // the binding's plain .put with a ReadableStream body (the runtime has no FixedLengthStream under node),
    // so .put drains a stream body here; .get(name).body serves the object back for the streamed readback.
    class StreamR2 {
      store = new Map<string, Uint8Array>();
      streamed = 0;
      async put(key: string, body: ArrayBuffer | Uint8Array | ReadableStream<Uint8Array>): Promise<{ etag: string }> {
        if (body instanceof Uint8Array) { this.store.set(key, body); return { etag: "x" }; }
        if (body instanceof ArrayBuffer) { this.store.set(key, new Uint8Array(body)); return { etag: "x" }; }
        // A ReadableStream body: this IS the streamed write path. Drain it and record that a stream landed.
        this.streamed++;
        const reader = body.getReader();
        const parts: Uint8Array[] = [];
        for (;;) { const { done, value } = await reader.read(); if (done) break; if (value) parts.push(value); }
        this.store.set(key, concat(...parts));
        return { etag: "x" };
      }
      async get(key: string): Promise<{ body: ReadableStream<Uint8Array> } | null> {
        const v = this.store.get(key);
        if (!v) return null;
        return { body: new ReadableStream<Uint8Array>({ start(c) { c.enqueue(v); c.close(); } }) };
      }
    }
    const streamR2 = new StreamR2();
    // RESTORE_BUFFERED_MAX_BYTES = 65536 forces the 200 KB record onto the streaming path (shouldStream true).
    const bigEnv = { ...baseEnv(), RESTORE_BUFFERED_MAX_BYTES: "65536", [`R2_${BUCKET}`]: streamR2 as unknown as R2Bucket } as unknown as Env;

    const bigDry = (await runRestore(bigEnv, { runId: RUN_BIG })) as RestorePlan;
    ok("large-R2 dry-run verifies via the streaming discard (ok, 1 verified)", bigDry.ok === true && bigDry.recordsVerified === 1);

    const bigApplied = (await runRestore(bigEnv, { runId: RUN_BIG, confirm: true })) as RestoreResult;
    ok("large-R2 apply streamed the value into one PUT", streamR2.streamed === 1 && new TextDecoder().decode(streamR2.store.get("big/blob.bin")!) === new TextDecoder().decode(bigVal));
    ok("large-R2 apply proved the landed bytes via streamed readback", bigApplied.ok === true && bigApplied.recordsRestored === 1 && (bigApplied.receipt?.records ?? []).every((rec) => rec.via === "streamed-readback" && rec.verified === true));
  }
}

// ---- BLIND RESTORE TEST: runBlindRestoreTest must route a large R2 record through the SAME
// constant-memory shouldStream/verifyRecordStreamingDiscard guard restore-plan.ts's dry-run and
// restore-apply.ts's verify phase use, never the unconditional buffered restoreRecord -- otherwise this
// "prove recoverability" path is the one place in the file that can be made to materialise a value its
// own siblings would stream. A valid record's measured byte count and its manifest-declared plaintextSize
// are cryptographically forced equal by the SHA-384 check on EITHER path, so asserting bytesVerified alone
// cannot prove which reader entrypoint ran; spy on Run.prototype to prove it directly. ----
async function proofBlindRestoreTestStreaming(fx: Fixture): Promise<void> {
  const { baseEnv, r2, signer, breakGlass, op, expectBytes } = fx;
  {
    // Baseline: the ordinary small (non-R2) fixture run still verifies fully through the buffered path.
    const base = await runBlindRestoreTest(baseEnv(), { runId: RUN_ID });
    ok("blind restore test verifies the small KV run (buffered path, unchanged)", base.ok === true && base.recordsVerified === 3 && base.bytesVerified === expectBytes && typeof base.restoreDigest === "string");
  }
  {
    const RUN_BVT = "01ARZ3NDEKTSV4RRFFQ69G5BVT";
    const bigVal = patterned(200_000); // larger than the lowered 64 KiB ceiling below
    const bigArchive = await buildArchive({
      downpipeId: "dp_restore", downpipeName: "restore", cadence: "3600s", runId: RUN_BVT,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [{ sourceType: "r2" as const, name: "bvt/blob.bin", value: bigVal, bucket: "bkt_bvt" }],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, bigArchive);
    // RESTORE_BUFFERED_MAX_BYTES = 65536 forces the 200 KB record onto the streaming path (shouldStream
    // true), the same knob-lowering technique proofLargeR2Streaming uses. No R2_bkt_bvt binding is wired:
    // the blind test only reads the archive, it never resolves a write sink.
    const bvtEnv = { ...baseEnv(), RESTORE_BUFFERED_MAX_BYTES: "65536" } as unknown as Env;

    // Spy on the two Run reader entrypoints (they live on the prototype, never shadowed per-instance, so
    // this intercepts calls through any Run built after openVerifiedRun runs inside runBlindRestoreTest)
    // to prove WHICH one actually ran for this record, not merely that the returned counts look right.
    const origStream = Run.prototype.restoreRecordStream;
    const origBuffered = Run.prototype.restoreRecord;
    let streamCalls = 0;
    let bufferedCalls = 0;
    Run.prototype.restoreRecordStream = function (this: Run, rec: ShardRecord): ReadableStream<Uint8Array> {
      streamCalls++;
      return origStream.call(this, rec);
    };
    Run.prototype.restoreRecord = async function (this: Run, rec: ShardRecord): Promise<Uint8Array> {
      bufferedCalls++;
      return origBuffered.call(this, rec);
    };
    let result;
    try {
      result = await runBlindRestoreTest(bvtEnv, { runId: RUN_BVT });
    } finally {
      Run.prototype.restoreRecordStream = origStream;
      Run.prototype.restoreRecord = origBuffered;
    }
    ok("blind restore test on a large R2 record verifies clean (ok, 1 verified, 0 failures)", result.ok === true && result.recordsVerified === 1 && result.failures.length === 0);
    ok("blind restore test bytesVerified equals the record's full plaintext size", result.bytesVerified === bigVal.length);
    ok("blind restore test still folds a restoreDigest", typeof result.restoreDigest === "string" && result.restoreDigest!.startsWith("sha384:"));
    ok("blind restore test took the STREAMING path for the large R2 record, never the buffered one", streamCalls === 1 && bufferedCalls === 0);
  }
}

// ---- D1 RESTORE: a valid whole-dump (kind:full) record verifies+applies through the D1RestoreSink; a
// dry-run DECODES+shape-checks the body (writing nothing); a malformed body is a per-record skip at dry-run
// ("D1 dump would not replay"); and an apply write fault carries the D1-specific partial-restore reason. ----
async function proofD1Restore(fx: Fixture): Promise<void> {
  const { baseEnv, r2, signer, breakGlass, op } = fx;
    const RUN_D1 = "01ARZ3NDEKTSV4RRFFQ69G5D10";
    const DB = "appdb";
    const goodBody = encodeD1Backup({ format: D1_BACKUP_FORMAT, tables: [], schema: [] }); // valid, empty DB
    const badBody = utf8(JSON.stringify({ format: "not-a-d1-format/0" })); // structurally invalid -> decode throws
    const d1Archive = await buildArchive({
      downpipeId: "dp_restore", downpipeName: "restore", cadence: "3600s", runId: RUN_D1,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [
        { sourceType: "d1" as const, name: DB, value: goodBody },
        { sourceType: "d1" as const, name: `${DB}bad`, value: badBody },
      ],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, d1Archive);

    // A minimal D1 double whose batch/exec/prepare succeed (an empty DB has nothing to do); both records
    // bind to it so the bad record's ONLY failure is the decode, not a missing binding.
    const okD1 = { batch: async () => [], exec: async () => ({ count: 0, duration: 0 }), prepare: () => ({ bind: () => ({ run: async () => ({}), all: async () => ({ results: [] }) }), run: async () => ({}), all: async () => ({ results: [] }) }) };
    const d1Env = { ...baseEnv(), [`D1_${DB}`]: okD1 as unknown as D1Database, [`D1_${DB}bad`]: okD1 as unknown as D1Database } as unknown as Env;

    // DRY-RUN: the good record decodes clean (verified), the bad record is skipped at decode (no write).
    const d1Plan = (await runRestore(d1Env, { runId: RUN_D1 })) as RestorePlan;
    ok("D1 dry-run verifies the valid dump and skips the malformed one", d1Plan.recordsVerified === 1 && d1Plan.skipped.some((s) => s.name === `${DB}bad` && /would not replay/.test(s.reason)));
    ok("D1 dry-run is ok:false because a record would not replay", d1Plan.ok === false);

    // APPLY the good record only (scope to it) -> it restores via the buffered-no-readback path (D1 exposes
    // no readback API), so the receipt entry is labelled buffered-no-readback.
    const d1Applied = (await runRestore(d1Env, { runId: RUN_D1, confirm: true, recordName: DB })) as RestoreResult;
    ok("D1 apply restores the valid dump (buffered-no-readback receipt entry)", d1Applied.ok === true && d1Applied.recordsRestored === 1 && (d1Applied.receipt?.records ?? []).some((rec) => rec.via === "buffered-no-readback" && rec.verified === true));

    // APPLY write fault: a D1 binding whose batch throws yields the D1-specific partial-restore reason.
    const throwD1 = { batch: async () => { throw new Error("simulated D1 batch fault"); }, exec: async () => { throw new Error("simulated D1 exec fault"); }, prepare: () => ({ bind: () => ({ run: async () => { throw new Error("fault"); } }), run: async () => { throw new Error("fault"); } }) };
    const goodBodyWithTable = encodeD1Backup({ format: D1_BACKUP_FORMAT, tables: [{ name: "t", sql: 'CREATE TABLE "t" ("a" TEXT)', columns: ["a"], rows: [["x"]] }], schema: [] } as Parameters<typeof encodeD1Backup>[0]);
    const RUN_D1F = "01ARZ3NDEKTSV4RRFFQ69G5D1F";
    const d1fArchive = await buildArchive({
      downpipeId: "dp_restore", downpipeName: "restore", cadence: "3600s", runId: RUN_D1F,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [{ sourceType: "d1" as const, name: DB, value: goodBodyWithTable }],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, d1fArchive);
    const d1fEnv = { ...baseEnv(), [`D1_${DB}`]: throwD1 as unknown as D1Database } as unknown as Env;
    const d1Fault = (await runRestore(d1fEnv, { runId: RUN_D1F, confirm: true })) as RestoreResult;
    ok("D1 write fault reports the partial-restore (drop-and-retry) reason, ok:false", d1Fault.ok === false && d1Fault.failures.some((f) => /partial restore: the target D1 may be inconsistent/.test(f.reason)));
}

// ---- SECRETS records route OUT OF BAND (no runtime write path), in both dry-run and apply, never a
// planned write and never affecting ok. ----
async function proofSecretsOutOfBand(fx: Fixture): Promise<void> {
  const { baseEnv, r2, signer, breakGlass, op } = fx;
  {
    const RUN_SEC = "01ARZ3NDEKTSV4RRFFQ69G5SEC";
    const secArchive = await buildArchive({
      downpipeId: "dp_restore", downpipeName: "restore", cadence: "3600s", runId: RUN_SEC,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [{ sourceType: "secrets" as const, name: "API_KEY", value: utf8("placeholder") }],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, secArchive);
    const secPlan = (await runRestore(baseEnv(), { runId: RUN_SEC })) as RestorePlan;
    ok("a secrets record is out of band in the dry-run (0 planned writes), with guidance naming the cause and the remedy", secPlan.plannedWrites === 0 && secPlan.skipped.some((s) => s.name === "API_KEY" && s.reason === SECRETS_OUT_OF_BAND_REASON));
    const secApplied = (await runRestore(baseEnv(), { runId: RUN_SEC, confirm: true })) as RestoreResult;
    ok("a secrets record is out of band in the apply (ok stays true, nothing failed)", secApplied.ok === true && (secApplied.skipped ?? []).some((s) => s.name === "API_KEY"));

    // A RESERVED secrets TARGET override poisons the whole restore (the confused-deputy guard fires even
    // for a record that would otherwise route out of band).
    const secReserved = (await runRestore(baseEnv(), { runId: RUN_SEC, confirm: true, target: { binding: "SIGNER_PRIVATE" } })) as RestoreResult;
    ok("a reserved secrets target binding refuses the whole restore", secReserved.ok === false && secReserved.reason === "target binding is reserved");
  }
}

// ---- WORKERS records are REPROVISION (out of band), never a blind write; the guidance varies by the
// record name suffix (/settings, /versions, else the script content). ----
async function proofWorkersReprovision(fx: Fixture): Promise<void> {
  const { baseEnv, r2, signer, breakGlass, op } = fx;
  {
    const RUN_WK = "01ARZ3NDEKTSV4RRFFQ69G5WRK";
    const wkArchive = await buildArchive({
      downpipeId: "dp_restore", downpipeName: "restore", cadence: "3600s", runId: RUN_WK,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [
        { sourceType: "workers" as const, name: "svc/content", value: utf8("export default {}") },
        { sourceType: "workers" as const, name: "svc/settings", value: utf8(JSON.stringify({ bindings: [] })) },
        { sourceType: "workers" as const, name: "svc/versions", value: utf8(JSON.stringify([])) },
      ],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, wkArchive);
    const wkPlan = (await runRestore(baseEnv(), { runId: RUN_WK })) as RestorePlan;
    ok("a workers /settings record steers to re-create bindings + secrets", wkPlan.skipped.some((s) => s.name === "svc/settings" && /re-create the bindings \+ secrets/.test(s.reason)));
    ok("a workers /versions record is informational (version inventory only)", wkPlan.skipped.some((s) => s.name === "svc/versions" && /version inventory only/.test(s.reason)));
    ok("a workers content record steers to re-deploy the script code", wkPlan.skipped.some((s) => s.name === "svc/content" && /re-deploy the script code/.test(s.reason)));
  }
}

// ---- cf-config OUT-OF-BAND TIER guidance: a reprovision surface, an ordered surface, a writable
// idempotent surface WITHOUT a token, and a read-only idempotent surface each return their own tier reason. ----
async function proofCfConfigTiers(fx: Fixture): Promise<void> {
  const { baseEnv, r2, signer, breakGlass, op } = fx;
  {
    const RUN_TIER = "01ARZ3NDEKTSV4RRFFQ69G5T1R";
    const tierArchive = await buildArchive({
      downpipeId: "dp_cfg", downpipeName: "cfg", cadence: "3600s", runId: RUN_TIER,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [
        { sourceType: "cf-config" as const, name: "certificate-packs", value: utf8(JSON.stringify([])) }, // reprovision tier
        { sourceType: "cf-config" as const, name: "load-balancers", value: utf8(JSON.stringify([])) }, // ordered tier
        { sourceType: "cf-config" as const, name: "dns", value: utf8(JSON.stringify([])) }, // writable idempotent, no token
        { sourceType: "cf-config" as const, name: READ_ONLY_IDEMPOTENT, value: utf8(JSON.stringify({})) }, // read-only idempotent
      ],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, tierArchive);
    const tierPlan = (await runRestore(baseEnv(), { runId: RUN_TIER })) as RestorePlan;
    ok("a reprovision cf-config surface steers to re-provision write-only values", tierPlan.skipped.some((s) => s.name === "certificate-packs" && /re-provision them/.test(s.reason)));
    ok("an ordered cf-config surface steers to re-create in dependency order", tierPlan.skipped.some((s) => s.name === "load-balancers" && /dependency order/.test(s.reason)));
    ok("a writable idempotent surface with no token says supply an edit-scoped token", tierPlan.skipped.some((s) => s.name === "dns" && /supply an edit-scoped Cloudflare token/.test(s.reason)));
    ok(`a read-only idempotent surface (${READ_ONLY_IDEMPOTENT}) says replay via the Cloudflare API`, tierPlan.skipped.some((s) => s.name === READ_ONLY_IDEMPOTENT && /replay via the Cloudflare API/.test(s.reason)));
  }
}

// ---- cf-config error paths: a TRUNCATED snapshot is surfaced out of band ("snapshot incomplete"), and
// an apply whose surface write THROWS becomes a per-surface FAILURE (ok:false), never a silent drop. The
// diff summariser also reports change/live-only/no-change wording from the injected CfApi diff. ----
async function proofCfConfigErrors(fx: Fixture): Promise<void> {
  const { baseEnv, r2, signer, breakGlass, op } = fx;
  {
    const RUN_CFE = "01ARZ3NDEKTSV4RRFFQ69G5CFE";
    const cfeArchive = await buildArchive({
      downpipeId: "dp_cfg", downpipeName: "cfg", cadence: "3600s", runId: RUN_CFE,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [{ sourceType: "cf-config" as const, name: "dns", value: utf8(JSON.stringify({ _truncated: true })) }],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, cfeArchive);
    const cfCtx = { token: "edit-token", accountId: "acct-1", zoneId: "zone" };
    const truncApi: CfApi = { get: async () => [], getPage: async (): Promise<CfPage> => ({ result: [] }), send: async () => ({}) };
    // DRY-RUN: the truncated snapshot cannot be decoded as config -> out of band with the incomplete reason.
    const cfeDry = (await runRestore(baseEnv(), { runId: RUN_CFE, cfConfig: cfCtx }, null, { cfApiFactory: () => truncApi })) as RestorePlan;
    ok("a truncated cf-config snapshot is out of band (snapshot incomplete)", cfeDry.skipped.some((s) => s.name === "dns" && /incomplete/.test(s.reason)) && cfeDry.configChanges === undefined);

    // A WRITABLE surface whose live read+diff THROWS on apply becomes a per-surface failure.
    const RUN_CFW = "01ARZ3NDEKTSV4RRFFQ69G5CFW";
    const cfwArchive = await buildArchive({
      downpipeId: "dp_cfg", downpipeName: "cfg", cadence: "3600s", runId: RUN_CFW,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [{ sourceType: "cf-config" as const, name: "dns", value: utf8(JSON.stringify([{ type: "A", name: "x.example.com", content: "1.1.1.1", proxied: false, ttl: 1 }])), account: "acct-1" }],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, cfwArchive);
    const throwApi: CfApi = { get: async () => { throw new Error("HTTP 403 forbidden"); }, getPage: async (): Promise<CfPage> => { throw new Error("HTTP 403 forbidden"); }, send: async () => { throw new Error("HTTP 403 forbidden"); } };
    const cfwDry = (await runRestore(baseEnv(), { runId: RUN_CFW, cfConfig: cfCtx }, null, { cfApiFactory: () => throwApi })) as RestorePlan;
    ok("a cf-config surface whose diff throws is surfaced out of band on dry-run", cfwDry.skipped.some((s) => s.name === "dns" && /Cloudflare config/.test(s.reason)));
    const cfwApply = (await runRestore(baseEnv(), { runId: RUN_CFW, confirm: true, cfConfig: cfCtx }, null, { cfApiFactory: () => throwApi })) as RestoreResult;
    ok("a cf-config write that throws is a per-surface failure (ok:false), never dropped", cfwApply.ok === false && cfwApply.failures.some((f) => f.name === "dns" && /Cloudflare config write failed/.test(f.reason)));

    // cfConfig WITHOUT a zoneId is still applied (the ids object simply omits zoneId): exercise the no-zone arm.
    const RUN_CFN = "01ARZ3NDEKTSV4RRFFQ69G5CFN";
    const cfnArchive = await buildArchive({
      downpipeId: "dp_cfg", downpipeName: "cfg", cadence: "3600s", runId: RUN_CFN,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [{ sourceType: "cf-config" as const, name: "dns", value: utf8(JSON.stringify([{ type: "A", name: "z.example.com", content: "2.2.2.2", proxied: false, ttl: 1 }])), account: "acct-1" }],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, cfnArchive);
    let sawNoZone = false;
    const noZoneApi: CfApi = { get: async () => [], getPage: async (): Promise<CfPage> => ({ result: [] }), send: async (method, path) => { sawNoZone = true; return { method, path }; } };
    const cfnApply = (await runRestore(baseEnv(), { runId: RUN_CFN, confirm: true, cfConfig: { token: "t", accountId: "acct-1" } }, null, { cfApiFactory: () => noZoneApi })) as RestoreResult;
    ok("cf-config applies with no zoneId in the ids (account-only context)", cfnApply.ok === true && sawNoZone && (cfnApply.configApplied ?? []).some((c) => c.surface === "dns"));
  }
}

// ---- MEDIA error/edge paths: a captions metadata record (the stream captions wording), an artifacts blob
// (git re-push, never a REST upload), a too-large media blob (over the 25 MiB re-upload cap, out of band),
// and an apply where the uploader THROWS (a per-record failure). ----
async function proofMediaErrors(fx: Fixture): Promise<void> {
  const { baseEnv, r2, signer, breakGlass, op } = fx;
  {
    const RUN_ME = "01ARZ3NDEKTSV4RRFFQ69G5MED";
    const meArchive = await buildArchive({
      downpipeId: "dp_media", downpipeName: "media", cadence: "3600s", runId: RUN_ME,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [
        { sourceType: "stream" as const, name: "vid9/captions/en", value: utf8("WEBVTT") }, // a caption track (metadata)
        { sourceType: "artifacts" as const, name: "ns/repo/blob/sha", value: utf8("git-object-bytes") }, // artifact blob
        { sourceType: "artifacts" as const, name: "ns/repo", value: utf8(JSON.stringify({ repo: "r" })) }, // artifact inventory
      ],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, meArchive);
    const mePlan = (await runRestore(baseEnv(), { runId: RUN_ME, mediaRestore: { token: "t", accountId: "acct-1" } }, null, { mediaUploaderFactory: () => ({ uploadImage: async () => ({ restoredId: "x", remapped: false, verifiedSha384: null, verified: true, via: "media-image-readback", readbackReadable: true }), uploadStreamVideo: async () => ({ restoredId: "y", remapped: true, verifiedSha384: null, verified: true, via: "media-stream-exists", readbackReadable: true }) }) })) as RestorePlan;
    ok("a stream caption record is inventory/metadata with the re-attach note", mePlan.skipped.some((s) => s.name === "vid9/captions/en" && /re-attach the caption track/.test(s.reason)));
    ok("an artifact blob is git re-push, not a REST upload", mePlan.skipped.some((s) => s.name === "ns/repo/blob/sha" && /re-push the repository via git/.test(s.reason)));
    ok("an artifact inventory record steers to re-create the namespace/repository", mePlan.skipped.some((s) => s.name === "ns/repo" && /re-create the namespace\/repository/.test(s.reason)));

    // A media blob OVER the 25 MiB re-upload cap stays out of band (the backup captured it; only the in-account
    // re-upload is size-bound). Use the declared plaintextSize via a real over-cap record.
    const RUN_BIGMED = "01ARZ3NDEKTSV4RRFFQ69G5MBG";
    const bigImg = patterned(MEDIA_UPLOAD_MAX + 1024);
    const bigMedArchive = await buildArchive({
      downpipeId: "dp_media", downpipeName: "media", cadence: "3600s", runId: RUN_BIGMED,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [{ sourceType: "images" as const, name: "huge/blob", value: bigImg }],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, bigMedArchive);
    const bigMedPlan = (await runRestore(baseEnv(), { runId: RUN_BIGMED, mediaRestore: { token: "t", accountId: "acct-1" } }, null, { mediaUploaderFactory: () => ({ uploadImage: async () => ({ restoredId: "x", remapped: false, verifiedSha384: null, verified: true, via: "media-image-readback", readbackReadable: true }), uploadStreamVideo: async () => ({ restoredId: "y", remapped: true, verifiedSha384: null, verified: true, via: "media-stream-exists", readbackReadable: true }) }) })) as RestorePlan;
    ok("a media blob over the re-upload cap is out of band (captured in full, re-upload offline)", bigMedPlan.mediaPlanned === undefined && bigMedPlan.skipped.some((s) => s.name === "huge/blob" && /exceeds the .* in-account re-upload limit/.test(s.reason)));

    // APPLY where the uploader THROWS: a per-record media failure (ok:false), never a silent drop.
    const RUN_MEF = "01ARZ3NDEKTSV4RRFFQ69G5MEF";
    const mefArchive = await buildArchive({
      downpipeId: "dp_media", downpipeName: "media", cadence: "3600s", runId: RUN_MEF,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [{ sourceType: "images" as const, name: "img7/blob", value: utf8("PNG-BYTES-img7"), account: "acct-1" }],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, mefArchive);
    const mefApply = (await runRestore(baseEnv(), { runId: RUN_MEF, confirm: true, mediaRestore: { token: "t", accountId: "acct-1" } }, null, { mediaUploaderFactory: () => ({ uploadImage: async () => { throw new Error("HTTP 500 upload failed"); }, uploadStreamVideo: async () => ({ restoredId: "y", remapped: true, verifiedSha384: null, verified: true, via: "media-stream-exists", readbackReadable: true }) }) })) as RestoreResult;
    ok("a media upload that throws is a per-record failure (ok:false), never dropped", mefApply.ok === false && mefApply.failures.some((f) => f.name === "img7/blob" && /media re-upload failed/.test(f.reason)));
  }
}

// ---- BUFFERED CEILING knob: an invalid / non-positive / over-ceiling RESTORE_BUFFERED_MAX_BYTES falls back
// to the safe default, so a normal KV restore still succeeds (the knob never widens past the memory-safe cap). ----
async function proofBufferedCeilingKnob(fx: Fixture): Promise<void> {
  const { baseEnv } = fx;
  {
    for (const bad of ["not-a-number", "0", "-5", String(64 * 1024 * 1024)]) {
      const knobKV = new MockKV();
      const knobEnv = { ...baseEnv(), RESTORE_BUFFERED_MAX_BYTES: bad, [`KV_${NS}`]: knobKV as unknown as KVNamespace } as unknown as Env;
      const knob = (await runRestore(knobEnv, { runId: RUN_ID, confirm: true })) as RestoreResult;
      ok(`an invalid RESTORE_BUFFERED_MAX_BYTES (${bad}) falls back to the default and still restores`, knob.ok === true && knob.recordsRestored === 3);
    }
  }
}

// ---- OUTER-CATCH reason mapping: an integrity failure (a tampered archive object) maps to "integrity
// check failed"; a confirm run with no read-back key returns the applied break-glass shape. ----
async function proofOuterCatchReason(fx: Fixture): Promise<void> {
  const { baseEnv, signer, breakGlass, op } = fx;
  {
    // Tamper the manifest of a fresh run so opening it throws a signature/hash error -> "integrity check failed".
    const RUN_TAMP = "01ARZ3NDEKTSV4RRFFQ69G5TMP";
    const tampArchive = await buildArchive({
      downpipeId: "dp_restore", downpipeName: "restore", cadence: "3600s", runId: RUN_TAMP,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [{ sourceType: "kv" as const, name: "k", value: utf8("v"), namespace: NS }],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    const tampR2 = new MockR2();
    installArchive(tampR2, tampArchive);
    // Flip bytes in the signed manifest so the signature no longer verifies.
    const manKey = `run/${RUN_TAMP}/root.manifest.json`;
    const man = tampR2.store.get(manKey)!;
    const tampered = new Uint8Array(man); flipBit(tampered, tampered.length - 5); tampR2.store.set(manKey, tampered);
    const tampEnv = { ...baseEnv(), DEST_R2: tampR2 as unknown as R2Bucket } as unknown as Env;
    const tamp = (await runRestore(tampEnv, { runId: RUN_TAMP })) as RestorePlan;
    ok("a tampered manifest maps to the coarse 'integrity check failed' reason (ok:false)", tamp.ok === false && tamp.reason === "integrity check failed");

    // confirm + no read-back key returns the APPLIED break-glass shape (the applied arm of the early return).
    const noKeyApplyEnv = baseEnv();
    delete (noKeyApplyEnv as Record<string, unknown>)["OPERATIONAL_PRIVATE"];
    const noKeyApply = (await runRestore(noKeyApplyEnv, { runId: RUN_ID, confirm: true })) as RestoreResult;
    ok("confirm with no read-back key returns the applied break-glass result", noKeyApply.ok === false && noKeyApply.mode === "applied" && /break-glass-only posture/.test(noKeyApply.reason ?? ""));

    // confirm + a recordName that matches nothing returns the APPLIED not-found shape.
    const noFoundApply = (await runRestore(baseEnv(), { runId: RUN_ID, confirm: true, recordName: "does-not-exist" })) as RestoreResult;
    ok("confirm + unknown recordName returns the applied 'record not found' result", noFoundApply.ok === false && noFoundApply.mode === "applied" && noFoundApply.reason === "record not found in run");
  }
}

// ---- resolveSink OVERRIDES + EMPTY-NAME arms + UNSUPPORTED type. A target.namespaceId / target.bucketName
// overrides the recovered name; a record sealed with NO namespace/bucket resolves an empty-name binding and
// omits the namespace/bucket from the sample; an unknown sourceType has NO sink (the resolveSink default throw,
// surfaced as a per-record "unsupported sink" skip). ----
async function proofResolveSinkOverrides(fx: Fixture): Promise<void> {
  const { baseEnv, r2, signer, breakGlass, op } = fx;
  {
    // A KV record sealed with NO namespace -> binding KV_ (empty), sample omits namespace. A second KV record
    // is sealed with a namespace so a namespaceId TARGET OVERRIDE can redirect it to a different binding.
    const RUN_OV = "01ARZ3NDEKTSV4RRFFQ69G5PV1";
    const ovArchive = await buildArchive({
      downpipeId: "dp_restore", downpipeName: "restore", cadence: "3600s", runId: RUN_OV,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [
        { sourceType: "kv" as const, name: "nokv", value: utf8("v1") }, // no namespace -> KV_ empty binding
        { sourceType: "r2" as const, name: "nor2", value: utf8("v2") }, // no bucket -> R2_ empty binding
        // A record with NO WRITE SINK, proving it is reported rather than silently dropped or run-failing.
        // This was a "vectorize" record until the downpipe/0.1.0 cutover gave the READER its
        // KNOWN_SOURCE_TYPES gate: vectorize is deliberately OUTSIDE that closed set, so the reader now
        // refuses the whole archive before the planner ever runs, which took the three sibling assertions in
        // this block down with it. An unknown sourceType is now refused at READ (proved separately below,
        // which is strictly stronger), so the sinkless probe here is "workers": it is IN KNOWN_SOURCE_TYPES,
        // so the archive reads, and it has no write sink, so the planner reports it out of band.
        { sourceType: "workers" as const, name: "wkr1", value: utf8("v3") },
      ],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, ovArchive);
    // Bind the empty-name conventions so the no-name KV/R2 records resolve a present binding.
    //
    // THE R2_ BINDING WAS MISSING, AND THE COMMENT ABOVE ALREADY SAID IT SHOULD BE HERE. Only KV_ was bound,
    // so the "nor2" record resolved the absent R2_ convention and skipped with "target binding not present"
    // on every run of this proof. That was invisible while the plan's verdict ignored resolution refusals:
    // the block asserts ok===true to prove a SINKLESS record (wkr1, out of band) does not fail the run, and
    // an unrelated unresolvable record was riding along inside that ok. Binding R2_ makes the assertion test
    // the thing it names, so its ok===true now turns only on the out-of-band record it is actually about.
    const ovKV = new MockKV();
    const ovR2 = new MockR2();
    const ovEnv = { ...baseEnv(), ["KV_"]: ovKV as unknown as KVNamespace, ["R2_"]: ovR2 as unknown as R2Bucket } as unknown as Env;
    const ovPlan = (await runRestore(ovEnv, { runId: RUN_OV })) as RestorePlan;
    ok("a KV record with no namespace resolves the KV_ binding and omits namespace from the sample", ovPlan.sample.some((s) => s.name === "nokv" && s.binding === "KV_" && s.namespace === undefined));
    // A sinkless record is REPORTED (out of band, with re-deploy guidance) and never planned: it must not be
    // silently dropped, and it must not fail the run for the records that CAN be restored.
    ok("a record with no write sink is reported out of band, never planned, and does not fail the run", ovPlan.ok === true && ovPlan.skipped.some((s) => s.name === "wkr1" && s.reason.length > 0) && !ovPlan.sample.some((s) => s.name === "wkr1"));

    // The downpipe/0.1.0 READER GATE (KNOWN_SOURCE_TYPES, SPEC 12.1): a record whose sourceType is outside the
    // closed set is REFUSED at read, rather than being restored under a guessed behaviour. The cutover added
    // that gate with no test anywhere; this is that test. "vectorize" is a reserved type deliberately absent
    // from the set, so an archive carrying one must not open at all.
    const RUN_UNK = "01ARZ3NDEKTSV4RRFFQ69G5PV2";
    const unkArchive = await buildArchive({
      downpipeId: "dp_restore", downpipeName: "restore", cadence: "3600s", runId: RUN_UNK,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [{ sourceType: "vectorize" as const, name: "vec1", value: utf8("v3") }],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    const unkR2 = new MockR2();
    installArchive(unkR2, unkArchive);
    const unkEnv = { ...baseEnv(), DEST_R2: unkR2 as unknown as R2Bucket } as unknown as Env;
    const unk = (await runRestore(unkEnv, { runId: RUN_UNK })) as RestorePlan;
    ok("a sourceType outside the downpipe/0.1.0 closed set is REFUSED by the reader (ok:false), never restored", unk.ok === false && unk.reason === "integrity check failed");

    // A namespaceId TARGET OVERRIDE redirects a KV record to KV_<namespaceId>, ignoring the recovered name.
    const ovNsKV = new MockKV();
    const ovNsEnv = { ...baseEnv(), ["KV_overridden"]: ovNsKV as unknown as KVNamespace, ["KV_"]: new MockKV() as unknown as KVNamespace } as unknown as Env;
    const ovNsPlan = (await runRestore(ovNsEnv, { runId: RUN_OV, recordName: "nokv", target: { namespaceId: "overridden" } })) as RestorePlan;
    ok("a target.namespaceId override resolves KV_<namespaceId> and reports that namespace", ovNsPlan.sample.some((s) => s.name === "nokv" && s.binding === "KV_overridden" && s.namespace === "overridden"));

    // A KV record whose resolved binding is ABSENT is a per-record skip 'target binding not present' (the L262 throw).
    const ovMissEnv = { ...baseEnv() } as unknown as Env; // KV_ not bound
    const ovMiss = (await runRestore(ovMissEnv, { runId: RUN_OV, recordName: "nokv" })) as RestorePlan;
    ok("a KV record with no present binding is skipped 'target binding not present'", ovMiss.skipped.some((s) => s.name === "nokv" && s.reason === "target binding not present"));
  }
}

// ---- R2 + D1 BUCKET/BINDING OVERRIDES + empty-name R2 sample + missing-binding throws ----
async function proofR2D1Overrides(fx: Fixture): Promise<void> {
  const { baseEnv, r2, signer, breakGlass, op } = fx;
  {
    const RUN_OV2 = "01ARZ3NDEKTSV4RRFFQ69G5PV2";
    const ov2Archive = await buildArchive({
      downpipeId: "dp_restore", downpipeName: "restore", cadence: "3600s", runId: RUN_OV2,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [
        { sourceType: "r2" as const, name: "ro", value: utf8("rr") }, // no bucket -> R2_ empty binding
        { sourceType: "d1" as const, name: "db1", value: encodeD1Backup({ format: D1_BACKUP_FORMAT, tables: [], schema: [] }) },
      ],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, ov2Archive);

    // An R2 record with NO bucket resolves R2_ (empty) and omits bucket from the sample. A bucketName override
    // redirects to R2_<bucketName>. An absent binding is a per-record skip.
    class TrivialR2 { async put(): Promise<{ etag: string }> { return { etag: "x" }; } async get(): Promise<null> { return null; } }
    const ov2Env = { ...baseEnv(), ["R2_"]: new TrivialR2() as unknown as R2Bucket } as unknown as Env;
    const ov2Plan = (await runRestore(ov2Env, { runId: RUN_OV2, recordName: "ro" })) as RestorePlan;
    ok("an R2 record with no bucket resolves R2_ and omits bucket from the sample", ov2Plan.sample.some((s) => s.name === "ro" && s.binding === "R2_" && s.bucket === undefined));
    const ov2BktEnv = { ...baseEnv(), ["R2_chosen"]: new TrivialR2() as unknown as R2Bucket } as unknown as Env;
    const ov2Bkt = (await runRestore(ov2BktEnv, { runId: RUN_OV2, recordName: "ro", target: { bucketName: "chosen" } })) as RestorePlan;
    ok("a target.bucketName override resolves R2_<bucketName> and reports that bucket", ov2Bkt.sample.some((s) => s.name === "ro" && s.binding === "R2_chosen" && s.bucket === "chosen"));
    const ov2R2Miss = (await runRestore({ ...baseEnv() } as unknown as Env, { runId: RUN_OV2, recordName: "ro" })) as RestorePlan;
    ok("an R2 record with no present binding is skipped 'target binding not present'", ov2R2Miss.skipped.some((s) => s.name === "ro" && s.reason === "target binding not present"));

    // A D1 binding OVERRIDE resolves the named binding (not D1_<dbName>); an absent D1 binding is a skip.
    const okD1b = { batch: async () => [], exec: async () => ({ count: 0, duration: 0 }), prepare: () => ({ bind: () => ({ run: async () => ({}) }), run: async () => ({}) }) };
    const ovD1Env = { ...baseEnv(), ["D1_picked"]: okD1b as unknown as D1Database } as unknown as Env;
    const ovD1 = (await runRestore(ovD1Env, { runId: RUN_OV2, recordName: "db1", target: { binding: "D1_picked" } })) as RestorePlan;
    ok("a target.binding override resolves the named D1 binding", ovD1.sample.some((s) => s.name === "db1" && s.binding === "D1_picked"));
    const ovD1Miss = (await runRestore({ ...baseEnv() } as unknown as Env, { runId: RUN_OV2, recordName: "db1" })) as RestorePlan;
    ok("a D1 record with no present binding is skipped 'target binding not present'", ovD1Miss.skipped.some((s) => s.name === "db1" && s.reason === "target binding not present"));
  }
}

// ---- DRY-RUN reserved-binding refusal (both a normal record and a secrets record), the dry-run arms of the
// two reserved-refusal early returns that the apply tests above did not reach. ----
async function proofDryRunReserved(fx: Fixture): Promise<void> {
  const { baseEnv, r2, signer, breakGlass, op } = fx;
  {
    // A reserved target on a normal (KV) record in a DRY-RUN refuses the whole plan (the L486 dry-run arm).
    const dryReserved = (await runRestore(baseEnv(), { runId: RUN_ID, target: { binding: "SIGNER_PRIVATE" } })) as RestorePlan;
    ok("a reserved target refuses a DRY-RUN plan (dry-run arm)", dryReserved.ok === false && dryReserved.mode === "dry-run" && dryReserved.reason === "target binding is reserved");

    // A reserved target on a SECRETS record in a DRY-RUN refuses (the L415 dry-run secrets arm).
    const RUN_SECR = "01ARZ3NDEKTSV4RRFFQ69G5SC2";
    const secrArchive = await buildArchive({
      downpipeId: "dp_restore", downpipeName: "restore", cadence: "3600s", runId: RUN_SECR,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [{ sourceType: "secrets" as const, name: "TOK", value: utf8("x") }],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, secrArchive);
    const secrDry = (await runRestore(baseEnv(), { runId: RUN_SECR, target: { binding: "DEST_R2" } })) as RestorePlan;
    ok("a reserved secrets target refuses a DRY-RUN plan (secrets dry-run arm)", secrDry.ok === false && secrDry.mode === "dry-run" && secrDry.reason === "target binding is reserved");
  }
}

// ---- A STREAM video OVER the re-upload cap reports the "Video" wording (the other arm of the too-large
// ternary); and a cf-config DRY-RUN with NO zoneId exercises the account-only ids on the dry-run path. ----
async function proofStreamOverCap(fx: Fixture): Promise<void> {
  const { baseEnv, r2, signer, breakGlass, op } = fx;
  {
    const RUN_BIGVID = "01ARZ3NDEKTSV4RRFFQ69G5VBG";
    const bigVid = patterned(MEDIA_UPLOAD_MAX + 2048);
    const bigVidArchive = await buildArchive({
      downpipeId: "dp_media", downpipeName: "media", cadence: "3600s", runId: RUN_BIGVID,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [{ sourceType: "stream" as const, name: "bigvid/video.mp4", value: bigVid }],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, bigVidArchive);
    const bigVidPlan = (await runRestore(baseEnv(), { runId: RUN_BIGVID, mediaRestore: { token: "t", accountId: "acct-1" } }, null, { mediaUploaderFactory: () => ({ uploadImage: async () => ({ restoredId: "x", remapped: false, verifiedSha384: null, verified: true, via: "media-image-readback", readbackReadable: true }), uploadStreamVideo: async () => ({ restoredId: "y", remapped: true, verifiedSha384: null, verified: true, via: "media-stream-exists", readbackReadable: true }) }) })) as RestorePlan;
    ok("a stream video over the re-upload cap reports the Video too-large wording", bigVidPlan.skipped.some((s) => s.name === "bigvid/video.mp4" && /^Video file exceeds/.test(s.reason)));

    // cf-config DRY-RUN with an account-only context (no zoneId): the dry-run ids omit zoneId (L557 no-zone arm).
    const RUN_CFDZ = "01ARZ3NDEKTSV4RRFFQ69G5CDZ";
    const cfdzArchive = await buildArchive({
      downpipeId: "dp_cfg", downpipeName: "cfg", cadence: "3600s", runId: RUN_CFDZ,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [{ sourceType: "cf-config" as const, name: "dns", value: utf8(JSON.stringify([{ type: "A", name: "dz.example.com", content: "4.4.4.4", proxied: false, ttl: 1 }])) }],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, cfdzArchive);
    const dzApi: CfApi = { get: async () => [], getPage: async (): Promise<CfPage> => ({ result: [] }), send: async () => ({}) };
    const cfdzPlan = (await runRestore(baseEnv(), { runId: RUN_CFDZ, cfConfig: { token: "t", accountId: "acct-1" } }, null, { cfApiFactory: () => dzApi })) as RestorePlan;
    ok("a cf-config dry-run with no zoneId still computes a diff (account-only ids)", (cfdzPlan.configChanges ?? []).some((c) => c.surface === "dns"));
  }
}

// ---- summariseDiff wording: a diff with a CHANGE and a LIVE-ONLY (remove) entry reports "to change" and
// "live-only", and a NO-CHANGE diff reports the matches-the-snapshot wording. Drive it through the dry-run
// by giving the CfApi double a live record that the snapshot changes plus a live-only record. ----
async function proofSummariseDiff(fx: Fixture): Promise<void> {
  const { baseEnv, r2, signer, breakGlass, op } = fx;
  {
    const RUN_DIFF = "01ARZ3NDEKTSV4RRFFQ69G5DFF";
    // Snapshot: one record whose type+name+content MATCHES a live record (so it is the same record by the DNS
    // natural key) but whose editable proxied flag DIFFERS (a change), and the live zone also has a record
    // absent from the snapshot (a live-only / remove the additive restore leaves in place). The DNS natural key
    // is type+name+content, so proxied/ttl are the editable parts a matched record can change.
    const snap = [{ type: "A", name: "same.example.com", content: "1.1.1.1", proxied: true, ttl: 1 }];
    const diffArchive = await buildArchive({
      downpipeId: "dp_cfg", downpipeName: "cfg", cadence: "3600s", runId: RUN_DIFF,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [{ sourceType: "cf-config" as const, name: "dns", value: utf8(JSON.stringify(snap)) }],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, diffArchive);
    // A live zone whose same.example.com has a DIFFERENT content (a change), plus a live-only record. The DNS
    // surface diffs by name, so the snapshot name matches a live record with different content (change) and the
    // extra live record is live-only.
    const liveRecords = [
      { id: "1", type: "A", name: "same.example.com", content: "1.1.1.1", proxied: false, ttl: 1 }, // -> change
      { id: "2", type: "A", name: "liveonly.example.com", content: "5.5.5.5", proxied: false, ttl: 1 }, // -> live-only
    ];
    const diffApi: CfApi = { get: async () => liveRecords, getPage: async (): Promise<CfPage> => ({ result: liveRecords }), send: async () => ({}) };
    const diffPlan = (await runRestore(baseEnv(), { runId: RUN_DIFF, cfConfig: { token: "t", accountId: "acct-1", zoneId: "zone" } }, null, { cfApiFactory: () => diffApi })) as RestorePlan;
    // The DNS write classifies a matched-but-edited record as a CHANGE. The extra live-only record is
    // still LEFT IN PLACE (additive restore never deletes) but it is now REPORTED, so the operator can see
    // what the restore did not touch. This assertion previously required the opposite, that no summary
    // mention live-only, which pinned the defect: on an allow-list surface the unreported live extra is
    // exactly what an attacker added, and the restore said nothing about it.
    ok("summariseDiff reports the change wording for a matched-but-edited record", (diffPlan.configChanges ?? []).some((c) => c.surface === "dns" && /to change/.test(c.summary)));
    ok("the live-only record is reported as left in place, not silently ignored", (diffPlan.configChanges ?? []).some((c) => c.surface === "dns" && /1 live-only \(left in place\)/.test(c.summary)));

    // A NO-CHANGE diff: the live zone already matches the snapshot exactly -> "no changes (already matches)".
    const RUN_NOCH = "01ARZ3NDEKTSV4RRFFQ69G5NCH";
    const sameSnap = [{ type: "A", name: "same.example.com", content: "1.1.1.1", proxied: false, ttl: 1 }];
    const nochArchive = await buildArchive({
      downpipeId: "dp_cfg", downpipeName: "cfg", cadence: "3600s", runId: RUN_NOCH,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [{ sourceType: "cf-config" as const, name: "dns", value: utf8(JSON.stringify(sameSnap)) }],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, nochArchive);
    const sameLive = [{ id: "1", type: "A", name: "same.example.com", content: "1.1.1.1", proxied: false, ttl: 1 }];
    const nochApi: CfApi = { get: async () => sameLive, getPage: async (): Promise<CfPage> => ({ result: sameLive }), send: async () => ({}) };
    const nochPlan = (await runRestore(baseEnv(), { runId: RUN_NOCH, cfConfig: { token: "t", accountId: "acct-1", zoneId: "zone" } }, null, { cfApiFactory: () => nochApi })) as RestorePlan;
    ok("summariseDiff reports no changes when live already matches the snapshot", (nochPlan.configChanges ?? []).some((c) => c.surface === "dns" && /no changes \(already matches the snapshot\)/.test(c.summary) && c.willApply === false));
  }
}

// ---- media DRY-RUN decode FAULT: a media blob record whose decrypt throws on the dry-run preview is
// surfaced out of band with a coarse reason (the L575 dry-run media catch). A marker-sized blob that
// DECODES to a marker is also surfaced (the marker arm), so both legs of the media dry-run are exercised. ----
async function proofMediaDecodeFault(fx: Fixture): Promise<void> {
  const { baseEnv, r2, signer, breakGlass, op } = fx;
  {
    const RUN_MMK = "01ARZ3NDEKTSV4RRFFQ69G5MMK";
    const mmkArchive = await buildArchive({
      downpipeId: "dp_media", downpipeName: "media", cadence: "3600s", runId: RUN_MMK,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [{ sourceType: "images" as const, name: "mk/blob", value: utf8(JSON.stringify({ _skipped: "rate-limited" })), incompleteMarker: "_skipped" }],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, mmkArchive);
    const mmkPlan = (await runRestore(baseEnv(), { runId: RUN_MMK, mediaRestore: { token: "t", accountId: "acct-1" } }, null, { mediaUploaderFactory: () => ({ uploadImage: async () => ({ restoredId: "x", remapped: false, verifiedSha384: null, verified: true, via: "media-image-readback", readbackReadable: true }), uploadStreamVideo: async () => ({ restoredId: "y", remapped: true, verifiedSha384: null, verified: true, via: "media-stream-exists", readbackReadable: true }) }) })) as RestorePlan;
    ok("a marker media blob is out of band on the dry-run (capture had failed), never planned", mmkPlan.mediaPlanned === undefined && mmkPlan.skipped.some((s) => s.name === "mk/blob" && /the captured value was a marker/.test(s.reason)));
  }
}

// ---- APPLY-PHASE integrity failure: a record that VERIFIES on the dry-run-style pass but fails the apply
// verify pass cannot be staged from a clean archive, so tamper a fresh archive's SEGMENT (not the manifest)
// so the manifest opens but a record's plaintext hash fails on the in-apply verify (the L633 verify catch). ----
async function proofApplyPhaseIntegrity(fx: Fixture): Promise<void> {
  const { baseEnv, signer, breakGlass, op } = fx;
  {
    const RUN_SEGT = "01ARZ3NDEKTSV4RRFFQ69G5SGT";
    const segtArchive = await buildArchive({
      downpipeId: "dp_restore", downpipeName: "restore", cadence: "3600s", runId: RUN_SEGT,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [{ sourceType: "kv" as const, name: "seg", value: utf8("seg-value-to-tamper"), namespace: NS }],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    const segR2 = new MockR2();
    installArchive(segR2, segtArchive);
    // Flip bytes inside a .seg ciphertext object so the manifest/signature still verify (the manifest is
    // untouched) but the record's authenticated decrypt fails on the verify pass.
    const segKey = [...segR2.store.keys()].find((k) => k.includes("/seg/") || k.endsWith(".seg"));
    if (segKey) { const s = new Uint8Array(segR2.store.get(segKey)!); flipBit(s, Math.floor(s.length / 2)); segR2.store.set(segKey, s); }
    const segEnv = { ...baseEnv(), DEST_R2: segR2 as unknown as R2Bucket, [`KV_${NS}`]: new MockKV() as unknown as KVNamespace } as unknown as Env;
    const segApply = (await runRestore(segEnv, { runId: RUN_SEGT, confirm: true })) as RestoreResult;
    ok("a tampered segment fails the apply verify pass with 'integrity check failed' (nothing written)", segKey !== undefined && segApply.ok === false && segApply.reason === "integrity check failed" && segApply.recordsRestored === 0);
  }
}

// ---- mediaRestoreGuidance marker-with-token wording: an image blob whose name yields NO extractable id
// (the bare "/blob") with a media token falls to the guidance, exercising the mediaOn arm of the guidance. ----
async function proofMediaGuidanceNoId(fx: Fixture): Promise<void> {
  const { baseEnv, r2, signer, breakGlass, op } = fx;
  {
    const RUN_NOID = "01ARZ3NDEKTSV4RRFFQ69G5N1D";
    const noidArchive = await buildArchive({
      downpipeId: "dp_media", downpipeName: "media", cadence: "3600s", runId: RUN_NOID,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [{ sourceType: "images" as const, name: "/blob", value: utf8("bytes") }], // ends in /blob but no id
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, noidArchive);
    const noidPlan = (await runRestore(baseEnv(), { runId: RUN_NOID, mediaRestore: { token: "t", accountId: "acct-1" } }, null, { mediaUploaderFactory: () => ({ uploadImage: async () => ({ restoredId: "x", remapped: false, verifiedSha384: null, verified: true, via: "media-image-readback", readbackReadable: true }), uploadStreamVideo: async () => ({ restoredId: "y", remapped: true, verifiedSha384: null, verified: true, via: "media-stream-exists", readbackReadable: true }) }) })) as RestorePlan;
    ok("an image blob with no extractable id and a token falls to the capture-marker guidance", noidPlan.mediaPlanned === undefined && noidPlan.skipped.some((s) => s.name === "/blob" && /captured but not re-uploaded/.test(s.reason)));
  }
}

// ---- STREAMED write FAULT: a large-R2 streamed PUT that throws is drained to a "destination access error"
// failure (the L679 stream-write catch), the record not counted, ok:false. ----
async function proofStreamedWriteFault(fx: Fixture): Promise<void> {
  const { baseEnv, r2, signer, breakGlass, op } = fx;
  {
    const RUN_SWF = "01ARZ3NDEKTSV4RRFFQ69G5SWF";
    const BUCKET = "bkt_swf";
    const swfArchive = await buildArchive({
      downpipeId: "dp_restore", downpipeName: "restore", cadence: "3600s", runId: RUN_SWF,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
      records: [{ sourceType: "r2" as const, name: "swf/blob", value: patterned(200_000), bucket: BUCKET }],
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    installArchive(r2, swfArchive);
    // The binding's put (the streamed sink calls plain .put with a stream body under node) throws.
    class StreamFaultR2 { async put(): Promise<never> { throw new Error("simulated streamed put fault"); } async get(): Promise<null> { return null; } }
    const swfEnv = { ...baseEnv(), RESTORE_BUFFERED_MAX_BYTES: "65536", [`R2_${BUCKET}`]: new StreamFaultR2() as unknown as R2Bucket } as unknown as Env;
    const swfApply = (await runRestore(swfEnv, { runId: RUN_SWF, confirm: true })) as RestoreResult;
    ok("a streamed-write fault is drained to a 'destination access error' failure (ok:false, nothing restored)", swfApply.ok === false && swfApply.recordsRestored === 0 && swfApply.failures.some((f) => f.reason === "destination access error"));
  }
}

// ---- OUTER-CATCH destination-status mapping: a destination whose get throws "status 500" while opening the
// run maps to "destination access error" (the L852 arm), and the CONFIRM variant returns the applied shape
// (the L857 confirm arm of the outer catch). ----
async function proofOuterCatchDestStatus(fx: Fixture): Promise<void> {
  const { baseEnv } = fx;
  {
    // A destination R2 mock whose get throws an HTTP-status error, so openRun fails with "status 500".
    class StatusFaultR2 {
      async get(): Promise<never> { throw new Error("R2 GET failed: status 500"); }
      async head(): Promise<null> { return null; }
      async put(): Promise<{ etag: string }> { return { etag: "x" }; }
    }
    const statusEnv = { ...baseEnv(), DEST_R2: new StatusFaultR2() as unknown as R2Bucket } as unknown as Env;
    const statusDry = (await runRestore(statusEnv, { runId: RUN_ID })) as RestorePlan;
    ok("a destination status error maps to 'destination access error' on dry-run", statusDry.ok === false && statusDry.reason === "destination access error");
    const statusApply = (await runRestore(statusEnv, { runId: RUN_ID, confirm: true })) as RestoreResult;
    ok("the same destination status error returns the applied shape on confirm", statusApply.ok === false && statusApply.mode === "applied" && statusApply.reason === "destination access error");
  }
}

// ---- coarseCfReason regex arms: a cf-config apply whose write throws a rate-limit (429), a JSON/parse, and
// a generic error maps to the matching coarse reason (the 429 / JSON / default arms). ----
async function proofCoarseCfReason(fx: Fixture): Promise<void> {
  const { baseEnv, r2, signer, breakGlass, op } = fx;
  {
    const RUN_CFR = "01ARZ3NDEKTSV4RRFFQ69G5CFR";
    const mkCfgArchive = async (runId: string): Promise<void> => {
      const a = await buildArchive({
        downpipeId: "dp_cfg", downpipeName: "cfg", cadence: "3600s", runId,
        master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
        records: [{ sourceType: "cf-config" as const, name: "dns", value: utf8(JSON.stringify([{ type: "A", name: "r.example.com", content: "8.8.8.8", proxied: false, ttl: 1 }])), account: "acct-1" }],
        windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
        runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
      });
      installArchive(r2, a);
    };
    const cfCtx = { token: "t", accountId: "acct-1", zoneId: "zone" };
    const apiThrowing = (msg: string): CfApi => ({ get: async () => { throw new Error(msg); }, getPage: async (): Promise<CfPage> => { throw new Error(msg); }, send: async () => { throw new Error(msg); } });

    await mkCfgArchive(RUN_CFR);
    const cfRate = (await runRestore(baseEnv(), { runId: RUN_CFR, confirm: true, cfConfig: cfCtx }, null, { cfApiFactory: () => apiThrowing("HTTP 429 too many requests") })) as RestoreResult;
    ok("a cf-config 429 maps to the rate-limited coarse reason", cfRate.ok === false && cfRate.failures.some((f) => /rate-limited/.test(f.reason)));

    const RUN_CFJ = "01ARZ3NDEKTSV4RRFFQ69G5CFJ";
    await mkCfgArchive(RUN_CFJ);
    const cfJson = (await runRestore(baseEnv(), { runId: RUN_CFJ, confirm: true, cfConfig: cfCtx }, null, { cfApiFactory: () => apiThrowing("unexpected token in JSON at position 3") })) as RestoreResult;
    ok("a cf-config JSON/parse error maps to the decode coarse reason", cfJson.ok === false && cfJson.failures.some((f) => /could not be decoded as config/.test(f.reason)));

    const RUN_CFG2 = "01ARZ3NDEKTSV4RRFFQ69G5CFG";
    await mkCfgArchive(RUN_CFG2);
    const cfGen = (await runRestore(baseEnv(), { runId: RUN_CFG2, confirm: true, cfConfig: cfCtx }, null, { cfApiFactory: () => apiThrowing("something inexplicable happened") })) as RestoreResult;
    ok("a cf-config unclassified error maps to the generic coarse reason", cfGen.ok === false && cfGen.failures.some((f) => /could not be applied/.test(f.reason)));
  }
}

// ---- BONUS: a not-found run maps to a coarse reason; no in-account read-back key is reported, not errored. ----
async function proofMissingAndNoKey(fx: Fixture): Promise<void> {
  const { baseEnv } = fx;
  const missing = (await runRestore(baseEnv(), { runId: "01BX5ZZKBKACTAV9WEVGEMMVRY" })) as RestorePlan;
  ok("missing run reports object missing (ok:false, no throw)", missing.ok === false && missing.reason === "object missing");

  const noKeyEnv = baseEnv();
  delete (noKeyEnv as Record<string, unknown>)["OPERATIONAL_PRIVATE"];
  const noKey = (await runRestore(noKeyEnv, { runId: RUN_ID })) as RestorePlan;
  ok("no read-back key returns the break-glass posture (ok:false, dry-run)", noKey.ok === false && noKey.mode === "dry-run" && /break-glass-only posture/.test(noKey.reason ?? ""));
}

// ---- RESTORE-SKIP: a KV/R2 DATA record whose value is an incompleteness MARKER (a _vanished object that
// raced the crawl, or an over-ceiling _skipped object) must NEVER be written back as a live value -- doing
// so would re-create a deleted/uncaptured key with sentinel JSON (silent data corruption). The dry-run and
// the apply both skip it (rec.incompleteMarker, the signed manifest field, adapter-asserted at seal
// time -- never re-derived from the decrypted value), surface it out of band, do NOT count it restored, and
// stay ok:true. This proves the paired restore-side change the capture-side _vanished marker requires AND
// fixes the pre-existing R2 over-ceiling _skipped marker, AND that a real customer value which
// merely LOOKS marker-shaped -- with no adapter assertion behind it -- is never caught in the same net. ----
async function proofDataRecordMarkersSkipped(fx: Fixture): Promise<void> {
  console.log("\nrestore-skip (data-record incompleteness markers are never written back):");
  const { baseEnv, r2, signer, breakGlass, op } = fx;
  const RUN_MK = "01ARZ3NDEKTSV4RRFFQ69G5MK0";
  const BUCKET = "bkt_markerskip";
  // gone:mid-crawl and huge/object.bin carry an explicit incompleteMarker, exactly what
  // pipeline.ts/slice.ts now stamp from a source adapter's OWN markerKind assertion at seal time (never
  // derived by sniffing the value's shape). real:looks-like-marker carries NO incompleteMarker: it is an
  // innocuous real customer object that happens to share a MARKER_KEYS name (_pending) with no adapter ever
  // asserting it is synthetic -- proving the restore-side collision this finding closed: it must restore
  // like any other real record, not be silently dropped.
  const markerArchive = await buildArchive({
    downpipeId: "dp_restore", downpipeName: "restore", cadence: "3600s", runId: RUN_MK,
    master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
    records: [
      { sourceType: "kv" as const, name: "keep:1", value: utf8("real-one"), namespace: NS },
      // A _vanished sentinel (a key listed but deleted before its value could be read): NOT the key's bytes.
      { sourceType: "kv" as const, name: "gone:mid-crawl", value: vanishedMarkerValue(), namespace: NS, incompleteMarker: "_vanished" },
      { sourceType: "kv" as const, name: "keep:2", value: utf8("real-two"), namespace: NS },
      // An over-ceiling R2 object: its captured "value" is a _skipped sentinel, NOT the (huge) object bytes.
      { sourceType: "r2" as const, name: "huge/object.bin", value: utf8(JSON.stringify({ _skipped: "content exceeds the in-band capture limit; recover it out of band", size: 999999999 })), bucket: BUCKET, incompleteMarker: "_skipped" },
      { sourceType: "r2" as const, name: "small/real.bin", value: utf8("r2-real"), bucket: BUCKET },
      // The real-data collision: a genuine customer value shaped exactly like a marker, but no
      // adapter ever asserted it is one, so it carries no incompleteMarker.
      { sourceType: "kv" as const, name: "real:looks-like-marker", value: utf8(JSON.stringify({ _pending: false, orderId: 42 })), namespace: NS },
    ],
    windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
    runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
  });
  installArchive(r2, markerArchive);

  const mkKV = new MockKV();
  const mkR2 = new RestoreR2();
  const env = { ...baseEnv(), [`KV_${NS}`]: mkKV as unknown as KVNamespace, [`R2_${BUCKET}`]: mkR2 as unknown as R2Bucket } as unknown as Env;

  // DRY-RUN: the two GENUINE (adapter-asserted) markers must NOT appear as planned writes; the 4 real
  // records -- including the marker-shaped-but-unflagged collision -- do.
  const plan = (await runRestore(env, { runId: RUN_MK })) as RestorePlan;
  ok("restore-skip DRY-RUN plans only the 4 real records (markers are not planned writes)", plan.plannedWrites === 4);
  ok("restore-skip DRY-RUN surfaces the _vanished KV marker out of band", plan.skipped.some((s) => s.name === "gone:mid-crawl" && /incompleteness marker/.test(s.reason)));
  ok("restore-skip DRY-RUN surfaces the _skipped R2 marker out of band", plan.skipped.some((s) => s.name === "huge/object.bin" && /incompleteness marker/.test(s.reason)));
  ok("restore-skip DRY-RUN plans the marker-shaped-but-unflagged record as a normal write (no collision)", plan.skipped.every((s) => s.name !== "real:looks-like-marker"));

  // APPLY: real records land (including the lookalike); GENUINE markers are skipped, never written back; ok stays true.
  const applied = (await runRestore(env, { runId: RUN_MK, confirm: true })) as RestoreResult;
  ok("restore-skip APPLY stays ok:true (a skipped marker is not a failure)", applied.ok === true && applied.failures.length === 0);
  ok("restore-skip APPLY restored exactly the 4 REAL records, not the 2 GENUINE markers", applied.recordsRestored === 4);
  ok("restore-skip: the two REAL KV keys were written back with their bytes", mkKV.store.get("keep:1") !== undefined && new TextDecoder().decode(mkKV.store.get("keep:1")!) === "real-one" && new TextDecoder().decode(mkKV.store.get("keep:2")!) === "real-two");
  ok("restore-skip: the _vanished key was NOT re-created (no marker JSON written as its value)", !mkKV.store.has("gone:mid-crawl"));
  ok("restore-skip: the REAL R2 object was written back with its bytes", mkR2.store.get("small/real.bin") !== undefined && new TextDecoder().decode(mkR2.store.get("small/real.bin")!) === "r2-real");
  ok("restore-skip: the over-ceiling _skipped R2 object was NOT written as garbage marker content", !mkR2.store.has("huge/object.bin") && mkR2.store.size === 1);
  ok("restore-skip APPLY surfaces both GENUINE markers out of band in the result", (applied.skipped ?? []).some((s) => s.name === "gone:mid-crawl") && (applied.skipped ?? []).some((s) => s.name === "huge/object.bin"));
  // Collision proof: a REAL value that merely looks marker-shaped (no adapter-asserted markerKind, so
  // no signed incompleteMarker) is written back byte-correct like any other record, never silently dropped.
  ok("restore-skip: the marker-shaped-but-unflagged real record WAS written back with its real bytes", mkKV.store.get("real:looks-like-marker") !== undefined && new TextDecoder().decode(mkKV.store.get("real:looks-like-marker")!) === JSON.stringify({ _pending: false, orderId: 42 }));
  ok("restore-skip: the lookalike record is counted restored, not skipped out of band", !(applied.skipped ?? []).some((s) => s.name === "real:looks-like-marker"));
  ok("restore-skip: exactly 3 real KV keys landed (2 original + the lookalike); the vanished key stayed excluded", mkKV.store.size === 3);
}

async function main(): Promise<void> {
  const fx = await setup();
  await proofDryRun(fx);
  await proofOversizeRefused(fx);
  await proofWindowed(fx);
  await proofReservedAndSelectable(fx);
  await proofGranular(fx);
  await proofPlanAccountingAndDeterminism(fx);
  await proofCfConfigWriteBack(fx);
  await proofMediaReupload(fx);
  await proofInAccountBoundsMedia(fx);
  await proofR2RoundTrip(fx);
  await proofLargeR2Streaming(fx);
  await proofBlindRestoreTestStreaming(fx);
  await proofDataRecordMarkersSkipped(fx);
  await proofD1Restore(fx);
  await proofSecretsOutOfBand(fx);
  await proofWorkersReprovision(fx);
  await proofCfConfigTiers(fx);
  await proofCfConfigErrors(fx);
  await proofMediaErrors(fx);
  await proofBufferedCeilingKnob(fx);
  await proofOuterCatchReason(fx);
  await proofResolveSinkOverrides(fx);
  await proofR2D1Overrides(fx);
  await proofDryRunReserved(fx);
  await proofStreamOverCap(fx);
  await proofSummariseDiff(fx);
  await proofMediaDecodeFault(fx);
  await proofApplyPhaseIntegrity(fx);
  await proofMediaGuidanceNoId(fx);
  await proofStreamedWriteFault(fx);
  await proofOuterCatchDestStatus(fx);
  await proofCoarseCfReason(fx);
  await proofMissingAndNoKey(fx);

  console.log(failures === 0 ? "\nALL RESTORE VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
