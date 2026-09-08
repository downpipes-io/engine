// End-to-end onboarding proof, fully in-memory: keygen (the byte formats the console's key
// ceremony produces) -> configure an in-memory engine Env -> the GET /admin/status presence
// contract (without leaking a secret) -> seal a small KV source through the real runBackup
// pipeline to an in-memory destination -> in-account runRestore back into a mock KV namespace
// -> bytes match. NO network, NO deploy, NO cost. Run:
//   node test/validate-onboarding.ts
//
// What this proves that the per-unit validators do not, end to end:
//  - the console key encoding is EXACTLY what the engine consumes (loadSigner derives the same
//    verifier, so a run it signs verifies on restore);
//  - a fully-wired in-memory engine reports ready via the new status contract WITHOUT any
//    secret value appearing in the serialised report;
//  - a KV source seals to an in-account destination and restores back with bytes matching;
//  - the no-custody posture holds: the operational private is genuinely optional (its absence
//    is reported, not errored), and the break-glass private is never needed for the in-account
//    operational restore path.

import { x25519 } from "@noble/curves/ed25519.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen, mldsaKeygen } from "../src/crypto/pq.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { ENGINE_VERSION } from "../src/format/version.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { hybridSign, hybridVerify } from "../src/crypto/sign.ts";
import { runBackup, type RunConfig, type RunClock } from "../src/seal/pipeline.ts";
import { KVSource } from "../src/sources/kv.ts";
import { runRestore } from "../src/admin/restore.ts";
import { buildStatus } from "../src/admin/status.ts";
import { AUDIT_CAP, AUDIT_NEAR_CAP_FRACTION } from "../src/admin/audit.ts";
import { MemoryDestination } from "./memdest.ts";
import type { RecipientEntry } from "../src/format/writer.ts";
import type { Env } from "../src/env.d.ts";
import type { RestorePlan, RestoreResult } from "../src/admin/restore-types.ts";

const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const NS = "ns_e2e";
const KVSET: Record<string, string> = { a: "alpha", b: "beta", "user:1": "gamma-longer" };

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// makeRecipient builds the console key-ceremony shape: the hybrid recipient public entry the
// engine wraps to (BREAK_GLASS_PUBLIC / OPERATIONAL_PUBLIC), and the 96-byte private identity
// (x25519 scalar(32) || ML-KEM seed(64)) that stays offline (break-glass) or, only on opt-in,
// becomes OPERATIONAL_PRIVATE for the in-account read-back.
function makeRecipient(role: string): { entry: RecipientEntry; recipientPublicB64: string; identity96: Uint8Array; identityB64: string } {
  const xk = x25519.keygen();
  const seed = rand(64);
  const ek = mlkemKeygen(seed).encapKey; // ml_kem1024 keygen from the stored 64-byte seed
  const recipientPublic = concat(xk.publicKey, ek); // x25519 pub(32) || ML-KEM ek(1568) = 1600B
  const identity96 = concat(xk.secretKey, seed); // x25519 scalar(32) || ML-KEM seed(64) = 96B
  return {
    entry: { role, pub: { x25519: xk.publicKey, mlkemEk: ek } },
    recipientPublicB64: b64urlEncode(recipientPublic),
    identity96,
    identityB64: b64urlEncode(identity96),
  };
}

// MockKV implements just the KVNamespace surface KVSource (list/get) and KVRestoreSink (put)
// use, tracking a put count so the dry-run assertion can prove zero writes. It is seeded for
// the seal side and starts empty for the restore side.
class MockKV {
  store = new Map<string, Uint8Array>();
  putCount = 0;
  constructor(seed?: Record<string, string>) {
    if (seed) for (const [k, v] of Object.entries(seed)) this.store.set(k, utf8(v));
  }
  async list(opts?: { prefix?: string; cursor?: string }): Promise<{ keys: { name: string }[]; list_complete: boolean; cursor?: string }> {
    const prefix = opts?.prefix ?? "";
    const keys = [...this.store.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name }));
    return { keys, list_complete: true };
  }
  async put(k: string, v: ArrayBuffer | Uint8Array): Promise<void> {
    this.putCount++;
    this.store.set(k, v instanceof Uint8Array ? v : new Uint8Array(v));
  }
  async get(k: string, _type?: string): Promise<ArrayBuffer | null> {
    const v = this.store.get(k);
    return v ? toAB(v) : null;
  }
}

// MockR2 serves the sealed archive object map through the R2 binding surface the R2
// destination reads (get -> { arrayBuffer, etag }, head, put). runRestore builds its dest via
// buildDestination(env), so the restore side reads through this when DEST_KIND="r2".
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

async function main(): Promise<void> {
  // ---- STEP 1: KEYGEN (the browser key ceremony, reproduced in Node) ----
  // SIGNER_PRIVATE = b64url(edSeed(32) || ML-DSA-87 secret). The engine's loadSigner must
  // derive the IDENTICAL verifier from this, or no run it signs could ever verify on restore.
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const mldsa = mldsaKeygen(mldsaSeed);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer = await loadSigner(signerPrivateB64);
  const verifier = verifierFrom(signer);
  ok(
    "signer public halves derive from the console encoding (ed + ML-DSA)",
    b64urlEncode(verifier.ed) === b64urlEncode(ed25519.getPublicKey(edSeed)) &&
      b64urlEncode(verifier.mldsa) === b64urlEncode(mldsa.publicKey),
  );
  // And the loaded signer actually signs and verifies (the console encoding == keys-env consumes).
  const probe = utf8("onboarding signer attestation");
  ok("loaded signer signs and hybrid-verifies", await hybridVerify(verifier, probe, await hybridSign(signer.edPrivate, signer.mldsaSecret, probe)));

  const breakGlass = makeRecipient("break-glass");
  const operational = makeRecipient("operational");
  const breakGlassPubB64 = breakGlass.recipientPublicB64; // BREAK_GLASS_PUBLIC
  const operationalPubB64 = operational.recipientPublicB64; // OPERATIONAL_PUBLIC
  const operationalPrivateB64 = operational.identityB64; // OPERATIONAL_PRIVATE (opt-in)

  // ---- STEP 2: CONFIGURE AN IN-MEMORY ENGINE Env ----
  // The dest double on the seal side: runBackup writes through the Destination interface, so
  // pass a MemoryDestination directly. The restore side reads via buildDestination(env), which
  // needs DEST_R2 to be an R2Bucket-shaped object, so copy the sealed objects into a MockR2.
  const memDest = new MemoryDestination();
  const restoreKV = new MockKV();
  const baseEnv = (mockR2: MockR2): Env =>
    ({
      SCHEDULER: {} as unknown as DurableObjectNamespace, // unused on the seal/restore path
      DEST_KIND: "r2",
      DEST_R2: mockR2 as unknown as R2Bucket,
      SIGNER_PRIVATE: signerPrivateB64,
      BREAK_GLASS_PUBLIC: breakGlassPubB64,
      OPERATIONAL_PUBLIC: operationalPubB64,
      OPERATIONAL_PRIVATE: operationalPrivateB64,
      [`KV_${NS}`]: restoreKV as unknown as KVNamespace,
    }) as unknown as Env;

  // ---- STEP 3: STATUS PRESENCE CONTRACT (Part 1), in-process, no HTTP ----
  // A fully-wired engine reports ready, and NO secret value leaks into the serialised report.
  const fullEnv = baseEnv(new MockR2());
  const status = buildStatus(fullEnv, 0);
  ok("status signerConfigured", status.signerConfigured === true);
  ok("status breakGlassConfigured", status.breakGlassConfigured === true);
  ok("status operationalConfigured.public", status.operationalConfigured.public === true);
  ok("status operationalConfigured.private", status.operationalConfigured.private === true);
  ok("status destConfigured + destKind r2", status.destConfigured === true && status.destKind === "r2");
  // Reference ENGINE_VERSION, never a literal, so this assertion tracks a version bump automatically.
  ok("status engineVersion + service surfaced", status.engineVersion === ENGINE_VERSION && status.service === "downpipe-engine");
  ok("status ready (signer && break-glass && dest)", status.ready === true);
  const statusJSON = JSON.stringify(status);
  ok(
    "status JSON leaks NO secret value (signer/break-glass-pub/operational-priv)",
    !statusJSON.includes(signerPrivateB64) && !statusJSON.includes(breakGlassPubB64) && !statusJSON.includes(operationalPrivateB64) && !statusJSON.includes(operationalPubB64),
  );

  // ---- Engine-hardening status fields ----
  // ADMIN_TOKEN_DISABLED: tokenFallbackDisabled mirrors the env flag, default false.
  ok("status tokenFallbackDisabled defaults false (no flag set)", status.tokenFallbackDisabled === false);
  const hardenedEnv = baseEnv(new MockR2());
  hardenedEnv.ADMIN_TOKEN_DISABLED = "true";
  ok("status tokenFallbackDisabled true when ADMIN_TOKEN_DISABLED set", buildStatus(hardenedEnv, 0).tokenFallbackDisabled === true);
  const looseEnv = baseEnv(new MockR2());
  looseEnv.ADMIN_TOKEN_DISABLED = "false";
  ok("status tokenFallbackDisabled false for a falsey flag value", buildStatus(looseEnv, 0).tokenFallbackDisabled === false);

  // auditNearCap: absent without a count (honestly not asserted); present and correct with one.
  ok("status auditNearCap ABSENT when no count is supplied", buildStatus(fullEnv, 0).auditNearCap === undefined && !("auditNearCap" in buildStatus(fullEnv, 0)));
  const nearThreshold = Math.floor(AUDIT_CAP * AUDIT_NEAR_CAP_FRACTION);
  ok("status auditNearCap false below the threshold", buildStatus(fullEnv, 0, { auditCount: nearThreshold - 1 }).auditNearCap === false);
  ok("status auditNearCap true at the threshold", buildStatus(fullEnv, 0, { auditCount: nearThreshold }).auditNearCap === true);
  ok("status auditNearCap true above the threshold (approaching the cap)", buildStatus(fullEnv, 0, { auditCount: AUDIT_CAP }).auditNearCap === true);

  // Provenance fields: absent when unset; surfaced verbatim when set; still no secret value.
  ok("status provenance fields ABSENT when unset", buildStatus(fullEnv, 0).artefactSha384 === undefined && buildStatus(fullEnv, 0).releaseSignerPin === undefined);
  const provEnv = baseEnv(new MockR2());
  provEnv.ARTEFACT_SHA384 = "sha384:abc123";
  provEnv.RELEASE_SIGNER_PIN = "release-signer-2026";
  const provStatus = buildStatus(provEnv, 0);
  ok("status surfaces artefactSha384 verbatim when set", provStatus.artefactSha384 === "sha384:abc123");
  ok("status surfaces releaseSignerPin verbatim when set", provStatus.releaseSignerPin === "release-signer-2026");
  ok("status provenance fields carry no secret (the signer private never appears)", !JSON.stringify(provStatus).includes(signerPrivateB64));

  // Negative: a missing signer is not ready; presence-only never throws.
  const noSignerEnv = baseEnv(new MockR2());
  delete (noSignerEnv as Record<string, unknown>)["SIGNER_PRIVATE"];
  const noSignerStatus = buildStatus(noSignerEnv, 0);
  ok("status without SIGNER_PRIVATE: signerConfigured false && ready false", noSignerStatus.signerConfigured === false && noSignerStatus.ready === false);

  // Negative: the ambiguous-destination case (R2 bound AND an S3 cred set, no DEST_KIND) is
  // refused exactly as the factory refuses it, so status reports not-ready with destKind null.
  const ambiguousEnv = baseEnv(new MockR2());
  delete (ambiguousEnv as Record<string, unknown>)["DEST_KIND"];
  ambiguousEnv.DEST_BUCKET = "an-s3-bucket"; // an S3 cred alongside the bound DEST_R2
  const ambiguousStatus = buildStatus(ambiguousEnv, 0);
  ok("status ambiguous dest: destConfigured false && destKind null", ambiguousStatus.destConfigured === false && ambiguousStatus.destKind === null);
  ok("status ambiguous dest leaks no S3 detail (DEST_BUCKET)", !JSON.stringify(ambiguousStatus).includes("an-s3-bucket"));

  // An S3 destination: status reports destKind s3 + configured and leaks NONE of the five S3
  // credential values (config-presence only, never echoed).
  const s3Env = baseEnv(new MockR2());
  delete (s3Env as Record<string, unknown>)["DEST_R2"]; // pure S3, no R2 binding
  s3Env.DEST_KIND = "s3";
  s3Env.DEST_ENDPOINT = "https://s3.example.com";
  s3Env.DEST_BUCKET = "secret-bucket-name";
  s3Env.DEST_REGION = "ap-southeast-2";
  s3Env.DEST_ACCESS_KEY_ID = "AKIA-secret-id";
  s3Env.DEST_SECRET_ACCESS_KEY = "super-secret-key";
  const s3Status = buildStatus(s3Env, 0);
  ok("status S3 dest: destConfigured true && destKind s3", s3Status.destConfigured === true && s3Status.destKind === "s3");
  const s3JSON = JSON.stringify(s3Status);
  ok(
    "status JSON leaks NONE of the five S3 credential values",
    !s3JSON.includes("https://s3.example.com") && !s3JSON.includes("secret-bucket-name") && !s3JSON.includes("ap-southeast-2") && !s3JSON.includes("AKIA-secret-id") && !s3JSON.includes("super-secret-key"),
  );

  // A CONSOLE-SET destination is stored S3-shaped, but its endpoint host tells R2 from S3: an R2
  // endpoint (<account>.r2.cloudflarestorage.com) must report destKind "r2" (in-account), NOT the
  // old blanket "s3 (out of account)" mislabel; a genuine third-party S3 host still reports "s3".
  const consoleEnv = baseEnv(new MockR2());
  delete (consoleEnv as Record<string, unknown>)["DEST_R2"];
  const r2ConsoleStatus = buildStatus(consoleEnv, 0, { consoleDestSet: true, consoleDestHost: "deadbeefdeadbeefdeadbeefdeadbeef.r2.cloudflarestorage.com" });
  ok("status console-set R2 endpoint: destConfigured true && destKind r2 (not mislabelled s3)", r2ConsoleStatus.destConfigured === true && r2ConsoleStatus.destKind === "r2");
  const r2ConsoleHttps = buildStatus(consoleEnv, 0, { consoleDestSet: true, consoleDestHost: "https://deadbeefdeadbeefdeadbeefdeadbeef.r2.cloudflarestorage.com/downpipe-archive" });
  ok("status console-set R2 endpoint as full URL is still detected as r2", r2ConsoleHttps.destKind === "r2");
  const foreignS3Status = buildStatus(consoleEnv, 0, { consoleDestSet: true, consoleDestHost: "s3.us-east-1.amazonaws.com" });
  ok("status console-set foreign S3 endpoint: destKind s3 (genuinely out of account)", foreignS3Status.destConfigured === true && foreignS3Status.destKind === "s3");
  const consoleNoHostStatus = buildStatus(consoleEnv, 0, { consoleDestSet: true });
  ok("status console-set with unknown host falls back to s3 (conservative)", consoleNoHostStatus.destKind === "s3" && consoleNoHostStatus.destConfigured === true);

  // ---- STEP 4: SEAL a small KV source through the REAL runBackup pipeline ----
  const sealKV = new MockKV(KVSET);
  const kvSource = new KVSource(sealKV as unknown as KVNamespace, NS);
  const cfg: RunConfig = {
    downpipeId: "dp_e2e",
    downpipeName: "onboarding",
    cadence: "3600s",
    selector: { include: [], exclude: [] },
    recipients: [breakGlass.entry, operational.entry], // break-glass first
  };
  const clock: RunClock = {
    runId: RUN_ID,
    runlogIndex: 1,
    prevRunId: null,
    now: "2026-06-07T00:00:00.000Z",
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
    master: rand(32),
  };
  const summary = await runBackup([kvSource], cfg, signer, memDest, clock);
  const expectBytes = Object.values(KVSET).reduce((n, v) => n + utf8(v).length, 0);
  ok("seal RunSummary records === 3", summary.records === 3);
  ok("seal RunSummary bytes === sum(utf8 lengths)", summary.bytes === expectBytes);
  ok("seal RunSummary runlogIndex === 1", summary.runlogIndex === 1);
  ok("seal wrote the root manifest + RUNLOG into the dest", memDest.entries().has(`run/${RUN_ID}/root.manifest.json`) && memDest.entries().has("_RECOVERY/RUNLOG"));

  // ---- STEP 5: IN-ACCOUNT RESTORE through the real runRestore handler ----
  // Copy the sealed objects into a MockR2 so buildDestination(env) can read the archive.
  const archiveR2 = new MockR2();
  for (const [k, b] of memDest.entries()) archiveR2.store.set(k, b);

  const applied = (await runRestore(baseEnv(archiveR2), { runId: RUN_ID, confirm: true })) as RestoreResult;

  // ---- STEP 6: BYTES MATCH (the core proof) ----
  ok("applied mode is 'applied'", applied.mode === "applied");
  ok("applied ok && all 3 verified + restored", applied.ok === true && applied.recordsRestored === 3 && applied.recordsVerified === 3);
  ok("applied reports no failures", applied.failures.length === 0);
  ok("applied bytesRestored equals the sealed plaintext total", applied.bytesRestored === expectBytes);
  let bytesMatch = true;
  for (const [name, v] of Object.entries(KVSET)) {
    const got = restoreKV.store.get(name);
    if (!got || new TextDecoder().decode(got) !== v) bytesMatch = false;
  }
  ok("every restored KV value byte-matches the original (round-trip)", bytesMatch);
  ok("restored exactly the 3 keys, nothing extra", restoreKV.store.size === 3);

  // Dry-run (default, no confirm) WRITES NOTHING, into a fresh KV namespace.
  const dryKV = new MockKV();
  const dryEnv = baseEnv(archiveR2);
  dryEnv[`KV_${NS}`] = dryKV as unknown as KVNamespace;
  const plan = (await runRestore(dryEnv, { runId: RUN_ID })) as RestorePlan;
  ok("dry-run mode is 'dry-run' && verified 3 && plans 3", plan.mode === "dry-run" && plan.ok === true && plan.recordsVerified === 3 && plan.plannedWrites === 3);
  ok("DRY-RUN WROTE NOTHING", dryKV.putCount === 0 && dryKV.store.size === 0);

  // No-custody: the operational private is optional. Without it the in-account restore reports
  // the break-glass-only posture (ok:false), never errored, proving the break-glass private is
  // not needed in-account for the operational restore path.
  const noOpEnv = baseEnv(archiveR2);
  delete (noOpEnv as Record<string, unknown>)["OPERATIONAL_PRIVATE"];
  const noOp = (await runRestore(noOpEnv, { runId: RUN_ID })) as RestorePlan;
  ok("no operational-private restore returns the break-glass posture (ok:false)", noOp.ok === false && /break-glass-only posture/.test(noOp.reason ?? ""));
  // And status agrees the operational private is simply absent (not a fault).
  ok("status reflects operational private absent without erroring", buildStatus(noOpEnv, 0).operationalConfigured.private === false);

  console.log(failures === 0 ? "\nALL ONBOARDING E2E VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
