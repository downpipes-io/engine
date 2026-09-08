// Secrets restore path -- SecretsRestoreSink, BoundSecretSink, and the
// routing in admin/restore.ts for a secrets target. Run:
//   node test/validate-secrets-restore.ts
//
// Covers:
//   1. SecretsRestoreSink unit tests: put() with and without a wired write path, putStream()
//      rejection, target() count, unregistered-name rejection.
//   2. Routing (dry-run): secrets records are routed to skipped with the Secrets Store out-of-band guidance (SECRETS_OUT_OF_BAND_REASON,
//      which names the read-only binding and the re-creation through the Cloudflare API or wrangler)
//      and are NOT counted in plannedWrites. plannedWrites must be 0 for a secrets-only archive.
//   3. Applied restore via runRestore (confirm:true): secrets records are skipped out of band,
//      NOT recorded as failures. The result is ok:true (no failures), recordsRestored=0,
//      failures=[], and skipped contains one entry per secret carrying SECRETS_OUT_OF_BAND_REASON.
//   4. SecretsRestoreSink in isolation: mixed bound/unbound sinks (one wired, one not).
//      NOTE: this part tests the sink directly, NOT via runRestore. The orchestrator now
//      routes secrets to outOfBand before any sink is constructed, so SecretsRestoreSink.put()
//      is no longer called from runRestore. The sink tests prove the class still behaves
//      correctly if ever called directly (e.g. when a wired write path is available in a
//      future extension).
//   5. Reserved-binding guard: a target override that names a reserved binding is refused
//      before any write, ok:false, reason "target binding is reserved".
//   6. No in-account read-back key is reported honestly (break-glass-only posture).
//
// Cloudflare Secrets Store bindings expose get() only at runtime; there is no runtime
// write path. Secrets records are therefore separated into an out-of-band skipped
// category before the plan is built. This means:
//   - dry-run: plannedWrites excludes secrets (they cannot be applied at runtime).
//   - apply: secrets records appear in result.skipped, not result.failures.
//   - ok:true even when a secrets-only archive is applied (nothing failed; records were
//     intentionally not written because no write path exists at runtime).
//
// In-memory doubles only. No network, no deploy, no cost.

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen, } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import { runRestore, guardTarget } from "../src/admin/restore.ts";
import { SecretsRestoreSink, type BoundSecretSink } from "../src/dest/restore-sink.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";
import type { RestorePlan, RestoreResult } from "../src/admin/restore-types.ts";
import { SECRETS_OUT_OF_BAND_REASON } from "../src/admin/restore-sinks.ts";

// THE SENTENCE ITSELF, SPELLED OUT HERE. Comparing a plan's reason against the imported constant proves the
// two sides agree and NOTHING about what either one says: rewrite the constant to any string at all and
// every such assertion stays green.
//
// So the required clauses are written out here, in this file, and checked against the constant's own text
// BEFORE it is used for anything. The equality checks below are then the plumbing
// check they were always meant to be. Each clause is one thing three documentation pages promise a customer:
// the CAUSE (why nothing writes it back) and the REMEDY (what the operator does instead, and where the value
// comes from). Editing the sentence is fine; editing away a clause fails here.
const SECRETS_REASON_REQUIRED_CLAUSES = [
  "read-only at runtime", // the cause, and the reason this is a platform limit rather than a fault of the run
  "no in-account write path", // the consequence, stated so nobody reads the record as merely deferred
  "offline reader", // WHERE the value comes back from; the console never displays a secret value
  "break-glass key", // and what opens it
  "Cloudflare API or wrangler", // the remedy the operator carries out with the recovered value
] as const;

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
  return {
    entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } },
    identity: concat(xk.secretKey, seed),
  };
}

// MockR2 serves the sealed archive objects through the R2 destination surface the factory-
// built R2 destination reads (get/head/put).
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

// The secrets the test archives. Two secrets so partial-failure can be demonstrated
// precisely (one wired, one not).
const SECRET_DB_PASS = { name: "DB_PASS", value: "super-secret-password-42" };
const SECRET_API_KEY = { name: "API_KEY", value: "test-api-key-value-for-restore" };
const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

// setup seals both secrets into an archive in MockR2 and returns the baseEnv factory the restore PARTs use.
async function setup(): Promise<{ baseEnv: () => Env }> {
  // Build a signer that the engine uses to both sign and verify the archive.
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerPrivateB64);

  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const operationalPrivateB64 = b64urlEncode(op.identity);

  // Seal both secrets into an archive placed in MockR2 so runRestore can read it back.
  const archive = await buildArchive({
    downpipeId: "dp_secrets",
    downpipeName: "secrets",
    cadence: "3600s",
    runId: RUN_ID,
    master: rand(32),
    recipients: [breakGlass.entry, op.entry],
    signer,
    records: [
      { sourceType: "secrets", name: SECRET_DB_PASS.name, value: utf8(SECRET_DB_PASS.value) },
      { sourceType: "secrets", name: SECRET_API_KEY.name, value: utf8(SECRET_API_KEY.value) },
    ],
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

  // baseEnv wires the engine with the R2 archive destination plus crypto material.
  const baseEnv = (): Env => ({
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: r2 as unknown as R2Bucket,
    SIGNER_PRIVATE: signerPrivateB64,
    OPERATIONAL_PRIVATE: operationalPrivateB64,
  } as unknown as Env);
  return { baseEnv };
}

// ---- PART 1: SecretsRestoreSink unit tests (in-memory doubles, no runRestore) ----
async function testSink(): Promise<void> {
  // 1a. put() with a wired BoundSecretSink.put routes to the bound secret by name and calls the write
  // function with the exact plaintext.
  let writtenValue = "";
  const wiredSink: BoundSecretSink = {
    name: SECRET_DB_PASS.name,
    put: async (v) => { writtenValue = v; },
  };
  const sinkWithWrite = new SecretsRestoreSink([wiredSink]);
  ok("SecretsRestoreSink sourceType is 'secrets'", sinkWithWrite.sourceType === "secrets");
  ok("SecretsRestoreSink target() describes the bound count", sinkWithWrite.target() === "secrets(1 bound)");
  await sinkWithWrite.put(SECRET_DB_PASS.name, utf8(SECRET_DB_PASS.value));
  ok("put() routes to the bound sink by name", wiredSink.name === SECRET_DB_PASS.name);
  ok("put() with a wired path calls put with the exact plaintext string", writtenValue === SECRET_DB_PASS.value);

  // 1b. put() with no wired put throws an honest message naming the secret.
  const noWriteSink: BoundSecretSink = { name: SECRET_API_KEY.name };
  const sinkNoWrite = new SecretsRestoreSink([noWriteSink]);
  let noWriteErr = "";
  try {
    await sinkNoWrite.put(SECRET_API_KEY.name, utf8(SECRET_API_KEY.value));
  } catch (e) {
    noWriteErr = (e as Error).message;
  }
  ok("put() with no wired path throws naming the secret", /no runtime write path/.test(noWriteErr) && noWriteErr.includes(SECRET_API_KEY.name));
  ok("put() no-write error names the read-only limitation", /read-only at runtime/.test(noWriteErr));

  // 1c. put() for a secret not in the sinks list throws with the name.
  const sinkMissing = new SecretsRestoreSink([wiredSink]);
  let missingErr = "";
  try {
    await sinkMissing.put("UNKNOWN_SECRET", utf8("x"));
  } catch (e) {
    missingErr = (e as Error).message;
  }
  ok("put() for an unregistered name throws naming the secret", /UNKNOWN_SECRET/.test(missingErr) && /no restore sink bound/.test(missingErr));

  // 1d. putStream() always throws (secrets are restored whole, not streamed).
  let streamErr = "";
  try {
    await sinkWithWrite.putStream("any", new ReadableStream() as ReadableStream<Uint8Array>, 0);
  } catch (e) {
    streamErr = (e as Error).message;
  }
  ok("putStream() throws for secrets (secrets are whole, not streamed)", /secrets are restored whole/.test(streamErr));

  // 1e. target() reflects the count of bound secrets.
  const multiSink = new SecretsRestoreSink([wiredSink, noWriteSink]);
  ok("target() reports count for multiple sinks", multiSink.target() === "secrets(2 bound)");
}

// ---- PART 2: Routing -- dry-run proves secrets are excluded from plannedWrites ----
async function testDryRunRouting(baseEnv: () => Env): Promise<void> {
  // A dry-run opens the archive and routes secrets records to skipped (not to the plan).
  // plannedWrites must be 0 for a secrets-only archive; secrets appear in skipped instead.
  // The sample must be empty (no records with a runtime write path). Both secrets records
  // appear in skipped carrying SECRETS_OUT_OF_BAND_REASON.
  const plan = (await runRestore(baseEnv(), { runId: RUN_ID })) as RestorePlan;
  ok("dry-run completes ok", plan.ok === true && plan.mode === "dry-run");
  // recordsVerified is still 0 because secrets are routed out before verification (they are
  // in outOfBand, not the plan window). plannedWrites must be 0.
  ok("dry-run plannedWrites is 0 for a secrets-only archive (secrets have no runtime write path)",
    plan.plannedWrites === 0);
  ok("dry-run sample is empty (no records with a runtime write path)", plan.sample.length === 0);
  // Both secrets must appear in skipped carrying SECRETS_OUT_OF_BAND_REASON.
  ok("dry-run skipped contains both secrets", plan.skipped.length === 2);
  const skippedNames = plan.skipped.map((s) => s.name).sort();
  ok("dry-run skipped names both secrets",
    skippedNames.join(",") === [SECRET_API_KEY.name, SECRET_DB_PASS.name].sort().join(","));
  for (const clause of SECRETS_REASON_REQUIRED_CLAUSES) {
    ok(`the Secrets Store guidance still says "${clause}"`, SECRETS_OUT_OF_BAND_REASON.includes(clause));
  }
  ok("the guidance does NOT claim anything writes the secret back (there is no such path, in the engine or the reader)",
    !/\b(re-?writes? it back|restored in ?account|written back to Secrets Store)\b/i.test(SECRETS_OUT_OF_BAND_REASON));
  ok("dry-run skipped reasons are the shared Secrets Store out-of-band guidance",
    plan.skipped.every((s) => s.reason === SECRETS_OUT_OF_BAND_REASON));
}

// ---- PART 3: Applied restore -- secrets are skipped out of band, not recorded as failures ----
async function testAppliedRestore(baseEnv: () => Env): Promise<void> {
  // Secrets records are routed to outOfBand before any sink is constructed; the orchestrator
  // never attempts a put() on a secrets record. The result is ok:true (no failures), with
  // secrets appearing in result.skipped rather than result.failures. This is the correct,
  // documented behaviour: the records were not written because no runtime write path exists,
  // not because of a transient fault.
  const applied = (await runRestore(baseEnv(), { runId: RUN_ID, confirm: true })) as RestoreResult;
  ok("applied mode is 'applied'", applied.mode === "applied");
  // Secrets are not in the plan window, so recordsVerified is 0.
  ok("applied recordsVerified is 0 (secrets are routed out before the plan window)", applied.recordsVerified === 0);
  // No failures: secrets were not attempted and cannot fail.
  ok("applied failures is empty (secrets are not attempted)", applied.failures.length === 0);
  // ok is true: nothing failed (secrets are skipped out of band, not failures).
  ok("applied ok is true when all records are skipped out of band", applied.ok === true);
  // recordsRestored and bytesRestored are 0.
  ok("applied recordsRestored is 0 (no runtime write paths)", applied.recordsRestored === 0);
  ok("applied bytesRestored is 0", applied.bytesRestored === 0);
  // Both secrets appear in result.skipped carrying SECRETS_OUT_OF_BAND_REASON.
  ok("applied skipped contains both secrets", (applied.skipped ?? []).length === 2);
  const appliedSkippedNames = (applied.skipped ?? []).map((s) => s.name).sort();
  ok("applied skipped names both secrets",
    appliedSkippedNames.join(",") === [SECRET_API_KEY.name, SECRET_DB_PASS.name].sort().join(","));
  ok("applied skipped reasons are the shared Secrets Store out-of-band guidance",
    (applied.skipped ?? []).every((s) => s.reason === SECRETS_OUT_OF_BAND_REASON));
  // No top-level reason field (not a failure of any kind).
  ok("applied result has no top-level reason field", applied.reason === undefined);

  // The receipt's skipped COUNT must equal the skipped LIST it was made from. These are two readers of
  // one shortfall: the console counts `skipped.length` off the apply result, while an auditor reads
  // `summary.recordsSkipped` out of the signed, audit-anchored receipt. Today both derive from the same
  // expression at the makeRestoreReceipt call site, so they agree by construction, and that is precisely
  // why nothing catches it if they stop. A later change that counted only SOME skip reasons would leave
  // the signed evidence and the screen disagreeing about how much of the archive is still absent from the
  // account, with the receipt the more authoritative of the two and the quieter about being wrong.
  const receiptSkipped = applied.receipt?.summary.recordsSkipped;
  ok("the applied restore produced a receipt to check the count against", applied.receipt !== undefined);
  ok(
    `the receipt's recordsSkipped equals the skipped list length (receipt ${String(receiptSkipped)}, list ${(applied.skipped ?? []).length})`,
    receiptSkipped === (applied.skipped ?? []).length,
  );
  // Non-zero here, so the field must actually be PRESENT. Asserting only equality would pass if both
  // sides were absent, which is the state this pairing exists to rule out.
  ok("recordsSkipped is present and non-zero when records were skipped", typeof receiptSkipped === "number" && receiptSkipped === 2);
}

// ---- PART 4: SecretsRestoreSink in isolation -- mixed wired/unwired sinks ----
async function testMixedSinks(): Promise<void> {
  // The orchestrator now routes secrets to outOfBand before any sink is constructed, so
  // SecretsRestoreSink.put() is never called from runRestore. This part tests the sink
  // class directly to prove it still behaves correctly if a wired write path is available
  // in a future extension: a wired put succeeds, an unwired put throws the documented error.
  let capturedDB = "";
  const sinkA: BoundSecretSink = { name: SECRET_DB_PASS.name, put: async (v) => { capturedDB = v; } };
  const sinkB: BoundSecretSink = { name: SECRET_API_KEY.name }; // no put -- unwired
  const mixedSink = new SecretsRestoreSink([sinkA, sinkB]);

  // put() for the wired secret succeeds and captures the exact plaintext.
  await mixedSink.put(SECRET_DB_PASS.name, utf8(SECRET_DB_PASS.value));
  ok("mixed-sink (isolation): wired secret is written with correct value", capturedDB === SECRET_DB_PASS.value);

  // put() for the unwired secret throws the documented read-only error.
  let mixedFailErr = "";
  try {
    await mixedSink.put(SECRET_API_KEY.name, utf8(SECRET_API_KEY.value));
  } catch (e) {
    mixedFailErr = (e as Error).message;
  }
  ok("mixed-sink (isolation): unwired secret throws with honest reason", /no runtime write path/.test(mixedFailErr));
}

// ---- PART 5: Reserved-binding guard ----
async function testReservedBindingGuard(baseEnv: () => Env): Promise<void> {
  // A target override naming a reserved binding must refuse the whole restore before any
  // write, return ok:false with reason "target binding is reserved", and record no failures
  // (refused before the write phase, not drained as individual failures).
  const refused = (await runRestore(baseEnv(), {
    runId: RUN_ID,
    confirm: true,
    target: { binding: "SIGNER_PRIVATE" },
  })) as RestoreResult;
  ok("reserved target binding refused (ok:false)", refused.ok === false);
  ok("reserved target reason is 'target binding is reserved'", refused.reason === "target binding is reserved");
  ok("reserved target refusal records no restorations", refused.recordsRestored === 0);

  // A dry-run with a reserved target binding is also refused before any verification.
  const refusedDry = (await runRestore(baseEnv(), {
    runId: RUN_ID,
    target: { binding: "SIGNER_PRIVATE" },
  })) as RestorePlan;
  ok("reserved target binding refused on dry-run too (ok:false)", refusedDry.ok === false && refusedDry.mode === "dry-run");
  ok("dry-run reserved reason is 'target binding is reserved'", refusedDry.reason === "target binding is reserved");

  // Other reserved bindings are also refused (spot-check OPERATIONAL_PRIVATE and DEST_R2).
  let opRefused = false;
  let destR2Refused = false;
  try { guardTarget("OPERATIONAL_PRIVATE"); } catch { opRefused = true; }
  try { guardTarget("DEST_R2"); } catch { destR2Refused = true; }
  ok("guardTarget refuses OPERATIONAL_PRIVATE", opRefused);
  ok("guardTarget refuses DEST_R2", destR2Refused);

  // A non-reserved binding is allowed through.
  ok("guardTarget allows a normal binding 'SECRETS'", guardTarget("SECRETS") === "SECRETS");
  ok("guardTarget allows a normal binding 'MY_SECRET_STORE'", guardTarget("MY_SECRET_STORE") === "MY_SECRET_STORE");
}

// ---- PART 6: No in-account read-back key is reported honestly, not errored ----
async function testNoReadBackKey(baseEnv: () => Env): Promise<void> {
  const noKeyEnv = baseEnv();
  delete (noKeyEnv as Record<string, unknown>)["OPERATIONAL_PRIVATE"];
  const noKey = (await runRestore(noKeyEnv, { runId: RUN_ID })) as RestorePlan;
  ok("no read-back key: break-glass posture reported (ok:false, dry-run)", noKey.ok === false && noKey.mode === "dry-run");
  ok("no read-back key: reason mentions break-glass posture", /break-glass-only posture/.test(noKey.reason ?? ""));
}

async function main(): Promise<void> {
  const { baseEnv } = await setup();
  await testSink();
  await testDryRunRouting(baseEnv);
  await testAppliedRestore(baseEnv);
  await testMixedSinks();
  await testReservedBindingGuard(baseEnv);
  await testNoReadBackKey(baseEnv);

  console.log(failures === 0
    ? "\nALL SECRETS RESTORE VALIDATIONS PASS"
    : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

// Catch unhandled rejections so a crash reports exit code 1 rather than 0.
main().catch((e) => {
  console.error(e);
  process.exit(1);
});

// Coverage summary:
//
// SecretsRestoreSink unit tests (PART 1):
//   - put() with a wired BoundSecretSink.put calls the write function with the exact
//     plaintext string decoded from the Uint8Array value
//   - put() with no wired put throws naming the secret and the read-only-at-runtime
//     limitation
//   - put() for an unregistered name throws naming the secret
//   - putStream() throws for secrets (secrets are restored whole, not streamed)
//   - target() reports the count of bound sinks
//
// Dry-run routing (PART 2):
//   - dry-run plannedWrites is 0 for a secrets-only archive (secrets have no runtime write
//     path and must not be counted as planned writes)
//   - dry-run sample is empty (no records with a runtime write path)
//   - both secrets appear in skipped carrying SECRETS_OUT_OF_BAND_REASON
//
// Applied restore via runRestore (PART 3):
//   - runRestore with confirm:true returns ok:true when all records are secrets (nothing
//     failed; records were intentionally not written)
//   - failures is empty (secrets are not attempted at runtime)
//   - both secrets appear in result.skipped carrying SECRETS_OUT_OF_BAND_REASON
//   - recordsRestored is 0 (no runtime write paths)
//
// SecretsRestoreSink in isolation -- mixed sinks (PART 4):
//   - wired put succeeds; unwired put throws the documented error
//   - NOTE: the orchestrator now routes secrets to outOfBand before any sink is
//     constructed; SecretsRestoreSink.put() is never called from runRestore. Part 4 tests
//     the sink class directly for future use when a wired write path is available.
//
// Reserved-binding guard (PART 5):
//   - confirm:true with a reserved target binding refuses before any write
//   - dry-run with a reserved target binding also refuses
//   - guardTarget refuses SIGNER_PRIVATE, OPERATIONAL_PRIVATE, DEST_R2
//   - guardTarget allows "SECRETS" and custom store names
//
// Runtime read-only limitation (PARTS 1 + 3):
//   - Secrets Store bindings are read-only at runtime; secrets are routed to outOfBand
//     before any sink is constructed (not silently failed or counted as plannedWrites)
