// The anti-rollback high-water FLOOR (cell G-P0-074), proven net-zero and deploy-free. It drives the REAL
// engine floor-check and the REAL channel-signature verifier in process, exactly as
// test/validate-residency-tier1.ts drives the real selection and fan-out functions.
//
// The design established three source facts this cell turns on, and none of them need a deploy:
//   1. the trusted signer UPDATE_SIGNER_PUBLIC is per-estate overridable with NO baked default
//      (src/admin/updates.ts:646, :660-665), unlike the licence signer, so a HARNESS-minted signer can BE the
//      trusted key with no engine change;
//   2. the floor refuses on the version STRING, FIRST and unconditionally in verifyAndGuard, before forward-only
//      and before any artefact hashing or upload (src/admin/update-types.ts:241-248, then planAndPromote calls
//      verifyAndGuard at src/admin/update-apply.ts:183, before the dry-run stop at :198); and
//   3. the shipped signer is hybridSign (src/crypto/sign.ts:140), so a genuinely-signed descriptor is
//      byte-compatible with what verifyChannel verifies (src/admin/updates.ts:554-585).
//
// So the floor is provable with a harness TEST-SIGNER and no deploy at all: a tokenless Preview of a below-floor
// descriptor is refused at anti-rollback-guard on the version string alone, with nothing uploaded, promoted or
// even downloaded. What this proves, over the real engine functions:
//   A  the REAL verifyChannel ACCEPTS a below-floor descriptor genuinely signed by the harness test-signer, and
//      the REAL floor (planAndPromote -> verifyAndGuard AND verifyAndGuard driven directly) then REFUSES it at
//      anti-rollback-guard, EVEN with allowDowngrade set, on the version STRING (compareSemver < 0), before the
//      artefact is ever hashed and with the throwing deploy driver never called (nothing uploaded/promoted).
//   B  WRONG-KEY companion: a below-floor descriptor signed by a DIFFERENT key FAILS the real verifyChannel at
//      sig-invalid and never reaches the floor, so the test-signer override RE-POINTED verification rather than
//      disabling it (were hybridVerify bugged to always-accept, this cell would fail). Two-sided: the same bytes
//      under the RIGHT key verify, and a single flipped signature byte fails.
//   C  REFUTER (default-FAIL): an ABOVE-floor descriptor validly signed by the SAME test-signer PASSES the floor
//      (planAndPromote reaches the dry-run plan; verifyAndGuard returns ok:true), so the refusal is specific to
//      below-floor and the floor is NOT vacuously always-refusing.
//
// Net-zero: in-process over the real pure functions, the signer is HARNESS-MINTED (crypto.subtle Ed25519 +
// mldsaKeygen; never the real release-signer key, never ~/Desktop/downpipes-live-keys), the descriptors and the
// artefact bytes are fake, the deploy driver THROWS on upload/deploy (any real deploy is a loud test failure),
// and the tokenless Preview never downloads the artefact. No estate, bucket, network, seed, spend, promote,
// recovery-code or per-estate override left set; teardown is process exit. Run: node test/validate-anti-rollback-floor-tier1.ts

import { b64urlDecode, b64urlEncode, hexEncode, utf8 } from "../src/crypto/bytes.ts";
import { parseVerifier } from "../src/crypto/keys.ts";
import { mldsaKeygen } from "../src/crypto/pq.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { type HybridVerifier, hybridSign } from "../src/crypto/sign.ts";
import type { CanaryLiveness } from "../src/canary/types.ts";
import { PROMOTE_GUARD_MESSAGES, planAndPromote } from "../src/admin/update-apply.ts";
import type { DeployDriver, HealthGate, SafeApplyInput } from "../src/admin/update-apply.ts";
import type { GuardInput } from "../src/admin/update-types.ts";
import { verifyAndGuard } from "../src/admin/update-types.ts";
import { compareSemver, isEngineCompatible, verifyChannel, verifyChannelDetailed } from "../src/admin/updates.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// The estate's settled high-water mark: the highest version this engine has ever successfully settled. The floor
// refuses any recommended version strictly below this string, EVEN with allowDowngrade set (R8,
// update-types.ts:184-189). "0.1.10" is an arbitrary settled high-water used to exercise the guard.
const HIGH_WATER = "0.1.10";

// ---- the HARNESS test-signer: minted here, never the real release-signer key --------------------------------
// A harness keypair of its own: an Ed25519 CryptoKey pair (the classical half) plus an ML-DSA-87 keypair (the
// post-quantum half), exactly the two halves the shipped hybridSign / hybridVerify pair operate on. The public
// halves are concatenated as Ed25519(32) || ML-DSA-87(2592) -- the SIGNER_PRIVATE/UPDATE_SIGNER_PUBLIC layout
// parseVerifier expects (keys.ts:90-93) -- so the verifier the floor test trusts is produced by the SAME
// parseVerifier(b64urlDecode(...)) path an estate's UPDATE_SIGNER_PUBLIC goes through at consult time
// (updates.ts:660-665). Nothing here reads or resembles the real kit key.
interface TestSigner {
  edPrivate: CryptoKey;
  edPublic: Uint8Array; // 32
  mldsaSecret: Uint8Array;
  mldsaPublic: Uint8Array; // 2592
}
async function mintSigner(): Promise<TestSigner> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  return { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };
}
// signerPublicField is the exact base64url value an estate would pin as UPDATE_SIGNER_PUBLIC for this signer.
function signerPublicField(s: TestSigner): string {
  const pub = new Uint8Array(s.edPublic.length + s.mldsaPublic.length);
  pub.set(s.edPublic);
  pub.set(s.mldsaPublic, s.edPublic.length);
  return b64urlEncode(pub);
}
// verifierOf round-trips that pinned field through the SAME parse the engine runs (updates.ts:662), so the
// HybridVerifier the floor test trusts is exactly what a real per-estate override would resolve to.
function verifierOf(s: TestSigner): HybridVerifier {
  return parseVerifier(b64urlDecode(signerPublicField(s)));
}
function channelBytes(obj: unknown): Uint8Array {
  return utf8(JSON.stringify(obj));
}
async function sign(s: TestSigner, bytes: Uint8Array): Promise<Uint8Array> {
  return hybridSign(s.edPrivate, s.mldsaSecret, bytes);
}

// ---- the net-zero deploy driver + gate + guard deps ---------------------------------------------------------
// netZeroDriver's uploadVersion and deployVersion THROW: nothing may be uploaded and nothing promoted, so a real
// deploy on this path is a loud test failure, not a silent side effect. currentLiveVersionId throws too UNLESS a
// liveVersionId is supplied (the refuter needs the record-rollback-target step to read one). The floor runs
// BEFORE record-rollback-target, so the below-floor cell supplies none and the read is never reached.
function netZeroDriver(opts?: { liveVersionId?: string }): DeployDriver {
  return {
    currentLiveVersionId: async (): Promise<string> => {
      if (opts?.liveVersionId !== undefined) return opts.liveVersionId;
      throw new Error("NET-ZERO VIOLATION: currentLiveVersionId reached (the floor must refuse before the rollback-target read)");
    },
    uploadVersion: async (): Promise<string> => {
      throw new Error("NET-ZERO VIOLATION: uploadVersion called (the floor must refuse before any upload)");
    },
    deployVersion: async (): Promise<void> => {
      throw new Error("NET-ZERO VIOLATION: deployVersion called (the floor must refuse before any promote)");
    },
  };
}
// aliveGate.baseline never gates anything here (phase-1 baseline read only); it is reached only on the refuter's
// dry-run plan, and returns a benign liveness so the plan completes cleanly.
const aliveGate: Pick<HealthGate, "baseline"> = { baseline: async (): Promise<CanaryLiveness> => "alive" };
// The SAME deps object planAndPromote hands verifyAndGuard (update-apply.ts:183), so driving verifyAndGuard
// directly exercises the identical real comparator + hash + compat functions.
const guardDeps = { sha384, hexEncode, isEngineCompatible, compareSemver };

// A fake rehearsal artefact + its true digest. The below-floor cell deliberately supplies a WRONG expectedSha384
// to prove the floor decides BEFORE verify-artefact; the refuter supplies the correct digest so the Preview is a
// full clean plan.
const artefactBytes = utf8("harness rehearsal engine bundle bytes (never deployed anywhere)");
let artefactSha384 = "";

// ---------------------------------------------------------------------------------------------------------
// Cell A: the below-floor descriptor is REFUSED at the floor, on the version string, before any upload.
// ---------------------------------------------------------------------------------------------------------
async function cellFloorRefusal(signer: TestSigner, verifier: HybridVerifier): Promise<void> {
  console.log("-- Cell A: below-floor descriptor refused at the anti-rollback floor on the version string (net-zero) --");
  const belowChannel = {
    channel: "harness-self-update",
    recommendedVersion: "0.1.9", // strictly below the settled high-water "0.1.10"
    artefacts: [{ version: "0.1.9", url: "https://harness.invalid/engine-0.1.9.mjs", sha384: artefactSha384, mainModule: "index.js" }],
  };
  const bytes = channelBytes(belowChannel);
  const sig = await sign(signer, bytes);

  // 1. The REAL signature path accepts the genuinely test-signed below-floor descriptor (real hybrid verify).
  const verified = await verifyChannel(bytes, sig, verifier);
  ok("the real verifyChannel ACCEPTS the below-floor descriptor genuinely signed by the harness test-signer (real Ed25519 + ML-DSA-87 verify, updates.ts:585)", verified !== null);
  ok("the signature-verified channel recommends the below-floor version 0.1.9", verified?.recommendedVersion === "0.1.9");
  const rec = verified?.recommendedVersion ?? "";

  // 2. Present the SIGNATURE-VERIFIED version to the REAL orchestrator planAndPromote as a tokenless Preview.
  //    allowDowngrade:true is the crux -- with it set, the ONLY guard that can refuse a below-floor version is
  //    the R8 floor (forward-only is bypassed), so a refusal at anti-rollback-guard proves R8, not forward-only.
  //    expectedSha384 is DELIBERATELY WRONG so that IF the floor did not short-circuit, verify-artefact would
  //    refuse instead -- observing the refusal at anti-rollback-guard proves the VERSION STRING decided first.
  const input: SafeApplyInput = {
    artefact: artefactBytes,
    expectedSha384: "deadbeef", // wrong on purpose; the floor is checked before verify-artefact ever runs
    meta: { version: rec },
    runningVersion: HIGH_WATER,
    recommendedVersion: rec,
    settledHighWaterMark: HIGH_WATER,
    allowDowngrade: true,
    dryRun: true,
  };
  const plan = await planAndPromote(netZeroDriver(), aliveGate, input);
  const antiStep = plan.steps.find((s) => s.step === "anti-rollback-guard");
  ok("planAndPromote REFUSED the below-floor Preview (outcome refused)", plan.outcome === "refused");
  ok("the refusing step is anti-rollback-guard (the R8 floor), even with allowDowngrade set", antiStep !== undefined && antiStep.ok === false);
  ok("verify-artefact NEVER ran, so the wrong artefact hash was irrelevant: the VERSION STRING decided first (update-types.ts:241-248 before :267)", !plan.steps.some((s) => s.step === "verify-artefact"));
  ok("nothing was uploaded and nothing promoted (no upload-version/promote step; the throwing driver was never called)", !plan.steps.some((s) => s.step === "upload-version" || s.step === "promote"));
  ok("the refusal reason is the PRODUCT'S OWN antiRollbackBelow wording, byte-identical (update-apply.ts:145)", plan.reason === PROMOTE_GUARD_MESSAGES.antiRollbackBelow(rec, HIGH_WATER));

  // 3. Drive the REAL floor function verifyAndGuard DIRECTLY for the precise typed refusal at the seam.
  const guardInput: GuardInput = {
    artefact: artefactBytes,
    expectedSha384: "deadbeef",
    meta: { version: rec },
    runningVersion: HIGH_WATER,
    recommendedVersion: rec,
    settledHighWaterMark: HIGH_WATER,
    allowDowngrade: true,
  };
  const guard = await verifyAndGuard(netZeroDriver(), guardInput, PROMOTE_GUARD_MESSAGES, () => {}, guardDeps);
  ok("verifyAndGuard returns ok:false at step anti-rollback-guard (update-types.ts:244-246)", guard.ok === false && guard.step === "anti-rollback-guard");
  ok("verifyAndGuard's reason is the product's antiRollbackBelow wording (byte-identical)", guard.ok === false && guard.reason === PROMOTE_GUARD_MESSAGES.antiRollbackBelow(rec, HIGH_WATER));

  // 4. The decision is a version-STRING comparison, nothing else: compareSemver("0.1.9","0.1.10") === -1.
  ok("the floor decided on the version STRING: compareSemver(0.1.9, 0.1.10) === -1 (below the high-water)", compareSemver(rec, HIGH_WATER) === -1);

  // 5. Fail-closed arm: an UNCOMPARABLE target vs a set floor is ALSO refused (antiRollbackIncomparable), so a
  //    channel pinning a non-semver version cannot slip under the floor by being incomparable to it.
  const incomparable = "harness-latest"; // non-numeric core -> compareSemver returns null -> refuse
  const incGuard = await verifyAndGuard(
    netZeroDriver(),
    { artefact: artefactBytes, expectedSha384: "deadbeef", meta: { version: incomparable }, runningVersion: HIGH_WATER, recommendedVersion: incomparable, settledHighWaterMark: HIGH_WATER, allowDowngrade: true },
    PROMOTE_GUARD_MESSAGES,
    () => {},
    guardDeps,
  );
  ok("an UNCOMPARABLE version vs the set floor is refused fail-closed at anti-rollback-guard (compareSemver === null)", compareSemver(incomparable, HIGH_WATER) === null && incGuard.ok === false && incGuard.step === "anti-rollback-guard");
  ok("the incomparable refusal uses the antiRollbackIncomparable wording (distinct from below-floor)", incGuard.ok === false && incGuard.reason === PROMOTE_GUARD_MESSAGES.antiRollbackIncomparable(incomparable, HIGH_WATER));
}

// ---------------------------------------------------------------------------------------------------------
// Cell B (WRONG-KEY companion): a descriptor signed by a DIFFERENT key fails verification, never reaching
// the floor -- so the test-signer override re-pointed verification rather than disabling it.
// ---------------------------------------------------------------------------------------------------------
async function cellWrongKey(signer: TestSigner, wrongSigner: TestSigner, verifier: HybridVerifier): Promise<void> {
  console.log("-- Cell B (WRONG-KEY): a different key fails verification and never reaches the floor (masking guard) --");
  const belowChannel = { channel: "harness-self-update", recommendedVersion: "0.1.9", artefacts: [{ version: "0.1.9", url: "https://harness.invalid/engine-0.1.9.mjs", sha384: artefactSha384, mainModule: "index.js" }] };
  const bytes = channelBytes(belowChannel);
  const goodSig = await sign(signer, bytes); // the estate's pinned test-signer
  const wrongSig = await sign(wrongSigner, bytes); // a DIFFERENT key the estate does not pin

  // The wrong-key descriptor is REJECTED at signature verification (cause sig-invalid), so its below-floor
  // version string NEVER reaches the floor. Were hybridVerify bugged to always-accept, these would pass and the
  // floor test could mask a real verification bug -- which is exactly what this companion exists to catch.
  ok("a below-floor descriptor signed by a DIFFERENT key FAILS verifyChannel (returns null)", (await verifyChannel(bytes, wrongSig, verifier)) === null);
  const detailed = await verifyChannelDetailed(bytes, wrongSig, verifier);
  ok("verifyChannelDetailed names the cause sig-invalid: the wrong-key descriptor never reaches the floor (updates.ts:585)", detailed.ok === false && detailed.cause === "sig-invalid");

  // Two-sided: the SAME bytes under the RIGHT key DO verify (the override trusts exactly the harness test-signer,
  // it did not disable verification), and a single flipped signature byte fails (the verifier is bit-sensitive).
  ok("the SAME bytes signed by the pinned harness test-signer DO verify (override re-pointed, did not disable)", (await verifyChannel(bytes, goodSig, verifier)) !== null);
  const tampered = goodSig.slice();
  tampered[0] = tampered[0]! ^ 0x01;
  ok("a single flipped byte in the valid signature FAILS verification (hybridVerify is bit-sensitive, not always-accept)", (await verifyChannel(bytes, tampered, verifier)) === null);
}

// ---------------------------------------------------------------------------------------------------------
// Cell C (REFUTER, default-FAIL): an ABOVE-floor descriptor validly signed by the SAME test-signer PASSES the
// floor, so the below-floor refusal is specific and not vacuously always-refusing.
// ---------------------------------------------------------------------------------------------------------
async function cellRefuter(signer: TestSigner, verifier: HybridVerifier): Promise<boolean> {
  console.log("-- Cell C (REFUTER, default-FAIL): an above-floor descriptor PASSES the floor (two-sided vs Cell A) --");
  let refuterHeld = false; // default-FAIL: only set true when the above-floor version demonstrably clears the floor
  const aboveChannel = {
    channel: "harness-self-update",
    recommendedVersion: "0.2.0", // strictly ABOVE the high-water "0.1.10"
    artefacts: [{ version: "0.2.0", url: "https://harness.invalid/engine-0.2.0.mjs", sha384: artefactSha384, mainModule: "index.js" }],
  };
  const bytes = channelBytes(aboveChannel);
  const sig = await sign(signer, bytes);
  const verified = await verifyChannel(bytes, sig, verifier);
  ok("the real verifyChannel ACCEPTS the above-floor descriptor signed by the same harness test-signer", verified !== null && verified.recommendedVersion === "0.2.0");
  const rec = verified?.recommendedVersion ?? "";

  // Present it to the REAL floor. runningVersion is the high-water so forward-only ALSO passes (0.2.0 > 0.1.10);
  // the correct digest lets verify-artefact pass; the driver hands back a known-good id for record-rollback-
  // target. The result is the full clean dry-run plan -- the floor let it through.
  const input: SafeApplyInput = {
    artefact: artefactBytes,
    expectedSha384: artefactSha384, // correct digest: verify-artefact passes
    meta: { version: rec },
    runningVersion: HIGH_WATER,
    recommendedVersion: rec,
    settledHighWaterMark: HIGH_WATER,
    dryRun: true,
  };
  const plan = await planAndPromote(netZeroDriver({ liveVersionId: "v-known-good" }), aliveGate, input);
  const firedFloor = plan.steps.some((s) => s.step === "anti-rollback-guard");
  ok("the floor did NOT fire for the above-floor version (no anti-rollback-guard step in the plan)", !firedFloor);
  ok("planAndPromote reached the dry-run plan (sailed past the floor and every guard, outcome dry-run)", plan.outcome === "dry-run");
  ok("verify-artefact PASSED and the rollback target was recorded (the Preview is a full clean plan)", plan.steps.some((s) => s.step === "verify-artefact" && s.ok) && plan.steps.some((s) => s.step === "record-rollback-target" && s.ok));
  ok("still net-zero on the refuter path: nothing uploaded/promoted (the dry-run stops before upload)", !plan.steps.some((s) => s.step === "upload-version" || s.step === "promote"));

  // Direct floor: verifyAndGuard returns ok:true for the above-floor input.
  const guard = await verifyAndGuard(netZeroDriver({ liveVersionId: "v-known-good" }), input, PROMOTE_GUARD_MESSAGES, () => {}, guardDeps);
  ok("verifyAndGuard returns ok:true for the above-floor version (the floor passed it)", guard.ok === true);
  ok("the floor's pass is a version-STRING comparison: compareSemver(0.2.0, 0.1.10) === 1 (above the high-water)", compareSemver(rec, HIGH_WATER) === 1);

  refuterHeld = !firedFloor && plan.outcome === "dry-run" && guard.ok === true;
  ok("REFUTER HELD: the above-floor descriptor PASSES the floor, so the below-floor refusal is specific and NOT vacuously always-refusing", refuterHeld === true);
  return refuterHeld;
}

async function main(): Promise<void> {
  artefactSha384 = hexEncode(await sha384(artefactBytes));
  const signer = await mintSigner();
  const wrongSigner = await mintSigner();
  const verifier = verifierOf(signer); // the estate's pinned UPDATE_SIGNER_PUBLIC, round-tripped through parseVerifier

  await cellFloorRefusal(signer, verifier);
  await cellWrongKey(signer, wrongSigner, verifier);
  const refuterHeld = await cellRefuter(signer, verifier);

  if (!refuterHeld) failures++; // belt-and-braces: a non-held refuter fails the suite even if its own ok() slipped
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nANTI-ROLLBACK FLOOR (G-P0-074) VECTORS PASS (the floor refuses a below-floor descriptor on the version string, before any upload; the wrong-key companion catches a masked verification bug; the above-floor refuter is cleared)");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
