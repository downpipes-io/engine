// Validate the attended-verification crypto core against the master-capsule conformance vector: the same
// per-run master the in-account reader recovers from a held identity can be recovered by the browser (here,
// the test) via openCapsule and handed to openRunWithMaster to open+verify the SAME run, a wrong master fails
// closed at the key commitment, a seeded sample verifies exactly the intended record count, and the live-
// possession challenge round-trips only for a holder of the break-glass private. This is the offline proof
// that attended verification hands the engine only a single-archive key, never the private key, and that a
// bad or replayed-but-mismatched master can never make verification pass.
//
// Run with `node test/validate-attest-crypto.ts`.

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { openRun, openRunWithMaster, readRunCapsule, type ObjectStore } from "../src/format/reader.ts";
import { openCapsule, parseWraps } from "../src/crypto/capsule.ts";
import { parseIdentity, parseVerifier } from "../src/crypto/keys.ts";
import { b64urlDecode, b64urlEncode, hexDecode, concat } from "../src/crypto/bytes.ts";
import { x25519PublicFromScalar } from "../src/crypto/x25519.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { decapsulateHybrid } from "../src/crypto/kem.ts";
import { issueAttestChallenge, deriveAttestProof, verifyAttestProof } from "../src/attest/challenge.ts";
import { verifySampledRun, verifyRunWithMaster, sampleCount } from "../src/attest/verify.ts";
import type { HybridRecipientPrivate } from "../src/crypto/kem.ts";
import type { Env } from "../src/env.d.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const VDIR = join(HERE, "vectors", "master-capsule");
const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const BIG = 1 << 30; // buffered path for the small vector records (nothing streams)

class DirStore implements ObjectStore {
  private base: string;
  constructor(base: string) {
    this.base = base;
  }
  async get(key: string): Promise<Uint8Array> {
    return new Uint8Array(await readFile(join(this.base, key)));
  }
}

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

async function text(p: string): Promise<string> {
  return new TextDecoder().decode(await readFile(p));
}

function eqRecords(a: { records: { recordId: string }[] }, b: { records: { recordId: string }[] }): boolean {
  if (a.records.length !== b.records.length) return false;
  const ids = new Set(a.records.map((r) => r.recordId));
  return b.records.every((r) => ids.has(r.recordId));
}

async function main(): Promise<void> {
  const store = new DirStore(join(VDIR, "archive"));
  const identity: HybridRecipientPrivate = parseIdentity(b64urlDecode((await text(join(VDIR, "identity.key"))).trim()));
  const verifier = parseVerifier(b64urlDecode((await text(join(VDIR, "signer.pub"))).trim()));

  // 1) The capsule the engine would serve the browser: masterCapsule wraps + keyCommitment, signature-verified.
  const cap = await readRunCapsule(store, RUN_ID, verifier);
  ok("readRunCapsule returns capsule wraps + keyCommitment for the signed run", cap.masterCapsule.length >= 1 && cap.keyCommitment.length > 0);

  // 2) The browser-side decap: recover the per-run master from the capsule with the held identity, exactly as
  //    the console will in the operator's browser (the identity never leaves it).
  const master = await openCapsule(parseWraps(cap.masterCapsule), identity, hexDecode(cap.keyCommitment));
  ok("openCapsule recovers a 32-byte per-run master", master.length === 32);

  // 3) openRunWithMaster(master) opens+verifies the SAME run as openRun(identity): the engine can verify from
  //    the browser-supplied master alone, without ever holding the private key.
  const viaMaster = await openRunWithMaster(store, RUN_ID, master, verifier, { verifyFreshness: false });
  const viaIdentity = await openRun(store, RUN_ID, identity, verifier, { verifyFreshness: false });
  ok("openRunWithMaster opens the run", viaMaster.records.length === cap.declaredRecordCount);
  ok("openRunWithMaster yields the same records as openRun(identity)", eqRecords(viaMaster, viaIdentity));

  // 4) A WRONG master fails closed at the key commitment (a bad decap, a garbage/replayed-but-mismatched value
  //    can never make verification pass against the wrong key).
  let wrongThrew = false;
  try {
    await openRunWithMaster(store, RUN_ID, new Uint8Array(32).fill(7), verifier, { verifyFreshness: false });
  } catch {
    wrongThrew = true;
  }
  ok("a wrong master fails closed (key commitment)", wrongThrew);

  // 5) Seeded sample: a full (100%) verify covers every record; a partial sample covers exactly sampleCount,
  //    and every sampled record decrypts-and-verifies against the vector.
  const seed = new Uint8Array(32).map((_, i) => (i * 37 + 11) & 0xff);
  const total = viaMaster.records.length;
  const full = await verifySampledRun(viaMaster, 100, seed, BIG);
  ok("100% sample verifies every record with no failures", full.ok && full.recordsVerified === total && full.failures === 0);
  if (total >= 2) {
    const half = await verifySampledRun(viaMaster, 50, seed, BIG);
    ok("50% sample verifies exactly sampleCount(total,50) records", half.recordsVerified === sampleCount(total, 50) && half.failures === 0);
    const halfAgain = await verifySampledRun(viaMaster, 50, seed, BIG);
    ok("the seeded sample is deterministic (same count for the same seed)", halfAgain.recordsVerified === half.recordsVerified);
  }
  ok("sampleCount floors at one record per run", sampleCount(1000, 0) >= 1 && sampleCount(5, 1) >= 1);
  ok("sampleCount at 100% is the whole run", sampleCount(1000, 100) === 1000);

  // 6) The live-possession challenge: derive the break-glass PUBLIC from the identity (the engine holds this
  //    in every posture), issue a challenge, and prove it only with the identity. A wrong proof is rejected.
  const bgPublic = concat(x25519PublicFromScalar(identity.x25519Scalar), mlkemKeygen(identity.mlkemSeed).encapKey);
  const challenge = await issueAttestChallenge(b64urlEncode(bgPublic));
  const sharedSecret = await decapsulateHybrid(identity, b64urlDecode(challenge.ciphertextB64));
  const proof = await deriveAttestProof(sharedSecret, b64urlDecode(challenge.nonceB64));
  ok("a holder of the break-glass private passes the live-possession challenge", await verifyAttestProof(challenge.proofHash, b64urlEncode(proof)));
  ok("a wrong proof fails the challenge", !(await verifyAttestProof(challenge.proofHash, b64urlEncode(new Uint8Array(32).fill(9)))));
  ok("the stored challenge value is only a hash (no shared secret / key material)", challenge.proofHash.startsWith("sha384:"));

  // 6b) FRESHNESS, which the module documents and nothing enforced. NONCE_LEN's own comment calls it "the
  //     fresh per-challenge nonce" and the header rests the feature on proving possession "RIGHT NOW", but
  //     no assertion anywhere compared two challenges, so the nonce could be a constant and every attest
  //     validator stayed green. With the nonce pinned to zeroes the ciphertext and the proof
  //     hash STILL differ per challenge, because encapsulateHybrid is independently fresh. So the freshness
  //     the feature actually depends on is the ENCAPSULATION, and the nonce is defence in depth. Both are
  //     asserted here, separately, so a future change that derandomises either one is caught by the cell
  //     that names it rather than by neither.
  const challenge2 = await issueAttestChallenge(b64urlEncode(bgPublic));
  ok("two challenges to the SAME break-glass public carry different nonces (the documented per-challenge freshness)", challenge.nonceB64 !== challenge2.nonceB64);
  ok("two challenges to the SAME break-glass public carry different ciphertexts (the encapsulation the security actually rests on)", challenge.ciphertextB64 !== challenge2.ciphertextB64);
  ok("two challenges to the SAME break-glass public store different proof hashes (so a captured proof cannot be replayed into the next session)", challenge.proofHash !== challenge2.proofHash);
  // Two-sided, so the three cells above cannot read as "everything differs". A proof derived for challenge
  // one must NOT satisfy challenge two: the proof is bound to its own challenge, not merely unique.
  ok("CONTROL: the FIRST challenge's proof does NOT satisfy the SECOND challenge (each proof is bound to its own)", !(await verifyAttestProof(challenge2.proofHash, b64urlEncode(proof))));
  // And the positive control for that refusal, so it is not passing because verifyAttestProof refuses
  // everything: the second challenge's own proof does satisfy it.
  const proof2 = await deriveAttestProof(await decapsulateHybrid(identity, b64urlDecode(challenge2.ciphertextB64)), b64urlDecode(challenge2.nonceB64));
  ok("CONTROL: the SECOND challenge's own proof DOES satisfy it (the refusal above is binding, not blanket)", await verifyAttestProof(challenge2.proofHash, b64urlEncode(proof2)));

  // 7) verifyRunWithMaster fails SAFE on a missing configuration: it never throws, it returns a structured
  //    ok:false with a coarse reason (the same fail-safe discipline the drill and blind test use), so a
  //    misconfigured attended verification can never wedge or leak.
  const failsafe = await verifyRunWithMaster({} as Env, RUN_ID, master, 100, seed);
  ok("verifyRunWithMaster fails safe (structured ok:false, never throws) on missing config", failsafe.ok === false && typeof failsafe.reason === "string");

  console.log(failures === 0 ? "\nATTEST-CRYPTO VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
