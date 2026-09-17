// The attended-verification live-possession challenge. Attended verification lets an offline-key-only
// customer prove their backups restorable by supplying, through their browser, only the per-run master keys
// (never the break-glass private, which stays in the browser). But a per-run master, once seen, could be
// stashed and replayed by a party that does NOT hold the recovery key, so a passing verification alone only
// proves "someone once had a valid master". This challenge closes that gap: at session start the engine
// encapsulates a fresh secret to the break-glass PUBLIC key it holds (in every posture), and only a party
// holding the break-glass PRIVATE (identity.key) can decapsulate it and reproduce the derived proof, so a
// passing prove step is positive evidence the operator holds the recovery key RIGHT NOW. It does not defend
// against a compromised engine (which owns its own records); its value is defeating a stashed-master replay
// by a non-key-holder, which is why the challenge, not the verify, is what a session gates on.
//
// STORAGE SAFETY: the engine stores only sha384(expectedProof) in the session record, which reveals nothing
// about the key or the KEM shared secret, so the "no key material in session storage" invariant holds.

import { encapsulateHybrid } from "../crypto/kem.ts";
import { loadRecipientPublic } from "../keys-env.ts";
import { hkdfSha384, sha384 } from "../crypto/primitives.ts";
import { b64urlEncode, b64urlDecode, utf8, hexEncode, hexDecode, constantTimeEqual } from "../crypto/bytes.ts";

// CHALLENGE_LABEL binds the proof derivation to this feature + format major, so a challenge proof can never
// be confused with any other HKDF output in the system. NONCE_LEN is the fresh per-challenge nonce.
const CHALLENGE_LABEL = "downpipe/0.1.0 attest-challenge";
const NONCE_LEN = 32;
const PROOF_LEN = 32;

// AttestChallenge is what issueAttestChallenge returns: the ciphertext + nonce the browser needs, and the
// server-side proof hash the session record stores (never sent to the browser). The browser is given only
// ciphertextB64 + nonceB64.
export interface AttestChallenge {
  ciphertextB64: string;
  nonceB64: string;
  proofHash: string; // "sha384:<hex>" of the expected proof; stored server-side, deleted once proven
}

// issueAttestChallenge encapsulates to the break-glass public key and derives the expected proof over a
// fresh nonce. Returns the ciphertext + nonce for the browser and sha384(expectedProof) for storage.
export async function issueAttestChallenge(breakGlassPublicB64: string): Promise<AttestChallenge> {
  const pub = loadRecipientPublic(breakGlassPublicB64);
  const enc = await encapsulateHybrid(pub);
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const proof = await hkdfSha384(enc.sharedSecret, nonce, utf8(CHALLENGE_LABEL), PROOF_LEN);
  const proofHash = `sha384:${hexEncode(await sha384(proof))}`;
  return { ciphertextB64: b64urlEncode(enc.cipherText), nonceB64: b64urlEncode(nonce), proofHash };
}

// deriveAttestProof is the browser-side derivation, exported so a validator can exercise the round trip: the
// browser decapsulates the ciphertext with identity.key to recover the same shared secret, then derives the
// proof over the nonce. (In production this runs in the console's ported crypto; the engine never sees the
// shared secret.)
export async function deriveAttestProof(sharedSecret: Uint8Array, nonce: Uint8Array): Promise<Uint8Array> {
  return hkdfSha384(sharedSecret, nonce, utf8(CHALLENGE_LABEL), PROOF_LEN);
}

// verifyAttestProof recomputes sha384 of the submitted proof and constant-time compares it to the stored
// hash. A match proves the submitter decapsulated the challenge with the break-glass private. Returns false
// on any malformed input rather than throwing, so a garbage proof is a clean "not proven", never a 500.
export async function verifyAttestProof(proofHash: string, submittedProofB64: string): Promise<boolean> {
  if (!proofHash.startsWith("sha384:")) return false;
  let submitted: Uint8Array;
  try {
    submitted = b64urlDecode(submittedProofB64);
  } catch {
    return false;
  }
  if (submitted.length !== PROOF_LEN) return false;
  let expected: Uint8Array;
  try {
    expected = hexDecode(proofHash.slice("sha384:".length));
  } catch {
    return false;
  }
  const got = await sha384(submitted);
  if (got.length !== expected.length) return false;
  return constantTimeEqual(got, expected);
}
