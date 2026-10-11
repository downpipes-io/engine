// The post-quantum primitives. ML-KEM-1024 (encapsulate, decapsulate, and the seed-to-key
// derivation used at key generation) and ML-DSA-87 (sign, verify) come from the pinned
// @noble/post-quantum. In src/ (the Worker) this is the only file that imports ML-KEM.
// src/keys-env.ts also imports ml_dsa87, but only to expand the stored ML-DSA-87 seed into the
// signer key pair at load. Outside the Worker, the offline scripts/generate-keys.ts imports both.
//
// The library is NOT constant-time-guaranteed, so what the engine does with it matters, and
// the honest answer depends on the posture. The engine does not only encapsulate and sign.
// It also decapsulates, and where it does so depends on the posture.
// In the two-recipient posture the engine holds
// OPERATIONAL_PRIVATE and decapsulates with it routinely: the restore drill, the hourly
// canary, verify-at-seal, in-console restore and the retention prune all do. In either
// posture, the control-plane auto-heal decapsulates with CONFIG_RECIPIENT_PRIVATE when it
// opens a sealed recovery export (src/cron/control-plane-pass.ts). Decapsulation with a
// LONG-LIVED key is precisely the shape a timing side channel targets, so the caveat is
// load-bearing there rather than theoretical. deploy.sh and the console key ceremony default
// a fresh engine to break-glass-only, where the operational key is absent.
//
// Two things bound it. An attacker needs to
// measure the engine's own timing from inside the customer's Cloudflare account, and anyone
// with that position already has the environment the keys sit in. And break-glass-only removes
// the archive-key exposure by removing the key rather than by mitigating it. The config key
// opens only the config export, never an archive. The Rust/WASM escalation remains the
// documented fallback if a constant-time implementation is required.

import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";

/**
 * The result of an ML-KEM-1024 encapsulation: the 1568-byte ciphertext (ct_M) and the 32-byte
 * shared secret (ss_M).
 */
export interface KEMEncapsulation {
  cipherText: Uint8Array; // 1568 bytes, ct_M
  sharedSecret: Uint8Array; // 32 bytes, ss_M
}

/**
 * Encapsulates to an ML-KEM-1024 encapsulation key, drawing fresh randomness, so the output is
 * not reproducible (matching the Go reference; see SPEC 14.1).
 *
 * @param encapKey - the 1568-byte ML-KEM-1024 encapsulation key.
 * @returns the 1568-byte ciphertext and the 32-byte shared secret.
 */
export function mlkemEncapsulate(encapKey: Uint8Array): KEMEncapsulation {
  const r = ml_kem1024.encapsulate(encapKey);
  return { cipherText: r.cipherText, sharedSecret: r.sharedSecret };
}

/**
 * Derives an ML-KEM-1024 keypair from a 64-byte seed, the same seed the Go reference stores as
 * the ML-KEM half of a recipient private identity. The engine keeps only the seed and the public
 * encapsulation key; the expanded decapsulation key is needed only to decapsulate, which the
 * engine never does.
 *
 * @param seed - the 64-byte ML-KEM seed.
 * @returns the encapsulation key (encapKey, 1568 bytes) and the expanded decapsulation key
 *   (decapKey, 3168 bytes).
 */
export function mlkemKeygen(seed: Uint8Array): { encapKey: Uint8Array; decapKey: Uint8Array } {
  const kp = ml_kem1024.keygen(seed);
  return { encapKey: kp.publicKey, decapKey: kp.secretKey };
}

/**
 * Recovers the ML-KEM-1024 shared secret from a ciphertext and an expanded decapsulation key.
 * Exposed for drills and validators; not used in the engine hot path.
 *
 * @param cipherText - the 1568-byte ML-KEM ciphertext.
 * @param decapKey - the expanded decapsulation key from mlkemKeygen.
 * @returns the 32-byte shared secret.
 */
export function mlkemDecapsulate(cipherText: Uint8Array, decapKey: Uint8Array): Uint8Array {
  return ml_kem1024.decapsulate(cipherText, decapKey);
}

/**
 * Signs a message with an ML-DSA-87 secret key.
 *
 * @param secretKey - the ML-DSA-87 secret key.
 * @param message - the message bytes to sign.
 * @returns the 4627-byte ML-DSA-87 signature.
 */
export function mldsaSign(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  // The noble convention is sign(message, secretKey).
  return ml_dsa87.sign(message, secretKey);
}

/**
 * Verifies an ML-DSA-87 signature over a message. Exposed for the cross-implementation validator
 * and the in-account drill reader.
 *
 * @param publicKey - the ML-DSA-87 public key.
 * @param message - the message bytes the signature should cover.
 * @param signature - the ML-DSA-87 signature to check.
 * @returns true when the signature verifies under the public key, false otherwise.
 */
export function mldsaVerify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  return ml_dsa87.verify(signature, message, publicKey);
}

/**
 * Generates an ML-DSA-87 keypair for the key ceremony.
 *
 * @param seed - an optional seed; when given the keypair is deterministic, when omitted it draws
 *   fresh randomness.
 * @returns the ML-DSA-87 public key and secret key.
 */
export function mldsaKeygen(seed?: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const kp = seed ? ml_dsa87.keygen(seed) : ml_dsa87.keygen();
  return { publicKey: kp.publicKey, secretKey: kp.secretKey };
}
