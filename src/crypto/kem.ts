import { concat } from "./bytes.ts";
import { hybridKEMCombine } from "./combiner.ts";
import { mlkemDecapsulate, mlkemEncapsulate, mlkemKeygen } from "./pq.ts";
import { x25519Ephemeral, x25519PublicFromScalar, x25519SharedSecret } from "./x25519.ts";

// The hybrid X25519 + ML-KEM-1024 KEM (SPEC 4), ported from internal/crypto/pq.go. The
// hybrid ciphertext is ct_M (1568) || ct_X (32) = 1600 bytes. The engine encapsulates;
// decapsulate is for drills and the validator.

const ML_KEM_CT_LEN = 1568;
const ML_KEM_EK_LEN = 1568;
const X25519_PUB_LEN = 32;

/**
 * A hybrid recipient's public key: the 32-byte X25519 public key and the 1568-byte ML-KEM-1024
 * encapsulation key. The engine holds only this public half.
 */
export interface HybridRecipientPublic {
  x25519: Uint8Array; // 32
  mlkemEk: Uint8Array; // 1568
}

/**
 * A hybrid recipient's private identity: the 32-byte X25519 scalar and the 64-byte ML-KEM seed.
 * Held offline as the break-glass identity, never by the engine.
 */
export interface HybridRecipientPrivate {
  x25519Scalar: Uint8Array; // 32
  mlkemSeed: Uint8Array; // 64
}

/**
 * The result of a hybrid encapsulation: the 32-byte shared secret and the 1600-byte hybrid
 * ciphertext (ML-KEM ct_M(1568) || X25519 ephemeral(32)).
 */
export interface HybridEncapsulation {
  sharedSecret: Uint8Array; // 32
  cipherText: Uint8Array; // 1600
}

/**
 * Encapsulates to a recipient public key, producing a fresh hybrid shared secret and the hybrid
 * ciphertext. This is the engine's KEM direction.
 *
 * @param pub - the recipient's hybrid public key.
 * @returns the 32-byte shared secret and the 1600-byte hybrid ciphertext.
 */
export async function encapsulateHybrid(pub: HybridRecipientPublic): Promise<HybridEncapsulation> {
  if (pub.mlkemEk.length !== ML_KEM_EK_LEN) {
    throw new Error(`ML-KEM encapsulation key is ${pub.mlkemEk.length} bytes, want ${ML_KEM_EK_LEN}`);
  }
  if (pub.x25519.length !== X25519_PUB_LEN) {
    throw new Error(`X25519 public key is ${pub.x25519.length} bytes, want ${X25519_PUB_LEN}`);
  }
  const m = mlkemEncapsulate(pub.mlkemEk);
  const eph = x25519Ephemeral();
  const ssX = x25519SharedSecret(eph.scalar, pub.x25519);
  const ss = await hybridKEMCombine(m.sharedSecret, ssX, eph.publicKey, pub.x25519);
  return { sharedSecret: ss, cipherText: concat(m.cipherText, eph.publicKey) };
}

/**
 * Recovers the hybrid shared secret from a hybrid ciphertext using the held recipient private
 * identity. Used by drills and the validator, not the engine hot path.
 *
 * @param priv - the held hybrid recipient private identity.
 * @param cipherText - the 1600-byte hybrid ciphertext (ct_M(1568) || ct_X(32)).
 * @returns the 32-byte hybrid shared secret.
 * @throws Error when the ciphertext is not exactly 1600 bytes; the X25519 step throws on an
 *   all-zero (non-contributory) shared secret.
 */
export async function decapsulateHybrid(priv: HybridRecipientPrivate, cipherText: Uint8Array): Promise<Uint8Array> {
  if (cipherText.length !== ML_KEM_CT_LEN + 32) {
    throw new Error(`hybrid ciphertext is ${cipherText.length} bytes, want ${ML_KEM_CT_LEN + 32}`);
  }
  const ctM = cipherText.subarray(0, ML_KEM_CT_LEN);
  const ctX = cipherText.subarray(ML_KEM_CT_LEN);
  const decapKey = mlkemKeygen(priv.mlkemSeed).decapKey;
  const ssM = mlkemDecapsulate(ctM, decapKey);
  const ssX = x25519SharedSecret(priv.x25519Scalar, ctX);
  const ourPub = x25519PublicFromScalar(priv.x25519Scalar);
  return hybridKEMCombine(ssM, ssX, ctX, ourPub);
}
