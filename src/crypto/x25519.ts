import { x25519 } from "@noble/curves/ed25519.js";
import { noteCryptoFault } from "../format/integrity-fault-ledger.ts";

// X25519 from @noble/curves, matching Go's crypto/ecdh X25519 (RFC 7748). The SPEC 4.1
// contributory abort (reject an all-zero shared secret) is enforced here, because some
// implementations return the all-zero secret rather than erroring.

/**
 * Derives the X25519 public key for a scalar (RFC 7748).
 *
 * @param scalar - the 32-byte X25519 scalar.
 * @returns the 32-byte X25519 public key.
 */
export function x25519PublicFromScalar(scalar: Uint8Array): Uint8Array {
  return x25519.getPublicKey(scalar);
}

/**
 * Generates a fresh ephemeral X25519 keypair.
 *
 * @returns the 32-byte scalar (secret) and its 32-byte public key.
 */
export function x25519Ephemeral(): { scalar: Uint8Array; publicKey: Uint8Array } {
  const kp = x25519.keygen();
  return { scalar: kp.secretKey, publicKey: kp.publicKey };
}

/**
 * Computes the X25519 ECDH shared secret and enforces the SPEC 4.1 contributory abort by
 * rejecting an all-zero result (some implementations return all-zero rather than erroring).
 *
 * @param scalar - the local 32-byte X25519 scalar.
 * @param peerPublic - the peer's 32-byte X25519 public key.
 * @returns the 32-byte shared secret.
 * @throws Error when the shared secret is all zero (a non-contributory point).
 */
export function x25519SharedSecret(scalar: Uint8Array, peerPublic: Uint8Array): Uint8Array {
  const ss = x25519.getSharedSecret(scalar, peerPublic);
  let zero = 0;
  for (const b of ss) zero |= b;
  if (zero === 0) {
    // G012: a non-contributory point is a CORRUPT (or hostile) recipient key, not a destination fault and not
    // a tamper of the archive. It coarsened into the run's generic failure and support chased buckets. Record
    // the closed class + role; the key bytes never ride.
    noteCryptoFault({ cls: "recipient-noncontributory", role: "recipient" });
    throw new Error("x25519 produced an all-zero shared secret (non-contributory point)");
  }
  return ss;
}
