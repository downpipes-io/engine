import { HYBRID_KEM_LABEL } from "../format/version.ts";
import { concat, utf8 } from "./bytes.ts";
import { hkdfSha384 } from "./primitives.ts";

/**
 * Derives the 32-byte hybrid shared secret from the ML-KEM and X25519 component secrets, binding
 * the X25519 ephemeral share and the recipient X25519 public key (SPEC 4.2). It mirrors X-Wing's
 * binding set generalised to ML-KEM-1024 over HKDF-SHA-384, and must reproduce the Go reference
 * (and the kem-combiner-kat) byte for byte: ikm = ssM || ssX, empty salt, info = label || 0x00 ||
 * ctX || pkX.
 *
 * @param ssM - the ML-KEM-1024 component shared secret.
 * @param ssX - the X25519 component shared secret.
 * @param ctX - the X25519 ephemeral public share (the X25519 "ciphertext").
 * @param pkX - the recipient's X25519 public key.
 * @returns the 32-byte combined hybrid shared secret.
 */
export function hybridKEMCombine(ssM: Uint8Array, ssX: Uint8Array, ctX: Uint8Array, pkX: Uint8Array): Promise<Uint8Array> {
  const info = concat(utf8(HYBRID_KEM_LABEL), new Uint8Array([0x00]), ctX, pkX);
  return hkdfSha384(concat(ssM, ssX), new Uint8Array(0), info, 32);
}
