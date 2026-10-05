// The classical and symmetric primitives, all from Web Crypto (crypto.subtle), matching
// the Go reference: SHA-384, HKDF-SHA-384, HMAC-SHA-384 and AES-256-GCM. These are
// available identically in the Workers runtime and in Node, so the same code runs in
// production and under the offline validators. Byte inputs are coerced with ab() at the
// crypto.subtle boundary, which TypeScript 5.7+ requires (Uint8Array<ArrayBuffer>); every
// buffer here is ArrayBuffer-backed so the coercion is sound and has no runtime cost.

import { ab } from "./bytes.ts";

const subtle = crypto.subtle;

/** GCM nonce length pinned by SPEC 7.8. */
const GCM_NONCE_LEN = 12;

/**
 * Computes the SHA-384 digest of the input via Web Crypto.
 *
 * @param data - the bytes to hash.
 * @returns the 48-byte SHA-384 digest.
 */
export async function sha384(data: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await subtle.digest("SHA-384", ab(data)));
}

/**
 * Derives bytes with HKDF-SHA-384 (extract and expand) via Web Crypto, matching the Go reference.
 *
 * @param ikm - the input keying material.
 * @param salt - the HKDF salt (may be empty).
 * @param info - the HKDF info / context string.
 * @param n - the number of output bytes to derive.
 * @returns the n derived bytes.
 */
export async function hkdfSha384(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, n: number): Promise<Uint8Array<ArrayBuffer>> {
  const key = await subtle.importKey("raw", ab(ikm), "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits({ name: "HKDF", hash: "SHA-384", salt: ab(salt), info: ab(info) }, key, n * 8);
  return new Uint8Array(bits);
}

/**
 * Computes the HMAC-SHA-384 of a message under a key via Web Crypto, the 48-byte keyed MAC used
 * for the segment address, the name MAC and the key commitment.
 *
 * @param key - the MAC key.
 * @param msg - the message bytes to authenticate.
 * @returns the 48-byte MAC.
 */
export async function hmacSha384(key: Uint8Array, msg: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const k = await subtle.importKey("raw", ab(key), { name: "HMAC", hash: "SHA-384" }, false, ["sign"]);
  return new Uint8Array(await subtle.sign("HMAC", k, ab(msg)));
}

/**
 * Encrypts plaintext under AES-256-GCM, returning ciphertext concatenated with the 16-byte tag,
 * exactly as Go's cipher.AEAD.Seal does.
 *
 * @param key - the 32-byte AES-256 key.
 * @param nonce - the 12-byte GCM nonce.
 * @param plaintext - the bytes to encrypt.
 * @param aad - optional additional authenticated data; omitted from the call when undefined or
 *   empty.
 * @returns the ciphertext followed by the 16-byte authentication tag.
 */
export async function aesGcmSeal(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array | undefined): Promise<Uint8Array<ArrayBuffer>> {
  if (nonce.length !== GCM_NONCE_LEN) throw new Error(`GCM nonce is ${nonce.length} bytes, want ${GCM_NONCE_LEN}`);
  const k = await subtle.importKey("raw", ab(key), "AES-GCM", false, ["encrypt"]);
  const params: AesGcmParams = { name: "AES-GCM", iv: ab(nonce), tagLength: 128 };
  if (aad && aad.length > 0) params.additionalData = ab(aad);
  return new Uint8Array(await subtle.encrypt(params, k, ab(plaintext)));
}

/**
 * Decrypts and authenticates an AES-256-GCM sealed buffer (ciphertext || 16-byte tag), reversing
 * aesGcmSeal.
 *
 * @param key - the 32-byte AES-256 key.
 * @param nonce - the 12-byte GCM nonce used to seal.
 * @param sealed - the ciphertext followed by its 16-byte tag.
 * @param aad - optional additional authenticated data; must match what was sealed.
 * @returns the recovered plaintext.
 * @throws when authentication fails (a wrong key, nonce, aad or any tampering).
 */
export async function aesGcmOpen(key: Uint8Array, nonce: Uint8Array, sealed: Uint8Array, aad: Uint8Array | undefined): Promise<Uint8Array<ArrayBuffer>> {
  if (nonce.length !== GCM_NONCE_LEN) throw new Error(`GCM nonce is ${nonce.length} bytes, want ${GCM_NONCE_LEN}`);
  const k = await subtle.importKey("raw", ab(key), "AES-GCM", false, ["decrypt"]);
  const params: AesGcmParams = { name: "AES-GCM", iv: ab(nonce), tagLength: 128 };
  if (aad && aad.length > 0) params.additionalData = ab(aad);
  return new Uint8Array(await subtle.decrypt(params, k, ab(sealed)));
}
