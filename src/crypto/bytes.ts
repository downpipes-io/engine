// Byte helpers shared by the crypto port. base64url no-pad and lowercase hex match the
// reference encodings (SPEC 11.4, 11.8); concatenation and the single-byte length
// prefix match internal/crypto/derive.go.

/**
 * Narrows a Uint8Array to the ArrayBuffer-backed generic that TypeScript 5.7+ requires at the
 * Web Crypto, fetch and DataView boundaries. Every buffer in this codebase is ArrayBuffer-backed
 * (never SharedArrayBuffer), so the assertion is sound and has no runtime cost.
 *
 * @param x - the byte array to re-type.
 * @returns the same array, typed as Uint8Array<ArrayBuffer> (no copy, no runtime change).
 */
export function ab(x: Uint8Array): Uint8Array<ArrayBuffer> {
  return x as Uint8Array<ArrayBuffer>;
}

/**
 * Concatenates byte arrays into one fresh ArrayBuffer-backed array, in order.
 *
 * @param parts - the byte arrays to join, left to right.
 * @returns a new array holding every part's bytes back to back.
 */
export function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/**
 * Appends a single-byte length prefix and the field to dst, the canonical length-prefixed
 * concatenation of SPEC 7.4.
 *
 * @param dst - the bytes to append to.
 * @param field - the field to length-prefix and append; must be at most 255 bytes.
 * @returns a new array of dst followed by the one-byte length and the field.
 * @throws Error when field is longer than 255 bytes (it cannot be length-prefixed in one byte).
 */
export function lpAppend(dst: Uint8Array, field: Uint8Array): Uint8Array<ArrayBuffer> {
  if (field.length > 255) throw new Error("length-prefixed field exceeds 255 bytes");
  return concat(dst, new Uint8Array([field.length]), field);
}

/**
 * Encodes a 32-bit unsigned integer as 4 big-endian bytes.
 *
 * @param n - the value to encode (treated as an unsigned 32-bit integer by DataView).
 * @returns the 4-byte big-endian encoding.
 */
export function u32be(n: number): Uint8Array<ArrayBuffer> {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

/**
 * Encodes a 64-bit unsigned integer as 8 big-endian bytes.
 *
 * @param n - the value to encode (treated as an unsigned 64-bit integer by DataView).
 * @returns the 8-byte big-endian encoding.
 */
export function u64be(n: bigint): Uint8Array<ArrayBuffer> {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, false);
  return b;
}

/**
 * Encodes a string to its UTF-8 bytes.
 *
 * @param s - the string to encode.
 * @returns the UTF-8 byte encoding.
 */
export function utf8(s: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(s);
}

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// Decode lookup table mapping an ASCII code point to its 6-bit value, or -1 when not in the
// alphabet. Computed once at module load so b64urlDecode does not rebuild it on every call.
const B64URL_LUT = (() => {
  const t = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64URL.length; i++) t[B64URL.charCodeAt(i)] = i;
  return t;
})();

/**
 * Encodes bytes as URL-safe base64 with no padding, matching Go's base64.RawURLEncoding
 * (alphabet A-Z a-z 0-9 - _, no trailing `=`).
 *
 * @param data - the bytes to encode.
 * @returns the no-padding base64url string.
 */
export function b64urlEncode(data: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 3 <= data.length; i += 3) {
    const n = (data[i]! << 16) | (data[i + 1]! << 8) | data[i + 2]!;
    out += B64URL[(n >> 18) & 63]! + B64URL[(n >> 12) & 63]! + B64URL[(n >> 6) & 63]! + B64URL[n & 63]!;
  }
  const rem = data.length - i;
  if (rem === 1) {
    const n = data[i]! << 16;
    out += B64URL[(n >> 18) & 63]! + B64URL[(n >> 12) & 63]!;
  } else if (rem === 2) {
    const n = (data[i]! << 16) | (data[i + 1]! << 8);
    out += B64URL[(n >> 18) & 63]! + B64URL[(n >> 12) & 63]! + B64URL[(n >> 6) & 63]!;
  }
  return out;
}

const B64STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Encodes bytes as STANDARD base64 (RFC 4648 alphabet A-Z a-z 0-9 + /, WITH `=` padding). This is the
 * form AWS S3 requires for the checksum and digest headers (x-amz-checksum-sha256, Content-MD5), which
 * are NOT the URL-safe no-padding form b64urlEncode produces (those carry `-`/`_` and drop padding, both
 * of which S3 rejects on those headers). Kept beside b64urlEncode so the two encodings never get confused
 * at a call site.
 *
 * @param data - the bytes to encode.
 * @returns the padded standard-base64 string.
 */
export function base64Encode(data: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 3 <= data.length; i += 3) {
    const n = (data[i]! << 16) | (data[i + 1]! << 8) | data[i + 2]!;
    out += B64STD[(n >> 18) & 63]! + B64STD[(n >> 12) & 63]! + B64STD[(n >> 6) & 63]! + B64STD[n & 63]!;
  }
  const rem = data.length - i;
  if (rem === 1) {
    const n = data[i]! << 16;
    out += `${B64STD[(n >> 18) & 63]!}${B64STD[(n >> 12) & 63]!}==`;
  } else if (rem === 2) {
    const n = (data[i]! << 16) | (data[i + 1]! << 8);
    out += `${B64STD[(n >> 18) & 63]!}${B64STD[(n >> 12) & 63]!}${B64STD[(n >> 6) & 63]!}=`;
  }
  return out;
}

/**
 * Strictly decodes a no-padding URL-safe base64 string, matching Go's
 * base64.RawURLEncoding.DecodeString exactly: only the URL-safe alphabet (A-Z a-z 0-9 - _) is
 * accepted; padding `=`, whitespace, `+`, `/` and any other out-of-alphabet character are
 * rejected; a length whose remainder modulo 4 is 1 is impossible under no-padding base64 and is
 * rejected; and non-canonical trailing bits (last-group bits that contribute to no output byte
 * must be zero) are rejected.
 *
 * @param s - the no-padding base64url string to decode.
 * @returns the decoded bytes.
 * @throws Error when the length is invalid (mod 4 equals 1), a character is outside the alphabet,
 *   or the trailing bits are non-canonical.
 */
export function b64urlDecode(s: string): Uint8Array<ArrayBuffer> {
  // length mod 4 == 1 can never represent a valid no-padding base64url byte sequence
  if (s.length % 4 === 1) {
    throw new Error(`invalid base64url length ${s.length}: length mod 4 must not be 1`);
  }

  // Each character carries 6 bits, so the decoded length is floor(len * 6 / 8). Allocate the
  // output up front and write into it directly to avoid an intermediate number[].
  const out = new Uint8Array(Math.floor((s.length * 6) / 8));
  let n = 0;
  let bits = 0;
  let acc = 0;
  for (const ch of s) {
    const code = ch.charCodeAt(0);
    // characters outside the 7-bit ASCII range are never valid base64url
    const v = code < 128 ? (B64URL_LUT[code] ?? -1) : -1;
    if (v < 0) throw new Error(`invalid base64url character: ${JSON.stringify(ch)}`);
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[n++] = (acc >> bits) & 0xff;
    }
  }

  // after consuming all characters, bits holds the count of unused trailing bits in acc.
  // those bits must all be zero; a non-zero value means the encoder wrote a non-canonical
  // encoding of fewer bytes (Go's RawURLEncoding returns CorruptInputError in this case).
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) {
    throw new Error("invalid base64url: non-canonical trailing bits");
  }

  return out;
}

/**
 * Computes the SHA-256 digest of the given bytes and returns it as a lowercase hex string. Shared
 * by the SigV4 signer, the STS client and the S3 destination so the digest call lives in one place.
 *
 * @param b - the bytes to hash.
 * @returns the lowercase hex SHA-256 digest.
 */
export async function sha256Hex(b: Uint8Array): Promise<string> {
  return hexEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", ab(b))));
}

/**
 * Encodes bytes as lowercase hexadecimal, two characters per byte.
 *
 * @param data - the bytes to encode.
 * @returns the lowercase hex string.
 */
export function hexEncode(data: Uint8Array): string {
  let out = "";
  for (const b of data) out += b.toString(16).padStart(2, "0");
  return out;
}

/**
 * Decodes a hexadecimal string to its bytes.
 *
 * STRICT VALIDATION: every pair of hex characters is checked before decoding, so a corrupted or truncated
 * input (e.g. a mangled segment object key) is REJECTED rather than silently coerced to a zero byte. A
 * malformed key and a genuinely deleted object must never be byte-identical to a caller: the reader's catch
 * classes a rejection as malformed-object-key, distinct from a clean not-found.
 *
 *
 * @param s - the hex string; its length must be even and every character must be a hex digit.
 * @returns the decoded bytes (one per two hex characters).
 * @throws Error when the string has an odd length or contains a non-hex character. The message carries no
 *   part of the input (the string can BE a customer object key): it names the fault, never the value.
 */
export function hexDecode(s: string): Uint8Array<ArrayBuffer> {
  if (s.length % 2 !== 0) throw new Error("odd-length hex string");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const pair = s.slice(i * 2, i * 2 + 2);
    // parseInt alone is NOT a sufficient guard: parseInt("zz", 16) is NaN (caught), but parseInt("0g", 16)
    // is 0 -- parseInt parses the leading "0" and STOPS at the non-hex "g", so a mixed valid/invalid pair
    // would otherwise slip through as a silent 0 byte. Validate both nibbles are hex digits first, so a
    // corrupted object key like "seg/0g/..." is classed malformed rather than decoding to a wrong-but-
    // well-formed id. The message names the fault, never the value (the string can BE a key).
    if (!/^[0-9a-fA-F]{2}$/.test(pair)) throw new Error("invalid hex string: non-hex character");
    out[i] = parseInt(pair, 16);
  }
  return out;
}

// crypto.subtle.timingSafeEqual is a Workers-runtime extension. The bundled WebWorker lib's
// SubtleCrypto shadows the @cloudflare/workers-types one at the global crypto.subtle, so the method
// is invisible to the type-checker even though it is present in the production runtime. This minimal
// shape restores just that one method for the cast below; it does not widen anything else.
interface TimingSafeSubtle {
  timingSafeEqual?: (a: ArrayBuffer | ArrayBufferView, b: ArrayBuffer | ArrayBufferView) => boolean;
}

/**
 * Compares two byte arrays for equality without an early-exit timing channel. In the Workers runtime
 * the platform primitive crypto.subtle.timingSafeEqual does the constant-time work; it requires
 * equal-length buffers and throws on a mismatch, so the length is checked first (the length is not
 * secret) and a mismatch returns false before the primitive is called. The standard Web Crypto used
 * by the Node test harness has no such method, so a constant-time XOR fallback (it always scans the
 * full equal length) is used there; both paths leak nothing through timing.
 *
 * @param a - the first byte array.
 * @param b - the second byte array.
 * @returns true when the arrays are the same length and every byte matches, false otherwise.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  // Invoke timingSafeEqual AS A METHOD on crypto.subtle. It must NEVER be pulled into a local and called
  // bare: the Workers runtime throws "Illegal invocation: function called with incorrect `this` reference"
  // when a platform primitive runs without its owning object as `this`. Every secret comparison in the
  // live runtime routes through here -- the admin token, the passkey assertion, the session MAC and the
  // recovery codes -- so a detached call would lock the whole engine out of auth.
  const subtle = crypto.subtle as unknown as TimingSafeSubtle;
  if (subtle.timingSafeEqual !== undefined) return subtle.timingSafeEqual(ab(a), ab(b));
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
