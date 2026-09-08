// The CBOR + COSE layer of the WebAuthn / passkey core, split out of passkey.ts so each module stays a
// coherent unit under 500 lines. This holds the minimal bounded CBOR decoder (the subset WebAuthn uses), the
// COSE_Key parse + validate (EC2 P-256 / RSA), and the COSE public-key import + assertion-signature verify
// (Web Crypto), plus the ASN.1/DER ECDSA-Sig-Value -> raw r||s conversion. The authenticator-data parser
// (passkey-authdata.ts) and the ceremony core (passkey.ts) import from here. This module is the CBOR/COSE
// core; its callers are passkey.ts and passkey-authdata.ts.
//
// SECURITY: every length is checked against the remaining buffer before it is consumed, so a truncated or
// oversized field is a typed rejection, never an out-of-range read; the DECODE depth + element counts are
// bounded so a deeply-nested / huge CBOR cannot blow the stack or drive a large allocation on the
// single-threaded DO; the DER converter is strict (no BER laxities), closing a signature-malleability source.
//
// Node 25 strip-types compatible and Workers-runtime compatible: Web Crypto only, no Node built-ins, no enums,
// explicit field declarations.

import { ab, b64urlEncode } from "../crypto/bytes.ts";
import type { WebauthnFaultClass } from "./diag-records.ts";
import { PasskeyError } from "./passkey-types.ts";

// structuralPasskeyError builds the SAME coarse PasskeyError("bad_request", ...) every structural defect has
// always thrown, and TAGS it with a CLOSED WebauthnFaultClass (support-pack G158). The client-facing response
// is byte-identical (still the coarse "bad_request", so no class is ever oracled back to a caller and the
// anti-enumeration property is preserved); the tag is read ONLY by the DO's ceremony catch, which bumps a
// counter in the bounded webauthnFaults aggregate the pack carries.
//
// Before this, all 14 of these defects collapsed into ONE counter (passkey-bad-request) with their real shape
// living in an errId'd Workers Logs line the vendor structurally cannot read -- so "our whole fleet of
// Ed25519-only security keys can never enrol" and "one user's previously-working passkey is rejected on every
// login" (a CORRUPTED STORED COSE key: login re-decodes the stored key through this very parser) were the
// same number in the pack.
//
// REDACTION: the tag carries the closed class and, for an unsupported algorithm, the offered COSE alg INTEGER
// (a small value from the fixed IANA COSE registry -- never a key, a coordinate, a credential id or a
// modulus). `detail` still rides on the Error for the Workers Logs line and is NEVER recorded.
//
// It is exported so passkey-authdata.ts (the sibling parser) tags its own defects through the same helper.
export function structuralPasskeyError(cls: WebauthnFaultClass, detail: string, coseAlg?: number): PasskeyError {
  const e = new PasskeyError("bad_request", detail);
  return Object.assign(e, { webauthnFaultClass: cls, ...(coseAlg !== undefined ? { coseAlg } : {}) });
}

// UTF8_DECODER is a single shared strict decoder reused across all CBOR text-string decodes. fatal:true so
// invalid UTF-8 is a rejection, not a replacement character. Hoisted to avoid a per-field allocation.
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

// COSE_ES256 / COSE_RS256 are the two COSE algorithm identifiers this core accepts, the same two the
// browser side requests in pubKeyCredParams (ES256 first, then RS256). ES256 is the near-universal
// passkey algorithm (platform authenticators and security keys); RS256 is accepted for the older
// authenticators that only do RSA. No other algorithm is accepted (an unexpected alg is a rejection),
// so the verifier's algorithm surface is exactly these two.
export const COSE_ES256 = -7;
export const COSE_RS256 = -257;

// COSE_KEY_MAX bounds the COSE public key blob (the trailing bytes of attested credential data). An
// ES256 key is ~77 bytes and an RS256 key ~270+ bytes; 2048 is a generous ceiling that still rejects a
// structure padded to drive the CBOR parser into wasted work on the single-threaded DO.
export const COSE_KEY_MAX = 2048;

// ---- Minimal, bounded CBOR decode (the subset WebAuthn uses) -----------------------------------
// WebAuthn's attestationObject is a CBOR map and the COSE_Key is a CBOR map; we need only the small
// CBOR subset those use: unsigned/negative integers, byte strings, text strings, arrays and maps, with
// definite lengths. We deliberately do NOT pull in a general CBOR library: a hand-written, strictly
// bounded decoder over exactly the supported major types is smaller, auditable, and rejects anything it
// does not understand (indefinite lengths, tags, floats, bignums) rather than silently accepting a
// structure a fuller parser might. Every length is checked against the remaining buffer before it is
// consumed, so a truncated or oversized field is a typed rejection, never an out-of-range read.

// CborValue is the closed set of decoded shapes. A map is decoded into an array of [key, value] PAIRS
// rather than an object, because a COSE_Key uses integer keys (and duplicate/!ordered keys must be
// detectable), which a plain object cannot represent faithfully.
type CborValue =
  | { t: "int"; v: number } // a CBOR unsigned or negative integer that fits a JS safe integer
  | { t: "bytes"; v: Uint8Array } // a CBOR byte string
  | { t: "text"; v: string } // a CBOR text string (UTF-8)
  | { t: "array"; v: CborValue[] }
  | { t: "map"; v: Array<[CborValue, CborValue]> };

// CborReader walks the buffer with an explicit cursor and bounds every read. It throws PasskeyError
// "bad_request" on any malformed/unsupported input; the DECODE depth is bounded so a deeply nested
// hostile structure cannot blow the stack on the single-threaded DO.
export class CborReader {
  private readonly buf: Uint8Array;
  private pos = 0;
  // MAX_DEPTH bounds nesting (a COSE_Key/attestationObject is shallow: a map of maps at most). 16 is far
  // beyond any legitimate WebAuthn structure and stops a hostile deeply-nested CBOR from recursing far.
  private static readonly MAX_DEPTH = 16;
  // MAX_ITEMS bounds the element count of any single array/map so a header claiming a huge count cannot
  // drive a large allocation/loop before the length-vs-buffer check would catch a truncation. A COSE_Key
  // has a handful of entries; 64 is a generous ceiling.
  private static readonly MAX_ITEMS = 64;

  constructor(buf: Uint8Array) {
    this.buf = buf;
  }

  // remaining is how many bytes are left to read; readByte/readBytes/need all check against it first.
  private remaining(): number {
    return this.buf.length - this.pos;
  }

  // position is the cursor offset (how many bytes have been consumed so far). parseAuthData uses it to
  // measure the exact span one decoded item (the COSE_Key) occupied, so the key bytes are captured
  // precisely even when extension data follows.
  position(): number {
    return this.pos;
  }

  private need(n: number): void {
    if (n < 0 || this.remaining() < n) {
      throw structuralPasskeyError("cbor-truncated", `cbor: need ${n} bytes, have ${this.remaining()}`);
    }
  }

  private readByte(): number {
    this.need(1);
    return this.buf[this.pos++]!;
  }

  private readBytes(n: number): Uint8Array {
    this.need(n);
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  // readUint reads the argument for an initial byte's additional-information value (the low 5 bits): a
  // value 0..23 is the argument itself; 24/25/26/27 read 1/2/4/8 following big-endian bytes. We reject
  // 28..30 (reserved) and 31 (indefinite length is not supported). An 8-byte argument is range-checked
  // to a JS safe integer so a value beyond 2^53-1 is rejected rather than silently losing precision.
  private readUint(ai: number): number {
    if (ai < 24) return ai;
    if (ai === 24) return this.readByte();
    if (ai === 25) {
      const b = this.readBytes(2);
      return (b[0]! << 8) | b[1]!;
    }
    if (ai === 26) {
      const b = this.readBytes(4);
      // Assemble as an unsigned 32-bit value without sign extension.
      return b[0]! * 0x1000000 + (b[1]! << 16) + (b[2]! << 8) + b[3]!;
    }
    if (ai === 27) {
      const b = this.readBytes(8);
      const hi = b[0]! * 0x1000000 + (b[1]! << 16) + (b[2]! << 8) + b[3]!;
      const lo = b[4]! * 0x1000000 + (b[5]! << 16) + (b[6]! << 8) + b[7]!;
      const v = hi * 0x100000000 + lo;
      if (!Number.isSafeInteger(v)) throw structuralPasskeyError("cbor-unsupported", "cbor: integer exceeds safe range");
      return v;
    }
    throw structuralPasskeyError("cbor-unsupported", `cbor: unsupported additional info ${ai}`);
  }

  // decode reads exactly one CBOR data item at the cursor, recursing for arrays/maps under the depth
  // bound. The major type is the top 3 bits of the initial byte; the additional information is the low 5.
  decode(depth = 0): CborValue {
    if (depth > CborReader.MAX_DEPTH) throw structuralPasskeyError("cbor-depth", "cbor: nesting too deep");
    const ib = this.readByte();
    const major = ib >> 5;
    const ai = ib & 0x1f;
    switch (major) {
      case 0: // unsigned integer
        return { t: "int", v: this.readUint(ai) };
      case 1: {
        // negative integer: the encoded value n represents -1 - n. Range-check the magnitude.
        const n = this.readUint(ai);
        const v = -1 - n;
        if (!Number.isSafeInteger(v)) throw structuralPasskeyError("cbor-unsupported", "cbor: negative integer exceeds safe range");
        return { t: "int", v };
      }
      case 2: {
        // byte string
        const len = this.readUint(ai);
        return { t: "bytes", v: this.readBytes(len).slice() };
      }
      case 3: {
        // text string (UTF-8). fatal:true so invalid UTF-8 is a rejection, not a replacement char.
        //
        // The fatal decoder throws a raw TypeError, which is the ONE structural defect here that did NOT
        // coarsen like its siblings: it escaped the PasskeyError contract entirely and surfaced through the
        // ceremony catch's "internal" arm (a 500-class log line), rather than as the coarse bad_request every
        // other malformed-CBOR branch returns. It is now a tagged structural rejection like the rest, so the
        // client response is the SAME coarse bad_request and the pack gets the honest class.
        const len = this.readUint(ai);
        const bytes = this.readBytes(len);
        try {
          return { t: "text", v: UTF8_DECODER.decode(bytes) };
        } catch {
          throw structuralPasskeyError("cbor-utf8", "cbor: text string is not valid UTF-8");
        }
      }
      case 4: // array
        return { t: "array", v: this.decodeArray(ai, depth) };
      case 5: // map
        return { t: "map", v: this.decodeMap(ai, depth) };
      default:
        // major types 6 (tags) and 7 (floats/simple) are not part of the WebAuthn subset we accept.
        throw structuralPasskeyError("cbor-unsupported", `cbor: unsupported major type ${major}`);
    }
  }

  // decodeArray reads a definite-length array, bounding the element count before allocating.
  private decodeArray(ai: number, depth: number): CborValue[] {
    const len = this.readUint(ai);
    if (len > CborReader.MAX_ITEMS) throw structuralPasskeyError("cbor-items-cap", "cbor: array too large");
    const out: CborValue[] = [];
    for (let i = 0; i < len; i++) out.push(this.decode(depth + 1));
    return out;
  }

  // decodeMap reads a definite-length map into [key, value] pairs, bounding the pair count before allocating.
  private decodeMap(ai: number, depth: number): Array<[CborValue, CborValue]> {
    const len = this.readUint(ai);
    if (len > CborReader.MAX_ITEMS) throw structuralPasskeyError("cbor-items-cap", "cbor: map too large");
    const out: Array<[CborValue, CborValue]> = [];
    for (let i = 0; i < len; i++) {
      const k = this.decode(depth + 1);
      const v = this.decode(depth + 1);
      out.push([k, v]);
    }
    return out;
  }

  // decodeTop decodes one item and asserts the whole buffer was consumed: a WebAuthn attestationObject
  // or COSE_Key is exactly one top-level item, so trailing bytes are a malformed/over-long structure
  // and are rejected (a forgery cannot append a second object to be ignored).
  decodeTop(): CborValue {
    const v = this.decode(0);
    if (this.remaining() !== 0) throw structuralPasskeyError("cbor-trailing", "cbor: trailing bytes after top-level item");
    return v;
  }
}

// mapGetInt finds an integer-keyed entry in a decoded CBOR map and returns its value, or undefined when
// absent. COSE_Key and the attestationObject's relevant fields use integer/text keys; this is the
// integer-key lookup (COSE labels are integers). A duplicate key (the same integer twice) is a
// malformed map and is rejected, so a forgery cannot smuggle a second value under the same label.
function mapGetInt(m: Array<[CborValue, CborValue]>, key: number): CborValue | undefined {
  let found: CborValue | undefined;
  for (const [k, v] of m) {
    if (k.t === "int" && k.v === key) {
      if (found !== undefined) throw structuralPasskeyError("cbor-duplicate-key", `cbor: duplicate map key ${key}`);
      found = v;
    }
  }
  return found;
}

// mapGetText finds a text-keyed entry (the attestationObject uses text keys "fmt"/"authData"/"attStmt").
export function mapGetText(m: Array<[CborValue, CborValue]>, key: string): CborValue | undefined {
  let found: CborValue | undefined;
  for (const [k, v] of m) {
    if (k.t === "text" && k.v === key) {
      if (found !== undefined) throw structuralPasskeyError("cbor-duplicate-key", `cbor: duplicate map key ${JSON.stringify(key)}`);
      found = v;
    }
  }
  return found;
}

// ---- COSE_Key parse (EC2 + RSA), bounded and fully validated -----------------------------------
// CoseKey is the decoded, validated public key. kty is the key type (2 = EC2, 3 = RSA); alg is the
// signature algorithm (-7 ES256 for EC2, -257 RS256 for RSA). For EC2: crv must be P-256 (1), and x/y
// are the 32-byte coordinates. For RSA: n is the modulus and e the public exponent. Every field is
// length/value validated; a missing or wrong-shaped field is a rejection.
export type CoseKey =
  | { kty: 2; alg: -7; crv: 1; x: Uint8Array; y: Uint8Array } // EC2 P-256, ES256
  | { kty: 3; alg: -257; n: Uint8Array; e: Uint8Array }; // RSA, RS256

// COSE label constants (RFC 9052; algorithm identifiers -7/-257 are RFC 9053): kty=1, alg=3; EC2 params
// crv=-1, x=-2, y=-3; RSA params n=-1, e=-2. RFC 9052/9053 obsolete RFC 8152; the label and algorithm
// values are unchanged.
const COSE_LABEL_KTY = 1;
const COSE_LABEL_ALG = 3;
const COSE_EC2_CRV = -1;
const COSE_EC2_X = -2;
const COSE_EC2_Y = -3;
const COSE_RSA_N = -1;
const COSE_RSA_E = -2;
const COSE_KTY_EC2 = 2;
const COSE_KTY_RSA = 3;
const COSE_CRV_P256 = 1;
export const P256_COORD_LEN = 32;
// RSA modulus bounds: 2048..4096 bits = 256..512 bytes. A leading zero byte (DER-style sign byte) is
// tolerated by stripping it before the length check, since some encoders include it. The exponent is a
// few bytes (commonly 65537 = 0x010001).
const RSA_N_MIN = 256;
const RSA_N_MAX = 512;
const RSA_E_MAX = 8;

// parseCoseKey decodes and validates a COSE_Key from its raw bytes, returning the typed CoseKey or
// throwing PasskeyError "bad_request" on anything malformed. It is the single COSE parser both the
// registration extract and the login verify use (the login re-decodes the STORED key bytes through this
// same path, so a stored key is validated identically on every use, never trusted as pre-parsed).
export function parseCoseKey(raw: Uint8Array): CoseKey {
  if (raw.length === 0 || raw.length > COSE_KEY_MAX) {
    throw structuralPasskeyError("cose-shape", `cose: key length ${raw.length} out of range`);
  }
  const top = new CborReader(raw).decodeTop();
  if (top.t !== "map") throw structuralPasskeyError("cose-shape", "cose: top-level is not a map");
  const m = top.v;
  const ktyV = mapGetInt(m, COSE_LABEL_KTY);
  const algV = mapGetInt(m, COSE_LABEL_ALG);
  if (ktyV === undefined || ktyV.t !== "int") throw structuralPasskeyError("cose-shape", "cose: missing/invalid kty");
  if (algV === undefined || algV.t !== "int") throw structuralPasskeyError("cose-shape", "cose: missing/invalid alg");
  const kty = ktyV.v;
  const alg = algV.v;

  if (kty === COSE_KTY_EC2) return parseCoseKeyEC2(m, alg);
  if (kty === COSE_KTY_RSA) return parseCoseKeyRSA(m, alg);
  throw structuralPasskeyError("cose-unsupported-kty", `cose: unsupported kty ${kty}`, alg);
}

// parseCoseKeyEC2 validates the EC2 P-256 branch (ES256): crv must be P-256 and x/y must be 32-byte
// coordinates, otherwise a typed rejection.
function parseCoseKeyEC2(m: Array<[CborValue, CborValue]>, alg: number): CoseKey {
  if (alg !== COSE_ES256) throw structuralPasskeyError("cose-unsupported-alg", `cose: EC2 key with unexpected alg ${alg}`, alg);
  const crvV = mapGetInt(m, COSE_EC2_CRV);
  const xV = mapGetInt(m, COSE_EC2_X);
  const yV = mapGetInt(m, COSE_EC2_Y);
  if (crvV === undefined || crvV.t !== "int" || crvV.v !== COSE_CRV_P256) {
    throw structuralPasskeyError("cose-shape", "cose: EC2 key crv is not P-256");
  }
  if (xV === undefined || xV.t !== "bytes" || xV.v.length !== P256_COORD_LEN) {
    throw structuralPasskeyError("cose-shape", "cose: EC2 key x is not a 32-byte coordinate");
  }
  if (yV === undefined || yV.t !== "bytes" || yV.v.length !== P256_COORD_LEN) {
    throw structuralPasskeyError("cose-shape", "cose: EC2 key y is not a 32-byte coordinate");
  }
  return { kty: 2, alg: -7, crv: 1, x: xV.v, y: yV.v };
}

// parseCoseKeyRSA validates the RSA branch (RS256): the modulus is bounded (after stripping a single
// leading sign byte) and the exponent is a few bytes, otherwise a typed rejection.
function parseCoseKeyRSA(m: Array<[CborValue, CborValue]>, alg: number): CoseKey {
  if (alg !== COSE_RS256) throw structuralPasskeyError("cose-unsupported-alg", `cose: RSA key with unexpected alg ${alg}`, alg);
  const nV = mapGetInt(m, COSE_RSA_N);
  const eV = mapGetInt(m, COSE_RSA_E);
  if (nV === undefined || nV.t !== "bytes") throw structuralPasskeyError("cose-shape", "cose: RSA key missing modulus n");
  if (eV === undefined || eV.t !== "bytes") throw structuralPasskeyError("cose-shape", "cose: RSA key missing exponent e");
  // Strip at most one leading zero sign byte from the modulus before bounding it.
  let n = nV.v;
  if (n.length > 0 && n[0] === 0x00) n = n.subarray(1);
  if (n.length < RSA_N_MIN || n.length > RSA_N_MAX) {
    throw structuralPasskeyError("cose-shape", `cose: RSA modulus length ${n.length} out of range`);
  }
  const e = eV.v;
  if (e.length === 0 || e.length > RSA_E_MAX) {
    throw structuralPasskeyError("cose-shape", `cose: RSA exponent length ${e.length} out of range`);
  }
  return { kty: 3, alg: -257, n: n.slice(), e: e.slice() };
}

// ---- ECDSA DER -> raw r||s conversion ----------------------------------------------------------
// WebAuthn ES256 assertion signatures are ASN.1 DER ECDSA-Sig-Value: SEQUENCE { r INTEGER, s INTEGER }.
// Web Crypto's ECDSA verify wants the raw fixed-length r||s (64 bytes for P-256). derEcdsaToRaw parses
// the DER strictly (it does NOT accept BER laxities) and left-pads each integer to 32 bytes. It rejects:
// a non-SEQUENCE, a length mismatch, a non-INTEGER element, a negative integer (high bit set with no
// leading zero), a non-minimal encoding (a superfluous leading zero), and an integer whose magnitude
// exceeds 32 bytes. This strictness matters: a lax converter is a classic signature-malleability and
// parser-confusion source, so the DER must be exactly well-formed.
export function derEcdsaToRaw(der: Uint8Array): Uint8Array {
  let pos = 0;
  const need = (n: number): void => {
    if (der.length < pos + n) throw structuralPasskeyError("der-signature-malformed", "der: truncated");
  };
  const readByte = (): number => {
    need(1);
    return der[pos++]!;
  };
  // SEQUENCE tag 0x30.
  if (readByte() !== 0x30) throw structuralPasskeyError("der-signature-malformed", "der: expected SEQUENCE");
  // The SEQUENCE length: short form only (an ECDSA P-256 signature is well under 128 bytes), so a long-
  // form length byte (high bit set) is rejected as non-canonical for this fixed-size structure.
  const seqLen = readByte();
  if (seqLen & 0x80) throw structuralPasskeyError("der-signature-malformed", "der: long-form length not allowed");
  if (seqLen !== der.length - pos) throw structuralPasskeyError("der-signature-malformed", "der: sequence length mismatch");

  const readInt = (): Uint8Array => {
    if (readByte() !== 0x02) throw structuralPasskeyError("der-signature-malformed", "der: expected INTEGER");
    const len = readByte();
    if (len & 0x80) throw structuralPasskeyError("der-signature-malformed", "der: integer long-form length not allowed");
    if (len === 0) throw structuralPasskeyError("der-signature-malformed", "der: zero-length integer");
    need(len);
    const bytes = der.subarray(pos, pos + len);
    pos += len;
    // The high bit of the first byte must be 0 (a positive integer); a 1 means the DER encoder would
    // have prefixed a 0x00, so a high-bit-set first byte here is a negative/invalid integer.
    if (bytes[0]! & 0x80) throw structuralPasskeyError("der-signature-malformed", "der: negative integer");
    // Minimal encoding: a leading 0x00 is allowed ONLY when the next byte's high bit is set (it is the
    // sign byte). A leading 0x00 followed by a high-bit-clear byte is a non-minimal encoding.
    if (bytes.length > 1 && bytes[0] === 0x00 && (bytes[1]! & 0x80) === 0) {
      throw structuralPasskeyError("der-signature-malformed", "der: non-minimal integer encoding");
    }
    // Strip a single leading sign 0x00 to get the magnitude, then it must fit 32 bytes.
    let mag = bytes;
    if (mag.length > 1 && mag[0] === 0x00) mag = mag.subarray(1);
    if (mag.length > P256_COORD_LEN) throw structuralPasskeyError("der-signature-malformed", "der: integer exceeds 32 bytes");
    const out = new Uint8Array(P256_COORD_LEN);
    out.set(mag, P256_COORD_LEN - mag.length);
    return out;
  };

  const r = readInt();
  const s = readInt();
  if (pos !== der.length) throw structuralPasskeyError("der-signature-malformed", "der: trailing bytes");
  const raw = new Uint8Array(P256_COORD_LEN * 2);
  raw.set(r, 0);
  raw.set(s, P256_COORD_LEN);
  return raw;
}

// ---- COSE public key import + signature verify (Web Crypto) -------------------------------------
// importCoseKey imports a parsed CoseKey as a Web Crypto verify-only CryptoKey. ES256 imports the EC2
// key as a JWK (P-256, base64url x/y) for ECDSA verify; RS256 imports the RSA key as a JWK (base64url
// n/e) for RSASSA-PKCS1-v1_5 verify. Importing via JWK avoids hand-assembling SPKI DER and lets Web
// Crypto reject a structurally invalid key.
//
// G158: a REFUSED import is now tagged key-import-failed. That class is the single most valuable one in the
// vocabulary because of WHERE it fires: the login path re-decodes and re-imports the STORED COSE key on every
// assertion, so key-import-failed on the LOGIN phase means the persisted credential record is CORRUPT (the
// user's device is fine and they can never sign in again), while the same class on the ENROL phase means the
// runtime refused the device's key. Those two tickets look identical today and have opposite remedies.
async function importCoseKey(key: CoseKey): Promise<{ cryptoKey: CryptoKey; algo: EcdsaParams | AlgorithmIdentifier }> {
  try {
    return await importCoseKeyInner(key);
  } catch (e) {
    if (e instanceof PasskeyError) throw e;
    throw structuralPasskeyError("key-import-failed", `cose: key import refused (${(e as Error).message})`);
  }
}

async function importCoseKeyInner(key: CoseKey): Promise<{ cryptoKey: CryptoKey; algo: EcdsaParams | AlgorithmIdentifier }> {
  if (key.kty === 2) {
    const jwk: JsonWebKey = {
      kty: "EC",
      crv: "P-256",
      x: b64urlEncode(key.x),
      y: b64urlEncode(key.y),
      ext: true,
    };
    const cryptoKey = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return { cryptoKey, algo: { name: "ECDSA", hash: "SHA-256" } };
  }
  // RSA, RS256.
  const jwk: JsonWebKey = {
    kty: "RSA",
    n: b64urlEncode(key.n),
    e: b64urlEncode(key.e),
    alg: "RS256",
    ext: true,
  };
  const cryptoKey = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  return { cryptoKey, algo: { name: "RSASSA-PKCS1-v1_5" } };
}

// verifySignature verifies a WebAuthn assertion signature over signedData = authenticatorData ||
// SHA-256(clientDataJSON), using the stored COSE public key. ES256: the DER signature is converted to
// raw r||s and verified with ECDSA P-256/SHA-256. RS256: the signature is verified as-is with RSASSA-
// PKCS1-v1_5/SHA-256. Returns true ONLY on a positive verification; any malformed signature, import
// failure, or non-verification returns false (it never throws here, so the caller maps a false to the
// coarse "signature" rejection and the precise reason is captured before this returns).
export async function verifySignature(key: CoseKey, signedData: Uint8Array, signature: Uint8Array): Promise<boolean> {
  const { cryptoKey, algo } = await importCoseKey(key);
  if (key.kty === 2) {
    // ES256: convert DER -> raw; a malformed DER throws PasskeyError, which the caller treats as a
    // non-verification (a bad signature, not a 500).
    const raw = derEcdsaToRaw(signature);
    return crypto.subtle.verify(algo as EcdsaParams, cryptoKey, ab(raw), ab(signedData));
  }
  // RS256: the signature is the raw PKCS#1 v1.5 block; verify directly.
  return crypto.subtle.verify(algo as AlgorithmIdentifier, cryptoKey, ab(signature), ab(signedData));
}
