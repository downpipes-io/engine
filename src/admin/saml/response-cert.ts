// The X.509 / DER side of the SAML ACS verifier, split out of response.ts so each module stays a coherent unit
// under 500 lines. This holds the standard-base64 decoder used for the SAMLResponse POST value AND for a PEM
// certificate body, plus the minimal, fully-bounded DER TLV reader and the three certificate extractors the
// verifier and the credential-lifecycle registry use:
//   - pemToSpki: PEM X.509 cert -> SubjectPublicKeyInfo (SPKI) DER bytes for crypto.subtle.importKey('spki').
//   - certNotAfter: one cert's notAfter expiry (epoch ms) for the lifecycle registry's MAX-notAfter display.
//   - certValidity: a cert's notBefore..notAfter window (epoch ms) for the verify-time freshness check (IDP-4).
// Every DER length read is bounded against the buffer (a length that runs past the end is a hard reject) and
// nothing is trusted beyond the structure we descend. The certificate is PUBLIC data (an IdP signing cert
// pinned on a connection), so none of this reads a secret.//
// Node 25 strip-types + Workers compatible: pure functions, no DOM, no Node builtins, no enums, explicit
// fields, error-as-value. Australian English; no em dashes.

function fail(reason: string): { ok: false; reason: string } {
  return { ok: false, reason };
}

// ---- standard base64 decode (NOT base64url) for the SAMLResponse POST value ----
// The HTTP POST binding encodes the SAML Response with RFC 2045 / standard base64 (alphabet + and /, with =
// padding). The shared bytes.ts decoder is base64url (- and _, no padding), so we decode standard base64 here,
// STRICTLY: we tolerate the whitespace a form/transport may introduce (a real SAMLResponse field carries no
// internal whitespace, but be liberal in what we strip and strict in what we accept), then require the standard
// alphabet + correct padding. Anything else fails closed (a malformed body is a clean reject, never a throw).
const B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// B64_STD_LUT maps an ASCII code point to its base64 value (or -1). Built once at module load rather than on
// every decodeBase64Std call (called per SAML response and per certificate body in a rollover set).
const B64_STD_LUT: Int16Array = (() => {
  const t = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64_STD.length; i++) t[B64_STD.charCodeAt(i)] = i;
  return t;
})();

export function decodeBase64Std(raw: string): { ok: true; bytes: Uint8Array } | { ok: false } {
  // Strip ASCII whitespace some transports/forms insert (space, tab, CR, LF). Everything else must be in the
  // standard alphabet or be padding.
  let s = "";
  for (const ch of raw) {
    if (ch === " " || ch === "\t" || ch === "\r" || ch === "\n") continue;
    s += ch;
  }
  if (s.length === 0) return { ok: false };
  if (s.length % 4 !== 0) return { ok: false }; // standard base64 is always a multiple of 4 with padding
  const body = s.replace(/=+$/, "");
  const pad = s.length - body.length;
  if (pad > 2) return { ok: false }; // at most two '=' pad characters, only at the very end
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const ch of body) {
    const code = ch.charCodeAt(0);
    const v = code < 128 ? (B64_STD_LUT[code] ?? -1) : -1;
    if (v < 0) return { ok: false };
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  // Non-canonical trailing bits (the bits that pad the last partial group) must be zero, matching a strict
  // decoder (so two distinct base64 strings cannot decode to the same bytes and slip a mutated body past a
  // byte-for-byte comparison elsewhere).
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) return { ok: false };
  return { ok: true, bytes: new Uint8Array(out) };
}

// ---- minimal DER TLV reader + X.509 SubjectPublicKeyInfo extraction ----
// pemToSpki strips the PEM armour from an X.509 certificate, base64-decodes the body to the DER, and WALKS the
// DER to return the SubjectPublicKeyInfo (SPKI) TLV bytes, which crypto.subtle.importKey('spki', ...) consumes.
// We do NOT trust any DER beyond the structure we descend, and EVERY length read is bounded against the buffer
// (a length that runs past the end is a hard reject). This is exported so it can be unit-tested in isolation
// against a known cert/SPKI pair (the dsig verifier round-trips raw SPKI; this is the PEM -> SPKI bridge).
//
// X.509 (RFC 5280):
//   Certificate ::= SEQUENCE {
//     tbsCertificate       SEQUENCE {
//       [0] EXPLICIT version   OPTIONAL,   -- context tag 0xA0
//       serialNumber           INTEGER,
//       signature              SEQUENCE,   -- AlgorithmIdentifier
//       issuer                 SEQUENCE,   -- Name
//       validity               SEQUENCE,
//       subject                SEQUENCE,   -- Name
//       subjectPublicKeyInfo   SEQUENCE { ... },   <-- we return THIS full TLV
//       ... },
//     signatureAlgorithm   SEQUENCE,
//     signatureValue       BIT STRING }

export type PemToSpkiResult = { ok: true; spki: Uint8Array } | { ok: false; reason: string };

// A single DER TLV: its tag byte, the byte offsets of its VALUE (contentStart..contentStart+length) and the
// offset just past the whole TLV (end), so a caller can step to the next sibling.
interface Tlv {
  tag: number;
  contentStart: number;
  length: number;
  end: number;
}

// readTlv reads ONE TLV at offset `pos` in `der`, returning its tag, content span and end offset, or null on any
// malformedness (truncated length, indefinite-length form, or a length that exceeds the buffer). DER forbids the
// BER indefinite-length form (0x80), and X.509 is always definite-length, so we reject it.
function readTlv(der: Uint8Array, pos: number): Tlv | null {
  if (pos < 0 || pos + 2 > der.length) return null; // need at least a tag + one length byte
  const tag = der[pos]!;
  let i = pos + 1;
  const first = der[i]!;
  i++;
  let length: number;
  if (first < 0x80) {
    // Short form: the length is this byte.
    length = first;
  } else if (first === 0x80) {
    // Indefinite length (BER) is not allowed in DER / X.509.
    return null;
  } else {
    // Long form: the low 7 bits are the number of subsequent length bytes (big-endian).
    const numBytes = first & 0x7f;
    if (numBytes === 0 || numBytes > 4) return null; // >4 would overflow a 32-bit length; reject the absurd
    if (i + numBytes > der.length) return null;
    length = 0;
    for (let k = 0; k < numBytes; k++) {
      length = length * 256 + der[i]!;
      i++;
    }
    // A length that does not fit a safe integer, or is negative, cannot be valid here.
    if (!Number.isSafeInteger(length) || length < 0) return null;
  }
  const contentStart = i;
  const end = contentStart + length;
  if (end > der.length || end < contentStart) return null; // bound the value against the buffer (overflow-safe)
  return { tag, contentStart, length, end };
}

// stripPemBase64 extracts the base64 body between the first BEGIN CERTIFICATE and the matching END CERTIFICATE
// armour lines, ignoring everything outside. Returns null when the armour is absent or malformed.
function stripPemBase64(pem: string): string | null {
  const begin = pem.indexOf("-----BEGIN CERTIFICATE-----");
  if (begin === -1) return null;
  const afterBegin = pem.indexOf("\n", begin);
  const bodyStart = afterBegin === -1 ? begin + "-----BEGIN CERTIFICATE-----".length : afterBegin + 1;
  const end = pem.indexOf("-----END CERTIFICATE-----", bodyStart);
  if (end === -1) return null;
  return pem.slice(bodyStart, end);
}

export function pemToSpki(pem: string): PemToSpkiResult {
  const body = stripPemBase64(pem);
  if (body === null) return fail("PEM is not a -----BEGIN CERTIFICATE----- block");
  const decoded = decodeBase64Std(body);
  if (!decoded.ok) return fail("certificate body is not valid base64");
  const der = decoded.bytes;

  // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
  const cert = readTlv(der, 0);
  if (cert === null || cert.tag !== 0x30) return fail("certificate is not a DER SEQUENCE");
  // The outer SEQUENCE should span the whole DER (a trailing-garbage cert is malformed); be lenient about
  // trailing bytes but require the content to be within bounds (readTlv already checked end <= der.length).

  // tbsCertificate ::= SEQUENCE { ... } is the FIRST element inside the Certificate SEQUENCE.
  const tbs = readTlv(der, cert.contentStart);
  if (tbs === null || tbs.tag !== 0x30) return fail("tbsCertificate is not a DER SEQUENCE");

  // Walk tbsCertificate's children in order, stepping to each next sibling, to reach subjectPublicKeyInfo.
  let pos = tbs.contentStart;
  const tbsEnd = tbs.end;

  // [0] EXPLICIT version OPTIONAL: a context-specific constructed tag 0xA0. Present in v2/v3 certs (almost all
  // real certs); absent in v1. Skip it only when present.
  const verOrSerial = readTlv(der, pos);
  if (verOrSerial === null || verOrSerial.end > tbsEnd) return fail("malformed tbsCertificate (version/serial)");
  if (verOrSerial.tag === 0xa0) {
    pos = verOrSerial.end; // skip the explicit version wrapper
  }
  // serialNumber ::= INTEGER (whether or not a version preceded it, the serial is next).
  const serial = readTlv(der, pos);
  if (serial === null || serial.tag !== 0x02 || serial.end > tbsEnd) return fail("malformed tbsCertificate (serialNumber)");
  pos = serial.end;

  // signature ::= SEQUENCE (AlgorithmIdentifier)
  const sigAlg = readTlv(der, pos);
  if (sigAlg === null || sigAlg.tag !== 0x30 || sigAlg.end > tbsEnd) return fail("malformed tbsCertificate (signature alg)");
  pos = sigAlg.end;

  // issuer ::= SEQUENCE (Name)
  const issuer = readTlv(der, pos);
  if (issuer === null || issuer.tag !== 0x30 || issuer.end > tbsEnd) return fail("malformed tbsCertificate (issuer)");
  pos = issuer.end;

  // validity ::= SEQUENCE
  const validity = readTlv(der, pos);
  if (validity === null || validity.tag !== 0x30 || validity.end > tbsEnd) return fail("malformed tbsCertificate (validity)");
  pos = validity.end;

  // subject ::= SEQUENCE (Name)
  const subject = readTlv(der, pos);
  if (subject === null || subject.tag !== 0x30 || subject.end > tbsEnd) return fail("malformed tbsCertificate (subject)");
  pos = subject.end;

  // subjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey } - the NEXT element. Return its FULL TLV
  // bytes (tag + length + value), which is exactly the SPKI DER importKey('spki', ...) wants. The TLV begins at
  // `pos` (its tag byte) and runs to spki.end, so the slice [pos, spki.end) is the complete SPKI - header and
  // content together - by construction.
  const spki = readTlv(der, pos);
  if (spki === null || spki.tag !== 0x30 || spki.end > tbsEnd) return fail("malformed tbsCertificate (subjectPublicKeyInfo)");
  return { ok: true, spki: der.slice(pos, spki.end) };
}

// certNotAfter parses an X.509 certificate PEM and returns its notAfter expiry as epoch milliseconds, or
// null on ANY malformedness (fail-open: a credential whose expiry cannot be read is simply not
// auto-observed, never surfaced as a false expiry). It reads only the notAfter bound from the shared
// parseCertValidity DER walk, so a cert whose notBefore is unreadable or out of order is also null. The
// certificate is PUBLIC data (an IdP signing cert pinned on a connection), so this reads no secret. The
// CALLER takes the MAX notAfter across a connection's rollover certs (so the registry reflects "SSO still
// works until the last cert lapses"); this function returns one cert's notAfter. Used by the credential
// lifecycle registry to auto-OBSERVE a SAML signing cert's expiry from an artefact the engine already holds.
export function certNotAfter(pem: string): number | null {
  return parseCertValidity(pem)?.notAfter ?? null;
}

// CertValidity is a pinned signing cert's notBefore..notAfter window as epoch milliseconds, used by the
// verify path (dsig.ts) to REJECT a signature made under a cert outside its validity window (IDP-4). It is
// distinct from certNotAfter (which the lifecycle registry uses for a single MAX-notAfter expiry display):
// the verify-time check needs BOTH bounds, on the SAME cert that verified the signature.
export interface CertValidity {
  notBefore: number;
  notAfter: number;
}

// certValidity parses an X.509 certificate PEM and returns BOTH its notBefore and notAfter as epoch
// milliseconds, or null on ANY malformedness. It walks the SAME bounded DER path as certNotAfter
// (Certificate -> tbsCertificate -> (optional [0] version) -> serialNumber -> signature -> issuer ->
// validity) and decodes validity's two child Time TLVs. The certificate is PUBLIC (an IdP signing cert
// pinned on a connection), so this reads no secret. Returning null (a cert whose window cannot be read) is
// treated by the verify path as "do not enforce a window for this cert" (fail-OPEN on the window only):
// the SIGNATURE itself is the primary trust gate; the validity window is a defence-in-depth freshness check
// layered on top, and an unreadable window must not turn a cryptographically-valid signature into a reject
// (which could lock out a working IdP over a DER-encoding quirk). The notBefore/notAfter ORDERING is also
// asserted (a cert with notBefore > notAfter is malformed -> null).
export function certValidity(pem: string): CertValidity | null {
  return parseCertValidity(pem);
}

// parseCertValidity is the single bounded DER walk that both certNotAfter and certValidity share. It
// descends Certificate -> tbsCertificate -> (optional [0] version) -> serialNumber -> signature -> issuer
// -> validity, then decodes validity's two child Time TLVs (notBefore, notAfter). It returns both bounds
// or null on ANY malformedness (including an unreadable Time, or a notBefore that is after its notAfter).
// certNotAfter reads only the notAfter from this result; certValidity returns the whole window. Keeping
// the walk in one place removes the duplication (and the divergence risk) on this security-critical parse.
function parseCertValidity(pem: string): CertValidity | null {
  const body = stripPemBase64(pem);
  if (body === null) return null;
  const decoded = decodeBase64Std(body);
  if (!decoded.ok) return null;
  const der = decoded.bytes;

  const cert = readTlv(der, 0);
  if (cert === null || cert.tag !== 0x30) return null;
  const tbs = readTlv(der, cert.contentStart);
  if (tbs === null || tbs.tag !== 0x30) return null;
  const tbsEnd = tbs.end;
  let pos = tbs.contentStart;

  // [0] EXPLICIT version OPTIONAL (context-specific constructed tag 0xA0); present in v2/v3, absent in v1.
  const verOrSerial = readTlv(der, pos);
  if (verOrSerial === null || verOrSerial.end > tbsEnd) return null;
  if (verOrSerial.tag === 0xa0) pos = verOrSerial.end;
  // serialNumber INTEGER
  const serial = readTlv(der, pos);
  if (serial === null || serial.tag !== 0x02 || serial.end > tbsEnd) return null;
  pos = serial.end;
  // signature AlgorithmIdentifier SEQUENCE
  const sigAlg = readTlv(der, pos);
  if (sigAlg === null || sigAlg.tag !== 0x30 || sigAlg.end > tbsEnd) return null;
  pos = sigAlg.end;
  // issuer Name SEQUENCE
  const issuer = readTlv(der, pos);
  if (issuer === null || issuer.tag !== 0x30 || issuer.end > tbsEnd) return null;
  pos = issuer.end;
  // validity ::= SEQUENCE { notBefore Time, notAfter Time }
  const validity = readTlv(der, pos);
  if (validity === null || validity.tag !== 0x30 || validity.end > tbsEnd) return null;

  const nbTlv = readTlv(der, validity.contentStart);
  if (nbTlv === null || nbTlv.end > validity.end) return null;
  const naTlv = readTlv(der, nbTlv.end);
  if (naTlv === null || naTlv.end > validity.end) return null;
  const notBefore = decodeDerTime(der, nbTlv);
  const notAfter = decodeDerTime(der, naTlv);
  if (notBefore === null || notAfter === null) return null;
  if (notBefore > notAfter) return null; // a malformed window (begins after it ends) is not enforceable
  return { notBefore, notAfter };
}

// decodeDerTime decodes a DER UTCTime (tag 0x17) or GeneralizedTime (tag 0x18) TLV to epoch
// milliseconds, or null on malformedness (fail-open). RFC 5280 requires UTC ("Z") and these forms:
// UTCTime YYMMDDHHMMSSZ (seconds mandatory in X.509; the no-seconds YYMMDDHHMMZ is tolerated);
// GeneralizedTime YYYYMMDDHHMMSSZ (no-seconds tolerated). The UTCTime two-digit-year pivot is RFC
// 5280's: 00..49 -> 20xx, 50..99 -> 19xx (so a 2050+ expiry is encoded as GeneralizedTime, never a
// wrapped UTCTime). Any non-ASCII byte, a missing trailing Z, the wrong digit count, or an out-of-range
// field is rejected as null.
function decodeDerTime(der: Uint8Array, t: Tlv): number | null {
  if (t.tag !== 0x17 && t.tag !== 0x18) return null;
  let s = "";
  for (let i = t.contentStart; i < t.end; i++) {
    const b = der[i]!;
    if (b < 0x20 || b > 0x7e) return null; // printable ASCII only
    s += String.fromCharCode(b);
  }
  if (!s.endsWith("Z")) return null; // X.509 mandates the UTC ("Z") form
  const core = s.slice(0, -1);
  let year: number;
  let rest: string; // MM DD HH MM [SS]
  if (t.tag === 0x17) {
    if (!/^\d{10}(\d{2})?$/.test(core)) return null; // YYMMDDHHMM[SS]
    const yy = Number(core.slice(0, 2));
    year = yy <= 49 ? 2000 + yy : 1900 + yy;
    rest = core.slice(2);
  } else {
    if (!/^\d{12}(\d{2})?$/.test(core)) return null; // YYYYMMDDHHMM[SS]
    year = Number(core.slice(0, 4));
    rest = core.slice(4);
  }
  const mo = Number(rest.slice(0, 2));
  const day = Number(rest.slice(2, 4));
  const hh = Number(rest.slice(4, 6));
  const mi = Number(rest.slice(6, 8));
  const ss = rest.length >= 10 ? Number(rest.slice(8, 10)) : 0;
  if (mo < 1 || mo > 12 || day < 1 || day > 31 || hh > 23 || mi > 59 || ss > 60) return null;
  const ms = Date.UTC(year, mo - 1, day, hh, mi, ss);
  return Number.isFinite(ms) ? ms : null;
}
