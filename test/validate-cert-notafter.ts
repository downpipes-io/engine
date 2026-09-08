// Prove certNotAfter (engine/src/admin/saml/response.ts): the X.509 notAfter parser the credential
// lifecycle registry uses to AUTO-OBSERVE a SAML IdP signing cert's expiry from an artefact the engine
// already holds (the public PEM pinned on the connection). In-memory only; no network, no crypto keys.
//   node test/validate-cert-notafter.ts
//
// We build minimal-but-valid DER certificates with a tiny encoder so the test controls the EXACT bytes
// of the validity SEQUENCE: UTCTime (tag 0x17, two-digit year, the RFC 5280 pivot 00..49 -> 20xx /
// 50..99 -> 19xx) and GeneralizedTime (tag 0x18, four-digit year, used for >= 2050). certNotAfter only
// walks Certificate -> tbsCertificate -> [version] -> serial -> sigAlg -> issuer -> validity, so the
// synthetic cert needs nothing past validity; this isolates the time-decoding logic. The MAX-across-
// rollover-certs rule is the CALLER's (it takes Math.max over a connection's certs), exercised here too.

import { certNotAfter, certValidity, pemToSpki, decodeBase64Std } from "../src/admin/saml/response-cert.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- minimal DER encoder ----------------------------------------------------------------------
// derLen encodes a content length in DER (short form < 128, else long form: 0x80|n then n big-endian bytes).
function derLen(n: number): number[] {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  let x = n;
  while (x > 0) {
    bytes.unshift(x & 0xff);
    x = Math.floor(x / 256);
  }
  return [0x80 | bytes.length, ...bytes];
}
// tlv builds one TLV: tag + length + content.
function tlv(tag: number, content: number[]): number[] {
  return [tag, ...derLen(content.length), ...content];
}
function ascii(s: string): number[] {
  return Array.from(s).map((c) => c.charCodeAt(0));
}
const utcTime = (s: string): number[] => tlv(0x17, ascii(s)); // e.g. "491231235959Z"
const genTime = (s: string): number[] => tlv(0x18, ascii(s)); // e.g. "20500101000000Z"

// buildCert assembles a minimal cert DER from a notBefore + notAfter Time TLV and returns it as a PEM.
// opts.withVersion adds the [0] EXPLICIT version wrapper (v3) so we prove the optional-version skip.
function buildCert(notBefore: number[], notAfter: number[], opts?: { withVersion?: boolean }): string {
  const serial = tlv(0x02, [0x01]);
  const sigAlg = tlv(0x30, []); // empty AlgorithmIdentifier; certNotAfter only checks the tag/bounds
  const issuer = tlv(0x30, []); // empty Name
  const validity = tlv(0x30, [...notBefore, ...notAfter]);
  const version = opts?.withVersion ? tlv(0xa0, tlv(0x02, [0x02])) : []; // [0] { INTEGER 2 }
  const tbs = tlv(0x30, [...version, ...serial, ...sigAlg, ...issuer, ...validity]);
  const cert = tlv(0x30, tbs);
  return toPem(Buffer.from(cert).toString("base64"));
}
function toPem(b64: string): string {
  const wrapped = b64.replace(/(.{64})/g, "$1\n");
  return `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----\n`;
}

// buildSpki returns a structurally valid SubjectPublicKeyInfo TLV (a SEQUENCE of an AlgorithmIdentifier
// SEQUENCE and a BIT STRING). pemToSpki only checks the SPKI tag and bounds, not the inner key, so a
// shape-correct SPKI is enough to drive the success path and to be byte-compared against the slice the
// walker returns. The opts.bigKey form pads the BIT STRING past 127 bytes so the SPKI's own length uses
// the DER long form, which exercises readTlv's multi-byte length decode.
function buildSpki(opts?: { bigKey?: boolean }): number[] {
  const algId = tlv(0x30, [...tlv(0x06, [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]), ...tlv(0x05, [])]);
  const keyBytes = opts?.bigKey ? new Array(200).fill(0xab) : [0xde, 0xad, 0xbe, 0xef];
  const bitString = tlv(0x03, [0x00, ...keyBytes]); // leading 0x00 = no unused bits
  return tlv(0x30, [...algId, ...bitString]);
}

// buildFullCert assembles a cert DER that reaches subjectPublicKeyInfo, so pemToSpki and certValidity have
// a complete tbsCertificate to walk (subject then SPKI follow validity). opts.withVersion adds the [0]
// EXPLICIT version wrapper; opts.bigKey makes the SPKI use a long-form length. Returns the PEM and the exact
// SPKI bytes embedded, so a caller can assert pemToSpki returns precisely those bytes.
function buildFullCert(
  notBefore: number[],
  notAfter: number[],
  opts?: { withVersion?: boolean; bigKey?: boolean },
): { pem: string; spki: Uint8Array } {
  const serial = tlv(0x02, [0x01]);
  const sigAlg = tlv(0x30, []);
  const issuer = tlv(0x30, []);
  const validity = tlv(0x30, [...notBefore, ...notAfter]);
  const subject = tlv(0x30, []);
  // Pass bigKey only when set: buildSpki's bigKey is optional and exactOptionalPropertyTypes rejects an
  // explicit undefined.
  const spki = buildSpki(opts?.bigKey !== undefined ? { bigKey: opts.bigKey } : {});
  const version = opts?.withVersion ? tlv(0xa0, tlv(0x02, [0x02])) : [];
  const tbs = tlv(0x30, [...version, ...serial, ...sigAlg, ...issuer, ...validity, ...subject, ...spki]);
  const cert = tlv(0x30, tbs);
  return { pem: toPem(Buffer.from(cert).toString("base64")), spki: new Uint8Array(spki) };
}

// bytesEqual compares two byte arrays for the SPKI round-trip assertion (the order does not matter here as
// both come from the same in-memory cert; a plain length-then-element compare is enough for a test double).
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// tlvDeclared builds a TLV whose declared length is forced to `declaredLen` while its real content is
// `content`. When declaredLen is shorter than the content, the wrapper's end falls INSIDE later content; a
// reader that bounds each child against the whole buffer (as readTlv does) will read the child fine but find
// child.end > parent.end, which is exactly the overrun arm of each guard (child.end > tbsEnd / validity.end).
// We keep declaredLen short form (< 128) for these vectors, which is all the cases need.
function tlvDeclared(tag: number, content: number[], declaredLen: number): number[] {
  return [tag, declaredLen, ...content];
}

// pemFromDer wraps raw DER bytes as a PEM certificate string.
function pemFromDer(der: number[]): string {
  return toPem(Buffer.from(der).toString("base64"));
}

// tbsChildren returns the ordered child bytes of a tbsCertificate up to and including validity, so a test can
// wrap them in a tbs SEQUENCE with a deliberately short declared length to force a chosen child to overrun.
function tbsChildren(): { serial: number[]; sigAlg: number[]; issuer: number[]; validity: number[] } {
  return {
    serial: tlv(0x02, [0x01]),
    sigAlg: tlv(0x30, []),
    issuer: tlv(0x30, []),
    validity: tlv(0x30, [...utcTime("200101000000Z"), ...utcTime("300101000000Z")]),
  };
}

function main(): void {
  // ---- UTCTime, with the RFC 5280 two-digit-year pivot ----------------------------------------
  {
    // notBefore, notAfter -> UTCTime year "49" pivots to 2049.
    const pem = buildCert(utcTime("200101000000Z"), utcTime("491231235959Z"));
    ok("UTCTime: notAfter '49' -> 2049-12-31T23:59:59Z", certNotAfter(pem) === Date.UTC(2049, 11, 31, 23, 59, 59));
  }
  {
    // notAfter "50..." pivots to 1950 (the low end of the pivot; proves 50..99 -> 19xx). notBefore is the
    // same 1950 instant so the window is well-ordered (certNotAfter now shares the ordered-window parser).
    const pem = buildCert(utcTime("500101000000Z"), utcTime("500101000000Z"));
    ok("UTCTime: notAfter '50' -> 1950-01-01T00:00:00Z (pivot 50->19xx)", certNotAfter(pem) === Date.UTC(1950, 0, 1, 0, 0, 0));
  }
  {
    // The pivot boundary the other way: "49" is the highest 20xx year.
    const pem = buildCert(utcTime("000101000000Z"), utcTime("491231000000Z"));
    ok("UTCTime: pivot boundary '49' is 2049 (not 1949)", certNotAfter(pem) === Date.UTC(2049, 11, 31, 0, 0, 0));
  }
  {
    // UTCTime without seconds (YYMMDDHHMMZ) is tolerated -> seconds default to 0.
    const pem = buildCert(utcTime("2001010000Z"), utcTime("3012312359Z"));
    ok("UTCTime: no-seconds form tolerated (seconds=0)", certNotAfter(pem) === Date.UTC(2030, 11, 31, 23, 59, 0));
  }

  // ---- GeneralizedTime, for >= 2050 -----------------------------------------------------------
  {
    const pem = buildCert(genTime("20300101000000Z"), genTime("20500101000000Z"));
    ok("GeneralizedTime: notAfter 2050-01-01T00:00:00Z", certNotAfter(pem) === Date.UTC(2050, 0, 1, 0, 0, 0));
  }
  {
    // A long-lived cert (Okta's 10-year default lands beyond 2050 from now): year 2099.
    const pem = buildCert(genTime("20500101000000Z"), genTime("20991231235959Z"));
    ok("GeneralizedTime: far-future 2099 parses", certNotAfter(pem) === Date.UTC(2099, 11, 31, 23, 59, 59));
  }

  // ---- the optional [0] version wrapper is skipped --------------------------------------------
  {
    const pem = buildCert(utcTime("200101000000Z"), utcTime("351231235959Z"), { withVersion: true });
    ok("v3 cert: the [0] EXPLICIT version wrapper is skipped", certNotAfter(pem) === Date.UTC(2035, 11, 31, 23, 59, 59));
  }

  // ---- MAX across rollover certs (the CALLER's rule) -----------------------------------------
  {
    const older = buildCert(utcTime("200101000000Z"), utcTime("260101000000Z")); // 2026
    const newer = buildCert(utcTime("250101000000Z"), utcTime("290101000000Z")); // 2029
    const certs = [older, newer];
    const nums = certs.map((c) => certNotAfter(c)).filter((n): n is number => n !== null);
    const max = Math.max(...nums);
    ok("MAX across certs: the later notAfter (2029) wins", max === Date.UTC(2029, 0, 1, 0, 0, 0));
    ok("MAX across certs: both certs parsed (no null)", nums.length === 2);
  }

  // ---- malformedness -> null (fail-open, never a false expiry) --------------------------------
  {
    ok("malformed: not a PEM -> null", certNotAfter("not a certificate") === null);
    ok("malformed: empty string -> null", certNotAfter("") === null);
    ok("malformed: PEM armour but garbled base64 -> null", certNotAfter("-----BEGIN CERTIFICATE-----\n@@@not base64@@@\n-----END CERTIFICATE-----\n") === null);
    // A valid base64 of non-DER bytes (random) -> the SEQUENCE walk fails -> null.
    ok("malformed: valid base64 but not DER -> null", certNotAfter(toPem(Buffer.from([1, 2, 3, 4, 5]).toString("base64"))) === null);
    // validity present but notAfter is NOT a Time tag (a SEQUENCE instead) -> null.
    {
      const badValidity = tlv(0x30, [...utcTime("200101000000Z"), ...tlv(0x30, [])]);
      const tbs = tlv(0x30, [...tlv(0x02, [0x01]), ...tlv(0x30, []), ...tlv(0x30, []), ...badValidity]);
      const pem = toPem(Buffer.from(tlv(0x30, tbs)).toString("base64"));
      ok("malformed: notAfter is not a Time tag -> null", certNotAfter(pem) === null);
    }
    // UTCTime with non-digit content -> null.
    {
      const pem = buildCert(utcTime("200101000000Z"), utcTime("XX1231235959Z"));
      ok("malformed: UTCTime with non-digit year -> null", certNotAfter(pem) === null);
    }
    // A Time without the trailing Z (local time) -> rejected (X.509 mandates UTC).
    {
      const pem = buildCert(utcTime("200101000000Z"), utcTime("301231235959"));
      ok("malformed: Time without trailing Z -> null", certNotAfter(pem) === null);
    }
    // Out-of-range month (13) -> null.
    {
      const pem = buildCert(utcTime("200101000000Z"), utcTime("301331235959Z"));
      ok("malformed: month 13 -> null", certNotAfter(pem) === null);
    }
  }

  // ---- pemToSpki: the PEM -> SubjectPublicKeyInfo bridge --------------------------------------
  // pemToSpki walks the same Certificate -> tbsCertificate path as certNotAfter but continues past
  // validity to subject and then returns the subjectPublicKeyInfo TLV. These cover its success path, its
  // long-form-length variant, and each structural fail() branch.
  {
    const { pem, spki } = buildFullCert(utcTime("200101000000Z"), utcTime("300101000000Z"));
    const r = pemToSpki(pem);
    ok("pemToSpki: extracts the exact SPKI TLV from a complete cert", r.ok === true && r.ok && bytesEqual(r.spki, spki));
  }
  {
    // A v3 cert with the [0] version wrapper present: pemToSpki must skip it and still land on the SPKI.
    const { pem, spki } = buildFullCert(utcTime("200101000000Z"), utcTime("300101000000Z"), { withVersion: true });
    const r = pemToSpki(pem);
    ok("pemToSpki: skips the [0] version wrapper and returns the SPKI", r.ok === true && r.ok && bytesEqual(r.spki, spki));
  }
  {
    // A SPKI large enough that its TLV length uses the DER long form, driving readTlv's multi-byte length
    // decode (the long-form path certNotAfter alone never reaches).
    const { pem, spki } = buildFullCert(utcTime("200101000000Z"), utcTime("300101000000Z"), { bigKey: true });
    const r = pemToSpki(pem);
    ok("pemToSpki: handles a SPKI whose length is DER long form", r.ok === true && r.ok && bytesEqual(r.spki, spki) && spki.length > 0x80);
  }
  {
    // No PEM armour at all -> the "not a CERTIFICATE block" fail() branch.
    const r = pemToSpki("nothing here");
    ok("pemToSpki: no PEM armour -> fail with the armour reason", r.ok === false && !r.ok && r.reason.includes("BEGIN CERTIFICATE"));
  }
  {
    // Armour present but the body is not valid base64 -> the "not valid base64" fail() branch.
    const r = pemToSpki("-----BEGIN CERTIFICATE-----\n@@@\n-----END CERTIFICATE-----\n");
    ok("pemToSpki: armour with non-base64 body -> fail with the base64 reason", r.ok === false && !r.ok && r.reason.includes("base64"));
  }
  {
    // Valid base64 of bytes that are not a SEQUENCE -> the outer "not a DER SEQUENCE" fail() branch.
    const r = pemToSpki(toPem(Buffer.from([0x02, 0x01, 0x01]).toString("base64")));
    ok("pemToSpki: not an outer SEQUENCE -> fail", r.ok === false && !r.ok && r.reason.includes("DER SEQUENCE"));
  }
  {
    // Outer SEQUENCE whose first child is not a SEQUENCE -> the "tbsCertificate is not a SEQUENCE" branch.
    const der = tlv(0x30, tlv(0x02, [0x01])); // SEQUENCE { INTEGER } - tbs is an INTEGER, not a SEQUENCE
    const r = pemToSpki(toPem(Buffer.from(der).toString("base64")));
    ok("pemToSpki: tbs not a SEQUENCE -> fail", r.ok === false && !r.ok && r.reason.includes("tbsCertificate"));
  }
  {
    // A tbs whose serial is missing (the element after the optional version is a SEQUENCE, not an INTEGER)
    // -> the "serialNumber" fail() branch.
    const tbs = tlv(0x30, tlv(0x30, [])); // first child is a SEQUENCE where a serial INTEGER is required
    const der = tlv(0x30, tbs);
    const r = pemToSpki(toPem(Buffer.from(der).toString("base64")));
    ok("pemToSpki: serial not an INTEGER -> fail", r.ok === false && !r.ok && r.reason.includes("serialNumber"));
  }
  {
    // tbs with a valid serial but the signature AlgorithmIdentifier is the wrong tag -> the "signature alg"
    // fail() branch.
    const tbs = tlv(0x30, [...tlv(0x02, [0x01]), ...tlv(0x02, [0x02])]); // serial OK, then INTEGER not SEQUENCE
    const der = tlv(0x30, tbs);
    const r = pemToSpki(toPem(Buffer.from(der).toString("base64")));
    ok("pemToSpki: signature alg not a SEQUENCE -> fail", r.ok === false && !r.ok && r.reason.includes("signature alg"));
  }
  {
    // Through signature alg but issuer is the wrong tag -> the "issuer" fail() branch.
    const tbs = tlv(0x30, [...tlv(0x02, [0x01]), ...tlv(0x30, []), ...tlv(0x02, [0x02])]);
    const der = tlv(0x30, tbs);
    const r = pemToSpki(toPem(Buffer.from(der).toString("base64")));
    ok("pemToSpki: issuer not a SEQUENCE -> fail", r.ok === false && !r.ok && r.reason.includes("issuer"));
  }
  {
    // Through issuer but validity is the wrong tag -> the "validity" fail() branch.
    const tbs = tlv(0x30, [...tlv(0x02, [0x01]), ...tlv(0x30, []), ...tlv(0x30, []), ...tlv(0x02, [0x02])]);
    const der = tlv(0x30, tbs);
    const r = pemToSpki(toPem(Buffer.from(der).toString("base64")));
    ok("pemToSpki: validity not a SEQUENCE -> fail", r.ok === false && !r.ok && r.reason.includes("validity"));
  }
  {
    // Through validity but subject is the wrong tag -> the "subject" fail() branch.
    const validity = tlv(0x30, [...utcTime("200101000000Z"), ...utcTime("300101000000Z")]);
    const tbs = tlv(0x30, [...tlv(0x02, [0x01]), ...tlv(0x30, []), ...tlv(0x30, []), ...validity, ...tlv(0x02, [0x02])]);
    const der = tlv(0x30, tbs);
    const r = pemToSpki(toPem(Buffer.from(der).toString("base64")));
    ok("pemToSpki: subject not a SEQUENCE -> fail", r.ok === false && !r.ok && r.reason.includes("subject"));
  }
  {
    // Through subject but the subjectPublicKeyInfo element is the wrong tag -> the SPKI fail() branch.
    const validity = tlv(0x30, [...utcTime("200101000000Z"), ...utcTime("300101000000Z")]);
    const tbs = tlv(0x30, [
      ...tlv(0x02, [0x01]),
      ...tlv(0x30, []),
      ...tlv(0x30, []),
      ...validity,
      ...tlv(0x30, []),
      ...tlv(0x02, [0x02]), // an INTEGER where the SPKI SEQUENCE belongs
    ]);
    const der = tlv(0x30, tbs);
    const r = pemToSpki(toPem(Buffer.from(der).toString("base64")));
    ok("pemToSpki: SPKI not a SEQUENCE -> fail", r.ok === false && !r.ok && r.reason.includes("subjectPublicKeyInfo"));
  }

  // ---- certValidity: BOTH bounds, with the notBefore <= notAfter ordering check ---------------
  // certValidity returns the notBefore..notAfter window the verify path (IDP-4) uses, or null on any
  // malformedness. The ordering guard (a window that begins after it ends) is unique to this function.
  {
    const { pem } = buildFullCert(utcTime("200101000000Z"), utcTime("300101120000Z"));
    const w = certValidity(pem);
    ok(
      "certValidity: returns the notBefore and notAfter window",
      w !== null && w.notBefore === Date.UTC(2020, 0, 1, 0, 0, 0) && w.notAfter === Date.UTC(2030, 0, 1, 12, 0, 0),
    );
  }
  {
    // A GeneralizedTime window for a far-future cert is parsed on both bounds.
    const { pem } = buildFullCert(genTime("20500101000000Z"), genTime("20600101000000Z"));
    const w = certValidity(pem);
    ok(
      "certValidity: GeneralizedTime window on both bounds",
      w !== null && w.notBefore === Date.UTC(2050, 0, 1, 0, 0, 0) && w.notAfter === Date.UTC(2060, 0, 1, 0, 0, 0),
    );
  }
  {
    // notBefore strictly after notAfter -> the ordering guard rejects it as null.
    const { pem } = buildFullCert(utcTime("300101000000Z"), utcTime("200101000000Z"));
    ok("certValidity: notBefore after notAfter -> null (ordering guard)", certValidity(pem) === null);
  }
  {
    // Not a PEM at all -> null at the stripPemBase64 gate.
    ok("certValidity: not a PEM -> null", certValidity("not a cert") === null);
  }
  {
    // Armour with a non-base64 body -> null at the decode gate.
    ok("certValidity: armour with garbled base64 -> null", certValidity("-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n") === null);
  }
  {
    // Valid base64 but not an outer SEQUENCE -> null.
    ok("certValidity: not a DER SEQUENCE -> null", certValidity(toPem(Buffer.from([0x02, 0x01, 0x01]).toString("base64"))) === null);
  }
  {
    // A notAfter that is not a Time tag inside an otherwise valid window -> decodeDerTime returns null.
    const validity = tlv(0x30, [...utcTime("200101000000Z"), ...tlv(0x30, [])]);
    const tbs = tlv(0x30, [
      ...tlv(0x02, [0x01]),
      ...tlv(0x30, []),
      ...tlv(0x30, []),
      ...validity,
      ...tlv(0x30, []),
      ...buildSpki(),
    ]);
    const der = tlv(0x30, tbs);
    ok("certValidity: notAfter not a Time tag -> null", certValidity(toPem(Buffer.from(der).toString("base64"))) === null);
  }

  // ---- decodeBase64Std: the standard-base64 (not base64url) decoder ----------------------------
  // The SAMLResponse POST value is standard base64; this decoder strips transport whitespace then accepts
  // only the standard alphabet with correct padding, and rejects non-canonical trailing bits. These vectors
  // drive the empty, length, padding, alphabet and trailing-bit branches directly.
  {
    const r = decodeBase64Std("TWE="); // "Ma"
    ok("decodeBase64Std: decodes a one-pad value", r.ok === true && r.ok && r.bytes.length === 2 && r.bytes[0] === 0x4d && r.bytes[1] === 0x61);
  }
  {
    // Embedded whitespace (space, tab, CR, LF) is stripped before decoding.
    const r = decodeBase64Std("VG Vz\td\nGNhc2U=");
    ok("decodeBase64Std: strips transport whitespace then decodes", r.ok === true && r.ok && Buffer.from(r.bytes).toString() === "Testcase");
  }
  {
    // Whitespace-only input collapses to empty -> the length === 0 reject (a branch the PEM callers never
    // reach because stripPemBase64 fails first on non-armour).
    ok("decodeBase64Std: whitespace-only -> reject (empty after strip)", decodeBase64Std("  \t\r\n").ok === false);
  }
  {
    // Length not a multiple of four -> reject.
    ok("decodeBase64Std: length not a multiple of 4 -> reject", decodeBase64Std("TWFlb").ok === false);
  }
  {
    // More than two padding characters -> reject (at most two '=' at the very end).
    ok("decodeBase64Std: more than two pad chars -> reject", decodeBase64Std("TW======").ok === false);
  }
  {
    // A character outside the standard alphabet (here '-', which is base64url) -> reject.
    ok("decodeBase64Std: out-of-alphabet character -> reject", decodeBase64Std("TW-l").ok === false);
  }
  {
    // A non-ASCII (>= 128) character takes the code-point guard's other arm and is rejected.
    ok("decodeBase64Std: non-ASCII character -> reject", decodeBase64Std("TWÿl").ok === false);
  }
  {
    // Non-canonical trailing bits: "TX==" decodes one byte but the last base64 digit carries low bits that
    // are not zero, so the strict trailing-bit check rejects it (two strings must not decode to one value).
    ok("decodeBase64Std: non-canonical trailing bits -> reject", decodeBase64Std("TX==").ok === false);
  }

  // ---- readTlv and decodeDerTime: remaining structural and range branches ---------------------
  {
    // Indefinite-length form (0x80) is BER, forbidden in DER -> the whole walk rejects. We put it as the
    // outer SEQUENCE's length so readTlv hits the 0x80 arm at the very first read.
    const der = [0x30, 0x80, 0x00, 0x00];
    ok("readTlv: indefinite-length (0x80) -> reject", certNotAfter(toPem(Buffer.from(der).toString("base64"))) === null);
  }
  {
    // A truncated buffer (a tag with no length byte) -> the pos + 2 > length guard rejects.
    const der = [0x30];
    ok("readTlv: truncated (no length byte) -> reject", certNotAfter(toPem(Buffer.from(der).toString("base64"))) === null);
  }
  {
    // A declared length that runs past the end of the buffer -> the end > der.length bound rejects.
    const der = [0x30, 0x05, 0x00]; // says 5 content bytes but only 1 follows
    ok("readTlv: length past end of buffer -> reject", certNotAfter(toPem(Buffer.from(der).toString("base64"))) === null);
  }
  {
    // GeneralizedTime whose digits do not match the expected pattern (a letter in the year) -> null.
    const { pem } = buildFullCert(genTime("20500101000000Z"), genTime("2X600101000000Z"));
    ok("decodeDerTime: GeneralizedTime with a non-digit -> null", certValidity(pem) === null);
  }
  {
    // A Time byte outside printable ASCII (a high byte 0xff in the content) -> the b > 0x7e guard rejects.
    const badTime = tlv(0x17, [...ascii("2001010000"), 0xff, 0x5a]); // ...then 0xff then 'Z'
    const { pem } = buildFullCert(utcTime("200101000000Z"), badTime);
    ok("decodeDerTime: non-printable byte in Time -> null", certNotAfter(pem) === null);
  }
  {
    // Out-of-range day (00) -> null (day < 1).
    const pem = buildCert(utcTime("200101000000Z"), utcTime("301200235959Z"));
    ok("decodeDerTime: day 00 -> null", certNotAfter(pem) === null);
  }
  {
    // Out-of-range hour (24) -> null (hh > 23).
    const pem = buildCert(utcTime("200101000000Z"), utcTime("301231245959Z"));
    ok("decodeDerTime: hour 24 -> null", certNotAfter(pem) === null);
  }
  {
    // Out-of-range minute (60) -> null (mi > 59).
    const pem = buildCert(utcTime("200101000000Z"), utcTime("301231236059Z"));
    ok("decodeDerTime: minute 60 -> null", certNotAfter(pem) === null);
  }
  {
    // A leap second (ss = 60) is the boundary the guard allows (ss > 60 rejects, ss == 60 is fine).
    const pem = buildCert(utcTime("200101000000Z"), utcTime("301231235960Z"));
    ok("decodeDerTime: leap second ss=60 is accepted", certNotAfter(pem) === Date.UTC(2030, 11, 31, 23, 59, 60));
  }

  // ---- the tbsCertificate child-bounds (overrun) arms ----------------------------------------
  // Each child guard in certNotAfter / certValidity is `child === null || ... || child.end > parentEnd`.
  // readTlv bounds a child against the WHOLE buffer, so a tbs (or validity) SEQUENCE that under-declares its
  // own length lets a child read cleanly yet end past the parent's end. forcedCert wraps the children in a
  // tbs whose declared length is forced short while the cert SEQUENCE still spans every physical byte, which
  // drives the `child.end > tbsEnd` (and `child.end > validity.end`) arm of each guard in turn.
  function forcedCert(children: number[], declaredTbsLen: number): string {
    const tbs = [0x30, declaredTbsLen, ...children];
    const cert = [0x30, ...derLen(tbs.length), ...tbs];
    return pemFromDer(cert);
  }
  const c = tbsChildren();
  const version = tlv(0xa0, tlv(0x02, [0x02])); // [0] { INTEGER 2 }

  {
    // tbs SEQUENCE header present but its content runs past the buffer -> tbs itself is unreadable (null).
    const der = [0x30, 0x02, 0x30, 0x02]; // cert holds only a tbs header claiming 2 bytes that do not follow
    ok("certNotAfter: tbs unreadable -> null", certNotAfter(pemFromDer(der)) === null);
    ok("certValidity: tbs unreadable -> null", certValidity(pemFromDer(der)) === null);
  }
  {
    // The first tbs child is unreadable (an INTEGER claiming more bytes than the buffer holds) -> the
    // verOrSerial === null arm.
    const pem = forcedCert([0x02, 0x05], 2);
    ok("certNotAfter: first child unreadable -> null", certNotAfter(pem) === null);
    ok("certValidity: first child unreadable -> null", certValidity(pem) === null);
  }
  {
    // No version, so verOrSerial is the serial; force tbsEnd inside it -> the verOrSerial.end > tbsEnd arm.
    const pem = forcedCert([...c.serial], 2);
    ok("certNotAfter: serial overruns tbs (no version) -> null", certNotAfter(pem) === null);
    ok("certValidity: serial overruns tbs (no version) -> null", certValidity(pem) === null);
    ok("pemToSpki: serial overruns tbs (no version) -> fail", (() => { const r = pemToSpki(pem); return r.ok === false && !r.ok && r.reason.includes("version/serial"); })());
  }
  {
    // Version present (so verOrSerial fits), then the serial overruns -> the serial.end > tbsEnd arm.
    const pem = forcedCert([...version, ...c.serial], version.length + 2);
    ok("certNotAfter: serial overruns tbs (after version) -> null", certNotAfter(pem) === null);
    ok("certValidity: serial overruns tbs (after version) -> null", certValidity(pem) === null);
  }
  {
    // Serial fits, signature alg overruns -> the sigAlg.end > tbsEnd arm.
    const pem = forcedCert([...c.serial, ...c.sigAlg], c.serial.length + 1);
    ok("certNotAfter: signature alg overruns tbs -> null", certNotAfter(pem) === null);
    ok("certValidity: signature alg overruns tbs -> null", certValidity(pem) === null);
  }
  {
    // Serial and sigAlg fit, issuer overruns -> the issuer.end > tbsEnd arm.
    const pem = forcedCert([...c.serial, ...c.sigAlg, ...c.issuer], c.serial.length + c.sigAlg.length + 1);
    ok("certNotAfter: issuer overruns tbs -> null", certNotAfter(pem) === null);
    ok("certValidity: issuer overruns tbs -> null", certValidity(pem) === null);
  }
  {
    // Serial, sigAlg and issuer fit, validity overruns -> the validity.end > tbsEnd arm.
    const base = c.serial.length + c.sigAlg.length + c.issuer.length;
    const pem = forcedCert([...c.serial, ...c.sigAlg, ...c.issuer, ...c.validity], base + 1);
    ok("certNotAfter: validity overruns tbs -> null", certNotAfter(pem) === null);
    ok("certValidity: validity overruns tbs -> null", certValidity(pem) === null);
  }
  {
    // Validity present but its first Time child is unreadable -> the notBefore === null arm.
    const badValidity = tlv(0x30, [0x17, 0x0d]); // a UTCTime claiming 13 bytes that do not follow
    const children = [...c.serial, ...c.sigAlg, ...c.issuer, ...badValidity];
    const pem = forcedCert(children, children.length);
    ok("certNotAfter: notBefore unreadable -> null", certNotAfter(pem) === null);
    ok("certValidity: notBefore unreadable -> null", certValidity(pem) === null);
  }
  {
    // Validity SEQUENCE under-declares its length so notBefore reads but ends past validity.end -> the
    // notBefore.end > validity.end arm.
    const nb = utcTime("200101000000Z");
    const validityShort = [0x30, nb.length - 1, ...nb];
    const children = [...c.serial, ...c.sigAlg, ...c.issuer, ...validityShort];
    const pem = forcedCert(children, children.length);
    ok("certNotAfter: notBefore overruns validity -> null", certNotAfter(pem) === null);
    ok("certValidity: notBefore overruns validity -> null", certValidity(pem) === null);
  }
  {
    // notBefore fits, notAfter is unreadable -> the notAfter === null arm.
    const nb = utcTime("200101000000Z");
    const naBad = [0x17, 0x0d]; // UTCTime claiming 13 bytes that do not follow
    const validityV = [0x30, ...derLen(nb.length + naBad.length), ...nb, ...naBad];
    const children = [...c.serial, ...c.sigAlg, ...c.issuer, ...validityV];
    const pem = forcedCert(children, children.length);
    ok("certNotAfter: notAfter unreadable -> null", certNotAfter(pem) === null);
    ok("certValidity: notAfter unreadable -> null", certValidity(pem) === null);
  }
  {
    // Validity under-declares so notAfter reads but ends past validity.end -> the notAfter.end > validity.end
    // arm.
    const nb = utcTime("200101000000Z");
    const na = utcTime("300101000000Z");
    const validityShort = [0x30, ...derLen(nb.length + na.length - 1), ...nb, ...na];
    const children = [...c.serial, ...c.sigAlg, ...c.issuer, ...validityShort];
    const pem = forcedCert(children, children.length);
    ok("certNotAfter: notAfter overruns validity -> null", certNotAfter(pem) === null);
    ok("certValidity: notAfter overruns validity -> null", certValidity(pem) === null);
  }

  // ---- readTlv long-form length edges --------------------------------------------------------
  {
    // A long-form length header claiming five length bytes (> 4) is rejected as absurd.
    ok("readTlv: long-form length with more than four bytes -> null", certNotAfter(pemFromDer([0x30, 0x85, 0, 0, 0, 0, 0])) === null);
  }
  {
    // A long-form header claiming two length bytes but only one present -> the bytes-past-end reject.
    ok("readTlv: long-form length bytes past end of buffer -> null", certNotAfter(pemFromDer([0x30, 0x82, 0x01])) === null);
  }

  // ---- stripPemBase64 armour edges -----------------------------------------------------------
  {
    // BEGIN armour with no END armour -> stripPemBase64 returns null.
    ok("stripPemBase64: no END armour -> null", certNotAfter("-----BEGIN CERTIFICATE-----\nQQ==") === null);
  }
  {
    // BEGIN armour with no newline after it (body on the same line): the bodyStart-after-armour branch is
    // taken and the body still decodes to a real notAfter.
    const validity = tlv(0x30, [...utcTime("200101000000Z"), ...utcTime("351231235959Z")]);
    const tbs = tlv(0x30, [...tlv(0x02, [0x01]), ...tlv(0x30, []), ...tlv(0x30, []), ...validity]);
    const b64 = Buffer.from(tlv(0x30, tbs)).toString("base64");
    const pem = `-----BEGIN CERTIFICATE-----${b64}-----END CERTIFICATE-----`;
    ok("stripPemBase64: no newline after BEGIN still decodes the body", certNotAfter(pem) === Date.UTC(2035, 11, 31, 23, 59, 59));
  }

  console.log(failures === 0 ? "\nCERT-NOTAFTER VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main();
