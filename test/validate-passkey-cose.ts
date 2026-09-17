// validate-passkey group: DIRECT unit tests of the COSE_Key parser bounds (parseCoseKey). Drives the EC2
// (P-256) accept and the curve / coordinate-length / kty-alg-mismatch / trailing-byte / empty / oversize /
// non-map / missing-label rejections, then the RSA (kty 3) branch family (wrong alg, missing modulus or
// exponent, out-of-range / empty / leading-zero modulus, empty / over-long exponent, the valid RSA accept),
// the unsupported-kty fall-through and the duplicate-integer-label rejection. Split out of
// validate-passkey.ts (behaviour-preserving); run via the validate-passkey.ts orchestrator.
import { b64urlDecode } from "../src/crypto/bytes.ts";
import { parseCoseKey, PasskeyError } from "../src/admin/passkey.ts";
import { ok, cborEncode, cat } from "./validate-passkey-harness.ts";

export async function run(): Promise<void> {
  // A valid EC2 P-256 key parses.
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { x: string; y: string };
  const goodCose = cborEncode({
    map: [
      [{ int: 1 }, { int: 2 }],
      [{ int: 3 }, { int: -7 }],
      [{ int: -1 }, { int: 1 }],
      [{ int: -2 }, { bytes: b64urlDecode(jwk.x) }],
      [{ int: -3 }, { bytes: b64urlDecode(jwk.y) }],
    ],
  });
  let parsed = false;
  try { parseCoseKey(goodCose); parsed = true; } catch { parsed = false; }
  ok("parseCoseKey accepts a valid EC2 P-256 key", parsed);

  // A wrong curve (crv != P-256) is rejected.
  const badCrv = cborEncode({
    map: [
      [{ int: 1 }, { int: 2 }],
      [{ int: 3 }, { int: -7 }],
      [{ int: -1 }, { int: 2 }], // crv P-384, not P-256
      [{ int: -2 }, { bytes: b64urlDecode(jwk.x) }],
      [{ int: -3 }, { bytes: b64urlDecode(jwk.y) }],
    ],
  });
  let threw = false;
  try { parseCoseKey(badCrv); } catch (e) { threw = e instanceof PasskeyError; }
  ok("parseCoseKey rejects a non-P-256 curve", threw);

  // A short coordinate is rejected.
  const shortX = cborEncode({
    map: [
      [{ int: 1 }, { int: 2 }],
      [{ int: 3 }, { int: -7 }],
      [{ int: -1 }, { int: 1 }],
      [{ int: -2 }, { bytes: new Uint8Array(16) }], // 16 bytes, not 32
      [{ int: -3 }, { bytes: b64urlDecode(jwk.y) }],
    ],
  });
  threw = false;
  try { parseCoseKey(shortX); } catch (e) { threw = e instanceof PasskeyError; }
  ok("parseCoseKey rejects a short EC2 coordinate", threw);

  // A kty/alg mismatch (EC2 kty with an RSA alg) is rejected.
  const ktyAlgMismatch = cborEncode({
    map: [
      [{ int: 1 }, { int: 2 }], // EC2
      [{ int: 3 }, { int: -257 }], // RS256 alg
      [{ int: -1 }, { int: 1 }],
      [{ int: -2 }, { bytes: b64urlDecode(jwk.x) }],
      [{ int: -3 }, { bytes: b64urlDecode(jwk.y) }],
    ],
  });
  threw = false;
  try { parseCoseKey(ktyAlgMismatch); } catch (e) { threw = e instanceof PasskeyError; }
  ok("parseCoseKey rejects a kty/alg mismatch", threw);

  // Trailing bytes after the COSE map are rejected (a forgery cannot append a second object).
  const trailing = cat(goodCose, new Uint8Array([0x00]));
  threw = false;
  try { parseCoseKey(trailing); } catch (e) { threw = e instanceof PasskeyError; }
  ok("parseCoseKey rejects trailing bytes", threw);

  // An empty key blob (length 0) is rejected by the length guard before any decode.
  threw = false;
  try { parseCoseKey(new Uint8Array(0)); } catch (e) { threw = e instanceof PasskeyError; }
  ok("parseCoseKey rejects an empty key blob", threw);

  // A key blob beyond COSE_KEY_MAX (2048) is rejected by the length guard (a padded blob meant to drive
  // the parser into wasted work). 2049 bytes of zero never reaches the decoder.
  threw = false;
  try { parseCoseKey(new Uint8Array(2049)); } catch (e) { threw = e instanceof PasskeyError; }
  ok("parseCoseKey rejects an oversized key blob", threw);

  // A top-level item that is not a map (here a bare integer) is rejected.
  threw = false;
  try { parseCoseKey(cborEncode({ int: 5 })); } catch (e) { threw = e instanceof PasskeyError; }
  ok("parseCoseKey rejects a non-map top-level item", threw);

  // A map missing the kty label is rejected (only alg present).
  threw = false;
  try { parseCoseKey(cborEncode({ map: [[{ int: 3 }, { int: -7 }]] })); } catch (e) { threw = e instanceof PasskeyError; }
  ok("parseCoseKey rejects a key missing kty", threw);

  // A map missing the alg label is rejected (only kty present).
  threw = false;
  try { parseCoseKey(cborEncode({ map: [[{ int: 1 }, { int: 2 }]] })); } catch (e) { threw = e instanceof PasskeyError; }
  ok("parseCoseKey rejects a key missing alg", threw);

  // An EC2 key whose y coordinate is not 32 bytes is rejected (x is valid, y is 16 bytes). This drives
  // the y-coordinate length check after the kty/alg/crv/x checks have all passed.
  const coord32 = new Uint8Array(32).fill(1);
  const shortY = cborEncode({
    map: [
      [{ int: 1 }, { int: 2 }],
      [{ int: 3 }, { int: -7 }],
      [{ int: -1 }, { int: 1 }],
      [{ int: -2 }, { bytes: coord32 }],
      [{ int: -3 }, { bytes: new Uint8Array(16) }],
    ],
  });
  threw = false;
  try { parseCoseKey(shortY); } catch (e) { threw = e instanceof PasskeyError; }
  ok("parseCoseKey rejects a short EC2 y coordinate", threw);

  // ---- RSA (kty 3) branch family ----
  // The RSA modulus and a canonical 65537 exponent reused across the valid RSA cases below.
  const rsaModulus = new Uint8Array(256).fill(0x80); // 256 bytes = 2048 bits, in range
  const rsaExponent = new Uint8Array([1, 0, 1]); // 65537

  // An RSA key (kty 3) with an alg other than RS256 (-257) is rejected.
  const rsaWrongAlg = cborEncode({ map: [[{ int: 1 }, { int: 3 }], [{ int: 3 }, { int: -7 }]] });
  threw = false;
  try { parseCoseKey(rsaWrongAlg); } catch (e) { threw = e instanceof PasskeyError; }
  ok("parseCoseKey rejects an RSA key with the wrong alg", threw);

  // An RSA key missing the modulus n is rejected.
  const rsaNoN = cborEncode({ map: [[{ int: 1 }, { int: 3 }], [{ int: 3 }, { int: -257 }], [{ int: -2 }, { bytes: rsaExponent }]] });
  threw = false;
  try { parseCoseKey(rsaNoN); } catch (e) { threw = e instanceof PasskeyError; }
  ok("parseCoseKey rejects an RSA key missing the modulus", threw);

  // An RSA key missing the exponent e is rejected.
  const rsaNoE = cborEncode({ map: [[{ int: 1 }, { int: 3 }], [{ int: 3 }, { int: -257 }], [{ int: -1 }, { bytes: rsaModulus }]] });
  threw = false;
  try { parseCoseKey(rsaNoE); } catch (e) { threw = e instanceof PasskeyError; }
  ok("parseCoseKey rejects an RSA key missing the exponent", threw);

  // An RSA modulus shorter than 2048 bits (here 100 bytes) is rejected by the length bound.
  const rsaShortN = cborEncode({ map: [[{ int: 1 }, { int: 3 }], [{ int: 3 }, { int: -257 }], [{ int: -1 }, { bytes: new Uint8Array(100).fill(0x80) }], [{ int: -2 }, { bytes: rsaExponent }]] });
  threw = false;
  try { parseCoseKey(rsaShortN); } catch (e) { threw = e instanceof PasskeyError; }
  ok("parseCoseKey rejects an out-of-range RSA modulus length", threw);

  // An RSA modulus carrying a single leading 0x00 DER sign byte is tolerated: the byte is stripped, then
  // the remaining 256 bytes fall in range, so the key parses. This drives the leading-zero strip true arm.
  const rsaLeadingZeroN = cborEncode({ map: [[{ int: 1 }, { int: 3 }], [{ int: 3 }, { int: -257 }], [{ int: -1 }, { bytes: cat(new Uint8Array([0x00]), rsaModulus) }], [{ int: -2 }, { bytes: rsaExponent }]] });
  let leadingZeroParsed = false;
  try { const k = parseCoseKey(rsaLeadingZeroN); leadingZeroParsed = k.kty === 3 && k.n.length === 256; } catch { leadingZeroParsed = false; }
  ok("parseCoseKey strips a single leading-zero modulus sign byte and accepts the key", leadingZeroParsed);

  // An empty modulus drives the leading-zero strip false arm (the n.length > 0 guard short-circuits), then
  // the length bound rejects the zero-length modulus.
  const rsaEmptyN = cborEncode({ map: [[{ int: 1 }, { int: 3 }], [{ int: 3 }, { int: -257 }], [{ int: -1 }, { bytes: new Uint8Array(0) }], [{ int: -2 }, { bytes: rsaExponent }]] });
  threw = false;
  try { parseCoseKey(rsaEmptyN); } catch (e) { threw = e instanceof PasskeyError; }
  ok("parseCoseKey rejects an empty RSA modulus", threw);

  // An empty exponent is rejected (the exponent must be at least one byte).
  const rsaEmptyE = cborEncode({ map: [[{ int: 1 }, { int: 3 }], [{ int: 3 }, { int: -257 }], [{ int: -1 }, { bytes: rsaModulus }], [{ int: -2 }, { bytes: new Uint8Array(0) }]] });
  threw = false;
  try { parseCoseKey(rsaEmptyE); } catch (e) { threw = e instanceof PasskeyError; }
  ok("parseCoseKey rejects an empty RSA exponent", threw);

  // An exponent longer than 8 bytes is rejected by the upper bound.
  const rsaLongE = cborEncode({ map: [[{ int: 1 }, { int: 3 }], [{ int: 3 }, { int: -257 }], [{ int: -1 }, { bytes: rsaModulus }], [{ int: -2 }, { bytes: new Uint8Array(9).fill(1) }]] });
  threw = false;
  try { parseCoseKey(rsaLongE); } catch (e) { threw = e instanceof PasskeyError; }
  ok("parseCoseKey rejects an over-long RSA exponent", threw);

  // A fully valid RSA key (in-range modulus and exponent) parses to the typed RSA shape, exercising the
  // RSA accept arm end to end.
  const rsaGood = cborEncode({ map: [[{ int: 1 }, { int: 3 }], [{ int: 3 }, { int: -257 }], [{ int: -1 }, { bytes: rsaModulus }], [{ int: -2 }, { bytes: rsaExponent }]] });
  let rsaParsed = false;
  try { const k = parseCoseKey(rsaGood); rsaParsed = k.kty === 3 && k.alg === -257 && k.e.length === 3; } catch { rsaParsed = false; }
  ok("parseCoseKey accepts a valid RSA key", rsaParsed);

  // An unsupported kty (neither EC2 nor RSA, here 5) falls through to the final rejection.
  const badKty = cborEncode({ map: [[{ int: 1 }, { int: 5 }], [{ int: 3 }, { int: -7 }]] });
  threw = false;
  try { parseCoseKey(badKty); } catch (e) { threw = e instanceof PasskeyError; }
  ok("parseCoseKey rejects an unsupported kty", threw);

  // A duplicate integer label (kty given twice) is a malformed map: the integer-key lookup rejects it, so
  // a forgery cannot smuggle a second value under the same COSE label.
  const dupKty = cborEncode({ map: [[{ int: 1 }, { int: 2 }], [{ int: 1 }, { int: 3 }], [{ int: 3 }, { int: -7 }]] });
  threw = false;
  try { parseCoseKey(dupKty); } catch (e) { threw = e instanceof PasskeyError; }
  ok("parseCoseKey rejects a duplicate integer label", threw);
}
