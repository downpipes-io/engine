// validate-passkey group: DIRECT unit tests of the strict DER -> raw ECDSA converter (the signature-
// malleability surface). Drives derEcdsaToRaw straight from the module under test against hand-built DER so
// the non-SEQUENCE, length-mismatch, negative/non-minimal/oversize integer, truncation, long-form length
// and trailing-byte rejections all fire. Split out of validate-passkey.ts (behaviour-preserving); run via
// the validate-passkey.ts orchestrator.
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { derEcdsaToRaw, PasskeyError } from "../src/admin/passkey.ts";
import { ok, rawToDer, cat } from "./validate-passkey-harness.ts";

export async function run(): Promise<void> {
  // A well-formed minimal signature round-trips.
  const raw = crypto.getRandomValues(new Uint8Array(64));
  // Force the high bits clear so rawToDer does not prepend sign bytes (keeps lengths predictable here).
  raw[0] = raw[0]! & 0x7f;
  raw[32] = raw[32]! & 0x7f;
  const der = rawToDer(raw);
  const back = derEcdsaToRaw(der);
  ok("derEcdsaToRaw round-trips a well-formed signature", b64urlEncode(back) === b64urlEncode(raw));

  // A non-SEQUENCE is rejected.
  let threw = false;
  try { derEcdsaToRaw(new Uint8Array([0x31, 0x00])); } catch (e) { threw = e instanceof PasskeyError; }
  ok("derEcdsaToRaw rejects a non-SEQUENCE", threw);

  // A sequence-length mismatch is rejected (claims more bytes than present).
  threw = false;
  try { derEcdsaToRaw(new Uint8Array([0x30, 0x05, 0x02, 0x01, 0x01])); } catch (e) { threw = e instanceof PasskeyError; }
  ok("derEcdsaToRaw rejects a sequence-length mismatch", threw);

  // A negative integer (high bit set, no 0x00 sign byte) is rejected.
  threw = false;
  try { derEcdsaToRaw(new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01])); } catch (e) { threw = e instanceof PasskeyError; }
  ok("derEcdsaToRaw rejects a negative integer", threw);

  // A non-minimal integer (leading 0x00 followed by a high-bit-clear byte) is rejected.
  threw = false;
  try { derEcdsaToRaw(new Uint8Array([0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01])); } catch (e) { threw = e instanceof PasskeyError; }
  ok("derEcdsaToRaw rejects a non-minimal integer encoding", threw);

  // A truncated buffer (only the SEQUENCE tag, no length byte to read) is rejected by the need() guard.
  threw = false;
  try { derEcdsaToRaw(new Uint8Array([0x30])); } catch (e) { threw = e instanceof PasskeyError; }
  ok("derEcdsaToRaw rejects a truncated buffer (need guard)", threw);

  // A long-form SEQUENCE length byte (high bit set) is non-canonical for this fixed-size structure.
  threw = false;
  try { derEcdsaToRaw(new Uint8Array([0x30, 0x81, 0x01, 0x00])); } catch (e) { threw = e instanceof PasskeyError; }
  ok("derEcdsaToRaw rejects a long-form SEQUENCE length", threw);

  // The first SEQUENCE element must be an INTEGER (tag 0x02); a different tag (here 0x03) is rejected.
  threw = false;
  try { derEcdsaToRaw(new Uint8Array([0x30, 0x03, 0x03, 0x01, 0x01])); } catch (e) { threw = e instanceof PasskeyError; }
  ok("derEcdsaToRaw rejects a non-INTEGER element", threw);

  // A long-form INTEGER length byte (high bit set) is rejected (short form only for this size).
  threw = false;
  try { derEcdsaToRaw(new Uint8Array([0x30, 0x03, 0x02, 0x81, 0x01])); } catch (e) { threw = e instanceof PasskeyError; }
  ok("derEcdsaToRaw rejects a long-form INTEGER length", threw);

  // A zero-length INTEGER is rejected (an ECDSA r/s value is never empty).
  threw = false;
  try { derEcdsaToRaw(new Uint8Array([0x30, 0x02, 0x02, 0x00])); } catch (e) { threw = e instanceof PasskeyError; }
  ok("derEcdsaToRaw rejects a zero-length INTEGER", threw);

  // An INTEGER magnitude beyond 32 bytes is rejected (r/s of P-256 fit 32 bytes). r is 33 magnitude
  // bytes (all 0x01, no sign bit set), s a single byte; the SEQUENCE length covers exactly r||s.
  threw = false;
  const bigR = cat(new Uint8Array([0x02, 33]), new Uint8Array(33).fill(0x01));
  const smallS = new Uint8Array([0x02, 0x01, 0x01]);
  const oversizeBody = cat(bigR, smallS);
  try { derEcdsaToRaw(cat(new Uint8Array([0x30, oversizeBody.length]), oversizeBody)); } catch (e) { threw = e instanceof PasskeyError; }
  ok("derEcdsaToRaw rejects an INTEGER beyond 32 bytes", threw);

  // Trailing bytes left INSIDE the SEQUENCE after r and s are consumed are rejected. The SEQUENCE length
  // matches the whole buffer (so the length check passes), but two stray bytes follow s, so the
  // end-of-input assert after reading both integers fires.
  threw = false;
  const rOk = new Uint8Array([0x02, 0x01, 0x01]);
  const sOk = new Uint8Array([0x02, 0x01, 0x01]);
  const trailBody = cat(rOk, sOk, new Uint8Array([0xaa, 0xbb]));
  try { derEcdsaToRaw(cat(new Uint8Array([0x30, trailBody.length]), trailBody)); } catch (e) { threw = e instanceof PasskeyError; }
  ok("derEcdsaToRaw rejects trailing bytes inside the SEQUENCE", threw);
}
