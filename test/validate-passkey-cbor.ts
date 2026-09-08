// validate-passkey group: DIRECT unit tests of the bounded CBOR decoder primitives (CborReader) and the
// text-key lookup (mapGetText). Drives the decode paths the COSE/attestation round trip does not naturally
// reach: the larger argument widths, the depth and element-count limits, the safe-integer guard (both the
// readUint and the negative-integer side), and the rejection of CBOR features outside the WebAuthn subset
// (reserved/indefinite lengths, tags and floats); then mapGetText's present/absent/duplicate cases. Split
// out of validate-passkey.ts (behaviour-preserving); run via the validate-passkey.ts orchestrator.
//
// CborReader and mapGetText are the lower-level CBOR primitives the COSE layer is built from. passkey.ts
// re-exports parseCoseKey/derEcdsaToRaw but not these two, so the direct rejection paths of the bounded
// decoder (depth, element-count and major-type limits) and the text-key duplicate guard are driven by
// importing them straight from the module under test.
import { CborReader, mapGetText } from "../src/admin/passkey-cose.ts";
import { PasskeyError } from "../src/admin/passkey.ts";
import { ok } from "./validate-passkey-harness.ts";

export async function run(): Promise<void> {
  let threw = false;
  const isRej = (bytes: Uint8Array): boolean => {
    try { new CborReader(bytes).decode(); return false; } catch (e) { return e instanceof PasskeyError; }
  };

  // A byte string whose length uses the 2-byte argument form (additional info 25) decodes correctly: head
  // 0x59 (major 2, ai 25), a 16-bit length of 1, then the one payload byte. This exercises the readUint
  // ai===25 path that a small COSE key never reaches.
  const twoByteLen = new CborReader(new Uint8Array([0x59, 0x00, 0x01, 0xaa])).decodeTop();
  ok("CborReader decodes a byte string with a 2-byte length argument", twoByteLen.t === "bytes" && twoByteLen.v.length === 1 && twoByteLen.v[0] === 0xaa);

  // A byte string whose length uses the 4-byte argument form (additional info 26) decodes correctly: head
  // 0x5a (major 2, ai 26), a 32-bit length of 1, then the one payload byte. This drives the readUint
  // ai===26 path.
  const fourByteLen = new CborReader(new Uint8Array([0x5a, 0x00, 0x00, 0x00, 0x01, 0xaa])).decodeTop();
  ok("CborReader decodes a byte string with a 4-byte length argument", fourByteLen.t === "bytes" && fourByteLen.v.length === 1 && fourByteLen.v[0] === 0xaa);

  // An unsigned integer at the very top of the JS safe-integer range (2^53-1) decodes exactly, exercising
  // the 8-byte argument form (additional info 27) on the accept side: head 0x1b then 0x001fffffffffffff.
  const maxSafe = new CborReader(new Uint8Array([0x1b, 0x00, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])).decode();
  ok("CborReader decodes an 8-byte unsigned integer at the safe-integer ceiling", maxSafe.t === "int" && maxSafe.v === Number.MAX_SAFE_INTEGER);

  // An unsigned integer one above the safe range (2^53) is rejected by the readUint safe-integer guard:
  // head 0x1b then 0x0020000000000000.
  threw = isRej(new Uint8Array([0x1b, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
  ok("CborReader rejects an unsigned integer above the safe range", threw);

  // An array (major type 4) of two integers decodes to the array shape. The attestation round trip only
  // builds maps and byte strings, so the array case is otherwise unexercised.
  const arr = new CborReader(new Uint8Array([0x82, 0x01, 0x02])).decodeTop();
  ok("CborReader decodes an array of two integers", arr.t === "array" && arr.v.length === 2 && arr.v[0]!.t === "int" && arr.v[0]!.v === 1);

  // Nesting beyond MAX_DEPTH (16) is rejected. Eighteen nested one-element arrays then an integer drive
  // the depth bound rather than blowing the stack.
  const deep: number[] = [];
  for (let i = 0; i < 18; i++) deep.push(0x81);
  deep.push(0x00);
  threw = isRej(new Uint8Array(deep));
  ok("CborReader rejects nesting deeper than the depth bound", threw);

  // An array header claiming more than MAX_ITEMS (64) entries is rejected before any allocation/loop: head
  // 0x98 (major 4, ai 24) with a one-byte count of 65.
  threw = isRej(new Uint8Array([0x98, 65]));
  ok("CborReader rejects an array larger than the element bound", threw);

  // A map header claiming more than MAX_ITEMS entries is likewise rejected: head 0xb8 (major 5, ai 24)
  // with a count of 65.
  threw = isRej(new Uint8Array([0xb8, 65]));
  ok("CborReader rejects a map larger than the element bound", threw);

  // A negative integer whose encoded magnitude is itself beyond the safe range is rejected inside readUint
  // (the magnitude never even becomes a JS number): head 0x3b (major 1, ai 27) with eight 0xff bytes.
  threw = isRej(new Uint8Array([0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]));
  ok("CborReader rejects a negative integer whose magnitude is beyond the safe range", threw);

  // A negative integer whose encoded magnitude is exactly 2^53-1 (a safe unsigned) but whose value
  // -1 - magnitude = -(2^53) is NOT a safe integer is rejected by the negative-integer safe-integer guard
  // specifically: head 0x3b then 0x001fffffffffffff. This drives the check on the negative side, distinct
  // from the readUint guard above.
  threw = isRej(new Uint8Array([0x3b, 0x00, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]));
  ok("CborReader rejects a negative integer whose negation falls below the safe range", threw);

  // A reserved additional-information value (28) is rejected: head 0x1c (major 0, ai 28).
  threw = isRej(new Uint8Array([0x1c]));
  ok("CborReader rejects a reserved additional-info value", threw);

  // Major type 7 (floats / simple values), outside the WebAuthn subset, is rejected: 0xf4 (false).
  threw = isRej(new Uint8Array([0xf4]));
  ok("CborReader rejects major type 7 (simple/float)", threw);

  // Major type 6 (semantic tags), outside the subset, is rejected: 0xc0 then a payload.
  threw = isRej(new Uint8Array([0xc0, 0x00]));
  ok("CborReader rejects major type 6 (tag)", threw);

  // mapGetText returns the value for a present text key, undefined for an absent one, and rejects a
  // duplicate text key (the same key twice is a malformed map a forgery cannot exploit).
  const single = new CborReader(new Uint8Array([0xa1, 0x61, 0x66, 0x09])).decode(); // { "f": 9 }
  const present = single.t === "map" ? mapGetText(single.v, "f") : undefined;
  const absent = single.t === "map" ? mapGetText(single.v, "z") : undefined;
  ok("mapGetText returns the value for a present text key and undefined for an absent one", present !== undefined && present.t === "int" && present.v === 9 && absent === undefined);

  const dupText = new CborReader(new Uint8Array([0xa2, 0x61, 0x66, 0x01, 0x61, 0x66, 0x02])).decode(); // { "f":1, "f":2 }
  threw = false;
  try { if (dupText.t === "map") mapGetText(dupText.v, "f"); } catch (e) { threw = e instanceof PasskeyError; }
  ok("mapGetText rejects a duplicate text key", threw);
}
