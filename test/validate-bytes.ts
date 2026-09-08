// Validates that b64urlDecode is strictly compatible with Go's
// base64.RawURLEncoding.DecodeString, and that the round-trip with b64urlEncode holds.
//
// Go's RawURLEncoding rejects:
//   - any character outside the URL-safe alphabet (A-Z a-z 0-9 - _)
//   - padding characters '='
//   - strings whose length mod 4 equals 1
//   - non-canonical trailing bits in the last encoded group
//
// Run with: node test/validate-bytes.ts

import { ab, b64urlDecode, b64urlEncode, base64Encode, concat, constantTimeEqual, hexDecode, hexEncode, lpAppend, u32be, u64be, utf8 } from "../src/crypto/bytes.ts";

let failures = 0;

function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function throws(label: string, fn: () => unknown, fragment: string): void {
  try {
    fn();
    console.log(`  FAIL ${label} (expected throw, got none)`);
    failures++;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const pass = msg.includes(fragment);
    console.log(
      pass
        ? `  ok   ${label}`
        : `  FAIL ${label} (error ${JSON.stringify(msg)} does not contain ${JSON.stringify(fragment)})`,
    );
    if (!pass) failures++;
  }
}

function hexBytes(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

function testCanonicalDecode(): void {
  // -----------------------------------------------------------------------
  // canonical decoding
  // -----------------------------------------------------------------------
  console.log("canonical decode:");

  // empty string -> zero bytes
  ok("empty string decodes to zero bytes", b64urlDecode("").length === 0);

  // 1 byte: 0xff -> b64url is "7w" (two chars, rem=1 byte)
  // 0xff in binary is 11111111
  // group: 111111 110000 = "7" "w" in url alphabet ('_' is 63, '-' is 62)
  // wait: B64URL[63]='_', B64URL[62]='-'
  // 0xff = 1111 1111
  // split into 6+2: 111111 and 11 << 4 = 110000 = 48 → 'w'? let me verify
  // Actually b64urlEncode([0xff]):
  //   i=0, rem=1: n = 0xff << 16 = 0xff0000
  //   (n >> 18) & 63 = (0xff0000 >> 18) & 63 = 0x3f & 63 = 63 → '_'? no wait
  //   B64URL[63] = '_', B64URL[(0xff0000 >> 12) & 63] = B64URL[(0xffc >> 0) & 63]
  //   (0xff0000 >> 18) = 0x3f = 63 → B64URL[63] = '_'
  //   (0xff0000 >> 12) & 63 = 0xff0 & 63 = 48 → B64URL[48] = 'w'
  // so [0xff] -> "_w"
  const oneByteResult = b64urlDecode("_w");
  ok("1-byte canonical: '_w' -> [0xff]", oneByteResult.length === 1 && oneByteResult[0] === 0xff);

  // 2 bytes: [0xfe, 0xca] -> b64urlEncode to verify
  const twoBytes = new Uint8Array([0xfe, 0xca]);
  const twoBytesEnc = b64urlEncode(twoBytes);
  const twoBytesBack = b64urlDecode(twoBytesEnc);
  ok(
    "2-byte canonical round-trip",
    twoBytesBack.length === 2 && twoBytesBack[0] === 0xfe && twoBytesBack[1] === 0xca,
  );

  // 3 bytes: full group of 4 chars -> no remainder
  const threeBytes = new Uint8Array([0xde, 0xad, 0xbe]);
  const threeBytesEnc = b64urlEncode(threeBytes);
  ok("3-byte encoded length is 4", threeBytesEnc.length === 4);
  const threeBytesBack = b64urlDecode(threeBytesEnc);
  ok(
    "3-byte canonical round-trip",
    threeBytesBack.length === 3 &&
      threeBytesBack[0] === 0xde &&
      threeBytesBack[1] === 0xad &&
      threeBytesBack[2] === 0xbe,
  );

  // all-zeros: a longer vector
  const zeros = new Uint8Array(9).fill(0);
  const zerosEnc = b64urlEncode(zeros);
  const zerosBack = b64urlDecode(zerosEnc);
  ok("9-byte all-zeros round-trip length", zerosBack.length === 9);
  ok("9-byte all-zeros round-trip content", hexBytes(zerosBack) === hexBytes(zeros));

  // all-ones (0xff * 12): three complete groups of 4
  const ones = new Uint8Array(12).fill(0xff);
  const onesEnc = b64urlEncode(ones);
  const onesBack = b64urlDecode(onesEnc);
  ok("12-byte all-0xff round-trip length", onesBack.length === 12);
  ok("12-byte all-0xff round-trip content", hexBytes(onesBack) === hexBytes(ones));

  // uses both URL-safe special chars: '-' (index 62) and '_' (index 63)
  // construct a byte that would produce both: 0b11111110 = 0xfe
  // [0xfe, 0x00] -> (0xfe << 16 | 0x00 << 8) -> 0xfe0000
  //   (>>18)&63 = 0x3f = 63 -> '_'
  //   (>>12)&63 = 0x3e = 62 -> '-'
  //   (>> 6)&63 = 0x00 = 0  -> 'A'
  const dashUnder = b64urlDecode("_-A");
  ok("input with '-' and '_' accepted", dashUnder.length === 2);
}

function testRoundTrip(): void {
  // -----------------------------------------------------------------------
  // large round-trip: 256-byte sequence with every byte value
  // -----------------------------------------------------------------------
  console.log("round-trip:");
  const all256 = new Uint8Array(256);
  for (let i = 0; i < 256; i++) all256[i] = i;
  const all256enc = b64urlEncode(all256);
  const all256back = b64urlDecode(all256enc);
  ok("256-byte all-values round-trip length", all256back.length === 256);
  ok("256-byte all-values round-trip content", hexBytes(all256back) === hexBytes(all256));
}

function testPaddingRejection(): void {
  // -----------------------------------------------------------------------
  // reject padding '='
  // -----------------------------------------------------------------------
  console.log("reject padding:");

  // standard padded base64url for [0xfe]: "_g==" - reject
  throws("reject '='-padded input (2 trailing '=')", () => b64urlDecode("_g=="), "invalid base64url character");

  // single trailing '=' - reject
  throws("reject '='-padded input (1 trailing '=')", () => b64urlDecode("_-A="), "invalid base64url character");

  // '=' in the middle - reject
  throws("reject '=' in the middle", () => b64urlDecode("_=AA"), "invalid base64url character");
}

function testCharacterRejection(): void {
  // -----------------------------------------------------------------------
  // reject standard-alphabet characters '+' and '/'
  // -----------------------------------------------------------------------
  console.log("reject standard-alphabet '+' and '/':");

  // standard base64 for a byte sequence that would use '+' or '/' in the standard alphabet
  // '>' (0x3e) is '+' in standard base64; '+' is char code 43 which is not in url alphabet
  throws("reject '+' (standard base64 char)", () => b64urlDecode("AA+A"), "invalid base64url character");
  throws("reject '/' (standard base64 char)", () => b64urlDecode("AA/A"), "invalid base64url character");

  // -----------------------------------------------------------------------
  // reject whitespace
  // -----------------------------------------------------------------------
  console.log("reject whitespace:");
  // use 4-char strings so the length check does not fire before the character check
  throws("reject space", () => b64urlDecode("A AA"), "invalid base64url character");
  throws("reject tab", () => b64urlDecode("A\tAA"), "invalid base64url character");
  throws("reject newline", () => b64urlDecode("A\nAA"), "invalid base64url character");
  throws("reject carriage return", () => b64urlDecode("A\rAA"), "invalid base64url character");

  // -----------------------------------------------------------------------
  // reject high-codepoint characters (above ASCII range)
  // -----------------------------------------------------------------------
  console.log("reject non-ASCII characters:");
  throws("reject U+00E9 (é)", () => b64urlDecode("AéAA"), "invalid base64url character");
  throws("reject U+2019 (smart quote)", () => b64urlDecode("A’A"), "invalid base64url character");
}

function testLengthValidation(): void {
  // -----------------------------------------------------------------------
  // reject length mod 4 == 1
  // -----------------------------------------------------------------------
  console.log("reject invalid length:");

  // single char: length 1, 1 % 4 == 1
  throws("reject length-1 string", () => b64urlDecode("A"), "length mod 4 must not be 1");

  // length 5: 5 % 4 == 1
  throws("reject length-5 string", () => b64urlDecode("AAAAA"), "length mod 4 must not be 1");

  // length 9: 9 % 4 == 1
  throws("reject length-9 string", () => b64urlDecode("AAAAAAAAA"), "length mod 4 must not be 1");

  // lengths 2, 3, 4 are all valid structural lengths
  ok("length-2 string accepted (1 byte)", b64urlDecode("AA").length === 1);
  ok("length-3 string accepted (2 bytes)", b64urlDecode("AAA").length === 2);
  ok("length-4 string accepted (3 bytes)", b64urlDecode("AAAA").length === 3);
}

function testTrailingBits(): void {
  // -----------------------------------------------------------------------
  // reject non-canonical trailing bits
  // -----------------------------------------------------------------------
  console.log("reject non-canonical trailing bits:");

  // 2-char group: represents 12 bits, emits 1 byte; bottom 4 bits of the last char
  // must be zero. 'AA' -> both chars are value 0 -> 000000 000000 -> trailing 4 bits = 0 (ok).
  // 'AB' -> 000000 000001 -> bottom 4 bits of acc after 1 byte emitted = 0001 != 0 -> reject
  throws("reject 2-char group with non-zero trailing bits ('AB')", () => b64urlDecode("AB"), "non-canonical trailing bits");

  // another: 'AC' -> 000000 000010 -> bottom 4 = 0010 -> reject
  throws(
    "reject 2-char group non-canonical ('AC')",
    () => b64urlDecode("AC"),
    "non-canonical trailing bits",
  );

  // 3-char group: represents 18 bits, emits 2 bytes; bottom 2 bits of last char must be zero.
  // 'AAA' -> 000000 000000 000000 -> trailing 2 bits = 0 (ok).
  // 'AAB' -> 000000 000000 000001 -> bottom 2 = 01 -> reject
  throws(
    "reject 3-char group with non-zero trailing bits ('AAB')",
    () => b64urlDecode("AAB"),
    "non-canonical trailing bits",
  );

  // 'AAC' -> 000000 000000 000010 -> bottom 2 = 10 -> reject
  throws(
    "reject 3-char group non-canonical ('AAC')",
    () => b64urlDecode("AAC"),
    "non-canonical trailing bits",
  );

  // these 3-char inputs ARE canonical (last char value is multiple of 4 -> bottom 2 bits 0)
  // 'AAE' -> value 4 = 000100, bottom 2 bits = 00 -> ok; decodes to [0x00, 0x04]? let me check:
  // 000000 000000 000100 -> 18 bits:
  //   first 8 = 00000000 = 0x00
  //   next 8 = 00000001 = 0x01? wait:
  //   000000|000000|000100
  //   = 000000000000000100
  //   first 8 bits: 00000000 = 0x00
  //   next 8 bits: 00000001 = 0x01
  //   remaining 2 bits: 00 -> canonical
  // so 'AAE' -> [0x00, 0x01]
  ok("canonical 3-char 'AAE' accepted", b64urlDecode("AAE").length === 2);

  // confirm the canonical trailing check does not fire for valid encodings:
  // b64urlEncode([0x00]) = 'AA', b64urlEncode([0x00, 0x00]) = 'AAA'
  ok("canonical 'AA' (encodes [0x00]) accepted", b64urlDecode("AA")[0] === 0);
  ok("canonical 'AAA' (encodes [0x00, 0x00]) accepted", b64urlDecode("AAA").length === 2);
}

function testConsistency(): void {
  // -----------------------------------------------------------------------
  // encode/decode consistency with b64urlEncode
  // -----------------------------------------------------------------------
  console.log("encode/decode consistency:");

  // any byte sequence produced by b64urlEncode must be accepted by b64urlDecode
  const testVectors: Array<[string, Uint8Array]> = [
    ["single byte 0x00", new Uint8Array([0x00])],
    ["single byte 0xff", new Uint8Array([0xff])],
    ["two bytes [0x00, 0xff]", new Uint8Array([0x00, 0xff])],
    ["two bytes [0xff, 0x00]", new Uint8Array([0xff, 0x00])],
    ["three bytes [0xde, 0xad, 0xbe]", new Uint8Array([0xde, 0xad, 0xbe])],
    ["four bytes [0x01, 0x23, 0x45, 0x67]", new Uint8Array([0x01, 0x23, 0x45, 0x67])],
    ["five bytes all 0xaa", new Uint8Array(5).fill(0xaa)],
    ["six bytes all 0x55", new Uint8Array(6).fill(0x55)],
    ["seven bytes 0x11", new Uint8Array(7).fill(0x11)],
  ];

  for (const [label, input] of testVectors) {
    const enc = b64urlEncode(input);
    const dec = b64urlDecode(enc);
    ok(`round-trip ${label}`, hexBytes(dec) === hexBytes(input));
  }
}

function testConstantTimeEqual(): void {
  // -----------------------------------------------------------------------
  // constantTimeEqual (now backed by crypto.subtle.timingSafeEqual)
  // -----------------------------------------------------------------------
  console.log("constantTimeEqual:");

  // Correctness preserved: equal secrets compare equal, a difference compares unequal.
  ok("equal arrays compare equal", constantTimeEqual(new Uint8Array([1, 2, 3, 4]), new Uint8Array([1, 2, 3, 4])) === true);
  ok("a first-byte difference compares unequal", constantTimeEqual(new Uint8Array([9, 2, 3, 4]), new Uint8Array([1, 2, 3, 4])) === false);
  ok("a last-byte difference compares unequal", constantTimeEqual(new Uint8Array([1, 2, 3, 4]), new Uint8Array([1, 2, 3, 5])) === false);
  ok("empty against empty compares equal", constantTimeEqual(new Uint8Array(0), new Uint8Array(0)) === true);

  // The primitive throws on a length mismatch, so the wrapper must short-circuit and return false,
  // never throw. Both directions of mismatch are covered, plus a longer pair.
  ok("a shorter-against-longer length mismatch returns false (no throw)", constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3])) === false);
  ok("a longer-against-shorter length mismatch returns false (no throw)", constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2])) === false);
  ok("an empty-against-nonempty length mismatch returns false (no throw)", constantTimeEqual(new Uint8Array(0), new Uint8Array([1])) === false);

  // A 64-byte equal pair (a typical secret length) round-trips through the primitive.
  const longA = new Uint8Array(64);
  for (let i = 0; i < 64; i++) longA[i] = (i * 7) & 0xff;
  const longB = longA.slice();
  ok("a 64-byte equal pair compares equal", constantTimeEqual(longA, longB) === true);
  longB[63] = (longB[63]! ^ 0x01) & 0xff;
  ok("a 64-byte pair differing in the last byte compares unequal", constantTimeEqual(longA, longB) === false);
}

// The byte helpers b64urlEncode/Decode + constantTimeEqual were the only functions exercised here; the rest of
// the crypto byte port (concat, ab, lpAppend, u32be, u64be, utf8, hexEncode, hexDecode, base64Encode) went
// untested, which is where the bytes.ts mutation survivors lived. Every one is pinned with exact assertions so
// a mutation that changes an operator, a constant or a boundary is caught, not survived.
function testUntestedHelpers(): void {
  // concat: order preserved, lengths summed, empty parts tolerated, a fresh (non-aliasing) buffer returned.
  ok("concat() of nothing is empty", concat().length === 0);
  ok("concat preserves order and total length", hexBytes(concat(new Uint8Array([1, 2]), new Uint8Array([3]), new Uint8Array([4, 5, 6]))) === "010203040506");
  ok("concat tolerates an empty middle part", hexBytes(concat(new Uint8Array([9]), new Uint8Array([]), new Uint8Array([8]))) === "0908");
  ok("concat returns a fresh array (mutating the result never touches an input)", (() => { const a = new Uint8Array([1]); const c = concat(a); c[0] = 2; return a[0] === 1; })());

  // ab: identity re-type (same bytes, same reference).
  ok("ab() returns the same underlying bytes", (() => { const x = new Uint8Array([7, 8]); return ab(x) === x; })());

  // lpAppend: a one-byte length prefix then the field; 255 accepted, 256 rejected.
  ok("lpAppend writes the one-byte length then the field", hexBytes(lpAppend(new Uint8Array([0xaa]), new Uint8Array([1, 2, 3]))) === "aa03010203");
  ok("lpAppend of an empty field writes a zero length byte", hexBytes(lpAppend(new Uint8Array([]), new Uint8Array([]))) === "00");
  ok("lpAppend accepts a 255-byte field (256 out: 1 length + 255)", lpAppend(new Uint8Array([]), new Uint8Array(255)).length === 256);
  throws("lpAppend rejects a 256-byte field", () => lpAppend(new Uint8Array([]), new Uint8Array(256)), "exceeds 255 bytes");

  // u32be / u64be: big-endian, fixed width, boundary values.
  ok("u32be(0) is four zero bytes", hexBytes(u32be(0)) === "00000000");
  ok("u32be(1) is big-endian (low byte last)", hexBytes(u32be(1)) === "00000001");
  ok("u32be(0x01020304) is big-endian", hexBytes(u32be(0x01020304)) === "01020304");
  ok("u32be(0xffffffff) is all ones", hexBytes(u32be(0xffffffff)) === "ffffffff");
  ok("u64be(0n) is eight zero bytes", hexBytes(u64be(0n)) === "0000000000000000");
  ok("u64be(1n) is big-endian (low byte last)", hexBytes(u64be(1n)) === "0000000000000001");
  ok("u64be(0x0102030405060708n) is big-endian", hexBytes(u64be(0x0102030405060708n)) === "0102030405060708");

  // utf8: ASCII, multi-byte, and the empty string.
  ok("utf8('') is empty", utf8("").length === 0);
  ok("utf8('A') is 0x41", hexBytes(utf8("A")) === "41");
  ok("utf8 encodes U+00E9 as the two-byte c3a9", hexBytes(utf8("é")) === "c3a9");
  ok("utf8 encodes a supplementary-plane emoji as 4 bytes", utf8("\u{1F600}").length === 4);

  // hexEncode: lowercase, zero-padded, two chars per byte.
  ok("hexEncode('') is empty", hexEncode(new Uint8Array([])) === "");
  ok("hexEncode zero-pads a low byte to two chars", hexEncode(new Uint8Array([0x0a])) === "0a");
  ok("hexEncode is lowercase", hexEncode(new Uint8Array([0xde, 0xad, 0xbe, 0xef])) === "deadbeef");
  ok("hexEncode of 0x00 0xff", hexEncode(new Uint8Array([0x00, 0xff])) === "00ff");

  // hexDecode: round-trips hexEncode, rejects odd length + non-hex (the closed silent-coercion hole).
  ok("hexDecode round-trips hexEncode", hexEncode(hexDecode("00ff10ab")) === "00ff10ab");
  ok("hexDecode('') is empty", hexDecode("").length === 0);
  throws("hexDecode rejects an odd-length string", () => hexDecode("abc"), "odd-length");
  throws("hexDecode rejects a non-hex character (never a silent zero)", () => hexDecode("zz"), "non-hex character");
  ok("hexDecode does not coerce a non-hex pair to zero", (() => { try { hexDecode("0g"); return false; } catch { return true; } })());

  // base64Encode: STANDARD alphabet WITH padding (distinct from the url-safe no-pad b64urlEncode).
  ok("base64Encode('') is empty", base64Encode(new Uint8Array([])) === "");
  ok("base64Encode pads one trailing byte with ==", base64Encode(new Uint8Array([0x66])) === "Zg==");
  ok("base64Encode pads two trailing bytes with =", base64Encode(new Uint8Array([0x66, 0x6f])) === "Zm8=");
  ok("base64Encode of a full three-byte group has no padding", base64Encode(new Uint8Array([0x66, 0x6f, 0x6f])) === "Zm9v");
  ok("base64Encode uses + and / (standard, not the url-safe - _)", base64Encode(new Uint8Array([0xfb, 0xff, 0xbf])) === "+/+/");
}

async function main(): Promise<void> {
  testCanonicalDecode();
  testRoundTrip();
  testPaddingRejection();
  testCharacterRejection();
  testLengthValidation();
  testTrailingBits();
  testConsistency();
  testConstantTimeEqual();
  testUntestedHelpers();

  // -----------------------------------------------------------------------
  // results
  // -----------------------------------------------------------------------
  console.log(failures === 0 ? "\nBYTES TESTS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
