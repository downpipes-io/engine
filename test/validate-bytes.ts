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
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import * as bytesModule from "../src/crypto/bytes.ts";
import { decodeCaller, encodeCaller, type Caller } from "../src/admin/identity.ts";
import { cellFromValue } from "../src/sources/d1-format.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

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
  // u64be REFUSES an out-of-range value rather than truncating it. DataView.setBigUint64 wraps modulo 2^64
  // (measured on Node 22: setBigUint64(0, 2n ** 64n) writes eight zero bytes, byte-identical to u64be(0n)),
  // and u64be's caller in the seal path is the STREAM chunk nonce, where re-emitting an earlier encoding is
  // a nonce re-use under one AES-256-GCM key. The Go reference refuses at the counter (internal/crypto/
  // stream.go advanceChunk); until this check landed the TypeScript encoder carried no bound at all, so the
  // three assertions below are the ones that would have passed against a silent wrap.
  ok("u64be(2^64 - 1) is the largest value it encodes", hexBytes(u64be(0xffff_ffff_ffff_ffffn)) === "ffffffffffffffff");
  throws("u64be REJECTS 2^64 rather than wrapping it to eight zero bytes", () => u64be(1n << 64n), "outside the unsigned 64-bit range");
  throws("u64be REJECTS 2^64 + 1 rather than wrapping it to one", () => u64be((1n << 64n) + 1n), "outside the unsigned 64-bit range");
  throws("u64be REJECTS a negative value rather than encoding its two's complement", () => u64be(-1n), "outside the unsigned 64-bit range");
  // The control that keeps the three assertions above from grading nothing: the platform primitive u64be
  // wraps really does wrap, so the refusals are catching a live truncation rather than an impossible one.
  ok("the wrap being refused is real: raw setBigUint64(2^64) writes the encoding of zero", (() => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, 1n << 64n, false); return hexBytes(b) === "0000000000000000"; })());
  ok("...and raw setBigUint64(-1n) writes the encoding of 2^64 - 1", (() => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, -1n, false); return hexBytes(b) === "ffffffffffffffff"; })());

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

// ---- Class guard: every byte-to-base64 path in the engine carries all 256 byte values -----------------
// The customer-path test (finding F1) found the D1 BLOB encoder building btoa's binary string with
// TextDecoder("latin1"). Under the WHATWG Encoding standard that label is windows-1252, which maps 27 bytes
// in 0x80-0x9F to code points above U+00FF, so btoa threw and the whole D1 backup failed on every retry. The
// codec test used the bytes [104, 105, 0, 255], none of them in that range. This guard grades each path
// against Node's own base64 over every byte value, alone and together, and scans src/ so a new path that
// builds text from bytes, or a new btoa call, is refused until it is added here with its proof.

function everyByteValue(): Uint8Array {
  const b = new Uint8Array(256);
  for (let i = 0; i < 256; i++) b[i] = i;
  return b;
}

// blobOf reads the base64url a D1 cell carries, or "" when the cell is not a tagged BLOB.
function blobOf(cell: unknown): string {
  return typeof cell === "object" && cell !== null && "$blob" in cell ? String((cell as { $blob: unknown }).$blob) : "";
}

// d1BlobAllShapes encodes one byte array through the three shapes D1 hands a BLOB to cellFromValue in
// (an ArrayBuffer, a typed-array view over a larger buffer, and the number[] that .raw() returns), and
// returns the three encodings. A refusal is returned as its error name, so a throw grades as a mismatch.
function d1BlobAllShapes(b: Uint8Array): string[] {
  const padded = new Uint8Array(b.length + 7);
  padded.set(b, 3);
  const shapes: unknown[] = [b.slice().buffer, padded.subarray(3, 3 + b.length), Array.from(b)];
  return shapes.map((v) => {
    try {
      return blobOf(cellFromValue(v));
    } catch (e) {
      return `threw ${(e as Error).name}`;
    }
  });
}

function testEveryBytePaths(): void {
  console.log("\nclass guard: every byte-to-base64 path carries all 256 byte values:");
  const all = everyByteValue();
  const url = (b: Uint8Array): string => Buffer.from(b).toString("base64url");
  const std = (b: Uint8Array): string => Buffer.from(b).toString("base64");

  // Each byte alone, then all 256 together, then a long cell that crosses the D1 encoder's chunk boundary,
  // then seeded random arrays.
  const cases: Uint8Array[] = [];
  for (let i = 0; i < 256; i++) cases.push(Uint8Array.of(i));
  cases.push(all, all.subarray(0x80, 0xa0), new Uint8Array(0));
  const long = new Uint8Array(3 * 8192 + 5);
  for (let i = 0; i < long.length; i++) long[i] = (i * 131 + 17) & 0xff;
  cases.push(long);
  let seed = 0x9e3779b9;
  for (let n = 0; n < 200; n++) {
    const b = new Uint8Array(seed % 97);
    for (let i = 0; i < b.length; i++) {
      seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
      b[i] = seed >>> 24;
    }
    cases.push(b);
  }

  let urlBad = 0;
  let stdBad = 0;
  let d1Bad = 0;
  let roundBad = 0;
  const d1Failed: number[] = [];
  for (const b of cases) {
    if (b64urlEncode(b) !== url(b)) urlBad++;
    if (base64Encode(b) !== std(b)) stdBad++;
    if (hexEncode(b64urlDecode(b64urlEncode(b))) !== hexEncode(b)) roundBad++;
    const shapes = d1BlobAllShapes(b);
    if (!shapes.every((x) => x === url(b))) {
      d1Bad++;
      if (b.length === 1) d1Failed.push(b[0]!);
    }
  }
  ok(`b64urlEncode matches Node's base64url on all ${cases.length} cases`, urlBad === 0);
  ok(`base64Encode matches Node's base64 on all ${cases.length} cases`, stdBad === 0);
  ok("b64urlDecode inverts b64urlEncode on every case", roundBad === 0);
  ok(
    `the D1 BLOB cell encoder (cellFromValue, all three input shapes) matches Node's base64url on every case${d1Failed.length ? ` (single bytes refused: ${d1Failed.map((x) => `0x${x.toString(16)}`).join(" ")})` : ""}`,
    d1Bad === 0,
  );

  // The admin caller header: JSON text to UTF-8 bytes, then byte-wise to btoa. Every Latin-1 code point, a
  // character from 0x80-0x9F's windows-1252 set, and an astral one must survive the round trip.
  let text = "";
  for (let c = 0x20; c <= 0xff; c++) text += String.fromCharCode(c);
  text += "\u20ac\u{1f600}";
  const caller: Caller = { method: "access", email: `x${text}@example.au`, subject: text, role: "owner", groups: [] };
  let callerRound = false;
  try {
    const back = decodeCaller(encodeCaller(caller));
    callerRound = back?.subject === text && back?.email === caller.email;
  } catch {
    callerRound = false;
  }
  ok("the caller header round-trips every Latin-1 code point, U+20AC and an astral character", callerRound);

  // HTTP Basic credentials: UTF-8, never btoa over the joined text (which throws above U+00FF).
  const basic = (bytesModule as Record<string, unknown>).basicCredentials as ((u: string, p: string) => string) | undefined;
  ok("crypto/bytes exports basicCredentials, the one HTTP Basic encoder", typeof basic === "function");
  if (typeof basic === "function") {
    ok("basicCredentials of ASCII text equals btoa's (no change for an ASCII secret)", basic("svc_downpipes", "s3cr3t-PASSWORD-abc") === btoa("svc_downpipes:s3cr3t-PASSWORD-abc"));
    let thrown = "";
    let got = "";
    try {
      got = basic("svc", text);
    } catch (e) {
      thrown = (e as Error).name;
    }
    ok(`basicCredentials of a secret with every Latin-1 code point, U+20AC and an astral character is its UTF-8 base64${thrown ? ` (threw ${thrown})` : ""}`, got === Buffer.from(`svc:${text}`, "utf8").toString("base64"));
  }

  // The source scan. SINGLE_BYTE_DECODER matches a TextDecoder given any label other than UTF-8: every
  // single-byte label the Encoding standard knows maps some byte above 0x7F to a code point that is not the
  // byte's own value, so such a decoder cannot stand in for "one code unit per byte".
  const SINGLE_BYTE_DECODER = /new\s+TextDecoder\(\s*["'`](?!utf-?8["'`])/i;
  const BTOA_CALL = /\bbtoa\(/g;
  // The reviewed btoa call sites, each with the proof that its input is a binary string or ASCII:
  //   identity.ts      encodeCaller: TextEncoder bytes, String.fromCharCode per byte (round trip above)
  //   oidc-verify.ts   b64url: SHA-256 digest bytes, String.fromCharCode per byte
  //   azure-blob.ts    block id: eight decimal digits
  //   d1-format.ts     bytesToB64url: String.fromCharCode per byte (graded above on every byte value)
  const BTOA_REVIEWED: Record<string, number> = { "admin/identity.ts": 1, "admin/oidc-verify.ts": 1, "dest/azure-blob.ts": 1, "sources/d1-format.ts": 1 };
  // Negative and positive controls: the patterns must fire on the old encoder's line and stay quiet on a
  // UTF-8 or label-free decoder, or a clean scan below would mean nothing.
  ok("scan control: the pattern fires on TextDecoder(\"latin1\")", SINGLE_BYTE_DECODER.test('new TextDecoder("latin1").decode(b)'));
  ok("scan control: the pattern fires on TextDecoder('iso-8859-1')", SINGLE_BYTE_DECODER.test("new TextDecoder('iso-8859-1')"));
  ok("scan control: the pattern is quiet on TextDecoder() and TextDecoder(\"utf-8\")", !SINGLE_BYTE_DECODER.test("new TextDecoder()") && !SINGLE_BYTE_DECODER.test('new TextDecoder("utf-8")'));
  const srcRoot = fileURLToPath(new URL("../src/", import.meta.url));
  const files = (readdirSync(srcRoot, { recursive: true }) as string[]).filter((f) => f.endsWith(".ts"));
  const decoders: string[] = [];
  const btoaCounts: Record<string, number> = {};
  for (const f of files) {
    const rel = f.split("\\").join("/");
    const lines = readFileSync(join(srcRoot, f), "utf8").split("\n");
    lines.forEach((line, i) => {
      if (/^\s*\/\//.test(line)) return; // a comment names the trap; it is not a call
      if (SINGLE_BYTE_DECODER.test(line)) decoders.push(`${rel}:${i + 1}`);
      const n = (line.match(BTOA_CALL) ?? []).length;
      if (n > 0) btoaCounts[rel] = (btoaCounts[rel] ?? 0) + n;
    });
  }
  ok(`the scan read the engine source (${files.length} .ts files)`, files.length > 100);
  ok(`no source file decodes bytes with a single-byte TextDecoder label${decoders.length ? ` (found: ${decoders.join(", ")})` : ""}`, decoders.length === 0);
  const unreviewed = Object.entries(btoaCounts).filter(([f, n]) => BTOA_REVIEWED[f] !== n);
  const gone = Object.keys(BTOA_REVIEWED).filter((f) => btoaCounts[f] === undefined);
  ok(
    `every btoa call in src/ is a reviewed site with its proof here${unreviewed.length || gone.length ? ` (unreviewed: ${unreviewed.map(([f, n]) => `${f} x${n}`).join(", ") || "none"}; listed but gone: ${gone.join(", ") || "none"})` : ""}`,
    unreviewed.length === 0 && gone.length === 0,
  );
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
  testEveryBytePaths();

  // -----------------------------------------------------------------------
  // results
  // -----------------------------------------------------------------------
  console.log(failures === 0 ? "\nBYTES TESTS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
