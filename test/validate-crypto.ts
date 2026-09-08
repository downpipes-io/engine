// Cross-implementation validator: reproduce the Go reference's deterministic crypto
// vectors with the TypeScript port and Web Crypto alone (no dependencies). Run with
// `node test/validate-crypto.ts`. This is the proof that the engine's crypto/format port
// is byte-compatible with the downpipe reference before the post-quantum library is
// wired in.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  b64urlEncode,
  b64urlDecode,
  hexEncode,
  hexDecode,
  concat,
  lpAppend,
  u32be,
  u64be,
  constantTimeEqual,
  utf8,
} from "../src/crypto/bytes.ts";
import { hybridKEMCombine } from "../src/crypto/combiner.ts";
import { x25519Ephemeral, x25519SharedSecret } from "../src/crypto/x25519.ts";
import {
  deriveCAK,
  segID,
  deriveNonSecretFileKey,
  deriveSecretsFileKey,
  deriveMK,
  deriveNameMACKey,
  deriveManifestWrapKey,
  nameMAC,
  keyCommitment,
  payloadKey,
} from "../src/crypto/derive.ts";
import { sealStream, openStream } from "../src/crypto/stream.ts";
import { ADDR_SINGLE_NON_SECRET, ADDR_PACKED, ADDR_SECRETS, CODEC_NONE, CODEC_GZIP } from "../src/format/version.ts";
import { decodeULID } from "../src/format/ulid.ts";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = join(here, "vectors");

// Every KAT field this suite reads is a string (b64url, hex, or a textual id), so the parsed vector
// is a string-keyed map. Typing it as such removes the `any` escape hatch and keeps a missing or
// misspelled vector key a compile-time error at every call site.
// A KAT is read as a field accessor that returns string (never undefined): a missing field is a
// broken/incomplete vector, so it fails loudly rather than flowing an undefined into a crypto call.
// This keeps every call site reading a plain string under noUncheckedIndexedAccess.
type Kat = (field: string) => string;
function readKAT(name: string): Kat {
  const raw = JSON.parse(readFileSync(join(vectors, name, "kat.json"), "utf8")) as Record<string, string>;
  return (field: string): string => {
    const v = raw[field];
    if (v === undefined) throw new Error(`KAT ${name} is missing field ${field}`);
    return v;
  };
}

let failures = 0;
function check(label: string, got: string, want: string): void {
  if (got === want) {
    console.log(`  ok   ${label}`);
  } else {
    failures++;
    console.log(`  FAIL ${label}\n        got  ${got}\n        want ${want}`);
  }
}

// ok asserts a boolean condition (used by the byte-helper known-answers and the key-tree
// binding checks below, which assert a property rather than a string equality).
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// rejectsWith asserts that fn throws AND the thrown message carries a substring. Asserting the
// message, not just that something threw, pins the SPECIFIC guard that fired: a blanked message
// or a redundant later guard taking over (a different message) is then a detectable change, which
// a bare throw/no-throw check could not see.
function rejectsWith(label: string, fn: () => unknown, sub: string): void {
  let msg = "(no throw)";
  try {
    fn();
  } catch (e) {
    msg = e instanceof Error ? e.message : String(e);
  }
  const pass = msg !== "(no throw)" && msg.includes(sub);
  ok(`${label} (message contains ${JSON.stringify(sub)})`, pass);
  if (!pass) console.log(`        got ${JSON.stringify(msg)}`);
}

const arr = (b: Uint8Array): string => Array.from(b).join(",");

// ---------------------------------------------------------------------------------------
// Byte-helper known answers (SPEC 11.4, 11.8) and length-prefixed concatenation (SPEC 7.4).
// The property suite (test/property/property-crypto-format.ts) round-trips these; these are the
// fixed reference encodings so a single-sided encode or decode defect, or a flipped boundary, is
// caught even where a round-trip would still close. base64url is Go's RawURLEncoding (alphabet
// A-Z a-z 0-9 - _, no padding), so the - and _ characters (alphabet indices 62 and 63) and the
// three remainder cases (0, 1, 2 trailing bytes) are each pinned.
// ---------------------------------------------------------------------------------------
function byteHelperKnownAnswers(): void {
  console.log("\nbyte-helper known answers:");
  // base64url encode across the three remainder cases and the - / _ alphabet positions.
  check("b64url encode [0,0,0] (rem 0)", b64urlEncode(new Uint8Array([0, 0, 0])), "AAAA");
  check("b64url encode [0] (rem 1)", b64urlEncode(new Uint8Array([0])), "AA");
  check("b64url encode [0,0] (rem 2)", b64urlEncode(new Uint8Array([0, 0])), "AAA");
  check("b64url encode 'Man' (rem 0)", b64urlEncode(utf8("Man")), "TWFu");
  check("b64url encode 'Ma' (rem 2)", b64urlEncode(utf8("Ma")), "TWE");
  check("b64url encode 'M' (rem 1)", b64urlEncode(utf8("M")), "TQ");
  check("b64url encode [255,255,255] is ____", b64urlEncode(new Uint8Array([255, 255, 255])), "____");
  check("b64url encode [0xfb,0xff] uses - and _", b64urlEncode(new Uint8Array([0xfb, 0xff])), "-_8");
  check("b64url encode [0xf8] hits alphabet index 62 (-)", b64urlEncode(new Uint8Array([0xf8])), "-A");
  check("b64url encode [0xfc] hits alphabet index 63 (_)", b64urlEncode(new Uint8Array([0xfc])), "_A");

  // base64url decode known answers and every rejection branch (length mod 4 == 1, non-canonical
  // trailing bits, an out-of-alphabet character, and a code point above the 7-bit ASCII range).
  check("b64url decode 'AQ' -> [1]", arr(b64urlDecode("AQ")), "1");
  check("b64url decode '' -> []", arr(b64urlDecode("")), "");
  check("b64url decode 'AAAA' -> [0,0,0]", arr(b64urlDecode("AAAA")), "0,0,0");
  rejectsWith("b64url decode rejects length mod 4 == 1 ('A')", () => b64urlDecode("A"), "length mod 4");
  rejectsWith("b64url decode rejects length 5 (mod 4 == 1)", () => b64urlDecode("AAAAA"), "length mod 4");
  rejectsWith("b64url decode rejects non-canonical trailing bits ('AB')", () => b64urlDecode("AB"), "non-canonical trailing bits");
  rejectsWith("b64url decode rejects non-canonical trailing bits ('-_')", () => b64urlDecode("-_"), "non-canonical trailing bits");
  rejectsWith("b64url decode rejects '+' (not in the URL-safe alphabet)", () => b64urlDecode("A+"), "invalid base64url character");
  rejectsWith("b64url decode rejects '/' (not in the URL-safe alphabet)", () => b64urlDecode("A/"), "invalid base64url character");
  rejectsWith("b64url decode rejects '=' padding", () => b64urlDecode("A="), "invalid base64url character");
  rejectsWith("b64url decode rejects a non-ASCII code point", () => b64urlDecode("AĀ"), "invalid base64url character");

  // hex encode/decode known answers and the odd-length rejection.
  check("hex encode [0,1,15,16,255]", hexEncode(new Uint8Array([0, 1, 15, 16, 255])), "00010f10ff");
  check("hex decode '00010f10ff'", arr(hexDecode("00010f10ff")), "0,1,15,16,255");
  rejectsWith("hex decode rejects an odd-length string", () => hexDecode("abc"), "odd-length hex");

  // concat preserves order across empty parts; the big-endian integer encoders pin byte order.
  check("concat keeps order across an empty part", arr(concat(new Uint8Array([1, 2]), new Uint8Array([3]), new Uint8Array(0), new Uint8Array([4, 5]))), "1,2,3,4,5");
  check("u32be 1 is big-endian", arr(u32be(1)), "0,0,0,1");
  check("u32be 0x01020304 is big-endian", arr(u32be(0x01020304)), "1,2,3,4");
  check("u32be 4294967295 is all ones", arr(u32be(4294967295)), "255,255,255,255");
  check("u64be 1 is big-endian", arr(u64be(1n)), "0,0,0,0,0,0,0,1");
  check("u64be 0x0102030405060708 is big-endian", arr(u64be(0x0102030405060708n)), "1,2,3,4,5,6,7,8");

  // lpAppend writes a one-byte length prefix then the field, and rejects a field over 255 bytes
  // (it cannot be length-prefixed in one byte). The 255/256 pair pins the exact boundary.
  check("lpAppend writes the one-byte length then the field", arr(lpAppend(new Uint8Array([9, 9]), new Uint8Array([7, 7, 7]))), "9,9,3,7,7,7");
  check("lpAppend on an empty field writes a zero length byte", arr(lpAppend(new Uint8Array([1]), new Uint8Array(0))), "1,0");
  ok("lpAppend accepts a 255-byte field (the boundary)", lpAppend(new Uint8Array(0), new Uint8Array(255)).length === 256);
  rejectsWith("lpAppend rejects a 256-byte field", () => lpAppend(new Uint8Array(0), new Uint8Array(256)), "exceeds 255 bytes");

  // constantTimeEqual: equal, a first-byte difference, a last-byte difference, a length mismatch,
  // and the empty/empty case. A difference at either end must register, not just one end.
  ok("constantTimeEqual: equal arrays are equal", constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])) === true);
  ok("constantTimeEqual: a first-byte difference is unequal", constantTimeEqual(new Uint8Array([9, 2, 3]), new Uint8Array([1, 2, 3])) === false);
  ok("constantTimeEqual: a last-byte difference is unequal", constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])) === false);
  ok("constantTimeEqual: a length mismatch is unequal", constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3])) === false);
  ok("constantTimeEqual: empty against empty is equal", constantTimeEqual(new Uint8Array(0), new Uint8Array(0)) === true);
}

// ---------------------------------------------------------------------------------------
// Key-tree binding (SPEC 7.2, 7.4, 6.3, 6.4, 8.4, 11.7, 7.8). The crypto-kat vector below pins
// the absolute output of deriveCAK/segID/deriveNonSecretFileKey/keyCommitment; these
// differential checks additionally pin that EACH declared input is actually mixed into the
// derivation, and that the helper functions the wired reader exercises only transitively
// (deriveSecretsFileKey, deriveMK, deriveNameMACKey, deriveManifestWrapKey, nameMAC, payloadKey)
// bind their inputs. A mutation that drops a length-prefixed context field, the secrets-class
// salt, the codec byte, the keyed-name separator, or swaps an HKDF salt for info would leave the
// output unchanged for some input and is caught here. The recordSalt is mixed only for the
// secrets address class (SPEC 7.2), so the non-secret address must IGNORE it while the secrets
// address must DEPEND on it; both directions are asserted.
// ---------------------------------------------------------------------------------------
async function keyTreeBinding(): Promise<void> {
  console.log("\nkey-tree input binding:");
  const master = new Uint8Array(32).fill(7);
  const masterB = new Uint8Array(32).fill(8);
  const seg = new Uint8Array(48).map((_, i) => i & 0xff);
  const segB = new Uint8Array(48).fill(1);
  const runId = new Uint8Array(16).fill(3);
  const runIdB = new Uint8Array(16).fill(4);
  const salt = new Uint8Array(16).fill(5);
  const saltB = new Uint8Array(16).fill(9);
  const recId = utf8("0123456789abcdef");
  const recIdB = utf8("ABCDEFGHIJKLMNOP");

  // segID (SPEC 7.2): 48 bytes; the class byte and (for secrets only) the record salt are mixed.
  const cak = await deriveCAK(master, "dp");
  const segNonSecret = await segID(cak, ADDR_SINGLE_NON_SECRET, salt, utf8("plain"));
  const segSecret = await segID(cak, ADDR_SECRETS, salt, utf8("plain"));
  ok("segID is 48 bytes", segNonSecret.length === 48);
  ok("segID binds the address class byte (non-secret != secret)", hexEncode(segNonSecret) !== hexEncode(segSecret));
  ok("segID binds the address class byte (non-secret != packed)", hexEncode(segNonSecret) !== hexEncode(await segID(cak, ADDR_PACKED, salt, utf8("plain"))));
  ok("segID for the secrets class binds the record salt", hexEncode(segSecret) !== hexEncode(await segID(cak, ADDR_SECRETS, saltB, utf8("plain"))));
  ok("segID for a non-secret class ignores the record salt", hexEncode(segNonSecret) === hexEncode(await segID(cak, ADDR_SINGLE_NON_SECRET, saltB, utf8("plain"))));

  // deriveNonSecretFileKey (SPEC 7.4): 32 bytes; binds master, segId and the codec byte.
  const fkNone = await deriveNonSecretFileKey(master, seg, CODEC_NONE);
  const fkGzip = await deriveNonSecretFileKey(master, seg, CODEC_GZIP);
  ok("non-secret file key is 32 bytes", fkNone.length === 32);
  ok("non-secret file key binds the codec byte", hexEncode(fkNone) !== hexEncode(fkGzip));
  ok("non-secret file key binds the master", hexEncode(fkNone) !== hexEncode(await deriveNonSecretFileKey(masterB, seg, CODEC_NONE)));
  ok("non-secret file key binds the segment id", hexEncode(fkNone) !== hexEncode(await deriveNonSecretFileKey(master, segB, CODEC_NONE)));

  // deriveSecretsFileKey (SPEC 7.4): 32 bytes; binds the run, record id and salt so a secret is
  // never deduplicated across runs, and differs from the non-secret key for the same segment.
  const sfk = await deriveSecretsFileKey({ master, segIDBytes: seg, recordID: recId, recordSalt: salt, runIDBytes: runId });
  ok("secrets file key is 32 bytes", sfk.length === 32);
  ok("secrets file key binds the run id", hexEncode(sfk) !== hexEncode(await deriveSecretsFileKey({ master, segIDBytes: seg, recordID: recId, recordSalt: salt, runIDBytes: runIdB })));
  ok("secrets file key binds the record id", hexEncode(sfk) !== hexEncode(await deriveSecretsFileKey({ master, segIDBytes: seg, recordID: recIdB, recordSalt: salt, runIDBytes: runId })));
  ok("secrets file key binds the record salt", hexEncode(sfk) !== hexEncode(await deriveSecretsFileKey({ master, segIDBytes: seg, recordID: recId, recordSalt: saltB, runIDBytes: runId })));
  ok("secrets file key differs from the non-secret file key for the same segment", hexEncode(sfk) !== hexEncode(fkNone));

  // deriveMK / deriveNameMACKey / deriveManifestWrapKey (SPEC 11.7, 6.4, 6.3): each is 32 bytes
  // and binds the run id; the wrap key additionally binds the shard id; the name-MAC key is not
  // the manifest subkey it is derived from.
  const mk = await deriveMK(master, runId);
  ok("manifest subkey is 32 bytes", mk.length === 32);
  ok("manifest subkey binds the run id", hexEncode(mk) !== hexEncode(await deriveMK(master, runIdB)));
  const nmk = await deriveNameMACKey(mk, runId);
  ok("name-MAC key is 32 bytes", nmk.length === 32);
  ok("name-MAC key binds the run id", hexEncode(nmk) !== hexEncode(await deriveNameMACKey(mk, runIdB)));
  ok("name-MAC key is not the manifest subkey it derives from", hexEncode(nmk) !== hexEncode(mk));
  const wrap = await deriveManifestWrapKey(mk, runId, "00000");
  ok("manifest-wrap key is 32 bytes", wrap.length === 32);
  ok("manifest-wrap key binds the shard id", hexEncode(wrap) !== hexEncode(await deriveManifestWrapKey(mk, runId, "00001")));
  ok("manifest-wrap key binds the run id", hexEncode(wrap) !== hexEncode(await deriveManifestWrapKey(mk, runIdB, "00000")));

  // nameMAC (SPEC 6.4): 48 bytes; binds the source type and name, and the 0x00 separator prevents
  // a concatenation ambiguity, so ("a","bc") and ("ab","c") must not collide.
  const nm = await nameMAC(nmk, "kv", "k");
  ok("name MAC is 48 bytes", nm.length === 48);
  ok("name MAC binds the source type", hexEncode(nm) !== hexEncode(await nameMAC(nmk, "r2", "k")));
  ok("name MAC binds the name", hexEncode(nm) !== hexEncode(await nameMAC(nmk, "kv", "k2")));
  ok("name MAC keeps the 0x00 separator (a,bc) != (ab,c)", hexEncode(await nameMAC(nmk, "a", "bc")) !== hexEncode(await nameMAC(nmk, "ab", "c")));

  // keyCommitment (SPEC 8.4): 48 bytes; binds the master and the run id.
  const kc = await keyCommitment(master, runId);
  ok("key commitment is 48 bytes", kc.length === 48);
  ok("key commitment binds the master", hexEncode(kc) !== hexEncode(await keyCommitment(masterB, runId)));
  ok("key commitment binds the run id", hexEncode(kc) !== hexEncode(await keyCommitment(master, runIdB)));

  // payloadKey (SPEC 7.8): 32 bytes; binds the file key and the payload nonce (the HKDF salt).
  const pk = await payloadKey(fkNone, new Uint8Array(16).fill(1));
  ok("payload key is 32 bytes", pk.length === 32);
  ok("payload key binds the payload nonce", hexEncode(pk) !== hexEncode(await payloadKey(fkNone, new Uint8Array(16).fill(2))));
  ok("payload key binds the file key", hexEncode(pk) !== hexEncode(await payloadKey(fkGzip, new Uint8Array(16).fill(1))));
}

// x25519Contributory exercises the SPEC 4.1 contributory-abort property of x25519SharedSecret: a
// normal ECDH round-trip agrees on the same secret, and an all-zero peer public key (a low-order
// point) must be rejected. The rejection may surface either from the underlying X25519 library (which
// rejects the low-order point outright) or from our own all-zero shared-secret guard when a library
// instead returns an all-zero result; both satisfy the contributory abort, so the test asserts that
// the call throws (the security property) rather than pinning one specific message.
function x25519Contributory(): void {
  const a = x25519Ephemeral();
  const b = x25519Ephemeral();
  const ssA = x25519SharedSecret(a.scalar, b.publicKey);
  const ssB = x25519SharedSecret(b.scalar, a.publicKey);
  ok("x25519 ECDH round-trip agrees", arr(ssA) === arr(ssB));
  let threw = false;
  try {
    x25519SharedSecret(a.scalar, new Uint8Array(32));
  } catch {
    threw = true;
  }
  ok("x25519 rejects an all-zero (low-order) peer public key", threw);
}

async function main(): Promise<void> {
  console.log("kem-combiner-kat:");
  const k = readKAT("kem-combiner-kat");
  const combine = await hybridKEMCombine(b64urlDecode(k("ssM")), b64urlDecode(k("ssX")), b64urlDecode(k("ctX")), b64urlDecode(k("pkX")));
  check("combiner output", b64urlEncode(combine), k("output"));

  console.log("crypto-kat:");
  const c = readKAT("crypto-kat");
  const master = b64urlDecode(c("master"));
  const plaintext = b64urlDecode(c("plaintext"));
  const nonce = b64urlDecode(c("payloadNonce"));
  const runIDBytes = decodeULID(c("runId"));

  const cak = await deriveCAK(master, c("downpipeId"));
  check("CAK", b64urlEncode(cak), c("cak"));

  const seg = await segID(cak, ADDR_SINGLE_NON_SECRET, new Uint8Array(0), plaintext);
  check("segId", hexEncode(seg), c("segIdHex"));

  const fileKey = await deriveNonSecretFileKey(master, seg, CODEC_NONE);
  check("fileKey", b64urlEncode(fileKey), c("fileKey"));

  const kc = await keyCommitment(master, runIDBytes);
  check("keyCommitment", hexEncode(kc), c("keyCommitment"));

  const body = await sealStream(fileKey, plaintext, nonce);
  check("STREAM body", b64urlEncode(body), c("streamBody"));

  // Round-trip: open what we sealed and confirm the plaintext.
  const reopened = await openStream(fileKey, body);
  check("STREAM round-trip", b64urlEncode(reopened), b64urlEncode(plaintext));

  // And open the Go-sealed body to prove cross-implementation decryption.
  const fromGo = await openStream(fileKey, b64urlDecode(c("streamBody")));
  check("open Go-sealed body", b64urlEncode(fromGo), b64urlEncode(plaintext));

  // The byte helpers and the key-tree input-binding checks, additive to the absolute vectors
  // above (they pin the reference outputs; these pin the encodings' boundaries and that every
  // declared input is actually mixed into each derivation).
  byteHelperKnownAnswers();
  x25519Contributory();
  await keyTreeBinding();

  console.log(failures === 0 ? "\nALL CRYPTO VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
