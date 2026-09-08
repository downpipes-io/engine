// Dedicated unit tests for the four downpipe/0.1.0 format primitives and the recovery
// bundle, mirroring the Go reference *_test.go files that the TS port did not previously
// have an equivalent for. The wired vector harness (validate-reader.ts)
// only exercises these primitives transitively against Go-generated CANONICAL vectors, so
// the divergence/negative paths and the engine's own bundle write->verify round-trip were
// uncovered. This suite drives the real production code in src/format/* directly with
// known-answer tests and negative controls, so it fails if any of those divergences return.
//
// Covered:
//   canonjson  - object keys sorted by UTF-16 code unit (including a supplementary key whose
//                code point would sort differently), arrays kept in order, nested objects,
//                integers stringified, and floats/unsafe integers/raw bytes rejected.
//   canonnum   - a dotted path resolved STRUCTURALLY (not by a substring scan), so a leaf-name
//                collision neither false-rejects nor masks an out-of-range real value; plus
//                the range/canonicality rejections (string form, over-ceiling, fractional,
//                negative, negative-zero).
//   merkle     - the RFC 6962 / SHA-384 root for a known 2-leaf and a known 3-leaf (odd-node
//                promotion) input, with the single-leaf and empty-tree edges, cross-checked
//                against an independent recomputation so the KATs are not tautological.
//   ulid       - a canonical ULID round-trips, and the over-128-bit first character is
//                rejected (the silent-truncation divergence the Go reader refuses).
//   bundle     - addBundle then verifyBundle succeeds (the engine's OWN bundle verifies
//                clean), and a one-byte tamper of a bundled file fails verification.
//
// Run: node test/validate-format-prims.ts

import { canonicalJSON } from "../src/format/canonjson.ts";
import { validateCanonicalCounts } from "../src/format/canonnum.ts";
import { merkleRoot } from "../src/format/merkle.ts";
import { decodeULID } from "../src/format/ulid.ts";
import { addBundle, verifyBundle, BUNDLE_PREFIX, type ObjectStoreReader } from "../src/format/bundle.ts";
import { Run, type ObjectStore } from "../src/format/reader.ts";
import { buildArchive, signerFingerprint, type Signer } from "../src/format/writer.ts";
import { sealNonSecretSegment } from "../src/crypto/segment.ts";
import { CODEC_NONE, VERSION } from "../src/format/version.ts";
import type { RootManifest, ShardRecord } from "../src/format/manifest.ts";
import { x25519 } from "@noble/curves/ed25519.js";
import { sha384 } from "../src/crypto/primitives.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import { concat, hexEncode, utf8 } from "../src/crypto/bytes.ts";
import type { HybridVerifier } from "../src/crypto/sign.ts";

let failures = 0;

function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// eq asserts a string value matches an expected literal, printing both on mismatch so a
// drift is diagnosable from the test output alone.
function eq(label: string, got: string, want: string): void {
  const pass = got === want;
  console.log(pass ? `  ok   ${label}` : `  FAIL ${label}\n        got  ${got}\n        want ${want}`);
  if (!pass) failures++;
}

// rejects asserts that fn throws; the divergence paths are all "must reject", so a swallowed
// or absent throw is a real regression, not cosmetic.
function rejects(label: string, fn: () => unknown): void {
  let threw = false;
  try {
    fn();
  } catch {
    threw = true;
  }
  ok(label, threw);
}

// rejectsWith asserts that fn throws AND the thrown message carries a substring. Pinning the
// message identifies the SPECIFIC guard that fired: a guard whose throw is removed (so a later,
// redundant guard catches the same input with a different message) or whose message is blanked
// is then a detectable change that a bare throw/no-throw check could not see.
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

// accepts asserts that fn does NOT throw (a canonical value passes the gate).
function accepts(label: string, fn: () => unknown): void {
  let threw = false;
  try {
    fn();
  } catch {
    threw = true;
  }
  ok(label, !threw);
}

async function rejectsAsync(label: string, fn: () => Promise<unknown>): Promise<void> {
  let threw = false;
  try {
    await fn();
  } catch {
    threw = true;
  }
  ok(label, threw);
}

async function acceptsAsync(label: string, fn: () => Promise<unknown>): Promise<void> {
  let threw = false;
  try {
    await fn();
  } catch {
    threw = true;
  }
  ok(label, !threw);
}

function str(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

// ---------------------------------------------------------------------------------------
// canonjson (SPEC 11.1): keys sorted by UTF-16 code unit, arrays in order, integers only,
// no insignificant whitespace, no HTML escaping. Mirrors canonjson_test.go.
// ---------------------------------------------------------------------------------------

// Nested object with unsorted keys at two levels, an array that must keep its given order,
// and a non-ASCII key. The expected bytes were derived from canonicalJSON and confirmed by
// hand: keys at each level are ordered A(0x41) < a(0x61) < b(0x62) < e-acute(0xE9), the
// inner object is recursively sorted (c < d), and [3,1,2] is NOT reordered.
eq(
  "canonjson sorts nested keys by UTF-16 unit and keeps array order",
  str(canonicalJSON({ b: 1, a: { d: 2, c: [3, 1, 2] }, "é": 4, A: 5 })),
  '{"A":5,"a":{"c":[3,1,2],"d":2},"b":1,"é":4}',
);

// THE UTF-16-vs-code-point distinction, the divergence canonjson_test.go's UTF16KeyOrder
// pins. A supplementary key (U+1F600, the surrogate pair D83D DE00) sorts by its FIRST
// UTF-16 code unit 0xD83D, which is ABOVE "~" (0x7E) but BELOW U+FFFF (0xFFFF). If the sort
// used Unicode code points instead of UTF-16 units, U+1F600 (code point 0x1F600) would sort
// AFTER U+FFFF, giving a different key order and a different signed byte string. The order
// "~", emoji, U+FFFF proves UTF-16 code-unit ordering (matching Go's lessUTF16).
eq(
  "canonjson orders a supplementary key by its UTF-16 code unit, not its code point",
  str(canonicalJSON({ "\u{1F600}": 1, "￿": 2, "~": 3 })),
  '{"~":3,"\u{1F600}":1,"￿":2}',
);

// Integers are emitted bare; the canonical form carries no insignificant whitespace.
eq("canonjson emits integers without whitespace", str(canonicalJSON({ n: 318, z: 0, neg: -3 })), '{"n":318,"neg":-3,"z":0}');

// JSON.stringify does not HTML-escape; canonical JSON must keep < > & literal, matching the
// Go reference's no-HTML-escape encoder.
eq("canonjson does not HTML-escape", str(canonicalJSON({ k: "<a>&b</a>" })), '{"k":"<a>&b</a>"}');

// Negative controls: a fractional number, an unsafe integer above the 2^53-1 ceiling, and
// raw bytes (which must be base64url-encoded to a string first) are all rejected, mirroring
// canonjson_test.go RejectsFloat.
rejects("canonjson rejects a fractional number", () => canonicalJSON({ n: 1.5 }));
rejects("canonjson rejects an integer above 2^53-1", () => canonicalJSON({ n: Number.MAX_SAFE_INTEGER + 2 }));
rejects("canonjson rejects raw bytes (must be base64url first)", () => canonicalJSON({ b: new Uint8Array([1, 2, 3]) }));
rejects("canonjson rejects a non-finite number", () => canonicalJSON({ n: Infinity }));

// Invalid UTF-8 / lone surrogates. A string carrying an unpaired surrogate has no
// valid UTF-8 encoding, so the Go reference (canonjson.go, utf8.ValidString) refuses to
// canonicalise it rather than let JSON.stringify emit an escaped \uD8xx and silently disagree
// on the signed bytes. These cases fail if that divergence returns. \uD800 is a lone high
// surrogate; \uDC00 a lone low surrogate; a high surrogate not followed by a low one is also
// lone. The rejection must apply to a string VALUE and to an object KEY, since both are signed.
rejects("canonjson rejects a lone high surrogate (U+D800) value", () => canonicalJSON({ k: "\uD800" }));
rejects("canonjson rejects a lone low surrogate (U+DC00) value", () => canonicalJSON({ k: "\uDC00" }));
rejects("canonjson rejects a high surrogate followed by a non-low unit", () => canonicalJSON({ k: "\uD83Dx" }));
rejects("canonjson rejects a lone surrogate buried mid-string", () => canonicalJSON({ k: "ok-\uDFFF-tail" }));
rejects("canonjson rejects a lone surrogate in an object KEY", () => canonicalJSON({ "\uD800": 1 }));

// A WELL-FORMED surrogate pair is a valid supplementary code point (here U+1F600, the pair
// D83D DE00) and must still be accepted and emitted unescaped as its UTF-8 bytes, so the
// rejection does not over-reach and break a legitimate emoji name. A literal U+FFFD
// (REPLACEMENT CHARACTER) is itself valid UTF-8 and must be accepted, proving the gate keys
// off lone surrogates and not off the presence of U+FFFD.
eq("canonjson accepts a well-formed surrogate pair (U+1F600)", str(canonicalJSON({ k: "\u{1F600}" })), '{"k":"\u{1F600}"}');
eq("canonjson accepts a literal U+FFFD (valid UTF-8)", str(canonicalJSON({ k: "�" })), '{"k":"�"}');

// The three scalar forms each have one canonical spelling: a boolean is "true"/"false", null is
// "null". A serialiser that collapsed false to the empty string, or routed a scalar through the
// object branch, would change the signed bytes and is caught here.
eq("canonjson serialises false as the literal false", str(canonicalJSON(false)), "false");
eq("canonjson serialises true as the literal true", str(canonicalJSON(true)), "true");
eq("canonjson serialises null as the literal null", str(canonicalJSON(null)), "null");
eq("canonjson serialises the three scalars inside an object", str(canonicalJSON({ a: true, b: false, c: null })), '{"a":true,"b":false,"c":null}');
eq("canonjson keeps array element order with the scalars", str(canonicalJSON([true, false, null])), "[true,false,null]");

// The surrogate gate at its exact range edges (canonjson.go hasLoneSurrogate). A high surrogate
// at the top of its range (U+DBFF) is still a high surrogate, so unpaired it must reject. A
// well-formed pair whose low half sits at either end of the low-surrogate range (U+DC00 or
// U+DFFF) is a valid supplementary code point and must be accepted. A high surrogate followed by
// a non-surrogate code point ABOVE the low-surrogate range (U+E000) is unpaired and must reject.
// These pin the <= / < boundaries that a bare lone-surrogate case would not move.
rejects("canonjson rejects a lone high surrogate at the top of the range (U+DBFF)", () => canonicalJSON({ k: String.fromCharCode(0xdbff) }));
accepts("canonjson accepts a pair whose low half is U+DC00 (range start)", () => canonicalJSON({ k: String.fromCharCode(0xd83d, 0xdc00) }));
accepts("canonjson accepts a pair whose low half is U+DFFF (range end)", () => canonicalJSON({ k: String.fromCharCode(0xd83d, 0xdfff) }));
rejects("canonjson rejects a high surrogate followed by U+E000 (above the low range)", () => canonicalJSON({ k: String.fromCharCode(0xd83d, 0xe000) }));

// Each canonjson rejection carries its own diagnostic. Asserting the message (not just that a
// throw happened) pins which guard fired: the lone-surrogate, non-integer, over-ceiling, raw-byte
// and unsupported-type rejections each have a distinct reason, and a non-integer must be caught by
// the integer guard (its message), not masked by the later safe-integer guard.
rejectsWith("canonjson lone-surrogate reason", () => canonicalJSON({ k: "\uD800" }), "lone surrogate");
rejectsWith("canonjson non-integer reason (not masked by the ceiling guard)", () => canonicalJSON({ n: 1.5 }), "non-integer number");
rejectsWith("canonjson over-ceiling reason", () => canonicalJSON({ n: Number.MAX_SAFE_INTEGER + 2 }), "exceeds the 2^53-1");
rejectsWith("canonjson raw-bytes reason", () => canonicalJSON({ b: new Uint8Array([1, 2, 3]) }), "base64url-encoded");
rejectsWith("canonjson unsupported-type reason (a function)", () => canonicalJSON((() => {}) as unknown), "unsupported value");
rejectsWith("canonjson unsupported-type reason (a bigint)", () => canonicalJSON(1n as unknown), "unsupported value");

// ---------------------------------------------------------------------------------------
// canonnum (SPEC 11.3): a dotted path is resolved STRUCTURALLY through the parsed object
// (Go resolvePath), not by scanning the source text for the leaf name. A
// substring scan that resolves the wrong field on a leaf-name collision must not regress; these cases fail
// if that shape returns. Field range/canonicality is also asserted here.
// ---------------------------------------------------------------------------------------

// A dotted path resolves the deep field, not a same-named sibling. The text scan would have
// hit the FIRST textual "runlogIndex" (the decoy under "x").
accepts(
  "canonnum resolves a dotted path structurally, not by leaf-name substring",
  () => validateCanonicalCounts('{"x":{"runlogIndex":"99"},"freshness":{"runlogIndex":3}}', "freshness.runlogIndex"),
);

// Masking direction: a benign decoy with the same leaf name must NOT mask an out-of-range
// real value at the requested path. The substring scan would read the benign meta.shardCount
// first and pass, letting an archive Go rejects through.
rejects(
  "canonnum does not let a benign decoy mask an over-ceiling target",
  () => validateCanonicalCounts('{"meta":{"shardCount":1},"shardCount":9007199254740993}', "shardCount"),
);
rejects(
  "canonnum does not let a benign decoy mask a string-form target",
  () => validateCanonicalCounts('{"x":{"runlogIndex":3},"freshness":{"runlogIndex":"7"}}', "freshness.runlogIndex"),
);

// A path through a missing nested object is permitted (missing field is allowed); it must
// NOT fall through to a same-named top-level value.
accepts(
  "canonnum treats a missing nested path as permitted, not matched at the top level",
  () => validateCanonicalCounts('{"runlogIndex":"99"}', "freshness.runlogIndex"),
);

// Range / canonicality of a single resolved value (parity with checkCanonicalCount).
accepts("canonnum accepts a canonical integer", () => validateCanonicalCounts('{"n":318}', "n"));
accepts("canonnum accepts zero", () => validateCanonicalCounts('{"n":0}', "n"));
accepts("canonnum accepts the 2^53-1 ceiling", () => validateCanonicalCounts(`{"n":${2 ** 53 - 1}}`, "n"));
accepts("canonnum permits a missing field", () => validateCanonicalCounts('{"other":1}', "n"));
rejects("canonnum rejects an in-range value carried as a string", () => validateCanonicalCounts('{"n":"318"}', "n"));
rejects("canonnum rejects an over-ceiling number (2^53)", () => validateCanonicalCounts('{"n":9007199254740993}', "n"));
rejects("canonnum rejects a fractional number", () => validateCanonicalCounts('{"n":1.5}', "n"));
rejects("canonnum rejects the exponent token 1e400 (-> Infinity)", () => validateCanonicalCounts('{"n":1e400}', "n"));
rejects("canonnum rejects a negative number", () => validateCanonicalCounts('{"n":-3}', "n"));
rejects("canonnum rejects negative zero", () => validateCanonicalCounts('{"n":-0}', "n"));

// ---------------------------------------------------------------------------------------
// merkle (SPEC 11.8): RFC 6962 over SHA-384. leaf = SHA-384(0x00 || recordHash),
// node = SHA-384(0x01 || left || right), an odd node promoted unchanged, the empty tree the
// SHA-384 of the empty string. The KATs below are cross-checked against an independent
// recomputation in the same test so a copy-paste hash does not lock in the implementation's
// own output (mirrors merkle_test.go empty/single/order/determinism).
// ---------------------------------------------------------------------------------------
async function merkleTests(): Promise<void> {
  // Deterministic record-hashes: SHA-384("leaf0"), SHA-384("leaf1"), SHA-384("leaf2").
  const rh = async (s: string) => sha384(utf8(s));
  const h0 = await rh("leaf0");
  const h1 = await rh("leaf1");
  const h2 = await rh("leaf2");

  // Independent leaf and node hashing for the cross-check.
  const leaf = (rh0: Uint8Array) => sha384(concat(new Uint8Array([0x00]), rh0));
  const node = (l: Uint8Array, r: Uint8Array) => sha384(concat(new Uint8Array([0x01]), l, r));
  const L0 = await leaf(h0);
  const L1 = await leaf(h1);
  const L2 = await leaf(h2);

  // 2-leaf: root = node(L0, L1). Pinned KAT plus the independent recomputation.
  const root2 = await merkleRoot([h0, h1]);
  eq("merkle 2-leaf root matches the known answer", hexEncode(root2), "5dce44db1671eaebcefc746becc0acb6c0ab84d1d1957ec1965b768727a493ad9c778c16020d469a728c4127c978d93d");
  eq("merkle 2-leaf root matches an independent recomputation", hexEncode(root2), hexEncode(await node(L0, L1)));

  // 3-leaf (odd-node promotion): level0 = [L0, L1, L2]; level1 = [node(L0,L1), L2 promoted];
  // root = node(node(L0,L1), L2). The pinned KAT and the independent recomputation must agree.
  const root3 = await merkleRoot([h0, h1, h2]);
  eq("merkle 3-leaf root (odd-node promotion) matches the known answer", hexEncode(root3), "2e2f2ec32655a1aab38a76e0229519ad77100f937b88ed357794526c8d6ecd6a65225e53ed878c7c9d01b0bf372a09ce");
  eq("merkle 3-leaf root matches an independent recomputation", hexEncode(root3), hexEncode(await node(await node(L0, L1), L2)));

  // The 3-leaf root MUST differ from the 2-leaf root: a regression that dropped the promoted
  // odd leaf would collapse them. (Also a guard that the promotion actually folds L2 in.)
  ok("merkle 3-leaf root differs from the 2-leaf root", hexEncode(root3) !== hexEncode(root2));

  // The root is order-sensitive: swapping two leaves changes the root (node() is not
  // commutative). This is what binds record order into the signature.
  const swapped = await merkleRoot([h1, h0]);
  ok("merkle root is order-sensitive (swapping leaves changes the root)", hexEncode(swapped) !== hexEncode(root2));

  // Single leaf: the root is the leaf hash itself, with no node wrapping.
  const root1 = await merkleRoot([h0]);
  eq("merkle single-leaf root is the leaf hash, unwrapped", hexEncode(root1), hexEncode(L0));

  // Empty tree: the SHA-384 of the empty string.
  const rootEmpty = await merkleRoot([]);
  eq("merkle empty-tree root is SHA-384 of the empty string", hexEncode(rootEmpty), hexEncode(await sha384(new Uint8Array(0))));
}

// ---------------------------------------------------------------------------------------
// ulid (SPEC 11.6): Crockford base32, 26 chars, canonical, the 16-byte salt form. The
// over-128-bit first character must be rejected (the silent-truncation divergence the Go
// reader refuses); a canonical ULID round-trips. Mirrors ulid_test.go.
// ---------------------------------------------------------------------------------------

// A canonical ULID (first char '0', so the top 2 of the 130 decoded bits are clear) decodes
// to 16 bytes and re-encodes to the same string. The re-encode is done here from the
// CROCKFORD alphabet so the round-trip does not lean on the decoder under test.
function reencodeULID(b: Uint8Array): string {
  const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  let bits = 0n;
  for (const x of b) bits = (bits << 8n) | BigInt(x);
  let out = "";
  for (let i = 0; i < 26; i++) {
    out = (CROCKFORD[Number(bits & 0x1fn)] ?? "") + out;
    bits >>= 5n;
  }
  return out;
}

const CANONICAL_ULID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const decodedULID = decodeULID(CANONICAL_ULID);
ok("ulid decodes a canonical string to 16 bytes", decodedULID.length === 16);
eq("ulid round-trips a canonical string through decode", reencodeULID(decodedULID), CANONICAL_ULID);

// '7' + 25 'Z' is the largest value whose first char (value 7, binary 00111) keeps bit 128
// clear; it is accepted and its top byte is 0xff.
const maxValid = decodeULID("7" + "Z".repeat(25));
ok("ulid accepts the top value fitting 128 bits ('7' + 25 'Z')", maxValid.length === 16 && maxValid[0] === 0xff);

// Negative controls. First char '8' (value 8, binary 01000) sets bit 128; 'Z'*26 sets bits
// 128 and 129. Silently truncating would collapse distinct runId strings to the same salt,
// so both must throw (the divergence the Go reader refuses).
rejects("ulid rejects an over-128-bit first character ('8')", () => decodeULID("8" + "0".repeat(25)));
rejects("ulid rejects the maximum 130-bit value (26 x 'Z')", () => decodeULID("Z".repeat(26)));
// Length and alphabet are also enforced.
rejects("ulid rejects a wrong-length string", () => decodeULID("0".repeat(25)));
rejects("ulid rejects a non-Crockford character ('I')", () => decodeULID("0".repeat(25) + "I"));

// The three ulid rejections each carry their own diagnostic. Asserting the message pins which
// guard fired: a wrong length, an out-of-alphabet character, or the over-128-bit first character.
// The bad-character case is its own reason, not the overflow reason it would otherwise fall
// through to (an out-of-alphabet character decodes to -1, which left unchecked makes the bit
// accumulator negative and trips the overflow guard with a different message).
rejectsWith("ulid wrong-length reason", () => decodeULID("0".repeat(25)), "26 characters");
rejectsWith("ulid invalid-character reason (not the overflow reason)", () => decodeULID("0".repeat(25) + "I"), "invalid ULID character");
rejectsWith("ulid over-128-bit first character reason", () => decodeULID("8" + "0".repeat(25)), "overflows 128 bits");

// ---------------------------------------------------------------------------------------
// bundle (SPEC 9): the engine's OWN recovery bundle written by addBundle must pass its own
// verifyBundle (the success path the wired vectors never reach), and a one-byte tamper of a
// bundled file must fail. Mirrors bundle_test.go TestBundleWriteVerify.
// ---------------------------------------------------------------------------------------
async function bundleTests(): Promise<void> {
  // A real run signer: a Web Crypto Ed25519 key and an ML-DSA-87 keypair, used exactly as
  // buildArchive uses them, so the test drives the production addBundle/verifyBundle code.
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  const verifier: HybridVerifier = { ed: edPublic, mldsa: mldsa.publicKey };

  // Write the bundle into a map, exactly as buildArchive does.
  const out = new Map<string, Uint8Array>();
  await addBundle(out, ed.privateKey, mldsa.secretKey);

  // The bundle set the engine writes every run is present (the four objects under the
  // versioned prefix). If addBundle's file set drifts, these reads fail.
  ok("bundle writes FORMAT.md", out.has(`${BUNDLE_PREFIX}FORMAT.md`));

  // FORMAT.md is the only guidance a recoverer holding nothing but the bucket has about WHICH READER opens
  // these bytes, so the two halves of that answer are pinned. It must name the archive's own format version
  // (a fact about these bytes, true forever), and it must point at the format-to-release mapping instead of
  // naming a reader release (a claim about releases that did not exist at seal time, and one the two
  // released tags already contradict, their format coverage being disjoint and inverted by tag order).
  const formatMd = new TextDecoder().decode(out.get(`${BUNDLE_PREFIX}FORMAT.md`) as Uint8Array);
  ok("FORMAT.md names the archive's own format version", formatMd.includes(VERSION));
  ok("FORMAT.md points at the per-release format mapping rather than a reader version", formatMd.includes("CHANGELOG.md"));
  ok("FORMAT.md tells the recoverer to prove the binary against these bytes", formatMd.includes("running a verify against these bytes"));
  ok("FORMAT.md states that it names no minimum reader version", formatMd.includes("names no minimum reader version"));
  // NEGATIVE: it must not acquire a reader-release pin. Written as a pattern over release-number shapes so
  // it catches a future "requires downpipe v0.3.0" however it is worded.
  ok("FORMAT.md pins no reader RELEASE number", !/\bv\d+\.\d+\.\d+\b/.test(formatMd));
  ok("bundle writes RECOVER.md", out.has(`${BUNDLE_PREFIX}RECOVER.md`));
  ok("bundle writes SHA384SUMS", out.has(`${BUNDLE_PREFIX}SHA384SUMS`));
  ok("bundle writes the detached SHA384SUMS signature", out.has(`${BUNDLE_PREFIX}SHA384SUMS.sig`));

  // RECOVER.md is the document a customer reads mid-recovery with nothing else to go on, so what it
  // SAYS is asserted, not only that it exists. The custody claims are the ones worth pinning: a
  // break-glass key held as an M-of-N quorum is the posture this whole workstream is about, and a
  // RECOVER.md that mentions only --identity tells those customers their shares are no use, at the
  // worst possible moment. The offline tool carries its own copy of this text for its selftest (Go,
  // separate repo, and the bundle content is not normative because each archive verifies against the
  // SHA384SUMS written in the same run); the two are held in step by the matching assertion there.
  //
  // The last three claims were added with the two defects they stand for. `--apply`:
  // restore plans by default, so the headline line without it exited 0 having written nothing, and a
  // customer following their only instruction mid-disaster got no data. The two signer.pub sentences:
  // the prose named only the break-glass identity, while restore and verify BOTH hard-require --signer,
  // so an operator reading the prose alone builds a one-file kit that cannot recover. A claim check is
  // the weaker half here; the strong half is test/bundle-recover-commands.ts, which RUNS every line.
  const recoverMd = new TextDecoder().decode(out.get(`${BUNDLE_PREFIX}RECOVER.md`) as Uint8Array);
  for (const claim of [
    "downpipe restore",
    "--identity identity.key",
    "--share",
    "--envelope",
    "M-of-N",
    "no complete key is written to disk",
    "neither Cloudflare nor the vendor",
    "--apply",
    "Both restore and verify require --signer",
    "a kit holding only the identity cannot recover",
  ]) {
    ok(`RECOVER.md still tells the customer about ${claim}`, recoverMd.includes(claim));
  }

  // The share count has to equal the quorum, and the document is written against a 3-of-N split, so a
  // custody line with fewer than three --share files is the exact line that exited 6 (ExitUsage) with
  // "need 3 distinct shares to recombine, got 2". This is a cheap structural backstop that runs in the
  // ordinary validate chain; the drive that actually proves the line works needs a built Go reader and
  // lives in scripts/e2e-writer-reader.sh.
  // Only INDENTED lines, so the prose sentence "Pass one --share for each custodian your quorum
  // requires" is not mistaken for the command it describes. Counting over the whole document would
  // let a one-share example pass on the strength of the paragraph above it.
  const custodyCmd = recoverMd
    .split("\n")
    .filter((l) => /^\s+\S/.test(l) && l.includes("--share"))
    .join(" ");
  ok("RECOVER.md's custody example passes one --share per custodian in a 3-of-N quorum", (custodyCmd.match(/--share /g) ?? []).length >= 3);

  // A read-only store over the written map (the verifyBundle ObjectStoreReader contract).
  const storeOf = (m: Map<string, Uint8Array>): ObjectStoreReader => ({
    get: async (key: string) => {
      const v = m.get(key);
      if (v === undefined) throw new Error(`missing ${key}`);
      return v;
    },
  });

  // Success path: the engine's own freshly written bundle verifies clean under its own
  // signer. This is the write->verify round-trip the wired vectors never exercise; it pins
  // addBundle's exact SHA384SUMS framing (two-space separator, sorted names, trailing
  // newline) and signed-file set against verifyBundle.
  await acceptsAsync("bundle: the engine's own written bundle verifies clean", () => verifyBundle(storeOf(out), verifier));

  // Tamper one byte of a SIGNED-AND-LISTED file (FORMAT.md). Its recorded SHA-384 no longer
  // matches, so verifyBundle must throw at the per-file hash check.
  const tampered = new Map(out);
  const orig = out.get(`${BUNDLE_PREFIX}FORMAT.md`)!;
  const flipped = new Uint8Array(orig);
  flipped[0] = flipped[0]! ^ 0x01;
  tampered.set(`${BUNDLE_PREFIX}FORMAT.md`, flipped);
  await rejectsAsync("bundle: a one-byte tamper of FORMAT.md fails verification", () => verifyBundle(storeOf(tampered), verifier));

  // A forged signature (one bit flipped) over the genuine SHA384SUMS must also fail, proving
  // the hybrid signature is actually checked (not just the per-file hashes).
  const badSig = new Map(out);
  const sigBytes = out.get(`${BUNDLE_PREFIX}SHA384SUMS.sig`)!;
  const sigFlipped = new Uint8Array(sigBytes);
  // The .sig object is base64url text; flip a byte of the decoded bytes via the text so the
  // signature no longer verifies while staying a parseable base64url string is not required
  // (verifyBundle decodes then verifies; a corrupted-but-decodable or undecodable input both
  // fail). Flip the last text character to a different valid base64url character.
  const lastIdx = sigFlipped.length - 1;
  const lastChar = String.fromCharCode(sigFlipped[lastIdx]!);
  sigFlipped[lastIdx] = (lastChar === "A" ? "B" : "A").charCodeAt(0);
  badSig.set(`${BUNDLE_PREFIX}SHA384SUMS.sig`, sigFlipped);
  await rejectsAsync("bundle: a forged SHA384SUMS signature fails verification", () => verifyBundle(storeOf(badSig), verifier));

  // Sanity: verifying under the WRONG signer (a fresh keypair) must fail, so a clean bundle
  // is not trusted under an unrelated key.
  const otherEd = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const otherEdPub = new Uint8Array(await crypto.subtle.exportKey("raw", otherEd.publicKey));
  const otherMldsa = mldsaKeygen();
  const wrongVerifier: HybridVerifier = { ed: otherEdPub, mldsa: otherMldsa.publicKey };
  await rejectsAsync("bundle: a clean bundle does not verify under the wrong signer", () => verifyBundle(storeOf(out), wrongVerifier));
}

// ---------------------------------------------------------------------------------------
// reader structural rejection (SPEC 7.4): a record that carries a packed slice on a
// segment of a MULTI-segment chain is malformed and must be rejected, mirroring the Go
// reference reader.go ("record %s mixes a packed slice with a multi-segment chain"). The
// previous TS reader only handled the single-segment-packed case and silently ignored a
// stray packed field on a multi-segment record. This drives the real Run.restoreRecord with
// two genuinely sealed non-secret segments, so the rejection fires exactly where Go's does
// (after the segments are decrypted and concatenated), and a positive control proves the
// same two-segment record WITHOUT a stray packed restores byte-correct.
// ---------------------------------------------------------------------------------------

// segObjFor builds a segment object path from a 48-byte segment id, in the same
// seg/<first-2-hex>/<full-hex>.seg shape the writer emits and segIDFromObject parses.
function segObjFor(segId: Uint8Array): string {
  const hex = hexEncode(segId);
  return `seg/${hex.slice(0, 2)}/${hex}.seg`;
}

// A read-only ObjectStore backed by an in-memory map (the Run.restoreRecord store contract).
function mapStore(m: Map<string, Uint8Array>): ObjectStore {
  return {
    get: async (key: string) => {
      const v = m.get(key);
      if (v === undefined) throw new Error(`missing ${key}`);
      return v;
    },
  };
}

async function readerStructuralTests(): Promise<void> {
  // A run master and two distinct 48-byte segment ids. The file key each segment is sealed
  // under is derived from master || segId, exactly as restoreRecord re-derives it, so these
  // are real openable segments and not stubs.
  const master = new Uint8Array(32).fill(7);
  const segIdA = new Uint8Array(48).map((_, i) => (i * 5 + 1) & 0xff);
  const segIdB = new Uint8Array(48).map((_, i) => (i * 9 + 2) & 0xff);
  const partA = utf8("alpha-segment-bytes");
  const partB = utf8("bravo-segment-bytes");

  const objA = segObjFor(segIdA);
  const objB = segObjFor(segIdB);
  const store = new Map<string, Uint8Array>();
  store.set(objA, await sealNonSecretSegment(master, segIdA, CODEC_NONE, partA, new Uint8Array(16).fill(1)));
  store.set(objB, await sealNonSecretSegment(master, segIdB, CODEC_NONE, partB, new Uint8Array(16).fill(2)));

  const whole = concat(partA, partB);
  // The plaintext hash the record must match (the reader's per-record backstop). A correct
  // hash isolates the structural check: the negative below is rejected for the packed/multi-
  // segment shape, not because the hash happens to mismatch.
  const wholeSha = hexEncode(await sha384(whole));

  // restoreRecord only reads store/master/runIDBytes off the Run, so a minimal cast root and
  // a zero run id are sufficient to exercise the real reassembly + structural-rejection path.
  const runIDBytes = new Uint8Array(16);
  const baseRecord: ShardRecord = {
    kind: "record",
    sourceType: "kv",
    name: "object-chain",
    keyNameHash: hexEncode(new Uint8Array(48)),
    recordId: "r000000000000000",
    plaintextSize: whole.length,
    plaintextSha384: wholeSha,
    recordHash: hexEncode(new Uint8Array(48)),
    codec: "none",
    segments: [
      { object: objA, chunkRange: [0, 1], packed: null },
      { object: objB, chunkRange: [0, 1], packed: null },
    ],
  };
  // ownsMaster is false: `master` is this file's buffer and is reused across every runFor below, so a Run
  // that wiped it on dispose would destroy something it never owned. That is the contract the class states.
  const runFor = (rec: ShardRecord) => new Run(mapStore(store), {} as RootManifest, master, false, runIDBytes, [rec], null);

  // Positive control: a plain two-segment chain (no packed field) reassembles and passes its
  // plaintext hash, so the rejection below is provably about the stray packed field.
  await acceptsAsync("reader: a clean multi-segment record restores byte-correct", async () => {
    const got = await runFor(baseRecord).restoreRecord(baseRecord);
    if (hexEncode(got) !== hexEncode(whole)) throw new Error("restored bytes differ from the concatenation");
  });

  // Negative: the SAME chain with a stray packed field on the first segment is the malformed
  // shape the Go reader rejects. The packed values are in range, so a bounds check could not
  // catch it; only the multi-segment structural gate does.
  const mixedRecord: ShardRecord = {
    ...baseRecord,
    segments: [
      { object: objA, chunkRange: [0, 1], packed: { offset: 0, length: 4 } },
      { object: objB, chunkRange: [0, 1], packed: null },
    ],
  };
  await rejectsAsync(
    "reader: a packed slice on a multi-segment chain is rejected (mixes a packed slice with a multi-segment chain)",
    () => runFor(mixedRecord).restoreRecord(mixedRecord),
  );

  // The stray packed field on the SECOND segment of the chain must also be rejected, proving
  // the gate scans every segment, not just the first.
  const mixedSecond: ShardRecord = {
    ...baseRecord,
    segments: [
      { object: objA, chunkRange: [0, 1], packed: null },
      { object: objB, chunkRange: [0, 1], packed: { offset: 0, length: 4 } },
    ],
  };
  await rejectsAsync(
    "reader: a packed slice on the second segment of a chain is rejected",
    () => runFor(mixedSecond).restoreRecord(mixedSecond),
  );

  // A SINGLE-segment packed record is still valid (the legitimate packed case): it owns a
  // byte slice of one segment and restores that slice, so the new gate did not break it.
  const packedSingle: ShardRecord = {
    ...baseRecord,
    plaintextSize: 5,
    plaintextSha384: hexEncode(await sha384(partA.subarray(0, 5))),
    segments: [{ object: objA, chunkRange: [0, 1], packed: { offset: 0, length: 5 } }],
  };
  await acceptsAsync("reader: a single-segment packed record still restores its slice", async () => {
    const got = await runFor(packedSingle).restoreRecord(packedSingle);
    if (hexEncode(got) !== hexEncode(partA.subarray(0, 5))) throw new Error("packed slice restored wrong bytes");
  });
}

// ---------------------------------------------------------------------------------------
// signer fingerprint (SPEC 11.4): the root's signingKeyFingerprint must be the REAL
// fingerprint of the run's signer (the "edmldsa1:"-prefixed SHA-384 of its Ed25519 ||
// ML-DSA-87 public keys), not the old "edmldsa1:engine" placeholder. This drives the real
// buildArchive write path, parses the emitted root.manifest.json, and asserts the field equals
// the signerFingerprint helper over the same signer and binds both signature halves. It is the
// byte-identical port of the Go conformance writer's crypto.SignerFingerprint hint.
// ---------------------------------------------------------------------------------------
async function signerFingerprintTests(): Promise<void> {
  const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
  const rand = (n: number) => crypto.getRandomValues(new Uint8Array(n));

  // A real run signer, exactly as buildArchive consumes one.
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  const signer: Signer = { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };

  // A single break-glass recipient (the writer requires break-glass first); its public key
  // material is not exercised by this test beyond letting the archive build. The X25519 and
  // ML-KEM-1024 public keys are generated exactly as the writer cross-check harness does.
  const xk = x25519.keygen();
  const mlkemEk = mlkemKeygen(rand(64)).encapKey;

  // Build a minimal archive. We only need the signed root.manifest.json, so a single buffered
  // KV record and one recipient suffice.
  const archive = await buildArchive({
    downpipeId: "dp_fp",
    downpipeName: "fingerprint-test",
    cadence: "0 * * * *",
    runId: RUN_ID,
    master: rand(32),
    recipients: [{ role: "break-glass", pub: { x25519: xk.publicKey, mlkemEk } }],
    signer,
    records: [{ sourceType: "kv", name: "k", value: utf8("v") }],
    windowStart: "2026-06-07T00:00:00.000Z",
    windowEnd: "2026-06-07T00:00:01.000Z",
    createdAt: "2026-06-07T00:00:01.000Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });

  const rootBytes = archive.get(`run/${RUN_ID}/root.manifest.json`);
  ok("fingerprint: archive emits a signed root.manifest.json", rootBytes !== undefined);
  if (!rootBytes) return;
  const root = JSON.parse(new TextDecoder().decode(rootBytes)) as { signingKeyFingerprint: string };

  // The emitted hint must be the REAL fingerprint the helper computes over this signer, and
  // must NOT be the old hardcoded placeholder.
  const want = await signerFingerprint({ ed: edPublic, mldsa: mldsa.publicKey });
  eq("fingerprint: root.signingKeyFingerprint is the real signer fingerprint", root.signingKeyFingerprint, want);
  ok("fingerprint: root.signingKeyFingerprint is not the old placeholder", root.signingKeyFingerprint !== "edmldsa1:engine");
  ok("fingerprint: hint has the edmldsa1: label and a 96-hex digest", /^edmldsa1:[0-9a-f]{96}$/.test(root.signingKeyFingerprint));

  // It binds the Ed25519 half: changing only ed changes the fingerprint.
  const otherEd = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const otherEdPub = new Uint8Array(await crypto.subtle.exportKey("raw", otherEd.publicKey));
  const fpOtherEd = await signerFingerprint({ ed: otherEdPub, mldsa: mldsa.publicKey });
  ok("fingerprint: binds the Ed25519 half (different ed -> different fingerprint)", fpOtherEd !== want);

  // It binds the ML-DSA-87 half: changing only mldsa changes the fingerprint.
  const otherMldsa = mldsaKeygen();
  const fpOtherMldsa = await signerFingerprint({ ed: edPublic, mldsa: otherMldsa.publicKey });
  ok("fingerprint: binds the ML-DSA-87 half (different mldsa -> different fingerprint)", fpOtherMldsa !== want);

  // Known-answer over fixed all-zero public material, cross-checked against an INDEPENDENT
  // recomputation (sha384 of ed||mldsa with the label), so the helper is not just compared to
  // itself: ed=32 zero bytes, mldsa=2592 zero bytes.
  const zEd = new Uint8Array(32);
  const zMldsa = new Uint8Array(2592);
  const independent = "edmldsa1:" + hexEncode(await sha384(concat(zEd, zMldsa)));
  eq("fingerprint: helper matches an independent SHA-384 over ed||mldsa", await signerFingerprint({ ed: zEd, mldsa: zMldsa }), independent);
}

async function main(): Promise<void> {
  await merkleTests();
  await bundleTests();
  await readerStructuralTests();
  await signerFingerprintTests();
  console.log(failures === 0 ? "\nFORMAT-PRIMS TESTS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
