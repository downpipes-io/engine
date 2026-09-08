// BYTE-FIDELITY: the keyed name-MAC carries a SOURCE NAME out to the manifest as a
// 48-byte content address. nameMAC (src/crypto/derive.ts) is hmacSha384(key, utf8(sourceType)
// || 0x00 || utf8(name)); its label INFO_NAME_MAC is frozen in src/format/version.ts. A3
// fuzzes the archive READER (hostile bytes coming IN); this is the inverse leg, pathological
// source NAMES going OUT through the name-MAC, which the existing validate-crypto.ts nameMAC
// section (48-byte length, source-type/name binding, the 0x00 separator on "a"/"bc" vs
// "ab"/"c") does not reach. Pure functions over synthetic names: no estate, no deploy, no key
// upload. Run with `node test/validate-name-mac-byte-fidelity.ts` from the engine dir.
//
// Every pathological name is CONSTRUCTED from explicit code points (String.fromCharCode /
// fromCodePoint), never a pasted literal, so the byte sequence under test is unambiguous.
//
// Cells:
//   byte-STABLE  -- a name yields the SAME 48-byte MAC across repeated calls (deterministic).
//   COLLISION    -- distinct pathological names (embedded NUL, 4-byte emoji, U+202E RTL
//                   override, lone surrogate, max-length, trailing-NUL pair, NFC vs NFD, a
//                   max-length pair differing only in the FINAL byte) yield pairwise-DISTINCT
//                   MACs; nothing in the corpus collides.
//   NO-TRUNCATE  -- a name with an embedded NUL is MAC'd over its FULL bytes, not silently
//                   truncated at the NUL (a|NUL|b != a|NUL|c; name != name|NUL), and the final
//                   byte of a max-length name is covered (no prefix-only hash).
//   FRAME-RTRIP  -- a name's bytes carried through frame() + unframeSeg/unframeDpe come back
//                   byte-identical for every pathological class, and a wrong magic is refused.
//
// DEFAULT-FAIL refuter: the COLLISION cell is re-run against two deliberately-broken MACs, one
// that truncates the name at the first NUL and one that MACs the byte length only, each of
// which MUST report a collision on this corpus. That proves the cell is not vacuous.

import { concat, hexEncode, u32be, utf8 } from "../src/crypto/bytes.ts";
import { deriveMK, deriveNameMACKey, nameMAC } from "../src/crypto/derive.ts";
import { hmacSha384 } from "../src/crypto/primitives.ts";
import { frame, unframeDpe, unframeSeg } from "../src/format/container.ts";
import { MAGIC_DPE, MAGIC_SEG } from "../src/format/version.ts";

// Code-point building blocks (no pasted literals anywhere in this file).
const NUL = String.fromCharCode(0x00); // U+0000 NUL
const RTL = String.fromCharCode(0x202e); // U+202E right-to-left override
const LONE_HI = String.fromCharCode(0xd800); // lone high surrogate (invalid UTF-16 on its own)
const LONE_LO = String.fromCharCode(0xdc00); // lone low surrogate
const REPL = String.fromCharCode(0xfffd); // U+FFFD replacement character
const EMOJI = String.fromCodePoint(0x1f600); // one 4-byte code point (F0 9F 98 80)
const E_NFC = String.fromCharCode(0x00e9); // e-acute, composed (NFC): C3 A9
const E_NFD = "e" + String.fromCharCode(0x0301); // e-acute, decomposed (NFD): 65 CC 81

let failures = 0;
function ok(label: string, cond: boolean): void {
  if (!cond) failures++;
  console.log(`  ${cond ? "ok  " : "FAIL"}  ${label}`);
}
const hx = (b: Uint8Array): string => hexEncode(b);
const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && hx(a) === hx(b);

// The pathological SOURCE-NAME corpus. Every entry is a DISTINCT JS string whose UTF-8 encoding
// is a distinct byte sequence, so a byte-faithful MAC keyed once must map them to distinct
// MACs. sourceType is held at "kv" (a member of the closed KNOWN_SOURCE_TYPES set): the name is
// the surface a customer's data can drive to a hostile shape, the source type cannot.
const corpus: ReadonlyArray<{ id: string; name: string }> = [
  { id: "plain", name: "backup-namespace" },
  { id: "nul-embedded-b", name: `a${NUL}b` }, // 61 00 62
  { id: "nul-embedded-c", name: `a${NUL}c` }, // 61 00 63 -- a NUL-truncating MAC collides this with nul-embedded-b
  { id: "emoji-4byte", name: EMOJI }, // F0 9F 98 80
  { id: "rtl-override", name: `invoice${RTL}gpj.exe` }, // U+202E right-to-left override embedded
  { id: "lone-surrogate", name: `x${LONE_HI}y` }, // lone high surrogate -> TextEncoder emits U+FFFD (EF BF BD)
  { id: "max-length-a", name: "a".repeat(1024) }, // a large name must not throw or truncate
  { id: "max-length-tail-b", name: `${"a".repeat(1023)}b` }, // differs from max-length-a only in the FINAL byte
  { id: "no-trailing-nul", name: "name" }, // 6E 61 6D 65
  { id: "trailing-nul", name: `name${NUL}` }, // 6E 61 6D 65 00 -- a NUL-truncating MAC collides this with no-trailing-nul
  { id: "nfc-e-acute", name: E_NFC }, // C3 A9
  { id: "nfd-e-acute", name: E_NFD }, // 65 CC 81
  { id: "empty", name: "" }, // the empty name: MAC over just utf8("kv") || 0x00
];

// A pairwise-distinctness probe: returns the first colliding pair of corpus ids under the given
// MAC function, or null when every pair is distinct. The COLLISION cell asserts null; the
// refuters assert non-null.
async function firstCollision(
  macFn: (sourceType: string, name: string) => Promise<Uint8Array>,
): Promise<string | null> {
  const macs = await Promise.all(corpus.map((c) => macFn("kv", c.name).then(hx)));
  for (let i = 0; i < macs.length; i++) {
    for (let j = i + 1; j < macs.length; j++) {
      if (macs[i] === macs[j]) return `${corpus[i]!.id} == ${corpus[j]!.id}`;
    }
  }
  return null;
}

async function main(): Promise<void> {
  const master = new Uint8Array(32).fill(7);
  const runId = new Uint8Array(16).fill(3);
  const mk = await deriveMK(master, runId);
  const nmk = await deriveNameMACKey(mk, runId);
  const real = (sourceType: string, name: string): Promise<Uint8Array> => nameMAC(nmk, sourceType, name);

  // ----- byte-STABLE ------------------------------------------------------------------------
  console.log("\nbyte-STABLE (deterministic across calls):");
  for (const c of corpus) {
    const a = await real("kv", c.name);
    const b = await real("kv", c.name);
    ok(`${c.id}: same name -> identical 48-byte MAC on a repeat call`, a.length === 48 && bytesEqual(a, b));
  }

  // ----- COLLISION --------------------------------------------------------------------------
  console.log("\nCOLLISION (distinct pathological names -> pairwise-distinct MACs):");
  const collision = await firstCollision(real);
  ok(`no two of the ${corpus.length} pathological names collide to one MAC`, collision === null);
  if (collision !== null) console.log(`    colliding pair: ${collision}`);
  // The specific pairs the format's content-addressing leans on:
  ok(
    "an embedded NUL is significant: kv/a|NUL|b != kv/a|NUL|c",
    hx(await real("kv", `a${NUL}b`)) !== hx(await real("kv", `a${NUL}c`)),
  );
  ok(
    "normalisation form is significant: NFC e-acute (U+00E9) != NFD e-acute (e + U+0301)",
    hx(await real("kv", E_NFC)) !== hx(await real("kv", E_NFD)),
  );

  // ----- NO-TRUNCATE ------------------------------------------------------------------------
  console.log("\nNO-TRUNCATE (full bytes MAC'd, not cut at a NUL or a prefix):");
  ok(
    "a trailing NUL is MAC'd: kv/name != kv/name|NUL|",
    hx(await real("kv", "name")) !== hx(await real("kv", `name${NUL}`)),
  );
  ok(
    "the FINAL byte of a 1024-byte name is covered (no prefix-only hash)",
    hx(await real("kv", "a".repeat(1024))) !== hx(await real("kv", `${"a".repeat(1023)}b`)),
  );
  // A NUL in the name does not throw and produces a full-length MAC.
  const nulMac = await real("kv", `a${NUL}b`);
  ok("a name with an embedded NUL yields a full 48-byte MAC (no throw, no short output)", nulMac.length === 48);

  // ----- FRAME-RTRIP ------------------------------------------------------------------------
  console.log("\nFRAME-RTRIP (frame -> unframe returns the name bytes byte-identical):");
  for (const c of corpus) {
    const payload = utf8(c.name);
    const seg = unframeSeg(frame(MAGIC_SEG, payload));
    const dpe = unframeDpe(frame(MAGIC_DPE, payload));
    ok(`${c.id}: .seg + .dpe round-trip returns the exact name bytes`, bytesEqual(seg, payload) && bytesEqual(dpe, payload));
  }
  // Framing validates the magic rather than silently mis-reading a payload.
  let threw = "";
  try {
    unframeDpe(frame(MAGIC_SEG, utf8(`a${NUL}b`)));
  } catch (e) {
    threw = (e as Error).message;
  }
  ok("unframeDpe refuses a .seg-framed payload (wrong magic), not a silent mis-read", /magic/.test(threw));

  // ----- DEFAULT-FAIL refuter ---------------------------------------------------------------
  // Two deliberately-broken name-MACs. If the engine's nameMAC behaved like either, the
  // COLLISION cell above would have to catch it; here it is proven to.
  console.log("\nDEFAULT-FAIL refuter (broken MACs MUST collide on this corpus):");
  const brokenTrunc = (sourceType: string, name: string): Promise<Uint8Array> => {
    const cut = name.indexOf(NUL);
    const truncated = cut >= 0 ? name.slice(0, cut) : name; // truncate the name at the first NUL
    return hmacSha384(nmk, concat(utf8(sourceType), new Uint8Array([0x00]), utf8(truncated)));
  };
  const brokenLengthOnly = (sourceType: string, name: string): Promise<Uint8Array> =>
    // MAC the byte length only, ignoring the content entirely.
    hmacSha384(nmk, concat(utf8(sourceType), new Uint8Array([0x00]), u32be(utf8(name).length)));

  const truncCollision = await firstCollision(brokenTrunc);
  ok("a NUL-truncating MAC DOES collide on the corpus (refuter has teeth)", truncCollision !== null);
  console.log(`    NUL-truncating collision: ${truncCollision}`);
  const lengthCollision = await firstCollision(brokenLengthOnly);
  ok("a length-only MAC DOES collide on the corpus (refuter has teeth)", lengthCollision !== null);
  console.log(`    length-only collision: ${lengthCollision}`);

  // ----- OBSERVATION (not a failure): the UTF-8 encoding boundary ----------------------------
  // nameMAC is byte-faithful to the UTF-8 ENCODING, and utf8() is TextEncoder, which maps every
  // lone surrogate (and a literal U+FFFD) to the same three bytes EF BF BD before the MAC. So a
  // lone high surrogate, a lone low surrogate and a literal replacement char share one MAC. This
  // is the encoding boundary, faithfully MAC'd, NOT a truncation defect; well-formed distinct
  // names never collide (the COLLISION cell above). It is recorded so the property is explicit.
  console.log("\nOBSERVATION (expected, documented in the ledger): the UTF-8 encoding boundary:");
  const loHi = hx(await real("kv", LONE_HI));
  const loLo = hx(await real("kv", LONE_LO));
  const repl = hx(await real("kv", REPL));
  ok(
    "lone surrogates and a literal U+FFFD collapse to one MAC (TextEncoder boundary, faithfully MAC'd)",
    loHi === loLo && loLo === repl,
  );

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: name-MAC byte-fidelity (${failures} failure${failures === 1 ? "" : "s"})`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
