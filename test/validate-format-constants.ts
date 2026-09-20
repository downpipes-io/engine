// FORMAT-CONSTANT CONFORMANCE GATE: the two downpipe/0.1.0 implementations' frozen constants must be equal,
// checked by a gate that reads BOTH files, rather than held in step by hand.
//
// WHY THIS EXISTS, and it is the gap the published cryptographic inventory names against itself. Section 10.3
// of the CBOM says the byte-level constants live in one source file per implementation (engine
// src/format/version.ts and downpipe internal/spec/spec.go) and that "the mechanism that holds those two
// files together is weaker than the other controls in this section: they are kept in step by hand and by the
// port discipline each file's own header states, not by a check that reads both and compares them".
//
// MEASURED 2026-09-10, and worse than the document said: `grep -rln "spec.go" scripts test` returned exactly
// one file, src/format/version.ts itself, and none of the 40 gates in scripts/ named spec.go at all. Meanwhile
// version.ts's own header asserted that the file "is checked against spec.go", so a reviewer reading the code
// would conclude the check existed and stop looking. This validator is that check; the header now names it.
//
// WHAT A DIVERGENCE COSTS. Every constant compared here pins a byte-level rule: a label that feeds an HKDF or
// a MAC, a chunk size, a container magic, an address domain separator, the codec identifiers, the closed
// source-type set. A label that differs by one byte does not fail loudly on either side. The writer seals, the
// reader derives a different key, and the archive is unreadable by the second implementation with no error
// either implementation can attribute. That is the silent interop break both file headers warn about, and
// until this gate existed nothing but discipline stood between the two files.
//
// THE PRECEDENT IT IS MODELLED ON is test/validate-schema-conformance.ts, which reads the live
// downpipe/docs/format/schema.json when DOWNPIPE_REPO is set and otherwise grades a vendored copy pinned by
// its SHA-384. The same two-source shape is used here for the same reason: the required `validate` CI job does
// not check out the downpipe repo, so a gate that could only read the sibling would refuse on every run in the
// job that matters, and a refusal on every run teaches a reader to ignore it.
//
// SOURCES, in order of authority:
//   - $DOWNPIPE_REPO/internal/spec/{spec,sourcetype,container}.go, the canonical files, when DOWNPIPE_REPO is
//     set (the e2e job checks the sibling out, so CI does read the live files there);
//   - otherwise the vendored copies at test/vectors/spec/, byte-for-byte, pinned by SHA-384 in
//     test/vectors/spec/SPEC_SHA384 so a silent edit to the vendored copy fails here.
// When both are present they MUST be byte-identical, which is what catches a live spec.go that has moved since
// the engine last re-vendored.
//
// WHY THE GO SIDE IS PARSED AS TEXT rather than built: a leaf package of plain const declarations parses with
// a small scanner, and a text read works with no Go toolchain present, which is the state of the required
// validate job. The TypeScript side is IMPORTED, not parsed, so the values compared are the ones the engine
// actually runs rather than a second reading of the same source text.
//
// Run: node test/validate-format-constants.ts
//      DOWNPIPE_REPO=/path/to/downpipe node test/validate-format-constants.ts   (cross-check the live files)

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import * as engineFormat from "../src/format/version.ts";
// HEADER_SIZE is the engine's counterpart to the Go ContainerHeaderSize. It lives in container.ts rather
// than version.ts because it is the framing helper's own constant, so it is imported here by name: the pair
// pins a byte-level rule (how many bytes precede the STREAM payload) and belongs in the comparison whatever
// file it sits in.
import { HEADER_SIZE } from "../src/format/container.ts";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";
import { requireFreshSiblings } from "../scripts/sibling-freshness.mjs";
import { reportSiblings } from "../scripts/lib/sibling-lag.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const VENDORED_DIR = join(HERE, "vectors", "spec");
const PIN_FILE = join(VENDORED_DIR, "SPEC_SHA384");
const GO_FILES = ["spec.go", "sourcetype.go", "container.go"] as const;

let pass = 0;
let fail = 0;
function ok(msg: string): void {
  pass++;
  console.log(`  ok   ${msg}`);
}
function bad(msg: string): void {
  fail++;
  console.error(`  FAIL ${msg}`);
}

function sha384(b: Buffer): string {
  return createHash("sha384").update(b).digest("hex");
}

// ---- resolve and verify the Go source ------------------------------------------------------------

const pins = new Map<string, string>();
for (const line of readFileSync(PIN_FILE, "utf8").split("\n")) {
  const m = /^([0-9a-f]{96})\s+(\S+)$/.exec(line.trim());
  if (m) pins.set(m[2]!, m[1]!);
}

const goSource = new Map<string, string>();
const vendoredBytes = new Map<string, Buffer>();
for (const name of GO_FILES) {
  const bytes = readFileSync(join(VENDORED_DIR, name));
  vendoredBytes.set(name, bytes);
  const expected = pins.get(name);
  const actual = sha384(bytes);
  if (expected === actual) {
    ok(`vendored test/vectors/spec/${name} matches its pinned SHA-384 (${actual.slice(0, 16)}...)`);
  } else {
    bad(
      `vendored ${name} SHA-384 drift: pinned ${expected ?? "(no pin)"} but file is ${actual}. ` +
        "If the Go file changed deliberately, re-vendor it and update test/vectors/spec/SPEC_SHA384.",
    );
  }
  goSource.set(name, new TextDecoder().decode(bytes));
}

const downpipeRepo = process.env.DOWNPIPE_REPO;
let sourceLabel = "vendored test/vectors/spec/";
if (downpipeRepo) {
  // WHICH DOWNPIPE TREE, and REFUSE when it is not the sibling's main, exactly as validate-schema-conformance
  // does and for the same reason: this arm's whole claim is "equal to the LIVE canonical constants". A
  // checkout that is behind makes that sentence false in both directions and says neither out loud. Only this
  // arm is guarded: with no DOWNPIPE_REPO the gate reads no sibling at all, so a freshness refusal there would
  // be a refusal about nothing.
  reportSiblings([{ name: "downpipe", path: downpipeRepo }], { gate: "format-constants (live cross-check)" });
  requireFreshSiblings([{ name: "downpipe", path: downpipeRepo }], {
    gate: "format-constants (live cross-check)",
    consequence: "the no-drift claim would be about older Go constants than the published ones",
    exit: (code: number) => {
      verdictSkipped(`REFUSED, exit ${code}: the downpipe checkout at DOWNPIPE_REPO is behind its own origin/main, so nothing was concluded`);
      process.exit(code);
    },
  });
  let readAll = true;
  const live = new Map<string, Buffer>();
  for (const name of GO_FILES) {
    try {
      live.set(name, readFileSync(join(downpipeRepo, "internal", "spec", name)));
    } catch {
      readAll = false;
    }
  }
  if (readAll) {
    sourceLabel = `${join(downpipeRepo, "internal", "spec")}/`;
    for (const name of GO_FILES) {
      const liveBytes = live.get(name)!;
      goSource.set(name, new TextDecoder().decode(liveBytes));
      if (sha384(liveBytes) === sha384(vendoredBytes.get(name)!)) {
        ok(`DOWNPIPE_REPO ${name} is byte-identical to the vendored engine copy (no drift)`);
      } else {
        bad(
          `DOWNPIPE_REPO internal/spec/${name} differs from the vendored engine copy. ` +
            "Re-vendor test/vectors/spec/ from the downpipe repo and update SPEC_SHA384.",
        );
      }
    }
  } else {
    console.log(`  note DOWNPIPE_REPO set but internal/spec was not fully readable; using the vendored copies`);
  }
}
console.log(`  note Go constant source: ${sourceLabel}`);

// ---- parse the Go constants ----------------------------------------------------------------------
// The three files are leaf declarations: `const Name = value`, `const Name byte = 0x01`, grouped
// `const ( ... )` and `var ( MagicSeg = [4]byte{...} )`. That is the whole grammar this needs, so a line
// scanner is enough and needs no Go toolchain. Comments are stripped OUTSIDE string literals only: every
// info label in spec.go contains "downpipe/0.1.0", and a naive split on "//" would cut the label in half and
// then compare two truncations that happen to agree.

function stripLineComment(line: string): string {
  let inString = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (c === "\\" && inString) {
      i++;
      continue;
    }
    if (c === '"') inString = !inString;
    else if (!inString && c === "/" && line[i + 1] === "/") return line.slice(0, i);
  }
  return line;
}

/** A normalised constant value: a tagged string, so a number and a string of digits can never compare equal. */
function normaliseGoValue(raw: string): string | null {
  const v = raw.trim();
  const str = /^"((?:[^"\\]|\\.)*)"$/.exec(v);
  if (str) return `str:${str[1]!.replace(/\\"/g, '"')}`;
  const hex = /^0x([0-9a-fA-F]+)$/.exec(v);
  if (hex) return `num:${Number.parseInt(hex[1]!, 16)}`;
  const dec = /^-?\d+$/.exec(v);
  if (dec) return `num:${Number.parseInt(v, 10)}`;
  const arr = /^\[\d+\]byte\{([^}]*)\}$/.exec(v);
  if (arr) {
    const parts = arr[1]!.split(",").map((p) => p.trim()).filter((p) => p.length > 0);
    const nums: number[] = [];
    for (const p of parts) {
      const n = /^0x([0-9a-fA-F]+)$/.test(p) ? Number.parseInt(p.slice(2), 16) : Number.parseInt(p, 10);
      if (!Number.isFinite(n)) return null;
      nums.push(n);
    }
    return `bytes:${nums.join(",")}`;
  }
  return null;
}

/** Every top-level const/var declaration in a Go file, as name -> normalised value. Unparseable values are
 * kept as name -> null so the coverage check below can still SEE the declaration and report it rather than
 * silently treating an unreadable constant as an absent one.
 *
 * FUNCTION BODIES ARE EXCLUDED BY BRACE DEPTH, and that is not tidiness. The first version of this scanner
 * had no depth tracking and picked up `out = append(out, ...)` from FrameContainer, then reported the local
 * variable `out` as an unported Go constant. A gate whose first finding is its own parser is a gate people
 * learn to wave through, so the scanner takes declarations only at brace depth 0, either on a `const`/`var`
 * line or inside a grouped `const (` / `var (` block. */
function parseGoDeclarations(text: string): Map<string, string | null> {
  const out = new Map<string, string | null>();
  let braceDepth = 0;
  let groupDepth = 0;
  for (const rawLine of text.split("\n")) {
    const line = stripLineComment(rawLine).trim();
    const opensGroup = /^(?:const|var)\s*\($/.test(line);
    const closesGroup = groupDepth > 0 && line === ")";
    if (braceDepth === 0 && (opensGroup || groupDepth > 0)) {
      if (opensGroup) {
        groupDepth++;
      } else if (closesGroup) {
        groupDepth--;
      }
    }
    // `const Name [type] = value` / `var Name = value`, or a line inside a grouped block.
    const m = braceDepth === 0 && !opensGroup && !closesGroup && line.length > 0
      ? /^(?:const\s+|var\s+)?([A-Za-z_][A-Za-z0-9_]*)(?:\s+[A-Za-z0-9_.\[\]]+)?\s*=\s*(.+?)$/.exec(line)
      : null;
    if (m !== null && (groupDepth > 0 || /^(?:const|var)\s/.test(line))) {
      const name = m[1]!;
      out.set(name, normaliseGoValue(m[2]!));
    }
    // Brace depth AFTER the line is judged, so a declaration and the body it opens are never confused.
    for (const c of stripLineComment(rawLine)) {
      if (c === "{") braceDepth++;
      else if (c === "}") braceDepth = Math.max(0, braceDepth - 1);
    }
  }
  return out;
}

const goConstants = new Map<string, string | null>();
for (const name of GO_FILES) {
  for (const [k, v] of parseGoDeclarations(goSource.get(name)!)) goConstants.set(k, v);
}

// The parser must not be silently empty: an empty map would make every "absent in Go" message below a
// parser bug reported as a drift finding.
if (goConstants.size >= 20) {
  ok(`parsed ${goConstants.size} declarations from the Go spec package`);
} else {
  bad(`the Go parser found only ${goConstants.size} declarations, which is too few to be the spec package (parser fault, not drift)`);
}

// ---- the pairs that pin a byte-level rule ----------------------------------------------------------
// Each row is [engine export, Go declaration]. A row exists here because the constant is READ BY BOTH
// implementations at the same point of the format: change one side and the archive one side writes is not the
// archive the other side reads.

const PAIRS: readonly (readonly [string, string])[] = [
  ["VERSION", "Version"],
  ["CHUNK_SIZE", "ChunkSize"],
  ["STREAM_NONCE_SIZE", "StreamNonceSize"],
  ["TAG_SIZE", "TagSize"],
  ["CODEC_NONE", "CodecNone"],
  ["CODEC_GZIP", "CodecGzip"],
  ["CODEC_NAME_NONE", "CodecNameNone"],
  ["CODEC_NAME_GZIP", "CodecNameGzip"],
  ["ADDR_SINGLE_NON_SECRET", "AddrSingleNonSecret"],
  ["ADDR_PACKED", "AddrPacked"],
  ["ADDR_SECRETS", "AddrSecrets"],
  ["INFO_CONTENT_ADDRESS", "InfoContentAddress"],
  ["INFO_MANIFEST_KEY", "InfoManifestKey"],
  ["INFO_MANIFEST_WRAP", "InfoManifestWrap"],
  ["INFO_NAME_MAC", "InfoNameMAC"],
  ["INFO_SEG_KEY", "InfoSegKey"],
  ["INFO_KEY_COMMIT", "InfoKeyCommit"],
  ["INFO_RECIPIENT_SET", "InfoRecipientSet"],
  ["INFO_CAPSULE_DEM", "InfoCapsuleDEM"],
  ["INFO_PAYLOAD", "InfoPayload"],
  ["HYBRID_KEM_LABEL", "HybridKEMLabel"],
  ["MAGIC_SEG", "MagicSeg"],
  ["MAGIC_DPE", "MagicDpe"],
  ["CONTAINER_VERSION", "ContainerVersion"],
  // The one pair whose engine half is not in version.ts (see the import note above).
  ["HEADER_SIZE", "ContainerHeaderSize"],
];

// ENGINE_ONLY names an engine export with NO counterpart in the Go spec package, with the reason. A name may
// only sit here because the Go side genuinely does not declare it, never because the pair is inconvenient.
const ENGINE_ONLY: Readonly<Record<string, string>> = {
  // The engine's own release version, not a format constant: it is bumped per engine release and the Go
  // reader has its own, unrelated release version.
  ENGINE_VERSION: "the engine's release version, not part of the archive format",
  // The Go reader derives the per-chunk nonce inside its STREAM implementation rather than exporting its
  // shape from the spec package, so there is nothing in internal/spec to compare against. The layout is
  // pinned instead by the shared known-answer vectors (test/vectors/crypto-kat*), which both readers run.
  CHUNK_NONCE_SIZE: "the Go side pins the chunk-nonce layout in its STREAM code, not in internal/spec",
  CHUNK_NONCE_COUNTER_OFFSET: "the Go side pins the chunk-nonce layout in its STREAM code, not in internal/spec",
  // maxSegmentChunks is UNEXPORTED and lives in internal/format/restore.go, a 400-line reader file. Vendoring
  // that file to pin one integer would put a reader implementation into the engine's test corpus, so this
  // ceiling stays checked by the interop demo (a segment over the ceiling is refused by the Go reader).
  MAX_SEGMENT_CHUNKS: "the Go counterpart is unexported in internal/format/restore.go, outside the spec package",
  // Compared below against the Go closed set, resolved through sourcetype.go's map, not by value equality.
  KNOWN_SOURCE_TYPES: "compared separately against sourcetype.go's closed set",
};

// GO_ONLY names a Go spec declaration with no engine counterpart, with the reason.
const GO_ONLY: Readonly<Record<string, string>> = {
  FileKeySize: "the engine has no named constant for the 32-byte derived key; its HKDF calls take the length inline",
  knownSourceTypes: "the Go closed set, compared below against KNOWN_SOURCE_TYPES",
  SourceKV: "a member of the closed source-type set, compared as a set below",
  SourceR2: "a member of the closed source-type set, compared as a set below",
  SourceSecrets: "a member of the closed source-type set, compared as a set below",
  SourceD1: "a member of the closed source-type set, compared as a set below",
  SourceWorkers: "a member of the closed source-type set, compared as a set below",
  SourceCFConfig: "a member of the closed source-type set, compared as a set below",
  SourceStream: "a member of the closed source-type set, compared as a set below",
  SourceImages: "a member of the closed source-type set, compared as a set below",
  SourceArtifacts: "a member of the closed source-type set, compared as a set below",
};

/** The engine value in the same tagged form the Go values take. */
function normaliseEngineValue(v: unknown): string | null {
  if (typeof v === "string") return `str:${v}`;
  if (typeof v === "number") return `num:${v}`;
  if (v instanceof Uint8Array) return `bytes:${[...v].join(",")}`;
  return null;
}

// versionExports is the single-source file's own surface, used for the coverage sweep below. engineValues
// adds the one constant that lives elsewhere, so the pair table can name it without the coverage sweep
// reporting a version.ts export that does not exist.
const versionExports = engineFormat as unknown as Record<string, unknown>;
const engineValues: Record<string, unknown> = { ...versionExports, HEADER_SIZE };

let compared = 0;
for (const [tsName, goName] of PAIRS) {
  if (!(tsName in engineValues)) {
    bad(`${tsName} is not among the engine constants this gate imports (src/format/version.ts plus the named extras); the pair table names a constant the engine no longer has`);
    continue;
  }
  if (!goConstants.has(goName)) {
    bad(`${goName} is not declared in the Go spec package (the pair table names a constant the reference no longer has)`);
    continue;
  }
  const engineValue = normaliseEngineValue(engineValues[tsName]);
  const goValue = goConstants.get(goName)!;
  if (engineValue === null) {
    bad(`${tsName} has a value shape this gate cannot compare (${typeof engineValues[tsName]}); the gate must be taught it rather than skipping it`);
    continue;
  }
  if (goValue === null) {
    bad(`${goName} has a value shape this gate cannot parse; the gate must be taught it rather than skipping it`);
    continue;
  }
  compared++;
  if (engineValue === goValue) {
    ok(`${tsName} === ${goName} (${engineValue})`);
  } else {
    bad(`FORMAT CONSTANT DIVERGENCE: ${tsName} is ${engineValue} but ${goName} is ${goValue}. One implementation would write an archive the other cannot read.`);
  }
}

// ANTI-VACUITY: the count of comparisons actually made must equal the table. A gate that compares nothing
// and reports no divergence is the failure mode this whole file exists to end.
if (compared === PAIRS.length) {
  ok(`compared all ${PAIRS.length} byte-level constant pairs`);
} else {
  bad(`only ${compared} of ${PAIRS.length} pairs were compared; the rest are reported above and this gate concluded nothing about them`);
}

// ---- the closed source-type set --------------------------------------------------------------------
// KNOWN_SOURCE_TYPES widens the FORMAT: the reader refuses a record whose sourceType is outside it, so a
// type the engine writes and the reference does not know is an archive the reference reader rejects. The Go
// set is the knownSourceTypes map, whose keys are the Source* constants, so it is resolved through them
// rather than by re-reading the constant list (a constant declared but never added to the map is not in the
// closed set, and that difference is exactly what this must catch).

function parseGoSourceTypeSet(text: string): string[] | null {
  const start = text.indexOf("var knownSourceTypes = map[string]struct{}{");
  if (start < 0) return null;
  const end = text.indexOf("\n}", start);
  if (end < 0) return null;
  const body = text.slice(start, end);
  const members: string[] = [];
  for (const rawLine of body.split("\n").slice(1)) {
    const line = stripLineComment(rawLine).trim();
    const m = /^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*\{\},?$/.exec(line);
    if (!m) continue;
    const value = goConstants.get(m[1]!);
    if (value === undefined || value === null || !value.startsWith("str:")) return null;
    members.push(value.slice("str:".length));
  }
  return members;
}

const goSourceTypes = parseGoSourceTypeSet(goSource.get("sourcetype.go")!);
if (goSourceTypes === null || goSourceTypes.length === 0) {
  bad("could not resolve the Go knownSourceTypes set through its Source* constants (parser fault, not drift)");
} else {
  const engineTypes = [...(versionExports.KNOWN_SOURCE_TYPES as ReadonlySet<string>)].sort();
  const goTypes = [...goSourceTypes].sort();
  const onlyEngine = engineTypes.filter((t) => !goTypes.includes(t));
  const onlyGo = goTypes.filter((t) => !engineTypes.includes(t));
  if (onlyEngine.length === 0 && onlyGo.length === 0) {
    ok(`KNOWN_SOURCE_TYPES === the Go closed source-type set (${goTypes.length} types: ${goTypes.join(", ")})`);
  } else {
    bad(
      "SOURCE-TYPE SET DIVERGENCE: " +
        `engine-only [${onlyEngine.join(", ") || "none"}], reference-only [${onlyGo.join(", ") || "none"}]. ` +
        "A type only the engine knows is written into archives the reference reader refuses.",
    );
  }
}

// ---- coverage: a NEW constant on either side must be paired or explained ----------------------------
// The drift this catches is the one a value comparison cannot see: a constant ADDED to one side and never
// ported. Without this the pair table would silently describe an older format than the one either file
// declares, which is the same "held in step by hand" failure one level up.

for (const name of Object.keys(versionExports)) {
  if (PAIRS.some(([ts]) => ts === name)) continue;
  if (name in ENGINE_ONLY) continue;
  bad(`src/format/version.ts exports ${name}, which is neither paired with a Go constant nor listed in ENGINE_ONLY with a reason`);
}

for (const name of goConstants.keys()) {
  if (PAIRS.some(([, go]) => go === name)) continue;
  if (name in GO_ONLY) continue;
  bad(`the Go spec package declares ${name}, which is neither paired with an engine constant nor listed in GO_ONLY with a reason`);
}

console.log("");
verdictReached(fail);
if (fail > 0) {
  console.error(`FORMAT CONSTANTS FAILED: ${fail} failure(s), ${pass} ok`);
  process.exit(1);
}
console.log(`FORMAT CONSTANTS PASS (${pass} checks)`);
