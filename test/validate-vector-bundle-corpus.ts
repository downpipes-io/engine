// The committed recovery bundles in the conformance corpus, verified by the engine's own verifyBundle.
//
// WHY THIS EXISTS. The vectors under test/vectors/*/archive/_RECOVERY/downpipe/0.1.0/ are shipped, signed,
// version-labelled artefacts: FORMAT.md and RECOVER.md are the in-bucket recovery instructions, the only
// guidance a recoverer holding nothing but a bucket has, and the vectors are the reference corpus a
// clean-room re-implementer is pointed at. A file nothing reads produces the same green as a file that
// passes, so this gate enumerates and verifies every one of them through verifyBundle itself, distinct from
// the bundle CODE PATH coverage validate-format-prims.ts and validate-bundle-verify-hostile.ts already
// provide (which prove the parser and the tamper checks, not that the committed artefacts themselves are
// read).
//
// WHAT IT ASSERTS, in three arms.
//
//   1. ENUMERATION, from `git ls-files` rather than a filesystem walk. The filesystem carries at least one
//      gitignored directory here (test/vectors/cf-openapi/, a 10 MB Cloudflare OpenAPI dump), so a walk
//      grades one machine's clutter. The prefix comes from BUNDLE_PREFIX, so a format-version bump moves
//      the query and the floor below turns the resulting zero into a failure rather than a clean sweep.
//
//   2. VERIFICATION, through verifyBundle itself rather than a reimplementation, against each vector's own
//      signer.pub. The EXPECTATION is read from the vector's expect.json, never from a list kept here: a
//      vector must verify unless its own labels.recoveryBundleVerified says false. That direction matters.
//      A gate that asserts the wrong expectation over a negative vector is how a corpus gets edited to suit
//      a test, and recovery-bundle-tampered exists precisely to fail. A vector opting out is additionally
//      required to be a negative that sets options.checkRecoveryBundle, so a positive cannot quietly
//      exempt itself, and a vector declaring false must still actually fail: a negative that starts
//      verifying is corpus drift in the other direction.
//
//   3. COMPLETENESS, over the vectors that carry NO bundle. The structural rule is derived rather than
//      listed (a bundle lives inside an archive/, so a directory with no archive/ is not an archive vector),
//      but a derived rule alone would silently accept a NEW bundle-less directory that ought to have one.
//      NO_ARCHIVE below closes that, and every field of it is RE-DERIVED on each run rather than read as
//      prose: the directory must still be tracked, must still have no archive/, and its named consumer must
//      still exist and still name it, so a declared entry cannot go on reading plausibly after its stated
//      cause has stopped being true.
//
// ANTI-VACUITY, and it is not the whole story. Exit 2 (could not check) is distinct from exit 1 (findings),
// and the floor below fails rather than passing on a short sweep. But a floor cannot catch BLINDNESS: a
// gate whose matcher only recognises the shapes its author thought of meets every floor while seeing
// nothing. The controls at the end plant real tampers in memory over a REAL corpus bundle and require the
// gate to name them, so a green here cannot be verifyBundle failing to look.
//
// Run: node test/validate-vector-bundle-corpus.ts

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { b64urlDecode, hexEncode, utf8 } from "../src/crypto/bytes.ts";
import { parseVerifier } from "../src/crypto/keys.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import type { HybridVerifier } from "../src/crypto/sign.ts";
import { BUNDLE_PREFIX, type ObjectStoreReader, verifyBundle } from "../src/format/bundle.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CANNOT_CHECK = 2;

// The floor is the number measured on this tree at the vendored corpus commit in test/vectors/VECTORS_COMMIT.
// It is a tripwire for the sweep being gutted (a bad re-vendor, a moved prefix, a glob that stops matching)
// and this gate then reporting a confident pass over the remnant. Adding a vector costs nothing; removing
// one costs a number somebody has to change on purpose, which is the asymmetry worth paying for.
const MIN_ARCHIVE_VECTORS = 45;
// Four objects per bundle: FORMAT.md, RECOVER.md, SHA384SUMS and the detached signature over it.
const FILES_PER_BUNDLE = 4;

/**
 * The tracked vector directories that carry no archive/ and therefore no recovery bundle, each with the
 * validator that consumes it. Nothing here is taken on trust: the directory and the consumer are both
 * re-derived from the tree on every run, so an entry that has stopped being true fails rather than reading
 * plausibly.
 */
const NO_ARCHIVE: Array<{ dir: string; consumer: string; why: string }> = [
  { dir: "acvp", consumer: "test/validate-acvp.ts", why: "verbatim NIST ACVP known-answer JSON subsets, not an archive" },
  { dir: "cf-config", consumer: "test/validate-cf-config-drift.ts", why: "Cloudflare config capture fixtures in JSON, not an archive" },
  { dir: "crypto-kat", consumer: "test/validate-crypto.ts", why: "known-answer JSON pinning the engine's stream crypto against the Go reference" },
  { dir: "crypto-kat-multichunk", consumer: "test/validate-crypto-kat-multichunk.ts", why: "multi-chunk known-answer JSON, no archive objects" },
  { dir: "kem-combiner-kat", consumer: "test/validate-crypto.ts", why: "KEM-combiner known-answer JSON, no archive objects" },
  { dir: "mldsa-kat", consumer: "test/validate-pq.ts", why: "ML-DSA-87 known-answer JSON, no archive objects" },
  { dir: "mldsa-seed-kat", consumer: "test/validate-mldsa-seed.ts", why: "ML-DSA-87 seed-expansion known-answer JSON, no archive objects" },
  { dir: "mlkem-kat", consumer: "test/validate-pq.ts", why: "ML-KEM-1024 known-answer JSON, no archive objects" },
];

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function cannotCheck(reason: string): never {
  console.error(`::error::[vector-bundle-corpus] ${reason} Exit ${CANNOT_CHECK}.`);
  /* skipped: advisory */
  process.exit(CANNOT_CHECK);
}

/** trackedFiles lists every tracked path under test/vectors, so untracked clutter cannot change a verdict. */
function trackedFiles(): string[] {
  try {
    return execFileSync("git", ["-C", ROOT, "ls-files", "test/vectors"], { encoding: "utf8" }).split("\n").filter((s) => s !== "");
  } catch (e) {
    cannotCheck(`git ls-files failed (${e instanceof Error ? e.message : String(e)}), so the corpus cannot be enumerated from the index.`);
  }
}

/** A read-only ObjectStoreReader over one vector's archive/ directory, the shape verifyBundle wants. */
function dirStore(archiveDir: string): ObjectStoreReader {
  return { async get(key: string): Promise<Uint8Array> { return new Uint8Array(await readFile(join(archiveDir, key))); } };
}

/** A read-only ObjectStoreReader over an in-memory map, used by the tamper controls. */
function mapStore(objects: Map<string, Uint8Array>): ObjectStoreReader {
  return {
    async get(key: string): Promise<Uint8Array> {
      const v = objects.get(key);
      if (v === undefined) throw new Error(`ENOENT: no such object ${key}`);
      return v;
    },
  };
}

async function loadVerifier(vectorDir: string): Promise<HybridVerifier> {
  return parseVerifier(b64urlDecode((await readFile(join(vectorDir, "signer.pub"), "utf8")).trim()));
}

/** refusalMessage runs fn and returns the message it threw, or null when it did not throw. */
async function refusalMessage(fn: () => Promise<unknown>): Promise<string | null> {
  try {
    await fn();
    return null;
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}

/**
 * refusalMentions answers "did it refuse, AND does the refusal name every one of these". Not throwing at
 * all is a failure, which is why this takes the null rather than being written as an optional chain: a
 * refusal that never happened must not read as a refusal whose wording could not be checked.
 */
function refusalMentions(msg: string | null, ...needles: string[]): boolean {
  if (msg === null) return false;
  const lower = msg.toLowerCase();
  return needles.every((n) => lower.includes(n.toLowerCase()));
}

interface VectorExpect {
  mode?: "positive" | "negative";
  options?: { checkRecoveryBundle?: boolean } | null;
  labels?: { recoveryBundleVerified?: boolean };
}

// ARM 1: enumeration, counted before anything is asserted about it.

const tracked = trackedFiles();
if (tracked.length === 0) cannotCheck("git ls-files returned nothing under test/vectors, so there is no corpus to grade.");

// The bundle path is built from BUNDLE_PREFIX rather than restated, so a format-version bump moves the
// query with the engine instead of leaving this gate pointed at an empty directory.
const escapedPrefix = BUNDLE_PREFIX.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
const BUNDLE_FILE_RE = new RegExp(`^test/vectors/([^/]+)/archive/${escapedPrefix}([^/]+)$`);
const ARCHIVE_FILE_RE = /^test\/vectors\/([^/]+)\/archive\//;
const VECTOR_ENTRY_RE = /^test\/vectors\/([^/]+)\//;

const bundleFilesByVector = new Map<string, string[]>();
for (const f of tracked) {
  const m = BUNDLE_FILE_RE.exec(f);
  if (m) {
    const list = bundleFilesByVector.get(m[1] as string) ?? [];
    list.push(m[2] as string);
    bundleFilesByVector.set(m[1] as string, list);
  }
}
const archiveVectors = new Set<string>();
for (const f of tracked) {
  const m = ARCHIVE_FILE_RE.exec(f);
  if (m) archiveVectors.add(m[1] as string);
}
const vectorDirs = new Set<string>();
for (const f of tracked) {
  const m = VECTOR_ENTRY_RE.exec(f);
  if (m) vectorDirs.add(m[1] as string);
}
const bundleVectors = [...bundleFilesByVector.keys()].sort();
const bundleFileCount = [...bundleFilesByVector.values()].reduce((n, v) => n + v.length, 0);
const markdownCount = [...bundleFilesByVector.values()].reduce((n, v) => n + v.filter((f) => f.endsWith(".md")).length, 0);
const noArchiveDirs = [...vectorDirs].filter((d) => !archiveVectors.has(d)).sort();

console.log("Counted from git ls-files, not the filesystem:");
console.log(`       tracked vector directories:        ${vectorDirs.size}`);
console.log(`       of those, carrying an archive/:    ${archiveVectors.size}`);
console.log(`       of those, carrying a bundle under ${BUNDLE_PREFIX}: ${bundleVectors.length}`);
console.log(`       bundle objects in total:           ${bundleFileCount}  (${markdownCount} of them markdown)`);
console.log(`       vector directories with no archive/: ${noArchiveDirs.length}  (${noArchiveDirs.join(" ") || "none"})`);

// THE ANTI-VACUITY FLOOR. Below it the sweep has not proven what a full sweep proves, and that is a
// could-not-check rather than a finding.
if (bundleVectors.length < MIN_ARCHIVE_VECTORS) {
  cannotCheck(
    `only ${bundleVectors.length} vector(s) carry a bundle under ${BUNDLE_PREFIX}, under the floor of ${MIN_ARCHIVE_VECTORS}. ` +
      "Either the corpus was gutted or the bundle prefix moved with a format-version bump; a pass over this many vectors would be a statement about almost nothing.",
  );
}

console.log("\nEvery archive vector carries a complete bundle:");
ok(`every vector with an archive/ carries a bundle (${archiveVectors.size} archive vectors, ${bundleVectors.length} bundles)`, archiveVectors.size === bundleVectors.length);
ok(`the bundle object count is exactly ${FILES_PER_BUNDLE} per bundle (${bundleFileCount} over ${bundleVectors.length})`, bundleFileCount === bundleVectors.length * FILES_PER_BUNDLE);
const EXPECTED_NAMES = ["FORMAT.md", "RECOVER.md", "SHA384SUMS", "SHA384SUMS.sig"];
const incomplete = bundleVectors.filter((v) => {
  const names = (bundleFilesByVector.get(v) ?? []).slice().sort();
  return names.join(",") !== EXPECTED_NAMES.slice().sort().join(",");
});
for (const v of incomplete) console.log(`       incomplete: ${v} has ${(bundleFilesByVector.get(v) ?? []).join(" ")}`);
ok(`every bundle holds exactly ${EXPECTED_NAMES.join(", ")} (${incomplete.length} incomplete)`, incomplete.length === 0);

// ARM 2: verification, one vector at a time, through verifyBundle against the vector's own signer.

console.log("\nEvery committed bundle verifies as its own expect.json declares:");
let mustVerify = 0;
let mustFail = 0;
for (const v of bundleVectors) {
  const vectorDir = join(ROOT, "test/vectors", v);
  const expectPath = join(vectorDir, "expect.json");
  if (!existsSync(expectPath)) {
    ok(`${v}: expect.json is present (the expectation is read from the corpus, never from this file)`, false);
    continue;
  }
  let expect: VectorExpect;
  try {
    expect = JSON.parse(readFileSync(expectPath, "utf8")) as VectorExpect;
  } catch (e) {
    ok(`${v}: expect.json parses (${e instanceof Error ? e.message : String(e)})`, false);
    continue;
  }
  const declared = expect.labels?.recoveryBundleVerified;
  const shouldVerify = declared !== false;
  const verifier = await loadVerifier(vectorDir);
  const msg = await refusalMessage(() => verifyBundle(dirStore(join(vectorDir, "archive")), verifier));
  if (shouldVerify) {
    mustVerify++;
    ok(`${v}: the committed bundle verifies under its own signer.pub${msg === null ? "" : ` (threw: ${msg})`}`, msg === null);
  } else {
    mustFail++;
    // A vector may only opt out by being a negative that asks for the bundle check. Without this a positive
    // could exempt itself with one label and the sweep would shrink silently.
    ok(`${v}: opting out of bundle verification is declared as a negative`, expect.mode === "negative");
    ok(`${v}: opting out of bundle verification sets options.checkRecoveryBundle`, expect.options?.checkRecoveryBundle === true);
    ok(`${v}: the committed bundle does NOT verify, as the vector declares`, msg !== null);
    ok(
      `${v}: the refusal names the recovery bundle as the rejection site${msg === null ? "" : ` ("${msg}")`}`,
      refusalMentions(msg, "recovery bundle"),
    );
  }
}
console.log(`       ${mustVerify} vector(s) must verify, ${mustFail} must not`);
ok(`the must-verify population is the whole corpus bar the declared negatives (${mustVerify} + ${mustFail} = ${bundleVectors.length})`, mustVerify + mustFail === bundleVectors.length);
ok("at least one vector declares that its bundle must NOT verify, so the negative direction is exercised", mustFail >= 1);

// ARM 3: the vectors that carry no bundle, and why that is correct for each.

console.log("\nEvery bundle-less vector directory is accounted for:");
const declaredNoArchive = new Set(NO_ARCHIVE.map((e) => e.dir));
const unexplained = noArchiveDirs.filter((d) => !declaredNoArchive.has(d));
for (const d of unexplained) console.log(`       unexplained: test/vectors/${d} has no archive/ and no entry in NO_ARCHIVE`);
ok(`every bundle-less vector directory has a NO_ARCHIVE entry (${unexplained.length} unexplained)`, unexplained.length === 0);

for (const e of NO_ARCHIVE) {
  // Stale check one: the entry still names something that is in the tree.
  ok(`NO_ARCHIVE ${e.dir}: the directory is still tracked`, vectorDirs.has(e.dir));
  // Stale check two: the stated reason has not stopped being true. A directory that has grown an archive/
  // now owes a bundle and must not go on being excused by an entry written before it did.
  ok(`NO_ARCHIVE ${e.dir}: still has no archive/, so the reason still holds (${e.why})`, !archiveVectors.has(e.dir));
  // Stale check three: the reason is re-derived rather than read. The named consumer must exist and must
  // still name the directory, so an entry cannot outlive the validator it points at.
  const consumerPath = join(ROOT, e.consumer);
  const consumerExists = existsSync(consumerPath);
  ok(`NO_ARCHIVE ${e.dir}: its consumer ${e.consumer} exists`, consumerExists);
  ok(
    `NO_ARCHIVE ${e.dir}: ${e.consumer} still names the directory`,
    consumerExists && readFileSync(consumerPath, "utf8").includes(e.dir),
  );
}

// CONTROLS. A floor proves the sweep was not empty. It cannot prove the sweep can FAIL. These plant real
// tampers in memory over a REAL corpus bundle and require verifyBundle to name each one, so the greens
// above cannot be the verification arm declining to look. Nothing on disk is touched.

console.log("\nControls (a real corpus bundle, tampered in memory, must be refused):");
const controlVector = bundleVectors.find((v) => {
  const p = join(ROOT, "test/vectors", v, "expect.json");
  if (!existsSync(p)) return false;
  return (JSON.parse(readFileSync(p, "utf8")) as VectorExpect).labels?.recoveryBundleVerified !== false;
});
if (controlVector === undefined) cannotCheck("no vector in the corpus is expected to verify, so there is no clean bundle to base the tamper controls on.");

const controlDir = join(ROOT, "test/vectors", controlVector, "archive");
const controlVerifier = await loadVerifier(join(ROOT, "test/vectors", controlVector));
const clean = new Map<string, Uint8Array>();
for (const name of EXPECTED_NAMES) clean.set(BUNDLE_PREFIX + name, new Uint8Array(await readFile(join(controlDir, BUNDLE_PREFIX + name))));

console.log(`       control base: test/vectors/${controlVector}`);
ok("CONTROL: the untampered copy of that bundle verifies, so the controls below start from a clean base", (await refusalMessage(() => verifyBundle(mapStore(clean), controlVerifier))) === null);

// Control one: the exact tamper shape this gate exists to catch, one byte appended to FORMAT.md. The signature over
// SHA384SUMS still verifies, so the refusal has to come from the per-file hash check.
const formatKey = `${BUNDLE_PREFIX}FORMAT.md`;
const tamperedFormat = new Map(clean);
const originalFormat = clean.get(formatKey) as Uint8Array;
const appended = new Uint8Array(originalFormat.length + 1);
appended.set(originalFormat, 0);
appended[originalFormat.length] = 0x20;
tamperedFormat.set(formatKey, appended);
const formatMsg = await refusalMessage(() => verifyBundle(mapStore(tamperedFormat), controlVerifier));
ok(
  `CONTROL: one byte appended to FORMAT.md is refused, and the refusal names FORMAT.md ("${formatMsg ?? "did not throw"}")`,
  refusalMentions(formatMsg, "FORMAT.md", "SHA-384"),
);

// Control two: a wrongly regenerated SHA384SUMS. The listed hashes now agree with the tampered bytes, so a
// checker that only compared hashes would pass. The detached signature no longer covers these sums, so the
// refusal must come from the signature gate, which verifyBundle runs BEFORE it enumerates a single line.
const regenerated = new Map(tamperedFormat);
let sums = "";
for (const name of ["FORMAT.md", "RECOVER.md"]) {
  sums += `${hexEncode(await sha384(regenerated.get(BUNDLE_PREFIX + name) as Uint8Array))}  ${name}\n`;
}
regenerated.set(`${BUNDLE_PREFIX}SHA384SUMS`, utf8(sums));
const sumsMsg = await refusalMessage(() => verifyBundle(mapStore(regenerated), controlVerifier));
ok(
  `CONTROL: a SHA384SUMS regenerated over the tampered file is refused at the SIGNATURE, not at the hashes ("${sumsMsg ?? "did not throw"}")`,
  refusalMentions(sumsMsg, "signature"),
);

// Control three: the right bundle under the wrong operator signer.
const otherVector = bundleVectors.find((v) => v !== controlVector);
if (otherVector !== undefined) {
  const wrongVerifier = await loadVerifier(join(ROOT, "test/vectors", otherVector));
  const wrongMsg = await refusalMessage(() => verifyBundle(mapStore(clean), wrongVerifier));
  ok(
    `CONTROL: the clean bundle does not verify under ${otherVector}'s signer ("${wrongMsg ?? "did not throw"}")`,
    refusalMentions(wrongMsg, "signature"),
  );
}

// Control four: the enumeration arm. A prefix that matches nothing must yield nothing, so a green above
// cannot be a pattern loose enough to match whatever it was pointed at.
const bogus = tracked.filter((f) => /^test\/vectors\/[^/]+\/archive\/_RECOVERY\/downpipe\/9\.9\.9\/[^/]+$/.test(f));
ok(`CONTROL: the enumeration is the prefix and not the glob (a version that does not exist matches ${bogus.length} files)`, bogus.length === 0);
ok("CONTROL: the real prefix matched only markdown, sums and signature names", [...bundleFilesByVector.values()].every((v) => v.every((n) => EXPECTED_NAMES.includes(n))));

console.log(
  failures === 0
    ? `\nVECTOR BUNDLE CORPUS PASS: ${bundleVectors.length} committed bundles (${bundleFileCount} objects, ${markdownCount} markdown) verified through verifyBundle, ${noArchiveDirs.length} bundle-less vector directories accounted for`
    : `\n${failures} FAILURE(S)`,
);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
