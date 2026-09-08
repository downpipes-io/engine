// src/format/version.ts is entirely hand-typed, and two things in it were tied to their sources by
// nothing at all. This gate ties them.
//
// 1. ENGINE_VERSION vs package.json. ENGINE_VERSION is what the engine reports to the update check and
//    what checkUpdates compares against the vendor-signed recommendedVersion (updateAvailable is
//    recommendedVersion !== ENGINE_VERSION). package.json's version is what the release is cut and
// published as. Nothing connected them: both read 0.1.9 by coincidence, and a release
//    that bumped one and not the other would have shipped an engine that either never sees an update it
//    should take, or reports one it has already taken, with no gate anywhere raising a word.
//
// 2. The derivation labels vs VERSION. Ten of the constants here are HKDF info strings and HMAC labels
//    of the form "downpipe/<v> <purpose>", each typed out in full. They are not decoration: the format
//    string is a KEY-DERIVATION LABEL, so a label at the wrong version derives different keys, and an
//    archive written with one set cannot be read by an engine built with another.
//
// This is not hypothetical, and it is why this gate exists rather than a comment.
//    the live update channel at update.downpipes.io still serves engine 0.1.9 bytes whose eleven labels
// all read downpipe/1.0, the format retired by the semver cutover, while this source tree
//    reads downpipe/0.1.0. The cutover is hard, with no dual-accept: checkFormatVersion (src/format/
//    structural-gates.ts) refuses downpipe/1.0 outright. A per-label typo produces exactly that class of
//    break, one label at a time and silently, since nothing else in the tree reads these strings back.
//
// Both checks are pure string comparisons over files already on disk, so this belongs in the fast
// validate chain.
//
// Run: node test/validate-version-constants-parity.ts

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { VERSION, ENGINE_VERSION } from "../src/format/version.ts";

let failures = 0;
function ok(label: string, cond: boolean, detail?: string): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}${!cond && detail ? `  (${detail})` : ""}`);
  if (!cond) failures++;
}

const ENGINE_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const VERSION_TS = path.join(ENGINE_DIR, "src", "format", "version.ts");

console.log("\nsrc/format/version.ts constants against their sources");

// ---- 1. ENGINE_VERSION is package.json's version -------------------------------------------------
{
  const pkgRaw = readFileSync(path.join(ENGINE_DIR, "package.json"), "utf8");
  const pkgVersion: unknown = JSON.parse(pkgRaw).version;
  ok("package.json declares a version string (the gate has something to compare against)", typeof pkgVersion === "string" && pkgVersion.length > 0);
  ok("ENGINE_VERSION is a bare x.y.z, with no downpipe/ prefix (that is VERSION's job)", /^\d+\.\d+\.\d+$/.test(ENGINE_VERSION), ENGINE_VERSION);
  ok(
    `ENGINE_VERSION === package.json version (${ENGINE_VERSION} vs ${String(pkgVersion)})`,
    ENGINE_VERSION === pkgVersion,
    "bump both together: src/format/version.ts is what the update check reports, package.json is what the release is published as",
  );
}

// ---- 2. every derivation label carries VERSION's own version -------------------------------------
// Read as TEXT, not through the imported bindings. Comparing the constants to each other would pass
// happily if they all drifted together, which is precisely what the live 0.1.9 artefact did.
{
  const src = readFileSync(VERSION_TS, "utf8");
  const code = src
    .split("\n")
    .filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l))
    .join("\n");

  ok("VERSION is a downpipe/x.y.z label", /^downpipe\/\d+\.\d+\.\d+$/.test(VERSION), VERSION);

  const labels = [...code.matchAll(/"(downpipe\/[^"]*)"/g)].flatMap((m) => (m[1] === undefined ? [] : [m[1]]));
  // A floor, so a refactor that stops matching cannot pass as "nothing to check". Ten labels plus
  // VERSION itself today.
  ok(`found the downpipe/ labels in ${path.relative(ENGINE_DIR, VERSION_TS)} (${labels.length} of them)`, labels.length >= 10, `only ${labels.length}`);

  const wrongVersion = labels.filter((l) => l !== VERSION && !l.startsWith(`${VERSION} `));
  ok(
    "every downpipe/ label in the file is at VERSION's own version",
    wrongVersion.length === 0,
    wrongVersion.join(", "),
  );

  // Each label must also be VERSION followed by a purpose, never a bare duplicate of VERSION: a
  // copy-paste that dropped the purpose would silently collide two derivations onto one label.
  const purposes = labels.filter((l) => l !== VERSION).map((l) => l.slice(VERSION.length + 1));
  ok("no derivation label is a bare copy of VERSION with no purpose", purposes.every((p) => p.length > 0));
  ok("every derivation label's purpose is distinct (no two derivations share a label)", new Set(purposes).size === purposes.length, `${purposes.length} labels, ${new Set(purposes).size} distinct`);

  // Non-vacuity: the retired label the live channel still serves must be recognised as wrong by the
  // same rule this gate applies, or the rule is not testing what it claims to. Held in a widened-type
  // local so the comparison is a real string check rather than one tsc folds away against VERSION's
  // literal type.
  const retired: string[] = ["downpipe/1.0", "downpipe/1.0 seg-key", "downpipe/1.0 payload"];
  const current: string = VERSION;
  ok(
    "the rule REJECTS the retired downpipe/1.0 labels the live channel still serves",
    retired.every((l) => l !== current && !l.startsWith(`${current} `)),
  );
}

if (failures > 0) process.exitCode = 1;
console.log(`\n${failures === 0 ? "VERSION CONSTANTS PARITY PASS" : `VERSION CONSTANTS PARITY: ${failures} FAILURE(S)`}`);
if (failures > 0) process.exit(1);
