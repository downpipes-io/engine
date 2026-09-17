#!/usr/bin/env node
// NO-RAW-NUL GATE for engine. One claim: no tracked source file here contains a raw NUL byte.
//
// ---------------------------------------------------------------------------------------------------
// WHY THIS FILE EXISTS IN THIS REPOSITORY, WHICH IS A SIBLING-GAP FINDING RATHER THAN A NEW RULE.
//
// The rule is not new. console/scripts/no-raw-nul-gate.mjs, docs/scripts/no-raw-nul-gate.mjs,
// harness/scripts/no-binary-source-gate.mjs and,, internal-docs and control-plane have
// each enforced it. This file is the internal-docs port adapted rather than re-invented. What was missing
// was a copy HERE, in the repository the defect has visited most.
//
// The gap was measured rather than assumed, by counting how often a raw NUL has actually
// landed in each repository's source history (every blob reachable from every ref, source extensions
// only, vendor and node_modules excluded):
//
//     repo            gate before today   distinct files that ever carried one   of those, git-blind
//     engine                  NO                        17                              4
//     harness                 yes                        7                              4
//     docs                    yes                        3                              0
//     console                 yes                        2                              1
//     control-plane           NO                         2                              1
//     internal-docs           NO                         1                              0
//     website                 NO                         0                              0
//     downpipe                NO                         0                              0
//
// The three repositories that HAD the gate account for twelve of the historical instances between them.
// engine alone, which had no gate, accounts for seventeen. So the rule was absent from precisely the
// repository the defect visits most, which is the shape this workspace has now recorded four times: a
// predicate branching on six callers and not the seventh, auditNearCap without configNearCap, six AAD
// domains imported and one driven, and a gate present in one repository and absent from its siblings.
//
// THAT SEVENTEEN WAS RE-MEASURED HERE INDEPENDENTLY BEFORE THIS FILE WAS WRITTEN, not taken on trust,
// because a reported number that nobody re-derives is a number that quietly becomes wrong. Reading every
// blob reachable from every ref, 10,781 blobs, gives 110 distinct paths that have carried a raw NUL. 93
// of them are `.dpe` and `.seg` archive fixtures, which are binary by design and are not this rule's
// business. The other SEVENTEEN are source, four of them git-blind:
//
//     scripts/dead-vocab-gate.mjs                                first NUL at byte 35211
//     scripts/impossible-comparison-gate.mjs                                        9341
//     src/admin/audit.ts                                                           41948
//     src/admin/passkey.ts                                                         37262
//     src/admin/saml/parser.ts                                                     17891
//     src/admin/support-sections-seal.ts                                           26492
//     test/lib/cf-restore-proofs.ts                                                 8580
//     test/validate-cov-sched-scheduler-do-observability.ts                        32597
//     test/validate-cov-sched-scheduler-do-passkey.ts                              25874
//     test/validate-destsim-pushauth.ts                                             2423  GIT-BLIND
//     test/validate-expiry.ts                                                      10955
//     test/validate-fuzzing-tier1.ts                                                6511  GIT-BLIND
//     test/validate-group-roles.ts                                                 25955
//     test/validate-restore-fault-evidence.ts                                      14134
//     test/validate-saml-c14n.ts                                                    3055  GIT-BLIND
//     test/validate-saml-metadata.ts                                                8883
//     test/write-corpus-archive.ts                                                  6579  GIT-BLIND
//
// THREE OF THOSE ARE THE ARGUMENT ON THEIR OWN: src/admin/audit.ts, src/admin/passkey.ts and
// src/admin/saml/parser.ts are product source a security review would grep, and while each carried its
// NUL a `git grep -I` for anything declared only there returned no matches and no error.
//
// ---------------------------------------------------------------------------------------------------
// WHY A RAW NUL IS DIFFERENT FROM EVERY OTHER ODD BYTE.
//
// It does not break the runtime. A string holding a literal NUL and one written with the escape are the
// SAME STRING, so a composite map key written with a raw separator works perfectly. Nothing fails.
//
// What it breaks is every text tool that reads the file. grep classifies a file containing a NUL as
// BINARY and prints "Binary file ... matches" rather than the matching line; with -I it skips the file
// entirely, reporting no matches at all rather than an error. It does not say it could not check. It says
// there is nothing there.
//
// AND THE OFFSET DECIDES HOW BAD IT IS. git judges a blob binary from its FIRST 8000 BYTES ONLY.
// One script carried two NULs at byte 16713, past that window, so
// git diff and git grep both read it as text and only grep went blind. Another
// carried one at byte 4648, inside the window, so git dropped the whole file and `git grep -I` could not
// see eight symbols declared only there. Same defect, two very different blast radii.
//
// THIS REPOSITORY'S HISTORY LANDS ON BOTH SIDES OF THAT LINE, which is why the window cannot be borrowed
// as the rule: 4 of its 17 instances sit inside the 8000 bytes and 13 sit past them, out to byte 41948.
// A check built on git's own classification would have reported thirteen of the seventeen as clean text
// and said nothing about them. This gate therefore reads every file WHOLE rather than reproducing git's
// window: a NUL past 8000 bytes is still a NUL, and grep still goes blind on it.
//
// ---------------------------------------------------------------------------------------------------
// WHY THIS LANDS GREEN RATHER THAN RED-FROM-BIRTH.
//
// Measured before it was written: 1,646 in-scope tracked files here, none of them carrying a raw NUL.
// There is no baseline file and no ratchet because there is no debt to record, and that is a measurement
// rather than an assumption. A gate that lands red is a gate its readers learn to skip, so if this
// repository had carried existing offenders the honest move would have been to record them as named debt
// and ratchet down from there. It did not, so the floor is simply zero.
//
// AND THAT ZERO WAS CHECKED FOR THE OBVIOUS WAY IT COULD BE FALSE, because "the gate found nothing" and
// "the gate looked at nothing" produce the same exit code. 73 TRACKED FILES IN THIS REPOSITORY DO CARRY A
// RAW NUL RIGHT NOW: 52 `.dpe` manifests and 21 `.seg` segments under test/vectors, which are sealed
// archive fixtures of the downpipe format and are binary on purpose. Every one of the 73 is excluded by
// the CONTENT test below, on its own stray control bytes rather than on its name, and the scope test
// still admits 1,646 files, so the zero is a finding and not a sweep. If the rule fired on those fixtures
// it would be switched off within the day, which is the only reason the scope test is worth its length.
//
// EXIT CODES. 0 clean. 1 an offender was found. 2 REFUSAL, meaning the check did not happen: the tracked
// set could not be listed, or it was too small to be the real one, or the run threw. A 2 OUTRANKS a 1 and
// outranks a pass. An uncaught throw exiting 1 would read as "finding found", and a stack trace read as a
// finding has already cost this workspace a pass, so every failure path here ends at 2.
//
// House style: Australian English, no em dashes, no rule-of-three, no AI attribution.

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// Text-bearing extensions, the FIRST of two scope tests. A file matching one is in scope without being
// read; a file matching none is judged on its CONTENT by inScope below, so a suffix nobody listed is not
// a hole.
const EXTS = new Set([
  ".ts",
  ".tsx",
  ".mts",
  ".cts",
  ".mjs",
  ".cjs",
  ".js",
  ".json",
  ".jsonl",
  ".md",
  ".yml",
  ".yaml",
  ".html",
  ".css",
  ".svg",
  ".sh",
  ".toml",
  ".txt",
  // Measured from this repository's own tracked set rather than carried over: 982 .ts, 132 .md, 128
  // .json, 42 .mjs, 8 .yml, 7 .toml, 5 .sh, 4 .mts, 4 .ndjson, 2 .svg, 1 .txt, 1 .yaml, plus 48 files
  // with no extension at all, which is exactly why the content test below is not optional here.
  ".ndjson",
]);

// Well below the 1,646 in-scope files actually present, so the floor catches a broken listing rather than
// tracking the repository's size and needing a bump on every file added.
const MIN_FILES = 900;

// git's binary-classification window, borrowed rather than picked, and used ONLY to decide whether a file
// is a real binary and therefore out of scope. It is deliberately NOT used to decide where to stop looking
// for NULs: see the header on why the offset changes the blast radius but never the verdict.
const CLASSIFY_BYTES = 8000;

/**
 * Every tracked file under `root` this rule should read, as paths relative to it.
 *
 * Exported so the self-test can drive the same listing over a fixture repository rather than take this
 * function's word for it.
 *
 * @param {string} root
 * @returns {string[]}
 */
export function trackedSourceFiles(root = ROOT) {
  const out = execFileSync("git", ["-C", root, "ls-files", "-z"], { maxBuffer: 1 << 28 });
  // The -z separator is itself a NUL, which is both the reason this gate exists and the reason the listing
  // must be split on bytes rather than on lines: a path may legitimately contain a newline, and git says
  // so by offering -z at all.
  return out
    .toString("utf8")
    .split("\u0000")
    .filter(Boolean)
    .filter((rel) => !rel.includes("node_modules/") && !rel.includes("vendor/") && inScope(root, rel));
}

/**
 * Is `rel` a text file this rule should read? DECIDED TWICE, and the second test is the point.
 *
 * An extension allowlist alone leaves a hole shaped exactly like the defect: a file saved under a suffix
 * nobody listed is out of scope silently, and the gate reports a clean repository. So a file outside the
 * list is read and judged by CONTENT instead, and there is no list to keep current.
 *
 * The content test is "text apart from the NUL", which is not circular: a NUL is the thing being looked
 * for, so it cannot be evidence of being binary, while any OTHER C0 control byte is something no source
 * file carries and a real binary carries constantly. One is enough to put a file out of scope, so archive
 * and image fixtures are excluded on their first stray byte rather than on their name. That judgement is
 * made over the first CLASSIFY_BYTES only; a file that passes it is then read WHOLE.
 *
 * @param {string} root
 * @param {string} rel
 * @returns {boolean}
 */
export function inScope(root, rel) {
  if (EXTS.has(extname(rel))) return true;
  let head;
  try {
    head = readFileSync(join(root, rel)).subarray(0, CLASSIFY_BYTES);
  } catch {
    return false; // a file git tracks but the disk cannot produce is the listing's problem, not this rule's
  }
  for (const b of head) {
    if (b === 0 || b === 9 || b === 10 || b === 13) continue; // the subject itself, tab, newline, return
    if (b < 0x20 || b === 0x7f) return false; // any other control byte: this is not a source file
  }
  return true;
}

/**
 * Reads `rel` under `root` as BYTES and reports every raw NUL in it. Bytes rather than a string,
 * deliberately: the whole subject of this gate is a reader that quietly declines to look.
 *
 * @param {string} root
 * @param {string} rel
 * @returns {{ rel: string, count: number, firstLine: number, firstByte: number, gitBlind: boolean } | null}
 */
export function nulOffence(root, rel) {
  let buf;
  try {
    buf = readFileSync(join(root, rel));
  } catch {
    return null;
  }
  const first = buf.indexOf(0);
  if (first === -1) return null;
  let count = 0;
  for (let i = 0; i < buf.length; i += 1) if (buf[i] === 0) count += 1;
  let line = 1;
  for (let i = 0; i < first; i += 1) if (buf[i] === 0x0a) line += 1;
  return { rel, count, firstLine: line, firstByte: first, gitBlind: first < CLASSIFY_BYTES };
}

/**
 * Grades one checkout. Separated from main so the self-test can drive the REAL production path over a
 * fixture tree rather than a paraphrase of it.
 *
 * @param {string} root
 * @returns {number} 0 clean, 1 offender found, 2 refusal
 */
export function grade(root) {
  let files;
  try {
    files = trackedSourceFiles(root);
  } catch (err) {
    console.error(`no-raw-nul-gate REFUSAL: could not list the tracked set (${String(err)}). Nothing was checked.`);
    return 2;
  }

  if (files.length < MIN_FILES) {
    console.error(
      `no-raw-nul-gate REFUSAL: only ${files.length} tracked source file(s) listed under ${root}, below the floor of ${MIN_FILES}. That is a broken listing, not a clean repository, and a pass here would prove nothing.`,
    );
    return 2;
  }

  const offenders = [];
  for (const rel of files) {
    const o = nulOffence(root, rel);
    if (o !== null) offenders.push(o);
  }

  if (offenders.length > 0) {
    console.error(`no-raw-nul-gate: ${offenders.length} tracked source file(s) contain a raw NUL byte, out of ${files.length} inspected.`);
    for (const o of offenders) {
      const where = o.gitBlind
        ? "INSIDE git's 8000-byte window, so git treats the whole file as binary and git grep -I drops it entirely"
        : "past git's 8000-byte window, so git still diffs it as text and only grep goes blind";
      console.error(`  FAIL  ${o.rel} carries ${o.count} raw NUL byte(s), the first at line ${o.firstLine} (byte ${o.firstByte}), ${where}.`);
    }
    console.error("");
    console.error("Write the six-character escape instead. It is the identical string at runtime, so nothing that runs changes.");
    console.error("Until you do, grep reports these files as binary rather than printing the matching line, so every");
    console.error("sweep that touches them is silently omitting them and its output cannot say so.");
    return 1;
  }

  console.log(`no-raw-nul-gate ok: ${files.length} tracked source file(s) inspected byte by byte, none carries a raw NUL, so grep and every other text tool can read all of them.`);
  return 0;
}

/**
 * Plants a NUL-bearing file and a clean twin in a THROWAWAY git repository and drives the real listing and
 * the real detector over both. A gate that reports zero must be able to show that it can report one.
 *
 * The bed is a temp directory and never this repository, deliberately. A self-test that plants its subject
 * into the corpus it sweeps measures itself: one pass did exactly that today, its arm found its own plant
 * in its own source, and it failed the first time it ran from the landed tree rather than a worktree.
 *
 * @returns {number} 0 pass, 2 the self-test itself failed
 */
function selfTest() {
  const bed = mkdtempSync(join(tmpdir(), "no-raw-nul-selftest-"));
  const failures = [];
  try {
    execFileSync("git", ["-C", bed, "init", "-q"]);
    // The offender. The NUL sits inside a string, which is where every real instance of this defect in
    // this workspace has been found: a composite map key separator or a control-character regex class.
    writeFileSync(join(bed, "offender.mjs"), Buffer.concat([Buffer.from('export const KEY = "a'), Buffer.from([0]), Buffer.from('b";\n')]));
    // The clean twin. Byte-different, string-identical at runtime, and this is the fix the gate asks for.
    writeFileSync(join(bed, "clean.mjs"), 'export const KEY = "a\\u0000b";\n');
    // A NUL PAST the 8000-byte window, and in THIS repository that is the majority shape rather than the
    // exotic one: 13 of the 17 historical instances above sit past 8000, src/admin/audit.ts as far out as
    // byte 41948. git still reads those as text, so a check built on git's own classification would have
    // called every one of them clean. It must STILL be reported: the offset changes the blast radius,
    // never the verdict.
    writeFileSync(join(bed, "late.mjs"), Buffer.concat([Buffer.from("// " + "x".repeat(9000) + '\nexport const K = "a'), Buffer.from([0]), Buffer.from('b";\n')]));
    // Outside the extension set and holding a NUL. It must NOT be reported, or the rule fires on the
    // archive fixtures this workspace legitimately tracks.
    writeFileSync(join(bed, "fixture.seg"), Buffer.from([0x01, 0x00, 0x02]));
    // Untracked and holding a NUL. It must NOT be reported, because the graded set is the tracked set.
    writeFileSync(join(bed, "stray.mjs"), Buffer.concat([Buffer.from('export const S = "x'), Buffer.from([0]), Buffer.from('y";\n')]));
    // NO EXTENSION AT ALL, and a NUL in it. This is the hole an allowlist leaves and the reason scope is
    // decided twice: it must be found on its CONTENT, because there is no suffix to list.
    writeFileSync(join(bed, "pre-commit-hook"), Buffer.concat([Buffer.from("#!/bin/sh\nX=a"), Buffer.from([0]), Buffer.from("b\n")]));
    // Also no extension, and genuinely binary. It must stay out of scope on its content, or the content
    // rule would drag every tracked binary in and the gate would fire on things that are not defects.
    writeFileSync(join(bed, "archive-blob"), Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x03, 0x02, 0x01]));
    execFileSync("git", ["-C", bed, "add", "offender.mjs", "clean.mjs", "late.mjs", "fixture.seg", "pre-commit-hook", "archive-blob"]);

    const listed = trackedSourceFiles(bed);
    if (!listed.includes("offender.mjs")) failures.push("the listing did not include the planted offender");
    if (!listed.includes("clean.mjs")) failures.push("the listing did not include the planted clean twin");
    if (listed.includes("fixture.seg")) failures.push("the listing included a .seg fixture, so the extension allowlist is not holding");
    if (listed.includes("stray.mjs")) failures.push("the listing included an UNTRACKED file, so the graded set is not the tracked set");
    if (!listed.includes("pre-commit-hook")) failures.push("the listing missed an extensionless TEXT file, so scope is decided by suffix alone and a file saved under a new suffix is invisible");
    if (listed.includes("archive-blob")) failures.push("the listing included an extensionless BINARY file, so the content rule admits real binaries and this gate would fire on things that are not defects");

    const offender = nulOffence(bed, "offender.mjs");
    if (offender === null) failures.push("the detector returned CLEAN on a file carrying a raw NUL, so a zero from it means nothing");
    else if (offender.count !== 1 || offender.firstLine !== 1 || !offender.gitBlind) failures.push(`the detector mis-read the planted NUL: ${JSON.stringify(offender)}`);

    if (nulOffence(bed, "clean.mjs") !== null) failures.push("the detector reported the ESCAPED form as an offence, so the fix it asks for would not pass");
    if (nulOffence(bed, "pre-commit-hook") === null) failures.push("the detector returned CLEAN on the extensionless text file carrying a raw NUL");

    const late = nulOffence(bed, "late.mjs");
    if (late === null) failures.push("the detector MISSED a NUL past byte 8000, so it has reproduced git's blind spot instead of covering it");
    else if (late.gitBlind) failures.push("a NUL past byte 8000 was reported as inside git's window, so the blast-radius sentence would be wrong");

    // The two strings really are the same at runtime. If they were not, the fix this gate demands would be
    // a behaviour change and the gate would not be free.
    const rawValue = "a" + String.fromCharCode(0) + "b";
    const escValue = JSON.parse('"a\\u0000b"');
    if (rawValue !== escValue) failures.push("the raw and escaped forms are NOT the same string, which would make this rule expensive rather than free");
    if (rawValue === "a\\u0000b") failures.push("the escape was read as six literal characters, so the equality above proves nothing");

    // THE FLOOR HAS TO BE ABLE TO FIRE. The bed holds six tracked files, far under MIN_FILES, so the
    // production path over it must REFUSE at 2 rather than report a clean repository. Without this the
    // anti-vacuity branch is prose.
    if (grade(bed) !== 2) failures.push("grading a six-file bed did not refuse, so the anti-vacuity floor is not load-bearing");
  } finally {
    rmSync(bed, { recursive: true, force: true });
  }

  if (failures.length > 0) {
    console.error("no-raw-nul-gate --self-test FAILED:");
    for (const f of failures) console.error(`  ${f}`);
    return 2;
  }
  console.log(
    "no-raw-nul-gate --self-test ok: a planted raw NUL is found and its escaped twin is not, a NUL PAST byte 8000 is still found, a .seg fixture and an untracked file are out of scope, an extensionless text file is in scope while an extensionless binary stays out, the two forms are the same string at runtime, and a too-small tracked set refuses at 2.",
  );
  return 0;
}

/**
 * Is this file the process entry point? CANONICALISED ON BOTH SIDES, which the ported version was not.
 *
 * The port compared `import.meta.url` against a `file://` string built from `resolve(process.argv[1])`,
 * and resolve() does not follow symlinks. Reached through a symlinked path, a file guarded that way
 * decides it is not the entry point, prints nothing, runs nothing and exits 0, which is the silent
 * decline this repository's verdict-guard-gate exists to catch and which it caught here: this gate was
 * its one finding when the file first landed in the chain, and the ported shape had passed in two sibling
 * repositories whose gates do not make this check.
 *
 * Spelled out rather than imported from test/lib/verdict-guard.ts (isEntryPoint) for the reason
 * scripts/stamp-build-id.mjs gives for the same decision: that module installs a process exit hook
 * forcing a non-zero exit when no verdict is declared, which is right for a validator under test/ and
 * wrong for a lint gate that already owns its exit codes, and it is TypeScript, which a plain
 * `node scripts/...` invocation on the pinned Node 22 cannot import.
 *
 * @returns {boolean}
 */
function invokedDirectly() {
  const argv1 = process.argv[1];
  if (argv1 === undefined) return false;
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(argv1);
  } catch {
    // A path that cannot be resolved is not the entry point, and must not throw out of a top-level guard.
    return false;
  }
}

// Guarded so this file can be imported without running, and wrapped so an uncaught throw exits 2 rather
// than 1. 1 means "finding found"; a crash that exits 1 is a crash being read as a finding.
if (invokedDirectly()) {
  let code = 2;
  try {
    code = process.argv.includes("--self-test") ? selfTest() : grade(ROOT);
  } catch (err) {
    console.error(`no-raw-nul-gate REFUSAL: the run threw and nothing was checked (${String(err)}).`);
    code = 2;
  }
  process.exit(code);
}
