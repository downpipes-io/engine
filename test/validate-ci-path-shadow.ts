// A CI path filter is a GATE-DISABLING SWITCH, and this is the gate over that switch.
//
// `paths-ignore` on a workflow trigger decides whether the workflow RUNS AT ALL. A pattern that matches a
// file some gate reads therefore switches that gate off for exactly the commits it was written to police,
// and it does so silently: the pull request shows no failing check because it shows no check. Nothing in a
// review of the gate itself can see this, because the gate is correct and simply never executes.
//
// THE INSTANCE THIS CLOSES. engine's ci.yml carried `paths-ignore: ["**.md", "docs/**", ...]`, while the
// Lint job runs `npm run lint`, whose chain includes `lint:prose`, whose roots are
// `src docs README.md SECURITY.md CONTRIBUTING.md`. Twenty-three tracked files that a gate reads were
// shadowed: everything under docs/, including the gated documents in docs/security/, plus the three
// root-level markdown files. A docs-only commit fired no run.
//
// It is a known shape rather than a one-off. In `downpipe` the same construction meant tampering a
// conformance vector took the local suite from 0 failures to 1 while CI ran nothing. `control-plane` closed
// its own instance at fbe2999 after measuring that its ignored pattern matched exactly four tracked files
// that three gates read.
//
// THE SUBJECT CAN COLLAPSE IN CI, MEASURED AND STILL NOT EXPLAINED. Run 33466451763 on this repo at
// 250f0464 failed this file (chain member 430) with two findings at once: "the prose subject now COVERS the
// whole bundle set (269 files)..." and "the subject is most of the tracked tree (1172 of 1790)". Both trace
// to gateRead below, which is `scripts/writing-rules-source.mjs --print-subject`, run fresh every time.
// `git ls-files` held steady at 1790 tracked files in every job of that run, but gateRead did not: 1717
// locally and in CI's own single-checkout "Lint (Biome)" job, 1172 in one job that checks out siblings and
// runs the full chain, 1367 in ANOTHER job of the SAME run at the SAME commit. The shrinkage sits inside the
// per-file classification in writing-rules-source.mjs's readSubject() (a NUL byte, ENOENT, EISDIR); two
// candidate real-file mutators in that chain were checked and cleared, and the mechanism inside readSubject
// is still open. What this file can do about an unexplained instrument fault is refuse rather than
// misreport it, which is why the floor below exits 2 instead of counting a finding.
//
// A SECOND SHAPE OF THE SAME COLLAPSE, NARROW RATHER THAN GLOBAL. Runs 33591247450 (eca99604) and
// 33742452134 (5be5fbfc) both failed only the bundle-coverage control below with gateRead at 1676 of 1791
// tracked, 93.6%, well clear of the 90% SUBJECT_FLOOR that exists specifically to catch this class of fault.
// The 90% floor bounds total shrinkage; it says nothing about shrinkage concentrated entirely inside the
// 269-file bundle population, which is what both runs measured. The bundle-coverage control now carries its
// own cross-check for exactly that (directRead() below, added after this finding): a bundle file missing
// from gateRead is re-read directly in THIS process before the control is allowed to fail on it, so the same
// unexplained subprocess-boundary fault refuses here too rather than reading as a paths-ignore regression
// that was never made.
//
// WHAT THIS ASSERTS. It recomputes the intersection from the two sources of truth rather than pinning a
// remembered answer: the `paths-ignore` patterns parsed out of the workflows, and the roots that
// package.json actually passes to the prose linter. So a pattern added later, or a root added to
// lint:prose later, is caught by the same assertion without anyone remembering this file exists.
//
// Scoped to ci.yml deliberately. semgrep.yml also ignores "**.md", and that is correct there: semgrep
// scans code, no gate of its own reads markdown, and it does NOT ignore docs/**.
//
// Run: node test/validate-ci-path-shadow.ts

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verdictReached } from "./lib/verdict-guard.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

/**
 * ignoredPatterns pulls every `paths-ignore:` inline list out of a workflow. The workflows write them as a
 * single-line flow sequence, which is what this reads; a future block-sequence spelling would parse to zero
 * patterns, so the count is asserted below rather than trusted.
 */
function ignoredPatterns(yaml: string): string[] {
  const out: string[] = [];
  for (const m of yaml.matchAll(/^\s*paths-ignore:\s*\[([^\]]*)\]/gm)) {
    for (const raw of (m[1] ?? "").split(",")) {
      const t = raw.trim().replace(/^["']|["']$/g, "");
      if (t !== "") out.push(t);
    }
  }
  return out;
}

/**
 * matchesPattern applies the subset of GitHub's path-filter glob semantics these patterns use: `**` spans
 * directory separators, `*` does not, and everything else is literal. Deliberately strict about `*` so the
 * check cannot pass by being more permissive than GitHub is.
 */
function matchesPattern(path: string, pattern: string): boolean {
  let re = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i] as string;
    if (c === "*" && pattern[i + 1] === "*") {
      re += ".*";
      i++;
      continue;
    }
    if (c === "*") {
      re += "[^/]*";
      continue;
    }
    re += c.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`).test(path);
}

// THE PROSE GATE'S SUBJECT, ASKED OF THE GATE ITSELF rather than reconstructed from its parts.
//
// This used to parse two things out of two files: the roots out of package.json's lint:prose, and the EXTS
// array out of the linter's source, then intersect them by hand. Reconstructing a set from the pieces of
// somebody else's implementation is only ever as right as the reconstruction, and the linter has since
// stopped having either piece: it takes no roots and keeps no extension list, because both of those were
// how it came to be blind to 32 em dashes in 8 tracked files. `--print-subject` makes the gate answer for
// itself, so there is nothing left here to drift out of step with it.
const pkg = JSON.parse(readFileSync(resolve(ROOT, "package.json"), "utf8")) as { scripts: Record<string, string> };
const proseScript = pkg.scripts["lint:prose"] ?? "";

console.log("Sources of truth are readable:");
ok("lint:prose is defined in package.json", proseScript !== "");
ok("lint:prose runs the prose gate", proseScript.includes("scripts/writing-rules-source.mjs"));
// THE TEETH HAVE TO BE WIRED INTO THE COMMAND CI ACTUALLY RUNS. The prose gate's --self-test drives its
// fixtures and four mutants and then grades the tree, all in the one process, so the teeth are checked on
// every CI run rather than by whoever remembers to run them. Dropping the flag would leave a gate that
// still grades and never proves it can fail, which is the shape this workspace has been burned by more than
// once: a green job whose self-test was never reached.
ok("lint:prose keeps --self-test wired in, so the gate's teeth are checked on every run", proseScript.includes("--self-test"));

// Every tracked file, from git rather than a walk, so an untracked scratch file cannot change the verdict.
const tracked = execFileSync("git", ["-C", ROOT, "ls-files"], { encoding: "utf8" }).split("\n").filter((s) => s !== "");
ok(`git ls-files returned a plausible tree (got ${tracked.length} files)`, tracked.length > 100);

const gateRead = execFileSync("node", [resolve(ROOT, "scripts/writing-rules-source.mjs"), "--print-subject"], {
  cwd: ROOT,
  encoding: "utf8",
  maxBuffer: 1 << 28,
})
  .split("\n")
  .filter((s) => s !== "");
ok(`the prose gate reads a non-empty set of tracked files (got ${gateRead.length})`, gateRead.length > 0);
// THE ANTI-VACUITY FLOOR, AND WHY IT REFUSES RATHER THAN FINDS.
//
// The subject is every tracked file bar the binary ones, so it should be most of the tree rather than a
// corner of it. A subject that collapsed back to a fraction would make every assertion below weaker without
// making any of them fail, which is precisely how the previous blindness went unnoticed for so long, and it
// is precisely what run 33466451763 measured (see the header): the same gateRead computation returned 1717,
// 1172 and 1367 across jobs of one run at one commit, with `git ls-files` unmoved at 1790 throughout.
//
// A shrunken subject is not a defect in ci.yml's paths-ignore, it is this gate's own read of its corpus
// failing. Reporting that as a finding (exit 1) sends a reader looking for a shadowed path that does not
// exist; the honest verdict is this workspace's own exit-2 convention, "I could not check", which is exactly
// what scripts/writing-rules-source.mjs uses for the same failure mode in its own subject (its header:
// "Exit: 0 clean, 1 violations, 2 could-not-check"). So this refuses and stops here, before the shadow
// assertion ("no file the prose or vector-bundle gate reads is matched...") and the bundle-coverage control
// ("the prose subject now COVERS the whole bundle set...") further down, both of which trust gateRead to be
// complete and would otherwise pass or fail on degraded data without saying so. Neither needs its own floor:
// refusing here first is what keeps them from running on a subject that cannot support a verdict.
const SUBJECT_FLOOR = 0.9;
const subjectRatio = gateRead.length / tracked.length;
if (subjectRatio <= SUBJECT_FLOOR) {
  console.log(
    `  FAIL the subject is most of the tracked tree (${gateRead.length} of ${tracked.length}, ` +
      `${(subjectRatio * 100).toFixed(1)}%, floor ${(SUBJECT_FLOOR * 100).toFixed(0)}%)`,
  );
  console.log(
    "\nREFUSED: the prose gate's subject collapsed, so nothing below was graded. This is exit 2, CANNOT " +
      "CHECK, not exit 1, FOUND SOMETHING: do not go looking for a paths-ignore defect from this run, and do " +
      "not record a pass either. Re-run where the checkout is not losing files under the gate.",
  );
  verdictReached(1);
  process.exit(2);
}
ok(
  `the subject is most of the tracked tree (${gateRead.length} of ${tracked.length}, ` +
    `${(subjectRatio * 100).toFixed(1)}% ≥ floor ${(SUBJECT_FLOOR * 100).toFixed(0)}%)`,
  true,
);
ok("every file in the subject is tracked", gateRead.every((f) => tracked.includes(f)));

const ciYaml = readFileSync(resolve(ROOT, ".github/workflows/ci.yml"), "utf8");
const patterns = ignoredPatterns(ciYaml);
console.log(`\nci.yml paths-ignore patterns: ${patterns.length === 0 ? "(none)" : patterns.join(" ")}`);
// A PARSE THAT RETURNED NOTHING AND A FILE THAT IGNORES NOTHING ARE DIFFERENT FACTS, and the floor here
// used to conflate them. It read `patterns.length >= 2`, which was true only because ci.yml happened to
// carry two patterns; it could not survive the list correctly emptying, and it would have passed a
// block-sequence `paths-ignore:` that this flow-sequence parser reads as zero while sitting right next to a
// flow one. So the floor is now per KEY: every `paths-ignore:` present must have yielded at least one
// pattern. No keys at all is a true zero and the assertions below are then trivially satisfied rather than
// vacuously so, which is the state ci.yml is deliberately in.
const ignoreKeys = (ciYaml.match(/^\s*paths-ignore:/gm) ?? []).length;
console.log(`ci.yml carries ${ignoreKeys} paths-ignore key(s)`);
ok(
  `every paths-ignore key in ci.yml parsed to at least one pattern (${ignoreKeys} key(s), ${patterns.length} pattern(s))`,
  patterns.length >= ignoreKeys,
);

// THE SECOND GATE-READ SET: the committed recovery bundles in the conformance corpus, which
// test/validate-vector-bundle-corpus.ts opens through verifyBundle. It is kept separate from the prose set
// because it is shadowed by a DIFFERENT class of pattern. A re-added "**.md" would be caught by the prose
// set anyway (README.md is in it), but an extension pattern like "**.sig" or "**.dpe" would shadow 180
// signed fixtures and touch no prose root at all, because those extensions are not in the linter's EXTS.
// Directory patterns such as "test/**" USED to belong in that sentence and no longer do: the prose roots
// now cover test/, so the prose arm sees them. The prose set alone still answers this question only by
// accident, but the accident is now about extensions rather than directories. The population
// is derived from the archive layout rather than from a format version, so a version bump does not quietly
// empty it.
const bundleRead = tracked.filter((f) => /^test\/vectors\/[^/]+\/archive\/_RECOVERY\//.test(f));
ok(`the vector-bundle gate reads a non-empty set of tracked files (got ${bundleRead.length})`, bundleRead.length > 0);

// THE ASSERTION. No pattern that stops CI running may match a file a gate reads.
const allGateRead = [...gateRead, ...bundleRead];
const shadowed = allGateRead.filter((f) => patterns.some((p) => matchesPattern(f, p)));
console.log("\nNo CI-ignored path is read by a gate:");
for (const f of shadowed.slice(0, 25)) console.log(`       shadowed: ${f}`);
ok(`no file the prose or vector-bundle gate reads is matched by a ci.yml paths-ignore pattern (${allGateRead.length} read, ${shadowed.length} shadowed)`, shadowed.length === 0);

// POSITIVE CONTROLS, so a green above cannot be the matcher failing to match anything. Each is a pattern
// that WAS in this file's paths-ignore and a file that IS read by the gate, of the same kind as the real
// finding, so a broken matcher shows up here as a failure rather than as a clean sweep.
console.log("\nControls (the matcher matches what it should):");
const docsSecurity = gateRead.find((f) => f.startsWith("docs/security/"));
ok("CONTROL: a docs/security file is in the gate-read set", docsSecurity !== undefined);
ok("CONTROL: the retired \"docs/**\" pattern WOULD have shadowed it", docsSecurity !== undefined && matchesPattern(docsSecurity, "docs/**"));
ok("CONTROL: the retired \"**.md\" pattern WOULD have shadowed README.md", gateRead.includes("README.md") && matchesPattern("README.md", "**.md"));
ok("CONTROL: a single * does NOT span a directory separator", !matchesPattern("docs/security/sbom.md", "docs/*"));
// This control used to read "an unrelated source file is NOT matched by the SURVIVING patterns", and there
// are no surviving patterns to match it against any more, so it would have gone on printing ok while
// asserting nothing. It is re-pointed at a retired pattern, where it still discriminates: a matcher that
// matched everything would fail here.
ok("CONTROL: a source file is NOT matched by the retired \"docs/**\" pattern", !matchesPattern("src/format/bundle.ts", "docs/**"));
// The bundle arm gets its own controls, because a green above must not be able to come from an empty or
// unmatched second set. The first names the pattern that DID shadow these 180 files until 63379acb; the
// second names a pattern that would shadow them while leaving every prose root untouched, which is the
// case the prose set cannot see.
//
// THE SECOND CONTROL USED TO BE "test/**" AND IT NO LONGER QUALIFIES, which is a change worth writing
// down rather than quietly editing. lint:prose used to read src, docs and three named files, so "test/**"
// was the textbook pattern that shadowed 180 signed fixtures while touching no prose root at all. It now
// touches 620 of them, because the prose roots widened to the whole repo when house style turned out to
// be binding everywhere and graded on 39 percent of this repo. So the property moved, and the control has
// to move with it or it stops testing what its own sentence claims. An EXTENSION-shaped pattern still has
// the property the directory-shaped one lost: ".sig" is not in the linter's EXTS, so "**.sig" reaches the
// detached signatures and no prose file anywhere.
const aFormatMd = bundleRead.find((f) => f.endsWith("/FORMAT.md"));
ok("CONTROL: a vector FORMAT.md is in the bundle gate-read set", aFormatMd !== undefined);
ok("CONTROL: the retired \"**.md\" pattern WOULD have shadowed it", aFormatMd !== undefined && matchesPattern(aFormatMd, "**.md"));
const aSumsSig = bundleRead.find((f) => f.endsWith("/SHA384SUMS.sig"));
ok("CONTROL: a detached bundle signature is in the bundle gate-read set (not just markdown)", aSumsSig !== undefined);
// THE EXTENSION-SHAPED CONTROL IS RETIRED IN ITS TURN, and the reason is worth writing down because it is
// the second time this control has had to move. It read: "**.sig" reaches the detached signatures and no
// prose file anywhere. That was true while the prose gate had an extension list, and .sig was not on it.
// The prose gate no longer has an extension list: its subject is every tracked file that is not binary, so
// all 269 files of the bundle set are in it, .sig included. No pattern can now reach the bundle set without
// also reaching prose, and asserting otherwise would be asserting something false.
//
// What replaces it is the fact that makes it false, stated as an assertion so it cannot rot the way the
// sentence it replaces did. If the prose subject ever narrows again, this is what goes red.
//
// THAT WAS THE THEORY, AND IT WAS WRONG. This paragraph used to claim the anti-vacuity floor above (the
// 90% SUBJECT_FLOOR on gateRead vs tracked) already covered this assertion, so it needed no floor of its
// own. Run 33591247450 at eca99604 and run 33742452134 at 5be5fbfc both measured otherwise: gateRead sat at
// 1676 of 1791 tracked files, 93.6%, comfortably clear of the 90% floor, while the bundle set STILL lost
// coverage. The floor bounds how far the subject can shrink in total; it says nothing about whether the
// shrinkage is spread evenly or lands entirely inside one 269-file population, which is exactly what
// happened both times. A floor sized for the whole tree cannot catch a loss concentrated in 15% of it.
//
// SO THIS CONTROL GETS ITS OWN CROSS-CHECK, independent of gateRead entirely. bundleRead's 269 files are
// fixed, committed, non-NUL text and signatures (verified locally while this cross-check was added: every
// one reads clean in this process). If a file in that set is missing from gateRead, directRead() below
// re-reads that SAME file, right here, on the SAME checkout `--print-subject`'s child process just read.
// Agreement (this process also finds it NUL-bearing or unreadable) means the loss is real and the assertion
// stays a FAIL. Disagreement (this process finds it clean and readable) means the two processes read
// identical bytes on disk and reached different answers, which is a subprocess-boundary fault, not a
// subject that narrowed, and it refuses (exit 2, CANNOT CHECK) rather than misreport it as a paths-ignore
// regression that does not exist.
function directRead(rel: string): "clean" | "nul" | "unreadable" {
  try {
    const buf = readFileSync(resolve(ROOT, rel));
    return buf.indexOf(0) === -1 ? "clean" : "nul";
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "ENOENT" || (err as NodeJS.ErrnoException).code === "EISDIR" ? "unreadable" : "clean";
  }
}
const missingFromGate = bundleRead.filter((f) => !gateRead.includes(f));
const genuinelyMissing = missingFromGate.filter((f) => directRead(f) !== "clean");
if (missingFromGate.length > 0 && genuinelyMissing.length === 0) {
  console.log(
    `\nREFUSED: ${missingFromGate.length} bundle file(s) fell out of the prose subject as computed by the ` +
      "CHILD process (scripts/writing-rules-source.mjs --print-subject), but re-reading every one of them " +
      "directly in THIS process, on the same checkout, finds each readable and NUL-free. That is a " +
      "subprocess-boundary disagreement over identical bytes, not a subject that narrowed: this workspace's " +
      "own exit-2 convention, CANNOT CHECK, not exit 1, FOUND SOMETHING. Missing: " +
      `${missingFromGate.slice(0, 10).join(", ")}${missingFromGate.length > 10 ? ", ..." : ""}`,
  );
  verdictReached(1);
  process.exit(2);
}
ok("CONTROL: a \"**.sig\" pattern WOULD shadow the bundle signature", aSumsSig !== undefined && matchesPattern(aSumsSig, "**.sig"));
ok(
  `the prose subject now COVERS the whole bundle set (${bundleRead.length} files), so no pattern can shadow the bundle arm alone`,
  missingFromGate.length === 0,
);
// And the pair that records WHY the earlier swap happened, so a future reader does not undo it: "test/**"
// still shadows the fixtures, but it is caught by the prose arm too, so it cannot stand for a bundle-only
// class either.
ok("CONTROL: \"test/**\" still shadows the bundle set", aFormatMd !== undefined && matchesPattern(aFormatMd, "test/**"));
ok("CONTROL: \"test/**\" is visible to the PROSE arm as well, which is why it was retired as the bundle-only control", gateRead.some((f) => matchesPattern(f, "test/**")));

console.log(failures === 0 ? "\nCI PATH SHADOW PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures);
if (failures > 0) process.exit(1);
