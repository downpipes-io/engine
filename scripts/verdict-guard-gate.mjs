#!/usr/bin/env node
// verdict-guard-gate: every validator entry point must be enrolled in the shared completion guard.
//
// WHY THIS GATE EXISTS. test/lib/verdict-guard.ts closes the class where a validator reaches exit 0
// without ever reaching its own tally, so every assertion in the run is incapable of failing. A guard
// that only some validators opt into is the same defect wearing a helmet, so the requirement is not a
// list kept by hand here: it is DERIVED from what the repo actually runs.
//
// THE DERIVATION, in order:
//   1. Entry points: every script path invoked as a process by a package.json script (transitively
//      through `npm run X` and through any `sh scripts/*.sh` it calls) or by a step in
//      .github/workflows/*.yml. YAML comments are stripped first, because two files (test/write-archive.ts
//      and test/scale-go-reader.ts) were derived as entry points purely from PROSE in ci.yml.
//   2. Direct invocations only: `node <path>` or `[npx] tsx <path>`. A file handed to vitest or stryker
//      is run by a framework that reports its own verdict, so the guard does not apply to it.
//   3. Required: an entry point under test/ that is a validator, decided by SHAPE, not by name alone:
//      its basename starts with `validate-`, OR it prints assertion-shaped lines, OR it has a tally
//      that decides the exit code.
// Then: every required entry point must import the guard and call verdictReached(), and must have some
// failure path at all.
//
// TWO SCOPES, DELIBERATELY DIFFERENT. Enrolment and "can it fail at all" apply to the validators under
// test/, because only a validator owes a verdict. The uncanonicalised main-guard finding applies to
// EVERY derived entry point, wherever it lives. Its defect is "this file silently did not run", which is
// no less a defect in a build or deploy script, and narrowing it to test/ is exactly what let
// scripts/stamp-build-id.mjs keep the retired shape while this gate reported a clean pass around it
// (widened). That script is run by scripts/deploy.sh as
// `node scripts/stamp-build-id.mjs || echo "artefact-hash stamp skipped ..."`, where the echo is the
// operator's only warning and fires only on a non-zero exit, so a silent decline at exit 0 suppresses
// the very message written to cover it.
//
// FAILS WHEN IT CANNOT RUN, and FAILS WHEN THERE IS NOTHING TO CHECK: exit 2 if package.json or the
// guard module is unreadable, if the guard module has lost its exit hook, if the derivation yields no
// entry points, or if the required set falls under the floor. A gate that silently checks nothing is
// the same bug it is here to catch.
//
// Run: node scripts/verdict-guard-gate.mjs

import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join, basename, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { blankComments, blankCommentsAndStrings } from "./lib/blank-comments.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const GUARD_REL = "test/lib/verdict-guard.ts";
// The floor is a count, not a list. It is deliberately well under the current number so ordinary churn
// does not trip it, while a derivation that collapses (a renamed script block, a regex that stops
// matching) cannot pass as "nothing to check".
const REQUIRED_FLOOR = 300;

function die(code, msg) {
  console.error(`verdict-guard-gate: ${msg}`);
  process.exit(code);
}

// ---- the guard module itself must exist and still have its teeth -------------------------------------
const guardAbs = join(REPO, GUARD_REL);
if (!existsSync(guardAbs)) die(2, `cannot check: ${GUARD_REL} is missing`);
const guardSrc = readFileSync(guardAbs, "utf8");
for (const [what, re] of [
  ["an exit listener", /process\.on\(\s*["']exit["']/],
  ["a forced non-zero exit code", /process\.exitCode\s*=\s*1/],
  ["an exported verdictReached", /export function verdictReached/],
]) {
  if (!re.test(guardSrc)) die(2, `cannot check: ${GUARD_REL} no longer contains ${what}, so enrolment would be meaningless`);
}

// ---- derive the entry points -------------------------------------------------------------------------
const pkgPath = join(REPO, "package.json");
if (!existsSync(pkgPath)) die(2, "cannot check: package.json is missing");
const scripts = JSON.parse(readFileSync(pkgPath, "utf8")).scripts ?? {};
if (Object.keys(scripts).length === 0) die(2, "cannot check: package.json declares no scripts");

// The verb immediately before the path is what says whether the guard applies. The trailing negative
// lookahead is load-bearing: without it ".json" matches as ".js" and the derivation invents entry points
// that never existed, which is how coverage/c8/coverage-summary.js first appeared in this list.
// The interpreter may be a literal (`node`, `tsx`, `npx tsx`) OR a shell variable, because
// scripts/e2e-writer-reader.sh sets NODE="${NODE:-node}" and invokes `"$NODE" test/write-archive.ts`.
// Matching only the literal missed that one entirely, and a validator invoked through a variable would
// have been silently unenrolled, which is the exact hole this gate exists to close.
const DIRECT_RE = /(?:^|[\s;&|(])(?:npx\s+)?(node|tsx|"?\$\{?[A-Z_][A-Z0-9_]*\}?"?)\s+(?:--[^\s]+\s+)*((?:\.\/)?(?:[A-Za-z0-9_.-]+\/)+[A-Za-z0-9_.-]+\.(?:ts|mts|cts|mjs|cjs|js))(?![A-Za-z0-9])/g;

const direct = new Map(); // repo-relative path -> Set(where)

function scanCommand(cmd, where, seen = new Set()) {
  for (const m of String(cmd).matchAll(DIRECT_RE)) {
    const p = m[2].replace(/^\.\//, "");
    if (!direct.has(p)) direct.set(p, new Set());
    direct.get(p).add(where);
  }
  for (const m of String(cmd).matchAll(/npm\s+run\s+(?:--silent\s+|-s\s+)?([A-Za-z0-9:_-]+)/g)) {
    if (seen.has(m[1])) continue;
    seen.add(m[1]);
    if (scripts[m[1]] !== undefined) scanCommand(scripts[m[1]], `${where} -> npm run ${m[1]}`, seen);
  }
  for (const m of String(cmd).matchAll(/(?:sh|bash)\s+((?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+\.sh)/g)) {
    const abs = join(REPO, m[1]);
    if (existsSync(abs)) scanCommand(readFileSync(abs, "utf8"), `${where} -> sh ${m[1]}`, seen);
  }
}

for (const [name, cmd] of Object.entries(scripts)) scanCommand(cmd, `npm:${name}`);

const wfDir = join(REPO, ".github", "workflows");
const workflows = existsSync(wfDir) ? readdirSync(wfDir).filter((f) => /\.ya?ml$/.test(f)) : [];
if (workflows.length === 0) die(2, "cannot check: no .github/workflows/*.yml found, so CI reachability cannot be derived");
for (const wf of workflows) {
  const src = readFileSync(join(wfDir, wf), "utf8")
    .split("\n")
    .map((l) => l.replace(/(^|\s)#.*$/, "$1"))
    .join("\n");
  scanCommand(src, `ci:${wf}`);
}

if (direct.size === 0) die(2, "cannot check: the derivation found no directly-invoked scripts at all");

// ---- decide which of them are validators, by shape ---------------------------------------------------
// blankComments and blankCommentsAndStrings are shared with validator-reachability-gate.mjs and
// crossrepo-typecheck-gate.mjs (scripts/lib/blank-comments.mjs), consolidated from three
// independently-written copies of the same scan. See that module's header for the full attack history
// (R-106 here, R-107 and R-109 in the other two gates) and the corpus-verification this function has had.
// The enrolment check below used to test comment-blanked text (strings intact) with a bare substring/
// regex search for "verdict-guard.ts" and "verdictReached(" ANYWHERE in the file, so a validator whose
// real import and real call were deleted still passed as "enrolled" when a STRING merely NAMED them.

// A real import statement of verdictReached is verified LINE BY LINE against the ORIGINAL source
// (the module specifier IS a string literal, so blankCommentsAndStrings would blank the very path
// this needs to read), but ONLY on a line the structural (comments+strings blanked) view still
// shows starting with the bare `import` keyword outside any string or comment -- so an `import ...`
// token sitting inside a decoy string or a multi-line template literal, which blankCommentsAndStrings
// blanks away on that same line, is never treated as a real import.
const IMPORT_LINE_RE = /^\s*import\s*\{[^}]*\bverdictReached\b[^}]*\}\s*from\s*["'`]([^"'`]*)["'`]/;
function importsVerdictGuard(src, structural) {
  const srcLines = src.split("\n");
  const structLines = structural.split("\n");
  for (let li = 0; li < structLines.length; li++) {
    if (!/^\s*import\b/.test(structLines[li])) continue;
    const m = IMPORT_LINE_RE.exec(srcLines[li] ?? "");
    if (m && /verdict-guard\.ts$/.test(m[1])) return true;
  }
  return false;
}

const ASSERTION_PRINT = /console\.log\([^)]*\b(?:"|'|`)\s*(?:ok|FAIL)/i;
// A TALLY is an accumulated count deciding the exit, which is what makes a script a validator. A bare
// process.exit(1) is NOT a tally: test/write-archive.ts is a fixture PRODUCER whose only exit(1) is a
// usage error, and treating that as a validator made the gate demand a verdict from something that has
// no assertions to report. The zero-comparison is the same shape the enrolment codemod locates.
const TALLY = /(?:[A-Za-z_$][\w$]*(?:\.[\w$]+|\(\))*(?:\.length)?)\s*(?:>|!==|!=|>=|===|==)\s*0[\s\S]{0,600}?(?:process\.exit\(\s*1\s*\)|process\.exitCode\s*=)|process\.exit\(\s*[A-Za-z_$][^)]*\?/;
const ANY_FAILURE_PATH = /process\.exit\(\s*[^0\s]|process\.exitCode\s*=|(^|\s)throw\s/m;

// entryPoints is EVERY derived entry point, whatever directory it lives in. `required` narrows to the
// validators under test/, which is the right scope for the enrolment and failure-path findings: only a
// validator owes a verdict. The main-guard finding below is deliberately NOT narrowed that way. Its
// defect is "this file silently did not run", which is a defect in ANY script a deploy or a workflow
// invokes, and scoping it to test/ is what let scripts/stamp-build-id.mjs carry the retired
// uncanonicalised shape while this gate reported a clean pass around it.
const entryPoints = [];
const required = [];
const skippedNotValidator = [];
for (const [p, where] of [...direct.entries()].sort()) {
  const abs = join(REPO, p);
  if (!existsSync(abs)) continue;
  if (/\/(vitest|runtime)\//.test(p)) continue; // run by a framework that reports its own verdict
  const src = readFileSync(abs, "utf8");
  const code = blankComments(src);
  // The main-guard check needs string/template interiors blanked too, not just comments. Every
  // validator ends with a template literal of the shape
  //   `VERDICT: ${failures === 0 ? ...} entry=${import.meta.url.replace(...)}`
  // which names an entry-point identity and compares on ONE line while being neither. Against the
  // comments-only view that read as four findings, all four false. Blanking strings removes them and
  // leaves real comparisons, which are never inside a literal.
  entryPoints.push({ path: p, src, code, structural: blankCommentsAndStrings(src), where: [...where] });
  if (!p.startsWith("test/")) continue;
  const isValidator = /^validate-/.test(basename(p)) || ASSERTION_PRINT.test(code) || TALLY.test(code);
  if (!isValidator) { skippedNotValidator.push(p); continue; }
  required.push({ path: p, src, code, where: [...where] });
}

if (required.length === 0) die(2, "cannot check: no validator entry points were derived, so there is nothing to check");
if (required.length < REQUIRED_FLOOR) {
  die(2, `cannot check: only ${required.length} validator entry points were derived, under the floor of ${REQUIRED_FLOOR}. The derivation has broken, or the chain has been gutted.`);
}

// ---- the two findings --------------------------------------------------------------------------------
const unenrolled = [];
const cannotFail = [];
// A main-module check that does not CANONICALISE decides "I am not the entry point" through a symlinked
// path, so the file prints nothing, runs nothing and exits 0. macOS ships /tmp as a symlink to
// private/tmp and every scratch worktree here sits under it, so this is not hypothetical: it took out
// six harness gates and one engine validator. Only realpathSync on BOTH sides closes it, which is what
// isEntryPoint() in the guard module does.
// The token must be an OPERAND of the comparison, not merely on the same line as one.
//
// Two failures shaped this. Requiring the token be literally adjacent to `===` misses every wrapped
// form, including the corrected one (realpathSync(fileURLToPath(import.meta.url)) === realpathSync(argv1)),
// which leaves the check with nothing to look at and calls that a pass. Accepting the token anywhere on
// a line carrying `===` produced four false positives instead: every validator ends with
//   `VERDICT: ${failures === 0 ? "PASS" : "FAIL"} ... entry=${import.meta.url.replace("file://", "")}`
// where a tally comparison and an entry-point identity share one line and neither is the other's
// operand. Blanking strings does not help, because a template SUBSTITUTION is code and stays.
//
// So: the token, allowing for closing parens, immediately precedes the `===`; or the `===` is
// immediately followed by the token, allowing for opening wrapper calls.
const IDENTITY = String.raw`(?:import\.meta\.url|process\.argv\[1\])`;
const MAIN_MODULE_CHECK = new RegExp(
  `${IDENTITY}\\s*\\)*\\s*===|===\\s*(?:[A-Za-z_$][\\w$]*\\s*\\(\\s*)*${IDENTITY}`,
);
// The canonicalisation must sit AT the comparison, not merely somewhere in the file. A file-wide
// /realpathSync/ test is a false negative waiting to happen, and it was one: scripts/stamp-build-id.mjs
// imports realpathSync from node:fs on line 53, so a file-wide exclusion cleared it no matter what the
// comparison on line 205 actually said. Measured by putting the retired expression back in a
// file that still carried the import, against which the file-wide form reported a clean pass.
const CANONICALISED = /realpathSync\s*\(|isEntryPoint\s*\(/;
/**
 * comparesWithoutCanonicalising finds each entry-point comparison and asks whether THAT comparison
 * canonicalises, looking only at the statement it sits in (the matched line, plus its neighbours, since
 * such a comparison is routinely wrapped after the `===`). An import twenty lines away no longer counts.
 */
function comparesWithoutCanonicalising(code) {
  const lines = code.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (!MAIN_MODULE_CHECK.test(lines[i])) continue;
    const window = lines.slice(Math.max(0, i - 1), i + 2).join("\n");
    if (!CANONICALISED.test(window)) return true;
  }
  return false;
}
const uncanonicalised = [];
for (const r of required) {
  // Both checks run against the STRUCTURAL view (comments AND string/template interiors blanked), or
  // a source line the structural view confirms is real code, so a decoy string or comment naming the
  // import/call cannot be mistaken for the real thing (see blankCommentsAndStrings above).
  const structural = blankCommentsAndStrings(r.src);
  const imports = importsVerdictGuard(r.src, structural);
  const declares = /verdictReached\s*\(/.test(structural);
  if (!imports || !declares) unenrolled.push({ ...r, imports, declares });
  if (!ANY_FAILURE_PATH.test(r.code)) cannotFail.push(r);
}
// The main-guard finding runs over EVERY entry point. A build or deploy script that decides it is not
// the entry point is worse off than a validator that does, not better: scripts/deploy.sh runs
// `node scripts/stamp-build-id.mjs || echo "artefact-hash stamp skipped ..."`, so the operator's only
// warning is reached on a NON-ZERO exit, and a guard that declines silently exits 0 and suppresses it.
for (const r of entryPoints) {
  if (comparesWithoutCanonicalising(r.structural)) uncanonicalised.push(r);
}

console.log(`verdict-guard-gate: ${direct.size} directly-invoked scripts derived, ${entryPoints.length} of them present on disk, ${required.length} of those validator entry points under test/`);
console.log(`  canonicalised-entry-guard check: all ${entryPoints.length} entry points (NOT only the validators)`);
console.log(`  guard module: ${GUARD_REL} present with its exit hook intact`);
console.log(`  not treated as validators (no validate- name, no assertion output, no tally): ${skippedNotValidator.length}${skippedNotValidator.length ? ` (${skippedNotValidator.join(", ")})` : ""}`);

let bad = 0;
if (cannotFail.length) {
  bad += cannotFail.length;
  console.log(`\n  ${cannotFail.length} validator entry point(s) have NO failure path at all, so they cannot fail for any reason:`);
  for (const r of cannotFail) console.log(`    ${r.path}  (invoked by ${r.where.join(", ")})`);
}
if (uncanonicalised.length) {
  bad += uncanonicalised.length;
  console.log(`\n  ${uncanonicalised.length} entry point(s) compare against process.argv[1] WITHOUT canonicalising:`);
  for (const r of uncanonicalised) console.log(`    ${r.path}  (invoked by ${r.where.join(", ")})`);
  console.log(`\n  Reached through a symlinked path such a file decides it is not the entry point, prints`);
  console.log(`  nothing, runs nothing and exits 0. Use isEntryPoint(import.meta.url) from ${GUARD_REL}.`);
}
if (unenrolled.length) {
  bad += unenrolled.length;
  console.log(`\n  ${unenrolled.length} validator entry point(s) are NOT enrolled in the completion guard:`);
  for (const r of unenrolled) {
    const why = !r.imports ? `does not import ${GUARD_REL}` : "imports the guard but never calls verdictReached()";
    console.log(`    ${r.path}  ${why}  (invoked by ${r.where.join(", ")})`);
  }
  console.log(`\n  Enrol each one with two lines: import { verdictReached } from "<rel>/lib/verdict-guard.ts";`);
  console.log(`  and verdictReached(<failureCount>); immediately before the tally that decides the exit code.`);
}

if (bad > 0) {
  console.log(`\nVERDICT GUARD GATE: ${bad} finding(s)`);
  process.exit(1);
}
console.log(`\nVERDICT GUARD GATE PASS (${required.length} validator entry points, all enrolled, all able to fail)`);
