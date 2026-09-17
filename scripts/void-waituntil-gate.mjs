#!/usr/bin/env node
// void-waituntil-gate: a bare `void <asyncCall>(...)` in an admin request-handler file may not INCREASE.
//
// WHY THIS EXISTS. A passkey diagnostic write was fire-and-forget
// with a bare `void`, threading no ctx.waitUntil, so the write did not reliably survive the request's
// lifecycle: nothing looked wrong (the response was correct), but the evidence was silently lost. Two
// independent live drives against `probe` reproduced it deterministically. An
// independent enumeration of every `void <call>(` site across router.ts, its router-*.ts spokes and
// scim.ts found 126 at the sha this gate first ran on; roughly 81 were fixed the same session, threading
// runtime.waitUntil (or, for scim.ts, the raw ExecutionContext.waitUntil it already carries) through a
// shared fireInBackground(runtime, task) helper. The remainder is real, counted debt, not fixed here.
//
// WHY A RATCHET, NOT A CLEAN GATE (same shape as lint-scope-gate.mjs). Fixing the remaining debt in one
// change means touching ~119 further call sites of router-core.ts's/router-session.ts's shared leaf
// helpers (rateLimited, requireStepUp, authRateLimited, resolveCaller and friends) across 22 files, a
// structural change out of scope for the session that wrote this gate. So the debt is MEASURED and
// PINNED: the exact count sits in void-waituntil-baseline.json, this gate refuses any INCREASE, and a new
// bare-void call site added anywhere in the scanned corpus without either an await or the escape hatch
// below fails the build. Ratcheting the pin down is the follow-up; the point of this file is that the
// count can no longer grow unnoticed the way it grew to 126 in the first place.
//
// THE ESCAPE HATCH. A call that is genuinely, deliberately fire-and-forget (its loss changes nothing
// observable) is marked with a trailing `// void-ok: <reason>` comment on the SAME line as the `void`
// call. The reason must be a real sentence (at least 12 non-whitespace characters after the colon): a
// bare `// void-ok` or `// void-ok: x` does not count, so the marker cannot be used as a silent bypass --
// it has to say WHY, in the diff, where a reviewer sees it. A marked call is excluded from the count
// entirely (it is not debt to ratchet down, it is a reviewed, deliberate decision).
//
// WHAT THIS DOES NOT PROVE. It is a syntactic pattern match (`void <identifier>(`), not a type checker: it
// cannot itself confirm the discarded call is async (Promise-returning) rather than a harmless `void
// someSyncCall()` idiom. Empirically, in this corpus, every matched identifier IS an async diagnostic/
// notify helper (verified by hand during the triage this gate follows from); a future false positive
// costs a one-line void-ok marker, which is the deliberately conservative bias (a false positive is
// annoying; a false negative is a silently lost write). It also does NOT prove a `fireInBackground(runtime,
// task)` call actually keeps its task alive in production -- only that the call is no longer a BARE void.
// That is the same distinction R-111's own fix drew: made awaitable is not the same as live-proven.
//
// SCOPE, STATED HONESTLY (how much of the corpus this can fail on). Scans exactly router.ts, every
// router-*.ts spoke and scim.ts under src/admin/ (router-helpers.ts excluded: it is the shared LEAF
// module the spokes import, not a spoke itself, and carries no request-handler call sites of its own).
// A void-discarded async call anywhere ELSE in the engine (sched/, seal/, cron/, another src/admin/*.ts
// file outside this set) is NOT covered by this gate.
//
// FAILS WHEN IT CANNOT RUN, OR WHEN THERE IS NOTHING TO CHECK: exit 2 if src/admin/ is missing or
// unreadable, if the glob matches zero files (a rename/move that silently emptied the scan), or if the
// baseline is missing/malformed. "0 files scanned" must never read as "0 violations, clean".
//
// Run: node scripts/void-waituntil-gate.mjs              (add --write-baseline to re-pin after a real fix)
//      node scripts/void-waituntil-gate.mjs --self-test   (proves the gate has teeth, on disposable fixtures)
//
// House style: Australian English, no em dashes, no rule-of-three, no AI attribution.

import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { blankComments } from "./lib/blank-comments.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const ADMIN_DIR = join(REPO, "src", "admin");
const BASELINE = join(REPO, "scripts", "void-waituntil-baseline.json");
const WRITE = process.argv.includes("--write-baseline");
const SELF_TEST = process.argv.includes("--self-test");

// VOID_CALL_RE matches a bare `void <identifier-or-member-path>(` -- a discarded CALL, never a discarded
// bare identifier (`void task;`, `void w;`): the fireInBackground fallback this gate's own fix pattern
// uses is exactly that shape, so it is structurally excluded by requiring the trailing "(".
const VOID_CALL_RE = /void ([a-zA-Z_][a-zA-Z0-9_.]*)\(/g;
// VOID_OK_RE requires a real reason: "void-ok:" followed by at least 12 non-whitespace characters.
const VOID_OK_RE = /\/\/\s*void-ok:\s*(\S.{11,})/;

function die(code, msg) {
  console.error(`void-waituntil-gate: ${msg}`);
  process.exit(code);
}

// scanDir finds the exact corpus: router.ts, router-*.ts (excluding router-helpers.ts) and scim.ts,
// directly under `dir` (not recursive: this is the admin router hub + its spokes, a flat directory).
function corpusFiles(dir) {
  if (!existsSync(dir)) return null;
  let names;
  try {
    names = readdirSync(dir);
  } catch {
    return null;
  }
  return names.filter((n) => n === "router.ts" || n === "scim.ts" || (/^router-.*\.ts$/.test(n) && n !== "router-helpers.ts")).sort();
}

// scanFile returns { violations, markedOk } for one file's text: violations are unmarked bare-void call
// sites (file, line, callee); markedOk are the ones the void-ok escape hatch legitimately covers.
//
// THE TWO HALVES READ DIFFERENT TEXT, ON PURPOSE, because they are looking for opposite things. A void CALL
// must be live code, so it is matched against the comment-blanked text. A void-ok MARKER must be a comment,
// so it is matched against the raw line and then CONFIRMED to sit inside a comment.
//
// The line filter this replaces (`/^\s*\/\//` on the trimmed line) saw only whole-line `//` comments. A
// `void handler(` inside a `/* ... */` block, or on a JSDoc `* ` continuation line, was read as live code,
// which matters more than it first appears: this gate is a COUNT ratchet, so inflating the count with
// comment prose and then re-pinning lets comment text buy room for real debt, and deleting such a comment
// later frees a slot a genuinely new bare void can occupy with the total unchanged. blankComments is
// quote-aware and offset-preserving, so the comparison is exact rather than an enumeration of the comment
// spellings someone thought of. Measured at the sha this landed on: 59 violations raw, 59 blanked, so the
// pinned baseline is unmoved and this is a hardening rather than a re-pin.
//
// The marker side had the mirror hole: VOID_OK_RE ran over the raw line, and the fallback `line.match`
// searches the WHOLE line, so a `// void-ok: <reason>` occurring inside a STRING would have exempted a real
// bare void sitting beside it. Requiring the match position to be blanked (i.e. to be comment bytes) makes
// the escape hatch reachable only from an actual comment, which is what "a reviewer sees it in the diff"
// always meant.
function scanFile(file, text) {
  const lines = text.split("\n");
  const blankedLines = blankComments(text).split("\n");
  const violations = [];
  const markedOk = [];
  // inComment answers whether offset `at` on line `idx` is comment bytes: blankComments overwrites exactly
  // the comment bytes with spaces and touches nothing else, so a position that differs between the raw and
  // blanked line is inside a comment.
  const inComment = (idx, at) => {
    const raw = lines[idx] ?? "";
    const blanked = blankedLines[idx] ?? "";
    return at < raw.length && raw[at] !== " " && blanked[at] === " ";
  };
  lines.forEach((line, idx) => {
    const code = blankedLines[idx] ?? "";
    for (const m of code.matchAll(VOID_CALL_RE)) {
      const callee = m[1];
      // Search the RAW line for the marker (it lives in a comment, which `code` has blanked away), then
      // require the match to actually be comment bytes.
      const after = line.slice(m.index).match(VOID_OK_RE);
      const anywhere = line.match(VOID_OK_RE);
      const okIndex = after ? m.index + after.index : anywhere ? anywhere.index : -1;
      if (okIndex >= 0 && inComment(idx, okIndex)) markedOk.push({ file, line: idx + 1, callee });
      else violations.push({ file, line: idx + 1, callee });
    }
  });
  return { violations, markedOk };
}

function runScan() {
  const files = corpusFiles(ADMIN_DIR);
  if (files === null) die(2, `cannot check: ${ADMIN_DIR} is missing or unreadable.`);
  if (files.length === 0) die(2, `cannot check: 0 files matched router.ts / router-*.ts / scim.ts under ${ADMIN_DIR}. A rename or move silently emptied the scan; that is not a clean pass.`);
  let violations = [];
  let markedOk = [];
  for (const name of files) {
    const text = readFileSync(join(ADMIN_DIR, name), "utf8");
    const r = scanFile(name, text);
    violations = violations.concat(r.violations);
    markedOk = markedOk.concat(r.markedOk);
  }
  return { files, violations, markedOk };
}

// selfTest proves the gate has teeth against disposable fixtures: a clean file (0 violations), a bad file
// (1 unmarked bare-void call: must be caught) and a marked file (1 void-ok call: must be EXCLUDED). It
// never touches the real corpus or the real baseline.
function selfTest() {
  const dir = mkdtempSync(join(tmpdir(), "void-waituntil-selftest-"));
  let pass = true;
  const check = (label, ok) => {
    console.log(`  ${ok ? "PASS" : "FAIL"}: ${label}`);
    if (!ok) pass = false;
  };
  try {
    const clean = `export async function handleThing(ctx) {\n  fireInBackground(ctx.runtime, recordThing(ctx.scheduler));\n  return new Response("ok");\n}\n`;
    const r1 = scanFile("clean.ts", clean);
    check("a fireInBackground-wrapped call is not flagged (fireInBackground( itself never matches, since it is not `void`)", r1.violations.length === 0);

    const bad = `export async function handleThing(ctx) {\n  void recordThing(ctx.scheduler, "x");\n  return new Response("ok");\n}\n`;
    const r2 = scanFile("bad.ts", bad);
    check("a bare `void recordThing(...)` call IS flagged", r2.violations.length === 1 && r2.violations[0].callee === "recordThing");

    const marked = `export async function handleThing(ctx) {\n  void recordThing(ctx.scheduler, "x"); // void-ok: purely cosmetic log line, no reader depends on it\n  return new Response("ok");\n}\n`;
    const r3 = scanFile("marked.ts", marked);
    check("a void-ok-marked call is excluded from violations", r3.violations.length === 0 && r3.markedOk.length === 1);

    const shortReason = `export async function handleThing(ctx) {\n  void recordThing(ctx.scheduler, "x"); // void-ok: meh\n  return new Response("ok");\n}\n`;
    const r4 = scanFile("short-reason.ts", shortReason);
    check("a void-ok marker with a too-short reason does NOT count as a valid escape (still flagged)", r4.violations.length === 1);

    const nonCall = `export async function handleThing(ctx) {\n  const task = recordThing(ctx.scheduler);\n  if (ctx.runtime?.waitUntil) ctx.runtime.waitUntil(task);\n  else void task;\n  return new Response("ok");\n}\n`;
    const r5 = scanFile("noncall.ts", nonCall);
    check("`void task;` (a bare identifier, the fireInBackground fallback shape) is never flagged", r5.violations.length === 0);

    const commentedOut = `export async function handleThing(ctx) {\n  // void recordThing(ctx.scheduler, "x");\n  return new Response("ok");\n}\n`;
    const r6 = scanFile("commented.ts", commentedOut);
    check("a commented-out void call is not flagged", r6.violations.length === 0);

    // COMMENT TOTALITY, both directions. These are the fixtures the old whole-line `//` filter could not
    // survive, and they run through the real scanFile rather than a copy of it.
    const blockComment = `export async function handleThing(ctx) {\n  /* the old shape was\n     void recordThing(ctx.scheduler, "x");\n     and it lost writes */\n  return new Response("ok");\n}\n`;
    const r7 = scanFile("block.ts", blockComment);
    check("a void call inside a BLOCK comment is not counted as debt", r7.violations.length === 0);

    const jsdocLine = `export async function handleThing(ctx) {\n  /**\n   * void recordThing(ctx.scheduler, "x") was the losing shape.\n   */\n  return new Response("ok");\n}\n`;
    const r8 = scanFile("jsdoc.ts", jsdocLine);
    check("a void call on a JSDoc continuation line is not counted as debt", r8.violations.length === 0);

    const trailingBlock = `export async function handleThing(ctx) {\n  const x = 1; /* void recordThing(ctx.scheduler); */ void recordThing(ctx.scheduler);\n  return new Response("ok");\n}\n`;
    const r9 = scanFile("trailing.ts", trailingBlock);
    check("a REAL void call beside a block comment quoting one is still caught exactly once", r9.violations.length === 1);

    // THE ESCAPE HATCH MUST BE A COMMENT. A void-ok marker inside a string is not a reviewed decision, it is
    // a string, and it must not exempt anything.
    const markerInString = `export async function handleThing(ctx) {\n  void recordThing(ctx.scheduler, "reason // void-ok: this is inside a string literal");\n  return new Response("ok");\n}\n`;
    const r10 = scanFile("marker-in-string.ts", markerInString);
    check("a void-ok marker inside a STRING does not exempt the call", r10.violations.length === 1 && r10.markedOk.length === 0);

    // Prove the "cannot run" / "nothing to check" fail-closed paths directly, not just by inspection.
    check("corpusFiles on a missing directory returns null (the caller must die(2), not pass)", corpusFiles(join(dir, "does-not-exist")) === null);
    check("corpusFiles on an existing but non-matching directory returns an empty array (the caller must die(2), not pass)", Array.isArray(corpusFiles(dir)) && corpusFiles(dir).length === 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  console.log(pass ? "\nvoid-waituntil-gate --self-test: ALL PASS" : "\nvoid-waituntil-gate --self-test: FAILED");
  process.exit(pass ? 0 : 1);
}

if (SELF_TEST) selfTest();

const { files, violations, markedOk } = runScan();

if (WRITE) {
  const payload = {
    "//": "Pinned bare-void-call count for src/admin's router.ts + router-*.ts spokes + scim.ts (void-waituntil-gate.mjs). Ratchet DOWN as more sites are fixed; the gate refuses any increase. Re-pin only with --write-baseline after a genuine fix, never to silence a new addition.",
    filesScanned: files.length,
    count: violations.length,
    bySignal: violations.reduce((acc, v) => {
      acc[v.callee] = (acc[v.callee] ?? 0) + 1;
      return acc;
    }, {}),
  };
  writeFileSync(BASELINE, `${JSON.stringify(payload, null, 2)}\n`);
  console.log(`void-waituntil-gate: baseline written: ${files.length} files, ${violations.length} unmarked bare-void call(s), ${markedOk.length} void-ok-marked.`);
  process.exit(0);
}

if (!existsSync(BASELINE)) die(2, `cannot check: ${BASELINE} is missing. Re-pin with --write-baseline.`);
let base;
try {
  base = JSON.parse(readFileSync(BASELINE, "utf8"));
} catch (e) {
  die(2, `cannot check: the baseline is unparseable (${e instanceof Error ? e.message : String(e)})`);
}
if (typeof base.count !== "number") die(2, "cannot check: the baseline carries no count");
// THE CORPUS MAY GROW, NEVER SHRINK. filesScanned was recorded from the first pin and compared against
// nothing, and a count ratchet over an unpinned corpus has an obvious way out: rename a spoke to a name
// `router-*.ts` no longer matches and every bare void in it leaves the tally, which reads as debt repaid.
// The zero-files guard above only catches the total collapse, not the loss of one file. A DECREASE is
// therefore a refusal to check rather than a pass; an increase is fine (a new spoke can only add sites, and
// the count comparison already judges those).
if (typeof base.filesScanned === "number" && files.length < base.filesScanned) {
  die(2, `cannot check: the corpus shrank from ${base.filesScanned} files to ${files.length}. A spoke was renamed, moved or deleted, and its bare-void sites left the tally without being fixed. Re-pin with --write-baseline only if the file genuinely went away.`);
}

console.log(`void-waituntil-gate: ${files.length} file(s) scanned (router.ts + router-*.ts spokes + scim.ts under src/admin/)`);
console.log(`  bare-void call sites: ${violations.length} (pinned ${base.count}), void-ok-marked: ${markedOk.length}`);

if (violations.length > base.count) {
  console.log(`\nVOID-WAITUNTIL GATE: bare-void call sites rose from ${base.count} to ${violations.length}.`);
  console.log("  Every site below discards an async call with a bare `void` and routes through no ctx.waitUntil, the");
  console.log("  exact shape R-111 proved loses a write in production. Either thread runtime.waitUntil through it");
  console.log("  (fireInBackground(runtime, task), the pattern this triage used throughout), or -- ONLY if losing it");
  console.log("  truly changes nothing observable -- mark it `// void-ok: <a real reason>` and re-pin.");
  for (const v of violations.slice(0, 50)) console.log(`    ${v.file}:${v.line}  void ${v.callee}(...)`);
  if (violations.length > 50) console.log(`    ... and ${violations.length - 50} more`);
  process.exit(1);
}
if (violations.length < base.count) console.log(`  count is BELOW the pin (${base.count} -> ${violations.length}); re-pin with --write-baseline.`);
console.log("\nVOID-WAITUNTIL GATE PASS");
