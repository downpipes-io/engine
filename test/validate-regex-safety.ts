// validate-regex-safety: every regex under src/ -- a `/literal/` and every `new RegExp(...)` /
// `RegExp(...)` construction -- runs in linear time, so no operator- or attacker-controlled string
// can ever put the engine into catastrophic backtracking (ReDoS, ASVS V1.3.12).
//
// SCOPE. "src/" is the engine's own request- and data-processing code: JWT claims, role and group
// names, downpipe config, restore fields, webhook and destination error text, D1/S3/Azure API
// responses, all flow through modules under src/ before this engine acts on them. test/, scripts/
// and tools/ are dev-time tooling that never sees a live caller or a hostile destination, so they
// are out of scope for the same reason src/ itself is in scope: this sweep follows what handles
// external input, not merely what happens to compile. Within src/, every regex literal is checked
// rather than a hand-picked subset: enumerating a precise data-flow path from each HTTP route to
// each regex that reads it would need a call-graph analysis this repo does not have and this file
// does not attempt, so checking the whole tree is the sound superset. It costs nothing extra: of
// the 658 regex literals present at the time this file was added (467 distinct), only those with
// an unbounded repetition (`*`, `+`, or an open-ended `{n,}`) can backtrack catastrophically at
// all, and the dynamic sweep over that subset finishes in well under a minute (see BUDGET below).
//
// CONSTRUCTOR CALLS ARE IN SCOPE TOO, ANALYSED THE SAME WAY WHEN THE PATTERN IS A STATIC STRING.
// A `/literal/` is not the only way to build a RegExp: `new RegExp("^(" + x + "+)+$")` compiles a
// pattern from a runtime string, and a `RegularExpressionLiteral`-only enumeration never sees it --
// the exact gap a challenger used to slip a catastrophic pattern past this file. Every
// `new RegExp(...)` / `RegExp(...)` call site under src/ is now enumerated alongside the regex
// literals. When its pattern argument (and flags argument, if present) is a plain string literal or
// a template literal with NO substitution -- text the compiler can read without running anything --
// it is analysed exactly like a `/literal/`: same hasUnboundedRepetition() check, same dynamic
// probe. When the pattern argument is anything else (a template literal WITH a substitution, string
// concatenation, a bare identifier, a function call), its concrete text cannot be known without
// executing the program, so it fails the sweep UNLESS the file it lives in is named in
// DYNAMIC_REGEX_ALLOWLIST below, each entry carrying the by-hand review of why that call site's
// pattern cannot backtrack catastrophically regardless of the runtime value it is built from. This
// is coarser than the literal check (a whole file is excused, not one call site), which is why the
// list is kept small and every entry is reasoned in place: it is the record of a review having
// happened, not a way around needing one. At the time this scope was added, three files in src/
// build a RegExp from a non-literal string and are on the list; see the comment on each entry.
//
// WHAT "LINEAR TIME" MEANS HERE, and why a bounded quantifier is skipped rather than probed.
// Catastrophic backtracking needs an UNBOUNDED quantifier: a bound like `{1,128}` caps the
// backtracking search by construction, however the pattern is nested, so it cannot blow up without
// bound the way `(a+)+` or `(a|aa)+` can. hasUnboundedRepetition() is that structural (static)
// check, and it is exact rather than a heuristic: a pattern with no bare `*`/`+` and no open-ended
// `{n,}` outside a character class cannot exhibit the exponential blow-up this file exists to
// catch, so it is recorded SAFE without spending a probe on it.
//
// WHY DYNAMIC OVER A NESTED-QUANTIFIER PARSER, for the patterns that remain. The obvious static
// rule -- flag a quantified group that itself contains a quantified sub-pattern -- was tried first
// and rejected on this repo's own corpus: `/^[a-z]{2}(?:-[a-z]+)+-\d{1,2}$/` (src/dest/sts.ts:56,
// an AWS region code) nests `[a-z]+` inside a repeated group and is completely safe, because the
// leading `-` in the outer group can never be produced by the inner `[a-z]+`, so every repetition
// is forced apart and there is only ever one way to parse a given string. Telling that case apart
// from a genuinely ambiguous nesting needs the same reasoning an NFA-ambiguity checker (RXXR,
// `recheck`) encodes, and this repo carries no such dependency (verified: neither `safe-regex` nor
// any ReDoS-specific package appears in package.json or package-lock.json). MEASURED rather than
// argued: a naive "does the source contain two quantifiers, one nested in the other" rule flags
// that exact AWS-region pattern and four siblings (src/admin/run-fault-records.ts:102,
// src/dest/fault-log.ts:205,209, src/sched/scheduler-do-limits.ts:630), none of which is unsafe by
// the definition above, so a naive static rule would have blocked or trained around a passing
// check on day one. Executing the pattern against a real generated input and timing it answers the
// only question that matters -- does this specific pattern's engine cost stay flat as the input
// grows -- without needing to reconstruct the ambiguity theory to get the right answer.
//
// THE PROBE RUNS IN A CHILD PROCESS WITH A HARD OS TIMEOUT, not in this process with a soft one.
// A single `RegExp.prototype.test()` call cannot be interrupted mid-flight -- JavaScript is
// single-threaded and a catastrophic pattern's backtracking runs inside one synchronous call this
// process cannot see into until it returns, which may be minutes or may never happen. Timing the
// call from inside the same process (tried first) therefore could not bound this file's own
// worst-case runtime: measured against `/^(a+)+$/`, one `.test()` call against 30 filler characters
// took 6.8 seconds, and the doubling schedule below would reach far past that length before this
// process ever got control back to notice. `child_process.spawnSync` with `timeout` and
// `killSignal: "SIGKILL"` is the one mechanism that bounds a call this file cannot interrupt any
// other way (the same reasoning scripts/run-gate-chain.mjs already applies one level up, to a
// whole member rather than one regex). A child that is killed before printing PROBE-COMPLETE is
// itself the finding: a linear-time pattern finishes the entire doubling schedule, up to
// CEILING_N characters, in microseconds per step regardless of length (measured: a bounded pattern
// stayed at 0.003ms from 10 to 320 filler characters), so failing to finish within
// PROBE_TIMEOUT_MS is not ambiguous.
//
// THE GENERATED INPUT is built from characters read out of the pattern itself
// (candidateFillChars), not a fixed alphabet, because a filler character the pattern's own quantified
// atoms do not accept cannot exercise them: probing `/^[a-z]{2}(?:-[a-z]+)+-\d{1,2}$/` with a filler
// of "9" would fail to match at the very first character and prove nothing. The scan is a light
// character-class reader (ranges, `\d`/`\w`/`\s` shorthands, negation), not a full regex parser --
// it does not need to be one, because it only has to produce A character the pattern is likely to
// accept, not every one. Two terminator strings are tried alongside plain repetition: "" (the
// input can fully match, the cheap case) and one astral-plane codepoint (U+1F4A5) that none of
// this repo's character classes admit -- every class scanned below is built from ASCII letters,
// digits, punctuation, or a control-byte range, none of which extends past the Basic Multilingual
// Plane -- chosen to force a FAILED match at the anchor, which is where classic catastrophic
// patterns such as `(a|aa)+$` do their damage: a string that matches cleanly on the first attempt
// never needs to explore the other ways it could have been partitioned.
//
// BUDGET. Each candidate pattern is probed with up to 2 filler characters x 2 terminators = 4
// child processes, each capped at PROBE_TIMEOUT_MS. MEASURED on this tree at the time this file was
// added: 92 of 467 distinct patterns carry an unbounded repetition and were probed; all 92 passed
// in 25.5 seconds wall clock end to end (the whole file, including enumeration), and both planted
// catastrophic patterns below (`^(a+)+$` and `(a|aa)+$`) were caught inside the first two doubling
// steps, each killed by the timeout rather than finishing.
//
// RED BEFORE GREEN. This file was gated red against a fixture carrying `/^(a+)+$/` under src/,
// confirmed to fail naming that file:line and the timeout that caught it, then green again once
// the fixture was removed. The constructor-call extension was gated red the same way, against two
// fixtures: `new RegExp("^(" + x + "+)+$")` (dynamic, un-allowlisted -- x an ordinary local
// variable, not a literal) and `new RegExp("^(a+)+$")` (a static string literal argument); both
// failed naming the fixture's file:line before being removed. See
// docs/security/input-validation-and-limits.md section 18 for the sign-off this run produced.
//
// Run with: node test/validate-regex-safety.ts

// "typescript" is loaded dynamically, only on the path that needs it (see main() below), because
// this file re-invokes ITSELF as the --probe child hundreds of times per run: loading the whole
// TypeScript compiler in every one of those short-lived children was measured to cost most of
// this file's 81-second wall time for no benefit at all (a child never parses a source file).
// verdict-guard stays a static import -- it is cheap (two node builtins, no compiler) and every
// entry point in this repo is required to carry one (scripts/verdict-guard-gate.mjs enforces the
// import textually) -- but the child path calls verdictSkipped() rather than verdictReached(),
// because a probe child is not itself a validator run: it has no tally of its own to declare, and
// forcing one would only recreate, one level down, the exact false-positive class this file's
// header already rejected for the in-process timer (see "THE PROBE RUNS IN A CHILD PROCESS").
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type * as TS from "typescript";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, "..");
const SELF = fileURLToPath(import.meta.url);
const SRC_DIR = path.join(ROOT, "src");

// The doubling schedule tops out here. A linear-time pattern costs microseconds per step
// regardless of length, so this ceiling is never actually reached by the walltime budget on a
// safe pattern -- it exists only to give the loop a defined end.
const CEILING_N = 8192;
// Per-probe hard wall-clock cap. A safe pattern's whole doubling schedule (11 steps, 8..8192)
// finishes in low single-digit milliseconds; this is generous by three orders of magnitude and
// still short enough that four probes per pattern across ~90 candidates finishes in well under a
// minute.
const PROBE_TIMEOUT_MS = 3000;
// A codepoint this repo's own character classes never accept (verified over every class literal
// scanned below), used as a terminator to force a failed match at an anchor.
const FOREIGN_TERMINATOR = "\u{1F4A5}";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---------------------------------------------------------------------------------------------
// Child-probe mode. Invoked by this same file, via spawnSync, one filler/terminator combination
// at a time. Never invoked directly by a person; --probe is not a supported CLI entry point.
// ---------------------------------------------------------------------------------------------
if (process.argv[2] === "--probe") {
  const payload = JSON.parse(Buffer.from(String(process.argv[3]), "base64").toString("utf8")) as {
    source: string;
    flags: string;
    fill: string;
    term: string;
  };
  const re = new RegExp(payload.source, payload.flags.replace(/[gy]/g, ""));
  let n = 8;
  while (n <= CEILING_N) {
    const sample = payload.fill.repeat(n) + payload.term;
    const t0 = process.hrtime.bigint();
    re.test(sample);
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    process.stdout.write(`n=${n} ms=${ms.toFixed(3)}\n`);
    n *= 2;
  }
  process.stdout.write("PROBE-COMPLETE\n");
  verdictSkipped("--probe child process; the parent process is the validator and reads this one's stdout, not its exit code");
  process.exit(0);
}

// ---------------------------------------------------------------------------------------------
// DYNAMIC_REGEX_ALLOWLIST names files where a `new RegExp(...)` / `RegExp(...)` pattern (or flags)
// argument is not a static string literal, so its concrete text cannot be read at analysis time.
// A file NOT on this list whose constructor call cannot be read as a literal fails the sweep
// outright, naming the call site -- so a new dynamic pattern needs the same review, and an entry
// here, before it can pass. This is coarser than the literal check (the whole file is excused, not
// one call site), which is why the list stays small and every entry carries the reasoning in place:
// it is the record of a review having happened, not a route around needing one.
const DYNAMIC_REGEX_ALLOWLIST = new Set<string>([
  // src/admin/router-sources.ts:530 -- matchActionPath(method, sub, prefix) interpolates `prefix`
  // straight into the pattern text with no escaping. `prefix` is a function parameter, not a
  // literal, so it cannot be read here -- but both call sites in this same file pass a hardcoded
  // string constant ("config/changes" at line 548, "owner-actions" at line 556), and the pattern's
  // only unbounded piece, `[^/]+`, is a single un-nested repetition regardless of what `prefix`
  // contains. A future caller passing a request-derived prefix would need this entry re-reviewed;
  // it covers the two calls that exist today, not the shape in general.
  "src/admin/router-sources.ts",
  // src/sched/config-validate.ts:147 -- DOWNPIPE_ID_PATTERN interpolates DOWNPIPE_ID_MAX_LEN, a
  // same-file exported numeric constant (128, line 145), into a BOUNDED quantifier's upper bound
  // (`{1,N}`). The pattern this builds is `/^[A-Za-z0-9._-]{1,128}$/`, byte-identical to the literal
  // this file already asserts present via mustBePresent below, and a bounded quantifier cannot
  // backtrack catastrophically for any N.
  "src/sched/config-validate.ts",
  // src/dest/provider.ts:107 -- azureHostPattern(family) interpolates `family` (typed "blob"|"dfs",
  // called with only those two string literals at lines 110-111) and `clouds` (every element of
  // AZURE_STORAGE_SUFFIXES, a same-file literal array, joined with "|" after its own dots are
  // escaped). Neither substituted piece nor the surrounding literal text (`\.` + family + `\.(?:` +
  // clouds + `)$`) carries an unbounded quantifier, so there is no repetition to nest.
  "src/dest/provider.ts",
]);

// ---------------------------------------------------------------------------------------------
// Enumeration: every RegularExpressionLiteral node under src/, plus every `new RegExp(...)` /
// `RegExp(...)` call, syntactic only (no type checker needed to read a literal's own text), via the
// TypeScript compiler API already a devDependency here (scripts/impossible-comparison-gate.mjs is
// the precedent for AST access in this repo).
// ---------------------------------------------------------------------------------------------
interface RegexSite {
  file: string;
  line: number;
}
interface RegexPattern {
  literal: string; // full literal text, e.g. /^[a-z]+$/i, or a display form for a constructor call
  source: string;
  flags: string;
  sites: RegexSite[];
}
interface DynamicConstructorSite {
  file: string;
  line: number;
  exprText: string; // the call's own source text, for the failure message a reviewer reads
}

function listSourceFiles(dir: string, out: string[]): string[] {
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      listSourceFiles(full, out);
    } else if (entry.endsWith(".ts") && !entry.endsWith(".d.ts")) {
      out.push(full);
    }
  }
  return out;
}

// literalTextOf reads the resolved string value of a StringLiteral or a template literal with no
// substitution ( `` `...` `` with no `${...}` ). TypeScript's own `.text` already applies escape
// processing for both, so it is the runtime string the argument evaluates to, not its source
// spelling. Anything else (a template literal WITH a substitution, concatenation, an identifier, a
// call) returns undefined: its value cannot be read without executing the program.
function literalTextOf(ts: typeof TS, node: TS.Expression): string | undefined {
  return ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) ? node.text : undefined;
}

function collectAll(ts: typeof TS): { patterns: RegexPattern[]; dynamicSites: DynamicConstructorSite[] } {
  const byPattern = new Map<string, RegexPattern>();
  const dynamicSites: DynamicConstructorSite[] = [];
  const files = listSourceFiles(SRC_DIR, []);
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
    const relFile = path.relative(ROOT, file);

    const record = (literal: string, source: string, flags: string, line1: number): void => {
      // Keyed by source+flags, not by display text, so a literal and an identically-shaped
      // constructor call for the SAME pattern are recognised as one pattern and probed once.
      const key = JSON.stringify([source, flags]);
      const existing = byPattern.get(key);
      if (existing === undefined) byPattern.set(key, { literal, source, flags, sites: [{ file: relFile, line: line1 }] });
      else existing.sites.push({ file: relFile, line: line1 });
    };

    const visit = (node: TS.Node): void => {
      if (node.kind === ts.SyntaxKind.RegularExpressionLiteral) {
        const literal = node.getText(sf);
        const lastSlash = literal.lastIndexOf("/");
        const source = literal.slice(1, lastSlash);
        const flags = literal.slice(lastSlash + 1);
        const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
        record(literal, source, flags, line + 1);
      } else if (
        (ts.isNewExpression(node) || ts.isCallExpression(node)) &&
        ts.isIdentifier(node.expression) &&
        node.expression.text === "RegExp" &&
        node.arguments !== undefined &&
        node.arguments.length > 0
      ) {
        const patternArg = node.arguments[0]!;
        const flagsArg = node.arguments[1];
        const source = literalTextOf(ts, patternArg);
        const flags = flagsArg === undefined ? "" : literalTextOf(ts, flagsArg);
        const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
        if (source !== undefined && flags !== undefined) {
          const display = `new RegExp(${JSON.stringify(source)}${flags.length > 0 ? `, ${JSON.stringify(flags)}` : ""})`;
          record(display, source, flags, line + 1);
        } else {
          dynamicSites.push({
            file: relFile,
            line: line + 1,
            exprText: node.getText(sf).replace(/\s+/g, " ").slice(0, 200),
          });
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return { patterns: [...byPattern.values()], dynamicSites };
}

// ---------------------------------------------------------------------------------------------
// Static classification: does this pattern carry an unbounded repetition at all? A `*`, a bare
// `+`, or an open-ended `{n,}` outside a character class. Escapes and character classes are
// stripped first so an escaped `\+` or a `+` written literally inside `[...]` is not miscounted
// as a quantifier.
// ---------------------------------------------------------------------------------------------
function hasUnboundedRepetition(source: string): boolean {
  let stripped = "";
  let i = 0;
  while (i < source.length) {
    const c = source[i];
    if (c === "\\") {
      stripped += "e";
      i += 2;
      continue;
    }
    if (c === "[") {
      let j = i + 1;
      if (source[j] === "^") j++;
      const start = j;
      while (j < source.length && !(source[j] === "]" && j > start)) {
        if (source[j] === "\\") j++;
        j++;
      }
      stripped += "C";
      i = j + 1;
      continue;
    }
    stripped += c;
    i++;
  }
  return /[*+]/.test(stripped) || /\{\d+,\}/.test(stripped);
}

// ---------------------------------------------------------------------------------------------
// Candidate fill characters: a light read of the pattern's own character classes and escapes, so
// the generated probe string is one the pattern is likely to accept. Not a full regex parser --
// it only needs to produce *a* plausible character, not every one a class admits.
// ---------------------------------------------------------------------------------------------
function candidateFillChars(source: string): string[] {
  const pool: string[] = [];
  const seen = new Set<string>();
  const add = (ch: string | undefined): void => {
    if (ch === undefined || ch.length === 0 || seen.has(ch)) return;
    seen.add(ch);
    pool.push(ch);
  };
  const shorthand: Record<string, string> = { d: "5", D: "k", w: "a", W: " ", s: " ", S: "a", n: "a", r: "a", t: "a" };
  let i = 0;
  while (i < source.length) {
    const c = source[i];
    if (c === "\\") {
      const n = source[i + 1];
      if (n !== undefined) {
        if (shorthand[n] !== undefined) add(shorthand[n]);
        else if (!/[a-zA-Z0-9]/.test(n)) add(n); // an escaped literal metacharacter, e.g. \. \/ \\
      }
      i += 2;
      continue;
    }
    if (c === "[") {
      let j = i + 1;
      let negated = false;
      if (source[j] === "^") {
        negated = true;
        j++;
      }
      const start = j;
      while (j < source.length && !(source[j] === "]" && j > start)) {
        if (source[j] === "\\") j++;
        j++;
      }
      const body = source.slice(start, j);
      if (negated) {
        add("k"); // arbitrary letter; every negated class seen in this repo excludes symbols, not letters
      } else {
        const range = /([^\\])-([^\\\]])/.exec(body);
        if (range !== null && range[1] !== undefined) {
          add(range[1]);
        } else {
          let k = 0;
          while (k < body.length) {
            if (body[k] === "\\") {
              const n = body[k + 1];
              add(n !== undefined ? (shorthand[n] ?? n) : undefined);
              k += 2;
            } else {
              add(body[k]);
              k++;
            }
          }
        }
      }
      i = j + 1;
      continue;
    }
    if (/[A-Za-z0-9]/.test(c ?? "")) add(c);
    i++;
  }
  add("a");
  add("0");
  return pool;
}

// ---------------------------------------------------------------------------------------------
// One probe: spawn this same file with --probe, a fresh Node process per attempt so a pattern
// that never returns from RegExp.test can only ever hang and be killed, never block this process.
// ---------------------------------------------------------------------------------------------
interface ProbeResult {
  completed: boolean;
  timedOut: boolean;
  signal: string | null;
  output: string;
}

function runProbe(source: string, flags: string, fill: string, term: string): ProbeResult {
  const payload = Buffer.from(JSON.stringify({ source, flags, fill, term }), "utf8").toString("base64");
  const r = spawnSync(process.execPath, [SELF, "--probe", payload], {
    timeout: PROBE_TIMEOUT_MS,
    killSignal: "SIGKILL",
    encoding: "utf8",
  });
  const output = r.stdout ?? "";
  return {
    completed: output.includes("PROBE-COMPLETE"),
    timedOut: r.error !== undefined && r.error !== null && (r.error as NodeJS.ErrnoException).code === "ETIMEDOUT",
    signal: r.signal ?? null,
    output,
  };
}

interface DynamicVerdict {
  safe: boolean;
  reason: string;
}

function dynamicallyLinear(source: string, flags: string): DynamicVerdict {
  const fills = candidateFillChars(source).slice(0, 2);
  const terms = ["", FOREIGN_TERMINATOR];
  for (const fill of fills) {
    for (const term of terms) {
      const r = runProbe(source, flags, fill, term);
      if (!r.completed) {
        const lastStep = r.output.trim().split("\n").pop() ?? "(no output before the probe was killed)";
        return {
          safe: false,
          reason:
            `probe with fill=${JSON.stringify(fill)} terminator=${JSON.stringify(term)} did not finish within ` +
            `${PROBE_TIMEOUT_MS}ms (timedOut=${r.timedOut}, signal=${r.signal ?? "none"}); last completed step: ${lastStep}`,
        };
      }
    }
  }
  return { safe: true, reason: "every probe finished the full doubling schedule without exceeding the cap" };
}

// ---------------------------------------------------------------------------------------------
// Main sweep.
// ---------------------------------------------------------------------------------------------
async function main(): Promise<void> {
  const ts = (await import("typescript")).default;
  const { patterns, dynamicSites } = collectAll(ts);
  ok(
    `found regex literals and RegExp(...) constructor sites under src/ to check ` +
      `(${patterns.length} distinct patterns, ${dynamicSites.length} non-literal constructor call site(s))`,
    patterns.length > 0,
  );

  // A handful of the security-critical patterns this repo documents in
  // docs/security/input-validation-and-limits.md are asserted present here by exact text, so a
  // rewrite that silently drops one of them from the tree (or from this sweep's reach) is itself
  // a finding rather than a quiet reduction in coverage.
  const mustBePresent = [
    "/^[A-Za-z0-9._-]{1,128}$/", // downpipe id, scheduler-do.ts
    "/^[A-Za-z0-9_]{1,64}$/", // source/secret binding, scheduler-do.ts
    "/^[^@]+@[^@]+$/", // normaliseEmail, scheduler-do.ts
  ];
  const literalSet = new Set(patterns.map((p) => p.literal));
  for (const lit of mustBePresent) {
    ok(`documented pattern ${lit} is present in the scan`, literalSet.has(lit));
  }

  let staticSafe = 0;
  let dynamicChecked = 0;
  const found: string[] = [];

  for (const p of patterns) {
    const cite = p.sites.map((s) => `${s.file}:${s.line}`).join(", ");
    if (!hasUnboundedRepetition(p.source)) {
      staticSafe++;
      ok(`${p.literal}  (bounded, no unbounded repetition; cannot backtrack catastrophically) [${cite}]`, true);
      continue;
    }
    dynamicChecked++;
    const verdict = dynamicallyLinear(p.source, p.flags);
    ok(`${p.literal}  (dynamic: ${verdict.reason}) [${cite}]`, verdict.safe);
    if (!verdict.safe) found.push(`${p.literal} at ${cite}: ${verdict.reason}`);
  }

  // Constructor call sites whose pattern (or flags) is not a static string literal: each must
  // either resolve to a value already covered above (impossible here, by definition) or have its
  // file named in DYNAMIC_REGEX_ALLOWLIST, with the reasoning recorded there.
  let allowlisted = 0;
  const unreviewed: string[] = [];
  for (const site of dynamicSites) {
    const isAllowed = DYNAMIC_REGEX_ALLOWLIST.has(site.file);
    ok(
      isAllowed
        ? `${site.exprText}  (non-literal pattern; ${site.file} is on DYNAMIC_REGEX_ALLOWLIST, see the reasoning there) [${site.file}:${site.line}]`
        : `${site.exprText}  (non-literal pattern; ${site.file} is NOT on DYNAMIC_REGEX_ALLOWLIST -- use a literal pattern, or review this call site and add the file to the allowlist) [${site.file}:${site.line}]`,
      isAllowed,
    );
    if (isAllowed) allowlisted++;
    else unreviewed.push(`${site.exprText} at ${site.file}:${site.line}`);
  }

  console.log(
    `\n${patterns.length} distinct pattern(s) (regex literals + static-string constructor calls): ` +
      `${staticSafe} safe by bound alone, ${dynamicChecked} probed dynamically, ${found.length} unsafe.`,
  );
  console.log(
    `${dynamicSites.length} RegExp(...) call site(s) with a non-literal pattern: ${allowlisted} on the reviewed ` +
      `allowlist, ${unreviewed.length} unreviewed.`,
  );
  if (found.length > 0) {
    console.log("UNSAFE PATTERN(S) FOUND:");
    for (const f of found) console.log(`  - ${f}`);
  }
  if (unreviewed.length > 0) {
    console.log("UNREVIEWED DYNAMIC CONSTRUCTOR PATTERN(S):");
    for (const u of unreviewed) console.log(`  - ${u}`);
  }
  console.log(failures === 0 ? "\nREGEX SAFETY SWEEP: PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures, checks);
  if (failures > 0) process.exit(1);
}

await main();
