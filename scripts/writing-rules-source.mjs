#!/usr/bin/env node

/**
 * Writing-rules linter for this repository's prose, wherever that prose lives.
 *
 * House style binds the whole workspace (design-system.md s9, and the GUARDRAILS comment policy). This gate
 * grades it, and grades its own debt against scripts/writing-rules-baseline.json.
 *
 * THE SUBJECT, AND WHY IT IS NAMED RATHER THAN IMPLIED.
 *
 * The subject is EVERY TRACKED FILE that does not contain a NUL byte, enumerated from `git ls-files`.
 * It is not a list of directories and not a list of extensions. Both of those were tried and both failed the
 * same way, so the reasoning is recorded here rather than left to be rediscovered.
 *
 *   - The extension list was ".ts .tsx .mts .cts .js .mjs .cjs .md". Measured against the tree it was meant
 *     to cover: 257 em dashes and 1 en dash sat in tracked files, and only 226 of them were graded. The
 *     other 32 sat in 8 files whose only distinguishing feature was a file extension nobody had thought
 *     about: five wrangler*.toml, two shell scripts under scripts/, and .gitignore. Two of the eight sat
 *     INSIDE a root the widening had just added, so the root was right and the extension still hid them.
 *   - The root list was 17 entries. It happened to cover every tracked file carrying a graded extension, so
 *     it looked complete, but it is a whitelist: a new top-level directory is invisible until somebody
 *     remembers to add it, and nothing fails when they do not.
 *
 * A whitelist of shapes cannot answer "is this file in scope", because the answer changes when a file is
 * renamed and nothing re-asks the question. `git ls-files` can, and it answers for every file at once.
 *
 * WHAT IS EXCLUDED, WITH ITS MEASURED COST.
 *
 *   - Files containing a NUL byte, currently 73, all of them .dpe and .seg archive fixtures. They are not
 *     prose, and decoding them as UTF-8 can manufacture a dash character that nobody wrote. The gate reports
 *     the number it excluded on every run, so the exclusion cannot quietly grow into a hiding place.
 *   - Untracked files, because they do not ship and are usually a scratch bed belonging to another pass.
 *
 * That is the whole exclusion list. There is no path exemption and no extension exemption.
 *
 * THE BANNED-WORD RULE HAS A NARROWER SUBJECT, and this one IS a shape decision. It reads comments, and
 * the comment scanner models JavaScript comment syntax, so it only runs on the JS and TypeScript family.
 * Running it on Markdown or JSON was measured and is worse than useless: `https://` opens a line comment to
 * the scanner, so the rule would fire on whatever followed a URL and would miss every real prose sentence.
 * Markdown and shipped UI copy keep their own checks, which are shaped for them.
 *
 * THE UNITS ARE DECLARED, because they used to disagree. Dash hits were counted per OCCURRENCE and banned
 * words per COMMENT, in one ledger, with nothing recording the difference. Five banned words in five line
 * comments counted 5 and five in one comment counted 1; forty in one block comment counted 1, reported at
 * the line the comment opened on. Every rule now counts occurrences and reports the line the occurrence is
 * actually on. The ledger declares the unit in its `units` field and this file refuses to run if the two
 * disagree, so they cannot drift apart again in silence.
 *
 * Usage:  node writing-rules-source.mjs                  grade the tree against the baseline
 *         node writing-rules-source.mjs --write-baseline record the current tree as the baseline
 *         node writing-rules-source.mjs --print-subject   print the subject, one path per line
 *         node writing-rules-source.mjs --self-test       prove the gate has teeth, then grade the tree
 * Exit:   0 clean, 1 violations, 2 could-not-check. Exit 2 covers a tree git cannot enumerate, an empty
 *         subject, a baseline that is missing, malformed or declares units this file does not implement,
 *         and any positional argument, which this gate no longer takes.
 *
 * EACH FLAG NAMES A WHOLE JOB, AND A RUN DOES EXACTLY ONE OF THEM. Two of the three jobs end without
 * grading anything, on purpose: --write-baseline records, --print-subject answers a question for
 * test/validate-ci-path-shadow.ts. --self-test is NOT one of those. It runs the fixtures and then grades,
 * in the one process, because it is the invocation CI makes.
 *
 * So the flags do not combine, and a run carrying two of them is refused at exit 2 rather than quietly
 * doing one and staying silent about the other. That silence was reachable in four ways, all measured:
 * --self-test beside --print-subject printed the subject and skipped the grade at exit 0; --self-test
 * beside --write-baseline banked a live violation into the ledger as "pre-existing" and exited 0;
 * --write-baseline beside --print-subject never wrote the ledger at all; and WRITING_RULES_MUTANT=1, a
 * bare environment variable meant for the mutation harness below, took the exact CI command to exit 0 with
 * nothing on stderr over a tree it never read. See planInvocation(), which answers for the whole command
 * line in one place, and checkArbitration(), which sweeps every combination of it.
 *
 * House style: Australian English, no em dashes, no rule-of-three, no AI attribution.
 */

import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SELF_PATH = fileURLToPath(import.meta.url);
const REPO = resolve(dirname(SELF_PATH), "..");
const BASELINE_REL = "scripts/writing-rules-baseline.json";

// The two dash characters are built from CODE POINTS, never typed. Two reasons, and the second is the one
// that matters. A typed control is refused outright by the raw-character gates two sibling repos carry, so a
// fixture that types the character cannot be shared. And because this file no longer CONTAINS the characters
// it detects, it no longer needs the structural baseline entry that used to say "this one can never reach
// zero". Every entry in the ledger is now real debt, with no line that is exempt by construction.
const EM_DASH = String.fromCodePoint(0x2014);
const EN_DASH = String.fromCodePoint(0x2013);

// Rule family -> the unit its counts are in. Asserted against the ledger's own declaration on every run.
const RULE_UNITS = {
  "em-dash": "occurrence",
  "en-dash": "occurrence",
  claim: "occurrence",
  "banned-word": "occurrence",
};

// The file extensions whose comment syntax extractComments() actually models. See the header: this is the
// banned-word rule's subject, and it is narrower than the gate's subject on purpose.
const COMMENT_EXTS = [".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs"];

const BANNED_AI_WORDS = [
  "delve",
  "utilize",
  "utilise",
  "leverage",
  "seamless",
  "comprehensive",
  "crucial",
  "pivotal",
  "transformative",
  "groundbreaking",
  "holistic",
  "nuanced",
  "paradigm",
  "testament",
  "cornerstone",
  "catalyst",
  "effortless",
  "cutting-edge",
];

/**
 * Scan source into comment spans. A small state machine tracks code, string and template literals (so a `//`
 * inside a string is not a comment) and emits each line and block comment with its starting line number.
 */
function extractComments(src) {
  const comments = [];
  const n = src.length;
  let i = 0;
  let line = 1;
  let state = "code";
  let quote = "";
  let buf = "";
  let bufLine = 0;
  while (i < n) {
    const c = src[i];
    const c2 = i + 1 < n ? src[i + 1] : "";
    if (state === "code") {
      if (c === "/" && c2 === "/") {
        state = "line";
        buf = "";
        bufLine = line;
        i += 2;
        continue;
      }
      if (c === "/" && c2 === "*") {
        state = "block";
        buf = "";
        bufLine = line;
        i += 2;
        continue;
      }
      if (c === '"' || c === "'" || c === "`") {
        state = "str";
        quote = c;
        i += 1;
        continue;
      }
      if (c === "\n") line += 1;
      i += 1;
      continue;
    }
    if (state === "str") {
      if (c === "\\") {
        if (c2 === "\n") line += 1;
        i += 2;
        continue;
      }
      if (c === quote) {
        state = "code";
        i += 1;
        continue;
      }
      if (c === "\n") line += 1;
      i += 1;
      continue;
    }
    if (state === "line") {
      if (c === "\n") {
        comments.push({ line: bufLine, text: buf });
        state = "code";
        line += 1;
        i += 1;
        continue;
      }
      buf += c;
      i += 1;
      continue;
    }
    if (state === "block") {
      if (c === "*" && c2 === "/") {
        comments.push({ line: bufLine, text: buf });
        state = "code";
        i += 2;
        continue;
      }
      if (c === "\n") line += 1;
      buf += c;
      i += 1;
      continue;
    }
  }
  if (state === "line") comments.push({ line: bufLine, text: buf });
  return comments;
}

/* Number of newlines in text before `end`, so an occurrence inside a block comment reports its own line. */
function newlinesBefore(text, end) {
  let n = 0;
  for (let i = 0; i < end && i < text.length; i++) if (text[i] === "\n") n += 1;
  return n;
}

/* Line-number lookup over one file, built once rather than rescanned from zero for every hit. */
function lineIndex(src) {
  const starts = [0];
  for (let i = 0; i < src.length; i++) if (src[i] === "\n") starts.push(i + 1);
  return (index) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= index) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
}

/* Run every rule over one file's text, pushing one hit per OCCURRENCE. */
function lintText(rel, src, hits) {
  // Dashes: whole file. They never appear in code syntax, only in comments or string literals, and house
  // style bans them in both.
  let line = 1;
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (ch === "\n") {
      line += 1;
      continue;
    }
    if (ch === EM_DASH) hits.push({ file: rel, line, rule: "em-dash" });
    else if (ch === EN_DASH) hits.push({ file: rel, line, rule: "en-dash" });
  }

  // Claim rules: whole file. These catch a FALSE claim rather than a style slip, so they are not confined
  // to comments; a wrong sentence in a docs page under docs/ is exactly the case.
  //
  // recovery-offline-only. The break-glass-only posture does NOT move recovery offline: the console ships
  // a break-glass restore panel for that posture, taking the key in the browser and wiping it after, and
  // the engine refuses a restore only when it has NEITHER an operational key NOR a browser-supplied
  // master. The claim was found on seven separate surfaces during the operational-key workstream,
  // including this repo's own docs/OPERATIONS.md, which is why it is a rule rather than an eighth
  // correction. It also implies a terminal step, against the rule that the portal completes every
  // customer action.
  //
  // It matches the SHAPE OF THE CLAIM ("recovery is/becomes/stays offline-only"), not mere proximity of
  // the words. Proximity was tried first and was too noisy to ship: within a 90-character window it fired
  // on "the offline reader is offline-only", which is TRUE by construction, and on "an offline-only
  // rehearsal ... a restore is exercised then", which is fine. A gate that flags true sentences trains
  // people to ignore it. Requiring recovery or restore to be the SUBJECT keeps those clean while still
  // catching the claim, and an adjacent negator clears an honest contrast ("recovery is not offline-only").
  const lineAt = lineIndex(src);
  for (const m of src.matchAll(
    /\b(recovery|restores?|restoring)\b(?:\s+\w+){0,3}?\s+(?:is|are|was|were|becomes?|remains?|stays?)\s+(?:then\s+|therefore\s+|effectively\s+)?(?:not\s+|never\s+)?offline[-\s]?only\b/gi,
  )) {
    if (/\b(not|never)\s+offline[-\s]?only\b/i.test(m[0])) continue;
    hits.push({ file: rel, line: lineAt(m.index), rule: "claim:recovery-offline-only" });
  }

  // Banned marketing words: comments only, and only where the comment scanner models the syntax.
  if (!COMMENT_EXTS.some((e) => rel.endsWith(e))) return;
  for (const { line: startLine, text } of extractComments(src)) {
    for (const word of BANNED_AI_WORDS) {
      const re = new RegExp(`\\b${word.replace(/[-]/g, "\\$&")}\\b`, "gi");
      for (const m of text.matchAll(re)) {
        hits.push({ file: rel, line: startLine + newlinesBefore(text, m.index), rule: `banned-word:${word}` });
      }
    }
  }
}

// THE BASELINE, AND WHY IT IS A LEDGER OF DEBT RATHER THAN A LIST OF EXEMPTIONS.
//
// House style binds this whole workspace, but for most of this repo's life this linter read only src, docs
// and three named files, and none of the tree's dashes were graded. The rule was binding and ungraded, and
// the ungraded half is where every violation actually lived. Widening the subject is the fix, but widening
// alone would have meant rewriting hundreds of dense technical comments in one mechanical pass, most of them
// in test/ files other passes drive nightly. So the subject widens and the existing hits are RECORDED, file
// by file and rule by rule, in writing-rules-baseline.json.
//
// WHAT MAKES THIS A RATCHET RATHER THAN A LOOPHOLE. The baseline fails in BOTH directions:
//
//   - a file with MORE hits than recorded fails. New work is graded at full strength, everywhere.
//   - a file with hits and NO baseline entry fails. A new file cannot quietly join the debt.
//   - a file with FEWER hits than recorded ALSO fails, asking for the number to be lowered. A cleanup that
//     is not banked leaves slack behind it, and slack is how a ratchet turns back into a ceiling.
//   - an entry the tree no longer supports fails, and the gate says WHICH of the three reasons applies.
//     See classifyStale() for why that distinction is the whole point of this rewrite.
//
// The rule itself is untouched: nothing is excused, and the outstanding total is printed on every green run.
// That last sentence used to be a reassurance and was in fact the sharpest edge in the gate, because a
// number going DOWN reads as progress and the gate would print a fall it had not earned. It is safe to say
// now only because the subject is the whole tracked tree and classifyStale() refuses to call a disappearance
// a cleanup.
const BASELINE_PATH = new URL("writing-rules-baseline.json", import.meta.url);

function readBaseline(path) {
  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    if (err.code === "ENOENT") return { fatal: `${BASELINE_REL} is missing, so nothing could be compared against it.` };
    throw err;
  }
  let doc;
  try {
    doc = JSON.parse(raw);
  } catch (err) {
    return { fatal: `${BASELINE_REL} is not valid JSON (${err.message}).` };
  }

  // THE UNITS ARE CHECKED BEFORE ANY NUMBER IS READ. A ledger whose numbers were measured under a different
  // unit is not a stricter ledger or a looser one, it is a ledger of a different quantity, and comparing
  // against it silently is how the mixed-unit defect survived in the first place.
  const declared = doc.units;
  if (!declared || typeof declared !== "object") {
    return { fatal: `${BASELINE_REL} has no 'units' object, so the unit its counts were measured in is unknown.` };
  }
  const want = Object.keys(RULE_UNITS).sort().join(",");
  const got = Object.keys(declared).sort().join(",");
  if (want !== got) {
    return { fatal: `${BASELINE_REL} declares units for [${got}] but this gate implements [${want}].` };
  }
  for (const [rule, unit] of Object.entries(declared)) {
    if (unit !== RULE_UNITS[rule]) {
      return { fatal: `${BASELINE_REL} says ${rule} is counted per '${unit}', this gate counts per '${RULE_UNITS[rule]}'.` };
    }
  }

  const entries = new Map();
  for (const [file, entry] of Object.entries(doc.entries ?? {})) {
    if (!entry || typeof entry.counts !== "object" || typeof entry.why !== "string" || entry.why.trim() === "") {
      return { fatal: `${BASELINE_REL} entry '${file}' needs both a counts object and a why.` };
    }
    // EVERY RULE THE LEDGER CARRIES A NUMBER FOR MUST HAVE A DECLARED UNIT. Checking the units object as a
    // whole is not enough on its own: it compares the DECLARED families against the ones this file
    // implements, and says nothing about a family the ledger has actually recorded counts under. A rule
    // added to the ledger whose unit nobody declared is how the two-units defect gets back in, one rule at
    // a time rather than all at once.
    for (const rule of Object.keys(entry.counts)) {
      const family = rule.includes(":") ? rule.slice(0, rule.indexOf(":")) : rule;
      if (!(family in RULE_UNITS)) {
        return { fatal: `${BASELINE_REL} entry '${file}' records rule '${rule}', whose family '${family}' has no declared unit.` };
      }
    }
    entries.set(file, entry);
  }
  return { entries };
}

function baselineDoc(observed) {
  const files = [...observed.keys()].sort();
  const entries = {};
  for (const file of files) {
    const counts = {};
    for (const [rule, n] of [...observed.get(file).entries()].sort()) counts[rule] = n;
    entries[file] = {
      counts,
      why: "Pre-existing when lint:prose took the whole tracked tree as its subject. Debt to rewrite, not an exemption.",
    };
  }
  const total = files.reduce((s, f) => s + [...observed.get(f).values()].reduce((a, b) => a + b, 0), 0);
  return {
    $schema_note:
      "Recorded house-style debt. counts are EXACT and are per OCCURRENCE, as the units field declares: more fails as a regression, fewer fails as an unbanked cleanup, and an entry the tree no longer supports fails with the reason named. See the header of scripts/writing-rules-source.mjs.",
    units: { ...RULE_UNITS },
    generated_against: `${total} hit(s) across ${files.length} file(s)`,
    entries,
  };
}

/**
 * THE FIX AT THE CENTRE OF THIS FILE.
 *
 * A baseline entry that the current run found no hits for used to produce one message, DANGLING, whose text
 * was "the file no longer breaks that rule. Remove the entry." That sentence is true for a cleanup and false
 * for everything else, and the gate could not tell the cases apart, so it printed the same instruction for
 * all of them. Following it was an exploit: move a file carrying 13 em dashes out of the scanned roots, do
 * exactly what the gate says, and the run goes green while the debt total prints a fall from 226 to 213. The
 * number going DOWN is what made it dangerous, because it reads as progress.
 *
 * The distinction the old check could not make needs two facts the old check did not have: which files were
 * actually READ, and which files the repository actually TRACKS. It had neither. `observed` holds only files
 * WITH hits, so a file that was read and is genuinely clean is absent from it for the same reason a file
 * that was never read is absent. Those are the two cases that most need telling apart, and the one map it
 * consulted gives them identical answers. The scanned set is therefore built explicitly, from every file the
 * run read, and never inferred from the hits.
 *
 * With the subject being the whole tracked tree, the three cases are answerable and they are genuinely
 * different pieces of advice:
 *
 *   CLEARED  the file was read and the rule is gone from it. A real cleanup. Bank it: lower the number, or
 *            remove the entry when the file has no rules left. This is the ONLY case where removal is right.
 *   UNGRADED the file is still tracked at that path and this gate did not read it. The prose did not change
 *            and the debt did not go away, the gate's view of it did. Removing the entry would launder it.
 *   GONE     the path is no longer tracked. It was deleted, or it was renamed. The gate cannot see a rename
 *            it never witnessed, and it says so rather than guessing. What it CAN say is what a rename must
 *            look like from here: the subject is every tracked file, so the content landed somewhere still
 *            in the subject, and its new path is failing in the same run as NEW. So a GONE with a NEW beside
 *            it is a rename and the entry belongs at the new path; a GONE alone is a deletion.
 */
function classifyStale(file, rule, count, scanned, tracked, ungradedReason) {
  if (!tracked.has(file)) {
    return (
      `  GONE     ${file} [${rule}] ${count} recorded, and the path is not tracked any more. ` +
      `If it was DELETED the debt went with it: remove the entry. If it was RENAMED the debt moved with the ` +
      `text: the new path is in this same report as NEW, and the entry belongs there rather than deleted.`
    );
  }
  if (!scanned.has(file)) {
    return (
      `  UNGRADED ${file} [${rule}] ${count} recorded, the file is still tracked, and this gate did not read ` +
      `it (${ungradedReason.get(file) ?? "not in the subject"}). The text did not change, only the view of ` +
      `it. Do NOT remove the entry: put the file back in the subject, or rewrite the text.`
    );
  }
  return `  CLEARED  ${file} [${rule}] ${count} recorded and the file was read with none found. Bank it: drop ${rule} from the entry in ${BASELINE_REL}.`;
}

/* Compare observed hits to the recorded baseline, returning one line per finding. */
function compareToBaseline(observed, baseline, hits, scanned, tracked, ungradedReason) {
  const findings = [];
  const lineFor = (file, rule) =>
    hits
      .filter((h) => h.file === file && h.rule === rule)
      .slice(0, 6)
      .map((h) => h.line)
      .join(", ");

  for (const [file, rules] of observed) {
    const entry = baseline.entries.get(file);
    for (const [rule, count] of rules) {
      const allowed = entry?.counts?.[rule] ?? 0;
      if (count > allowed) {
        findings.push(`  NEW      ${file} [${rule}] ${count} found, ${allowed} recorded. Lines: ${lineFor(file, rule)}`);
      } else if (count < allowed) {
        findings.push(
          `  BANK     ${file} [${rule}] ${count} found but ${allowed} recorded. Lower the number in ${BASELINE_REL}.`,
        );
      }
    }
  }

  for (const [file, entry] of baseline.entries) {
    const rules = observed.get(file);
    for (const [rule, count] of Object.entries(entry.counts)) {
      if (!rules?.has(rule)) findings.push(classifyStale(file, rule, count, scanned, tracked, ungradedReason));
    }
  }
  return findings.sort();
}

/**
 * The subject, from git rather than from a walk. A walk has to be told where to look and what to look at,
 * and both of those told it wrong. git ls-files knows every file the repository will ship, including the
 * ones nobody thought to name.
 */
function trackedFiles(repo) {
  // stderr is captured rather than inherited: when this throws, the message belongs in the gate's own
  // exit-2 line, not interleaved ahead of it as a bare git error the caller has to guess the source of.
  const out = execFileSync("git", ["-C", repo, "ls-files", "-z"], {
    encoding: "buffer",
    maxBuffer: 1 << 28,
    stdio: ["ignore", "pipe", "pipe"],
  });
  return out
    .toString("utf8")
    .split("\0")
    .filter((s) => s !== "");
}

/**
 * Read the whole subject. A file is excluded when it holds a NUL BYTE, which is the test for "this is not
 * prose": it is a byte-value search over the raw buffer, not a pattern over decoded text. That distinction
 * is load-bearing. Written as a text pattern the check is easy to spell in a way that matches every file or
 * no file at all, and the self-test drives both directions against a fixture whose NUL is written from a
 * byte value rather than typed.
 */
function readSubject(repo, tracked) {
  const files = [];
  const texts = new Map();
  const ungradedReason = new Map();
  let binary = 0;
  for (const rel of tracked) {
    let buf;
    try {
      buf = readFileSync(join(repo, rel));
    } catch (err) {
      if (err.code === "ENOENT" || err.code === "EISDIR") {
        // Tracked but not on disk (a submodule gitlink, or an index that is ahead of the worktree).
        ungradedReason.set(rel, "tracked but not readable as a file on disk");
        continue;
      }
      throw err;
    }
    if (buf.indexOf(0) !== -1) {
      binary += 1;
      ungradedReason.set(rel, "contains a NUL byte, so it is not prose");
      continue;
    }
    files.push(rel);
    texts.set(rel, buf.toString("utf8"));
  }
  return { files, texts, ungradedReason, binary };
}

/**
 * run() is the whole gate, with the repository and the ledger passed in rather than baked in, so the
 * self-test can drive it against disposable fixture repositories and read the real exit code.
 */
function run({ repo, baselinePath, write = false }) {
  const lines = [];
  const errs = [];
  let tracked;
  try {
    tracked = trackedFiles(repo);
  } catch (err) {
    errs.push(`writing-rules-source: could not enumerate ${repo} with git ls-files (${err.message}).`);
    return { code: 2, lines, errs };
  }
  // ANTI-VACUITY. This gate's exit code used to be the hit count alone, and a mistyped root scanned NOTHING
  // and reported "0 violations" at exit 0. A run that read no file proved nothing, and must say so.
  if (tracked.length === 0) {
    errs.push(`writing-rules-source: git ls-files returned no files in ${repo}, so this check proved nothing.`);
    return { code: 2, lines, errs };
  }
  const { files, texts, ungradedReason, binary } = readSubject(repo, tracked);
  if (files.length === 0) {
    errs.push(`writing-rules-source: 0 readable text files among ${tracked.length} tracked, so this check proved nothing.`);
    return { code: 2, lines, errs };
  }

  const hits = [];
  // The SCANNED set is built from what was actually read. It is deliberately not derived from the hits: a
  // file that was read and is clean has no hits, and so does a file that was never opened, and telling those
  // two apart is the entire job of classifyStale().
  const scanned = new Set();
  for (const rel of files) {
    lintText(rel, texts.get(rel), hits);
    scanned.add(rel);
  }
  if (scanned.size !== files.length) {
    errs.push(`writing-rules-source: internal invariant broken, ${scanned.size} scanned against a subject of ${files.length}.`);
    return { code: 2, lines, errs };
  }

  const observed = new Map();
  for (const h of hits) {
    if (!observed.has(h.file)) observed.set(h.file, new Map());
    const m = observed.get(h.file);
    m.set(h.rule, (m.get(h.rule) ?? 0) + 1);
  }

  if (write) {
    writeFileSync(baselinePath, `${JSON.stringify(baselineDoc(observed), null, 2)}\n`);
    lines.push(`writing-rules-source: baseline written, ${hits.length} recorded across ${observed.size} file(s)`);
    return { code: 0, lines, errs };
  }

  const baseline = readBaseline(baselinePath);
  if (baseline.fatal) {
    errs.push(`writing-rules-source: ${baseline.fatal}`);
    return { code: 2, lines, errs };
  }
  const findings = compareToBaseline(observed, baseline, hits, scanned, new Set(tracked), ungradedReason);
  const debt = [...baseline.entries.values()].reduce(
    (s, e) => s + Object.values(e.counts).reduce((a, b) => a + b, 0),
    0,
  );

  if (findings.length === 0) {
    // The outstanding number is printed on EVERY green run, together with what was NOT graded, so the
    // excluded set is a number somebody looks at rather than a silence.
    lines.push(
      `writing-rules-source: 0 NEW violations across ${scanned.size} of ${tracked.length} tracked file(s), ` +
        `${binary} excluded as binary; ${debt} pre-existing recorded in ${BASELINE_REL} across ${baseline.entries.size} file(s)`,
    );
    return { code: 0, lines, errs };
  }

  errs.push(`writing-rules-source: ${findings.length} finding(s) against ${BASELINE_REL}`, "");
  for (const f of findings) errs.push(f);
  errs.push(
    "",
    "House style bans these characters and words everywhere in this workspace. Rewrite the line: a comma, a colon,",
    'parentheses, "to" for a numeric range, or a full stop. A hit belongs in the ledger only as RECORDED DEBT, with',
    "its reason written in, and the only finding above that is fixed by deleting an entry is CLEARED.",
  );
  return { code: 1, lines, errs };
}

// ---------------------------------------------------------------------------------------------------------
// MODE ARBITRATION. What this run was asked to do, decided ONCE, from the whole command line at once.
// ---------------------------------------------------------------------------------------------------------

const KNOWN_FLAGS = new Set(["--write-baseline", "--print-subject", "--self-test"]);

// Every known flag names a mode. --self-test maps to "grade" because that is what it does after its
// fixtures pass, and that mapping is the reason it can never be one of the modes that skip the grade.
const MODE_OF_FLAG = {
  "--write-baseline": "write-baseline",
  "--print-subject": "print-subject",
  "--self-test": "grade",
};

// THE MODES THAT DO NOT GRADE, WRITTEN DOWN RATHER THAN INFERRED FROM WHICH BRANCH HAPPENS TO RUN. That
// inference is what the dispatcher used to do, and it is how a second flag came to decide what the first
// one did. A mode reaching exit 0 without grading has to be on this list, and checkArbitration() sweeps
// every combination of flag and environment to prove that no other route onto it exists.
const NON_GRADING_MODES = new Set(["write-baseline", "print-subject", "self-test-only"]);

/**
 * Is the file now running the one its repository TRACKS, or a disposable copy of it?
 *
 * This is the fact that WRITING_RULES_MUTANT=1 used to assert on its own, and an environment variable is
 * not evidence of anything: anybody can set it, and setting it against the real gate turned the CI command
 * into a green run over an ungraded tree. The mutation subjects runMutants() spawns are written into a temp
 * directory that no repository tracks, so the difference between a subject and the gate is a fact about the
 * process rather than a claim in its environment, and it is read here rather than believed.
 *
 * "unknown" is a third answer on purpose. git failing to run is not the same as git saying no, and the
 * caller refuses on both rather than treating a missing instrument as a licence to skip the grade.
 *
 * IT DID NOT FIRE ON THE LIKELIEST WAY THE INSTRUMENT FAILS, which is the correction here. The third
 * answer was reached only when the spawn errored or the status was null, so it covered git not being on
 * the PATH and git being killed by a signal. git RUNNING AND BEING UNABLE TO ANSWER exits 128, and 128 is
 * non-zero, so it fell to "untracked", which is the permissive arm: the one that lets WRITING_RULES_MUTANT
 * skip the grade. Driven in a copy of this tree with no .git, the mutation variable beside --self-test
 * reached EXIT 0 with the tree never graded, which is the exact shape this repair exists to close, reached
 * through a different door.
 *
 * So the mapping is written from what git actually answers rather than from zero against everything else.
 * Measured with git 2.50.1: 0 for a tracked path, 1 for a path the index does not hold whether or not it
 * exists on disk, 128 where there is no repository to ask. ONE is the only status that means "no", and
 * every other way of not saying yes is the instrument failing to answer. Asking rev-parse
 * --is-inside-work-tree first was the alternative, and it is weaker: it needs a second process and it
 * still leaves every status other than 0 and 1 mapping to the permissive arm.
 */
function selfTrackedState(repo, selfPath) {
  const rel = relative(repo, selfPath);
  if (rel === "" || rel.startsWith("..")) return "unknown";
  const r = spawnSync("git", ["-C", repo, "ls-files", "--error-unmatch", "--", rel], {
    stdio: ["ignore", "ignore", "ignore"],
  });
  if (r.error || r.status === null) return "unknown";
  if (r.status === 0) return "tracked";
  if (r.status === 1) return "untracked";
  return "unknown";
}

/**
 * Turn a command line into the one job it asks for, or into a refusal that says why.
 *
 * It is a pure function of its three inputs so that checkArbitration() can sweep the whole product of them
 * without spawning anything, and so that a mutation can put either guard back and be caught by that sweep.
 * The dispatcher at the foot of this file does what it returns and decides nothing itself.
 */
function planInvocation(argv, mutantEnv, selfTracked) {
  const flags = argv.filter((a) => a.startsWith("--"));
  const positional = argv.filter((a) => !a.startsWith("--"));
  // A POSITIONAL ARGUMENT IS REFUSED RATHER THAN IGNORED. This gate used to take root directories, and a
  // caller still passing them would otherwise be silently scanning something other than what it asked for.
  if (positional.length > 0) {
    return { refuse: `'${positional[0]}' looks like a root. This gate takes no roots: its subject is every tracked file.` };
  }
  const unknown = flags.find((f) => !KNOWN_FLAGS.has(f));
  if (unknown !== undefined) {
    return { refuse: `unknown flag '${unknown}'. Known flags: ${[...KNOWN_FLAGS].join(" ")}.` };
  }
  const modes = [...KNOWN_FLAGS].filter((f) => flags.includes(f));
  if (modes.length > 1) {
    return {
      refuse:
        `${modes.join(" and ")} were given together, and each of them names a different job. Only one of those ` +
        `jobs grades the tree, so a run carrying both would do one of them and say nothing about the other. ` +
        `Ask for one job at a time.`,
    };
  }
  if (mutantEnv) {
    if (selfTracked !== "untracked") {
      const because =
        selfTracked === "tracked"
          ? "this file is the one tracked by the repository it would otherwise grade"
          : "whether this file is tracked could not be established";
      return {
        refuse:
          `WRITING_RULES_MUTANT=1 declares this process a disposable mutation subject, and ${because}. That ` +
          `mode stops before the grade, so honouring it here would report success over a tree nothing read. ` +
          `Unset the variable.`,
      };
    }
    if (!flags.includes("--self-test")) {
      return {
        refuse:
          "WRITING_RULES_MUTANT=1 was set without --self-test, so this process has no fixtures to run and no " +
          "tree it is allowed to grade.",
      };
    }
    return { selfTest: true, mode: "self-test-only" };
  }
  return { selfTest: flags.includes("--self-test"), mode: modes.length === 1 ? MODE_OF_FLAG[modes[0]] : "grade" };
}

// ---------------------------------------------------------------------------------------------------------
// SELF-TEST. Every fixture repository below is disposable, is a real git repository because the subject is
// derived from git, and every dash and NUL in it is written from a CODE POINT or a BYTE VALUE rather than
// typed. Each case names the defect it would have caught.
// ---------------------------------------------------------------------------------------------------------

/**
 * THE MUTANTS. Each one puts a single fix back the way it was and asserts the self-test above goes RED.
 *
 * A passing self-test only proves the fixtures agree with the code as written. It cannot tell a fix from a
 * coincidence, and three of the four mutations below produced a fully green suite in earlier drafts of this
 * work, which is exactly the evidence a green run is not able to give you. So the mutations run here, in
 * the gate, rather than being described in a report: the file rewrites itself into a temp copy, runs that
 * copy, and requires a non-zero exit.
 *
 * The CONTROL is the unmutated copy, which must exit 0. Without it a broken spawn would make every mutant
 * "redden" for reasons that have nothing to do with the mutation.
 *
 * Each mutation asserts that its search text was actually FOUND. A find-and-replace that silently matched
 * nothing yields a copy identical to the original, which exits 0, which reads as a fix that is not needed.
 */
function runMutants(check, declare) {
  const src = readFileSync(SELF_PATH, "utf8");
  // THE BED IS A REAL REPOSITORY THAT DOES NOT TRACK THE SUBJECT, and it used to be a bare temp directory
  // that no repository could answer about at all. The difference is the whole premise of this harness. A
  // subject is allowed to stop after its fixtures because it is a disposable copy, and the fact it rests
  // on is git SAYING the file is not tracked. In a bare temp directory git cannot say anything: it exits
  // 128, and the old mapping read that as "not tracked", so every subject here was admitted by the
  // instrument failing rather than by an answer. Correcting that mapping turned all six subjects into
  // refusals, which is how this came to light. Making the bed a repository makes the premise true instead
  // of arguing the mapping back.
  //
  // A CHILD SITS AT <bed>/scripts/<name>.mjs BECAUSE REPO IS THE PARENT OF THE SCRIPT'S DIRECTORY. Put a
  // child at the top of the bed and its REPO becomes the system temp directory, which is not a repository
  // and puts the subject straight back where it started.
  const dir = mkdtempSync(join(tmpdir(), "writing-rules-mutants-"));
  execFileSync("git", ["-C", dir, "init", "-q"]);
  mkdirSync(join(dir, "scripts"), { recursive: true });

  const spawn = (name, text) => {
    const p = join(dir, "scripts", `${name}.mjs`);
    writeFileSync(p, text);
    const r = spawnSync(process.execPath, [p, "--self-test"], {
      encoding: "utf8",
      env: { ...process.env, WRITING_RULES_MUTANT: "1" },
    });
    return r.status;
  };

  const controlStatus = spawn("control", src);
  check(`CONTROL: an unmutated copy of this file passes its own self-test (exit ${controlStatus})`, controlStatus === 0);
  // THE BED'S OWN PREMISE, ASSERTED RATHER THAN ASSUMED, and it is the control that says the subjects
  // below are admitted for a reason. git must ANSWER here, and its answer must be the one that means
  // untracked. A bed that had stopped being a repository would answer 128, every subject would refuse,
  // and the mutant checks would all read exit 2, which is a harness that never ran rather than a fix that
  // works.
  check(
    `CONTROL: the harness bed is a repository that ANSWERS "not tracked" for its subjects (${selfTrackedState(dir, join(dir, "scripts", "control.mjs"))})`,
    selfTrackedState(dir, join(dir, "scripts", "control.mjs")) === "untracked",
  );

  const mutations = [
    [
      "the dangling remedy, put back to the one message that told you to remove the entry",
      "function classifyStale(file, rule, count, scanned, tracked, ungradedReason) {",
      "function classifyStale(file, rule, count, scanned, tracked, ungradedReason) {\n  return \"  DANGLING \" + file + \" [\" + rule + \"] is recorded but the file no longer breaks that rule. Remove the entry.\";",
    ],
    [
      "the banned-word unit, put back to one hit per COMMENT at the line the comment opened on",
      "      for (const m of text.matchAll(re)) {",
      "      if (!re.test(text)) continue;\n      for (const m of [{ index: 0 }]) {",
    ],
    [
      "the subject, put back to an extension list",
      "    files.push(rel);",
      '    if (![".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs", ".md"].some((e) => rel.endsWith(e))) {\n      ungradedReason.set(rel, "extension not in the list");\n      continue;\n    }\n    files.push(rel);',
    ],
    [
      "the scanned set, inferred from the hits instead of from what was read",
      "compareToBaseline(observed, baseline, hits, scanned, new Set(tracked), ungradedReason)",
      "compareToBaseline(observed, baseline, hits, new Set(observed.keys()), new Set(tracked), ungradedReason)",
    ],
    [
      "the mode flags, put back to a run where a second flag silently decides what the first one did",
      '  if (modes.length > 1) {',
      '  if (false) {',
    ],
    [
      "the mutant environment variable, put back to a claim believed rather than a fact read",
      '    if (selfTracked !== "untracked") {',
      "    if (false) {",
    ],
    [
      "the third answer, put back to a permissive untracked for every way git can fail short of not running",
      '  if (r.status === 1) return "untracked";\n  return "unknown";',
      '  return r.status === 0 ? "tracked" : "untracked";',
    ],
  ];

  // EVERY ANCHOR BELOW APPEARS AT LEAST TWICE IN THIS FILE, because the mutation table quotes the very text
  // it searches for. A bare replace() would take the first occurrence and happen to be right only because
  // the code sits above the table, which is an ordering nothing enforces. So the file is split at this
  // function and the replacement is applied to the CODE half alone, with the anchor required to occur there
  // EXACTLY ONCE. An anchor that has drifted, or that now matches twice, fails as a named check rather than
  // mutating a line nobody meant.
  const boundary = src.indexOf("function runMutants(check, declare) {");
  check("the code half of this file was located", boundary > 0);
  const codeHalf = src.slice(0, boundary);
  const testHalf = src.slice(boundary);

  const occurrences = (haystack, needle) => haystack.split(needle).length - 1;

  // The block below makes two checks per mutation, so it says how many times it will repeat rather than
  // leaving the floor to guess. A table that loses an entry lowers the floor by exactly two.
  declare("one check pair per mutation", mutations.length);

  for (const [label, from, to] of mutations) {
    const n = occurrences(codeHalf, from);
    check(`MUTANT anchor is unique in the code half: ${label} (found ${n})`, n === 1);
    if (n !== 1) continue;
    const mutated = codeHalf.replace(from, to) + testHalf;
    // EXIT 1 EXACTLY, never merely non-zero. Exit 2 is could-not-check, and a child that could not check
    // is not a mutant that reddened: it is a mutant that never ran.
    const status = mutated === src ? -1 : spawn(label.slice(0, 20).replace(/\W/g, "-"), mutated);
    check(`MUTANT reddens at exit 1: ${label} (exit ${status})`, status === 1);
  }

  rmSync(dir, { recursive: true, force: true });
}

function fixtureRepo(files) {
  const dir = mkdtempSync(join(tmpdir(), "writing-rules-"));
  execFileSync("git", ["-C", dir, "init", "-q"]);
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, content);
  }
  execFileSync("git", ["-C", dir, "add", "-A"]);
  return dir;
}

function ledger(entries) {
  return JSON.stringify({ units: { ...RULE_UNITS }, entries }, null, 2);
}

/**
 * THE CONTROL AGAINST THE DEFECT THIS FILE WAS LAST CAUGHT BY: A MODE THAT REACHES EXIT 0 WITHOUT GRADING.
 *
 * planInvocation() is pure, so the whole product of its inputs is small enough to sweep rather than sample:
 * every subset of the known flags, both settings of the mutation variable, and each of the three answers to
 * "is this file tracked". Sampling is what the previous round did, by writing one check per route somebody
 * had already found, and the two routes that landed were the ones nobody had thought to write a check for.
 *
 * This runs in a mutation subject as well as in the gate. It has to: runMutants() spawns its children with
 * the mutation variable set, so anything guarded by "not a mutant" is invisible to the mutation harness and
 * a mutation that put either guard back would go unpunished. Nothing here spawns a process, so it is cheap
 * enough to run in every child.
 */
function checkArbitration(check) {
  const flags = [...KNOWN_FLAGS];
  const subsets = [];
  for (let mask = 0; mask < 1 << flags.length; mask++) subsets.push(flags.filter((_, i) => (mask >> i) & 1));
  const trackedStates = ["tracked", "untracked", "unknown"];
  const cells = [];
  for (const subset of subsets) {
    for (const mutantEnv of [false, true]) {
      for (const tracked of trackedStates) {
        cells.push({ subset, mutantEnv, tracked, plan: planInvocation(subset, mutantEnv, tracked) });
      }
    }
  }
  // The sweep's own size is DERIVED, never written down, so a flag added to KNOWN_FLAGS doubles it without
  // anybody remembering to raise a number. A fixed count here is how a population grows past its own check.
  check(
    `the arbitration sweep is the whole product: ${flags.length} flags, ${subsets.length} subsets, 2 environments, ${trackedStates.length} tracked states, ${cells.length} cells`,
    flags.length >= 3 && subsets.length === 2 ** flags.length && cells.length === subsets.length * 2 * trackedStates.length,
  );

  const accepted = cells.filter((c) => c.plan.refuse === undefined);
  const grading = accepted.filter((c) => c.plan.mode === "grade");
  const nonGrading = accepted.filter((c) => c.plan.mode !== "grade");

  // CONTROLS BEFORE INVARIANTS. A sweep that accepted nothing, or that graded nothing, satisfies every
  // invariant below by being empty, and would read as a clean bill of health for a gate with no modes left.
  check(`CONTROL: the sweep accepts cells, so the invariants below are not vacuous (${accepted.length} of ${cells.length})`, accepted.length > 0);
  check(`CONTROL: accepted cells that GRADE are reachable (${grading.length})`, grading.length > 0);
  check(`CONTROL: refusal is reachable (${cells.length - accepted.length} refused)`, cells.length - accepted.length > 0);
  check(`CONTROL: accepted cells that do NOT grade are reachable, so the next check has something to bind (${nonGrading.length})`, nonGrading.length > 0);

  // INVARIANT ONE. Every accepted plan either grades or is one of the modes declared not to.
  const undeclared = nonGrading.filter((c) => !NON_GRADING_MODES.has(c.plan.mode));
  check(`every accepted plan either grades or holds a DECLARED non-grading mode (${undeclared.length} do neither)`, undeclared.length === 0);

  // INVARIANT TWO. A non-grading mode is only ever reached by asking for it by name. This is the one that
  // fails when a second flag decides what the first one did: nobody asked for the mode that ran.
  const flagOfMode = new Map(Object.entries(MODE_OF_FLAG).map(([f, m]) => [m, f]));
  const unasked = nonGrading.filter((c) =>
    c.plan.mode === "self-test-only"
      ? !(c.mutantEnv && c.tracked === "untracked")
      : !(c.subset.length === 1 && c.subset[0] === flagOfMode.get(c.plan.mode)),
  );
  check(`every accepted non-grading plan was asked for by name and by itself (${unasked.length} were not)`, unasked.length === 0);

  // INVARIANT THREE, THE ONE THIS ROUND EXISTS FOR. --self-test is the invocation CI makes, so no flag and
  // no environment beside it may take it to a run that ends without grading, other than a real mutation
  // subject, which is an untracked copy of this file and cannot be a checkout of the repository.
  const withSelfTest = cells.filter((c) => c.subset.includes("--self-test"));
  const selfTestSkips = withSelfTest.filter(
    (c) => c.plan.refuse === undefined && c.plan.mode !== "grade" && !(c.mutantEnv && c.tracked === "untracked"),
  );
  check(`--self-test never reaches a non-grading run outside a disposable copy (${withSelfTest.length} cells swept, ${selfTestSkips.length} skips)`, selfTestSkips.length === 0);

  // INVARIANT FOUR. The mutation variable is refused wherever the file is not a disposable copy, and the
  // count is derived from the sweep rather than typed, for the reason given at the top.
  const envOnRealGate = cells.filter((c) => c.mutantEnv && c.tracked !== "untracked");
  check(
    `WRITING_RULES_MUTANT is refused wherever this file is not an untracked copy (${envOnRealGate.length} cells)`,
    envOnRealGate.length === subsets.length * (trackedStates.length - 1) && envOnRealGate.every((c) => c.plan.refuse !== undefined),
  );

  // NAMED CELLS, so the report shows the routes rather than only a tally of them. Each was DRIVEN as a real
  // process against a real tree carrying a real violation before it was written down here.
  const viaEnv = planInvocation(["--self-test"], true, "tracked");
  check("ROUTE the mutation variable set against the tracked gate is refused", viaEnv.refuse?.includes("WRITING_RULES_MUTANT") === true);
  const viaPrint = planInvocation(["--self-test", "--print-subject"], false, "tracked");
  check("ROUTE --self-test beside --print-subject is refused", viaPrint.refuse !== undefined);
  const viaWrite = planInvocation(["--self-test", "--write-baseline"], false, "tracked");
  check("ROUTE --self-test beside --write-baseline is refused, so a self-test cannot bank a live violation", viaWrite.refuse !== undefined);
  const viaBoth = planInvocation(["--write-baseline", "--print-subject"], false, "tracked");
  check("ROUTE --write-baseline beside --print-subject is refused rather than skipping the write in silence", viaBoth.refuse !== undefined);

  // AND THE FOUR THAT MUST STILL WORK. A refusal that refuses everything is a gate nobody can run.
  const ci = planInvocation(["--self-test"], false, "tracked");
  check("CONTROL: the CI invocation runs the fixtures AND grades", ci.refuse === undefined && ci.selfTest === true && ci.mode === "grade");
  const bare = planInvocation([], false, "tracked");
  check("CONTROL: a bare run grades", bare.refuse === undefined && bare.selfTest === false && bare.mode === "grade");
  const subject = planInvocation(["--print-subject"], false, "tracked");
  check("CONTROL: --print-subject alone is still the query the CI path-shadow test calls", subject.refuse === undefined && subject.mode === "print-subject");
  const mutant = planInvocation(["--self-test"], true, "untracked");
  check("CONTROL: a real mutation subject, an untracked copy, may still stop after its fixtures", mutant.refuse === undefined && mutant.mode === "self-test-only");
}

/**
 * The same arbitration, driven as REAL PROCESSES reading REAL EXIT CODES, because a plan the dispatcher
 * ignores is a guard clause upstream of nothing. The subject is a tracked copy of this file inside a
 * disposable repository carrying one planted dash, so the copy is in the same position as the gate itself:
 * tracked by the repository it grades.
 *
 * NO CELL MAY REACH A SELF-TEST THAT IS NOT A MUTATION SUBJECT, and this is a hard rule rather than a
 * preference, because breaking it costs more than the check is worth. The first draft of this block carried
 * a cell for --self-test beside --print-subject. With the arbitration intact the cell refuses in
 * milliseconds. With the guard it tests REMOVED, which is the one state the cell exists for, the copy runs
 * the whole harness one level down, reaches this block again, and spawns two more of itself: it does not
 * redden, it recurses, and driving it that way is what hung my bed for two minutes. A gate whose failure
 * mode is a fork bomb has stopped being a gate.
 *
 * So every cell here either carries no --self-test at all, or carries it with the mutation variable set,
 * which makes the child a mutation subject that skips this block by construction. The rule is asserted
 * below rather than left to whoever edits the table next. The flag pairings themselves are swept
 * exhaustively by checkArbitration(), which spawns nothing and which the mutation harness defends, and one
 * refusal that carries no --self-test proves end to end that a refusal reaches the process exit code.
 */
function runArbitrationCells(check, declare) {
  const dir = fixtureRepo({
    "scripts/writing-rules-source.mjs": readFileSync(SELF_PATH, "utf8"),
    "scripts/writing-rules-baseline.json": ledger({}),
    "dirty.md": `a planted line ${EM_DASH} carrying one em dash\n`,
  });
  const gate = join(dir, "scripts", "writing-rules-source.mjs");
  const spawnCell = (args, mutantEnv) => {
    const env = { ...process.env };
    if (mutantEnv) env.WRITING_RULES_MUTANT = "1";
    else delete env.WRITING_RULES_MUTANT;
    return spawnSync(process.execPath, [gate, ...args], { encoding: "utf8", env }).status;
  };

  // THE POSITIVE CONTROL COMES FIRST, and every cell below is worthless without it: this copy, on this
  // tree, GRADES and FINDS the planted dash. A copy that could not find it would make every refusal below
  // read as a pass for reasons that have nothing to do with arbitration.
  const bare = spawnCell([], false);
  check(`CONTROL: the tracked copy grades its own repository and finds the planted dash (exit ${bare})`, bare === 1);

  const cells = [
    [["--print-subject", "--write-baseline"], false, 2, "two mode flags together, so a refusal reaches the exit code"],
    [["--self-test"], true, 2, "--self-test with the mutation variable set against a tracked copy"],
    [[], true, 2, "the mutation variable set with no flag at all"],
    [["--nonsense"], false, 2, "an unknown flag"],
    [["src"], false, 2, "a positional argument, which this gate stopped taking"],
    [["--print-subject"], false, 0, "--print-subject alone, the declared query mode"],
    [["--write-baseline"], false, 0, "--write-baseline alone, the declared record mode, run last because it rewrites the ledger"],
  ];
  // THE RULE FROM THE HEADER, ASSERTED. A cell carrying --self-test without the mutation variable would run
  // the harness again one level down and spawn its own cells, so a guard breaking would hang rather than
  // redden. Every cell either avoids --self-test or makes the child a mutation subject, which skips this
  // block by construction, and that bound holds however many guards are broken at once.
  const recursive = cells.filter(([args, mutantEnv]) => args.includes("--self-test") && !mutantEnv);
  check(`no cell can reach a self-test outside a mutation subject, so a broken guard reddens rather than recurses (${recursive.length} would)`, recursive.length === 0);

  // THE COMMAND CI RUNS FOR THIS GATE MUST BE ONE THAT GRADES, and until now nothing asserted it. The CI
  // path-shadow test checks that lint:prose NAMES this file and says nothing about the flags it names it
  // with, so re-pointing that one script at --write-baseline would leave the job green over every
  // violation, for as long as nobody looked, and would read in a diff as somebody regenerating a ledger.
  // Two flags can no longer combine to skip the grade, so the last way to reach exit 0 without grading is
  // to ASK for a mode that does not grade, and this is where that is asked about.
  const pkgPath = join(REPO, "package.json");
  const proseScript = existsSync(pkgPath) ? JSON.parse(readFileSync(pkgPath, "utf8")).scripts?.["lint:prose"] : undefined;
  check(`the repository declares a lint:prose that runs this gate (${proseScript ?? "absent"})`, typeof proseScript === "string" && proseScript.includes("writing-rules-source.mjs"));
  // An absent script yields a deliberately POISONED argument list rather than an empty one, because an
  // empty list plans as a bare run, which grades, and would let the next check pass on a repository that
  // has no such command at all.
  const ciFlags = typeof proseScript === "string" ? proseScript.split(/\s+/).filter((a) => a.startsWith("--")) : ["--print-subject"];
  const ciPlan = planInvocation(ciFlags, false, "tracked");
  check(
    `the lint:prose command GRADES the tree (flags ${JSON.stringify(ciFlags)}, mode ${ciPlan.refuse === undefined ? ciPlan.mode : "refused"})`,
    ciPlan.refuse === undefined && ciPlan.mode === "grade",
  );

  declare("one check per arbitration cell", cells.length);

  for (const [args, mutantEnv, want, why] of cells) {
    const status = spawnCell(args, mutantEnv);
    check(`ARBITRATION exits ${want}: ${why} (exit ${status})`, status === want);
  }
  rmSync(dir, { recursive: true, force: true });
}

/**
 * Count the check() CALL SITES between two markers in this file's own source.
 *
 * THE PATTERN IS ANCHORED TO THE START OF A LINE, and the sentence above is why. A bare search for the
 * call text reads PROSE as code: the first draft of this counter found seven sites that do not exist,
 * every one of them the words in this very comment, and each of them was then multiplied by the number of
 * cells in a loop. That is the comment-scanner defect this repository has been bitten by before, so the
 * comment stays exactly as written and now serves as a live control: revert the anchor and the floor rises
 * above the population, which is a red run rather than a quiet one.
 */
function countCheckSites(src, startMarker, endMarker) {
  const a = src.indexOf(startMarker);
  if (a < 0) return { error: `region start marker not found: ${startMarker.trim().slice(0, 48)}` };
  const b = src.indexOf(endMarker, a + startMarker.length);
  if (b < 0) return { error: `region end marker not found: ${endMarker.trim().slice(0, 48)}` };
  return { sites: (src.slice(a, b).match(/^[ \t]*check\(/gm) ?? []).length };
}

/**
 * THE SELF-TEST'S OWN COUNT, FLOORED, WITH THE FLOOR MOVING AS THE POPULATION MOVES.
 *
 * The self-test reported "39 of 39 passed" under the mutation variable and "49 of 49 passed" without it,
 * and called both of them a pass. Ten checks had gone and the verdict did not move, which is the same
 * defect as the gate it protects, one level down: a number printed rather than checked.
 *
 * A written-down floor would not fix it. A sibling repository carried one at 120 while its population went
 * from 188 to 214, so a fall to 189 sailed over a floor nobody had moved, and the fall was the whole
 * finding. So the floor here is DERIVED from this file on every run, by counting the check() call sites in
 * each block that was meant to run, and a block that repeats says how many times it will repeat rather than
 * being guessed at. Add a check and the floor rises by one. Add a mutation and it rises by two. Skip a
 * block and its declaration never arrives, which is a named failure rather than a smaller number.
 */
function populationFloor(src, asMutant, declared) {
  // EVERY MARKER IS ANCHORED TO THE START OF A LINE, and that is not tidiness. This table quotes the very
  // text it searches for, so a marker written bare would match its own entry here, and for one of them the
  // entry sits EARLIER in the file than the code it names. The region would then start inside this table
  // and the count would be right by luck rather than by construction. A leading newline cannot match a
  // quoted entry, because an entry is never at the start of a line.
  const M_MUTATION_LOOP = "\n  for (const [label, from, to] of mutations) {";
  const M_CELL_LOOP = "\n  for (const [args, mutantEnv, want, why] of cells) {";
  const regions = [
    { name: "fixture cases", from: "\nfunction selfTest() {", to: "\nconst PLAN = planInvocation(", runs: true, per: null },
    { name: "flag arbitration", from: "\nfunction checkArbitration(check) {", to: "\nfunction runArbitrationCells(", runs: true, per: null },
    { name: "mutation harness", from: "\nfunction runMutants(check, declare) {", to: M_MUTATION_LOOP, runs: !asMutant, per: null },
    { name: "per mutation", from: M_MUTATION_LOOP, to: "\nfunction fixtureRepo(files) {", runs: !asMutant, per: "one check pair per mutation" },
    { name: "arbitration cells", from: "\nfunction runArbitrationCells(check, declare) {", to: M_CELL_LOOP, runs: !asMutant, per: null },
    { name: "per arbitration cell", from: M_CELL_LOOP, to: "\nfunction countCheckSites(", runs: !asMutant, per: "one check per arbitration cell" },
  ];
  let floor = 0;
  const problems = [];
  for (const r of regions) {
    // A MARKER IS RESOLVED EVEN WHEN ITS BLOCK IS NOT DUE TO RUN. A region that has drifted out of the file
    // would otherwise go unnoticed in exactly the mode that does not use it, and be discovered by the floor
    // silently dropping in the mode that does.
    const counted = countCheckSites(src, r.from, r.to);
    if (counted.error) {
      problems.push(`${r.name}: ${counted.error}`);
      continue;
    }
    // A REGION THAT COUNTS ZERO IS A PATTERN THAT MATCHED NOTHING, not a block with no checks in it. Every
    // region named here exists to hold checks, so an empty one means the markers now bracket the wrong
    // text or the pattern stopped fitting the code, and either way the floor it contributes is a fiction.
    if (counted.sites === 0) {
      problems.push(`${r.name}: the markers resolved but no check call site was found between them`);
      continue;
    }
    if (!r.runs) continue;
    if (r.per === null) {
      floor += counted.sites;
      continue;
    }
    const times = declared.get(r.per);
    if (times === undefined) {
      problems.push(`${r.name}: the block was due to run and never said how many times it would repeat`);
      continue;
    }
    floor += counted.sites * times;
  }
  return { floor, problems };
}

function selfTest() {
  let pass = true;
  const checks = [];
  const check = (label, cond, detail = "") => {
    checks.push(`  ${cond ? "ok  " : "FAIL"} ${label}${detail ? ` ${detail}` : ""}`);
    if (!cond) pass = false;
  };
  const beds = [];
  // Each block that REPEATS declares how many times, so the floor below multiplies by a number the run
  // actually holds rather than by one somebody wrote down once.
  const declared = new Map();
  const declare = (block, times) => declared.set(block, times);
  const drive = (files, baseline) => {
    const dir = fixtureRepo(files);
    beds.push(dir);
    const bp = join(dir, "ledger.json");
    writeFileSync(bp, baseline);
    return run({ repo: dir, baselinePath: bp });
  };
  const dash = (n) => Array.from({ length: n }, () => EM_DASH).join(" ");
  const debtEntry = (counts) => ({ counts, why: "fixture" });

  // A FIXTURE MUST NOT BE SPELLED THE WAY THE RULE READS IT. This gate's subject is every tracked file and
  // this file is tracked, so a fixture that types a banned word inside a comment, or types the claim
  // sentence anywhere, becomes debt in the very ledger it is testing. That is what the retired "structural"
  // baseline entry used to be: a line that could never reach zero. The banned word is taken from the rule's
  // own list, so a reordered list still yields a real one, and the claim sentence is assembled rather than
  // written out, so the phrase never appears contiguously in this source.
  const BAD = BANNED_AI_WORDS[0];
  check("the self-test drew a real banned word from the rule's own list", typeof BAD === "string" && BAD.length > 2);
  const CLAIM_SENTENCE = `recovery is ${"offline"}-only`;

  // ---- 1. THE REMEDY THAT WAS THE EXPLOIT --------------------------------------------------------------
  // A recorded file that leaves the gate's view must NEVER be answered with "remove the entry".
  {
    const src = `// note ${dash(3)}\n`;
    const base = ledger({ "a.ts": debtEntry({ "em-dash": 3 }) });

    const clean = drive({ "a.ts": "// note\n" }, base);
    check("CLEARED when the file was read and the rule is genuinely gone", clean.code === 1 && clean.errs.some((l) => l.includes("CLEARED  a.ts")));
    check("CLEARED is the one verdict that tells you to drop the entry", clean.errs.some((l) => l.includes("CLEARED") && l.includes("Bank it")));

    const gone = drive({ "b.ts": "const b = 1;\n" }, base);
    check("GONE when the recorded path is no longer tracked", gone.code === 1 && gone.errs.some((l) => l.includes("GONE     a.ts")));
    check("GONE never says remove the entry unconditionally", !gone.errs.some((l) => l.includes("GONE") && /\bRemove the entry\b/.test(l)));

    // THE EXPLOIT ITSELF, driven end to end: the file is renamed out of the old path, the text untouched.
    const renamed = drive({ "moved/a.ts": src }, base);
    check("a rename is refused, not laundered", renamed.code === 1);
    check("a rename reports GONE at the old path", renamed.errs.some((l) => l.includes("GONE     a.ts")));
    check("and NEW at the new path, so the debt is conserved", renamed.errs.some((l) => l.includes("NEW      moved/a.ts [em-dash] 3 found")));

    // The other half of the exploit: the file stays put and leaves the SUBJECT instead. The bed carries a
    // second, ordinary file so that the run is graded rather than stopped by the empty-subject floor, which
    // is a different refusal and would prove nothing about this one.
    const nulled = drive({ "a.ts": `// note ${dash(3)}\n${String.fromCharCode(0)}`, "keep.ts": "const k = 1;\n" }, base);
    check("UNGRADED when the file is tracked but the gate could not read it", nulled.code === 1 && nulled.errs.some((l) => l.includes("UNGRADED a.ts")));
    check("UNGRADED names the reason it fell out of the subject", nulled.errs.some((l) => l.includes("NUL byte")));
    check("UNGRADED forbids removing the entry", nulled.errs.some((l) => l.includes("UNGRADED") && l.includes("Do NOT remove")));
  }

  // ---- 2. MIXED UNITS ----------------------------------------------------------------------------------
  // Control and attack differ only in how the same five instances are laid out. Both must count 5.
  {
    const comment = (body) => `${"//"} ${body}`;
    const fiveLines = `const a = 1;\n${Array.from({ length: 5 }, (_, i) => comment(`${BAD} ${i}`)).join("\n")}\n`;
    const oneLine = `const a = 1;\n${comment(Array.from({ length: 5 }, () => BAD).join(" "))}\n`;
    const block = `/*\n${Array.from({ length: 40 }, (_, i) => ` * ${BAD} ${i}`).join("\n")}\n */\nconst a = 1;\n`;
    const empty = ledger({});

    const ctrl = drive({ "a.ts": fiveLines }, empty);
    check("CONTROL five banned words on five lines count 5", ctrl.errs.some((l) => l.includes(`[banned-word:${BAD}] 5 found`)));
    const atk = drive({ "a.ts": oneLine }, empty);
    check("five banned words in ONE comment also count 5", atk.errs.some((l) => l.includes(`[banned-word:${BAD}] 5 found`)));
    const big = drive({ "a.ts": block }, empty);
    check("forty in one block comment count 40, not 1", big.errs.some((l) => l.includes(`[banned-word:${BAD}] 40 found`)));
    check("and each occurrence reports its own line, not the line the comment opened on", big.errs.some((l) => /Lines: 2, 3, 4, 5, 6, 7/.test(l)));

    const dashCtrl = drive({ "a.ts": `${Array.from({ length: 5 }, (_, i) => `// x${i} ${EM_DASH}`).join("\n")}\n` }, empty);
    check("CONTROL dashes were already per occurrence and still are", dashCtrl.errs.some((l) => l.includes("[em-dash] 5 found")));

    // The unit is declared and the declaration is load-bearing.
    const wrongUnit = drive({ "a.ts": "const a = 1;\n" }, JSON.stringify({ units: { ...RULE_UNITS, "banned-word": "comment" }, entries: {} }));
    check("a ledger declaring a unit this gate does not implement refuses at 2", wrongUnit.code === 2);
    const noUnit = drive({ "a.ts": "const a = 1;\n" }, JSON.stringify({ entries: {} }));
    check("a ledger with no units field at all refuses at 2", noUnit.code === 2);
    const undeclared = drive({ "a.ts": "const a = 1;\n" }, ledger({ "a.ts": debtEntry({ "made-up-rule": 1 }) }));
    check("a ledger recording a rule whose family has no declared unit refuses at 2", undeclared.code === 2);
    const declaredFamily = drive({ "a.ts": "const a = 1;\n" }, ledger({ "a.ts": debtEntry({ "banned-word:anything": 1 }) }));
    check("CONTROL: a rule in a DECLARED family is accepted, so the check is not refusing everything", declaredFamily.code === 1);
  }

  // ---- 3. THE SUBJECT ----------------------------------------------------------------------------------
  // Every one of these was invisible to the extension list, and two of them sat inside a graded root.
  {
    const empty = ledger({});
    const withDash = (n) => `# comment ${dash(n)}\n`;
    const wide = drive(
      {
        "wrangler.toml": withDash(2),
        "scripts/deploy.sh": `#!/bin/sh\n# note ${dash(1)}\n`,
        ".gitignore": withDash(1),
        "nobody/thought/of/this/dir/NOTES.md": withDash(1),
      },
      empty,
    );
    check("a .toml at the repo root is graded", wide.errs.some((l) => l.includes("wrangler.toml [em-dash] 2 found")));
    check("a shell script is graded", wide.errs.some((l) => l.includes("scripts/deploy.sh [em-dash] 1 found")));
    check("a dotfile is graded", wide.errs.some((l) => l.includes(".gitignore [em-dash] 1 found")));
    check("a directory no root list names is graded", wide.errs.some((l) => l.includes("dir/NOTES.md [em-dash] 1 found")));

    // The NUL test discriminates, in BOTH directions. An empty pattern would match every file and a typed
    // control would be refused by sibling repositories, so the NUL is written from a byte value.
    const nul = String.fromCharCode(0);
    const binBed = fixtureRepo({ "keep.md": withDash(1), "blob.seg": `abc${nul}def` });
    beds.push(binBed);
    const bp = join(binBed, "ledger.json");
    writeFileSync(bp, empty);
    const binRun = run({ repo: binBed, baselinePath: bp });
    check("CONTROL the text file beside a binary one is still graded", binRun.errs.some((l) => l.includes("keep.md [em-dash] 1 found")));
    const sub = readSubject(binBed, trackedFiles(binBed));
    check("the NUL-bearing file is excluded", !sub.files.includes("blob.seg") && sub.binary === 1);
    check("and the file without a NUL is NOT excluded", sub.files.includes("keep.md"));

    // Untracked files are outside the subject, so another pass's scratch bed cannot turn this gate red.
    const bed = fixtureRepo({ "a.md": "clean\n" });
    beds.push(bed);
    writeFileSync(join(bed, "scratch.md"), withDash(9));
    const bp2 = join(bed, "ledger.json");
    writeFileSync(bp2, empty);
    const untracked = run({ repo: bed, baselinePath: bp2 });
    check("an untracked file is not graded", untracked.code === 0, `(exit ${untracked.code})`);
  }

  // ---- 4. THE RATCHET STILL FAILS IN BOTH DIRECTIONS ---------------------------------------------------
  {
    const two = `// a ${EM_DASH}\n// b ${EM_DASH}\n`;
    const more = drive({ "a.ts": `${two}// c ${EM_DASH}\n` }, ledger({ "a.ts": debtEntry({ "em-dash": 2 }) }));
    check("MORE than recorded fails", more.code === 1 && more.errs.some((l) => l.includes("NEW      a.ts")));
    const fewer = drive({ "a.ts": `// a ${EM_DASH}\n` }, ledger({ "a.ts": debtEntry({ "em-dash": 2 }) }));
    check("FEWER than recorded fails as an unbanked cleanup", fewer.code === 1 && fewer.errs.some((l) => l.includes("BANK     a.ts")));
    const none = drive({ "a.ts": two }, ledger({}));
    check("hits with NO entry fail", none.code === 1 && none.errs.some((l) => l.includes("NEW      a.ts")));
    const exact = drive({ "a.ts": two }, ledger({ "a.ts": debtEntry({ "em-dash": 2 }) }));
    check("EXACTLY the recorded number passes", exact.code === 0, `(exit ${exact.code})`);
    const enDash = drive({ "a.ts": `// r ${EN_DASH}\n` }, ledger({}));
    check("the en dash is a rule of its own", enDash.errs.some((l) => l.includes("[en-dash] 1 found")));
    const claim = drive({ "a.md": `${CLAIM_SENTENCE}\n` }, ledger({}));
    check("the claim rule fires", claim.errs.some((l) => l.includes("[claim:recovery-offline-only]")));
    const negated = drive({ "a.md": `${CLAIM_SENTENCE.replace(" is ", " is not ")}\n` }, ledger({}));
    check("and clears an honest negation", negated.code === 0, `(exit ${negated.code})`);
  }

  // ---- 5. COULD-NOT-CHECK IS EXIT 2, AND ONLY THAT -----------------------------------------------------
  {
    const notARepo = mkdtempSync(join(tmpdir(), "writing-rules-norepo-"));
    beds.push(notARepo);
    writeFileSync(join(notARepo, "ledger.json"), ledger({}));
    const r = run({ repo: notARepo, baselinePath: join(notARepo, "ledger.json") });
    check("a tree git cannot enumerate is exit 2", r.code === 2, `(exit ${r.code})`);
    const bed = fixtureRepo({ "a.ts": "const a = 1;\n" });
    beds.push(bed);
    const missing = run({ repo: bed, baselinePath: join(bed, "no-such-ledger.json") });
    check("a missing ledger is exit 2", missing.code === 2, `(exit ${missing.code})`);
    writeFileSync(join(bed, "bad.json"), "{not json");
    const bad = run({ repo: bed, baselinePath: join(bed, "bad.json") });
    check("a malformed ledger is exit 2", bad.code === 2, `(exit ${bad.code})`);
    const emptyRepo = fixtureRepo({});
    beds.push(emptyRepo);
    writeFileSync(join(emptyRepo, "ledger.json"), ledger({}));
    execFileSync("git", ["-C", emptyRepo, "rm", "-q", "--cached", "-r", "--ignore-unmatch", "."]);
    const vac = run({ repo: emptyRepo, baselinePath: join(emptyRepo, "ledger.json") });
    check("a tree with nothing tracked is exit 2, never a green zero", vac.code === 2, `(exit ${vac.code})`);

    // ---- THE THIRD ANSWER, DRIVEN OVER THE WAY THE INSTRUMENT ACTUALLY FAILS -------------------------
    // checkArbitration() sweeps planInvocation() over all three tracked states, so the arbitration on top
    // of this fact was well defended and the fact itself was not: nothing drove selfTrackedState() over a
    // directory git cannot answer about. It returned "untracked" there, which is the arm that lets the
    // mutation variable skip the grade. These run in a mutation subject too, so a mutant putting the
    // permissive mapping back is punished by them rather than sailing past.
    const trackedBed = fixtureRepo({ "scripts/self.mjs": "const a = 1;\n" });
    beds.push(trackedBed);
    check(
      "selfTrackedState: a file its repository tracks reads as tracked",
      selfTrackedState(trackedBed, join(trackedBed, "scripts/self.mjs")) === "tracked",
    );
    writeFileSync(join(trackedBed, "scratch.mjs"), "const b = 2;\n");
    check(
      "CONTROL: a real untracked copy still reads as untracked, so the permissive arm is still reachable",
      selfTrackedState(trackedBed, join(trackedBed, "scratch.mjs")) === "untracked",
    );
    // THE CONTROL THAT STOPS THE NEXT CHECK PASSING FOR THE WRONG REASON. selfTrackedState() has a second
    // route to "unknown", the guard on a path outside the repository, and a fixture that took that route
    // would read as green while saying nothing about git's status at all. So the path is asserted to be
    // INSIDE the bed, and git is asserted to answer something that is neither yes nor its one way of
    // saying no. A bed that turned out to sit inside some enclosing repository would answer 1 here and
    // fail this control rather than quietly proving nothing.
    writeFileSync(join(notARepo, "self.mjs"), "const c = 3;\n");
    const noRepoRel = relative(notARepo, join(notARepo, "self.mjs"));
    const noRepoProbe = spawnSync("git", ["-C", notARepo, "ls-files", "--error-unmatch", "--", noRepoRel], {
      stdio: ["ignore", "ignore", "ignore"],
    });
    check(
      `CONTROL: the bed is a real non-repository reached through the git call, not through the outside-the-repo guard (rel ${noRepoRel}, git status ${noRepoProbe.status})`,
      noRepoRel === "self.mjs" && noRepoProbe.status !== null && noRepoProbe.status !== 0 && noRepoProbe.status !== 1,
    );
    check(
      "selfTrackedState: git running and unable to answer is UNKNOWN, not untracked",
      selfTrackedState(notARepo, join(notARepo, "self.mjs")) === "unknown",
    );
    // AND THE TWO HALVES JOINED, because each was defensible alone while the composition was the defect.
    check(
      "the mutation variable over a tracked state git could not establish is refused rather than allowed to skip the grade",
      planInvocation(["--self-test"], true, selfTrackedState(notARepo, join(notARepo, "self.mjs"))).refuse !== undefined,
    );
  }

  // ---- 6. THE MODES CANNOT SUBSTITUTE FOR EACH OTHER ---------------------------------------------------
  // Pure, spawns nothing, and runs in a mutation subject too, so the two guards it defends are inside the
  // mutation harness's reach rather than behind the very condition that harness sets.
  checkArbitration(check);

  if (!AS_MUTANT) {
    runMutants(check, declare);
    runArbitrationCells(check, declare);
  }

  // THE COUNT IS CHECKED, NOT MERELY PRINTED. checks.length is read BEFORE this call is recorded, so the
  // one added is this check's own call site, which the floor counts along with every other.
  const floored = populationFloor(readFileSync(SELF_PATH, "utf8"), AS_MUTANT, declared);
  check(
    `the self-test ran its whole population: ${checks.length + 1} checks against a floor of ${floored.floor} derived from this file`,
    floored.problems.length === 0 && checks.length + 1 >= floored.floor,
    floored.problems.length > 0 ? `[${floored.problems.join("; ")}]` : "",
  );

  for (const d of beds) rmSync(d, { recursive: true, force: true });
  for (const c of checks) console.log(c);
  const total = checks.length;
  const failed = checks.filter((c) => c.startsWith("  FAIL")).length;
  console.log(pass ? `\nwriting-rules-source --self-test: ${total} of ${total} passed` : `\nwriting-rules-source --self-test: ${failed} of ${total} FAILED`);
  return pass;
}

// ---------------------------------------------------------------------------------------------------------

// THE DISPATCHER DECIDES NOTHING. planInvocation() reads the whole command line, the environment and the
// one fact about this process that an environment cannot fake, and returns the single job to do. What
// follows carries that job out. The arrangement is the fix: while each condition was tested on its own,
// down the file, a second flag could reach a branch the first flag had already answered for, and the run
// ended at exit 0 having graded nothing.
const SELF_TRACKED = selfTrackedState(REPO, SELF_PATH);
const PLAN = planInvocation(process.argv.slice(2), process.env.WRITING_RULES_MUTANT === "1", SELF_TRACKED);

// A child spawned as a mutation subject runs its fixture checks, skips the harness (or it would recurse
// without end) and never grades a real tree, because it is sitting in a temp directory that is not one.
const AS_MUTANT = PLAN.refuse === undefined && PLAN.mode === "self-test-only";

if (PLAN.refuse !== undefined) {
  console.error(`writing-rules-source: ${PLAN.refuse}`);
  process.exit(2);
}

// --self-test RUNS THE SELF-TEST AND THEN GRADES THE TREE, in one process, because that is the invocation
// CI actually makes. A self-test wired into a command nobody runs is the shape this workspace has been
// burned by repeatedly: the gate reads green and its teeth were never checked. Here the same line does both,
// and the self-test's own output lands in the same job log as the verdict.
if (PLAN.selfTest) {
  const passed = selfTest();
  // A MUTATION SUBJECT STOPS HERE, and this line is the difference between evidence and theatre. Without
  // it the child fell through to grading the temp directory it was written into, which is not a git
  // repository, so it exited 2. Every mutant then "reddened" whether or not the mutation had done anything,
  // and the control caught it only because the control expects an exact 0. The mutant checks expect an
  // exact 1 for the same reason: exit 2 is could-not-check, and a mutant that could not check has proved
  // nothing about the fix it was written to defend.
  if (AS_MUTANT) process.exit(passed ? 0 : 1);
  if (!passed) process.exit(1);
}

if (PLAN.mode === "print-subject") {
  // Used by test/validate-ci-path-shadow.ts, which must intersect CI's paths-ignore with the files this gate
  // really reads. It reads them from here rather than re-deriving them, so the two cannot drift apart.
  const { files } = readSubject(REPO, trackedFiles(REPO));
  if (files.length === 0) {
    console.error("writing-rules-source: --print-subject produced no files, so a caller would prove nothing.");
    process.exitCode = 2;
  } else {
    // NO EXPLICIT process.exit() ON THIS PATH ANY MORE, and that omission is the whole fix. This used to
    // be `for (const f of files) console.log(f); process.exit(0);`, and process.exit() is documented
    // (nodejs.org/api/process.html#processexitcode) to force termination "as quickly as possible even if
    // there are still asynchronous operations pending that have not yet completed fully, including... I/O
    // operations". A write to a PIPE -- exactly what this call is every time it matters, since
    // test/validate-ci-path-shadow.ts reads it through execFileSync's captured stdout, never a TTY -- is
    // one of those operations, and a payload this large (1718 lines) does not fit one pipe buffer.
    //
    // MEASURED, not theorised, and the first attempt at this fix (a single process.stdout.write() call
    // with exit moved into its completion callback) measured the actual mechanism: piped locally, the
    // write's callback fired, and the process exited, after exactly 65536 bytes had reached the pipe --
    // one 64KB kernel pipe buffer, byte for byte -- with the remainder silently gone. The callback answers
    // "did libuv hand this chunk to its write queue", not "has a slow reader on the other end finished
    // draining it", so a callback-gated exit() still races a pipe a slow reader has not caught up with.
    // Before that, in CI, the same shape (many console.log() calls, then exit()) measured the same class
    // of loss three separate times (engine CI runs eca99604, 5be5fbfc, 22bdbaf5): a different subset of
    // lines missing each time, always near 1676 of 1718, once precisely enough to name the three files it
    // dropped from one fixture directory while a fourth file in that SAME directory survived -- something
    // no per-file NUL/ENOENT classification fault can produce, but a write cut off partway through the
    // line list produces exactly. Neither shape is a defect in readSubject()'s classification (the
    // earlier investigation that cleared it, recorded in this file's own history, was looking in the right
    // file for the wrong bug); the defect is in how this call's OUTPUT leaves the process.
    //
    // Removing the explicit exit() is the fix precisely BECAUSE it stops racing the writes at all: Node's
    // normal shutdown (falling off the end of the event loop with no pending handles) does not terminate
    // until every pending write has actually drained, slow reader included, which is the property
    // process.exit() explicitly forfeits. process.exitCode records the intended code without forcing
    // early termination, and console.log's ordinary buffering (small per-line writes, not one payload
    // larger than a pipe buffer) means there is no single write left that could overrun one again.
    for (const f of files) console.log(f);
  }
} else {
  // EVERY REMAINING PATH READS THE TREE. There is no fourth branch and no fall-through, so a mode that
  // somehow reached here without being one of the two named above still gets graded rather than skipped.
  // Guarded with `else` now (it used to follow an unconditional process.exit() in the branch above, which
  // stopped execution just as reliably); print-subject no longer force-exits, so without this guard its
  // success path would fall through into a full grading run it was never meant to reach.
  const result = run({ repo: REPO, baselinePath: BASELINE_PATH, write: PLAN.mode === "write-baseline" });
  for (const l of result.lines) console.log(l);
  for (const l of result.errs) console.error(l);
  // process.exitCode, NOT process.exit(result.code): the same pipe-truncation hazard the print-subject
  // fix above measures and explains applies here too, and this path's own output can run past a pipe
  // buffer on a large violation report. Node drains every pending write before a natural exit; exit()
  // does not wait for it.
  process.exitCode = result.code;
}
