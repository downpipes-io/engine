// The input-validation and limits document cites the code, and the code moves. This gate keeps the two in
// agreement.
//
// WHAT IT GRADES. docs/security/input-validation-and-limits.md is the ASVS V2.1.1 and V2.1.3 reference for
// every rule that reaches the engine without a console field. Each rule there carries a citation of the form
// `symbol` at `path:line` (or `path:first-last`), and each limit carries `NAME` = `value` at `path:line`.
// The document says so in its own "How to read a citation" section, and that grammar is the contract this
// file enforces:
//
//   1. the cited path exists under the engine root and the cited line is inside the file;
//   2. the pinned symbol is on the cited line, in CODE, not in a comment on that line. A comment that names
//      the identifier is not the control, so a trailing // comment is cut before the match, and a line that
//      is wholly a comment matches nothing;
//   3. a value citation's literal is on the cited line beside the symbol, so a retuned constant reddens the
//      sentence that quotes the old number;
//   4. every backtick token shaped like a path:line is part of a pinned citation. A bare `path:line` with no
//      symbol in front of it is a citation nothing can check, so it is refused rather than skipped;
//   5. every limit constant declared in src/ whose name matches the limit patterns below is named in the
//      document, so a new per-user or account-global ceiling cannot land undocumented. The patterns cover
//      every rate limiter (exported or not: the ingest pull cap is module-private), the bulk-create caps, and
//      the named retention caps, TTLs and leases the document tables.
//
// WHY LINE NUMBERS ARE GRADED STRICTLY HERE. The field catalogue's verifier treats a moved-but-intact pin as
// current and prints the corrected line. That leniency exists because the catalogue is graded from three
// repositories at different tips. This document lives in the same repository as the code it cites, lands in
// the same commit, and has no cross-repo cycle to break, so a stale line number is a defect the author can
// fix in the same change. Tolerance is zero: the document is the pin.
//
// WHAT A RED LOOKS LIKE. Measured on the document this gate landed with, four plants, each restored after:
// `src/sched/scheduler-do.ts:1658` for validateConfig (a citation into a 960-line file) fails check 1 naming
// the file's length; RING_CAP re-cited one line down fails check 2 with the empty line it landed on; a
// sentence claiming `source.type must be kv/r2/secrets/d1` at config-validate.ts:355 fails check 2 printing
// the template the line really carries; renaming every mention of BULK_DOWNPIPES_MAX_GATED fails check 5
// naming the constant and its declaration line.
//
// Run with `node test/validate-limits-doc-citations.ts`.
//
// House style: Australian English, no em dashes, no rule-of-three.

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verdictReached } from "./lib/verdict-guard.ts";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const DOC = "docs/security/input-validation-and-limits.md";

// MIN_CITATIONS is the anti-vacuity floor: a document that somehow parsed to fewer pinned citations than
// this has lost its citations, not passed them. The document carries several hundred; the floor is set
// well under that so an honest edit never trips it, and well above zero so an emptied file cannot pass.
const MIN_CITATIONS = 150;

// LIMIT_NAME_PATTERNS is the completeness set (check 5). A constant is in scope when its name matches one
// of these AND its declaration line assigns a numeric literal or a numeric product.
const LIMIT_NAME_PATTERNS: RegExp[] = [
  /_MAX_PER_(WINDOW|IP|EMAIL)$/,
  /^BULK_DOWNPIPES_MAX/,
  /^(RING|AUDIT|DRILL_EVIDENCE|CONFIG_HISTORY|SAMPLE)_CAP$/,
  /^FLEET_DRILL_MAX$/,
  /^(APPROVAL|PRUNE_APPROVAL)_TTL_MS$/,
  /^(INFLIGHT|RUNLOG)_LEASE_MS$/,
  /^MAX_IN_ACCOUNT_RESTORE_RECORDS$/,
  /^(GROUPS_MAX|GROUP_NAME_MAX|REASON_MAX_LEN|NOTE_MAX_LEN|CHANGE_NUMBER_MAX|CHANGE_REASON_MAX|STS_DURATION_MAX|AUDIT_PAGE_MAX)$/,
];

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

/** codePart cuts a trailing // comment that sits outside every quoted string on the line. */
function codePart(line: string): string {
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (quote !== null) {
      if (ch === "\\") {
        i++;
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      continue;
    }
    if (ch === "/" && line[i + 1] === "/") return line.slice(0, i);
  }
  return line;
}

/** isWholeComment is true for a line that is only a // or /* or * comment. */
function isWholeComment(line: string): boolean {
  const t = line.trim();
  return t.startsWith("//") || t.startsWith("/*") || t.startsWith("*");
}

const docPath = resolve(ROOT, DOC);
if (!existsSync(docPath)) {
  console.error(`FAIL limits-doc-citations: ${DOC} is missing, so there is nothing to grade.`);
  verdictReached(1, 1);
  process.exit(1);
}
const doc = readFileSync(docPath, "utf8");

const fileCache = new Map<string, string[] | null>();
function linesOf(rel: string): string[] | null {
  if (fileCache.has(rel)) return fileCache.get(rel)!;
  const abs = resolve(ROOT, rel);
  const lines = existsSync(abs) && statSync(abs).isFile() ? readFileSync(abs, "utf8").split("\n") : null;
  fileCache.set(rel, lines);
  return lines;
}

console.log(`\n-- ${DOC}: every citation lands on the symbol it names --\n`);

// A pinned citation: `pin` at `path:line` or `path:first-last`. A value citation: `NAME` = `value` at
// `path:line`. The document wraps at 100 columns, so the pin, the word "at" and the target may sit on two
// lines; the whitespace between them is matched across a line break, and the reported line is the line the
// target sits on.
const CITATION = /`([^`]+)`\s+at\s+`((?:src|test|scripts|lib)\/[^`\s:]+):(\d+)(?:-(\d+))?`/g;
const VALUE_BEFORE = /`([A-Za-z_][A-Za-z0-9_]*)`\s+=\s*$/;
// Any backtick token shaped like a citation target, pinned or not (check 4).
const TARGET = /`((?:src|test|scripts|lib)\/[^`\s:]+):(\d+)(?:-(\d+))?`/g;

const lineStarts: number[] = [0];
for (let i = 0; i < doc.length; i++) if (doc[i] === "\n") lineStarts.push(i + 1);
function lineAt(index: number): number {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineStarts[mid]! <= index) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

let citations = 0;
let valueCitations = 0;
const badLines: string[] = [];
const pinnedSpans: Array<[number, number]> = [];

for (const m of doc.matchAll(CITATION)) {
  citations++;
  const pin = m[1]!;
  const rel = m[2]!;
  const first = Number(m[3]);
  const last = m[4] !== undefined ? Number(m[4]) : first;
  const start = m.index!;
  const end = start + m[0].length;
  const docLine = lineAt(end - 1);
  pinnedSpans.push([start, end]);
  const lines = linesOf(rel);
  if (lines === null) {
    badLines.push(`doc:${docLine} cites ${rel}, which is not a file under the engine root`);
    continue;
  }
  if (first < 1 || last < first || last > lines.length) {
    badLines.push(`doc:${docLine} cites ${rel}:${first}${last !== first ? `-${last}` : ""}, outside the file's ${lines.length} lines`);
    continue;
  }
  const code = lines
    .slice(first - 1, last)
    .map((l) => (isWholeComment(l) ? "" : codePart(l)))
    .join("\n");
  if (!code.includes(pin)) {
    badLines.push(`doc:${docLine} pins \`${pin}\` to ${rel}:${first}${last !== first ? `-${last}` : ""}, and the cited code does not carry it (cited line: ${lines[first - 1]!.trim()})`);
    continue;
  }
  // A value citation: the text just before this citation reads `NAME` =, and the pin the CITATION regex
  // already captured (the backtick token right before " at ") is the value itself. The value must be on the
  // cited line too, so a retuned constant reddens the document that still quotes the old number.
  const before = doc.slice(Math.max(0, start - 200), start).replace(/\s+/g, " ").trimEnd();
  const v = VALUE_BEFORE.exec(before);
  if (v !== null) {
    valueCitations++;
    const name = v[1]!;
    const value = pin;
    const squash = (s: string) => s.replace(/\s+/g, "");
    if (!squash(code).includes(squash(value))) {
      badLines.push(`doc:${docLine} states \`${name}\` = \`${value}\`, and ${rel}:${first} reads: ${lines[first - 1]!.trim()}`);
    }
  }
}
// Check 4: an unpinned target.
for (const t of doc.matchAll(TARGET)) {
  const s = t.index!;
  const e = s + t[0].length;
  const covered = pinnedSpans.some(([a, b]) => s >= a && e <= b);
  if (!covered) badLines.push(`doc:${lineAt(s)} carries the bare citation ${t[0]} with no \`symbol\` at in front of it, so nothing pins it`);
}

ok(`the document carries at least ${MIN_CITATIONS} pinned citations (${citations} found, ${valueCitations} of them value citations)`, citations >= MIN_CITATIONS);
ok(`every pinned citation lands on its symbol and every value citation on its literal (${badLines.length} bad)`, badLines.length === 0);
for (const b of badLines) console.log(`       ${b}`);

console.log(`\n-- every limit constant in src/ is named in the document --\n`);

function walk(dir: string, out: string[]): void {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (p.endsWith(".ts") && !p.endsWith(".d.ts")) out.push(p);
  }
}
const srcFiles: string[] = [];
walk(resolve(ROOT, "src"), srcFiles);
ok(`src/ holds TypeScript files to scan (${srcFiles.length})`, srcFiles.length > 0);

const DECL = /^(?:export )?const ([A-Z][A-Z0-9_]*)\s*=\s*([0-9][0-9_]*(?:\s*\*\s*[0-9][0-9_]*)*)\s*;/;
const declared: Array<{ name: string; where: string }> = [];
for (const f of srcFiles) {
  const lines = readFileSync(f, "utf8").split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = DECL.exec(lines[i]!);
    if (m === null) continue;
    const name = m[1]!;
    if (LIMIT_NAME_PATTERNS.some((re) => re.test(name))) declared.push({ name, where: `${f.slice(ROOT.length)}:${i + 1}` });
  }
}
ok(`the completeness scan found limit constants to check (${declared.length})`, declared.length > 0);
// CONTROL: the scan sees the module-private ingest cap, the one the exported-only pattern would miss.
ok("CONTROL: the scan reaches a module-private limit (INGEST_PULL_RATE_LIMIT_MAX_PER_WINDOW)", declared.some((d) => d.name === "INGEST_PULL_RATE_LIMIT_MAX_PER_WINDOW"));
ok("CONTROL: the scan reaches the per-email recovery cap (RECOVERY_RATE_MAX_PER_EMAIL)", declared.some((d) => d.name === "RECOVERY_RATE_MAX_PER_EMAIL"));

const missing = declared.filter((d) => !doc.includes(`\`${d.name}\``));
ok(`every limit constant is named in the document (${declared.length - missing.length} of ${declared.length})`, missing.length === 0);
for (const m of missing) console.log(`       undocumented: ${m.name} declared at ${m.where}`);

console.log(failures === 0 ? "\nLIMITS-DOC-CITATIONS PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures, checks);
if (failures > 0) process.exit(1);
