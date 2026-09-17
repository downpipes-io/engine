// The session-lifetime documentation must state what the code enforces, and cite it where it is.
//
// WHY THIS EXISTS. docs/security/identity-sessions-and-files.md is the auditor-facing answer to ASVS 5.0
// V7.1.1 (lifetime bounds documented, with the NIST SP 800-63B justification), V7.1.2 (concurrent-session
// policy), V7.1.3 (federated session coordination) and V7.6.1 (RP/IdP lifetime behaves as documented).
// Every number on that page is a copy of a constant in src/admin/session.ts, every "Deviation" verdict in
// its 800-63B table is a comparison against that constant, and every file:line beside a constant is a
// cache of where the declaration sits today. Each of those goes stale on its own: a constant can be
// retuned without the page learning it, a declaration can move ten lines when a comment above it grows,
// and the 800-63B verdict column would read "Deviation" for a bound that no longer deviates.
//
// Measured before this gate landed: the same document cited `session.ts:50` for SESSION_TTL_MS (a
// comment line; the declaration is `:53`), `:177` for the expiry check (a comment about HMAC; the check
// is `:334`), and `access.ts:165` for the Access exp check (accessDenySignal; the check is `:288`). All
// three resolved to a real line, so nothing that only checks "does the line exist" would have fired.
//
// WHAT IT ASSERTS, in three layers:
//   - VALUES. The §2.1a bounds table must carry, for each of the five constants, the cell this gate DERIVES
//     from the imported constant and from the constant's declaration line in session.ts. A retuned constant,
//     a moved declaration, or a page that quotes a different number all fail here.
//   - VERDICTS. The §2.1a 800-63B comparison table must carry the verdict this gate derives by comparing
//     the imported constant to the revision 4 figure (held here, because the standard fixes it). So a
//     2-hour idle bound must read "Deviation" beside the 1-hour AAL2 figure, and if the idle bound were
//     ever tightened under an hour the page would have to stop calling it a deviation.
//   - CITATIONS. Every `engine/<path>.ts:N` in the sections this gate owns (§2.1a, §2.7, and the four
//     V7 rows in §2.5) must land on a non-blank line, and where the page writes a symbol beside the
//     citation (`symbol`, `path:N`) the symbol must be ON that line. A comment mentioning it does not count.
//   - The rows and tokens the requirements literally ask for: a §2.5 row for each of V7.1.1, V7.1.2,
//     V7.1.3 and V7.6.1; "unlimited" and "never evicts" on the concurrency row; "SessionNotOnOrAfter" and
//     "single logout" in §2.7.
//
// SIBLING POSTURE. The customer-facing pages (docs/src/content/docs/identity-access/session-management.mdx
// and reference/api/sign-in-flows.mdx) carry the same numbers and the same two federation facts. They are
// graded when a docs checkout is found (DOWNPIPES_DOCS, or a sibling), and REFUSED (exit 2) when that
// checkout is behind its own origin/main, exactly as validate-posture-and-docs-parity.ts does. Absent docs,
// the in-repo checks still run and the pages are reported as not graded; --require turns that into a
// failure, which is the convention CI uses.
//
// Run with `node test/validate-docs-session-parity.ts [--require]`.
//
// House style: Australian English, no em dashes, no rule-of-three, no AI attribution.

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { reportSiblings } from "../scripts/lib/sibling-lag.mjs";
import { requireFreshSiblings } from "../scripts/sibling-freshness.mjs";
import { SESSION_IDLE_MS, SESSION_SLIDE_MS, SESSION_TTL_MS, STEPUP_FRESH_MS, STEPUP_TOKEN_TTL_MS } from "../src/admin/session.ts";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";

const HERE = fileURLToPath(new URL("..", import.meta.url));
const REQUIRE = process.argv.includes("--require");
const DOC = "docs/security/identity-sessions-and-files.md";
const SESSION_SRC = "src/admin/session.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const HOUR = 60 * 60 * 1000;
const MINUTE = 60 * 1000;

/** "12 hours", "1 hour", "15 minutes": the exact cell shape §2.1a uses. */
function human(ms: number): string {
  if (ms % HOUR === 0) {
    const h = ms / HOUR;
    return `${h} ${h === 1 ? "hour" : "hours"}`;
  }
  const m = ms / MINUTE;
  return `${m} ${m === 1 ? "minute" : "minutes"}`;
}

/** The text between a heading and the next heading of the same or higher level, or "" when absent. */
function section(text: string, heading: string, nextHeadings: string[]): string {
  const start = text.indexOf(heading);
  if (start < 0) return "";
  let end = text.length;
  for (const h of nextHeadings) {
    const i = text.indexOf(h, start + heading.length);
    if (i >= 0 && i < end) end = i;
  }
  return text.slice(start, end);
}

const doc = readFileSync(resolve(HERE, DOC), "utf8");
const sessionSrc = readFileSync(resolve(HERE, SESSION_SRC), "utf8").split("\n");

/** 1-based line of `export const NAME =` in session.ts, or null. The declaration, never a comment naming it. */
function declarationLine(name: string): number | null {
  const i = sessionSrc.findIndex((l) => l.startsWith(`export const ${name} =`));
  return i >= 0 ? i + 1 : null;
}

console.log("\n-- the session-lifetime doc states what session.ts enforces, and cites it where it is --\n");

const s21a = section(doc, "### 2.1a ", ["### 2.2 "]);
const s25 = section(doc, "### 2.5 ", ["### 2.6 "]);
const s27 = section(doc, "### 2.7 ", ["## 3. "]);
ok("§2.1a (lifetime policy and 800-63B alignment) exists", s21a.length > 0);
ok("§2.5 (ASVS V6/V7 mapping) exists", s25.length > 0);
ok("§2.7 (federated session coordination) exists", s27.length > 0);

// ---- VALUES: the five bounds, each derived from the constant and from where it is declared ----------------
const BOUNDS: Array<[string, number]> = [
  ["SESSION_TTL_MS", SESSION_TTL_MS],
  ["SESSION_IDLE_MS", SESSION_IDLE_MS],
  ["SESSION_SLIDE_MS", SESSION_SLIDE_MS],
  ["STEPUP_FRESH_MS", STEPUP_FRESH_MS],
  ["STEPUP_TOKEN_TTL_MS", STEPUP_TOKEN_TTL_MS],
];
for (const [name, ms] of BOUNDS) {
  const line = declarationLine(name);
  ok(`${name} is declared as an export const in ${SESSION_SRC}`, line !== null);
  if (line === null) continue;
  const cell = `| \`${name}\` (\`engine/src/admin/session.ts:${line}\`) | ${human(ms)} |`;
  ok(`§2.1a states ${name} as ${human(ms)} at session.ts:${line}`, s21a.includes(cell));
  if (!s21a.includes(cell)) console.log(`       expected cell: ${cell}`);
}

// ---- VERDICTS: the 800-63B revision 4 comparison, derived rather than transcribed -------------------------
// The figures are NIST SP 800-63B rev 4, §2.2.3 (AAL2) and §2.3.3 (AAL3), read from
// pages.nist.gov/800-63-4/sp800-63b.html. They are the standard's, so they are held here.
const NIST_ROWS: Array<{ row: string; figure: string; limitMs: number; bound: number }> = [
  { row: "AAL2 overall (2.2.3)", figure: "SHOULD be no more than 24 hours", limitMs: 24 * HOUR, bound: SESSION_TTL_MS },
  { row: "AAL2 inactivity (2.2.3)", figure: "SHOULD be no more than 1 hour", limitMs: 1 * HOUR, bound: SESSION_IDLE_MS },
  { row: "AAL3 overall (2.3.3)", figure: "SHALL be no more than 12 hours", limitMs: 12 * HOUR, bound: SESSION_TTL_MS },
  { row: "AAL3 inactivity (2.3.3)", figure: "SHOULD be no more than 15 minutes", limitMs: 15 * MINUTE, bound: SESSION_IDLE_MS },
];
let deviations = 0;
for (const r of NIST_ROWS) {
  const verdict = r.bound <= r.limitMs ? "Within the figure" : "Deviation";
  if (verdict === "Deviation") deviations++;
  const expected = `| ${r.row} | ${r.figure} | ${human(r.bound)} | ${verdict} |`;
  ok(`§2.1a compares ${r.row}: ${human(r.bound)} is "${verdict}"`, s21a.includes(expected));
  if (!s21a.includes(expected)) console.log(`       expected row: ${expected}`);
}
ok("§2.1a names NIST SP 800-63B and its revision", s21a.includes("NIST SP 800-63B") && s21a.includes("revision 4"));
ok(
  deviations > 0 ? "§2.1a carries a justification for the deviation it records" : "§2.1a records no deviation, so no justification is owed",
  deviations > 0 ? s21a.includes("**Justification for the inactivity deviation.**") : !s21a.includes("**Justification"),
);
ok("§2.1a states that the combination is judged appropriate", s21a.includes("is judged appropriate"));

// ---- CITATIONS: every file:line in the owned sections resolves, and a named symbol is ON its line ---------
const V7_ROWS = ["V7.1.1", "V7.1.2", "V7.1.3", "V7.6.1"];
const rowsOwned = V7_ROWS.map((id) => s25.split("\n").find((l) => l.startsWith(`| ${id} - `)) ?? "");
for (let i = 0; i < V7_ROWS.length; i++) ok(`§2.5 carries a row for ${V7_ROWS[i]}`, rowsOwned[i] !== "");
const owned = [s21a, s27, ...rowsOwned].join("\n");

// `engine/src/x.ts:12` and `engine/src/x.ts:12-15`, plus the short `:12` form that inherits the last path.
const CITE = /`(engine\/[A-Za-z0-9_./-]+\.ts):(\d+)(?:-(\d+))?`|(?<![\w/])`:(\d+)(?:-(\d+))?`/g;
let lastPath: string | null = null;
let citations = 0;
const sourceCache = new Map<string, string[] | null>();
function fileLines(rel: string): string[] | null {
  if (!sourceCache.has(rel)) {
    const p = resolve(HERE, rel.replace(/^engine\//, ""));
    sourceCache.set(rel, existsSync(p) ? readFileSync(p, "utf8").split("\n") : null);
  }
  return sourceCache.get(rel) ?? null;
}
const unresolved: string[] = [];
for (const m of owned.matchAll(CITE)) {
  let path: string | null;
  let from: number;
  let to: number;
  if (m[1] !== undefined) {
    path = m[1];
    lastPath = path;
    from = Number(m[2]);
    to = m[3] !== undefined ? Number(m[3]) : from;
  } else {
    path = lastPath;
    from = Number(m[4]);
    to = m[5] !== undefined ? Number(m[5]) : from;
  }
  if (path === null) continue;
  citations++;
  const lines = fileLines(path);
  if (lines === null) {
    unresolved.push(`${path}:${from} (file missing)`);
    continue;
  }
  for (let n = from; n <= to; n++) {
    const text = lines[n - 1];
    if (text === undefined || text.trim() === "" || /^[\s{}();,]*$/.test(text)) unresolved.push(`${path}:${n} (blank, past EOF, or lone punctuation)`);
  }
}
ok(`every engine citation in the owned sections lands on a real line (${citations} citations)`, citations > 0 && unresolved.length === 0);
for (const u of unresolved) console.log(`       unresolved: ${u}`);

// A symbol written beside a citation must be on the cited line: (`symbol`, `path:N`) and `symbol`, `path:N`.
const SYMBOL_CITE = /`([A-Za-z_][A-Za-z0-9_]*)`,? \(?`(engine\/[A-Za-z0-9_./-]+\.ts):(\d+)/g;
const misplaced: string[] = [];
let symbolCitations = 0;
for (const m of owned.matchAll(SYMBOL_CITE)) {
  const [, symbol, path, lineStr] = m as unknown as [string, string, string, string];
  const lines = fileLines(path);
  symbolCitations++;
  const text = lines?.[Number(lineStr) - 1] ?? "";
  // Strip a trailing line comment so a comment that merely mentions the symbol cannot satisfy this.
  const code = text.replace(/\/\/.*$/, "");
  if (!code.includes(symbol)) misplaced.push(`${symbol} is not on ${path}:${lineStr}`);
}
ok(`every symbol written beside a citation is on that line (${symbolCitations} pairs)`, symbolCitations > 0 && misplaced.length === 0);
for (const s of misplaced) console.log(`       misplaced: ${s}`);

// ---- The literal clauses the requirements ask for -----------------------------------------------------------
const rowV712 = rowsOwned[1] ?? "";
ok("the V7.1.2 row states the allowed count (unlimited)", rowV712.includes("Allowed: unlimited"));
ok("the V7.1.2 row states the maximum-reached behaviour (none, never evicts)", rowV712.includes("never evicts an existing session"));
ok("the V7.1.3 row points at §2.7", (rowsOwned[2] ?? "").includes("§2.7"));
ok("§2.7 names the SAML SessionNotOnOrAfter bound", s27.includes("SessionNotOnOrAfter"));
ok("§2.7 states the single-logout position", s27.includes("single logout"));
ok(`§2.7 states the ${human(SESSION_TTL_MS)} cap and the ${human(SESSION_IDLE_MS)} idle bound`, s27.includes(`${SESSION_TTL_MS / HOUR}-hour cap`) && s27.includes(`${SESSION_IDLE_MS / HOUR}-hour idle bound`));
ok(`§2.7 states the ${human(STEPUP_FRESH_MS)} step-up figure`, s27.includes(`(${human(STEPUP_FRESH_MS)})`));

// ---- The customer-facing pages, when a docs checkout is beside this engine ---------------------------------
const PAGE = "src/content/docs/identity-access/session-management.mdx";
const FLOWS_PAGE = "src/content/docs/reference/api/sign-in-flows.mdx";
const docsRoot = [
  process.env.DOWNPIPES_DOCS,
  resolve(HERE, "../docs"),
  resolve(HERE, "../../docs"),
  resolve(HERE, "../../../docs"),
  resolve(HERE, "../../../../docs"),
]
  .filter((p): p is string => typeof p === "string" && p !== "")
  .find((c) => existsSync(resolve(c, PAGE)));

if (docsRoot === undefined) {
  if (REQUIRE) {
    ok(`--require was passed and ${PAGE} was not found in any candidate docs checkout`, false);
  } else {
    console.log(`  note docs pages NOT graded: no docs checkout beside this engine (set DOWNPIPES_DOCS, or pass --require to fail instead)`);
  }
} else {
  reportSiblings([{ name: "docs", path: docsRoot }], { gate: "docs-session-parity" });
  requireFreshSiblings([{ name: "docs", path: docsRoot }], {
    gate: "docs-session-parity",
    consequence: "its findings about the customer pages would describe an older docs tree than the one that ships",
    exit: (code: number) => {
      verdictSkipped(`REFUSED, exit ${code}: the docs checkout beside this engine is behind its own origin/main, so nothing was concluded`);
      process.exit(code);
    },
  });
  const WORDS: Record<number, string> = { 1: "one", 2: "two", 3: "three", 4: "four", 6: "six", 8: "eight", 12: "twelve", 24: "twenty-four" };
  const page = readFileSync(resolve(docsRoot, PAGE), "utf8");
  const ttlWord = WORDS[SESSION_TTL_MS / HOUR];
  const idleWord = WORDS[SESSION_IDLE_MS / HOUR];
  ok("session-management.mdx states the absolute cap in words", ttlWord !== undefined && page.includes(`${ttlWord}-hour absolute cap`));
  ok("session-management.mdx states the idle timeout in words", idleWord !== undefined && page.includes(`${idleWord}-hour idle timeout`));
  ok("session-management.mdx names NIST SP 800-63B and the inactivity deviation", page.includes("NIST SP 800-63B") && page.includes("deviation"));
  ok('session-management.mdx has a "## Concurrent sessions" section', page.includes("## Concurrent sessions"));
  ok("session-management.mdx states that a new sign-in never evicts an existing session", page.includes("never evicts an existing session"));
  ok("session-management.mdx states the SAML SessionNotOnOrAfter cap", page.includes("SessionNotOnOrAfter"));
  ok("session-management.mdx states that there is no single logout", page.includes("no single logout"));
  const flows = readFileSync(resolve(docsRoot, FLOWS_PAGE), "utf8");
  const lifetimeRow = flows.split("\n").find((l) => l.startsWith("| Lifetime |")) ?? "";
  ok("sign-in-flows.mdx lifetime row names SessionNotOnOrAfter and the OIDC non-cap", lifetimeRow.includes("SessionNotOnOrAfter") && lifetimeRow.includes("OIDC"));
  ok("sign-in-flows.mdx carries a Concurrent sessions row", flows.split("\n").some((l) => l.startsWith("| Concurrent sessions |")));
}

console.log(`\n${failures === 0 ? "DOCS-SESSION-PARITY PASS" : `DOCS-SESSION-PARITY: ${failures} FAILED`}\n`);
verdictReached(failures, checks);
process.exit(failures === 0 ? 0 : 1);
