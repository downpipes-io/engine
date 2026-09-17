// The contextual-controls documentation (ASVS V8.1.3, V8.1.4) must agree with the code it describes.
//
// WHY THIS EXISTS. docs/security/identity-sessions-and-files.md section 2.6 defines every environmental and
// contextual attribute the engine uses in a security decision, with its threshold and its action, and
// docs/security/input-validation-and-limits.md section 17 is the limiter reference. Both are auditor-facing,
// and a document nothing reads against the tree drifts: a sentence can deny a limiter the code keys on, and
// a line citation can outlive the code it pointed at. This gate reads both documents against the tree.
//
// WHAT IT ASSERTS:
//   - section 17 carries neither of the two sentences that would deny the source IP as a limiter key;
//   - every `file:line` citation in section 2.6 and section 17 names a file that exists, a line inside it,
//     and a line (or range) on which one of the identifiers named beside the citation appears;
//   - a citation with no line number names a file that contains one of the identifiers named beside it;
//   - section 2.6 names every IP-keyed limiter namespace the source uses (derived from the source, not listed
//     here) and the sign-in-context policy flag;
//   - each threshold in the contextual decision table renders the code's constant, and every STEPUP_SUBS route
//     is listed, with the stated count equal to the set's size;
//   - section 17 states each rate constant with the code's value;
//   - the ASVS mapping table carries a V8.1.3 row and a V8.1.4 row, both pointing at section 2.6.
//
// Both documents live in this repo, so there is no sibling checkout to find and no skip path.
//
// Run with `node test/validate-contextual-authz-docs-parity.ts`.
//
// House style: Australian English, no em dashes, no AI attribution.

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { STEPUP_SUBS } from "../src/admin/router-core.ts";
import { SESSION_IDLE_MS, SESSION_TTL_MS, STEPUP_FRESH_MS, STEPUP_TOKEN_TTL_MS } from "../src/admin/session.ts";
import { SEEN_CONTEXT_CAP, SEEN_CONTEXT_TTL_MS } from "../src/admin/sign-in-context.ts";
import {
  ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW,
  AUTH_RATE_LIMIT_MAX_PER_WINDOW,
  RATE_LIMIT_MAX_PER_WINDOW,
  RATE_LIMIT_WINDOW_MS,
  RECOVERY_RATE_MAX_PER_EMAIL,
  RECOVERY_RATE_MAX_PER_IP,
  RECOVERY_RATE_WINDOW_MS,
} from "../src/sched/scheduler-do-limits.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

const HERE = fileURLToPath(new URL("..", import.meta.url));
const IDENTITY_DOC = "docs/security/identity-sessions-and-files.md";
const LIMITS_DOC = "docs/security/input-validation-and-limits.md";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const identityDoc = readFileSync(resolve(HERE, IDENTITY_DOC), "utf8");
const limitsDoc = readFileSync(resolve(HERE, LIMITS_DOC), "utf8");

// A section runs from its heading to the next heading of the same or a higher level.
function section(doc: string, headingPrefix: string, stopAt: RegExp): string {
  const start = doc.indexOf(headingPrefix);
  if (start < 0) return "";
  const rest = doc.slice(start + headingPrefix.length);
  const m = stopAt.exec(rest);
  return headingPrefix + (m === null ? rest : rest.slice(0, m.index));
}

const s26 = section(identityDoc, "### 2.6 ", /\n(###? |---)/);
const s17 = section(limitsDoc, "## 17. ", /\n## (?!17)/);
const mapping = section(identityDoc, "## 4. ASVS mapping summary", /\n## /);

console.log("\n-- the contradictions section 17 used to carry are gone --\n");
ok("section 17 does not say the bucket is keyed never on the source IP", !limitsDoc.includes("never the source IP"));
ok("section 17 does not say a per-IP limiter is explicitly avoided", !limitsDoc.includes("per-IP limiter is explicitly avoided"));

console.log("\n-- every citation in section 2.6 and section 17 resolves in this tree --\n");

// A citation is a backticked path into src/, with an optional :line or :line-line. The engine doc writes
// `engine/src/...`; the limits doc writes `src/...`. Both resolve against this repo.
const CITATION = /`(?:engine\/)?(src\/[A-Za-z0-9_./-]+\.ts)(?::(\d+)(?:-(\d+))?)?`/g;
// The identifiers beside a citation are the other backticked spans in the same unit: a table row is its own
// unit, and a paragraph or bullet is one unit up to the next blank line.
function units(text: string): string[] {
  const out: string[] = [];
  let para: string[] = [];
  const flush = (): void => {
    if (para.length > 0) out.push(para.join("\n"));
    para = [];
  };
  for (const line of text.split("\n")) {
    if (line.startsWith("|")) {
      flush();
      out.push(line);
    } else if (line.trim() === "") {
      flush();
    } else {
      para.push(line);
    }
  }
  flush();
  return out;
}

const fileCache = new Map<string, string[] | null>();
function fileLines(rel: string): string[] | null {
  const cached = fileCache.get(rel);
  if (cached !== undefined) return cached;
  const abs = resolve(HERE, rel);
  const lines = existsSync(abs) ? readFileSync(abs, "utf8").split("\n") : null;
  fileCache.set(rel, lines);
  return lines;
}

// Identifier spans: a backticked token of at least four characters that is not itself a path into the
// tree and not a bare number. Four is the floor because a three-character span such as `exp` sits inside
// `export` on almost every constant line, which would make the check vacuous.
function identifiersBeside(unit: string, citationSpan: string): string[] {
  const out: string[] = [];
  for (const m of unit.matchAll(/`([^`\n]+)`/g)) {
    const span = m[0];
    const body = m[1] as string;
    if (span === citationSpan) continue;
    if (/(?:^|\/)(?:src|test|docs)\//.test(body)) continue;
    if (body.length < 4) continue;
    if (/^[\d.:-]+$/.test(body)) continue;
    out.push(body);
  }
  return out;
}

function checkCitations(label: string, text: string): void {
  let seen = 0;
  for (const unit of units(text)) {
    for (const m of unit.matchAll(CITATION)) {
      seen++;
      const rel = m[1] as string;
      const from = m[2] === undefined ? null : Number(m[2]);
      const to = m[3] === undefined ? from : Number(m[3]);
      const lines = fileLines(rel);
      if (lines === null) {
        ok(`${label}: ${m[0]} names a file that exists`, false);
        continue;
      }
      const idents = identifiersBeside(unit, m[0]);
      if (from === null) {
        const whole = lines.join("\n");
        const hit = idents.find((id) => whole.includes(id));
        ok(`${label}: ${m[0]} contains one of [${idents.join(", ")}]`, hit !== undefined);
        continue;
      }
      if (to === null || from < 1 || to > lines.length || to < from) {
        ok(`${label}: ${m[0]} is inside the file (${lines.length} lines)`, false);
        continue;
      }
      const cited = lines.slice(from - 1, to).join("\n");
      const hit = idents.find((id) => cited.includes(id));
      ok(`${label}: ${m[0]} carries one of [${idents.join(", ")}] on the cited line(s)`, hit !== undefined);
    }
  }
  ok(`${label}: the section carries citations to check (${seen})`, seen > 0);
}

checkCitations("2.6", s26);
checkCitations("17", s17);

console.log("\n-- section 2.6 names every IP-keyed namespace the source uses --\n");

function walk(dir: string, out: string[]): void {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (p.endsWith(".ts")) out.push(p);
  }
}
const srcFiles: string[] = [];
walk(resolve(HERE, "src"), srcFiles);
const ipNamespaces = new Set<string>();
for (const f of srcFiles) {
  for (const m of readFileSync(f, "utf8").matchAll(/`([a-z-]*ip):\$\{/g)) ipNamespaces.add(`${m[1]}:`);
}
ok(`the source keys at least two IP namespaces (${[...ipNamespaces].join(", ")})`, ipNamespaces.size >= 2);
for (const ns of ipNamespaces) ok(`section 2.6 names the \`${ns}\` namespace`, s26.includes(`\`${ns}\``));
ok("section 2.6 names the `recovery-rate:` namespace", s26.includes("`recovery-rate:`"));
ok("section 2.6 names the `sub:` per-caller namespace", s26.includes("`sub:`"));
ok("section 2.6 names the notifyNewSignInContext policy flag", s26.includes("`notifyNewSignInContext`"));

console.log("\n-- the contextual decision table renders the code's thresholds --\n");

// Durations render the way the table writes them: whole hours as "12 h", whole minutes as "5 min", whole days
// as "90 days", otherwise seconds.
function duration(ms: number): string {
  if (ms % 86_400_000 === 0) return `${ms / 86_400_000} days`;
  if (ms % 3_600_000 === 0) return `${ms / 3_600_000} h`;
  if (ms % 60_000 === 0) return `${ms / 60_000} min`;
  return `${ms / 1000} s`;
}
function rate(max: number, windowMs: number): string {
  return `${max} per ${windowMs / 1000} s`;
}

const rows = s26.split("\n").filter((l) => l.startsWith("|"));
function row(key: string): string | null {
  return rows.find((r) => (r.split("|")[1] ?? "").toLowerCase().includes(key.toLowerCase())) ?? null;
}
function expectRow(key: string, needles: string[]): void {
  const r = row(key);
  ok(`table row "${key}" exists`, r !== null);
  if (r === null) return;
  for (const n of needles) ok(`row "${key}" states ${JSON.stringify(n)}`, r.includes(n));
}

expectRow("Session absolute age", [duration(SESSION_TTL_MS), "SESSION_TTL_MS"]);
expectRow("Session inactivity", [duration(SESSION_IDLE_MS), "SESSION_IDLE_MS"]);
expectRow("Action sensitivity", [
  duration(STEPUP_FRESH_MS),
  "STEPUP_FRESH_MS",
  duration(STEPUP_TOKEN_TTL_MS),
  "STEPUP_TOKEN_TTL_MS",
  "STEPUP_SUBS",
  `${STEPUP_SUBS.size} routes`,
  "stepUpRequired",
]);
expectRow("Source IP on the sign-in ceremonies", [rate(AUTH_RATE_LIMIT_MAX_PER_WINDOW, RATE_LIMIT_WINDOW_MS), "AUTH_RATE_LIMIT_MAX_PER_WINDOW", "429"]);
expectRow("Source IP and target email on the recovery-code sign-in", [
  `${RECOVERY_RATE_MAX_PER_IP} per ${RECOVERY_RATE_WINDOW_MS / 1000} s per IP`,
  `${RECOVERY_RATE_MAX_PER_EMAIL} per ${RECOVERY_RATE_WINDOW_MS / 1000} s per email`,
  "RECOVERY_RATE_MAX_PER_IP",
  "RECOVERY_RATE_MAX_PER_EMAIL",
]);
expectRow("Source IP on the break-glass bearer", [rate(ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW, RATE_LIMIT_WINDOW_MS), "ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW", "429"]);
expectRow("Verified caller identity on a mutating route", [rate(RATE_LIMIT_MAX_PER_WINDOW, RATE_LIMIT_WINDOW_MS), "RATE_LIMIT_MAX_PER_WINDOW", "429", "fail open"]);
expectRow("Request Origin on a mutating cookie-session request", ["CONSOLE_ORIGIN", "403"]);
expectRow("Absent `CF-Connecting-IP`", ["allow"]);
expectRow("Source IP prefix on a proven sign-in", [duration(SEEN_CONTEXT_TTL_MS), `${SEEN_CONTEXT_CAP} prefixes`, "/24", "/48", "notify"]);

const missingRoutes = [...STEPUP_SUBS].filter((r) => !s26.includes(`\`${r}\``));
ok(`every STEPUP_SUBS route is listed in section 2.6 (${STEPUP_SUBS.size} routes)`, missingRoutes.length === 0);
if (missingRoutes.length > 0) console.log(`       missing: ${missingRoutes.join(", ")}`);
// The reverse: a route listed as step-up gated that the set does not hold would send a reviewer to a gate
// that does not exist. Only backticked absolute routes inside the step-up list paragraph are considered.
const stepUpList = section(s26, "The step-up gated routes", /\n\n/);
const listed = [...stepUpList.matchAll(/`(\/[A-Za-z0-9/_-]+)`/g)].map((m) => m[1] as string);
const phantom = listed.filter((r) => !STEPUP_SUBS.has(r));
ok("the step-up list names no route STEPUP_SUBS does not hold", listed.length > 0 && phantom.length === 0);
if (phantom.length > 0) console.log(`       listed but not gated: ${phantom.join(", ")}`);

console.log("\n-- section 17 states each rate constant with the code's value --\n");

const constants: Array<[string, number | string]> = [
  ["RATE_LIMIT_MAX_PER_WINDOW", RATE_LIMIT_MAX_PER_WINDOW],
  ["RATE_LIMIT_WINDOW_MS", "60_000"],
  ["AUTH_RATE_LIMIT_MAX_PER_WINDOW", AUTH_RATE_LIMIT_MAX_PER_WINDOW],
  ["ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW", ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW],
  ["RECOVERY_RATE_WINDOW_MS", "60_000"],
  ["RECOVERY_RATE_MAX_PER_IP", RECOVERY_RATE_MAX_PER_IP],
  ["RECOVERY_RATE_MAX_PER_EMAIL", RECOVERY_RATE_MAX_PER_EMAIL],
];
ok("the window constants render as 60_000 (the code's literal)", RATE_LIMIT_WINDOW_MS === 60_000 && RECOVERY_RATE_WINDOW_MS === 60_000);
// The doc states each constant as `NAME` = `VALUE` (both sides backtick-wrapped, section 17's house
// style throughout). The backtick is not whitespace, so a bare \s*=\s* between the two identifiers
// never matches the doc's own rendering; each side's backtick is optional here so the check still
// passes a citation written without one.
for (const [name, value] of constants) {
  ok(`section 17 states ${name} = ${value}`, new RegExp(`${name}\`?\\s*=\\s*\`?${value}\\b`).test(s17));
}
ok("section 17 cross-references section 2.6 of the identity document", s17.includes("identity-sessions-and-files.md") && s17.includes("2.6"));
ok("section 17 names the fail posture of each limiter", s17.includes("Fail posture per surface"));

console.log("\n-- the ASVS mapping table points V8.1.3 and V8.1.4 at section 2.6 --\n");
for (const id of ["V8.1.3", "V8.1.4", "V8.2.4"]) {
  const r = mapping.split("\n").find((l) => l.startsWith(`| ${id} `));
  ok(`mapping row ${id} exists and cites 2.6`, r?.includes("| 2.6 |") === true);
}
ok("section 2.6's heading names V8.1.3, V8.1.4 and V8.2.4", /### 2\.6 .*V8\.1\.3.*V8\.1\.4.*V8\.2\.4/.test(s26));

console.log(`\n${failures === 0 ? "CONTEXTUAL-AUTHZ-DOCS-PARITY PASS" : `CONTEXTUAL-AUTHZ-DOCS-PARITY: ${failures} FAILED`} (${checks} checks)\n`);
verdictReached(failures, checks);
process.exit(failures === 0 ? 0 : 1);
