// The file-handling policy (docs/security/file-handling.md) stays in agreement with the trees it cites.
//
// WHY THIS EXISTS. ASVS V5.1.1 asks for DOCUMENTATION: the permitted types, extensions and maximum sizes
// (including the unpacked size) for each file-accepting feature, and how a file is made safe to download and
// process. A document like that rots in two ways nothing else in this repo notices. A ceiling it quotes can
// stop matching the constant in the code, and a console file picker can be added or moved without the policy
// naming it. Both leave a policy that reads well and describes a product that no longer exists.
//
// WHAT IS GRADED, in three parts:
//
//   1. Every `repo/path:line` citation in the document resolves to a non-blank line in the named tree. A
//      citation that lands on a blank line or past the end of the file is INERT, and inert citations are the
//      class the field catalogue's own gate learned to refuse.
//
//   2. The ceilings table. Each row names a constant and a value; the cited line must hold that constant, and
//      the literal on it must evaluate to the value in the table. The evaluator accepts the shapes the
//      constants take (`64 * 1024`, `200_000_000`, `1 << 20`, `2 << 30`) and nothing else. A derived row
//      (`maxDecompressedBytes`) must equal the product of the two rows it is derived from.
//
//   3. Every `"control":"file"` row in internal-docs' field catalogue must be cited in the document at the
//      line where the console declares that control, and the console line cited must hold the declaration
//      text the catalogue pins for that row. That ties the document to the console tree and to the catalogue
//      by CONTENT, so a stale line number in either cannot pass as agreement.
//
// SIBLING POSTURE matches validate-console-route-parity.ts: the engine's own citations are always graded;
// a sibling (console, downpipe, control-plane, internal-docs) is graded when it can be found and its
// checks are SKIPPED with a note when it cannot, so a single-repo checkout stays buildable. Under --require
// an absent sibling is a failure. A sibling that is behind its own origin/main is refused (exit 2) rather
// than graded, through the shared sibling-freshness helper, with its escape hatch.
//
// Run with `node test/validate-file-handling-doc.ts [--require]`. Overrides: DOWNPIPES_CONSOLE_ROOT,
// DOWNPIPES_DOWNPIPE_ROOT, DOWNPIPES_CONTROL_PLANE_ROOT, DOWNPIPES_INTERNAL_DOCS_ROOT.
//
// House style: Australian English, no em dashes, no rule-of-three.

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";
import { requireFreshSiblings } from "../scripts/sibling-freshness.mjs";
import { reportSiblings } from "../scripts/lib/sibling-lag.mjs";

const HERE = fileURLToPath(new URL("..", import.meta.url));
const REQUIRE = process.argv.includes("--require");
const DOC = "docs/security/file-handling.md";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- sibling resolution -----------------------------------------------------------------------------------
type Repo = "engine" | "console" | "downpipe" | "control-plane" | "internal-docs";
const MARKERS: Record<Exclude<Repo, "engine">, string> = {
  console: "src/lib/keydecap.ts",
  downpipe: "cmd/downpipe/main.go",
  "control-plane": "src/http.ts",
  "internal-docs": "FIELD-CATALOGUE/catalogue.jsonl",
};
const ENV: Record<Exclude<Repo, "engine">, string[]> = {
  console: ["DOWNPIPES_CONSOLE_ROOT", "DOWNPIPES_CONSOLE"],
  downpipe: ["DOWNPIPES_DOWNPIPE_ROOT", "DOWNPIPES_DOWNPIPE"],
  "control-plane": ["DOWNPIPES_CONTROL_PLANE_ROOT", "DOWNPIPES_CONTROL_PLANE"],
  "internal-docs": ["DOWNPIPES_INTERNAL_DOCS_ROOT", "DOWNPIPES_INTERNAL_DOCS"],
};
function findSibling(name: Exclude<Repo, "engine">): string | null {
  const candidates = [
    ...ENV[name].map((k) => process.env[k]),
    resolve(HERE, `../${name}`),
    resolve(HERE, `../../${name}`),
    resolve(HERE, `../../../${name}`),
    resolve(HERE, `../../../../${name}`),
  ].filter((c): c is string => typeof c === "string" && c !== "");
  return candidates.find((c) => existsSync(resolve(c, MARKERS[name]))) ?? null;
}
const roots: Record<Repo, string | null> = {
  engine: HERE,
  console: findSibling("console"),
  downpipe: findSibling("downpipe"),
  "control-plane": findSibling("control-plane"),
  "internal-docs": findSibling("internal-docs"),
};
const present = (Object.keys(roots) as Repo[]).filter((r) => r !== "engine" && roots[r] !== null);
const absent = (Object.keys(roots) as Repo[]).filter((r) => roots[r] === null);
if (absent.length > 0 && REQUIRE) {
  console.error(`FAIL file-handling-doc: --require was passed and these siblings were not found: ${absent.join(", ")}`);
  process.exit(1);
}
for (const r of absent) console.log(`note  ${r}: no checkout beside this engine, so its citations and checks are SKIPPED (pass --require to fail instead)`);

// Name the trees the verdict is a function of, and refuse a stale one rather than grade it.
const siblingList = present.map((name) => ({ name, path: roots[name] as string }));
if (siblingList.length > 0) {
  reportSiblings(siblingList, { gate: "file-handling-doc" });
  requireFreshSiblings(siblingList, {
    gate: "file-handling-doc",
    consequence: "it would grade the policy against an older tree than the one that ships",
    exit: (code: number) => {
      verdictSkipped(`REFUSED, exit ${code}: a sibling checkout beside this engine is behind its own origin/main, so nothing was concluded`);
      process.exit(code);
    },
  });
}

const doc = readFileSync(resolve(HERE, DOC), "utf8");
const lineCache = new Map<string, string[]>();
function linesOf(repo: Repo, rel: string): string[] | null {
  const root = roots[repo];
  if (root === null) return null;
  const key = `${repo}/${rel}`;
  const hit = lineCache.get(key);
  if (hit) return hit;
  const p = resolve(root, rel);
  if (!existsSync(p)) return [];
  const lines = readFileSync(p, "utf8").split("\n");
  lineCache.set(key, lines);
  return lines;
}
function lineAt(repo: Repo, rel: string, n: number): string | null | undefined {
  const lines = linesOf(repo, rel);
  if (lines === null) return null; // sibling absent
  return lines[n - 1];
}
const collapse = (s: string): string => s.replace(/\s+/g, " ").trim();

console.log(`\n-- ${DOC} agrees with the trees it cites --\n`);

// ---- 1. every citation resolves --------------------------------------------------------------------------
const CITE = /\b(engine|console|downpipe|control-plane)\/([A-Za-z0-9_./-]+?\.(?:ts|go|mjs|md|json)):(\d+)(?:-(\d+))?/g;
const cited = new Map<string, { repo: Repo; rel: string; from: number; to: number }>();
for (const m of doc.matchAll(CITE)) {
  const repo = m[1] as Repo;
  const rel = m[2] as string;
  const from = Number(m[3]);
  const to = m[4] !== undefined ? Number(m[4]) : from;
  cited.set(`${repo}/${rel}:${m[3]}${m[4] !== undefined ? `-${m[4]}` : ""}`, { repo, rel, from, to });
}
ok(`the document carries citations to grade (${cited.size} distinct)`, cited.size >= 60);
let skippedCitations = 0;
let inert = 0;
for (const [label, c] of cited) {
  if (roots[c.repo] === null) {
    skippedCitations++;
    continue;
  }
  const lines = linesOf(c.repo, c.rel) ?? [];
  const exists = lines.length > 0;
  const ends = [c.from, c.to];
  const resolved = exists && ends.every((n) => n >= 1 && n <= lines.length && collapse(lines[n - 1] ?? "") !== "" && !/^[\]\)\}\];,\s]*$/.test(collapse(lines[n - 1] ?? "")));
  if (!resolved) {
    inert++;
    console.log(`  FAIL citation ${label} is INERT (${exists ? `line holds: ${JSON.stringify(collapse(lines[c.from - 1] ?? "<past end>")).slice(0, 80)}` : "file not found"})`);
  }
}
checks += cited.size - skippedCitations;
failures += inert;
ok(`every graded citation resolves to a non-blank line (${cited.size - skippedCitations} graded, ${skippedCitations} skipped for absent siblings, ${inert} inert)`, inert === 0);

// ---- 2. the ceilings table -------------------------------------------------------------------------------
const UNIT: Record<string, number> = { KiB: 1024, MiB: 1024 * 1024, GiB: 1024 * 1024 * 1024, MB: 1_000_000, bytes: 1 };
function parseValue(cell: string): number | null {
  const m = /^\s*(\d+(?:\.\d+)?)\s*(KiB|MiB|GiB|MB|bytes)?\s*$/.exec(cell);
  if (!m) return null;
  return Number(m[1]) * (m[2] !== undefined ? (UNIT[m[2]] ?? Number.NaN) : 1);
}
// evalLiteral accepts integers joined by `*` and `<<`, with `_` separators and whitespace, and nothing else.
function evalLiteral(src: string): number | null {
  const s = src.replace(/_/g, "").replace(/\s+/g, "");
  if (!/^[0-9*<]+$/.test(s) || s === "") return null;
  const shifts = s.split("<<");
  const products = shifts.map((part) => {
    const factors = part.split("*");
    if (factors.some((f) => !/^\d+$/.test(f))) return Number.NaN;
    return factors.reduce((a, f) => a * Number(f), 1);
  });
  if (products.some((p) => Number.isNaN(p))) return null;
  return products.reduce((a, p) => a * 2 ** p);
}
function literalOn(line: string): string | null {
  const eq = line.indexOf("=");
  if (eq === -1) return null;
  let rhs = line.slice(eq + 1);
  const cut = [rhs.indexOf(";"), rhs.indexOf("//")].filter((i) => i !== -1);
  if (cut.length > 0) rhs = rhs.slice(0, Math.min(...cut));
  return rhs.trim();
}
const tableStart = doc.indexOf("| Ceiling | Value | Constant | Where |");
ok("the ceilings table is present", tableStart !== -1);
const tableRows: { ceiling: string; value: number | null; valueCell: string; constant: string; repo: Repo; rel: string; line: number }[] = [];
if (tableStart !== -1) {
  const after = doc.slice(tableStart).split("\n").slice(2);
  for (const row of after) {
    if (!row.startsWith("|")) break;
    const cells = row.split("|").slice(1, -1).map((c) => c.trim());
    const [ceiling, valueCell, constantCell, whereCell] = cells as [string, string, string, string];
    const constant = constantCell.replace(/`/g, "");
    const where = /^`?(engine|console|downpipe|control-plane)\/([^:`]+):(\d+)`?$/.exec(whereCell);
    if (!where) {
      ok(`ceilings row "${ceiling}" cites one repo/path:line`, false);
      continue;
    }
    tableRows.push({ ceiling, value: parseValue(valueCell), valueCell, constant, repo: where[1] as Repo, rel: where[2] as string, line: Number(where[3]) });
  }
}
ok(`the ceilings table names every documented ceiling (${tableRows.length} rows, floor 10)`, tableRows.length >= 10);
const valueByConstant = new Map<string, number>();
for (const r of tableRows) if (r.value !== null) valueByConstant.set(r.constant, r.value);
for (const r of tableRows) {
  const label = `${r.constant} at ${r.repo}/${r.rel}:${r.line} evaluates to ${r.valueCell}`;
  if (roots[r.repo] === null) {
    console.log(`  skip ${label} (${r.repo} absent)`);
    continue;
  }
  const line = lineAt(r.repo, r.rel, r.line);
  if (line === undefined || line === null) {
    ok(label, false);
    continue;
  }
  if (!line.includes(r.constant)) {
    ok(`${label}: the cited line names the constant`, false);
    continue;
  }
  if (r.constant === "maxDecompressedBytes") {
    const chunks = valueByConstant.get("maxSegmentChunks");
    const size = valueByConstant.get("ChunkSize");
    const derived = line.includes("maxSegmentChunks") && line.includes("ChunkSize") && chunks !== undefined && size !== undefined && r.value === chunks * size;
    ok(`${label} as the product of maxSegmentChunks and ChunkSize`, derived);
    continue;
  }
  const lit = literalOn(line);
  const got = lit === null ? null : evalLiteral(lit);
  ok(`${label} (line literal: ${lit ?? "<none>"})`, r.value !== null && got !== null && got === r.value);
}

// ---- 3. every catalogued file picker is cited at its declaration ------------------------------------------
if (roots["internal-docs"] === null || roots.console === null) {
  console.log("  skip the field-catalogue file rows (internal-docs or console absent)");
} else {
  const catalogue = readFileSync(resolve(roots["internal-docs"], "FIELD-CATALOGUE/catalogue.jsonl"), "utf8")
    .split("\n")
    .filter((l) => l.trim() !== "")
    .map((l) => JSON.parse(l) as { key: string; file: string; line: number; control: string; cite_pins?: Record<string, string> });
  const fileRows = catalogue.filter((r) => r.control === "file");
  ok(`the catalogue holds file-picker rows to reconcile (${fileRows.length}, floor 8)`, fileRows.length >= 8);
  for (const row of fileRows) {
    const pin = row.cite_pins?.[`${row.file}:${row.line}`];
    if (pin === undefined) {
      ok(`catalogue row ${row.key} carries a pin for its own declaration`, false);
      continue;
    }
    const docCites = [...cited.values()].filter((c) => c.repo === "console" && c.rel === row.file);
    const matching = docCites.filter((c) => {
      const line = lineAt("console", row.file, c.from);
      return typeof line === "string" && collapse(line) === collapse(pin) && line.includes('h("input"');
    });
    ok(`catalogue file row ${row.key} is cited in the document at the console line that declares it (${matching.length > 0 ? `console/${row.file}:${matching[0]?.from}` : `${docCites.length} citation(s) into that file, none at the declaration`})`, matching.length > 0);
  }
}

console.log(`\n${failures === 0 ? `FILE-HANDLING-DOC PASS (${checks} checks)` : `FILE-HANDLING-DOC: ${failures} FAILED of ${checks} checks`}\n`);
verdictReached(failures);
process.exit(failures === 0 ? 0 : 1);
