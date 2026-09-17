// The data classification inventory must agree with the tree it describes (ASVS V14.1.1, V14.1.2, V14.2.4).
//
// WHY THIS EXISTS. docs/security/data-classification.md is the document an assessor reads to learn what
// sensitive data the engine holds, at which protection level, and under which controls. It is cited by
// file and line into the source. Between June and the engine gained a native identity
// provider, sealed credential envelopes, a SCIM bearer, a licence token, a config-recipient key pair and
// dual-control approval records, and the document gained none of them; in the same span 22 of its 28
// line-pinned citations came to point at lines their identifier was no longer on, and its summary table
// said retention was not enforced while its asset rows said it was. Nothing was red. This gate is what
// would have been.
//
// WHAT IT ASSERTS, against the tree rather than against the document's own claims:
//   1. CITATIONS. Every backtick citation of the form `engine/<path>[:line[-line]]` names a file that
//      exists, a line range inside that file, and, for a line-pinned citation into engine/src, carries an
//      anchor `(`identifier`[, `identifier`])` whose every identifier appears on a NON-COMMENT line inside
//      the range. A citation whose line drifted fails on the anchor, which is the check a bare
//      "file exists with at least N lines" cannot make.
//   2. COVERAGE (V14.1.1). Every secret-bearing binding declared in src/env.d.ts (a name ending in _TOKEN,
//      _KEY, _PRIVATE, _SECRET or _PUBLIC, or carrying SIGNER, BREAK_GLASS, OPERATIONAL or
//      CONFIG_RECIPIENT, plus DEST_ACCESS_KEY_ID) is named in an asset row or in the encoded-artefacts
//      table, and so is every Durable Object secret key constant in src/sched/scheduler-do-keys.ts and
//      the `idpsecret:` client-secret prefix in src/admin/oidc-store.ts.
//   3. MATRIX (V14.1.2). The "Protection requirements per level" table exists with exactly the four level
//      rows L0 to L3, exactly the nine required columns, and no empty cell.
//   4. SUMMARY AGREEMENT (V14.2.4). Every asset row has a summary row and vice versa, and no summary row
//      reads "No" under "Retention enforced" when its asset row says retention is enforced or opt-in.
//   5. SIBLING (V14.1.2, control plane). When a control-plane checkout is beside this engine, its
//      data-classification.md carries the same matrix, shaped the same way, with its own citations
//      resolving in its own tree, and every secret-bearing binding in its own src/env.d.ts and
//      wrangler.toml is named in its own asset rows, the same coverage check as check 2 runs for the
//      engine's own bindings. Absent the sibling the check is SKIPPED with a note, and FAILS under
//      --require, the convention validate-posture-and-docs-parity.ts documents.
//
// Run with `node test/validate-data-classification-doc.ts [--require]`.
//
// House style: Australian English, no em dashes, no rule-of-three, no AI attribution.

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verdictReached } from "./lib/verdict-guard.ts";

const HERE = fileURLToPath(new URL("..", import.meta.url));
const REQUIRE = process.argv.includes("--require");
const DOC = "docs/security/data-classification.md";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean, detail?: string): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) {
    failures++;
    if (detail) console.log(`       ${detail}`);
  }
}

const doc = readFileSync(resolve(HERE, DOC), "utf8");
const docLines = doc.split("\n");

// ---- section slicing --------------------------------------------------------------------------------------
// A section runs from its heading line to the next heading of the same or a higher level.
function sectionIn(lines: string[], headingPrefix: string): { start: number; end: number; text: string } | null {
  const start = lines.findIndex((l) => l.startsWith(headingPrefix));
  if (start < 0) return null;
  const level = (/^#+/.exec(headingPrefix) as RegExpExecArray)[0].length;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    const m = /^(#+)\s/.exec(lines[i] as string);
    if (m && (m[1] as string).length <= level) {
      end = i;
      break;
    }
  }
  return { start, end, text: lines.slice(start, end).join("\n") };
}
function section(headingPrefix: string): { start: number; end: number; text: string } | null {
  return sectionIn(docLines, headingPrefix);
}

const encoded = section("### 1.2 Encoded is not protected");
const matrix = section("### 1.3 Protection requirements per level");
const assets = section("## 2. Asset inventory");
const summary = section("## 3. Summary table");
ok("section 1.2 (encoded artefacts) exists", encoded !== null);
ok("section 1.3 (protection requirements per level) exists", matrix !== null);
ok("section 2 (asset inventory) exists", assets !== null);
ok("section 3 (summary table) exists", summary !== null);

// ---- 1. citations ----------------------------------------------------------------------------------------
// `engine/<path>[:N[-M]]` optionally followed by ` (`ident`, `ident`)`. Only the engine's own tree is
// resolved here; sibling paths (control-plane/, website/) are resolved in the sibling block below.
const CITE = /`(engine\/[^`\s]+?)(?::(\d+)(?:-(\d+))?)?`(?:\s*\(((?:`[^`]+`(?:,\s*)?)+)\))?/g;

function isCommentLine(line: string): boolean {
  const t = line.trim();
  return t.startsWith("//") || t.startsWith("/*") || t.startsWith("*") || t.startsWith("*/");
}

const fileCache = new Map<string, string[] | null>();
function fileLines(root: string, rel: string): string[] | null {
  const key = `${root}::${rel}`;
  if (fileCache.has(key)) return fileCache.get(key) as string[] | null;
  const p = resolve(root, rel);
  const lines = existsSync(p) ? readFileSync(p, "utf8").split("\n") : null;
  fileCache.set(key, lines);
  return lines;
}

type Cite = { raw: string; path: string; from: number | null; to: number | null; anchors: string[]; line: number };
function citationsIn(text: string, prefix: RegExp, baseLine: number): Cite[] {
  const out: Cite[] = [];
  const lines = text.split("\n");
  lines.forEach((l, i) => {
    for (const m of l.matchAll(prefix)) {
      const from = m[2] !== undefined ? Number(m[2]) : null;
      const to = m[3] !== undefined ? Number(m[3]) : from;
      const anchors = m[4] !== undefined ? Array.from((m[4] as string).matchAll(/`([^`]+)`/g), (a) => a[1] as string) : [];
      out.push({ raw: m[0], path: m[1] as string, from, to, anchors, line: baseLine + i + 1 });
    }
  });
  return out;
}

function checkCitation(root: string, stripPrefix: string, c: Cite, anchorRequiredUnder: string): void {
  const rel = c.path.startsWith(stripPrefix) ? c.path.slice(stripPrefix.length) : c.path;
  const lines = fileLines(root, rel);
  const where = `${DOC}:${c.line}`;
  if (lines === null) {
    ok(`${where} ${c.raw} names a file that exists`, false, `${rel} is not in the tree`);
    return;
  }
  if (c.from === null) return; // a file-level citation: existence is the whole claim
  const to = c.to as number;
  if (c.from < 1 || to < c.from || to > lines.length) {
    ok(`${where} ${c.raw} line range is inside the file`, false, `${rel} has ${lines.length} lines`);
    return;
  }
  if (!rel.startsWith(anchorRequiredUnder)) return;
  if (c.anchors.length === 0) {
    ok(`${where} ${c.raw} carries an identifier anchor`, false, "a line-pinned source citation must name the identifier on that line");
    return;
  }
  const codeLines = lines.slice(c.from - 1, to).filter((l) => !isCommentLine(l));
  for (const a of c.anchors) {
    const found = codeLines.some((l) => l.includes(a));
    ok(`${where} ${c.raw} has \`${a}\` on a code line in range`, found, found ? undefined : `lines ${c.from}-${to} of ${rel} do not carry ${a} outside a comment`);
  }
}

console.log("\n-- 1. every engine citation resolves, and every pinned source citation has its identifier on the line --\n");
const engineCites = citationsIn(doc, CITE, 0);
ok(`the document carries engine citations (${engineCites.length} found)`, engineCites.length > 50);
for (const c of engineCites) checkCitation(HERE, "engine/", c, "src/");
const pinnedSrc = engineCites.filter((c) => c.from !== null && c.path.startsWith("engine/src/"));
console.log(`       ${pinnedSrc.length} line-pinned source citations graded with anchors`);

// ---- 2. coverage (V14.1.1) ---------------------------------------------------------------------------------
console.log("\n-- 2. every secret-bearing binding and Durable Object secret key has a row --\n");
const envLines = fileLines(HERE, "src/env.d.ts") as string[];
ok("src/env.d.ts is readable", envLines !== null);
const bindingNames = new Set<string>();
for (const l of envLines ?? []) {
  const m = /^\s+([A-Z][A-Z0-9_]+)\??:/.exec(l);
  if (m) bindingNames.add(m[1] as string);
}
const SECRET_SUFFIX = /(_TOKEN|_KEY|_PRIVATE|_SECRET|_PUBLIC)$/;
const SECRET_MARK = /(SIGNER|BREAK_GLASS|OPERATIONAL|CONFIG_RECIPIENT)/;
const secretBindings = [...bindingNames].filter((n) => SECRET_SUFFIX.test(n) || SECRET_MARK.test(n) || n === "DEST_ACCESS_KEY_ID").sort();
ok(`env.d.ts declares secret-bearing bindings (${secretBindings.length} found)`, secretBindings.length >= 15, secretBindings.join(", "));
const namedIn = `${encoded?.text ?? ""}\n${assets?.text ?? ""}`;
for (const b of secretBindings) {
  const named = new RegExp(`\`${b}\``).test(namedIn);
  ok(`binding ${b} is named in an asset row or the encoded-artefacts table`, named, named ? undefined : `add a section 2 row (or a section 1.2 entry) naming \`${b}\``);
}
const keysLines = fileLines(HERE, "src/sched/scheduler-do-keys.ts") as string[];
const doSecretKeys = (keysLines ?? []).map((l) => /^export const ([A-Z0-9_]+_KEY_KEY) = /.exec(l)?.[1]).filter((n): n is string => typeof n === "string");
ok(`scheduler-do-keys.ts declares Durable Object secret keys (${doSecretKeys.length} found)`, doSecretKeys.length >= 2, doSecretKeys.join(", "));
for (const k of doSecretKeys) {
  ok(`Durable Object secret key ${k} is named in an asset row`, new RegExp(`\`${k}\``).test(assets?.text ?? ""));
}
const oidcStore = fileLines(HERE, "src/admin/oidc-store.ts") as string[];
ok("oidc-store.ts still keys the client secret under idpsecret:", (oidcStore ?? []).some((l) => l.includes("idpsecret:")));
ok("the idpsecret: client-secret store is named in an asset row", (assets?.text ?? "").includes("`idpsecret:<id>`"));

// ---- 3. matrix shape (V14.1.2) -----------------------------------------------------------------------------
const REQUIRED_COLUMNS = [
  "Encryption in transit",
  "Encryption at rest (application layer)",
  "Database-level encryption",
  "Integrity verification",
  "Retention",
  "Logging",
  "Access control around this level in logs",
  "Privacy and privacy-enhancing techniques",
  "Other confidentiality",
];
function tableRows(text: string): string[][] {
  return text
    .split("\n")
    .filter((l) => l.trim().startsWith("|"))
    .map((l) => l.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim()));
}
function checkMatrix(label: string, text: string | undefined): void {
  console.log(`\n-- 3. ${label}: the protection requirements matrix has four level rows, nine columns, no empty cell --\n`);
  const rows = tableRows(text ?? "").filter((r) => !r.every((c) => /^-+$/.test(c)));
  const header = rows[0];
  ok(`${label}: the matrix has a header row`, header !== undefined);
  if (!header) return;
  const cols = header.slice(1);
  ok(`${label}: the matrix columns are exactly the nine required, in order`, JSON.stringify(cols) === JSON.stringify(REQUIRED_COLUMNS), `found: ${cols.join(" | ")}`);
  const body = rows.slice(1);
  const levels = body.map((r) => (r[0] ?? "").replace(/\*/g, ""));
  ok(`${label}: the matrix has exactly the four level rows L0, L1, L2, L3`, JSON.stringify(levels) === JSON.stringify(["L0", "L1", "L2", "L3"]), `found: ${levels.join(", ")}`);
  for (const r of body) {
    ok(`${label}: row ${(r[0] ?? "").replace(/\*/g, "")} has ${REQUIRED_COLUMNS.length} cells`, r.length === REQUIRED_COLUMNS.length + 1, `found ${r.length - 1}`);
    r.slice(1).forEach((cell, i) => {
      ok(`${label}: row ${(r[0] ?? "").replace(/\*/g, "")} column "${REQUIRED_COLUMNS[i]}" is not empty`, cell.length > 0);
    });
  }
}
checkMatrix("engine", matrix?.text);

// ---- 4. summary agreement (V14.2.4) ------------------------------------------------------------------------
console.log("\n-- 4. the summary table agrees with the asset rows --\n");
const assetHeadings = new Map<string, { title: string; retention: string }>();
if (assets) {
  let current: string | null = null;
  for (const l of docLines.slice(assets.start, assets.end)) {
    const h = /^### (2\.\d+) (.+)$/.exec(l);
    if (h) {
      current = h[1] as string;
      assetHeadings.set(current, { title: h[2] as string, retention: "" });
      continue;
    }
    const r = /^\|\s*Retention\s*\|\s*(.+?)\s*\|$/.exec(l);
    if (r && current) (assetHeadings.get(current) as { retention: string }).retention = r[1] as string;
  }
}
ok(`section 2 numbers its asset rows (${assetHeadings.size} found)`, assetHeadings.size >= 25);
const summaryRows = tableRows(summary?.text ?? "").filter((r) => /^2\.\d+ /.test(r[0] ?? ""));
ok(`section 3 carries one row per asset (${summaryRows.length} found)`, summaryRows.length === assetHeadings.size, `assets ${assetHeadings.size}, summary rows ${summaryRows.length}`);
const summaryHeader = tableRows(summary?.text ?? "")[0] ?? [];
const retentionCol = summaryHeader.indexOf("Retention enforced");
ok('section 3 has a "Retention enforced" column', retentionCol >= 0);
const seen = new Set<string>();
for (const r of summaryRows) {
  const num = (/^(2\.\d+) /.exec(r[0] as string) as RegExpExecArray)[1] as string;
  seen.add(num);
  const asset = assetHeadings.get(num);
  ok(`summary row ${num} has a matching asset row`, asset !== undefined);
  if (!asset || retentionCol < 0) continue;
  const enforced = /enforced|opt-in/i.test(asset.retention);
  const cell = (r[retentionCol] ?? "").trim();
  if (enforced) {
    ok(`summary row ${num} (${asset.title}) does not say retention is "No" while the asset row says it is enforced or opt-in`, !/^no\b/i.test(cell), `summary cell reads "${cell}"; asset row reads "${asset.retention.slice(0, 80)}"`);
  }
}
for (const num of assetHeadings.keys()) ok(`asset row ${num} has a summary row`, seen.has(num));

// ---- 5. control-plane sibling ------------------------------------------------------------------------------
console.log("\n-- 5. the control-plane inventory carries the same matrix --\n");
function siblingCandidates(name: string): string[] {
  return [process.env[`DOWNPIPES_${name.toUpperCase().replace(/-/g, "_")}`], resolve(HERE, `../${name}`), resolve(HERE, `../../${name}`), resolve(HERE, `../../../${name}`), resolve(HERE, `../../../../${name}`)].filter(
    (p): p is string => typeof p === "string" && p !== "",
  );
}
const CP_DOC = "docs/security/data-classification.md";
const cpRoot = siblingCandidates("control-plane").find((c) => existsSync(resolve(c, CP_DOC)));
if (cpRoot === undefined) {
  ok("a control-plane checkout is beside this engine (pass --require to fail instead)", !REQUIRE, "control-plane/docs/security/data-classification.md not found in any candidate");
  console.log("       control-plane matrix: SKIPPED, no sibling checkout");
} else {
  const cpDoc = readFileSync(resolve(cpRoot, CP_DOC), "utf8");
  const cpLines = cpDoc.split("\n");
  const start = cpLines.findIndex((l) => /^#{2,3} .*Protection requirements per level/.test(l));
  ok("control-plane: the matrix section exists", start >= 0);
  if (start >= 0) {
    let end = cpLines.length;
    for (let i = start + 1; i < cpLines.length; i++) {
      if (/^#{1,3} /.test(cpLines[i] as string)) {
        end = i;
        break;
      }
    }
    const cpMatrix = cpLines.slice(start, end).join("\n");
    checkMatrix("control-plane", cpMatrix);
    const CP_CITE = /`((?:src|scripts|test)\/[^`\s]+?)(?::(\d+)(?:-(\d+))?)?`(?:\s*\(((?:`[^`]+`(?:,\s*)?)+)\))?/g;
    const cpCites = citationsIn(cpMatrix, CP_CITE, start);
    ok(`control-plane: the matrix cites its own source (${cpCites.length} citations)`, cpCites.length > 10);
    for (const c of cpCites) checkCitation(cpRoot, "", c, "src/");
  }

  // ---- 5b. control-plane coverage (V14.1.1), the same check as section 2 but against the sibling tree --
  console.log("\n-- 5b. control-plane: every secret-bearing binding in env.d.ts and wrangler.toml has a row --\n");
  const cpEnvLines = fileLines(cpRoot, "src/env.d.ts");
  ok("control-plane: src/env.d.ts is readable", cpEnvLines !== null);
  const cpWranglerLines = fileLines(cpRoot, "wrangler.toml");
  ok("control-plane: wrangler.toml is readable", cpWranglerLines !== null);
  const cpBindingNames = new Set<string>();
  for (const l of cpEnvLines ?? []) {
    const m = /^\s+([A-Z][A-Z0-9_]+)\??:/.exec(l);
    if (m) cpBindingNames.add(m[1] as string);
  }
  for (const l of cpWranglerLines ?? []) {
    const m = /^#?\s*binding\s*=\s*"([A-Z][A-Z0-9_]+)"/.exec(l);
    if (m) cpBindingNames.add(m[1] as string);
  }
  const cpSecretBindings = [...cpBindingNames].filter((n) => SECRET_SUFFIX.test(n) || SECRET_MARK.test(n)).sort();
  ok(`control-plane: env.d.ts and wrangler.toml declare secret-bearing bindings (${cpSecretBindings.length} found)`, cpSecretBindings.length >= 5, cpSecretBindings.join(", "));
  const cpAssets = sectionIn(cpLines, "## 2. Asset inventory");
  ok("control-plane: section 2 (asset inventory) exists", cpAssets !== null);
  for (const b of cpSecretBindings) {
    const named = new RegExp(`\`${b}\``).test(cpAssets?.text ?? "");
    ok(`control-plane: binding ${b} is named in an asset row`, named, named ? undefined : `add a section 2 row in the control-plane document naming \`${b}\``);
  }
}

// ---- website cross-reference (section 1.1) ------------------------------------------------------------------
const websiteRoot = siblingCandidates("website").find((c) => existsSync(resolve(c, "src/pages/compliance/privacy-act.astro")));
const websiteCites = Array.from(doc.matchAll(/`(website\/[^`\s]+)`/g), (m) => m[1] as string);
ok(`section 1.1 cross-references the public compliance pages (${websiteCites.length} found)`, websiteCites.length >= 2);
if (websiteRoot === undefined) {
  console.log("       website pages: SKIPPED, no sibling checkout");
} else {
  for (const w of websiteCites) ok(`${w} exists in the website checkout`, existsSync(resolve(websiteRoot, w.slice("website/".length))));
}

console.log(`\n${failures === 0 ? "DATA-CLASSIFICATION-DOC PASS" : `DATA-CLASSIFICATION-DOC: ${failures} FAILED`} (${checks} checks)\n`);
verdictReached(failures, checks);
process.exit(failures === 0 ? 0 : 1);
