// typecheck-scope-gate: the .mjs files under test/, scripts/ and tools/ are inside the TYPE checker's
// world, and their error count may not grow.
//
// WHY. lint-scope-gate brought those three directories under biome, and its own header names the sibling
// hole it did not close: "the same scope hole as the typecheck one". That hole is still open, and it is
// subtler than an absent config. tsconfig.workspace.json ALREADY lists all three directories and already
// sets allowJs, so tsc reads 39 .mjs files across them. checkJs is unset, so it reads them and checks
// nothing. The include list includes them and grades none of them, which is why `npm run typecheck` is
// exit 0 with 897 real diagnostics sitting in the tree.
//
// MEASURED, not supposed: a slackRows array in scripts/max-lines-lint.mjs inferred as (string | number)[]
// and its arithmetic went unchecked here, while console's typecheck:scripts refused the identical code.
// Same defect, same day, one repo blind to it.
//
// WHY A RATCHET RATHER THAN A CLEAN GATE. Turning checkJs on outright means fixing 897 diagnostics across
// three directories that every pass edits, which is a separate change set. So the debt is MEASURED and
// PINNED, exactly as lint-scope-baseline.json does for biome: the count sits in the baseline, this gate
// refuses any increase, and the number is visible rather than invisible. Ratcheting down is the follow-up.
//
// Usage:
//   node scripts/typecheck-scope-gate.mjs                   check
//   node scripts/typecheck-scope-gate.mjs --write-baseline  re-pin after a genuine reduction
//   node scripts/typecheck-scope-gate.mjs --self-test       prove the comparison bites
//
// Exit codes: 0 the count held or fell, 1 it grew, 2 could not check.
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const BASELINE = join(ROOT, "scripts", "typecheck-scope-baseline.json");
const TAG = "[typecheck-scope]";

// Same exemption, same reason, as lint-scope-gate.mjs: a public export vendors this one file
// byte-identical from internal-docs/PUBLISH, it is not this repository's own maintained source,
// and its typeless JS added 23 checkJs diagnostics to a tree where application source had not
// moved at all (measured). Matched against the start of a tsc diagnostic line, which is a
// repo-relative path.
const EXPORT_VENDORED_EXEMPT = ["scripts/publishable-gate.mjs"];

/**
 * The whole comparison, pure so --self-test can drive it with no compiler.
 * @param {number} found @param {number} pinned
 * @returns {"grew"|"held"|"fell"}
 */
export function verdictFor(found, pinned) {
  if (found > pinned) return "grew";
  if (found < pinned) return "fell";
  return "held";
}

/** @param {number} code @param {string} msg @returns {never} */
function die(code, msg) {
  console.error(`::error::${TAG} ${msg}`);
  process.exit(code);
}

if (process.argv.includes("--self-test")) {
  const cases = [
    ["a count above the pin GREW", verdictFor(898, 897), "grew"],
    ["one above the pin is still a growth", verdictFor(898, 897), "grew"],
    ["the pin exactly is held", verdictFor(897, 897), "held"],
    ["below the pin FELL, and is not a failure", verdictFor(800, 897), "fell"],
    ["zero against a nonzero pin is a fall", verdictFor(0, 897), "fell"],
  ];
  let bad = 0;
  for (const [name, got, want] of cases) {
    const ok = got === want;
    if (!ok) bad++;
    console.log(`  ${ok ? "ok  " : "FAIL"} ${name}${ok ? "" : ` (got ${got}, want ${want})`}`);
  }
  console.log(`${TAG} self-test: ${cases.length} case(s), ${bad} failure(s)`);
  process.exit(bad ? 1 : 0);
}

// --pretty false: without it, this TypeScript version's default reporter groups diagnostics into a
// per-file summary table instead of printing one "path(line,col): error TSnnnn: ..." line per finding.
// The regex below reads that per-line form; against the grouped table it matches nothing, which is the
// exact "config that read no files" shape the zero-guard below exists to catch, so the flag stays pinned
// here rather than becoming a silent miscount.
const r = spawnSync("npx", ["tsc", "-p", "tsconfig.checkjs.json", "--noEmit", "--pretty", "false"], { cwd: ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
if (r.error) die(2, `cannot check: tsc did not run (${r.error.message})`);
const out = `${r.stdout ?? ""}${r.stderr ?? ""}`;
if (out.trim() === "" && r.status !== 0) die(2, `cannot check: tsc exited ${r.status} with no output`);
const lines = out
  .split("\n")
  .filter((l) => /error TS\d+:/.test(l))
  .filter((l) => !EXPORT_VENDORED_EXEMPT.some((p) => l.startsWith(`${p}(`)));
const found = lines.length;
// A zero here is far more likely to be a config that read nothing than a clean tree, and this gate's whole
// subject is a config that read nothing. So a zero against a nonzero pin REFUSES rather than celebrating.
const pinned = JSON.parse(readFileSync(BASELINE, "utf8")).errors;
if (found === 0 && pinned > 0) die(2, `cannot check: tsc reported 0 errors against a pin of ${pinned}. That is the shape of a config that read no files, which is the defect this gate exists for. Verify with: npx tsc -p tsconfig.checkjs.json --noEmit`);

/** @type {Record<string, number>} */
const byDir = {};
for (const l of lines) {
  const d = /^([a-z]+)\//.exec(l);
  const dir = d?.[1];
  if (dir !== undefined) byDir[dir] = (byDir[dir] ?? 0) + 1;
}
console.log(`${TAG} ${found} diagnostic(s) with checkJs ON across test/, scripts/ and tools/ (pinned ${pinned})`);
for (const [d, n] of Object.entries(byDir).sort((a, b) => b[1] - a[1])) console.log(`  ${String(n).padStart(5)}  ${d}/`);

if (process.argv.includes("--write-baseline")) {
  writeFileSync(BASELINE, `${JSON.stringify({ "//": "Pinned typecheck diagnostic count for test/, scripts/ and tools/ with checkJs ON. Ratchet DOWN; the gate refuses any increase. Re-pin only with --write-baseline after a genuine reduction.", errors: found }, null, 2)}\n`, "utf8");
  console.log(`${TAG} baseline re-pinned at ${found}`);
  process.exit(0);
}

const verdict = verdictFor(found, pinned);
if (verdict === "grew") die(1, `the count GREW from ${pinned} to ${found}. A new type error under test/, scripts/ or tools/ is exactly what this ratchet exists to stop. Fix it, or re-pin deliberately with --write-baseline and say why.`);
if (verdict === "fell") console.log(`${TAG} FELL from ${pinned} to ${found}. Re-pin with --write-baseline to keep the ratchet tight.`);
console.log(`${TAG} OK: the count ${verdict}.`);
