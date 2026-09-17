#!/usr/bin/env node
// lint-scope-gate: test/, scripts/ and tools/ are inside the linter's world, and their diagnostic count
// may not grow.
//
// WHY. biome.json used to be files.includes:["src/**"] and the lint script was "biome lint src", so the
// three directories that hold every validator, every gate and every fixture were linted by NOTHING. That
// is the same scope hole as the typecheck one (tsconfig.json was include:["src"]), and it is why a
// validator could print three FAIL lines and exit 0 for as long as it did: no checker of any kind read
// the directory it lived in.
//
// WHY A RATCHET RATHER THAN A CLEAN GATE. Bringing the three directories under `biome lint
// --error-on-warnings` in one change means fixing 169 error-and-warning diagnostics across the test tree,
// which is a separate change set and would collide with every other pass editing test/ today. So the debt
// is MEASURED and PINNED instead: the exact counts sit in lint-scope-baseline.json, this gate refuses any
// increase, and the numbers are visible rather than invisible. Ratcheting down is the follow-up; the
// point of this file is that the hole can no longer widen unnoticed, and can no longer be forgotten.
//
// FAILS WHEN IT CANNOT RUN: exit 2 if biome cannot be invoked, if the baseline is missing or malformed,
// or if biome reports it processed no files at all, which is what happens when the paths are excluded by
// configuration. "Checked 0 files" passing as clean is the exact bug this campaign is about.
//
// Run: node scripts/lint-scope-gate.mjs        (add --write-baseline to re-pin after a genuine reduction)

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const DIRS = ["test", "scripts", "tools"];
const BASELINE = join(REPO, "scripts", "lint-scope-baseline.json");
const WRITE = process.argv.includes("--write-baseline");

// A public export vendors this one file byte-identical from internal-docs/PUBLISH across engine,
// console, downpipe and docs; it is not part of this repository's own maintained source, the same
// reasoning publishable-gate.mjs itself already applies to exempt it from ITS OWN token scan (see
// SELF_REFERENTIAL_EXEMPT there). Counting its diagnostics against a baseline pinned to this
// repo's own tree compares two different trees under one number: measured, its typeless JS added
// 2 biome warnings and 23 checkJs diagnostics to a tree where application source had not moved at
// all. Excluded by exact path, not by directory, so a real file this repo adds under scripts/
// still counts.
const EXPORT_VENDORED_EXEMPT = new Set(["scripts/publishable-gate.mjs"]);

function die(code, msg) {
  console.error(`lint-scope-gate: ${msg}`);
  process.exit(code);
}

const r = spawnSync("npx", ["biome", "lint", "--max-diagnostics=5000", "--reporter=json", ...DIRS], {
  cwd: REPO,
  encoding: "utf8",
  maxBuffer: 64 * 1024 * 1024,
});
if (r.error) die(2, `cannot check: biome did not run (${r.error.message})`);
if (!r.stdout || r.stdout.trim() === "") die(2, `cannot check: biome produced no JSON on stdout. stderr was:\n${(r.stderr ?? "").slice(0, 800)}`);

let report;
try {
  report = JSON.parse(r.stdout);
} catch (e) {
  die(2, `cannot check: biome's JSON was unparseable (${e instanceof Error ? e.message : String(e)})`);
}

// The vacuity check. When biome.json excludes these paths it prints "No files were processed in the
// specified paths" and reports zero diagnostics, which reads exactly like clean.
//
// `scanned` sums BOTH summary buckets and that is the only honest count here. This line used to also
// compute `filesChecked = summary.changed ?? summary.unchanged ?? 0` and print it: `changed` counts files
// the run REWROTE, which is always 0 under `biome lint` without --write, and `??` takes a present 0 rather
// than falling through, so every green run of this gate ended in the words "filesChecked=0". A gate whose
// stated purpose is to refuse a zero-file scan should not print a zero next to its own pass, and the
// mislabel is removed rather than explained away.
const scanned = (report.summary?.unchanged ?? 0) + (report.summary?.changed ?? 0);
if (scanned === 0) {
  die(2, `cannot check: biome processed 0 files across ${DIRS.join(", ")}. The paths are excluded by biome.json, so this gate would pass on an empty scan.`);
}

const counts = { error: 0, warning: 0, information: 0 };
for (const d of report.diagnostics ?? []) {
  if (EXPORT_VENDORED_EXEMPT.has(d.location?.path)) continue;
  const sev = d.severity === "info" ? "information" : d.severity;
  if (sev in counts) counts[sev]++;
}

if (WRITE) {
  writeFileSync(BASELINE, `${JSON.stringify({ "//": "Pinned diagnostic counts for the directories that no lint chain covered before scripts/lint-scope-gate.mjs. Ratchet these DOWN; the gate refuses any increase. Re-pin only with --write-baseline after a genuine reduction.", dirs: DIRS, filesScanned: scanned, counts }, null, 2)}\n`);
  console.log(`lint-scope-gate: baseline written: ${scanned} files, ${counts.error} error(s), ${counts.warning} warning(s), ${counts.information} info(s)`);
  process.exit(0);
}

if (!existsSync(BASELINE)) die(2, `cannot check: ${BASELINE} is missing. Re-pin with --write-baseline.`);
let base;
try {
  base = JSON.parse(readFileSync(BASELINE, "utf8"));
} catch (e) {
  die(2, `cannot check: the baseline is unparseable (${e instanceof Error ? e.message : String(e)})`);
}
if (typeof base.counts?.error !== "number" || typeof base.counts?.warning !== "number") die(2, "cannot check: the baseline carries no counts");

console.log(`lint-scope-gate: ${scanned} files scanned across ${DIRS.join(", ")}`);
// THIS LINE IS PARSED BY ANOTHER REPOSITORY. harness/scripts/ratchet-headroom-gate.mjs registers this
// gate and reads `errors N (pinned M...)` and `warnings N (pinned M...)` off this exact output to measure
// how much slack the ratchet is carrying. Adding ", ENFORCED" here broke both of its probes,
// because they required the bracket to close straight after the number, and that gate REFUSED with exit 2
// rather than reporting zero slack. Nothing warned the person editing this file, because the consumer is
// in a sibling repository with no dependency path to here. Its regexes now tolerate a trailing qualifier,
// so a future one costs nothing, but the NUMBER and the word `pinned` are load-bearing: keep them.
console.log(`  errors ${counts.error} (pinned ${base.counts.error}, ENFORCED), warnings ${counts.warning} (pinned ${base.counts.warning}, ENFORCED)`);
console.log(`  infos ${counts.information} (pinned ${base.counts.information}, NOT RATCHETED UPWARD: this count may rise without failing)`);

// The ratchet covers errors and warnings ONLY. Information-severity diagnostics are counted, printed and
// pinned, and a RISE in them does not fail: only a FALL is reported, as a prompt to re-pin. That asymmetry
// is deliberate and it is stated in the output because it was not, and the silence misled. MEASURED
// : a run printed "infos 1352 (pinned 1351)" and PASSED. The pin had gone stale under ten new
// files from another pass, and the line read as a third enforced count sitting one above its pin. A number
// printed beside the word "pinned" claims to be held. If this ever becomes enforced, add "information" to
// the loop below and re-pin in the same commit.
const grown = [];
for (const k of ["error", "warning"]) {
  if (counts[k] > base.counts[k]) grown.push(`${k}s rose from ${base.counts[k]} to ${counts[k]}`);
}
if (grown.length) {
  console.log(`\nLINT SCOPE GATE: ${grown.join("; ")}`);
  console.log("  These directories were linted by nothing until recently. Do not add to the debt: fix the new");
  console.log("  diagnostics, or ratchet the baseline DOWN, never up.");
  process.exit(1);
}
const shrunk = ["error", "warning", "information"].filter((k) => counts[k] < base.counts[k]);
if (shrunk.length) console.log(`  ${shrunk.join(", ")} count(s) are BELOW the pin; re-pin with --write-baseline.`);
console.log("\nLINT SCOPE GATE PASS");
