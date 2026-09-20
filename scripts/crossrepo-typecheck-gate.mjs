// Cross-repo type-check gate.
//
// A validator that imports a SIBLING repo cannot be type-checked by a single-repo checkout. The engine has one
// (test/validate-console-keygen-roundtrip.ts imports the console's own key ceremony), and when it was added it
// broke the `quality` CI job with TS2307 "cannot find module ../../console/src/keygen.ts", because that job
// checks out the engine alone. It also broke `npm run typecheck:test` on a developer box, differently: with the
// sibling present, tsc followed into the console's browser code and failed for a missing DOM lib instead. Red
// both ways, and neither error said anything about the engine.
//
// The split that fixes it is small: those files are excluded from tsconfig.test.json and included by
// tsconfig.workspace.json, which adds DOM and is run by the Cross-repo gates job where the sibling is checked
// out. The split is also the risk, so this gate holds it in BOTH directions:
//
//   1. Every test file that imports a sibling repo is excluded from tsconfig.test.json.
//      Without this the next such validator breaks `quality` exactly as the first one did.
//   2. Every one of them is type-checked by tsconfig.workspace.json.
//      Without this the exclusion in 1 silently means "never type-checked anywhere".
//   3. Every one of them is RUN by `npm run validate:workspace`.
//      Type-checking is not execution; a cross-repo validator nothing runs proves nothing.
//   4. Nothing else is excluded from tsconfig.test.json.
//      This is the direction that matters most. Excluding a file is how a real type error gets hidden, and
//      "add it to the exclude list" is the cheapest wrong fix available. A non-cross-repo entry fails here.
//   5. `validate:workspace` actually invokes `typecheck:workspace`.
//      Otherwise 2 is a claim about a config no chain runs.
//
// Membership is decided by asking tsc, via --showConfig, which files each config RESOLVES to, rather than by
// reading the exclude arrays. That way any spelling of the exclusion is judged by its effect.
//
// Usage:
//   node scripts/crossrepo-typecheck-gate.mjs            report, exit 0
//   node scripts/crossrepo-typecheck-gate.mjs --enforce   exit 1 on any breach

import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { blankComments, blankCommentsAndStrings } from "./lib/blank-comments.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const TEST_DIR = join(ROOT, "test");
const ENFORCE = process.argv.includes("--enforce");

// The sibling repos a workspace checkout puts beside this one. An import of ../../<name>/ reaches out of this
// repo, and nothing inside a single-repo checkout can resolve it.
const SIBLINGS = ["console", "control-plane", "docs", "downpipe", "website", "harness"];

const problems = [];
const fail = (msg) => problems.push(msg);

// ---- 1. Which test files import a sibling repo. -----------------------------------------------------------
// Comment-blanked first: a commented-out cross-repo import is not one, and counting it would put a file on the
// exclusion list that has no business there, which rule 4 would then report as a breach. This is the same
// comment blindness that once made the reachability gate call an orphan wired.
//
// STRING-blanked too, to decide which of the comment-blanked matches below are real (R-109, engine-guard-
// attack, 2026-08-03, closed here as part of the three-gate consolidation onto scripts/lib/blank-comments.mjs).
// blankComments alone leaves string content untouched, and the match itself is read out of that string-intact
// text (a real module specifier IS a string, so the path has to come from there). Left unchecked, this cuts
// BOTH ways, opposite to R-106/R-107's false negatives:
//   - OVER-TRIGGER (false FAIL): a file with no real import but a decoy string shaped like one, e.g.
//     `'note: from "../../console/x.ts" is what a real import would look like'`, was treated as a genuine
//     cross-repo importer by rules 1-3, demanding an exclusion and a validate:workspace entry it has no
//     business needing. Confirmed live: adding exactly that decoy to an ordinary reached file made the gate
//     fail with two false FAILs naming it.
//   - BLIND (false PASS): rule 4 exists to catch a file added to tsconfig.test.json's exclude array WITHOUT a
//     real cross-repo import (excluding a file is the cheapest wrong fix for a real type error, this module's
//     own comment says so). The same decoy string that trips rules 1-3 also satisfies rule 4's
//     `crossRepoFiles.has(file)` check, so a file excluded for no legitimate reason and merely carrying that
//     decoy sails through as "earned", exit 0. Confirmed live: excluding a decoy-only file from
//     tsconfig.test.json and wiring it into validate:workspace (so rules 1-3 also stay quiet) produced a clean
//     "ok" report with no findings at all.
// Fixed by requiring the matched leading keyword (`from`, `import(`, or `require(`) to still be present,
// unblanked, at the same offset in the structural (comment- AND string-blanked) view before a match counts.
// A decoy string blanks that keyword text away to spaces in the structural view (it is string interior); a
// real import leaves it untouched, since it is real code. Verified corpus-clean: 0 static specifiers on the
// real tree before and after this fix (the two existing cross-repo validators both use a computed, not
// static, specifier, so they were never in this list; see the "computed at run time" branch below, which is
// deliberately never gated and needs no structural check, per rule 4's own comment on why it stays report-only).
const walk = (dir, prefix = "") => {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "vitest" || entry.name === "node_modules") continue;
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) out.push(...walk(join(dir, entry.name), rel));
    else if (entry.name.endsWith(".ts")) out.push(rel);
  }
  return out;
};

// Only a STATIC module specifier matters here, and the distinction is not academic. This repo already had a
// cross-repo validator before the one that broke: test/validate-ramp-settle-console-client.ts reaches the
// console's update client through `await import(resolve(HERE, "../../console", ...))`. tsc cannot resolve a
// computed specifier, so that file type-checks in a single-repo checkout and must NOT be excluded from
// tsconfig.test.json. A substring search for "../../console/" flags it anyway, and would then demand an
// exclusion that hides its real type errors. So the specifier is matched where it is used as one: after
// `from`, `import(` or `require(`, as a literal.
const SIB = SIBLINGS.join("|");
// Group 1 captures the leading keyword text itself (not just matched non-capturing), so the structural check
// below can compare that exact span against the comment-AND-string-blanked view at the same offset: real code
// leaves it untouched there, a decoy sitting inside a string blanks it to spaces.
const STATIC_SPECIFIER = new RegExp(String.raw`\b(from|import\s*\(|require\s*\()\s*(['"])(\.\./\.\./(${SIB})/[^'"]*)\2`, "g");
// Recorded for the report only, never gated on: a computed path that reaches a sibling at run time. It says
// the file needs the workspace to RUN, which is why validate:workspace exists, but it says nothing about the
// type-check split this gate holds.
const RUNTIME_PATH = new RegExp(String.raw`(['"])(\.\./\.\./(?:\.\./)?(${SIB}))(?:/[^'"]*)?\1`, "g");

const crossRepo = [];
const runtimeOnly = [];
for (const rel of walk(TEST_DIR).sort()) {
  const raw = readFileSync(join(TEST_DIR, rel), "utf8");
  const src = blankComments(raw); // comments blanked, strings intact -- the specifier is read out of here
  const structural = blankCommentsAndStrings(raw); // comments AND strings blanked, offsets aligned with src/raw
  const statics = [...src.matchAll(STATIC_SPECIFIER)]
    .filter((m) => structural.slice(m.index, m.index + m[1].length) === m[1])
    .map((m) => m[4]);
  if (statics.length > 0) {
    crossRepo.push({ file: `test/${rel}`, sibling: [...new Set(statics)].sort().join(", ") });
    continue;
  }
  // RUNTIME_PATH is deliberately NOT structural-checked: its whole job is to find a sibling path living
  // inside a bare string argument (no leading from/import(/require( keyword at all, e.g.
  // `resolve(HERE, "../../console", ...)`), and it is report-only, never gated (rule 4 above explains why).
  const runtime = [...src.matchAll(RUNTIME_PATH)].map((m) => m[3]);
  if (runtime.length > 0) runtimeOnly.push({ file: `test/${rel}`, sibling: [...new Set(runtime)].sort().join(", ") });
}

// ---- 2. What each config actually type-checks. ----------------------------------------------------------
// tsc resolves `extends`, include and exclude and prints the concrete file list, so this measures effect
// rather than intent. A config that cannot be read at all is a failure, not an empty answer: an empty file
// list would otherwise satisfy every rule below by vacuity.
// Invoked by explicit path to node_modules/typescript-7/bin/tsc, not "npx tsc": "typescript" (6.x, the
// compiler-API package) and "typescript-7" (the aliased 7.x package this CLI comes from) both declare a
// "tsc" bin, so node_modules/.bin/tsc is whichever one npm linked last.
const TSC = join(ROOT, "node_modules", "typescript-7", "bin", "tsc");
const filesOf = (config) => {
  let raw;
  try {
    raw = execFileSync("node", [TSC, "-p", config, "--showConfig"], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 32 * 1024 * 1024,
    });
  } catch (err) {
    fail(`${config}: tsc --showConfig failed, so this gate cannot tell what it type-checks: ${err.message}`);
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    fail(`${config}: tsc --showConfig did not return JSON: ${err.message}`);
    return null;
  }
  return new Set((parsed.files ?? []).map((f) => f.replace(/^\.\//, "")));
};
// There is no separate "did it resolve to nothing" guard because tsc will not produce a config that matches no
// input: it exits with "No inputs were found in config file" and the catch above reports that. The vacuity risk
// that IS reachable is the workspace config quietly covering LESS than the single-repo one, which the
// containment check below rules out.

const single = filesOf("tsconfig.test.json");
const workspace = filesOf("tsconfig.workspace.json");

// ---- 3. The npm scripts, for rules 3 and 5. -------------------------------------------------------------
const scripts = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).scripts ?? {};
const workspaceChain = scripts["validate:workspace"] ?? "";
if (!workspaceChain) fail("package.json has no validate:workspace script, so no cross-repo validator is run at all");
if (!scripts["typecheck:workspace"]) fail("package.json has no typecheck:workspace script");
else if (!workspaceChain.includes("typecheck:workspace")) {
  fail("validate:workspace does not invoke typecheck:workspace, so tsconfig.workspace.json is never applied by a chain");
}

// ---- 4. The five rules. ---------------------------------------------------------------------------------
if (single && workspace) {
  const crossRepoFiles = new Set(crossRepo.map((c) => c.file));

  // Containment. The workspace config exists to check MORE than the single-repo one, never less, so anything
  // the single-repo config covers must still be covered here. Narrowing its include, or excluding something
  // from it, would otherwise reduce what CI type-checks while every rule below still passed.
  const dropped = [...single].filter((f) => !workspace.has(f)).sort();
  if (dropped.length > 0) {
    fail(`tsconfig.workspace.json drops ${dropped.length} file(s) that tsconfig.test.json type-checks, starting with ${dropped[0]}: it must cover a superset, not a different set`);
  }

  for (const { file, sibling } of crossRepo) {
    if (single.has(file)) {
      fail(`${file} imports ../../${sibling}/ but is type-checked by tsconfig.test.json, which the single-repo quality job runs without that sibling: it will fail there with TS2307`);
    }
    if (!workspace.has(file)) {
      fail(`${file} imports ../../${sibling}/ and is excluded from tsconfig.test.json, but tsconfig.workspace.json does not type-check it either, so it is type-checked NOWHERE`);
    }
    if (workspaceChain && !workspaceChain.includes(file.replace(/^test\//, ""))) {
      fail(`${file} imports ../../${sibling}/ but validate:workspace does not run it, so nothing executes it`);
    }
  }

  // Rule 4. Anything the workspace config type-checks and the single-repo one does not is, by construction,
  // excluded from tsconfig.test.json. Every such file must earn it by importing a sibling.
  for (const file of [...workspace].sort()) {
    if (single.has(file)) continue;
    if (crossRepoFiles.has(file)) continue;
    fail(`${file} is excluded from tsconfig.test.json but imports no sibling repo: excluding a file is not a fix for a type error in it`);
  }
}

// ---- 5. Report. -----------------------------------------------------------------------------------------
console.log(`cross-repo validators, static specifier (gated): ${crossRepo.length}`);
for (const { file, sibling } of crossRepo) console.log(`  ${file}  ->  ${sibling}`);
console.log(`cross-repo validators, computed at run time (reported, not gated): ${runtimeOnly.length}`);
for (const { file, sibling } of runtimeOnly) console.log(`  ${file}  ->  ${sibling}`);
console.log(`tsconfig.test.json files: ${single ? single.size : "unreadable"}`);
console.log(`tsconfig.workspace.json files: ${workspace ? workspace.size : "unreadable"}`);

if (problems.length === 0) {
  console.log("ok  the single-repo and workspace type-checks cover every file exactly once between them");
  process.exit(0);
}
console.log(`\n${problems.length} problem${problems.length === 1 ? "" : "s"}:`);
for (const p of problems) console.log(`  FAIL ${p}`);
if (!ENFORCE) {
  console.log("\n(reporting only, pass --enforce to fail)");
  process.exit(0);
}
process.exit(1);
