// Validator reachability gate.
//
// A test file that no npm script reaches is not coverage, it is a file. This repo had several: they
// pass when run by hand, are counted when someone lists the suite, and gate nothing. The failure is
// silent by construction, because a validator that never runs never fails.
//
// This gate lists every test/validate-*.ts and fails on any that no chain can reach. Reachability is
// TRANSITIVE: validate-api.ts is named by the chain and imports validate-api-pure.ts and
// validate-api-shared.ts, so those are reached too. Only genuinely orphaned files fail.
//
// Reachability is measured from the GATING chains only, not from any npm script. That distinction is
// the whole point: `validate-bulk-create.ts` was reachable from `validate:otlp-push`, a narrow target
// no CI job invokes, so "some script mentions it" was true while "anything gates it" was false.
// GATING_ENTRYPOINTS below is the set a CI job actually runs; a validator reachable only from
// somewhere else is an orphan.
//
// Usage:
//   node scripts/validator-reachability-gate.mjs            report, exit 0
//   node scripts/validator-reachability-gate.mjs --enforce   exit 1 on any orphan

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { blankComments, blankCommentsAndStrings } from "./lib/blank-comments.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const TEST_DIR = join(ROOT, "test");
const ENFORCE = process.argv.includes("--enforce");

// Files that are deliberately not in any chain, each with the reason. An entry here is a decision on
// the record, which is the point: the alternative is an orphan nobody ever notices.
const EXEMPT = new Map([
  ["validate-ramp-settle-console-client.ts", "drives the real console update client against the real engine router (own header); reachable only via validate:workspace, dropped above for the same reason"],
  ["validate-console-keygen-roundtrip.ts", "cross-repo: needs ../console (own header). Reachable only via validate:workspace in the private repo's cross-repo CI job, dropped above; not orphaned there, just unreachable from a standalone export"],
  // (empty today; add "validate-x.ts" -> "why it is not chained" as needed)
]);

// The scripts a CI job actually runs. Keep this in step with .github/workflows/ci.yml.
// Exported tree only: validate:workspace, validate:schema-conformance, coverage removed here -- each runs only from a CI job that checks out a private sibling repository (see workflow-transform.mjs), which cannot travel with a standalone public export; keeping them in GATING_ENTRYPOINTS would fail reachability against a workflow this tree no longer ships
const GATING_ENTRYPOINTS = [
  "validate",
  // Runs in CI as its own step (see .github/workflows/ci.yml). Deliberately NOT inside `validate`: it runs
  // a full gate per guard, so chaining it would multiply the cost of every validate run.
  "validate:cf-guards",
  // Runs in its own job (stamp-idempotency, .github/workflows/ci.yml): real wrangler builds, kept out of
  // `validate` for the same reason as cf-guards above, cost rather than skip risk.
  "validate:stamp-idempotency",
  "lint",
  "test:runtime",
  "test:property",
  "test:vitest",
  "typecheck:test",
];

const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const scripts = pkg.scripts ?? {};

// Expand `npm run x` references transitively so a validator inside a sub-script still counts, while a
// script no gating entrypoint reaches does not.
//
// It follows TWO forms of reference, and the second is load-bearing: `validate` no longer holds the chain
// itself, it invokes scripts/run-gate-chain.mjs over `validate:chain` so every member runs instead of the
// chain stopping at its first red. Without following that indirection this gate would read `validate` as a
// one-command script naming no validator at all and declare the entire suite orphaned. Kept as a pattern
// rather than a second hard-coded entrypoint name so wrapping another chain the same way stays correct here.
function expand(name, seen = new Set()) {
  if (seen.has(name) || scripts[name] === undefined) return "";
  seen.add(name);
  const body = String(scripts[name]);
  let out = body;
  for (const m of body.matchAll(/npm run ([A-Za-z0-9:_-]+)/g)) out += ` ${expand(m[1], seen)}`;
  for (const m of body.matchAll(/run-gate-chain\.mjs\s+([A-Za-z0-9:_-]+)/g)) out += ` ${expand(m[1], seen)}`;
  return out;
}
const allScriptText = GATING_ENTRYPOINTS.map((e) => expand(e)).join(" && ");

// ANTI-VACUITY. Everything below is computed from this list, and the exit code is the orphan count alone, so
// an empty list reports "every validator is reachable" and exits 0. That is the exact failure this gate was
// written to catch, one level up: a check that cannot fail on an empty input is not a check. A missing test
// directory and a directory whose contents no longer match the naming convention both land here.
if (!existsSync(TEST_DIR)) {
  console.error(`[validator-reachability] FAIL: ${TEST_DIR} does not exist, so there is nothing to check.`);
  process.exit(1);
}
const validators = readdirSync(TEST_DIR)
  .filter((f) => f.startsWith("validate-") && f.endsWith(".ts"))
  .sort();
if (validators.length === 0) {
  console.error(`[validator-reachability] FAIL: no test/validate-*.ts found under ${TEST_DIR}.`);
  console.error("Either the validators are gone or the naming convention changed; a pass here would prove nothing.");
  process.exit(1);
}

// Seed: every validator named directly in any npm script.
const reached = new Set(validators.filter((f) => allScriptText.includes(f)));

// blankCommentsAndStrings (scripts/lib/blank-comments.mjs, shared with verdict-guard-gate.mjs and
// crossrepo-typecheck-gate.mjs, consolidated 2026-08-03 from three independently-written copies of the
// same scan) additionally blanks the INTERIOR of every string and template literal (keeping delimiters
// and newlines, so offsets stay aligned with `src`/the raw file), used ONLY to verify a candidate import
// match below is real code, never to read a path from (a real module specifier IS a string, so
// blankComments -- which leaves strings intact -- is still what the regexes below match against).
//
// WHY THIS MATTERS HERE (2026-08-03): blankComments strips comments but leaves string
// content untouched, and the two matchAll regexes below have no requirement that a `from "./x.ts"` or
// `import("./x.ts")` match sit in real import syntax rather than inside an unrelated STRING that
// merely contains that text. Confirmed live: adding a genuine orphan (test/validate-guard-attack-
// orphan.ts, reachable from nothing) made this gate correctly report 1 orphaned; adding one decoy
// string to an already-reached file -- `'see also from "./validate-guard-attack-orphan.ts" for...'`,
// never a real import -- made the orphan vanish, 0 orphaned, exit 0. Same class this module's own
// header describes for a commented-out import, one level worse: a STRING was never blanked at all,
// where a comment at least gets blanked today.
const isRealKeyword = (structural, index, keyword) => structural.slice(index, index + keyword.length) === keyword;

// Transitive closure over relative imports, so a helper pulled in by a chained validator counts.
const importsOf = (file) => {
  let raw = "";
  try {
    raw = readFileSync(join(TEST_DIR, file), "utf8");
  } catch {
    return [];
  }
  const src = blankComments(raw); // comments blanked, strings intact -- module paths live in strings
  const structural = blankCommentsAndStrings(raw); // comments AND strings blanked, offsets aligned with src/raw
  const out = [];
  for (const m of src.matchAll(/from\s+"\.\/([A-Za-z0-9_.-]+\.ts)"/g)) {
    if (isRealKeyword(structural, m.index, "from")) out.push(m[1]);
  }
  for (const m of src.matchAll(/import\(\s*"\.\/([A-Za-z0-9_.-]+\.ts)"\s*\)/g)) {
    if (isRealKeyword(structural, m.index, "import")) out.push(m[1]);
  }
  return out;
};

let grew = true;
while (grew) {
  grew = false;
  for (const f of [...reached]) {
    for (const dep of importsOf(f)) {
      if (validators.includes(dep) && !reached.has(dep)) {
        reached.add(dep);
        grew = true;
      }
    }
  }
}

// GATING_ENTRYPOINTS is a CLAIM about CI, and until now nothing checked it. Every validator in this repo is
// reachable from that list, which is only worth anything if CI actually runs each entry. If an entry is
// renamed, or a CI step is dropped, the list quietly starts describing a pipeline that no longer exists and
// every validator behind it is orphaned without a single gate going red.
//
// That is not hypothetical here. Three gates in this workspace were found in one sitting doing exactly this
// from the other direction: present, passing locally, invoked by no CI job. This closes the loop for the
// entries this file depends on.
const wfDir = join(HERE, "..", ".github/workflows");
if (existsSync(wfDir)) {
  const ci = readdirSync(wfDir)
    .filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"))
    .map((f) => readFileSync(join(wfDir, f), "utf8"))
    .join("\n");
  // The escape here was a botched find-replace: its replacement string was a fragment of the source line
  // below it, so nothing was ever escaped. It happened to be inert, because no entrypoint name in this repo
  // contains a regex metacharacter. It would not have stayed inert: an unescaped `.` in a name matches ANY
  // character, so an entrypoint written `validate.workspace` would have matched the CI line for
  // `validate:workspace` and reported a script CI does not run as run.
  const escapeForRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const unrun = GATING_ENTRYPOINTS.filter((e) => !new RegExp(`npm run ${escapeForRegex(e)}(\\s|"|'|$)`, "m").test(ci));
  if (unrun.length > 0) {
    console.error("");
    console.error("GATING_ENTRYPOINTS names scripts that NO CI workflow runs, so the validators behind them gate nothing:");
    for (const e of unrun) console.error(`  ${e}`);
    console.error("Either add the CI step, or remove the entry and accept those validators are orphaned.");
    process.exit(1);
  }
  console.log(`[validator-reachability] all ${GATING_ENTRYPOINTS.length} gating entrypoints are run by a CI workflow`);
} else {
  // Not a skip that reads as a pass: this repo HAS workflows, so their absence is a broken checkout rather
  // than a repo that never had CI, and the gate says so instead of quietly dropping half of itself.
  console.error("[validator-reachability] FAIL: no .github/workflows here, so the entrypoint-vs-CI check could not run.");
  process.exit(1);
}

const orphans = validators.filter((f) => !reached.has(f) && !EXEMPT.has(f));

console.log(`[validator-reachability] ${validators.length} validators, ${reached.size} reachable from an npm script, ${orphans.length} orphaned, ${EXEMPT.size} exempt`);
if (orphans.length > 0) {
  console.log("\nORPHANED VALIDATORS (no npm script reaches them, directly or by import):");
  for (const f of orphans) console.log(`  test/${f}`);
  console.log("\nWire each into a chain, or add it to EXEMPT in this file with the reason.");
}
if (ENFORCE && orphans.length > 0) {
  console.error(`\n[validator-reachability] FAIL (enforce): ${orphans.length} validator(s) reach no npm script, so they gate nothing.`);
  process.exit(1);
}
console.log(orphans.length === 0 ? "[validator-reachability] OK: every validator is reachable." : "[validator-reachability] report mode: not failing the build.");
