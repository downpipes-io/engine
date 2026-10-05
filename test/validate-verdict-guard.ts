// Validates the shared completion guard ITSELF (test/lib/verdict-guard.ts) against the class it exists
// to close: a validator reaching exit 0 without ever reaching its own tally.
//
// A guard nobody tests is a guard that can quietly stop guarding, and this one is load-bearing for 373
// engine entry points, so each shape is driven as a REAL child process and the child's EXIT CODE is
// read, not inferred. The fixtures live in test/lib/verdict-guard-fixtures/ and are the shapes actually
// found in this repo:
//   drain                 an await that never settles (the measured case, test/validate-destsim-selftest.ts)
//   exit-zero-early       process.exit(0) before the tally
//   early-return          a return before the tally
//   swallowed-rejection   a rejection eaten by an empty .catch()
//   export-only           a file that only exports its work (test/validate-notify-crud.ts's old shape)
//   vacuous               a verdict declared over zero checks
//   pass / fail           the two honest outcomes, so the guard is proven NOT to be always-red
//   skipped               a declared skip, which must stay exit 0 and must not trip the guard
//
// Run: node test/validate-verdict-guard.ts

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verdictReached } from "./lib/verdict-guard.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "lib", "verdict-guard-fixtures");

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

interface Run {
  code: number | null;
  out: string;
  err: string;
}
function run(fixture: string): Run {
  const r = spawnSync(process.execPath, [join(FIX, fixture)], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });
  return { code: r.status, out: r.stdout ?? "", err: r.stderr ?? "" };
}

console.log("verdict-guard self-test: every way a validator can skip its own tally");

// ---- the shapes that must become exit 1 --------------------------------------------------------------
for (const [fixture, what] of [
  ["drain.ts", "an await that never settles"],
  ["exit-zero-early.ts", "a process.exit(0) before the tally"],
  ["early-return.ts", "an early return before the tally"],
  ["swallowed-rejection.ts", "a rejection swallowed by an empty catch"],
  ["export-only.ts", "a file that only exports its work"],
] as const) {
  const r = run(fixture);
  ok(`${what}: exits 1, not 0`, r.code === 1);
  ok(`${what}: says why on stderr`, r.err.includes("VERDICT GUARD"));
  ok(`${what}: names the entry point it fired for`, r.err.includes(fixture));
}

// The drain fixture must ALSO be shown to print a real FAIL and still have exited 0 without the guard,
// otherwise the test above proves only that the guard is loud, not that it caught anything real.
{
  const r = run("drain.ts");
  ok("drain: the run really did print FAIL assertions", /^\s*FAIL /m.test(r.out));
  ok("drain: its own verdict line is genuinely absent", !r.out.includes("DRAIN FIXTURE PASS"));
  ok("drain: the guard reports how far it got", /wrote \d+ bytes to stdout/.test(r.err));
}

// ---- nothing to check is not a pass ------------------------------------------------------------------
{
  const r = run("vacuous.ts");
  ok("a verdict declared over zero checks exits 1", r.code === 1);
  ok("a verdict declared over zero checks says so", r.err.includes("Nothing was checked"));
}
{
  // The guard's own worst failure mode: setting process.exitCode inside verdictReached is NOT final, so a
  // process.exit(0) on the next line overrode a refusal and the guard printed "Forcing exit 1" while the
  // process exited 0. vacuous.ts passed for the wrong reason, having no exit(0) after its call.
  const r = run("refused-then-exit-zero.ts");
  ok("a REFUSED verdict followed by process.exit(0) still exits 1", r.code === 1);
  ok("the guard says the refusal was overridden", r.err.includes("refused its verdict and then exited 0"));
  ok("and it still explains the original refusal", r.err.includes("Nothing was checked"));
}
{
  // The floor has to be the ASSERTION count, not "wrote something". This fixture prints three lines and
  // asserts nothing, so a bytes-written floor passes it and an assertion-line floor does not. Four real
  // validators were silent on pass and wrote their FAIL lines to stderr, which is how the weaker floor
  // was found to be too weak: on stdout, a run that asserted 313 things and one that asserted none looked
  // identical.
  const r = run("abstained.ts");
  ok("a verdict declared with output but no assertions exits 1", r.code === 1);
  ok("the abstain message says how far it got", /printed 0 assertion lines in \d+ bytes/.test(r.err));
  ok("the abstain message names the way out", r.err.includes("verdictReached(failures, checks)"));
  ok("a bytes-written floor would have passed it", r.out.length > 0);
}

// ---- the guard must NOT be always-red ---------------------------------------------------------------
{
  const r = run("pass.ts");
  ok("an honest pass still exits 0", r.code === 0);
  ok("an honest pass draws no guard message at all", !r.err.includes("VERDICT GUARD"));
  ok("an honest pass prints its own verdict", r.out.includes("PASS FIXTURE PASS"));
  // The log-reading half of a verification needs a fixed anchor too: reading only the exit code misses
  // a failing run whose log was grepped with a pattern the local grep does not support.
  ok("an honest pass prints the guard's canonical verdict line", r.out.includes("VERDICT: PASS"));
  ok("the canonical line carries the counts", /VERDICT: PASS failures=0 checks=2/.test(r.out));
}
{
  const r = run("fail.ts");
  ok("an honest failure exits 1 by its own route", r.code === 1);
  ok("an honest failure draws no guard message", !r.err.includes("VERDICT GUARD"));
  ok("an honest failure prints its own tally", r.out.includes("1 FAILURE(S)"));
  ok("a failing run is greppable as a FIXED string, not a regex", r.out.includes("VERDICT: FAIL"));
}

// ---- a declared skip stays a skip -------------------------------------------------------------------
{
  const r = run("skipped.ts");
  ok("a declared skip stays exit 0", r.code === 0);
  ok("a declared skip is greppable on one line", r.out.includes("VERDICT SKIPPED:"));
  ok("a declared skip does not trip the guard", !r.err.includes("VERDICT GUARD"));
}

// ---- the guard's own teeth, read from its source ----------------------------------------------------
// If someone removes the exit listener or the forced exit code, every check above would still pass for
// the wrong reason on some future refactor, so assert the mechanism is present as well as effective.
{
  const src = spawnSync("cat", [join(HERE, "lib", "verdict-guard.ts")], { encoding: "utf8" }).stdout ?? "";
  ok("the guard installs an exit listener", /process\.on\(\s*"exit"/.test(src));
  ok("the guard forces a non-zero exit code", /process\.exitCode\s*=\s*1/.test(src));
  ok("the guard writes its message to stderr, not the stream it counts", /process\.stderr\.write/.test(src));
}

console.log(failures === 0 ? `\nVERDICT GUARD SELF-TEST PASS (${checks} checks)` : `\n${failures} FAILURE(S)`);
verdictReached(failures, checks);
if (failures > 0) process.exit(1);
