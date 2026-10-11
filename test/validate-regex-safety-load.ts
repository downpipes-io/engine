// validate-regex-safety-load: test/validate-regex-safety.ts gives a ReDoS verdict only when the
// machine is fast enough to measure, and still catches a real ReDoS.
//
// THE DEFECT. The sweep spawns a child per probe under a hard wall-clock cap, and the cap also
// covers the time Node takes to start that child. With a fixed 3-second cap, a loaded machine made
// safe patterns time out, and the sweep reported them as ReDoS. On 29 Sep two runs flagged four
// safe patterns this way. A load flake that reads as a security finding can bury a real one.
//
// HOW THIS FILE MAKES LOAD. It does not mock the spawn. It preloads a small module into every probe
// child (NODE_OPTIONS=--import) that blocks for a set time before the child starts its work. A
// counter file lets one scenario slow only some children, so load can rise or fall during a run.
// The children are the real probe children of the sweep, spawned the real way.
//
// WHAT IT PROVES.
//   1. A healthy machine: a safe pattern is linear, and the planted `^(a+)+$` is ReDoS.
//   2. Load from the start of the run: the whole sweep exits 2, CANNOT CHECK, with no FAIL line.
//   3. Load that rises after the start-of-run baseline: the kill re-measures the baseline, finds it
//      unhealthy, and gives CANNOT CHECK, not ReDoS.
//   4. Load that passes: the kill re-measures a healthy baseline, retries, and the safe pattern is
//      linear.
//   5. Moderate load: the cap grows with the baseline, a safe pattern is linear, and `^(a+)+$` is
//      still ReDoS.
// On main (before the baseline existed) scenario 2 reported a FAIL for every probed pattern, and the
// load of scenarios 3 and 4 made a safe pattern read as ReDoS.
//
// Run with: node test/validate-regex-safety-load.ts

import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { ephemeralTmpDir } from "./testutil.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import {
  BASELINE_HEALTHY_MS,
  type Baseline,
  CAP_PER_BASELINE,
  capFor,
  gradePattern,
  measureBaseline,
  PROBE_CEILING_MS,
  PROBE_FLOOR_MS,
} from "./validate-regex-safety.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SWEEP = path.join(HERE, "validate-regex-safety.ts");
const SAFE = "^[a-z]+$";
const PLANTED = "^(a+)+$";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean, detail = ""): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}${detail ? `\n         ${detail}` : ""}`);
  if (!cond) failures++;
}

// The slow-start module. It acts only in a probe child (argv carries --probe), so the process that
// runs the sweep starts at normal speed. Children numbered FROM..TO (1-based, counted in the counter
// file) block for SLOW_MS before they run.
const dir = ephemeralTmpDir("regex-safety-load-");
const stub = path.join(dir, "slow-start.mjs");
writeFileSync(
  stub,
  `import { readFileSync, writeFileSync } from "node:fs";
if (process.argv.includes("--probe")) {
  const plan = JSON.parse(process.env.REGEX_SAFETY_LOAD_PLAN);
  const n = Number(readFileSync(plan.counter, "utf8")) + 1;
  writeFileSync(plan.counter, String(n));
  if (n >= plan.from && n <= plan.to) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, plan.slowMs);
}
`,
);
const ORIGINAL_NODE_OPTIONS = process.env.NODE_OPTIONS;
let planNo = 0;

// load() turns the slow start on for children FROM..TO; the children inherit process.env at spawn time.
function load(slowMs: number, from: number, to: number): void {
  const counter = path.join(dir, `counter-${++planNo}`);
  writeFileSync(counter, "0");
  process.env.REGEX_SAFETY_LOAD_PLAN = JSON.stringify({ counter, slowMs, from, to });
  process.env.NODE_OPTIONS = `${ORIGINAL_NODE_OPTIONS ?? ""} --import=${pathToFileURL(stub).href}`.trim();
}
function noLoad(): void {
  delete process.env.REGEX_SAFETY_LOAD_PLAN;
  if (ORIGINAL_NODE_OPTIONS === undefined) delete process.env.NODE_OPTIONS;
  else process.env.NODE_OPTIONS = ORIGINAL_NODE_OPTIONS;
}
// The slow start for an unhealthy machine: over BASELINE_HEALTHY_MS, so the baseline cannot pass.
const TOO_SLOW_MS = BASELINE_HEALTHY_MS + 1000;
const fakeBaseline = (ms: number): Baseline => ({ ms, healthy: true, detail: "" });

console.log("-- the cap rule --");
ok(`a fast baseline gets the ${PROBE_FLOOR_MS}ms floor`, capFor(fakeBaseline(100)) === PROBE_FLOOR_MS);
ok(`the cap is ${CAP_PER_BASELINE} x a slower baseline`, capFor(fakeBaseline(2000)) === CAP_PER_BASELINE * 2000);
ok(`the cap never passes the ${PROBE_CEILING_MS}ms ceiling`, capFor(fakeBaseline(9000)) === PROBE_CEILING_MS);
ok("the healthy limit keeps every healthy cap within the ceiling", CAP_PER_BASELINE * BASELINE_HEALTHY_MS <= PROBE_CEILING_MS);

console.log("-- 1. a healthy machine --");
noLoad();
{
  const state = { baseline: measureBaseline() };
  ok(`the baseline is healthy with no load (${state.baseline.detail})`, state.baseline.healthy);
  const safe = gradePattern(SAFE, "", state);
  ok(`/${SAFE}/ is linear`, safe.kind === "linear", safe.reason);
  const planted = gradePattern(PLANTED, "", state);
  ok(`the planted /${PLANTED}/ is ReDoS`, planted.kind === "redos", planted.reason);
}

console.log("-- 2. load from the start: the whole sweep exits 2, CANNOT CHECK --");
load(TOO_SLOW_MS, 1, Number.MAX_SAFE_INTEGER);
{
  const r = spawnSync(process.execPath, [SWEEP], { encoding: "utf8", timeout: 300_000, env: process.env });
  const out = r.stdout ?? "";
  ok("the sweep exits 2", r.status === 2, `status=${r.status} signal=${r.signal} tail=${out.slice(-600)}`);
  const tail = `stdout tail: ${out.slice(-600)} stderr tail: ${(r.stderr ?? "").slice(-600)}`;
  ok("it says CANNOT CHECK: machine too slow to measure", out.includes("CANNOT CHECK: machine too slow to measure"), tail);
  ok("it declares a skip, not a pass", out.includes("VERDICT SKIPPED") && !out.includes("REGEX SAFETY SWEEP: PASS"), tail);
  ok("it prints no FAIL line, so no pattern reads as ReDoS", !/^\s*FAIL\b/m.test(out), out.match(/^\s*FAIL.*$/m)?.[0] ?? "");
  ok("it still grades the bounded patterns", /^\s*ok\s+.*\(bounded, no unbounded repetition/m.test(out));
}

console.log("-- 3. load rises after the start-of-run baseline --");
noLoad();
{
  const state = { baseline: measureBaseline() };
  ok(`the start-of-run baseline is healthy (${state.baseline.detail})`, state.baseline.healthy);
  load(TOO_SLOW_MS, 1, Number.MAX_SAFE_INTEGER);
  const v = gradePattern(SAFE, "", state);
  ok(`/${SAFE}/ is CANNOT CHECK, not ReDoS`, v.kind === "cannot-check", `${v.kind}: ${v.reason}`);
  ok("the kill re-measured the baseline and found it unhealthy", !state.baseline.healthy, state.baseline.detail);
}

console.log("-- 4. load that passes: the re-measured baseline is healthy, and the retry finishes --");
noLoad();
{
  const state = { baseline: measureBaseline() };
  load(TOO_SLOW_MS, 1, 1);
  const v = gradePattern(SAFE, "", state);
  ok(`/${SAFE}/ is linear after one slow child`, v.kind === "linear", `${v.kind}: ${v.reason}`);
}

console.log("-- 5. moderate load: the cap grows, and a real ReDoS is still caught --");
load(1500, 1, Number.MAX_SAFE_INTEGER);
{
  const state = { baseline: measureBaseline() };
  ok(`the baseline under 1500ms of start delay is healthy (${state.baseline.detail})`, state.baseline.healthy);
  ok(`the cap grew past the ${PROBE_FLOOR_MS}ms floor (${capFor(state.baseline)}ms)`, capFor(state.baseline) > PROBE_FLOOR_MS);
  const safe = gradePattern(SAFE, "", state);
  ok(`/${SAFE}/ is linear`, safe.kind === "linear", `${safe.kind}: ${safe.reason}`);
  const planted = gradePattern(PLANTED, "", state);
  ok(`the planted /${PLANTED}/ is still ReDoS`, planted.kind === "redos", `${planted.kind}: ${planted.reason}`);
}
noLoad();

console.log(failures === 0 ? "\nREGEX SAFETY LOAD: PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures, checks);
if (failures > 0) process.exit(1);
