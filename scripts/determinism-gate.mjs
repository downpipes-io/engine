#!/usr/bin/env node
// DETERMINISM GATE: run a population of chain members REPEATEDLY on one unchanged tree and report any
// member whose VERDICT is not a function of that tree.
//
// WHY THIS EXISTS, and it is not "flaky tests are annoying". A flake is worse than an ordinary failing test
// in a way that has already cost this repo a finding. In a mutation run a site is recorded as HELD if some
// member goes red under the plant. A member that reds on its own, unprompted, CREDITS A GUARD THAT MAY NOT
// EXIST: the site is filed as protected and nobody looks at it again. That is the anti-detector shape. It
// does not produce a noisy red somebody investigates, it produces A CONFIDENT GREEN IN THE LEDGER, and the
// standing rule here is that false negatives matter as much as false positives because nobody investigates
// a green.
//
// MEASURED, on this repo. test/validate-passkey.ts failed 1 run in 240 on a pristine tree at 4397fd69 and
// was the SOLE KILLER of arm B7 in an earlier re-run of the mutation corpus, so one manufactured red
// turned one could-not-check into a KILLED. The cause was a product ordering defect (the passkey witness
// epoch was opened after the credential's createdAt had already been taken from the clock, so a millisecond
// tick between the two reads made a brand-new credential read as older than the record-keeping). It cost
// the other way too: several passes have spent hours chasing inherited reds that were environmental.
//
// WHAT THIS ADDS THAT THE EXISTING INSTRUMENTS CANNOT SEE, because three passes have now rebuilt the same
// harness and the rule is to extend rather than write another. scripts/guard-mutation-harness.mjs decides
// arm LIVENESS from a member's stable output, self-calibrated over TWO pristine runs; its baseline compares
// the two runs' LINES and discards their EXIT CODES, so a member that passes once and fails once is folded
// into the intersection and never named. scripts/gate-red-proof.mjs plants a violation and demands a red,
// which grades a gate's SENSITIVITY on a deliberately broken tree and says nothing about repeatability on
// an unbroken one. Neither answers "does this member return the same verdict twice", and that is the only
// question here. Both of those files are reused rather than reimplemented: `runMember` and `classify` are
// imported from the harness, so the exit-code discipline below is the harness's own.
//
// AN EXIT CODE READ FROM A PIPE IS UNREAD. `runMember` writes each run's code to a file with `echo $?` and
// reads it back, which is why it is imported rather than replaced by a spawnSync here.
//
// SERIAL BY CONSTRUCTION. Members are run one at a time and never in parallel. Concurrency is a prime cause
// of the very defect this gate hunts, and a detector that manufactures the thing it detects is worthless.
// It is also why this is not enrolled in validate:chain: repeats x members is minutes to hours, and a gate
// nobody can afford to run is a gate that gets switched off.
//
// THE VERDICT CONVENTION, and refusal outranks a pass. 0 clean, 1 a finding, 2 could-not-check. A member
// that could not be run, or whose exit code could not be read, makes this gate REFUSE rather than report a
// clean sweep over the members that did run, because "no member flaked" is also true of a run that graded
// none. An uncaught throw exits 2, not 1: a crash has established nothing, and reporting a crash as a
// finding is the same false claim one level up.
//
// THE POPULATION IS ASSERTED, NOT ASSUMED. The chain is split from package.json and must meet a floor, the
// selection must be non-empty, and the number of members graded and runs performed is printed beside the
// verdict. Every one of those refuses rather than passes when it cannot be established.
//
// THE FLOOR IS REQUIRED AND HAS NO DEFAULT, which this file learned about itself the day it landed. It
// shipped defaulting to 422 while validate:chain stood at 422, and the chain reached 423 hours later, so the
// default had quietly become a member of slack nobody chose. `run-gate-chain.mjs` states the rule this now
// follows: the floor is the member count rather than a round number under it, so an addition is frictionless
// and a removal costs a number somebody has to write on purpose.
//
// THE DETECTOR CARRIES ITS OWN POSITIVE CONTROL. `--self-test` runs a deliberately coin-flipping member and
// a deliberately stable one through the same code path as a real run and asserts this gate reports the
// first and not the second. A flake detector that has never seen a flake is not a proven detector, and this
// workspace has shipped a gate whose zero meant only that its subject was empty.
//
// Usage:
//   node scripts/determinism-gate.mjs --repeats 3 --min-members 423 [--chain validate:chain]
//                                               [--only <substring>] [--max-members N]
//   node scripts/determinism-gate.mjs --self-test
//
// House style: Australian English, no em dashes, no rule-of-three.

import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { classify, runMember } from "./guard-mutation-harness.mjs";

/** This file's own path, so the self-test can drive the CLI rather than only its exported functions. */
const SELF = fileURLToPath(import.meta.url);

const TAG = "[determinism]";
const CLEAN = 0;
const FOUND_SOMETHING = 1;
const CANNOT_RUN = 2;
const ROOT = process.cwd();

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i > 0 && process.argv[i + 1] !== undefined ? process.argv[i + 1] : fallback;
}

// gradeOne runs ONE member `repeats` times and returns the distribution of what came back. It records the
// CLASSIFIED outcome beside the raw code: two runs that both exit 1 for different reasons are still a
// stable verdict, and two runs that differ at all are not, so the raw code is what decides and the class is
// carried for the report. A code that could not be read is its own outcome and is never defaulted to zero.
export function gradeOne(cmd, root, scratch, repeats) {
  const codes = [];
  const classes = [];
  let unreadable = 0;
  for (let i = 0; i < repeats; i++) {
    let r;
    try {
      r = runMember(cmd, root, scratch);
    } catch (e) {
      unreadable++;
      codes.push(null);
      classes.push(`unreadable(${e?.message ?? e})`);
      continue;
    }
    if (typeof r.code !== "number" || Number.isNaN(r.code)) {
      unreadable++;
      codes.push(null);
      classes.push("unreadable");
      continue;
    }
    codes.push(r.code);
    classes.push(classify(r));
  }
  const distinct = [...new Set(codes.map((c) => String(c)))];
  return { cmd, codes, classes, unreadable, stable: unreadable === 0 && distinct.length === 1, distinct };
}

// selectMembers establishes the POPULATION. Every branch here refuses rather than returning a short list,
// because a silently shortened population is exactly how a sweep comes to report a clean result over work
// it did not do.
export function selectMembers(pkgScripts, chain, minMembers, only, maxMembers) {
  if (!pkgScripts[chain]) return { error: `package.json has no "${chain}" script, so the population this gate grades has vanished rather than passed` };
  const all = pkgScripts[chain].split("&&").map((s) => s.trim()).filter(Boolean);
  if (all.length < minMembers) return { error: `"${chain}" splits to only ${all.length} member(s), under the floor of ${minMembers}. A sweep this small has not proven what a full chain proves` };
  let sel = only ? all.filter((m) => m.includes(only)) : all;
  if (sel.length === 0) return { error: `--only ${JSON.stringify(only)} selected 0 of ${all.length} member(s). "No member flaked" is also true of a run that graded none` };
  const capped = maxMembers > 0 && sel.length > maxMembers;
  if (capped) sel = sel.slice(0, maxMembers);
  return { all: all.length, selected: sel, capped };
}

function selfTest() {
  const scratch = mkdtempSync(join(tmpdir(), "determinism-selftest-"));
  let bad = 0;
  const check = (name, cond) => {
    console.log(`${cond ? "  ok  " : "  FAIL"} ${name}`);
    if (!cond) bad++;
  };
  // KNOWN POSITIVE: a member whose exit code is a coin flip. If this gate cannot report this, it cannot
  // report anything, and its zeros are worthless.
  const flaky = `node -e "process.exit(Math.random() < 0.5 ? 0 : 1)"`;
  let sawUnstable = false;
  for (let attempt = 0; attempt < 8 && !sawUnstable; attempt++) {
    if (!gradeOne(flaky, ROOT, scratch, 12).stable) sawUnstable = true;
  }
  check("known positive: a coin-flipping member is reported as UNSTABLE", sawUnstable);
  // KNOWN NEGATIVE: a member that always passes must never be reported. A detector that fires on everything
  // is the same as one that fires on nothing.
  check("known negative: an always-passing member is reported as stable", gradeOne(`node -e "process.exit(0)"`, ROOT, scratch, 6).stable);
  // A member that always FAILS the same way is stable, not flaky. This gate grades repeatability, never
  // correctness, and conflating the two would turn every genuine red into a flake report.
  check("known negative: an always-failing member is stable, because this grades repeatability not correctness", gradeOne(`node -e "process.exit(1)"`, ROOT, scratch, 6).stable);
  // The population floor must bite.
  check("population: a chain under the floor REFUSES", Boolean(selectMembers({ c: "a && b" }, "c", 10, null, 0).error));
  check("population: an --only that selects nothing REFUSES", Boolean(selectMembers({ c: "a && b" }, "c", 1, "zzz", 0).error));
  check("population: a missing chain REFUSES", Boolean(selectMembers({}, "nope", 1, null, 0).error));
  check("population: a satisfied floor is accepted", selectMembers({ c: "a && b" }, "c", 2, null, 0).selected?.length === 2);
  // The floor being REQUIRED lives in main() rather than in selectMembers, so it is proved by driving this
  // file's own CLI rather than by asserting against a function the CLI might stop calling. Both arms: no
  // floor must refuse, and a floor below 2 must refuse for the same reason.
  check("cli: omitting --min-members REFUSES with exit 2", runMember(`node ${JSON.stringify(SELF)} --repeats 2`, ROOT, scratch).code === CANNOT_RUN);
  check("cli: --repeats 1 REFUSES with exit 2, because one run cannot disagree with itself", runMember(`node ${JSON.stringify(SELF)} --repeats 1 --min-members 1`, ROOT, scratch).code === CANNOT_RUN);
  // A PASS FROM THIS GATE MUST SAY WHAT IT DID NOT COVER, and that is asserted rather than trusted to
  // survive an edit. Measured: this gate graded validate-cf-pace STABLE across 5 repeats at the
  // commit where it was still broken, because it runs each member ALONE and that member only failed under
  // the load of its 432 neighbours. A detector with a known positive it cannot see must say so on every
  // clean run, or the next reader takes the clean run for "no flaky members".
  {
    const clean = runMember(`node ${JSON.stringify(SELF)} --repeats 2 --min-members 1 --only validate-verdict-guard.ts`, ROOT, scratch);
    check("cli: a PASS names its SCOPE, that each member ran alone", clean.code === CLEAN && clean.log.includes("SCOPE: each member ran ALONE"));
    check("cli: and cites the member that proved the limit, so the caveat carries its evidence", clean.log.includes("validate-cf-pace"));
  }
  console.log(`${TAG} self-test: ${bad === 0 ? "PASS" : `${bad} FAILED`}`);
  return bad === 0 ? CLEAN : FOUND_SOMETHING;
}

function main() {
  if (process.argv.includes("--self-test")) return selfTest();

  const chain = arg("--chain", "validate:chain");
  const repeats = Number(arg("--repeats", "3"));
  const minMembers = Number(arg("--min-members", ""));
  const only = arg("--only", null);
  const maxMembers = Number(arg("--max-members", "0"));

  // Two runs is the least that can disagree. One run grades nothing about repeatability, and a default that
  // silently accepted it would make this gate pass by construction.
  if (!Number.isInteger(repeats) || repeats < 2) {
    console.error(`::error::${TAG} --repeats must be an integer of at least 2; one run cannot disagree with itself. Exit ${CANNOT_RUN}.`);
    return CANNOT_RUN;
  }
  // THE FLOOR IS REQUIRED AND CARRIES NO DEFAULT, for the reason run-gate-chain.mjs states about its own:
  // it is a tripwire for the chain being gutted, not a target, and a default silently applies yesterday's
  // number to today's chain. This file shipped with a default of 422 while the chain stood at 422, and the
  // chain reached 423 the same day, so the default became a member of slack that nobody had chosen. A floor
  // equal to the count costs one number per deliberate removal and nothing at all for an addition.
  if (!Number.isInteger(minMembers) || minMembers < 1) {
    console.error(`::error::${TAG} --min-members is required and must be a positive integer. It is the floor that stops a gutted chain reporting a confident pass over the remnant, and a default would apply the wrong number to the next chain wrapped here. Exit ${CANNOT_RUN}.`);
    return CANNOT_RUN;
  }
  const pkgPath = join(ROOT, "package.json");
  if (!existsSync(pkgPath)) {
    console.error(`::error::${TAG} no package.json at ${pkgPath}, so there is no population to grade. Exit ${CANNOT_RUN}.`);
    return CANNOT_RUN;
  }
  const scripts = JSON.parse(readFileSync(pkgPath, "utf8")).scripts ?? {};
  const pop = selectMembers(scripts, chain, minMembers, only, maxMembers);
  if (pop.error) {
    console.error(`::error::${TAG} ${pop.error}. Exit ${CANNOT_RUN}.`);
    return CANNOT_RUN;
  }

  const scratch = mkdtempSync(join(tmpdir(), "determinism-determinism-"));
  console.log(`${TAG} grading ${pop.selected.length} of ${pop.all} member(s) of "${chain}", ${repeats} run(s) each, SERIALLY, on the tree as it stands.`);
  if (pop.capped) console.log(`${TAG} NOTE: --max-members capped the selection, so this is a SAMPLE and a clean result covers the sample only.`);

  const unstable = [];
  const refused = [];
  let runsDone = 0;
  for (let i = 0; i < pop.selected.length; i++) {
    const m = pop.selected[i];
    const g = gradeOne(m, ROOT, scratch, repeats);
    runsDone += g.codes.length;
    if (g.unreadable > 0) {
      refused.push(g);
      console.log(`${TAG} ${i + 1}/${pop.selected.length} REFUSED ${g.unreadable}/${repeats} run(s) produced no readable exit code  ${m}`);
    } else if (!g.stable) {
      unstable.push(g);
      console.log(`${TAG} ${i + 1}/${pop.selected.length} UNSTABLE codes=[${g.codes.join(",")}]  ${m}`);
    } else {
      console.log(`${TAG} ${i + 1}/${pop.selected.length} stable exit=${g.codes[0]}  ${m}`);
    }
  }

  // ANTI-VACUITY. The count of runs actually performed is asserted, not merely printed, so a verdict can
  // never be issued over an empty sweep.
  if (runsDone === 0) {
    console.error(`::error::${TAG} 0 runs performed, so nothing was graded and "no member flaked" would be vacuously true. Exit ${CANNOT_RUN}.`);
    return CANNOT_RUN;
  }
  console.log(`\n${TAG} ${pop.selected.length} member(s) EXAMINED across ${runsDone} run(s).`);

  for (const g of refused) console.error(`::error::${TAG} REFUSED: ${g.cmd} (${g.unreadable}/${repeats} run(s) gave no readable exit code, so its repeatability is unknown)`);
  for (const g of unstable) console.error(`::error::${TAG} NON-DETERMINISTIC: ${g.cmd} returned exit codes [${g.codes.join(",")}] over ${repeats} identical runs on one unchanged tree. Every mutation verdict this member contributes to is unsafe: a self-inflicted red manufactures a KILL, which records a site as guarded and hides the finding.`);

  if (refused.length > 0) {
    console.error(`::error::${TAG} ${refused.length} member(s) could not be graded, so this is NOT a clean sweep even though ${unstable.length} member(s) were found unstable. Exit ${CANNOT_RUN}, not ${unstable.length > 0 ? FOUND_SOMETHING : CLEAN}.`);
    return CANNOT_RUN;
  }
  if (unstable.length > 0) {
    console.error(`${TAG} ${unstable.length} of ${pop.selected.length} member(s) are NON-DETERMINISTIC. Exit ${FOUND_SOMETHING}.`);
    return FOUND_SOMETHING;
  }
  // WHAT A PASS HERE DOES NOT COVER, stated in the output because it was learned the expensive way.
  //
  // This gate runs each member ALONE and SERIALLY, so it finds a member that disagrees with ITSELF. It
  // cannot find a member that only disagrees when its 432 neighbours are running around it, and that class
  // is real: `validate-cf-pace` failed inside a 433-member chain run, passed 3 of 3
  // standalone, and this gate graded it STABLE across 5 repeats at the very commit where it was still
  // broken. Its assertion timed a wall-clock refill window that only closes when the machine is busy
  // BEFORE the clock is read, so running it quietly is running it in the one condition it cannot fail in.
  //
  // A KNOWN POSITIVE THAT THE DETECTOR CANNOT SEE is worth more than a caveat, so it is named here rather
  // than left for the next reader to rediscover. "No member flaked" and "no member flaked when run alone"
  // are different claims, and only the second one is on offer.
  console.log(`${TAG} PASS: every one of ${pop.selected.length} member(s) returned an identical verdict across all ${repeats} runs.`);
  console.log(`${TAG} SCOPE: each member ran ALONE. A member that only fails under the load of its neighbours is NOT covered, and validate-cf-pace was exactly that on 2026-08-29: stable here, red in the chain.`);
  return CLEAN;
}

const isMain = process.argv[1]?.endsWith("determinism-gate.mjs");
if (isMain) {
  try {
    process.exit(main());
  } catch (e) {
    // A THROW IS A COULD-NOT-CHECK, NEVER A FINDING. The gate crashed, so it established nothing, and exit
    // 1 would license the reading "the population was graded and here are the violations".
    console.error(`::error::${TAG} threw before reaching a verdict, so nothing was established: ${e?.stack ?? e}. Exit ${CANNOT_RUN}.`);
    process.exit(CANNOT_RUN);
  }
}
