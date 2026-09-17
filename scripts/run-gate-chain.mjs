#!/usr/bin/env node
// GATE CHAIN RUNNER: run every member of a gate chain, then report every failure.
//
// WHY THIS EXISTS, measured on this repo rather than argued. `npm run validate` was a single `&&` chain of
// 383 members. `&&` stops at the first non-zero exit, which is right for a build and wrong for a gate suite:
// the chain stopped at member 219, test/validate-cmp-compound-faults.ts, and the 164 members
// behind it had not run for as long as that member had been red. Running those 164 individually took 169
// seconds and found THREE reds, not one. Two of the three had the same root cause as the member that
// stopped the chain: commit d3099399 added a spend-time identity re-resolution to the restore-approval
// machine, and three separate fixtures had never seeded their principals into the DO role table. One commit
// broke three validators and the chain could only ever show the first.
//
// The coverage number was measured over the same truncated run, so it was a figure over roughly 57 per cent
// of the suite that read as a figure over all of it.
//
// WHAT THIS ADDS THAT THE EXISTING GATES CANNOT SEE. scripts/validator-reachability-gate.mjs already fails
// on a validator no gating chain names, and that is a MEMBERSHIP claim. Membership is not execution: every
// one of those 164 was a member in good standing, named by the chain, counted by the reachability gate, and
// none of them ran. Ordering is invisible to a wiring gate by construction. This runner closes that, and it
// is the only thing that can.
//
// NO DECLARED-RED TABLE, DELIBERATELY. The sibling implementation in ../harness carries one: a named member
// may be excused from gating if it has a written reason and an owner. It also carries the record of that
// mechanism failing. Its validate:surface-gap entry read plausibly for a day after its stated cause had
// stopped being true, because a declaration's reason is prose and nothing re-reads prose. The harness runner
// can detect exactly one kind of staleness, a declared member that starts PASSING, and the failure that
// actually happened was a declared member that stayed red for reasons its own entry never mentioned.
//
// This repo does not need the mechanism. After the three fixtures above were fixed there is one red left in
// the whole chain, test/validate-cov-admin-router-restore.ts, and it is a genuine red that should gate until
// someone fixes it. Adding an excusing mechanism with nothing to excuse is how the first entry gets written
// for convenience. If engine ever does need one, the thing to solve first is the staleness the harness
// entry demonstrates, not the ergonomics.
//
// ANTI-VACUITY. Exit 2 rather than 0 when this runner cannot actually check anything: no such script, or a
// chain that splits to fewer than MIN_MEMBERS. A runner that cannot fail on an empty input is not a gate,
// and the whole reason this file exists is that a gate reported success over work it had not done.
//
// WHAT THE CHAIN'S OWN EXIT CODE MEANS, and why a refusal outranks a finding. The convention in this repo is
// 0 clean, 1 a finding, 2 could-not-check, with exit 2 reserved for the instrument being unable to answer
// rather than for a question it declines to treat as its own. Until this runner read each
// member's code, printed it in the run log, and then returned a flat 1 for any non-zero. A member that
// refused because it could not establish its own subject came out of the chain looking exactly like a member
// that had graded a full population and found violations.
//
// That flattening undid work done one level down. scripts/writing-rules-source.mjs refuses when git cannot
// establish whether a file is tracked, and refuses rather than reports when the population it was going to
// grade falls away. Both refusals reached this runner, and this runner published them as findings.
//
// PRECEDENCE. Any refusal makes the chain refuse. Failing that, any finding makes the chain report a
// finding. Failing both, the chain is clean. The argument is about what a reader is entitled to conclude
// from the code alone. Exit 1 licenses the reading "every member graded its subject, and what follows is the
// complete set of violations". That reading is false as soon as one member could not grade its subject,
// because the set is then drawn from a population nobody established. Exit 2 licenses no reading at all,
// which is the honest answer when part of the sweep did not happen. The opposite precedence would turn an
// unknown into a known, which is the defect this file already exists to catch one level up.
//
// Nothing is lost by choosing that way round. A finding under a refusing chain is still printed with its
// exit code beside the member that produced it, and both codes are non-zero, so neither reads as a green.
//
// THE CHAIN STILL RUNS EVERY MEMBER after one has refused, and that is deliberate rather than an oversight.
// Stopping at a refusal is what `&&` already did, and the 164 unrun members above are the measured cost of
// it. A refusal changes the verdict, not the sweep.
//
// A CODE THE MEMBER DID NOT CHOOSE IS ALSO A REFUSAL. A member killed by a signal, or reported by the shell
// as 127 not found or 126 not executable, never reached a verdict of its own. Reading those as findings is
// the same mistake in a worse place, because a renamed or deleted gate script would then come back as
// "violations found". One case this cannot reach: `npm run <missing-script>` is reported by npm as exit 1,
// so a member whose npm script has gone still reads as a finding. The floor above is what covers that shape.
//
// MEASURED, because the whole fix depends on it: every member of `lint:chain` is an `npm run`, and npm
// propagates its child's exit code unchanged, so a gate that exits 2 arrives here as 2 rather than as npm's
// own 1. That was verified against this repo's npm before the precedence above was written down.
//
// THE FLOOR IS THE MEMBER COUNT, not a round number below it. It was 300 against 384 members and 8 against
// 10, and that slack was measured rather than argued: deleting `npm run lint:reachability` and
// `npm run lint:verdict-guard` from lint:chain left 8 members, met the floor exactly, and every gate in the
// repo stayed green. The validator-reachability gate cannot see that, because its population is
// test/validate-*.ts and the lint chain's members are scripts/*.mjs, so it went on printing
// "OK: every validator is reachable" at exit 0 after being removed from the chain itself.
//
// A floor equal to the count costs one number per intentional removal and nothing at all for an addition,
// which is the common direction. That asymmetry is the point: adding a gate should be frictionless, and
// removing one should be a line in a diff somebody has to write on purpose.
//
// The alternative considered and REFUSED was a second reachability gate over scripts/*-gate.mjs. Measured
// on the whole history of this repo: all 12 gate and lint scripts were wired into a chain in the SAME
// COMMIT that added them, so such a rule has never had a defect to catch here. The removal direction is the
// one that actually got past a gate, and the floor closes it.
//
// IT DRIVES THE LINT CHAIN TOO, and that is not symmetry for its own sake. `npm run lint` is a ten-member
// && chain that exits 1 at lint:size on a pre-existing max-lines finding. Behind that stop sat lint:scope,
// red at 149 warnings against a pinned baseline of 146, refusing an increase nobody had been told about. The
// same disease at a tenth the scale, found the same way.
//
// Usage: node scripts/run-gate-chain.mjs <script-name> <min-members>
//
// House style: Australian English, no em dashes, no rule-of-three, no AI attribution.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const TAG = "[gate-chain]";
const CANNOT_RUN = 2;
const FOUND_SOMETHING = 1;
const CLEAN = 0;
const ROOT = process.cwd();

// MEMBER_CAP_MS is the hard wall-clock cap on ONE member, after which it is killed and reported as a
// refusal. Without it this runner waits forever on a member that does not exit, and the chain waits with
// it. scripts/deploy.sh runs `npm run validate` as a blocking preflight under `set -e`, so an unbounded
// wait here is an unbounded wait in the deploy a customer follows: no output, no progress, no timeout,
// and not a failure, which is worse, because a hang cannot be told from a slow step.
//
// PORTED FROM console/scripts/run-gate-chain.mjs, where the defect was measured:
// test/validate-break-glass-restore.ts printed VERDICT: PASS failures=0 at about two seconds and then held
// the event loop for just under an hour on an uncancelled timer in the screen it drives. THE ENGINE CHAIN
// HAS NO MEMBER OF THAT SHAPE TODAY, and that was measured rather than assumed: all 427 members were run
// under a hard cap and every one exited. It is landed here anyway, because the cap is not a fix for a
// member, it is the thing that makes the next one visible in minutes instead of an hour.
//
// A HANG IS A REFUSAL, NOT A FINDING, by the argument this file already makes for exit 127 and for a
// signal: a member that never exited has not told this runner it graded its subject, whatever it printed.
//
// FIFTEEN MINUTES, AND THE NUMBER WAS SET BY THIS REPO'S OWN SLOWEST MEMBERS, both of which were
// surprises. `npm run test:runtime` stands in front of a whole nested suite and exits 0 in 305 seconds,
// and test/validate-streaming-restore.ts exits 0 in 64 seconds; the latter was briefly and wrongly filed
// as a hang under a 45-second cap. A cap that fires on a healthy member is a FALSE HANG, and a false hang
// in a deploy preflight is worse than the defect it was added for, because it kills a passing gate and
// reports a customer's own tree as broken. Fifteen minutes is about three times the slowest member here.
//
// THE ONE OVERRIDE CAN ONLY TIGHTEN IT. GATE_CHAIN_CAP_MS is clamped to the ceiling, so it can only cause
// MORE members to be reported as not exiting, never fewer. That forecloses the use every knob here would
// otherwise invite: raising it at the moment a member starts hanging, which is the moment it is working.
const MEMBER_CAP_CEILING_MS = 900_000;
const MEMBER_CAP_MS = (() => {
  const raw = process.env.GATE_CHAIN_CAP_MS;
  if (raw === undefined || raw === "") return MEMBER_CAP_CEILING_MS;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) return MEMBER_CAP_CEILING_MS;
  return Math.min(n, MEMBER_CAP_CEILING_MS);
})();

// Classify one finished member against the 0/1/2 convention. EXIT 1 IS THE ONLY FINDING. Everything
// non-zero that is not exactly 1 is a refusal, including codes outside the convention altogether. That is
// the same argument as the precedence above, applied one level smaller: a member that answered 3, or was
// never started, or was killed, has not told this runner that it graded its subject, and inventing the
// claim that it did is exactly the move being closed. Both classes are non-zero, so the cost of being
// wrong in this direction is a red reported under the wrong red, and the cost of being wrong in the other
// direction is an ungraded subject reported as a graded one.
function classify(r) {
  // A MEMBER THAT NEVER EXITED IS TESTED FIRST, and named rather than swept into the generic spawn failure
  // below, because the two are opposite states: a member that could not be spawned did nothing at all, and
  // a member that did not exit may well have printed a full green verdict before it stopped. The reader
  // needs to know the verdict on screen is real AND that the process behind it never ended, and "could not
  // be spawned" would say the opposite of both.
  if (r.error && r.error.code === "ETIMEDOUT") {
    return { kind: "refused", code: CANNOT_RUN, why: `did not exit within ${MEMBER_CAP_MS / 1000}s and was killed, so it never reached a verdict this runner could read (any verdict it printed is about its checks, not about it ending)` };
  }
  if (r.error) return { kind: "refused", code: CANNOT_RUN, why: `could not be spawned (${r.error.message})` };
  if (r.signal) return { kind: "refused", code: 128, why: `was killed by ${r.signal} before reaching a verdict` };
  if (typeof r.status !== "number") return { kind: "refused", code: CANNOT_RUN, why: "ended without an exit status this runner can read" };
  if (r.status === 0) return { kind: "pass", code: 0, why: "passed" };
  if (r.status === FOUND_SOMETHING) return { kind: "found", code: 1, why: "exited 1, which is a finding" };
  if (r.status === CANNOT_RUN) return { kind: "refused", code: 2, why: "exited 2, which is could-not-check" };
  if (r.status === 127) return { kind: "refused", code: 127, why: "was not found by the shell, so it graded nothing" };
  if (r.status === 126) return { kind: "refused", code: 126, why: "was not executable, so it graded nothing" };
  return { kind: "refused", code: r.status, why: `exited ${r.status}, which is outside the 0/1/2 convention, so whether it graded anything is unknown` };
}

function main(argv) {
  const chain = argv[0];
  // The floor is REQUIRED and per-chain, with no default. It is not a target, it is a tripwire for the chain
  // being gutted (by a bad merge, a truncated edit, a script rename) and this runner then reporting a
  // confident PASS over the remnant. A default would silently apply the wrong number to the next chain
  // wrapped here, and a floor that is wrong in the lenient direction is the same failure this file exists to
  // catch, one level up.
  const minMembers = Number(argv[1]);
  if (!chain || !Number.isInteger(minMembers) || minMembers < 1) {
    console.error(`::error::${TAG} usage: node scripts/run-gate-chain.mjs <script-name> <min-members>. The floor is required so a gutted chain cannot pass. Exit ${CANNOT_RUN}.`);
    return CANNOT_RUN;
  }
  const pkgPath = join(ROOT, "package.json");
  if (!existsSync(pkgPath)) {
    console.error(`::error::${TAG} no package.json at ${pkgPath}, so there is no chain to run. Exit ${CANNOT_RUN}.`);
    return CANNOT_RUN;
  }
  const scripts = JSON.parse(readFileSync(pkgPath, "utf8")).scripts ?? {};
  if (!scripts[chain]) {
    console.error(`::error::${TAG} package.json has no "${chain}" script, so the chain this runner is meant to drive has vanished rather than passed. Exit ${CANNOT_RUN}.`);
    return CANNOT_RUN;
  }
  const members = scripts[chain].split("&&").map((s) => s.trim()).filter(Boolean);
  if (members.length < minMembers) {
    console.error(`::error::${TAG} "${chain}" splits to only ${members.length} member(s), under the floor of ${minMembers}. A sweep this small has not proven what a full chain proves. Exit ${CANNOT_RUN}.`);
    return CANNOT_RUN;
  }

  const refused = [];
  const found = [];
  const started = Date.now();
  // The cap is ANNOUNCED before the first member runs, so a person watching a long chain (or a customer
  // watching `npm run deploy`, which blocks on this) can tell a slow member from one that will be killed,
  // and so the cap in force is a fact on the transcript rather than a constant a reader must look up here.
  console.log(`${TAG} running ${members.length} member(s) of "${chain}", each capped at ${MEMBER_CAP_MS / 1000}s.`);

  for (let i = 0; i < members.length; i++) {
    const m = members[i];
    const t0 = Date.now();
    // SIGKILL rather than the default SIGTERM: the member being killed is one that is not making progress,
    // and a handler that swallows SIGTERM would leave this runner waiting on the process it just gave up
    // on. stdio stays "inherit", so a capped member's own output is already on screen when the cap fires.
    const r = spawnSync(m, { shell: true, stdio: "inherit", cwd: ROOT, timeout: MEMBER_CAP_MS, killSignal: "SIGKILL" });
    const v = classify(r);
    const secs = ((Date.now() - t0) / 1000).toFixed(1);
    const entry = { m, code: v.code, i: i + 1, why: v.why };
    if (v.kind === "pass") {
      console.log(`${TAG} ${i + 1}/${members.length} PASS ${secs}s  ${m}`);
    } else if (v.kind === "refused") {
      refused.push(entry);
      console.log(`${TAG} ${i + 1}/${members.length} REFUSED exit=${v.code} ${secs}s  ${m}`);
    } else {
      found.push(entry);
      console.log(`${TAG} ${i + 1}/${members.length} FAIL exit=${v.code} ${secs}s  ${m}`);
    }
  }

  const wall = ((Date.now() - started) / 1000).toFixed(0);
  console.log(`\n${TAG} ${members.length} member(s) of "${chain}" all RUN in ${wall}s. Not one was skipped behind a failing neighbour.`);

  // The per-member annotations come out before the verdict and name the member either way, so the operator
  // learns which member produced which code no matter which of the two codes the chain settles on.
  for (const { m, code, i, why } of refused) {
    console.error(`::error::${TAG} member ${i} REFUSED exit=${code}: ${m} (${why})`);
  }
  for (const { m, code, i, why } of found) {
    console.error(`::error::${TAG} member ${i} FAILED exit=${code}: ${m} (${why})`);
  }

  if (refused.length > 0) {
    console.error(`${TAG} ${refused.length} member(s) of "${chain}" COULD NOT CHECK and ${found.length} found something, across ${members.length} member(s).`);
    const partial =
      found.length > 0
        ? `The ${found.length} finding(s) above are real, but they were gathered over a part of the population rather than all of it.`
        : "No member reported a finding, and that is not a clean result either, because part of the population was never graded.";
    console.error(`::error::${TAG} this chain is NOT a grade. At least one member could not establish its own subject. ${partial} Exit ${CANNOT_RUN}, not ${FOUND_SOMETHING}.`);
    return CANNOT_RUN;
  }
  if (found.length > 0) {
    console.error(`${TAG} ${found.length} failure(s) across ${members.length} member(s) of "${chain}". Every member graded its subject. Exit ${FOUND_SOMETHING}.`);
    return FOUND_SOMETHING;
  }
  console.log(`${TAG} PASS: every member of "${chain}" ran, graded its subject, and none failed.`);
  return CLEAN;
}

process.exit(main(process.argv.slice(2)));
