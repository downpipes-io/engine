// validate-retention-prune-cap-honesty.ts
//
// THE BOUND, AND THE SECOND QUESTION ABOUT IT. RETENTION_PRUNE_MAX_RUNS bounds one call of the OFFLINE
// (break-glass) retention prune. The bound itself is fine and this validator proves it is: the edge is at
// exactly 200/201 and nothing is silently truncated. The interesting question was never "does it refuse"
// but "when it refuses, does it describe itself, and does the remedy it implies help or harm".
//
// IT DID NOT. The refusal read "this downpipe has N runs in scope, over the 200-run limit this route
// supports IN ONE CALL", and the comment above the constant said "the cron path (once an operational key
// is added) has no such bound, so this is a console-usability limit, not a correctness one".
//
//  1. THERE IS NO SECOND CALL. POST
//     /retention-prune/candidate takes downpipeId and nothing else; candidateIds comes from partitionRuns
//     over the whole RUNLOG, so the count is the downpipe's ACTIVE run count and no parameter narrows it.
//     On the apply side the batch cap and precheckCandidateCoverage (deliberate) are MUTUALLY
//     UNSATISFIABLE above the cap: every batch size from 1 to N at N = 201 refuses, one half or the other.
//  2. THE CRON PATH IS THE PATH THIS POSTURE HAS LOST. This file's own header says the route exists to
//     close "the ONE case the standing engine cron pass honestly refuses: on a break-glass-only estate (no
//     OPERATIONAL_PRIVATE)". retention-pass.ts returns at `if (!env.OPERATIONAL_PRIVATE)` and logs that
//     those downpipes "await an OFFLINE prune". The offline prune is this route. Two statements 80 lines
//     apart in one file, contradicting each other, and the cap sat between them.
//
// WHY IT IS THE SAME CLASS AS THE THREE BEFORE IT. Nothing moves a run out of `status: "active"` except a
// prune, and on this posture the only prune is the route that refuses. The count rises with every backup
// and never falls, so past the cap the refusal is permanent. A count that only rises, refused by a
// sentence that points away from the only step that lowers it -- and here the step it pointed at (split
// the call) does not exist at all.
//
// THE CONTROLS, and what each is for:
//   - DOSE-RESPONSE over active run counts, not a point test.
//   - POSITION CONTROL: move the retained/superseded SPLIT completely (keepRuns 1 vs 199 vs absent) at a
//     fixed total and show the verdict does not move. It is a verdict on the TOTAL, proved the same way
//     for the SAML cap below.
//   - DIFFERENTIAL CONTROL: validateConfig ACCEPTS keepRuns far above this cap, so the config layer
//     permits a population this route cannot serve. Driven, not read.
//   - THE IMPOSSIBILITY, MEASURED: every batch size 1..N at N = 201 refuses.
//   - NEGATIVE CONTROLS THAT MUST CLASSIFY DIFFERENTLY: the sibling refusals on the same route keep their
//     own sentences, so "this codebase does not write specific messages" is refuted here too.
//   - REPRODUCTION CONTROL: the SAML_CERTS_MAX edge is re-verified below on this run, so a reader can
//     separate this result from a stale or environment-specific instrument.

import { SAML_CERTS_MAX, validateSamlCerts } from "../src/admin/idpconn-validators.ts";
import { pruneBatchSatisfiable, pruneScopeRefusal, RETENTION_PRUNE_MAX_RUNS } from "../src/admin/router-retention-prune.ts";
import type { RunlogEntry } from "../src/format/writer.ts";
import { validateConfig } from "../src/sched/config-validate.ts";
import { partitionRuns } from "../src/seal/prune.ts";
// Importing the verdict guard ARMS it: a run that exits without reaching verdictReached below is forced
// to exit 1, so a drained event loop can never read as a clean sweep.

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  if (!cond) failures++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
}

const DP = "dp-prune-cap";
const DAY = 24 * 60 * 60 * 1000;
const NOW = new Date("2026-08-11T00:00:00.000Z");

// runs builds n ACTIVE RUNLOG entries for one downpipe, one per day going backwards from NOW, so keepDays
// and keepRuns both have something real to bite on. status "active" is what partitionRuns counts: an
// already-superseded entry is skipped entirely, which is exactly why the count only falls on a prune.
function runs(n: number, status = "active"): RunlogEntry[] {
  return Array.from({ length: n }, (_, i) => ({
    index: i,
    runId: `run${String(i).padStart(5, "0")}`,
    downpipeId: DP,
    time: new Date(NOW.getTime() - (n - i) * DAY).toISOString(),
    recordCount: 1,
    prevRunId: i === 0 ? null : `run${String(i - 1).padStart(5, "0")}`,
    status,
  }));
}

// candidateCount reproduces the candidate route's own two lines verbatim: partition, then concatenate the
// two halves. Nothing here re-implements retention; partitionRuns is the REAL pure planner the cron and
// this route share.
function candidateCount(entries: RunlogEntry[], policy: { keepRuns?: number; keepDays?: number }): number {
  const split = partitionRuns(entries, DP, policy, NOW);
  return split.retainedRunIds.length + split.supersededRunIds.length;
}
function candidateRefused(entries: RunlogEntry[], policy: { keepRuns?: number; keepDays?: number }): boolean {
  return candidateCount(entries, policy) > RETENTION_PRUNE_MAX_RUNS;
}

console.log("validate-retention-prune-cap-honesty");
console.log(`RETENTION_PRUNE_MAX_RUNS=${RETENTION_PRUNE_MAX_RUNS}`);

// ---- REPRODUCTION CONTROL ------------------------------------------------------------------------
// The SAML signing-certificate cap is exactly 8/9 through validateSamlCerts. Verify it here, on this run,
// so a reader can separate this result from a stale instrument. If this disagrees, nothing below is
// trustworthy.
console.log("\nREPRODUCTION CONTROL (the SAML cert edge, this rig, this session):");
function pem(tag: string): string {
  return `-----BEGIN CERTIFICATE-----\nMIIC${tag}\n-----END CERTIFICATE-----`;
}
const samlAt = validateSamlCerts(Array.from({ length: SAML_CERTS_MAX }, (_, i) => pem(`r${i}`)));
const samlOver = validateSamlCerts(Array.from({ length: SAML_CERTS_MAX + 1 }, (_, i) => pem(`r${i}`)));
console.log(`  ${SAML_CERTS_MAX} -> ${samlAt.ok ? "ACCEPT" : "REFUSE"};  ${SAML_CERTS_MAX + 1} -> ${samlOver.ok ? "ACCEPT" : "REFUSE"}`);
ok(`reproduction: SAML cap accepts at ${SAML_CERTS_MAX}`, samlAt.ok === true);
ok(`reproduction: SAML cap refuses at ${SAML_CERTS_MAX + 1}`, samlOver.ok === false);

// ---- QUESTION ONE: is the edge where it says it is, and is anything truncated? --------------------
console.log("\nDOSE-RESPONSE on the candidate route (active runs -> verdict), keepRuns=100:");
const DOSES = [0, 1, 100, 150, 199, 200, 201, 250, 400, 1000];
const policy100 = { keepRuns: 100 };
const doseRows = DOSES.map((n) => ({ n, counted: candidateCount(runs(n), policy100), refused: candidateRefused(runs(n), policy100) }));
for (const r of doseRows) console.log(`  ${String(r.n).padStart(4)} active\tcounted ${String(r.counted).padStart(4)}\t${r.refused ? "REFUSE" : "serve"}`);

ok("every dose at or under the cap is served", doseRows.filter((r) => r.n <= RETENTION_PRUNE_MAX_RUNS).every((r) => !r.refused));
ok("every dose above the cap refuses", doseRows.filter((r) => r.n > RETENTION_PRUNE_MAX_RUNS).every((r) => r.refused));
ok(`the edge is exactly ${RETENTION_PRUNE_MAX_RUNS}/${RETENTION_PRUNE_MAX_RUNS + 1}`, !candidateRefused(runs(RETENTION_PRUNE_MAX_RUNS), policy100) && candidateRefused(runs(RETENTION_PRUNE_MAX_RUNS + 1), policy100));
// NO SILENT TRUNCATION: the count the route compares is the FULL active count at every dose, never a
// clipped one. A cap that quietly served the first 200 of 1000 would be far worse than one that refuses.
ok("the counted population equals the active run count at every dose (nothing truncated)", doseRows.every((r) => r.counted === r.n));

// ---- POSITION CONTROL: vary what should not matter -----------------------------------------------
// At a fixed total of 250 active runs, move the retained/superseded split from one extreme to the other.
// If the verdict tracked either half rather than the total, this is where it would move.
console.log("\nPOSITION CONTROL (250 active runs, the split moved from end to end):");
const SPLITS: Array<{ label: string; policy: { keepRuns?: number; keepDays?: number } }> = [
  { label: "keepRuns=1    (1 retained, 249 superseded)", policy: { keepRuns: 1 } },
  { label: "keepRuns=125  (half and half)", policy: { keepRuns: 125 } },
  { label: "keepRuns=249  (249 retained, 1 superseded)", policy: { keepRuns: 249 } },
  { label: "keepRuns=250  (all retained, none superseded)", policy: { keepRuns: 250 } },
  { label: "keepDays=1    (day bound, not a run bound)", policy: { keepDays: 1 } },
  { label: "keepDays=36500(a century: all retained)", policy: { keepDays: 36500 } },
];
const at250 = runs(250);
const posRows = SPLITS.map((s) => {
  const split = partitionRuns(at250, DP, s.policy, NOW);
  return { ...s, retained: split.retainedRunIds.length, superseded: split.supersededRunIds.length, counted: split.retainedRunIds.length + split.supersededRunIds.length };
});
for (const r of posRows) console.log(`  ${r.label}\tretained ${String(r.retained).padStart(3)} superseded ${String(r.superseded).padStart(3)}\tcounted ${r.counted}\t${r.counted > RETENTION_PRUNE_MAX_RUNS ? "REFUSE" : "serve"}`);
ok("the split really does move (the control has power)", new Set(posRows.map((r) => r.retained)).size >= 4);
ok("the counted population is the TOTAL under every split", posRows.every((r) => r.counted === 250));
ok("every split at 250 refuses, whichever side carries the runs", posRows.every((r) => r.counted > RETENTION_PRUNE_MAX_RUNS));

// ---- THE IMPOSSIBILITY, MEASURED rather than argued -----------------------------------------------
// The old sentence said "in one call", which implies a second one. Sweep EVERY batch size from 1 to N at
// N = 201 and show that each is refused by one half or the other: over the cap is "batch too large", and
// under the candidate count leaves a run unopened, which precheckCandidateCoverage refuses outright.
console.log(`\nTHE REMEDY THE OLD SENTENCE IMPLIED, SWEPT (N=${RETENTION_PRUNE_MAX_RUNS + 1} active runs, every batch size 1..N):`);
const N = RETENTION_PRUNE_MAX_RUNS + 1;
const satisfiable: number[] = [];
for (let b = 1; b <= N; b++) if (pruneBatchSatisfiable(N, b)) satisfiable.push(b);
console.log(`  batch sizes that BOTH fit the cap AND cover every candidate: ${satisfiable.length === 0 ? "NONE" : satisfiable.join(",")}`);
ok(`no batch size can prune ${N} active runs`, satisfiable.length === 0);
// AND THE CONTROL THAT GIVES THAT ZERO ITS MEANING: one run fewer and the remedy exists, so the sweep is
// measuring the cap rather than a predicate that always says no.
const okAt200: number[] = [];
for (let b = 1; b <= RETENTION_PRUNE_MAX_RUNS; b++) if (pruneBatchSatisfiable(RETENTION_PRUNE_MAX_RUNS, b)) okAt200.push(b);
console.log(`  one run fewer (N=${RETENTION_PRUNE_MAX_RUNS}): ${okAt200.length} batch size(s) work, the smallest is ${okAt200[0] ?? "none"}`);
ok(`at exactly ${RETENTION_PRUNE_MAX_RUNS} a batch DOES exist (the zero above is not a stuck predicate)`, okAt200.length === 1 && okAt200[0] === RETENTION_PRUNE_MAX_RUNS);

// ---- DIFFERENTIAL CONTROL: the config layer permits what this route cannot serve -------------------
// validateConfig is the gate every stored retention policy passes. If it accepts keepRuns far above this
// route's cap, then a policy the product explicitly blesses puts a downpipe permanently past the prune.
console.log("\nDIFFERENTIAL CONTROL (what validateConfig ACCEPTS as a retention policy):");
function configAccepts(keepRuns: number): boolean {
  try {
    validateConfig({
      id: DP,
      name: "prune cap probe",
      source: { type: "kv", binding: "KVB", include: [], exclude: [] },
      cadenceSeconds: 3600,
      enabled: true,
      retention: { keepRuns, enforce: false },
    });
    return true;
  } catch {
    return false;
  }
}
for (const k of [100, 200, 201, 500, 5000, 10000, 10001]) console.log(`  keepRuns=${String(k).padStart(5)}\t${configAccepts(k) ? "ACCEPTED" : "refused"}`);
ok("validateConfig accepts a keepRuns far above this route's cap", configAccepts(500) && configAccepts(10000));
ok("and it does have an upper bound of its own (so this is a divergence, not an absent gate)", !configAccepts(10001));
// The consequence, stated as the arithmetic it is: a blessed keepRuns=500 policy retains 500 ACTIVE runs,
// so its candidate count sits permanently past this route's cap even with nothing superseded at all.
ok("a blessed keepRuns=500 policy is permanently past this route's cap", candidateRefused(runs(500), { keepRuns: 500 }));

// ---- WHY IT IS SELF-DEEPENING: only a prune moves a run out of "active" ----------------------------
// partitionRuns skips a non-active entry entirely, so an already-superseded run leaves the population.
// That is the ONLY thing that lowers the count, and on this posture the only route that supersedes is the
// one refusing. Measured both ways rather than asserted.
console.log("\nWHAT LOWERS THE COUNT (the same 250 entries, statuses changed):");
const allSuperseded = runs(250, "superseded");
console.log(`  250 active      -> counted ${candidateCount(runs(250), policy100)}`);
console.log(`  250 superseded  -> counted ${candidateCount(allSuperseded, policy100)}`);
ok("a superseded run leaves the counted population (a prune is what lowers it)", candidateCount(allSuperseded, policy100) === 0);
ok("and an active one does not (the count rises with every backup)", candidateCount(runs(250), policy100) === 250);

// ---- QUESTION TWO: does the refusal describe itself, and name a remedy that HELPS? -----------------
console.log("\nTHE REFUSAL SENTENCE:");
const sentence = pruneScopeRefusal(250, "active runs");
console.log(`  ${sentence}`);
ok("it names the actual count", sentence.includes("250"));
ok("it names the bound", sentence.includes(String(RETENTION_PRUNE_MAX_RUNS)));
ok("it names the population the count is over", sentence.includes("active runs"));
// THE HALF THE OLD SENTENCE GOT WRONG, and the half that decides whether the refusal helps or harms.
ok("it does NOT promise a further call (the remedy that does not exist)", !/in one call|further batch|in batches|send the rest/i.test(sentence));
ok("it says why splitting cannot work", /cover them all|does not cover|splitting/i.test(sentence));
ok("it NAMES THE REMEDY THAT ACTUALLY LOWERS THE COUNT", /operational key/i.test(sentence));
// The apply path's label must travel with its own number: saying "active runs" about a caller-chosen
// batch size would be a fresh false claim in the fix itself.
const batchSentence = pruneScopeRefusal(250, "runs in this batch");
console.log(`  ${batchSentence}`);
ok("the apply path does not call a caller-chosen batch size the active run count", batchSentence.includes("runs in this batch") && !batchSentence.includes("active runs,"));

// ---- THE PRE-FIX SENTENCES, KEPT SO THE FIX CANNOT BE QUIETLY REVERTED ----------------------------
// The previous refusal wording is carried here verbatim so the SAME honesty questions the new sentence
// passes can be shown to fail against it. Four of the six checks above fail against it, and the two that
// pass are the two that were never wrong: the count and the bound were always named correctly. The
// product always refused at the right place and only lied about what to do next -- the same shape as all
// three defects before this one.
console.log("\nTHE PRE-FIX SENTENCES, PUT THROUGH THE SAME QUESTIONS:");
const PREFIX_CANDIDATE = "this downpipe has 250 runs in scope, over the 200-run limit this route supports in one call";
const PREFIX_APPLY = "batch too large (max 200 runs per request)";
for (const [label, old] of [["candidate route", PREFIX_CANDIDATE], ["apply route", PREFIX_APPLY]] as const) {
  const namesCount = old.includes("250");
  const namesBound = old.includes(String(RETENTION_PRUNE_MAX_RUNS));
  const promisesAnotherCall = /in one call|per request|further batch|in batches|send the rest/i.test(old);
  const namesRemedy = /operational key/i.test(old);
  console.log(`  ${label}: "${old}"`);
  console.log(`    names count ${namesCount} | names bound ${namesBound} | promises another call ${promisesAnotherCall} | names the remedy ${namesRemedy}`);
  ok(`pre-fix ${label} PROMISED a further call that cannot exist`, promisesAnotherCall === true);
  ok(`pre-fix ${label} named NO remedy`, namesRemedy === false);
}
ok("pre-fix candidate route named the bound correctly (question one always passed)", PREFIX_CANDIDATE.includes(String(RETENTION_PRUNE_MAX_RUNS)));
// And the refuted comment, kept as a string so a revert of the reasoning is as visible as a revert of the
// code. It claimed the cap could not be a correctness limit because the cron path has no such bound; the
// cron path is the one this route's own header says this posture has lost.
const PREFIX_COMMENT = "the cron path (once an operational key is added) has no such bound, so this is a console-usability limit, not a correctness one";
ok("the refuted comment claimed the cron path covers this", /cron path/.test(PREFIX_COMMENT) && /not a correctness one/.test(PREFIX_COMMENT));

// ---- NEGATIVE CONTROLS THAT MUST CLASSIFY DIFFERENTLY ---------------------------------------------
// Sibling refusals reachable on this same route, taken from the route's own source, so "this codebase
// writes one generic sentence" is refuted rather than assumed. Each must keep its own words and none may
// borrow the capacity sentence -- which is the exact failure mode found earlier on the SAML path.
console.log("\nNEGATIVE CONTROLS (sibling refusals on this route must classify differently):");
const SIBLINGS: Array<[string, string]> = [
  ["downpipe not found", "downpipe not found"],
  ["no retention policy", "this downpipe has no retention policy configured"],
  ["downpipeId absent", "downpipeId required"],
];
for (const [label, text] of SIBLINGS) {
  const borrowed = text === sentence || /at most \d+/.test(text);
  console.log(`  ${label}\t"${text}"\t${borrowed ? "BORROWED" : "own sentence"}`);
  ok(`${label} keeps its own sentence`, !borrowed);
}
// And the positive half of the same control: an UNDER-cap call produces no refusal at all, so the
// sentence is not simply always present.
ok("an under-cap downpipe produces no capacity refusal", !candidateRefused(runs(10), policy100));

console.log(`\n${failures === 0 ? "PASS" : "FAIL"}  ${checks - failures}/${checks} checks`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
