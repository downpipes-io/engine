// The attended-verification cadence oracle (src/admin/attended-cadence.ts).
//
// The module is pure, so every rule it must satisfy is testable here without an estate, a clock or a
// notification.
//
// The four that matter, and each earns its assertions:
//
//   - PER DOWNPIPE, not estate-newest. An estate-newest reading is satisfied by verifying one downpipe out
//     of forty, so the test below has a fresh downpipe alongside a stale one and requires the stale one to
//     still be overdue.
//   - ONLY the full keyed method credits. A blind-test or keyless-attest proof carries no sample rate or
//     scope, so crediting it would let a one-record test read as a full one. Both are asserted NOT to count.
//   - NEVER-VERIFIED is not OVERDUE. A recovered estate restores its cadence but not its proof history, so
//     conflating them would alert during the hour the operator can least act.
//   - NO CADENCE SET is not a breach. An unset interval must behave exactly as today, or the feature turns a
//     silent browser preference into a live obligation for every existing customer at once.
//
// Run with `node test/validate-attended-cadence.ts`.
//
import { dueFor, evaluateAttendedCadence } from "../src/admin/attended-cadence.ts";
import { ATTENDED_CADENCE_CHECK_ID, buildAttendedCadence } from "../src/admin/posture-checks.ts";
import { CHECK_SEVERITY, computePosture, detectRegressions, snapshotOf } from "../src/admin/posture.ts";
import { buildRestoreTestsReport } from "../src/admin/reports.ts";
import { restoreTestsBlocksForTest } from "../src/pdf.ts";
import type { PostureDownpipeInput } from "../src/admin/posture-types.ts";
import { healthyInput } from "./validate-posture-shared.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const NOW = 1_800_000_000_000;
const DAY = 86_400_000;

function dp(id: string, over: Partial<PostureDownpipeInput> = {}): PostureDownpipeInput {
  return { id, name: `dp-${id}`, lastRunId: `run-${id}`, ...over };
}

console.log("\n-- the attended-verification cadence oracle --\n");

// ---- the has-a-run exclusion -----------------------------------------------------------------------------
ok(
  "a downpipe that has never completed a run is EXCLUDED, not overdue (nothing to verify yet)",
  dueFor({ id: "a", name: "a" }, 30, NOW).state === "excluded",
);
ok(
  "and an empty lastRunId counts as never having run",
  dueFor({ id: "a", name: "a", lastRunId: "" }, 30, NOW).state === "excluded",
);

// ---- never-verified is its own state ---------------------------------------------------------------------
// The safety property: a recovered estate restores org policy (and so the cadence) but not its proof
// history, so treating "no proof" as "overdue" would alert during the recovery itself.
ok(
  "a downpipe with a run and no proof at all is NEVER-VERIFIED, not overdue",
  dueFor(dp("b"), 30, NOW).state === "never-verified",
);

// ---- only the FULL keyed method credits ------------------------------------------------------------------
const fresh = { restoreProvenAt: NOW - 2 * DAY };
ok(
  "a full attended proof inside the cadence reads CURRENT",
  dueFor(dp("c", { ...fresh, restoreProvenMethod: "attended-blind-test" }), 30, NOW).state === "current",
);
ok(
  "a blind-test proof does NOT count (no sample rate or scope, so a one-record test is indistinguishable)",
  dueFor(dp("d", { ...fresh, restoreProvenMethod: "blind-test" }), 30, NOW).state === "never-verified",
);
ok(
  "a keyless-attest proof does NOT count (it performs no decryption at all)",
  dueFor(dp("e", { ...fresh, restoreProvenMethod: "keyless-attest" }), 30, NOW).state === "never-verified",
);
ok(
  "a method with no timestamp does not count either",
  dueFor(dp("f", { restoreProvenMethod: "attended-blind-test" }), 30, NOW).state === "never-verified",
);

// ---- the boundary ----------------------------------------------------------------------------------------
const atEdge = dp("g", { restoreProvenMethod: "attended-blind-test", restoreProvenAt: NOW - 30 * DAY });
ok("a proof exactly at the cadence is still CURRENT (the interval is inclusive)", dueFor(atEdge, 30, NOW).state === "current");
const pastEdge = dp("h", { restoreProvenMethod: "attended-blind-test", restoreProvenAt: NOW - 31 * DAY });
ok("and one day past it is OVERDUE", dueFor(pastEdge, 30, NOW).state === "overdue");
ok("the verdict carries the age in whole days, so a caller need not recompute it", dueFor(pastEdge, 30, NOW).ageDays === 31);

// ---- an unset cadence is not a breach --------------------------------------------------------------------
// The field is optional and unset must behave exactly as today, or every existing customer
// acquires a live obligation the moment this ships.
ok(
  "with NO cadence set, a years-old proof is still CURRENT rather than overdue",
  dueFor(dp("i", { restoreProvenMethod: "attended-blind-test", restoreProvenAt: NOW - 900 * DAY }), 0, NOW).state === "current",
);
ok(
  "and a negative cadence is treated the same as unset, never as an instant breach",
  dueFor(dp("j", { restoreProvenMethod: "attended-blind-test", restoreProvenAt: NOW - 900 * DAY }), -1, NOW).state === "current",
);

// ---- a clock disagreement must not invent a lapse ---------------------------------------------------------
ok(
  "a proof stamped in the future clamps to zero days and reads CURRENT, never overdue",
  dueFor(dp("k", { restoreProvenMethod: "attended-blind-test", restoreProvenAt: NOW + 5 * DAY }), 30, NOW).state === "current",
);

// ---- per downpipe, which is the whole concession ------------------------------------------------------------
// An estate-newest reading would be satisfied by the fresh one here and would report the stale one clean.
const estate = [
  dp("fresh", { restoreProvenMethod: "attended-blind-test", restoreProvenAt: NOW - 1 * DAY }),
  dp("stale", { restoreProvenMethod: "attended-blind-test", restoreProvenAt: NOW - 400 * DAY }),
  dp("unproven"),
  { id: "norun", name: "dp-norun" },
];
const summary = evaluateAttendedCadence(estate, 30, NOW);
ok("one fresh downpipe does NOT clear a stale one (the estate-newest trap)", summary.overdue.length === 1 && summary.overdue[0]?.id === "stale");
ok("the unproven downpipe lands in neverVerified, not overdue", summary.neverVerified.length === 1 && summary.neverVerified[0]?.id === "unproven");
ok("the downpipe with no run is excluded from both", summary.excluded.length === 1 && summary.excluded[0]?.id === "norun");
ok("every downpipe appears exactly once across the groups plus current", summary.perDownpipe.length === 4);
ok("the summary echoes the cadence it was evaluated against", summary.cadenceDays === 30);

// ---- it reports, it does not decide -----------------------------------------------------------------------
// Nothing here gates work. The only public surface is a verdict, so a caller cannot
// accidentally treat this as an authorisation decision.
ok(
  "an all-overdue estate still returns a summary rather than throwing or signalling a block",
  evaluateAttendedCadence([dp("z", { restoreProvenMethod: "attended-blind-test", restoreProvenAt: 0 })], 1, NOW).overdue.length === 1,
);

// ---- the posture check ------------------------------------------------------------------------------------
// The check is what a customer and an auditor actually see, so what matters is when it
// is SILENT as much as what it says.

function postureInput(over: Record<string, unknown> = {}): Parameters<typeof buildAttendedCadence>[0] {
  return {
    status: {} as never,
    downpipes: estate,
    operationalPrivatePresent: false,
    ...over,
  } as unknown as Parameters<typeof buildAttendedCadence>[0];
}

// NOT APPLICABLE when no interval is stated. An estate that never chose one has no obligation, so
// manufacturing a finding would turn a silent browser preference into a live finding for every existing
// customer at once.
ok("with NO cadence stated the check is OMITTED entirely, not passed and not failed", buildAttendedCadence(postureInput({ attendedCadenceDays: 0 }), NOW) === null);
ok("and an absent field is the same as 0", buildAttendedCadence(postureInput({}), NOW) === null);

// NOT APPLICABLE on an operational estate: restore-test-recency already grades unattended proof there, so a
// second finding about an attended rhythm nobody needs would be noise.
ok(
  "with an operational key present the check is OMITTED even when a cadence is stated",
  buildAttendedCadence(postureInput({ attendedCadenceDays: 30, operationalPrivatePresent: true }), NOW) === null,
);

const failing = buildAttendedCadence(postureInput({ attendedCadenceDays: 30 }), NOW);
ok("on a break-glass-only estate with a stated cadence the check applies", failing !== null);
ok("and it FAILS when a downpipe is past the interval", failing?.auto === "fail");
// The two states must read differently. A recovered estate is never-verified, not lapsed, and telling that
// operator they have lapsed would be wrong and unhelpable in the hour it lands.
ok("the detail names the OVERDUE downpipe by the interval it passed", failing?.detail.includes("past the 30-day interval") === true);
ok("and names the NEVER-VERIFIED one separately, never as the same lapse", failing?.detail.includes("never attended-verified") === true);
ok("the excluded no-run downpipe is not counted against the estate", failing?.detail.includes("of 3 downpipes with a completed run") === true);
ok("the remediation names the split-custody route, not just a key file", failing?.remediation.includes("quorum of shares") === true);

const clean = buildAttendedCadence(
  postureInput({
    attendedCadenceDays: 30,
    downpipes: [dp("a", { restoreProvenMethod: "attended-blind-test", restoreProvenAt: NOW - 2 * DAY }), { id: "b", name: "dp-b" }],
  }),
  NOW,
);
ok("an estate inside its interval PASSES", clean?.auto === "pass");
ok("and the passing detail still excludes the downpipe with no run", clean?.detail.includes("The one downpipe with a completed run") === true);
const cleanPlural = buildAttendedCadence(
  postureInput({
    attendedCadenceDays: 30,
    downpipes: [
      dp("a", { restoreProvenMethod: "attended-blind-test", restoreProvenAt: NOW - 2 * DAY }),
      dp("b", { restoreProvenMethod: "attended-blind-test", restoreProvenAt: NOW - 3 * DAY }),
    ],
  }),
  NOW,
);
ok("and it reads naturally in the plural too", cleanPlural?.detail.includes("All 2 downpipes with a completed run have") === true);

// Severity: a lapsed proof rhythm is an assurance obligation, not a failure of the backup, and nothing gates
// on it. Critical here would put a red finding on an estate whose backups are fine.
ok("the check is registered at MEDIUM severity, never critical", CHECK_SEVERITY[ATTENDED_CADENCE_CHECK_ID] === "medium");

// ---- step 4: the alert, which needed NO new machinery -------------------------------------------------------
// The notification step is conditional on the dedup being expressible in the existing notify machinery,
// because the remedy for an overdue proof is a person, and on split custody a quorum, so an alert that
// repeats on a cron rhythm trains the operator to ignore it.
//
// It is expressible, and it already exists. detectRegressions fires ONLY on a transition (a check that passed
// in the prior snapshot and needs attention now), and routePostureRegressions maps a non-critical check to
// severity "warning". So a steadily-overdue estate never re-fires, and this check pages at warning rather
// than critical. What follows proves the parts specific to THIS check rather than re-asserting the detector,
// which validate-posture-compute.ts already covers.

// healthyInput is the shared fixture the posture suite already uses, so this exercises a REAL PostureInput
// rather than a minimal stub that computePosture would reject. It is break-glass-only here, because that is
// the only posture in which the cadence check applies at all.
function reportFor(over: Record<string, unknown>): ReturnType<typeof computePosture> {
  const base = healthyInput();
  return computePosture(
    {
      ...base,
      status: { ...base.status, operationalConfigured: { public: true, private: false } },
      operationalPrivatePresent: false,
      downpipes: estate,
      ...over,
    } as never,
    NOW,
  );
}

const overdueReport = reportFor({ attendedCadenceDays: 30 });
const cadenceCheck = overdueReport.checks.find((c) => c.id === ATTENDED_CADENCE_CHECK_ID);
ok("the cadence check reaches the computed posture report", cadenceCheck !== undefined);
ok("and it is graded MEDIUM, so routePostureRegressions maps it to WARNING and never critical", cadenceCheck?.severity === "medium");

// The transition case: it was passing, now it is not.
const passingReport = reportFor({
  attendedCadenceDays: 30,
  downpipes: [dp("a", { restoreProvenMethod: "attended-blind-test", restoreProvenAt: NOW - 2 * DAY })],
});
const regs = detectRegressions(overdueReport, snapshotOf(passingReport));
ok("falling behind the interval IS a posture regression, so it alerts once", regs.some((r) => r.id === ATTENDED_CADENCE_CHECK_ID));
ok("and the regression carries the medium severity, not critical", regs.find((r) => r.id === ATTENDED_CADENCE_CHECK_ID)?.severity === "medium");

// The steady state: still overdue, no new alert, falls out of the existing detector rather than needing a
// repeat timer.
ok(
  "a STILL-overdue estate does not re-alert, because the prior snapshot was already failing",
  detectRegressions(overdueReport, snapshotOf(overdueReport)).length === 0,
);

// The sharp one. An operator who states a cadence for the FIRST TIME on an estate whose downpipes are
// already past it must not be paged the moment they save the setting: the check was absent from the prior
// snapshot, and detectRegressions treats an absent prior as no prior good state to fall from.
const noCadenceReport = reportFor({ attendedCadenceDays: 0 });
ok("with no cadence the check is absent from the report entirely", noCadenceReport.checks.every((c) => c.id !== ATTENDED_CADENCE_CHECK_ID));
ok(
  "so TURNING THE CADENCE ON with downpipes already overdue does not page the operator who just saved it",
  detectRegressions(overdueReport, snapshotOf(noCadenceReport)).length === 0,
);

// ---- the auditor artefacts ----------------------------------------------------------------------------------
// A report that grades recency without carrying the TARGET is not self-contained: a reader can see when each
// downpipe was last proven and cannot say whether that meets what the estate committed to. Both the report
// body and the signed PDF now carry the stated interval.

const rt = buildRestoreTestsReport([], [], { fromSeconds: 0, toSeconds: Math.floor(NOW / 1000) }, 90);
ok("the restore-tests report carries the stated interval", rt.attendedCadenceDays === 90);
ok("an unstated interval is carried as 0, not omitted", buildRestoreTestsReport([], [], { fromSeconds: 0, toSeconds: Math.floor(NOW / 1000) }, 0).attendedCadenceDays === 0);
ok("and a negative interval is normalised to 0 rather than reported as a target", buildRestoreTestsReport([], [], { fromSeconds: 0, toSeconds: Math.floor(NOW / 1000) }, -5).attendedCadenceDays === 0);

// The PDF is what an auditor actually reads. 0 must render as "not stated" and never as a missed target: an
// estate that has committed to no rhythm has not failed one.
const statedBlocks = JSON.stringify(restoreTestsBlocksForTest({ recency: [], evidence: [], attendedCadenceDays: 90 }));
ok("the signed PDF states the interval before the measurements", statedBlocks.includes("Stated recoverability-proof interval"));
ok("and names the number", statedBlocks.includes("every 90 days"));
const unstatedBlocks = JSON.stringify(restoreTestsBlocksForTest({ recency: [], evidence: [], attendedCadenceDays: 0 }));
ok("with no interval stated the PDF says so", unstatedBlocks.includes("has not stated an interval"));
ok("and says plainly it is NOT a missed target", unstatedBlocks.includes("That is not a missed target"));

console.log(`\n${failures === 0 ? "ATTENDED-CADENCE PASS" : `ATTENDED-CADENCE: ${failures} FAILED`}\n`);
if (failures > 0) process.exitCode = 1;
process.exit(failures === 0 ? 0 : 1);
