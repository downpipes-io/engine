// Gates the REPORTING half of test/live-cf-capture-completeness.ts, with no credential and no network.
//
// THE CLASS IT CLOSES. That harness could not pass. `verdictReached(gaps.length)` passes no check count,
// and the run prints no line in the house assertion shape, so the verdict guard refused the verdict and
// forced exit 1 even on a clean sweep: measured live it reported 313 surfaces, 97 complete, 216 not
// observable, 0 gaps, and exited 1. Its only exit 0 on any account was the SKIP path. A gate whose single
// green is "did not run" is worse than one that cannot fail, because the red is indistinguishable from a
// real finding and the green is indistinguishable from nothing happening.
//
// The second half of the defect is what the report SAID. A refused read and an account that simply does
// not use a product were both filed under one `notObservable` total. The harness built the two strings and
// then printed only the length, so the distinction existed in memory and never reached a reader. That is
// the same silent-drop shape the cf-config auto capture mode had, one layer up: the tool knew and did not
// say.
//
// Neither half needs a live account to gate, and a check that needs a credential is a check that does not
// run in CI. So the reporting half is pure and exported, and this file drives it with fixtures. The two
// child processes at the end are the part that matters: they measure the VERDICT GUARD's real exit code
// against the old shape and the new one, rather than asserting what the guard is believed to do.

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { classifyCaptureOutcome, reportCapture, type CaptureTally } from "./live-cf-capture-completeness.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(msg: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${msg}`);
  if (!cond) failures++;
}

const tally = (over: Partial<CaptureTally> = {}): CaptureTally => ({ complete: [], gaps: [], empty: [], unreadable: [], seeded: [], seedFailed: [], ...over });

console.log("-- classifyCaptureOutcome: four outcomes, and the two that are not a pass are not each other --");
ok("real data with its contents -> complete", classifyCaptureOutcome([{ name: "a", items: [1] }]).kind === "complete");
ok("a single object -> complete", classifyCaptureOutcome({ enabled: true }).kind === "complete");
ok("a scalar read -> complete", classifyCaptureOutcome("on").kind === "complete");
ok("an empty list -> empty (the account does not use it)", classifyCaptureOutcome([]).kind === "empty");
ok("null -> empty", classifyCaptureOutcome(null).kind === "empty");
ok("a count with no array holding what it counts -> gap", classifyCaptureOutcome([{ name: "l", count: 3 }]).kind === "gap");
ok("a list of bare identifiers -> gap", classifyCaptureOutcome(["tag-1", "tag-2"]).kind === "gap");
// THE FIX, first half. This used to return the same "nothing to look at" as an empty account.
ok("a read that answered with an _unavailable marker -> UNREADABLE, not empty", classifyCaptureOutcome({ _unavailable: "refused" }).kind === "unreadable");
ok("and that is a different outcome from an empty account", classifyCaptureOutcome({ _unavailable: "refused" }).kind !== classifyCaptureOutcome([]).kind);
// The count rule must not fire on a count that IS accompanied by its contents, or every healthy list surface
// would report a gap. This is the control on the rule that does the failing.
ok("a count WITH its array -> complete (the gap rule does not fire on healthy data)", classifyCaptureOutcome([{ name: "l", count: 2, items: ["a", "b"] }]).kind === "complete");
ok("a zero count with no array -> complete (nothing is being counted away)", classifyCaptureOutcome([{ name: "l", count: 0 }]).kind === "complete");

console.log("\n-- reportCapture: the check count is the surfaces actually judged, never the sweep size --");
const clean = reportCapture(tally({ complete: ["dns", "rulesets"], empty: ["spectrum"], unreadable: ["page-rules: read refused (other)"] }), 313);
ok("failures is the gap count", clean.failures === 0);
ok("checks counts ONLY complete + gaps, so a sweep that judged 2 surfaces claims 2, not 313", clean.checks === 2);
// Stated as a DIFFERENCE rather than as a value, because "checks === 2" would hold just as well if the
// count were computed from something else that happened to be 2 on this fixture.
const plusEmpty = reportCapture(tally({ complete: ["dns", "rulesets"], empty: ["spectrum", "extra-1", "extra-2"], unreadable: ["page-rules: read refused (other)"] }), 313);
ok("adding two more EMPTY surfaces does not move the check count", plusEmpty.checks === clean.checks);
const plusUnreadable = reportCapture(tally({ complete: ["dns", "rulesets"], empty: ["spectrum"], unreadable: ["page-rules: read refused (other)", "logpush: read refused (403)"] }), 313);
ok("adding another UNREADABLE surface does not move it either", plusUnreadable.checks === clean.checks);
const plusComplete = reportCapture(tally({ complete: ["dns", "rulesets", "zone-settings"], empty: ["spectrum"], unreadable: ["page-rules: read refused (other)"] }), 313);
ok("adding a surface judged on REAL DATA does move it (the count is not simply frozen)", plusComplete.checks === clean.checks + 1);
const withGap = reportCapture(tally({ complete: ["dns"], gaps: ["gateway-lists: carries count=3 but no array holding what it counts"] }), 313);
ok("a gap is a failure", withGap.failures === 1);
ok("and is still counted as a check (it was judged on real data)", withGap.checks === 2);
const judgedNothing = reportCapture(tally({ empty: ["a", "b"], unreadable: ["c: read refused (403)"] }), 313);
ok("a sweep that judged NOTHING declares 0 checks, so the guard refuses it rather than passing it", judgedNothing.checks === 0);

console.log("\n-- reportCapture: a refusal is NAMED, and never folded into the empty count --");
const text = clean.lines.join("\n");
ok("the refused surface is named in the output", text.includes("page-rules: read refused (other)"));
ok("the unreadable count is reported separately from the empty count", /nothing configured\s+1/.test(text) && /UNREADABLE\s+1/.test(text));
ok("the empty line still says it is NOT a pass", /nothing configured[^\n]*NOT a pass/.test(text));
ok("the unreadable line says it is neither a pass nor an empty account", /UNREADABLE[^\n]*NOT a pass and NOT an empty account/.test(text));
// The whole point is that the reader can tell them apart. If both totals were the same number this
// assertion would still hold, so it names the strings rather than counting them.
ok("the two are distinct labels, not one 'not observable' bucket", text.includes("nothing configured") && text.includes("UNREADABLE") && !text.includes("NOT OBSERVABLE"));
ok("a clean sweep still prints its PASS line", text.includes("CF-CONFIG CAPTURE COMPLETENESS PASS"));
ok("a sweep with a gap prints the gap and its reason", withGap.lines.join("\n").includes("gateway-lists: carries count=3"));

console.log("\n-- THE MEASUREMENT: the verdict guard's real exit code, old shape against new --");
// Not an assertion about what the guard is believed to do. Two child processes, two exit codes.
const guardPath = fileURLToPath(new URL("./lib/verdict-guard.ts", import.meta.url));
const runChild = (body: string): number => {
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", `import { verdictReached } from ${JSON.stringify(guardPath)};\n${body}`], { encoding: "utf8" });
  return r.status ?? -1;
};
// The OLD shape: exactly the lines the harness printed on a clean live sweep, then verdictReached(0) with
// no check count. This is the run that reported 0 gaps and exited 1.
const oldShape = runChild(
  [
    'console.log("-- 313 surfaces --");',
    'console.log("  complete, on real data   97");',
    'console.log("  NOT OBSERVABLE           216 (nothing on this account to inspect; NOT a pass)");',
    'console.log("  GAPS                     0");',
    'console.log("\\nCF-CONFIG CAPTURE COMPLETENESS PASS");',
    "verdictReached(0);",
  ].join("\n"),
);
ok("the OLD shape (no check count, no assertion lines) is REFUSED by the guard: exit 1 on a clean sweep", oldShape === 1);
// The NEW shape: the same clean sweep, declaring the count it judged. This is the run that must be able to pass.
const newShape = runChild(
  [
    'console.log("-- 313 surfaces --");',
    'console.log("  complete, on real data   97");',
    "verdictReached(0, 97);",
  ].join("\n"),
);
ok("the NEW shape (declaring 97 checks) PASSES: exit 0", newShape === 0);
// And the guard must still refuse a sweep that judged nothing, or the repair would have bought a false green.
const judgedNothingChild = runChild(['console.log("-- 313 surfaces --");', "verdictReached(0, 0);"].join("\n"));
ok("a sweep declaring 0 checks is STILL refused: exit 1 (the repair did not buy a false green)", judgedNothingChild === 1);
// A real gap must still fail, whatever the check count says.
const gapChild = runChild(['console.log("-- 313 surfaces --");', "verdictReached(1, 97);"].join("\n"));
ok("a sweep declaring a gap still fails: exit 1", gapChild === 1);

console.log(failures === 0 ? "\nCF-CAPTURE-COMPLETENESS REPORT PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures);
if (failures > 0) process.exit(1);
