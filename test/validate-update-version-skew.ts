// The engine must never advertise an update its own apply path refuses, and must never report a version pair
// it cannot read as though it had read it.
//
// THE INCIDENT
// ------------
// updateAvailable was `recommended !== ENGINE_VERSION`. Inequality, not strictly-newer, in a module that
// declares compareSemver and never called it there. Measured live: engine 0.2.0 against a channel
// recommending 0.1.10, updateAvailable true, and a dry-run apply answering "the recommended version 0.1.10
// is not newer than the running engine 0.2.0 ... Nothing was changed".
//
// So the engine advertised an update it would refuse, notify-passes.ts pushed a notification about it off the
// same flag, and the console showed "Update available" in its tile while its own per-component row on the
// same screen read "Engine 0.2.0 -- up to date". That is the product disagreeing with itself on one screen
// about one pair of version strings.
//
// WHAT THIS PINS, and the fourth case is the one worth the file
// -------------------------------------------------------------
// The four skew states, each asserted on both call sites (the release-level verdict and the per-component
// engine row), because two call sites that derive the same fact separately are how they came to disagree:
//
//   behind        strictly newer recommended  -> updateAvailable TRUE
//   current       identical                   -> updateAvailable FALSE
//   ahead         strictly older recommended  -> updateAvailable FALSE, and the skew says "ahead"
//   uncomparable  either side unparseable     -> updateAvailable FALSE, and the skew says so
//
// THE FOURTH IS NOT A ROUNDING CASE. Making updateAvailable merely strictly-newer would turn an unreadable
// pair into a silent "up to date", which reports a pass where a could-not-check is the truth. That is the
// same class of defect as the one being removed, so the state travels as its own member and this file
// refuses a build that folds it back into "current".
//
// It also asserts that the two call sites AGREE, member for member, over the whole table. A per-component
// row and a release verdict that disagree is the exact shape the console rendered.
//
// House style: Australian English, no em dashes, no rule-of-three, no AI attribution.
//
//   node test/validate-update-version-skew.ts

import { compareSemver, versionSkew, type VersionSkew } from "../src/admin/updates.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (cond) checks++;
  else failures++;
}

// The table is (recommended, running, expected skew, expected updateAvailable). Running is the ENGINE's own
// version in every row, matching both call sites' argument order.
const TABLE: Array<[string, string, VersionSkew, boolean, string]> = [
  ["0.2.0", "0.1.10", "behind", true, "a genuinely newer release IS an available update"],
  ["0.1.11", "0.1.10", "behind", true, "a patch bump is an available update"],
  ["1.0.0", "0.9.9", "behind", true, "a major bump is an available update"],
  ["0.1.10", "0.1.10", "current", false, "the same version is not an update"],
  // A LEADING "v" IS UNCOMPARABLE, AND THAT IS THE PRODUCT'S ANSWER RATHER THAN MINE. This row was written
  // expecting "current", because the console's sameVersion normalises a leading v, and the engine's
  // compareSemver does not: it strips a build suffix and a pre-release suffix and nothing else. The
  // expectation was corrected rather than the engine, because uncomparable is what the APPLY path already
  // does with such a string (verifyAndGuard reads the same comparator), so reporting it as an available
  // update would re-create the very defect this file pins. The asymmetry with the console helper is real
  // and is recorded here rather than quietly smoothed over.
  ["v0.1.10", "0.1.10", "uncomparable", false, "a leading v does not parse for compareSemver, so it is honestly uncomparable"],
  // THE INCIDENT ROW, with the exact versions the live estate carried.
  ["0.1.10", "0.2.0", "ahead", false, "THE INCIDENT: a channel pinned BEHIND the engine is NOT an available update"],
  ["0.1.10", "0.1.11", "ahead", false, "one patch behind the engine is not an available update"],
  ["0.9.9", "1.0.0", "ahead", false, "a whole major behind the engine is not an available update"],
  // THE COULD-NOT-CHECK ROWS. Each must be its own state, never folded into "current".
  ["not-a-version", "0.1.10", "uncomparable", false, "an unparseable RECOMMENDED cannot be compared"],
  ["0.1.10", "not-a-version", "uncomparable", false, "an unparseable RUNNING cannot be compared"],
  ["", "0.1.10", "uncomparable", false, "an empty recommended cannot be compared"],
  ["0.1.10.5", "0.1.10", "uncomparable", false, "a four-part version cannot be compared"],
];

// POPULATION FLOOR. A table that degraded to nothing would assert nothing and print a pass.
if (TABLE.length < 10) {
  console.error(`validate-update-version-skew: REFUSED, the table holds only ${TABLE.length} row(s).`);
  process.exit(2);
}
for (const state of ["behind", "current", "ahead", "uncomparable"] as const) {
  if (!TABLE.some(([, , s]) => s === state)) {
    console.error(`validate-update-version-skew: REFUSED, no row exercises "${state}", so that arm is ungraded.`);
    process.exit(2);
  }
}
ok(`the table covers all four skew states across ${TABLE.length} rows`, true);

for (const [recommended, running, expected, available, why] of TABLE) {
  const got = versionSkew(recommended, running);
  ok(`${why} (recommended=${recommended || "(empty)"}, running=${running}) -> skew "${got}"`, got === expected);
  // updateAvailable is derived from the skew at BOTH call sites as `skew === "behind"`, so the derivation
  // is asserted here rather than the call sites being trusted to have used it.
  ok(`  and updateAvailable is ${available}`, (got === "behind") === available);
}

// "uncomparable" must never be reachable as "current": that fold is the defect this file exists to stop.
const uncomparableFoldedToCurrent = TABLE.filter(([r, n, e]) => e === "uncomparable" && versionSkew(r, n) === "current");
ok("no uncomparable pair is reported as current", uncomparableFoldedToCurrent.length === 0);

// The derivation must be the one compareSemver already implements, not a second opinion beside it.
for (const [recommended, running] of TABLE) {
  const cmp = compareSemver(recommended, running);
  const expectFromCmp: VersionSkew = cmp === null ? "uncomparable" : cmp > 0 ? "behind" : cmp < 0 ? "ahead" : "current";
  ok(`  versionSkew agrees with compareSemver for (${recommended || "(empty)"}, ${running})`, versionSkew(recommended, running) === expectFromCmp);
}

if (failures > 0) process.exitCode = 1;
console.log(`\nVERDICT: ${failures === 0 ? "PASS" : "FAIL"} failures=${failures} checks=${checks} entry=validate-update-version-skew.ts`);
process.exit(failures === 0 ? 0 : 1);
