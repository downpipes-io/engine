// Every closed set the docs ENUMERATE must match the code, and the docs' own counts must be true.
//
// Two pages so far: the posture checks and the notifiable alert events. Both are auditor- and
// operator-facing, both state a count, and both say or imply that the set is fixed in the code.
//
// WHY THIS EXISTS. docs/assurance-audit/posture-score.mdx is an AUDITOR-FACING page. It states a number of
// named checks, says in as many words that "the set is fixed in the code, so the list does not vary by
// account", and then tables them with a severity each. A reader is entitled to treat that table as the whole
// set.
//
// On 2026-07-28 it was FOUR behind. It said twenty-one and the product graded twenty-five:
// environment-self-backup, update-apply-provenance and update-version-drift had been shipped without the
// page learning them, and attended-verification-cadence made a fourth. Three of those four predate this
// workstream, so this is not one careless commit, it is the absence of anything that would notice.
//
// The check lives HERE because CHECK_SEVERITY is here. A docs-side gate would have to hardcode the number it
// is checking, which is the same drift one step removed.
//
// WHAT IT ASSERTS, and the third is the one that catches the subtle case:
//   - every check id in CHECK_SEVERITY appears in the page's table
//   - the page names no check id the product does not grade
//   - the page's stated TOTAL and its per-severity breakdown match the table, in words, because the prose is
//     what a reader skims and it is perfectly possible to add a row and leave the sentence wrong
//
// SIBLING POSTURE. Absent docs SKIP with a note by default, so a single-repo engine checkout stays buildable,
// and FAIL under --require, which is the convention verify-doc-links documents and which CI passes. That is
// deliberate: a gate that quietly opts out when it cannot look is the failure it exists to prevent.
//
// Run with `node test/validate-posture-and-docs-parity.ts [--require]`.
//
// House style: Australian English, no em dashes, no rule-of-three.

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CHECK_SEVERITY } from "../src/admin/posture.ts";
import { severityOf } from "../src/notify-routing.ts";
import { NOTIFY_EVENT_NAMES } from "../src/notify/types.ts";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";
import { requireFreshSiblings } from "../scripts/sibling-freshness.mjs";
import { reportSiblings } from "../scripts/lib/sibling-lag.mjs";

const HERE = fileURLToPath(new URL("..", import.meta.url));
const REQUIRE = process.argv.includes("--require");

/**
 * Where the docs might be, best first: an explicit override, then progressively further out.
 *
 * The extra levels are not padding. This engine is worked through a git WORKTREE at
 * engine/.worktrees/<name>, so the docs site is FOUR levels up from here, not one. And the engine has its
 * own engine/docs directory, which a shallower search finds first and which is not the docs site at all.
 * Each candidate is confirmed by the PAGE existing under it rather than by the directory existing, which is
 * what stops that wrong match: engine/docs has no assurance-audit/posture-score.mdx.
 */
function docsCandidates(): string[] {
  return [
    process.env.DOWNPIPES_DOCS,
    resolve(HERE, "../docs"),
    resolve(HERE, "../../docs"),
    resolve(HERE, "../../../docs"),
    resolve(HERE, "../../../../docs"),
  ].filter((p): p is string => typeof p === "string" && p !== "");
}

const PAGE = "src/content/docs/assurance-audit/posture-score.mdx";
const EVENTS_PAGE = "day-2/alert-events.mdx";
const root = docsCandidates().find((c) => existsSync(resolve(c, PAGE)));
if (root === undefined) {
  if (REQUIRE) {
    console.error(`FAIL posture-and-docs-parity: --require was passed and ${PAGE} was not found in any candidate docs checkout.`);
    process.exit(1);
  }
  console.log("ok   posture-and-docs-parity: SKIPPED, no docs checkout beside this engine (pass --require to fail instead)");
  // DECLARE the skip. Exiting 0 here having checked nothing is the same false green as a hang, and the
  // coverage job is exactly where it bites: it runs a plain `npm run validate` with no sibling repos
  // checked out, so this path is the one CI actually takes. verdictSkipped does not force a red, because
  // the sibling checkout is genuinely optional here and --require is how a caller makes it mandatory.
  verdictSkipped("no docs checkout beside this engine (pass --require to fail instead)");
  process.exit(0);
}

// WHICH DOCS TREE, and REFUSE when it is not the sibling's main.
//
// Measured on 2026-08-08 against this exact file: PASS failures=0 against docs origin/main 4d4f97f5, and
// FAIL failures=4, exit 1, against docs b9c8021 checked out beside it. Nothing in the engine changed between
// the two runs, and the failing output named the docs tree ZERO times (positive control on the same capture:
// "posture" occurs twice). So this gate's verdict was a function of a docs checkout it never named, and its
// red was indistinguishable from a red about the docs page as it actually stands.
//
// REFUSE rather than grade and say so, and the two are not equivalent here. Every line this gate prints is a
// specific, actionable claim about the docs page ("the page states twenty-six named checks"), and a reader
// acts on it by editing that page. Against a tree 220 commits behind, three of those four claims were about
// prose that main already carries, so the repair would have been made to a page that was already right. The
// mirror case is worse and is silent: a docs page that main has already broken reads green here because the
// stale tree still has the old, matching text. Neither direction is discountable from the output, and the
// gate costs under a second to re-run once the checkout is fast-forwarded.
//
// The measurement is printed BEFORE the refusal decision, so a run that proceeds still says which tree it
// graded. Naming the tree is the repair; refusing is what naming it justifies when the tree is behind.
reportSiblings([{ name: "docs", path: root }], { gate: "posture-and-docs-parity" });
requireFreshSiblings([{ name: "docs", path: root }], {
  gate: "posture-and-docs-parity",
  consequence: "its per-check findings would describe an older docs page than the one that ships",
  // The refusal is a VERDICT and has to be declared like any other, or test/lib/verdict-guard.ts reports
  // the exit as a validator that reached process exit without declaring one, which is a different and much
  // more alarming fault. `exit` is documented as a test seam; it is an injection point, and this is the
  // production use of it. The code is passed straight through, so exit 2 stays 2 and never becomes the 1
  // that verdictSkipped({ require: true }) would produce: CANNOT CHECK must not arrive as FOUND SOMETHING.
  exit: (code: number) => {
    verdictSkipped(`REFUSED, exit ${code}: the docs checkout beside this engine is behind its own origin/main, so nothing was concluded`);
    process.exit(code);
  },
});

const page = readFileSync(resolve(root, PAGE), "utf8");

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

console.log("\n-- the posture checks the docs promise are the whole set --\n");

// The table rows are `| \`check-id\` | ... |`. The page carries other tables (statuses, override kinds), so
// the ids are intersected with what the product grades rather than assumed to be checks.
const tabled = new Set<string>();
for (const m of page.matchAll(/^\|\s*`([a-z][a-z0-9-]*)`\s*\|/gm)) tabled.add(m[1] as string);

const graded = Object.keys(CHECK_SEVERITY);
const missing = graded.filter((id) => !tabled.has(id));
ok(`every graded check is documented (${graded.length} graded)`, missing.length === 0);
if (missing.length > 0) console.log(`       missing from the page: ${missing.join(", ")}`);

// The reverse: a page naming a check the product does not grade sends an auditor looking for a control that
// does not exist. Only ids that LOOK like check ids are considered, so the status and override-kind tables
// on the same page are not mistaken for checks: an id is suspect only if it is absent from CHECK_SEVERITY
// AND appears in the checks table's own severity column shape.
const CHECK_ROW = /^\|\s*`([a-z][a-z0-9-]*)`\s*\|[^|]*\|\s*(Critical|High|Medium|Low)\s*\|/gm;
const documentedChecks: string[] = [];
for (const m of page.matchAll(CHECK_ROW)) documentedChecks.push(m[1] as string);
const phantom = documentedChecks.filter((id) => !Object.hasOwn(CHECK_SEVERITY, id));
ok("the page names no check the product does not grade", phantom.length === 0);
if (phantom.length > 0) console.log(`       named but not graded: ${phantom.join(", ")}`);

// The prose count. A row can be added and the sentence left behind, which is exactly how this page reached
// twenty-one while the product graded twenty-five.
const WORDS: Record<number, string> = {
  20: "twenty", 21: "twenty-one", 22: "twenty-two", 23: "twenty-three", 24: "twenty-four", 25: "twenty-five",
  26: "twenty-six", 27: "twenty-seven", 28: "twenty-eight", 29: "twenty-nine", 30: "thirty",
};
const total = graded.length;
const totalWord = WORDS[total];
ok(`the total ${total} has a spelled form this gate knows`, totalWord !== undefined);
if (totalWord !== undefined) {
  ok(`the page states ${totalWord} named checks`, page.includes(`${totalWord} named checks`));
  ok(`and its summary line says ${totalWord} checks`, page.includes(`That is ${totalWord} checks`));
}

// The per-severity breakdown, which is a second place the same number can go stale independently.
const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
for (const sev of Object.values(CHECK_SEVERITY)) counts[sev] = (counts[sev] ?? 0) + 1;
const SMALL: Record<number, string> = { 1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve" };
const breakdown = `${SMALL[counts.critical ?? 0]} critical, ${SMALL[counts.high ?? 0]} high, ${SMALL[counts.medium ?? 0]} medium and ${SMALL[counts.low ?? 0]} low`;
ok(`the severity breakdown matches the code (${breakdown})`, page.includes(breakdown));

// ---- the alert-events page, the same shape and currently CORRECT ------------------------------------------
// day-2/alert-events.mdx enumerates NOTIFY_EVENT_NAMES with a severity each and states the count three times.
// It is complete and accurate today. It is gated anyway, for the reason the posture page teaches: that page
// was also correct once, and the four checks that drifted onto it did so with nothing watching. A gate is
// cheapest to add while the thing it guards is right.
const eventsPath = resolve(root, "src/content/docs", EVENTS_PAGE);
if (!existsSync(eventsPath)) {
  ok(`the alert-events page exists at ${EVENTS_PAGE}`, false);
} else {
  const events = readFileSync(eventsPath, "utf8");
  const missingEvents = NOTIFY_EVENT_NAMES.filter((e) => !new RegExp(`\\|\\s*\`${e}\`\\s*\\|`).test(events));
  ok(`every notifiable event is documented (${NOTIFY_EVENT_NAMES.length} events)`, missingEvents.length === 0);
  if (missingEvents.length > 0) console.log(`       missing from the page: ${missingEvents.join(", ")}`);

  // The severity column is the engine's own mapping, so it must AGREE with severityOf. It is matched as a
  // PREFIX rather than equality on purpose: three events carry a compound severity ("info, or warning on a
  // shortfall") because the emit site escalates above the static base, and the page is being MORE precise
  // than the mapping there. Demanding equality would punish that precision.
  const wrongSeverity = NOTIFY_EVENT_NAMES.filter((e) => {
    const m = new RegExp(`\\|\\s*\`${e}\`\\s*\\|\\s*([^|]+?)\\s*\\|`).exec(events);
    const documented = m?.[1];
    return documented === undefined || !documented.startsWith(severityOf(e));
  });
  ok("each documented severity starts with the engine's own severityOf value", wrongSeverity.length === 0);
  if (wrongSeverity.length > 0) console.log(`       severity drift: ${wrongSeverity.join(", ")}`);

  const evWord = WORDS[NOTIFY_EVENT_NAMES.length];
  ok(`the event total ${NOTIFY_EVENT_NAMES.length} has a spelled form this gate knows`, evWord !== undefined);
  if (evWord !== undefined) ok(`the page states ${evWord} events`, events.includes(`${evWord} events`));
}

console.log(`\n${failures === 0 ? "POSTURE-AND-DOCS-PARITY PASS" : `POSTURE-AND-DOCS-PARITY: ${failures} FAILED`}\n`);
verdictReached(failures);
process.exit(failures === 0 ? 0 : 1);
