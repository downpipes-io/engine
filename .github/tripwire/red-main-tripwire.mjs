#!/usr/bin/env node
// THE RED-MAIN TRIPWIRE. It opens a GitHub issue the first time main goes red, and closes it when main
// goes green again.
//
// WHY IT EXISTS, measured rather than asserted. The workspace's internal test harness had main red for 38
// consecutive CI runs on 2026-08-03/04 and nothing in this workspace said so. This file is copied into every
// repo, though copies have since diverged (three distinct digests across six repos as at 2026-09-01), so the
// measurement is named against that harness rather than "this repo": a claim that travels must stay true in
// the repo it lands in. What eventually found it was a scheduled sweep by a
// pass looking at something else, which means the thirty-eighth red was the one that got noticed rather
// than the first. Four repos here already run `schedule:` workflows, so the missing thing was never the
// ability to run something periodically; it was that a poll answers "is it red now", and the question worth
// paying for is "when did it STOP being green", which only a transition can answer.
//
// WHY A workflow_run TRIPWIRE AND NOT A POLL, and this is the load-bearing property rather than a
// preference: this workflow is triggered BY the CI run's completion, not by the CI run's success. It is
// therefore the one check in the repo that a red main cannot mask. Every gate that lives inside the CI
// chain shares the chain's fate, so the moment the chain is red the gate grading the chain is silent, which
// is the exact failure mode the 38 runs demonstrated. A poll would also survive that, but a poll fires on
// the thirty-eighth red as readily as the first and cannot tell them apart, and it costs a run every N
// minutes forever rather than one short job per CI run.
//
// TWO FAILURE MODES THIS IS DESIGNED AGAINST, because either makes it useless in the situation it exists
// for.
//
//   NOISE. It must not open a fresh issue on every red run of an ongoing streak. Thirty-eight issues is
//   thirty-eight notifications, and a notification stream nobody can read is indistinguishable from
//   silence. So an open tripwire issue suppresses opening another. The streak is not lost: each further
//   red run EDITS the open issue, which GitHub does not notify on, so the streak is visible in one place
//   at no cost to the reader.
//
//   SILENCE ON AN ABSENT PREDECESSOR. "The previous run was green" is not the only reason to fire.
//   Five of the 49 commits between the internal test harness's last green and the streak's discovery received NO CI RUN AT
//   ALL, because pushes were batched and only the tip of a push is graded. A run can also be cancelled,
//   skipped or fail at startup, and the very first run of a workflow has no predecessor by construction.
//   Treating any of those as "not a transition" would make the tripwire quietest exactly where the history
//   is thinnest. So only a predecessor POSITIVELY KNOWN to be a failure suppresses the alert. Absent,
//   cancelled, skipped, timed out and startup_failure all fire.
//
// THE ONE COST THIS ACCEPTS, stated rather than hidden: installed part way through an existing red streak,
// it stays quiet until main goes green once, because every red it sees has a red predecessor. That is the
// same rule that makes it quiet during a streak, and it self-heals on the first green. The alternative,
// firing on a red with a red predecessor whenever no issue is open, reopens an issue a human has just
// deliberately closed, on the next CI run, forever. Between a tripwire that can be silenced by a human
// decision and one that cannot be silenced at all, the first is the one people keep.
//
// SELF-TEST FIRST, EVERY RUN. decide() is pure and the fixtures below exercise every branch of it,
// including an anti-vacuity check that the fixture set still reaches every action and that decide() has not
// collapsed to a constant. The live path refuses to run if any fixture fails, because a tripwire whose
// decision function has stopped being able to say "open" is a tripwire that reports quiet.
//
// Usage:
//   node .github/tripwire/red-main-tripwire.mjs --selftest    fixtures only, no network, no writes
//   node .github/tripwire/red-main-tripwire.mjs --dry-run     decide against the live API, write nothing
//   node .github/tripwire/red-main-tripwire.mjs               decide and act
//
// Environment, all supplied by the workflow:
//   GH_TOKEN            a token with issues: write and actions: read on this repo
//   GITHUB_REPOSITORY   owner/name
//   GITHUB_API_URL      optional, defaults to https://api.github.com
//   TRIPWIRE_RUN_JSON   the triggering run, as ${{ toJSON(github.event.workflow_run) }}
//
// House style: Australian English, no em dashes, no rule-of-three, precise claims.

const LABEL = "red-main";
const MARKER = "<!-- red-main-tripwire -->";
const STREAK_MARKER = "<!-- red-main-tripwire:streak -->";

// ---- the decision, pure ------------------------------------------------------------------------------
//
// previousState is one of:
//   "success"        the previous completed run on this branch concluded success
//   "failure"        it concluded failure, so this red is a continuation rather than a transition
//   "absent"         there is no earlier completed run of this workflow on this branch at all
//   "indeterminate"  there is one, and it concluded cancelled / skipped / timed_out / startup_failure /
//                    action_required / neutral / null. It is not evidence that main was green, and it is
//                    not evidence that main was red.
//
// Returns { action, why } where action is one of "open", "update", "close", "none".
export function decide({ conclusion, previousState, hasOpenIssue }) {
  if (conclusion === "success") {
    return hasOpenIssue
      ? { action: "close", why: "main is green again and a red-main issue is open" }
      : { action: "none", why: "main is green and no red-main issue is open" };
  }
  if (conclusion !== "failure") {
    // Cancelled, skipped, timed out, neutral, action_required. None of these is evidence about main, and
    // a cancelled run is routinely a superseded push rather than a fault. Acting on them would make the
    // tripwire fire on ordinary traffic, which is the noise rule again one step along.
    return { action: "none", why: `conclusion ${String(conclusion)} is not evidence about main either way` };
  }
  if (hasOpenIssue) {
    return { action: "update", why: "main is still red and its issue is already open, so the streak is recorded there rather than in a new issue" };
  }
  if (previousState === "failure") {
    return { action: "none", why: "the previous run on this branch was already red, so this is a streak and not a transition" };
  }
  return {
    action: "open",
    why:
      previousState === "success"
        ? "main went from green to red"
        : previousState === "absent"
          ? "main is red and there is no earlier run to compare against, which is not a reason to stay quiet"
          : `main is red and the previous run concluded ${previousState}, which is not evidence that main was green`,
  };
}

// ---- adoption, which is the question the transition rule cannot answer -------------------------------
//
// decide() grades a TRANSITION, so it is silent about a main that was already red before it was installed:
// every red it sees has a red predecessor, and the README states that cost plainly. Two of the three
// saturated repos in this workspace on 2026-08-05 were in exactly that position, so for them a transition
// tripwire would have opened nothing, ever, until main went green once of its own accord.
//
// decideAdopt() grades a STATE instead: main is red now, and no issue says so. It is deliberately a
// different function rather than a flag on decide(), because the two answer different questions and
// merging them would let the state rule leak into the per-run path, where it reopens an issue a human just
// closed on the very next CI run. That is the noise failure the whole design is built to avoid.
//
// IT IS RUN ONCE, BY HAND, AND THE WORKFLOW DOES NOT CALL IT. There is no `schedule:` for it on purpose.
// A cron that asks "is main red" answers the same way on the first red and the thirty-eighth, which is how
// a scheduled sweep came to find a 38-run streak on its thirty-eighth run rather than its first. Adoption
// is a one-shot that converts an existing streak into the same durable issue the transition path would
// have opened, after which the transition path carries it, including closing it on the first green.
export function decideAdopt({ conclusion, hasOpenIssue }) {
  if (conclusion !== "failure") {
    return { action: "none", why: `the latest completed run on main concluded ${String(conclusion)}, so there is no standing red to adopt` };
  }
  if (hasOpenIssue) {
    return { action: "none", why: "main is red and an issue already says so, so there is nothing to adopt" };
  }
  return { action: "open", why: "main is red now and nothing says so, which no transition will ever reveal" };
}

/**
 * The workflows in this repo, other than the one being graded, that a push to `branch` can run.
 *
 * WHY THIS EXISTS. This tripwire grades ONE workflow, and its issue previously read as though it graded
 * main. On the docs repo at b0cc5ccd the CI workflow concluded success while Security Audit concluded
 * failure at the same commit, so main was red and the tripwire was correct, silent and misleading at once.
 * A reader cannot be expected to hold the difference in their head, so the issue names the gap.
 *
 * IT READS THE CHECKOUT, NOT THE API. The job already checks out main, the files are on disk, and this adds
 * no dependency to a script whose whole design is to depend on nothing in the repo it watches. A file that
 * cannot be read is skipped rather than guessed at.
 *
 * THE PARSE IS DELIBERATELY NARROW. It recognises a top-level `on:` block containing a `push:` key whose
 * `branches:` names this branch, in either the inline or the dashed-list form. A workflow triggered some
 * other way, `push:` on tags alone among them, is not a workflow a push to this branch can run, and is not
 * listed. Comments are stripped before any key is matched, because a scanner that reads a commented-out
 * `push:` as a real one is the failure mode this workspace has already shipped once.
 */
export function otherPushWorkflows(files, branch, gradedName) {
  const out = [];
  for (const { text } of files) {
    const lines = text.split("\n").map((l) => (l.trimStart().startsWith("#") ? "" : l.replace(/\s+#.*$/, "")));
    const nameLine = lines.find((l) => /^name:\s*\S/.test(l));
    if (nameLine === undefined) continue;
    const name = nameLine.replace(/^name:\s*/, "").trim().replace(/^["']|["']$/g, "");
    if (name === gradedName) continue;
    const onAt = lines.findIndex((l) => /^(on|["']on["']):\s*$/.test(l));
    if (onAt === -1) continue;
    let onEnd = lines.length;
    for (let i = onAt + 1; i < lines.length; i++) {
      if (/^\S/.test(lines[i])) { onEnd = i; break; }
    }
    const onBlock = lines.slice(onAt + 1, onEnd);
    const pushAt = onBlock.findIndex((l) => /^ {2}push:\s*$/.test(l));
    if (pushAt === -1) continue;
    let pushEnd = onBlock.length;
    for (let i = pushAt + 1; i < onBlock.length; i++) {
      if (/^ {0,2}\S/.test(onBlock[i])) { pushEnd = i; break; }
    }
    const pushBlock = onBlock.slice(pushAt + 1, pushEnd);
    const branchesAt = pushBlock.findIndex((l) => /^ {4}branches:/.test(l));
    if (branchesAt === -1) continue;
    const unquote = (s) => s.trim().replace(/^["']|["']$/g, "");
    const inline = pushBlock[branchesAt].replace(/^ {4}branches:\s*/, "").trim();
    const named = [];
    if (inline.startsWith("[")) {
      for (const item of inline.replace(/^\[|\]$/g, "").split(",")) if (item.trim() !== "") named.push(unquote(item));
    } else {
      for (const l of pushBlock.slice(branchesAt + 1)) {
        if (/^ {6}-\s*\S/.test(l)) named.push(unquote(l.replace(/^ {6}-\s*/, "")));
        else if (l.trim() !== "") break;
      }
    }
    if (named.includes(branch)) out.push(name);
  }
  return out.sort((a, b) => a.localeCompare(b));
}

/** The `.github/workflows` files of the checkout, as { text } records. Empty if the directory is unreadable. */
async function workflowFiles() {
  try {
    const { readdirSync, readFileSync } = await import("node:fs");
    return readdirSync(".github/workflows")
      .filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"))
      .map((f) => ({ text: readFileSync(`.github/workflows/${f}`, "utf8") }));
  } catch {
    return [];
  }
}

/**
 * The scope paragraph. It is on every issue this tripwire opens, because the gap it names is the one thing a
 * reader cannot infer from the issue's presence or its absence.
 */
export function scopeLines(gradedName, branch, others) {
  const lines = [
    "### What this tripwire does not watch",
    "",
    `It grades the workflow named \`${gradedName}\` and nothing else, so its silence means \`${gradedName}\` is green rather than \`${branch}\` is.`,
  ];
  if (others.length === 0) {
    lines.push("", `No other workflow in this repo runs on a push to \`${branch}\`, so on this repo the two happen to mean the same thing.`);
  } else {
    lines.push(
      "",
      `${others.length} other workflow${others.length === 1 ? "" : "s"} in this repo can also run on a push to \`${branch}\` and ${others.length === 1 ? "is" : "are"} outside this tripwire: ${others.map((n) => `\`${n}\``).join(", ")}.`,
      "",
      "Widening the trigger to cover them is not a one-line change. This tripwire keeps one issue per repo, so a",
      "second watched workflow concluding success closes the issue a first one opened, and at a commit where the",
      "two disagree the answer depends on which finishes first. See ORDER_FIXTURES in",
      "`.github/tripwire/red-main-tripwire.mjs`, which runs both orders and asserts they still differ.",
    );
  }
  return lines;
}

/** Map a run's conclusion to the three-way state above. */
export function stateOf(previousRun) {
  if (previousRun === undefined || previousRun === null) return "absent";
  if (previousRun.conclusion === "success") return "success";
  if (previousRun.conclusion === "failure") return "failure";
  return "indeterminate";
}

// ---- the fixtures ------------------------------------------------------------------------------------
const FIXTURES = [
  // The transition this whole thing exists for.
  { name: "green then red opens", input: { conclusion: "failure", previousState: "success", hasOpenIssue: false }, want: "open" },
  // The noise rule, in both of the shapes a streak takes.
  { name: "red then red with an issue open only updates", input: { conclusion: "failure", previousState: "failure", hasOpenIssue: true }, want: "update" },
  { name: "red then red with no issue stays quiet", input: { conclusion: "failure", previousState: "failure", hasOpenIssue: false }, want: "none" },
  // A second red inside a streak whose predecessor was not itself a failure. The issue is open, so it must
  // still not open another: hasOpenIssue outranks the transition.
  { name: "red after green but an issue is already open updates rather than opening a second", input: { conclusion: "failure", previousState: "success", hasOpenIssue: true }, want: "update" },
  // The absent-predecessor rule. Both of its shapes fire.
  { name: "red with no previous run at all opens", input: { conclusion: "failure", previousState: "absent", hasOpenIssue: false }, want: "open" },
  { name: "red after a cancelled run opens", input: { conclusion: "failure", previousState: "indeterminate", hasOpenIssue: false }, want: "open" },
  // Recovery.
  { name: "green with an issue open closes it", input: { conclusion: "success", previousState: "failure", hasOpenIssue: true }, want: "close" },
  { name: "green with no issue does nothing", input: { conclusion: "success", previousState: "success", hasOpenIssue: false }, want: "none" },
  { name: "green with no issue does nothing even after a red", input: { conclusion: "success", previousState: "failure", hasOpenIssue: false }, want: "none" },
  // Conclusions that are not evidence. A cancelled run must never close an open issue: main is still red,
  // and a superseded push cancelling a run would otherwise clear the alert while nothing was fixed.
  { name: "a cancelled run does not close an open issue", input: { conclusion: "cancelled", previousState: "failure", hasOpenIssue: true }, want: "none" },
  { name: "a skipped run does nothing", input: { conclusion: "skipped", previousState: "success", hasOpenIssue: false }, want: "none" },
  { name: "a null conclusion does nothing", input: { conclusion: null, previousState: "success", hasOpenIssue: true }, want: "none" },
  // stateOf, which is where a conclusion string becomes one of the three words above.
  { name: "stateOf undefined is absent", state: undefined, want: "absent" },
  { name: "stateOf a success run", state: { conclusion: "success" }, want: "success" },
  { name: "stateOf a failure run", state: { conclusion: "failure" }, want: "failure" },
  { name: "stateOf a cancelled run is indeterminate", state: { conclusion: "cancelled" }, want: "indeterminate" },
  { name: "stateOf a startup_failure run is indeterminate", state: { conclusion: "startup_failure" }, want: "indeterminate" },
  { name: "stateOf a run still without a conclusion is indeterminate", state: { conclusion: null }, want: "indeterminate" },
];

// Fixtures for the state rule, kept apart from the transition fixtures because the two functions must not
// be allowed to converge. The load-bearing pair is the first two: adoption fires on a red whose predecessor
// was also red, which is precisely the case decide() declines.
const ADOPT_FIXTURES = [
  { name: "a standing red with no issue is adopted", input: { conclusion: "failure", hasOpenIssue: false }, want: "open" },
  { name: "a standing red that already has an issue is not adopted twice", input: { conclusion: "failure", hasOpenIssue: true }, want: "none" },
  { name: "a green main is not adopted", input: { conclusion: "success", hasOpenIssue: false }, want: "none" },
  { name: "adoption never closes, that stays the transition path's job", input: { conclusion: "success", hasOpenIssue: true }, want: "none" },
  { name: "a cancelled latest run is not adopted", input: { conclusion: "cancelled", hasOpenIssue: false }, want: "none" },
  { name: "a null conclusion is not adopted", input: { conclusion: null, hasOpenIssue: false }, want: "none" },
];

// ---- what widening `workflows:` would cost, run rather than argued -----------------------------------
//
// THE QUESTION. This tripwire watches one workflow, and eight workflows can fail on a push to main in the
// docs repo, so its silence is not the same claim as "main is green". The obvious repair is to widen the
// `workflows:` list in the workflow file. This section exists because that repair is worse than the gap.
//
// THE COUPLING. previousRun() queries `/actions/workflows/{workflow_id}/runs`, so the transition history is
// per watched workflow. openTripwireIssue() searches the repo for ONE issue carrying one marker, so the
// issue is NOT per watched workflow. Two watched workflows therefore share one piece of state, and decide()
// closes that state on any success while an issue is open. Nothing in the decision path groups by head sha.
//
// THE CONSEQUENCE, which is what the fixtures below run. At one commit with CI green and Security Audit red,
// the outcome depends on which run finishes first. Security Audit first opens the issue and CI then closes
// it, so the repo reports green while a gate is red. CI first does nothing and Security Audit then opens the
// issue, which is correct. Same commit, same two conclusions, opposite answers.
//
// THIS FIXTURE IS ALSO A TRIPWIRE ON THE TRIPWIRE. It asserts that the two orders DISAGREE. If someone later
// gives each watched workflow its own issue marker the disagreement goes away, this fixture fails, and its
// failure message is the go-ahead to widen the list.
export function simulateSharedIssue(events) {
  let hasOpenIssue = false;
  const trace = [];
  for (const e of events) {
    const { action } = decide({ conclusion: e.conclusion, previousState: e.previousState, hasOpenIssue });
    if (action === "open") hasOpenIssue = true;
    else if (action === "close") hasOpenIssue = false;
    trace.push(`${e.workflow} ${e.conclusion} -> ${action}`);
  }
  return { hasOpenIssue, trace };
}

// Both orders describe ONE commit on main: CI concluded success on it and Security Audit concluded failure
// on it. That is not hypothetical, it is what docs did at b0cc5ccd.
const SAME_SHA_AUDIT_RED_FIRST = [
  { workflow: "Security Audit", conclusion: "failure", previousState: "success" },
  { workflow: "CI", conclusion: "success", previousState: "success" },
];
const SAME_SHA_CI_GREEN_FIRST = [
  { workflow: "CI", conclusion: "success", previousState: "success" },
  { workflow: "Security Audit", conclusion: "failure", previousState: "success" },
];

const ORDER_FIXTURES = [
  { name: "widened: audit red then CI green at one sha ends with NO issue, so a red gate is reported as green", events: SAME_SHA_AUDIT_RED_FIRST, wantOpen: false },
  { name: "widened: CI green then audit red at one sha ends with an issue open", events: SAME_SHA_CI_GREEN_FIRST, wantOpen: true },
  // Not a race, just arithmetic: once the issue is shared, the next green run of any watched workflow closes
  // a standing red belonging to another one. A11y Axe, which the docs and website repos carry and the other
  // three do not, is paths-filtered and is often the only one a push to either of those runs.
  { name: "widened: a standing audit red is closed by the next green run of an unrelated watched workflow", events: [{ workflow: "Security Audit", conclusion: "failure", previousState: "success" }, { workflow: "A11y Axe", conclusion: "success", previousState: "success" }], wantOpen: false },
  // The control. Watching one workflow, which is what this repo does, has no order to get wrong.
  { name: "unwidened: CI alone, green then red, opens and stays open", events: [{ workflow: "CI", conclusion: "success", previousState: "success" }, { workflow: "CI", conclusion: "failure", previousState: "success" }], wantOpen: true },
  // A skipped run must never be read as redness. Scorecard carries `if: github.event.repository.private ==
  // false`, so it concludes `skipped` on every run while a repo is private, and the streaks are long. Every
  // count below is the unbroken run of skips on main as at 2026-08-05, measured by paginating that
  // workflow's whole run history and reading down from the newest, so each is bounded by a real non-skipped
  // run rather than by the edge of a page: 199 on docs, 85 on downpipe, 56 on control-plane, and none at all
  // on website or the internal test harness, neither of which carries a `scorecard.yml`, so in those two
  // the streak has no subject rather than a small value. That test harness's own was measured the same way
  // and by the same rule it comes out absent: the workflows API lists exactly two workflows for it, its CI
  // workflow and this tripwire, so
  // there is no Scorecard run history to read down. A naive "latest run was not success" reader would call
  // every one of the skips in the other three a red main.
  //
  // The repos are named individually because this file is copied into all of them, and a count measured in
  // one is not a fact about the others: an earlier copy of this comment stated a streak of 14 as a fact about
  // "this repo" and was wrong in every repo it was read in, docs included, by more than an order of
  // magnitude. Treat the counts as a dated measurement and the `if` above as the durable fact, because each
  // count grows by one on every push and is stale by the time it is read.
  { name: "unwidened: a skipped run of a watched workflow opens nothing", events: [{ workflow: "Scorecard", conclusion: "skipped", previousState: "success" }], wantOpen: false },
  { name: "unwidened: a skipped run does not close a standing red either", events: [{ workflow: "CI", conclusion: "failure", previousState: "success" }, { workflow: "Scorecard", conclusion: "skipped", previousState: "success" }], wantOpen: true },
];

// Fixtures for the workflow-file parse. A parser is graded on what it must NOT match as much as on what it
// must, so half of these are workflows that a push to main does not run.
const wf = (text) => [{ text }];
const PARSE_FIXTURES = [
  { name: "a push trigger with an inline branch list is listed", files: wf('name: Docs lints\non:\n  push:\n    branches: [main]\n'), want: ["Docs lints"] },
  { name: "a push trigger with a dashed branch list is listed", files: wf('name: Biome\non:\n  push:\n    branches:\n      - main\n      - release\n'), want: ["Biome"] },
  { name: "a quoted branch name is listed", files: wf("name: Q\non:\n  push:\n    branches: ['main']\n"), want: ["Q"] },
  { name: "the graded workflow is never listed against itself", files: wf('name: CI\non:\n  push:\n    branches: [main]\n'), want: [] },
  { name: "a push on tags only is not a push to main", files: wf("name: Release\non:\n  push:\n    tags:\n      - 'v*'\n"), want: [] },
  { name: "a push to another branch is not a push to main", files: wf('name: Elsewhere\non:\n  push:\n    branches: [develop]\n'), want: [] },
  { name: "a pull_request trigger alone is not a push", files: wf('name: PR only\non:\n  pull_request:\n    branches: [main]\n'), want: [] },
  { name: "a schedule alone is not a push", files: wf("name: Weekly\non:\n  schedule:\n    - cron: '0 5 * * 1'\n"), want: [] },
  { name: "a workflow_run trigger is not a push, so the tripwire never lists itself", files: wf('name: Red-main tripwire\non:\n  workflow_run:\n    workflows: ["CI"]\n    branches: [main]\n'), want: [] },
  // The comment trap. A scanner that reads commented-out YAML as live YAML has already shipped in this
  // workspace once, so both the whole-line and the trailing forms are graded.
  { name: "a commented-out push trigger is not a trigger", files: wf('name: Commented\non:\n  # push:\n  #   branches: [main]\n  pull_request:\n    branches: [main]\n'), want: [] },
  { name: "a trailing comment naming main does not create a trigger", files: wf('name: Trailing\non:\n  pull_request: # push branches: [main] one day\n    branches: [main]\n'), want: [] },
  { name: "several files are listed together and sorted", files: [{ text: 'name: Zed\non:\n  push:\n    branches: [main]\n' }, { text: 'name: Alpha\non:\n  push:\n    branches: [main]\n' }], want: ["Alpha", "Zed"] },
  { name: "a file with no name key is skipped rather than guessed at", files: wf('on:\n  push:\n    branches: [main]\n'), want: [] },
  { name: "paths filters do not stop a workflow being listed, because a filtered workflow still reddens main when it runs", files: wf("name: Filtered\non:\n  push:\n    branches: [main]\n    paths:\n      - 'src/**'\n"), want: ["Filtered"] },
];

export function selftest() {
  const failures = [];
  const actionsSeen = new Set();
  const adoptSeen = new Set();
  for (const f of PARSE_FIXTURES) {
    const got = otherPushWorkflows(f.files, "main", "CI");
    if (got.join("|") !== f.want.join("|")) failures.push(`parse/${f.name}: wanted [${f.want}], got [${got}]`);
  }
  if (PARSE_FIXTURES.length < 14) failures.push(`only ${PARSE_FIXTURES.length} parse fixtures, below the floor of 14`);
  // A parser that returned the empty list for everything would pass eight of the fourteen above, so at least
  // one fixture must come back non-empty.
  if (!PARSE_FIXTURES.some((f) => f.want.length > 0 && otherPushWorkflows(f.files, "main", "CI").length > 0)) {
    failures.push("no parse fixture returns a workflow, so otherPushWorkflows may have collapsed to the empty list");
  }
  // The scope paragraph must say something different when there is a gap and when there is not, or it stops
  // carrying the finding it exists for.
  if (scopeLines("CI", "main", []).join("\n") === scopeLines("CI", "main", ["Security Audit"]).join("\n")) {
    failures.push("scopeLines reads the same with and without unwatched workflows, so it names no gap");
  }
  if (!scopeLines("CI", "main", ["Security Audit"]).join("\n").includes("Security Audit")) {
    failures.push("scopeLines does not name the unwatched workflows it was given");
  }
  for (const f of ORDER_FIXTURES) {
    const { hasOpenIssue, trace } = simulateSharedIssue(f.events);
    if (hasOpenIssue !== f.wantOpen) failures.push(`order/${f.name}: wanted issue open=${f.wantOpen}, got ${hasOpenIssue} via ${trace.join(" | ")}`);
  }
  // The disagreement itself is the finding, so it is asserted rather than left implicit in two fixtures that
  // could both be edited to agree. When this line fails, the shared-issue coupling is gone and widening the
  // `workflows:` list in red-main-tripwire.yml has become safe.
  if (simulateSharedIssue(SAME_SHA_AUDIT_RED_FIRST).hasOpenIssue === simulateSharedIssue(SAME_SHA_CI_GREEN_FIRST).hasOpenIssue) {
    failures.push("the two completion orders at one sha now agree, so the one issue per repo is no longer shared across watched workflows and `workflows:` can be widened");
  }
  if (ORDER_FIXTURES.length < 6) failures.push(`only ${ORDER_FIXTURES.length} order fixtures, below the floor of 6`);
  for (const f of ADOPT_FIXTURES) {
    const got = decideAdopt(f.input).action;
    adoptSeen.add(got);
    if (got !== f.want) failures.push(`adopt/${f.name}: wanted ${f.want}, got ${got}`);
  }
  // Same anti-vacuity argument as below. An adoption rule collapsed to "none" would pass five of these six
  // and fail silently on the only one it exists for, so both of its actions must be reached.
  for (const required of ["open", "none"]) {
    if (!adoptSeen.has(required)) failures.push(`no adopt fixture reaches action "${required}", so that branch is ungraded`);
  }
  if (ADOPT_FIXTURES.length < 6) failures.push(`only ${ADOPT_FIXTURES.length} adopt fixtures, below the floor of 6`);
  for (const f of FIXTURES) {
    const got = Object.hasOwn(f, "state") ? stateOf(f.state) : decide(f.input).action;
    if (Object.hasOwn(f, "input")) actionsSeen.add(got);
    if (got !== f.want) failures.push(`${f.name}: wanted ${f.want}, got ${got}`);
  }
  // ANTI-VACUITY. Every count above is derived from FIXTURES, so an emptied or truncated fixture list
  // reports a clean sweep having compared nothing, and a decide() that had collapsed to returning "none"
  // for everything would pass every "none" case while failing silently on the one case the tripwire is
  // for. Both are caught by requiring that the fixture set still reaches all four actions.
  for (const required of ["open", "update", "close", "none"]) {
    if (!actionsSeen.has(required)) failures.push(`no fixture reaches action "${required}", so that branch is ungraded`);
  }
  if (FIXTURES.length < 15) failures.push(`only ${FIXTURES.length} fixtures, below the floor of 15`);
  if (failures.length > 0) {
    console.error(`[tripwire] SELF-TEST FAILED, ${failures.length} of ${FIXTURES.length + 4} checks:`);
    for (const f of failures) console.error(`  ${f}`);
    return false;
  }
  console.log(`[tripwire] self-test OK: ${FIXTURES.length} transition fixtures with all four actions reached, ${ADOPT_FIXTURES.length} adoption fixtures with both, ${ORDER_FIXTURES.length} shared-issue order fixtures with the two orders still disagreeing, ${PARSE_FIXTURES.length} workflow-trigger parse fixtures.`);
  return true;
}

// ---- the live path -----------------------------------------------------------------------------------

const API = (process.env.GITHUB_API_URL ?? "https://api.github.com").replace(/\/+$/, "");
const REPO = process.env.GITHUB_REPOSITORY ?? "";
const TOKEN = process.env.GH_TOKEN ?? "";

async function api(method, path, body) {
  const res = await fetch(path.startsWith("http") ? path : `${API}${path}`, {
    method,
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${TOKEN}`,
      "x-github-api-version": "2022-11-28",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${method} ${path} -> ${res.status} ${res.statusText}: ${text.slice(0, 400)}`);
  }
  return res.status === 204 ? null : res.json();
}

/**
 * The completed run on this branch immediately before this one, or undefined if there is none.
 *
 * THE `created` BOUND IS LOAD-BEARING and was added after the first dry run got it wrong. The runs endpoint
 * returns the workflow's most recent runs, newest first, with no notion of "before this one". Asked for one
 * page and then filtered down to run numbers below the run being graded, it answers correctly for the
 * newest run and answers "there is no previous run" for anything older than a page, because the page it
 * fetched contains nothing old enough. Measured against the internal test harness's own history on 2026-08-04: grading run
 * #281, the first red of the 38-run streak, reported previousState "absent" when run #280 exists and
 * concluded success. That is not a harmless imprecision. The two states produce the same ACTION here, but
 * the issue body would have told a reader there was nothing to compare against on the one run where the
 * comparison is the whole finding, and it would have skipped the ungraded-commit range that comparison
 * feeds. Bounding the query by the graded run's own created_at makes the first page the right page at any
 * age, and the paging loop below covers a bound that lands on a burst of same-second runs.
 */
async function previousRun(run) {
  const isEarlier = (r) =>
    r.id !== run.id &&
    r.event !== "pull_request" &&
    // run_number is monotonic per workflow and a re-run keeps it, so it orders runs the way a reader does.
    // created_at breaks the tie between attempts of one run number.
    (r.run_number < run.run_number || (r.run_number === run.run_number && Date.parse(r.created_at) < Date.parse(run.created_at)));
  for (let page = 1; page <= 3; page++) {
    const q = new URLSearchParams({
      branch: run.head_branch,
      status: "completed",
      per_page: "30",
      page: String(page),
      exclude_pull_requests: "true",
      created: `<=${run.created_at}`,
    });
    const list = await api("GET", `/repos/${REPO}/actions/workflows/${run.workflow_id}/runs?${q}`);
    const runs = list.workflow_runs ?? [];
    const earlier = runs.filter(isEarlier).sort((a, b) => b.run_number - a.run_number || Date.parse(b.created_at) - Date.parse(a.created_at));
    if (earlier.length > 0) return earlier[0];
    if (runs.length < 30) return undefined;
  }
  return undefined;
}

/**
 * How long main has been red, read from state rather than from an event. Walks the completed runs of one
 * named workflow on main, newest first, and stops at the first success.
 *
 * IT COUNTS RUNS THAT ARE NOT SUCCESSES, NOT RUNS THAT FAILED. A streak broken up by cancelled runs, which
 * is what a repo taking rapid pushes looks like, is one streak and not three. The `latest` it returns is
 * still graded on its own conclusion by decideAdopt, so a cancelled newest run adopts nothing.
 */
async function mainStreak(workflowName) {
  const runs = [];
  for (let page = 1; page <= 4; page++) {
    const q = new URLSearchParams({ branch: "main", status: "completed", per_page: "100", page: String(page), exclude_pull_requests: "true" });
    const list = await api("GET", `/repos/${REPO}/actions/runs?${q}`);
    const got = list.workflow_runs ?? [];
    for (const r of got) if (r.name === workflowName) runs.push(r);
    if (got.length < 100) break;
  }
  runs.sort((a, b) => b.run_number - a.run_number || Date.parse(b.created_at) - Date.parse(a.created_at));
  if (runs.length === 0) return { latest: undefined, streak: 0, oldest: undefined, exhausted: false };
  let streak = 0;
  let oldest;
  for (const r of runs) {
    if (r.conclusion === "success") break;
    streak += 1;
    oldest = r;
  }
  // Honest about the window rather than reporting a floor as a total. A streak that fills the pages read is
  // "at least this long", and saying so is the difference between a measurement and a guess.
  return { latest: runs[0], streak, oldest, exhausted: streak === runs.length };
}

function adoptBody({ workflowName, latest, streak, oldest, exhausted, others }) {
  const age = oldest === undefined ? "unknown" : `${((Date.now() - Date.parse(oldest.created_at)) / 3600000).toFixed(1)} hours`;
  return [
    MARKER,
    "",
    `**${workflowName}** has not concluded \`success\` on \`main\` for ${exhausted ? "at least " : ""}${streak} consecutive completed run${streak === 1 ? "" : "s"}.`,
    "",
    "| | |",
    "| --- | --- |",
    `| Commit | \`${latest.head_sha}\` |`,
    `| Latest run | [#${latest.run_number}](${latest.html_url}), concluded \`${latest.conclusion}\` |`,
    oldest === undefined ? "" : `| Red since | [#${oldest.run_number}](${oldest.html_url}) at \`${oldest.head_sha.slice(0, 8)}\`, ${oldest.created_at}, about ${age} ago |`,
    `| Why this fired | the tripwire was installed onto a main that was already red |`,
    "",
    "This issue was opened by the red-main tripwire's one-shot adoption, not by a transition. The transition",
    "path is silent about a main that was already red when it was installed, because every red it sees has a",
    "red predecessor, so a standing streak would otherwise never be reported at all. From here the ordinary",
    "path carries this issue: further red runs are appended below, and the first run that concludes success",
    "closes it.",
    "|SCOPE|",
    STREAK_MARKER,
  ]
    .filter((l) => l !== "")
    .join("\n")
    // The blank-line filter above is what keeps the table together, so the scope paragraph is spliced in
    // after it rather than written through it.
    .replace("|SCOPE|", ["", ...scopeLines(workflowName, "main", others), ""].join("\n"));
}

/** The jobs of a run that did not succeed, named. */
async function failedJobs(runId) {
  const out = [];
  for (let page = 1; page <= 5; page++) {
    const list = await api("GET", `/repos/${REPO}/actions/runs/${runId}/jobs?per_page=100&page=${page}&filter=latest`);
    for (const j of list.jobs ?? []) if (j.conclusion !== "success" && j.conclusion !== "skipped") out.push(j);
    if ((list.jobs ?? []).length < 100) break;
  }
  return out;
}

/** The open tripwire issue, if there is one. */
async function openTripwireIssue() {
  const q = new URLSearchParams({ state: "open", labels: LABEL, per_page: "20" });
  const list = await api("GET", `/repos/${REPO}/issues?${q}`);
  return (list ?? []).filter((i) => i.pull_request === undefined).find((i) => typeof i.body === "string" && i.body.includes(MARKER));
}

/**
 * The commits between the previously graded run and this one. Five of 49 commits on the internal test harness went
 * ungraded because a batched push grades only its tip, so the reader needs to know which commits are in
 * the blast radius rather than only which sha the runner happened to see.
 */
async function ungradedBetween(previous, run) {
  if (previous === undefined || previous.head_sha === run.head_sha) return [];
  try {
    const cmp = await api("GET", `/repos/${REPO}/compare/${previous.head_sha}...${run.head_sha}`);
    // The last commit IS this run's head, which was graded. Everything before it was not graded on its own.
    return (cmp.commits ?? []).slice(0, -1).map((c) => ({ sha: c.sha, title: (c.commit?.message ?? "").split("\n")[0] }));
  } catch (err) {
    // A degraded range is worth saying rather than hiding, but it is never worth suppressing the alert.
    console.log(`[tripwire] could not compare ${previous.head_sha}..${run.head_sha}: ${err.message}`);
    return [];
  }
}

function issueBody({ run, previous, previousState, jobs, ungraded, others }) {
  const lines = [
    MARKER,
    `**${run.name}** concluded \`failure\` on \`${run.head_branch}\`.`,
    "",
    `| | |`,
    `| --- | --- |`,
    `| Commit | \`${run.head_sha}\` |`,
    `| Run | [#${run.run_number}](${run.html_url}) |`,
    `| Previous run on this branch | ${previous === undefined ? "**none**, this is the first" : `[#${previous.run_number}](${previous.html_url}) at \`${previous.head_sha}\`, concluded \`${previous.conclusion ?? "null"}\``} |`,
    `| Why this fired | ${previousState === "success" ? "green to red transition" : previousState === "absent" ? "no earlier run to compare against" : `previous run concluded \`${previousState}\`, which is not evidence main was green`} |`,
    "",
    "### Jobs that did not succeed",
    "",
  ];
  if (jobs.length === 0) lines.push("No job reported a non-success conclusion, so the run itself failed before or outside its jobs (a startup failure, or a cancelled matrix).");
  else for (const j of jobs) lines.push(`- **${j.name}** (\`${j.conclusion}\`) [log](${j.html_url})`);
  if (ungraded.length > 0) {
    lines.push(
      "",
      "### Commits in this window that got no CI run of their own",
      "",
      "A batched push is graded only at its tip, so any of these could be the one that broke it.",
      "",
    );
    for (const c of ungraded) lines.push(`- \`${c.sha.slice(0, 8)}\` ${c.title}`);
  }
  lines.push(
    "",
    ...scopeLines(run.name, run.head_branch, others),
    "",
    "This issue was opened by the red-main tripwire on the first red run after a green one, and it closes",
    "itself when a run on this branch concludes success. It does not open a second issue while this one is",
    "open; further red runs are appended below.",
    "",
    STREAK_MARKER,
  );
  return lines.join("\n");
}

/**
 * Append a streak line to an already open issue. An issue EDIT does not notify subscribers, which is the
 * whole reason a streak is recorded this way rather than as a comment: the reader who wants the length of
 * the streak can see it, and the reader who does not is not paged for it.
 */
function withStreakLine(body, run, jobs) {
  const at = body.indexOf(STREAK_MARKER);
  const head = at === -1 ? `${body}\n\n${STREAK_MARKER}` : body.slice(0, at + STREAK_MARKER.length);
  const tail = at === -1 ? "" : body.slice(at + STREAK_MARKER.length);
  const names = jobs.length === 0 ? "no job named" : jobs.map((j) => j.name).join(", ");
  const line = `\n- still red at \`${run.head_sha.slice(0, 8)}\`, run [#${run.run_number}](${run.html_url}), ${names}`;
  // Idempotent: a re-run of the tripwire over the same CI run must not double the line.
  if (tail.includes(`run [#${run.run_number}](`)) return body;
  return `${head}${tail}${line}`;
}

async function main() {
  if (!selftest()) process.exit(1);
  if (process.argv.includes("--selftest")) return;

  const dryRun = process.argv.includes("--dry-run");

  if (process.argv.includes("--adopt")) {
    const workflowName = process.env.TRIPWIRE_WORKFLOW ?? "";
    if (REPO === "" || TOKEN === "" || workflowName === "") {
      console.error("[tripwire] --adopt needs GITHUB_REPOSITORY, GH_TOKEN and TRIPWIRE_WORKFLOW. Failing rather than reporting quiet.");
      process.exit(2);
    }
    const { latest, streak, oldest, exhausted } = await mainStreak(workflowName);
    if (latest === undefined) {
      console.error(`[tripwire] no completed run of "${workflowName}" on main. Check the name against the workflow's own name: field.`);
      process.exit(2);
    }
    const existing = await openTripwireIssue();
    const { action, why } = decideAdopt({ conclusion: latest.conclusion, hasOpenIssue: existing !== undefined });
    console.log(`[tripwire] ${workflowName} on main: latest #${latest.run_number} ${latest.conclusion}, non-green streak ${exhausted ? ">=" : ""}${streak}`);
    console.log(`[tripwire] open issue: ${existing === undefined ? "none" : `#${existing.number}`}`);
    console.log(`[tripwire] ADOPT DECISION ${action}: ${why}`);
    if (action !== "open") return;
    const body = adoptBody({ workflowName, latest, streak, oldest, exhausted, others: otherPushWorkflows(await workflowFiles(), "main", workflowName) });
    const title = `main is red: ${workflowName} has not been green since ${oldest.head_sha.slice(0, 8)}`;
    if (dryRun) console.log(`[tripwire] --dry-run, would open: ${title}\n${body}`);
    else {
      const issue = await api("POST", `/repos/${REPO}/issues`, { title, body, labels: [LABEL] });
      console.log(`[tripwire] opened #${issue.number} ${issue.html_url}`);
    }
    return;
  }

  const raw = process.env.TRIPWIRE_RUN_JSON;
  if (raw === undefined || raw.trim() === "") {
    console.error("[tripwire] TRIPWIRE_RUN_JSON is empty, so there is no run to grade. This gate fails rather than reporting quiet.");
    process.exit(2);
  }
  if (REPO === "" || TOKEN === "") {
    console.error("[tripwire] GITHUB_REPOSITORY or GH_TOKEN is empty, so nothing could be read or written. Failing rather than reporting quiet.");
    process.exit(2);
  }
  const run = JSON.parse(raw);
  console.log(`[tripwire] ${run.name} run #${run.run_number} on ${run.head_branch} at ${run.head_sha}: ${run.conclusion}`);

  const previous = await previousRun(run);
  const previousState = stateOf(previous);
  const existing = await openTripwireIssue();
  const { action, why } = decide({ conclusion: run.conclusion, previousState, hasOpenIssue: existing !== undefined });
  console.log(`[tripwire] previous run: ${previous === undefined ? "none" : `#${previous.run_number} ${previous.conclusion}`} -> state ${previousState}`);
  console.log(`[tripwire] open issue: ${existing === undefined ? "none" : `#${existing.number}`}`);
  console.log(`[tripwire] DECISION ${action}: ${why}`);

  // Read on every run, not only when an issue is written, because the step summary carries the same scope
  // caveat as the issue body. A green run's summary is the one a reader is most likely to mistake for a
  // statement about main.
  const others = otherPushWorkflows(await workflowFiles(), run.head_branch, run.name);
  const summary = [
    `### Red-main tripwire`,
    "",
    `- run [#${run.run_number}](${run.html_url}) concluded \`${run.conclusion}\` on \`${run.head_branch}\``,
    `- previous run on this branch: **${previousState}**`,
    `- open red-main issue: ${existing === undefined ? "none" : `#${existing.number}`}`,
    `- decision: **${action}**, ${why}`,
    others.length === 0
      ? `- scope: \`${run.name}\` is the only workflow a push to \`${run.head_branch}\` runs, so this does grade the branch`
      : `- scope: this grades \`${run.name}\` only. Not watched, and able to redden \`${run.head_branch}\` on their own: ${others.map((n) => `\`${n}\``).join(", ")}`,
  ];

  if (action === "open" || action === "update") {
    const jobs = await failedJobs(run.id);
    if (action === "open") {
      const ungraded = await ungradedBetween(previous, run);
      const body = issueBody({ run, previous, previousState, jobs, ungraded, others });
      const title = `main is red: ${run.name} failed at ${run.head_sha.slice(0, 8)}`;
      if (dryRun) console.log(`[tripwire] --dry-run, would open: ${title}\n${body}`);
      else {
        const issue = await api("POST", `/repos/${REPO}/issues`, { title, body, labels: [LABEL] });
        console.log(`[tripwire] opened #${issue.number} ${issue.html_url}`);
        summary.push(`- opened #${issue.number}`);
      }
    } else {
      const body = withStreakLine(existing.body ?? MARKER, run, jobs);
      if (body === existing.body) console.log(`[tripwire] #${existing.number} already records run #${run.run_number}, nothing to do`);
      else if (dryRun) console.log(`[tripwire] --dry-run, would append a streak line to #${existing.number}`);
      else {
        await api("PATCH", `/repos/${REPO}/issues/${existing.number}`, { body });
        console.log(`[tripwire] appended a streak line to #${existing.number}`);
      }
      summary.push(`- appended to #${existing.number} rather than opening a second issue`);
    }
  } else if (action === "close") {
    if (dryRun) console.log(`[tripwire] --dry-run, would close #${existing.number}`);
    else {
      await api("POST", `/repos/${REPO}/issues/${existing.number}/comments`, {
        body: `main is green again: [run #${run.run_number}](${run.html_url}) concluded \`success\` at \`${run.head_sha}\`.\n\nClosed by the red-main tripwire.`,
      });
      await api("PATCH", `/repos/${REPO}/issues/${existing.number}`, { state: "closed", state_reason: "completed" });
      console.log(`[tripwire] closed #${existing.number}`);
      summary.push(`- closed #${existing.number}`);
    }
  }

  if (process.env.GITHUB_STEP_SUMMARY !== undefined) {
    const { appendFileSync } = await import("node:fs");
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${summary.join("\n")}\n`);
  }
}

// Guard on realpath, not on the raw argv path. node records import.meta.url after resolving symlinks, so
// comparing it against pathToFileURL(process.argv[1]) is false for any invocation reaching this file
// through a symlinked directory, and main() then never runs while the process still exits 0. That exact
// fail-open guard was found in this workspace on 2026-08-04 in a gate that printed nothing and passed.
const { realpathSync } = await import("node:fs");
const { pathToFileURL } = await import("node:url");
const invokedDirectly = process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(new URL(import.meta.url).pathname);
if (invokedDirectly) {
  await main().catch((err) => {
    console.error(`[tripwire] ${err.stack ?? err.message}`);
    process.exit(1);
  });
}
