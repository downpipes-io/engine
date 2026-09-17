// The OTHER posture for a verdict that depends on a sibling checkout: grade it, and SAY WHICH TREE.
//
// WHY THERE ARE TWO POSTURES, and why this is not a softer version of the first one.
// -----------------------------------------------------------------------------------
// ../sibling-freshness.mjs REFUSES, exit 2, when a gate would grade against a sibling that is behind its own
// origin/main. That is right for a gate whose output is a list of specific claims about the sibling's
// content, because such a verdict is acted on: a reader repairs the thing it names. Against a stale tree
// both directions are wrong, and neither is discountable from the output.
//
// It is the WRONG answer for two other shapes, and forcing them into it would cost more than it bought:
//
//   A SURVEY of many checkouts, most of which are legitimately not at main. scripts/resync-surface-counts.mjs
//   deliberately reads every worktree of every target and reports the ones that are not ours to fix. Refusing
//   at the first stale one would leave it unable to do the only thing it exists for.
//
//   A DEMONSTRATION whose result stays true of the tree it ran against. scripts/e2e-writer-reader.sh builds
//   the sibling Go reader and really does write, restore and reject a tampered archive. A pass against an
//   older reader is a fact about that reader, not a guess, and `make demo` is run by hand against whatever
//   downpipe checkout the operator has. What that run owes its reader is the VERSION it proved, which is
//   exactly what it did not print.
//
// So the failure this module addresses is not "graded a stale tree". It is "graded a tree it never named".
// Silence is the defect; pinning, and reading an older tree on purpose, are not.
//
// WHAT IT PRINTS, per sibling, every run, on stderr:
//
//   sibling  downpipe at /Users/x/downpipes/downpipe, HEAD 4d4f97f5, 0 commit(s) behind its own origin/main
//   sibling  docs     at /Users/x/downpipes/docs,     HEAD 0aec5de8, 13 commit(s) BEHIND its own origin/main
//   sibling  website  at /Users/x/downpipes/website,  HEAD 91ab33cd, lag UNKNOWN (no origin/main ref)
//
// UNKNOWN is its own outcome and is never rounded to zero. A checkout with no origin/main ref supports no
// conclusion about its currency, which is ordinary in a single-repo clone and is a configuration fault in CI.
//
// THE LAG IS MEASURED LOCALLY, with no fetch. That is deliberate and it is the same choice
// ../sibling-freshness.mjs documents: fetching would make a local gate depend on the network and on
// credentials, and the already-fetched ref catches the case that actually bites, a checkout somebody has left
// behind. It also means the number is honest in the habitat where it is wrong to be silent, the workstation.
//
// HOW IT READS IN CI. This engine's workflows check every sibling out at that repository's DEFAULT BRANCH and
// never at a pin, and none of them rewrites a sibling's origin/main afterwards (0 such rewrites on non-comment
// lines across all six workflow files, against a control of 53 non-comment `uses:` lines in ci.yml alone; the
// comment restriction matters because ci.yml's own comment states this measurement and would otherwise be
// counted by it). So in CI the measured lag is 0 because the tree really is at main, not because the
// measurement was disarmed. That is the difference from harness/.github/workflows/ci.yml, which update-refs
// the engine checkout's origin/main to its pin for a stated reason and thereby makes every HEAD..origin/main
// guard in that checkout compute 0 whatever the pin is. A line that says 0 in both places must be able to say
// WHY it is 0, so the sha is printed beside the number and never on its own.
//
// House style: Australian English, no em dashes, no rule-of-three, no AI attribution.

import { execFileSync } from "node:child_process";
import { existsSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { behindOriginMain, requireFreshSiblings } from "../sibling-freshness.mjs";

/**
 * The short HEAD sha of a checkout, or null when that cannot be read.
 *
 * Not exported: siblingLag is the only caller and knip gates this repo on dead exports.
 *
 * @param {string} repoPath
 * @returns {string | null}
 */
function headSha(repoPath) {
  try {
    const sha = execFileSync("git", ["-C", repoPath, "rev-parse", "--short=8", "HEAD"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return sha === "" ? null : sha;
  } catch {
    return null;
  }
}

/**
 * Measure one sibling checkout: where it is, what it is at, and how far behind its own origin/main.
 *
 * `behind` is null for UNKNOWN (not a git checkout, or no origin/main ref) and that is never rounded to 0.
 *
 * @param {string} name
 * @param {string | null | undefined} path
 * @returns {{name: string, path: string | null, present: boolean, head: string | null, behind: number | null}}
 */
export function siblingLag(name, path) {
  const p = typeof path === "string" && path !== "" ? path : null;
  const present = p !== null && existsSync(p);
  if (!present) return { name, path: p, present: false, head: null, behind: null };
  return { name, path: p, present: true, head: headSha(p), behind: behindOriginMain(p) };
}

/**
 * One line describing a measured sibling. BEHIND is upper-case because it is the case a reader must not skim.
 *
 * `bare` drops the leading `sibling <name>` for a caller that already prints the name in its own column, so
 * a survey does not read "docs sibling docs at ...". The measurement is identical either way.
 *
 * @param {{name: string, path: string | null, present: boolean, head: string | null, behind: number | null}} s
 * @param {{bare?: boolean}} [opts]
 * @returns {string}
 */
export function siblingLagLine(s, opts = {}) {
  const lead = opts.bare === true ? "" : `sibling  ${s.name} `;
  if (!s.present) return `${lead}NOT PRESENT at ${s.path ?? "(no path resolved)"}`;
  const head = s.head === null ? "HEAD unreadable" : `HEAD ${s.head}`;
  const lag =
    s.behind === null
      ? "lag UNKNOWN (no origin/main ref, which is not the same as up to date)"
      : s.behind === 0
        ? "0 commit(s) behind its own origin/main"
        : `${s.behind} commit(s) BEHIND its own origin/main`;
  return `${lead}at ${s.path}, ${head}, ${lag}`;
}

/**
 * Measure every sibling a caller actually read and print one line each, then hand the measurements back.
 *
 * This never changes an exit code. A caller that wants a refusal calls requireFreshSiblings instead, and a
 * caller that wants BOTH (say it, then refuse) calls this first so the measurement is on the record either
 * way.
 *
 * @param {Array<{name: string, path: string | null | undefined}>} siblings
 * @param {object} [opts]
 * @param {string} [opts.gate] this gate's name, for the heading
 * @param {(msg: string) => void} [opts.log] for tests
 * @returns {Array<{name: string, path: string | null, present: boolean, head: string | null, behind: number | null}>}
 */
export function reportSiblings(siblings, opts = {}) {
  const log = opts.log ?? ((m) => console.error(m));
  const measured = siblings.map((s) => siblingLag(s.name, s.path));
  const gate = opts.gate ?? "this gate";
  // The heading names the gate so a chained run of several gates cannot have one gate's lag line read as
  // another's. A bare list of siblings in a 300-member chain log is unattributable.
  log(`note  ${gate} graded against the sibling checkout(s) below, and its verdict is a function of them:`);
  for (const s of measured) log(`  ${siblingLagLine(s)}`);
  const stale = measured.filter((s) => typeof s.behind === "number" && s.behind > 0);
  if (stale.length > 0) {
    log(`      ${stale.length} of those is behind its own origin/main, so any verdict below is about THAT tree,`);
    log("      not about the sibling's main. Fast-forward it and run again before recording this result.");
  }
  return measured;
}

// ---- CLI, for callers that are not JavaScript --------------------------------------------------------------
// scripts/e2e-writer-reader.sh is a shell script and cannot import a module. Rather than give it a fourth
// re-implementation of `git rev-list --count`, it shells this.
//
//   node scripts/lib/sibling-lag.mjs --report downpipe=/path/to/downpipe      always exit 0, print the lines
//   node scripts/lib/sibling-lag.mjs --require docs=/path/to/docs --gate NAME exit 2 when any is behind
//
// --require delegates to requireFreshSiblings so there is one refusal mechanism in this repo, not two.
//
// THE ENTRY-POINT TEST CANONICALISES BOTH SIDES, for the reason test/lib/verdict-guard.ts records at length:
// macOS ships /tmp as a symlink to /private/tmp, every scratch worktree in this workspace sits under it, and
// `import.meta.url === \`file://${process.argv[1]}\`` therefore decides the file is not the entry point,
// prints nothing and exits 0. A CLI whose whole job is to say what a run graded must not be the thing that
// goes quiet, so this is realpathSync on both sides rather than a string comparison.
function isCliEntry() {
  const argv1 = process.argv[1];
  if (argv1 === undefined) return false;
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(argv1);
  } catch {
    return false;
  }
}
if (isCliEntry()) {
  const argv = process.argv.slice(2);
  const mode = argv.includes("--require") ? "require" : "report";
  const gateAt = argv.indexOf("--gate");
  const gate = gateAt >= 0 ? (argv[gateAt + 1] ?? "this gate") : "this gate";
  const pairs = argv
    .filter((a) => !a.startsWith("--") && a.includes("="))
    .map((a) => {
      const i = a.indexOf("=");
      return { name: a.slice(0, i), path: a.slice(i + 1) };
    });
  if (pairs.length === 0) {
    // Refusing an empty invocation is the whole lesson of this workspace's gate history: a checker that
    // cannot fail on no input reads as a pass to every caller that only looks at the exit code.
    console.error("sibling-lag: no name=path pair given, so nothing was measured. This is exit 2, not a pass.");
    process.exit(2);
  }
  reportSiblings(pairs, { gate });
  if (mode === "require") {
    requireFreshSiblings(pairs, {
      gate,
      consequence: "the result would be about an older sibling tree than the one it names",
    });
  }
}
