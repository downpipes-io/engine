// Refuse to grade this repo's HEAD against a SIBLING CHECKOUT that is behind its own origin/main.
//
// WHY THIS EXISTS
// ---------------
// The workspace checkouts at ~/Desktop/downpipes/<repo> are shared between concurrent runs and run arbitrarily far
// behind their own origin/main. Every cross-repo gate here resolves its siblings to those trees by default.
// So a gate reads this repo at HEAD, reads the sibling at whenever-that-tree-last-moved, and prints a
// confident verdict about a comparison nobody made.
//
// That is not a smaller version of the truth, it is a different one, and it has been banked as fact:
//
//   a sibling 20+ behind       three separate runs reported behaviour-catalogue-gate red and recorded it as
//                              a known failure. It was green.
//   engine 13 behind           a root-caused diagnosis of the console approval gate read as live. Both halves
//                              were already fixed on main, and a run was spent on a refuted premise.
//   engine 18 behind           an audit-inventory re-pin moved 19 further pins on the second pass, and the
//                              stale tree hid a recordAudit to auditChecked migration that produced four
//                              false DEAD-ACTION findings.
//   engine behind              the AUDIT_ACTIONS count pin itself was authored against a sibling that had
//                              not merged origin/main.
//
// A missing sibling is loud. A STALE one resolves every path happily and answers every question.
//
// WHAT THIS DOES. Each sibling a gate actually reads is asked how far behind its own origin/main it is, and
// a gate that would grade against a stale one exits 2 instead of printing a verdict. No fetch: that would
// make a local check depend on the network and on credentials, and the already-fetched ref catches the case
// that matters, a checkout somebody has left behind.
//
// EXIT 2, NOT 1, and the difference carries information. Exit 1 is a FINDING: the gate ran and something is
// wrong with the code. Exit 2 is CANNOT CHECK: the gate did not run, and no conclusion of any kind may be
// drawn from it. Reading a 2 as a 1 is how a stale tree becomes a bug report.
//
// This is the mechanism a sibling repository's own citation-verification script already had, generalised. That
// script found it the hard way: it reported 0 inert citations against an engine 44 commits behind, and 19
// the moment the checkout was fast-forwarded, with nothing in the catalogue changed.
//
// THE ESCAPE HATCH is deliberate and it is loud.
//
//   DOWNPIPES_ALLOW_STALE_SIBLINGS=engine,docs   proceed despite those repos being behind, and no others
//   DOWNPIPES_ALLOW_STALE_SIBLINGS=1             proceed despite any repo being behind
//
// Both print every repo they let through and how far behind it is, on stderr, every run. A suppression that
// does not say what it suppressed is indistinguishable from the bug. The named-repo form is the one to
// prefer: `=1` covers repos you have not thought about yet, including ones that go stale after you set it.
//
// DOWNPIPES_REQUIRE_SIBLING_FRESHNESS=1 turns "freshness unknown" into a refusal too. A checkout with no
// origin/main ref supports no conclusion about its currency, which is fine on a single-repo clone and is a
// configuration fault in CI, where the ref is always there. CI sets it.
//
// A RELEASE-TAG PIN is graded against the newest release tag, not against main. CI checks the reader out at
// a v* tag on purpose, so every later commit on the reader's main (a SECURITY.md edit is enough) made that
// checkout "behind" and turned the nightly red with nothing graded having changed (engine run 38276133304,
// 12 Oct). A checkout whose HEAD is exactly the newest v* tag it has fetched is fresh. One at an OLDER v* tag
// while a newer one exists is exit 1, "pin bump owed": a finding, and the hatch above does not suppress it,
// because suppressing it is how an engine silently falls behind a released reader.
//
// CANONICAL COPY. This file is duplicated verbatim into each repo that needs it, because a repo cannot
// import it from a sibling without reintroducing the dependency it exists to police. Keep the copies in
// step; `git grep -l sibling-freshness` across the workspace finds all of them.

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";

/**
 * How many commits `repoPath` is behind its own origin/main, or null when that cannot be determined.
 *
 * Null is returned for a path that is not a git checkout, and for one whose origin/main ref is absent. Those
 * are different from zero and must not be rounded to it.
 *
 * @param {string} repoPath
 * @returns {number | null}
 */
export function behindOriginMain(repoPath) {
  try {
    const n = Number.parseInt(
      execFileSync("git", ["-C", repoPath, "rev-list", "--count", "HEAD..origin/main"], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim(),
      10,
    );
    return Number.isNaN(n) ? null : n;
  } catch {
    return null;
  }
}

const RELEASE_TAG = /^v(\d+)\.(\d+)\.(\d+)$/;

/**
 * The X, Y and Z of a tag that matches RELEASE_TAG.
 *
 * @param {string} tag
 * @returns {number[]}
 */
function releaseNumbers(tag) {
  return (RELEASE_TAG.exec(tag) ?? []).slice(1).map(Number);
}

/**
 * Numeric X.Y.Z order for two tags that both match RELEASE_TAG.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function compareReleaseTags(a, b) {
  const x = releaseNumbers(a);
  const y = releaseNumbers(b);
  for (let i = 0; i < 3; i += 1) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

/**
 * The non-empty output lines of a git command in `repoPath`, or `ok: false` when git fails, so that a failed
 * read is never mistaken for "no tags".
 *
 * @param {string} repoPath
 * @param {string[]} args
 * @returns {{ok: true, lines: string[]} | {ok: false}}
 */
function gitLines(repoPath, args) {
  try {
    const out = execFileSync("git", ["-C", repoPath, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    return { ok: true, lines: out.split("\n").map((l) => l.trim()).filter(Boolean) };
  } catch {
    return { ok: false };
  }
}

/**
 * The release tag `repoPath`'s HEAD sits on and the newest release tag it has fetched, or null when HEAD is on
 * no X.Y.Z release tag or git cannot read the tags. Only fetched tags are read (no network, as for origin/main above): CI checks out with
 * fetch-depth 0, which fetches every tag.
 *
 * @param {string} repoPath
 * @returns {{tag: string, newest: string} | null}
 */
export function releasePin(repoPath) {
  // A tag read that git cannot answer is no pin, so the checkout is graded on its lag, which refuses.
  const atHead = gitLines(repoPath, ["tag", "--points-at", "HEAD"]);
  if (!atHead.ok) return null;
  const tag = atHead.lines.filter((t) => RELEASE_TAG.test(t)).sort(compareReleaseTags).at(-1);
  if (tag === undefined) return null;
  const all = gitLines(repoPath, ["tag", "--list", "v*"]);
  if (!all.ok) return null;
  return { tag, newest: all.lines.filter((t) => RELEASE_TAG.test(t)).sort(compareReleaseTags).at(-1) ?? tag };
}

/** The repos the caller is allowed to grade against while stale, from the environment. */
function allowance(env) {
  const raw = (env.DOWNPIPES_ALLOW_STALE_SIBLINGS ?? "").trim();
  if (raw === "") return { all: false, named: new Set() };
  if (raw === "1" || raw.toLowerCase() === "all") return { all: true, named: new Set() };
  return { all: false, named: new Set(raw.split(",").map((s) => s.trim()).filter(Boolean)) };
}

/**
 * Refuse, with exit 2, when any sibling this gate reads is behind its own origin/main. A sibling on a release
 * tag is graded against the newest release tag instead: at it, fresh; behind it, exit 1 (pin bump owed).
 *
 * @param {Array<{name: string, path: string | null | undefined}>} siblings the repos actually read
 * @param {object} [opts]
 * @param {string} [opts.gate] this gate's name, for the message
 * @param {string} [opts.consequence] what the verdict would have described instead
 * @param {string[]} [opts.legacyAllowEnv] older suppression variables that must keep working
 * @param {boolean} [opts.allowEmpty] permit a call that names no sibling at all (default false)
 * @param {NodeJS.ProcessEnv} [opts.env] for tests
 * @param {(code: number) => never} [opts.exit] for tests
 * @param {(msg: string) => void} [opts.log] for tests
 */
export function requireFreshSiblings(siblings, opts = {}) {
  const env = opts.env ?? process.env;
  const exit = opts.exit ?? ((c) => process.exit(c));
  const log = opts.log ?? ((m) => console.error(m));
  const gate = opts.gate ?? "this gate";
  const consequence = opts.consequence ?? "the verdict would describe old code";

  // A gate that resolved NOTHING and checked nothing is the failure mode this project keeps finding: it
  // reads as a pass. Naming no sibling is only ever right for a caller that says so.
  // The predicate is annotated so the narrowing PROPAGATES: without it every later use of s.path is
  // `string | null | undefined` to a typechecker, which is how this line reported a TS2345 once scripts/
  // came inside the tsc program at all.
  const present = siblings.filter(
    /** @returns {s is {name: string, path: string}} */
    (s) => typeof s?.path === "string" && s.path !== "" && existsSync(s.path),
  );
  if (present.length === 0 && opts.allowEmpty !== true) {
    log(`FATAL: ${gate} resolved no sibling checkout, so it has nothing to check and ${consequence}.`);
    log("A cross-repo gate with no sibling on disk is a configuration fault, not a pass. Check the siblings out");
    log("beside this repo, or pass allowEmpty when a single-repo clone genuinely means skip.");
    return exit(2);
  }

  const allowed = allowance(env);
  const legacy = (opts.legacyAllowEnv ?? []).some((v) => env[v] === "1");

  const stale = [];
  const unknown = [];
  const pinBehind = [];
  for (const s of present) {
    const behind = behindOriginMain(s.path);
    const pin = behind !== null && behind > 0 ? releasePin(s.path) : null;
    if (behind === null) unknown.push(s);
    else if (pin !== null && pin.tag === pin.newest) {
      log(`note  ${s.name} is pinned at ${pin.tag}, its newest release tag; the ${behind} commit(s) on main after it are not lag.`);
    } else if (pin !== null) pinBehind.push({ ...s, ...pin });
    else if (behind > 0) stale.push({ ...s, behind });
  }

  // Say what is being suppressed, always, before deciding anything. A hatch that goes quiet the moment it
  // works is the same shape as no hatch at all.
  const suppressed = stale.filter((s) => legacy || allowed.all || allowed.named.has(s.name));
  if (suppressed.length > 0) {
    log(`note  ${gate} is proceeding against ${suppressed.length} STALE sibling checkout(s), suppressed by`);
    log(`      ${legacy ? (opts.legacyAllowEnv ?? []).join("/") : "DOWNPIPES_ALLOW_STALE_SIBLINGS"}:`);
    for (const s of suppressed) log(`        ${s.name}: ${s.behind} commit(s) behind origin/main, at ${s.path}`);
    log("      Any finding below is about that older tree, not about origin/main.");
  }
  // A repo named in the hatch that is NOT stale is worth saying too, so the list gets pruned rather than
  // growing until it covers a repo somebody did mean to check. Only for repos THIS call actually looked at:
  // a gate that reads console has no opinion on whether naming engine was justified, and saying so anyway
  // produced a "drop it from the list" line about the very repo being suppressed two calls earlier.
  for (const n of allowed.named) {
    if (present.some((s) => s.name === n) && !stale.some((s) => s.name === n)) {
      log(`note  DOWNPIPES_ALLOW_STALE_SIBLINGS names ${n}, which is not behind origin/main here. Drop it from the list.`);
    }
  }

  if (unknown.length > 0) {
    const names = unknown.map((s) => s.name).join(", ");
    if (env.DOWNPIPES_REQUIRE_SIBLING_FRESHNESS === "1") {
      log(`FATAL: ${gate} cannot tell whether ${names} is current with origin/main, and`);
      log("DOWNPIPES_REQUIRE_SIBLING_FRESHNESS=1 says that is a configuration fault rather than a fact of the");
      log("checkout. Fetch origin in that repo so the ref exists, or unset the variable outside CI.");
      return exit(2);
    }
    log(`note  freshness unknown for ${names} (no origin/main ref); graded against whatever is on disk`);
  }

  const blocking = stale.filter((s) => !suppressed.includes(s));
  if (blocking.length > 0) {
    log(`FATAL: ${gate} would grade against a sibling checkout that is behind its own origin/main, so ${consequence}:\n`);
    for (const s of blocking) log(`  ${s.name}: ${s.behind} commit(s) behind origin/main, at ${s.path}`);
    log("");
    log("This is exit 2, CANNOT CHECK, not exit 1, FOUND SOMETHING. Nothing may be concluded from this run:");
    log("do not record a failure here as a known one, and do not record a pass here as evidence. Fast-forward");
    log("that checkout and run again, or set DOWNPIPES_ALLOW_STALE_SIBLINGS to the repo names you deliberately");
    log("mean to grade against an old tree (it prints every repo it lets through).");
    return exit(2);
  }

  // After the exit-2 checks: a finding needs a run that could check. Not suppressible (see the header).
  if (pinBehind.length > 0) {
    log(`FAIL: ${gate} reads a sibling pinned to an older release tag than one it has fetched. Pin bump owed:\n`);
    for (const s of pinBehind) log(`  ${s.name}: pinned at ${s.tag}, newest release tag ${s.newest}, at ${s.path}`);
    log("");
    log("This is exit 1, a finding. Move the pin to the newest release tag.");
    return exit(1);
  }
}
