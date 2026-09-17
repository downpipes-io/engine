#!/usr/bin/env node
// Both dependency trees, graded separately, with an acknowledgement path on exactly one of them.
//
// ONE IMPLEMENTATION, COPIED BYTE FOR BYTE, AND THE COPY POLICES ITSELF. This file is identical in every
// repository that carries it. Nothing in it is repository-specific: every repository-specific sentence
// lives in that repository's own .github/dependency-advisories.json, which is data this file reads and
// never contains. The digest below is the sha256 of this file with the single line that declares the
// digest removed, so each copy checks itself against the canonical body with no sibling checkout, no
// network, and no shared package. Two copies that both pass have the same body hash and the same digest
// line, so they are the same bytes; a pass that edits one copy reddens that repository's own CI on that
// push, in the repository where the edit happened.
//
// WHY NOT FOUR HAND-WRITTEN GATES, and why not a shared package either. Four independent gates is the
// drift this workspace paid for in the same week this was written: three copies of
// scripts/sibling-freshness.mjs diverged on their own main while two written statements said they must
// not, and the requirement had been recorded twice and changed nothing. A published package is the
// correct-in-principle answer and is refused on the same ground
// the sibling-freshness copy gate refuses it: version-pinned per repository, the copies would
// drift by PIN instead of by bytes, and a stale pin is silent. What is taken here is duplication that a
// gate polices, and the policing is cheaper than the sibling-freshness case because a self-digest needs
// no peer on disk at all.
//
// THE TWO TREES ARE NOT SYMMETRIC, and the asymmetry is the design rather than an accident of it.
//
//   PRODUCTION is a hard gate at high and critical with NO acknowledgement path, and the gate refuses an
//   acknowledgement that turns up there. Each repository states its own reason in productionTreeRule,
//   which is required: a repository that cannot say why its production tree is ungovernable by a written
//   excuse has not thought about it, and this gate will not grade it. There is no field anywhere that
//   could soften the production verdict, in any repository, whatever that reason says.
//
//   THE BUILD TREE is ratcheted rather than gated at a severity. Gating it at high would make this job
//   permanently red for advisories no commit in the repository can satisfy, and a job that is always red
//   is a job that teaches its reader to stop looking. So it is gated on CHANGE, in both directions: an
//   advisory that is not acknowledged fails, and an acknowledgement the tree no longer carries also
//   fails. The build tree is in scope, not out of it. It is where the code that bundles, tests and
//   deploys the shipped artefact runs.
//
// AN ACKNOWLEDGEMENT THAT CANNOT BE FORGOTTEN. The failure mode of a list like this is that it becomes
// permanent and silent, which is worse than the red it replaced. Two things stop that here. An entry
// records the severity npm reports, and a re-rating upward fails rather than passing under the old word.
// And an entry whose fix IS reachable must carry a reviewBy date, after which the gate fails: a deferral
// comes back on a known day, while an advisory genuinely beyond reach stays quiet because there is
// nothing a date would achieve. "Transitive" is not a reason and will not be accepted as one, because
// every entry in such a file is transitive.
//
// EVERY TREE, NOT THE ROOT TREE. A repository can hold more than one lockfile, and auditing the root and
// printing a repository-wide verdict is a false negative rather than a partial answer. This gate walks
// the checkout for package-lock.json, audits every one it finds, and FAILS on any it finds that the
// config's `trees` list does not declare. The case is not hypothetical: one sibling repository's root tree audited
// clean while its nested workers/sink tree carried six advisories, two of them high, and the only thing
// pointing at it was a Dependabot alert naming the manifest path.
//
// THE EMPTY LIST IS THE GOAL AND IT IS REACHABLE. When this file was written every repository that
// carries it had been taken to zero acknowledged advisories, by npm `overrides` that move a transitive
// package inside its own major and leave wrangler, miniflare, workerd and @cloudflare/vitest-pool-workers
// untouched. An acknowledgement is therefore a live claim that a fix was looked for and not found, not a
// resting state.
//
// The word "posture" is not used in any of this. It already means the key-custody posture in the console
// and the engine, and the security-channel posture in the website, and a second meaning on the same word
// in the same scripts directory is how a reader ends up at the wrong gate.
//
// THREE OUTCOMES, not two, because two is what let a bare `npm audit --omit=dev --audit-level=high` pass:
//
//   exit 0  CHECKED. Clean, or clean with the acknowledged list printed in full.
//   exit 1  CHECKED AND FOUND SOMETHING.
//   exit 2  REFUSED, COULD NOT CHECK. npm audit did not produce a report, or the acknowledgement file is
//           missing or unreadable, so this run has established nothing. Kept distinct from exit 1 on
//           purpose: a gate that reports "I could not look" as "I looked and it was fine" is the defect
//           this whole file is here for.
//
// This gate is synchronous. There is no await in it, and a repository whose verdict-guard rules exempt
// straight-line scanners under scripts/ is relying on that.
//
// THE COMPLETION GUARD, and the one place the family had to bend. control-plane and docs require every
// entry point to import scripts/lib/verdict-guard.mjs and call verdictReached before the exit that
// reports the outcome. the other repositories have no such module, so a static import of it here
// would crash this gate at load there, and an `await import()` would make the file
// asynchronous, which is exactly what console's verdict-guard rules say a scripts/ gate must not become.
// So `main` is exported and takes hooks, and it runs itself only when it IS the entry module. The two
// repositories that require enrolment invoke a small local file, scripts/dependency-advisory-guarded.mjs,
// which imports their guard and passes verdictReached in. The hook is the seam, this file is still the
// same bytes everywhere, and the divergence is one visible extra file in two repositories rather than a
// silent fork of a 400-line gate.
//
// Run: node scripts/dependency-advisory-gate.mjs
//      node scripts/dependency-advisory-gate.mjs --self-test
//      node scripts/dependency-advisory-guarded.mjs           (control-plane and docs)
//
// It writes nothing, anywhere. The acknowledged list and the stated boundary go to stdout in full on
// every run, which is what a reader of the CI log sees.
//
// FS-WRITES: none outside this repo
//
// House style: Australian English, no em dashes, no rule-of-three.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const SELF = fileURLToPath(import.meta.url);
const ROOT = dirname(dirname(SELF));
const CONFIG_PATH = join(ROOT, ".github", "dependency-advisories.json");
const BLOCKING = new Set(["high", "critical"]);
const DIGEST_DECLARATION = /^const CANONICAL_BODY_SHA256 = .*$/m;
const CANONICAL_BODY_SHA256 = "5ee5817a8bd4f433d073468a19d3810528ce90f5e5f560fa728d93b01637b6e3";

// The self-check. Hashing the file with the declaration line removed is what lets the constant live in
// the file it describes. A copy that fails this has been edited in one repository and nowhere else, which
// is the drift, and it is reported where it happened rather than waiting for a sibling to notice.
export function bodyDigest(source) {
  return createHash("sha256").update(source.replace(DIGEST_DECLARATION, "")).digest("hex");
}

// EVERY lockfile in the repository, found rather than assumed. This exists because assuming the root is
// the whole repository is a false negative that had already happened: a sibling repository's root tree
// audited clean while its nested workers/sink/package-lock.json carried six advisories, two of
// them high, and the only thing that pointed at it was a Dependabot alert naming the manifest path. A
// gate that audits one tree and reports "clean" for a repository is worse than no gate, because the
// number it prints is about a different question from the one its reader is asking.
export function lockfilesUnder(root) {
  const skip = new Set(["node_modules", "dist", "build", "coverage", "vendor"]);
  const found = [];
  const walk = (dir) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.isDirectory()) {
        // EVERY dot-directory, not a list of them. The first draft named .git, .wrangler, .astro and
        // .venv and let .worktrees through, and a sibling repository's worktree-overscan gate caught it in
        // CI: a linked git worktree nested under a checkout holds a complete second copy of
        // the repository, so a walk that descends into it reads another branch's lockfiles as part of
        // this one and reports trees this commit does not have.
        if (!e.name.startsWith(".") && !skip.has(e.name)) walk(join(dir, e.name));
      } else if (e.name === "package-lock.json") {
        found.push(relative(root, dir) || ".");
      }
    }
  };
  walk(root);
  return found.sort();
}

// `npm audit` exits non-zero when it finds something, so its exit code says whether to expect a finding
// and nothing more. The JSON on stdout is the result. What is NOT done here: `|| true` followed by
// reading `$?`, which makes the captured code unconditionally zero and the fatal branch unreachable.
export function npmAudit(args, cwd = ROOT) {
  let stdout = "";
  try {
    stdout = execFileSync("npm", ["audit", "--json", ...args], { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (err) {
    stdout = /** @type {any} */ (err).stdout || "";
    if (!stdout.trim()) throw new Error(`npm audit ${args.join(" ")} produced no output: ${/** @type {Error} */ (err).message}`);
  }
  const parsed = JSON.parse(stdout);
  if (!parsed || typeof parsed.vulnerabilities !== "object") {
    throw new Error(`npm audit ${args.join(" ")} returned no vulnerabilities map, so it did not audit anything.`);
  }
  return parsed;
}

// Every distinct advisory in a report, keyed by GHSA id. npm nests the real advisories under `via` and
// mixes them with plain strings naming another vulnerable package, so reading the top level alone counts
// packages and reports no advisory at all.
export function advisoriesOf(report) {
  /** @type {Map<string, {id: string, severity: string, title: string, packages: Set<string>}>} */
  const found = new Map();
  for (const [pkg, entry] of Object.entries(report.vulnerabilities || {})) {
    for (const via of /** @type {any} */ (entry).via || []) {
      if (typeof via === "string") continue;
      const id = String(via.url || "").split("/").pop() || "";
      if (!id.startsWith("GHSA-")) continue;
      const seen = found.get(id);
      if (seen) seen.packages.add(pkg);
      else found.set(id, { id, severity: String(via.severity), title: String(via.title || ""), packages: new Set([pkg]) });
    }
  }
  return found;
}

// Pure, so the self-test drives every branch with no network and no lockfile.
//
// The parameter shape is written out because `lockfilesFound = []` on its own infers `never[]` under
// tsc, and every call passing real paths then fails TS2345. Three repositories bring scripts/ inside a
// type-checked program and all three reddened on it.
/**
 * @param {{
 *   config: any,
 *   prodAdvisories: Map<string, any>,
 *   buildAdvisories: Map<string, any>,
 *   lockfilesFound?: string[],
 *   today: string,
 * }} input
 */
export function grade({ config, prodAdvisories, buildAdvisories, lockfilesFound = [], today }) {
  const channels = [];
  const problems = [];
  const acknowledged = Object.fromEntries(
    Object.entries(config.acknowledgedBuildTreeAdvisories || {}).filter(([k]) => !k.startsWith("$")),
  );

  // 0a. Which trees this repository has, against which it says it audits. Both directions, because both
  // have teeth: an undeclared lockfile is a tree nothing has ever looked at, and a declared path with no
  // lockfile is a declaration that audits nothing while reading as coverage.
  const declared = Array.isArray(config.trees) ? config.trees.map(String) : [];
  if (declared.length === 0) {
    problems.push(
      "trees in .github/dependency-advisories.json is missing or empty, so this gate has not been told what to audit.\n" +
        "  List every directory holding a package-lock.json, the repository root as \".\".",
    );
  }
  for (const path of lockfilesFound) {
    if (!declared.includes(path)) {
      problems.push(
        `${path}/package-lock.json is in this repository and trees in .github/dependency-advisories.json does not list it, so nothing audits it.\n` +
          `  Add it to trees. A repository-wide verdict drawn from the root tree alone is a verdict about a different question.`,
      );
    }
  }
  for (const path of declared) {
    if (!lockfilesFound.includes(path)) {
      problems.push(`trees in .github/dependency-advisories.json lists ${path} and there is no package-lock.json there, so that entry audits nothing.`);
    }
  }
  channels.push({
    name: "declared-trees",
    verdict: declared.length > 0 && declared.length === lockfilesFound.length && lockfilesFound.every((p) => declared.includes(p)) ? "COMPLETE" : "INCOMPLETE",
    detail: `${lockfilesFound.length} lockfile(s) found, ${declared.length} declared: ${declared.join(", ") || "(none)"}`,
  });

  // 0. The production rule this repository wrote for itself. Required, because the hard gate below is
  // only honest if somebody said out loud what production means here.
  const rule = config.productionTreeRule;
  if (typeof rule !== "string" || rule.trim().length < 40) {
    problems.push(
      "productionTreeRule in .github/dependency-advisories.json is missing or too short to be an argument.\n" +
        "  The production tree has no acknowledgement path in any repository. Say what production is here and what a\n" +
        "  high advisory against it would mean, so the hard gate below is a decision rather than an inherited default.",
    );
  }

  // 1. Production. Hard, and with no field anywhere that could soften it.
  const prodBad = [...prodAdvisories.values()].filter((a) => BLOCKING.has(a.severity));
  if (prodBad.length > 0) {
    channels.push({ name: "npm-audit-production", verdict: "FOUND", detail: `${prodBad.length} advisory(ies) at high or above` });
    for (const a of prodBad) {
      problems.push(
        `the PRODUCTION tree carries ${a.id} (${a.severity}) through ${[...a.packages].join(", ")}: ${a.title}\n` +
          `  There is no acknowledgement path for the production tree. ${typeof rule === "string" ? rule : ""}\n` +
          `  Fix it, or remove the dependency.`,
      );
    }
  } else {
    channels.push({ name: "npm-audit-production", verdict: "CLEAN", detail: `${prodAdvisories.size} advisory(ies), none at high or above` });
  }
  // The asymmetry, enforced rather than merely stated. An entry written for the build tree that has since
  // turned up in production must not go on being read as a decision somebody made about production.
  for (const id of Object.keys(acknowledged)) {
    if (!prodAdvisories.has(id)) continue;
    problems.push(
      `${id} is acknowledged for the BUILD tree and npm audit now reports it in the PRODUCTION tree.\n` +
        `  The acknowledgement covers the build tree only. Remove the dependency or fix the advisory.`,
    );
  }

  // 2. The build tree, ratcheted in both directions.
  const fresh = [...buildAdvisories.values()].filter((a) => !(a.id in acknowledged));
  for (const a of fresh) {
    problems.push(
      `the BUILD tree carries ${a.id} (${a.severity}) through ${[...a.packages].join(", ")}, and nothing acknowledges it: ${a.title}\n` +
        `  Fix it first, and an npm \`overrides\` entry that moves the package inside its own major usually reaches\n` +
        `  where \`npm audit fix\` will not. Only if that fails, add it to acknowledgedBuildTreeAdvisories in\n` +
        `  .github/dependency-advisories.json with a package, a severity, the version that fixes it, whether that fix\n` +
        `  is reachable from here, and a reason. "Transitive" is not a reason: every entry in that file is transitive.`,
    );
  }
  channels.push(
    fresh.length > 0
      ? { name: "npm-audit-build-tree", verdict: "FOUND", detail: `${fresh.length} advisory(ies) not acknowledged` }
      : { name: "npm-audit-build-tree", verdict: "CLEAN", detail: `${buildAdvisories.size} advisory(ies), every one acknowledged` },
  );

  for (const [id, entry] of Object.entries(acknowledged)) {
    const live = buildAdvisories.get(id);
    if (!live) {
      problems.push(
        `.github/dependency-advisories.json acknowledges ${id} and npm audit no longer reports it.\n` +
          `  Delete the entry. An acknowledgement nobody removes is how a list of known problems becomes a list of nothing.`,
      );
      continue;
    }
    // Shape, checked rather than trusted. A row missing a field is a row that was never argued.
    for (const field of ["package", "severity", "fixedIn", "reason"]) {
      const value = /** @type {any} */ (entry)[field];
      if (typeof value !== "string" || value.trim() === "") problems.push(`the acknowledgement of ${id} has no ${field}, so it records nothing a reader can check.`);
    }
    if (typeof /** @type {any} */ (entry).fixReachable !== "boolean") {
      problems.push(`the acknowledgement of ${id} does not say whether a fix is reachable, which is the field that decides whether it is a dead end or a deferral.`);
    }
    if (entry.severity && entry.severity !== live.severity) {
      problems.push(
        `.github/dependency-advisories.json records ${id} as ${entry.severity} and npm audit now reports it as ${live.severity}.\n` +
          `  A re-rating is a real event. Read the advisory again and decide the entry again, rather than updating the word.`,
      );
    }
    if (entry.fixReachable === true) {
      const by = entry.reviewBy;
      if (typeof by !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(by)) {
        problems.push(`the acknowledgement of ${id} says a fix is reachable and carries no reviewBy date, so it is a deferral with no day on which it comes back.`);
      } else if (today > by) {
        // The remedy goes on its own line rather than into a sentence with a clause bolted after it. An
        // earlier version wrote "<toFix>, or set a new date", which reads as "...--dry-run`., or set a new
        // date" whenever the recorded remedy ends in a full stop, and the remedy is the part a reader acts
        // on.
        problems.push(
          `the acknowledgement of ${id} (${live.severity}, ${live.packages.size ? [...live.packages].join(", ") : entry.package}) deferred a REACHABLE fix to ${by}, and that date has passed.\n` +
            `  Take it: ${entry.toFix || "the fix recorded in its reason"}\n` +
            `  Or set a new reviewBy date and say in the reason what changed. Not a new date on its own.`,
        );
      }
    }
  }

  // 3. The boundary, which is required and therefore cannot be quietly deleted to make the run look wider
  // than it is.
  const notCovered = Object.entries(config.notCovered || {}).filter(([k]) => !k.startsWith("$"));
  if (notCovered.length === 0) {
    problems.push(
      "the notCovered block in .github/dependency-advisories.json is missing or empty.\n" +
        "  This gate reads the npm lockfile and nothing else, so there is always something it does not see. A green run with\n" +
        "  no stated boundary reads as a clean repository rather than a checked channel.",
    );
  }
  for (const [name, reason] of notCovered) {
    if (typeof reason !== "string" || reason.trim() === "") problems.push(`notCovered names ${name} with no reason, so it says a question is unanswered without saying why.`);
  }
  channels.push({ name: "stated-boundary", verdict: notCovered.length > 0 ? "DECLARED" : "MISSING", detail: `${notCovered.length} question(s) this gate does not answer` });

  return { channels, problems, acknowledged, notCovered };
}

function renderTable(channels) {
  return ["| Channel | Verdict | Evidence |", "| --- | --- | --- |", ...channels.map((c) => `| \`${c.name}\` | ${c.verdict} | ${c.detail} |`)].join("\n");
}

function selfTest(hooks) {
  const cases = [];
  const record = (name, ok, detail) => cases.push({ name, ok, detail });
  /** @returns {[string, {id: string, severity: string, title: string, packages: Set<string>}]} */
  const adv = (id, severity) => [id, { id, severity, title: `${id} title`, packages: new Set(["p"]) }];
  const ack = (over = {}) => ({ package: "p", severity: "high", fixedIn: "p 9.9.9", fixReachable: false, reason: "measured", ...over });
  const RULE = "production here is the code that ships to the customer, and an advisory against it is not something a file can excuse.";
  const base = { prodAdvisories: new Map(), buildAdvisories: new Map(), lockfilesFound: ["."], today: "2026-08-08" };
  const boundary = { "some-channel": "a reason" };
  const cfg = (over = {}) => ({ productionTreeRule: RULE, trees: ["."], notCovered: boundary, ...over });

  {
    const r = grade({ ...base, config: cfg(), prodAdvisories: new Map([adv("GHSA-aaaa-aaaa-aaaa", "high")]) });
    record("a high advisory in the production tree fails", r.problems.some((p) => p.includes("PRODUCTION")), JSON.stringify(r.problems));
  }
  {
    const r = grade({ ...base, config: cfg(), prodAdvisories: new Map([adv("GHSA-bbbb-bbbb-bbbb", "moderate")]) });
    record("a moderate advisory in the production tree does not fail", r.problems.length === 0, JSON.stringify(r.problems));
  }
  {
    // The asymmetry. The same acknowledgement that holds in the build tree must not hold in production.
    const config = cfg({ acknowledgedBuildTreeAdvisories: { "GHSA-cccc-cccc-cccc": ack() } });
    const r = grade({
      ...base,
      config,
      prodAdvisories: new Map([adv("GHSA-cccc-cccc-cccc", "high")]),
      buildAdvisories: new Map([adv("GHSA-cccc-cccc-cccc", "high")]),
    });
    record("an acknowledgement does not cover the production tree", r.problems.some((p) => p.includes("covers the build tree only")), JSON.stringify(r.problems));
  }
  {
    const config = cfg({ acknowledgedBuildTreeAdvisories: { "GHSA-known-known-know": ack() } });
    const r = grade({ ...base, config, buildAdvisories: new Map([adv("GHSA-known-known-know", "high"), adv("GHSA-newnew-newn", "low")]) });
    record("a build-tree advisory outside the list fails", r.problems.some((p) => p.includes("GHSA-newnew-newn")), JSON.stringify(r.problems));
  }
  {
    const config = cfg({ acknowledgedBuildTreeAdvisories: { "GHSA-known-known-know": ack() } });
    const r = grade({ ...base, config, buildAdvisories: new Map([adv("GHSA-known-known-know", "high")]) });
    record("an acknowledged build-tree advisory passes", r.problems.length === 0, JSON.stringify(r.problems));
  }
  {
    const config = cfg({ acknowledgedBuildTreeAdvisories: { "GHSA-gone-gone-gone": ack() } });
    const r = grade({ ...base, config });
    record("an acknowledgement the tree no longer carries fails", r.problems.some((p) => p.includes("Delete the entry")), JSON.stringify(r.problems));
  }
  {
    const config = cfg({ acknowledgedBuildTreeAdvisories: { "GHSA-rate-rate-rate": ack({ severity: "moderate" }) } });
    const r = grade({ ...base, config, buildAdvisories: new Map([adv("GHSA-rate-rate-rate", "high")]) });
    record("an advisory re-rated upward fails under its old word", r.problems.some((p) => p.includes("re-rating")), JSON.stringify(r.problems));
  }
  {
    const config = cfg({ acknowledgedBuildTreeAdvisories: { "GHSA-bare-bare-bare": { severity: "high" } } });
    const r = grade({ ...base, config, buildAdvisories: new Map([adv("GHSA-bare-bare-bare", "high")]) });
    record(
      "an entry with no reason and no reachability verdict fails",
      r.problems.some((p) => p.includes("no reason")) && r.problems.some((p) => p.includes("whether a fix is reachable")),
      JSON.stringify(r.problems),
    );
  }
  {
    const config = cfg({ acknowledgedBuildTreeAdvisories: { "GHSA-defr-defr-defr": ack({ fixReachable: true }) } });
    const r = grade({ ...base, config, buildAdvisories: new Map([adv("GHSA-defr-defr-defr", "high")]) });
    record("a reachable fix with no review date fails", r.problems.some((p) => p.includes("no day on which it comes back")), JSON.stringify(r.problems));
  }
  {
    const config = cfg({ acknowledgedBuildTreeAdvisories: { "GHSA-defr-defr-defr": ack({ fixReachable: true, reviewBy: "2026-09-30" }) } });
    const r = grade({ ...base, config, buildAdvisories: new Map([adv("GHSA-defr-defr-defr", "high")]) });
    record("a reachable fix inside its review window passes", r.problems.length === 0, JSON.stringify(r.problems));
  }
  {
    const config = cfg({ acknowledgedBuildTreeAdvisories: { "GHSA-defr-defr-defr": ack({ fixReachable: true, reviewBy: "2026-08-07" }) } });
    const r = grade({ ...base, config, buildAdvisories: new Map([adv("GHSA-defr-defr-defr", "high")]) });
    record("a reachable fix past its review date fails", r.problems.some((p) => p.includes("that date has passed")), JSON.stringify(r.problems));
  }
  {
    const config = cfg({ acknowledgedBuildTreeAdvisories: { "GHSA-dead-dead-dead": ack({ fixReachable: false }) } });
    const r = grade({ ...base, config, buildAdvisories: new Map([adv("GHSA-dead-dead-dead", "high")]), today: "2029-01-01" });
    record("an unreachable fix needs no date and does not expire", r.problems.length === 0, JSON.stringify(r.problems));
  }
  {
    const r = grade({ ...base, config: { productionTreeRule: RULE } });
    record("a missing boundary block fails", r.problems.some((p) => p.includes("notCovered block")), JSON.stringify(r.problems));
  }
  {
    const r = grade({ ...base, config: { productionTreeRule: RULE, notCovered: { "some-channel": "" } } });
    record("a boundary entry with no reason fails", r.problems.some((p) => p.includes("with no reason")), JSON.stringify(r.problems));
  }
  {
    const r = grade({ ...base, config: { notCovered: boundary } });
    record("a missing production rule fails", r.problems.some((p) => p.includes("productionTreeRule")), JSON.stringify(r.problems));
  }
  {
    const r = grade({ ...base, config: { productionTreeRule: "transitive", notCovered: boundary } });
    record("a production rule too short to be an argument fails", r.problems.some((p) => p.includes("productionTreeRule")), JSON.stringify(r.problems));
  }
  {
    // The false negative that had already happened, driven as a case rather than described in a comment.
    const r = grade({ ...base, config: cfg(), lockfilesFound: [".", "workers/sink"] });
    record("a lockfile the config does not declare fails", r.problems.some((p) => p.includes("workers/sink/package-lock.json")), JSON.stringify(r.problems));
  }
  {
    const r = grade({ ...base, config: cfg({ trees: [".", "workers/sink"] }), lockfilesFound: [".", "workers/sink"] });
    record("every lockfile declared passes", r.problems.length === 0, JSON.stringify(r.problems));
  }
  {
    const r = grade({ ...base, config: cfg({ trees: [".", "gone"] }), lockfilesFound: ["."] });
    record("a declared tree with no lockfile fails", r.problems.some((p) => p.includes("audits nothing")), JSON.stringify(r.problems));
  }
  {
    const r = grade({ ...base, config: cfg({ trees: [] }) });
    record("no declared trees fails", r.problems.some((p) => p.includes("has not been told what to audit")), JSON.stringify(r.problems));
  }
  {
    // The walker, driven against this repository rather than a fixture, so a skip-list mistake shows up.
    const found = lockfilesUnder(ROOT);
    record("the lockfile walk finds this repository's own root lockfile", found.includes("."), JSON.stringify(found));
    record("the lockfile walk does not descend into node_modules", !found.some((p) => p.includes("node_modules")), JSON.stringify(found));
  }
  {
    // The copy check, driven rather than asserted: an edited body no longer hashes to the declaration.
    const source = readFileSync(SELF, "utf8");
    record("this copy hashes to the declared canonical body", bodyDigest(source) === CANONICAL_BODY_SHA256, `${bodyDigest(source)} != ${CANONICAL_BODY_SHA256}`);
    record("an edited copy does not hash to the declared canonical body", bodyDigest(`${source}\n// a pass edits one copy\n`) !== CANONICAL_BODY_SHA256, "an edit left the digest unchanged");
    record(
      "changing only the declaration line does not change the body digest",
      bodyDigest(source.replace(DIGEST_DECLARATION, 'const CANONICAL_BODY_SHA256 = "0";')) === bodyDigest(source),
      "the declaration line is inside the hashed body",
    );
  }

  const failures = cases.filter((c) => !c.ok);
  for (const c of cases) console.log(`${c.ok ? "ok  " : "FAIL"} dependency-advisory self-test: ${c.name}${c.ok ? "" : `\n     ${c.detail}`}`);
  if (cases.length === 0) {
    console.error("FAIL dependency-advisory self-test: no cases ran, so this proved nothing.");
    hooks.onRefusal("the self-test ran no cases, so it proved nothing");
    process.exit(2);
  }
  console.log(`${failures.length === 0 ? "ok  " : "FAIL"} dependency-advisory self-test: ${cases.length} case(s), ${failures.length} failing`);
  hooks.onVerdict(failures.length, cases.length);
  process.exit(failures.length === 0 ? 0 : 1);
}

// `hooks` is how a repository that requires completion-guard enrolment supplies its own guard without
// this file importing one. The defaults do nothing, which is what the repositories with no guard module
// want, and they are called immediately before every exit including both refusals.
//
// The signatures are written out for the same reason grade's parameter shape is: a bare `() => {}`
// default infers a zero-argument function, and every call passing a tally then fails TS2554 in the
// repositories that type-check scripts/.
/**
 * @param {{
 *   onVerdict?: (failures: number, checks: number) => void,
 *   onRefusal?: (reason: string) => void,
 * }} [hooks]
 */
export function main({ onVerdict = () => {}, onRefusal = () => {} } = {}) {
  const hooks = { onVerdict, onRefusal };
  if (process.argv.includes("--self-test")) return selfTest(hooks);

  if (!existsSync(CONFIG_PATH)) {
    console.error(`REFUSED: ${CONFIG_PATH} does not exist, so there is nothing to compare an audit against and this run proves nothing.`);
    hooks.onRefusal("the acknowledgement file does not exist, so there was nothing to compare an audit against");
    process.exit(2);
  }
  /** @type {any} */
  let config;
  try {
    config = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
  } catch (err) {
    console.error(`REFUSED: ${CONFIG_PATH} did not parse, so nothing was graded. ${/** @type {Error} */ (err).message}`);
    hooks.onRefusal("the acknowledgement file did not parse, so nothing was graded");
    process.exit(2);
  }

  const lockfilesFound = lockfilesUnder(ROOT);
  // Audit what this repository HAS, not only what it declared. An undeclared tree is graded and then
  // reported as undeclared, so a pass cannot hide a tree by leaving it out of the list.
  const toAudit = [...new Set([...lockfilesFound, ...(Array.isArray(config.trees) ? config.trees.map(String) : [])])].sort();
  const prodAdvisories = new Map();
  const buildAdvisories = new Map();
  const merge = (into, from) => {
    for (const [id, a] of from) {
      const seen = into.get(id);
      if (seen) for (const p of a.packages) seen.packages.add(p);
      else into.set(id, a);
    }
  };
  const audited = [];
  for (const path of toAudit) {
    const cwd = join(ROOT, path);
    if (!existsSync(join(cwd, "package-lock.json"))) continue;
    try {
      merge(prodAdvisories, advisoriesOf(npmAudit(["--omit=dev"], cwd)));
      merge(buildAdvisories, advisoriesOf(npmAudit([], cwd)));
      audited.push(path);
    } catch (err) {
      console.error(`REFUSED: the dependency audit did not run in ${path}, so nothing was checked. ${/** @type {Error} */ (err).message}`);
      hooks.onRefusal(`npm audit did not run in ${path}, so nothing was checked`);
      process.exit(2);
    }
  }
  if (audited.length === 0) {
    console.error("REFUSED: no tree was audited, so this run established nothing.");
    hooks.onRefusal("no tree was audited, so this run established nothing");
    process.exit(2);
  }

  const today = new Date().toISOString().slice(0, 10);
  const { channels, problems, acknowledged, notCovered } = grade({ config, prodAdvisories, buildAdvisories, lockfilesFound, today });
  channels.unshift({ name: "trees-audited", verdict: "AUDITED", detail: audited.join(", ") });

  // The copy check runs beside the audit rather than before it, so a divergent copy is reported together
  // with what it found instead of hiding the finding behind a refusal.
  const mine = bodyDigest(readFileSync(SELF, "utf8"));
  const canonical = mine === CANONICAL_BODY_SHA256;
  channels.push({ name: "copy-parity", verdict: canonical ? "CANONICAL" : "DIVERGED", detail: `body sha256 ${mine.slice(0, 16)}` });
  if (!canonical) {
    problems.push(
      `this copy of the gate does not hash to the canonical body: ${mine} against a declared ${CANONICAL_BODY_SHA256}.\n` +
        `  This file is copied byte for byte into every repository that carries it, and every repository-specific\n` +
        `  sentence belongs in .github/dependency-advisories.json instead. Either put the edit in that file, or make the\n` +
        `  same edit in every copy and reissue the declaration in all of them together.`,
    );
  }

  const ackLines = Object.entries(acknowledged).map(
    ([id, e]) => `- \`${id}\` ${e.severity} in ${e.package}, fixed in ${e.fixedIn}. ${e.fixReachable ? `Reachable, deferred to ${e.reviewBy}.` : "Not reachable from here."} ${e.reason}`,
  );
  const boundaryLines = notCovered.map(([name, reason]) => `- \`${name}\`: ${reason}`);

  console.log(renderTable(channels));
  console.log(`\nACKNOWLEDGED BUILD-TREE ADVISORIES (${ackLines.length}), printed in full every run:`);
  for (const line of ackLines) console.log(`  ${line}`);
  if (ackLines.length === 0) console.log("  (none, and that is the goal rather than a gap: every advisory this tree carried was fixed)");
  console.log(`\nWHAT THIS GATE DOES NOT ANSWER (${boundaryLines.length}), printed in full every run:`);
  for (const line of boundaryLines) console.log(`  ${line}`);

  if (problems.length > 0) {
    console.error("\nFAIL dependency-advisory:");
    for (const p of problems) console.error(`  ${p}`);
    console.error(`\nVERDICT: FOUND failures=${problems.length} channels=${channels.length}`);
    hooks.onVerdict(problems.length, channels.length);
    process.exit(1);
  }
  console.log(`\nVERDICT: CHECKED failures=0 channels=${channels.length}, ${ackLines.length} acknowledged advisory(ies), ${boundaryLines.length} stated boundary(ies)`);
  hooks.onVerdict(0, channels.length);
}

// Runs itself only when it IS the process entry. Under scripts/dependency-advisory-guarded.mjs this file
// is imported, and a module that grades on import would run the audit twice and exit before its caller
// had armed anything.
//
// BOTH SIDES ARE CANONICALISED, and the first draft of this line was not. `resolve()` normalises a path
// and does not follow a symlink, so reached through a symlinked path this file would decide it is not the
// entry point, print nothing, run nothing and exit 0. A gate that silently passes when it is invoked
// through a link is the exact failure this whole file exists to stop, and engine's verdict-guard rules
// name that shape after finding it in seven gates across the sibling repositories.
function isProcessEntry() {
  const argv1 = process.argv[1];
  if (!argv1) return false;
  try {
    return realpathSync(argv1) === realpathSync(SELF);
  } catch {
    // An argv[1] that does not resolve is not this file, and a refusal to decide is not a licence to run.
    return false;
  }
}

if (isProcessEntry()) main();
