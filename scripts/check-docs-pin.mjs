#!/usr/bin/env node
// check-docs-pin: the docs checkout CI grades the posture-score page against is a commit that exists
// on the docs remote.
//
// .github/docs-pin holds one full 40-character docs sha. ci.yml checks the docs site out at that sha
// (not at the default branch), so test/validate-posture-and-docs-parity.ts --require grades the
// engine's CHECK_SEVERITY against a docs page nobody moved underneath the run. The docs repository
// pins the engine the same way (docs/.github/engine-pin), and the website pins its releases.
//
// THE TWO ACCEPTED STATES, both read from a docs checkout with full history (DOWNPIPES_DOCS):
//
//   1. ON MAIN: the pin is an ancestor of, or equal to, docs origin/main. PASS.
//   2. OFF MAIN: the pin exists on the docs remote (some remote branch contains it) but is not on docs
//      main. PASS, with a loud line naming the branches, and a VERDICT line that says so. This state
//      exists ONLY so a coordinated engine and docs change can land: when an engine change and the docs
//      page that lists its new posture check move together, the engine pins the pushed docs branch
//      commit for that one landing, and the next landing moves the pin to docs main.
//
// FAIL CLOSED. A sha that is not in the docs checkout at all is refused (exit 1). A missing checkout,
// a checkout without origin/main, or a shallow checkout that cannot resolve the pin is reported as a
// check that could not run (exit 2), never as a pass. A commit that no remote branch contains is not
// "on the docs remote", so it is refused too.
//
// Usage:
//   node scripts/check-docs-pin.mjs               grade .github/docs-pin against $DOWNPIPES_DOCS
//   node scripts/check-docs-pin.mjs --self-test   prove every state on disposable git repositories
//
// Exit codes: 0 pass (on main, or off main and loud). 1 refused (malformed pin, unknown sha, or a
// commit on no remote branch). 2 could not check (missing or shallow checkout, no origin/main).

import { existsSync, readFileSync, realpathSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PIN_PATH = resolve(ROOT, ".github", "docs-pin");
const SHA_RE = /^[0-9a-f]{40}$/;
const MAIN_REF = "origin/main";

/**
 * @param {string} root
 * @param {...string} args
 * @returns {string}
 */
function git(root, ...args) {
  return execFileSync("git", ["-C", root, ...args], { stdio: "pipe" }).toString();
}

/**
 * @param {string} pinText
 * @returns {{ ok: true, sha: string } | { ok: false, reason: string }}
 */
export function parsePin(pinText) {
  const sha = pinText.trim();
  if (!SHA_RE.test(sha)) {
    return { ok: false, reason: `.github/docs-pin does not hold a single 40-character lowercase-hex sha (read: ${JSON.stringify(pinText.slice(0, 80))})` };
  }
  return { ok: true, sha };
}

/**
 * @param {string} docsRoot
 * @param {string} sha
 * @returns {{ ok: true, state: "main" } | { ok: true, state: "off-main", branches: string[] } | { ok: false, kind: "cannot-check" | "refused", reason: string }}
 */
export function evaluateDocsPin(docsRoot, sha) {
  if (!existsSync(join(docsRoot, ".git"))) {
    return { ok: false, kind: "cannot-check", reason: `no docs checkout with git history at ${docsRoot} (DOWNPIPES_DOCS). A pin this script cannot verify is not a verified pin.` };
  }
  let shallow = false;
  try {
    shallow = git(docsRoot, "rev-parse", "--is-shallow-repository").trim() === "true";
  } catch (err) {
    return { ok: false, kind: "cannot-check", reason: `${docsRoot} is not a readable git checkout (${String(/** @type {Error} */ (err).message).split("\n")[0]})` };
  }
  try {
    git(docsRoot, "rev-parse", "--verify", "--quiet", `${MAIN_REF}^{commit}`);
  } catch {
    return { ok: false, kind: "cannot-check", reason: `${docsRoot} has no ${MAIN_REF}, so the pin cannot be placed against docs main. Check the docs out with fetch-depth: 0.` };
  }
  let present = true;
  try {
    git(docsRoot, "cat-file", "-e", `${sha}^{commit}`);
  } catch {
    present = false;
  }
  if (!present) {
    if (shallow) {
      return { ok: false, kind: "cannot-check", reason: `the pinned sha ${sha} is not in ${docsRoot}, which is a shallow checkout; give it full history before this check can run.` };
    }
    return { ok: false, kind: "refused", reason: `the pinned sha ${sha} is not a commit in the docs repository at ${docsRoot}. Pin a commit that exists on the docs remote.` };
  }
  let onMain;
  try {
    git(docsRoot, "merge-base", "--is-ancestor", sha, MAIN_REF);
    onMain = true;
  } catch (err) {
    if (/** @type {{ status?: number }} */ (err).status !== 1) {
      return { ok: false, kind: "cannot-check", reason: `git could not place ${sha} against ${MAIN_REF} in ${docsRoot}${shallow ? " (shallow checkout)" : ""}.` };
    }
    onMain = false;
  }
  if (onMain) return { ok: true, state: "main" };
  /** @type {string[]} */
  let branches = [];
  try {
    branches = git(docsRoot, "branch", "-r", "--contains", sha)
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l !== "" && !l.includes("->"));
  } catch {
    branches = [];
  }
  if (branches.length === 0) {
    return { ok: false, kind: "refused", reason: `the pinned sha ${sha} is in ${docsRoot} but no remote branch contains it, so it is not on the docs remote. Push it, or pin docs main.` };
  }
  return { ok: true, state: "off-main", branches };
}

/**
 * Prints the verdict for one evaluation and returns the exit code.
 * @param {ReturnType<typeof evaluateDocsPin>} result
 * @param {string} sha
 * @param {string} docsRoot
 * @param {(line: string) => void} [log]
 * @param {(line: string) => void} [err]
 * @returns {number}
 */
export function report(result, sha, docsRoot, log = console.log, err = console.error) {
  if (result.ok && result.state === "main") {
    log(`check-docs-pin: docs pin ${sha.slice(0, 12)} is on docs ${MAIN_REF} (checked against ${docsRoot}).`);
    log("check-docs-pin: VERDICT: PASS (docs pin is on main)");
    return 0;
  }
  if (result.ok) {
    log(`check-docs-pin: OFF-MAIN docs pin ${sha.slice(0, 12)} (on branch ${result.branches.join(", ")}); move the pin to docs main in the next landing`);
    log("check-docs-pin: VERDICT: PASS (OFF-MAIN docs pin, on a pushed docs branch only)");
    return 0;
  }
  err(`check-docs-pin: ${result.reason}`);
  if (result.kind === "cannot-check") {
    err("check-docs-pin: VERDICT: SKIPPED could-not-check");
    return 2;
  }
  err("check-docs-pin: VERDICT: FAIL refused");
  return 1;
}

function invokedDirectly() {
  const argv1 = process.argv[1];
  if (argv1 === undefined) return false;
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(argv1);
  } catch {
    // A path that cannot be resolved is not the entry point, and must not throw out of a top-level guard.
    return false;
  }
}

async function main() {
  if (process.argv.includes("--self-test")) {
    const { selfTest } = await import("./check-docs-pin.selftest.mjs");
    const { failures, checks, lines } = selfTest({ parsePin, evaluateDocsPin, report });
    for (const l of lines) console.log(l);
    console.log(
      failures === 0
        ? `check-docs-pin --self-test: ${checks} case(s), every pin state this gate claims to accept or refuse behaved as claimed. VERDICT: PASS`
        : `check-docs-pin --self-test: ${failures} of ${checks} case(s) did NOT behave as claimed. VERDICT: FAIL`,
    );
    return failures === 0 ? 0 : 1;
  }
  if (!existsSync(PIN_PATH)) {
    console.error(`check-docs-pin: ${PIN_PATH} does not exist.`);
    console.error("check-docs-pin: VERDICT: SKIPPED could-not-check");
    return 2;
  }
  const pin = parsePin(readFileSync(PIN_PATH, "utf8"));
  if (!pin.ok) {
    console.error(`check-docs-pin: ${pin.reason}`);
    console.error("check-docs-pin: VERDICT: FAIL refused");
    return 1;
  }
  const docsRoot = process.env.DOWNPIPES_DOCS ? resolve(process.env.DOWNPIPES_DOCS) : resolve(ROOT, "..", "docs");
  return report(evaluateDocsPin(docsRoot, pin.sha), pin.sha, docsRoot);
}

// Guarded so the module can be imported without running, and wrapped so a crash exits 2 rather than 1:
// 1 means "refused", and a crash read as a refusal is a defect read as a finding.
if (invokedDirectly()) {
  let code = 2;
  try {
    code = await main();
  } catch (e) {
    console.error(`check-docs-pin: the run threw and nothing was checked (${String(e)}).`);
    console.error("check-docs-pin: VERDICT: SKIPPED could-not-check");
  }
  process.exit(code);
}
