#!/usr/bin/env node
// The installed tree must match the lockfile, so a stale install is named rather than mistaken for broken
// code.
//
// WHAT THIS IS FOR. Merging a branch that changed dependencies leaves node_modules behind the lockfile.
// The next gate run then fails with exit 127, which is the shell saying a binary is not there, and 127
// looks exactly like a test failure in a chain of `npm run` steps. It cost time three separate times on
// : astro, biome and the docs build each came back 127 after a merge, each read as a real
// failure for a moment, and each was one `npm install` away.
//
// The signal is npm's own record. node_modules/.package-lock.json is what npm wrote when it last
// installed, so comparing it against package-lock.json says whether the tree on disk is the tree the lock
// describes. No network, no install, no resolution: two JSON files.
//
// TWO EXCLUSIONS, and both are needed or this reports a fault on every machine:
//   - optional packages, which npm is entitled not to install
//   - packages gated on os/cpu, the platform-specific binaries every toolchain ships for other systems.
//     On this machine that is 125 of 580 entries, so without this the check is pure noise.
//
// It reports the FIRST few names rather than all of them. A gate that prints 400 lines is one nobody
// reads, and the fix is the same regardless of how many are missing.
//
// House style: Australian English, no em dashes, no rule-of-three, no AI attribution.

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname;
const LOCK = join(ROOT, "package-lock.json");
const INSTALLED = join(ROOT, "node_modules", ".package-lock.json");

if (!existsSync(LOCK)) {
  console.error("FAIL deps-installed: no package-lock.json, so there is nothing to check the tree against.");
  process.exit(1);
}
// A git WORKTREE usually has no node_modules of its own: node resolves upward, so the checkout it was
// created from supplies the dependencies. That is how this workspace runs the engine and the website, so
// treating it as an empty environment would fail the very layout the work happens in.
//
// The ancestor is used, and then held to THIS repo's lockfile. Resolving upward is only safe while the
// two locks agree, and nothing otherwise says when they stop: a branch that changes a dependency would
// quietly build against the parent's version instead of its own.
function findInstallRecord(startDir) {
  let dir = startDir;
  for (let i = 0; i < 5; i++) {
    const candidate = join(dir, "node_modules", ".package-lock.json");
    if (existsSync(candidate)) return { path: candidate, dir };
    const up = dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return null;
}

const record = existsSync(INSTALLED) ? { path: INSTALLED, dir: ROOT } : findInstallRecord(dirname(ROOT));
if (record === null) {
  console.error(
    "FAIL deps-installed: no node_modules/.package-lock.json here or in any parent, so nothing is installed.\n" +
      "  Run `npm install`. Without it every gate that shells out to a binary fails with exit 127, which\n" +
      "  reads like broken code rather than an empty node_modules.",
  );
  process.exit(1);
}
const usingAncestor = record.dir !== ROOT;

const lock = JSON.parse(readFileSync(LOCK, "utf8"));
const installed = JSON.parse(readFileSync(record.path, "utf8"));

const have = new Map();
for (const [k, v] of Object.entries(installed.packages ?? {})) {
  if (k) have.set(k, v.version);
}

const want = new Map();
for (const [k, v] of Object.entries(lock.packages ?? {})) {
  if (!k) continue;
  if (v.optional === true) continue;
  if (v.os !== undefined || v.cpu !== undefined) continue;
  want.set(k, v.version);
}

// A gate that compares nothing reads exactly like a passing gate.
// Only an EMPTY set proves nothing was compared. A fixed floor was wrong: the harness lockfile has 38
// entries of which 29 are optional or platform-gated, so 8 required is its honest whole tree.
if (want.size === 0) {
  console.error("FAIL deps-installed: the lockfile lists no required packages, so nothing was compared.");
  process.exit(1);
}
if (have.size === 0) {
  console.error("FAIL deps-installed: npm's install record lists no packages, so it could not be compared.");
  process.exit(1);
}

const missing = [...want.keys()].filter((k) => !have.has(k));
const mismatched = [...want.entries()].filter(([k, v]) => have.has(k) && have.get(k) !== v).map(([k]) => k);

if (missing.length > 0 || mismatched.length > 0) {
  console.error("FAIL deps-installed: node_modules does not match package-lock.json.\n");
  if (missing.length > 0) {
    console.error(`  ${missing.length} package(s) in the lock are not installed, starting with:`);
    for (const m of missing.slice(0, 5)) console.error(`    ${m}`);
  }
  if (mismatched.length > 0) {
    console.error(`  ${mismatched.length} package(s) installed at a different version, starting with:`);
    for (const m of mismatched.slice(0, 5)) console.error(`    ${m}: lock ${want.get(m)}, installed ${have.get(m)}`);
  }
  console.error(
    "\n  Run `npm install`. This usually means a merge changed dependencies. Left alone, the next gate that\n" +
      "  shells out to a binary fails with exit 127, and 127 in a chain of npm scripts reads like a test\n" +
      "  failure rather than a missing install.",
  );
  process.exit(1);
}

const where = usingAncestor ? ` (installed in ${record.dir}, which this worktree resolves up to)` : "";
console.log(`ok   deps-installed: all ${want.size} required packages match the lockfile${where}`);
