// Resync every downstream repo to the engine's canonical surface counts.
//
// WHY THIS EXISTS
// ---------------
// Proving one writer moves `proven`, which moves the published in-band figure, which makes the docs
// snapshot, the website pin and their prose stale in the same instant. That happened three times in one
// afternoon and each round cost a manual sweep across two repos and a dozen prose files. The generators
// in each repo already know how to regenerate themselves; what was missing was one command that runs
// them all against the same engine checkout and reports what is still out of step.
//
// This script does NOT edit prose. It regenerates the machine-owned artefacts and then tells you which
// hand-written passages still disagree, because a number embedded in a sentence needs a human to decide
// whether the sentence still reads correctly at the new value.
//
// Usage, from the engine checkout whose counts are authoritative:
//   node scripts/resync-surface-counts.mjs           report only
//   node scripts/resync-surface-counts.mjs --write    regenerate the downstream artefacts

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { siblingLag, siblingLagLine } from "./lib/sibling-lag.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ENGINE = resolve(HERE, "..");
// The sibling repos live beside the engine's OWN root, not beside a worktree of it, so walk up out of
// any .worktrees/<name> segment before looking for them.
const WORKSPACE = ENGINE.includes("/.worktrees/") ? resolve(ENGINE.split("/.worktrees/")[0], "..") : resolve(ENGINE, "..");
const WRITE = process.argv.includes("--write");
// Only checkouts on this branch are written to. Everything else is reported and left alone.
const BRANCH = (process.argv.find((a) => a.startsWith("--branch=")) ?? "--branch=cf-surfaces-314-2026-07-26").slice("--branch=".length);

function canonical() {
  const out = execFileSync("node", [join(ENGINE, "test/validate-cf-config-surface-count.ts")], { cwd: ENGINE }).toString();
  const line = out.split("\n").find((l) => l.trim().startsWith("{"));
  if (line === undefined) throw new Error("the count validator printed no canonical line");
  return JSON.parse(line);
}

const TARGETS = [
  { repo: "docs", script: "scripts/gen-cf-surfaces.mjs", check: ["--check"], refresh: ["--refresh"] },
  { repo: "website", script: "scripts/gen-cf-config-surfaces.mjs", check: ["--check"], refresh: [] },
];

const counts = canonical();
console.log(`engine canonical: ${JSON.stringify(counts)}\n`);

let stale = 0;
let skipped = 0;
for (const t of TARGETS) {
  // A repo may be checked out at its root or at a worktree of it; try the root first, then any worktree
  // that carries the generator, so this works whichever the operator has open.
  const roots = [join(WORKSPACE, t.repo), ...(existsSync(join(WORKSPACE, t.repo, ".worktrees")) ? execFileSync("ls", [join(WORKSPACE, t.repo, ".worktrees")]).toString().trim().split("\n").filter(Boolean).map((w) => join(WORKSPACE, t.repo, ".worktrees", w)) : [])];
  // Check EVERY checkout that carries the generator, not the first one found. A repo commonly has its
  // main clone on one branch and a worktree on another, and picking whichever came first reported "in
  // step" from a checkout that had none of the relevant work in it. A wrong green is worse than a noisy
  // report, so each checkout is named and judged on its own.
  const found = roots.filter((r) => existsSync(join(r, t.script)));
  if (found.length === 0) {
    // This used to `continue` here with no other trace. A run where every TARGET is
    // skipped this way still fell through to `stale === 0` and printed "all downstream artefacts in
    // step", which is not a smaller version of the truth, it is the opposite of it: nothing was read at
    // all. Skips are now counted and change both the exit code and the closing line.
    console.log(`  ${t.repo.padEnd(9)} SKIP, no ${t.script} found`);
    skipped += 1;
    continue;
  }
  const env = { ...process.env, DOWNPIPES_ENGINE: ENGINE };
  for (const root of found) {
  // A workspace holds several sessions' checkouts side by side. Regenerating into someone else's branch
  // would be an edit they never asked for, so --write is confined to checkouts on BRANCH (default: the
  // surface branch). Every checkout is still REPORTED, because a stale sibling is worth knowing about
  // even when it is not ours to fix.
  const branch = (() => { try { return execFileSync("git", ["branch", "--show-current"], { cwd: root, stdio: "pipe" }).toString().trim(); } catch { return ""; } })();
  const mine = branch === BRANCH;
  const label = `${t.repo}${root.includes("/.worktrees/") ? `:${root.split("/.worktrees/")[1]}` : ""}`;
  // WHICH CHECKOUT, said out loud, per checkout. GRADE AND SAY SO, and this is the one place in the repo
  // where refusing would be wrong on purpose: the loop above deliberately visits EVERY worktree of every
  // target, most of them other sessions' branches which are not at main and are not ours to fix. A gate that
  // exits 2 at the first one behind origin/main could never do the only thing this script exists for, which
  // is to survey them all. The line below is what "in step" and "STALE" were previously missing: the branch,
  // the sha and the lag of the tree the verdict on the next line is about.
  console.log(`  ${label.padEnd(22)} ${siblingLagLine(siblingLag(t.repo, root), { bare: true })}${branch === "" ? "" : `, branch ${branch}`}`);
  const run = (args) => {
    try {
      execFileSync("node", [t.script, ...args], { cwd: root, env, stdio: "pipe" });
      return { ok: true, out: "" };
    } catch (e) {
      return { ok: false, out: `${e.stdout ?? ""}${e.stderr ?? ""}`.trim().split("\n").slice(-2).join(" | ") };
    }
  };
  const before = run(t.check);
  if (before.ok) {
    console.log(`  ${label.padEnd(22)} in step`);
    continue;
  }
  stale += 1;
  if (!WRITE || !mine) {
    console.log(`  ${label.padEnd(22)} STALE${mine ? "" : ` (branch ${branch}, not ours, left alone)`}: ${before.out}`);
    continue;
  }
  run(t.refresh);
  const after = run(t.check);
  console.log(`  ${label.padEnd(22)} ${after.ok ? "regenerated, now in step" : `regenerated, STILL STALE: ${after.out}`}`);
  if (!after.ok) console.log(`  ${" ".repeat(22)} a pinned figure or a hand-written passage needs a human; the generator cannot decide wording`);
  }
}

// Exit non-zero on either signal, and on DIFFERENT codes: 2 for "could not check" (a target skipped
// because no checkout of it carries the generator), reserved and distinct from 1, which stays for "checked
// every target and at least one is genuinely stale". A caller that greps for any non-zero exit, without
// reading the message, must not read "nothing was on disk to check" as "found a defect".
if (skipped > 0) {
  console.log(`\n${skipped} target(s) skipped, no checkout on disk carried the generator; nothing was verified for ${skipped === TARGETS.length ? "any of them" : "them"}.`);
  // Only say something about the targets that WERE read when there were any. With every target skipped
  // there is no remainder to report, and a line about "the rest" would be the same vacuous reassurance
  // this change exists to remove.
  if (skipped < TARGETS.length) {
    console.log(stale === 0 ? "The rest report in step, but that is not the same claim as all downstream artefacts being in step." : `${stale} of the rest report stale${WRITE ? " and have been regenerated" : "; re-run with --write"}.`);
  }
  process.exit(2);
}
console.log(stale === 0 ? "\nall downstream artefacts in step" : `\n${stale} repo(s) were stale${WRITE ? " and have been regenerated" : "; re-run with --write"}`);
process.exit(stale === 0 ? 0 : 1);
