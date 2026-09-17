// Every cf-config safety guard must be LOAD-BEARING: neuter it and something must go red.
//
// WHY THIS EXISTS
// ---------------
// Three gaps were found in three sittings, all the same shape: a guard enforced in one module, consumed in
// another, and no test that would notice the consumer dropping it. F10 (an unproven writer must not run by
// default), F9 through the plan (a diff of pure removals must not read as an apply), and one branch of B3
// (an absent nested array is not an empty one). Each was found by hand, by deleting the condition and
// watching the suite stay green.
//
// Grepping does not find these. The attempt that started this file searched the tests for
// `nestedLiveOnly` and `nestedCollections`, found nothing, and concluded B3 was untested. B3 is thoroughly
// tested; the block that does it drives the real surface and never names either identifier. Searching for
// an identifier is not searching for a behaviour.
//
// Stryker is configured in this repo, but it mutates six crypto and format files. None of the cf-config
// write path is in its list, so none of this was covered by it.
//
// WHAT THIS IS, AND WHAT IT IS NOT
// --------------------------------
// It is a CURATED mutation test: a hand-picked list of the conditions that carry a safety claim, each with
// the gate that should die when it is removed. The list is not a fixed size and is meant to grow: a new
// guard without an entry here is a guard nobody has checked is load-bearing. It is not general mutation testing and does not try to be.
// A general run over this file set would spend most of its time on mutants nobody would ever write, and
// the interesting question here is narrow: is each guard we CLAIM to have actually held up by a test?
//
// A guard whose removal changes nothing is reported as UNGUARDED. That is not necessarily a bug in the
// product, but it is always a gap in the evidence, and it is exactly the state all three earlier gaps were
// in.
//
// SAFETY: IT MUTATES A SANDBOX, NEVER THE REAL TREE, AND THAT IS NOT A TIDINESS PREFERENCE
// ----------------------------------------------------------------------------------------
// This file used to edit the real src files in place and restore them, with every mutation inside a
// try/finally. That was safe against ITSELF and unsafe against everything else, because the corruption was
// visible to every other process sharing the checkout for as long as the window lasted.
//
// MEASURED, on a clone of this repo, not argued. Driving `node test/validate-cf-config-write-generated.ts`
// in a loop while the OLD form of this file ran alongside it produced 26 reds in 126 runs, every one of
// them the line "FAIL the configPlan.push is guarded by the resolved allow-list, not merely near a mention
// of it". The same validator run 40 times with nothing else going was green 40 times, and green 5 of 5
// immediately after the 26 reds. So the corruption made a validator SAY A SAFETY GUARD WAS MISSING when it
// was there, and the accusation evaporated the moment anyone re-ran it to look.
//
// That is the worst debugging shape available. An intra-process race at least reproduces under load; this
// one is inter-process through the filesystem, so isolating the accused validator is precisely the act that
// destroys the evidence. The 26 reds cluster at the start of the run because guards 1 and 2 both neuter
// src/admin/restore-plan.ts while spawning validate-restore.ts, which is the slowest gate here, so that one
// file is corrupt for roughly 18 of the run's 28 mutated seconds.
//
// The blast radius was never the six gates below. It was every reader of the seven mutated files: the other
// validators that import them, a typecheck, an editor, a second checkout-sharing agent. A lock would only
// have covered the readers that agreed to take it, and a guard others opt into is the defect wearing a
// helmet. Copying is the only remedy that covers a reader that has never heard of this file.
//
// So: one temp copy of src, test and scripts per run, mutated and restored INSIDE the copy, with the gate
// spawned at the copy's root. The real tree is opened read-only and never written, which is also why the
// old "*** WAS NOT RESTORED ***" catastrophe path can no longer strand a developer's checkout.
//
// WHY THE BASELINE PASS BELOW IS NOT OPTIONAL. In a test whose verdict is "the gate died, so the guard is
// load-bearing", ANY cause of death reads as ok. A sandbox missing a file the gate needs would therefore
// turn all thirteen cases green while proving nothing at all, and it would look exactly like a healthy run.
// Each distinct gate is run once UNMUTATED in the sandbox first and must exit 0. That is the positive
// control for the copy, and it is what makes a later "ok" mean the mutation killed the gate rather than the
// sandbox did.
//
// COST: about 0.5s to build the copy and about 8s for the six baseline runs, against roughly 28s of mutated
// gate time this file already spent. Run with `node test/validate-cf-guards-are-load-bearing.ts`. Slow (it
// runs a gate per guard), so it is NOT in the default validate chain; it is wired to its own npm script.

import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";

interface Guard {
  what: string; // the safety claim, in the terms the product makes it
  file: string;
  find: string; // the exact source of the condition
  replace: string; // the neutered form
  gate: string; // the test that must die
}

const GUARDS: Guard[] = [
  {
    what: "F10: an UNPROVEN writer must not run when a restore names no scope",
    file: "src/admin/restore-plan.ts",
    find: "&& allowedSurfaces.has(rec.name)",
    replace: "",
    gate: "test/validate-restore.ts",
  },
  {
    what: "F9: a diff of pure removals must not read as an apply",
    file: "src/admin/restore-plan.ts",
    find: 'willApply: res.changes.some((c) => c.action !== "remove")',
    replace: "willApply: res.changes.length > 0",
    gate: "test/validate-restore.ts",
  },
  {
    what: "B3: an update must not silently drop an entry from a nested collection",
    file: "src/sources/cf-config-write.ts",
    find: "const lostNested = nestedLiveOnly(spec, match, snap);",
    replace: "const lostNested: Array<{ field: string; entries: unknown[] }> = [];",
    gate: "test/validate-cf-config-write.ts",
  },
  {
    what: "B3: an ABSENT nested array in the snapshot is not an EMPTY one",
    file: "src/sources/cf-config-write.ts",
    find: "if (!Array.isArray(liveArr) || !Array.isArray(snapArr)) continue;",
    replace: "if (!Array.isArray(liveArr) || !Array.isArray(snapArr)) { if (Array.isArray(liveArr) && liveArr.length > 0) out.push({ field, entries: liveArr }); continue; }",
    gate: "test/validate-cf-config-write.ts",
  },
  {
    what: "the default restore scope is the PROVEN set, not every surface carrying a writer",
    file: "src/admin/approvals.ts",
    find: "const allowed = explicit === undefined ? inBand.filter((id) => PROVEN_WRITE_SURFACES.has(id)) : inBand.filter((id) => explicit.includes(id));",
    replace: "const allowed = explicit === undefined ? inBand : inBand.filter((id) => explicit.includes(id));",
    gate: "test/validate-cf-config-write-generated.ts",
  },
  {
    what: "the plan hash binds the resolved cf-config surface set (widening invalidates an approval)",
    file: "src/admin/approvals.ts",
    find: "surfaces: resolveCfConfigSurfaces(req.cfConfig.surfaces)",
    replace: "surfaces: []",
    gate: "test/validate-restore.ts",
  },
  {
    // A bare `true` would let a drifted or automated caller wave the guard through without ever naming the
    // foreign account, which is the whole reason it is a type-to-confirm rather than a boolean.
    what: "cross-account: the caller must echo the EXACT target account, not merely assert something",
    file: "src/admin/restore-cross-account.ts",
    find: "return leg !== undefined && leg.confirmDifferentAccountId === w.targetAccount;",
    replace: "return leg !== undefined && leg.confirmDifferentAccountId !== undefined;",
    gate: "test/validate-restore-cross-account.ts",
  },
  {
    what: "cross-zone: the caller must echo the EXACT target zone, not merely assert something",
    file: "src/admin/restore-cross-account.ts",
    find: "return body.cfConfig?.confirmDifferentZoneId === w.targetZone;",
    replace: "return body.cfConfig?.confirmDifferentZoneId !== undefined;",
    gate: "test/validate-restore-cross-account.ts",
  },
  {
    // Cloudflare marks plan-gated settings non-editable. Writing one anyway turns a fact about the plan into
    // a per-run error, and on a surface the operator cannot fix.
    what: "a setting the account marks NOT EDITABLE is skipped rather than written",
    file: "src/sources/cf-config-write-settings.ts",
    find: "if (snap.editable === false || (live !== null && typeof live === \"object\" && live.editable === false)) {",
    replace: "if (false) {",
    gate: "test/validate-cf-config-write.ts",
  },
  {
    // It records which account and zone the archive came from. Treating it as a surface would attempt to
    // write the identity of the backup INTO the account being restored.
    what: "the cf-config identity record is out of band, never a restorable surface",
    file: "src/admin/restore-plan.ts",
    find: "if (rec.name === CF_CONFIG_IDENTITY_ID) {",
    replace: "if (false) {",
    gate: "test/validate-restore.ts",
  },
  {
    // The one that got through. A restore driven with a token that was merely too NARROW attempted every
    // item, had every item refused 401/403, and reported ok:true with an empty failures list, because a
    // classified per-item skip reached configApplied and stopped there.
    what: "a cf-config surface the API refused must make the apply report ok:false, not success",
    file: "src/admin/restore-apply.ts",
    find: "if (unrestored.length > 0) {",
    replace: "if (false) {",
    gate: "test/validate-restore-underscoped-token.ts",
  },
  {
    // And the receipt half of the same defect. The receipt is what the customer keeps as evidence, so a
    // surface that wrote nothing signing as verified is worse than the silent ok: it is attested.
    what: "a cf-config surface the API refused must not sign as verified on the receipt",
    file: "src/admin/restore-apply.ts",
    find: 'verified: unrestored.length === 0, via: "cf-config-applied" });',
    replace: 'verified: true, via: "cf-config-applied" });',
    gate: "test/validate-restore-underscoped-token.ts",
  },
  {
    what: "HTTP 204 is a success, not a refusal",
    file: "src/sources/cf-config-core.ts",
    find: "if (resp.status === 204) return { result: null };",
    replace: "",
    gate: "test/validate-cf-api-status.ts",
  },
];

// REPO_ROOT is derived from this file rather than from process.cwd(), so the sandbox is a copy of the tree
// this file belongs to even when it is invoked from somewhere else.
const REPO_ROOT = resolve(fileURLToPath(new URL(".", import.meta.url)), "..");

// The directories the six spawned gates actually reach for. src is the only one that gets mutated; test and
// scripts are copied rather than symlinked because Node resolves a module's realpath, so a symlinked test
// file would resolve its own `../src/` back into the REAL tree and quietly undo the whole sandbox. The
// baseline pass below is what proves this set is complete; do not shorten it on the strength of a reading.
const SANDBOX_DIRS = ["src", "test", "scripts"];
const SANDBOX_FILES = ["package.json", "tsconfig.json", "tsconfig.test.json"];

const sandbox = mkdtempSync(join(tmpdir(), "cf-guards-sandbox-"));
// A sandbox that is not under the OS temp dir is not a sandbox, and the failure it would produce is writing
// mutated source into somebody's checkout. Refuse rather than proceed: this is exit 2, could not check.
if (!resolve(sandbox).startsWith(resolve(tmpdir()))) {
  console.error(`*** refusing to mutate outside the OS temp dir: ${sandbox} ***`);
  // Declared, not silent. A refusal is a verdict like any other, and the completion guard cannot tell a
  // deliberate refusal from a run that fell out before its tally unless it is said out loud.
  verdictSkipped(`REFUSED, exit 2: the sandbox path ${sandbox} is not under the OS temp dir, so no mutation was attempted`);
  process.exit(2);
}
for (const d of SANDBOX_DIRS) cpSync(join(REPO_ROOT, d), join(sandbox, d), { recursive: true });
for (const f of SANDBOX_FILES) cpSync(join(REPO_ROOT, f), join(sandbox, f));
// node_modules is read, never written, so a symlink is correct here and saves copying the whole tree.
symlinkSync(join(REPO_ROOT, "node_modules"), join(sandbox, "node_modules"));
console.log(`sandbox: ${sandbox} (a copy of ${SANDBOX_DIRS.join(", ")}; the real tree is never written)`);

/** runGate runs one gate AT THE SANDBOX ROOT, so every `../src/` import it makes lands in the copy. */
function runGate(gate: string): number {
  return spawnSync("node", [gate], { cwd: sandbox, encoding: "utf8" }).status ?? 1;
}

let unguarded = 0;
let broken = 0;

// BASELINE: every distinct gate must pass on the UNMUTATED sandbox before a single mutation is applied.
// Without this, a gate that cannot run in the copy dies for the wrong reason and this file calls that "ok".
console.log("\nbaseline (each gate must pass on the unmutated sandbox, or every ok below is meaningless):");
let sandboxBroken = 0;
for (const gate of [...new Set(GUARDS.map((g) => g.gate))]) {
  const status = runGate(gate);
  console.log(status === 0 ? `  ok      ${gate} passes in the sandbox` : `  BROKEN  ${gate} FAILS in the sandbox before any mutation (exit ${status}); the copy is incomplete or the gate is already red`);
  if (status !== 0) sandboxBroken++;
}
if (sandboxBroken > 0) {
  console.error(`\n*** ${sandboxBroken} gate(s) do not pass on the unmutated sandbox, so NOTHING below could be concluded. ***`);
  rmSync(sandbox, { recursive: true, force: true });
  // Exit 2, could not check, not exit 1, found something: a broken sandbox says nothing about the guards.
  verdictSkipped(`REFUSED, exit 2: ${sandboxBroken} gate(s) fail on the unmutated sandbox, so no mutation result could be believed`);
  process.exit(2);
}

console.log("");
for (const g of GUARDS) {
  const target = join(sandbox, g.file);
  const original = readFileSync(target, "utf8");
  if (!original.includes(g.find)) {
    // The guard's source has moved or been reworded. That is NOT a pass: this file can no longer prove
    // anything about it, and a silently-skipped case is the failure mode the whole suite is written against.
    console.log(`  BROKEN  ${g.what}\n          its source no longer contains the expected condition in ${g.file}; update this file`);
    broken++;
    continue;
  }
  let restored = false;
  try {
    writeFileSync(target, original.replace(g.find, g.replace), "utf8");
    const died = runGate(g.gate) !== 0;
    console.log(died ? `  ok      ${g.what}\n          (removing it fails ${g.gate})` : `  UNGUARDED ${g.what}\n          removing it from ${g.file} changes NOTHING in ${g.gate}`);
    if (!died) unguarded++;
  } finally {
    // Restoring between cases still matters inside the sandbox, or mutations would compound and every case
    // after the first would be graded against a tree carrying the previous guard's removal as well.
    writeFileSync(target, original, "utf8");
    restored = readFileSync(target, "utf8") === original;
  }
  if (!restored) {
    console.error(`\n*** the sandbox copy of ${g.file} WAS NOT RESTORED, so the remaining cases would compound. ***`);
    rmSync(sandbox, { recursive: true, force: true });
    verdictSkipped(`REFUSED, exit 2: the sandbox copy of ${g.file} was not restored, so the remaining cases could not be graded`);
    process.exit(2);
  }
}

rmSync(sandbox, { recursive: true, force: true });

console.log(
  unguarded === 0 && broken === 0
    ? `\nCF GUARDS ARE LOAD-BEARING: all ${GUARDS.length} checked`
    : `\n${unguarded} UNGUARDED, ${broken} BROKEN of ${GUARDS.length}`,
);
verdictReached(unguarded + broken);
if (unguarded > 0 || broken > 0) process.exit(1);
