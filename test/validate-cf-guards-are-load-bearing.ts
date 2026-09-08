// Every cf-config safety guard must be LOAD-BEARING: neuter it and something must go red.
//
// WHAT THIS IS, AND WHAT IT IS NOT
// --------------------------------
// It is a CURATED mutation test: a hand-picked list of the conditions that carry a safety claim, each with
// the gate that should die when it is removed. The list is not a fixed size and is meant to grow: a new
// guard without an entry here is a guard nobody has checked is load-bearing. It is not general mutation
// testing and does not try to be. A general run over this file set would spend most of its time on mutants
// nobody would ever write, and the interesting question here is narrow: is each guard we CLAIM to have
// actually held up by a test?
//
// A guard whose removal changes nothing is reported as UNGUARDED. That is not necessarily a bug in the
// product, but it is always a gap in the evidence.
//
// SAFETY: IT MUTATES A SANDBOX, NEVER THE REAL TREE
// ---------------------------------------------------
// Each run makes one temporary copy of src, test and scripts, mutates and restores each guard's file INSIDE
// the copy, and spawns the gate at the copy's root. The real tree is opened read-only and never written, so
// a mutation can never corrupt a checkout another process is reading.
//
// WHY THE BASELINE PASS BELOW IS NOT OPTIONAL. In a test whose verdict is "the gate died, so the guard is
// load-bearing", ANY cause of death reads as ok. A sandbox missing a file the gate needs would therefore
// turn all cases green while proving nothing at all, and it would look exactly like a healthy run. Each
// distinct gate is run once UNMUTATED in the sandbox first and must exit 0. That is the positive control for
// the copy, and it is what makes a later "ok" mean the mutation killed the gate rather than the sandbox did.
//
// Slow (it runs a gate per guard), so it is NOT in the default validate chain; it is wired to its own npm
// script. Run with `node test/validate-cf-guards-are-load-bearing.ts`.

import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

interface Guard {
  what: string; // the safety claim, in the terms the product makes it
  file: string;
  find: string; // the exact source of the condition
  replace: string; // the neutered form
  gate: string; // the test that must die
}

const GUARDS: Guard[] = [
  {
    what: "an UNPROVEN writer must not run when a restore names no scope",
    file: "src/admin/restore-plan.ts",
    find: "&& allowedSurfaces.has(rec.name)",
    replace: "",
    gate: "test/validate-restore.ts",
  },
  {
    what: "a diff of pure removals must not read as an apply",
    file: "src/admin/restore-plan.ts",
    find: 'willApply: res.changes.some((c) => c.action !== "remove")',
    replace: "willApply: res.changes.length > 0",
    gate: "test/validate-restore.ts",
  },
  {
    what: "an update must not silently drop an entry from a nested collection",
    file: "src/sources/cf-config-write.ts",
    find: "const lostNested = nestedLiveOnly(spec, match, snap);",
    replace: "const lostNested: Array<{ field: string; entries: unknown[] }> = [];",
    gate: "test/validate-cf-config-write.ts",
  },
  {
    what: "an ABSENT nested array in the snapshot is not an EMPTY one",
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
    // A restore driven with a token that is merely too NARROW attempts every item and has every item
    // refused 401/403; a classified per-item skip must not reach configApplied and report success anyway.
    what: "a cf-config surface the API refused must make the apply report ok:false, not success",
    file: "src/admin/restore-apply.ts",
    find: "if (unrestored.length > 0) {",
    replace: "if (false) {",
    gate: "test/validate-restore-underscoped-token.ts",
  },
  {
    // The receipt is what the customer keeps as evidence, so a surface that wrote nothing signing as
    // verified is worse than a silent failure: it is attested.
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
  /* skipped: advisory */
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
  /* skipped: advisory */
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
    /* skipped: advisory */
    process.exit(2);
  }
}

rmSync(sandbox, { recursive: true, force: true });

console.log(
  unguarded === 0 && broken === 0
    ? `\nCF GUARDS ARE LOAD-BEARING: all ${GUARDS.length} checked`
    : `\n${unguarded} UNGUARDED, ${broken} BROKEN of ${GUARDS.length}`,
);
if (unguarded + broken > 0) process.exitCode = 1;
if (unguarded > 0 || broken > 0) process.exit(1);
