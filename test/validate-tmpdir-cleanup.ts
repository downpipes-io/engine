// Guard: the ephemeral-tmp creators this pass fixed actually remove their scratch dirs, on every exit
// path, not only the happy one.
//
// THE FINDING. A per-user /tmp held about 48 GB: downpipes-fuzz-* alone accounted for 50,221 directories,
// downpipes-chunkbound-* 4,354, downpipes-sliceb-* 2,451, plus thousands more under downpipes-recordset-,
// downpipes-crossrun- and replica-restore-. Every one of those prefixes is a validator that called
// mkdtempSync(join(tmpdir(), prefix)) -- some of them once per fast-check case, so a single run of
// validate-fuzzing-tier1.ts alone makes ~230 of them -- and never removed the directory. A full disk
// voids a gate silently (the gate cannot write its own scratch state), so this is a genuine availability
// risk, not tidiness.
//
// THE FIX (test/testutil.ts's ephemeralTmpDir) is a single process "exit" handler that removes every
// registered dir however the process ends: a clean return, a thrown error inside an fc.assert body, or an
// explicit process.exit(). This guard proves that holds for real, not just by reading the source: it runs
// a representative set of the fixed validators as CHILD PROCESSES, each pointed at its own empty,
// disposable TMPDIR, and asserts that directory is empty again once the child has exited.
//
// WHY A CHILD PROCESS PER TARGET, not an in-process call. The cleanup fires on "exit", which never fires
// mid-process -- calling newTmp() in-process here would create a dir this guard's own exit hook would
// later sweep, proving nothing about the TARGET file's behaviour. A child process gives each target a
// real, independent process exit to be judged against, using the exact entry point the validate chain
// itself invokes.
//
// THE PLANT (how this guard is known to have teeth, not just to pass): reverting any one of the fixed
// files' newTmp()/ephemeralTmpDir() call back to a bare mkdtempSync (no registration, no cleanup) makes
// the matching iteration of this guard FAIL, because the child's private TMPDIR is left non-empty. That
// was run by hand against the pre-fix tree for validate-fuzzing-tier1.ts and validate-fuzzing-
// chunkboundary.ts (this file's required minimum) before this file was added to the chain: both failed
// red, both pass green on the fixed tree. See the commit message for the exact before/after evidence.
//
// Run: node test/validate-tmpdir-cleanup.ts

import { mkdtempSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { verdictReached } from "./lib/verdict-guard.ts";

const here = dirname(fileURLToPath(import.meta.url));

// The representative set. The finding named downpipes-fuzz- (tier1) and downpipes-chunkbound-
// (chunkboundary) by count, so both are required; the other three fixed test/*.ts creators (recordset,
// slice-boundary, crossrun-substitution, replica-restore) are the identical pattern and are included so a
// regression in any one of them is caught here rather than only by the next disk-full incident.
const TARGETS = [
  "validate-fuzzing-tier1.ts",
  "validate-fuzzing-chunkboundary.ts",
  "validate-fuzzing-slice-boundary.ts",
  "validate-fuzzing-recordset.ts",
  "validate-crossrun-substitution.ts",
  "validate-replica-restore.ts",
];

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

/**
 * Runs one target validator as a child process with its OWN fresh, empty TMPDIR (never the real OS temp
 * dir, so a genuine leak elsewhere on the machine cannot be mistaken for this target's), then reports the
 * child's exit code and whatever that TMPDIR still holds.
 */
function runUnderFreshTmpdir(rel: string): { code: number | null; leftovers: string[] } {
  const scratchParent = mkdtempSync(join(tmpdir(), "tmpdir-guard-"));
  const scratchTmp = join(scratchParent, "tmp");
  mkdirSync(scratchTmp);
  try {
    // FUZZ_SCALE=1 pins the fuzz members to their own default (already a smoke test, not a soak) so this
    // guard's runtime does not depend on an operator's export left over from a coverage-guided run.
    const res = spawnSync(process.execPath, [join(here, rel)], {
      encoding: "utf8",
      env: { ...process.env, TMPDIR: scratchTmp, FUZZ_SCALE: "1" },
    });
    const leftovers = readdirSync(scratchTmp);
    if (leftovers.length > 0 || res.status !== 0) {
      // Surfaced on a failure only: this guard's job is to say WHICH target and WHAT was left behind, not
      // to reprint 200+ lines of a passing fuzz validator's own assertions.
      console.log(`    --- ${rel} exit=${res.status} stderr(tail)=${(res.stderr ?? "").slice(-400)}`);
    }
    return { code: res.status, leftovers };
  } finally {
    rmSync(scratchParent, { recursive: true, force: true });
  }
}

function main(): void {
  for (const rel of TARGETS) {
    const { code, leftovers } = runUnderFreshTmpdir(rel);
    ok(`${rel} ran to completion (exit ${code})`, code === 0);
    ok(`${rel} left its private TMPDIR empty afterwards (found: ${leftovers.length > 0 ? leftovers.join(", ") : "none"})`, leftovers.length === 0);
  }
  console.log(failures === 0 ? `\nTMPDIR CLEANUP GUARD OK: ${TARGETS.length} fixed creators each left an empty TMPDIR behind` : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main();
