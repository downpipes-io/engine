// A single ephemeral-scratch-dir helper for the .mjs gates under scripts/, mirroring
// test/testutil.ts's ephemeralTmpDir for the .ts validators under test/. Both exist because a gate
// (e.g. determinism-gate.mjs) that mkdtemps a scratch dir per invocation, self-tests AND real runs
// alike, and never removes it, is how tens of thousands of dirs accumulate under the OS temp dir over
// repeated `npm run validate:chain` / `npm run lint:chain` invocations until a full disk silently voids
// a gate that never even ran.
//
// The cleanup runs from a process "exit" handler rather than a try/finally around each call site so it
// fires whichever way the process ends: a clean return, a thrown error, or an explicit process.exit().
// That is the one point every one of these gates' several exit paths (CLEAN, CANNOT_RUN, FOUND_SOMETHING)
// shares.
//

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ephemeralDirs = [];
let exitHookArmed = false;

function armExitCleanup() {
  if (exitHookArmed) return;
  exitHookArmed = true;
  process.on("exit", () => {
    for (const dir of ephemeralDirs.splice(0)) {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        /* best-effort: the process is already exiting, and failing that exit over a scratch dir it is
           about to lose control of anyway would trade a leaked dir for a lost exit code */
      }
    }
  });
}

/**
 * mkdtempSync(join(tmpdir(), prefix)) that removes itself on process exit (success, a thrown error, or
 * process.exit()), so a gate never has to thread its own try/finally around every scratch dir it makes.
 *
 * @param {string} prefix
 * @returns {string}
 */
export function ephemeralTmpDir(prefix) {
  armExitCleanup();
  const dir = mkdtempSync(join(tmpdir(), prefix));
  ephemeralDirs.push(dir);
  return dir;
}
