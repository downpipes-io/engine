// Mutation test for the reset-before-hash idempotency property in scripts/stamp-build-id.mjs.
//
// THE DEFECT THIS PINS. Without a reset-before-hash step, stamp-build-id.mjs would hash whatever is
// ALREADY sitting in the committed src/format/build-stamp.ts and then overwrite that file with the
// result: a hash computed over its own prior output, fed back in as the next run's input. Two
// consecutive runs against one checkout, same commit, same config, nothing else touched, would then
// produce two unrelated digests. A script that runs this once per estate against
// the ONE shared ../engine checkout across a fleet would then have every estate after the first inherit the
// previous estate's leftover stamp, and every estate would report an unrelated digest, none matching
// manifest/engine-artefact.json's expectation.
//
// WHAT THIS FILE PROVES. Two consecutive stamps against an unchanged checkout, in the FIXED mode
// (resetFirst: true, the only mode scripts/stamp-build-id.mjs's main() ever uses) must be IDENTICAL.
// That alone is the acceptance case; everything else here proves the test is not vacuous by reproducing
// the regression on demand (resetFirst: false, kept in the module ONLY for this test) and proving the
// fix recovers determinism even from a corrupted leftover state.
//
// THIS IS A LIVE TEST: it shells out to `wrangler deploy --dry-run` for real (no network beyond wrangler's
// own local bundling) three times, roughly 45-90 seconds total. It is therefore NOT wired into `npm run
// validate`'s fast chain (nothing else in that chain spawns a real wrangler build); run it directly before
// or after touching scripts/stamp-build-id.mjs. The existing .github/workflows/reproducibility-check.yml
// proves a DIFFERENT property -- byte-identical output across two independent fresh clones -- which would
// NOT catch this defect, since both of ITS builds start from a clean checkout and never reuse accumulated
// build-stamp.ts state the way repeated in-place invocations across a fleet do.
//
// It mutates this checkout's REAL src/format/build-stamp.ts (wrangler always bundles the actual file on
// disk; there is no way to point it at an alternate path) and restores the committed placeholder in a
// finally block on every exit path, success or failure, so it never leaves the tree dirty.
//
// Run: node test/validate-stamp-idempotency.ts

import { readFileSync, writeFileSync } from "node:fs";
import { resetStampToPlaceholder, stampOnce, STAMP_PATH } from "../scripts/stamp-build-id.mjs";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean, detail?: string): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}${!cond && detail ? `  (${detail})` : ""}`);
  if (!cond) failures++;
}

async function main(): Promise<void> {
  const original = readFileSync(STAMP_PATH, "utf8");

  try {
    // ---- 1. THE ACCEPTANCE CASE: fixed mode is idempotent ----
    resetStampToPlaceholder();
    console.log("run 1 (fixed mode)...");
    const run1 = await stampOnce({ resetFirst: true });
    console.log(`  digest ${run1.digest.slice(0, 16)}  ${run1.bundleBytes} bytes`);
    console.log("run 2 (fixed mode, same checkout, nothing changed)...");
    const run2 = await stampOnce({ resetFirst: true });
    console.log(`  digest ${run2.digest.slice(0, 16)}  ${run2.bundleBytes} bytes`);
    ok(
      "two consecutive stamps against an unchanged checkout are IDENTICAL (the property that failed)",
      run1.digest === run2.digest,
      `run1=${run1.digest} run2=${run2.digest}`,
    );
    ok("both runs report a well-formed 96-hex SHA-384", /^[0-9a-f]{96}$/.test(run1.digest) && /^[0-9a-f]{96}$/.test(run2.digest));

    // ---- 2. THE TEST IS NOT VACUOUS: reproduce the regression on demand ----
    resetStampToPlaceholder();
    console.log("broken run 1 (fixed mode, establishes a real stamp)...");
    const broken1 = await stampOnce({ resetFirst: true });
    console.log(`  digest ${broken1.digest.slice(0, 16)}`);
    console.log("broken run 2 (resetFirst: false, hashes broken1's leftover stamp)...");
    const broken2 = await stampOnce({ resetFirst: false });
    console.log(`  digest ${broken2.digest.slice(0, 16)}`);
    ok(
      "WITHOUT the reset, a second run diverges from the first (this is what a vacuous test would miss)",
      broken1.digest !== broken2.digest,
      `broken1=${broken1.digest} broken2=${broken2.digest}`,
    );
    // NOT pinned to exact digests: those depend on the source tree at a given commit, and this test has
    // to keep passing on every commit after it, including ones that legitimately move every digest here.
    // The inequality above is the durable assertion.

    // ---- 3. RECOVERY: the fix is not merely first-run-lucky; it recovers from a corrupted leftover state ----
    console.log("recovery run (fixed mode again, after broken2 left a stray stamp on disk)...");
    const recovered = await stampOnce({ resetFirst: true });
    console.log(`  digest ${recovered.digest.slice(0, 16)}`);
    ok(
      "a fixed-mode stamp after a corrupted leftover state lands back on the SAME digest as run1/run2",
      recovered.digest === run1.digest,
      `recovered=${recovered.digest} expected=${run1.digest}`,
    );

    // ---- 4. resetStampToPlaceholder writes EXACTLY the committed placeholder, not a lookalike ----
    resetStampToPlaceholder();
    const afterReset = readFileSync(STAMP_PATH, "utf8");
    ok("resetStampToPlaceholder's output is byte-identical to the file this checkout started with", afterReset === original);
  } finally {
    writeFileSync(STAMP_PATH, original);
  }

  console.log(failures === 0 ? "\nALL STAMP-IDEMPOTENCY VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
