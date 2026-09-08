// A lost demo fresh-first-run marker clear is COUNTED, not swallowed, and the count reaches the pack.
//
// WHY THIS EXISTS. installSecretsAndAudit clears the demo fresh-first-run marker after a landed key install.
// That call was a bare `catch {}` with no drop tracking, two lines below an audit append that DOES call
// noteDroppedWrite. So a lost clear was invisible.
//
// The loss is not cosmetic. The marker MASKS the key-presence booleans (status.ts), because a demo reset
// cannot delete the engine's Worker Secrets. An estate whose clear failed therefore reports KEYLESS while
// physically holding keys. Worse, installRekeyDecision reads that SAME masked view, so the
// already-provisioned guard is blind and every subsequent "first install" silently RE-KEYS the estate for
// real, which is the one thing that guard exists to prevent.
//
// A failed clear masks a landed install: POST /admin/keys/install can return 200 with the keys genuinely
// written, while GET /admin/status keeps reporting signer=false breakGlass=false ready=false because the
// stale marker was never cleared. A later POST /admin/setup/acknowledge clears the marker and the keys
// appear at once, proving the install had landed all along.
//
// The kind must reach the PACK as well as the DO. diag-records.ts:426 drops any kind outside the closed set,
// and support-sections-diag.ts projects the pack through PACK_DROPPED_WRITE_KINDS. A kind that is durable but
// absent from the pack would be counted where nobody reads it, which is the same defect wearing a hat.
//
// Run: node test/validate-demo-first-run-clear-checked.ts

import { readFileSync } from "node:fs";
import { DROPPED_WRITE_KINDS } from "../src/admin/diag-records.ts";
import { PACK_DROPPED_WRITE_KINDS } from "../src/admin/support-sections-diag.ts";

let failures = 0;
function ok(what: string, cond: boolean): void {
  if (cond) {
    console.log(`  ok   ${what}`);
  } else {
    console.log(`  FAIL ${what}`);
    failures += 1;
  }
}

const KIND = "demo-first-run-clear";
const src = readFileSync(new URL("../src/admin/router-keys.ts", import.meta.url), "utf8");

console.log("\nDEMO FIRST-RUN CLEAR IS CHECKED");

// 1. The vocabulary, both halves. Durable without pack visibility is not visibility.
ok("the kind is in the CLOSED dropped-write vocabulary, so the DO will not discard it", (DROPPED_WRITE_KINDS as readonly string[]).includes(KIND));
ok("and it reaches the PACK vocabulary, so a reader can actually see the loss", PACK_DROPPED_WRITE_KINDS.includes(KIND));

// 2. THE DEFECT ITSELF, asserted at the call site rather than through a type. Reverting the fix must fail
// this, which is what the mutation check proves; a type-level assertion would survive that revert.
const clearSite = /doURL\("\/demo\/first-run\/clear"\)/g;
const sites = src.match(clearSite) ?? [];
ok("the install path still clears the marker at all", sites.length >= 1);

// The bare form this replaced: a clear whose failure goes nowhere.
ok(
  "no clear is swallowed by a bare catch that records nothing",
  !/doURL\("\/demo\/first-run\/clear"\)[^\n]*\}\s*catch\s*\{\s*\/\*[^*]*\*\/\s*\}/.test(src),
);

// The install-path clear must count the loss on BOTH failure shapes: a non-2xx answer and a throw. A check
// that only caught the throw would miss the commoner one, which is exactly how the audit append two lines
// above it was wrong before it was fixed.
const installClear = src.slice(src.indexOf('doURL("/demo/first-run/clear")'));
const window = installClear.slice(0, 900);
ok("a NON-2XX answer to the clear is counted", /cleared\.ok/.test(window) && /noteDroppedWrite\("demo-first-run-clear"\)/.test(window));
ok("a THROWN failure of the clear is counted too", (window.match(/noteDroppedWrite\("demo-first-run-clear"\)/g) ?? []).length >= 2);
ok("and the count is flushed, so it reaches the durable aggregate rather than dying with the isolate", /flushDroppedWrites\(scheduler\)/.test(window));

// 3. It must stay FAIL-OPEN. A lost clear must never turn a landed install into a failure for the operator.
ok("the clear never throws out of the install path (still fail-open)", !/await scheduler\.fetch\(doURL\("\/demo\/first-run\/clear"\)[^\n]*\);\s*\n\s*if \(!cleared\.ok\) \{\s*\n\s*throw/.test(src));

console.log(failures === 0 ? "\nDEMO FIRST-RUN CLEAR PASS\n" : `\nDEMO FIRST-RUN CLEAR FAIL (${failures})\n`);
if (failures > 0) process.exitCode = 1;
process.exit(failures === 0 ? 0 : 1);
