// Prove the SRE-alerting module (engine/src/notify.ts) and the reconcileAlerts/markAlertsDelivered
// two-phase flow in the scheduler DO against in-memory doubles only.
// No network, no deploy, no cost. Run:
//   node test/validate-notify.ts
//
// This file is a THIN ORCHESTRATOR (split to keep each module under
// the size cap). The actual vectors live in the sibling validate-notify-*.ts modules; this file
// imports each group's run function and calls them in the SAME order the suite has always run, so
// `node test/validate-notify.ts` still executes the full suite with identical assertions and order.
// The shared failure counter lives in ./validate-notify-shared.ts (getFailures) so the verdict here
// reflects every assertion across all groups.
//
// Coverage (unchanged):
//  isAllowedWebhookUrl: https-only, workers.dev reject, length cap, userinfo reject.
//  classify / shouldAlert: enabled=false, in-flight-only (no alert), failed precedence,
//    stale-from-last-success, unparseable-time guard, transition + cooldown gate, and the
//    new failed-transition-retry path.
//  buildAlert: field surface assertion (id/name/state/lastRunAt/lastRunId ONLY; no key
//    material/values/secrets -- the no-custody surface).
//  Two-phase first-alert retry: reconcileAlerts returns pendingTransitionIds; markAlertsDelivered
//    clears cooldowns for failed transitions so the next tick re-alerts.

import { getFailures } from "./validate-notify-shared.ts";
import { runDetection } from "./validate-notify-detection.ts";
import { runTwoPhase } from "./validate-notify-twophase.ts";
import { runRouting } from "./validate-notify-routing.ts";
import { runCrud } from "./validate-notify-crud.ts";
import { runDigest } from "./validate-notify-digest.ts";

// ---- Main ----------------------------------------------------------------------------------

async function main(): Promise<void> {
  await runDetection();
  await runTwoPhase();
  await runRouting();
  await runCrud();
  await runDigest();

  const failures = getFailures();
  console.log(failures === 0 ? "\nNOTIFY VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
