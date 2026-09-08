// Prove the security centre / posture (contract section 7): the PURE computePosture over the starter
// check set, the score weighting, the risk-accept fold, the regression detection, and the DO storage +
// routes (compute, risk-accept/unaccept with the posture.riskaccept re-check, snapshot-based regression).
// In-memory doubles only; no network, no deploy, no cost. Run:
//   node test/validate-posture.ts
//
// This file is a thin orchestrator: the suite is split across
// validate-posture-compute.ts (the pure computePosture groups) and validate-posture-routes.ts (the DO
// routes), over the shared fixtures in validate-posture-shared.ts. Each group is called here in the same
// order it ran before, through the single shared ok() / failures counter, so the full suite still runs and
// the final summary stays authoritative.
//
// Coverage:
//  computePosture: each starter check fails when its condition holds and passes otherwise; the fixed
//    severities; the weighted pass fraction (critical 5 / high 3 / medium 2 / low 1); the always-pass
//    info checks (audit-export-available, encryption-pq-hybrid); operational-private surfaced as a finding
//    when present; sort is most-severe-first with fail-before-pass.
//  risk-accept fold: a failing check whose id is accepted reads risk-accepted and counts toward the score.
//  snapshotOf / detectRegressions: a previously-passing check that now fails is a regression; a new check
//    or a recovered check is not; a risk-accepted check is not a regression.
//  DO routes: POST /posture computes from the router slice + DO state, snapshots, and returns regressions;
//    accept/unaccept re-check posture.riskaccept (a non-owner is refused); an unknown checkId is rejected;
//    a second compute after a check flips to failing returns the regression.

import { failureCount } from "./validate-posture-shared.ts";
import { runCompute } from "./validate-posture-compute.ts";
import { runRoutes } from "./validate-posture-routes.ts";

async function main(): Promise<void> {
  runCompute();
  await runRoutes();

  const failures = failureCount();
  console.log(failures === 0 ? "\nPOSTURE VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
