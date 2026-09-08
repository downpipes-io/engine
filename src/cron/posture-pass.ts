// runPostureEvaluationPass -- the SCHEDULED security-centre evaluation (the "who watches when nobody is
// looking" pass). The posture report is computed live on every console view and every report, and each
// computation snapshots the outcome set and detects regressions. But an UNWATCHED account never computes,
// so a previously-passing check could regress silently until the next human read. This pass closes that
// gap: at most once per POSTURE_EVALUATION_INTERVAL_MS it recomputes the posture through the SAME single
// path a read uses (computePostureViaDO, which also routes any detected regression as a posture-regression
// notification), so regression alerts fire within the interval even on an account nobody has opened.
//
// Cost discipline: the due check is one cheap DO read (the snapshot's own timestamp); the full computation
// (which includes the live WORM capability probe of the default destination) only runs when the interval
// has lapsed, and every ORDINARY read also refreshes the snapshot, so an actively-viewed account never
// pays an extra scheduled computation. Fully fail-open: any fault degrades to "no evaluation this tick",
// never a crashed cron. The pass computes with a NULL caller (no per-email recovery-code finding), which
// is safe because every check is account-level; the caller-scoped recovery-codes-low check is simply not
// graded on the scheduled evaluation (it is per-identity by design).

import { doURL } from "../do-url.ts";
import { computePostureViaDO } from "../admin/router-posture.ts";
import type { Env } from "../env.d.ts";
import { log } from "../log.ts";
import { noteCronPass } from "./cron-fault-ledger.ts";

// POSTURE_EVALUATION_INTERVAL_MS is the scheduled-evaluation cadence: 6 hours. Chosen so a regression on
// an unwatched account pages within a quarter of a day, at a cost of at most 4 posture computations (each
// one destination Object-Lock probe + DO reads) per day.
export const POSTURE_EVALUATION_INTERVAL_MS = 6 * 60 * 60 * 1000;

// runPostureEvaluationPass asks the DO whether the scheduled evaluation is due and, if so, computes the
// posture through the single shared path (which snapshots, detects and routes regressions). Returns true
// when the pass completed (including the not-due fast path), false when it bailed on a fault.
export async function runPostureEvaluationPass(env: Env, scheduler: DurableObjectStub): Promise<boolean> {
  try {
    const resp = await scheduler.fetch(doURL("/posture/evaluation-due"), {
      method: "POST",
      body: JSON.stringify({ intervalMs: POSTURE_EVALUATION_INTERVAL_MS }),
      headers: { "content-type": "application/json" },
    });
    const { due } = (await resp.json()) as { due?: boolean };
    if (due !== true) return true;
    await computePostureViaDO(env, scheduler, null);
    return true;
  } catch (e) {
    // G132: classify the throw at the site that holds it (a DO fetch, a parse, a budget bail).
    noteCronPass("posture", false, e);
    log("error", `posture evaluation pass skipped this tick: ${(e as Error).message}`);
    return false;
  }
}
