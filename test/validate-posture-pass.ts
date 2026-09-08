// Prove the SCHEDULED security-centre evaluation pass (src/cron/posture-pass.ts): the due gate (a cheap
// snapshot-age read; a full computation only when the interval lapsed), the compute-through-the-single-path
// behaviour (the DO snapshots on the scheduled evaluation exactly as it does on a read), the
// caller-less computation (no per-email recovery finding, account-level checks unchanged), and the
// fail-open discipline (a faulting scheduler degrades to "no evaluation this tick", never a throw).
// In-memory doubles only; no network, no deploy, no cost. Run:
//   node test/validate-posture-pass.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { Env } from "../src/env.d.ts";
import { runPostureEvaluationPass, POSTURE_EVALUATION_INTERVAL_MS } from "../src/cron/posture-pass.ts";
import { ok, failureCount, MockStorage } from "./validate-posture-shared.ts";
import { POSTURE_SNAPSHOT_KEY, type PostureSnapshot } from "../src/admin/posture.ts";

function makeHarness(): { storage: MockStorage; scheduler: DurableObjectStub; env: Env } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  // A minimal env: no destination, no beacon, no signer. gatherWormSlice degrades to not-configured and
  // the regression routing is fail-open, so the pass exercises the real compute path end to end.
  const env = {} as unknown as Env;
  return { storage, scheduler: stub, env };
}

async function main(): Promise<void> {
  ok("interval: the scheduled evaluation cadence is 6 hours", POSTURE_EVALUATION_INTERVAL_MS === 6 * 60 * 60 * 1000);

  // First tick on a fresh account: no snapshot exists, so the evaluation is DUE and computes, persisting
  // the snapshot (the proof the full computation ran through the single shared path).
  const h1 = makeHarness();
  ok("pass: fresh account has no snapshot", !h1.storage.has(POSTURE_SNAPSHOT_KEY));
  const ran1 = await runPostureEvaluationPass(h1.env, h1.scheduler);
  ok("pass: first tick completes", ran1 === true);
  ok("pass: first tick computed and persisted the snapshot", h1.storage.has(POSTURE_SNAPSHOT_KEY));
  const snap1 = h1.storage.rawGet<PostureSnapshot>(POSTURE_SNAPSHOT_KEY);
  ok("pass: the scheduled snapshot grades the account-level checks", (snap1?.checks.length ?? 0) > 10);
  // The caller-less evaluation never grades the per-identity recovery-codes finding.
  ok("pass: the caller-less evaluation has no recovery-codes-low entry", snap1?.checks.every((c) => c.id !== "recovery-codes-low") === true);

  // Second tick immediately after: NOT due (the snapshot is fresh), so the pass fast-paths without
  // recomputing (proved by the snapshot timestamp staying identical).
  const before = h1.storage.rawGet<PostureSnapshot>(POSTURE_SNAPSHOT_KEY)?.at;
  const ran2 = await runPostureEvaluationPass(h1.env, h1.scheduler);
  ok("pass: an immediate second tick completes (fast path)", ran2 === true);
  ok("pass: the not-due tick did not recompute (snapshot timestamp unchanged)", h1.storage.rawGet<PostureSnapshot>(POSTURE_SNAPSHOT_KEY)?.at === before);

  // A stale snapshot (older than the interval) makes the evaluation due again.
  const h2 = makeHarness();
  await runPostureEvaluationPass(h2.env, h2.scheduler);
  const snap = h2.storage.rawGet<PostureSnapshot>(POSTURE_SNAPSHOT_KEY);
  if (snap) {
    await h2.storage.put(POSTURE_SNAPSHOT_KEY, { ...snap, at: new Date(Date.now() - POSTURE_EVALUATION_INTERVAL_MS - 60_000).toISOString() });
  }
  const staleBefore = h2.storage.rawGet<PostureSnapshot>(POSTURE_SNAPSHOT_KEY)?.at;
  await runPostureEvaluationPass(h2.env, h2.scheduler);
  ok("pass: a stale snapshot makes the evaluation due (recomputed, timestamp advanced)", h2.storage.rawGet<PostureSnapshot>(POSTURE_SNAPSHOT_KEY)?.at !== staleBefore);

  // Fail-open: a scheduler whose fetch throws degrades to "no evaluation this tick" (returns false),
  // never a thrown cron.
  const broken = {
    fetch: () => Promise.reject(new Error("do unavailable")),
  } as unknown as DurableObjectStub;
  const ran3 = await runPostureEvaluationPass({} as unknown as Env, broken);
  ok("pass: a faulting scheduler degrades fail-open (false, no throw)", ran3 === false);

  const failures = failureCount();
  console.log(failures === 0 ? "\nPOSTURE PASS VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
