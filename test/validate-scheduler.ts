// Prove the SchedulerDO dispatch logic end to end with in-memory doubles only.
// No network, no deploy, no cost. Run:
//   node test/validate-scheduler.ts
//
// This file is a thin ORCHESTRATOR: each cohesive group of vectors lives in a sibling
// validate-scheduler-<area>.ts module that exports a run(), and the shared in-memory doubles, the
// ok() assertion sink and the config builders live in validate-scheduler-shared.ts. main() imports
// and calls each group in order, so this command executes the full suite with all assertions.
//
// What this covers:
//  - addDownpipe stores a DownpipeState and listDownpipes returns it;
//  - due() returns only enabled, not-in-flight downpipes whose nextRunAt is <= now;
//  - trigger() marks the downpipe in-flight and allocates a monotonically increasing
//    runlogIndex, appending an in-flight history row;
//  - completeRun() resolves the matching in-flight row (status ok/failed, coarse counts,
//    and the NEW archiveBytesWritten/segmentsWritten/durationMs throughput fields);
//  - coalescing: a downpipe already in-flight is skipped by trigger() (returns { skipped });
//  - RING_CAP=50 truncation: the ring keeps only the 50 newest entries (head shifted off);
//  - runlogIndex is monotonically increasing across multiple triggers;
//  - a failed run (empty runId) does not advance lastRunId and does not double-allocate an
//    index (gap-tolerance);
//  - completeRun with no matching index (empty runId completion no-op) returns ok:true;
//  - throughput fields round-trip through completeRun into the history entry;
//  - completeRun is idempotent: a duplicate or stale completion is a no-op and never
//    clobbers a row another run already resolved, nor clears the in-flight flag of a NEWER run;
//  - rearmAlarm never schedules an alarm in the past: a wedged enabled downpipe with a
//    past-due nextRunAt is floored to now + ALARM_MIN_DELAY_MS, not armed immediately;
//  - cron / timezone / blackout scheduling (validate-scheduler-cron.ts);
//  - the due-time index in O(due), its persistence and reconciliation (validate-scheduler-index.ts);
//  - reconcileReplicationAlerts transitions + cooldown (validate-scheduler-replication.ts);
//  - the validateConfig authority-boundary unit suite (validate-scheduler-validateconfig.ts);
//  - the constant-time bootstrap-invite compare + the in-DO authz 403 mapping (validate-scheduler-auth.ts).

import { getFailures } from "./validate-scheduler-shared.ts";
import { run as runLifecycle } from "./validate-scheduler-lifecycle.ts";
import { run as runRunlog } from "./validate-scheduler-runlog.ts";
import { run as runCron } from "./validate-scheduler-cron.ts";
import { run as runIndex } from "./validate-scheduler-index.ts";
import { run as runReplication } from "./validate-scheduler-replication.ts";
import { run as runValidateConfig } from "./validate-scheduler-validateconfig.ts";
import { run as runAuth } from "./validate-scheduler-auth.ts";

async function main(): Promise<void> {
  await runLifecycle();
  await runRunlog();
  await runCron();
  await runIndex();
  await runReplication();
  runValidateConfig();
  await runAuth();

  const failures = getFailures();
  console.log(failures === 0 ? "\nSCHEDULER-DO VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
