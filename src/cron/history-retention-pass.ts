// The run-history retention purge pass for the cron driver (cron/drive.ts). ASVS V14.1.2: this is the
// enforcement half of the run-history ring's documented retention policy
// (docs/security/data-classification.md section 2.14, sched/history-retention.ts). The ring is already
// bounded by COUNT (RING_CAP, scheduler-do-limits.ts), but nothing bounded it by AGE, so a low-traffic
// downpipe could keep a run's metadata for as long as the account exists. purgeRunHistoryEntries
// (sched/history-retention.ts) is the single pure policy; this pass is the thin cron-side caller of the
// DO's own enforcement route (POST /history-retention-pass, scheduler-do-routing.ts), so the storage
// read-modify-write stays inside the DO's single-writer boundary and this pass never touches storage
// itself.
//
// The engine Durable Object receives no env: the retention window travels in the POST body as the plain
// constant RUN_HISTORY_MAX_AGE_MS, never an env-derived fact, and the DO falls back to the same constant
// when the body omits it.
//
// Fail-open, like every other cron pass in this file family: a DO hiccup degrades to "no purge this
// tick", never a crashed cron.

import { doURL } from "../do-url.ts";
import { log } from "../log.ts";
import { RUN_HISTORY_MAX_AGE_MS } from "../sched/history-retention.ts";

/**
 * runHistoryRetentionPurge asks the scheduler DO to purge every downpipe's run-history ring of entries
 * older than the retention window, and logs a one-line summary when it actually removed anything.
 *
 * @param scheduler - the scheduler DO stub.
 */
export async function runHistoryRetentionPurge(scheduler: DurableObjectStub): Promise<void> {
  const r = await scheduler.fetch(doURL("/history-retention-pass"), {
    method: "POST",
    body: JSON.stringify({ maxAgeMs: RUN_HISTORY_MAX_AGE_MS }),
    headers: { "content-type": "application/json" },
  });
  if (!r.ok) throw new Error(`run-history retention purge: DO returned ${r.status}`);
  const { downpipesScanned, entriesPurged } = (await r.json()) as { downpipesScanned: number; entriesPurged: number };
  if (entriesPurged > 0) {
    log("info", `run-history retention purge: removed ${entriesPurged} expired entr${entriesPurged === 1 ? "y" : "ies"} across ${downpipesScanned} downpipe(s)`);
  }
}
