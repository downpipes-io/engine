// The CHECKED writer for the estate-sizing probe's outcome classes.
//
// The sink and its DO route already existed; nothing ever posted to them, so the aggregate the support pack
// projects was permanently empty -- a ledger recording into a void, which is indistinguishable from no ledger
// at all. This is the missing write.
//
// It rides recordDiagWrite like every other diagnostic writer, so a write the DO drops is itself counted in
// droppedWrites and the pack's under-count caveat stays honest: observing a fault must never break the path it
// observed, but a lost observation must never be silent either.
//
// NO-CUSTODY: the body carries a CLOSED source type and a CLOSED outcome class, nothing else. The Cloudflare
// GraphQL error body -- which quotes the account tag, the namespace id and the bucket name -- is discarded at
// the classifier and never reaches this module.

import { recordDiagWrite } from "./diag-writer.ts";
import { doURL } from "../do-url.ts";

/**
 * recordCostSizing posts one sizing probe's drained outcomes to the scheduler DO, one row per source it
 * attempted. The DO's applyCostSizing is the redaction chokepoint: an out-of-vocabulary source type or class
 * is DROPPED there (so no caller-derived string can become a storage key), and every count is clamped.
 *
 * @param scheduler - the scheduler DO stub.
 * @param rows - the drained {sourceType, cls} rows (empty when the probe sized nothing).
 */
export async function recordCostSizing(scheduler: DurableObjectStub, rows: ReadonlyArray<{ sourceType: string; cls: string }>): Promise<void> {
  if (rows.length === 0) return;
  await recordDiagWrite(scheduler, "cost-sizing", async () => {
    // One POST per row: the DO folds each into the per-source-type record. The row count is bounded by the
    // probe's own 64-row cap, and only a source the operator actually configured produces one.
    for (const r of rows) {
      await scheduler.fetch(doURL("/diag/cost-sizing"), {
        method: "POST",
        body: JSON.stringify({ sourceType: r.sourceType, class: r.cls }),
        headers: { "content-type": "application/json" },
      });
    }
    return new Response(null, { status: 204 });
  });
}
