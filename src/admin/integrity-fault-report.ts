// THE DRAIN for the integrity fault ledger.
//
// format/integrity-fault-ledger.ts is where the seal / verify / restore core records a fault at the exact site
// that knows it (a read-side 403 behind an "absent" verdict, the SPEC 8.3 stage that actually failed, the
// failing record's one-way digest and the declared-vs-recovered counts, the key role that was mis-provisioned,
// the segment and chunk a streaming open aborted on). That core is PURE -- no DO stub, no env -- so the ledger
// had nowhere to go. This module is the seam: at every point a crawl, a verify or a restore ENDS, it takes the
// drained snapshot and posts it to the scheduler DO's bounded per-downpipe aggregate, from which the pack
// projects the integrityFaults section.
//
// DISCIPLINE (the same as seal/run-fault-report.ts, which it sits beside):
//   - BEST-EFFORT, and CHECKED. It routes through recordDiagWrite, so a post that is dropped (a DO outage, a
//     non-2xx) is itself counted in droppedWrites["integrity-faults"] and lands the moment the DO comes back.
//     It never throws: observing a verification failure must never mask it.
//   - SILENT WHEN CLEAN. A verify that passed drains an empty snapshot and posts NOTHING: no subrequest, no
//     record, no pack row. Silence is the healthy steady state.
//   - THE DRAIN IS UNCONDITIONAL. A Workers isolate is WARM and serves many runs, so the ledger must be emptied
//     even when the snapshot is not worth posting -- a fault carried into the NEXT downpipe's run would be
//     mis-attributed, and a mis-attributed fault is worse than a missing one (it sends support to the wrong
//     archive).
//   - NO NEW REDACTION SURFACE. Everything in the snapshot is already a closed enum, a clamped int or a
//     shape-gated hex digest, and applyIntegrityFaults (admin/diag-records.ts) re-gates every field DO-side, so
//     this module adds no trust of its own.

import { drainIntegrityFaultLedger, isEmptyIntegritySnapshot, resetIntegrityFaultLedger } from "../format/integrity-fault-ledger.ts";
import { recordDiagWrite } from "./diag-writer.ts";
import { doURL } from "../do-url.ts";

/**
 * beginIntegrityFaults clears the isolate-local ledger before a crawl / verify / restore, so a warm isolate
 * cannot attribute a previous run's integrity fault to this one.
 */
export function beginIntegrityFaults(): void {
  resetIntegrityFaultLedger();
}

/**
 * reportIntegrityFaults DRAINS the integrity fault ledger at the end of a crawl, verify or restore and posts
 * whatever evidence it carries to the scheduler DO. It is the ONLY caller of drainIntegrityFaultLedger, and the
 * drain is unconditional (see the header). It never throws and posts nothing for a clean run.
 *
 * @param scheduler - the scheduler DO stub.
 * @param downpipeId - the customer's own downpipe id, for attribution.
 */
export async function reportIntegrityFaults(scheduler: DurableObjectStub, downpipeId: string): Promise<void> {
  try {
    // Drain FIRST and unconditionally, whatever happens below.
    const snapshot = drainIntegrityFaultLedger();
    if (typeof downpipeId !== "string" || downpipeId === "") return;
    if (isEmptyIntegritySnapshot(snapshot)) return; // a clean verify records nothing at all

    await recordDiagWrite(scheduler, "integrity-faults", () =>
      scheduler.fetch(doURL("/diag/integrity-faults"), {
        method: "POST",
        body: JSON.stringify({ id: downpipeId, snapshot }),
        headers: { "content-type": "application/json" },
      }),
    );
  } catch {
    // Best-effort by construction: a fault WHILE reporting a fault must never mask the run's own outcome.
  }
}
