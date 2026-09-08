// RUN-FAULT REPORTER -- the missing seam between the source/destination fault ledgers and the support pack.
//
// The Wave-D source ledger (sources/source-fault-ledger.ts) and destination fault log (dest/fault-log.ts,
// dest/dest-io.ts) recorded their evidence at the exact fault site and then had NOWHERE TO PUT IT:
// drainSourceFaultLedger() had no caller in src/ at all, and destFaults()/destIo() were read by nothing on
// the run path. The evidence lived and died inside one Worker isolate. This module is the drain: it runs at
// every point a crawl ENDS -- the inline Worker slice, each RunSealDO slice, and the buffered whole-run path
// -- takes the drained snapshot, and posts it to the scheduler DO's bounded per-downpipe aggregates, from
// which the pack projects the sourceFaults / destFaults sections.
//
// DISCIPLINE (unchanged from the writers it serves):
//   - BEST-EFFORT, and CHECKED. It routes through recordDiagWrite, so a post that is dropped (a DO outage,
//     a non-2xx) is itself counted in droppedWrites["run-faults"] and lands the moment the DO comes back --
//     the pack's own under-count caveat. Observing a fault must never break the run that hit it, and this
//     never throws.
//   - SILENT WHEN CLEAN. A crawl with no faults and a destination with no faults post NOTHING: no subrequest,
//     no record, no pack section. The healthy fleet's steady state is silence.
//   - NO NEW REDACTION SURFACE. Everything posted is already coarse: the ledgers only ever hold closed enums,
//     clamped counts and engine-chosen product tokens / one-way handles. The DO re-gates every field again
//     through admin/run-fault-records.ts (the chokepoint), so this module adds no trust.

import { recordDiagWrite } from "../admin/diag-writer.ts";
import { beginIntegrityFaults, reportIntegrityFaults } from "../admin/integrity-fault-report.ts";
import { doURL } from "../do-url.ts";
import type { Destination } from "../dest/types.ts";
import { drainSourceFaultLedger, isEmptyFaultLedger, resetSourceFaultLedger } from "../sources/source-fault-ledger.ts";
import { beginRunObservations, drainRunObservations, isEmptyRunObservations, type RunObservations } from "./run-observations.ts";
import { postSealFault } from "./seal-fault-post.ts";

// beginRunFaults clears the isolate-local source ledger before a crawl. A Workers isolate is WARM and serves
// many runs, so without this a previous downpipe's faults would be attributed to this one -- a mis-attributed
// fault is worse than a missing one (it sends support to the wrong source).
//
// It also clears the FORMAT + CRYPTO integrity ledger (format/integrity-fault-ledger.ts), drained on the same
// run boundary and for the same reason: the seal's verify-at-seal pass records into it, and a stage or locator
// carried into the next downpipe's run would name the wrong archive.
export function beginRunFaults(): void {
  resetSourceFaultLedger();
  beginIntegrityFaults();
  // The seal-path observation ledger (G065 / G066 / G189 / G222) is cleared on the same run boundary and for the
  // same reason: a warm isolate must never attribute one downpipe's skips, strandings, seal mode or lock-plane
  // faults to the NEXT downpipe's run.
  beginRunObservations();
}

// destSnapshots reads the destination's optional diagnostic accessors. Both are optional on the Destination
// contract (only the S3/R2 drivers implement them), and a driver that does not is honestly absent, never
// fabricated as zero.
function destSnapshots(dest: Destination | undefined): { faults?: unknown; io?: unknown } {
  if (dest === undefined) return {};
  const faults = typeof dest.destFaults === "function" ? dest.destFaults() : undefined;
  const io = typeof dest.destIo === "function" ? dest.destIo() : undefined;
  // A snapshot is evidence when a real op FAILED (total > 0) OR when the store behaved non-conformantly with
  // no failing op at all (G085/G119/G206/G207: a listing truncated without a cursor, a missing ETag on a
  // conditional PUT, an engine guard refusal). The anomaly half is the whole point of those gaps -- the run
  // reports ok -- so gating the post on total alone would drop exactly the evidence they exist to carry.
  const anomalous = faults !== undefined && faults.anomalies !== undefined && Object.keys(faults.anomalies).length > 0;
  return {
    ...(faults !== undefined && (faults.total > 0 || anomalous) ? { faults } : {}),
    ...(io !== undefined ? { io } : {}),
  };
}

// ioIsQuiet reports whether a destination's degradation snapshot carries nothing worth recording. Every field
// is a counter, so "all zero" is the clean state; minEffectiveRatePerSec alone (never driven down) is not
// evidence either.
function ioIsQuiet(io: unknown): boolean {
  if (typeof io !== "object" || io === null) return true;
  const r = io as Record<string, unknown>;
  for (const k of ["throttleObservations", "retryAttemptsTotal", "timeouts", "conditionalPutConflicts", "headNon200CollapsedToAbsent", "retryAfterUnparseable"]) {
    const v = r[k];
    if (typeof v === "number" && v > 0) return false;
  }
  return true;
}

/**
 * reportRunFaults DRAINS the source fault ledger and reads the destination's fault/degradation snapshots at
 * the end of a crawl, and posts whatever evidence they carry to the scheduler DO. It is the ONLY caller of
 * drainSourceFaultLedger, and the drain is unconditional (the ledger must be emptied even when the snapshot
 * is not worth posting, or a warm isolate would carry this run's faults into the next one).
 *
 * It never throws and never posts anything for a clean run.
 *
 * @param scheduler - the scheduler DO stub.
 * @param downpipeId - the customer's own downpipe id, for attribution.
 * @param dest - the destination this crawl wrote to, when one was built (absent on a pre-destination fault).
 */
export async function reportRunFaults(scheduler: DurableObjectStub, downpipeId: string, dest?: Destination): Promise<void> {
  // The FORMAT + CRYPTO evidence of the same crawl (the verify-at-seal pass, the writer's zero-byte default,
  // a key-provisioning fault, a streaming abort). It drains and posts on the SAME run boundary, and is
  // deliberately its own post: a source fault and an integrity fault are different aggregates with different
  // vocabularies, and one being unreportable must not suppress the other.
  await reportIntegrityFaults(scheduler, downpipeId);
  try {
    // Drain FIRST and unconditionally: the isolate-local ledgers must be empty for the next run whatever else
    // happens below (an early return, a refused post).
    const source = drainSourceFaultLedger();
    const obs = drainRunObservations();
    if (typeof downpipeId !== "string" || downpipeId === "") return;
    // G065 / G066 / G189 / G222: the seal-path evidence detected deep in the PURE core (a record skipped as
    // changed-mid-crawl and WHY, destination bytes the engine stranded, the run's requested-vs-effective seal
    // mode, the RUNLOG lock plane's own faults). Those modules take a Destination and a budget, not a DO stub, so
    // they NOTE into the ledger and this -- the one place a crawl already ends -- posts it to the seal-fault ring.
    await postRunObservations(scheduler, downpipeId, obs);
    const sourceEvidence = !isEmptyFaultLedger(source);
    const { faults, io } = destSnapshots(dest);
    const destEvidence = faults !== undefined || !ioIsQuiet(io);
    if (!sourceEvidence && !destEvidence) return; // a clean run records nothing at all

    await recordDiagWrite(scheduler, "run-faults", () =>
      scheduler.fetch(doURL("/diag/run-faults"), {
        method: "POST",
        body: JSON.stringify({
          id: downpipeId,
          ...(sourceEvidence ? { source } : {}),
          ...(destEvidence ? { dest: { ...(faults !== undefined ? { faults } : {}), ...(io !== undefined ? { io } : {}) } } : {}),
        }),
        headers: { "content-type": "application/json" },
      }),
    );
  } catch {
    // Best-effort by construction: a fault WHILE reporting a fault must never mask the run's own outcome.
  }
}

// postRunObservations projects the drained ledger onto the seal-fault ring: one record per KIND that carries
// evidence, so the ring's per-kind vocabulary stays clean. Best-effort and fail-open (postSealFault never
// throws): observing a fault must never break the run that hit it. Every field is a closed enum, a count or a
// one-way `h:<12 hex>` handle -- there is NO field on these records that could hold a message, an object name, a
// bucket or a customer value.
async function postRunObservations(scheduler: DurableObjectStub, downpipeId: string, obs: RunObservations): Promise<void> {
  if (isEmptyRunObservations(obs)) return; // a clean crawl records nothing at all
  const at = Date.now();
  // G065: one record per closed skip CAUSE -- the distinction between genuine content churn and a persistent
  // 403 / timeout / short read on the resume range-read, which are the same aggregate counter today.
  for (const [cause, count] of Object.entries(obs.skipsByCause)) {
    await postSealFault(scheduler, {
      kind: "record-skipped-changed",
      at,
      downpipeId,
      skipCause: cause,
      skipped: count,
      ...(obs.skipHandles.length > 0 ? { handles: obs.skipHandles } : {}),
      ...(obs.partialsAbandoned > 0 ? { partialsAbandoned: obs.partialsAbandoned } : {}),
    });
  }
  // G066: one record per stranding CLASS, with an integer COUNT (never a boolean).
  for (const [cls, count] of Object.entries(obs.strandsByClass)) {
    await postSealFault(scheduler, { kind: "dest-stranding", at, downpipeId, strandClass: cls, stranded: count });
  }
  // G189: the run's requested-vs-effective seal mode (the silent fan-out-to-serial downgrade).
  if (obs.sealMode !== undefined) {
    await postSealFault(scheduler, {
      kind: "seal-mode",
      at,
      downpipeId,
      requestedMode: obs.sealMode.requested,
      effectiveMode: obs.sealMode.effective,
      ...(obs.sealMode.ranges !== undefined ? { fanoutRanges: obs.sealMode.ranges } : {}),
      ...(obs.sealMode.downgradeReason !== undefined ? { downgradeReason: obs.sealMode.downgradeReason } : {}),
      ...(obs.sealMode.underCrawlChecked !== undefined ? { underCrawlChecked: obs.sealMode.underCrawlChecked } : {}),
      ...(obs.sealMode.budgetOverrideForced !== undefined ? { budgetOverrideForced: obs.sealMode.budgetOverrideForced } : {}),
    });
  }
  // G108: the REFUSE-TO-SIGN completeness guards. These runs produced NO ARCHIVE, and the two counts that size
  // the shortfall (found vs expected) existed only inside a raw thrown message that coarsened to a generic
  // failed run row. One record per guard that fired, each with its closed kind and its two integers.
  for (const c of obs.completeness) {
    await postSealFault(scheduler, { kind: c.kind, at, downpipeId, found: c.found, expected: c.expected, ...(c.ordinal !== undefined ? { ordinal: c.ordinal } : {}) });
  }
  // G283: the destination's RUNLOG was ABSENT while this downpipe has prior runs on it, so the signed root
  // chained onto NOTHING (prevRunId=null) and the history silently restarted -- what a downpipe repointed at a
  // re-created or wrong bucket looks like, and indistinguishable from a first run until now.
  if (obs.runlogAbsent !== undefined) {
    await postSealFault(scheduler, { kind: "runlog-absent", at, downpipeId, priorRuns: obs.runlogAbsent.priorRuns, historyChainRestarted: true });
  }
  // G222: the RUNLOG lock / CAS plane counters. A non-zero count here means the SCHEDULER plane flaked, not the
  // destination -- the misattribution that sends support to investigate a perfectly healthy bucket while the run
  // parks "runlog contended" or dies with a destination-access class.
  const l = obs.lock;
  if (l.acquireFaults > 0 || l.windowExhausted > 0 || l.casExhausted > 0 || l.sigPublishSkipped > 0 || l.releaseFaults > 0) {
    await postSealFault(scheduler, {
      kind: "lock-plane",
      at,
      downpipeId,
      lockAcquireFaults: l.acquireFaults,
      lockWindowExhausted: l.windowExhausted,
      casExhausted: l.casExhausted,
      sigPublishSkipped: l.sigPublishSkipped,
      releaseFaults: l.releaseFaults,
    });
  }
}
