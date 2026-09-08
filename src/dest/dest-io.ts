// dest-io.ts -- the bounded, closed-shape record of destination DEGRADATION on runs that SUCCEEDED (G186).
//
// THE PROBLEM: fault-log.ts records why an op FAILED. It says nothing about the run that finished green but
// took ten times as long, or cost ten times as much. Those runs are the hardest tickets in the product and
// the pack cannot even see them:
//   - the store pushed back (503/429) and the pacer HALVED its rate, over and over, so a backup that used to
//     take 20 minutes now takes six hours (runs[].durationMs shows the slowness; nothing attributes it);
//   - the credential lost s3:HeadObject, so exists() -- which collapses EVERY non-200 to "absent" -- reports
//     every already-uploaded segment as missing, and the run re-uploads the entire archive, every night,
//     silently defeating content-addressed dedup;
//   - a conditional PUT lost its precondition (412) again and again because two engines are fighting over one
//     RUNLOG;
//   - the endpoint black-holed and the fetch bound aborted, and the multipart step retried it away;
//   - the store sent a Retry-After the engine could not parse, so it backed off on a guess instead.
// Every one of these is swallowed by design (they are all correctly RIDDEN OUT), and every one of them is the
// answer to a ticket.
//
// THE SHAPE: one small counter set per destination INSTANCE (read back through Destination.destIo(), the
// exact model of multipartAbortFailures() / destFaults(), so a run row can carry it), plus an ISOLATE-LOCAL
// tally that mirrors every bump and is FLUSHED to the DO's bounded admin-counter aggregate on the next
// buildDestination in this isolate (the diag-writer.ts pending-tally protocol, verbatim: a flush that fails
// re-pends, and the loss of the flush is itself counted as a dropped write). So the evidence is durable even
// though the dest layer has no end-of-run hook of its own, and an isolate that dies holding a tally loses it
// -- the same irreducible floor the rest of the diagnostic layer already accepts, and strictly better than
// the zero durability that exists today.
//
// NO-CUSTODY REDACTION (binding): every field is a CLAMPED NON-NEGATIVE INT (or, for the pacer, a clamped
// rate in requests/second). There is no key, no status string, no header value, no endpoint, no bucket and no
// error text anywhere in this module -- there is nowhere for one to go: the counters are ints and the wire
// tally's key space is a fixed, closed list of counter names.

import { noteDroppedWrite, recordDiagWrite } from "../admin/diag-writer.ts";
import type { DestIoSnapshot } from "./types.ts";

// Re-exported so the existing consumers (r2.ts, s3.ts, the run-fault records) keep importing it from
// here unchanged. Only the DECLARATION moved, to break the cycle; the import surface did not.
export type { DestIoSnapshot } from "./types.ts";

/**
 * DEST_IO_COUNTERS is the CLOSED vocabulary of destination degradations, mapping each counter to the closed
 * admin-counter name it is reported under (ADMIN_COUNTER_NAMES in admin/diag-records.ts, whose applier is the
 * redaction chokepoint that drops anything outside it).
 *
 *   throttleObservations           the store answered 503/429: real backpressure, and the pacer halved its
 *                                  rate in response. A rising count IS the "why is it suddenly slow" answer.
 *   retryAttemptsTotal             a multipart step was RE-ISSUED after a transient fault. Retries that
 *                                  succeed are invisible today; they are also the cost.
 *   timeouts                       an outbound request hit the finite fetch bound and was aborted: the
 *                                  endpoint black-holed rather than refused.
 *   conditionalPutConflicts        a conditional PUT lost its precondition (412 / R2's null): a concurrent
 *                                  writer won. On the RUNLOG that means two engines are fighting.
 *   headNon200CollapsedToAbsent    a HEAD answered something OTHER than 200 or 404 (a 403 lost permission, a
 *                                  5xx outage) and exists() collapsed it to "absent" -- so the segment is
 *                                  re-uploaded. THE dedup-defeating fault, and completely silent today.
 *   retryAfterUnparseable          the store sent a Retry-After the engine could not read, so it backed off
 *                                  on a guess rather than on the store's own instruction.
 */
export const DEST_IO_COUNTERS = {
  throttleObservations: "dest-io-throttled",
  retryAttemptsTotal: "dest-io-retry-attempt",
  timeouts: "dest-io-timeout",
  conditionalPutConflicts: "dest-io-conditional-put-conflict",
  headNon200CollapsedToAbsent: "dest-io-head-collapsed-absent",
  retryAfterUnparseable: "dest-io-retry-after-unparseable",
} as const;
/**
 * DestIoCounter is one key of DEST_IO_COUNTERS: the CLOSED set of degradation counters a destination may
 * bump, and therefore the whole key space of the isolate-local tally and of the wire snapshot. Bounding
 * the type this way is what keeps the tally from growing: it can hold no more entries than there are
 * members here, whatever a run does.
 */
export type DestIoCounter = keyof typeof DEST_IO_COUNTERS;

const DEST_IO_COUNTER_NAMES = Object.keys(DEST_IO_COUNTERS) as DestIoCounter[];


// COUNT_CAP bounds every counter so a pathological run (a store that 503s a million times) cannot produce an
// unbounded integer on a run row or in the wire tally. It is far above any real degradation.
const COUNT_CAP = 1_000_000;
// RATE_CAP bounds the recorded rate. The pacer's own floor is 1 req/s and its base is a small configured
// number, so this is a defensive ceiling only.
const RATE_CAP = 100_000;

// clampCount folds a bump into a bounded non-negative integer.
function clampCount(n: number): number {
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.min(COUNT_CAP, Math.trunc(n));
}

// pendingIo is the ISOLATE-LOCAL tally of degradation counts not yet reported to the DO. Module scope is
// deliberate and is the same construction diag-writer.ts's pendingDrops uses: the dest layer has no end-of-run
// hook, so a bump made during one slice is carried by the NEXT buildDestination in this isolate (the cron seal
// loop builds a destination per run, so an account with any live schedule flushes continuously). Bounded by
// DEST_IO_COUNTERS: six integer counters, so it can never grow.
const pendingIo = new Map<DestIoCounter, number>();

/**
 * pendingDestIo is the current isolate-local tally (a copy). Test-only observability; production code never
 * reads it (the DO aggregate is the durable record).
 *
 * @returns a snapshot of the pending {counter: count} tally.
 */
export function pendingDestIo(): Record<string, number> {
  return Object.fromEntries(pendingIo);
}

/**
 * resetPendingDestIo clears the isolate-local tally. Test-only (a fresh isolate starts empty); it exists so
 * one validator case cannot leak a pending count into the next.
 */
export function resetPendingDestIo(): void {
  pendingIo.clear();
}

/**
 * destIoBumps renders the pending tally as the {closed admin-counter name: count} body the DO's
 * POST /diag/admin-counters route folds into its bounded aggregate. The key space is exactly the values of
 * DEST_IO_COUNTERS, so nothing else can reach the wire.
 *
 * @returns the wire tally, empty when nothing is pending.
 */
export function destIoBumps(): Record<string, number> {
  const bumps: Record<string, number> = {};
  for (const [counter, n] of pendingIo) {
    if (n > 0) bumps[DEST_IO_COUNTERS[counter]] = clampCount(n);
  }
  return bumps;
}

/**
 * flushDestIo reports the isolate-local degradation tally to the DO's bounded admin-counter aggregate and
 * clears it. It is a NO-OP when nothing is pending, so a healthy destination costs no subrequest at all. On a
 * failed flush the tally is RESTORED (folding in anything bumped while it was in flight) and the loss is
 * itself counted as a dropped write, so the pack can never read "no degradation" when the truth is "the
 * recorder could not reach the DO". It NEVER throws: a diagnostic write must not break a backup.
 *
 * @param scheduler - the scheduler DO stub.
 */
export async function flushDestIo(scheduler: DurableObjectStub): Promise<void> {
  if (pendingIo.size === 0) return;
  const bumps = destIoBumps();
  const carried = new Map(pendingIo);
  pendingIo.clear();
  if (Object.keys(bumps).length === 0) return;
  const landed = await recordDiagWrite(scheduler, "admin-counter", () =>
    scheduler.fetch("https://scheduler.internal/diag/admin-counters", {
      method: "POST",
      body: JSON.stringify({ bumps }),
      headers: { "content-type": "application/json" },
    }),
  );
  if (landed) return;
  // The flush was dropped (recordDiagWrite has already counted the LOSS itself): put the tally back so a
  // later successful flush still lands the degradation evidence rather than the reporter losing it.
  for (const [counter, n] of carried) pendingIo.set(counter, clampCount((pendingIo.get(counter) ?? 0) + n));
}

/**
 * DestIo is one destination instance's degradation counter set. The S3 and R2 destinations each hold one and
 * note into it from the branches they otherwise swallow; the seal driver reads snapshot() back through
 * Destination.destIo() to stamp a run row. Every bump ALSO lands in the isolate-local tally, so the evidence
 * is durable even for a caller that never reads the snapshot.
 */
export class DestIo {
  private counts: Record<DestIoCounter, number> = {
    throttleObservations: 0,
    retryAttemptsTotal: 0,
    timeouts: 0,
    conditionalPutConflicts: 0,
    headNon200CollapsedToAbsent: 0,
    retryAfterUnparseable: 0,
  };
  private minRate: number | undefined;

  /**
   * note bumps one closed counter, on both the instance and the isolate-local tally.
   *
   * @param counter - the closed counter name.
   */
  note(counter: DestIoCounter): void {
    this.counts[counter] = clampCount(this.counts[counter] + 1);
    pendingIo.set(counter, clampCount((pendingIo.get(counter) ?? 0) + 1));
  }

  /**
   * noteStatus folds one OBSERVED response status into the degradation record: a 503/429 is the store's own
   * backpressure signal (the same statuses the pacer halves on), and nothing else is. It takes the status as
   * an INT and records only a count -- the status is never retained, and no other status leaves a trace.
   *
   * @param status - the observed HTTP status.
   */
  noteStatus(status: number): void {
    if (status === 503 || status === 429) this.note("throttleObservations");
  }

  /**
   * noteEffectiveRate records the pacer's CURRENT adaptive rate, keeping the WORST (lowest) one seen. It is a
   * clamped non-negative integer in requests/second: a rate, never a timing trace.
   *
   * @param rate - the pacer's current effective rate (req/s).
   */
  noteEffectiveRate(rate: number): void {
    if (!Number.isFinite(rate) || rate < 0) return;
    const r = Math.min(RATE_CAP, Math.floor(rate));
    if (this.minRate === undefined || r < this.minRate) this.minRate = r;
  }

  /**
   * snapshot is the bounded per-instance record: six clamped counters plus the pacer's worst effective rate.
   * Every field is an int; there is no string field in the shape at all.
   *
   * @returns the snapshot (a fresh copy; the caller cannot mutate the counters).
   */
  snapshot(): DestIoSnapshot {
    return { ...this.counts, ...(this.minRate !== undefined ? { minEffectiveRatePerSec: this.minRate } : {}) };
  }

  /**
   * degraded reports whether ANYTHING was noted on this instance, so a caller can stamp the run row only when
   * there is something to say (a clean run carries no destIo block at all).
   *
   * @returns true when any counter is non-zero.
   */
  degraded(): boolean {
    return DEST_IO_COUNTER_NAMES.some((k) => this.counts[k] > 0);
  }
}

/**
 * noteDestIoWriteLost records that a degradation flush could not even be ATTEMPTED (no scheduler binding is
 * reachable from this context). It counts the loss in the same dropped-write aggregate the rest of the
 * diagnostic layer uses, so the pack never reads a quiet destination when the recorder was mute.
 */
export function noteDestIoWriteLost(): void {
  noteDroppedWrite("admin-counter");
}
