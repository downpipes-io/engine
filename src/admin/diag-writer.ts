// The CHECKED best-effort diagnostic writer.
//
// THE PROBLEM: every diagnostic / bookkeeping write the engine makes from the Worker edge is fire-and-forget
// -- `scheduler.fetch(...).catch(() => {})`, or an awaited fetch whose RESPONSE is never checked. A DO that
// is unavailable (or that answers a non-2xx) therefore drops the write SILENTLY. The pack then UNDER-COUNTS
// during the exact outage it exists to explain: a lockout window shows an empty authSignals aggregate, a
// post-deploy pack lacks its deploy keystone (indistinguishable from "no redeploy happened"), a live
// integration's pull trail stops advancing and reads as abandoned. Absence of evidence reads as absence of
// problems -- the worst possible failure mode for a remote-diagnosis product.
//
// THE FIX (writer-side, no in-flight persistence): recordDiagWrite CHECKS the response. On a failure it NOTES
// the closed kind in an ISOLATE-LOCAL pending tally, and that tally is FLUSHED (piggy-backed) on the next
// diagnostic write that succeeds. So the gap is durably recorded the moment the DO comes back -- which is
// exactly when the pack is generated. An isolate that dies while holding a pending tally loses it: that is
// the irreducible floor (there is nowhere durable to put it during a total DO outage), and it is strictly
// better than the prior ZERO durability.
//
// NO-CUSTODY: the only thing that ever crosses the wire is a {closed kind: int count} tally. The dropped
// payload itself (an audit row, a signal name, a licence reason, a token) is NEVER retained or re-sent --
// this records the LOSS, not the lost content.

import type { DroppedWriteKind } from "./diag-records.ts";
import { doURL } from "../do-url.ts";

// pendingDrops is the isolate-local tally of diagnostic writes that FAILED and have not yet been reported.
// Module scope (one per isolate) is deliberate: a Workers isolate serves many requests, so a drop noted on
// one request is carried by the next request's successful write. It is bounded by DROPPED_WRITE_KINDS (a
// handful of integer counters), so it can never grow.
const pendingDrops = new Map<DroppedWriteKind, number>();

/**
 * Notes a dropped diagnostic write in the isolate-local tally. Exported for the call sites that own their own
 * fetch shape (and for the validator); most callers should use recordDiagWrite, which notes AND flushes.
 *
 * @param kind - the closed kind of write that was lost.
 */
export function noteDroppedWrite(kind: DroppedWriteKind): void {
  pendingDrops.set(kind, (pendingDrops.get(kind) ?? 0) + 1);
}

/**
 * pendingDroppedWrites is the current isolate-local tally (a copy). Test-only observability; production code
 * never reads it (the DO aggregate is the durable record).
 *
 * @returns a snapshot of the pending {kind: count} tally.
 */
export function pendingDroppedWrites(): Record<string, number> {
  return Object.fromEntries(pendingDrops);
}

/**
 * resetPendingDroppedWrites clears the isolate-local tally. Test-only (a fresh isolate starts empty); it
 * exists so one validator case cannot leak a pending drop into the next.
 */
export function resetPendingDroppedWrites(): void {
  pendingDrops.clear();
}

/**
 * flushDroppedWrites reports the pending tally to the DO's bounded droppedWrites aggregate and clears it. On
 * a failed flush the tally is RESTORED (never lost), so the next successful write re-attempts it. It is a
 * NO-OP when nothing is pending, so the healthy steady state costs no subrequest at all. It never throws.
 *
 * @param scheduler - the scheduler DO stub.
 */
export async function flushDroppedWrites(scheduler: DurableObjectStub): Promise<void> {
  if (pendingDrops.size === 0) return;
  const drops = Object.fromEntries(pendingDrops);
  pendingDrops.clear();
  try {
    const resp = await scheduler.fetch(doURL("/diag/dropped-writes"), {
      method: "POST",
      body: JSON.stringify({ drops }),
      headers: { "content-type": "application/json" },
    });
    if (resp.ok) return;
  } catch {
    // fall through to the restore below: the DO is still unreachable
  }
  // The flush itself was dropped: put the tally back (folding in anything noted while it was in flight) so
  // the loss is reported by a later successful write rather than being silently lost by the reporter.
  for (const [kind, n] of Object.entries(drops)) {
    pendingDrops.set(kind as DroppedWriteKind, (pendingDrops.get(kind as DroppedWriteKind) ?? 0) + n);
  }
}

/**
 * recordDiagWrite runs ONE best-effort diagnostic / bookkeeping DO write and CHECKS it: a throw or a non-2xx
 * is counted in the droppedWrites aggregate instead of vanishing. It NEVER throws and NEVER alters the
 * caller's path (the caller has already decided its response); it is deliberately awaitable so a test can
 * flush it, while production callers may fire-and-forget with `void`.
 *
 * The pending tally is flushed on the SUCCESS path (so a gap from an earlier outage lands as soon as the DO
 * is healthy again) and re-attempted on the failure path (harmless: it re-pends).
 *
 * @param scheduler - the scheduler DO stub.
 * @param kind - the closed kind to count if this write is lost.
 * @param write - the write itself; its Response is checked for a 2xx.
 * @returns true when the write landed, false when it was dropped (and counted).
 */
export async function recordDiagWrite(scheduler: DurableObjectStub, kind: DroppedWriteKind, write: () => Promise<Response>): Promise<boolean> {
  try {
    const resp = await write();
    if (resp.ok) {
      await flushDroppedWrites(scheduler);
      return true;
    }
  } catch {
    // a transport throw is the same loss as a non-2xx: count it below
  }
  noteDroppedWrite(kind);
  await flushDroppedWrites(scheduler);
  return false;
}
