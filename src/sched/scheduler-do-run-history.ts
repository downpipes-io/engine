// RunHistoryMixin holds the scheduler DO's read views of run history and replication state: the
// per-destination replication map (replication), the recent-run ring (history) and the point-in-time
// resolver over that ring (runAt). SchedulerCoreMixin (scheduler-do-scheduling.ts) writes both stores in
// completeRun and recordReplicationState; this mixin only reads them. Neither mixin calls the other.

import { resolveRunAt } from "../admin/point-in-time.ts";
import type { PointInTimeRun } from "../admin/restore-types.ts";
import { annotatePredecessorChain, type RunHistoryEntryWithChain } from "../admin/run-chain.ts";
import type { DestReplState, RunHistoryEntry, SchedulerDOCtor } from "./scheduler-do-base.ts";

export function RunHistoryMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // replication returns a downpipe's per-destination replication state (one id) or every downpipe's
    // (no id), keyed by downpipeId then destinationId. Read-only; carries no key material or plaintext.
    async replication(id: string | null): Promise<{ dests: Record<string, DestReplState> } | { byDownpipe: Record<string, Record<string, DestReplState>> }> {
      if (id) return { dests: (await this.state.storage.get<Record<string, DestReplState>>(`repl:${id}`)) ?? {} };
      const all = await this.state.storage.list<Record<string, DestReplState>>({ prefix: "repl:" });
      const byDownpipe: Record<string, Record<string, DestReplState>> = {};
      for (const [k, v] of all) byDownpipe[k.slice("repl:".length)] = v;
      return { byDownpipe };
    }

    // history returns a downpipe's recent-run ring newest-first; with no id it returns every
    // downpipe's ring keyed by id (each newest-first). It is read-only and carries no key
    // material or plaintext, only the run-activity rows.
    //
    // Each row also carries prevRunIdStatus (run-chain.ts), so an admin/auditor read of this
    // one surface can reconstruct the predecessor chain honestly -- "first run", "predecessor
    // retained in this ring", "predecessor pruned (aged out of the retained window)", or "unknown
    // (recorded before this field existed)" -- rather than a bare id or an absent field that reads
    // like a broken chain. annotatePredecessorChain is called PER DOWNPIPE (once per ring), never over
    // the merged fleet, so a predecessor is only ever resolved within its own downpipe's chain.
    //
    // RESIDUE: THE FLEET SHAPE ALSO CARRIES A RETAINED-VERSUS-RECORDED PAIR, and without it an
    // EMPTY byDownpipe map was byte-identical to a brand-new estate. Both settle ok:true with nothing in
    // them, so a console that has just lost every run row and a console that has never run one read the
    // same response and print the same sentence. No console change can separate them, because the fact
    // that separates them was never on the wire.
    //
    // THE SIBLING ALREADY SOLVED THIS FOR THE AUDIT LOG AND THIS IS ITS SHAPE. auditCountAndNearCap
    // returns auditCount beside auditRolledOverCount precisely because a count of what SURVIVES cannot
    // report what was DESTROYED, and verifyAudit keeps a stored rollover record AS WELL AS deriving one
    // from earliestSeq, because the derivation has nothing to read once the log empties. The run-history
    // chain already had the derived half: run-chain.ts annotates the oldest retained row "pruned" when
    // its predecessor aged out of RING_CAP, exactly like derivedRolledOver = firstSeq > 1. What it never
    // had is the half that still answers when the rings are empty, which is the only case in which the
    // conflation bites.
    //
    // IT IS DERIVED FROM runlogCounter RATHER THAN FROM A NEW STORED COUNTER, AND THAT CHOICE IS THE
    // LOAD-BEARING ONE. runlogCounter is account-global, monotonic, allocated at trigger() and left
    // untouched when a downpipe is deleted, so it is ALREADY POPULATED on every estate now running. A
    // freshly introduced cumulative counter would start at zero on the whole installed base and answer
    // "nothing has rolled over" for every estate that has already lost its history, which reproduces the
    // defect it was added to close and hides it behind a field that looks like a fix.
    //
    // runlogCounterReset is the SAME derivation the support pack's scheduler-signals uses (counter <
    // maxHistoryIndex, SCHED runlog-counter-reset), computed here from rings already in hand at no extra
    // storage read. It is on the response so a reader can never take rolledOverCount from a counter that
    // has been wound back: a reset counter under-reports the loss, and saying so is the honest answer.
    async history(id: string | null): Promise<{ entries: RunHistoryEntryWithChain[] } | { byDownpipe: Record<string, RunHistoryEntryWithChain[]>; runsRecordedTotal: number; runsRetainedCount: number; runsRolledOverCount: number; runlogCounterReset?: true }> {
      if (id) {
        const arr = (await this.state.storage.get<RunHistoryEntry[]>(`hist:${id}`)) ?? [];
        return { entries: annotatePredecessorChain([...arr].reverse()) };
      }
      // listAllByPrefix pages the whole prefix so a fleet larger than one DO_LIST_PAGE does not have its
      // run history silently truncated at the first page (the per-downpipe id read above is unaffected).
      const map = await this.listAllByPrefix<RunHistoryEntry[]>("hist:");
      const byDownpipe: Record<string, RunHistoryEntryWithChain[]> = {};
      let runsRetainedCount = 0;
      let maxHistoryIndex = 0;
      for (const [k, arr] of map) {
        const rows = Array.isArray(arr) ? arr : [];
        runsRetainedCount += rows.length;
        for (const row of rows) if (typeof row.index === "number" && Number.isFinite(row.index) && row.index > maxHistoryIndex) maxHistoryIndex = row.index;
        byDownpipe[k.slice("hist:".length)] = annotatePredecessorChain([...rows].reverse());
      }
      const counterRaw = await this.state.storage.get<number>("runlogCounter");
      const runsRecordedTotal = typeof counterRaw === "number" && Number.isFinite(counterRaw) && counterRaw > 0 ? Math.floor(counterRaw) : 0;
      // Clamped at zero for the same reason verifyAudit clamps firstSeq - 1: a counter that has been wound
      // back below what the rings still hold must not report a NEGATIVE loss, and runlogCounterReset beside
      // it says the figure is a floor rather than a measurement.
      const runsRolledOverCount = Math.max(0, runsRecordedTotal - runsRetainedCount);
      return {
        byDownpipe,
        runsRecordedTotal,
        runsRetainedCount,
        runsRolledOverCount,
        ...(runsRecordedTotal < maxHistoryIndex ? { runlogCounterReset: true as const } : {}),
      };
    }

    // runAt is the POINT-IN-TIME resolver: GET /runs/at?downpipe=&at=<rfc3339> -> the latest
    // SUCCESSFUL run of that downpipe completed AT-OR-BEFORE the given instant, from its bounded run-history
    // ring, via the pure resolveRunAt. A restore then proceeds with the resolved runId through the existing
    // path. It is bounded to what the ring retains (and resolveRunAt reports the retained window honestly on
    // a miss), so a console can offer a recovery timeline without implying a point older than the oldest
    // retained run is recoverable. A missing downpipe (or an unparseable `at`) is surfaced honestly, never a
    // throw: an empty ring resolves to found:false with the no-successful-run reason. Reads only the ring's
    // redaction-safe fields (run id + status + completion time + index); no secret.
    async runAt(downpipeId: string | null, atRaw: string | null): Promise<PointInTimeRun & { error?: string }> {
      if (!downpipeId) return { downpipeId: "", found: false, reason: "downpipe required", error: "downpipe required" };
      const atMs = atRaw !== null ? Date.parse(atRaw) : NaN;
      if (!Number.isFinite(atMs)) return { downpipeId, found: false, reason: "an at=<rfc3339> timestamp is required", error: "at required" };
      const ring = (await this.state.storage.get<RunHistoryEntry[]>(`hist:${downpipeId}`)) ?? [];
      const resolved = resolveRunAt(downpipeId, ring, atMs);
      // A SUCCESSFUL run whose startedAt will not parse is EXCLUDED from this resolution, so a run that
      // genuinely covers T is invisible and the customer is told no run exists -- a data-loss-grade wrong
      // answer produced by a timestamp bug. resolveRunAt already reports the exclusion ON THIS RESPONSE
      // (excludedCorruptRuns), which the console can show; the counter is the PACK's copy of the same fact,
      // and it is the one a support engineer reads, because a pack is built long after the console call that
      // gave the wrong answer. Counts only: never the row, never the timestamp that would not parse. It fires
      // ONLY when a row was actually dropped, so a clean ring records nothing.
      if ((resolved.excludedCorruptRuns ?? 0) > 0) await this.bumpAdminCounterLocal("pit-corrupt-run-excluded", resolved.excludedCorruptRuns ?? 0);
      return resolved;
    }
  };
}
