// The roster-hygiene REPORT + REPAIR pair (support-pack roster integrity), layered as a leaf method group
// like every sibling scheduler-DO mixin. rosterHygiene is the read side (the structural census of the dp:
// roster the support pack projects) and reconcileRoster is the write side (the heal-to-invariant repair of
// the ghost classes that census names); the pure deterministic analysis and plan both live in
// roster-hygiene.ts, so this mixin owns only the storage walk, the batch ring reads and the repair
// application. `this` is SchedulerDOSurface (like every sibling
// mixin), so they call this.listAllByPrefix / this.persistDownpipeState / this.rebuildDueIndex exactly as
// before, and the routing dispatch (scheduler-do-routing.ts) reaches them through the composed class.

import { hexEncode } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import { analyseRoster, embeddedConfigId, planRosterRepair, type RosterHygieneReport } from "./roster-hygiene.ts";
import { recordCapTruncation, recordRosterClaimantDiscard, recordStorageAnomaly } from "./sched-fault-ledger.ts";
import { ALERT_COOLDOWN_PREFIX, type DownpipeState, REPL_ALERT_COOLDOWN_PREFIX, type RunHistoryEntry, type SchedulerDOCtor } from "./scheduler-do-base.ts";

// RosterMixin layers the roster report/repair pair over the shared DO surface (see the file header above
// for what lives here and why).
export function RosterMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // rosterHygiene reports the structural integrity of the dp: roster (ghost rows the delete route
    // cannot reach, and well-formed rows that have never run, which is what a standing "Unknown" map
    // edge is when the roster is sound). Ids and keys only, redaction-safe; the support pack projects
    // it so a customer bundle self-diagnoses the "permanent grey line on my map" question.
    async rosterHygiene(): Promise<RosterHygieneReport> {
      const entries = await this.listAllByPrefix<unknown>("dp:");
      // Batch-read the run rings for the WELL-FORMED ids only (ghosts are structural regardless of
      // history). storage.get(string[]) returns a Map in one round trip, capped at 128 keys per call.
      const ids: string[] = [];
      for (const [key, value] of entries) {
        const embedded = embeddedConfigId(value);
        if (embedded !== null && key === `dp:${embedded}`) ids.push(embedded);
      }
      const idsWithRuns = new Set<string>();
      const DO_GET_BATCH = 128;
      for (let i = 0; i < ids.length; i += DO_GET_BATCH) {
        const chunk = ids.slice(i, i + DO_GET_BATCH).map((id) => `hist:${id}`);
        const got = await this.state.storage.get<RunHistoryEntry[]>(chunk);
        for (const [k, ring] of got) {
          if (Array.isArray(ring) && ring.length > 0) idsWithRuns.add(k.slice("hist:".length));
        }
      }
      const report = analyseRoster(entries, idsWithRuns);
      // G325: the ghost/never-ran lists are capped at ROSTER_LIST_CAP. The report now SAYS so (ghostsTruncated /
      // neverRanTruncated), and the dropped rows are also folded into the shared capTruncations ledger so the
      // pack carries one place to read "a record you are looking at was clamped". Counts only; the dropped rows'
      // ids stay out. Best-effort: the report returned is unchanged whether or not the ledger write lands.
      await recordCapTruncation(this.state.storage, "roster-ghosts", report.ghostsDropped);
      await recordCapTruncation(this.state.storage, "roster-never-ran", report.neverRanDropped);
      return report;
    }

    // reconcileRoster repairs the ghost classes rosterHygiene reports, per the pure deterministic plan
    // (roster-hygiene.ts planRosterRepair): malformed rows and twinned mismatches are removed with their
    // residue; a twinless mismatch is REHOMED under its embedded id (state preserved, invariant
    // restored) with its ring/repl moved when the correct slots are free. Never-ran rows are valid
    // configs and are never touched (abstain). Like POST /sources/reattach-missing, this is a
    // heal-to-invariant repair, not a config change: it creates, edits or removes no operator-approved
    // configuration, so it does not route through the change-control gate; the router records the audit
    // row. Finishes with a due-index rebuild so any index residue a ghost ever seeded is dropped.
    async reconcileRoster(): Promise<{ removed: number; rehomed: number; ghostsRemaining: number }> {
      const entries = await this.listAllByPrefix<unknown>("dp:");
      const plan = planRosterRepair(entries);
      let removed = 0;
      let rehomed = 0;
      for (const action of plan) {
        if (action.act === "rehome") {
          // The value is a structurally sound DownpipeState whose key was wrong (planRosterRepair only
          // rehomes a row with a readable embedded id and no healthy twin). persistDownpipeState writes
          // dp:<toId> and maintains the due index for it.
          await this.persistDownpipeState(entries.get(action.key) as DownpipeState);
          await this.state.storage.delete(action.key);
          // Move the ghost's ring/repl residue to the correct id ONLY when that slot is empty (never
          // clobber real history); either way the misplaced residue is dropped.
          const ring = await this.state.storage.get<RunHistoryEntry[]>(`hist:${action.suffixId}`);
          if (ring !== undefined && (await this.state.storage.get(`hist:${action.toId}`)) === undefined) {
            await this.state.storage.put(`hist:${action.toId}`, ring);
          }
          await this.state.storage.delete(`hist:${action.suffixId}`);
          const repl = await this.state.storage.get(`repl:${action.suffixId}`);
          if (repl !== undefined && (await this.state.storage.get(`repl:${action.toId}`)) === undefined) {
            await this.state.storage.put(`repl:${action.toId}`, repl);
          }
          await this.state.storage.delete(`repl:${action.suffixId}`);
          rehomed++;
        } else {
          // G105: a delete-ghost over a row that DOES carry an embedded config id is not a malformed-row
          // cleanup, it is a DIVERGENT CLAIMANT whose config we are discarding because a healthy twin exists.
          // The operator's edits in that row (its schedule, its retention, its destination) go with it, which is
          // the "after the repair my downpipe has the wrong schedule" ticket, and the repair recorded nothing
          // but a count. File the two ids (the customer's own labels, the class the pack already carries) and a
          // ONE-WAY digest of the discarded config, so support can say what was taken; the config content itself
          // is never carried.
          const value = entries.get(action.key);
          const embedded = embeddedConfigId(value);
          if (embedded !== null) {
            const digest = hexEncode(await sha384(new TextEncoder().encode(JSON.stringify(value)))).slice(0, 12);
            await recordRosterClaimantDiscard(this.state.storage, action.suffixId, embedded, digest);
            await recordStorageAnomaly(this.state.storage, "roster-claimant-discarded");
          }
          await this.state.storage.delete(action.key);
          await this.state.storage.delete(`hist:${action.suffixId}`);
          await this.state.storage.delete(`repl:${action.suffixId}`);
          await this.state.storage.delete(`${ALERT_COOLDOWN_PREFIX}${action.suffixId}`);
          await this.state.storage.delete(`${REPL_ALERT_COOLDOWN_PREFIX}${action.suffixId}`);
          removed++;
        }
      }
      // Rebuild the due index from the repaired dp: truth (a mismatch ghost's embedded id may have
      // seeded an index entry over the years; the rebuild drops anything the truth no longer requires).
      if (plan.length > 0) await this.rebuildDueIndex();
      const after = await this.rosterHygiene();
      return { removed, rehomed, ghostsRemaining: after.ghostCount };
    }
  };
}
