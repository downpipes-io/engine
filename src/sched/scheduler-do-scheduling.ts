// The per-downpipe SCHEDULING CORE. SchedulerCoreMixin owns the due-time index (dueIndexKeyFor +
// persistDownpipeState + the rebuildDueIndex/maybeReconcileDueIndex backstop; the O(due) optimisation),
// the run-state machine (due/leased/trigger/heartbeat/completeRun + runlogIndex allocation), the
// replication state, the run-history + point-in-time reads, and the DO alarm (alarm/rearmAlarm +
// nextWithJitter); the cron driver in index.ts is still the seal driver (F11).

import { sweepOidcStates, sweepSamlRequests } from "../admin/oidc-store.ts";
import type { PasskeyChallenge } from "../admin/passkey.ts";
import { resolveRunAt } from "../admin/point-in-time.ts";
import type { PointInTimeRun } from "../admin/restore-types.ts";
import { annotatePredecessorChain, type RunHistoryEntryWithChain } from "../admin/run-chain.ts";
import { log } from "../log.ts";
import { isValidTimeZone, nextFireAfter, parseCron } from "./cron.ts";
import { allDestinationIds, nextReplAnchors } from "./destinations.ts";
import { classifyReplicationReason, isMalformedDestList, recordAlertingHealth, recordCompletionDiagnostics, recordContractFault, recordDestResolveFallback } from "./sched-fault-ledger.ts";
import { deferPastBlackoutsResolved, jitteredCadence, scheduleTimeZone } from "./schedule-window.ts";
import { ALARM_MIN_DELAY_MS, CONFIG_SCHEMA_VERSION, type CompleteRunReq, type DestReplState, DO_LIST_MAX_PAGES, DO_LIST_PAGE, type DownpipeConfig, type DownpipeSchedule, type DownpipeState, DUE_INDEX_HEALTH_KEY, DUE_INDEX_PREFIX, DUE_RECONCILE_TICK_KEY, INFLIGHT_LEASE_MS, migrateOrRejectConfig, PASSKEY_CHALLENGE_PREFIX, pad16, RECONCILE_EVERY_TICKS, RING_CAP, type RunHistoryEntry, SCHED_HEALTH_KEY, type SchedulerDOCtor, SEEN_ASSERTION_PREFIX, STATE_REFUSED_PREFIX, STATE_REFUSED_READ_CAP, STEPUP_TOKEN_PREFIX, STORAGE_FAULT_KEY, StateRefusedError, TICK_LEASE_MS, TICK_OUTCOME_KEY } from "./scheduler-do-base.ts";
import { appendTickOutcome, classifyStorageFault, EMPTY_SCHED_HEALTH, EMPTY_STORAGE_FAULTS, newULID, nowMillisISO, type StorageFaultCounter, schedHealthView, stateRefusalView, type TickOutcome, type TickReport } from "./scheduler-helpers.ts";
import type { BlackoutResolve, CronResolve, CronResolveClass, SchedHealthCounters, StateRefusal } from "./types.ts";

export function SchedulerCoreMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // dueIndexKeyFor returns the due-time index key for a downpipe state, or null when the state must
    // NOT have an index entry (disabled, or a null/non-numeric nextRunAt). It is the SINGLE place the
    // key shape (due:<pad16(nextRunAt)>:<id>) is derived, so the write (persistDownpipeState), the
    // delete-on-reschedule (also persistDownpipeState, using the PRIOR state) and the rebuild
    // (rebuildDueIndex) cannot drift from one another. Number.isFinite rejects NaN/Infinity defensively
    // even though DownpipeState.nextRunAt is typed number (a malformed persisted record can never inject
    // a bad index key).
    dueIndexKeyFor(ds: DownpipeState): string | null {
      if (!ds.config.enabled) return null;
      if (typeof ds.nextRunAt !== "number" || !Number.isFinite(ds.nextRunAt)) return null;
      return `${DUE_INDEX_PREFIX}${pad16(ds.nextRunAt)}:${ds.config.id}`;
    }

    // persistDownpipeState is the SINGLE writer of a dp:<id> record and the due-time index that mirrors
    // it. EVERY path that stores a DownpipeState (addDownpipe, trigger, heartbeat, completeRun,
    // completeRestoreTest, recordRestoreProven, the cf-config discovery/mode routes) goes through here so
    // the index can never be left stale by a write that forgot to maintain it. It:
    //   (a) reads the CURRENTLY stored dp:<id> to learn the PREVIOUS nextRunAt/enabled,
    //   (b) deletes the previous due:<pad>:<id> key (if the prior state had one), so a reschedule or a
    //       disable removes the old due-time entry rather than leaving a duplicate,
    //   (c) puts the new dp:<id> state,
    //   (d) writes the new due:<pad>:<id> key IFF the new state is enabled with a numeric nextRunAt.
    // The dp: write is the source of truth; the index is a derived secondary that due() always
    // re-validates against the dp: truth, and rebuildDueIndex() can rebuild from scratch, so even if a
    // crash interleaves these puts the worst case is a transient stale/missing index entry that the next
    // due() filter ignores and the periodic reconcile repairs, so a downpipe is never silently dropped.
    async persistDownpipeState(ds: DownpipeState): Promise<void> {
      const id = ds.config.id;
      try {
        const prior = await this.state.storage.get<DownpipeState>(`dp:${id}`);
        if (prior) {
          const priorKey = this.dueIndexKeyFor(prior);
          // Only delete the prior index key when it differs from the new one: a no-schedule-change write
          // (e.g. heartbeat bumping inFlightSince) keeps the same key, so skipping the delete avoids a
          // needless delete+put churn while staying correct (the put below rewrites the same key anyway).
          if (priorKey !== null && priorKey !== this.dueIndexKeyFor(ds)) await this.state.storage.delete(priorKey);
        }
        // Stamp the schema version at the STORAGE BOUNDARY (R4), mirroring the seal checkpoint's `v:1`: the
        // spread leaves the in-memory DownpipeState the run path and addDownpipe's return use UNCHANGED, so
        // only the at-rest record carries the version that migrateOrRejectConfig checks on read. A record
        // written before this shipped has no field and reads back as legacy v1 (accepted), so current/absent
        // records stay byte-identical in behaviour; this is a pure forward/back-compat stamp, not a change today.
        await this.state.storage.put(`dp:${id}`, { ...ds, schemaVersion: CONFIG_SCHEMA_VERSION });
        const newKey = this.dueIndexKeyFor(ds);
        if (newKey !== null) await this.state.storage.put(newKey, 1);
      } catch (e) {
        // persist-state-storage-fault (SCHED) / do-value-size-limit (INFRA): the persist FAILS LOUD -- we
        // re-throw so the seal loop still counts a sealErrors + a failed run row (behaviour unchanged) -- but
        // FIRST we PROMOTE it into the DISTINCT storage-fault counter, classifying a DO 128 KiB value-too-large
        // put from a generic storage failure. recordStorageFault is best-effort (a value-too-large fault is
        // per-key, so its small counter write succeeds; a total outage swallows it and the tick sealErrors + the
        // interval gap remain the evidence). It never throws, so it cannot mask or replace the original error.
        // The fault is ATTRIBUTED to the downpipe whose record was being persisted (G040): without it, a climbing
        // valueTooLarge count names no downpipe, so nobody can tell WHICH downpipe's state has outgrown the DO
        // 128 KiB per-value cap (the one that then never advances its next-run time). The id is the customer's own
        // label, clamped at the recording site; the raw storage error text is classified, never recorded.
        await this.recordStorageFault(classifyStorageFault(e), id);
        throw e;
      }
    }

    // rebuildDueIndex is the RECONCILIATION BACKSTOP (the safety net): it full-scans the dp: truth and
    // rebuilds the entire due: index from it, so the index can never permanently drift from the dp:
    // states. It (a) BUILDS the index on first deploy (downpipes that existed before this version was
    // deployed have dp: records but no due: entries yet), and (b) SELF-HEALS any drift from a missed
    // write or a manual storage edit. It is O(N) (one full dp: page-scan + a delete of the old index +
    // a write per enabled downpipe), so due() calls it only LAZILY (empty index, non-empty dp:) and
    // periodically (every RECONCILE_EVERY_TICKS ticks), keeping it rare relative to the O(due) fast path.
    async rebuildDueIndex(): Promise<void> {
      const states = await this.listAllByPrefix<DownpipeState>("dp:");
      // Drop every existing due: key first, so a stale entry whose downpipe was deleted/disabled/
      // rescheduled outside persistDownpipeState (drift) does not survive the rebuild. The
      // enumeration is PAGED via listAllByPrefix (M2/R0-1): a bare un-paged list() returns at most
      // one page (~DO_LIST_PAGE keys), so a drifted index holding MORE than a page of stale entries
      // would only have its first page deleted and the tail would leak past the rebuild (the index
      // would never converge to the dp: truth at fleet scale). listAllByPrefix pages the whole
      // prefix with an ascending startAfter cursor, so the delete is complete at any scale.
      const existing = await this.listAllByPrefix<unknown>(DUE_INDEX_PREFIX);
      const indexEntriesBeforeRebuild = existing.size;
      for (const k of existing.keys()) await this.state.storage.delete(k);
      // Re-add an index entry for every CURRENT enabled, numeric-nextRunAt downpipe, straight from dp: truth.
      let indexEntriesRequired = 0;
      for (const ds of states.values()) {
        const key = this.dueIndexKeyFor(ds);
        if (key !== null) {
          await this.state.storage.put(key, 1);
          indexEntriesRequired++;
        }
      }
      // Stamp the due-index parity snapshot (SCHED due-index-drift / rebuild-partial-or-too-big) for the
      // support pack: the entries the index held BEFORE this rebuild vs the entries dp: truth actually
      // requires, plus the total fleet size. `matched` is the healthy steady state (the index already agreed
      // with dp: truth); a mismatch means the index had DRIFTED (a missed write, a manual edit) or was being
      // built for the first time (indexEntriesBeforeRebuild 0). Counts + a flag + a timestamp only (no-custody);
      // best-effort so a stamp fault never breaks the rebuild the fleet's dispatch depends on.
      try {
        await this.state.storage.put(DUE_INDEX_HEALTH_KEY, {
          at: Date.now(),
          indexEntriesBeforeRebuild,
          indexEntriesRequired,
          dpTotal: states.size,
          matched: indexEntriesBeforeRebuild === indexEntriesRequired,
        });
      } catch {
        /* the parity stamp is diagnostic only; never fail the index rebuild for it. But a FAILED stamp is
           itself a fault worth counting (G040): the pack's dueIndex block then serves the PRIOR snapshot as if
           it were fresh, so a diagnoser reads a healthy parity that was never actually re-measured. The counter
           lets schedulerSignals mark the snapshot STALE rather than pass it off as current. */
        await this.recordSchedHealth("parity-stamp-failed");
      }
    }

    // maybeReconcileDueIndex bumps the persisted tick counter and runs rebuildDueIndex when either
    // backstop condition fires: the index is EMPTY while dp: is NOT (first-deploy / wiped-index
    // detection) OR RECONCILE_EVERY_TICKS ticks have elapsed since the last reconcile. It returns
    // whether a rebuild ran (so a test can assert the reconcile cadence). The counter is persisted so
    // the cadence survives isolate eviction. Listing one key from each prefix (limit 1) is cheap and
    // does NOT scan the fleet.
    async maybeReconcileDueIndex(): Promise<boolean> {
      const tick = ((await this.state.storage.get<number>(DUE_RECONCILE_TICK_KEY)) ?? 0) + 1;
      await this.state.storage.put(DUE_RECONCILE_TICK_KEY, tick);
      // First-deploy / empty-index detection: probe ONE due: key and ONE dp: key (limit 1, O(1)). An
      // empty index over a non-empty fleet means the index has never been built (or was wiped), so
      // build it now rather than dispatching nothing.
      const anyIndex = await this.state.storage.list<unknown>({ prefix: DUE_INDEX_PREFIX, limit: 1 });
      const anyDp = await this.state.storage.list<unknown>({ prefix: "dp:", limit: 1 });
      const indexEmptyButFleetNot = anyIndex.size === 0 && anyDp.size > 0;
      if (indexEmptyButFleetNot || tick % RECONCILE_EVERY_TICKS === 0) {
        await this.rebuildDueIndex();
        return true;
      }
      return false;
    }

    // due returns the enabled, not-in-flight downpipes whose next run is due. The cron-driven driver in
    // index.ts asks for these and runs each (allocate index, seal, complete), keeping the seal out of the
    // DO (design F11).
    //
    // SCALE (ENG-SCALE-09): instead of scanning EVERY downpipe (O(N) per tick), it lists only the
    // due-time index range [due:, due:<pad16(now+1)>), i.e. exactly the candidates whose nextRunAt <= now,
    // so the hot path is O(due), not O(N). The index is an OPTIMISATION, never the source of truth: each
    // candidate's dp: state is re-fetched and the EXACT existing predicate is re-applied against that
    // live state, so a stale index entry (a since-deleted/disabled/rescheduled downpipe) is filtered out
    // and can NEVER cause a wrong dispatch. maybeReconcileDueIndex() runs the O(N) rebuild lazily on
    // first deploy and periodically, so any drift self-heals and a downpipe is never silently dropped.
    // The returned shape is unchanged ({ due: DownpipeState[] }), and for a small fleet the set is
    // byte-identical to the old listDownpipes().filter(...) (the parity test asserts this).
    async due(): Promise<{ due: DownpipeState[] }> {
      // Reconciliation backstop FIRST (builds the index on first deploy so the scan below is populated,
      // and periodically self-heals drift). It is the safety net that guarantees the index converges to
      // the dp: truth even if a write ever skipped the index.
      await this.maybeReconcileDueIndex();
      const now = Date.now();
      // Candidate keys: every due: entry with pad16(nextRunAt) < pad16(now+1), i.e. nextRunAt <= now.
      // The half-open [start, end) range with end = due:<pad16(now+1)> includes nextRunAt === now and
      // excludes anything strictly after now. This is O(due), independent of the total fleet size.
      //
      // PAGE the range exactly as listAllByPrefix pages a prefix: the platform caps a single list() at
      // ~DO_LIST_PAGE keys, so a tick on which MORE than a page of downpipes is due at once would
      // otherwise silently truncate, and every due downpipe past the first page would be missed, the very
      // failure the index is meant to prevent. The FIRST page is the half-open range [DUE_INDEX_PREFIX,
      // end); each subsequent page uses startAfter (EXCLUSIVE) on the last key of the prior page, the same
      // ascending-cursor discipline as listAllByPrefix, so there is no overlap and no gap. A short page is
      // the exhaustion signal. Total work stays O(due): the loop only ever visits keys whose nextRunAt is
      // <= now, never the whole fleet.
      const end = `${DUE_INDEX_PREFIX}${pad16(now + 1)}`;
      const due: DownpipeState[] = [];
      let startAfter: string | undefined;
      for (let guard = 0; guard < DO_LIST_MAX_PAGES; guard++) {
        const page = await this.state.storage.list<unknown>({
          ...(startAfter === undefined ? { start: DUE_INDEX_PREFIX } : { startAfter }),
          end,
          limit: DO_LIST_PAGE,
        });
        if (page.size === 0) break;
        let lastKey: string | undefined;
        for (const key of page.keys()) {
          lastKey = key;
          // Parse the <id> out of due:<pad16>:<id>. The pad is exactly 16 digits and the prefix is fixed,
          // so the id is everything after the second colon (an id may itself contain a colon; it is sliced, not
          // split), so reconstruct the offset rather than split(":").
          const id = key.slice(DUE_INDEX_PREFIX.length + 16 + 1);
          if (id.length === 0) continue; // malformed index key (defensive); skip it
          const d = await this.state.storage.get<DownpipeState>(`dp:${id}`);
          if (!d) continue; // stale index entry for a deleted downpipe; the reconcile drops it, dispatch ignores it
          // Read-time schema guard (R4): this is THE load-bearing source-selection read (the seal loop
          // captures the source set from the states this returns), so a record stamped by a NEWER engine
          // (a rollback reading new-shape state) must NOT be dispatched under this older code, which could
          // mis-read a load-bearing source field and seal a wrong/empty set while still reporting ok. Fail
          // loud as SKIP-WITH-ALERT rather than throw, so one future-stamped downpipe cannot halt the WHOLE
          // fleet's backups (a throw here would 500 the /due endpoint and dispatch nothing for the tick);
          // the offending downpipe is left undispatched (no silent partial) and the rest of the tick proceeds.
          try {
            migrateOrRejectConfig(d);
          } catch (e) {
            log("error", `due: skipping downpipe ${id} with unreadable schema: ${(e as Error).message}`);
            // SKIP-WITH-ALERT was really skip-with-Workers-Logs (G095/G210): the skipped downpipe produced no run
            // row, no failed run, no marker -- just growing staleness the pack could not explain. STAMP the
            // refusal (closed class + the version pair + a count) so the pack can say "this downpipe is stamped by
            // a newer schema: you rolled the engine back". Best-effort and non-throwing, so the skip-the-one-pipe,
            // dispatch-the-rest behaviour of this loop is unchanged.
            if (e instanceof StateRefusedError) await this.recordStateRefusal(id, e.refusalClass, e.storedVersion);
            continue;
          }
          // Re-apply the EXACT existing predicate against the LIVE state, the source of truth: enabled,
          // not genuinely leased (an expired-lease in-flight pipe is re-included so a crashed run
          // self-heals on the next trigger), and actually due. A stale index entry that no longer
          // satisfies this (rescheduled into the future, since-disabled) is filtered out here, so the
          // index can never cause a wrong dispatch.
          if (d.config.enabled && !this.leased(d, now) && d.nextRunAt <= now) due.push(d);
        }
        // A short page exhausts the range; only a FULL page means there may be more, after the last key.
        if (page.size < DO_LIST_PAGE || lastKey === undefined) break;
        startAfter = lastKey; // exclusive cursor for the next page (ascending key order)
      }
      return { due };
    }

    // leased reports whether a downpipe is genuinely in flight: inFlight AND within INFLIGHT_LEASE_MS of
    // its trigger. An inFlight pipe past the lease (or one with no timestamp, i.e. pre-lease persisted
    // state) is treated as a crashed run, NOT leased, so due()/trigger() reclaim it instead of wedging.
    leased(d: DownpipeState, now: number): boolean {
      return d.inFlight && d.inFlightSince !== undefined && now - d.inFlightSince <= INFLIGHT_LEASE_MS;
    }

    // trigger allocates the next runlogIndex inside the storage transaction and marks the
    // downpipe in flight, returning the run id + index for the seal handler to use.
    async trigger(req: { id: string }): Promise<{ runId: string; index: number; prevRunId: string | null; config: DownpipeConfig } | { skipped: string }> {
      const ds = await this.state.storage.get<DownpipeState>(`dp:${req.id}`);
      if (!ds) throw new Error(`unknown downpipe ${req.id}`);
      // Read-time schema guard (R4): trigger returns this config to the seal (the manual run-now path,
      // POST /admin/trigger, builds its seal state directly from this returned config), so it is a
      // load-bearing source-selection read. Refuse to allocate a run on a record stamped by a NEWER engine
      // (a rollback reading new-shape state) which could seal a wrong/empty source set: throw so the manual
      // path surfaces a 500 to the operator and the cron driver's per-downpipe catch frees the lease for a
      // later tick, rather than sealing a silent partial. (The scheduled path already skipped it in due().)
      // The refusal is STAMPED before it is re-thrown (G095/G210): a run-now that 500s leaves no failed-trigger
      // row either, so without this stamp the ONLY record of "this record is stamped by a newer schema" is a
      // Workers Logs line. Re-throwing keeps the caller's behaviour byte-identical.
      try {
        migrateOrRejectConfig(ds);
      } catch (e) {
        if (e instanceof StateRefusedError) await this.recordStateRefusal(req.id, e.refusalClass, e.storedVersion);
        throw e;
      }
      // The record read CLEAN, so any earlier refusal stamp is stale (the engine was re-upgraded, or the record
      // was migrated). Clear it so a repaired downpipe stops reporting a fault it no longer has.
      await this.clearStateRefusal(req.id);
      const now = Date.now();
      // G090 (the data-loss one): this downpipe's destinationIds list is PRESENT but holds no usable entry, so
      // primaryDestinationId falls through to the legacy single id, and failing that to the ENV DEFAULT. The
      // run then seals to a destination the operator did not choose, the run row records the destination
      // actually used, and nothing anywhere says the engine substituted it -- "my backups are landing in the
      // wrong bucket", undiagnosable. Stamped at run ALLOCATION (the one chokepoint every run passes through),
      // as a closed class + the customer's own downpipe id; never a bucket, endpoint or credential.
      if (isMalformedDestList(ds.config)) await recordDestResolveFallback(this.state.storage, "malformed-list-fallback", ds.config.id);
      if (this.leased(ds, now)) return { skipped: "a previous run is still in flight (coalesced)" };
      // If it is inFlight but the lease expired, the previous run crashed (the isolate was evicted, hit a
      // CPU/wall-clock limit, or was redeployed between trigger and complete). Reclaim it: resolve the
      // orphaned in-flight history row to "abandoned" and allocate a fresh run. The RUNLOG append is
      // idempotent on (runId,index), so a reclaimed re-run is safe (ENG-B2).
      const reclaiming = ds.inFlight;
      const index = ((await this.state.storage.get<number>("runlogCounter")) ?? 0) + 1;
      const runId = newULID(now);
      const prevRunId = ds.lastRunId;
      ds.inFlight = true;
      ds.inFlightSince = now;
      const hist = (await this.state.storage.get<RunHistoryEntry[]>(`hist:${req.id}`)) ?? [];
      if (reclaiming) {
        for (let i = hist.length - 1; i >= 0; i--) {
          if (hist[i]!.status === "in-flight") {
            hist[i]!.status = "abandoned";
            hist[i]!.error = "abandoned (run lease expired)";
            break;
          }
        }
      }
      // Append an in-flight history row in the SAME transaction as the counter/state puts, so an
      // allocated run always has a history line (completeRun later resolves it in place by matching
      // index). The ring is bounded to RING_CAP newest-last.
      hist.push({ runId, index, startedAt: nowMillisISO(), status: "in-flight", prevRunId });
      while (hist.length > RING_CAP) hist.shift();
      await this.state.storage.put("runlogCounter", index);
      // Routed through the single index-maintaining writer. trigger sets inFlight/inFlightSince but does
      // NOT change enabled/nextRunAt, so the due: key is unchanged (an in-flight pipe stays indexed; due()
      // excludes it via the live `leased` check, and an expired-lease pipe is re-included for reclaim).
      await this.persistDownpipeState(ds);
      await this.state.storage.put(`hist:${req.id}`, hist);
      return { runId, index, prevRunId, config: ds.config };
    }

    // heartbeat renews the in-flight LEASE for the run that holds it (a SLICED run spans many
    // invocations, so a long seal would otherwise cross INFLIGHT_LEASE_MS and be reclaimed as
    // crashed mid-flight). It bumps inFlightSince ONLY when the caller still owns the run: the
    // named history row is still in-flight AND records this runId, and the downpipe is in flight
    // (the same ownership predicate completeRun gates on). A heartbeat from a reclaimed run
    // returns owned:false so the stale sealer abandons instead of duelling the new owner.
    async heartbeat(req: { id: string; runId: string; index: number }): Promise<{ owned: boolean }> {
      const ds = await this.state.storage.get<DownpipeState>(`dp:${req.id}`);
      if (!ds?.inFlight) return { owned: false };
      const hist = (await this.state.storage.get<RunHistoryEntry[]>(`hist:${req.id}`)) ?? [];
      const row = hist.find((h) => h.index === req.index) ?? null;
      const owned = row !== null && row.status === "in-flight" && row.runId === req.runId;
      if (!owned) return { owned: false };
      ds.inFlightSince = Date.now();
      // Routed through the single index-maintaining writer (a heartbeat only bumps the lease timestamp,
      // so the due: key is unchanged; persistDownpipeState detects that and skips the re-key).
      await this.persistDownpipeState(ds);
      return { owned: true };
    }

    // completeRun clears the in-flight flag, records the run id and the next due time, and
    // resolves the matching in-flight history row in place (status + coarse outcome counts).
    //
    // It is IDEMPOTENT and guarded against a stale or duplicate completion (ENG-M13). The join key
    // between a trigger and its completion is the monotonic runlogIndex: it is allocated once per run,
    // never reused, and gap-tolerant, so an index uniquely names ONE run for all time. A completion
    // may legitimately land at most once per run, but a retried POST, or a late completion from a run
    // that was already reclaimed, can arrive again or out of order. Such a completion must NOT:
    //   - overwrite a history row that has already been terminally resolved (ok/failed/abandoned) by
    //     this or another run, and
    //   - clear the in-flight flag when that flag now belongs to a DIFFERENT, newer run.
    // We therefore resolve the row this completion NAMES and act only when that row is still the run
    // currently in flight for that index (ownsInFlight). A newer trigger reclaims an orphaned run by
    // marking the old in-flight row "abandoned" and opening a fresh in-flight row at a NEW index (see
    // trigger), so a stale completion bearing the old index finds an already-resolved row here, owns
    // nothing, and is a no-op for both the state and the ring.
    async completeRun(req: CompleteRunReq): Promise<{ ok: true }> {
      const hist = (await this.state.storage.get<RunHistoryEntry[]>(`hist:${req.id}`)) ?? null;
      const row = hist ? (hist.find((h) => h.index === req.index) ?? null) : null;
      // The completion OWNS the current in-flight run only when the named row is still in-flight AND
      // it is the run that row records: either the empty-runId FAILED convention (req.runId === "",
      // which by design carries no id and is matched by index alone), or a runId that matches the
      // row's allocated id. A completion that names no live in-flight row (an unknown/zero index, the
      // rare drive-catch path, or a row a newer run already resolved) owns nothing.
      const ownsInFlight = row !== null && row.status === "in-flight" && (req.runId === "" || row.runId === req.runId);
      // G221: a completion that owns nothing is DISCARDED in silence. Usually that is the benign late/duplicate
      // retry this guard exists for, but it is also how a REAL completion is lost after a reclaim (the run then
      // keeps reading "abandoned" in the pack though it finished). Count the drop: closed class only, no body.
      if (!ownsInFlight) await recordContractFault(this.state.storage, "run-completion-unowned", "unowned-drop");

      const ds = await this.state.storage.get<DownpipeState>(`dp:${req.id}`);
      // Clear the in-flight flag ONLY for the run that currently holds it. A duplicate or stale
      // completion whose row is already resolved, or whose run was superseded by a newer in-flight
      // run, must not flip inFlight=false out from under the live run (ENG-M13). The in-flight LEASE
      // (ENG-B2) remains the backstop that reclaims a run whose completion never lands at all (e.g.
      // the narrow drive-catch index-0 path where the trigger committed but the seal never started).
      if (ds && ownsInFlight) {
        ds.inFlight = false;
        delete ds.inFlightSince; // clear the lease on completion (ENG-B2)
        // An empty runId signals a FAILED run (the lock is cleared so the next tick retries);
        // only a successful run advances lastRunId, so the prevRunId chain is never corrupted.
        if (req.runId) ds.lastRunId = req.runId;
        // G299 (the never-reported replica): advance the MONOTONE sealed-run counter on a SUCCESSFUL run, on
        // the SAME predicate as lastRunId above (an empty runId is the failed convention, and a failed run
        // sealed nothing to replicate, so it must not advance the count -- a downpipe whose every run fails
        // owes its replicas no copy, and its replicas must never be accused of losing one). Then re-derive the
        // anchor map: nextReplAnchors is idempotent for a destination that already has one, so the ONLY effect
        // here is to BACKFILL a configured destination that has none -- the record was written before the
        // anchor existed, or arrived through a control-plane import. The backfill anchors it at the count
        // INCLUDING this run, which UNDERSTATES how long it may have been failing. That is the conservative
        // direction on purpose: the pack would rather stay silent for two more successful runs than assert a
        // history the engine never observed.
        if (req.runId) ds.sealedRuns = (ds.sealedRuns ?? 0) + 1;
        const anchors = nextReplAnchors(ds.replAnchors, allDestinationIds(ds.config), ds.sealedRuns ?? 0);
        if (anchors !== undefined) ds.replAnchors = anchors;
        else delete ds.replAnchors;
        // Stamp the "archive integrity last verified" recency ONLY on a SUCCESSFUL run (a non-empty runId,
        // i.e. status !== "failed"). A clean seal built the per-record hashes, signed the manifest and
        // appended + re-signed the RUNLOG chain (seal/pipeline.ts runBackup), so a successful completion IS
        // an integrity verification of the just-written archive. A FAILED run takes the empty-runId path and
        // never sets this, so the protection statement is never given a false "integrity-checked" (honest:
        // only stamped when integrity was actually verified). The console reads this (mapped to
        // lastIntegrityVerifiedAt/Ok) to say "integrity-checked daily" instead of "never integrity-checked".
        // Record the latest verify-at-seal verdict (ENG-RST-01) for the posture seal-verification check
        // and /admin/status, on a SUCCESSFUL run only (a failed run sealed nothing to read back). It is
        // recorded for BOTH outcomes (verified AND suspect), so a suspect readback is observable.
        if (req.runId && req.sealVerification !== undefined) ds.lastSealVerify = req.sealVerification;
        // Stamp the integrity-verified recency on a successful run, BUT only when verify-at-seal did not
        // come back SUSPECT: if the readback verify FAILED, the just-written archive is not affirmatively
        // verified, so stamping "integrity-checked" would be a false positive. A run with no verdict (the
        // feature off, or an older driver) keeps the prior behaviour (a clean completion stamps it).
        if (req.runId && req.sealVerification?.status !== "suspect") ds.integrityVerified = { at: Date.now(), how: "run" };
        // Post-backup retest request (restorability heal): a SUCCESSFUL run landing while the last
        // scheduled restore test did not PASS (never passed, deferred for no-run, or genuinely failed)
        // means the evidence the drill was missing now exists, so mark the downpipe due for a prompt
        // retest instead of waiting out the remaining cadence (a stale "failed" verdict used to sit on
        // the restore screen for up to a week after the archive was already healthy). Only when a
        // restore-test cadence is configured (an explicit 0 keeps scheduled testing off); consumed by
        // completeRestoreTest on the next completion, so it can never re-fire in a loop.
        if (req.runId && (ds.config.restoreTestCadenceSeconds ?? 0) > 0 && ds.lastRestoreTestOk !== true) {
          ds.restoreTestRetestAt = Date.now();
        }
        const rescheduled = this.nextWithJitter(ds.config.cadenceSeconds, ds.config.schedule);
        ds.nextRunAt = rescheduled.next;
        // Stamp the cron-resolution outcome (SCHED cron-runtime-fallback-to-cadence / invalid-tz-runtime /
        // impossible-cron-runtime): set the closed class when there is a cron to resolve, else CLEAR any stale
        // stamp so a downpipe switched back to cadence does not keep an old cron-fault class. Diagnostic only.
        if (rescheduled.cronResolve) ds.cronResolve = rescheduled.cronResolve;
        else delete ds.cronResolve;
        // Stamp the blackout-resolution outcome (G322 blackout-windows-silently-violated) on the same terms: set
        // the closed class when there are windows to resolve, else CLEAR any stale stamp so a downpipe whose
        // windows were removed does not keep reporting an old violation. Class + time only; window minutes never.
        if (rescheduled.blackoutResolve) ds.blackoutResolve = rescheduled.blackoutResolve;
        else delete ds.blackoutResolve;
        // Routed through the single index-maintaining writer. completeRun ADVANCES nextRunAt (always
        // LATER, never earlier), so this is the key reschedule path: persistDownpipeState deletes the old
        // due:<oldNextRunAt> entry and writes the new due:<newNextRunAt> one, keeping the index in step.
        await this.persistDownpipeState(ds);
        // SCALE (sched-rearmalarm-on-every-completion): do NOT run the O(N) full-fleet rearmAlarm() here.
        // completeRun fires on EVERY run completion, so an O(N) listDownpipes scan per completion is O(N^2)
        // work per tick at fleet scale on the single-threaded DO. It is also unnecessary: a completion only
        // ever advances THIS downpipe's nextRunAt LATER (never earlier), so it can never require pulling the
        // alarm earlier. The alarm is a BACKSTOP (the */15 cron is the dispatcher, and the effective cadence
        // floor IS that 15-min tick), and it self-rearms to the true global min on each firing (alarm()) and
        // on every upsert (addDownpipe), so the wake chain stays alive without scanning the fleet here. As a
        // cheap O(1) safety net, if NO alarm is currently pending (a fleet that has only completed runs, never
        // upserted, since the last firing), arm one at this downpipe's next run so the DO is guaranteed to wake
        // and re-arm precisely. Tolerate a minimal storage double (the Node validators' mocks may omit
        // getAlarm, exactly as kv.ts tolerates a double without getWithMetadata): a missing getAlarm is
        // treated as "an alarm is pending" so the safety-net is a no-op there; real workerd storage always
        // provides getAlarm, so the precise O(1) check runs in production.
        const getAlarmFn = (this.state.storage as { getAlarm?: () => Promise<number | null> }).getAlarm;
        if (typeof getAlarmFn === "function" && (await getAlarmFn.call(this.state.storage)) === null) {
          await this.state.storage.setAlarm(Math.max(ds.nextRunAt, Date.now() + ALARM_MIN_DELAY_MS));
        }
      }
      // Resolve the named ring row in place, but ONLY while this completion still owns the in-flight
      // run (gated on the same ownsInFlight predicate as the state above, so the two never disagree).
      // A completion whose row is already terminally resolved is a no-op, so a duplicate or stale
      // completion can never clobber a resolved row's status/counts back to a different outcome
      // (ENG-M13). The row keeps its allocated runId even on failure (req.runId is "" by convention).
      if (hist && row !== null && ownsInFlight) {
        row.status = req.status ?? (req.runId ? "ok" : "failed");
        if (req.recordCount !== undefined) row.recordCount = req.recordCount;
        if (req.bytes !== undefined) row.bytes = req.bytes;
        if (req.archiveBytesWritten !== undefined) row.archiveBytesWritten = req.archiveBytesWritten;
        if (req.segmentsWritten !== undefined) row.segmentsWritten = req.segmentsWritten;
        if (req.durationMs !== undefined) row.durationMs = req.durationMs;
        // Surface records the seal could not capture this run (slice-skipped-records-not-surfaced): a
        // non-zero count means the archive is intentionally short of the live source, visible on the row.
        if (req.recordsSkipped !== undefined) row.recordsSkipped = req.recordsSkipped;
        // WS-P2: in-scope objects that vanished (were deleted) mid-crawl between list and value read. A
        // non-zero count means the live source churned under the backup; surfaced on the row for the pack.
        if (req.recordsVanished !== undefined) row.recordsVanished = req.recordsVanished;
        // R1-1: records sealed as incompleteness sentinels (markers, not the real bytes). A non-zero
        // count means the archive completed but is intentionally short of the live source.
        if (req.recordsIncomplete !== undefined) row.recordsIncomplete = req.recordsIncomplete;
        // R1-1 per-marker breakdown: WHICH incompleteness kinds the run sealed (the support pack carries it
        // verbatim; the diagnostics-bot consumes it separately). KEY identity + integer count only.
        if (req.incompleteByMarker !== undefined) row.incompleteByMarker = req.incompleteByMarker;
        // WS-P1 per-kind attribution: WHICH surface/object was short (redaction-safe closed/product-token ids
        // only). The support pack carries it verbatim beside incompleteByMarker; the diagnostics-bot names it.
        if (req.incompleteIds !== undefined) row.incompleteIds = req.incompleteIds;
        if (req.opCounts !== undefined) row.opCounts = req.opCounts; // exact per-resource op tally (cost Phase 3)
        // Record the verify-at-seal verdict on the row (ENG-RST-01) so the run list / status can show
        // "verified at seal" (or "suspect") per run. Only on a successful row (a failed run sealed
        // nothing to verify); absent when the feature is off or the driver predates it.
        if (row.status === "ok" && req.sealVerification !== undefined) row.sealVerification = req.sealVerification;
        // Stranded multipart parts (multipart-abort-stranded-parts): a FAILED multipart upload's best-effort
        // abort ALSO failed on this run's destination, leaving invisible part-storage. The seal driver derives
        // this BOOLEAN from the destination's abort-failure counter and posts it on EITHER outcome (a stranding
        // most often accompanies a failed run, but a later slice can strand while the run overall completes ok),
        // so stamp it on the row whenever it is set and clear it otherwise (a re-resolved clean row never keeps
        // a stale flag). A boolean only; never a key/id/value.
        if (req.multipartAbortFailed === true) row.multipartAbortFailed = true;
        else delete row.multipartAbortFailed;
        // Carry a coarse error only on failure; success never records one.
        if (row.status === "failed" && req.error) row.error = req.error;
        else delete row.error;
        // Carry the 12-hex correlation digest alongside the coarse error on a FAILED row, so the support pack
        // reads it back byte-identical to the Logpush `[cause <hex>]` line for the same fault. Mirrors `error`:
        // set only on a failed row that carries one, cleared otherwise so a re-resolved ok row never keeps a
        // stale digest, and absent when an older driver omitted it.
        if (row.status === "failed" && req.causeDigest) row.causeDigest = req.causeDigest;
        else delete row.causeDigest;
        // Record the destination this run SEALED to (the failover-chosen origin) on a successful row,
        // and seed its replication state: the origin is now PROVEN to hold this run. A failed run sealed
        // nowhere, so it records no origin (a resolver then falls back to the configured primary).
        if (row.status === "ok" && req.runId && req.destinationId) {
          row.destinationId = req.destinationId;
          await this.recordReplicationState(req.id, { destinationId: req.destinationId, ok: true, runId: req.runId, index: req.index });
        }
        // DEST-1: a FAILED run carries the destination id(s) PROVEN down this run (the failover down set,
        // or the sole destination of a single-dest downpipe whose write faulted with a destination-access
        // error). Record a lastOk:false reachability heartbeat for each so the map's per-destination "down"
        // indicator lights up for a single/default-destination outage too, not just a fan-out replica. The
        // heartbeat is forward-only on holdsIndex (recordReplicationState never rewinds it on a failure), so
        // a down record can never drop a destination's proven-copy count. A run that later succeeds refreshes
        // the same destination to lastOk:true (the origin seed above), so the indicator self-heals.
        // G120: every down destination used to read the literal "unreachable", so support could not tell an
        // EXPIRED CREDENTIAL from a WORM refusal from a timeout - three faults with three different owners and
        // three different fixes. classifyReplicationReason REDUCES the driver's coarse run-error class (itself a
        // closed vocabulary carrying the store's sanitised code) to ONE closed member and DISCARDS the string:
        // no S3 error text, endpoint host or bucket name ever reaches the record.
        const downReason = classifyReplicationReason(req.error);
        if (row.status === "failed" && Array.isArray(req.downDestinationIds)) {
          for (const downId of req.downDestinationIds) {
            if (typeof downId === "string" && downId.length > 0) await this.recordReplicationState(req.id, { destinationId: downId, ok: false, reason: downReason });
          }
        }
        // G120 (env-default destination) + G076 (a staleness rule that can never arm): both are per-completion
        // observations over the SAME facts, so they share one never-throwing recorder in sched-fault-ledger.ts.
        await recordCompletionDiagnostics(this.state.storage, {
          downpipeId: req.id,
          status: row.status,
          coarseError: req.error,
          hasDestinationId: req.destinationId !== undefined,
          downDestinationCount: Array.isArray(req.downDestinationIds) ? req.downDestinationIds.length : 0,
          cadenceSeconds: ds?.config.cadenceSeconds,
          newestStartedAt: hist.length > 0 ? hist[hist.length - 1]!.startedAt : undefined,
        });
        await this.state.storage.put(`hist:${req.id}`, hist);
      }
      return { ok: true };
    }

    // recordReplicationState updates ONE destination's DestReplState for a downpipe (the scheduler DO is
    // the single writer of `repl:` state, exactly as for run history). A success advances holdsRunId/
    // holdsIndex but only FORWARD by index, so a late or duplicate record can never rewind the proven
    // copy, and clears the reason; a failure leaves holds* intact (the destination still holds whatever
    // it last held) and records the coarse reason + the failed-attempt time, the reachability heartbeat
    // that surfaces the "destination down" indicator. destinationId is required (an env-default run with
    // no console destination id records nothing, so the single-destination path keeps no repl state).
    async recordReplicationState(id: string, r: { destinationId?: string; ok: boolean; runId?: string; index?: number; holdsFrom?: number; reason?: string }): Promise<void> {
      if (!r.destinationId) return;
      const key = `repl:${id}`;
      const map = (await this.state.storage.get<Record<string, DestReplState>>(key)) ?? {};
      const prev = map[r.destinationId];
      const next: DestReplState = {
        holdsRunId: prev?.holdsRunId ?? null,
        holdsIndex: prev?.holdsIndex ?? -1,
        ...(prev?.holdsFrom !== undefined ? { holdsFrom: prev.holdsFrom } : {}),
        lastOk: r.ok,
        lastAttemptAt: Date.now(),
      };
      if (r.ok && r.runId && typeof r.index === "number" && r.index > next.holdsIndex) {
        next.holdsRunId = r.runId;
        next.holdsIndex = r.index;
      }
      // Advance the proven FLOOR forward-only UP (the ring floor only moves up as runs age out of the
      // history ring). A higher floor means the destination can prove LESS below it, so max-pinning is the
      // conservative retains-more direction and can never widen the covered window a prune trusts.
      if (r.ok && typeof r.holdsFrom === "number" && r.holdsFrom > (next.holdsFrom ?? Number.NEGATIVE_INFINITY)) {
        next.holdsFrom = r.holdsFrom;
      }
      if (!r.ok && r.reason) next.reason = r.reason;
      map[r.destinationId] = next;
      await this.state.storage.put(key, map);
    }

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

    // runAt is the POINT-IN-TIME resolver (E4/C1): GET /runs/at?downpipe=&at=<rfc3339> -> the latest
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
      // G082: a SUCCESSFUL run whose startedAt will not parse is EXCLUDED from this resolution, so a run that
      // genuinely covers T is invisible and the customer is told no run exists -- a data-loss-grade wrong
      // answer produced by a timestamp bug. resolveRunAt already reports the exclusion ON THIS RESPONSE
      // (excludedCorruptRuns), which the console can show; the counter is the PACK's copy of the same fact,
      // and it is the one a support engineer reads, because a pack is built long after the console call that
      // gave the wrong answer. Counts only: never the row, never the timestamp that would not parse. It fires
      // ONLY when a row was actually dropped, so a clean ring records nothing.
      if ((resolved.excludedCorruptRuns ?? 0) > 0) await this.bumpAdminCounterLocal("pit-corrupt-run-excluded", resolved.excludedCorruptRuns ?? 0);
      return resolved;
    }

    // acquireTickLease is the cron driver's SINGLE-FLIGHT guard (C3-07). drive() (the scheduled() body) takes it
    // at the top of a tick and releases it at the end, so two OVERLAPPING */15 cron ticks -- a slow tick still in
    // flight when the platform fires the next one, possibly in a SEPARATE isolate -- do not both run the pass
    // sequence. It is the SAME single-threaded-DO compare-and-set the RUNLOG lock relies on (acquireRunlogLock):
    // the DO serialises storage round-trips, so no other tick's acquire interleaves between this get and put, and
    // two concurrent acquires cannot both observe an unheld/expired lease and both take it.
    //
    // It is DEFENCE-IN-DEPTH, not the correctness floor. The per-run in-flight lease already COALESCES a duplicate
    // seal dispatch inside trigger() (a second tick's /trigger for the same downpipe returns skipped), and the
    // alert / expiry / replication / source-drift / canary / update-alert tail passes each dedupe atomically in
    // this DO. The one tail that CANNOT dedupe an overlap on its own is the digest flush: digestDue only READS,
    // and the paired digestSent clears AFTER out-of-band delivery, so two overlapping ticks could deliver the
    // same summary twice. This lease closes that residual and spares the wasted duplicate reachability probes.
    //
    // The lease SELF-EXPIRES after TICK_LEASE_MS (~one cron interval): a tick whose isolate was evicted before it
    // released cannot wedge the schedule, since the next tick past the expiry reclaims it. Release-on-completion
    // (releaseTickLease) is the PRIMARY mechanism -- a normal tick holds it for seconds -- so a lease still held
    // when the next */15 fires means a genuine overlap (skip is correct) or a very recent crash (self-heals within
    // a tick). drive() acquires it FAIL-OPEN: an unreachable DO is treated as "proceed without the guard".
    async acquireTickLease(): Promise<{ acquired: boolean; token?: string }> {
      const cur = await this.state.storage.get<{ token: string; expiresAt: number }>("tickLease");
      const now = Date.now();
      if (cur && cur.expiresAt > now) return { acquired: false };
      const token = crypto.randomUUID();
      await this.state.storage.put("tickLease", { token, expiresAt: now + TICK_LEASE_MS });
      return { acquired: true, token };
    }

    // releaseTickLease frees the single-flight tick lease iff the caller holds the CURRENT token (the same
    // stale-token guard as releaseRunlogLock: a tick that stalled past its lease and was superseded by a newer
    // tick cannot free the newer tick's lease). A wrong or absent token is a harmless no-op. Never throws.
    async releaseTickLease(req: { token?: string }): Promise<{ ok: true }> {
      const cur = await this.state.storage.get<{ token: string; expiresAt: number }>("tickLease");
      if (cur && cur.token === req.token) await this.state.storage.delete("tickLease");
      return { ok: true };
    }

    // recordTickOutcome appends one cron-tick OUTCOME to the bounded ring (INFRA cron-green-but-passes-crash /
    // subrequest-budget-starved-tick; SCHED due-page-cap-truncation / coalesced-runs-invisible /
    // budget-estimate-overdraw-kill / single-missed-tick-undetected). The cron driver (drive()) POSTs a
    // TickReport at the END of each invocation, so a tick that reported "ok" but dispatched nothing, overdrew
    // its budget, or crashed a pass is durably visible. The DO stamps the time (never the Worker) and derives
    // the interval since the prior tick (a large gap = missed ticks). Pure clamping/append in appendTickOutcome.
    async recordTickOutcome(report: TickReport): Promise<{ ok: true }> {
      const ring = (await this.state.storage.get<TickOutcome[]>(TICK_OUTCOME_KEY)) ?? [];
      await this.state.storage.put(TICK_OUTCOME_KEY, appendTickOutcome(ring, report, Date.now()));
      return { ok: true };
    }

    // schedulerSignals returns the redaction-safe scheduler-liveness aggregate for the support pack: the
    // per-tick outcome ring (the false-green detector), the due-index parity snapshot (SCHED due-index-drift /
    // rebuild-partial-or-too-big), and the runlog counter + max run-history index (SCHED runlog-counter-reset).
    // Counts / flags / clamped timestamps only -- no id, name or value (no-custody). Best-effort per field.
    // It also returns (G040) the housekeeping-health counters + a parityStampStale flag, and (G095/G210) the
    // per-downpipe state-refusal stamps, both redaction-safe by construction (counts, closed enums, clamped ints,
    // and the customer's OWN downpipe label -- the same class the pack already carries in downpipes[]).
    async schedulerSignals(): Promise<{
      ticks: TickOutcome[];
      dueIndex: Record<string, unknown>;
      runlog: { counter: number; maxHistoryIndex: number };
      listCaps: { pageSize: number; maxPages: number; historyRings: number };
      storageFaults: StorageFaultCounter;
      schedHealth: SchedHealthCounters & { parityStampStale: boolean };
      stateRefusals: { total: number; truncated: boolean; downpipes: Array<StateRefusal & { downpipeId: string }> };
    }> {
      const ticks = (await this.state.storage.get<TickOutcome[]>(TICK_OUTCOME_KEY)) ?? [];
      const dueIndex = (await this.state.storage.get<Record<string, unknown>>(DUE_INDEX_HEALTH_KEY)) ?? {};
      // storageFaults (SCHED persist-state-storage-fault / INFRA do-value-size-limit): the DISTINCT cumulative
      // persist-state storage-fault counter, isolating the persist/storage-fault subset (and the value-too-large
      // sub-subset) from the generic tick sealErrors/passErrors. Zeroed when the persist path has never faulted.
      const storageFaults = (await this.state.storage.get<StorageFaultCounter>(STORAGE_FAULT_KEY)) ?? EMPTY_STORAGE_FAULTS;
      const counter = (await this.state.storage.get<number>("runlogCounter")) ?? 0;
      // The highest run index any downpipe's history ring records. runlog-counter-reset is detectable when the
      // global runlogCounter is LOWER than a run already recorded (a wiped/reset counter re-allocates indices
      // that collide with retained history). Bounded scan over the hist: prefix (the same ring the pack reads).
      let maxHistoryIndex = 0;
      const hist = await this.listAllByPrefix<RunHistoryEntry[]>("hist:");
      for (const arr of hist.values()) for (const row of arr) if (typeof row.index === "number" && row.index > maxHistoryIndex) maxHistoryIndex = row.index;
      // listCaps (INFRA do-list-pagination-cap): the platform per-list page size + the paging guard, alongside
      // a LIVE per-prefix entry count (the history-ring count, reusing the scan above). A fleet whose per-prefix
      // count approaches pageSize*maxPages risks silent truncation of the DO's own paged reads (and of the pack's
      // history/downpipe reads, which use the same listAllByPrefix). The diagnoser compares the live counts (this
      // historyRings + dueIndex.dpTotal + the bundle's downpipes.length) against pageSize*maxPages. Constants + a count.
      // schedHealth (G040): the housekeeping faults that are otherwise fully silent. parityStampStale is DERIVED:
      // the last parity-stamp WRITE failed more recently than the snapshot the dueIndex block above is serving,
      // so that snapshot is stale and must not be read as a fresh parity measurement.
      const schedHealthRaw = (await this.state.storage.get<SchedHealthCounters>(SCHED_HEALTH_KEY)) ?? EMPTY_SCHED_HEALTH;
      const schedHealth = schedHealthView(schedHealthRaw, dueIndex.at);
      // stateRefusals (G095/G210): the downpipes whose persisted record this engine REFUSED to read (a rollback
      // reading new-shape state, or a corrupt version stamp). Each is a downpipe that silently stopped producing
      // runs. Capped so a fleet-wide rollback cannot unbound the section; `total` reports the true count.
      const refusalKeys = await this.state.storage.list<StateRefusal>({ prefix: STATE_REFUSED_PREFIX, limit: STATE_REFUSED_READ_CAP + 1 });
      const refusals: Array<StateRefusal & { downpipeId: string }> = [];
      for (const [k, v] of refusalKeys) {
        if (refusals.length >= STATE_REFUSED_READ_CAP) break;
        const row = stateRefusalView(k.slice(STATE_REFUSED_PREFIX.length), v);
        if (row !== null) refusals.push(row);
      }
      return {
        ticks,
        dueIndex,
        runlog: { counter: Math.max(0, Math.floor(counter)), maxHistoryIndex },
        listCaps: { pageSize: DO_LIST_PAGE, maxPages: DO_LIST_MAX_PAGES, historyRings: hist.size },
        storageFaults,
        schedHealth,
        stateRefusals: { total: refusalKeys.size, truncated: refusalKeys.size > STATE_REFUSED_READ_CAP, downpipes: refusals },
      };
    }

    // alarm re-arms the timer when the next due time arrives. In this v1 the cron-driven
    // path in index.ts is the actual driver: on each tick it asks the DO for the due
    // downpipes (GET /due) and runs each out of the DO (trigger -> seal -> complete), so
    // the DO never seals inline (design F11). Precise alarm-driven dispatch (the alarm
    // itself invoking the seal handler via a service binding so sub-cron-interval cadences
    // are honoured) is a refinement that needs the engine wired as a service binding and
    // env passed to the DO; it is not done here, so scheduling precision is bounded by the
    // cron interval.
    async alarm(): Promise<void> {
      // Opportunistic housekeeping on each alarm wakeup: prune abandoned single-use IdP login records (an OIDC
      // /start or SAML /start whose callback/ACS never completed leaves an oidcstate:/samlreq: record behind).
      // The single-use + TTL check in consumeOidcState/consumeSamlRequest is the SECURITY guarantee (a stale
      // record can never mint a session); this is purely to stop DO storage growing without bound. Best-effort:
      // a sweep error must never break the alarm re-arm.
      try {
        const nowMs = Date.now();
        await sweepOidcStates(this.idpKv, nowMs);
        await sweepSamlRequests(this.idpKv, nowMs);
        // Prune expired SAML one-time-use assertion markers (value = notOnOrAfter; past that the marker is moot,
        // since a replayed assertion past its window already fails the Conditions check at consume).
        const seen = await this.state.storage.list<number>({ prefix: SEEN_ASSERTION_PREFIX });
        for (const [k, exp] of seen) if (typeof exp !== "number" || exp <= nowMs) await this.state.storage.delete(k);
        // Prune expired step-up artefacts (ASVS V7.5.1): single-use assertion challenges (the stepup: scope) and
        // the single-use step-up tokens. Both are single-use + TTL-checked at consume (the security guarantee);
        // this only bounds storage when a begin/finish was never followed by the matching consume.
        const stepupCh = await this.state.storage.list<PasskeyChallenge>({ prefix: `${PASSKEY_CHALLENGE_PREFIX}stepup:` });
        for (const [k, rec] of stepupCh) if (!rec || typeof rec.expiresAt !== "number" || rec.expiresAt <= nowMs) await this.state.storage.delete(k);
        const stepupTok = await this.state.storage.list<{ expiresAt: number }>({ prefix: STEPUP_TOKEN_PREFIX });
        for (const [k, rec] of stepupTok) if (!rec || typeof rec.expiresAt !== "number" || rec.expiresAt <= nowMs) await this.state.storage.delete(k);
      } catch {
        /* housekeeping is best-effort: a sweep error must never break the alarm re-arm. But a PERSISTENTLY
           failing sweep grows DO storage for months with zero evidence until the storage limits bite (G040), so
           COUNT it: a climbing sweepFaults count with a recent lastAt is the fact support needs to explain a DO
           that is quietly filling up. The counter write is itself best-effort and cannot throw. */
        await this.recordSchedHealth("sweep-fault");
      }
      await this.rearmAlarm();
      // DEP-04: the cron-independent staleness dead-man. This alarm is the ONE timer that survives a
      // deploy dropping [triggers].crons (which silences the cron-driven alert sweep AND the backups it
      // guards together), so AFTER re-arming it backstops the sweep, but ONLY when the cron has gone
      // silent (throttled in runCronDeadManSweep, so a healthy cron pays no sweep and never double-fires).
      // It is self-guarding (best-effort), so it can never break the re-arm above.
      await this.runCronDeadManSweep();
    }

    async rearmAlarm(): Promise<void> {
      // The due-time index is sorted by pad16(nextRunAt), so its FIRST key already names the globally-
      // earliest due time. Read just that one key (O(1)) instead of scanning the whole fleet (O(N)); the
      // index only ever holds enabled, numeric-nextRunAt downpipes, so the earliest key is the next alarm.
      const firstPage = await this.state.storage.list<unknown>({ prefix: DUE_INDEX_PREFIX, limit: 1 });
      const firstKey = firstPage.keys().next().value;
      if (firstKey === undefined) return;
      // Key shape is due:<pad16(nextRunAt)>:<id>; the 16-character pad16 block after the prefix is the time.
      const next = Number.parseInt(firstKey.slice(DUE_INDEX_PREFIX.length, DUE_INDEX_PREFIX.length + 16), 10);
      if (!Number.isFinite(next)) {
        // G188: A CORRUPT DUE-INDEX KEY STOPS THE ALARM CHAIN DEAD. Returning without setAlarm means this DO
        // never wakes again on its own -- and the alarm is the ONE timer that survives a deploy dropping
        // [triggers].crons, so the cron dead-man (which only runs at the END of alarm()) never fires either.
        // Both safety nets go at once, silently. Count it (a closed event + a time; never the key). A non-zero
        // count here is a first-class DATA-LOSS signal, not a scheduling quirk.
        await recordAlertingHealth(this.state.storage, "alarm-rearm-skipped-corrupt-key");
        return;
      }
      // Clamp the armed time so it is never in the past (XC-M8). A wedged enabled downpipe (a crash in
      // the narrow window between trigger and seal leaves it inFlight with a past-due nextRunAt that
      // only completion advances) would otherwise pin the min at a past time; setAlarm(past) fires
      // immediately and alarm() re-arms the same past value, a self-refire storm of zero-work wakeups.
      // Flooring to now + ALARM_MIN_DELAY_MS turns a past-due time into a single short-delayed wakeup.
      // The floor only bites a past or near-past time; a healthy pipe's nextRunAt is a full cadence
      // (>= 60s) out, so a genuine near-future alarm is never delayed. NOTE: the alarm only re-arms
      // and does not yet dispatch the seal (XC-M7); precise alarm-driven dispatch is a deferred
      // refinement that needs the engine wired as a service binding so the alarm callback can seal.
      const armAt = Math.max(next, Date.now() + ALARM_MIN_DELAY_MS);
      await this.state.storage.setAlarm(armAt);
    }

    // computeNextRunAt is the SINGLE place a downpipe's next nextRunAt is derived, used by both the
    // create/upsert path (addDownpipe) and the post-run path (completeRun). It dispatches on the
    // config's schedule:
    //   - schedule.cron present -> the next matching wall-clock minute in schedule.timeZone (via
    //     nextFireAfter), NOT jittered: a cron operator picked an exact minute ("fire at 02:00"), and
    //     +/-10% jitter on a daily cron would be hours, defeating the point. The cron's own minute
    //     granularity plus the per-downpipe phase already de-correlates a fleet enough.
    //   - no cron -> the cadenceSeconds path, with the existing backwards jitter (thundering-herd
    //     spread), byte-identical to before for every pre-existing config.
    // Then, on EITHER path, a computed fire that lands inside an active blackout window is deferred to
    // the first instant after the window. The cron computation is wrapped defensively: a schedule that
    // somehow reached here malformed (it cannot via the validated write path) falls back to the cadence
    // path rather than throwing inside the scheduler, so a bad schedule never wedges dispatch.
    // nextWithJitter now ALSO classifies the cron-resolution OUTCOME (SCHED cron-runtime-fallback-to-cadence /
    // invalid-tz-runtime / impossible-cron-runtime) so the caller can stamp it on the downpipe state for the
    // support pack. The returned `next` epoch is byte-identical to before for every case (cron-ok -> the cron
    // fire; any fault or no cron -> the jittered cadence; then deferPastBlackouts on either), so scheduling
    // behaviour is unchanged; only the diagnostic `cronResolve` class is new. cronResolve is null for a
    // cadence-only downpipe (nothing to resolve), so the caller CLEARS any stale stamp when the cron is removed.
    // It ALSO classifies the BLACKOUT-window resolution outcome (G322): a deferral that exhausts the hop ceiling
    // and fires INSIDE a declared change-freeze window, and a window saved with equal start/end minutes that
    // therefore covers nothing and has never applied, are both silent today (blackout windows are deliberately
    // never carried in the pack). The returned `next` epoch is byte-identical on every path; only the diagnostic
    // class is new. blackoutResolve is null for a downpipe with no windows, so the caller CLEARS a stale stamp.
    nextWithJitter(cadenceSeconds: number, schedule?: DownpipeSchedule): { next: number; cronResolve: CronResolve | null; blackoutResolve: BlackoutResolve | null } {
      const now = Date.now();
      let base: number;
      let cronResolve: CronResolve | null = null;
      if (schedule?.cron) {
        const tz = scheduleTimeZone(schedule);
        if (!isValidTimeZone(tz)) {
          // The stored IANA zone is not recognised by this runtime: nextFireAfter would throw here, so
          // classify tz-invalid and degrade to cadence WITHOUT running the (throwing) cron computation.
          base = jitteredCadence(now, cadenceSeconds);
          cronResolve = { class: "tz-invalid", at: now };
        } else {
          try {
            base = nextFireAfter(schedule.cron, now, tz);
            cronResolve = { class: "ok", at: now };
          } catch {
            // The zone is valid, so the throw is either an unparseable cron or a parseable-but-impossible one
            // (no next fire within the search bound). Distinguish the two by parsing (cheap), so the pack can
            // tell a typo'd expression from an impossible date. Either way we degrade to the plain cadence,
            // exactly as before (behaviour-preserving defence-in-depth).
            base = jitteredCadence(now, cadenceSeconds);
            let cls: CronResolveClass = "no-next-fire";
            try {
              parseCron(schedule.cron);
            } catch {
              cls = "cron-parse";
            }
            cronResolve = { class: cls, at: now };
          }
        }
      } else {
        base = jitteredCadence(now, cadenceSeconds);
      }
      const deferred = deferPastBlackoutsResolved(base, schedule);
      const hasWindows = (schedule?.blackoutWindows?.length ?? 0) > 0;
      return { next: deferred.at, cronResolve, blackoutResolve: hasWindows ? { class: deferred.class, at: now } : null };
    }
  };
}
