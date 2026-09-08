// engine-sys-struct-06 / engine-sys-arch-01 (god-module split): the SRE alerting subsystem (the
// on-call persona: backup-failure/stale and replication alert detection and reconciliation)
// extracted from the SchedulerDO god module into a mixin.
// SreAlertingMixin layers these over a base whose `this` is SchedulerDOSurface; dispatch and `this`
// binding are byte-identical. The alert-cooldown discipline and the classify/shouldAlert detection
// are unchanged, and the DO does NO network I/O at all (the Worker delivers).

import { ADMIN_COUNTERS_KEY, type AdminCounters, applyAdminCounters } from "../admin/diag-records.ts";
import { ALERT_COOLDOWN_MS, type AlertState, buildAlert, classify, classifyReplication, type DownpipeAlert, isRunEvictionRisk, type MinRun, NOTIFY_CHANNEL_PREFIX, type NotifyChannel, type NotifyEmission, type NotifyEvent, severityOf, shouldAlert } from "../notify.ts";
import { allDestinationIds, primaryDestinationId } from "./destinations.ts";
// G188: the alerting pipeline's OWN health. Every recorder below is best-effort and never throws, so the
// alert path it observes is behaviourally unchanged.
import { recordAlertingHealth } from "./sched-fault-ledger.ts";
import { ALERT_COOLDOWN_PREFIX, type AlertCooldown, CRON_ALERT_SWEEP_AT_KEY, CRON_DEADMAN_STALL_MS, CRON_DEADMAN_SWEEP_AT_KEY, CRON_DEADMAN_SWEEP_INTERVAL_MS, type DestReplState, RECENT_SUCCESS_WINDOW_MS, REPL_ALERT_COOLDOWN_PREFIX, type ReplAlertCooldown, RING_CAP, type RunHistoryEntry, type SchedulerDOCtor, SUCCESS_NOTIFIED_PREFIX } from "./scheduler-do-base.ts";
import { SOURCE_DRIFT_KEY, VOLUME_REGRESSION_KEY } from "./scheduler-do-records.ts";

// PendingRecovery marks a downpipe whose auto-resolve RECOVERY (the "incident cleared" close) failed to
// deliver, so the resolve is still OWED and must be retried on later reconciliation ticks until it lands, the
// downpipe relapses, or a time bound is hit (finding F4: a transient blip during recovery would otherwise
// strand a PagerDuty/JSM/ServiceNow incident open forever, since the falling edge fires exactly once). It is
// DELIBERATELY separate from AlertCooldown: the alert-cooldown lifecycle (deleted on the falling edge) stays
// pristine, so a relapse is a fresh transition and is never suppressed. It is written ONLY when the Worker
// reports a FAILED recovery delivery, so the happy path (delivered first time) records nothing and the
// emission path behaves exactly as before this feature. It lives here (its only consumer) rather than in the
// records leaf, which sits at its size budget.
export interface PendingRecovery {
  state: AlertState; // which alert state's incident the owed resolve closes (rebuilds the recovery on retry)
  at: number; // epoch ms of the FIRST failed delivery; the retry age bound reads this and never resets it
}

// PENDING_RECOVERY_PREFIX keys the per-downpipe owed-resolve markers, alongside alert:/repl-alert-cd:/etc.
export const PENDING_RECOVERY_PREFIX = "pending-recovery:";

// RECOVERY_RETRY_WINDOW_MS bounds how long an undelivered recovery is retried before it is given up
// (fail-open): long enough to ride a transient sink outage across several 15-minute cron ticks, short enough
// not to retry a permanently-dead sink forever. One hour matches the alert-cooldown horizon.
export const RECOVERY_RETRY_WINDOW_MS = 60 * 60 * 1000;

export function SreAlertingMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // ---- SRE alerting (the on-call persona): backup-failure/stale + replication detection ------
    // Detection decides WHETHER a downpipe is in an alertable state; WHERE the alert goes is the
    // notify-channel model (a channel plus a rule), and the Worker does the delivering. This mixin
    // therefore does no network I/O and holds no destination.

    // bumpReplicationCopyCountInvalid records G209's counter through the SAME bounded applier the Worker edge
  // posts to (applyAdminCounters is the redaction chokepoint: an out-of-vocabulary name is dropped and every
  // count is clamped), rather than opening a second, parallel aggregate. Best-effort by design: observing a
  // fault must never break the alerting path it observed, and a dropped diagnostic write of this kind is
  // itself already visible in the pack's droppedWrites caveat.
  async bumpReplicationCopyCountInvalid(): Promise<void> {
    try {
      const prior = await this.state.storage.get<AdminCounters>(ADMIN_COUNTERS_KEY);
      await this.state.storage.put(ADMIN_COUNTERS_KEY, applyAdminCounters(prior, { "replication-copy-count-invalid": 1 }, new Date().toISOString()));
    } catch {
      // best-effort: the alert still routes.
    }
  }

    // listAlertCooldowns is the redaction-safe read of the per-downpipe ALERT-COOLDOWN state (NOTIF:
    // cooldown-suppresses-renudge-1h). A persistently stale/failed downpipe pages ONCE and is then suppressed
    // for ALERT_COOLDOWN_MS, so after the first page a still-broken pipe leaves no fresh alert; this surfaces
    // WHICH downpipes are within a re-nudge cooldown and SINCE WHEN, for BOTH the staleness/failure stream
    // (alert:) and the 3-2-1 replication stream (repl-alert-cd:), so "why didn't I get re-alerted about a
    // still-broken pipe" is answerable (it alerted at `at` and is suppressed until at + cooldownMs). It reads
    // ONLY the closed cooldown records: the customer's own downpipe id (the storage-key suffix), a closed
    // state enum, and an epoch ms; never a secret, key, value, or detail. Bounded by the downpipe count.
    async listAlertCooldowns(): Promise<{ cooldownMs: number; alert: Array<{ downpipeId: string; state: AlertState; at: number }>; replication: Array<{ downpipeId: string; state: ReplAlertCooldown["state"]; at: number }> }> {
      const alertMap = await this.listAllByPrefix<AlertCooldown>(ALERT_COOLDOWN_PREFIX);
      const replMap = await this.listAllByPrefix<ReplAlertCooldown>(REPL_ALERT_COOLDOWN_PREFIX);
      const alert = [...alertMap.entries()].map(([key, v]) => ({ downpipeId: key.slice(ALERT_COOLDOWN_PREFIX.length), state: v.state, at: v.at }));
      const replication = [...replMap.entries()].map(([key, v]) => ({ downpipeId: key.slice(REPL_ALERT_COOLDOWN_PREFIX.length), state: v.state, at: v.at }));
      return { cooldownMs: ALERT_COOLDOWN_MS, alert, replication };
    }

    // reconcileSourceDrift is the EDGE-TRIGGER behind the proactive "source-detached" alert. The Worker's
    // source-drift cron pass computes the CURRENT set of configured-but-unbound source binding names (the
    // live env bindings vs the roster) and passes it here; this diffs it against the stored marker (the
    // names already alerted as detached), returns the NEWLY detached ones (so the Worker routes EXACTLY ONE
    // alert per new detach, never every tick), then REWRITES the marker to the current set so a re-attached
    // binding CLEARS (its absence re-arms the alert) and a later re-detach fires again. The source mirror of
    // reconcileAlerts' cooldown: one storage read + at most one write, idempotent on a stable set, and NO
    // network I/O (the Worker delivers). It carries ONLY binding NAMES (the customer's own redaction-safe
    // operational data); it cannot reach a key, a value, or a secret. The missing set is small (bounded by
    // the engine's source bindings), so the single-key string[] stays cheap.
    async reconcileSourceDrift(missing: string[]): Promise<{ newlyDetached: string[] }> {
      const current = [...new Set((Array.isArray(missing) ? missing : []).filter((b): b is string => typeof b === "string" && b !== ""))].sort();
      const prior = (await this.state.storage.get<string[]>(SOURCE_DRIFT_KEY)) ?? [];
      const priorSet = new Set(prior);
      const newlyDetached = current.filter((b) => !priorSet.has(b));
      // Rewrite the marker to EXACTLY the current set when it changed (a grow OR a shrink), so a re-attach
      // clears and a re-detach re-arms; skip the write when unchanged so a steady state costs only the read.
      if (current.length !== prior.length || current.some((b, i) => b !== prior[i])) {
        await this.state.storage.put(SOURCE_DRIFT_KEY, current);
      }
      return { newlyDetached };
    }

    // reconcileVolumeRegression is the EDGE-TRIGGER behind the retention "backup-volume-regression" alert, the
    // volume-guard sibling of reconcileSourceDrift. The retention prune pass computes the CURRENT set of
    // downpipe ids whose volume high-water run the guard HELD (retention refused to evict the last FULL backup
    // for smaller/empty runs) and passes it here; this diffs it against the stored marker (the ids already
    // alerted as regressed), returns the NEWLY regressed ones (so the Worker routes EXACTLY ONE alert per new
    // regression, never every tick), then REWRITES the marker to the current set so a downpipe whose volume
    // RECOVERED clears (its absence re-arms the alert) and a later re-regression fires again. One storage read
    // + at most one write, idempotent on a stable set, and NO network I/O (the Worker delivers). It carries
    // ONLY downpipe ids (the customer's own redaction-safe identifiers); it cannot reach a key, value, or
    // secret. The set is small (bounded by the retention-configured downpipes), so the single-key string[] stays cheap.
    async reconcileVolumeRegression(regressed: string[]): Promise<{ newlyRegressed: string[] }> {
      const current = [...new Set((Array.isArray(regressed) ? regressed : []).filter((d): d is string => typeof d === "string" && d !== ""))].sort();
      const prior = (await this.state.storage.get<string[]>(VOLUME_REGRESSION_KEY)) ?? [];
      const priorSet = new Set(prior);
      const newlyRegressed = current.filter((d) => !priorSet.has(d));
      // Rewrite the marker to EXACTLY the current set when it changed (a grow OR a shrink), so a recovery
      // clears and a re-regression re-arms; skip the write when unchanged so a steady state costs only the read.
      if (current.length !== prior.length || current.some((d, i) => d !== prior[i])) {
        await this.state.storage.put(VOLUME_REGRESSION_KEY, current);
      }
      return { newlyRegressed };
    }

    // reconcileAlerts is the INTERNAL detection tick the cron driver calls each reconciliation. It is
    // a no-op (returns an empty batch) when no notify channel is configured, so the cost of running it
    // is one storage list in the common unconfigured case. Otherwise it computes, for every downpipe,
    // whether it is NEWLY stale/failed (transition-based) and not within its per-downpipe cooldown, builds
    // the redaction-safe alert lines, RECORDS the new last-alerted state for each alerted downpipe (so the
    // next tick does not re-spam), and CLEARS the cooldown record for any downpipe that has recovered
    // (so a future relapse alerts immediately). It returns the alert batch and pendingTransitionIds for
    // the Worker to route out-of-band; the DO does no network I/O itself (the same separation as the
    // seal, design F11), which keeps delivery's fail-open behaviour entirely in the Worker and means a DO
    // storage op here can never be blocked on a customer's slow endpoint.
    //
    // Two-phase delivery (Fix 1: first-alert retry). Cooldowns for STATE-TRANSITION alerts (where
    // lastAlertedState !== the new state, i.e. the FIRST notification of a brand-new failure or a
    // stale<->failed flip) are recorded OPTIMISTICALLY here so the reconciliation is atomic, but those
    // downpipe ids are returned in pendingTransitionIds. After the Worker delivers and learns
    // whether delivery succeeded, it calls POST /alerts-delivered. That route clears the cooldown for
    // any id in failedTransitionIds so the NEXT tick re-attempts delivery rather than suppressing it
    // for the full cooldown window. A same-state re-nudge (still broken, within the cooldown) keeps
    // its cooldown regardless of delivery outcome: re-nudge storms are the signal worth suppressing.
    //
    // It carries ONLY the customer's own redaction-safe operational data (downpipe id/name/state and
    // the last run's id/time); it cannot reach a key, a value, a selector, or a binding name.
    //
    // AUTO-RESOLVE (mon-autoresolve, M3): the RECOVERY mirror of the alert stream. `recoveries` carries
    // one NotifyEmission per downpipe that just crossed back to healthy (the falling edge of the SAME
    // cooldown this method already tracked), built where the cooldown used to be silently deleted below.
    // See that branch for the exactly-once + severity-parity reasoning.
    async reconcileAlerts(): Promise<{ alerts: DownpipeAlert[]; pendingTransitionIds: string[]; successes: NotifyEmission[]; recoveries: NotifyEmission[]; pendingRecoveryIds: string[] }> {
      // Detection runs when there is somewhere to deliver: at least one configured notify channel. The
      // common UNconfigured case short-circuits to an empty batch for one storage list.
      const channelCount = (await this.state.storage.list<NotifyChannel>({ prefix: NOTIFY_CHANNEL_PREFIX })).size;
      if (channelCount === 0) {
        // G188: DETECTION IS NOW OFF, and the short-circuit says so to nobody. A tenant that deletes its last
        // notify channel silently stops detecting staleness and failure entirely -- the pack shows an empty
        // alert history that is indistinguishable from a healthy fleet. Count the off-pass (a closed event, no
        // channel address, no url) so "why did no staleness alert ever fire" is answerable from the pack.
        await recordAlertingHealth(this.state.storage, "detection-off-no-sink");
        return { alerts: [], pendingTransitionIds: [], successes: [], recoveries: [], pendingRecoveryIds: [] };
      }
      const now = Date.now();
      const downpipes = await this.listDownpipes();
      // Bulk-read the three per-downpipe prefixes ONCE via paginated prefix scans instead of three
      // sequential storage.get round trips inside the loop. This turns O(3N) sequential reads (which
      // the single-threaded DO cannot parallelise) into O(1) prefix scans plus in-memory map lookups,
      // so the reconciliation tick stays cheap as the per-account downpipe count grows.
      const cooldownMap = await this.listAllByPrefix<AlertCooldown>(ALERT_COOLDOWN_PREFIX);
      const histMap = await this.listAllByPrefix<RunHistoryEntry[]>("hist:");
      const successMap = await this.listAllByPrefix<string>(SUCCESS_NOTIFIED_PREFIX);
      // Owed-resolve markers (finding F4): a downpipe here has a recovery whose delivery previously failed, so
      // the resolve must be retried until it lands, the downpipe relapses, or it ages out. Bulk-read once.
      const pendingRecoveryMap = await this.listAllByPrefix<PendingRecovery>(PENDING_RECOVERY_PREFIX);
      const alerts: DownpipeAlert[] = [];
      const pendingTransitionIds: string[] = [];
      const successes: NotifyEmission[] = [];
      const recoveries: NotifyEmission[] = [];
      const pendingRecoveryIds: string[] = [];
      // alertedThisTick / recoveredThisTick let the retry loop below drop an owed-resolve marker that this
      // tick already superseded (a relapse re-opened the incident, or a fresh falling edge re-emitted its
      // close). nameById lets the retry loop rebuild a recovery for a still-healthy downpipe by id.
      const alertedThisTick = new Set<string>();
      const recoveredThisTick = new Set<string>();
      const nameById = new Map(downpipes.map((d) => [d.config.id, d.config.name] as const));
      // buildRecoveryEmission is the ONE place a recovery (auto-resolve close) emission is shaped, shared by
      // the falling-edge branch and the F4 retry loop so a retried resolve is byte-identical to the first
      // attempt (same event -> same PagerDuty dedup_key, so the retry closes the same incident).
      const buildRecoveryEmission = (state: AlertState, id: string, name: string): NotifyEmission => {
        const event: NotifyEvent = state === "failed" ? "backup-failure" : "backup-stale";
        const detail = state === "failed" ? `${name}: the last run succeeded; the previous failure has cleared` : `${name}: a recent run succeeded; the staleness has cleared`;
        return { event, severity: severityOf(event), downpipeId: id, downpipeName: name, detail, at: new Date(now).toISOString(), recovered: true };
      };
      for (const ds of downpipes) {
        const cooldownKey = `${ALERT_COOLDOWN_PREFIX}${ds.config.id}`;
        const cooldown = cooldownMap.get(cooldownKey) ?? null;
        // The detector reads only the redaction-safe subset of the run-history ring (status + start
        // time + run id), newest-LAST as stored. An absent ring is an empty history (a pending pipe).
        const ring = histMap.get(`hist:${ds.config.id}`) ?? [];
        // An abandoned run (a crashed run reclaimed by the lease) is failure-like for staleness: it must
        // NOT reset the last-success clock, so it maps to "failed" for the classifier's MinRun view. The
        // full RunHistoryEntry keeps the distinct "abandoned" status for the console display.
        const history: MinRun[] = ring.map((h) => ({ runId: h.runId, startedAt: h.startedAt, status: h.status === "abandoned" ? "failed" : h.status, ...(h.recordsIncomplete !== undefined ? { recordsIncomplete: h.recordsIncomplete } : {}) }));
        const detectionInput = {
          config: { id: ds.config.id, name: ds.config.name, cadenceSeconds: ds.config.cadenceSeconds, enabled: ds.config.enabled },
          history,
          ...(cooldown ? { lastAlertedState: cooldown.state, lastAlertedAt: cooldown.at } : {}),
        };
        const toAlert = shouldAlert(detectionInput, now);
        if (toAlert !== null) {
          alerts.push(buildAlert({ id: ds.config.id, name: ds.config.name }, history, toAlert));
          // Determine whether this is a STATE TRANSITION: a new alertable state the customer has not
          // been warned about yet (lastAlertedState !== toAlert). A transition alert is the highest
          // priority case: the on-call feature failing on the very first notification of a brand-new
          // failure is the scenario it exists to cover. We record the cooldown optimistically (so the
          // reconciliation is a single storage pass and concurrent ticks do not both fire), but we
          // add the id to pendingTransitionIds so the Worker can clear it on delivery failure.
          // A same-state re-nudge (persistently broken, still within the cooldown window, already
          // warned in this state) keeps its cooldown regardless: the re-nudge is advisory; a missed
          // nudge is acceptable. The storm-prevention logic must not be defeated by delivery failures
          // on re-nudges, which is a much less critical path.
          const isTransition = cooldown === null || cooldown.state !== toAlert;
          await this.state.storage.put(cooldownKey, { state: toAlert, at: now } satisfies AlertCooldown);
          if (isTransition) pendingTransitionIds.push(ds.config.id);
          // This downpipe is alerting again: any owed resolve from a prior recovery is superseded (the
          // incident is re-opened by this trigger). The F4 retry loop drops its marker (never suppressed).
          alertedThisTick.add(ds.config.id);
        } else if (cooldown !== null && classify(detectionInput, now) === null) {
          // The downpipe has RECOVERED (it was alerted before and is now healthy). AUTO-RESOLVE
          // (mon-autoresolve): emit the recovery on this FALLING EDGE, exactly once, before clearing the
          // cooldown that gated it -- the cooldown IS the "prior firing condition" state (nothing new to
          // persist), so once it is deleted a still-healthy downpipe has nothing left to re-fire from on
          // a later tick, and a fresh relapse starts a fresh transition as before.
          //
          // The recovery reuses the SAME event (mapped from the cleared cooldown.state) and the SAME
          // downpipeId the trigger used, with recovered:true, so deliverToChannel -> the PagerDuty
          // adapter sends event_action:"resolve" keyed on the IDENTICAL dedup_key
          // (`downpipe:<id>:<event>`) the trigger used, auto-closing that incident. severityOf is
          // deterministic for both AlertStates (backup-failure is always critical, backup-stale is
          // always warning; neither is ever escalated, unlike run-at-risk-eviction below), so
          // recomputing it here reproduces EXACTLY the severity the trigger used -- which is what
          // guarantees the recovery clears the same rule minSeverity bar the trigger did (it reaches
          // every channel the trigger reached, not just the ones matching a lower default severity).
          //
          // Two-phase retry (finding F4): the recovery is still EMITTED once here on the falling edge and the
          // cooldown deleted exactly as before (so a relapse is a fresh transition, never suppressed). What
          // changed is the delivery is no longer fire-and-forget: the Worker reports the outcome, and a FAILED
          // recovery delivery writes a pending-recovery marker (recordRecoveryDelivery) that the retry loop
          // below re-emits on later ticks until the resolve lands, the downpipe relapses, or it ages out --
          // so a transient blip during recovery can no longer strand a PagerDuty/JSM/ServiceNow incident open.
          // The emission reuses the SAME event + downpipeId the trigger used (recovered:true), so the resolve
          // is keyed on the IDENTICAL dedup_key and closes that exact incident; severityOf is deterministic
          // for both states so it clears the same rule minSeverity bar the trigger did.
          recoveries.push(buildRecoveryEmission(cooldown.state, ds.config.id, ds.config.name));
          recoveredThisTick.add(ds.config.id);
          await this.state.storage.delete(cooldownKey);
        }

        // Newly-succeeded run (transition-based, the success mirror of the failure cooldown above): when
        // the NEWEST RESOLVED run is ok and its runId has not been emitted yet, emit ONE backup-success.
        // Bounded to a genuinely RECENT success so this detector going live (or a channel being wired)
        // never back-fires a burst of "succeeded" notices for old runs; the marker is updated either way,
        // so an old success is silenced once and a new one fires exactly once. A disabled downpipe is
        // never emitted. The Worker delivers (same DO/Worker separation as the alert stream).
        let latestOkRun: MinRun | undefined;
        for (let i = history.length - 1; i >= 0; i--) {
          const h = history[i];
          if (h === undefined || h.status === "in-flight") continue;
          if (h.status === "ok") latestOkRun = h;
          break; // the newest resolved run; only a success is a backup-success candidate
        }
        if (latestOkRun !== undefined) {
          const successKey = `${SUCCESS_NOTIFIED_PREFIX}${ds.config.id}`;
          const lastNotifiedRunId = successMap.get(successKey) ?? null;
          if (lastNotifiedRunId !== latestOkRun.runId) {
            const startedMs = Date.parse(latestOkRun.startedAt);
            const recent = Number.isFinite(startedMs) && now - startedMs <= RECENT_SUCCESS_WINDOW_MS;
            if (recent && ds.config.enabled) {
              // R1-1: a run that sealed incompleteness sentinels (markers, not the real bytes) is NOT a
              // clean success: surface the count in the detail so the operator sees the backup is short of
              // the live source rather than reading a bare "succeeded". The count is redaction-safe.
              const incomplete = latestOkRun.recordsIncomplete ?? 0;
              const detail = incomplete > 0
                ? `${ds.config.name} backup completed with ${incomplete} item${incomplete === 1 ? "" : "s"} not fully captured`
                : `${ds.config.name} backup succeeded`;
              successes.push({
                event: "backup-success",
                severity: "info",
                downpipeId: ds.config.id,
                downpipeName: ds.config.name,
                detail,
                at: new Date(now).toISOString(),
              });
            }
            await this.state.storage.put(successKey, latestOkRun.runId);
          }
        }
      }
      // RECOVERY RETRY LOOP (finding F4). Re-emit an owed resolve for a downpipe whose recovery delivery
      // previously FAILED (a pending-recovery marker exists) and which is still healthy this tick, so a
      // transient blip during recovery cannot strand an incident open. This loop is INERT on the happy path:
      // a marker is written only by the Worker's failed-delivery report (recordRecoveryDelivery), so a
      // recovery that delivered first time leaves nothing here. Precedence, per marker:
      //   - superseded THIS tick (the downpipe re-alerted, or a fresh falling edge already re-emitted its
      //     close): drop the marker -- the newer signal owns the incident now;
      //   - aged out past the retry window: give up (fail-open, never retry a dead sink forever);
      //   - the downpipe no longer exists: drop the orphan marker;
      //   - otherwise still healthy with an owed resolve: re-emit the recovery and keep the marker (the
      //     Worker will clear it on a successful delivery, or leave it for the next tick on another failure).
      for (const [key, marker] of pendingRecoveryMap) {
        const id = key.slice(PENDING_RECOVERY_PREFIX.length);
        if (alertedThisTick.has(id) || recoveredThisTick.has(id)) {
          await this.state.storage.delete(key);
          continue;
        }
        if (now - marker.at > RECOVERY_RETRY_WINDOW_MS) {
          // G188: THE OWED RESOLVE IS BEING ABANDONED. The backup recovered, the close was owed, delivery kept
          // failing, and the marker is deleted here -- so the customer's incident stays open forever and the
          // one record that explained it is destroyed in the same statement. Count the abandonment (a closed
          // event + a time; no downpipe id, no channel) before the delete: "the incident never auto-closed
          // even though the backup recovered" is otherwise unanswerable.
          await recordAlertingHealth(this.state.storage, "abandoned-recovery-resolve");
          await this.state.storage.delete(key);
          continue;
        }
        const name = nameById.get(id);
        if (name === undefined) {
          await this.state.storage.delete(key);
          continue;
        }
        recoveries.push(buildRecoveryEmission(marker.state, id, name));
        pendingRecoveryIds.push(id);
      }
      return { alerts, pendingTransitionIds, successes, recoveries, pendingRecoveryIds };
    }

    // markAlertsDelivered is the two-phase callback the Worker calls after it has attempted the
    // POST. deliveredIds is informational (the cooldown is already written; the delivered case is the
    // happy path and needs no correction). failedTransitionIds lists any state-TRANSITION alerts that
    // were not delivered; the DO deletes their cooldown records so the NEXT reconciliation tick
    // re-qualifies them (lastAlertedState will be absent again and shouldAlert fires immediately).
    // Same-state re-nudge failures are NOT passed here (their ids are not in pendingTransitionIds) and
    // their cooldowns are intentionally kept (storm prevention). This method is fail-open: unknown ids
    // are silently ignored (a no-op delete is fine), and any storage error is swallowed by the caller's
    // outer try/catch in drive(). It never throws on its own.
    async markAlertsDelivered(req: { deliveredIds?: string[]; failedTransitionIds?: string[] }): Promise<{ cleared: number }> {
      const failed = Array.isArray(req.failedTransitionIds) ? req.failedTransitionIds : [];
      let cleared = 0;
      for (const id of failed) {
        if (typeof id === "string" && id.length > 0) {
          await this.state.storage.delete(`${ALERT_COOLDOWN_PREFIX}${id}`);
          cleared++;
        }
      }
      return { cleared };
    }

    // recordRecoveryDelivery is the two-phase callback the Worker calls after attempting the auto-resolve
    // RECOVERY batch (finding F4), the recovery mirror of markAlertsDelivered. deliveredIds clear any owed-
    // resolve marker (the resolve landed -> stop retrying). `failed` lists the recoveries whose delivery
    // FAILED, each with the alert state its resolve closes: the FIRST failure writes a pending-recovery
    // marker (so reconcileAlerts re-emits on later ticks until it lands, the downpipe relapses, or it ages
    // out); a REPEAT failure keeps the existing marker so its `at` -- the retry-window anchor -- never resets.
    // Fail-open, like markAlertsDelivered: unknown ids are no-ops, an unrecognised state is skipped, and any
    // storage error is swallowed by the caller's outer try/catch. It never throws on its own.
    async recordRecoveryDelivery(req: { deliveredIds?: string[]; failed?: Array<{ id?: unknown; state?: unknown }> }): Promise<{ cleared: number; owed: number }> {
      let cleared = 0;
      const delivered = Array.isArray(req.deliveredIds) ? req.deliveredIds : [];
      for (const id of delivered) {
        if (typeof id === "string" && id.length > 0 && (await this.state.storage.delete(`${PENDING_RECOVERY_PREFIX}${id}`))) cleared++;
      }
      let owed = 0;
      const failed = Array.isArray(req.failed) ? req.failed : [];
      for (const f of failed) {
        const id = typeof f?.id === "string" ? f.id : "";
        const state = f?.state;
        if (id.length === 0 || (state !== "failed" && state !== "stale")) continue;
        const key = `${PENDING_RECOVERY_PREFIX}${id}`;
        // Write on the FIRST failure only; a repeat failure keeps the original marker (its `at` anchors the
        // retry window, so a persistently-down sink is given up a bounded time after the FIRST failure, not
        // perpetually re-armed).
        if ((await this.state.storage.get<PendingRecovery>(key)) === undefined) {
          await this.state.storage.put(key, { state, at: Date.now() } satisfies PendingRecovery);
          owed++;
        }
      }
      return { cleared, owed };
    }

    // runCronDeadManSweep is the DEP-04 cron-independent staleness dead-man (the dead-man's-dead-man),
    // run from the SchedulerDO's own platform alarm() AFTER its housekeeping + rearmAlarm. The whole
    // staleness/failure alert sweep (reconcileAlerts) is otherwise driven ONLY by the Worker cron
    // (scheduled() -> drive() -> runAlertPass -> POST /reconcile-alerts), so a deploy that drops a
    // downpipe's [triggers].crons silences the backups AND their staleness detector together (the detector
    // is co-resident with, and driven by, the very heartbeat it monitors). The DO alarm is the one timer
    // that survives such a deploy, so it backstops the sweep when, and ONLY when, the cron has gone silent.
    //
    // THROTTLE (no redundant load when the cron is healthy):
    //   - It reads the cron heartbeat (CRON_ALERT_SWEEP_AT_KEY, stamped only by the /reconcile-alerts
    //     route). While the cron is driving, now - lastCron stays within CRON_DEADMAN_STALL_MS and this
    //     returns immediately after ONE storage read, so a healthy cron pays no sweep and never double-fires.
    //   - Once the cron looks dead it throttles ITS OWN cadence to CRON_DEADMAN_SWEEP_INTERVAL_MS: the alarm
    //     re-fires ~1 Hz while downpipes sit overdue (rearmAlarm floors a past-due time to now+min-delay), so
    //     without this it would sweep every wakeup; instead it stands in for the missing */15 tick.
    //
    // DELIVERY (the honest limit of an INTERNAL dead-man): the DO has no env (its constructor takes only
    // `state`), so it cannot reach the env-bound notify-channel adapters (Slack/email/webhook channels) the
    // Worker delivers through, and it therefore DELIVERS NOTHING. It detects, records the trip and the
    // undeliverable batch, and ROLLS BACK the optimistic transition cooldowns (exactly as runAlertPass does
    // on a failed transition) so the eventual cron-driven alert is NOT suppressed. This is THE residual that
    // argues for an EXTERNAL monitor as the primary control; the internal dead-man is a detector, not a pager.
    //
    // The alert COOLDOWN (reused, unchanged) does all the de-duplication: reconcileAlerts records it
    // optimistically and shouldAlert suppresses a re-nudge within ALERT_COOLDOWN_MS, so even if the cron
    // resumes and both paths sweep near each other the alert fires once, never twice. Fully best-effort: a
    // storage or delivery fault is swallowed so the dead-man can never break the alarm re-arm (already done).
    async runCronDeadManSweep(): Promise<void> {
      try {
        const now = Date.now();
        // Cron-liveness gate: a recent cron-driven sweep means the detector is alive -> do nothing (one read).
        const lastCron = (await this.state.storage.get<number>(CRON_ALERT_SWEEP_AT_KEY)) ?? 0;
        if (now - lastCron <= CRON_DEADMAN_STALL_MS) return;
        // The cron looks dead. Self-throttle so the ~1 Hz alarm re-fire does not sweep every wakeup; stand in
        // for the missing cron at its own cadence. A first-ever backstop (no marker) reads 0 and proceeds.
        const lastSweep = (await this.state.storage.get<number>(CRON_DEADMAN_SWEEP_AT_KEY)) ?? 0;
        if (now - lastSweep < CRON_DEADMAN_SWEEP_INTERVAL_MS) return;
        await this.state.storage.put(CRON_DEADMAN_SWEEP_AT_KEY, now);
        // G188: THE DEAD-MAN HAS TRIPPED. Reaching here means the cron driver has been silent past
        // CRON_DEADMAN_STALL_MS -- backups are not being dispatched and the alert sweep is not being driven --
        // and the backstop DETECTED it, stood in for it, and recorded nothing. This counter (a closed event +
        // the trip time) IS the pack's cron-driver-silent signal, and it is the fact behind "our engine went
        // quiet for six hours and nothing told us". Recorded BEFORE the sweep, so a sweep that then faults
        // still leaves the trip on record.
        await recordAlertingHealth(this.state.storage, "cron-deadman-tripped");
        // Run the SAME sweep the cron runs. reconcileAlerts records cooldowns and returns the newly
        // stale/failed batch plus the transition ids (its behaviour is unchanged; this is just a second,
        // throttled caller). No channels -> it short-circuits to an empty batch (one list).
        // `successes` and `recoveries` are deliberately NOT destructured: like the alerts below, both need
        // the env-bound notify-channel adapters (Slack/email/PagerDuty/...) this env-free backstop cannot
        // reach (see above). The cron-driven runAlertPass (which HAS env) delivers all three once it resumes.
        const { alerts, pendingTransitionIds } = await this.reconcileAlerts();
        if (alerts.length === 0) return;
        // G188: THE BATCH REACHED NO SINK, and it never can from here. The env-free backstop holds no channel
        // adapter, so a batch it detects during a cron outage is GENERATED and then DISCARDED: the customer
        // gets zero pages and, without this counter, the pack would show nothing at all. Count the
        // undeliverable batch (a count; never a channel address or a url).
        await recordAlertingHealth(this.state.storage, "undeliverable-alert-batch");
        // Two-phase feedback, identical to runAlertPass on a failed delivery: clear the optimistic cooldowns
        // for the TRANSITION alerts so the next sweep (this backstop, or the cron once it resumes) re-fires
        // immediately rather than suppressing for the full cooldown window. A same-state re-nudge (no
        // transition) is not rolled back, mirroring the cron path.
        if (pendingTransitionIds.length > 0) {
          await this.markAlertsDelivered({ failedTransitionIds: pendingTransitionIds });
        }
      } catch {
        // Best-effort: a storage/delivery fault must never escape into alarm() (rearmAlarm already ran).
        // G188: but a fault INSIDE the backstop is exactly the "the dead-man was dead too" case, and it hit a
        // BARE catch. Count it (the class only, never the throw). Guarded again: the recorder never throws,
        // and even if storage is fully down this cannot escape into alarm().
        try {
          await recordAlertingHealth(this.state.storage, "deadman-sweep-fault");
        } catch {
          /* the store is down; the tick ring's missed-interval gap remains the evidence */
        }
      }
    }

    // reconcileReplicationAlerts is the INTERNAL replication-health detection tick the cron driver calls
    // each reconciliation, the 3-2-1 sibling of reconcileAlerts. It detects, per FAN-OUT downpipe (one
    // with two or more configured destinations), two redundancy conditions from the DO's own state (no
    // destination I/O): the proven off-site copy set falling BELOW the configured count
    // (replication-degraded), and a still-lagging copy whose missing run is about to roll off the fixed
    // RING_CAP run-history ring (run-at-risk-eviction). A single-destination downpipe has no off-site
    // redundancy to lose, so it is skipped. It mirrors reconcileAlerts exactly: transition-based (it pages
    // once when a downpipe first enters a replication-alert state, escalating when it crosses from
    // degraded into at-risk), cooldown-throttled (one re-nudge per ALERT_COOLDOWN_MS via the per-downpipe
    // repl-alert-cd: record), and it RECORDS the cooldown OPTIMISTICALLY and returns the transition ids in
    // pendingTransitionIds so the Worker can clear a cooldown whose delivery failed (the same two-phase
    // discipline as reconcileAlerts; the Worker re-uses markAlertsDelivered with a SEPARATE prefix below).
    // A downpipe that has recovered to neither condition has its cooldown cleared so a future relapse
    // alerts immediately. It does NO network I/O (the DO never reaches a customer endpoint) and returns
    // redaction-safe emissions only: the downpipe id/name plus the configured/proven copy counts (and, for
    // an at-risk run, which run index is closing), never a destination secret, key, value or fingerprint.
    //
    // Proven-copy accounting (the HONEST limb): provenCopies is the size of the set of destinations PROVEN
    // to hold the latest resolved successful run. The run's recorded ORIGIN destination is always proven
    // (the seal wrote it there). Every OTHER destination is proven only when its DestReplState.holdsIndex
    // is at or past that run's account-global index (the replicate backlog advances holdsIndex only to the
    // highest CONTIGUOUS run a destination holds, so holdsIndex >= latestIndex truthfully means it holds
    // that run). configuredCopies is allDestinationIds(config).length. classifyReplication compares the two.
    // run-at-risk-eviction fires only when the ring is at RING_CAP and a lagging destination's holdsIndex is
    // below the ring head (the oldest live run index, the next to be evicted): once that run rolls off, the
    // window to reconcile the lagging copy for it has closed. It escalates to critical when eviction would
    // leave only a single proven copy (the origin alone).
    //
    // AUTO-RESOLVE (mon-autoresolve, M3): `recoveries` carries one NotifyEmission per downpipe whose HELD
    // degraded/at-risk cooldown CLEARS, emitted at EVERY one of the three clear sites so a prior trigger's
    // PagerDuty incident is never stranded open: recovered-to-fully-proven (the main falling edge below), a
    // fan-out edited back to a single destination (the alert no longer applies), and no-assessable-run (no
    // ok run to reason about) -- each reuses the cooldown's own event + persisted severity so the dedup_key
    // resolves the exact incident the trigger opened. This is ALSO where the brief's "destination unreachable -> now healthy"
    // condition lives: this codebase has no separate "destination-unreachable" NotifyEvent (a raw per-
    // destination reachability signal, DestReplState.lastOk, feeds only the console's "down" indicator
    // today; see support-sections-seal.ts), and an unreachable replica is the common ROOT CAUSE of
    // replication-degraded (a stuck mirror never advances holdsIndex, so the proven-copy count falls
    // short). Recovering fully-proven here means every configured destination is reachable and caught up
    // again, so the recovery detail says so explicitly. A separate stand-alone event was deliberately NOT
    // added: it would page a SECOND time for the same underlying fault replication-degraded already
    // reports (the flapping/noise the brief says not to introduce), and a new NotifyEvent would need the
    // testEventWiringCompleteness extension the brief flags -- reusing the existing event stays inside the
    // "recovery = same event + recovered:true" recipe the trigger side already proves out. A raw per-
    // destination reachability signal is better exposed as a metric (downpipe_destination_healthy, the
    // sibling mon-metrics Prometheus build) than a second incident stream.
    async reconcileReplicationAlerts(): Promise<{ emissions: NotifyEmission[]; pendingTransitionIds: string[]; recoveries: NotifyEmission[] }> {
      // Same short-circuit as reconcileAlerts: detection runs only when there is SOMEWHERE to deliver (at
      // least one notify channel), so the common unconfigured account costs one list.
      const channelCount = (await this.state.storage.list<NotifyChannel>({ prefix: NOTIFY_CHANNEL_PREFIX })).size;
      if (channelCount === 0) {
        // G188: the replication half of the same detection-off short-circuit (the one that would have told the
        // customer a replica has stopped keeping up). Same closed event, same counter.
        await recordAlertingHealth(this.state.storage, "detection-off-no-sink");
        return { emissions: [], pendingTransitionIds: [], recoveries: [] };
      }
      const now = Date.now();
      const downpipes = await this.listDownpipes();
      // Bulk-read the three per-downpipe prefixes ONCE (cooldown, run-history ring, repl state) instead
      // of three sequential storage.get round trips per downpipe, the same O(1)-scan optimisation as
      // reconcileAlerts. The single-threaded DO cannot parallelise the per-downpipe gets, so the prefix
      // scans keep this cron tick cheap as the per-account downpipe count grows.
      const cooldownMap = await this.listAllByPrefix<ReplAlertCooldown>(REPL_ALERT_COOLDOWN_PREFIX);
      const histMap = await this.listAllByPrefix<RunHistoryEntry[]>("hist:");
      const replMap = await this.listAllByPrefix<Record<string, DestReplState>>("repl:");
      const emissions: NotifyEmission[] = [];
      const pendingTransitionIds: string[] = [];
      const recoveries: NotifyEmission[] = [];
      const at = new Date(now).toISOString();
      for (const ds of downpipes) {
        const allDests = allDestinationIds(ds.config);
        const configuredCopies = allDests.length;
        const cooldownKey = `${REPL_ALERT_COOLDOWN_PREFIX}${ds.config.id}`;
        const cooldown = cooldownMap.get(cooldownKey) ?? null;
        // A single-destination (or destination-less) downpipe has no off-site redundancy to lose, so it is
        // skipped. But a HELD cooldown here means a prior degraded/at-risk trigger opened a PagerDuty
        // incident, and clearing the cooldown without a resolve would strand that incident OPEN forever. So
        // emit the recovery FIRST (recovered:true, the SAME event + downpipeId so the dedup_key matches the
        // trigger), then delete: a fan-out edited back to one destination means the replication alert no
        // longer APPLIES, and the honest close is to say so, not to go silent. severity reuses the persisted
        // trigger value (the escalation-carry rationale of the main branch below).
        if (configuredCopies < 2) {
          if (cooldown !== null) {
            recoveries.push({
              event: cooldown.state,
              severity: cooldown.severity ?? severityOf(cooldown.state),
              downpipeId: ds.config.id,
              downpipeName: ds.config.name,
              detail: `${ds.config.name}: now configured for a single destination; the replication alert no longer applies and is cleared`,
              at,
              recovered: true,
            });
            await this.state.storage.delete(cooldownKey);
          }
          continue;
        }
        const ring = histMap.get(`hist:${ds.config.id}`) ?? [];
        // The proven-copy accounting needs a sealed run to reason about. Find the newest RESOLVED ok run
        // (newest-last ring), which carries the origin destination and the index every copy is measured
        // against. With no ok run yet (a brand-new or never-succeeded pipe) there is nothing to be degraded
        // about, so clear any stale cooldown and skip.
        let latestOk: RunHistoryEntry | undefined;
        for (let i = ring.length - 1; i >= 0; i--) {
          const h = ring[i];
          if (h === undefined || h.status === "in-flight") continue;
          if (h.status === "ok") latestOk = h;
          break; // newest resolved run only; a non-ok newest run is not a proven copy
        }
        // With no ok run to reason about, "healthy" cannot be VERIFIED (there is no baseline run to compute
        // proven copies against), so this is not a confirmed HEALTH recovery. But a HELD cooldown still means
        // a prior degraded/at-risk trigger's PagerDuty incident is OPEN, and clearing it without a resolve
        // would strand it open forever, so emit the recovery first (recovered:true, the SAME event +
        // downpipeId so the dedup_key matches), then delete. The honest close is "no assessable run; the
        // prior replication alert is cleared" -- backup health itself is reported by the separate
        // backup-failure/backup-stale stream. severity reuses the persisted trigger value.
        if (latestOk === undefined) {
          if (cooldown !== null) {
            recoveries.push({
              event: cooldown.state,
              severity: cooldown.severity ?? severityOf(cooldown.state),
              downpipeId: ds.config.id,
              downpipeName: ds.config.name,
              detail: `${ds.config.name}: no recent successful run to assess replication; the prior replication alert is cleared (backup health is reported separately)`,
              at,
              recovered: true,
            });
            await this.state.storage.delete(cooldownKey);
          }
          continue;
        }
        const latestIndex = latestOk.index;
        const origin = latestOk.destinationId ?? primaryDestinationId(ds.config);
        const repl = replMap.get(`repl:${ds.config.id}`) ?? {};
        // The proven set: the origin is always proven (the seal wrote the run there); every other
        // CONFIGURED destination is proven only when its holdsIndex is at or past the latest run's index.
        // Using a set over allDests keyed by destination keeps the origin from being double-counted.
        const proven = new Set<string>();
        if (origin !== undefined && allDests.includes(origin)) proven.add(origin);
        for (const destId of allDests) {
          if (proven.has(destId)) continue;
          const st = repl[destId];
          if (st && st.holdsIndex >= latestIndex) proven.add(destId);
        }
        const provenCopies = proven.size;

        // Eviction risk: the ring is at capacity, so its HEAD (the oldest live run index) is the next to
        // roll off. A destination whose holdsIndex is below the head still lacks a run that is about to be
        // evicted, so the window to reconcile that copy is closing. headIndex is the lowest index in the
        // current ring (the run-history ring is index-ordered newest-last, so the head is ring[0]).
        const ringAtCap = ring.length >= RING_CAP;
        const headIndex = ring.length > 0 ? ring.reduce((m, e) => Math.min(m, e.index), ring[0]!.index) : -1;
        // The most-behind CONFIGURED destination's holdsIndex (the origin holds everything; a destination
        // with no repl row holds nothing, holdsIndex -1). Only non-origin destinations can lag.
        let minHoldsIndex = latestIndex; // start from "fully caught up"; lower it for any lagging copy
        let mostBehindDestId: string | undefined; // the lagging copy the auto-heal liveness verdict reads
        for (const destId of allDests) {
          if (destId === origin) continue;
          const st = repl[destId];
          const h = st ? st.holdsIndex : -1;
          if (h < minHoldsIndex) {
            minHoldsIndex = h;
            mostBehindDestId = destId;
          }
        }
        const evictionRisk = isRunEvictionRisk({ ringAtCap, headIndex, holdsIndex: minHoldsIndex }).atRisk;
        // G209: classifyReplication returns copyCountInvalid when the configured copy count is unreadable --
        // in which case it CANNOT decide degraded-vs-healthy, and the whole replication-degraded alert quietly
        // stops firing for that downpipe. An alert that never fires reads exactly like a fleet with nothing
        // wrong, which is the failure mode this audit exists to remove: the detector switching ITSELF off is
        // now a counted fact. The alerting decision is unchanged (an undecidable count is still not "degraded",
        // because a guessed alert is worse than none); only the SILENCE is now attributable.
        const replVerdict = classifyReplication({ configuredCopies, provenCopies });
        if (replVerdict.copyCountInvalid) await this.bumpReplicationCopyCountInvalid();
        const degraded = replVerdict.degraded;
        // AUTO-HEAL liveness (DEST replica catch-up): is the most-behind lagging copy actively CATCHING UP, or
        // stuck? The keyless replicate pass copies a destination's whole backlog of ALREADY-SIGNED runs every
        // tick and records lastOk on each attempt (the reachability heartbeat). lastOk:true on the lagging
        // copy means the pass reached it and is advancing it on its own (a safe self-heal of signed runs, NOT
        // a promotion of an unverified copy), so the alert can say "recovering"; lastOk:false (or no repl row
        // yet) means the copy is unreachable/stuck and a human should look. The number of runs it trails the
        // ring head by is surfaced so "behind the ring head" is concrete, not a bare flag.
        const behindReplState = mostBehindDestId !== undefined ? repl[mostBehindDestId] : undefined;
        const catchingUp = behindReplState?.lastOk === true;
        const behindHeadBy = headIndex >= 0 && minHoldsIndex < headIndex ? headIndex - minHoldsIndex : 0;

        // Choose the SINGLE most-severe applicable condition for this downpipe (at-risk outranks degraded):
        // one cooldown per downpipe, one emission per tick, exactly as the staleness/failure stream is one
        // alert per downpipe. A downpipe can be both degraded and at-risk; the at-risk page is the more
        // urgent (a run is about to become unrecoverably under-replicated), so it wins.
        const state: ReplAlertCooldown["state"] | null = evictionRisk ? "run-at-risk-eviction" : degraded ? "replication-degraded" : null;
        if (state === null) {
          // Recovered to neither condition. AUTO-RESOLVE (mon-autoresolve): when a cooldown was held (this
          // downpipe WAS degraded or at-risk), emit the recovery on this falling edge, exactly once, before
          // clearing the cooldown (the same "delete is the only state that mattered" reasoning as
          // reconcileAlerts above -- once gone, a still-healthy downpipe has nothing left to re-fire from).
          // The recovery reuses the SAME event (the cleared cooldown.state) and downpipeId with
          // recovered:true, so PagerDuty resolves the matching dedup_key. severity reuses the EXACT value
          // persisted on the cooldown at trigger time (falling back to the base severityOf for a record
          // written before that field existed): this is what carries a run-at-risk-eviction ESCALATION
          // (the last-proven-copy case) through to the recovery, so it clears the same rule minSeverity bar
          // the escalated trigger did. See the method comment for why this also covers "destination
          // unreachable -> now healthy" rather than a separate NotifyEvent.
          if (cooldown !== null) {
            const recoveredSeverity = cooldown.severity ?? severityOf(cooldown.state);
            const recoveredDetail =
              cooldown.state === "run-at-risk-eviction"
                ? `${ds.config.name}: the at-risk run is no longer exposed to eviction; ${provenCopies} of ${configuredCopies} copies proven, every destination reachable`
                : `${ds.config.name}: replication recovered; ${provenCopies} of ${configuredCopies} copies proven, every destination reachable`;
            recoveries.push({
              event: cooldown.state,
              severity: recoveredSeverity,
              downpipeId: ds.config.id,
              downpipeName: ds.config.name,
              detail: recoveredDetail,
              at,
              recovered: true,
            });
            await this.state.storage.delete(cooldownKey);
          }
          continue;
        }
        // Throttle a persistently SAME-state condition to one re-nudge per ALERT_COOLDOWN_MS. A state
        // TRANSITION (a new condition, or degraded -> at-risk) alerts immediately regardless of the window.
        const isTransition = cooldown === null || cooldown.state !== state;
        if (!isTransition && now - cooldown.at < ALERT_COOLDOWN_MS) continue;

        // Build the redaction-safe one-liner: the downpipe name + the configured/proven copy counts (and,
        // for an at-risk run, the run index closing). The name is the operator's own redaction-safe label
        // and the counts/index are integers; nothing here is a secret, key, value, selector or fingerprint.
        let detail: string;
        let severity: NotifyEmission["severity"];
        // The auto-heal suffix: when the lagging copy is reachable and being advanced by the replicate pass,
        // say so (the operator can wait); when it is not, the copy is stuck and the alert is the call to act.
        const healSuffix = catchingUp ? "; replication is catching it up" : "; the lagging copy is not reachable, check the destination";
        if (state === "run-at-risk-eviction") {
          // Escalate to critical when eviction would leave only the single origin copy proven.
          severity = provenCopies <= 1 ? "critical" : severityOf("run-at-risk-eviction");
          // Louder "behind the ring head" detail: name how many runs the lagging copy trails the head by, so
          // the urgency (the run about to roll off, the gap to close) is concrete rather than a bare flag.
          detail = `${ds.config.name}: run ${headIndex} is about to age out of history with ${provenCopies} of ${configuredCopies} copies proven; a replica is behind the ring head by ${behindHeadBy} run(s)${healSuffix}`;
        } else {
          severity = severityOf("replication-degraded");
          detail = `${ds.config.name}: ${provenCopies} of ${configuredCopies} copies proven${healSuffix}`;
        }
        emissions.push({
          event: state,
          severity,
          downpipeId: ds.config.id,
          downpipeName: ds.config.name,
          detail,
          at,
          catchingUp,
        });
        // Record the cooldown OPTIMISTICALLY (single storage pass, concurrent ticks do not both fire) and
        // flag a TRANSITION so the Worker can clear it on a delivery failure (two-phase, like reconcileAlerts).
        // severity rides along (mon-autoresolve) so a later recovery can reuse the EXACT value used here
        // (the run-at-risk-eviction escalation case above), rather than recompute a possibly-lower base.
        await this.state.storage.put(cooldownKey, { state, at: now, severity } satisfies ReplAlertCooldown);
        if (isTransition) pendingTransitionIds.push(ds.config.id);
      }
      return { emissions, pendingTransitionIds, recoveries };
    }

    // markReplicationAlertsDelivered is the two-phase callback the Worker calls after attempting to deliver
    // the replication alert batch, the repl-alert-cd: sibling of markAlertsDelivered. It clears the
    // cooldown for any state-TRANSITION id whose delivery reached no channel so the NEXT tick re-attempts
    // rather than suppressing it for the full window. Fail-open and non-throwing (a no-op delete on an
    // unknown id is fine); same-state re-nudge failures are NOT passed here (storm prevention).
    async markReplicationAlertsDelivered(req: { failedTransitionIds?: string[] }): Promise<{ cleared: number }> {
      const failed = Array.isArray(req.failedTransitionIds) ? req.failedTransitionIds : [];
      let cleared = 0;
      for (const id of failed) {
        if (typeof id === "string" && id.length > 0) {
          await this.state.storage.delete(`${REPL_ALERT_COOLDOWN_PREFIX}${id}`);
          cleared++;
        }
      }
      return { cleared };
    }
  };
}
