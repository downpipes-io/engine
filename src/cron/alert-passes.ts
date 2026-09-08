// Alert-stream passes for the cron driver (cron/drive.ts): runAlertPass (the newly stale/
// failed downpipe alerts + the backup-success stream), runReplicationAlertPass (the 3-2-1
// replication-degraded / run-at-risk-eviction emissions), runSourceDriftPass (the proactive
// source-detachment alert) and runExpiryPass (the credential/key expiry notices). Each
// routes through cron/notify-passes.ts and is guarded so a fault degrades to "skip this
// pass this tick", never a crashed cron. All moved VERBATIM out of cron/drive.ts to finish
// the *-pass.ts split of that orchestrator; the behaviour is unchanged.

import { planRosterReattach } from "../admin/roster-reattach.ts";
import { doURL, type schedulerStub } from "../admin/router.ts";
import { enumerateBoundSources } from "../admin/router-sources.ts";
import type { Env } from "../env.d.ts";
import { log } from "../log.ts";
import { type DownpipeAlert, type NotifyEmission, type NotifyEvent, severityOf } from "../notify.ts";
import type { DownpipeState } from "../sched/scheduler-do.ts";
import { noteCronPass } from "./cron-fault-ledger.ts";
import { routeNotification } from "./notify-passes.ts";

// ---- the delivery-FEEDBACK confirms (support-pack gap audit, G165) --------------------------
//
// The three feedback confirms below (/alerts-delivered, /recovery-delivered, /replication-alerts-delivered)
// are the writes that CLOSE the loop after an alert was routed: they clear the OPTIMISTIC cooldown of a
// transition that reached no channel (so the next tick re-attempts), and they clear/keep the owed-resolve
// marker that decides whether PagerDuty's incident is ever auto-closed. When one of them is lost, the
// customer-visible symptom is silence: "we never got a second warning while the pipe stayed broken" (the
// cooldown stayed written) and "PagerDuty never auto-closed after recovery" (the owed resolve was dropped).
//
// TWO DEFECTS THIS FIXES (G165):
//   1. Only a THROW was ever caught. A DO that ANSWERS -- a 404 after a partial deploy that skewed the route
//      chain, a 400, a 500 under load -- returns a Response, so `await scheduler.fetch(...)` resolved happily
//      and the pass treated a lost confirm as a successful one. The single most likely real-world failure of
//      these routes was therefore invisible to BOTH the cooldown logic and the pack. The response is now
//      CHECKED (resp.ok), so a non-2xx is counted exactly like a transport throw.
//   2. Two of the three streams counted NOTHING at all. Only /alerts-delivered bumped the notifyHealth
//      aggregate; the recovery and replication confirms logged to Workers Logs (which the pack cannot
//      collect) and vanished. All three now record, so notifyHealth.feedbackFails is a TRUE count of the
//      whole feedback surface rather than a lossy sample of one stream's throw-only path.
// And the counter's own write is no longer fire-and-forget: the `.catch(() => {})` bump was itself the write
// most likely to be lost in the very fault window it exists to prove (same DO, same tick), so it is now
// checked and retried once.
//
// NO-CUSTODY (binding): the only thing that reaches the durable record is an integer bump of a closed field
// name ({ field: "feedbackFails" }). The route path is an engine-owned literal and the HTTP status an int;
// both go to Workers Logs only. No alert, downpipe id/name, detail, channel, endpoint or error message can
// ride -- the confirm's BODY is never re-sent, never inspected and never recorded. This records the LOSS,
// never the lost content.

/**
 * Records ONE delivery-feedback failure in the DO's notifyHealth aggregate (the pack's notifyHealth.
 * feedbackFails, section 4.7). CHECKED and retried once, unlike the prior fire-and-forget bump: a diagnostic
 * write that is silently dropped makes the pack UNDER-COUNT during exactly the outage it exists to explain.
 * It never throws (a bookkeeping bump must never break the alert pass that observed the fault).
 *
 * @param scheduler - the scheduler DO stub.
 */
async function bumpFeedbackFail(scheduler: DurableObjectStub): Promise<void> {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const resp = await scheduler.fetch(doURL("/notify/health-bump"), {
        method: "POST",
        body: JSON.stringify({ field: "feedbackFails" }),
        headers: { "content-type": "application/json" },
      });
      if (resp.ok) return;
    } catch {
      // a transport throw is the same loss as a non-2xx: retry once, then give up below
    }
  }
  // The counter itself was lost. There is nowhere durable left to put it (the DO is the sink, and the DO is
  // what just refused), so the honest floor is a log line: the pack will under-count this window by one.
  log("error", "notify feedbackFails bump was lost (the pack under-counts this window by one)");
}

/**
 * Posts ONE delivery-feedback confirm and CHECKS it. A throw AND a non-2xx are both "the confirm did not
 * land", and both are counted in notifyHealth.feedbackFails, so a stuck cooldown / an unclosed resolve has a
 * durable, pack-visible cause instead of a Workers-Logs-only line. Never throws: the pass's contract is that
 * a feedback fault degrades to "the cooldown stays written", never a crashed cron.
 *
 * @param scheduler - the scheduler DO stub.
 * @param path - the engine-owned DO route literal (never a customer value).
 * @param body - the confirm payload (ids the DO already holds); it is posted, never recorded.
 * @returns true when the confirm landed (2xx), false when it was lost (and counted).
 */
async function confirmFeedback(scheduler: DurableObjectStub, path: string, body: unknown): Promise<boolean> {
  try {
    const resp = await scheduler.fetch(doURL(path), {
      method: "POST",
      body: JSON.stringify(body),
      headers: { "content-type": "application/json" },
    });
    if (resp.ok) return true;
    // The DO ANSWERED, and refused. Nothing about the answer is recorded beyond the count: the status is an
    // int for the log line only.
    log("error", `${path} feedback refused (non-critical): status ${resp.status}`);
  } catch (e: unknown) {
    log("error", `${path} feedback failed (non-critical): ${(e as Error).message}`);
  }
  await bumpFeedbackFail(scheduler);
  return false;
}

// runAlertPass routes the NEWLY stale/failed downpipe alerts and the backup-success stream. It returns
// whether the pass COMPLETED (true) or bailed in its own guard (false), so drive() can fold a "a pass
// crashed while the tick still reported green" (the false-green signal) into the per-tick outcome record.
export async function runAlertPass(env: Env, scheduler: ReturnType<typeof schedulerStub>): Promise<boolean> {
  // Notifications (the on-call persona): after the runs are reconciled, ask the scheduler DO for the
  // batch of NEWLY stale/failed downpipes (transition-based, cooldown-throttled in the DO), then route
  // each through the notification model (contract section 2): map the alert state to a NotifyEvent,
  // resolve the matching channels (global + per-downpipe rules) in the DO, deliver to each via the
  // channel adapters, and record a redaction-safe history entry per delivery. This is the ONLY place a
  // notification leaves the account, and it is observability, never a control: it runs AFTER the run
  // loop so it can never delay a backup, and the whole block is guarded so a DO hiccup OR a delivery
  // failure degrades to "no notification this tick", never a crashed cron invocation. Every delivery
  // is fail-open and non-throwing (deliverEmission swallows all errors); this outer try/catch is the
  // same belt-and-braces discipline the per-run loop uses. The DO returns no alerts when no notify
  // channel is configured at all, so the common case costs one read.
  //
  // Two-phase delivery: reconcileAlerts records cooldowns OPTIMISTICALLY
  // and returns pendingTransitionIds (the ids whose cooldown was written as a state TRANSITION, i.e.
  // the first warning of a brand-new failure). After routing we report back to the DO: a transition
  // whose routing delivered to NO channel has its cooldown cleared so the next tick re-attempts; a
  // transition delivered to at least one channel keeps its cooldown. Same-state re-nudge failures are
  // not passed back (storm prevention). "Delivered" here means at least one channel accepted the send.
  try {
    const alertResp = await scheduler.fetch(doURL("/reconcile-alerts"), { method: "POST" });
    const { alerts, pendingTransitionIds, successes, recoveries } = (await alertResp.json()) as { alerts: DownpipeAlert[]; pendingTransitionIds: string[]; successes?: NotifyEmission[]; recoveries?: NotifyEmission[] };
    const at = new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
    const pending = new Set(pendingTransitionIds);
    const deliveredIds: string[] = [];
    const failedTransitionIds: string[] = [];
    for (const alert of alerts) {
      // Map the alert state to the notification event + redaction-safe one-line detail. The detail is
      // the downpipe name + state ONLY (the same surface the alert already carries), never a secret.
      const event: NotifyEvent = alert.state === "failed" ? "backup-failure" : "backup-stale";
      const detail = alert.state === "failed" ? `${alert.name} last run failed` : `${alert.name} is stale (no recent successful backup)`;
      const delivered = await routeNotification(env, scheduler, {
        event,
        severity: severityOf(event),
        downpipeId: alert.id,
        downpipeName: alert.name,
        detail,
        at,
      });
      // Track the transition cooldown feedback only for ids the DO flagged as transitions.
      if (pending.has(alert.id)) {
        if (delivered) deliveredIds.push(alert.id);
        else failedTransitionIds.push(alert.id);
      }
    }
    // Report delivery outcome to the DO only when there were transition alerts to track (avoids a
    // pointless round-trip on a tick of re-nudges only). AWAITED so the feedback completes before this
    // pass (and the enclosing waitUntil(drive())) resolves, rather than racing Worker shutdown. A throw
    // degrades to "cooldown stays written" (the conservative fallback); the next state change re-alerts.
    if (pendingTransitionIds.length > 0) {
      // The delivery-feedback confirm did not land (it threw, OR the DO answered non-2xx: a skewed route
      // chain after a partial deploy, a 500 under load), so the OPTIMISTIC cooldown stays written without
      // the delivery accounting reconciled (NOTIF: alerts-delivered-feedback-fail-keeps-cooldown) and the
      // pipe is silently stuck in cooldown. confirmFeedback counts it in notifyHealth.feedbackFails (G165),
      // so the pack can name the cause instead of showing a healthy notify pipeline through the silence.
      await confirmFeedback(scheduler, "/alerts-delivered", { deliveredIds, failedTransitionIds });
    }

    // Backup-success stream: the DO returns one emission per NEWLY-succeeded run (recency-bounded and
    // marker-tracked so each fires exactly once). Route each through the SAME fail-open path as the
    // failure alerts; a success-class event a digest rule selects is deferred by resolveDelivery (the
    // DO records the pending entry on resolve), and a non-digest rule delivers now. No cooldown
    // feedback: a success is a one-shot per run, not a transition that re-nudges.
    for (const emission of successes ?? []) {
      await routeNotification(env, scheduler, emission);
    }

    // AUTO-RESOLVE (mon-autoresolve, M3): the DO returns one emission per downpipe that just crossed
    // back to healthy (recovered:true, the SAME event + downpipeId the trigger used), built on the
    // falling edge of the SAME cooldown the transition alerts above use, PLUS a re-emission for any
    // downpipe with an owed resolve whose prior delivery failed (finding F4). Route each through the
    // identical fail-open path so deliverToChannel -> the PagerDuty adapter sends event_action:"resolve"
    // keyed on the matching dedup_key, auto-closing the incident the trigger opened; the other channels
    // (webhook/Slack/Teams/email) render it as a fresh, honestly-worded "recovered/cleared" notice.
    //
    // TWO-PHASE RETRY (finding F4): the delivery is no longer fire-and-forget. Each recovery's outcome is
    // reported back to the DO -- a delivered resolve clears its owed-resolve marker, a FAILED one writes/keeps
    // a marker so reconcileAlerts re-emits it on later ticks until it lands, the downpipe relapses, or it
    // ages out. A transient blip during recovery therefore can no longer strand an incident open. The feed-
    // back is best-effort like the /alerts-delivered confirm: a hiccup is swallowed, never crashing the pass.
    const deliveredRecoveryIds: string[] = [];
    const failedRecoveries: Array<{ id: string; state: "failed" | "stale" }> = [];
    for (const emission of recoveries ?? []) {
      const delivered = await routeNotification(env, scheduler, emission);
      if (emission.downpipeId === null) continue;
      if (delivered) deliveredRecoveryIds.push(emission.downpipeId);
      else failedRecoveries.push({ id: emission.downpipeId, state: emission.event === "backup-failure" ? "failed" : "stale" });
    }
    if (deliveredRecoveryIds.length > 0 || failedRecoveries.length > 0) {
      // A LOST recovery confirm strands the incident the trigger opened: a delivered resolve whose confirm
      // is dropped keeps its owed-resolve marker (harmless, it re-emits), but a FAILED resolve whose confirm
      // is dropped never gets a marker written, so reconcileAlerts will not retry it and PagerDuty stays open
      // for ever ("PagerDuty never auto-closed after recovery"). Until G165 this stream counted NOTHING at
      // all, in either the throw or the non-2xx case; confirmFeedback now records it.
      await confirmFeedback(scheduler, "/recovery-delivered", { deliveredIds: deliveredRecoveryIds, failed: failedRecoveries });
    }
    return true;
  } catch (e) {
    // G132: the pass failed. Classify the throw HERE, where the exception is in hand -- the driver only
    // ever sees the false return, so a class recorded there could never be better than "other".
    noteCronPass("alerts", false, e);
    log("error", `alert reconciliation skipped this tick: ${(e as Error).message}`);
    return false;
  }
}

// runReplicationAlertPass routes the replication-degraded / run-at-risk-eviction emissions.
export async function runReplicationAlertPass(env: Env, scheduler: ReturnType<typeof schedulerStub>): Promise<boolean> {
  // Replication health (3-2-1): after the staleness/failure stream, ask the scheduler DO for the fan-out
  // downpipes whose proven off-site copy set has fallen below the configured count (replication-degraded)
  // or whose still-lagging copy is about to lose a run to ring eviction (run-at-risk-eviction). Detection
  // is transition-based and cooldown-throttled in the DO (the repl-alert-cd: prefix, mirroring the alert
  // stream); the emissions already carry their NotifyEvent + severity, so route each through the SAME
  // fail-open notification model. It runs AFTER the run loop so it never delays a backup, and the whole
  // block is guarded so a DO hiccup OR a delivery failure degrades to "no replication alert this tick",
  // never a crashed cron. The DO returns no emissions when no delivery destination is configured or no
  // downpipe fans out, so the common case costs two reads. Two-phase (KEPT from the alert path): a
  // transition whose routing delivered to NO channel has its cooldown cleared so the next tick retries.
  try {
    const replResp = await scheduler.fetch(doURL("/reconcile-replication-alerts"), { method: "POST" });
    const { emissions, pendingTransitionIds, recoveries } = (await replResp.json()) as { emissions: NotifyEmission[]; pendingTransitionIds: string[]; recoveries?: NotifyEmission[] };
    const pending = new Set(pendingTransitionIds);
    const failedTransitionIds: string[] = [];
    for (const emission of emissions) {
      const delivered = await routeNotification(env, scheduler, emission);
      if (emission.downpipeId !== null && pending.has(emission.downpipeId) && !delivered) {
        failedTransitionIds.push(emission.downpipeId);
      }
    }
    // AWAITED so the feedback completes before this pass (and the enclosing waitUntil(drive())) resolves,
    // rather than racing Worker shutdown. A throw degrades to "cooldown stays written" as before.
    if (pendingTransitionIds.length > 0) {
      // Same stuck-cooldown consequence as the alert stream, on the repl-alert-cd: cooldowns: a lost confirm
      // leaves a degraded fan-out silently cooled with no second warning. Until G165 this stream counted
      // NOTHING at all, in either the throw or the non-2xx case; confirmFeedback now records it.
      await confirmFeedback(scheduler, "/replication-alerts-delivered", { failedTransitionIds });
    }

    // AUTO-RESOLVE (mon-autoresolve, M3): route the replication-degraded / run-at-risk-eviction
    // recoveries the same fail-open way (recovered:true, same event + downpipeId as the trigger they
    // close), so PagerDuty resolves the matching dedup_key. No two-phase retry here, mirroring
    // runAlertPass's recoveries loop: a recovery is a one-shot notice, not a "you are broken" alert.
    for (const emission of recoveries ?? []) {
      await routeNotification(env, scheduler, emission);
    }
    return true;
  } catch (e) {
    noteCronPass("replication-alerts", false, e);
    log("error", `replication alert reconciliation skipped this tick: ${(e as Error).message}`);
    return false;
  }
}

// runExpiryPass routes the credential/key expiry threshold-crossing notices.
// runSourceDriftPass PROACTIVELY detects a configured source whose binding the engine no longer exposes
// (a deploy dropped it, or the resource was deleted) and routes ONE "source-detached" alert per NEW detach,
// instead of waiting for that downpipe's next backup run to fail. It computes the missing set HERE (it holds
// env, so it can enumerate the live bindings, and reads the roster from the DO), then hands the set to the DO
// for the edge-trigger (reconcileSourceDrift diffs vs its marker, so a persistently-missing source pages once
// and a re-attach re-arms it). Same Worker/DO split as runAlertPass: the DO owns the state, the Worker
// delivers. Fully guarded: a fault degrades to "no source-drift check this tick", never a crashed cron.
export async function runSourceDriftPass(env: Env, scheduler: ReturnType<typeof schedulerStub>): Promise<boolean> {
  try {
    const states = (await (await scheduler.fetch(doURL("/downpipes"), { method: "GET" })).json()) as DownpipeState[];
    const bound = enumerateBoundSources(env);
    const liveNames = new Set<string>([...bound.kv, ...bound.r2, ...bound.d1, ...bound.secrets]);
    const plan = planRosterReattach(states.map((s) => s.config), liveNames);
    // Every detached binding (rebuildable + unreconstructable) -> its type, deduped. The roster derives the
    // set, so each binding is referenced by >=1 downpipe (plan.affects[binding] is non-empty).
    const detachedType = new Map<string, string>();
    for (const a of plan.toAttach) detachedType.set(a.binding, a.type);
    for (const u of plan.unreconstructable) if (!detachedType.has(u.binding)) detachedType.set(u.binding, u.type);
    // ALWAYS reconcile (even with nothing missing) so the DO marker CLEARS when a source is re-attached and a
    // future re-detach re-alerts. The DO returns only the NEWLY detached bindings to alert on.
    const reconResp = await scheduler.fetch(doURL("/source-drift/reconcile"), { method: "POST", body: JSON.stringify({ missing: [...detachedType.keys()] }), headers: { "content-type": "application/json" } });
    const { newlyDetached } = (await reconResp.json()) as { newlyDetached: string[] };
    if (newlyDetached.length === 0) return true;
    const nameById = new Map(states.map((s) => [s.config.id, s.config.name]));
    const at = new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
    for (const binding of newlyDetached) {
      const dpIds = plan.affects[binding] ?? [];
      const dpNames = dpIds.map((id) => nameById.get(id) ?? id);
      const firstId = dpIds[0] ?? null;
      const breaks = dpNames.length > 0 ? `it backs up ${dpNames.length} downpipe${dpNames.length === 1 ? "" : "s"} (${dpNames.join(", ")}), whose next runs will fail` : "no downpipe currently covers it";
      const detail = `Source binding ${binding} is no longer attached to the engine; ${breaks}. Re-attach it from the Sources screen to resume backups.`;
      const event: NotifyEvent = "source-detached";
      await routeNotification(env, scheduler, { event, severity: severityOf(event), downpipeId: firstId, downpipeName: firstId !== null ? (nameById.get(firstId) ?? null) : null, detail, at });
    }
    return true;
  } catch (e) {
    noteCronPass("source-drift", false, e);
    log("error", `source-drift pass skipped this tick: ${(e as Error).message}`);
    return false;
  }
}

export async function runExpiryPass(env: Env, scheduler: ReturnType<typeof schedulerStub>): Promise<boolean> {
  // Credential and key expiry (contract section 4): after the alert stream, ask the scheduler DO for
  // the items that have crossed a NEW notification threshold (transition-based, cooldown-throttled in
  // the DO, mirroring reconcile-alerts), then route each as a credential-expiry notification (warning).
  // This is the ONLY place an expiry notice leaves the account, and it is observability, never a
  // control: it runs AFTER the run loop so it can never delay a backup, and the whole block is guarded
  // so a DO hiccup OR a delivery failure degrades to "no expiry notice this tick", never a crashed
  // cron. routeNotification is itself fully fail-open. The DO returns no emissions when no item is
  // tracked, so the common case costs one read. The detail is the item label + days-remaining only
  // (redaction-safe; never a secret), and the event is account-level so downpipeId/downpipeName are null.
  try {
    const expResp = await scheduler.fetch(doURL("/expiry/reconcile"), { method: "POST" });
    const { emissions } = (await expResp.json()) as { emissions: Array<{ id: string; detail: string }> };
    const at = new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
    for (const em of emissions) {
      await routeNotification(env, scheduler, {
        event: "credential-expiry",
        severity: severityOf("credential-expiry"),
        downpipeId: null,
        downpipeName: null,
        detail: em.detail,
        at,
      });
    }
    return true;
  } catch (e) {
    noteCronPass("expiry", false, e);
    log("error", `expiry reconciliation skipped this tick: ${(e as Error).message}`);
    return false;
  }
}
