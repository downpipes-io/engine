// Notification + canary + update-alert tail passes for the cron driver (cron/drive.ts). routeNotification
// is the two-phase DO+Worker routing the whole notification model funnels through; runUpdateAlertIfNew
// fires the one-shot new-version alert; flushDigests delivers the due daily/weekly success digests; and
// runCanaryIfDue flies the canary and routes its transitions (plus the promoted-but-unsettled update
// safety net). Everything here was MOVED VERBATIM out of src/index.ts to keep that entry module a thin
// handler; the behaviour is unchanged. index.ts re-exports flushDigests (the behaviour-neutral test seam)
// and imports runCanaryIfDue for the manual canary-fly-now runtime. This module imports nothing from
// index.ts, so there is no cycle.
import { doURL } from "../do-url.ts";
import { checkUpdates } from "../admin/updates.ts";
import { runCanaryCycle } from "../canary/cycle.ts";
import { aggregateLiveness, type CanaryCheckResult, type CanaryFlightPlan } from "../canary/types.ts";
import type { Env } from "../env.d.ts";
import { ENGINE_VERSION } from "../format/version.ts";
import { log } from "../log.ts";
import {
  type DeliveryRecord,
  type DigestBatch,
  deliverEmission,
  deliverToChannel,
  digestEmissionFor,
  type NotifyChannel,
  type NotifyEmission,
  severityOf,
} from "../notify.ts";
import {
  noteDigestNoTransport,
  noteDroppedEmission,
  noteNotifyHistoryAppendFailure,
  noteUndeliveredCriticalAlert,
  noteUpdateChannelCheck,
  noteUpdateConfirmClearFailure,
} from "./cron-fault-ledger.ts";

// runUpdateAlertIfNew checks the signed update channel and, on a newer recommended version, fires exactly
// ONE "update-available" notification per version. The dedupe is server-side and atomic: the DO's
// claimUpdateAlert alerts only when the recommended version differs from the last-alerted one and records
// it inside a single read-modify-write, so two concurrent ticks cannot both fire and a steady "update
// available" state never re-fires. The notification detail is REDACTION-SAFE, the version + risk class + a
// one-line changelog summary + "review it in the console", and NEVER a token, url or hash (C17). It is
// fully fail-open: a missing channel config short-circuits cheaply (checkUpdates returns configured:false),
// and any fault is swallowed by the caller's guard. It NEVER auto-applies anything, the apply stays an
// explicit, owner-gated, dry-run-default action; this only tells the owner a version exists.
export async function runUpdateAlertIfNew(env: Env, scheduler: DurableObjectStub): Promise<void> {
  // checkUpdates is pull-only, https-only, pinned-key-verified, and never throws out (returns a structured
  // status). When the channel is unconfigured/unverified or there is no newer version, do nothing.
  const status = await checkUpdates(env);
  // G319: a channel that is CONFIGURED and does not VERIFY is the tamper / signing-key-rotation case, and the
  // pass simply returned -- no alert, no local evidence, so "we were never told a critical update existed" had
  // nothing at all behind it. Record the verification verdict (a boolean + a counter, never the channel
  // document) on every tick the channel is configured; an unconfigured channel records nothing (it is opt-in).
  if (status.configured) noteUpdateChannelCheck(status.verified === true);
  if (!status.configured || !status.verified || status.updateAvailable !== true) return;
  const version = typeof status.recommendedVersion === "string" ? status.recommendedVersion : "";
  if (version === "") return;
  // Atomic, once-per-version claim in the DO (dedupe). Only fire when the DO says this version is new.
  const claimResp = await scheduler.fetch(doURL("/update-alert-claim"), {
    method: "POST",
    body: JSON.stringify({ recommendedVersion: version }),
    headers: { "content-type": "application/json" },
  });
  const { shouldAlert } = (await claimResp.json()) as { shouldAlert: boolean };
  if (!shouldAlert) return;
  // Build the redaction-safe detail: version + risk + a single changelog line if present. NEVER a url/hash.
  const risk = typeof status.riskClass === "string" ? status.riskClass : "migration";
  const firstChange = Array.isArray(status.changelog) && status.changelog.length > 0 && typeof status.changelog[0]?.text === "string" ? status.changelog[0]!.text : null;
  const summary = firstChange ? `, ${firstChange.slice(0, 120)}` : "";
  const detail = `engine ${version} is available (risk: ${risk})${summary}. Review and apply it from the console Updates section.`;
  const at = new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
  // G184: the claim above is SPENT -- the DO has recorded this version as alerted, so it will never fire again
  // -- and until now the delivered boolean this returns was DISCARDED. A routing failure therefore consumed the
  // one-shot budget and delivered nothing, permanently. Latch the undelivered alert (closed event name only).
  const delivered = await routeNotification(env, scheduler, {
    event: "update-available",
    severity: severityOf("update-available"),
    downpipeId: null,
    downpipeName: null,
    detail,
    at,
  });
  if (!delivered) noteUndeliveredCriticalAlert("update-available", true);
}

// flushDigests delivers the due notification digests (contract section 2). It asks the DO for the
// per-channel batches whose window has elapsed (passing in nowMs, since the DO has no wall clock),
// renders ONE redaction-safe summary per channel (a roll-up of counts per event type + the touched
// downpipe names, built by digestEmissionFor; never a secret), delivers it via the SAME fail-open
// channel delivery the live stream uses (deliverToChannel, which never throws), records a
// NotifyHistoryEntry per delivered digest (via /notify/record, the same two-phase history append the
// live stream uses), and then clears the consumed pending entries via /notify/digest-sent {ids}.
//
// FAIL-OPEN throughout: deliverToChannel swallows all errors, every DO fetch is awaited inside this
// function's own caller-level guard, and a per-batch failure is isolated so one bad channel never
// blocks the rest. CLEAR-ON-ATTEMPT: a batch's pending entries are cleared once the flush has
// ATTEMPTED delivery this tick, whether or not the per-channel POST/send succeeded. This is the
// deliberate trade-off for a low-criticality success-summary: it bounds the pending store (a
// permanently unreachable channel cannot accumulate digest entries forever), the window has already
// elapsed so the batch is "old", and the delivered:false outcome is still recorded in the history so
// the failure stays observable. The higher-priority failure/stale stream is the one that retries on a
// failed first delivery (the two-phase cooldown clear); a missed success digest is acceptable.
// deliverDigestBatch delivers ONE due digest batch and returns the pending seqs to clear (clear-on-attempt).
// It fetches the live channel by id (it may have been edited/disabled since the deferral). A channel that no
// longer exists or is disabled is skipped for DELIVERY, but its consumed seqs are still returned so a deleted
// channel's deferrals do not accumulate forever. A thrown path (e.g. the channel fetch threw) propagates to the
// caller, which then does NOT clear the seqs, so they remain pending and the next tick retries them.
async function deliverDigestBatch(env: Env, scheduler: DurableObjectStub, batch: DigestBatch, at: string): Promise<number[]> {
  const chResp = await scheduler.fetch(doURL(`/notify/channel?id=${encodeURIComponent(batch.channelId)}`), { method: "GET" });
  const { channel } = (await chResp.json()) as { channel: NotifyChannel | null };
  const emission: NotifyEmission = digestEmissionFor(batch.summary, at);
  // B3/G294: a digest whose channel has since been DELETED or DISABLED cannot be delivered. Its seqs are
  // still returned below (so a dead channel's deferrals cannot accumulate forever, which is right), but the
  // batch must not vanish with NO trace of the outcome. This records an honest delivered:false history entry
  // (code "no-transport", the same closed reason the live Slack/webhook adapters use for "no url configured"),
  // so the notify history shows the digest as undeliverable. PREVIOUSLY this branch wrote nothing at all -- no
  // delivery, no history row -- while the entries were still cleared from the pending store, so the batch was
  // silently dropped with no honest record; only an internal-only tally (noteDigestNoTransport) ever counted it.
  let records: DeliveryRecord[];
  if (channel?.enabled) {
    const r = await deliverToChannel(env, channel, emission);
    records = [{ channelId: channel.id, channelKind: channel.kind, delivered: r.ok }];
  } else {
    noteDigestNoTransport();
    records = [{ channelId: batch.channelId, channelKind: batch.channelKind, delivered: false, code: "no-transport" }];
  }
  // Record one redaction-safe history entry for the digest attempt (the same /notify/record append the live
  // stream uses), whether it delivered or the channel was gone, so an undeliverable digest still leaves a row.
  // The detail is the rolled-up summary line, never a secret.
  // G294: CHECK the append. A non-2xx used to pass for a write (the response was never read), so a delivered
  // digest could leave no history row and the pack would show the flush as if it never ran.
  const rec = await scheduler.fetch(doURL("/notify/record"), {
    method: "POST",
    body: JSON.stringify({ emission, records }),
    headers: { "content-type": "application/json" },
  });
  if (!rec.ok) noteNotifyHistoryAppendFailure();
  return batch.seqs;
}

export async function flushDigests(env: Env, scheduler: DurableObjectStub): Promise<void> {
  const nowMs = Date.now();
  const at = new Date(nowMs).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
  const dueResp = await scheduler.fetch(doURL("/notify/digest-due"), {
    method: "POST",
    body: JSON.stringify({ nowMs }),
    headers: { "content-type": "application/json" },
  });
  const { batches } = (await dueResp.json()) as { batches: DigestBatch[] };
  if (batches.length === 0) return;
  const cleared: number[] = [];
  for (const batch of batches) {
    try {
      const seqs = await deliverDigestBatch(env, scheduler, batch, at);
      // Mark this batch's pending entries for clearing (clear-on-attempt; see the function comment).
      for (const seq of seqs) cleared.push(seq);
    } catch (e) {
      // A per-batch failure must not abort the rest of the flush; log coarsely and continue. The
      // batch's entries are NOT added to `cleared` on a thrown path (e.g. the channel fetch threw), so
      // they remain pending and the next tick retries them.
      log("error", `digest batch for channel skipped (non-critical): ${(e as Error).message}`);
    }
  }
  // Clear the consumed pending entries transactionally (the DO deletes exactly these seqs, so a
  // success deferred AFTER the due-read keeps its later seq and survives for the next window). A failed
  // clear degrades to "the batch re-delivers next window" (a duplicate summary), never a thrown cron.
  if (cleared.length > 0) {
    await scheduler.fetch(doURL("/notify/digest-sent"), {
      method: "POST",
      body: JSON.stringify({ ids: cleared }),
      headers: { "content-type": "application/json" },
    });
  }
}

// routeNotification routes ONE emission through the notification model (contract section 2.3), the
// two-phase DO + Worker split that mirrors reconcile-alerts: the DO resolves the immediate channels
// (and records any digest deferral), the Worker delivers via the channel adapters (it holds env), and
// the Worker posts the per-channel outcomes back so the DO appends the redaction-safe history. It is
// fully fail-open: deliverEmission never throws, and the whole function is wrapped so a routing hiccup
// degrades to "not delivered this tick" (false) rather than escaping into the cron. It returns whether
// the emission was delivered to AT LEAST ONE channel (the cooldown feedback uses this).
export async function routeNotification(env: Env, scheduler: DurableObjectStub, emission: NotifyEmission): Promise<boolean> {
  try {
    const resolveResp = await scheduler.fetch(doURL("/notify/resolve"), {
      method: "POST",
      body: JSON.stringify({ emission }),
      headers: { "content-type": "application/json" },
    });
    const { now } = (await resolveResp.json()) as { now: NotifyChannel[]; digestedCount: number; emission: NotifyEmission | null };
    if (now.length === 0) return false;
    const records: DeliveryRecord[] = await deliverEmission(env, emission, now);
    // Record the per-channel outcomes so the DO appends history. Fire-and-forget within the guard: a
    // failed record write degrades to "fewer history rows", never a thrown cron. This promise is not
    // registered with ctx.waitUntil (no ExecutionContext is threaded here), so if the isolate exits the
    // moment routeNotification returns the record write may not complete. That silent loss is acceptable
    // for a non-critical history row; the delivery itself has already happened above.
    // G294: AWAIT the history append and CHECK it. It used to be fire-and-forget with no ctx.waitUntil, so an
    // isolate that exited the moment routeNotification returned could drop the row for an alert that WAS
    // delivered -- and the pack's answer to "was our critical alert delivered?" is that row. The append is one
    // DO round trip on a path that has already made several, and a failure is now COUNTED rather than logged
    // into the void. It still never throws into the caller: the delivery has already happened.
    try {
      const rec = await scheduler.fetch(doURL("/notify/record"), {
        method: "POST",
        body: JSON.stringify({ emission, records }),
        headers: { "content-type": "application/json" },
      });
      if (!rec.ok) noteNotifyHistoryAppendFailure();
    } catch (e) {
      noteNotifyHistoryAppendFailure();
      log("error", `notify history record failed (non-critical): ${(e as Error).message}`);
    }
    return records.some((r) => r.delivered);
  } catch (e) {
    // A whole notify pass skipped because a DO fetch threw (NOTIF: do-fetch-throws-pass-skipped). Record it
    // best-effort so "alerts silently stopped because the pass never ran" is visible in the pack, then keep
    // the fail-open contract (never escape into the cron).
    scheduler.fetch(doURL("/notify/health-bump"), { method: "POST", body: JSON.stringify({ field: "passSkips" }) }).catch(() => {});
    // G294: passSkips is ANONYMOUS (and its own bump can silently fail). Name the EVENT that was lost whole, so
    // a pack can say WHICH alert never left the engine rather than "some number of emissions were skipped".
    noteDroppedEmission(emission.event);
    log("error", `notification routing skipped (non-critical): ${(e as Error).message}`);
    return false;
  }
}

// runCanaryIfDue flies the canary when the DO says it is due (the two-phase canaryDue/canaryComplete
// split, mirroring the run loop and the scheduled restore tests). The DO owns the schedule, the
// in-flight lease and the state; this Worker does the heavy seal/read/restore I/O via runCanaryCycle
// (which never throws and touches only the isolated _CANARY/ namespace) and posts the redaction-safe
// result back. On a TRANSITION only (the bird fell dead, or recovered) it routes exactly one
// notification, so a persistent death does not page every hour and a steady-alive bird is silent. It
// is fully fail-open: a fault degrades to no flight, never a crashed cron, and never alters a backup.
export async function runCanaryIfDue(env: Env, scheduler: DurableObjectStub): Promise<{ shouldAlert: boolean }> {
  const dueResp = await scheduler.fetch(doURL("/canary/due"), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ nowMs: Date.now() }) });
  const { due, run } = (await dueResp.json()) as { due: boolean; run?: CanaryFlightPlan };
  if (!due || !run || !Array.isArray(run.dests) || run.dests.length === 0) return { shouldAlert: false };
  // Fly the WHOLE eight-aspect cycle against EACH destination in turn. runCanaryCycle never throws and
  // touches only that destination's isolated _CANARY/ namespace, so a per-destination fault degrades to
  // that destination's result (ailing/dead) and never affects the others or a real backup.
  const results: CanaryCheckResult[] = [];
  for (const dest of run.dests) {
    results.push(await runCanaryCycle(env, scheduler, dest));
  }
  const compResp = await scheduler.fetch(doURL("/canary/complete"), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ run, results }) });
  const { transitions } = (await compResp.json()) as { transitions: Array<{ destinationId: string | null; label: string; transitioned: "dead" | "recovered" }> };
  const at = new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");

  // escalateRollbackIfNeeded returns whether it claimed the one-shot rollbackNeeded (shouldAlert): the cron
  // callers ignore it (behaviour unchanged); the on-demand canary-tick route surfaces it so a journey can
  // assert the FOLD-1 dedupe. confirmUpdateIfSettled is unchanged.
  const escalation = await escalateRollbackIfNeeded(env, scheduler, results, at);
  await confirmUpdateIfSettled(scheduler, results);

  if (Array.isArray(transitions) && transitions.length > 0) {
    const reasonByDest = new Map(results.map((r) => [r.destinationId ?? null, r.deadReason]));
    await notifyCanaryTransitions(env, scheduler, transitions, reasonByDest, at);
  }
  return { shouldAlert: escalation.claimed };
}

// escalateRollbackIfNeeded is FOLD 1, the GUARANTEED SAFETY NET for a promoted-but-unsettled update. The
// two-phase apply promotes the new version LIVE (phase 1) and the console drives the canary-gate +
// auto-rollback as phase 2; if phase 2 never runs (the page was closed between promote and settle), nothing
// reverts on its own. The engine deliberately holds NO deploy credential (no-custody), so it CANNOT
// auto-roll-back unattended, but the hourly canary CAN auto-DETECT the failure (it already flies here,
// tokenless) and page the owner so the one-click rollback is impossible to miss. When this flight's aggregate
// verdict is NOT alive AND an update verification is unsettled AND the running engine IS that promoted version
// (ENGINE_VERSION === pending.recommendedVersion, a tokenless accurate signal that the bad new code is live),
// we claim a one-shot CRITICAL "rollback needed" alert (deduped in the DO so a persistent failure pages once,
// not every hour) and record a flag the console surfaces as an URGENT one-click-rollback prompt. This NEVER
// deploys; the rollback stays a human-confirmed one click. Fully fail-open: a fault degrades to "no escalation
// this tick", never a crashed cron.
async function escalateRollbackIfNeeded(env: Env, scheduler: DurableObjectStub, results: CanaryCheckResult[], at: string): Promise<{ claimed: boolean }> {
  const verdict = aggregateLiveness(results.map((r) => r.status));
  if (verdict === "alive") return { claimed: false };
  try {
    const statusResp = await scheduler.fetch(doURL("/update-status"), { method: "GET" });
    const { pending } = (await statusResp.json()) as { pending: null | { recommendedVersion?: string; toVersion?: string } };
    if (pending && pending.recommendedVersion === ENGINE_VERSION) {
      const claimResp = await scheduler.fetch(doURL("/update-rollback-needed-claim"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ recommendedVersion: pending.recommendedVersion, toVersion: pending.toVersion ?? "", canaryVerdict: verdict }),
      });
      const { shouldAlert } = (await claimResp.json()) as { shouldAlert: boolean };
      if (shouldAlert) {
        // G184: the WORST case of the claim-then-deliver pattern. The one-shot rollback-needed claim is spent
        // above, so a routing failure here means the owner is NEVER paged about a bad update that is live --
        // and this call site discarded the delivered boolean entirely. Latch it.
        const delivered = await routeNotification(env, scheduler, {
          event: "update-rollback-needed",
          severity: severityOf("update-rollback-needed"),
          downpipeId: null,
          downpipeName: "Engine update",
          detail: `The engine update to ${pending.recommendedVersion} was promoted live but its verification never finished, and the hourly canary now finds it unhealthy (${verdict}). Open the console and roll back in one click, your data and recovery are unaffected (archives are immutable; restore is out-of-band).`,
          at,
        });
        if (!delivered) noteUndeliveredCriticalAlert("update-rollback-needed", true);
      }
      // Surface the one-shot claim result so the on-demand canary-tick route can return shouldAlert (the cron
      // callers ignore it). A persistent unsettled bad build claims true once, then false (the FOLD-1 dedupe).
      return { claimed: shouldAlert };
    }
  } catch (e) {
    log("error", `update rollback-needed escalation skipped (non-critical): ${(e as Error).message}`);
  }
  // Not a promoted-but-unsettled bad build this tick (no matching pending), or a fail-open DO hiccup: no claim.
  return { claimed: false };
}

// confirmUpdateIfSettled is the BACKGROUND CONFIRMATION half of the 0.1.5 UX design (§3): a KEEP the
// settle route decided via the self-check (the canary itself could not gate; confirmationPending:true on
// the engine's `last` record) is honest but provisional until the hourly canary sings on the SAME version.
// On an ALIVE aggregate verdict this clears the flag (POST /update-confirm, bookkeeping only, no token
// needed: a keep is never a deploy). On anything else (dead, ailing, pending) it does NOTHING NEW and
// deploys NOTHING: a DEAD verdict already pages through notifyCanaryTransitions/escalateRollbackIfNeeded
// above via the EXISTING unhealthy alerting, and the console's standalone rollback (the one-click, token
// path) covers recovery -- unchanged custody, the engine still holds no deploy credential to act on
// unattended. Fully fail-open: a fault degrades to "no confirmation this tick", never a crashed cron.
export async function confirmUpdateIfSettled(scheduler: DurableObjectStub, results: CanaryCheckResult[]): Promise<void> {
  if (aggregateLiveness(results.map((r) => r.status)) !== "alive") return;
  try {
    const statusResp = await scheduler.fetch(doURL("/update-status"), { method: "GET" });
    const { last } = (await statusResp.json()) as { last: null | { outcome?: string; confirmationPending?: boolean; recommendedVersion?: string } };
    if (last && last.outcome === "applied" && last.confirmationPending === true && typeof last.recommendedVersion === "string" && last.recommendedVersion === ENGINE_VERSION) {
      // G319: an applied update that shows "verification pending" FOREVER is this clear failing, tick after
      // tick, with only a log line behind it. Check the response and count the failure.
      const resp = await scheduler.fetch(doURL("/update-confirm"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ recommendedVersion: last.recommendedVersion }),
      });
      if (!resp.ok) noteUpdateConfirmClearFailure();
    }
  } catch (e) {
    noteUpdateConfirmClearFailure();
    log("error", `update confirmation-pending clear skipped (non-critical): ${(e as Error).message}`);
  }
}

// notifyCanaryTransitions routes exactly ONE notification per destination that crossed a threshold this
// flight (fell dead, or recovered), naming the destination. A persistent death pages once (the DO dedupes the
// transitions), a steady-alive bird is silent.
async function notifyCanaryTransitions(
  env: Env,
  scheduler: DurableObjectStub,
  transitions: Array<{ destinationId: string | null; label: string; transitioned: "dead" | "recovered" }>,
  reasonByDest: Map<string | null, string | null>,
  at: string,
): Promise<void> {
  for (const t of transitions) {
    if (t.transitioned === "dead") {
      // G184: the DO has already DEDUPED this transition (a persistent death pages once), so an undelivered
      // canary-dead is a page that will never be re-attempted: the "the destination died and nobody was told"
      // ticket. The delivered boolean was discarded here; latch it instead.
      const delivered = await routeNotification(env, scheduler, {
        event: "canary-dead",
        severity: severityOf("canary-dead"),
        downpipeId: null,
        downpipeName: "Canary",
        detail: `Canary dead on ${t.label}, evacuate the coalmine: ${reasonByDest.get(t.destinationId ?? null) ?? "a byte strayed from the known data"}`,
        at,
      });
      if (!delivered) noteUndeliveredCriticalAlert("canary-dead", true);
    } else {
      await routeNotification(env, scheduler, {
        event: "canary-recovered",
        severity: severityOf("canary-recovered"),
        downpipeId: null,
        downpipeName: "Canary",
        detail: `Canary alive again on ${t.label}; every byte returned exactly`,
        at,
      });
    }
  }
}
