// The cron driver: drive() is the body of the Worker's scheduled() handler (src/index.ts keeps the
// thin wiring that calls it). It reconciles the scheduler DO, runs the due downpipes oldest-due-first
// under ONE shared per-invocation subrequest budget, then runs the trailing passes in priority order:
// alert reconciliation, the expiry stream, scheduled restore tests, replication, retention prune (which
// runs AFTER replication so a trailing replica catches up before the primary prunes), the canary flight,
// the digest flush and the new-version alert. Each pass plus each per-downpipe step is
// guarded so a fault degrades to "skip this pass this tick", never a crashed cron invocation. The whole
// orchestrator (and the per-pass helpers it calls) was MOVED VERBATIM out of src/index.ts to keep that
// entry module a thin handler; the behaviour is unchanged. This module imports the pass helpers from the
// cron/* siblings (not from index.ts), so there is no cycle. drive() itself is a thin orchestrator over
// the named pass sub-functions, each moved verbatim into its cron/* pass sibling (reconcileAndDue +
// runSealLoop in seal-loop-pass.ts; the alert / replication-alert / source-drift / expiry passes in
// alert-passes.ts; runRestoreTestPass in restore-test-pass.ts; runDiscoveryPass in discovery-pass.ts);
// the retention/canary/replication/digest/update passes already delegate to cron/* helpers.

import { doURL, schedulerStub } from "../admin/router.ts";
import type { Env } from "../env.d.ts";
import { log } from "../log.ts";
import { budgetFromEnv } from "../seal/budget.ts";
import { runReplications } from "../seal/replicate.ts";
import { runAlertPass, runExpiryPass, runReplicationAlertPass, runSourceDriftPass } from "./alert-passes.ts";
import { runBeaconEmitPass } from "./beacon-emit.ts";
import { runControlPlaneExportPass, runControlPlaneHealthPass, runDeployObservePass } from "./control-plane-pass.ts";
import { type CronPassName, noteCronPass, noteTickRecordFailure, recordCronDestProbeFaults, recordCronHealth, resetCronFaultLedger } from "./cron-fault-ledger.ts";
import { runDiscoveryPass } from "./discovery-pass.ts";
import { flushDigests, runCanaryIfDue, runUpdateAlertIfNew } from "./notify-passes.ts";
import { runOtlpPushPass } from "./otlp-push-pass.ts";
import { runPostureEvaluationPass } from "./posture-pass.ts";
import { runOrphanReconcile } from "./reconcile-pass.ts";
import { runRestoreTestPass } from "./restore-test-pass.ts";
import { runRetentionPrunes } from "./retention-pass.ts";
import { reconcileAndDue, runSealLoop } from "./seal-loop-pass.ts";
import { runSiemPushPass } from "./siem-push-pass.ts";

// DRIVE_OVERHEAD_SUBREQUESTS is the cron invocation's fixed non-seal spend against the
// shared platform cap: the /tick + /due calls made before the budget exists, and the
// trailing passes after the seal loop (alert reconciliation + webhook sends, the expiry
// pass, scheduled restore drills, the digest flush). Reserved up front so the seal loop
// cannot overdraw what the tail of the invocation still needs.
const DRIVE_OVERHEAD_SUBREQUESTS = 30;

// CRON_INTERVAL_MS is the engine's own cron cadence (wrangler.toml `crons = ["*/15 * * * *"]`). It is passed
// to the DO so it can derive the tick GAP (G205): how many ticks are MISSING between the previous recorded
// tick and this one. Without it, a hole in the tick ring (a DO-unreachable tick, which records nothing at
// all) is indistinguishable from a cron that never fired.
const CRON_INTERVAL_MS = 15 * 60 * 1000;

// drive is the cron entry the scheduled() handler calls. It takes a DO-level SINGLE-FLIGHT tick lease (C3-07)
// so two OVERLAPPING */15 cron ticks (a slow tick still in flight when the platform fires the next one,
// possibly in a separate isolate) cannot both run the pass sequence, runs runScheduledTick under it, then
// releases the lease. See acquireTickLease (scheduler-do-scheduling.ts) for why the lease is DEFENCE-IN-DEPTH
// (the per-run in-flight lease inside trigger() already coalesces a duplicate seal; every mutating tail pass
// dedupes atomically in the DO; the lease closes the one tail an overlap could double, the digest flush, and
// spares the wasted duplicate reachability probes). The acquire is FAIL-OPEN: an unreachable DO proceeds
// without the guard, exactly as reconcileAndDue already skips a tick on a DO outage.
export async function drive(env: Env): Promise<void> {
  const scheduler = schedulerStub(env);
  // C3-07: acquire the single-flight tick lease before doing any work. Only an EXPLICIT acquired:false (a tick
  // genuinely still in flight, holding the lease) skips this invocation; any other outcome -- including a DO
  // blip that throws, or an unrecognised response -- proceeds WITHOUT the guard (fail-open, no worse than
  // before the lease existed). The releasing tick, the self-expiry, and the DO alarm keep the schedule live.
  let tickLeaseToken: string | undefined;
  try {
    const leaseResp = await scheduler.fetch(doURL("/tick-lease/acquire"), { method: "POST" });
    const lease = (await leaseResp.json()) as { acquired?: boolean; token?: string };
    if (lease.acquired === false) {
      // A previous tick still holds the lease (a slow tick overlapping this */15 fire). Skip: that tick is
      // already reconciling and dispatching the SAME due set, every mutating step is idempotent at the DO, and
      // the digest flush must run once, so proceeding would only duplicate work. Nothing is stranded (the DO
      // alarm and the next */15 tick remain the per-downpipe timers). Deliberately do NOT reset the isolate-
      // local cron ledger here: a same-isolate overlap's in-flight tick must keep its ledger untouched.
      log("info", "cron tick skipped: a previous tick still holds the single-flight lease");
      return;
    }
    tickLeaseToken = lease.token;
  } catch (e) {
    // The DO was unreachable acquiring the lease: proceed without the single-flight guard rather than let the
    // guard itself stop a tick. reconcileAndDue re-checks DO liveness below and skips cleanly if it is down.
    log("error", `tick-lease acquire unavailable, proceeding without the single-flight guard: ${(e as Error).message}`);
  }
  try {
    await runScheduledTick(env, scheduler);
  } finally {
    // Release the lease so the NEXT */15 tick runs immediately (release-on-completion is the primary mechanism;
    // TICK_LEASE_MS is only the crash backstop). Best-effort: a failed release degrades to "the lease self-
    // expires within a cron interval", never a thrown cron. Skipped when we never acquired it (a DO blip above
    // left no token, so this invocation owns nothing to release).
    if (tickLeaseToken !== undefined) {
      try {
        await scheduler.fetch(doURL("/tick-lease/release"), { method: "POST", body: JSON.stringify({ token: tickLeaseToken }), headers: { "content-type": "application/json" } });
      } catch (e) {
        log("error", `tick-lease release skipped (it self-expires within a cron interval): ${(e as Error).message}`);
      }
    }
  }
}

// runScheduledTick is the body of one cron invocation, run under drive()'s single-flight tick lease (C3-07).
// It reconciles the scheduler DO, runs the due downpipes under one shared per-invocation subrequest budget,
// then runs the trailing passes in priority order (alert reconciliation, replication alerts, the expiry
// stream, scheduled restore tests, replication, retention prune, the canary flight, cf-config discovery, the
// digest flush and the new-version alert). Replication runs BEFORE retention (M5(b)) so a trailing replica
// catches up on its backlog before the primary prunes the source data. Each pass is a guarded sub-function so
// a fault degrades to "skip this pass this tick", never a crashed cron invocation. It was split out of drive()
// only so the tick lease can wrap it in one place; the reconcile + pass sequence below is unchanged.
async function runScheduledTick(env: Env, scheduler: ReturnType<typeof schedulerStub>): Promise<void> {
  // Clear the isolate-local cron ledger: a Workers isolate is WARM and serves many invocations, so without
  // this a previous tick's pass outcomes would be re-reported as this tick's. (The carried tick-record-
  // failure tally deliberately SURVIVES the reset: reporting it later is its whole purpose.)
  resetCronFaultLedger();
  const due = await reconcileAndDue(scheduler);
  if (due === null) {
    // G205: the scheduler DO was unreachable at the /tick or /due preamble, so this invocation does NOTHING
    // and records NOTHING -- a HOLE in the tick ring that reads exactly like a cron that never fired. The
    // sink for the record is the very thing that is down, so the failure is noted in the isolate-local tally
    // and reported by the NEXT healthy tick, which is what turns the hole into a recorded cause.
    noteTickRecordFailure();
    return;
  }
  // ONE budget for the whole cron invocation (design F13): every due downpipe's inline
  // first slice, the scheduler round-trips and the notification passes all share the
  // platform's per-invocation subrequest cap, so the budget is shared too. A tick with
  // many due downpipes spends a slice of it on each (the rest of each run continues on
  // the seal DO's own alarm budgets) instead of dying on the cap mid-loop.
  const budget = budgetFromEnv(env);
  // The invocation's NON-SEAL overhead shares the same platform cap the budget guards:
  // the /tick and /due calls already made, the per-downpipe /trigger and /start
  // round-trips, and the trailing passes (alert reconciliation + webhook sends, the
  // expiry pass, scheduled restore drills, the digest flush). Spend a fixed lump up
  // front so "700 subrequests" means 700 of everything this invocation does, not 700
  // of sealing plus an invisible margin that a crowded tick can overdraw.
  budget.spend(DRIVE_OVERHEAD_SUBREQUESTS);
  // Accumulate the per-tick OUTCOME (scheduler-liveness new-logging). passErrors counts every pass that
  // bailed in its own guard OR threw to drive() this tick -- the "a pass crashed while the cron still
  // reported green" (false-green) signal. It is posted to the DO at the very end so the support pack can
  // see a tick that completed but did no useful work.
  let passErrors = 0;
  // tallyPass keeps the anonymous passErrors integer (the pack's existing false-green signal) AND attributes
  // the outcome to a CLOSED pass name (G132), so "no alerts / no restore tests / no exports for days" finally
  // says WHICH pass. A pass that failed already recorded its own closed error class at its catch (where the
  // exception is in hand); noteCronPass will not let this classless tally overwrite that.
  const tallyPass = (name: CronPassName, completed: boolean): void => {
    if (!completed) passErrors++;
    noteCronPass(name, completed);
  };
  // guarded runs one pass that reports by THROWING, tallying and CLASSIFYING the throw at the site that holds
  // it. Three of these passes (deploy-observe among them) never moved passErrors at all before.
  const guarded = async (name: CronPassName, label: string, fn: () => Promise<void>): Promise<void> => {
    try {
      await fn();
      noteCronPass(name, true);
    } catch (e) {
      passErrors++;
      noteCronPass(name, false, e);
      log("error", `${label} skipped this tick: ${(e as Error).message}`);
    }
  };
  const sealSummary = await runSealLoop(env, due, budget);
  noteCronPass("seal-loop", sealSummary.sealErrors === 0);
  tallyPass("alerts", await runAlertPass(env, scheduler));
  tallyPass("replication-alerts", await runReplicationAlertPass(env, scheduler));
  // Proactive source-detachment alert: page once when a configured source's binding goes missing, rather
  // than waiting for that downpipe's next run to fail (the DO edge-triggers so a persistent miss pages once).
  tallyPass("source-drift", await runSourceDriftPass(env, scheduler));
  tallyPass("expiry", await runExpiryPass(env, scheduler));
  tallyPass("restore-tests", await runRestoreTestPass(env, scheduler, budget));

  // Replication (3-2-1 fan-out): catch every fan-out downpipe's destinations up on their whole backlog,
  // copying each run from its origin so the same sealed bytes live in all configured destinations. It runs
  // AFTER the seal loop so a replica copy never delays a primary backup, but DELIBERATELY BEFORE the
  // retention prune below (M5(b)): retention prunes the PRIMARY (it deletes a superseded run-tree + its
  // orphaned seg/ data), so a replica that was briefly down and never received a run would be permanently
  // stranded without those bytes if the primary pruned the run first in the same tick. Replicating first
  // lets a trailing replica catch up on its whole backlog before any prune can remove the source data.
  // It shares this invocation's subrequest budget (yielding before the platform cap; the pass is
  // idempotent, so it resumes next tick), and the whole pass plus each per-destination step is fail-open (a
  // fault degrades to "mirrored next tick", never a crashed cron). Cheap when no downpipe fans out (one
  // /downpipes read).
  await guarded("replication", "replication pass", () => runReplications(env, scheduler, budget));

  // Retention prune (ASVS V14.2.7: classification-driven retention with automatic deletion). For each
  // downpipe that HAS a retention policy, compute the prune PLAN (which older runs fall outside the
  // keepRuns/keepDays window, the run-tree objects to delete, and the now-orphaned segments) and, ONLY
  // when retention.enforce === true, apply it (mark the superseded RUNLOG entries + re-sign under the
  // RUNLOG lock, then delete the run-trees and orphaned segments). DRY-RUN by default: an absent/false
  // enforce computes and logs the plan but writes/deletes NOTHING. It runs AFTER the run loop AND AFTER
  // replication (M5(b)) so a trailing replica catches up on its backlog before the primary prunes the
  // source data out from under it, and so a prune never delays a backup. The whole block plus each
  // per-downpipe step is guarded so a planner/apply fault or a DO hiccup degrades to "no prune this tick",
  // never a crashed cron. It is cheap by construction: only downpipes WITH retention configured are
  // considered, so an account that has set no retention policy pays one list and skips the rest.
  await guarded("retention", "retention prune pass", () => runRetentionPrunes(env, scheduler));

  // Orphan reconcile DRY-RUN INVENTORY (scale-rearch P2e, report-only). For every destination bucket
  // the fleet seals to, discover the run-trees physically present but ABSENT from that bucket's signed
  // RUNLOG (the orphaned-but-recoverable bytes a contended/throttled/crashed finalise leaves behind),
  // classify each, and EMIT a per-class inventory in the structured log. It DELETES NOTHING and
  // SALVAGES NOTHING (the enforced GC + salvage ride the sharded-RUNLOG keystone, a multi-day project).
  // It runs AFTER replication and retention (independent of both) so it never delays a backup, and is
  // gated behind the ORPHAN_RECONCILE env flag (DEFAULT OFF), so it is a no-op until an operator opts
  // in. The whole pass is fail-open: a missing key or a DO hiccup degrades to "no inventory this tick",
  // never a crashed cron.
  await guarded("orphan-reconcile", "orphan reconcile pass", () => runOrphanReconcile(env, scheduler));

  // Canary backup (the on-by-default known-answer integrity flight): ask the DO if the canary is due
  // and, if so, fly it OUT OF THE DO (the same seal-stays-out-of-the-DO separation as runs and
  // scheduled tests) and post the result back. The flight writes only its own known corpus under an
  // isolated _CANARY/ namespace and never a customer archive or a real binding, so it can never
  // affect a real backup. It runs AFTER the run loop so it never delays a backup, and the whole block
  // is guarded so a flight fault or a DO hiccup degrades to "no canary flight this tick", never a
  // crashed cron. canary-dead / canary-recovered fire ONLY on a transition (see runCanaryIfDue).
  await guarded("canary", "canary flight", async () => {
    // runCanaryIfDue now returns the one-shot rollbackNeeded claim (for the on-demand canary-tick route); the
    // cron ignores it, so discard it to keep the guarded() Promise<void> contract.
    await runCanaryIfDue(env, scheduler);
  });

  tallyPass("discovery", await runDiscoveryPass(env, scheduler, budget));

  // Scheduled security-centre evaluation: at most once per interval, recompute the posture through the
  // single shared path so a regression on an UNWATCHED account still fires its posture-regression
  // notification (an ordinary console read/report also refreshes the snapshot, so an active account never
  // pays extra here). Cheap when not due (one DO snapshot-age read); fail-open like every pass.
  tallyPass("posture", await runPostureEvaluationPass(env, scheduler));

  // INFRA-1 control-plane recovery. The HEALTH pass runs first (cheap: one DO read; it only probes a
  // bucket when the plane is empty) so a detected amnesia latches recovery-required + alerts THIS tick.
  // The EXPORT pass keeps the signed recovery artefact current (change-gated: it only re-signs + writes
  // when the head config posture changed). Both run LAST (after backups/replication) so they never delay a
  // backup, and both are fully fail-open (a fault degrades to "next tick", never a crashed cron).
  // DETERMINISTIC per-tick deploy-identity observation (not gated on a status poll) so a deploy / redeploy is
  // recorded even on an unattended account (owner-#1 "did a deploy drop my bindings?"). Cheap + fail-open.
  await guarded("deploy-observe", "control-plane deploy-observe pass", () => runDeployObservePass(env, scheduler));
  await guarded("cp-health", "control-plane health pass", () => runControlPlaneHealthPass(env, scheduler, budget));
  await guarded("cp-export", "control-plane export pass", () => runControlPlaneExportPass(env, scheduler, budget));

  // OPT-IN vendor beacon (no-custody, content-free, fail-open): OFF unless the operator set BEACON_URL +
  // BEACON_INGEST_KEY. When on, it emits the aggregate downpipe-beacon-v1 (counts + engine version + CF
  // deploy id; nothing per-downpipe) so the control-plane per-account deploy ledger can record a deploy
  // (a cfVersionId change), the independent vendor-side signal that lets the support diagnosis attribute
  // BINDING-DROPPED-BY-DEPLOY. Runs LAST so it never delays a backup; its own try/catch is belt-and-braces
  // over the pass's internal fail-open.
  await guarded("beacon", "vendor beacon pass", () => runBeaconEmitPass(env, scheduler));

  // Notification digest flush (contract section 2: the daily/weekly success-stream summary). Wave 1
  // DEFERS each success-class emission a digest rule selected into the DO under the notify-digest:
  // prefix; this is the flush that turns the accumulated deferrals into ONE redaction-safe summary per
  // channel and delivers it. It runs LAST (after the alert/expiry/restore-test passes) so a digest can
  // never delay a backup or any higher-priority notification, and the whole block is guarded so a DO
  // hiccup OR a delivery failure degrades to "no digest this tick", never a crashed cron. The DO has
  // no wall clock, so the Worker PASSES IN the current epoch-millis; the window per channel is computed
  // in the DO from that minus the channel's oldest deferred entry. The DO returns no batches when
  // nothing is deferred or no window has elapsed, so the common case costs one storage read.
  await guarded("digest", "digest flush", () => flushDigests(env, scheduler));

  // New-version alert (W3): pull + verify the signed update channel and, when it advertises a NEWER
  // recommended version than the running engine, fire ONE notification through the customer's existing
  // notify channels. It runs LAST (lowest priority, never delays a backup), is PULL-ONLY + signature-pinned
  // (the vendor never pushes, no new trust surface), deduped in the DO to fire ONCE per new version (never
  // spammed), and FULLY fail-open: an unconfigured channel, a failed check, or a delivery fault all degrade
  // to "no alert this tick", never a crashed cron and never anything touching the data or recovery path.
  await guarded("update-alert", "update-available alert", () => runUpdateAlertIfNew(env, scheduler));

  // Outbound SIEM audit-log push: drain audit events since the last-pushed
  // cursor to the configured push destination, if any. OPT-IN (no destination configured, or disabled, is a
  // silent no-op) and runs LAST so it never delays a backup or a higher-priority notification; the whole
  // block is guarded so a DO hiccup or an unexpected fault degrades to "no push this tick", never a crashed
  // cron. A rejected delivery to the customer's own SIEM endpoint is still a COMPLETED pass (the outcome is
  // recorded on the trail and the audit chain); only an unexpected fault counts against passErrors.
  try {
    tallyPass("siem-push", await runSiemPushPass(env, scheduler));
  } catch (e) {
    passErrors++;
    noteCronPass("siem-push", false, e);
    log("error", `siem push pass skipped this tick: ${(e as Error).message}`);
  }

  // Outbound OTLP/HTTP metrics push: push the canonical backup-health
  // metric snapshot to the configured OTLP collector, if any. OPT-IN (no destination configured, or
  // disabled, is a silent no-op) and runs LAST alongside the SIEM push so it never delays a backup or a
  // higher-priority notification; the whole block is guarded so a DO hiccup or an unexpected fault degrades
  // to "no push this tick", never a crashed cron. A rejected delivery to the customer's own collector is
  // still a COMPLETED pass (the outcome is recorded on the trail); only an unexpected fault counts against
  // passErrors.
  try {
    tallyPass("otlp-push", await runOtlpPushPass(env, scheduler));
  } catch (e) {
    passErrors++;
    noteCronPass("otlp-push", false, e);
    log("error", `otlp push pass skipped this tick: ${(e as Error).message}`);
  }

  // Record the per-tick OUTCOME LAST (scheduler-liveness new-logging): the DO appends a clamped, redaction-safe
  // TickReport (counts + flags only) to its bounded ring, stamping the time and deriving the interval since the
  // prior tick. This is the pack's answer to "the cron reported green but my backups silently stopped": a tick
  // that dispatched 0 of N due (DO blip / all coalesced), overdrew its subrequest budget (starvation), or
  // crashed a pass is now durably visible, and a large tick interval reveals missed ticks. Fully fail-open: a
  // recording fault degrades to "no outcome this tick", never a crashed cron (the interval on the NEXT recorded
  // tick still reveals the gap). It is the final act of the invocation so the budget spend reflects the whole tick.
  try {
    await scheduler.fetch(doURL("/tick-outcome"), {
      method: "POST",
      body: JSON.stringify({
        due: due.length,
        dispatched: sealSummary.dispatched,
        coalesced: sealSummary.coalesced,
        carried: sealSummary.carried,
        sealErrors: sealSummary.sealErrors,
        passErrors,
        budgetCap: budget.subrequestBudget,
        budgetSpent: budget.subrequestsSpent,
      }),
    });
  } catch (e) {
    // G205: the tick-outcome POST itself failed, so this tick leaves a HOLE in the ring. Note it in the
    // isolate-local tally so the NEXT healthy tick reports the hole with a cause, rather than the ring
    // silently skipping an entry (indistinguishable from a cron that never fired).
    noteTickRecordFailure();
    log("error", `tick-outcome record skipped this tick: ${(e as Error).message}`);
  }

  // The invocation's HEALTH evidence, posted LAST (G084/G132/G133/G205/G220/G234/G278): which passes ran and
  // which failed with what closed class, the tick-ring holes carried from ticks that could not report at all,
  // the cf-config discovery skips, the auto-heal stalls, the beacon's env presence + fail class, and the SIEM
  // shaping/cursor fallbacks. Both writes are CHECKED (a dropped post is counted in droppedWrites and lands
  // the moment the DO comes back) and neither throws: observing a cron fault must never crash the cron.
  await recordCronDestProbeFaults(scheduler);
  await recordCronHealth(scheduler, CRON_INTERVAL_MS);
}
