// The OPERATIONAL-SIGNAL and REPORTING half of the SchedulerDO's RPC dispatch (the route() dispatcher,
// sub-mixin 2 of 4). This sub-mixin owns the per-subsystem sub-dispatch methods for SRE alerting +
// notifications + the expiry tracker (the cooldown-throttled, two-phase reconcile/deliver signal
// hooks) and the reporting surfaces (scheduled restore-tests, posture, the report data the router
// signs, and coverage). Each method is a switch over the SAME `${method} ${pathname}` key that
// returns the handler Response for a key it owns or null ("not my route"); route() (in
// scheduler-do-routing.ts) chains these among the other sub-dispatches. This sub-mixin's `this` is
// SchedulerDOSurface (like every sibling mixin), so each sub-dispatch calls the owning handler
// (this.reconcileAlerts / this.listNotifyChannels / this.computePostureReport / ...) with the SAME
// dispatch and `this` binding.

import { CALLER_HEADER, decodeCaller } from "../admin/identity.ts";
import { redactChannelSecretForRead } from "../notify.ts";
import { readSchedDiag, recordClientDiagnostics, recordContractFault } from "./sched-fault-ledger.ts";
import { CRON_ALERT_SWEEP_AT_KEY, type SchedulerDOCtor } from "./scheduler-do-base.ts";

export function RoutingSignalsMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // SRE alerting: the two-phase reconcile/deliver hooks (base + 3-2-1 replication).
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link. The arms are verbatim from the original single switch.
    async routeSreAlerting(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "POST /reconcile-alerts":
        // DEP-04 cron heartbeat: stamp that the CRON-driven alert sweep ran this tick, so the DO's own
        // alarm() can tell when the cron has gone silent (a deploy dropping [triggers].crons) and run the
        // staleness sweep itself as a cron-independent dead-man. ONLY the cron reaches this route; the
        // alarm backstop calls reconcileAlerts() directly, so this marker is a pure cron-liveness signal.
        await this.state.storage.put(CRON_ALERT_SWEEP_AT_KEY, Date.now());
        return this.json(await this.reconcileAlerts());
      // POST /source-drift/reconcile is the proactive source-detached sibling of /reconcile-alerts: the cron
      // driver computes the CURRENT set of configured-but-unbound source binding names (live env vs roster)
      // and posts them here; the DO edge-triggers (diffs vs the stored marker) and returns the NEWLY detached
      // ones so the Worker routes exactly one "source-detached" alert per new detach. NO network I/O here.
      case "POST /source-drift/reconcile": {
        // G221: the `?? []` coercion below is not benign - an EMPTY list means "nothing is detached any more",
        // so a malformed body silently CLEARS the detached-source marker and a real, ongoing source detachment
        // reads as healed in the pack. Count the coercion (never the body) before taking it.
        const driftBody = (await req.json()) as { missing?: unknown };
        if (!Array.isArray(driftBody.missing)) await recordContractFault(this.state.storage, "drift-reconcile", driftBody.missing === undefined ? "coerced-default" : "bad-body");
        return this.json(await this.reconcileSourceDrift(Array.isArray(driftBody.missing) ? (driftBody.missing as string[]) : []));
      }
      // POST /volume-regression/reconcile is the retention volume-guard sibling of /source-drift/reconcile: the
      // retention prune pass posts the CURRENT set of downpipe ids whose volume high-water run the guard held,
      // and the DO edge-triggers (diffs vs the stored marker) and returns the NEWLY regressed ones so the Worker
      // routes exactly one "backup-volume-regression" alert per new regression. NO network I/O here.
      case "POST /volume-regression/reconcile": {
        // G221: same `[]` coercion, same consequence - a malformed body clears the volume-regression marker, so
        // a downpipe whose backup volume collapsed reads as recovered.
        const volBody = (await req.json()) as { regressed?: unknown };
        if (!Array.isArray(volBody.regressed)) await recordContractFault(this.state.storage, "volume-reconcile", volBody.regressed === undefined ? "coerced-default" : "bad-body");
        return this.json(await this.reconcileVolumeRegression(Array.isArray(volBody.regressed) ? (volBody.regressed as string[]) : []));
      }
      // POST /alerts-delivered is the two-phase callback the Worker calls after it has attempted
      // to POST the alert batch. deliveredIds carries the downpipe ids for which the delivery
      // succeeded (or for which the cooldown should be kept regardless); failedTransitionIds
      // carries the downpipe ids whose cooldown was recorded optimistically as a state-TRANSITION
      // alert but whose delivery failed. Clearing a failed transition's cooldown means the next
      // tick re-attempts rather than suppressing it for the full cooldown window, which is the
      // scenario that matters most: the very first notification of a brand-new failure.
      case "POST /alerts-delivered":
        return this.json(await this.markAlertsDelivered((await req.json()) as { deliveredIds?: string[]; failedTransitionIds?: string[] }));
      // POST /recovery-delivered is the two-phase callback for the auto-resolve RECOVERY batch (finding F4),
      // the recovery mirror of /alerts-delivered. deliveredIds clear the owed-resolve marker (the resolve
      // landed); `failed` carries the recoveries whose delivery failed (with the alert state their resolve
      // closes) so the DO writes/keeps a pending-recovery marker and reconcileAlerts retries on later ticks.
      case "POST /recovery-delivered":
        return this.json(await this.recordRecoveryDelivery((await req.json()) as { deliveredIds?: string[]; failed?: Array<{ id?: unknown; state?: unknown }> }));
      // POST /reconcile-replication-alerts is the 3-2-1 replication-health sibling of /reconcile-alerts:
      // the cron driver calls it each tick to learn which fan-out downpipes have a degraded proven-copy
      // set or a run about to age out while a copy still lags. It returns redaction-safe emissions
      // (already carrying their NotifyEvent + severity) and the transition ids for the two-phase clear,
      // and does NO network I/O itself (the Worker delivers, the same separation as reconcile-alerts).
      case "POST /reconcile-replication-alerts":
        return this.json(await this.reconcileReplicationAlerts());
      // POST /replication-alerts-delivered is the two-phase callback: the Worker reports which
      // state-transition replication alerts failed to deliver so the DO clears their cooldown and the
      // next tick re-attempts (the repl-alert-cd: sibling of /alerts-delivered).
      case "POST /replication-alerts-delivered":
        return this.json(await this.markReplicationAlertsDelivered((await req.json()) as { failedTransitionIds?: string[] }));
      // Notifications (contract section 2): channels, rules, history, and the internal routing hooks.
      // Channels/rules WRITES are gated by the router on notify.config; the DO re-checks the forwarded
      // caller holds the capability (defence in depth, like requireCapability). READS are
      // any authenticated role (the router gates them on posture.read; the two read arms below take no
      // caller, so the router is the only enforcement point for these reads). The two INTERNAL
      // routes (/notify/resolve and
      // /notify/record) are the same two-phase pattern as reconcile-alerts/alerts-delivered: the DO
      // resolves routing + records the digest deferral and returns the immediate channels for the
      // Worker to deliver (the Worker holds env for the send_email binding and the network POST), then
      // the Worker posts the per-channel outcomes back so the DO appends the redaction-safe history.
        default:
          return null;
      }
    }

    // Notifications (contract section 2): channels, rules, history, the routing/record hooks, and digest flush.
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link. The arms are verbatim from the original single switch.
    async routeNotify(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "GET /notify/channels":
        // The operator-facing list REDACTS each channel's sealed apiKey (presence-only; the jsm/servicenow
        // bearer/basic credential must never round-trip out of a read, even on the CONFIG_WRAP_KEY-absent
        // plaintext floor). The INTERNAL single-channel read (GET /notify/channel below) is NOT redacted --
        // the router's test-send delivery path needs the real credential to authenticate the send.
        return this.json((await this.listNotifyChannels()).map(redactChannelSecretForRead));
      case "POST /notify/channels":
        return this.gatedConfigMutation("notify-channel-set", (await req.json()) as unknown, decodeCaller(req.headers.get(CALLER_HEADER)));
      case "POST /notify/channels/delete":
        return this.gatedConfigMutation("notify-channel-delete", (await req.json()) as { id?: string }, decodeCaller(req.headers.get(CALLER_HEADER)));
      case "GET /notify/rules":
        return this.json(await this.listNotifyRules());
      case "POST /notify/rules":
        return this.gatedConfigMutation("notify-rule-set", (await req.json()) as unknown, decodeCaller(req.headers.get(CALLER_HEADER)));
      case "POST /notify/rules/delete":
        return this.gatedConfigMutation("notify-rule-delete", (await req.json()) as { id?: string }, decodeCaller(req.headers.get(CALLER_HEADER)));
      case "GET /notify/history":
        return this.json(await this.listNotifyHistory());
      case "GET /notify/channel":
        // Internal single-channel fetch the router's test-send uses (the router delivers with env).
        return this.json(await this.getNotifyChannel(url.searchParams.get("id")));
      case "POST /notify/history/test-send":
        // Records a manual test-send outcome on the history ring, flagged test:true (router-gated on
        // notify.config; the mixin re-checks). Rules and digests never read it.
        // G246 (R7): code + platformCode ride the body so the persisted test row carries a REASON. Both are
        // re-gated inside recordTestSend against the same closed sets the real delivery path uses.
        return this.json(await this.recordTestSend(decodeCaller(req.headers.get(CALLER_HEADER)), (await req.json()) as { channelId?: unknown; delivered?: unknown; detail?: unknown; code?: unknown; platformCode?: unknown }));
      case "POST /notify/resolve":
        return this.json(await this.resolveNotify((await req.json()) as { emission?: unknown }));
      case "POST /notify/record":
        return this.json(await this.recordNotify((await req.json()) as { emission?: unknown; records?: unknown }));
      // Digest flush (contract section 2: the daily/weekly success-stream summary). The Worker PASSES
      // IN nowMs (the DO has no wall clock); /notify/digest-due returns the per-channel batches whose
      // window has elapsed (computed from nowMs minus that channel's oldest deferred entry), and the
      // paired /notify/digest-sent {ids} clears EXACTLY the pending entries the Worker delivered. Both
      // are INTERNAL (reached only by the cron driver's scheduler.fetch, like /notify/resolve|record).
      case "POST /notify/digest-due":
        return this.json(await this.digestDue((await req.json()) as { nowMs?: unknown }));
      case "POST /notify/digest-sent":
        return this.json(await this.digestSent((await req.json()) as { ids?: unknown }));
      // NOTIF needs-new-logging: the Worker reports a SILENT drop in the notify pipeline so "alerts stopped"
      // is visible: a whole pass skipped (a /notify/resolve|record DO fetch threw) or a delivery-feedback
      // failure (the /alerts-delivered confirm threw, leaving a pipe in cooldown). Closed field only. INTERNAL.
      case "POST /notify/health-bump": {
        const body = (await req.json()) as { field?: unknown };
        const field = body.field === "passSkips" || body.field === "feedbackFails" ? body.field : null;
        if (field === null) {
          // G221: an out-of-vocabulary field is REJECTED here while the Worker's fire-and-forget bump ignores
          // the 400 - so after a partial deploy the notify drop-counter silently stops incrementing and the
          // pack shows a healthy notify pipeline through an outage. Count the enum drift.
          await recordContractFault(this.state.storage, "notify-health", "enum-drift");
          return this.jsonStatus({ ok: false, reason: "a valid health field is required" }, 400);
        }
        await this.bumpNotifyHealth(field);
        return this.json({ ok: true });
      }
      // The notify-pipeline drop-counter record, read by the support pack (counts + a timestamp only).
      case "GET /notify/health":
        return this.json((await this.getNotifyHealth()) ?? { passSkips: 0, recordSkips: 0, parseRejects: 0, feedbackFails: 0, lastAt: "" });
      // The pending-digest queue depth + oldest deferred entry + the per-cadence window state (dueAt), so a
      // digest that never flushes shows WHICH cadence is stuck and WHEN its batch should have flushed.
      case "GET /notify/digest-pending":
        return this.json(await this.digestPending());
      // The per-downpipe alert-cooldown state (cooldown-suppresses-renudge-1h): which pipes are within a
      // re-nudge cooldown and since when, so "why didn't I get re-alerted about a still-broken pipe" is
      // answerable. Read-only, redaction-safe (downpipe id + a closed state enum + an epoch ms).
      case "GET /notify/cooldowns":
        return this.json(await this.listAlertCooldowns());
      // Credential and key expiry tracker (contract section 4). The items live in THIS DO under the
      // `expiry:` prefix. WRITES gate on the expiry.config capability (the router gates first; the DO
      // re-checks the forwarded caller, defence in depth like requireNotifyConfig). READS (GET /expiry)
      // are any authenticated role (the router gates on posture.read; the arm below takes no caller, so the
      // router is the only enforcement point for this read). The route returns COMPUTED ExpiryStatus[] (the
      // daysRemaining + state projection), not the raw items, so a reader cannot distinguish "stored
      // expiry" from "computed view". POST /expiry/reconcile is the INTERNAL hook the cron driver calls
      // each tick: the DO computes which items have crossed a NEW notification threshold (transition-
      // based, cooldown-throttled, mirroring reconcileAlerts) and returns the emissions for the Worker
      // to route out-of-band; the DO does no network I/O itself.
        default:
          return null;
      }
    }

    // Credential and key expiry tracker (contract section 4).
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link. The arms are verbatim from the original single switch.
    async routeExpiry(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "GET /expiry":
        return this.json(await this.listExpiryStatuses());
      case "GET /expiry/warnings":
        // Internal: the router calls this during GET /admin/status to light up status.expiryWarnings.
        return this.json(await this.expiryWarningCount());
      case "POST /expiry":
        // Routed through the change-control gate (gatedConfigMutation): gate OFF applies inline as before;
        // gate ON queues a pending change a second expiry.config holder must approve, so a tracked-expiry
        // change obeys the same "config changes need two approvers" model the customer expects.
        return this.gatedConfigMutation("expiry-item-set", (await req.json()) as unknown, decodeCaller(req.headers.get(CALLER_HEADER)));
      case "POST /expiry/delete":
        return this.gatedConfigMutation("expiry-item-delete", (await req.json()) as { id?: string }, decodeCaller(req.headers.get(CALLER_HEADER)));
      case "POST /expiry/reconcile":
        return this.json(await this.reconcileExpiry());
      case "POST /expiry/observe-licence":
        // INTERNAL (reached only by the router's own scheduler.fetch): after a licence activate/clear,
        // refresh or drop the engine-OBSERVED `licence` expiry item from the licence token's own
        // notAfter (an artefact the engine already holds + verifies, no secret). Credential lifecycle.
        return this.json(await this.observeLicence((await req.json()) as { notAfter?: unknown }));
      case "POST /expiry/observe-attach":
        // INTERNAL: the router calls this after a source attach to record the spent ephemeral attach
        // token as a pending-cleanup registry row (reminding the operator to delete it in Cloudflare).
        return this.json(await this.observeAttach((await req.json()) as { tokenId?: unknown; expiresOn?: unknown; permissionSummary?: unknown; sourcesAttached?: unknown }));
      case "POST /expiry/cleanup-attest":
        // The operator attests they deleted a spent credential in Cloudflare (expiry.config; the router
        // gates first, the DO re-checks). An ATTESTATION, never a verified deletion.
        return this.json(await this.cleanupAttest((await req.json()) as { id?: unknown }, decodeCaller(req.headers.get(CALLER_HEADER))));
        default:
          return null;
      }
    }

    // Scheduled restore tests (contract section 5) + the restorability-proven record.
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link. The arms are verbatim from the original single switch.
    async routeRestoreTests(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "POST /restore-tests-due":
        return this.json(await this.restoreTestsDue());
      case "POST /restore-test-complete":
        return this.json(await this.completeRestoreTest((await req.json()) as { id?: string; ok?: boolean; at?: number; reason?: string; deferred?: string; durationMs?: number; bytesVerified?: number; recordsVerified?: number; deepVerify?: { runId?: string; cursor?: number; records?: number; wrapped?: boolean }; oom?: { maxRecordBytes?: number; safeBytes?: number; overSafe?: boolean } }));
      // restore-test-tick-killed: the cron driver stamps the "drill in flight" marker just before running a
      // scheduled restore-test drill; completeRestoreTest clears it on completion, so a marker left behind is
      // the read-side "the drill's tick was killed mid-flight" signal. DIAGNOSTIC only (a single timestamp).
      case "POST /restore-test-start":
        return this.json(await this.startRestoreTest((await req.json()) as { id?: string; at?: number }));
      // Orphan-reconcile pack signal (support-pack modes reconcile-orphans-invisible / runlog-corrupt-parse):
      // the cron's REPORT-ONLY reconcile pass posts a bounded, redaction-safe per-destination inventory +
      // RUNLOG-health summary here (POST), and the support bundle reads it back (GET). Both are DIAGNOSTIC
      // only: nothing here reads or mutates an archive, RUNLOG or the seal path; recordReconcileInventory
      // re-validates + clamps every field (fail-closed on a malformed value).
      case "POST /reconcile-inventory":
        return this.json(await this.recordReconcileInventory((await req.json()) as Record<string, unknown>));
      case "GET /reconcile-inventory":
        return this.json(await this.reconcileInventory());
      // Retention-prune pass record (gaps G071/G190): the cron's retention pass posts ONE bounded,
      // redaction-safe record per tick (POST) -- what it skipped and why, what each downpipe's prune actually
      // did (applied / dry-run / no-op / deferred / error, with the CLOSED deferral and error classes), and how
      // many prune AUDIT writes were lost -- and the support bundle reads the latest back (GET), so the whole
      // "storage keeps growing despite my retention policy" family (enforce never set / perpetually deferred /
      // half-applied / WORM-refused) is diagnosable. DIAGNOSTIC only: nothing here reads or mutates an
      // archive, RUNLOG or the seal path;
      // recordRetentionPass re-runs the sanitiser on the posted body (drifted enums dropped, counts clamped).
      case "POST /retention-record":
        return this.json(await this.recordRetentionPass((await req.json()) as Record<string, unknown>));
      case "GET /retention-state":
        return this.json(await this.retentionState());
      // Seal-fault OBSERVE ring (support-pack seal-integrity modes shard-list-truncated /
      // shard-truncation-stalekeys / lease-lost-abandon / orphan-root-worm-leak / signer-rotation-strands-runs):
      // the per-downpipe seal DO posts a coarse observation at a fault's detection point (POST), and the
      // support bundle reads them back (GET). DIAGNOSTIC only -- nothing here reads or mutates an archive,
      // RUNLOG or the seal path; recordSealFault re-validates + clamps + drops an out-of-vocabulary kind.
      case "POST /seal-fault":
        return this.json(await this.recordSealFault((await req.json()) as Record<string, unknown>));
      case "GET /seal-faults":
        return this.json(await this.sealFaults());
      // The SCHEDULER-DO FAULT LEDGER (sched-fault-ledger.ts): the single INTERNAL read the support pack
      // projects for the DO-side ceremony faults (G013/G014/G039), the errorId ring a customer's quoted
      // "err:ab12cd" is dereferenced against (G013), the Worker<->DO contract faults (G221), the recorders' own
      // dropped writes (G104 - a non-zero count means every other counter in the pack is a LOWER BOUND for that
      // window), the env-default destination's reachability heartbeat (G120) and the downpipes whose staleness
      // rule can never arm (G076). Redaction-safe by construction: closed-enum keys, integer counts, clamped
      // timestamps, opaque server-minted error ids and the customer's own downpipe labels.
      case "GET /sched-diag":
        return this.json(await readSchedDiag(this.state.storage));
      // CLIENT DIAGNOSTICS (G172/G173/G174/G176/G178/G181, and the console half of G097). The console keeps a
      // bounded, closed-class diagnostic ring IN THE BROWSER -- a crashed boot, a console-Worker 500, a bulk
      // protect that created 300 of 1000 and halted, an update stuck at "Still verifying", a dual-control route
      // 404ing after a partial upgrade -- and POSTS it here when the customer generates a support pack. It is
      // NOT a background beacon: nothing is transmitted anywhere on its own, and the evidence rides only inside
      // the point-in-time artefact the customer chose to share.
      //
      // The body is UNTRUSTED (browser-authored). recordClientDiagnostics -> applyClientDiagnostics is the
      // single redaction chokepoint: every enum is closed-set validated (an out-of-vocabulary value is DROPPED,
      // never stored, so no browser string can become a storage key), every count is clamped, the build id must
      // be version-shaped, and nothing else on the body is read -- so an error message, a stack, a screen name,
      // a route path, an item name or a URL structurally cannot enter the pack. It is best-effort and never
      // throws: a diagnostic ring must never be able to fail the pack build that carries it.
      case "POST /client-diag":
        await recordClientDiagnostics(this.state.storage, await req.json().catch(() => ({})));
        return this.json({ ok: true });
      // On-demand fleet drill (SCALE-2): start a bulk restore-test campaign over the whole fleet (or a
      // downpipeIds subset). The router gates the public /drill-all route on drill.run and forwards the
      // verified caller; the DO re-checks drill.run on that caller (defence in depth) and refuses to clobber
      // an in-progress campaign. The body is optional ({} when absent), so a bare POST drills everything.
      case "POST /fleet-drill/start":
        return this.json(await this.startFleetDrill((await req.json().catch(() => ({}))) as { downpipeIds?: unknown }, decodeCaller(req.headers.get(CALLER_HEADER))));
      // INTERNAL (the cron driver): return up to `cap` downpipe states to drill this tick from the active
      // campaign, marking each in flight. The cron runs each drill OUT OF THE DO via the same scheduled-test
      // path and the /restore-test-complete callback advances the campaign.
      case "POST /fleet-drill/next":
        return this.json(await this.fleetDrillNextBatch((((await req.json().catch(() => ({}))) as { cap?: number }).cap) ?? 1));
      // The fleet-drill progress view (active campaign, else the last finished one). Read-only, redaction-safe;
      // the router forwards GET /admin/drill-all here for the console progress surface.
      case "GET /fleet-drill/status":
        return this.json(await this.fleetDrillStatus());
      // Restorability assurance: record the "offline restorability last proven" record for a downpipe
      // after a BLIND restore test or KEYLESS attestation PASSED. The router gates the public route on
      // restore.verify and forwards the verified caller; the DO re-checks restore.verify on that caller
      // (defence in depth, like requireCapability for the other write paths) and stamps who+when+method
      // onto the downpipe state. It carries only redaction-safe provenance (no key, no value).
      case "POST /restore-proven":
        return this.json(await this.recordRestoreProven((await req.json()) as { downpipeId?: string; method?: string; runId?: string; at?: number }, decodeCaller(req.headers.get(CALLER_HEADER))));
      // Attended verification (key-posture attend). The SESSION state machine under `attest-session:<id>`
      // (scheduler-do-attest.ts) + the NARROW per-run compliance stamp (observability's
      // recordAttendedVerification). The router does the crypto (issue the challenge, verify the proof, read
      // capsules, sample runs from a master) and forwards redaction-safe results here; every method re-checks
      // drill.run + ownership (caller.subject === session.createdBy) on the forwarded caller. The MASTERS never
      // reach the DO -- they are used only in the router's verify request. INTERNAL (the router's own
      // scheduler.fetch, like /restore-proven). attest-record is admin-driven, not a cron route.
      case "POST /attest-session/create":
        return this.json(await this.attestSessionCreate((await req.json()) as { sampleRate?: number; seedB64?: string; proofHash?: string; runs?: Array<{ downpipeId?: string; runId?: string; name?: string; recordCount?: number }> }, decodeCaller(req.headers.get(CALLER_HEADER))));
      case "GET /attest-session/get":
        return this.json(await this.attestSessionGet(url.searchParams.get("id") ?? "", decodeCaller(req.headers.get(CALLER_HEADER))));
      case "POST /attest-session/prove":
        return this.json(await this.attestSessionMarkProven(((await req.json()) as { id?: string }).id ?? "", decodeCaller(req.headers.get(CALLER_HEADER))));
      case "POST /attest-session/record-verify":
        return this.json(await this.attestSessionRecordVerify((await req.json()) as { id?: string; results?: Array<{ runId?: string; state?: string; recordsVerified?: number; recordsTotal?: number; at?: number }> }, decodeCaller(req.headers.get(CALLER_HEADER))));
      case "POST /attest-session/abort":
        return this.json(await this.attestSessionAbort(((await req.json()) as { id?: string }).id ?? "", decodeCaller(req.headers.get(CALLER_HEADER))));
      case "POST /attest-record":
        return this.json(await this.recordAttendedVerification((await req.json()) as { downpipeId?: string; runId?: string; ok?: boolean; sampleRate?: number; provenSession?: boolean; reason?: string; at?: number }, decodeCaller(req.headers.get(CALLER_HEADER))));
      // Security centre / posture (contract section 7). The DO is the storage authority for the
      // risk-accept records (`posture-accept:` prefix) and the regression snapshot (POSTURE_SNAPSHOT_KEY).
      // POST /posture COMPUTES the report: the router supplies the env-derived presence slice (it cannot
      // be read in the DO) plus the beacon flag in the body; the DO adds the state it
      // owns (downpipes + recency, expiry statuses, the failure-rule boolean, the owner count, the
      // identity slice, the override records), runs the pure computePosture, snapshots the outcome set,
      // detects any previously-good check that now needs attention, and returns the report PLUS the regressions for the
      // router to route as posture-regression notifications (the DO does no network I/O, the same
      // separation as reconcileAlerts). The two writes (accept/unaccept) re-check posture.riskaccept from
      // the forwarded caller (defence in depth, like requireCapability). It is a POST because it computes and
      // snapshots (a state mutation); the router gates it on posture.read for the read intent.
        default:
          return null;
      }
    }

    // Security centre / posture (contract section 7): compute + the risk-accept writes.
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link. The arms are verbatim from the original single switch.
    async routePosture(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "POST /posture":
        return this.json(await this.computePostureReport((await req.json()) as { status?: unknown; beaconEnabled?: unknown; callerEmail?: unknown; worm?: unknown }));
      // The scheduled-evaluation due check (the cron posture pass): a cheap snapshot-age read so the
      // pass only pays a full computation (including the live WORM probe) when the interval has lapsed.
      case "POST /posture/evaluation-due":
        return this.json(await this.postureEvaluationDue((await req.json()) as { intervalMs?: unknown }));
      case "POST /posture/accept":
        return this.gatedConfigMutation("posture-accept", (await req.json()) as { checkId?: string; reason?: string; kind?: string }, decodeCaller(req.headers.get(CALLER_HEADER)));
      case "POST /posture/unaccept":
        return this.gatedConfigMutation("posture-unaccept", (await req.json()) as { checkId?: string }, decodeCaller(req.headers.get(CALLER_HEADER)));
      // Reporting (contract section 6). The DO gathers the per-kind data it owns (drill-evidence + recency
      // for restore-tests; the run-history-derived run stats for sla-compliance) and returns the
      // structured body; the router assembles + signs the Report (the signer is in env, which the DO does
      // not hold). The posture and immutability bodies are assembled by the router directly (posture via
      // POST /posture above; immutability from the env-derived status slice), so they need no DO data
      // route. period is forwarded so the DO bounds the evidence/run window. INTERNAL (reached only by the
      // router's own scheduler.fetch); the router gates the public route on reports.read.
        default:
          return null;
      }
    }

    // Reporting (contract section 6): the per-kind data the DO owns for the router to assemble + sign.
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link. The arms are verbatim from the original single switch.
    async routeReports(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "POST /reports/restore-tests-data":
        return this.json(await this.restoreTestsReportData((await req.json()) as { period?: unknown }));
      case "POST /reports/sla-data":
        return this.json(await this.slaReportData((await req.json()) as { period?: unknown }));
      case "POST /reports/change-requests-data":
        // The change-requests report gather: the change-recorded CR ledger entries. The router period-filters +
        // projects them (buildChangeRequestsReport); they are already redaction-safe audit events.
        return this.json({ events: await this.gatherChangeRecordedEvents() });
      // Coverage and gap detection (what is and is not backed up). The reference inventory lives in THIS
      // DO under the single COVERAGE_INVENTORY_KEY, stored as REFERENCE DATA ONLY: it is structurally
      // distinct from every binding/secret/dp: key, it never grants data access, and no seal/restore path
      // ever reads it. POST /coverage/inventory gates on access.policy (the DO re-checks the forwarded
      // caller, defence in depth, like the people/access-policy writes) and stores the validated, bounded
      // inventory. GET /coverage computes the gap view from the inventory + the downpipe states the DO
      // already holds; with NO inventory stored it returns the honest-unknown shape (hasInventory:false),
      // never an implied full coverage. The read is any authenticated role (the router gates it on
      // posture.read); it is the customer's own redaction-safe coverage view.
        default:
          return null;
      }
    }

    // Coverage and gap detection: the reference inventory write + the computed gap view.
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link. The arms are verbatim from the original single switch.
    async routeCoverage(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "POST /coverage/inventory":
        return this.gatedConfigMutation("coverage-inventory", (await req.json()) as unknown, decodeCaller(req.headers.get(CALLER_HEADER)));
      case "GET /coverage":
        return this.json(await this.coverage());
      // Config-as-a-source versioning (Phase 4, the DEFAULT self-contained layer). The hash-chained,
      // signed version history lives in THIS DO under the `confighist:` prefix, a dedicated keyspace
      // entirely separate from the data-backup R2 archive and the `audit:` chain. It is PURELY ADDITIVE
      // observability: a version is captured AFTER a config mutation has already committed (auto-snapshot,
      // best-effort, never failing the mutation) or on an explicit manual snapshot, and nothing here
      // gates or alters how config is applied. POST /config/snapshot is the manual capture (the router
      // gates it on access.policy, the owner/policy level; the DO records the requesting author). The
      // three reads (history list, one version, the plain-English diff) are forwarders the router gates on
      // downpipe.read (the same read capability that lets a caller view the config via GET /downpipes);
      // the DO serves them from the stored, ordered chain. None accept a secret value: a snapshot
      // references secrets by NAME only (snapshotConfig copies a closed named-metadata set, never a value).
        default:
          return null;
      }
    }
  };
}
