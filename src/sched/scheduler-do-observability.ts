// engine-sys-struct-06 / engine-sys-arch-01 (god-module split): the read-mostly observability cluster
// (contract section 5 scheduled restore tests and section 7 security-centre posture) extracted from the
// SchedulerDO god module into a mixin. The section 6 reporting + RTO + coverage/gap detection sibling lives
// in ./scheduler-do-reporting.ts (ReportingMixin), split out so neither file exceeds the module-size
// guardrail. ObservabilityMixin layers these methods over a base whose `this` is SchedulerDOSurface, so they keep calling
// `this.appendAudit`, `this.listDownpipes`, `this.requireCapabilityResolved`, `this.state` etc. exactly
// as before; dispatch and `this` binding are byte-identical. No storage key, route string, status code,
// response body or auth gate changed; the same capability re-checks run on the same paths in the same order.

import { isWrappedSecret, } from "../admin/config-secret.ts";
import { expiryStatuses } from "../admin/expiry.ts";
import type { AuthMethod, Capability, Role } from "../admin/identity.ts";
import { listIdpConnections } from "../admin/oidc-store.ts";
import { computePosture, detectRegressions, isKnownCheckId, isOverrideKind, overrideOf, POSTURE_ACCEPT_PREFIX, POSTURE_ID_PATTERN, POSTURE_SNAPSHOT_KEY, type PostureDownpipeInput, type PostureExpiryInput, type PostureIdentityInput, type PostureInput, type PostureOverrideInput, type PostureRegression, type PostureReport, type PostureSnapshot, type PostureWormInput, type RiskAccept, snapshotOf } from "../admin/posture.ts";
import { remainingCount } from "../admin/recovery.ts";
import { appendRtoSample } from "../admin/rto.ts";
// G324: the closed beacon failure-cause vocabulary the cron already computes; the DO re-validates against it.
import { BEACON_FAIL_CLASSES } from "../cron/cron-fault-ledger.ts";
import { type RetentionPassRecord, sanitiseRetentionPassRecord } from "../cron/retention-record.ts";
import { ruleSelects } from "../notify.ts";
import { type ReconcileSignal, sanitiseReconcileSignal } from "../seal/reconcile.ts";
import { type SealFault, sanitiseSealFault } from "../seal/seal-faults.ts";
import { allDestinationIds } from "./destinations.ts";
import { recordCapTruncation, recordDrillDrop, recordPostureInputFault, recordStorageAnomaly, recordVocabDrop } from "./sched-fault-ledger.ts";
import { AuthError, BEACON_ATTEMPT_RING_CAP, BEACON_STATE_KEY, type BeaconAttempt, type BeaconAttemptState, type DownpipeState, DRIVE_BUDGET_YIELD_KEY, type DriveBudgetYieldState, FLEET_DRILL_ACTIVE_KEY, FLEET_DRILL_FAILED_SAMPLE, FLEET_DRILL_INFLIGHT_TIMEOUT_MS, FLEET_DRILL_LAST_KEY, FLEET_DRILL_MAX, type FleetDrillCampaign, type FleetDrillProgress, PASSKEY_USER_PREFIX, REASON_MAX_LEN, type RestoreProvenMethod, type SchedulerDOCtor } from "./scheduler-do-base.ts";
import { INFLIGHT_LEASE_MS } from "./scheduler-do-records.ts";
import { newULID, nowMillisISO, validateFreeText } from "./scheduler-helpers.ts";
import type { RunHistoryEntry } from "./types.ts";

// The orphan-reconcile pack signal (support-pack modes reconcile-orphans-invisible / runlog-corrupt-parse)
// lives under ONE key as a { [destKey]: ReconcileSignal } map, bounded to the freshest RECONCILE_SIGNAL_MAX
// destinations so a churning fleet cannot grow it unbounded. Structurally distinct from every dp:/hist:/
// repl: key; it is pure diagnostic REFERENCE data (counts + booleans), never read by any seal/restore path.
const RECONCILE_SIGNAL_KEY = "signal:reconcile";
const RECONCILE_SIGNAL_MAX = 32;

// The seal-fault observation ring (support-pack seal-integrity modes shard-list-truncated /
// shard-truncation-stalekeys / lease-lost-abandon / orphan-root-worm-leak / signer-rotation-strands-runs)
// lives under ONE key as a newest-last SealFault[] bounded to the freshest SEAL_FAULT_MAX. Like the
// reconcile signal it is pure diagnostic REFERENCE data (a closed kind + the customer's own ids + ints /
// a boolean), structurally distinct from every dp:/hist:/repl:/signal:reconcile key and never read by any
// seal / restore path. Bounded so a pathological run of faults cannot grow it unbounded.
const SEAL_FAULT_KEY = "signal:seal-faults";
// RETENTION_PASS_KEY holds the LATEST retention-prune pass record (G071/G190). A single slot, not a ring: the
// pass is a cron tick and each record supersedes the last, so one key answers "what did retention do last tick".
const RETENTION_PASS_KEY = "signal:retention-pass";
const SEAL_FAULT_MAX = 64;

export function ObservabilityMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // beaconAggregate computes the CONTENT-FREE fleet aggregate the opt-in vendor beacon carries: the
    // downpipe count, a coarse healthy/stalled split (stalled = a run whose in-flight LEASE has expired --
    // a wedged run that never completed), and ONE account-wide max recent-run index. COUNTS ONLY -- never a
    // per-downpipe row, never a name, never a value -- so the beacon built from it cannot reconstruct
    // cadence or leak data (the no-custody envelope the beacon must stay inside). It is what feeds the
    // control-plane per-account DEPLOY LEDGER (cron/beacon-emit.ts -> the cfVersionId carried alongside).
    async beaconAggregate(): Promise<{ downpipeCount: number; healthy: number; stalled: number; runlogMaxIndex: number }> {
      const states = await this.listDownpipes();
      const now = Date.now();
      let stalled = 0;
      for (const ds of states) {
        if (ds.inFlight && typeof ds.inFlightSince === "number" && now - ds.inFlightSince > INFLIGHT_LEASE_MS) stalled++;
      }
      // One account-wide max recent-run index, read from the history rings (the index lives on the run row,
      // not the downpipe state). Bounded: it scans only the bounded recent-run rings, never full history.
      const rings = await this.listAllByPrefix<RunHistoryEntry[]>("hist:");
      let runlogMaxIndex = 0;
      for (const ring of rings.values()) {
        for (const e of Array.isArray(ring) ? ring : []) {
          if (typeof e.index === "number" && e.index > runlogMaxIndex) runlogMaxIndex = e.index;
        }
      }
      return { downpipeCount: states.length, healthy: states.length - stalled, stalled, runlogMaxIndex };
    }

    // recordBeaconAttempt persists the OUTCOME of the most recent opt-in vendor-beacon POST (cron/
    // beacon-emit.ts posts it here after each attempt). Closed shape only: when it happened, whether the
    // POST returned 2xx, and the coarse HTTP status (clamped). It lets the support pack answer "is the
    // beacon reaching the vendor?" (beacon-post-lost) without the beacon path holding any state itself.
    // The beacon pass swallows any error from this call, so a persist hiccup never delays a backup.
    // G324: it now also carries the closed FAILURE CLASS the cron computed (a malformed BEACON_URL vs a
    // network fault vs a non-2xx rejection vs a DO read fault) and keeps a bounded RING of the last few
    // attempts, because a last-attempt-only ok:false with no status could say neither WHY the beacon is not
    // landing nor whether it is intermittent. errorClass is re-validated HERE against the closed
    // BEACON_FAIL_CLASSES set (an internal call, but the DO bounds its own inputs), so no caller-derived
    // string can enter the record; the URL and the ingest key were never passed and can never be stored.
    async recordBeaconAttempt(req: { ok?: unknown; status?: unknown; errorClass?: unknown }): Promise<{ ok: true }> {
      const ok = req.ok === true;
      const status = typeof req.status === "number" && Number.isFinite(req.status) ? Math.max(0, Math.min(999, Math.floor(req.status))) : undefined;
      // Closed-set validated: an out-of-vocabulary class is DROPPED, never stored.
      const errorClass = !ok && typeof req.errorClass === "string" && (BEACON_FAIL_CLASSES as readonly string[]).includes(req.errorClass) ? req.errorClass : undefined;
      const attempt: BeaconAttempt = {
        at: Date.now(),
        ok,
        ...(status !== undefined ? { status } : {}),
        ...(errorClass !== undefined ? { errorClass } : {}),
      };
      const prior = ((await this.state.storage.get(BEACON_STATE_KEY)) as BeaconAttemptState | undefined) ?? null;
      const priorRing = Array.isArray(prior?.recent) ? prior.recent : [];
      const ring = [...priorRing, attempt];
      const rec: BeaconAttemptState = {
        ...attempt,
        recent: ring.length > BEACON_ATTEMPT_RING_CAP ? ring.slice(ring.length - BEACON_ATTEMPT_RING_CAP) : ring,
      };
      await this.state.storage.put(BEACON_STATE_KEY, rec);
      return { ok: true };
    }

    // getBeaconState returns the last-recorded beacon attempt outcome, or null when the beacon has never
    // emitted (never configured, or configured-but-not-yet-ticked). Redaction-safe (timestamp + bool + int).
    async getBeaconState(): Promise<BeaconAttemptState | null> {
      return ((await this.state.storage.get(BEACON_STATE_KEY)) as BeaconAttemptState | undefined) ?? null;
    }

    // recordDriveBudgetYield bumps the cumulative cron seal-loop budget-yield tally (failover-probe-budget-
    // exhaustion): the cron posts here when the shared per-invocation subrequest budget ran low before every
    // due downpipe was dispatched, so undispatched downpipes were carried to the next tick. It has no per-run
    // home (the yield happens BEFORE a run is allocated), so this per-account counter is where the fault lives.
    // Closed shape only: a cumulative count, the last yield time, and the clamped last carried-over count. The
    // cron swallows any error from this call (best-effort, fail-open), so a persist hiccup never delays a backup.
    async recordDriveBudgetYield(req: { carried?: unknown }): Promise<{ ok: true }> {
      const prior = ((await this.state.storage.get(DRIVE_BUDGET_YIELD_KEY)) as DriveBudgetYieldState | undefined) ?? null;
      const carried = typeof req.carried === "number" && Number.isFinite(req.carried) ? Math.max(0, Math.min(1_000_000, Math.floor(req.carried))) : 0;
      const rec: DriveBudgetYieldState = {
        count: (prior?.count ?? 0) + 1,
        lastAt: Date.now(),
        lastCarried: carried,
      };
      await this.state.storage.put(DRIVE_BUDGET_YIELD_KEY, rec);
      return { ok: true };
    }

    // getDriveBudgetYield returns the cumulative seal-loop budget-yield record, or null when the seal loop has
    // never yielded (the healthy fleet-under-budget case). Redaction-safe (a count + a timestamp + an int).
    async getDriveBudgetYield(): Promise<DriveBudgetYieldState | null> {
      return ((await this.state.storage.get(DRIVE_BUDGET_YIELD_KEY)) as DriveBudgetYieldState | undefined) ?? null;
    }

    // ---- Scheduled restore tests (contract section 5) -------------------------------------
    // The cadence lives on the downpipe config (restoreTestCadenceSeconds, defaulted weekly on create);
    // the per-downpipe recency lives on the downpipe state (lastRestoreTestAt/Ok). The scheduler does
    // NOT run the drill itself (the seal/read-back stays out of the DO, the same separation as runs): it
    // reports which downpipes are DUE, the cron driver runs the in-account drill out of the DO and posts
    // the outcome back here. A break-glass-only posture (no operational private) cannot self-test; the
    // cron records an info note for it and never a false pass (the driver decides that; the DO just
    // records what it is told).

    // restoreTestsDue returns the downpipes whose scheduled restore test is due: cadence enabled
    // (restoreTestCadenceSeconds > 0) AND (never tested OR last test older than the cadence). It reads
    // only the config + recency on the state, never any key material. The driver runs each due downpipe's
    // drill and posts /restore-test-complete. A disabled downpipe is still eligible for a restore test of
    // its EXISTING archives (recovery does not depend on the schedule being active), so this does not
    // filter on config.enabled; it filters only on the restore-test cadence being on.
    async restoreTestsDue(): Promise<{ due: DownpipeState[] }> {
      const now = Date.now();
      const all = await this.listDownpipes();
      const due = all.filter((d) => {
        const cadence = d.config.restoreTestCadenceSeconds ?? 0;
        if (cadence <= 0) return false; // off
        // A post-backup retest request (completeRun stamps it when a successful run lands while the
        // last test did not pass) makes the downpipe due IMMEDIATELY: the fresh run is the evidence
        // the last test was missing, so waiting out the remaining cadence would keep a stale
        // failed/deferred verdict on screen for up to a week. Consumed by completeRestoreTest.
        if (d.restoreTestRetestAt !== undefined) return true;
        // Never tested: due once there is a RUN to drill, never immediately on creation (a downpipe with no
        // completed run yet would otherwise defer, be recorded ok:false, and read "Last test failed" despite
        // never having run). The first successful run requests the first test via the retest stamp above, so
        // nothing is lost by waiting.
        if (d.lastRestoreTestAt === undefined) return d.lastRunId !== null;
        return now - d.lastRestoreTestAt >= cadence * 1000;
      });
      return { due };
    }

    // completeRestoreTest records the outcome of a scheduled restore test onto the downpipe state
    // (lastRestoreTestAt/Ok), so posture and reports can read recency without scanning the evidence log.
    // It is the cron driver's callback after running the drill. It is a no-op for an unknown downpipe (a
    // downpipe deleted between the due-check and the completion). `at` defaults to the DO clock when
    // absent. It carries only the boolean outcome and the timestamp, never a key or value. It does NOT
    // touch the run lock, the run cadence, or the run-history ring (a restore test is a read-back drill,
    // not a backup run); it only updates the restore-test recency fields.
    async completeRestoreTest(req: { id?: string; ok?: boolean; at?: number; reason?: string; deferred?: string; durationMs?: number; bytesVerified?: number; recordsVerified?: number; deepVerify?: { runId?: string; cursor?: number; records?: number; wrapped?: boolean }; oom?: { maxRecordBytes?: number; safeBytes?: number; overSafe?: boolean } }): Promise<{ ok: true }> {
      if (typeof req.id !== "string" || req.id.length === 0) return { ok: true };
      const ds = await this.state.storage.get<DownpipeState>(`dp:${req.id}`);
      if (!ds) {
        // G059: the drill RAN, and its verdict is being thrown away because the downpipe was renamed or deleted
        // between dispatch and callback. Answering ok:true is right (the campaign must still converge), and it
        // is also why "we drilled the fleet and half the results never appeared" had no cause. Count the drop.
        await recordDrillDrop(this.state.storage, "completion-unknown-downpipe");
        return { ok: true }; // downpipe gone; nothing to record
      }
      const at = typeof req.at === "number" && Number.isFinite(req.at) ? req.at : Date.now();
      ds.lastRestoreTestAt = at;
      ds.lastRestoreTestOk = req.ok === true;
      // Any completion (pass, failure or deferral) CONSUMES a pending post-backup retest request:
      // the request asked for exactly one prompt drill, and that drill has now completed, so the
      // flag must not re-trigger next tick (a deferral or failure outcome is itself the answer;
      // the next successful run re-requests if the outcome still is not a pass).
      delete ds.restoreTestRetestAt;
      // The deferral kind: a valid kind on a not-ok completion marks this completion a DEFERRAL
      // (no-run / posture / no-records), which the console renders as "could not test", never
      // "tested and failed". A pass or a real failure clears it (absent = the last completion was
      // real evidence). Closed THREE-value vocabulary enforced here; anything else is absent.
      // no-records arrived with the drill's zero-record clause: a run holding no records was being
      // reported as a PASS, and merely flipping it to not-ok would have made the OPPOSITE false
      // claim, because the check below reads a not-ok WITHOUT a kind as real failure evidence.
      if (req.ok !== true && (req.deferred === "no-run" || req.deferred === "posture" || req.deferred === "no-records")) {
        ds.lastRestoreTestDeferred = req.deferred;
      } else {
        // G092 (version skew, the cruel one): a NEW deferral kind from a newer cron falls through this gate,
        // so a drill that could not run at all is recorded as a plain not-ok completion and the console tells
        // the customer their backup "failed its restore test". Count the drop so that accusation is traceable
        // to a skewed component rather than to their data.
        if (req.ok !== true && typeof req.deferred === "string" && req.deferred.length > 0) await recordVocabDrop(this.state.storage, "deferral-kind");
        delete ds.lastRestoreTestDeferred;
      }
      // restore-test-tick-killed: the drill reached a completion, so CLEAR the in-flight start marker
      // startRestoreTest set. A marker left BEHIND (never cleared) means the drill's cron tick was killed
      // mid-flight before it could complete -- the read-side "attempted but incomplete" signal the pack reads.
      delete ds.restoreTestStartedAt;
      // scheduled-restore-fail-reason (support pack): persist WHY the most recent scheduled restore test
      // failed + a consecutive-failure streak, so the cause survives past the bounded notify ring / evidence
      // note. A PASS clears the reason and resets the streak (absent = currently healthy); a real FAILURE
      // (ok:false WITH a reason code the cron classifier already produced) stamps the closed short code and
      // increments the streak; a DEFERRAL (ok:false with NO reason: break-glass-only posture or no completed
      // run yet) leaves both UNTOUCHED, since it is neither pass nor fail evidence. The code is stored as an
      // opaque, length-clamped string; membership in the closed vocabulary is enforced where the cron
      // classifies it and (defence-in-depth) again where the pack projects it, so a bad internal value can
      // never reach the bundle.
      if (req.ok === true) {
        delete ds.lastRestoreTestReason;
        delete ds.restoreTestConsecutiveFailures;
      } else if (typeof req.reason === "string" && req.reason.length > 0) {
        ds.lastRestoreTestReason = req.reason.slice(0, 40);
        ds.restoreTestConsecutiveFailures = (ds.restoreTestConsecutiveFailures ?? 0) + 1;
      }
      // lastRestoreOom (INFRA isolate-oom-restore): stamp the restore-subsystem OOM-risk marker the drill measured
      // (the largest single record it buffered WHOLE -- the drill has no streaming path -- the memory-safe ceiling,
      // and whether it crossed). Recorded on BOTH a pass and a drained failure, so the isolate-OOM early warning
      // rides regardless of verdict. Validated numbers only (a malformed/absent measurement is ignored, never
      // fabricated); overSafe is re-derived from the two sizes here so the stored flag can't be spoofed by the caller.
      const oom = req.oom;
      // G059: an OOM measurement the DO cannot use is IGNORED, so the isolate-OOM early warning silently stops
      // advancing and lastRestoreOom reads as "we have never measured" rather than "we keep failing to".
      if (oom !== undefined && !(typeof oom.maxRecordBytes === "number" && Number.isFinite(oom.maxRecordBytes) && oom.maxRecordBytes > 0 && typeof oom.safeBytes === "number" && Number.isFinite(oom.safeBytes) && oom.safeBytes > 0)) {
        await recordDrillDrop(this.state.storage, "malformed-oom");
      }
      if (oom && typeof oom.maxRecordBytes === "number" && Number.isFinite(oom.maxRecordBytes) && oom.maxRecordBytes > 0 && typeof oom.safeBytes === "number" && Number.isFinite(oom.safeBytes) && oom.safeBytes > 0) {
        const maxRecordBytes = Math.trunc(oom.maxRecordBytes);
        const safeBytes = Math.trunc(oom.safeBytes);
        ds.lastRestoreOom = { at, maxRecordBytes, safeBytes, overSafe: maxRecordBytes > safeBytes };
      }
      // Windowed deep-verify cursor (INT-1): persist the advanced cursor so the next scheduled tick
      // resumes where this one stopped, rotating full decrypt coverage across ticks. A killed tick never
      // posted here, so the cursor is unchanged and the next tick simply re-covers the same window (no
      // coverage lost). lastFullPassAt is stamped when a tick wrapped past the end (a full pass over every
      // record completed) and otherwise carried forward, so it records the last time the whole run was
      // deep-verified. All fields are validated numbers / the customer's own runId; never a key or value.
      const dv = req.deepVerify;
      // G059: a deep-verify cursor the DO cannot use is IGNORED, so the next tick re-covers the SAME window
      // forever: the rotating full-decrypt coverage silently stalls while the pack shows a live cursor.
      if (dv !== undefined && !(typeof dv.runId === "string" && dv.runId.length > 0 && typeof dv.cursor === "number" && Number.isFinite(dv.cursor) && dv.cursor >= 0 && typeof dv.records === "number" && Number.isFinite(dv.records) && dv.records >= 0)) {
        await recordDrillDrop(this.state.storage, "malformed-cursor");
      }
      if (dv && typeof dv.runId === "string" && dv.runId.length > 0 && typeof dv.cursor === "number" && Number.isFinite(dv.cursor) && dv.cursor >= 0 && typeof dv.records === "number" && Number.isFinite(dv.records) && dv.records >= 0) {
        const priorFullPass = ds.deepVerify && ds.deepVerify.runId === dv.runId ? ds.deepVerify.lastFullPassAt : undefined;
        const lastFullPassAt = dv.wrapped === true ? at : priorFullPass;
        ds.deepVerify = {
          runId: dv.runId,
          cursor: Math.trunc(dv.cursor),
          records: Math.trunc(dv.records),
          updatedAt: at,
          ...(typeof lastFullPassAt === "number" ? { lastFullPassAt } : {}),
        };
      }
      // RTO sample (E4/C1): a SUCCESSFUL drill that measured a positive duration AND verified ≥1 byte
      // contributes one recovery-throughput sample to the bounded ring. A failed/break-glass/no-run drill
      // carries no measurement (durationMs/bytesVerified absent), so no sample is recorded and the RTO
      // estimate stays honestly "unknown" until a real drill measures recovery work. appendRtoSample bounds
      // the ring (RTO_SAMPLE_CAP) and drops a malformed measurement, so a bad sample can never poison the
      // estimate.
      //
      // G318: "basedOnDrills says 2 but we ran 15 restore tests." THIS is the site the other 13 vanished at: a
      // drill that completed OK but whose measurement is unusable is silently NOT sampled, so the RTO estimate
      // is built on a fraction of the drills the pack shows, and the discrepancy had no explanation at all.
      //
      // The DROP is right (a NaN duration or a zero-byte drill carries no throughput signal and would corrupt
      // the estimate); its invisibility was the gap. Recorded ONLY when a measurement was CLAIMED and could not
      // be used: an ok drill that carries NO durationMs/bytesVerified at all (a break-glass or no-run drill)
      // measured nothing by design and is not a fault, so it records nothing -- that is the noise line, and it
      // is drawn on presence, not on value. Counts only: the offending number never rides.
      if (req.ok === true && typeof req.durationMs === "number" && !(Number.isFinite(req.durationMs) && req.durationMs >= 0)) {
        await this.bumpAdminCounterLocal("rto-sample-rejected-non-finite-duration");
      } else if (req.ok === true && typeof req.durationMs === "number" && typeof req.bytesVerified === "number" && !(Number.isFinite(req.bytesVerified) && req.bytesVerified > 0)) {
        await this.bumpAdminCounterLocal("rto-sample-rejected-non-positive-bytes");
      }
      if (req.ok === true && typeof req.durationMs === "number" && Number.isFinite(req.durationMs) && req.durationMs >= 0 && typeof req.bytesVerified === "number" && Number.isFinite(req.bytesVerified) && req.bytesVerified > 0) {
        ds.recoverySamples = appendRtoSample(ds.recoverySamples, {
          at,
          durationMs: req.durationMs,
          bytesVerified: req.bytesVerified,
          recordsVerified: typeof req.recordsVerified === "number" && Number.isFinite(req.recordsVerified) && req.recordsVerified >= 0 ? req.recordsVerified : 0,
        });
      }
      // Routed through the single index-maintaining writer (this write does not change enabled/nextRunAt,
      // so the due: key is unchanged; persistDownpipeState detects that and skips the needless re-key).
      await this.persistDownpipeState(ds);
      // SCALE-2: a scheduled restore test's completion ALSO advances an active on-demand fleet-drill
      // campaign IFF this downpipe was dispatched by it (advanceFleetDrill is a no-op otherwise), so the
      // SAME completion callback that records recency drives the bulk-drill progress without a second
      // round-trip. Best-effort: a fleet-drill bookkeeping hiccup must never fail the recency record.
      await this.advanceFleetDrill(req.id, req.ok === true);
      return { ok: true };
    }

    // startRestoreTest stamps the "restore test in flight" marker (restoreTestStartedAt) on a downpipe just
    // before the cron driver runs its scheduled drill (support-pack mode restore-test-tick-killed). It is the
    // read-side counterpart of the run's inFlightSince lease: completeRestoreTest clears it on any completion,
    // so a marker LEFT BEHIND (still set, and older than a drill could take) means the drill's cron tick was
    // KILLED mid-flight before it completed -- an "attempted but incomplete" restore test that the recency
    // fields alone (lastRestoreTestAt stays stale) could not distinguish from "never tested". A no-op for an
    // unknown downpipe; `at` defaults to the DO clock. It touches ONLY this marker field -- not the run lock,
    // cadence, history ring or any seal path -- and stores a single timestamp, never a key or value.
    async startRestoreTest(req: { id?: string; at?: number }): Promise<{ ok: true }> {
      if (typeof req.id !== "string" || req.id.length === 0) return { ok: true };
      const ds = await this.state.storage.get<DownpipeState>(`dp:${req.id}`);
      if (!ds) return { ok: true }; // downpipe gone; nothing to mark
      ds.restoreTestStartedAt = typeof req.at === "number" && Number.isFinite(req.at) ? req.at : Date.now();
      await this.persistDownpipeState(ds);
      return { ok: true };
    }

    // recordReconcileInventory persists ONE destination's bounded orphan-reconcile + RUNLOG-health signal
    // (support-pack modes reconcile-orphans-invisible / reconcile-circuit-breaker / runlog-corrupt-parse).
    // The cron's report-only reconcile pass (which deletes nothing and only LOGGED before) posts this each
    // pass. It is a DIAGNOSTIC write only: nothing here reads or mutates an archive/RUNLOG/seal path. Every
    // field is re-validated + clamped defensively (an internal call, but fail-closed on a malformed value):
    // counts are non-negative ints, the health/breaker flags are strict booleans, the abstain class is a
    // closed enum, and the destKey is length-bounded. Redaction-safe by construction: no runId/key/value.
    // Bounded to the freshest RECONCILE_SIGNAL_MAX destinations. No-op-safe: it never throws to the caller.
    async recordReconcileInventory(body: Record<string, unknown>): Promise<{ ok: true }> {
      // sanitiseReconcileSignal (seal/reconcile.ts) is the SINGLE redaction chokepoint for this signal, the twin
      // of sanitiseSealFault: clamped non-negative ints, strict booleans, a closed runlogHealth, the closed
      // RECONCILE_DEFER_CLASSES abstain vocabulary, a length-bounded destKey, and every unknown field DROPPED,
      // so the G211 split counts (undeterminedWithinGrace/Unreadable/PendingClassify, the neverReferenced
      // tamper-vs-crashed-finalise split, and the circuit-breaker fraction) are always carried through
      // rather than depending on a hand-rolled field list staying in sync.
      const signal: ReconcileSignal = sanitiseReconcileSignal(body, Date.now());
      const destKey = signal.destKey;
      const map = (await this.state.storage.get<Record<string, ReconcileSignal>>(RECONCILE_SIGNAL_KEY)) ?? {};
      map[destKey] = signal;
      // Cap: keep only the RECONCILE_SIGNAL_MAX freshest destinations (by pass time) so the map is bounded.
      const keys = Object.keys(map);
      if (keys.length > RECONCILE_SIGNAL_MAX) {
        const drop = keys.sort((a, b) => (map[a]!.at) - (map[b]!.at)).slice(0, keys.length - RECONCILE_SIGNAL_MAX);
        for (const k of drop) delete map[k];
        // G325: a large-fleet tenant's OLDEST destinations are being EVICTED from this map, and the reader
        // could not tell an evicted destination from one that never reconciled -- so a 40-destination estate's
        // 8 oldest buckets simply vanished from the reconcile view with no marker. Count the evicted rows (a
        // cumulative count; the dropped destKeys stay out by construction).
        await recordCapTruncation(this.state.storage, "reconcile-signal-map", drop.length);
      }
      await this.state.storage.put(RECONCILE_SIGNAL_KEY, map);
      return { ok: true };
    }

    // reconcileInventory returns the stored per-destination reconcile signals for the support pack, newest
    // first. Redaction-safe (counts + booleans + a coarse abstain class + the customer's own destination
    // labels). Empty when the orphan-reconcile pass has never run (it is opt-in via ORPHAN_RECONCILE).
    async reconcileInventory(): Promise<{ byDest: ReconcileSignal[] }> {
      const map = (await this.state.storage.get<Record<string, ReconcileSignal>>(RECONCILE_SIGNAL_KEY)) ?? {};
      return { byDest: Object.values(map).sort((a, b) => b.at - a.at) };
    }

    // recordSealFault appends ONE bounded, redaction-safe seal-fault observation to the ring (support-pack
    // seal-integrity modes shard-list-truncated / shard-truncation-stalekeys / lease-lost-abandon /
    // orphan-root-worm-leak / signer-rotation-strands-runs). The per-downpipe seal DO (RunSealDO) posts this
    // at a fault's detection point; here it is a DIAGNOSTIC write only -- nothing reads or mutates an archive,
    // RUNLOG or the seal path. sanitiseSealFault validates + clamps every field and DROPS an out-of-vocabulary
    // kind (fail-closed on a malformed value, even for an internal call). The ring is a plain array bounded to
    // the freshest SEAL_FAULT_MAX observations (drop the oldest), so a churning fleet cannot grow it unbounded.
    // No-op-safe: an unknown kind is silently ignored; it never throws to the caller.
    // The body is taken WHOLE (Record<string, unknown>) rather than as a named field list: sanitiseSealFault is
    // the allowlist, so naming the fields here as well only risks the two drifting apart -- exactly what dropped
    // the retention prune evidence (deferClass / skipped / unparseableTime / superseded / partial, G190).
    async recordSealFault(body: Record<string, unknown>): Promise<{ ok: true }> {
      const fault = sanitiseSealFault(body, Date.now());
      if (fault === null) {
        // G092 (version skew): the seal DO is a SEPARATE Worker script, so a partial update leaves it emitting
        // fault kinds this DO's closed set does not hold. The ring then stays EMPTY while the seal path faults
        // on every run, which reads in the pack as a healthy fleet. Count the drop, never the kind token.
        await recordVocabDrop(this.state.storage, "seal-fault");
        return { ok: true }; // out-of-vocabulary kind: ignore, never persist
      }
      const ring = (await this.state.storage.get<SealFault[]>(SEAL_FAULT_KEY)) ?? [];
      ring.push(fault);
      // Keep only the freshest SEAL_FAULT_MAX (drop the oldest head): the ring is newest-last.
      const bounded = ring.length > SEAL_FAULT_MAX ? ring.slice(ring.length - SEAL_FAULT_MAX) : ring;
      await this.state.storage.put(SEAL_FAULT_KEY, bounded);
      return { ok: true };
    }

    // sealFaults returns the stored seal-fault observations for the support pack, NEWEST FIRST. Redaction-safe
    // (a closed kind + the customer's own ids + non-negative ints / a boolean). Empty when no seal-fault has
    // been observed (the healthy fleet's steady state -- these fire only on a truncation / abandon / strand /
    // stale-cleanup / orphan-reclaim).
    async sealFaults(): Promise<{ faults: SealFault[] }> {
      const ring = (await this.state.storage.get<SealFault[]>(SEAL_FAULT_KEY)) ?? [];
      return { faults: [...ring].reverse() };
    }

    // recordRetentionPass persists the LATEST retention-prune pass record (gaps G071/G190). The cron's retention
    // pass builds one bounded, redaction-safe record per tick and POSTs it here; without this slot the post was a
    // silent no-op and the whole "storage keeps growing despite a retention policy" family stayed dark. It is a
    // LATEST-PASS slot, not a ring: the pass runs on a cron and each record supersedes the last, so one key
    // answers "what did retention actually do on its most recent tick, and why did it not reclaim anything".
    //
    // sanitiseRetentionPassRecord (cron/retention-pass.ts) is the single redaction chokepoint, re-run HERE on the
    // posted body (never trusting the caller): drifted enum members are DROPPED, counts clamped, ids capped at
    // 128 chars, and the destination/downpipe arrays capped. A DIAGNOSTIC write only -- it touches no archive,
    // RUNLOG or seal path -- and it never throws to the caller.
    async recordRetentionPass(body: Record<string, unknown>): Promise<{ ok: true }> {
      const clean = sanitiseRetentionPassRecord(body as unknown as RetentionPassRecord);
      // The latest-pass slot keeps its documented meaning (what did the CRON tick do): an attended
      // record covers ONE downpipe, so it folds into the per-destination sidecar below but never
      // supersedes the cron's whole-tick record (B61).
      if (clean.attended !== true) await this.state.storage.put(RETENTION_PASS_KEY, clean);
      // B61: fold the sanitised record into the per-destination prune sidecar (DestConfigMixin), the rows
      // destStatusOf's lastPrune join reads. Same write boundary, same sanitised record, both callers.
      await this.foldDestPruneRecord(clean);
      return { ok: true };
    }

    // retentionState returns the latest retention-prune pass record for the support pack, or null before the
    // pass has ever run (honest absence: retention is a real, distinct posture from "the pass never ran").
    // Redaction-safe by construction: closed enums, clamped counts, and the customer's own downpipe/destination
    // ids -- the same class downpipes[] and replication already carry. No object key, message or policy rides.
    async retentionState(): Promise<{ record: RetentionPassRecord | null }> {
      const rec = (await this.state.storage.get<RetentionPassRecord>(RETENTION_PASS_KEY)) ?? null;
      return { record: rec };
    }

    // recordRestoreProven stamps the "offline restorability last proven" record onto a downpipe's state
    // after a BLIND restore test or KEYLESS attestation PASSED (the router calls this ONLY on a pass). It is
    // the affirmative-proof counterpart of completeRestoreTest: that one records every scheduled run pass OR
    // fail (recency); this one records only a PASS (who+when+method+runId), so the console can show "offline
    // restorability last proven on <date> by <who>". It re-checks restore.verify on the forwarded caller
    // (defence in depth: the router gates first and returns the first-class 403, so reaching the throw here
    // means the gate was bypassed and failing closed is correct), bounds the method to the closed set, and is
    // a no-op for an unknown downpipe (deleted between the proof and the record). The prover email comes from
    // the verified caller (null for the bare-token fallback, which is not attributable); `at` defaults to the
    // DO clock. It stores only redaction-safe provenance, never a key or value.
    async recordRestoreProven(
      req: { downpipeId?: string; method?: string; runId?: string; at?: number },
      caller: { role: Role; email: string | null } | null,
    ): Promise<{ ok: boolean }> {
      this.requireCapability(caller, "restore.verify");
      if (typeof req.downpipeId !== "string" || req.downpipeId.length === 0) return { ok: false };
      const method: RestoreProvenMethod | null = req.method === "blind-test" || req.method === "keyless-attest" ? req.method : null;
      if (method === null) throw new Error("method must be blind-test or keyless-attest");
      if (typeof req.runId !== "string" || req.runId.length === 0) throw new Error("runId required");
      const ds = await this.state.storage.get<DownpipeState>(`dp:${req.downpipeId}`);
      if (!ds) {
        // G059: a restorability proof that PASSED is being discarded. This is affirmative evidence the customer
        // paid a full blind restore / keyless attestation to produce; losing it silently is the worst of the
        // drill drops. Count it (the downpipe is gone, so there is nothing to stamp it onto).
        await recordDrillDrop(this.state.storage, "proof-dropped");
        return { ok: false }; // downpipe gone; nothing to record
      }
      const at = typeof req.at === "number" && Number.isFinite(req.at) ? req.at : Date.now();
      ds.restoreProven = {
        at,
        by: caller?.email ? caller.email : null,
        method,
        runId: req.runId,
      };
      // A passed BLIND restore test or KEYLESS attestation re-verified the archive's cryptographic integrity
      // (signature + completeness + anti-rollback, and the blind test decrypts-and-verifies every record), so
      // a pass also refreshes the "archive integrity last verified" recency the protection statement reads.
      // This is reached ONLY on a pass (the router calls recordRestoreProven only when the proof passed), so
      // it is never a false positive. how:"attest" distinguishes it from the run-seal path; the timestamp is
      // the same `at` as the proof, so the two stamps agree.
      ds.integrityVerified = { at, how: "attest" };
      // Routed through the single index-maintaining writer (recording the restorability proof does not
      // change enabled/nextRunAt, so the due: key is unchanged).
      await this.persistDownpipeState(ds);
      return { ok: true };
    }

    // recordAttendedVerification is the NARROW compliance stamp for an ATTENDED verification run (key-posture
    // attend): the operator supplied their break-glass key through the browser and the engine sampled-and-
    // verified ONE run of a downpipe. The router calls this per run AFTER computing the verify result (the
    // masters are used only in that request and never reach the DO). It re-checks drill.run on the forwarded
    // caller (defence in depth, like recordRestoreProven; the router gates first and returns the first-class
    // 403, so reaching the throw here means the gate was bypassed and failing closed is correct) and is a
    // no-op for an unknown downpipe. It writes ONLY the restore-test RECENCY fields, marking the kind
    // "attended" and the sample rate, so a compliance surface can never mistake a partial attended sample for
    // a full scheduled test: lastRestoreTestAt/Ok, lastRestoreTestKind, lastRestoreTestSampleRate;
    // lastRestoreTestDeferred is cleared (an attended run is never a deferral); the fail reason + streak are
    // set on a failure (a closed code the router already coarsened) and cleared on a pass, mirroring
    // completeRestoreTest's handling but WITHOUT the RTO/deep-verify/OOM/retest/fleet-drill machinery a
    // scheduled completion carries. ONLY a FULL (sampleRate >= 100) proven pass is an affirmative
    // recoverability + integrity proof, so only then does it ALSO stamp restoreProven (method
    // "attended-blind-test", the proven runId) + integrityVerified (how "attest"); a sub-100 sample or an
    // unproven session records the recency + kind but never over-claims a full proof. All fields are
    // redaction-safe (a timestamp, a bool, a closed kind/code, ints, the prover's email, the run id).
    async recordAttendedVerification(
      req: { downpipeId?: string; runId?: string; ok?: boolean; sampleRate?: number; provenSession?: boolean; reason?: string; at?: number },
      caller: { role: Role; email: string | null; capabilities?: ReadonlySet<Capability> } | null,
    ): Promise<{ ok: boolean }> {
      this.requireCapability(caller, "drill.run");
      if (typeof req.downpipeId !== "string" || req.downpipeId.length === 0) return { ok: false };
      const ds = await this.state.storage.get<DownpipeState>(`dp:${req.downpipeId}`);
      if (!ds) return { ok: false }; // downpipe gone; nothing to record
      const at = typeof req.at === "number" && Number.isFinite(req.at) ? req.at : Date.now();
      const ok = req.ok === true;
      // The sample rate the attended run actually covered (1..100). Clamped defensively; an absent/garbled
      // value degrades to 1 (the minimum), so a malformed call can never over-claim a full 100% proof.
      const sampleRate = typeof req.sampleRate === "number" && Number.isFinite(req.sampleRate)
        ? Math.max(1, Math.min(100, Math.trunc(req.sampleRate)))
        : 1;
      ds.lastRestoreTestAt = at;
      ds.lastRestoreTestOk = ok;
      ds.lastRestoreTestKind = "attended";
      ds.lastRestoreTestSampleRate = sampleRate;
      // An attended run either verified a sample or failed on it; it is NEVER a deferral (no-run / posture),
      // so clear any prior deferral marker so the console never reads "could not test" after a real attempt.
      delete ds.lastRestoreTestDeferred;
      // Fail reason + consecutive-failure streak, mirroring completeRestoreTest: a PASS clears both (absent =
      // currently healthy); a FAILURE stamps the closed short code the router already coarsened (clamped) and
      // increments the streak. The code is stored opaque + length-clamped; membership in the closed vocabulary
      // is enforced where the router coarsens it (coarseRestoreTestReasonCode).
      if (ok) {
        delete ds.lastRestoreTestReason;
        delete ds.restoreTestConsecutiveFailures;
      } else {
        ds.lastRestoreTestReason = (typeof req.reason === "string" && req.reason.length > 0 ? req.reason : "other").slice(0, 40);
        ds.restoreTestConsecutiveFailures = (ds.restoreTestConsecutiveFailures ?? 0) + 1;
      }
      // A FULL (100%), PROVEN attended pass is an affirmative recoverability + integrity proof (every record
      // decrypted-and-verified, under a session that proved live possession of the break-glass private), so it
      // refreshes restoreProven + integrityVerified exactly like a passed blind restore test. A sub-100 sample
      // or an unproven session records only the recency + kind above and never over-claims a full proof.
      if (ok && sampleRate >= 100 && req.provenSession === true && typeof req.runId === "string" && req.runId.length > 0) {
        ds.restoreProven = { at, by: caller?.email ? caller.email : null, method: "attended-blind-test", runId: req.runId };
        ds.integrityVerified = { at, how: "attest" };
      }
      // Routed through the single index-maintaining writer (this write does not change enabled/nextRunAt, so
      // the due: key is unchanged). It deliberately does NOT touch deepVerify, recoverySamples/RTO,
      // lastRestoreOom, restoreTestRetestAt or the fleet-drill campaign: an attended verification is an
      // operator-driven point proof, not a scheduled cron drill.
      await this.persistDownpipeState(ds);
      return { ok: true };
    }

    // ---- On-demand fleet drill (SCALE-2) -------------------------------------------------------------
    // "Drill the whole fleet now": a bulk restore-test campaign that fans the EXISTING per-downpipe
    // restore-test machinery out across cron ticks instead of waiting weeks for each downpipe's weekly
    // cadence to fall due. The DO owns only the WORKLIST + progress; it never runs the drill itself (the
    // seal/read-back stays out of the DO, exactly like runs and scheduled tests). The cron driver drains a
    // capped batch per tick (fleetDrillNextBatch), runs the in-account drill for each OUT OF THE DO via the
    // same runScheduledRestoreTest path the scheduled test uses (so the integrity-drill semantics are
    // identical: nothing is weakened, INT-1's full-decrypt drill is inherited), and the same
    // /restore-test-complete callback that records recency advances the campaign (advanceFleetDrill). The
    // per-tick cap + shared subrequest budget live in the cron, so the fleet drill never competes with
    // backups for the platform cap. A campaign carries no key material or plaintext, only downpipe ids +
    // counts.

    // progressView projects a campaign to the redaction-safe at-a-glance status (counts + the small failed
    // sample, never the full pending worklist). active=true only while the campaign is still running.
    fleetDrillProgress(c: FleetDrillCampaign): FleetDrillProgress {
      const pending = c.pending.length;
      const inFlight = Object.keys(c.inFlight).length;
      return {
        campaignId: c.campaignId,
        startedAt: c.startedAt,
        startedBy: c.startedBy,
        total: c.total,
        passed: c.passed,
        failed: c.failed,
        completed: c.passed + c.failed,
        pending,
        inFlight,
        remaining: pending + inFlight,
        done: c.done,
        ...(typeof c.finishedAt === "number" ? { finishedAt: c.finishedAt } : {}),
        failedSample: c.failedSample,
      };
    }

    // startFleetDrill creates a bulk restore-test campaign over the whole fleet (or a downpipeIds subset),
    // re-checking drill.run on the forwarded caller (defence in depth, like recordRestoreProven; the router
    // gates first and returns the first-class 403, so reaching the throw here means the gate was bypassed and
    // failing closed is correct). It REFUSES to clobber an in-progress campaign (returns alreadyActive with
    // its progress) so two overlapping fleet drills can never run at once. The worklist is the current set of
    // downpipe ids; eligibility (no run yet / break-glass posture) is decided per downpipe by the drill
    // itself at dispatch (recorded as a deferral, never a false pass), exactly as the scheduled test does.
    async startFleetDrill(
      req: { downpipeIds?: unknown },
      caller: { role: Role; email: string | null; capabilities?: ReadonlySet<Capability> } | null,
    ): Promise<{ ok: boolean; campaignId?: string; total?: number; alreadyActive?: boolean; reason?: string }> {
      this.requireCapability(caller, "drill.run");
      const existing = await this.state.storage.get<FleetDrillCampaign>(FLEET_DRILL_ACTIVE_KEY);
      if (existing && !existing.done) {
        return { ok: false, alreadyActive: true, campaignId: existing.campaignId, total: existing.total };
      }
      const all = await this.listDownpipes();
      let ids = all.map((d) => d.config.id);
      // Optional subset: an explicit downpipeIds restricts the campaign to those that exist (an unknown id
      // is silently dropped rather than failing the whole start). Only string ids are honoured.
      if (Array.isArray(req.downpipeIds) && req.downpipeIds.length > 0) {
        const want = new Set(req.downpipeIds.filter((x): x is string => typeof x === "string"));
        ids = ids.filter((id) => want.has(id));
      }
      if (ids.length === 0) return { ok: false, reason: "no matching downpipes to drill" };
      if (ids.length > FLEET_DRILL_MAX) {
        throw new Error(`fleet drill exceeds the ${FLEET_DRILL_MAX}-downpipe cap; narrow it with a downpipeIds subset`);
      }
      const campaign: FleetDrillCampaign = {
        campaignId: newULID(Date.now()),
        startedAt: Date.now(),
        startedBy: caller?.email ? caller.email : null,
        total: ids.length,
        pending: ids,
        inFlight: {},
        passed: 0,
        failed: 0,
        failedSample: [],
        done: false,
      };
      await this.state.storage.put(FLEET_DRILL_ACTIVE_KEY, campaign);
      return { ok: true, campaignId: campaign.campaignId, total: campaign.total };
    }

    // fleetDrillNextBatch returns up to `cap` downpipe states to drill from the active campaign, marking each
    // in flight (so its completion can be attributed to the campaign). It first RE-QUEUES any in-flight member
    // whose completion never arrived (a lost callback or a budget-exhausted tick): after FLEET_DRILL_INFLIGHT_
    // TIMEOUT_MS it goes back to the head of the worklist so the campaign self-heals and always converges. A
    // downpipe deleted between start and dispatch is counted as failed (so the campaign can still finish). The
    // campaign FINISHES (done + finishedAt, moved to fleetdrill:last, active deleted) the moment pending and
    // inFlight are both empty. INTERNAL (the cron driver only), like /restore-tests-due.
    async fleetDrillNextBatch(capRaw: number): Promise<{ due: DownpipeState[]; campaignId: string | null; done: boolean }> {
      const campaign = await this.state.storage.get<FleetDrillCampaign>(FLEET_DRILL_ACTIVE_KEY);
      if (!campaign || campaign.done) return { due: [], campaignId: null, done: true };
      const now = Date.now();
      // Re-queue stale in-flight members (self-heal). Iterate a snapshot so the delete is safe.
      for (const [id, at] of Object.entries(campaign.inFlight)) {
        if (typeof at !== "number" || now - at >= FLEET_DRILL_INFLIGHT_TIMEOUT_MS) {
          delete campaign.inFlight[id];
          campaign.pending.unshift(id);
          // G059: THE "stuck at 3 remaining for two days" SIGNAL. The self-heal re-queues a member whose
          // completion never arrived -- and if the cause is permanent (a drill that always times out) it will
          // re-queue the same members forever, invisibly, because the campaign's progress view only shows
          // "remaining". A non-zero member-requeued count is what tells support the campaign is LOOPING, not slow.
          await recordDrillDrop(this.state.storage, "member-requeued");
        }
      }
      const cap = Number.isFinite(capRaw) && capRaw >= 1 ? Math.floor(capRaw) : 1;
      const due: DownpipeState[] = [];
      while (due.length < cap && campaign.pending.length > 0) {
        const id = campaign.pending.shift();
        if (id === undefined) break;
        const ds = await this.state.storage.get<DownpipeState>(`dp:${id}`);
        if (!ds) {
          // Deleted between start and dispatch: count it done-as-failed so the campaign still converges.
          // G059: this is a DELETED downpipe being reported to the customer as a drill FAILURE -- an alarming
          // red count for something that no longer exists. Recording the class lets the pack (and support) say
          // "N of your M drill failures are deleted downpipes, not broken backups".
          await recordDrillDrop(this.state.storage, "member-deleted-failed");
          campaign.failed++;
          if (campaign.failedSample.length < FLEET_DRILL_FAILED_SAMPLE) campaign.failedSample.push(id);
          continue;
        }
        campaign.inFlight[id] = now;
        due.push(ds);
      }
      await this.persistOrFinishFleetDrill(campaign, now);
      return { due, campaignId: campaign.campaignId, done: campaign.done };
    }

    // advanceFleetDrill moves ONE downpipe out of the active campaign's in-flight set into passed/failed when
    // its restore-test completes. It is a no-op when there is no active campaign, the campaign is done, or the
    // id was not dispatched by THIS campaign (a plain cadence-due completion), so the same completion callback
    // serves both the scheduled test and the fleet drill without conflating them. Best-effort: it swallows any
    // storage hiccup so a fleet-drill bookkeeping fault never fails the recency record that called it.
    async advanceFleetDrill(id: string, passed: boolean): Promise<void> {
      try {
        const campaign = await this.state.storage.get<FleetDrillCampaign>(FLEET_DRILL_ACTIVE_KEY);
        if (!campaign || campaign.done) return;
        if (!(id in campaign.inFlight)) return;
        delete campaign.inFlight[id];
        if (passed) campaign.passed++;
        else {
          campaign.failed++;
          if (campaign.failedSample.length < FLEET_DRILL_FAILED_SAMPLE) campaign.failedSample.push(id);
        }
        await this.persistOrFinishFleetDrill(campaign, Date.now());
      } catch {
        /* fleet-drill bookkeeping is best-effort; never fail the completion that called us */
        // G059: swallowing the fault is right (the recency record must land) and it means the campaign's counts
        // are now SHORT by one and it may never converge -- the other half of "stuck at N remaining". Count it.
        // The recorder is itself never-throwing, so this cannot re-enter the catch it lives in.
        await recordDrillDrop(this.state.storage, "campaign-bookkeeping-failed");
      }
    }

    // persistOrFinishFleetDrill is the single writer of campaign state: it FINISHES the campaign (done +
    // finishedAt, copied to fleetdrill:last, active key deleted) the moment pending and inFlight are both
    // empty, else it just persists the in-progress campaign. Centralised so fleetDrillNextBatch and
    // advanceFleetDrill cannot disagree on the completion condition.
    async persistOrFinishFleetDrill(campaign: FleetDrillCampaign, now: number): Promise<void> {
      const inFlightCount = Object.keys(campaign.inFlight).length;
      if (campaign.pending.length === 0 && inFlightCount === 0) {
        campaign.done = true;
        campaign.finishedAt = now;
        await this.state.storage.put(FLEET_DRILL_LAST_KEY, campaign);
        await this.state.storage.delete(FLEET_DRILL_ACTIVE_KEY);
      } else {
        await this.state.storage.put(FLEET_DRILL_ACTIVE_KEY, campaign);
      }
    }

    // fleetDrillStatus returns the active campaign's progress (active=true) or, when none is running, the most
    // recently finished one (active=false), or null if no fleet drill has ever run. Read-only, redaction-safe.
    async fleetDrillStatus(): Promise<{ active: boolean; campaign: FleetDrillProgress | null }> {
      const active = await this.state.storage.get<FleetDrillCampaign>(FLEET_DRILL_ACTIVE_KEY);
      if (active && !active.done) return { active: true, campaign: this.fleetDrillProgress(active) };
      const last = await this.state.storage.get<FleetDrillCampaign>(FLEET_DRILL_LAST_KEY);
      if (last) return { active: false, campaign: this.fleetDrillProgress(last) };
      return { active: false, campaign: null };
    }

    // ---- Security centre / posture (contract section 7) -----------------------------------------------
    // The risk-accept records live under `posture-accept:<checkId>` and the regression snapshot under
    // POSTURE_SNAPSHOT_KEY, both in THIS DO (the single storage authority). The posture COMPUTATION is the
    // pure computePosture (posture.ts); the DO supplies the inputs it owns and the router supplies the
    // env-derived presence slice (the DO holds no env). The two writes re-check posture.riskaccept from the
    // forwarded caller, the defence-in-depth pattern requireCapability uses. NO-CUSTODY: a PostureInput and a
    // RiskAccept carry only redaction-safe metadata; neither type has a field that could hold a secret.

    // requirePostureRiskAccept is the DO-side authority re-check for a posture risk-accept write: the
    // forwarded caller must hold posture.riskaccept (owner only). It THROWS -> 400 on refusal, the same
    // discipline as requireCapability; the router returns the first-class 403 before forwarding, so reaching this
    // throw means the gate was bypassed and failing closed is correct.
    requirePostureRiskAccept(caller: { role: Role; capabilities?: ReadonlySet<Capability> } | null): void {
      // posture.riskaccept is owner-reserved and can NEVER be in a custom role (OWNER_RESERVED_CAPABILITIES),
      // so callerHolds here can only ever pass for an owner built-in (or owner-token); the capabilities-set
      // path is for uniformity with the other re-checks and cannot confer this owner-only cap to a custom role.
      if (!this.callerHolds(caller, "posture.riskaccept")) throw new AuthError("forbidden: posture.riskaccept capability required");
    }

    // listRiskAccepts reads the whole risk-accept set once (small: at most one per check id).
    async listRiskAccepts(): Promise<RiskAccept[]> {
      const map = await this.state.storage.list<RiskAccept>({ prefix: POSTURE_ACCEPT_PREFIX });
      return [...map.values()];
    }

    // notifyHasFailureRule reports whether ANY enabled notify rule selects the backup-failure event (the
    // failure-alerts posture check). It reuses the pure ruleSelects with a representative critical
    // backup-failure emission and a null downpipeId, so a GLOBAL rule that selects backup-failure (or
    // "all") at a minSeverity of critical-or-below qualifies; a per-downpipe-only rule does NOT qualify for
    // the account-level "is failure alerting configured at all" question (it would not fire for an
    // arbitrary downpipe), which is the conservative reading of the check. Computed from the stored rules.
    async notifyHasFailureRule(): Promise<boolean> {
      const rules = await this.listNotifyRulesRaw();
      return rules.some((r) => ruleSelects(r, "backup-failure", "critical", null));
    }

    // gatherPostureState builds the part of the PostureInput the DO owns: the per-downpipe recency slice,
    // the per-item coarse expiry state, the failure-rule boolean, the owner count, the per-check
    // owner-override records and the identity slice (admin-strong-auth). The router supplies the
    // env-derived presence slice + the beacon flag, which are merged in computePostureReport. It reads
    // only redaction-safe fields and can never surface a secret.
    async gatherPostureState(now: number): Promise<{
      downpipes: PostureDownpipeInput[];
      expiry: PostureExpiryInput[];
      notifyFailureRuleSet: boolean;
      ownerCount: number;
      overrides: Map<string, PostureOverrideInput>;
      identity?: PostureIdentityInput;
    }> {
      const states = await this.listDownpipes();
      const downpipes: PostureDownpipeInput[] = states.map((d) => ({
        id: d.config.id,
        name: d.config.name,
        // How many DISTINCT destinations this downpipe is pinned to (3-2-1 redundancy). 0 = it follows
        // the default = one effective copy (not redundant); >=2 = a source written to two places.
        destinationCount: allDestinationIds(d.config).length,
        ...(d.config.restoreTestCadenceSeconds !== undefined ? { restoreTestCadenceSeconds: d.config.restoreTestCadenceSeconds } : {}),
        // lastRunId (the last SUCCESSFUL run's id; null = never completed a run) -> the
        // restore-test-recency check's has-a-run GATE. Only a downpipe with a sealed archive is graded
        // for restore-test staleness; a never-run downpipe is named, not failed. Carried only when set
        // (absent = never run), so the gate reads "has completed a run" exactly. Projecting it is what
        // makes the critical check actually evaluate: the prior code gated on a `lastRunAt` epoch the
        // DownpipeState never held and this projection never wrote, so the check always passed (F-W4-5).
        ...(typeof d.lastRunId === "string" && d.lastRunId !== "" ? { lastRunId: d.lastRunId } : {}),
        ...(d.lastRestoreTestAt !== undefined ? { lastRestoreTestAt: d.lastRestoreTestAt } : {}),
        ...(d.lastRestoreTestOk !== undefined ? { lastRestoreTestOk: d.lastRestoreTestOk } : {}),
        // The durable keyed attested-verification stamp (restoreProven) + the deferral discriminator
        // (lastRestoreTestDeferred), so buildRestoreTestRecency can credit a full attended proof across a
        // scheduled-test DEFERRAL (break-glass-only posture) without ever masking a genuine fresh
        // restore-test failure. See posture-checks.ts buildRestoreTestRecency for the full predicate.
        ...(d.restoreProven !== undefined ? { restoreProvenAt: d.restoreProven.at, restoreProvenMethod: d.restoreProven.method } : {}),
        ...(d.lastRestoreTestDeferred !== undefined ? { lastRestoreTestDeferred: d.lastRestoreTestDeferred } : {}),
        // Verify-at-seal verdict (ENG-RST-01) -> the seal-verification check: a SUSPECT last verdict
        // (status !== "verified") fails it. Absent when the downpipe has never run with the feature on.
        ...(d.lastSealVerify !== undefined ? { lastSealVerifyOk: d.lastSealVerify.status === "verified", lastSealVerifyAt: d.lastSealVerify.at } : {}),
      }));
      const expiryItems = await this.listExpiryItemsRaw();
      const expiry: PostureExpiryInput[] = expiryStatuses(expiryItems, now).map((s) => ({ label: s.label, state: s.state, ...(s.lifecycleClass !== undefined ? { lifecycleClass: s.lifecycleClass } : {}), ...(s.cleanupState !== undefined ? { cleanupState: s.cleanupState } : {}) }));
      const notifyFailureRuleSet = await this.notifyHasFailureRule();
      // The role and pending lists are independent reads; run them concurrently since gatherPostureState is on
      // the hot path (every POST /posture and every cron tick that evaluates posture).
      const [roleEntries, pendingEntries] = await Promise.all([this.listRoleEntries(), this.listPendingEntries()]);
      const ownerCount = this.countOwners(roleEntries, pendingEntries, now);
      // The override records, keyed by check id; overrideOf folds the legacy-record default (no kind =>
      // risk-accepted) in one place so every reader agrees.
      const overrides = new Map<string, PostureOverrideInput>();
      for (const record of await this.listRiskAccepts()) overrides.set(record.checkId, overrideOf(record));
      const identity = await this.gatherPostureIdentity();
      return { downpipes, expiry, notifyFailureRuleSet, ownerCount, overrides, ...(identity !== undefined ? { identity } : {}) };
    }

    // gatherPostureIdentity builds the identity slice for the admin-strong-auth check: how many
    // admin-capable identities exist (Owner / access-admin role entries, bound and pending), how many of
    // those have at least one enrolled passkey, and how many IdP connections are enabled. COUNTS ONLY
    // (no email, subject or key leaves this function). Fully best-effort: any fault returns undefined and
    // the check degrades to its honest cannot-verify reading, never a fabricated verdict or a failed read.
    async gatherPostureIdentity(): Promise<PostureIdentityInput | undefined> {
      try {
        const [roleEntries, pendingEntries] = await Promise.all([this.listRoleEntries(), this.listPendingEntries()]);
        const adminEmails = new Set<string>();
        for (const e of roleEntries) {
          if ((e.role === "owner" || e.role === "access-admin") && typeof e.email === "string" && e.email !== "") adminEmails.add(e.email.toLowerCase());
        }
        for (const p of pendingEntries) {
          if ((p.role === "owner" || p.role === "access-admin") && typeof p.email === "string" && p.email !== "") adminEmails.add(p.email.toLowerCase());
        }
        // Passkey users: one record per enrolled email (a user may hold several credentials; presence of
        // the user record is the "has at least one passkey" signal the check needs).
        const passkeyUsers = await this.state.storage.list<{ email?: string }>({ prefix: PASSKEY_USER_PREFIX });
        const passkeyEmails = new Set<string>();
        for (const u of passkeyUsers.values()) {
          if (typeof u.email === "string" && u.email !== "") passkeyEmails.add(u.email.toLowerCase());
        }
        let adminsWithPasskey = 0;
        for (const email of adminEmails) if (passkeyEmails.has(email)) adminsWithPasskey++;
        const conns = await listIdpConnections(this.idpKv);
        const idpConnectionsEnabled = conns.filter((c) => c.enabled === true).length;
        return { adminIdentities: adminEmails.size, adminsWithPasskey, idpConnectionsEnabled };
      } catch {
        // G105: the honest cannot-verify is right, and it is also invisible: the posture check ABSTAINS and
        // the report simply omits the identity verdict, so a persistently faulting read looks like a posture
        // nobody configured. Count the degraded read (kind only, never the fault).
        await recordStorageAnomaly(this.state.storage, "posture-read-failed");
        // G334: and count it as a POSTURE INPUT FAULT too, so it rides in the posture section beside the
        // finding it degraded. This is the "admin-strong-auth has said cannot-verify for weeks" ticket: a
        // DROPPED IDP_KV BINDING (a permanent, one-line fix) reads exactly like a transient blip without it.
        await recordPostureInputFault(this.state.storage, "identity-read-failed");
        return undefined; // honest cannot-verify; never a fabricated verdict
      }
    }

    // postureEvaluationDue reports whether the SCHEDULED posture evaluation (the cron pass that keeps
    // regression alerts firing on an unwatched account) is due: true when no snapshot exists yet, when the
    // last snapshot is older than intervalMs, or when the stored timestamp is unreadable (fail-toward-
    // evaluating; the evaluation itself is cheap and idempotent). Every posture computation (a console
    // read, a report, or the cron pass itself) refreshes the snapshot, so an actively-read account never
    // pays an extra scheduled computation.
    async postureEvaluationDue(req: { intervalMs?: unknown }): Promise<{ due: boolean; lastEvaluatedAt: string | null }> {
      const interval = typeof req.intervalMs === "number" && Number.isFinite(req.intervalMs) && req.intervalMs > 0 ? req.intervalMs : 6 * 60 * 60 * 1000;
      const prior = await this.state.storage.get<PostureSnapshot>(POSTURE_SNAPSHOT_KEY);
      if (prior === undefined) return { due: true, lastEvaluatedAt: null };
      const at = Date.parse(prior.at);
      if (!Number.isFinite(at)) {
        // G105: a corrupt snapshot timestamp silently forces a re-evaluation every tick and makes
        // lastEvaluatedAt read as "never evaluated". Fail-toward-evaluating is correct; being silent about it
        // is not (a snapshot key being corrupted is a storage-corruption signal, not a scheduling quirk).
        await recordStorageAnomaly(this.state.storage, "snapshot-ts-corrupt");
        return { due: true, lastEvaluatedAt: null };
      }
      return { due: Date.now() - at >= interval, lastEvaluatedAt: prior.at };
    }

    // computePostureReport is the POST /posture handler: it merges the router-supplied presence slice +
    // auth posture + beacon flag with the DO-owned state, runs the pure computePosture, snapshots the
    // pass/fail set for regression detection, detects any previously-passing check that now fails, persists
    // the new snapshot, and returns { report, regressions }. The router routes each regression as a
    // posture-regression notification (the DO does no network I/O). The presence slice is bounded
    // defensively (the route is internal, but the DO bounds its own inputs): a missing/garbled field
    // defaults to the SAFE (worse-posture) reading so a malformed call never fabricates a green posture.
    async computePostureReport(req: { status?: unknown; beaconEnabled?: unknown; callerEmail?: unknown; worm?: unknown; configWrapKeyConfigured?: unknown; liveVersionId?: unknown }): Promise<{ report: PostureReport; regressions: PostureRegression[] }> {
      const now = Date.now();
      // G334: the two SLICE faults that produce a SPURIOUS or a flattened finding, and were recorded nowhere.
      // A version-skewed router (or a garbled internal call) forwards a status slice the DO cannot read; every
      // status-derived check then falls back to its WORST-POSTURE default, which is the right fail-safe and the
      // wrong story: it manufactures a "retire the break-glass token" regression out of a deploy skew. Same for
      // a WORM slice that arrives present-but-unusable: the immutability check flattens a REAL misconfiguration
      // to "not configured". Counted as closed classes; the forwarded value itself never rides.
      if (req.status !== undefined && (typeof req.status !== "object" || req.status === null)) {
        await recordPostureInputFault(this.state.storage, "status-slice-malformed");
      }
      if (req.worm !== undefined && this.parsePostureWormSlice(req.worm) === undefined) {
        await recordPostureInputFault(this.state.storage, "worm-slice-malformed");
      }
      const slice = this.parsePostureStatusSlice(req.status);
      // OVERRIDE the two DO-OWNED break-glass-disposal latches from this DO's own storage (the authoritative
      // source), so the dispose-bootstrap-token finding reflects the real consume/retire state regardless of
      // what the router forwarded. adminTokenPresent stays the router's env-derived value (env is the router's
      // to read). This keeps computePosture pure while sourcing each fact from its true owner.
      slice.bootstrapConsumed = await this.getBootstrapConsumed();
      slice.breakGlassTokenRetired = await this.getBreakGlassTokenRetired();
      // recoveryBreakGlassReady (DO-owned): the dispose-bootstrap-token finding only PROMPTS disposal when a
      // way back in exists - recovery codes acknowledged for an Owner OR a second Owner. Computed here from the
      // DO's own latches/role table, the SAME predicate the retire endpoint enforces, so the finding and the
      // action agree on when disposal is safe.
      const owned = await this.gatherPostureState(now);
      slice.recoveryBreakGlassReady = (await this.recoveryBreakGlassVerdict()).ready || owned.ownerCount >= 2;
      // NOTE: the caller's own auth method is deliberately NOT an input. The attributable-admin-access
      // check is computed from ACCOUNT-LEVEL facts (the shared-token fallback's effective state), so the
      // same account scores identically for every reader and for the scheduled evaluation (no per-caller
      // flapping, no spurious regression when readers with different sign-in methods alternate).
      const beaconEnabled = req.beaconEnabled === true;
      // recoveryCodesRemaining: the CALLER'S OWN unconsumed count (the router forwards the verified caller
      // email). Scoped to the one email so the recovery-codes-low finding is about the caller's own set and
      // never another user's. A caller with no email (the bare-token break-glass) has no per-email count, so
      // the field is left ABSENT and the low finding is not raised for the token caller (it has no codes).
      const callerEmail = this.normaliseEmail(req.callerEmail);
      const recoveryCodesRemaining = callerEmail ? remainingCount(await this.getRecoveryRecord(callerEmail)) : undefined;
      // The WORM observable state is GATHERED BY THE ROUTER (env policy + the live capability probe of the
      // default destination, both of which need env/destination I/O the DO does not do) and forwarded here.
      // The DO bounds it defensively; an absent/garbled slice degrades to the honest not-configured reading
      // (the immutability check then reports "not configured" rather than fabricating a verdict).
      const worm = this.parsePostureWormSlice(req.worm);
      // Destination-credential at-rest encryption: the wrap-key presence is the router's env fact
      // (forwarded), the plaintext/total counts are DO-owned (the destinations collection). A stored secret
      // that is not a WrappedSecret envelope is a pre-encryption plaintext credential (isWrappedSecret is a
      // pure shape check, no key needed). Together they drive the dest-cred-encryption check.
      const destList = (await this.loadDestinations()).list;
      const destCredEncryption = {
        wrapKeyConfigured: req.configWrapKeyConfigured === true,
        plaintextCount: destList.filter((d) => !isWrappedSecret(d.secretAccessKey)).length,
        total: destList.length,
      };
      // Change management (OWNER OPT-IN "Require Change Number"): the emergency-change-review compliance check.
      // required is the policy flag (DO-owned); the marker is the cumulative emergency-change tally. When the
      // policy is off the check is not applicable (the builder returns null), so this is included unconditionally
      // and the builder decides. Redaction-safe: a flag + a count + a date.
      const emergencyMarker = await this.readEmergencyChangeMarker();
      const changeManagement = {
        required: await this.getRequireChangeNumber(),
        emergencyCount: emergencyMarker.count,
        ...(emergencyMarker.lastAt !== null ? { emergencyLastAt: emergencyMarker.lastAt } : {}),
      };
      // The stated attended-verification interval, 0 when the operator has not chosen one. It is read
      // unconditionally because the CHECK decides applicability, not this assembly: an input that silently
      // omitted the number on an operational estate would make the check's own not-applicable branch
      // untestable from here. One integer, no secret.
      const attendedCadenceDays = await this.getAttendedCadenceDays();
      // Environment-self-backup observable: is Downpipes' OWN control-plane export healthy? Read the export
      // state (has anything been written), the last export health (did it reach every destination), the
      // auto-heal record (a refusal) and the recovery latch. Supplied ONLY when there is something to back up
      // (a destination AND at least one downpipe), else the check is not applicable and is not raised.
      let selfBackup: PostureInput["selfBackup"] | undefined;
      // The recipient-pin drift verdict, computed by the export cron because the comparison needs the
      // recipient publics (env bindings this Durable Object cannot read) and carried here on the export
      // health record. null when no export pass has recorded one yet.
      let recipientPinDrift: PostureInput["recipientPinDrift"] = null;
      if (destList.length > 0 && owned.downpipes.length > 0) {
        const [cpState, cpHealth, cpLatch, cpRecord] = await Promise.all([
          this.getControlPlaneExportState(),
          this.getControlPlaneExportHealth(),
          this.getControlPlaneRecoveryRequired(),
          this.getControlPlaneRecoveryRecord(),
        ]);
        recipientPinDrift = cpHealth?.recipientPinDrift ?? null;
        selfBackup = {
          exportPresent: cpState !== null,
          allDestinationsWrote: cpHealth?.wroteAny === true && cpHealth.perDest.every((d) => d.ok),
          autoHealRefused: cpRecord?.refused !== undefined,
          recoveryRequired: cpLatch.required,
        };
      }
      // Update integrity (DP-0/DP-D): the supply-chain observables for the update-apply-provenance +
      // update-version-drift checks. The expectation resolves from the last settled ENGINE outcome
      // (applied -> the promoted version id stays live; rolled-back -> the reverted-to id; any other
      // outcome sets no expectation). liveVersionId is the router's env-derived version_metadata id
      // (the DO cannot read env); absent reads as cannot-compare, never a fabricated verdict. The
      // record is DO-owned (UPDATE_KEY), so this is the authoritative read.
      const updRecord = await this.getUpdateRecord();
      const engineLast = updRecord.last ?? null;
      // G219: after a FAILED rollback the engine is still serving the version it tried to leave -- which the
      // record holds in toVersion, exactly as an applied one does, so the drift check must keep checking in
      // this state rather than treating it as incomparable. applied-unconfirmed is the same shape: the promote
      // landed, so toVersion is what SHOULD be live, and the whole point is that it could not be confirmed.
      const engineOutcome = engineLast?.outcome;
      const expectedLiveVersionId =
        engineOutcome === "applied" || engineOutcome === "applied-unconfirmed" || engineOutcome === "rollback-failed" || engineOutcome === "rollback-failed-still-split"
          ? engineLast?.toVersion
          : engineOutcome === "rolled-back"
            ? engineLast?.fromVersion
            : undefined;
      const liveVersionId = typeof req.liveVersionId === "string" && req.liveVersionId !== "" ? req.liveVersionId : undefined;
      // Alternate legitimately-live ids (review findings #1/#3): a ramp-settled applied outcome is
      // DELIBERATELY still a two-version split (version_metadata reports whichever slice served this
      // request), and a promoted-but-unsettled pending has the promoted version legitimately live
      // before `last` catches up. Neither state may read as an out-of-band redeploy; the drift check
      // passes on any id in this set and says why.
      const alternates: string[] = [];
      if (engineLast?.outcome === "applied" && typeof engineLast.percentage === "number" && typeof engineLast.fromVersion === "string" && engineLast.fromVersion !== "") {
        alternates.push(engineLast.fromVersion);
      }
      const pendingRec = updRecord.pending ?? null;
      if (pendingRec !== null) {
        if (pendingRec.toVersion !== "") alternates.push(pendingRec.toVersion);
        // A ramp pending is itself a live split, so the prior version is also legitimately serving.
        if (pendingRec.fromVersion !== "") alternates.push(pendingRec.fromVersion);
      }
      const updateIntegrity = {
        ...(engineLast?.outcome !== undefined ? { lastEngineOutcome: engineLast.outcome } : {}),
        ...(typeof expectedLiveVersionId === "string" && expectedLiveVersionId !== "" ? { expectedLiveVersionId } : {}),
        ...(alternates.length > 0 ? { alternateLiveVersionIds: alternates } : {}),
        ...(liveVersionId !== undefined ? { liveVersionId } : {}),
        lastAppliedDigestPresent: engineLast?.outcome === "applied" && typeof engineLast.artefactSha384 === "string" && engineLast.artefactSha384 !== "",
        ...(typeof engineLast?.readback?.verdict === "string" && engineLast.readback.verdict !== "" ? { readbackVerdict: engineLast.readback.verdict } : {}),
      };
      const input: PostureInput = {
        status: slice,
        downpipes: owned.downpipes,
        expiry: owned.expiry,
        notifyFailureRuleSet: owned.notifyFailureRuleSet,
        ownerCount: owned.ownerCount,
        operationalPrivatePresent: slice.operationalConfigured.private,
        recipientPinDrift,
        beaconEnabled,
        overrides: owned.overrides,
        destCredEncryption,
        changeManagement,
        attendedCadenceDays,
        ...(selfBackup !== undefined ? { selfBackup } : {}),
        updateIntegrity,
        ...(owned.identity !== undefined ? { identity: owned.identity } : {}),
        ...(recoveryCodesRemaining !== undefined ? { recoveryCodesRemaining } : {}),
        ...(worm !== undefined ? { worm } : {}),
      };
      const report = computePosture(input, now);
      // Regression detection: compare against the prior snapshot, then persist the new one. A previously-
      // passing check that now fails is a regression the router emits as a posture-regression notification.
      const prior = (await this.state.storage.get<PostureSnapshot>(POSTURE_SNAPSHOT_KEY)) ?? null;
      const regressions = detectRegressions(report, prior);
      await this.state.storage.put(POSTURE_SNAPSHOT_KEY, snapshotOf(report));
      return { report, regressions };
    }

    // parsePostureStatusSlice bounds the env-derived presence slice the router forwards. Every boolean
    // defaults to the SAFE (worse-posture) reading when absent/garbled: destConfigured/breakGlassConfigured
    // default false (the check fails, the honest "not configured"), operationalConfigured.private defaults
    // false (no weakening claimed), tokenFallbackDisabled defaults false (access not asserted enforced). So
    // a malformed internal call degrades to a conservative posture, never a fabricated green one.
    parsePostureStatusSlice(raw: unknown): PostureInput["status"] {
      const s = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
      const op = (typeof s.operationalConfigured === "object" && s.operationalConfigured !== null ? s.operationalConfigured : {}) as Record<string, unknown>;
      return {
        destConfigured: s.destConfigured === true,
        breakGlassConfigured: s.breakGlassConfigured === true,
        operationalConfigured: { public: op.public === true, private: op.private === true },
        tokenFallbackDisabled: s.tokenFallbackDisabled === true,
        // adminTokenPresent is env-derived, so it comes from the router-forwarded slice. It defaults to the
        // WORSE-POSTURE reading (true = a shared-token path may exist) when absent/garbled, because the
        // attributable-admin-access check keys on it and a malformed internal call must never fabricate a
        // GREEN posture (the slice's standing principle). The cost is bounded: on a malformed call the
        // dispose-bootstrap-token prompt could fire spuriously (a harmless "retire the token" nudge), which
        // is the conservative direction; the real router always forwards the concrete boolean.
        // bootstrapConsumed and breakGlassTokenRetired are DO-OWNED, so they are seeded false here and
        // OVERRIDDEN in computePostureReport from this DO's own latches (the authoritative source); a
        // forwarded value for them is ignored, so the router cannot move the finding by what it claims for
        // the DO-owned facts.
        adminTokenPresent: s.adminTokenPresent !== false,
        bootstrapConsumed: false,
        breakGlassTokenRetired: false,
        // recoveryBreakGlassReady is DO-OWNED too: seeded false here and OVERRIDDEN in computePostureReport from
        // this DO's own recovery-ack latch + owner count, so the router cannot move the dispose finding by what
        // it claims for this fact.
        recoveryBreakGlassReady: false,
      };
    }

    // parsePostureWormSlice bounds the router-forwarded WORM observable state for the immutability check.
    // It returns undefined when nothing usable was forwarded (an older router, or no destination to probe),
    // so the check falls back to the honest not-configured reading rather than a fabricated verdict. Every
    // field is read defensively: configured/misconfigured default false (the safe "off" reading), the modes
    // are accepted only as the two known literals, days only as a positive integer, and bucketEnforces only
    // as true / false / "unknown" (any other value is dropped, so an absent probe never reads as enforcing).
    parsePostureWormSlice(raw: unknown): PostureWormInput | undefined {
      if (typeof raw !== "object" || raw === null) return undefined;
      const w = raw as Record<string, unknown>;
      const mode = w.mode === "governance" || w.mode === "compliance" ? (w.mode as "governance" | "compliance") : undefined;
      const probeMode = w.probeMode === "governance" || w.probeMode === "compliance" ? (w.probeMode as "governance" | "compliance") : undefined;
      const retentionDays = typeof w.retentionDays === "number" && Number.isInteger(w.retentionDays) && (w.retentionDays as number) > 0 ? (w.retentionDays as number) : undefined;
      const probeDays = typeof w.probeDays === "number" && Number.isInteger(w.probeDays) && (w.probeDays as number) > 0 ? (w.probeDays as number) : undefined;
      // bucketEnforces: only true, false, or the literal "unknown" are honoured; anything else (or absent)
      // is left undefined so the check never reads a missing probe as enforcing (the safe cannot-confirm path).
      const be = w.bucketEnforces;
      const bucketEnforces = be === true || be === false ? be : be === "unknown" ? "unknown" : undefined;
      // defaultRetention: honoured only as a real boolean AND only alongside an enforcing bucket, which is
      // the only state the probe sets it in. A default-retention claim on a bucket that does not read as
      // enforcing is not a state the router can produce, so it is dropped rather than carried.
      const defaultRetention = bucketEnforces === true && typeof w.defaultRetention === "boolean" ? w.defaultRetention : undefined;
      return {
        configured: w.configured === true,
        misconfigured: w.misconfigured === true,
        ...(mode !== undefined ? { mode } : {}),
        ...(retentionDays !== undefined ? { retentionDays } : {}),
        ...(bucketEnforces !== undefined ? { bucketEnforces } : {}),
        ...(probeMode !== undefined ? { probeMode } : {}),
        ...(probeDays !== undefined ? { probeDays } : {}),
        ...(defaultRetention !== undefined ? { defaultRetention } : {}),
      };
    }

    // acceptPostureRisk records an owner OVERRIDE for a check (posture.riskaccept re-checked): a
    // risk-acceptance, an attested pass, a compensating control, or a not-applicable determination. The
    // checkId must be a REAL posture check id (isKnownCheckId) and a safe storage-key fragment
    // (POSTURE_ID_PATTERN): only a real check may be overridden, so a typo or a crafted id is a 400, not a
    // dangling record. The kind must be a known override kind (isOverrideKind); ABSENT defaults to
    // "risk-accepted" so an older console keeps working unchanged. The reason is REQUIRED for every kind
    // (the customer states why it passes / does not apply / is accepted) and bounded (validateFreeText).
    // acceptedBy is the verified Owner email, or null for the bare-token break-glass (no attributable
    // email). It records the override in the audit chain as a first-class posture-override-set with the
    // check id + kind (redaction-safe); the reason text is deliberately NOT written to the tamper-evident
    // log (it lives on the record and in the reports).
    async acceptPostureRisk(
      req: { checkId?: string; reason?: string; kind?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; capabilities?: ReadonlySet<Capability>; sourceIp?: string | null } | null,
    ): Promise<{ ok: true }> {
      this.requirePostureRiskAccept(caller);
      if (typeof req.checkId !== "string" || !POSTURE_ID_PATTERN.test(req.checkId) || !isKnownCheckId(req.checkId)) {
        throw new Error("checkId must be a known posture check id");
      }
      const kind = req.kind === undefined ? "risk-accepted" : req.kind;
      if (!isOverrideKind(kind)) throw new Error("kind must be one of risk-accepted, attested-pass, compensating-control, not-applicable");
      if (typeof req.reason !== "string" || req.reason.trim().length === 0) throw new Error("reason required");
      const reasonErr = validateFreeText(req.reason, "reason", REASON_MAX_LEN);
      if (reasonErr !== null) throw new Error(reasonErr);
      const record: RiskAccept = {
        checkId: req.checkId,
        kind,
        reason: req.reason.trim(),
        acceptedBy: caller?.email ? caller.email : null,
        acceptedAt: nowMillisISO(),
      };
      await this.state.storage.put(`${POSTURE_ACCEPT_PREFIX}${req.checkId}`, record);
      await this.appendAudit({
        actorEmail: record.acceptedBy,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "posture-override-set",
        outcome: "success",
        target: { kind: "posture-check", checkId: req.checkId, overrideKind: kind },
      });
      return { ok: true };
    }

    // unacceptPostureRisk removes an override (posture.riskaccept re-checked), idempotent (removing an
    // absent override is a no-op success). It records an audit entry only when something was actually
    // removed (mirroring deleteRole), naming the check and the withdrawn kind (no reason text).
    async unacceptPostureRisk(
      req: { checkId?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; capabilities?: ReadonlySet<Capability>; sourceIp?: string | null } | null,
    ): Promise<{ ok: true; removed: boolean }> {
      this.requirePostureRiskAccept(caller);
      if (typeof req.checkId !== "string" || req.checkId.length === 0) throw new Error("checkId required");
      const prior = await this.state.storage.get<RiskAccept>(`${POSTURE_ACCEPT_PREFIX}${req.checkId}`);
      const removed = await this.state.storage.delete(`${POSTURE_ACCEPT_PREFIX}${req.checkId}`);
      if (removed) {
        await this.appendAudit({
          actorSubject: caller ? caller.subject : null,
          actorEmail: caller?.email ? caller.email : null,
          actorMethod: caller ? caller.method : "access",
          sourceIp: caller?.sourceIp ?? null,
          action: "posture-override-withdrawn",
          outcome: "success",
          target: { kind: "posture-check", checkId: req.checkId, overrideKind: prior !== undefined ? (prior.kind ?? "risk-accepted") : null },
        });
      }
      return { ok: true, removed };
    }
  };
}
