// validate-cron-deadman: the DEP-04 cron-independent staleness dead-man (the dead-man's-dead-man).
// The staleness/failure alert sweep (reconcileAlerts) is normally driven ONLY by the Worker cron
// (scheduled() -> drive() -> runAlertPass -> POST /reconcile-alerts); a deploy that drops a downpipe's
// [triggers].crons silences the backups AND that detector together. The SchedulerDO's own platform
// alarm() is the one timer that survives such a deploy, so it carries a THROTTLED backstop
// (runCronDeadManSweep) that runs the same sweep, but ONLY when the cron has gone silent.
//
// This drives the REAL SchedulerDO over the shared in-memory storage double and the REAL alarm()
// production method (not a stub), with a captured global fetch. The backstop DELIVERS NOTHING (the DO
// holds no env, so it can reach no channel adapter), so the captured fetch is a NO-EGRESS proof and the
// real outcome of every vector is the alerting-health ledger, a written/rolled-back alert cooldown, the
// cron heartbeat the route stamps, and the throttle marker.
//
//   1) cron-removed -> the backstop FIRES: an old cron heartbeat + a stale downpipe -> alarm() runs the
//      sweep, records the trip and the undeliverable batch, and rolls the transition cooldown back.
//   2) cron-healthy -> NO redundant sweep / NO double-alert: a recent heartbeat -> alarm() does not
//      sweep (no trip, no cooldown), while the cron path (reconcileAlerts) still fires normally.
//   3) threshold boundary: just-under (healthy, no sweep) vs just-over (stalled, sweep).
//   4) self-throttle: once the cron looks dead the alarm re-fires ~1 Hz, so a recent backstop sweep
//      suppresses the next one (no double sweep), and it releases after the interval.
//   5) two-phase rollback discipline: only the optimistic TRANSITION cooldowns roll back; a same-state
//      re-nudge keeps its cooldown, so a re-nudge storm stays suppressed.
//   6) stalled but nothing stale -> the sweep runs and finds an empty batch (nothing undeliverable).
//   7) best-effort: a storage fault inside the backstop is swallowed and never escapes alarm().
//   8) the cron heartbeat: POST /reconcile-alerts stamps CRON_ALERT_SWEEP_AT_KEY (cron-only liveness).
//   9) a recovery during a cron outage is OWED, not dropped: the backstop writes a pending-recovery marker,
//      so the resumed cron re-emits the resolve that closes the incident the trigger opened.
//  10) an outage longer than the retry window: a mocked clock drives throttled backstop sweeps past
//      RECOVERY_RETRY_WINDOW_MS. Each sweep re-arms the marker, so the resumed cron still sends the owed
//      resolve and nothing is counted as abandoned.
//
// Run: node test/validate-cron-deadman.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { SchedulerDOSurface } from "../src/sched/scheduler-do-base.ts";
import { MockStorage, makeScheduler, stubFetch, makeConfig } from "./validate-notify-shared.ts";
import { NOTIFY_CHANNEL_PREFIX } from "../src/notify-routing.ts";
import { ALERT_COOLDOWN_MS } from "../src/notify.ts";
import { ALERT_COOLDOWN_PREFIX } from "../src/sched/scheduler-do-records.ts";
import { CRON_ALERT_SWEEP_AT_KEY, CRON_DEADMAN_STALL_MS, CRON_DEADMAN_SWEEP_AT_KEY, CRON_DEADMAN_SWEEP_INTERVAL_MS } from "../src/sched/scheduler-do-limits.ts";
import { ALERTING_HEALTH_KEY } from "../src/sched/sched-fault-ledger.ts";
import { PENDING_RECOVERY_PREFIX, RECOVERY_RETRY_WINDOW_MS } from "../src/sched/scheduler-do-sre-alerting.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// surf casts the real SchedulerDO to its public testable surface so alarm()/runCronDeadManSweep/
// reconcileAlerts can be driven directly; these are the SAME production methods the routes/platform call.
const surf = (dobj: unknown): SchedulerDOSurface => dobj as unknown as SchedulerDOSurface;

// seedChannel writes a notify channel directly, which is what makes detection run at all: with no channel
// reconcileAlerts short-circuits to an empty batch. The backstop cannot DELIVER to it (the DO holds no env
// for the channel adapters), which is exactly the limit these vectors pin.
async function seedChannel(storage: MockStorage): Promise<void> {
  await storage.put(`${NOTIFY_CHANNEL_PREFIX}c1`, { id: "c1", kind: "webhook", name: "Sink", url: "https://hooks.example.com/deadman", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" });
}

// health reads one counter off the alerting-health ledger, which is now the backstop's ONLY observable
// output: the DO makes no network call at all, so a captured POST can no longer stand in for "it swept".
function health(storage: MockStorage, event: string): number {
  const agg = storage.rawGet<Record<string, { count: number; lastAt: string }>>(ALERTING_HEALTH_KEY);
  return agg?.[event]?.count ?? 0;
}

// installFetchMock replaces the global fetch with a capturing double, so ANY outbound call the backstop
// might make is observable. The backstop must make none: it holds no env and therefore no channel adapter,
// so every captured-length assertion below is a proof of NO EGRESS rather than of a delivery.
function installFetchMock(): { captured: Array<{ url: string }>; restore: () => void } {
  const captured: Array<{ url: string }> = [];
  const original = globalThis.fetch;
  (globalThis as { fetch: unknown }).fetch = async (url: unknown): Promise<unknown> => {
    captured.push({ url: String(url) });
    return { ok: true, status: 200, body: null };
  };
  return { captured, restore: () => { (globalThis as { fetch: unknown }).fetch = original; } };
}

// seedDownpipe writes a dp: state + a hist: ring directly (faster than the upsert path). okAgoMs sets how
// long ago the last SUCCESSFUL run started; > 3x the cadence makes classify() return "stale".
async function seedDownpipe(storage: MockStorage, id: string, opts?: { cadenceSeconds?: number; okAgoMs?: number }): Promise<void> {
  const cadenceSeconds = opts?.cadenceSeconds ?? 3600;
  const okAgoMs = opts?.okAgoMs ?? cadenceSeconds * 1000 * 5; // 5 cadences ago -> comfortably stale
  const now = Date.now();
  await storage.put(`dp:${id}`, { config: makeConfig(id, { cadenceSeconds }), nextRunAt: now + 3_600_000, lastRunId: "r-old", inFlight: false });
  await storage.put(`hist:${id}`, [{ runId: "r-old", index: 1, startedAt: new Date(now - okAgoMs).toISOString(), status: "ok" }]);
}

async function main(): Promise<void> {
  // ============================================================================================
  // 1) CRON-REMOVED -> the backstop FIRES (the gap is closed).
  // ============================================================================================
  {
    const { storage, stub } = makeScheduler();
    await seedChannel(storage);
    await seedDownpipe(storage, "p1");
    // The cron has gone silent: its last alert sweep was longer ago than the stall threshold.
    await storage.put(CRON_ALERT_SWEEP_AT_KEY, Date.now() - CRON_DEADMAN_STALL_MS - 60_000);
    const fx = installFetchMock();
    try {
      await surf(stub).alarm();
    } finally {
      fx.restore();
    }
    ok("cron-removed: the backstop DETECTED the dead cron and recorded the trip", health(storage, "cron-deadman-tripped") === 1);
    ok("cron-removed: the batch it detected reached NO sink, and the ledger says so", health(storage, "undeliverable-alert-batch") === 1);
    ok("cron-removed: the env-free backstop made NO outbound call", fx.captured.length === 0);
    ok("cron-removed: the optimistic transition cooldown was ROLLED BACK (the cron re-fires on resume)", storage.rawGet(`${ALERT_COOLDOWN_PREFIX}p1`) === undefined);
    ok("cron-removed: the backstop-sweep throttle marker was stamped", typeof storage.rawGet<number>(CRON_DEADMAN_SWEEP_AT_KEY) === "number");
  }

  // ============================================================================================
  // 2) CRON-HEALTHY -> NO redundant sweep / NO double-alert, and the cron path still fires.
  // ============================================================================================
  {
    const { storage, stub } = makeScheduler();
    await seedChannel(storage);
    await seedDownpipe(storage, "p1");
    // The cron drove its alert sweep just now: the detector is alive, so the alarm must not sweep.
    await storage.put(CRON_ALERT_SWEEP_AT_KEY, Date.now() - 1000);
    const fx = installFetchMock();
    try {
      await surf(stub).alarm();
    } finally {
      fx.restore();
    }
    ok("cron-healthy: alarm() ran NO backstop sweep (the trip was never recorded)", health(storage, "cron-deadman-tripped") === 0 && fx.captured.length === 0);
    ok("cron-healthy: the alarm wrote no cooldown (it never swept)", storage.rawGet(`${ALERT_COOLDOWN_PREFIX}p1`) === undefined);
    ok("cron-healthy: the alarm did not stamp the backstop-sweep marker", storage.rawGet<number>(CRON_DEADMAN_SWEEP_AT_KEY) === undefined);
    // The cron path itself is UNCHANGED: reconcileAlerts (what /reconcile-alerts calls) still detects stale.
    const r = await surf(stub).reconcileAlerts();
    ok("cron-healthy: the cron path (reconcileAlerts) still fires the stale alert normally", r.alerts.length === 1 && r.alerts[0]?.state === "stale");
  }

  // ============================================================================================
  // 3) THRESHOLD BOUNDARY: just-under (healthy) vs just-over (stalled).
  // ============================================================================================
  {
    // Just-UNDER the stall threshold -> treated as healthy -> no sweep.
    const { storage, stub } = makeScheduler();
    await seedChannel(storage);
    await seedDownpipe(storage, "p1");
    await storage.put(CRON_ALERT_SWEEP_AT_KEY, Date.now() - CRON_DEADMAN_STALL_MS + 60_000);
    const fx = installFetchMock();
    try {
      await surf(stub).alarm();
    } finally {
      fx.restore();
    }
    ok("boundary: just-UNDER the stall threshold -> no backstop sweep", health(storage, "cron-deadman-tripped") === 0);
  }
  {
    // Just-OVER the stall threshold -> stalled -> sweep fires.
    const { storage, stub } = makeScheduler();
    await seedChannel(storage);
    await seedDownpipe(storage, "p1");
    await storage.put(CRON_ALERT_SWEEP_AT_KEY, Date.now() - CRON_DEADMAN_STALL_MS - 60_000);
    const fx = installFetchMock();
    try {
      await surf(stub).alarm();
    } finally {
      fx.restore();
    }
    ok("boundary: just-OVER the stall threshold -> the backstop sweep fires", health(storage, "cron-deadman-tripped") === 1);
  }

  // ============================================================================================
  // 4) SELF-THROTTLE: once the cron looks dead the alarm re-fires ~1 Hz, so the backstop sweep is
  //    capped to its own interval (no redundant sweep on every wakeup), and releases after it.
  // ============================================================================================
  {
    // A RECENT backstop sweep suppresses the next one even for a brand-new stale downpipe (so the
    // ~1 Hz alarm re-fire does not sweep the fleet every second). The cron is stalled.
    const { storage, stub } = makeScheduler();
    await seedChannel(storage);
    await seedDownpipe(storage, "fresh"); // no cooldown -> would alert if swept
    await storage.put(CRON_ALERT_SWEEP_AT_KEY, Date.now() - CRON_DEADMAN_STALL_MS - 60_000);
    await storage.put(CRON_DEADMAN_SWEEP_AT_KEY, Date.now() - 1000); // a sweep happened ~1s ago
    const fx = installFetchMock();
    try {
      await surf(stub).alarm();
    } finally {
      fx.restore();
    }
    ok("throttle: a recent backstop sweep suppresses the next wakeup's sweep (no double sweep)", health(storage, "cron-deadman-tripped") === 0);
  }
  {
    // After the throttle interval elapses, the backstop sweeps again (stands in for the next */15 tick).
    const { storage, stub } = makeScheduler();
    await seedChannel(storage);
    await seedDownpipe(storage, "fresh");
    await storage.put(CRON_ALERT_SWEEP_AT_KEY, Date.now() - CRON_DEADMAN_STALL_MS - 60_000);
    await storage.put(CRON_DEADMAN_SWEEP_AT_KEY, Date.now() - CRON_DEADMAN_SWEEP_INTERVAL_MS - 1000); // older than the interval
    const fx = installFetchMock();
    try {
      await surf(stub).alarm();
    } finally {
      fx.restore();
    }
    ok("throttle: once the interval has elapsed the backstop sweeps again", health(storage, "cron-deadman-tripped") === 1);
  }

  // ============================================================================================
  // 5) two-phase ROLLBACK discipline: transitions roll back, a same-state re-nudge does not.
  // ============================================================================================
  {
    // A downpipe already in cooldown from a PRIOR alert is a same-state re-nudge, not a transition, so the
    // sweep does not roll ITS cooldown back: only the optimistic TRANSITION cooldowns are rolled back, and
    // a re-nudge storm stays suppressed. This is the discipline runAlertPass uses on a failed delivery.
    const { storage, stub } = makeScheduler();
    await seedChannel(storage);
    await seedDownpipe(storage, "p1");
    // A cooldown recorded long enough ago that the re-nudge is eligible, in the SAME state detection finds.
    await storage.put(`${ALERT_COOLDOWN_PREFIX}p1`, { state: "stale", at: Date.now() - ALERT_COOLDOWN_MS - 60_000 });
    await storage.put(CRON_ALERT_SWEEP_AT_KEY, Date.now() - CRON_DEADMAN_STALL_MS - 60_000);
    const fx = installFetchMock();
    try {
      await surf(stub).alarm();
    } finally {
      fx.restore();
    }
    ok("re-nudge: the undeliverable batch was still counted", health(storage, "undeliverable-alert-batch") === 1);
    ok("re-nudge: a same-state re-nudge KEEPS its cooldown (only transitions roll back)", (storage.rawGet<{ state: string }>(`${ALERT_COOLDOWN_PREFIX}p1`))?.state === "stale");
    ok("re-nudge: still no outbound call from the env-free backstop", fx.captured.length === 0);
  }

  // ============================================================================================
  // 6) STALLED but nothing stale: the sweep runs, finds an empty batch, delivers nothing.
  // ============================================================================================
  {
    const { storage, stub } = makeScheduler();
    await seedChannel(storage);
    await seedDownpipe(storage, "p1", { okAgoMs: 1000 }); // a fresh success -> NOT stale
    await storage.put(CRON_ALERT_SWEEP_AT_KEY, Date.now() - CRON_DEADMAN_STALL_MS - 60_000);
    const fx = installFetchMock();
    try {
      await surf(stub).alarm();
    } finally {
      fx.restore();
    }
    ok("stalled-but-healthy-fleet: the sweep found an EMPTY batch, so nothing was undeliverable", health(storage, "undeliverable-alert-batch") === 0 && fx.captured.length === 0);
    ok("stalled-but-healthy-fleet: the sweep still ran (trip recorded + throttle marker stamped), it just found nothing", health(storage, "cron-deadman-tripped") === 1 && typeof storage.rawGet<number>(CRON_DEADMAN_SWEEP_AT_KEY) === "number");
  }

  // ============================================================================================
  // 7) BEST-EFFORT: a storage fault inside the backstop is swallowed, never escapes alarm().
  // ============================================================================================
  {
    // A storage double whose get throws ONLY for the cron heartbeat key, so housekeeping + rearmAlarm
    // still work and only the dead-man's first read faults -> the internal try/catch must swallow it.
    class ThrowHeartbeatGet extends MockStorage {
      async get<T>(key: string): Promise<T | undefined>;
      async get<T>(keys: string[]): Promise<Map<string, T>>;
      async get<T>(keyOrKeys: string | string[]): Promise<T | undefined | Map<string, T>> {
        if (keyOrKeys === CRON_ALERT_SWEEP_AT_KEY) throw new Error("simulated storage failure");
        if (Array.isArray(keyOrKeys)) return super.get<T>(keyOrKeys);
        return super.get<T>(keyOrKeys);
      }
    }
    const storage = new ThrowHeartbeatGet();
    const stub = new SchedulerDO({ storage } as unknown as DurableObjectState);
    await seedChannel(storage);
    await seedDownpipe(storage, "p1");
    let threw = false;
    const fx = installFetchMock();
    try {
      await surf(stub).alarm();
    } catch {
      threw = true;
    } finally {
      fx.restore();
    }
    ok("best-effort: a storage fault in the backstop is swallowed (alarm did not throw)", !threw);
    ok("best-effort: the faulting sweep recorded the fault class and made no outbound call", health(storage, "deadman-sweep-fault") === 1 && fx.captured.length === 0);
  }

  // ============================================================================================
  // 8) THE CRON HEARTBEAT: POST /reconcile-alerts stamps the cron-liveness marker (cron-only).
  // ============================================================================================
  {
    const { storage, stub } = makeScheduler();
    ok("heartbeat: precondition - no cron heartbeat before the first reconcile", storage.rawGet<number>(CRON_ALERT_SWEEP_AT_KEY) === undefined);
    const resp = await stubFetch(stub, "POST", "/reconcile-alerts");
    ok("heartbeat: /reconcile-alerts returns 200", resp.status === 200);
    ok("heartbeat: the cron-driven sweep stamps CRON_ALERT_SWEEP_AT_KEY", typeof storage.rawGet<number>(CRON_ALERT_SWEEP_AT_KEY) === "number");
  }

  // ============================================================================================
  // 9) A RECOVERY DURING A CRON OUTAGE IS OWED, NOT DROPPED.
  // ============================================================================================
  {
    // The downpipe was alerted stale (a cooldown exists) and has since succeeded, so this sweep is its
    // falling edge. reconcileAlerts deletes the cooldown and returns the recovery; the env-free backstop
    // cannot deliver it, so it must leave a pending-recovery marker for the cron to send on resume.
    const { storage, stub } = makeScheduler();
    await seedChannel(storage);
    await seedDownpipe(storage, "p1", { okAgoMs: 1000 });
    await storage.put(`${ALERT_COOLDOWN_PREFIX}p1`, { state: "stale", at: Date.now() - 10 * 60_000 });
    await storage.put(CRON_ALERT_SWEEP_AT_KEY, Date.now() - CRON_DEADMAN_STALL_MS - 60_000);
    const fx = installFetchMock();
    try {
      await surf(stub).alarm();
    } finally {
      fx.restore();
    }
    ok("owed-resolve: the falling edge consumed the cooldown", storage.rawGet(`${ALERT_COOLDOWN_PREFIX}p1`) === undefined);
    const marker = storage.rawGet<{ state: string; at: number }>(`${PENDING_RECOVERY_PREFIX}p1`);
    ok("owed-resolve: the backstop wrote a pending-recovery marker for the undelivered resolve", marker?.state === "stale" && typeof marker.at === "number");
    ok("owed-resolve: still no outbound call from the env-free backstop", fx.captured.length === 0);
    // The cron resumes: its sweep re-emits the SAME recovery (backup-stale, recovered:true), so the
    // Worker sends the resolve on the trigger's dedup key and the incident closes.
    const r = await surf(stub).reconcileAlerts();
    const rec = r.recoveries.find((e) => e.downpipeId === "p1");
    ok("owed-resolve: the resumed cron re-emits the recovery the backstop could not deliver", rec?.recovered === true && rec.event === "backup-stale" && r.pendingRecoveryIds.includes("p1"));
  }

  // ============================================================================================
  // 10) AN OUTAGE LONGER THAN THE RETRY WINDOW: throttled sweeps on a mocked clock, then the cron resumes.
  // ============================================================================================
  {
    // The recovery lands on the first backstop sweep (the vector 9 set-up). Date.now is then advanced one
    // sweep interval at a time, so each runCronDeadManSweep passes its own throttle, until the outage is
    // longer than RECOVERY_RETRY_WINDOW_MS. The marker must be re-armed on every sweep. If it kept the first
    // sweep's anchor, the resumed cron's retry loop would abandon the owed resolve as aged out.
    const realNow = Date.now;
    let clock = realNow();
    Date.now = () => clock;
    try {
      const { storage, stub } = makeScheduler();
      await seedChannel(storage);
      // A six-hourly cadence keeps the downpipe healthy (not stale) for the whole simulated outage.
      await seedDownpipe(storage, "p1", { cadenceSeconds: 6 * 3600, okAgoMs: 1000 });
      await storage.put(`${ALERT_COOLDOWN_PREFIX}p1`, { state: "stale", at: clock - 10 * 60_000 });
      const cronLastSeen = clock - CRON_DEADMAN_STALL_MS - 60_000;
      await storage.put(CRON_ALERT_SWEEP_AT_KEY, cronLastSeen);
      const fx = installFetchMock();
      const outageStart = clock;
      const anchors: number[] = [];
      try {
        await surf(stub).runCronDeadManSweep();
        anchors.push(storage.rawGet<{ at: number }>(`${PENDING_RECOVERY_PREFIX}p1`)?.at ?? -1);
        while (clock - outageStart <= RECOVERY_RETRY_WINDOW_MS + CRON_DEADMAN_SWEEP_INTERVAL_MS) {
          clock += CRON_DEADMAN_SWEEP_INTERVAL_MS + 1000;
          await surf(stub).runCronDeadManSweep();
          anchors.push(storage.rawGet<{ at: number }>(`${PENDING_RECOVERY_PREFIX}p1`)?.at ?? -1);
        }
      } finally {
        fx.restore();
      }
      ok("long-outage: the backstop swept at least five times across the outage", anchors.length >= 5 && health(storage, "cron-deadman-tripped") === anchors.length);
      ok("long-outage: the simulated outage is longer than the retry window", clock - outageStart > RECOVERY_RETRY_WINDOW_MS);
      ok("long-outage: every sweep re-armed the marker to its own sweep time", anchors.every((a, i) => i === 0 || a > anchors[i - 1]!) && anchors[anchors.length - 1] === clock);
      ok("long-outage: no outbound call from the env-free backstop", fx.captured.length === 0);
      // The cron resumes a minute after the last backstop sweep and runs its own reconcileAlerts.
      clock += 60_000;
      const r = await surf(stub).reconcileAlerts();
      const rec = r.recoveries.find((e) => e.downpipeId === "p1");
      ok("long-outage: the resumed cron re-emits the owed resolve (backup-stale, recovered:true)", rec?.recovered === true && rec.event === "backup-stale" && r.pendingRecoveryIds.includes("p1"));
      ok("long-outage: the owed resolve was not abandoned", health(storage, "abandoned-recovery-resolve") === 0);
    } finally {
      Date.now = realNow;
    }
  }

  console.log(failures === 0 ? "\nvalidate-cron-deadman: ALL PASS" : `\nvalidate-cron-deadman: ${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

await main();
