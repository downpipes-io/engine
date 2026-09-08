// Pins the auto-resolve RECOVERY RETRY: a recovery (auto-resolve "incident cleared"
// close) whose delivery FAILS is retried on later reconciliation ticks until it lands, the downpipe relapses,
// or it ages out -- so a transient blip during recovery can no longer strand a PagerDuty/JSM/ServiceNow
// incident open. // Without the retry, a recovery fires exactly once on the falling edge and a failed delivery is a
// silent, permanent stranding.
//
// The fix is DELIBERATELY minimal-blast-radius: the emission path is unchanged (the recovery still fires once
// on the falling edge and the alert cooldown is still deleted there, so a relapse is never suppressed), and
// the retry is driven by a SEPARATE pending-recovery marker that is written ONLY when the Worker reports a
// FAILED recovery delivery. The happy path (delivered first time) writes nothing and behaves exactly as
// before -- which is why the existing validate-autoresolve.ts vectors stay green.
//
// Run: node test/validate-destsim-autoresolve-retry.ts

import { ok, getFailures, makeScheduler, stubFetch, ownerFetch, makeConfig, freshStart } from "./validate-notify-shared.ts";
import { PENDING_RECOVERY_PREFIX, type PendingRecovery } from "../src/sched/scheduler-do-sre-alerting.ts";

type Recon = { recoveries?: Array<{ event: string; downpipeId: string | null; recovered?: boolean }>; alerts: Array<{ id: string; state: string }>; pendingRecoveryIds?: string[] };

async function main(): Promise<void> {
  // A driver: seed a downpipe + notify channel, then drive reconcile / recovery-delivery over ticks.
  const setup = async (id: string) => {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig(id));
    await ownerFetch(stub, "POST", "/notify/channels", { kind: "webhook", name: "Alerts", url: "https://hooks.example.com/f4" });
    const reconcile = async (): Promise<Recon> => (await (await stubFetch(stub, "POST", "/reconcile-alerts")).json()) as Recon;
    const recoveryDelivered = async (delivered: string[], failed: Array<{ id: string; state: string }>): Promise<void> => {
      await stubFetch(stub, "POST", "/recovery-delivered", { deliveredIds: delivered, failed });
    };
    const fail = async (): Promise<void> => {
      await storage.put(`hist:${id}`, [{ runId: `f-${Math.floor(Number(id.replace(/\D/g, "")) || 1)}`, index: 1, startedAt: new Date().toISOString(), status: "failed" }]);
    };
    const recover = async (): Promise<void> => {
      await storage.put(`hist:${id}`, [
        { runId: "f1", index: 1, startedAt: new Date(Date.now() - 120_000).toISOString(), status: "failed" },
        { runId: "ok1", index: 2, startedAt: freshStart(), status: "ok" },
      ]);
    };
    return { stub, storage, reconcile, recoveryDelivered, fail, recover };
  };

  // ---- Scenario A: a FAILED recovery delivery is retried until it succeeds ----
  {
    const d = await setup("dp-retry");
    await d.fail();
    const t1 = await d.reconcile();
    ok("A t1: first failure alerts (transition)", t1.alerts.length === 1);

    await d.recover();
    const t2 = await d.reconcile();
    ok("A t2: falling edge emits exactly one recovery", (t2.recoveries ?? []).length === 1 && t2.recoveries?.[0]?.downpipeId === "dp-retry");
    ok("A t2: it is not yet a retry (no marker exists on the first emission)", (t2.pendingRecoveryIds ?? []).length === 0);
    // Worker reports the recovery delivery FAILED -> the DO writes an owed-resolve marker.
    await d.recoveryDelivered([], [{ id: "dp-retry", state: "failed" }]);
    ok("A: a pending-recovery marker is written on the failed delivery", d.storage.rawGet<PendingRecovery>(`${PENDING_RECOVERY_PREFIX}dp-retry`) !== undefined);

    const t3 = await d.reconcile();
    ok("A t3: RETRY -- the recovery is re-emitted while still healthy (never silently stranded)", (t3.recoveries ?? []).length === 1 && t3.recoveries?.[0]?.recovered === true);
    ok("A t3: the re-emission is flagged as a pending-recovery retry", (t3.pendingRecoveryIds ?? []).includes("dp-retry"));
    // Fails again -> marker kept.
    await d.recoveryDelivered([], [{ id: "dp-retry", state: "failed" }]);
    const t4 = await d.reconcile();
    ok("A t4: still retrying after a second failed delivery", (t4.recoveries ?? []).length === 1);
    // Now it delivers -> marker cleared.
    await d.recoveryDelivered(["dp-retry"], []);
    ok("A: the marker is cleared once the resolve is delivered", d.storage.rawGet(`${PENDING_RECOVERY_PREFIX}dp-retry`) === undefined);
    const t5 = await d.reconcile();
    ok("A t5: no more retry once the resolve landed (no storm)", (t5.recoveries ?? []).length === 0);
  }

  // ---- Scenario B: the HAPPY path is unchanged -- a delivered recovery writes no marker, never retries ----
  {
    const d = await setup("dp-happy");
    await d.fail();
    await d.reconcile();
    await d.recover();
    const t2 = await d.reconcile();
    ok("B t2: falling edge emits one recovery", (t2.recoveries ?? []).length === 1);
    // Worker reports SUCCESS.
    await d.recoveryDelivered(["dp-happy"], []);
    ok("B: no marker written on a delivered recovery (happy path unchanged)", d.storage.rawGet(`${PENDING_RECOVERY_PREFIX}dp-happy`) === undefined);
    const t3 = await d.reconcile();
    ok("B t3: a delivered recovery is one-shot -- no repeat emission (matches pre-F4 behaviour)", (t3.recoveries ?? []).length === 0);
  }

  // ---- Scenario C: a RELAPSE supersedes an owed resolve -- and is NEVER suppressed ----
  {
    const d = await setup("dp-relapse");
    await d.fail();
    await d.reconcile();
    await d.recover();
    await d.reconcile();
    await d.recoveryDelivered([], [{ id: "dp-relapse", state: "failed" }]); // recovery delivery failed -> marker
    ok("C: marker present after the failed recovery", d.storage.rawGet(`${PENDING_RECOVERY_PREFIX}dp-relapse`) !== undefined);
    // It fails AGAIN before the resolve was retried-delivered.
    await d.storage.put("hist:dp-relapse", [
      { runId: "f1", index: 1, startedAt: new Date(Date.now() - 240_000).toISOString(), status: "failed" },
      { runId: "ok1", index: 2, startedAt: new Date(Date.now() - 180_000).toISOString(), status: "ok" },
      { runId: "f2", index: 3, startedAt: new Date().toISOString(), status: "failed" },
    ]);
    const tRelapse = await d.reconcile();
    ok("C: the relapse re-alerts immediately (NOT suppressed -- the retry never touches the cooldown lifecycle)", tRelapse.alerts.length === 1 && tRelapse.alerts[0]?.state === "failed");
    ok("C: the relapse emits no stale recovery", (tRelapse.recoveries ?? []).length === 0);
    ok("C: the owed-resolve marker is dropped (the new incident supersedes it)", d.storage.rawGet(`${PENDING_RECOVERY_PREFIX}dp-relapse`) === undefined);
  }

  // ---- Scenario D: an aged-out marker is given up (fail-open, no perpetual retry of a dead sink) ----
  {
    const d = await setup("dp-aged");
    await d.recover(); // healthy, no cooldown
    // Seed an owed-resolve marker whose first failure was well beyond the retry window (2 hours ago > 1h).
    await d.storage.put(`${PENDING_RECOVERY_PREFIX}dp-aged`, { state: "failed", at: Date.now() - 2 * 60 * 60 * 1000 } satisfies PendingRecovery);
    const t = await d.reconcile();
    ok("D: an aged-out marker emits no retry (given up)", (t.recoveries ?? []).length === 0);
    ok("D: the aged-out marker is deleted (not left to linger)", d.storage.rawGet(`${PENDING_RECOVERY_PREFIX}dp-aged`) === undefined);
  }

  // ---- Scenario E: an ORPHAN marker (its downpipe no longer exists) is dropped, never retried ----
  {
    const d = await setup("dp-live");
    await d.recover(); // a real, healthy downpipe so reconcile does not short-circuit
    // A marker for a downpipe that no longer exists (deleted between the recovery and this tick).
    await d.storage.put(`${PENDING_RECOVERY_PREFIX}dp-ghost`, { state: "stale", at: Date.now() } satisfies PendingRecovery);
    const t = await d.reconcile();
    ok("E: an orphan marker (downpipe gone) emits no retry", (t.recoveries ?? []).find((r) => r.downpipeId === "dp-ghost") === undefined);
    ok("E: the orphan marker is deleted", d.storage.rawGet(`${PENDING_RECOVERY_PREFIX}dp-ghost`) === undefined);
  }

  console.log(getFailures() === 0 ? "\nDESTSIM AUTO-RESOLVE RETRY (F4) PASS" : `\n${getFailures()} FAILURE(S)`);
  if (getFailures() > 0) process.exitCode = 1;
  if (getFailures() > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
