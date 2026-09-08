// Two-phase reconcile/deliver vectors for the validate-notify suite (TC-N-06..TC-N-09), split
// out of validate-notify.ts. Covers the first-alert retry,
// recovery clearing the cooldown, the no-channel short-circuit and markAlertsDelivered fail-open.

import { type DownpipeAlert } from "../src/notify.ts";
import { ok, makeScheduler, stubFetch, ownerFetch, makeConfig, NOW, staleStart, freshStart } from "./validate-notify-shared.ts";

// ---- TC-N-06: Two-phase first-alert retry via reconcileAlerts + markAlertsDelivered ------
// This tests that a NEWLY stale/failed downpipe whose first alert POST fails retries
// promptly on the next tick rather than being suppressed for the full cooldown window.

async function testTwoPhaseRetry(): Promise<void> {
  const { stub, storage } = makeScheduler();

  // Add a downpipe.
  await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-alert"));

  // Configure a notify channel (required for reconcileAlerts to produce alerts).
  // addNotifyChannel is notify.config-gated; use ownerFetch to send the caller header.
  await ownerFetch(stub, "POST", "/notify/channels", { kind: "webhook", name: "Alerts", url: "https://hooks.example.com/alert" });

  // Write a failed history entry directly into storage (fastest way to put the pipe in a
  // detectable alertable state without going through the full trigger/complete cycle, which
  // is already covered by validate-scheduler.ts). Ring is newest-last.
  const failedEntry = {
    runId: "run-fail-01",
    index: 1,
    startedAt: new Date(NOW - 60_000).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"),
    status: "failed",
  };
  await storage.put("hist:dp-alert", [failedEntry]);

  // First reconcile: no prior cooldown, so this is a state transition. pendingTransitionIds
  // should contain "dp-alert" and the cooldown record should be written.
  const r1 = await stubFetch(stub, "POST", "/reconcile-alerts");
  ok("two-phase: reconcileAlerts returns 200", r1.status === 200);
  const body1 = await r1.json() as {
    alerts: DownpipeAlert[];
    pendingTransitionIds: string[];
  };
  const { alerts, pendingTransitionIds } = body1;
  // The reconcile answer carries NO delivery destination. The legacy single webhook used to ride
  // back on a `url` field the Worker POSTed directly; delivery is now the channel model's job, so the DO
  // hands back detection only. Asserted on the SHAPE, so a re-added destination field fails here.
  ok("two-phase: the reconcile answer carries no destination field", !("url" in (body1 as Record<string, unknown>)));
  ok("two-phase: one alert emitted", alerts.length === 1);
  ok("two-phase: alert id matches downpipe", alerts[0]?.id === "dp-alert");
  ok("two-phase: alert state is 'failed'", alerts[0]?.state === "failed");
  ok("two-phase: pendingTransitionIds contains the pipe id", pendingTransitionIds.includes("dp-alert"));
  ok("two-phase: cooldown key written optimistically", storage.has("alert:dp-alert"));

  // Simulate delivery FAILURE: call /alerts-delivered with the id in failedTransitionIds.
  const r2 = await stubFetch(stub, "POST", "/alerts-delivered", {
    deliveredIds: [],
    failedTransitionIds: ["dp-alert"],
  });
  ok("two-phase: /alerts-delivered returns 200", r2.status === 200);
  const { cleared } = await r2.json() as { cleared: number };
  ok("two-phase: cleared count is 1", cleared === 1);
  ok("two-phase: cooldown key cleared after failed transition", !storage.has("alert:dp-alert"));

  // Second reconcile: cooldown is gone, so the pipe re-qualifies as a state transition.
  const r3 = await stubFetch(stub, "POST", "/reconcile-alerts");
  const { alerts: alerts2, pendingTransitionIds: pt2 } = await r3.json() as {
    alerts: DownpipeAlert[];
    pendingTransitionIds: string[];
  };
  ok("two-phase: second reconcile re-emits after failed delivery", alerts2.length === 1);
  ok("two-phase: second reconcile still a transition (no prior delivered cooldown)", pt2.includes("dp-alert"));

  // Now simulate delivery SUCCESS: call /alerts-delivered with the id in deliveredIds.
  const r4 = await stubFetch(stub, "POST", "/alerts-delivered", {
    deliveredIds: ["dp-alert"],
    failedTransitionIds: [],
  });
  ok("two-phase: /alerts-delivered success: 200", r4.status === 200);
  const { cleared: c2 } = await r4.json() as { cleared: number };
  ok("two-phase: no cooldowns cleared on success path (failedTransitionIds empty)", c2 === 0);
  ok("two-phase: cooldown key kept after successful delivery", storage.has("alert:dp-alert"));

  // Third reconcile: cooldown is present + state is still 'failed' (same state) -> suppressed.
  const r5 = await stubFetch(stub, "POST", "/reconcile-alerts");
  const { alerts: alerts3 } = await r5.json() as { alerts: DownpipeAlert[]; pendingTransitionIds: string[] };
  ok("two-phase: third reconcile suppressed (cooldown held after successful delivery)", alerts3.length === 0);
}

// ---- TC-N-07: reconcileAlerts recovery clears cooldown -----------------------------------
// A downpipe that recovers (no longer stale/failed) has its cooldown cleared so a future
// relapse alerts immediately.

async function testRecoveryClears(): Promise<void> {
  const { stub, storage } = makeScheduler();
  await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-recover"));
  await ownerFetch(stub, "POST", "/notify/channels", { kind: "webhook", name: "Alerts", url: "https://hooks.example.com/alert" });

  // Put a stale entry into history and a cooldown record into storage (simulating a prior alert).
  const staleEntry = {
    runId: "run-stale-01",
    index: 1,
    startedAt: staleStart(),
    status: "ok",
  };
  await storage.put("hist:dp-recover", [staleEntry]);
  await storage.put("alert:dp-recover", { state: "stale", at: NOW - 100 });
  ok("recovery: cooldown written before reconcile", storage.has("alert:dp-recover"));

  // Write a FRESH ok run (recovery). Ring is newest-last.
  const freshEntry = {
    runId: "run-ok-01",
    index: 2,
    startedAt: freshStart(),
    status: "ok",
  };
  await storage.put("hist:dp-recover", [staleEntry, freshEntry]);

  // Reconcile: classify should return null (healthy), so the recovery branch clears the cooldown.
  const r = await stubFetch(stub, "POST", "/reconcile-alerts");
  const { alerts, recoveries } = await r.json() as {
    alerts: DownpipeAlert[];
    pendingTransitionIds: string[];
    recoveries?: Array<{ event: string; severity: string; downpipeId: string | null; downpipeName: string | null; detail: string; recovered?: boolean }>;
  };
  ok("recovery: no alert emitted after recovery", alerts.length === 0);
  ok("recovery: cooldown cleared on recovery (relapse alerts immediately)", !storage.has("alert:dp-recover"));

  // AUTO-RESOLVE: the falling edge of a "stale" cooldown emits exactly one
  // backup-stale recovery, recovered:true, for the SAME downpipe, so PagerDuty resolves the matching
  // dedup_key (downpipe:dp-recover:backup-stale, identical to whatever trigger opened it).
  ok("recovery: exactly one recovery emitted", (recoveries ?? []).length === 1);
  const rec = (recoveries ?? [])[0];
  ok("recovery: recovery event mirrors the cleared cooldown state (stale -> backup-stale)", rec?.event === "backup-stale");
  ok("recovery: recovery carries recovered:true", rec?.recovered === true);
  ok("recovery: recovery targets the SAME downpipe id", rec?.downpipeId === "dp-recover");
  ok("recovery: recovery severity matches backup-stale's base severity (warning)", rec?.severity === "warning");
  ok("recovery: recovery detail says the staleness cleared (no secret)", /staleness has cleared/.test(rec?.detail ?? "") && !/https?:\/\//.test(rec?.detail ?? ""));
}

// ---- TC-N-07b: reconcileAlerts recovery from a FAILED cooldown emits backup-failure recovered:true --
// The sibling of testRecoveryClears for the OTHER AlertState branch (failed -> backup-failure), so both
// arms of the cooldown.state -> NotifyEvent mapping are proven, not just the stale one.

async function testFailedRecoveryEmitsBackupFailure(): Promise<void> {
  const { stub, storage } = makeScheduler();
  await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-recover-fail"));
  await ownerFetch(stub, "POST", "/notify/channels", { kind: "webhook", name: "Alerts", url: "https://hooks.example.com/alert" });

  await storage.put(`alert:dp-recover-fail`, { state: "failed", at: NOW - 100 });
  const freshEntry = { runId: "run-ok-fx", index: 1, startedAt: freshStart(), status: "ok" };
  await storage.put("hist:dp-recover-fail", [freshEntry]);

  const r = await stubFetch(stub, "POST", "/reconcile-alerts");
  const { recoveries } = await r.json() as {
    recoveries?: Array<{ event: string; severity: string; downpipeId: string | null; recovered?: boolean; detail: string }>;
  };
  ok("failed-recovery: exactly one recovery emitted", (recoveries ?? []).length === 1);
  const rec = (recoveries ?? [])[0];
  ok("failed-recovery: recovery event mirrors the cleared cooldown state (failed -> backup-failure)", rec?.event === "backup-failure");
  ok("failed-recovery: recovery severity matches backup-failure's base severity (critical)", rec?.severity === "critical");
  ok("failed-recovery: recovery carries recovered:true", rec?.recovered === true);
  ok("failed-recovery: cooldown cleared", !storage.has("alert:dp-recover-fail"));

  // A downpipe with NO prior cooldown never recovers (nothing to fall from): a fresh, always-healthy
  // downpipe must emit zero recoveries, proving the falling edge cannot fire without a prior firing state.
  await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-always-healthy"));
  await storage.put("hist:dp-always-healthy", [{ runId: "run-ah", index: 1, startedAt: freshStart(), status: "ok" }]);
  const r2 = await stubFetch(stub, "POST", "/reconcile-alerts");
  const { recoveries: recoveries2 } = await r2.json() as { recoveries?: unknown[] };
  const forAlwaysHealthy = ((recoveries2 ?? []) as Array<{ downpipeId: string | null }>).filter((e) => e.downpipeId === "dp-always-healthy");
  ok("no-prior-state: a downpipe with no prior cooldown emits no recovery", forAlwaysHealthy.length === 0);
}

// ---- TC-N-08: no-channel short-circuit in reconcileAlerts --------------------------------

async function testNoChannelShortCircuit(): Promise<void> {
  const { stub } = makeScheduler();
  await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-nowh"));
  // No notify channel configured, so there is nowhere to deliver and detection short-circuits.
  const r = await stubFetch(stub, "POST", "/reconcile-alerts");
  ok("no-channel: 200", r.status === 200);
  const { alerts, pendingTransitionIds } = await r.json() as {
    alerts: DownpipeAlert[];
    pendingTransitionIds: string[];
  };
  ok("no-channel: alerts is empty", alerts.length === 0);
  ok("no-channel: pendingTransitionIds is empty", pendingTransitionIds.length === 0);
}

// ---- TC-N-09: markAlertsDelivered ignores unknown ids (fail-open) -----------------------

async function testMarkAlertsDeliveredUnknownIds(): Promise<void> {
  const { stub } = makeScheduler();
  // Call /alerts-delivered with ids that have no cooldown record; should be a no-op no-throw.
  const r = await stubFetch(stub, "POST", "/alerts-delivered", {
    deliveredIds: ["unknown-pipe-1"],
    failedTransitionIds: ["unknown-pipe-2"],
  });
  ok("markAlertsDelivered: unknown ids -> 200 (no-op, fail-open)", r.status === 200);
  const { cleared } = await r.json() as { cleared: number };
  // "cleared" increments once per processed failedTransitionId regardless of whether the cooldown key
  // existed (delete is idempotent). One id is passed, so the contract is exactly 1, not an arbitrary
  // number; asserting the value catches a regression that miscounts or zeroes the result.
  ok("markAlertsDelivered: cleared count is 1 for one processed id", cleared === 1);
}

// runTwoPhase runs the two-phase reconcile/deliver groups in their original order.
export async function runTwoPhase(): Promise<void> {
  console.log("two-phase first-alert retry");
  await testTwoPhaseRetry();

  console.log("recovery clears cooldown");
  await testRecoveryClears();

  console.log("failed-cooldown recovery emits backup-failure recovered:true; no prior state -> no recovery");
  await testFailedRecoveryEmitsBackupFailure();

  console.log("no-webhook short-circuit");
  await testNoChannelShortCircuit();

  console.log("markAlertsDelivered unknown ids");
  await testMarkAlertsDeliveredUnknownIds();
}
