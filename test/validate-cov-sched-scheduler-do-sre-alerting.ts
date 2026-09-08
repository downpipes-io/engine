// validate-cov-sched-scheduler-do-sre-alerting: focused branch-coverage vectors for the SRE alerting
// mixin (src/sched/scheduler-do-sre-alerting.ts), the on-call persona. It drives the REAL SchedulerDO
// through the shared notify harness (the route dispatch, plus seeded DO storage where a state is faster
// to set up directly) and asserts a real outcome for every vector: an HTTP status, a returned body
// field, an audited actor, or a stored/cleared cooldown or success marker. It covers:
//   - reconcileAlerts: the no-destination short-circuit, the channel-only detection path, failure/abandoned
//     detection, the transition vs re-nudge cooldown split, recovery clearing the cooldown, and the
//     backup-success stream (recent vs stale, enabled vs disabled, incomplete markers, already-notified,
//     in-flight skip and a newest-failed run yielding no success);
//   - markAlertsDelivered: the two-phase clear (valid id vs blank id vs a non-array body);
//   - reconcileReplicationAlerts: degraded vs run-at-risk-eviction, the critical last-copy escalation,
//     the catching-up vs not-reachable auto-heal suffix, the single-destination/no-ok/healthy skips that
//     clear a stale cooldown, the same-state suppression and elapsed re-nudge, and the proven-copy maths;
//   - markReplicationAlertsDelivered: the same two-phase clear on the replication cooldown prefix.
//
// Run: node test/validate-cov-sched-scheduler-do-sre-alerting.ts

import { makeScheduler, stubFetch, makeConfig } from "./validate-notify-shared.ts";
import { ALERT_COOLDOWN_MS } from "../src/notify.ts";
import { NOTIFY_CHANNEL_PREFIX } from "../src/notify-routing.ts";
import { ALERT_COOLDOWN_PREFIX, REPL_ALERT_COOLDOWN_PREFIX, SUCCESS_NOTIFIED_PREFIX, SOURCE_DRIFT_KEY, VOLUME_REGRESSION_KEY } from "../src/sched/scheduler-do-records.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- Tiny fixture helpers -------------------------------------------------------------------
// A run-history ring is newest-LAST. These build the redaction-safe subset the detector reads.
interface RunEntry {
  runId: string;
  index: number;
  startedAt: string;
  status: "ok" | "failed" | "in-flight" | "abandoned";
  destinationId?: string;
  recordsIncomplete?: number;
}
const iso = (ms: number): string => new Date(ms).toISOString();

type Store = ReturnType<typeof makeScheduler>["storage"];
async function seedDp(storage: Store, id: string, cfg: Record<string, unknown> = {}): Promise<void> {
  await storage.put(`dp:${id}`, { config: makeConfig(id, cfg), nextRunAt: Date.now() + 3_600_000, lastRunId: null, inFlight: false });
}
const find = <T extends { downpipeId?: string | null; id?: string }>(arr: T[], id: string): T | undefined =>
  arr.find((e) => (e.downpipeId ?? e.id) === id);

async function main(): Promise<void> {
  const NOW = Date.now();

  // ============================================================================================
  // 1) reconcileAlerts short-circuit + the channel-configured detection path.
  // ============================================================================================
  {
    // No channel -> short-circuit to an empty batch (one storage list).
    const { storage, stub } = makeScheduler();
    await seedDp(storage, "dp-x");
    await storage.put("hist:dp-x", [{ runId: "r1", index: 1, startedAt: iso(NOW - 60_000), status: "failed" }] satisfies RunEntry[]);
    const r = await stubFetch(stub, "POST", "/reconcile-alerts");
    ok("reconcileAlerts: route returns 200", r.status === 200);
    const b = (await r.json()) as { alerts: unknown[]; pendingTransitionIds: string[]; successes: unknown[] };
    ok("reconcileAlerts: no destination -> empty alerts", b.alerts.length === 0);
    ok("reconcileAlerts: no destination -> empty pending + successes", b.pendingTransitionIds.length === 0 && b.successes.length === 0);
  }
  {
    // A CHANNEL configured -> detection runs.
    const { storage, stub } = makeScheduler();
    await storage.put(`${NOTIFY_CHANNEL_PREFIX}c1`, { id: "c1", kind: "webhook", url: "https://hooks.example.com/c1" });
    await seedDp(storage, "dp-c");
    await storage.put("hist:dp-c", [{ runId: "rc1", index: 1, startedAt: iso(NOW - 60_000), status: "failed" }] satisfies RunEntry[]);
    const r = await stubFetch(stub, "POST", "/reconcile-alerts");
    const b = (await r.json()) as { alerts: Array<{ id: string; state: string }> };
    ok("reconcileAlerts: a channel-configured tenant detects an alert", b.alerts.length === 1 && b.alerts[0]!.id === "dp-c");
  }

  // ============================================================================================
  // 1b) reconcileSourceDrift: the edge-trigger marker behind the proactive source-detached alert.
  // ============================================================================================
  {
    const { storage, stub } = makeScheduler();
    const marker = async (): Promise<string[]> => ((await storage.get(SOURCE_DRIFT_KEY)) as string[] | undefined) ?? ["<unset>"];
    // First sighting of two missing bindings -> both NEWLY detached; the marker is written (sorted).
    const r1 = await stubFetch(stub, "POST", "/source-drift/reconcile", { missing: ["SRC_B", "SRC_A"] });
    ok("source-drift: route returns 200", r1.status === 200);
    const b1 = (await r1.json()) as { newlyDetached: string[] };
    ok("source-drift: first sighting -> both newly detached, sorted", JSON.stringify(b1.newlyDetached) === JSON.stringify(["SRC_A", "SRC_B"]));
    ok("source-drift: marker persisted to the current set", JSON.stringify(await marker()) === JSON.stringify(["SRC_A", "SRC_B"]));
    // The same set again -> nothing NEW (edge-triggered: pages once, the write is skipped on no change).
    const b2 = (await (await stubFetch(stub, "POST", "/source-drift/reconcile", { missing: ["SRC_A", "SRC_B"] })).json()) as { newlyDetached: string[] };
    ok("source-drift: unchanged set -> no new alerts (edge-triggered)", b2.newlyDetached.length === 0);
    // SRC_A re-attached, SRC_C newly detached -> only SRC_C is new; the marker rewrites to the current set.
    const b3 = (await (await stubFetch(stub, "POST", "/source-drift/reconcile", { missing: ["SRC_B", "SRC_C"] })).json()) as { newlyDetached: string[] };
    ok("source-drift: a new detach in a changed set -> only the new one", JSON.stringify(b3.newlyDetached) === JSON.stringify(["SRC_C"]));
    ok("source-drift: marker rewritten (re-attached SRC_A dropped)", JSON.stringify(await marker()) === JSON.stringify(["SRC_B", "SRC_C"]));
    // All re-attached -> empty set, marker clears (so a later re-detach re-arms).
    const b4 = (await (await stubFetch(stub, "POST", "/source-drift/reconcile", { missing: [] })).json()) as { newlyDetached: string[] };
    ok("source-drift: all re-attached -> no new alerts, marker cleared", b4.newlyDetached.length === 0 && JSON.stringify(await marker()) === JSON.stringify([]));
    // Re-detach of SRC_B AFTER the clear -> re-alerts (re-armed); empty/non-string entries are dropped.
    const b5 = (await (await stubFetch(stub, "POST", "/source-drift/reconcile", { missing: ["SRC_B", "", 7] as unknown as string[] })).json()) as { newlyDetached: string[] };
    ok("source-drift: re-detach after clear re-alerts; empty/non-string dropped", JSON.stringify(b5.newlyDetached) === JSON.stringify(["SRC_B"]));
  }

  // ============================================================================================
  // 1c) reconcileVolumeRegression: the edge-trigger marker behind the retention volume-guard alert.
  // ============================================================================================
  {
    const { storage, stub } = makeScheduler();
    const marker = async (): Promise<string[]> => ((await storage.get(VOLUME_REGRESSION_KEY)) as string[] | undefined) ?? ["<unset>"];
    // First sighting of two regressed downpipes -> both NEWLY regressed; the marker is written (sorted).
    const r1 = await stubFetch(stub, "POST", "/volume-regression/reconcile", { regressed: ["dp_b", "dp_a"] });
    ok("volume-regression: route returns 200", r1.status === 200);
    const b1 = (await r1.json()) as { newlyRegressed: string[] };
    ok("volume-regression: first sighting -> both newly regressed, sorted", JSON.stringify(b1.newlyRegressed) === JSON.stringify(["dp_a", "dp_b"]));
    ok("volume-regression: marker persisted to the current set", JSON.stringify(await marker()) === JSON.stringify(["dp_a", "dp_b"]));
    // The same set again -> nothing NEW (edge-triggered: pages once, the write is skipped on no change).
    const b2 = (await (await stubFetch(stub, "POST", "/volume-regression/reconcile", { regressed: ["dp_a", "dp_b"] })).json()) as { newlyRegressed: string[] };
    ok("volume-regression: unchanged set -> no new alerts (edge-triggered)", b2.newlyRegressed.length === 0);
    // dp_a recovered, dp_c newly regressed -> only dp_c is new; the marker rewrites to the current set.
    const b3 = (await (await stubFetch(stub, "POST", "/volume-regression/reconcile", { regressed: ["dp_b", "dp_c"] })).json()) as { newlyRegressed: string[] };
    ok("volume-regression: a new regression in a changed set -> only the new one", JSON.stringify(b3.newlyRegressed) === JSON.stringify(["dp_c"]));
    ok("volume-regression: marker rewritten (recovered dp_a dropped)", JSON.stringify(await marker()) === JSON.stringify(["dp_b", "dp_c"]));
    // All recovered -> empty set, marker clears (so a later re-regression re-arms).
    const b4 = (await (await stubFetch(stub, "POST", "/volume-regression/reconcile", { regressed: [] })).json()) as { newlyRegressed: string[] };
    ok("volume-regression: all recovered -> no new alerts, marker cleared", b4.newlyRegressed.length === 0 && JSON.stringify(await marker()) === JSON.stringify([]));
    // Re-regression AFTER the clear -> re-alerts (re-armed); empty/non-string entries are dropped.
    const b5 = (await (await stubFetch(stub, "POST", "/volume-regression/reconcile", { regressed: ["dp_b", "", 7] as unknown as string[] })).json()) as { newlyRegressed: string[] };
    ok("volume-regression: re-regression after clear re-alerts; empty/non-string dropped", JSON.stringify(b5.newlyRegressed) === JSON.stringify(["dp_b"]));
  }

  // ============================================================================================
  // 3) reconcileAlerts detection across the full branch matrix (one tick over many downpipes).
  // ============================================================================================
  {
    const { storage, stub } = makeScheduler();
    await storage.put(`${NOTIFY_CHANNEL_PREFIX}ch-main`, { id: "ch-main", kind: "webhook", url: "https://hooks.example.com/main" });

    await seedDp(storage, "dp-fail");
    await storage.put("hist:dp-fail", [{ runId: "f1", index: 1, startedAt: iso(NOW - 60_000), status: "failed" }] satisfies RunEntry[]);

    // An ABANDONED newest run maps to failed for the staleness view -> alertable as failed.
    await seedDp(storage, "dp-aband");
    await storage.put("hist:dp-aband", [{ runId: "a1", index: 1, startedAt: iso(NOW - 60_000), status: "abandoned" }] satisfies RunEntry[]);

    // A recent fully-captured success -> backup-success "succeeded".
    await seedDp(storage, "dp-ok");
    await storage.put("hist:dp-ok", [{ runId: "o1", index: 1, startedAt: iso(NOW - 30_000), status: "ok", recordsIncomplete: 0 }] satisfies RunEntry[]);

    // Incomplete successes -> "N items not fully captured" (plural vs singular).
    await seedDp(storage, "dp-inc3");
    await storage.put("hist:dp-inc3", [{ runId: "i3", index: 1, startedAt: iso(NOW - 30_000), status: "ok", recordsIncomplete: 3 }] satisfies RunEntry[]);
    await seedDp(storage, "dp-inc1");
    await storage.put("hist:dp-inc1", [{ runId: "i1", index: 1, startedAt: iso(NOW - 30_000), status: "ok", recordsIncomplete: 1 }] satisfies RunEntry[]);

    // An OLD success (older than the recent window, still within the stale budget) -> no emission, marker set.
    await seedDp(storage, "dp-old");
    await storage.put("hist:dp-old", [{ runId: "ol1", index: 1, startedAt: iso(NOW - 9_000_000), status: "ok" }] satisfies RunEntry[]);

    // A DISABLED downpipe with a recent ok run -> no alert, no success emission (the marker still advances).
    await seedDp(storage, "dp-dis", { enabled: false });
    await storage.put("hist:dp-dis", [{ runId: "d1", index: 1, startedAt: iso(NOW - 30_000), status: "ok" }] satisfies RunEntry[]);

    // An UNPARSEABLE startedAt -> Number.isFinite false -> not recent -> no success (marker still advances),
    // and classify reads resolved-ok-with-no-parseable-time as healthy (no false stale alert).
    await seedDp(storage, "dp-bad");
    await storage.put("hist:dp-bad", [{ runId: "b1", index: 1, startedAt: "not-a-date", status: "ok" }] satisfies RunEntry[]);

    // A newest IN-FLIGHT row is skipped; the prior ok run is the backup-success candidate.
    await seedDp(storage, "dp-inflight");
    await storage.put("hist:dp-inflight", [
      { runId: "if-ok", index: 1, startedAt: iso(NOW - 30_000), status: "ok", recordsIncomplete: 0 },
      { runId: "if-run", index: 2, startedAt: iso(NOW - 1_000), status: "in-flight" },
    ] satisfies RunEntry[]);

    // The newest RESOLVED run is failed -> alert failed AND no backup-success (latestOk undefined).
    await seedDp(storage, "dp-failnewest");
    await storage.put("hist:dp-failnewest", [
      { runId: "fn-ok", index: 1, startedAt: iso(NOW - 30_000), status: "ok" },
      { runId: "fn-fail", index: 2, startedAt: iso(NOW - 1_000), status: "failed" },
    ] satisfies RunEntry[]);

    // An ALREADY-NOTIFIED success (marker == latest runId) -> no re-emission.
    await seedDp(storage, "dp-noted");
    await storage.put("hist:dp-noted", [{ runId: "n1", index: 1, startedAt: iso(NOW - 30_000), status: "ok" }] satisfies RunEntry[]);
    await storage.put(`${SUCCESS_NOTIFIED_PREFIX}dp-noted`, "n1");

    // A pending downpipe with NO run-history ring at all -> the absent-ring default ([]) path; not alertable.
    await seedDp(storage, "dp-nohist");

    const r = await stubFetch(stub, "POST", "/reconcile-alerts");
    const b = (await r.json()) as {
      alerts: Array<{ id: string; state: string }>;
      pendingTransitionIds: string[];
      successes: Array<{ downpipeId: string; detail: string; event: string }>;
    };

    ok("reconcileAlerts: a failed newest run alerts failed", find(b.alerts, "dp-fail")?.state === "failed");
    ok("reconcileAlerts: an abandoned newest run alerts failed", find(b.alerts, "dp-aband")?.state === "failed");
    ok("reconcileAlerts: a newest-failed (after an ok) run alerts failed", find(b.alerts, "dp-failnewest")?.state === "failed");
    ok("reconcileAlerts: a healthy recent ok run does not alert", find(b.alerts, "dp-ok") === undefined);
    ok("reconcileAlerts: all first-time failures are transitions (pending)", ["dp-fail", "dp-aband", "dp-failnewest"].every((id) => b.pendingTransitionIds.includes(id)));

    ok("reconcileAlerts: a clean success emits 'backup succeeded'", /backup succeeded/.test(find(b.successes, "dp-ok")?.detail ?? ""));
    ok("reconcileAlerts: an incomplete success reports plural items", /completed with 3 items not fully captured/.test(find(b.successes, "dp-inc3")?.detail ?? ""));
    ok("reconcileAlerts: an incomplete success of one reports singular item", /completed with 1 item not fully captured/.test(find(b.successes, "dp-inc1")?.detail ?? ""));
    ok("reconcileAlerts: the in-flight newest row is skipped, prior ok succeeds", find(b.successes, "dp-inflight") !== undefined);
    ok("reconcileAlerts: an old success (past the recent window) does not emit", find(b.successes, "dp-old") === undefined);
    ok("reconcileAlerts: a disabled downpipe emits no success", find(b.successes, "dp-dis") === undefined);
    ok("reconcileAlerts: an unparseable run time emits no success", find(b.successes, "dp-bad") === undefined);
    ok("reconcileAlerts: a newest-failed run emits no backup-success", find(b.successes, "dp-failnewest") === undefined);
    ok("reconcileAlerts: an already-notified success does not re-emit", find(b.successes, "dp-noted") === undefined);
    ok("reconcileAlerts: a downpipe with no run history is not alertable", find(b.alerts, "dp-nohist") === undefined && find(b.successes, "dp-nohist") === undefined);

    // The success marker is written even for the silenced (old/disabled/bad) downpipes so they fire at most once.
    ok("reconcileAlerts: the old success advanced its notify marker", storage.rawGet<string>(`${SUCCESS_NOTIFIED_PREFIX}dp-old`) === "ol1");
    ok("reconcileAlerts: a freshly-emitted success advanced its notify marker", storage.rawGet<string>(`${SUCCESS_NOTIFIED_PREFIX}dp-ok`) === "o1");
  }

  // ============================================================================================
  // 4) reconcileAlerts cooldown discipline: recovery-clear, suppress, transition, re-nudge.
  // ============================================================================================
  {
    const { storage, stub } = makeScheduler();
    await storage.put(`${NOTIFY_CHANNEL_PREFIX}ch-cd`, { id: "ch-cd", kind: "webhook", url: "https://hooks.example.com/cd" });

    // RECOVERED: a prior cooldown + a healthy recent ok run -> classify null -> the cooldown is cleared.
    await seedDp(storage, "dp-recover");
    await storage.put("hist:dp-recover", [{ runId: "rc", index: 1, startedAt: iso(NOW - 30_000), status: "ok" }] satisfies RunEntry[]);
    await storage.put(`${ALERT_COOLDOWN_PREFIX}dp-recover`, { state: "failed", at: NOW - 100 });

    // SUPPRESSED: still failed, same state, within the cooldown window -> no alert, cooldown kept (classify != null).
    await seedDp(storage, "dp-suppress");
    await storage.put("hist:dp-suppress", [{ runId: "sp", index: 1, startedAt: iso(NOW - 60_000), status: "failed" }] satisfies RunEntry[]);
    await storage.put(`${ALERT_COOLDOWN_PREFIX}dp-suppress`, { state: "failed", at: NOW });

    // TRANSITION from a DIFFERENT prior state (stale -> failed) -> alerts and is a pending transition.
    await seedDp(storage, "dp-trans");
    await storage.put("hist:dp-trans", [{ runId: "tr", index: 1, startedAt: iso(NOW - 60_000), status: "failed" }] satisfies RunEntry[]);
    await storage.put(`${ALERT_COOLDOWN_PREFIX}dp-trans`, { state: "stale", at: NOW - 100 });

    // RE-NUDGE: same state, cooldown ELAPSED -> alerts again but is NOT a transition (cooldown.state == state).
    await seedDp(storage, "dp-renudge");
    await storage.put("hist:dp-renudge", [{ runId: "rn", index: 1, startedAt: iso(NOW - 60_000), status: "failed" }] satisfies RunEntry[]);
    await storage.put(`${ALERT_COOLDOWN_PREFIX}dp-renudge`, { state: "failed", at: NOW - 2 * ALERT_COOLDOWN_MS });

    const r = await stubFetch(stub, "POST", "/reconcile-alerts");
    const b = (await r.json()) as { alerts: Array<{ id: string; state: string }>; pendingTransitionIds: string[] };

    ok("reconcileAlerts: a recovered downpipe does not alert", find(b.alerts, "dp-recover") === undefined);
    ok("reconcileAlerts: recovery clears the cooldown (relapse alerts immediately)", storage.rawGet(`${ALERT_COOLDOWN_PREFIX}dp-recover`) === undefined);
    ok("reconcileAlerts: a same-state in-cooldown failure is suppressed", find(b.alerts, "dp-suppress") === undefined);
    ok("reconcileAlerts: a suppressed (still-broken) cooldown is NOT cleared", storage.rawGet(`${ALERT_COOLDOWN_PREFIX}dp-suppress`) !== undefined);
    ok("reconcileAlerts: a state change (stale->failed) alerts", find(b.alerts, "dp-trans")?.state === "failed");
    ok("reconcileAlerts: a state change is a pending transition", b.pendingTransitionIds.includes("dp-trans"));
    ok("reconcileAlerts: an elapsed same-state cooldown re-nudges (alerts)", find(b.alerts, "dp-renudge")?.state === "failed");
    ok("reconcileAlerts: a re-nudge is NOT a pending transition", !b.pendingTransitionIds.includes("dp-renudge"));
  }

  // ============================================================================================
  // 5) markAlertsDelivered: two-phase clear (valid id, blank id, non-array body).
  // ============================================================================================
  {
    const { storage, stub } = makeScheduler();
    await storage.put(`${ALERT_COOLDOWN_PREFIX}keep`, { state: "failed", at: NOW });
    await storage.put(`${ALERT_COOLDOWN_PREFIX}gone`, { state: "failed", at: NOW });

    const r1 = await stubFetch(stub, "POST", "/alerts-delivered", { deliveredIds: ["keep"], failedTransitionIds: ["gone", ""] });
    ok("markAlertsDelivered: route returns 200", r1.status === 200);
    const c1 = (await r1.json()) as { cleared: number };
    ok("markAlertsDelivered: one valid failed id is cleared (blank id skipped)", c1.cleared === 1);
    ok("markAlertsDelivered: the failed-transition cooldown is deleted", storage.rawGet(`${ALERT_COOLDOWN_PREFIX}gone`) === undefined);
    ok("markAlertsDelivered: a delivered (kept) cooldown is retained", storage.rawGet(`${ALERT_COOLDOWN_PREFIX}keep`) !== undefined);

    // A body with NO failedTransitionIds (not an array) -> cleared 0 (the Array.isArray false branch).
    const r2 = await stubFetch(stub, "POST", "/alerts-delivered", { deliveredIds: ["x"] });
    ok("markAlertsDelivered: a body without failedTransitionIds clears nothing", ((await r2.json()) as { cleared: number }).cleared === 0);
  }

  // ============================================================================================
  // 6) reconcileReplicationAlerts: short-circuit, then the full branch matrix in one tick.
  // ============================================================================================
  {
    // No channel at all -> empty.
    const { storage, stub } = makeScheduler();
    await seedDp(storage, "rr-x", { destinationIds: ["A", "B"] });
    await storage.put("hist:rr-x", [{ runId: "x", index: 1, startedAt: iso(NOW), status: "ok", destinationId: "A" }] satisfies RunEntry[]);
    const r = await stubFetch(stub, "POST", "/reconcile-replication-alerts");
    const b = (await r.json()) as { emissions: unknown[]; pendingTransitionIds: string[] };
    ok("reconcileReplicationAlerts: no destination -> empty emissions", r.status === 200 && b.emissions.length === 0 && b.pendingTransitionIds.length === 0);
  }
  {
    const { storage, stub } = makeScheduler();
    await storage.put(`${NOTIFY_CHANNEL_PREFIX}ch-repl`, { id: "ch-repl", kind: "webhook", url: "https://hooks.example.com/repl" });

    const fullRing = (origin: string): RunEntry[] =>
      Array.from({ length: 50 }, (_, i) => ({ runId: `r${i + 1}`, index: i + 1, startedAt: iso(NOW), status: "ok", destinationId: origin }));

    // rr-deg: 3 dests, 2 of 3 proven, lagging copy reachable -> replication-degraded, "catching it up".
    await seedDp(storage, "rr-deg", { destinationIds: ["A", "B", "C"] });
    await storage.put("hist:rr-deg", [{ runId: "d9", index: 9, startedAt: iso(NOW), status: "ok", destinationId: "A" }] satisfies RunEntry[]);
    await storage.put("repl:rr-deg", { B: { holdsRunId: "d9", holdsIndex: 9, lastOk: true }, C: { holdsRunId: "d8", holdsIndex: 8, lastOk: true } });

    // rr-norepl: 2 dests, NO repl row -> the second copy is unproven (st undefined) and "not reachable".
    await seedDp(storage, "rr-norepl", { destinationIds: ["A", "B"] });
    await storage.put("hist:rr-norepl", [{ runId: "nr5", index: 5, startedAt: iso(NOW), status: "ok", destinationId: "A" }] satisfies RunEntry[]);

    // rr-noorigin: the ok run carries NO destinationId -> origin falls back to primaryDestinationId(config).
    await seedDp(storage, "rr-noorigin", { destinationIds: ["A", "B"] });
    await storage.put("hist:rr-noorigin", [{ runId: "no5", index: 5, startedAt: iso(NOW), status: "ok" }] satisfies RunEntry[]);
    await storage.put("repl:rr-noorigin", { B: { holdsRunId: "no4", holdsIndex: 4, lastOk: true } });

    // rr-behind-zero: a degraded pipe whose lagging copy is AT/above the ring head -> behindHeadBy 0 branch.
    await seedDp(storage, "rr-behind-zero", { destinationIds: ["A", "B"] });
    await storage.put("hist:rr-behind-zero", [
      { runId: "bz5", index: 5, startedAt: iso(NOW), status: "ok", destinationId: "A" },
      { runId: "bz9", index: 9, startedAt: iso(NOW), status: "ok", destinationId: "A" },
    ] satisfies RunEntry[]);
    await storage.put("repl:rr-behind-zero", { B: { holdsRunId: "bz7", holdsIndex: 7, lastOk: true } });

    // rr-single-cd: a single-destination pipe with a STALE cooldown -> skip + clear the cooldown.
    await seedDp(storage, "rr-single-cd", { destinationIds: ["only"] });
    await storage.put("hist:rr-single-cd", [{ runId: "s1", index: 1, startedAt: iso(NOW), status: "ok", destinationId: "only" }] satisfies RunEntry[]);
    await storage.put(`${REPL_ALERT_COOLDOWN_PREFIX}rr-single-cd`, { state: "replication-degraded", at: NOW });

    // rr-single-nocd: a single-destination pipe with no cooldown -> skip, nothing to clear.
    await seedDp(storage, "rr-single-nocd", { destinationIds: ["only"] });
    await storage.put("hist:rr-single-nocd", [{ runId: "s2", index: 1, startedAt: iso(NOW), status: "ok", destinationId: "only" }] satisfies RunEntry[]);

    // rr-nook-cd: a fan-out pipe with NO ok run + a stale cooldown -> skip + clear the cooldown.
    await seedDp(storage, "rr-nook-cd", { destinationIds: ["A", "B"] });
    await storage.put("hist:rr-nook-cd", [{ runId: "nk", index: 2, startedAt: iso(NOW), status: "failed", destinationId: "A" }] satisfies RunEntry[]);
    await storage.put(`${REPL_ALERT_COOLDOWN_PREFIX}rr-nook-cd`, { state: "replication-degraded", at: NOW });

    // rr-nook-nocd: a fan-out pipe with no ok run + no cooldown -> skip, nothing to clear.
    await seedDp(storage, "rr-nook-nocd", { destinationIds: ["A", "B"] });
    await storage.put("hist:rr-nook-nocd", [{ runId: "nk2", index: 2, startedAt: iso(NOW), status: "failed", destinationId: "A" }] satisfies RunEntry[]);

    // rr-healthy-cd: a fully-proven fan-out (ring not at cap) + a stale cooldown -> recover + clear.
    await seedDp(storage, "rr-healthy-cd", { destinationIds: ["A", "B"] });
    await storage.put("hist:rr-healthy-cd", [{ runId: "h5", index: 5, startedAt: iso(NOW), status: "ok", destinationId: "A" }] satisfies RunEntry[]);
    await storage.put("repl:rr-healthy-cd", { B: { holdsRunId: "h5", holdsIndex: 5, lastOk: true } });
    await storage.put(`${REPL_ALERT_COOLDOWN_PREFIX}rr-healthy-cd`, { state: "replication-degraded", at: NOW });

    // rr-atrisk-crit: a FULL ring, the only other copy lags below the head and is unreachable -> CRITICAL.
    // A prior degraded cooldown makes this an escalation (degraded -> at-risk) transition.
    await seedDp(storage, "rr-atrisk-crit", { destinationIds: ["A", "B"] });
    await storage.put("hist:rr-atrisk-crit", fullRing("A"));
    await storage.put("repl:rr-atrisk-crit", { B: { holdsRunId: null, holdsIndex: 0, lastOk: false } });
    await storage.put(`${REPL_ALERT_COOLDOWN_PREFIX}rr-atrisk-crit`, { state: "replication-degraded", at: NOW });

    // rr-atrisk-warn: a FULL ring with TWO proven copies but a third lagging -> at-risk but NOT critical.
    await seedDp(storage, "rr-atrisk-warn", { destinationIds: ["A", "B", "C"] });
    await storage.put("hist:rr-atrisk-warn", fullRing("A"));
    await storage.put("repl:rr-atrisk-warn", { B: { holdsRunId: "r50", holdsIndex: 50, lastOk: true }, C: { holdsRunId: "r0", holdsIndex: 0, lastOk: true } });

    // rr-nohist: a fan-out pipe with NO run-history ring -> the absent-ring default ([]) path, then skipped
    // (no ok run to reason about). No cooldown to clear.
    await seedDp(storage, "rr-nohist", { destinationIds: ["A", "B"] });

    // rr-inflight: the NEWEST ring row is in-flight (skipped); the prior ok run is the proven-copy anchor.
    await seedDp(storage, "rr-inflight", { destinationIds: ["A", "B"] });
    await storage.put("hist:rr-inflight", [
      { runId: "rif5", index: 5, startedAt: iso(NOW), status: "ok", destinationId: "A" },
      { runId: "rif6", index: 6, startedAt: iso(NOW), status: "in-flight" },
    ] satisfies RunEntry[]);
    await storage.put("repl:rr-inflight", { B: { holdsRunId: "rif4", holdsIndex: 4, lastOk: true } });

    // rr-renudge: degraded, same-state cooldown ELAPSED -> emits but is NOT a transition.
    await seedDp(storage, "rr-renudge", { destinationIds: ["A", "B"] });
    await storage.put("hist:rr-renudge", [{ runId: "re5", index: 5, startedAt: iso(NOW), status: "ok", destinationId: "A" }] satisfies RunEntry[]);
    await storage.put("repl:rr-renudge", { B: { holdsRunId: "re4", holdsIndex: 4, lastOk: true } });
    await storage.put(`${REPL_ALERT_COOLDOWN_PREFIX}rr-renudge`, { state: "replication-degraded", at: NOW - 2 * ALERT_COOLDOWN_MS });

    const r = await stubFetch(stub, "POST", "/reconcile-replication-alerts");
    ok("reconcileReplicationAlerts: route returns 200", r.status === 200);
    const b = (await r.json()) as {
      emissions: Array<{ event: string; severity: string; downpipeId: string; detail: string; catchingUp?: boolean }>;
      pendingTransitionIds: string[];
    };

    const deg = find(b.emissions, "rr-deg");
    ok("repl: a 2-of-3 fan-out emits replication-degraded (warning)", deg?.event === "replication-degraded" && deg?.severity === "warning");
    ok("repl: degraded detail reports 2 of 3 copies proven", /2 of 3 copies proven/.test(deg?.detail ?? ""));
    ok("repl: a reachable lagging copy reads 'catching it up'", deg?.catchingUp === true && /catching it up/.test(deg?.detail ?? ""));
    ok("repl: degraded detail is secret-free (carries no url)", !!deg && !/https?:\/\//.test(deg.detail));

    const norepl = find(b.emissions, "rr-norepl");
    ok("repl: a pipe with no repl row is degraded (unproven copy)", norepl?.event === "replication-degraded");
    ok("repl: an unreachable lagging copy reads 'not reachable'", norepl?.catchingUp === false && /not reachable/.test(norepl?.detail ?? ""));

    ok("repl: an ok run with no recorded origin still classifies (degraded)", find(b.emissions, "rr-noorigin")?.event === "replication-degraded");
    ok("repl: a lagging-but-above-head copy still degrades", find(b.emissions, "rr-behind-zero")?.event === "replication-degraded");
    ok("repl: a fan-out pipe with no history emits nothing", find(b.emissions, "rr-nohist") === undefined);
    ok("repl: the in-flight newest row is skipped; the prior ok anchors a degraded verdict", find(b.emissions, "rr-inflight")?.event === "replication-degraded");

    ok("repl: a single-destination pipe emits nothing", find(b.emissions, "rr-single-cd") === undefined && find(b.emissions, "rr-single-nocd") === undefined);
    ok("repl: a single-destination pipe's stale cooldown is cleared", storage.rawGet(`${REPL_ALERT_COOLDOWN_PREFIX}rr-single-cd`) === undefined);
    ok("repl: a no-ok-run pipe emits nothing", find(b.emissions, "rr-nook-cd") === undefined && find(b.emissions, "rr-nook-nocd") === undefined);
    ok("repl: a no-ok-run pipe's stale cooldown is cleared", storage.rawGet(`${REPL_ALERT_COOLDOWN_PREFIX}rr-nook-cd`) === undefined);
    ok("repl: a fully-proven pipe emits nothing", find(b.emissions, "rr-healthy-cd") === undefined);
    ok("repl: a recovered pipe's cooldown is cleared", storage.rawGet(`${REPL_ALERT_COOLDOWN_PREFIX}rr-healthy-cd`) === undefined);

    const crit = find(b.emissions, "rr-atrisk-crit");
    ok("repl: a last-copy eviction risk escalates to critical", crit?.event === "run-at-risk-eviction" && crit?.severity === "critical");
    ok("repl: at-risk detail names the head run aging out", /run 1 is about to age out/.test(crit?.detail ?? ""));
    ok("repl: an escalation (degraded->at-risk) is a pending transition", b.pendingTransitionIds.includes("rr-atrisk-crit"));

    const warn = find(b.emissions, "rr-atrisk-warn");
    ok("repl: a multi-copy eviction risk is at-risk but only a warning", warn?.event === "run-at-risk-eviction" && warn?.severity === "warning");

    const renudge = find(b.emissions, "rr-renudge");
    ok("repl: an elapsed same-state cooldown re-nudges (emits)", renudge?.event === "replication-degraded");
    ok("repl: a replication re-nudge is NOT a pending transition", !b.pendingTransitionIds.includes("rr-renudge"));

    // A SECOND tick: rr-deg now has a fresh cooldown of the SAME state within the window -> suppressed.
    const r2 = await stubFetch(stub, "POST", "/reconcile-replication-alerts");
    const b2 = (await r2.json()) as { emissions: Array<{ downpipeId: string }> };
    ok("repl: a same-state within-cooldown tick suppresses the degraded re-nudge", find(b2.emissions, "rr-deg") === undefined);
  }

  // ============================================================================================
  // 7) markReplicationAlertsDelivered: two-phase clear on the repl-alert-cd prefix.
  // ============================================================================================
  {
    const { storage, stub } = makeScheduler();
    await storage.put(`${REPL_ALERT_COOLDOWN_PREFIX}keep`, { state: "replication-degraded", at: NOW });
    await storage.put(`${REPL_ALERT_COOLDOWN_PREFIX}gone`, { state: "replication-degraded", at: NOW });

    const r1 = await stubFetch(stub, "POST", "/replication-alerts-delivered", { failedTransitionIds: ["gone", ""] });
    ok("markReplicationAlertsDelivered: route returns 200", r1.status === 200);
    const c1 = (await r1.json()) as { cleared: number };
    ok("markReplicationAlertsDelivered: one valid failed id is cleared (blank skipped)", c1.cleared === 1);
    ok("markReplicationAlertsDelivered: the failed transition cooldown is deleted", storage.rawGet(`${REPL_ALERT_COOLDOWN_PREFIX}gone`) === undefined);
    ok("markReplicationAlertsDelivered: an untouched cooldown is retained", storage.rawGet(`${REPL_ALERT_COOLDOWN_PREFIX}keep`) !== undefined);

    const r2 = await stubFetch(stub, "POST", "/replication-alerts-delivered", {});
    ok("markReplicationAlertsDelivered: a non-array body clears nothing", ((await r2.json()) as { cleared: number }).cleared === 0);
  }

  console.log(failures === 0 ? "\nVECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
