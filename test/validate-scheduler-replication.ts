// reconcileReplicationAlerts vectors: replication-degraded transition +
// cooldown, run-at-risk-eviction at the ring cap (escalated to critical), no alert for a single-
// destination pipe, and the fully-replicated case where recovery clears the cooldown. Detail strings
// must stay secret-free.
import { ok, makeScheduler, stubFetch, makeConfig } from "./validate-scheduler-shared.ts";

export async function run(): Promise<void> {
  // ---- TC-REPL-01: reconcileReplicationAlerts: replication-degraded transition + cooldown ----------
  // A 3-destination downpipe whose latest ok run is held by only 2 of 3 copies must emit ONE
  // replication-degraded alert on the proven<configured transition, then stay SILENT within the cooldown
  // window (a same-state re-nudge is suppressed for ALERT_COOLDOWN_MS). The detail must be secret-free.
  {
    const { stub, storage } = makeScheduler();
    // A delivery destination must exist for detection to run (mirrors reconcileAlerts' short-circuit).
    await storage.put("notify-channel:ch-detect", { id: "ch-detect", kind: "webhook", name: "Sink", url: "https://sink.example.com/hook", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" });
    const id = "dp-repl-degraded";
    const cfg = makeConfig(id, { destinationIds: ["dest-A", "dest-B", "dest-C"] });
    await storage.put(`dp:${id}`, { config: cfg, nextRunAt: Date.now() + 3_600_000, lastRunId: "run-9", inFlight: false });
    // Latest ok run at index 9, sealed to dest-A (the origin, always proven).
    await storage.put(`hist:${id}`, [
      { runId: "run-9", index: 9, startedAt: new Date().toISOString(), status: "ok", destinationId: "dest-A" },
    ]);
    // dest-B is caught up (holdsIndex 9, proven); dest-C lags at 8 (NOT proven). 2 of 3 proven.
    await storage.put(`repl:${id}`, {
      "dest-B": { holdsRunId: "run-9", holdsIndex: 9, lastOk: true, lastAttemptAt: Date.now() },
      "dest-C": { holdsRunId: "run-8", holdsIndex: 8, lastOk: true, lastAttemptAt: Date.now() },
    });

    const r1 = await stubFetch(stub, "POST", "/reconcile-replication-alerts");
    ok("repl-degraded: 200 response", r1.status === 200);
    const b1 = await r1.json() as { emissions: Array<{ event: string; severity: string; downpipeId: string | null; detail: string }>; pendingTransitionIds: string[] };
    ok("repl-degraded: exactly one emission on the proven<configured transition", b1.emissions.length === 1);
    const em = b1.emissions[0]!;
    ok("repl-degraded: event is replication-degraded", em.event === "replication-degraded");
    ok("repl-degraded: severity is warning", em.severity === "warning");
    ok("repl-degraded: downpipeId is the degraded pipe", em.downpipeId === id);
    ok("repl-degraded: detail reports 2 of 3 copies proven", /2 of 3 copies proven/.test(em.detail));
    ok("repl-degraded: the first alert is a transition (in pendingTransitionIds)", b1.pendingTransitionIds.includes(id));
    // Detail must carry NO destination ids, runIds, or url (redaction-safe: name + counts only).
    ok("repl-degraded: detail carries no destination id", !/dest-[ABC]/.test(em.detail));
    ok("repl-degraded: detail carries no runId", !/run-/.test(em.detail));
    ok("repl-degraded: detail carries no url", !/https?:\/\//.test(em.detail));

    // Second tick within the cooldown: SAME state, must be suppressed (no re-nudge storm).
    const r2 = await stubFetch(stub, "POST", "/reconcile-replication-alerts");
    const b2 = await r2.json() as { emissions: unknown[]; pendingTransitionIds: string[] };
    ok("repl-degraded: suppressed within the cooldown window (no second emission)", b2.emissions.length === 0);
    ok("repl-degraded: no transition id on the suppressed tick", b2.pendingTransitionIds.length === 0);
  }

  // ---- TC-REPL-02: reconcileReplicationAlerts: run-at-risk-eviction at the ring cap ---------------
  // When the run-history ring is AT CAP (RING_CAP entries) and a destination still lacks the run at the
  // ring head (the next to be evicted), the detector emits run-at-risk-eviction. Escalates to critical
  // when only the origin copy would remain proven.
  {
    const { stub, storage } = makeScheduler();
    await storage.put("notify-channel:ch-detect", { id: "ch-detect", kind: "webhook", name: "Sink", url: "https://sink.example.com/hook", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" });
    const id = "dp-repl-atrisk";
    const cfg = makeConfig(id, { destinationIds: ["dest-A", "dest-B"] });
    await storage.put(`dp:${id}`, { config: cfg, nextRunAt: Date.now() + 3_600_000, lastRunId: "run-50", inFlight: false });
    // A FULL ring of RING_CAP=50 entries, indices 1..50, all ok, sealed to dest-A. Head index is 1.
    const fullRing = Array.from({ length: 50 }, (_, i) => ({
      runId: `run-${i + 1}`,
      index: i + 1,
      startedAt: new Date().toISOString(),
      status: "ok" as const,
      destinationId: "dest-A",
    }));
    await storage.put(`hist:${id}`, fullRing);
    // dest-B lags far behind (holdsIndex 0): it lacks the head run (index 1) about to be evicted, and it
    // is the ONLY other copy, so eviction would leave just the origin proven -> critical.
    await storage.put(`repl:${id}`, {
      "dest-B": { holdsRunId: null, holdsIndex: 0, lastOk: false, lastAttemptAt: Date.now(), reason: "unreachable" },
    });

    const r = await stubFetch(stub, "POST", "/reconcile-replication-alerts");
    ok("repl-atrisk: 200 response", r.status === 200);
    const b = await r.json() as { emissions: Array<{ event: string; severity: string; downpipeId: string | null; detail: string }>; pendingTransitionIds: string[] };
    ok("repl-atrisk: exactly one emission when the ring is at cap with a behind copy", b.emissions.length === 1);
    const em = b.emissions[0]!;
    ok("repl-atrisk: event is run-at-risk-eviction", em.event === "run-at-risk-eviction");
    ok("repl-atrisk: escalated to critical (only the origin copy would remain)", em.severity === "critical");
    ok("repl-atrisk: downpipeId is the at-risk pipe", em.downpipeId === id);
    ok("repl-atrisk: detail names the head run index 1 closing", /run 1 is about to age out/.test(em.detail));
    ok("repl-atrisk: detail reports 1 of 2 copies proven", /1 of 2 copies proven/.test(em.detail));
    ok("repl-atrisk: detail carries no destination id", !/dest-[AB]/.test(em.detail));
    ok("repl-atrisk: detail carries no url", !/https?:\/\//.test(em.detail));
    ok("repl-atrisk: the alert is a transition", b.pendingTransitionIds.includes(id));

    // Same-state re-nudge within the cooldown window is suppressed (one page per ALERT_COOLDOWN_MS).
    const r2 = await stubFetch(stub, "POST", "/reconcile-replication-alerts");
    const b2 = await r2.json() as { emissions: unknown[]; pendingTransitionIds: string[] };
    ok("repl-atrisk: suppressed within the cooldown window (no second emission)", b2.emissions.length === 0);
    ok("repl-atrisk: no transition id on the suppressed tick", b2.pendingTransitionIds.length === 0);
  }

  // ---- TC-REPL-03: a single-destination downpipe never replication-alerts -------------------------
  // No off-site redundancy to lose: a one-destination downpipe must produce no replication emission even
  // when its (sole) copy is the only one. This guards against crying wolf on a non-fan-out downpipe.
  {
    const { stub, storage } = makeScheduler();
    await storage.put("notify-channel:ch-detect", { id: "ch-detect", kind: "webhook", name: "Sink", url: "https://sink.example.com/hook", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" });
    const id = "dp-repl-single";
    const cfg = makeConfig(id, { destinationIds: ["dest-only"] });
    await storage.put(`dp:${id}`, { config: cfg, nextRunAt: Date.now() + 3_600_000, lastRunId: "run-3", inFlight: false });
    await storage.put(`hist:${id}`, [
      { runId: "run-3", index: 3, startedAt: new Date().toISOString(), status: "ok", destinationId: "dest-only" },
    ]);
    const r = await stubFetch(stub, "POST", "/reconcile-replication-alerts");
    const b = await r.json() as { emissions: unknown[] };
    ok("repl-single: a single-destination downpipe emits no replication alert", b.emissions.length === 0);
  }

  // ---- TC-REPL-04: a fully-replicated fan-out downpipe never alerts, and recovery clears the cooldown
  // All copies proven and the ring not at cap: no emission. Then, after a degraded tick set a cooldown,
  // recovering to fully-proven must CLEAR the cooldown so a future relapse re-alerts immediately.
  {
    const { stub, storage } = makeScheduler();
    await storage.put("notify-channel:ch-detect", { id: "ch-detect", kind: "webhook", name: "Sink", url: "https://sink.example.com/hook", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" });
    const id = "dp-repl-healthy";
    const cfg = makeConfig(id, { destinationIds: ["dest-A", "dest-B"] });
    await storage.put(`dp:${id}`, { config: cfg, nextRunAt: Date.now() + 3_600_000, lastRunId: "run-5", inFlight: false });
    await storage.put(`hist:${id}`, [
      { runId: "run-5", index: 5, startedAt: new Date().toISOString(), status: "ok", destinationId: "dest-A" },
    ]);
    // Start DEGRADED (dest-B behind) so the first tick sets a cooldown.
    await storage.put(`repl:${id}`, { "dest-B": { holdsRunId: "run-4", holdsIndex: 4, lastOk: true, lastAttemptAt: Date.now() } });
    const r1 = await stubFetch(stub, "POST", "/reconcile-replication-alerts");
    ok("repl-recover: degraded fires once and writes a cooldown", (await r1.json() as { emissions: unknown[] }).emissions.length === 1);
    ok("repl-recover: a cooldown record exists after the degraded alert", storage.rawGet(`repl-alert-cd:${id}`) !== undefined);
    // Now dest-B catches up (holdsIndex 5): fully proven, ring not at cap -> no alert AND cooldown cleared.
    await storage.put(`repl:${id}`, { "dest-B": { holdsRunId: "run-5", holdsIndex: 5, lastOk: true, lastAttemptAt: Date.now() } });
    const r2 = await stubFetch(stub, "POST", "/reconcile-replication-alerts");
    const b2 = await r2.json() as { emissions: unknown[]; recoveries?: Array<{ event: string; severity: string; downpipeId: string; detail: string; recovered?: boolean }> };
    ok("repl-recover: no emission once fully proven", b2.emissions.length === 0);
    ok("repl-recover: the cooldown is cleared on recovery (a relapse re-alerts immediately)", storage.rawGet(`repl-alert-cd:${id}`) === undefined);

    // AUTO-RESOLVE: the falling edge of the replication-degraded cooldown emits
    // exactly one recovery, recovered:true, the SAME event + downpipeId, so PagerDuty resolves the
    // matching dedup_key (downpipe:<id>:replication-degraded). The detail names "destination unreachable
    // -> now healthy" in plain language (every configured destination reachable) since this codebase has
    // no separate destination-unreachable event (see the module comment in scheduler-do-sre-alerting.ts).
    ok("repl-recover: exactly one recovery emitted", (b2.recoveries ?? []).length === 1);
    const rrec = (b2.recoveries ?? [])[0];
    ok("repl-recover: recovery event mirrors the cleared cooldown state", rrec?.event === "replication-degraded");
    ok("repl-recover: recovery carries recovered:true", rrec?.recovered === true);
    ok("repl-recover: recovery targets the SAME downpipe id", rrec?.downpipeId === id);
    ok("repl-recover: recovery severity is warning (replication-degraded's base, not escalated)", rrec?.severity === "warning");
    ok("repl-recover: recovery detail says every destination is reachable", /every destination reachable/.test(rrec?.detail ?? ""));
    ok("repl-recover: recovery detail is secret-free (no destination id/url)", !/dest-[AB]/.test(rrec?.detail ?? "") && !/https?:\/\//.test(rrec?.detail ?? ""));
  }

  // ---- TC-REPL-04b: a run-at-risk-eviction recovery carries the ESCALATED (critical) severity through --
  // The trigger for run-at-risk-eviction may be escalated to critical (the last-proven-copy case); the
  // recovery must reuse that EXACT persisted severity, not recompute the warning base, or a customer rule
  // gated at minSeverity:critical would never see the resolve and the PagerDuty incident would stay open.
  {
    const { stub, storage } = makeScheduler();
    await storage.put("notify-channel:ch-detect", { id: "ch-detect", kind: "webhook", name: "Sink", url: "https://sink.example.com/hook", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" });
    const id = "dp-repl-atrisk-recover";
    const cfg = makeConfig(id, { destinationIds: ["dest-A", "dest-B"] });
    await storage.put(`dp:${id}`, { config: cfg, nextRunAt: Date.now() + 3_600_000, lastRunId: "run-50", inFlight: false });
    const fullRing = Array.from({ length: 50 }, (_, i) => ({
      runId: `run-${i + 1}`, index: i + 1, startedAt: new Date().toISOString(), status: "ok" as const, destinationId: "dest-A",
    }));
    await storage.put(`hist:${id}`, fullRing);
    // dest-B lags at the ring head -> the only other copy is behind -> critical (last-copy escalation).
    await storage.put(`repl:${id}`, { "dest-B": { holdsRunId: null, holdsIndex: 0, lastOk: false, lastAttemptAt: Date.now(), reason: "unreachable" } });

    const r1 = await stubFetch(stub, "POST", "/reconcile-replication-alerts");
    const b1 = await r1.json() as { emissions: Array<{ event: string; severity: string }> };
    ok("repl-atrisk-recover: the trigger escalates to critical", b1.emissions[0]?.event === "run-at-risk-eviction" && b1.emissions[0]?.severity === "critical");
    ok("repl-atrisk-recover: the escalated severity is persisted on the cooldown", storage.rawGet<{ severity?: string }>(`repl-alert-cd:${id}`)?.severity === "critical");

    // dest-B catches all the way up (past the ring, holdsIndex tracks the newest run): fully proven again.
    await storage.put(`repl:${id}`, { "dest-B": { holdsRunId: "run-50", holdsIndex: 50, lastOk: true, lastAttemptAt: Date.now() } });
    const r2 = await stubFetch(stub, "POST", "/reconcile-replication-alerts");
    const b2 = await r2.json() as { emissions: unknown[]; recoveries?: Array<{ event: string; severity: string; downpipeId: string }> };
    ok("repl-atrisk-recover: no emission once fully proven", b2.emissions.length === 0);
    ok("repl-atrisk-recover: exactly one recovery emitted", (b2.recoveries ?? []).length === 1);
    const rec = (b2.recoveries ?? [])[0];
    ok("repl-atrisk-recover: recovery event is run-at-risk-eviction", rec?.event === "run-at-risk-eviction");
    ok("repl-atrisk-recover: recovery severity STAYS critical (reuses the persisted escalation, not the warning base)", rec?.severity === "critical");
  }

  // ---- TC-INCOMPLETE-01: the backup-success notification carries recordsIncomplete ----------
  // A run that sealed incompleteness sentinels (markers, not the real bytes) must NOT notify a bare
  // "succeeded": reconcileAlerts' backup-success stream must report "completed with N items not fully
  // captured". A run with zero markers reports the plain success detail.
  {
    const { stub, storage } = makeScheduler();
    await storage.put("notify-channel:ch-detect", { id: "ch-detect", kind: "webhook", name: "Sink", url: "https://sink.example.com/hook", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" });
    const id = "dp-incomplete";
    const cfg = makeConfig(id, { destinationIds: ["dest-A"] });
    await storage.put(`dp:${id}`, { config: cfg, nextRunAt: Date.now() + 3_600_000, lastRunId: "run-77", inFlight: false });
    // Newest resolved run is ok and RECENT (now), sealed 3 incompleteness sentinels this run.
    await storage.put(`hist:${id}`, [
      { runId: "run-77", index: 77, startedAt: new Date().toISOString(), status: "ok", destinationId: "dest-A", recordsIncomplete: 3 },
    ]);
    const r = await stubFetch(stub, "POST", "/reconcile-alerts");
    ok("incomplete: 200 response", r.status === 200);
    const b = await r.json() as { successes: Array<{ event: string; detail: string; downpipeId: string | null }> };
    ok("incomplete: exactly one backup-success emission", b.successes.length === 1 && b.successes[0]!.event === "backup-success");
    ok("incomplete: the success detail reports N items not fully captured", /completed with 3 items not fully captured/.test(b.successes[0]!.detail));
    ok("incomplete: the success detail is NOT a bare 'succeeded'", !/backup succeeded/.test(b.successes[0]!.detail));
    // Redaction-safe: a plain count, no runId / destination id leaked into the detail.
    ok("incomplete: detail carries no runId", !/run-/.test(b.successes[0]!.detail));
    ok("incomplete: detail carries no destination id", !/dest-/.test(b.successes[0]!.detail));
  }

  // ---- TC-INCOMPLETE-02: a fully-captured run reports the plain success detail (0 markers) ----
  {
    const { stub, storage } = makeScheduler();
    await storage.put("notify-channel:ch-detect", { id: "ch-detect", kind: "webhook", name: "Sink", url: "https://sink.example.com/hook", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" });
    const id = "dp-complete";
    const cfg = makeConfig(id, { destinationIds: ["dest-A"] });
    await storage.put(`dp:${id}`, { config: cfg, nextRunAt: Date.now() + 3_600_000, lastRunId: "run-88", inFlight: false });
    await storage.put(`hist:${id}`, [
      { runId: "run-88", index: 88, startedAt: new Date().toISOString(), status: "ok", destinationId: "dest-A", recordsIncomplete: 0 },
    ]);
    const r = await stubFetch(stub, "POST", "/reconcile-alerts");
    const b = await r.json() as { successes: Array<{ detail: string }> };
    ok("complete: exactly one backup-success emission", b.successes.length === 1);
    ok("complete: a fully-captured run reports the plain 'backup succeeded' detail", /backup succeeded/.test(b.successes[0]!.detail) && !/not fully captured/.test(b.successes[0]!.detail));
  }
}
