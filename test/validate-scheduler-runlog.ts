// SchedulerDO runlog / alarm / removal vectors. Covers the no-op completion, throughput round-trip, disabled-excluded due(),
// unknown-id 400, idempotent/stale/superseded completions, the rearmAlarm clamp + soonest tracking,
// removeDownpipe, nextWithJitter bounds and the in-flight exclusion reason.
import { ok, makeScheduler, syncDueIndex, stubFetch, makeConfig, LEASE_EXPIRED_MS } from "./validate-scheduler-shared.ts";
import type { DownpipeConfig } from "./validate-scheduler-shared.ts";

export async function run(): Promise<void> {
  // ---- TC-10: completeRun with unknown/missing index is a no-op (empty-runId convention) ---
  {
    const { stub } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-noop"));

    // Trigger once to have a valid downpipe state.
    const t = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-noop" })).json() as { runId: string; index: number };

    // Call complete with an index that was never allocated (index 999).
    const r = await stubFetch(stub, "POST", "/complete", {
      id: "dp-noop",
      runId: "",
      index: 999,
      status: "failed",
    });
    ok("no-op completion: 200 response", r.status === 200);
    const body = await r.json() as { ok: true };
    ok("no-op completion: returns { ok: true }", body.ok === true);

    // The real in-flight entry (index 1) must be untouched.
    const histR = await stubFetch(stub, "GET", `/history?id=dp-noop`);
    const { entries } = await histR.json() as { entries: Array<{ index: number; status: string }> };
    const real = entries.find((e) => e.index === t.index);
    ok("no-op completion: real entry still in-flight (unaffected)", real?.status === "in-flight");
    ok("no-op completion: ring still has exactly 1 entry", entries.length === 1);
  }

  // ---- TC-11: throughput fields round-trip through completeRun ------------------------
  // This is the primary new-field regression: archiveBytesWritten/segmentsWritten/durationMs
  // are conditionally applied (only when present in the request), so an old caller omitting
  // them must leave the row without those fields (no undefined/null pollution).
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-thruput"));

    // Run WITH all throughput fields.
    const t1 = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-thruput" })).json() as { runId: string; index: number };
    await stubFetch(stub, "POST", "/complete", {
      id: "dp-thruput",
      runId: t1.runId,
      index: t1.index,
      status: "ok",
      archiveBytesWritten: 12345,
      segmentsWritten: 7,
      durationMs: 2200,
    });

    const hist1 = storage.rawGet<Array<{ index: number; archiveBytesWritten?: number; segmentsWritten?: number; durationMs?: number }>>("hist:dp-thruput") ?? [];
    const e1 = hist1.find((h) => h.index === t1.index);
    ok("throughput round-trip: archiveBytesWritten survives completeRun", e1?.archiveBytesWritten === 12345);
    ok("throughput round-trip: segmentsWritten survives completeRun", e1?.segmentsWritten === 7);
    ok("throughput round-trip: durationMs survives completeRun", e1?.durationMs === 2200);

    // Run WITHOUT throughput fields: the row must lack those keys entirely.
    const t2 = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-thruput" })).json() as { runId: string; index: number };
    await stubFetch(stub, "POST", "/complete", {
      id: "dp-thruput",
      runId: t2.runId,
      index: t2.index,
      status: "ok",
      recordCount: 5,
    });

    const hist2 = storage.rawGet<Array<{ index: number; archiveBytesWritten?: number; segmentsWritten?: number; durationMs?: number }>>("hist:dp-thruput") ?? [];
    const e2 = hist2.find((h) => h.index === t2.index);
    ok("throughput round-trip: absent archiveBytesWritten not written (undefined)", e2?.archiveBytesWritten === undefined);
    ok("throughput round-trip: absent segmentsWritten not written (undefined)", e2?.segmentsWritten === undefined);
    ok("throughput round-trip: absent durationMs not written (undefined)", e2?.durationMs === undefined);
  }

  // ---- TC-12: due() excludes disabled downpipes even when nextRunAt is past ----------
  // Belt-and-braces: explicitly backdate a DISABLED pipe and confirm it is not returned.
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-dis2", { enabled: false }));

    const dpStored = storage.rawGet<{ config: DownpipeConfig; nextRunAt: number; inFlight: boolean; lastRunId: null }>("dp:dp-dis2");
    if (dpStored) {
      dpStored.nextRunAt = Date.now() - 60_000;
      await storage.put("dp:dp-dis2", dpStored);
      await syncDueIndex(storage, "dp-dis2"); // disabled -> no index entry, but keep the helper consistent across backdates
    }
    const { due } = await (await stubFetch(stub, "GET", "/due")).json() as { due: Array<{ config: { id: string } }> };
    ok("due: disabled pipe excluded even when past-due", !due.some((d) => d.config.id === "dp-dis2"));
  }

  // ---- TC-13: trigger on unknown downpipe returns 400 ---------------------------------
  {
    const { stub } = makeScheduler();
    const r = await stubFetch(stub, "POST", "/trigger", { id: "dp-does-not-exist" });
    ok("trigger unknown id: 400 response", r.status === 400);
    const b = await r.json() as { error: string };
    ok("trigger unknown id: error message references the id", b.error.includes("dp-does-not-exist"));
  }

  // ---- TC-14a: a DUPLICATE success completion is a no-op (idempotency) -------
  // A retried /complete POST for an already-resolved run must not re-overwrite the resolved
  // row's counts nor re-advance lastRunId / re-jitter nextRunAt. The row is resolved once; a
  // second completion bearing different counts finds the row no longer in-flight and is ignored.
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-dup"));

    const t = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-dup" })).json() as { runId: string; index: number };

    // First (genuine) success completion records counts.
    await stubFetch(stub, "POST", "/complete", { id: "dp-dup", runId: t.runId, index: t.index, status: "ok", recordCount: 10, bytes: 1000 });

    const afterFirst = storage.rawGet<{ lastRunId: string | null; nextRunAt: number }>("dp:dp-dup")!;
    const nextRunAtAfterFirst = afterFirst.nextRunAt;
    ok("dup-complete: first completion advanced lastRunId", afterFirst.lastRunId === t.runId);

    // A DUPLICATE success completion for the SAME run, carrying DIFFERENT counts, must be ignored.
    await stubFetch(stub, "POST", "/complete", { id: "dp-dup", runId: t.runId, index: t.index, status: "ok", recordCount: 999, bytes: 999999 });

    const histDup = storage.rawGet<Array<{ index: number; status: string; recordCount?: number; bytes?: number }>>("hist:dp-dup")!;
    const eDup = histDup.find((h) => h.index === t.index);
    ok("dup-complete: row status stays ok", eDup?.status === "ok");
    ok("dup-complete: row recordCount NOT re-overwritten by the duplicate", eDup?.recordCount === 10);
    ok("dup-complete: row bytes NOT re-overwritten by the duplicate", eDup?.bytes === 1000);

    const afterDup = storage.rawGet<{ lastRunId: string | null; nextRunAt: number }>("dp:dp-dup")!;
    ok("dup-complete: lastRunId unchanged by the duplicate", afterDup.lastRunId === t.runId);
    ok("dup-complete: nextRunAt NOT re-jittered by the duplicate", afterDup.nextRunAt === nextRunAtAfterFirst);
  }

  // ---- TC-14b: a STALE completion does not clobber an already-resolved (failed) row ----
  // The race the audit calls out: a late completion (a presumed-dead run that did land) arrives
  // AFTER the row was resolved to failed. It must not flip the resolved row's outcome, nor
  // advance lastRunId off the empty-runId failure convention.
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-stale"));

    const t = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-stale" })).json() as { runId: string; index: number };

    // Resolve the run to FAILED first (empty runId convention).
    await stubFetch(stub, "POST", "/complete", { id: "dp-stale", runId: "", index: t.index, status: "failed", error: "connection timeout" });

    // A LATE success completion for the same index/run arrives after the failure was recorded.
    await stubFetch(stub, "POST", "/complete", { id: "dp-stale", runId: t.runId, index: t.index, status: "ok", recordCount: 7 });

    const hist = storage.rawGet<Array<{ index: number; status: string; error?: string; recordCount?: number }>>("hist:dp-stale")!;
    const e = hist.find((h) => h.index === t.index);
    ok("stale-complete: resolved row stays failed (late success ignored)", e?.status === "failed");
    ok("stale-complete: failed row keeps its coarse error", e?.error === "connection timeout");
    ok("stale-complete: late success counts NOT written onto the resolved row", e?.recordCount === undefined);

    const ds = storage.rawGet<{ lastRunId: string | null }>("dp:dp-stale")!;
    ok("stale-complete: lastRunId not advanced by the late success", ds.lastRunId === null);
  }

  // ---- TC-14c: a stale completion does not clear a NEWER in-flight run -------
  // The headline guard. Run 1 is triggered, then reclaimed by the lease and superseded by run 2
  // (run 1's row -> abandoned, run 2 in-flight at a new index). A LATE completion for run 1 must
  // be a no-op: it must NOT clear run 2's in-flight flag, must NOT touch run 1's abandoned row,
  // and must NOT touch run 2's in-flight row.
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-supersede", { enabled: true }));

    // Run 1: triggered and marked in-flight.
    const t1 = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-supersede" })).json() as { runId: string; index: number };

    // Age run 1 past the lease and make it due, so the next trigger RECLAIMS it (a crashed run).
    const stored = storage.rawGet<{ inFlightSince?: number; nextRunAt: number }>("dp:dp-supersede")!;
    stored.inFlightSince = Date.now() - LEASE_EXPIRED_MS;
    stored.nextRunAt = Date.now() - 1000;
    await storage.put("dp:dp-supersede", stored);
    await syncDueIndex(storage, "dp-supersede"); // re-sync the index to the backdated nextRunAt

    // Run 2: reclaims (a fresh run at a new index); run 1's row becomes abandoned.
    const t2 = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-supersede" })).json() as { runId: string; index: number; skipped?: string };
    ok("supersede: run 2 is a fresh reclaim (not skipped)", typeof t2.runId === "string" && t2.runId !== t1.runId);
    ok("supersede: run 2 allocates a newer index", t2.index === t1.index + 1);

    // A LATE completion for RUN 1 (the old, now-abandoned run) arrives.
    await stubFetch(stub, "POST", "/complete", { id: "dp-supersede", runId: t1.runId, index: t1.index, status: "ok", recordCount: 3 });

    // Run 2's in-flight flag and lease must be intact: the stale run-1 completion must NOT clear it.
    const dsAfter = storage.rawGet<{ inFlight: boolean; inFlightSince?: number; lastRunId: string | null }>("dp:dp-supersede")!;
    ok("supersede: the newer run 2 is STILL in-flight after the stale completion", dsAfter.inFlight === true);
    ok("supersede: run 2's lease was not cleared", typeof dsAfter.inFlightSince === "number");
    ok("supersede: lastRunId not advanced to the stale run 1", dsAfter.lastRunId !== t1.runId);

    const histS = storage.rawGet<Array<{ runId: string; index: number; status: string; recordCount?: number }>>("hist:dp-supersede")!;
    const row1 = histS.find((h) => h.index === t1.index);
    const row2 = histS.find((h) => h.index === t2.index);
    ok("supersede: run 1's row stays abandoned (stale completion ignored)", row1?.status === "abandoned");
    ok("supersede: the stale completion did not write counts onto run 1's row", row1?.recordCount === undefined);
    ok("supersede: run 2's row stays in-flight (untouched)", row2?.status === "in-flight");
  }

  // ---- TC-14d: the NEW in-flight run can still complete normally after a stale completion ---
  // Guard regression check: hardening completeRun must not strand the live run. After the stale
  // run-1 completion above, run 2's own genuine completion must still resolve its row and clear
  // the flag (the guard keys on the run that owns the in-flight lease, so the live run is fine).
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-live", { enabled: true }));

    const t1 = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-live" })).json() as { runId: string; index: number };
    const s = storage.rawGet<{ inFlightSince?: number; nextRunAt: number }>("dp:dp-live")!;
    s.inFlightSince = Date.now() - LEASE_EXPIRED_MS;
    s.nextRunAt = Date.now() - 1000;
    await storage.put("dp:dp-live", s);
    await syncDueIndex(storage, "dp-live"); // re-sync the index to the backdated nextRunAt
    const t2 = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-live" })).json() as { runId: string; index: number };

    // Stale run-1 completion (ignored), then run 2's genuine success completion.
    await stubFetch(stub, "POST", "/complete", { id: "dp-live", runId: t1.runId, index: t1.index, status: "ok" });
    await stubFetch(stub, "POST", "/complete", { id: "dp-live", runId: t2.runId, index: t2.index, status: "ok", recordCount: 5 });

    const ds = storage.rawGet<{ inFlight: boolean; lastRunId: string | null }>("dp:dp-live")!;
    ok("live-complete: run 2 is no longer in-flight after its own completion", ds.inFlight === false);
    ok("live-complete: lastRunId advanced to run 2", ds.lastRunId === t2.runId);
    const hist = storage.rawGet<Array<{ index: number; status: string; recordCount?: number }>>("hist:dp-live")!;
    ok("live-complete: run 2's row resolved to ok", hist.find((h) => h.index === t2.index)?.status === "ok");
    ok("live-complete: run 2's counts recorded", hist.find((h) => h.index === t2.index)?.recordCount === 5);
  }

  // ---- TC-15: rearmAlarm never schedules an alarm in the past -----------------
  // A wedged enabled downpipe (a past-due nextRunAt that only completion would advance) must not
  // pin the alarm in the past: setAlarm(past) refires immediately and alarm() re-arms the same
  // past value, a self-refire storm. rearmAlarm floors the armed time to now + ALARM_MIN_DELAY_MS.
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-wedged", { enabled: true }));

    // Backdate nextRunAt well into the past (a wedged/crashed run that never completed).
    const wedged = storage.rawGet<{ nextRunAt: number }>("dp:dp-wedged")!;
    wedged.nextRunAt = Date.now() - 10 * 60 * 1000; // 10 minutes ago
    await storage.put("dp:dp-wedged", wedged);
    await syncDueIndex(storage, "dp-wedged"); // keep the index consistent with the backdated nextRunAt

    const before = Date.now();
    // POST /tick drives alarm() -> rearmAlarm(), the same path a fired DO alarm takes.
    await stubFetch(stub, "POST", "/tick");
    const after = Date.now();

    ok("rearm-clamp: an alarm was armed", storage.lastAlarmAt !== null);
    // The load-bearing property: the armed time is NOT in the past. With the clamp it is floored to
    // roughly now + ALARM_MIN_DELAY_MS (a positive future delay); without the clamp it would be the
    // past nextRunAt, far below `before`.
    ok("rearm-clamp: armed time is not in the past (>= the now used to arm)", (storage.lastAlarmAt ?? 0) >= before);
    // And it is only a SHORT delay ahead (the floor, not some far-future time): bounded by the
    // wall-clock window of the call plus the floor (1000ms) and a little slack.
    ok("rearm-clamp: armed time is a short floored delay, not far future", (storage.lastAlarmAt ?? 0) <= after + 1000 + 50);
  }

  // ---- TC-15b: rearmAlarm arms a HEALTHY pipe at its real (future) nextRunAt -----------
  // The clamp must only bite a past/near-past time: a genuinely future nextRunAt (a full cadence
  // out) is armed exactly, never delayed by the floor.
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-healthy", { enabled: true }));

    const healthy = storage.rawGet<{ nextRunAt: number }>("dp:dp-healthy")!;
    const future = Date.now() + 3600_000; // 1 hour out, far beyond the floor
    healthy.nextRunAt = future;
    await storage.put("dp:dp-healthy", healthy);
    await syncDueIndex(storage, "dp-healthy"); // keep the index consistent with the future nextRunAt

    await stubFetch(stub, "POST", "/tick");
    ok("rearm-clamp: a healthy future nextRunAt is armed exactly (clamp does not bite)", storage.lastAlarmAt === future);
  }

  // ---- TC-15c: rearmAlarm tracks the SOONEST enabled pipe ---------------------
  // When multiple enabled pipes exist, the alarm must be armed at the minimum nextRunAt across
  // ALL enabled pipes (clamped to now + ALARM_MIN_DELAY_MS when past). A bug that picks ANY pipe
  // other than the soonest would delay wakeups for fast-cadence pipes behind a slow one.
  // Three pipes: soonest (30 min out), later (2 hours out), disabled (nextRunAt = 1 min out but
  // excluded because disabled). Only the soonest enabled pipe must set the alarm.
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-soonest", { enabled: true, cadenceSeconds: 3600 }));
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-later", { enabled: true, cadenceSeconds: 3600 }));
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-dis-soonest", { enabled: false, cadenceSeconds: 3600 }));

    const soonestAt = Date.now() + 30 * 60 * 1000;   // 30 minutes out
    const laterAt   = Date.now() + 2 * 3600 * 1000;  // 2 hours out
    const disabledAt = Date.now() + 60 * 1000;        // 1 minute out - disabled, must be ignored

    const s1 = storage.rawGet<{ nextRunAt: number }>("dp:dp-soonest")!;
    s1.nextRunAt = soonestAt;
    await storage.put("dp:dp-soonest", s1);

    const s2 = storage.rawGet<{ nextRunAt: number }>("dp:dp-later")!;
    s2.nextRunAt = laterAt;
    await storage.put("dp:dp-later", s2);

    const s3 = storage.rawGet<{ nextRunAt: number }>("dp:dp-dis-soonest")!;
    s3.nextRunAt = disabledAt;
    await storage.put("dp:dp-dis-soonest", s3);

    // Keep the due-time index consistent with all three backdated states (rearmAlarm reads dp: directly,
    // not the index, but staying consistent everywhere keeps the test faithful to the production writer).
    await syncDueIndex(storage, "dp-soonest");
    await syncDueIndex(storage, "dp-later");
    await syncDueIndex(storage, "dp-dis-soonest");

    await stubFetch(stub, "POST", "/tick");

    ok("rearm-soonest: alarm was armed", storage.lastAlarmAt !== null);
    // The alarm must equal the soonest ENABLED pipe, not the later one.
    ok("rearm-soonest: alarm equals soonest enabled pipe (not the later one)", storage.lastAlarmAt === soonestAt);
    // Negative control: the alarm must not be the later pipe's time.
    ok("rearm-soonest: alarm is not the later pipe's nextRunAt (wrong pipe would fail here)", storage.lastAlarmAt !== laterAt);
    // Negative control: the disabled pipe is even sooner but must be ignored.
    ok("rearm-soonest: alarm is not the disabled pipe's nextRunAt (disabled pipes excluded)", storage.lastAlarmAt !== disabledAt);
  }

  // ---- TC-15d: rearmAlarm - removing the soonest pipe re-arms to the next soonest ------
  // Guard for the removeDownpipe path: after the soonest pipe is deleted, rearmAlarm must
  // pick the next soonest enabled pipe. This covers the rearmAlarm call inside removeDownpipe.
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-del-soon", { enabled: true, cadenceSeconds: 3600 }));
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-del-later", { enabled: true, cadenceSeconds: 3600 }));

    const soonAt  = Date.now() + 20 * 60 * 1000;  // 20 minutes out
    const laterAt = Date.now() + 90 * 60 * 1000;  // 90 minutes out

    const sa = storage.rawGet<{ nextRunAt: number }>("dp:dp-del-soon")!;
    sa.nextRunAt = soonAt;
    await storage.put("dp:dp-del-soon", sa);

    const sb = storage.rawGet<{ nextRunAt: number }>("dp:dp-del-later")!;
    sb.nextRunAt = laterAt;
    await storage.put("dp:dp-del-later", sb);

    await syncDueIndex(storage, "dp-del-soon");
    await syncDueIndex(storage, "dp-del-later");

    // Confirm the alarm initially tracks the sooner pipe.
    await stubFetch(stub, "POST", "/tick");
    ok("rearm-delete: initial alarm is the soonest pipe", storage.lastAlarmAt === soonAt);

    // Delete the soonest pipe. rearmAlarm runs inside removeDownpipe.
    await stubFetch(stub, "POST", "/delete", { id: "dp-del-soon" });

    // After deletion the alarm must have re-armed to the next soonest (the later pipe).
    ok("rearm-delete: after removing the soonest pipe the alarm advances to the next soonest", storage.lastAlarmAt === laterAt);
    // Negative control: the alarm must not still be the deleted pipe's time.
    ok("rearm-delete: alarm is not the deleted pipe's old time", storage.lastAlarmAt !== soonAt);
  }

  // ---- TC-16: removeDownpipe removes the pipe from list, due, and history ----------------
  // A deleted downpipe must be completely gone: not in GET /downpipes, not in GET /due (even
  // when past-due), and its history ring must be dropped.
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-del", { enabled: true }));

    // Trigger once so a history ring exists.
    const t = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-del" })).json() as { runId: string; index: number };
    await stubFetch(stub, "POST", "/complete", { id: "dp-del", runId: t.runId, index: t.index, status: "ok" });

    // Backdate nextRunAt so it would appear in due() if it were still present.
    const stored = storage.rawGet<{ nextRunAt: number }>("dp:dp-del")!;
    stored.nextRunAt = Date.now() - 5_000;
    await storage.put("dp:dp-del", stored);
    await syncDueIndex(storage, "dp-del"); // index must reflect the backdate so due() sees it before deletion

    // Confirm it IS in due() before deletion.
    const { due: dueBefore } = await (await stubFetch(stub, "GET", "/due")).json() as { due: Array<{ config: { id: string } }> };
    ok("removeDownpipe: pipe is in due() before deletion (precondition)", dueBefore.some((d) => d.config.id === "dp-del"));

    // Delete the downpipe.
    const delR = await stubFetch(stub, "POST", "/delete", { id: "dp-del" });
    ok("removeDownpipe: /delete returns 200", delR.status === 200);
    const delBody = await delR.json() as { deleted: boolean };
    ok("removeDownpipe: deleted is true", delBody.deleted === true);

    // Must be gone from GET /downpipes.
    const listR = await stubFetch(stub, "GET", "/downpipes");
    const list = await listR.json() as Array<{ config: { id: string } }>;
    ok("removeDownpipe: pipe absent from /downpipes after deletion", !list.some((d) => d.config.id === "dp-del"));

    // Must be absent from GET /due even though nextRunAt is in the past.
    const { due: dueAfter } = await (await stubFetch(stub, "GET", "/due")).json() as { due: Array<{ config: { id: string } }> };
    ok("removeDownpipe: pipe absent from /due after deletion", !dueAfter.some((d) => d.config.id === "dp-del"));

    // History ring must be dropped from storage.
    const histAfter = storage.rawGet<unknown>("hist:dp-del");
    ok("removeDownpipe: history ring dropped from storage", histAfter === undefined);

    // Raw storage key must be gone too.
    const dpAfter = storage.rawGet<unknown>("dp:dp-del");
    ok("removeDownpipe: downpipe state key dropped from storage", dpAfter === undefined);

    // Deleting again must return deleted: false (idempotent).
    const del2 = await (await stubFetch(stub, "POST", "/delete", { id: "dp-del" })).json() as { deleted: boolean };
    ok("removeDownpipe: second deletion returns deleted: false (idempotent)", del2.deleted === false);
  }

  // ---- TC-17: nextWithJitter bounds (exposed via trigger + storage inspection) ---------
  // nextWithJitter jitters BACKWARDS: it must return a value in [now + cadence*0.9, now + cadence]
  // so a run never lands beyond its cadence (a "daily" pipe reads as <= a day, not 24-26h).
  // JITTER_FRACTION is 0.1 (10 %). We cannot import the private method directly, but addDownpipe
  // calls it and stores the result as nextRunAt, so we can inspect the stored state.
  {
    const { storage, stub } = makeScheduler();
    const cadenceSeconds = 3600; // one hour
    const before = Date.now();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-jitter", { cadenceSeconds }));
    const after = Date.now();

    const stored = storage.rawGet<{ nextRunAt: number }>("dp:dp-jitter")!;
    const low  = before + cadenceSeconds * 1000 * 0.9; // cadence * (1 - 0.10)
    const high = after  + cadenceSeconds * 1000;       // never beyond the full cadence

    ok("nextWithJitter: nextRunAt <= now + cadence (never beyond cadence)", stored.nextRunAt <= high);
    ok("nextWithJitter: nextRunAt >= now + cadence * 0.9 (bounded backward jitter)", stored.nextRunAt >= low);

    // After a completed run the same jitter discipline must hold for the re-scheduled time.
    const t = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-jitter" })).json() as { runId: string; index: number };
    const beforeComplete = Date.now();
    await stubFetch(stub, "POST", "/complete", { id: "dp-jitter", runId: t.runId, index: t.index, status: "ok" });
    const afterComplete = Date.now();

    const storedAfter = storage.rawGet<{ nextRunAt: number }>("dp:dp-jitter")!;
    const lowAfter  = beforeComplete + cadenceSeconds * 1000 * 0.9;
    const highAfter = afterComplete  + cadenceSeconds * 1000;
    ok("nextWithJitter: re-scheduled nextRunAt <= now + cadence after completion", storedAfter.nextRunAt <= highAfter);
    ok("nextWithJitter: re-scheduled nextRunAt >= now + cadence*0.9 after completion", storedAfter.nextRunAt >= lowAfter);
  }

  // ---- TC-18: in-flight pipe with past nextRunAt is excluded from due() for the right reason ----
  // An in-flight pipe whose nextRunAt is in the past must NOT appear in due() while its lease is
  // still active. This exercises the coalescing guard explicitly: the pipe is excluded because it
  // is LEASED (genuinely in-flight), not because nextRunAt is in the future. We verify this by
  // also confirming the pipe DOES re-appear once the lease expires (TC-06b already covers the
  // full reclaim path; here we focus on why the exclusion happens while the lease is fresh).
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-lease-reason", { enabled: true }));

    // Trigger to put the pipe in-flight with a fresh lease.
    await stubFetch(stub, "POST", "/trigger", { id: "dp-lease-reason" });

    // Backdate nextRunAt so the pipe WOULD be due if it were not in-flight.
    const stored = storage.rawGet<{ inFlight: boolean; inFlightSince?: number; nextRunAt: number }>("dp:dp-lease-reason")!;
    ok("in-flight-exclusion precondition: pipe is in-flight", stored.inFlight === true);
    ok("in-flight-exclusion precondition: lease timestamp is set", typeof stored.inFlightSince === "number");
    stored.nextRunAt = Date.now() - 10_000; // 10 seconds in the past
    await storage.put("dp:dp-lease-reason", stored);
    await syncDueIndex(storage, "dp-lease-reason"); // index reflects the past nextRunAt; the lease, not the index, gates due()

    // With a fresh lease the pipe must be absent from due() even though nextRunAt is past.
    const { due: dueFreshLease } = await (await stubFetch(stub, "GET", "/due")).json() as { due: Array<{ config: { id: string } }> };
    ok("in-flight-exclusion: pipe with past nextRunAt absent from due() while lease is fresh", !dueFreshLease.some((d) => d.config.id === "dp-lease-reason"));

    // Expire the lease by back-dating inFlightSince past INFLIGHT_LEASE_MS (30 min).
    const storedExpired = storage.rawGet<{ inFlight: boolean; inFlightSince?: number; nextRunAt: number }>("dp:dp-lease-reason")!;
    storedExpired.inFlightSince = Date.now() - LEASE_EXPIRED_MS;
    await storage.put("dp:dp-lease-reason", storedExpired);
    await syncDueIndex(storage, "dp-lease-reason"); // nextRunAt unchanged here; the index entry is the same

    // Now the lease is expired: the pipe must re-appear in due() (the lease guard no longer blocks it).
    const { due: dueExpiredLease } = await (await stubFetch(stub, "GET", "/due")).json() as { due: Array<{ config: { id: string } }> };
    ok("in-flight-exclusion: pipe re-appears in due() once lease expires (lease was the reason, not nextRunAt)", dueExpiredLease.some((d) => d.config.id === "dp-lease-reason"));

    // Confirm it is the LEASE that matters and not some other property: nextRunAt was already in the
    // past before the lease expired, so the transition from absent to present is caused solely by the
    // lease expiry. We also confirm inFlight is still true in storage (the state has not changed;
    // only the inFlightSince timestamp moved).
    const storedFinal = storage.rawGet<{ inFlight: boolean }>("dp:dp-lease-reason")!;
    ok("in-flight-exclusion: inFlight flag is still true (no external mutation changed the state)", storedFinal.inFlight === true);
  }
}
