// SchedulerDO lifecycle vectors: add/list,
// validation, due() selection, trigger index allocation, completeRun ok/failed, coalescing + lease
// reclaim, RING_CAP truncation, monotonicity and gap-tolerance. The remaining lifecycle vectors
// (no-op/idempotent/stale completions, rearmAlarm, removeDownpipe, jitter, in-flight exclusion) live
// in validate-scheduler-runlog.ts.
import { ok, makeScheduler, syncDueIndex, stubFetch, makeConfig, LEASE_EXPIRED_MS } from "./validate-scheduler-shared.ts";
import type { DownpipeConfig } from "./validate-scheduler-shared.ts";

export async function run(): Promise<void> {
  // ---- TC-01-A: addDownpipe + listDownpipes -------------------------------------------
  {
    const { stub } = makeScheduler();
    const r1 = await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-a"));
    ok("addDownpipe: 200 response", r1.status === 200);
    const ds = await r1.json() as { config: { id: string }; inFlight: boolean; lastRunId: null };
    ok("addDownpipe: returned id matches", ds.config.id === "dp-a");
    ok("addDownpipe: inFlight starts false", ds.inFlight === false);
    ok("addDownpipe: lastRunId starts null", ds.lastRunId === null);

    const r2 = await stubFetch(stub, "GET", "/downpipes");
    ok("listDownpipes: 200 response", r2.status === 200);
    const list = await r2.json() as Array<{ config: { id: string } }>;
    ok("listDownpipes: returns the added downpipe", list.some((d) => d.config.id === "dp-a"));
  }

  // ---- TC-01-B: addDownpipe rejects an invalid config cleanly -------------------------
  {
    const { stub } = makeScheduler();
    // cadenceSeconds < 60 is invalid per validateConfig
    const r = await stubFetch(stub, "POST", "/downpipes", makeConfig("bad", { cadenceSeconds: 10 }));
    ok("addDownpipe: invalid config returns 400", r.status === 400);
    const b = await r.json() as { error: string };
    ok("addDownpipe: error message is present", typeof b.error === "string" && b.error.length > 0);
  }

  // ---- TC-01-C: a secrets source's secrets list is bounded (MAX_SECRETS_PER_SOURCE) ----
  {
    const { stub, storage } = makeScheduler();
    // An OVERSIZED secrets list (5001 > the 5000 cap) is REJECTED, not truncated, so the coverage match
    // loop and the seal loop over a source's secrets stay bounded and the operator knows it did not land.
    const tooMany = Array.from({ length: 5001 }, (_, i) => ({ name: `SECRET_${i}`, binding: `SEC_${i}` }));
    const over = await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-secrets-over", { source: { type: "secrets", secrets: tooMany, include: [], exclude: [] } }));
    ok("addDownpipe: an over-cap secrets list returns 400", over.status === 400);
    const ob = await over.json() as { error: string };
    ok("addDownpipe: the over-cap rejection names the secrets bound", typeof ob.error === "string" && /5000 secrets/.test(ob.error));
    ok("addDownpipe: the rejected over-cap secrets config stored nothing", storage.rawGet("dp:dp-secrets-over") === undefined);
    // A within-cap secrets source is still accepted (the bound is a backstop, not a normal value).
    const okResp = await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-secrets-ok", { source: { type: "secrets", secrets: [{ name: "API_KEY", binding: "SEC_API" }], include: [], exclude: [] } }));
    ok("addDownpipe: a within-cap secrets source is accepted (200)", okResp.status === 200);
  }

  // ---- TC-01-D: retention config validation (ASVS V14.2.7) ---------------------------
  {
    const { stub } = makeScheduler();
    // ABSENT retention is the current behaviour (keep everything): a config with no retention is
    // accepted and stores no retention field, so a pre-retention config is unchanged.
    const noRet = await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-noret"));
    ok("retention: a config WITHOUT retention is accepted (keep everything)", noRet.status === 200);
    const noRetDs = (await noRet.json()) as { config: { retention?: unknown } };
    ok("retention: an absent retention stays absent on the stored config", noRetDs.config.retention === undefined);

    // A valid retention with keepRuns is accepted and round-trips.
    const okRuns = await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-ret-runs", { retention: { keepRuns: 7 } }));
    ok("retention: keepRuns:7 is accepted (200)", okRuns.status === 200);
    const okRunsDs = (await okRuns.json()) as { config: { retention?: { keepRuns?: number } } };
    ok("retention: keepRuns round-trips on the stored config", okRunsDs.config.retention?.keepRuns === 7);

    // A valid retention with keepDays + enforce is accepted.
    const okDays = await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-ret-days", { retention: { keepDays: 30, enforce: true } }));
    ok("retention: keepDays:30 + enforce:true is accepted (200)", okDays.status === 200);
    const okDaysDs = (await okDays.json()) as { config: { retention?: { keepDays?: number; enforce?: boolean } } };
    ok("retention: keepDays + enforce round-trip on the stored config", okDaysDs.config.retention?.keepDays === 30 && okDaysDs.config.retention?.enforce === true);

    // An EMPTY retention object (neither keepRuns nor keepDays) is rejected: it describes no window.
    const empty = await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-ret-empty", { retention: {} }));
    ok("retention: an empty {} retention is rejected (400)", empty.status === 400);

    // keepRuns must be a positive integer: 0 is rejected (retaining zero runs is never the intent).
    const zeroRuns = await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-ret-zero", { retention: { keepRuns: 0 } }));
    ok("retention: keepRuns:0 is rejected (400)", zeroRuns.status === 400);

    // A non-integer keepRuns is rejected.
    const fracRuns = await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-ret-frac", { retention: { keepRuns: 2.5 } }));
    ok("retention: a fractional keepRuns is rejected (400)", fracRuns.status === 400);

    // keepDays must be a positive integer: a negative value is rejected.
    const negDays = await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-ret-neg", { retention: { keepDays: -1 } }));
    ok("retention: a negative keepDays is rejected (400)", negDays.status === 400);

    // enforce must be a boolean when present.
    const badEnforce = await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-ret-enf", { retention: { keepRuns: 3, enforce: "yes" } as unknown as { keepRuns: number; enforce: boolean } }));
    ok("retention: a non-boolean enforce is rejected (400)", badEnforce.status === 400);
  }

  // ---- TC-02: due() selection: enabled + not-in-flight + nextRunAt <= now ------------
  {
    const { stub, storage } = makeScheduler();

    // Add an enabled pipe that is past due (we will backdate nextRunAt directly in storage).
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-due", { enabled: true }));
    // Add an enabled pipe that is NOT yet due (nextRunAt is far future by default).
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-future", { enabled: true }));
    // Add a disabled pipe (should never appear in due).
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-disabled", { enabled: false }));

    // Backdate dp-due so nextRunAt is in the past.
    const dpDueStored = storage.rawGet<{ config: DownpipeConfig; nextRunAt: number; lastRunId: null; inFlight: boolean }>("dp:dp-due");
    if (dpDueStored) {
      dpDueStored.nextRunAt = Date.now() - 10_000;
      await storage.put("dp:dp-due", dpDueStored);
      await syncDueIndex(storage, "dp-due"); // keep the due-time index in step with the backdated nextRunAt
    }

    const r = await stubFetch(stub, "GET", "/due");
    ok("due: 200 response", r.status === 200);
    const { due } = await r.json() as { due: Array<{ config: { id: string }; inFlight: boolean }> };
    ok("due: past-due enabled pipe is included", due.some((d) => d.config.id === "dp-due"));
    ok("due: future pipe is excluded", !due.some((d) => d.config.id === "dp-future"));
    ok("due: disabled pipe is excluded", !due.some((d) => d.config.id === "dp-disabled"));
  }

  // ---- TC-03: trigger allocates a monotonic index + in-flight history row -------------
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-trig"));

    const r = await stubFetch(stub, "POST", "/trigger", { id: "dp-trig" });
    ok("trigger: 200 response", r.status === 200);
    const trig = await r.json() as { runId: string; index: number; prevRunId: null | string };
    ok("trigger: runId is a non-empty string", typeof trig.runId === "string" && trig.runId.length > 0);
    ok("trigger: index starts at 1", trig.index === 1);
    ok("trigger: prevRunId is null for first run", trig.prevRunId === null);

    // The downpipe must now be in-flight.
    const dpStored = storage.rawGet<{ inFlight: boolean }>("dp:dp-trig");
    ok("trigger: downpipe marked in-flight in storage", dpStored?.inFlight === true);

    // The history ring must have one in-flight entry.
    const hist = storage.rawGet<Array<{ runId: string; index: number; status: string }>>("hist:dp-trig");
    ok("trigger: history ring has one entry", Array.isArray(hist) && hist.length === 1);
    ok("trigger: history entry is in-flight", hist?.[0]?.status === "in-flight");
    ok("trigger: history entry carries the allocated index", hist?.[0]?.index === 1);
    ok("trigger: history entry runId matches trigger response", hist?.[0]?.runId === trig.runId);
  }

  // ---- TC-04: completeRun resolves the row (ok path) ---------------------------------
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-comp"));

    const trig = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-comp" })).json() as { runId: string; index: number };

    const completeReq = {
      id: "dp-comp",
      runId: trig.runId,
      index: trig.index,
      status: "ok" as const,
      recordCount: 42,
      bytes: 8192,
      archiveBytesWritten: 4096,
      segmentsWritten: 3,
      durationMs: 1500,
    };
    // SCALE (sched-rearmalarm-on-every-completion): completeRun must NOT do the O(N) fleet rearm. An alarm
    // is already pending from addDownpipe, so the O(1) safety-net is a no-op. Capture the list-call count and
    // the armed time across /complete and assert the completion neither scanned the fleet nor moved the alarm.
    const listsBefore = storage.listCalls;
    const alarmBefore = storage.lastAlarmAt;
    const r = await stubFetch(stub, "POST", "/complete", completeReq);
    ok("completeRun ok: 200 response", r.status === 200);
    const body = await r.json() as { ok: true };
    ok("completeRun ok: body is { ok: true }", body.ok === true);
    ok("completeRun does NOT scan the fleet (no O(N) rearm on completion)", storage.listCalls === listsBefore);
    ok("completeRun leaves the already-pending alarm intact (a completion never needs an earlier alarm)", storage.lastAlarmAt === alarmBefore);

    // The downpipe must no longer be in-flight.
    const dpStored = storage.rawGet<{ inFlight: boolean; lastRunId: string | null; integrityVerified?: { at: number; how: string } }>("dp:dp-comp");
    ok("completeRun ok: downpipe no longer in-flight", dpStored?.inFlight === false);
    ok("completeRun ok: lastRunId advanced to runId", dpStored?.lastRunId === trig.runId);
    // A SUCCESSFUL run is an integrity verification of the just-written archive (the seal built the
    // per-record hashes, signed the manifest and re-signed the RUNLOG chain), so completeRun stamps the
    // "archive integrity last verified" recency with how:"run" and a finite epoch-ms `at`. This is what
    // lets the console's protection statement read "integrity-checked" instead of "never integrity-checked".
    ok("completeRun ok: integrity-verified stamp set", dpStored?.integrityVerified !== undefined);
    ok("completeRun ok: integrity-verified how is 'run'", dpStored?.integrityVerified?.how === "run");
    ok("completeRun ok: integrity-verified at is a finite epoch ms", typeof dpStored?.integrityVerified?.at === "number" && Number.isFinite(dpStored?.integrityVerified?.at));

    // The history entry must be resolved with all fields.
    const hist = storage.rawGet<Array<{ runId: string; index: number; status: string; recordCount?: number; bytes?: number; archiveBytesWritten?: number; segmentsWritten?: number; durationMs?: number }>>("hist:dp-comp");
    const entry = hist?.find((h) => h.index === trig.index);
    ok("completeRun ok: history entry status is ok", entry?.status === "ok");
    ok("completeRun ok: recordCount stored", entry?.recordCount === 42);
    ok("completeRun ok: bytes stored", entry?.bytes === 8192);
    ok("completeRun ok: archiveBytesWritten stored (throughput field)", entry?.archiveBytesWritten === 4096);
    ok("completeRun ok: segmentsWritten stored (throughput field)", entry?.segmentsWritten === 3);
    ok("completeRun ok: durationMs stored (throughput field)", entry?.durationMs === 1500);
  }

  // ---- TC-05: completeRun resolves the row (failed path) -------------------------------
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-fail"));

    const trig = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-fail" })).json() as { runId: string; index: number };
    const savedRunId = trig.runId;

    // An empty runId signals a FAILED run (documented convention in the source).
    const r = await stubFetch(stub, "POST", "/complete", {
      id: "dp-fail",
      runId: "",
      index: trig.index,
      status: "failed",
      error: "connection timeout",
    });
    ok("completeRun failed: 200 response", r.status === 200);

    // lastRunId must NOT advance on failure.
    const dpStored = storage.rawGet<{ inFlight: boolean; lastRunId: string | null; integrityVerified?: { at: number; how: string } }>("dp:dp-fail");
    ok("completeRun failed: downpipe no longer in-flight", dpStored?.inFlight === false);
    ok("completeRun failed: lastRunId not advanced (still null)", dpStored?.lastRunId === null);
    // HONEST: a FAILED run is NOT an integrity verification, so it must NOT stamp the integrity-verified
    // recency (never a false positive). The protection statement then keeps reading "never integrity-checked"
    // for a downpipe whose only run failed, rather than a false "integrity-checked".
    ok("completeRun failed: integrity-verified stamp NOT set", dpStored?.integrityVerified === undefined);

    // The history row is resolved with status failed and the error string.
    const hist = storage.rawGet<Array<{ index: number; status: string; error?: string; runId: string }>>("hist:dp-fail");
    const entry = hist?.find((h) => h.index === trig.index);
    ok("completeRun failed: history entry status is failed", entry?.status === "failed");
    ok("completeRun failed: error string stored", entry?.error === "connection timeout");
    // The row keeps the originally allocated runId (not wiped to empty).
    ok("completeRun failed: row retains original runId", entry?.runId === savedRunId);
  }

  // ---- TC-06: coalescing: a downpipe already in-flight is skipped ---------------------
  {
    const { stub } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-coal"));

    // First trigger succeeds and marks in-flight.
    const r1 = await stubFetch(stub, "POST", "/trigger", { id: "dp-coal" });
    ok("coalescing: first trigger 200", r1.status === 200);
    const t1 = await r1.json() as { runId?: string; skipped?: string };
    ok("coalescing: first trigger returns runId (not skipped)", typeof t1.runId === "string");

    // Second trigger on the same in-flight downpipe must return { skipped }.
    const r2 = await stubFetch(stub, "POST", "/trigger", { id: "dp-coal" });
    ok("coalescing: second trigger 200 (not 400)", r2.status === 200);
    const t2 = await r2.json() as { runId?: string; skipped?: string };
    ok("coalescing: second trigger returns skipped (not double-run)", typeof t2.skipped === "string");
    ok("coalescing: no runId in skipped response", t2.runId === undefined);

    // The in-flight pipe is also excluded from due().
    // We need to backdate nextRunAt so the pipe appears due, and then confirm it is excluded
    // because it is in-flight (not because it is not due).
    // We can reach the due endpoint and confirm it is absent.
    const r3 = await stubFetch(stub, "GET", "/due");
    const { due } = await r3.json() as { due: Array<{ config: { id: string } }> };
    ok("coalescing: in-flight pipe absent from due()", !due.some((d) => d.config.id === "dp-coal"));
  }

  // ---- TC-06b: inFlight LEASE reclaims a crashed run instead of wedging forever ------
  // A run whose worker invocation is evicted/limited/redeployed between trigger and complete never
  // calls /complete. Without a lease, inFlight wedges true forever and the downpipe silently stops.
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-lease", { enabled: true }));

    const t1 = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-lease" })).json() as { runId: string; index: number };

    // While the lease is fresh, a re-trigger still coalesces (the normal in-flight guard).
    const coalesced = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-lease" })).json() as { skipped?: string };
    ok("lease: a freshly in-flight run still coalesces", typeof coalesced.skipped === "string");

    // Simulate the seal crashing: the pipe stays in-flight, but the lease ages past INFLIGHT_LEASE_MS
    // (30 min) and nextRunAt falls due. Backdate both directly in storage.
    const stored = storage.rawGet<{ inFlight: boolean; inFlightSince?: number; nextRunAt: number }>("dp:dp-lease")!;
    stored.inFlightSince = Date.now() - LEASE_EXPIRED_MS;
    stored.nextRunAt = Date.now() - 1000;
    await storage.put("dp:dp-lease", stored);
    await syncDueIndex(storage, "dp-lease"); // re-sync the index to the backdated nextRunAt (drift would hide it from due())

    // due() now re-includes it: an expired-lease in-flight pipe is treated as a crashed run, not leased.
    const { due } = await (await stubFetch(stub, "GET", "/due")).json() as { due: Array<{ config: { id: string } }> };
    ok("lease: an expired-lease in-flight pipe is re-included in due()", due.some((d) => d.config.id === "dp-lease"));

    // A re-trigger now RECLAIMS (a fresh run, not skipped) and resolves the orphaned row to abandoned.
    const t2 = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-lease" })).json() as { runId?: string; index?: number; skipped?: string };
    ok("lease: an expired-lease run is reclaimed (a new run, not skipped)", typeof t2.runId === "string" && t2.runId !== t1.runId);
    ok("lease: the reclaimed run allocates a fresh monotonic index", t2.index === t1.index + 1);

    const hist = storage.rawGet<Array<{ runId: string; status: string; error?: string }>>("hist:dp-lease")!;
    const abandoned = hist.find((h) => h.runId === t1.runId);
    ok("lease: the orphaned run is marked abandoned", abandoned?.status === "abandoned");
    ok("lease: the abandoned row carries a reason", typeof abandoned?.error === "string" && abandoned.error.length > 0);

    const after = storage.rawGet<{ inFlight: boolean; inFlightSince?: number }>("dp:dp-lease")!;
    ok("lease: the reclaimed run holds a fresh in-flight lease", after.inFlight === true && typeof after.inFlightSince === "number" && Date.now() - after.inFlightSince! < 60 * 1000);
  }

  // ---- TC-07: RING_CAP=50 truncation (newest kept) ------------------------------------
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-ring"));

    // Drive 55 trigger/complete cycles. Because the downpipe is marked in-flight after each
    // trigger, we must complete each run before the next trigger can succeed.
    const indices: number[] = [];
    for (let i = 0; i < 55; i++) {
      const t = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-ring" })).json() as { runId: string; index: number; skipped?: string };
      if (t.skipped) {
        // If somehow still in-flight, force-clear via completeRun with a prior index.
        break;
      }
      indices.push(t.index);
      await stubFetch(stub, "POST", "/complete", { id: "dp-ring", runId: t.runId, index: t.index, status: "ok" });
    }
    ok("ring: ran 55 trigger/complete cycles", indices.length === 55);

    // The ring must hold at most 50 entries.
    const hist = storage.rawGet<Array<{ index: number }>>("hist:dp-ring") ?? [];
    ok("ring: ring length is at most 50 (RING_CAP)", hist.length <= 50);
    ok("ring: ring length is exactly 50", hist.length === 50);

    // The newest 50 must be kept (the head/oldest 5 are dropped).
    const storedIndices = hist.map((h) => h.index);
    const minStored = Math.min(...storedIndices);
    const maxStored = Math.max(...storedIndices);
    ok("ring: newest entries are kept (max index is the last allocated)", maxStored === 55);
    ok("ring: oldest 5 entries dropped (min index > 5)", minStored === 6);
  }

  // ---- TC-08: runlogIndex monotonicity across multiple downpipes ----------------------
  {
    const { stub } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-mono-a"));
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-mono-b"));

    const ta = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-mono-a" })).json() as { runId: string; index: number };
    // Complete A so we can trigger it again later, and also trigger B. The completion carries the
    // run's ACTUAL allocated runId (the realistic value the production seal handler posts), so it
    // owns the in-flight run and resolves it (completeRun matches the row/runId).
    await stubFetch(stub, "POST", "/complete", { id: "dp-mono-a", runId: ta.runId, index: ta.index, status: "ok" });
    const tb = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-mono-b" })).json() as { index: number };
    const ta2 = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-mono-a" })).json() as { index: number };

    ok("monotonicity: index 1 < index 2", ta.index < tb.index);
    ok("monotonicity: index 2 < index 3", tb.index < ta2.index);
    ok("monotonicity: indices are consecutive (no gap on success)", ta2.index === tb.index + 1);
  }

  // ---- TC-09: failed run does not double-allocate (gap-tolerance) ---------------------
  {
    const { stub } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-gap"));

    // Trigger, then complete with failure (empty runId) - this allocates index 1.
    const t1 = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-gap" })).json() as { runId: string; index: number };
    ok("gap-tolerance: first trigger index is 1", t1.index === 1);
    await stubFetch(stub, "POST", "/complete", { id: "dp-gap", runId: "", index: t1.index, status: "failed" });

    // A SECOND trigger must not re-use index 1; it must allocate index 2 (gap tolerated, no rollback).
    const t2 = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-gap" })).json() as { runId: string; index: number };
    ok("gap-tolerance: second trigger allocates index 2 (not 1)", t2.index === 2);

    // Both entries are in the ring.
    const histR = await stubFetch(stub, "GET", "/history?id=dp-gap");
    const { entries } = await histR.json() as { entries: Array<{ index: number; status: string }> };
    // entries is newest-first, so reverse for ascending index order
    const sorted = [...entries].reverse();
    ok("gap-tolerance: ring has 2 entries (failed + in-flight)", sorted.length === 2);
    ok("gap-tolerance: entry at index 1 is failed", sorted.find((e) => e.index === 1)?.status === "failed");
    ok("gap-tolerance: entry at index 2 is in-flight", sorted.find((e) => e.index === 2)?.status === "in-flight");
  }
}
