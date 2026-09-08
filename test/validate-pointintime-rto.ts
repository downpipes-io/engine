// Prove POINT-IN-TIME run resolution + the RTO ESTIMATE: restore can select by timestamp, and both RPO
// and RTO are surfaced. In-memory doubles only; no network, no deploy. Run:
//   node test/validate-pointintime-rto.ts
//
// Coverage:
//  resolveRunAt (pure point-in-time, at-or-before): resolves the LATEST SUCCESSFUL run completed at-or-
//    before T; ignores failed/abandoned/in-flight rows; an exact-boundary T resolves the run that
//    completed AT T; a T after the newest run resolves the newest; a T BEFORE every retained run is an
//    HONEST miss (found:false) carrying the retained-window bounds; an empty ring is the no-successful-run
//    miss. The completion instant is startedAt + durationMs (the recovery point), legacy rows fall back to
//    startedAt. Bounded to what the ring retains (retained-window honesty).
//  estimateRto (pure RTO): DERIVED from observed drill throughput scaled to the archive size; carries the
//    "based on N drills" sample count + a confidence + the fixed caveat; reports "unknown" (known:false,
//    NO number) with no drill history (NEVER a fabricated value); a zero-byte/zero-duration sample is not
//    usable; the fleet roll-up pools samples; appendRtoSample bounds the ring + drops a malformed sample.
//  DO routes: GET /runs/at resolves via the stored ring (and 400s a missing downpipe / unparseable at);
//    GET /rto derives per-downpipe + fleet; POST /restore-test-complete records an RTO sample only for a
//    successful positive-byte measurement (a failed/zero test records none, so RTO stays honestly unknown).

import { resolveRunAt, completionMs } from "../src/admin/point-in-time.ts";
import { estimateRto, estimateFleetRto, appendRtoSample, RTO_CAVEAT, RTO_SAMPLE_CAP, type RtoSample } from "../src/admin/rto.ts";
import { SchedulerDO, type DownpipeState, type RunHistoryEntry } from "../src/sched/scheduler-do.ts";
import type { PointInTimeRun } from "../src/admin/restore-types.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

function makeScheduler(): { storage: MockStorage; stub: SchedulerDO } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  return { storage, stub: new SchedulerDO(state) };
}

function fetchDO(dobj: SchedulerDO, method: string, path: string, body?: unknown): Promise<Response> {
  const url = `https://scheduler.internal${path}`;
  const headers: Record<string, string> = body !== undefined ? { "content-type": "application/json" } : {};
  const init: RequestInit = { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) };
  return dobj.fetch(new Request(url, init));
}

const ISO = (ms: number): string => new Date(ms).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
const T0 = Date.parse("2026-06-01T00:00:00.000Z");
const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

// run builds a RunHistoryEntry. status defaults to "ok"; durationMs sets the completion offset from start.
function run(runId: string, index: number, startMs: number, status: RunHistoryEntry["status"] = "ok", durationMs = 0, bytes?: number, recordCount?: number): RunHistoryEntry {
  return {
    runId,
    index,
    startedAt: ISO(startMs),
    status,
    ...(durationMs ? { durationMs } : {}),
    ...(bytes !== undefined ? { bytes } : {}),
    ...(recordCount !== undefined ? { recordCount } : {}),
  };
}

// makeDownpipe builds a minimal DownpipeState the DO reads (config + the recovery samples for the RTO path).
function makeDownpipe(id: string, name: string, extra: Partial<DownpipeState> = {}): DownpipeState {
  return {
    config: { id, name, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: `KV_${id}`, include: [], exclude: [] } } as DownpipeState["config"],
    nextRunAt: T0,
    lastRunId: null,
    inFlight: false,
    ...extra,
  };
}

async function main(): Promise<void> {
  // =========================================================================================
  // PART 1: resolveRunAt, the pure point-in-time (at-or-before) rule + retained-window honesty
  // =========================================================================================
  {
    // A ring (newest-LAST, as the DO stores it) of three successful runs a day apart, each taking 1 hour,
    // plus a FAILED run and an IN-FLIGHT run that must never be recovery points.
    const ring: RunHistoryEntry[] = [
      run("r1", 1, T0 + 0 * DAY, "ok", HOUR), // completes T0 + 1h
      run("r2", 2, T0 + 1 * DAY, "ok", HOUR), // completes T0 + 1d + 1h
      run("rFail", 3, T0 + 2 * DAY, "failed", HOUR),
      run("r3", 4, T0 + 3 * DAY, "ok", HOUR), // completes T0 + 3d + 1h
      run("rInflight", 5, T0 + 4 * DAY, "in-flight"),
    ];

    // T squarely after r2's completion but before r3: resolves r2 (the latest successful at-or-before T).
    const atBetween = resolveRunAt("dp1", ring, T0 + 2 * DAY);
    ok("PIT: resolves the latest successful run at-or-before T", atBetween.found === true && atBetween.runId === "r2");
    ok("PIT: resolved completedAt is startedAt + durationMs (the recovery point)", atBetween.completedAt === ISO(T0 + 1 * DAY + HOUR));
    ok("PIT: a FAILED run between r2 and T is never chosen", atBetween.runId !== "rFail");

    // T after the newest successful run resolves that newest run (r3), not the in-flight one.
    const atLatest = resolveRunAt("dp1", ring, T0 + 10 * DAY);
    ok("PIT: T after all runs resolves the NEWEST successful run", atLatest.found === true && atLatest.runId === "r3");
    ok("PIT: an IN-FLIGHT run is never a recovery point", atLatest.runId !== "rInflight");

    // EXACT boundary: T exactly at r2's completion instant resolves r2 (at-OR-before, inclusive).
    const atExact = resolveRunAt("dp1", ring, T0 + 1 * DAY + HOUR);
    ok("PIT: T exactly at a run's completion resolves THAT run (inclusive at-or-before)", atExact.found === true && atExact.runId === "r2");
    // One ms BEFORE r2 completes resolves r1 (r2 has not completed yet at that instant).
    const atJustBefore = resolveRunAt("dp1", ring, T0 + 1 * DAY + HOUR - 1);
    ok("PIT: one ms before r2 completes resolves the prior run r1", atJustBefore.found === true && atJustBefore.runId === "r1");

    // HONEST MISS: T before EVERY retained successful run -> found:false with the retained-window bounds.
    const atBeforeAll = resolveRunAt("dp1", ring, T0 - 1 * DAY);
    ok("PIT: T before every retained run is an HONEST miss (found:false)", atBeforeAll.found === false && atBeforeAll.runId === undefined);
    ok("PIT: the miss reason names the retained window honestly", /at or before/.test(atBeforeAll.reason ?? ""));
    ok("PIT: the miss carries retainedFrom = the OLDEST retained run completion", atBeforeAll.retainedFrom === ISO(T0 + 1 * HOUR));
    ok("PIT: the miss carries retainedTo = the NEWEST retained run completion", atBeforeAll.retainedTo === ISO(T0 + 3 * DAY + HOUR));

    // An EMPTY ring (or one with no successful run) is the distinct no-successful-run miss.
    const emptyMiss = resolveRunAt("dp1", [], T0);
    ok("PIT: an empty ring is a found:false with the no-successful-run reason", emptyMiss.found === false && /no successful run retained/.test(emptyMiss.reason ?? ""));
    const onlyFailed = resolveRunAt("dp1", [run("rF", 1, T0, "failed", HOUR)], T0 + DAY);
    ok("PIT: a ring with only failed runs is the no-successful-run miss (no retained window)", onlyFailed.found === false && onlyFailed.retainedFrom === undefined);

    // completionMs: a legacy row without durationMs falls back to startedAt (the conservative under-estimate).
    ok("PIT: completionMs falls back to startedAt when durationMs is absent", completionMs(run("rL", 1, T0, "ok")) === T0);
    ok("PIT: completionMs adds durationMs when present", completionMs(run("rD", 1, T0, "ok", HOUR)) === T0 + HOUR);
  }

  // =========================================================================================
  // PART 2: estimateRto, DERIVED from drill durations, honest-unknown, never fabricated
  // =========================================================================================
  {
    // UNKNOWN with no samples: known:false, confidence "none", NO number, an honest reason.
    const none = estimateRto({ id: "dp1", name: "Primary", samples: [] });
    ok("RTO: no drill history -> known:false (UNKNOWN, not a guess)", none.known === false && none.confidence === "none");
    ok("RTO: unknown carries NO fabricated estimate number", none.estimateSeconds === undefined && none.basedOnDrills === undefined);
    ok("RTO: unknown states an honest reason", /no restore-test history/.test(none.reason ?? ""));

    // A zero-byte or zero-duration sample carries no throughput signal -> still UNKNOWN.
    const unusable = estimateRto({ id: "dp1", name: "Primary", samples: [{ at: T0, durationMs: 0, bytesVerified: 0, recordsVerified: 0 }], archiveBytes: 1000 });
    ok("RTO: a zero-duration/zero-byte sample is not usable -> still unknown", unusable.known === false);

    // DERIVED from one sample: a drill verified 1 MiB in 1000 ms = 1 MiB/s; archive is 10 MiB -> ~10 s.
    const MiB = 1024 * 1024;
    const oneDrill = estimateRto({ id: "dp1", name: "Primary", samples: [{ at: T0, durationMs: 1000, bytesVerified: 1 * MiB, recordsVerified: 1 }], archiveBytes: 10 * MiB });
    ok("RTO: derived from observed throughput, scaled to the archive (~10s for 10MiB at 1MiB/s)", oneDrill.known === true && oneDrill.estimateSeconds === 10);
    ok("RTO: carries the 'based on N drills' sample count", oneDrill.basedOnDrills === 1);
    ok("RTO: reports the measured throughput it derived from (~1MiB/s)", Math.abs((oneDrill.observedThroughputBytesPerSec ?? 0) - MiB) < 2);
    ok("RTO: a single sample is LOW confidence (thin signal)", oneDrill.confidence === "low");
    ok("RTO: a known estimate carries the fixed honest caveat", oneDrill.caveat === RTO_CAVEAT && /approximate/.test(oneDrill.caveat ?? ""));

    // More samples covering a representative fraction raise confidence; the estimate is the AGGREGATE
    // throughput (so one anomalous drill is damped). 6 drills each 1 MiB / 500 ms = 2 MiB/s aggregate;
    // archive 6 MiB (the drills covered the whole archive) -> 3 s, HIGH confidence (>=5 samples, full cover).
    const many: RtoSample[] = Array.from({ length: 6 }, (_x, i) => ({ at: T0 + i * 1000, durationMs: 500, bytesVerified: 1 * MiB, recordsVerified: 1 }));
    const manyDrill = estimateRto({ id: "dp1", name: "Primary", samples: many, archiveBytes: 6 * MiB });
    ok("RTO: aggregates throughput across samples (6MiB at 2MiB/s -> 3s)", manyDrill.known === true && manyDrill.estimateSeconds === 3);
    ok("RTO: several representative samples earn HIGH confidence", manyDrill.confidence === "high" && manyDrill.basedOnDrills === 6);

    // No archive size known: the estimate falls back to the largest observed per-drill duration, LOW conf.
    const noArchive = estimateRto({ id: "dp1", name: "Primary", samples: [{ at: T0, durationMs: 4000, bytesVerified: 1 * MiB, recordsVerified: 1 }] });
    ok("RTO: with no archive size, falls back to the observed drill time (4s), low confidence", noArchive.known === true && noArchive.estimateSeconds === 4 && noArchive.confidence === "low");

    // Fleet roll-up pools every sample and sums the archive sizes.
    const fleet = estimateFleetRto([
      { id: "dp1", name: "A", samples: [{ at: T0, durationMs: 1000, bytesVerified: 1 * MiB, recordsVerified: 1 }], archiveBytes: 5 * MiB },
      { id: "dp2", name: "B", samples: [{ at: T0, durationMs: 1000, bytesVerified: 1 * MiB, recordsVerified: 1 }], archiveBytes: 5 * MiB },
    ]);
    ok("RTO: fleet roll-up pools samples + sums archive (10MiB at 1MiB/s -> 10s)", fleet.known === true && fleet.estimateSeconds === 10 && fleet.basedOnDrills === 2);
    ok("RTO: fleet roll-up carries no per-downpipe id", fleet.id === undefined);
    const fleetEmpty = estimateFleetRto([{ id: "dp1", name: "A", samples: [] }]);
    ok("RTO: fleet with no samples anywhere is honestly unknown", fleetEmpty.known === false);

    // appendRtoSample bounds the ring and drops a malformed sample.
    let ring2: RtoSample[] | undefined;
    for (let i = 0; i < RTO_SAMPLE_CAP + 5; i++) ring2 = appendRtoSample(ring2, { at: T0 + i, durationMs: 100, bytesVerified: 1000, recordsVerified: 1 });
    ok("RTO: the sample ring is bounded at RTO_SAMPLE_CAP", (ring2 ?? []).length === RTO_SAMPLE_CAP);
    ok("RTO: the ring keeps the NEWEST samples (oldest rolled off)", (ring2 ?? [])[RTO_SAMPLE_CAP - 1]?.at === T0 + RTO_SAMPLE_CAP + 4);
    const dropped = appendRtoSample([], { at: T0, durationMs: NaN, bytesVerified: 1000, recordsVerified: 1 });
    ok("RTO: a malformed sample (NaN duration) is dropped, never poisons the ring", dropped.length === 0);
  }

  // =========================================================================================
  // PART 3: the DO routes (GET /runs/at, GET /rto, POST /restore-test-complete sample recording)
  // =========================================================================================
  {
    const { storage, stub } = makeScheduler();
    // Seed one downpipe + its run-history ring (newest-last) directly into storage.
    await storage.put("dp:dp1", makeDownpipe("dp1", "Primary"));
    const ring: RunHistoryEntry[] = [
      run("r1", 1, T0 + 0 * DAY, "ok", HOUR, 5_000_000, 3),
      run("r2", 2, T0 + 1 * DAY, "ok", HOUR, 10_000_000, 5),
    ];
    await storage.put("hist:dp1", ring);

    // GET /runs/at resolves via the stored ring.
    const rAt = await fetchDO(stub, "GET", `/runs/at?downpipe=dp1&at=${encodeURIComponent(ISO(T0 + 2 * DAY))}`);
    const atBody = (await rAt.json()) as PointInTimeRun;
    ok("DO /runs/at: 200 and resolves the latest run at-or-before T", rAt.status === 200 && atBody.found === true && atBody.runId === "r2");
    // A T before all retained runs is found:false (still a 200, a valid answer, not an error).
    const rMiss = await fetchDO(stub, "GET", `/runs/at?downpipe=dp1&at=${encodeURIComponent(ISO(T0 - DAY))}`);
    const missBody = (await rMiss.json()) as PointInTimeRun;
    ok("DO /runs/at: an honest miss is a 200 with found:false", rMiss.status === 200 && missBody.found === false && typeof missBody.retainedFrom === "string");
    // A missing downpipe / unparseable at carries an `error` hint in the body (the DO returns it; the
    // ROUTER maps that hint to a 400, proven in validate-admin-router). Calling the DO directly, the
    // contract is the error-carrying body that distinguishes "you asked wrong" from a found:false answer.
    const rNoDp = await fetchDO(stub, "GET", `/runs/at?at=${encodeURIComponent(ISO(T0))}`);
    const noDpBody = (await rNoDp.json()) as { found: boolean; error?: string };
    ok("DO /runs/at: a missing downpipe carries an error hint (router maps to 400)", noDpBody.found === false && typeof noDpBody.error === "string");
    const rBadAt = await fetchDO(stub, "GET", `/runs/at?downpipe=dp1&at=not-a-date`);
    const badAtBody = (await rBadAt.json()) as { found: boolean; error?: string };
    ok("DO /runs/at: an unparseable at carries an error hint (router maps to 400)", badAtBody.found === false && typeof badAtBody.error === "string");
    // An unknown downpipe (no ring) resolves to the no-successful-run miss, still 200.
    const rUnknown = await fetchDO(stub, "GET", `/runs/at?downpipe=ghost&at=${encodeURIComponent(ISO(T0))}`);
    const ghostBody = (await rUnknown.json()) as PointInTimeRun;
    ok("DO /runs/at: an unknown downpipe is found:false (no ring), not an error", rUnknown.status === 200 && ghostBody.found === false);

    // GET /rto with NO samples yet -> the downpipe is honestly unknown (the ring exists but no drill ran).
    const rRto0 = await fetchDO(stub, "GET", "/rto");
    const rto0 = (await rRto0.json()) as { fleet: { known: boolean }; downpipes: Array<{ id?: string; known: boolean }> };
    ok("DO /rto: with no drill samples, the downpipe RTO is honestly unknown", rRto0.status === 200 && rto0.downpipes[0]?.known === false && rto0.fleet.known === false);

    // POST /restore-test-complete WITHOUT a measurement records NO sample (still unknown).
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp1", ok: true, at: T0 + 2 * DAY });
    const afterNoMeasure = (await storage.get<DownpipeState>("dp:dp1"))!;
    ok("DO restore-test-complete: a result with NO measurement records no RTO sample", (afterNoMeasure.recoverySamples ?? []).length === 0);

    // POST /restore-test-complete WITH a successful measurement records ONE sample.
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp1", ok: true, at: T0 + 3 * DAY, durationMs: 2000, bytesVerified: 1_000_000, recordsVerified: 1 });
    const afterMeasure = (await storage.get<DownpipeState>("dp:dp1"))!;
    ok("DO restore-test-complete: a successful measurement records ONE RTO sample", (afterMeasure.recoverySamples ?? []).length === 1 && afterMeasure.recoverySamples?.[0]?.durationMs === 2000);
    // A FAILED test (ok:false) with a measurement records NO sample (a failed recovery is no throughput signal).
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp1", ok: false, at: T0 + 4 * DAY, durationMs: 9999, bytesVerified: 1_000_000 });
    const afterFail = (await storage.get<DownpipeState>("dp:dp1"))!;
    ok("DO restore-test-complete: a FAILED test records no RTO sample", (afterFail.recoverySamples ?? []).length === 1);

    // GET /rto NOW derives a real estimate (1 sample, archive = latest run's 10MB) at low confidence, with
    // the caveat, and the fleet roll-up is known too.
    const rRto1 = await fetchDO(stub, "GET", "/rto");
    const rto1 = (await rRto1.json()) as { fleet: { known: boolean; estimateSeconds?: number }; downpipes: Array<{ id?: string; known: boolean; estimateSeconds?: number; basedOnDrills?: number; confidence: string; caveat?: string }> };
    const dpRto = rto1.downpipes[0];
    ok("DO /rto: derives a known estimate once a drill sample exists", rRto1.status === 200 && dpRto?.known === true && typeof dpRto?.estimateSeconds === "number");
    ok("DO /rto: the estimate carries based-on-N-drills + a caveat", dpRto?.basedOnDrills === 1 && /approximate/.test(dpRto?.caveat ?? ""));
    ok("DO /rto: the fleet roll-up is known with an estimate", rto1.fleet.known === true && typeof rto1.fleet.estimateSeconds === "number");
    // The estimate scaled the 1MB-in-2000ms throughput (~0.5MB/s) to the 10MB archive -> ~20s.
    ok("DO /rto: the estimate is the derived archive-scaled recovery time (~20s)", (dpRto?.estimateSeconds ?? 0) >= 18 && (dpRto?.estimateSeconds ?? 0) <= 22);

    // GET /rto?id= scopes to one downpipe but keeps the fleet roll-up.
    const rScoped = await fetchDO(stub, "GET", "/rto?id=dp1");
    const scoped = (await rScoped.json()) as { fleet: { known: boolean }; downpipes: Array<{ id?: string }> };
    ok("DO /rto?id=: scopes the downpipes list to the one id", scoped.downpipes.length === 1 && scoped.downpipes[0]?.id === "dp1");
    const rScopedGhost = await fetchDO(stub, "GET", "/rto?id=ghost");
    const scopedGhost = (await rScopedGhost.json()) as { downpipes: unknown[] };
    ok("DO /rto?id=ghost: an unknown id yields an empty downpipes list (no fabricated row)", scopedGhost.downpipes.length === 0);
  }

  console.log(failures === 0 ? "\nALL POINT-IN-TIME + RTO VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
