// prevRunId is on no admin-observable surface, so an auditor cannot
// reconstruct the per-run predecessor chain from any admin read." prevRunId was computed correctly at
// trigger() and threaded through the seal path (mirrored in the destination-local RUNLOG's
// freshness.prevRunId), but the scheduler DO's own RunHistoryEntry ring -- the thing GET /history serves,
// which is the ONLY admin/console-observable run-activity surface -- never carried it. Run:
//   node test/validate-run-history-prevrunid.ts
//
// Coverage:
//  annotatePredecessorChain (pure, run-chain.ts): classifies each row's prevRunId against ITS OWN ring's
//    runId membership into an honest verdict -- "none" (this IS the downpipe's first run), "retained" (the
//    predecessor's own row is in this same ring), "pruned" (a real predecessor exists but aged out of the
//    RING_CAP-bounded window -- NOT a broken chain, an honest truncation), "unknown" (a row sealed before
//    this field existed, carries no prevRunId key at all). Never coerces a real-but-absent id to null or
//    empty string (which would read as "no predecessor" / a rewritten chain).
//  the DO route (GET /history): trigger() now stamps prevRunId onto the in-flight row it appends, so a
//    live multi-run downpipe's GET /history response lets an admin/auditor walk runId -> prevRunId ->
//    runId back through the WHOLE retained chain without a second read or any private-key material.

import type { DurableObjectState } from "@cloudflare/workers-types";
import { annotatePredecessorChain, type RunHistoryEntryWithChain } from "../src/admin/run-chain.ts";
import { SchedulerDO, type DownpipeState, type RunHistoryEntry } from "../src/sched/scheduler-do.ts";

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

function run(runId: string, index: number, startMs: number, status: RunHistoryEntry["status"] = "ok", prevRunId?: string | null): RunHistoryEntry {
  return {
    runId,
    index,
    startedAt: ISO(startMs),
    status,
    ...(prevRunId !== undefined ? { prevRunId } : {}),
  };
}

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
  // PART 1: annotatePredecessorChain, the pure per-row classifier
  // =========================================================================================
  {
    const ring: RunHistoryEntry[] = [
      run("r1", 1, T0 + 0 * HOUR, "ok", null), // the downpipe's first run ever
      run("r2", 2, T0 + 1 * HOUR, "ok", "r1"), // predecessor r1 IS in this ring
      run("r3", 3, T0 + 2 * HOUR, "ok", "r0-aged-off"), // predecessor real but pruned from the ring
      run("r4", 4, T0 + 3 * HOUR, "ok"), // legacy row: no prevRunId key at all
    ];
    const annotated = annotatePredecessorChain(ring);
    const byId = new Map(annotated.map((e) => [e.runId, e]));

    ok("chain: a genuine first run (prevRunId=null) classifies 'none'", byId.get("r1")?.prevRunIdStatus === "none" && byId.get("r1")?.prevRunId === null);
    ok("chain: a predecessor present in the SAME ring classifies 'retained'", byId.get("r2")?.prevRunIdStatus === "retained" && byId.get("r2")?.prevRunId === "r1");
    ok("chain: a real predecessor absent from the ring classifies 'pruned', not empty/null", byId.get("r3")?.prevRunIdStatus === "pruned" && byId.get("r3")?.prevRunId === "r0-aged-off");
    ok("chain: pruned NEVER reads as an empty string (that would look like a broken chain)", byId.get("r3")?.prevRunId !== "" && byId.get("r3")?.prevRunId !== undefined);
    ok("chain: a legacy row with no prevRunId key classifies 'unknown', not 'none'", byId.get("r4")?.prevRunIdStatus === "unknown");
    ok("chain: 'unknown' is DISTINCT from 'none' (predates-field vs genuinely-first)", byId.get("r4")?.prevRunIdStatus !== byId.get("r1")?.prevRunIdStatus);

    // Order-independence: classifying the same ring reversed gives identical verdicts (membership is a set).
    const reversedAnnotated = annotatePredecessorChain([...ring].reverse());
    const reversedById = new Map(reversedAnnotated.map((e) => [e.runId, e.prevRunIdStatus]));
    ok("chain: classification is order-independent (newest-first vs newest-last agree)", reversedById.get("r2") === "retained" && reversedById.get("r3") === "pruned");
  }

  // =========================================================================================
  // PART 2: THE DEFECT -- GET /history is the only admin-observable run-activity surface, and an
  // auditor must be able to reconstruct the WHOLE predecessor chain from it alone.
  // =========================================================================================
  {
    const { storage, stub } = makeScheduler();
    await storage.put("dp:dp1", makeDownpipe("dp1", "Primary"));

    // Run 1: trigger + complete (genuinely the first run -- no prior lastRunId).
    const t1 = (await (await fetchDO(stub, "POST", "/trigger", { id: "dp1" })).json()) as { runId: string; index: number; prevRunId: string | null };
    ok("DO /trigger: the first-ever run's prevRunId is null (this is trigger's own honest signal)", t1.prevRunId === null);
    await fetchDO(stub, "POST", "/complete", { id: "dp1", runId: t1.runId, index: t1.index, status: "ok" });

    // Run 2: trigger + complete. Its prevRunId should be run 1's id (the successful-run chain).
    const t2 = (await (await fetchDO(stub, "POST", "/trigger", { id: "dp1" })).json()) as { runId: string; index: number; prevRunId: string | null };
    ok("DO /trigger: the second run's prevRunId is the first run's id", t2.prevRunId === t1.runId);
    await fetchDO(stub, "POST", "/complete", { id: "dp1", runId: t2.runId, index: t2.index, status: "ok" });

    // THE ADMIN READ: GET /history is what the console/API/an auditor actually reads. Before the fix,
    // its RunHistoryEntry rows carried runId/index/startedAt/status and coarse counts -- NO prevRunId
    // anywhere, so nothing here let a reader walk the chain; only the raw DO storage (`hist:dp1`, not an
    // admin surface at all) or the sealed destination-local RUNLOG (a different subsystem entirely) had it.
    const histResp = await fetchDO(stub, "GET", "/history?id=dp1");
    const histBody = (await histResp.json()) as { entries: RunHistoryEntryWithChain[] };
    ok("GET /history: 200 with the downpipe's ring", histResp.status === 200 && histBody.entries.length === 2);

    const byRunId = new Map(histBody.entries.map((e) => [e.runId, e]));
    const row1 = byRunId.get(t1.runId);
    const row2 = byRunId.get(t2.runId);

    // THE ASSERTION THAT FAILS ON UNFIXED MAIN: an admin read of run history exposes the predecessor
    // chain -- row2 names row1 as its predecessor, and row1 honestly has none.
    ok("GET /history: row1 (the first run) carries prevRunId=null (no predecessor)", row1 !== undefined && "prevRunId" in row1 && row1.prevRunId === null);
    ok("GET /history: row2 carries prevRunId = row1's runId (the reconstructable chain)", row2 !== undefined && row2.prevRunId === t1.runId);
    ok("GET /history: row2's predecessor is RETAINED in this same response", row2?.prevRunIdStatus === "retained");
    ok("GET /history: row1's predecessor status is honestly 'none' (first run), not 'pruned'", row1?.prevRunIdStatus === "none");

    // An auditor can now walk the chain end-to-end purely from this ONE admin read: newest -> oldest.
    let cursor: RunHistoryEntryWithChain | undefined = row2;
    const walked: string[] = [];
    while (cursor) {
      walked.push(cursor.runId);
      const prev: string | null | undefined = cursor.prevRunId;
      cursor = prev ? byRunId.get(prev) : undefined;
    }
    ok("GET /history: the FULL predecessor chain is walkable from one admin read (newest to first)", walked.length === 2 && walked[0] === t2.runId && walked[1] === t1.runId);
  }

  // =========================================================================================
  // PART 3: byDownpipe fleet shape (GET /history with no id) carries the same chain, scoped correctly
  // per downpipe (a predecessor is never resolved against a DIFFERENT downpipe's ring).
  // =========================================================================================
  {
    const { storage, stub } = makeScheduler();
    await storage.put("dp:dpA", makeDownpipe("dpA", "A"));
    await storage.put("dp:dpB", makeDownpipe("dpB", "B"));
    // dpB's ring happens to reuse the SAME runId string as one of dpA's rows would need to avoid
    // cross-contamination; use distinct ids to keep the fixture unambiguous either way.
    await storage.put("hist:dpA", [run("a1", 1, T0, "ok", null), run("a2", 2, T0 + HOUR, "ok", "a1")]);
    await storage.put("hist:dpB", [run("b1", 1, T0, "ok", "ghost-not-in-b")]);

    const fleetResp = await fetchDO(stub, "GET", "/history");
    const fleetBody = (await fleetResp.json()) as { byDownpipe: Record<string, RunHistoryEntryWithChain[]> };
    const aRows = new Map(fleetBody.byDownpipe.dpA?.map((e) => [e.runId, e]));
    const bRows = new Map(fleetBody.byDownpipe.dpB?.map((e) => [e.runId, e]));
    ok("GET /history (fleet): dpA's a2 resolves its predecessor within its OWN ring", aRows.get("a2")?.prevRunIdStatus === "retained");
    ok("GET /history (fleet): dpB's b1 predecessor is honestly 'pruned' (a real id, not in dpB's ring)", bRows.get("b1")?.prevRunIdStatus === "pruned" && bRows.get("b1")?.prevRunId === "ghost-not-in-b");
  }

  console.log(failures === 0 ? "\nALL RUN-HISTORY PREDECESSOR-CHAIN VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
