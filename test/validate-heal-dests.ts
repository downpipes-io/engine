// Validates the heal-dests resilience + auto-heal work (the replica catch-up surfacing) end to end against
// the REAL scheduler DO and the REAL restore-destination fallback:
//
//   DESTINATION DOWN  A single/default-destination outage now lights the map's per-destination "down"
//           indicator, not merely a failed run. A FAILED completion carrying downDestinationIds records a
//           lastOk:false reachability heartbeat (forward-only on holdsIndex, so a down record never drops a
//           proven copy), and a later successful run refreshes the same destination to lastOk:true (self-heal).
//   REMOVED ORIGIN  Restoring a run whose recorded destination(s) were force-removed (the sole copy) no
//           longer returns a generic "object missing": withRunDestFallback re-labels it with the actionable
//           removed-origin cause when every recorded candidate resolves to null. A still-configured
//           destination, or a run with no recorded destinations, is unaffected.
//   AUTO-HEAL  reconcileReplicationAlerts surfaces whether the lagging copy is actively CATCHING UP
//           (the most-behind replica's last replication attempt succeeded => the keyless replicate pass is
//           advancing an already-signed backlog, a safe self-heal) vs stuck, and names how many runs the
//           replica is behind the ring head by. It never promotes an unverified copy (proven accounting is
//           unchanged).
//
// In-memory DO storage + an in-memory scheduler stub; no network, no deploy. Run: node test/validate-heal-dests.ts.

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { withRunDestFallback } from "../src/admin/router-sources.ts";
import { REASON_OBJECT_MISSING, REASON_ORIGIN_REMOVED, REASON_INTEGRITY } from "../src/restore-reasons.ts";
import { RING_CAP } from "../src/sched/scheduler-do-limits.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

function makeDO(seed: Record<string, unknown>): { dobj: SchedulerDO; storage: MockStorage } {
  const storage = new MockStorage();
  for (const [k, v] of Object.entries(seed)) storage.seed(k, v);
  return { dobj: new SchedulerDO({ storage } as unknown as DurableObjectState), storage };
}

interface ReplView {
  dests: Record<string, { lastOk: boolean; holdsIndex: number; reason?: string }>;
}

// ---- DEST-1: single/default-destination outage lights the per-destination down indicator -------------
async function testDest1SingleDestDown(): Promise<void> {
  console.log("-- a single-destination outage records a per-destination down heartbeat --");
  const { dobj, storage } = makeDO({
    "dp:single": { config: { id: "single", name: "Solo", destinationIds: ["default"] } },
    // An in-flight history row this FAILED completion (empty runId, matched by index) owns.
    "hist:single": [{ index: 7, runId: "r7", downpipeId: "single", startedAt: 1, status: "in-flight" }],
  });

  // The seal faulted on the sole destination (destination-access class): the driver names it down.
  await dobj.completeRun({ id: "single", runId: "", index: 7, status: "failed", error: "destination access error", downDestinationIds: ["default"] });
  const r1 = (await dobj.replication("single")) as ReplView;
  ok("the sole destination is recorded down (lastOk:false)", r1.dests.default?.lastOk === false);
  ok("the down record carries the coarse reason", r1.dests.default?.reason === "unreachable");
  ok("a down record proves nothing held (holdsIndex stays -1, no proven-copy drop)", r1.dests.default?.holdsIndex === -1);
  const row = (await (await dobj.fetch(new Request("https://scheduler.internal/history?id=single", { method: "GET" }))).json()) as { entries: Array<{ status: string }> };
  ok("the run itself is still recorded failed (honest outcome)", row.entries[0]?.status === "failed");

  // A later SUCCESSFUL run on the same destination refreshes it to lastOk:true (self-heal).
  storage.seed("hist:single", [{ index: 8, runId: "r8", downpipeId: "single", startedAt: 2, status: "in-flight" }]);
  await dobj.completeRun({ id: "single", runId: "r8", index: 8, status: "ok", destinationId: "default", recordCount: 1, bytes: 1 });
  const r2 = (await dobj.replication("single")) as ReplView;
  ok("a subsequent successful run heals the indicator (lastOk:true, holdsIndex advanced)", r2.dests.default?.lastOk === true && r2.dests.default?.holdsIndex === 8);
}

// A failure that was NOT a destination-access fault never carries a down set (the seal path only attaches
// it on the destination-access class), so the heartbeat is untouched: prove the DO ignores its absence.
async function testDest1NonDestFailureNoHeartbeat(): Promise<void> {
  console.log("-- a non-destination failure records no false down heartbeat --");
  const { dobj } = makeDO({
    "dp:single": { config: { id: "single", name: "Solo", destinationIds: ["default"] } },
    "hist:single": [{ index: 3, runId: "r3", downpipeId: "single", startedAt: 1, status: "in-flight" }],
  });
  // A source-class failure: no downDestinationIds on the completion (the seal path omits it).
  await dobj.completeRun({ id: "single", runId: "", index: 3, status: "failed", error: "source read error" });
  const r = (await dobj.replication("single")) as ReplView;
  ok("no down heartbeat is fabricated when the cause was not the destination", r.dests.default === undefined);
}

// ---- a removed-origin restore names the cause instead of a generic object-missing -------------
type Result = { ok: boolean; reason?: string };

function schedulerStub(handlers: { destsForRun: string[]; configForId: (id: string) => unknown }): DurableObjectStub {
  return {
    fetch: async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : (input as Request).url;
      if (url.includes("/downpipes/dests-for-run")) {
        return new Response(JSON.stringify({ destinationIds: handlers.destsForRun }), { status: 200 });
      }
      if (url.includes("/dest-config")) {
        const m = url.match(/[?&]id=([^&]+)/);
        const id = m ? decodeURIComponent(m[1]!) : "";
        return new Response(JSON.stringify({ config: handlers.configForId(id) }), { status: 200 });
      }
      return new Response("{}", { status: 200 });
    },
  } as unknown as DurableObjectStub;
}

const CONFIGURED_DEST = { endpoint: "https://acct.r2.cloudflarestorage.com", bucket: "b", region: "auto", accessKeyId: "AKID", secretAccessKey: "SECRET" };

async function testDest2RemovedOrigin(): Promise<void> {
  console.log("-- a run whose only recorded destination was force-removed names the cause --");

  // Recorded origin "gone" no longer resolves (force-removed) => every candidate is null => the op falls
  // through to the env default and returns object-missing. The fallback re-labels it removed-origin.
  {
    const scheduler = schedulerStub({ destsForRun: ["gone"], configForId: () => null });
    const res = await withRunDestFallback<Result>(scheduler, "r1", undefined, async () => ({ ok: false, reason: REASON_OBJECT_MISSING }));
    ok("removed sole destination => actionable removed-origin reason (not generic object missing)", res.reason === REASON_ORIGIN_REMOVED && res.ok === false);
  }

  // Negative 1: the recorded destination is STILL configured, so a genuine object-missing stays as-is (it
  // is a real availability fault on a live destination, not a removed-origin case).
  {
    const scheduler = schedulerStub({ destsForRun: ["live"], configForId: () => CONFIGURED_DEST });
    const res = await withRunDestFallback<Result>(scheduler, "r2", undefined, async () => ({ ok: false, reason: REASON_OBJECT_MISSING }));
    ok("a still-configured destination keeps the genuine object-missing reason", res.reason === REASON_OBJECT_MISSING);
  }

  // Negative 2: an INTEGRITY failure is never re-labelled (it returns immediately, is excluded from the
  // fallback set, and must surface loud — integrity != availability).
  {
    const scheduler = schedulerStub({ destsForRun: ["gone"], configForId: () => null });
    const res = await withRunDestFallback<Result>(scheduler, "r3", undefined, async () => ({ ok: false, reason: REASON_INTEGRITY }));
    ok("an integrity failure is NEVER masked as removed-origin", res.reason === REASON_INTEGRITY);
  }

  // Negative 3: a run with NO recorded destinations (the [undefined] default fallback) is not a removed
  // origin — keep the generic object-missing rather than over-claiming a removal.
  {
    const scheduler = schedulerStub({ destsForRun: [], configForId: () => null });
    const res = await withRunDestFallback<Result>(scheduler, "r4", undefined, async () => ({ ok: false, reason: REASON_OBJECT_MISSING }));
    ok("a run with no recorded destinations keeps the generic reason (no false removal)", res.reason === REASON_OBJECT_MISSING);
  }

  // A successful read short-circuits and never reaches the re-label (a live replica still serves the run).
  {
    const scheduler = schedulerStub({ destsForRun: ["gone"], configForId: () => null });
    const res = await withRunDestFallback<Result>(scheduler, "r5", undefined, async () => ({ ok: true }));
    ok("a successful restore is returned untouched", res.ok === true && res.reason === undefined);
  }
}

// ---- AUTO-HEAL: catching-up vs stuck surfacing on the replication alerts ------------------------------
interface Emission {
  event: string;
  severity: string;
  detail: string;
  catchingUp?: boolean;
}

function fanOutSeed(replLastOk: boolean): Record<string, unknown> {
  return {
    "notify-channel:ch-detect": { id: "ch-detect", kind: "webhook", name: "Sink", url: "https://hooks.example.com/x", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" }, // a notify channel exists, so detection runs
    "dp:fan": { config: { id: "fan", name: "Fan", destinationIds: ["origin", "replica"] } },
    // One ok run at index 5 from origin; the replica lags at holdsIndex 3.
    "hist:fan": [{ index: 5, runId: "r5", downpipeId: "fan", startedAt: 1, status: "ok", destinationId: "origin" }],
    "repl:fan": { replica: { holdsRunId: "r3", holdsIndex: 3, lastOk: replLastOk, lastAttemptAt: 1 } },
  };
}

async function testAutoHealCatchingUp(): Promise<void> {
  console.log("-- AUTO-HEAL: degraded alert distinguishes a catching-up replica from a stuck one --");

  {
    const { dobj } = makeDO(fanOutSeed(true));
    const { emissions } = await dobj.reconcileReplicationAlerts();
    const e = emissions.find((x) => x.downpipeId === "fan") as Emission | undefined;
    ok("a degraded fan-out fires", e?.event === "replication-degraded");
    ok("catchingUp:true when the lagging replica's last attempt succeeded (safe self-heal of signed runs)", e?.catchingUp === true);
    ok("the detail says replication is catching it up", e?.detail.includes("catching it up") === true);
  }
  {
    const { dobj } = makeDO(fanOutSeed(false));
    const { emissions } = await dobj.reconcileReplicationAlerts();
    const e = emissions.find((x) => x.downpipeId === "fan") as Emission | undefined;
    ok("catchingUp:false when the lagging replica is unreachable (a human must look)", e?.catchingUp === false);
    ok("the detail says the lagging copy is not reachable", e?.detail.includes("not reachable") === true);
  }
}

async function testAutoHealBehindRingHead(): Promise<void> {
  console.log("-- AUTO-HEAL: a run-at-risk alert names how far the replica is behind the ring head --");
  // A full ring (indices 1..RING_CAP) so it is at capacity; head = 1. The replica holds index 0 (below the
  // head about to roll off) => eviction risk, and proven copies = 1 (origin only) => critical escalation.
  const ring = Array.from({ length: RING_CAP }, (_, i) => ({ index: i + 1, runId: `r${i + 1}`, downpipeId: "fan", startedAt: i + 1, status: "ok", destinationId: "origin" }));
  const { dobj } = makeDO({
    "notify-channel:ch-detect": { id: "ch-detect", kind: "webhook", name: "Sink", url: "https://hooks.example.com/x", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" },
    "dp:fan": { config: { id: "fan", name: "Fan", destinationIds: ["origin", "replica"] } },
    "hist:fan": ring,
    "repl:fan": { replica: { holdsRunId: null, holdsIndex: 0, lastOk: true, lastAttemptAt: 1 } },
  });
  const { emissions } = await dobj.reconcileReplicationAlerts();
  const e = emissions.find((x) => x.downpipeId === "fan") as Emission | undefined;
  ok("a run-at-risk-eviction fires when the ring is full and a copy lags below the head", e?.event === "run-at-risk-eviction");
  ok("it escalates to critical when eviction would leave a single proven copy", e?.severity === "critical");
  ok("the detail names the runs-behind-the-ring-head gap", e?.detail.includes("behind the ring head by 1 run(s)") === true);
  ok("catchingUp still reflects the reachable, advancing replica", e?.catchingUp === true);
}

async function main(): Promise<void> {
  console.log("HEAL-DESTS RESILIENCE + AUTO-HEAL VECTORS");
  await testDest1SingleDestDown();
  await testDest1NonDestFailureNoHeartbeat();
  await testDest2RemovedOrigin();
  await testAutoHealCatchingUp();
  await testAutoHealBehindRingHead();
  console.log("");
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.log(`HEAL-DESTS VECTORS FAILED (${failures})`);
    process.exit(1);
  }
  console.log("HEAL-DESTS VECTORS PASS");
}

void main();
