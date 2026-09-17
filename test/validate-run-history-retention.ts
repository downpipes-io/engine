// validate-run-history-retention: ASVS V14.1.2 first increment. The per-downpipe run-history ring
// (`hist:<id>`, scheduler-do-scheduling.ts) is bounded by COUNT (RING_CAP, scheduler-do-limits.ts) but,
// before this, by nothing else -- a low-traffic downpipe kept its first run's metadata for as long as
// the account existed. purgeRunHistoryEntries (sched/history-retention.ts) is the pure retention policy;
// this validator drives it directly AND through the real DO route
// (POST /history-retention-pass, scheduler-do-routing.ts) so both the policy and its wiring are proven,
// not merely re-implemented as a second copy.
//
// Run: node test/validate-run-history-retention.ts

import type { DurableObjectState } from "@cloudflare/workers-types";
import { purgeRunHistoryEntries, RUN_HISTORY_MAX_AGE_DAYS, RUN_HISTORY_MAX_AGE_MS } from "../src/sched/history-retention.ts";
import { SchedulerDO, type DownpipeState, type RunHistoryEntry } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ISO = (ms: number): string => new Date(ms).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
const T0 = Date.parse("2026-01-01T00:00:00.000Z");
const DAY = 24 * 60 * 60 * 1000;

function row(runId: string, startMs: number, status: RunHistoryEntry["status"] = "ok"): RunHistoryEntry {
  return { runId, index: 1, startedAt: ISO(startMs), status };
}

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

function makeDownpipe(id: string): DownpipeState {
  return {
    config: { id, name: id, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: `KV_${id}`, include: [], exclude: [] } } as DownpipeState["config"],
    nextRunAt: T0,
    lastRunId: null,
    inFlight: false,
  };
}

async function main(): Promise<void> {
  // =========================================================================================
  // PART 1: purgeRunHistoryEntries, the pure policy (no storage, no DO).
  // =========================================================================================
  {
    const now = T0 + 500 * DAY;
    const ring: RunHistoryEntry[] = [
      row("old-ok", T0), // 500 days old: past the 400-day window -> purged
      row("old-failed", T0 + 1 * DAY, "failed"), // also past the window, and status is irrelevant to age
      row("recent-ok", now - 10 * DAY), // 10 days old: well within the window -> kept
      row("boundary-inside", now - RUN_HISTORY_MAX_AGE_MS + DAY), // one day inside the window -> kept
      row("boundary-outside", now - RUN_HISTORY_MAX_AGE_MS - DAY), // one day past the window -> purged
      row("ancient-in-flight", T0, "in-flight"), // 500 days old but STILL IN FLIGHT -> never purged
      { runId: "no-timestamp", index: 1, startedAt: "not-a-date", status: "ok" } as RunHistoryEntry, // unparseable -> kept (fail-safe)
    ];
    const { kept, purged } = purgeRunHistoryEntries(ring, now, RUN_HISTORY_MAX_AGE_MS);
    const keptIds = new Set(kept.map((e) => e.runId));

    ok("policy: an entry well past the retention window is purged", !keptIds.has("old-ok"));
    ok("policy: age, not outcome status, drives the purge (a failed run also ages out)", !keptIds.has("old-failed"));
    ok("policy: a recent entry is kept", keptIds.has("recent-ok"));
    ok("policy: an entry one day inside the window is kept (boundary is exclusive of the max, not off-by-one)", keptIds.has("boundary-inside"));
    ok("policy: an entry one day past the window is purged", !keptIds.has("boundary-outside"));
    ok("policy: an in-flight run is NEVER purged regardless of age (the scheduler still tracks it by runId)", keptIds.has("ancient-in-flight"));
    ok("policy: an entry whose timestamp will not parse is kept, fail-safe towards retaining data", keptIds.has("no-timestamp"));
    ok("policy: the purged count matches the entries actually dropped", purged === 3 && purged === ring.length - kept.length);
    ok("policy: relative order of kept entries is preserved (a stable filter, not a resort)", kept.map((e) => e.runId).join(",") === ["old-ok", "old-failed", "recent-ok", "boundary-inside", "boundary-outside", "ancient-in-flight", "no-timestamp"].filter((id) => keptIds.has(id)).join(","));

    // A zero-length ring costs nothing and purges nothing (the common case: most downpipes never age out).
    const emptyResult = purgeRunHistoryEntries([], now, RUN_HISTORY_MAX_AGE_MS);
    ok("policy: an empty ring purges nothing", emptyResult.purged === 0 && emptyResult.kept.length === 0);

    // Negative control: a window so large nothing can ever be older than it purges nothing, proving the
    // function can in fact return a NON-EMPTY purge count elsewhere in this run (checked above) rather
    // than always reporting zero regardless of input.
    const neverExpires = purgeRunHistoryEntries(ring, now, Number.MAX_SAFE_INTEGER);
    ok("policy negative control: an unreachable retention window purges nothing (the purge above was real, not a constant zero)", neverExpires.purged === 0 && neverExpires.kept.length === ring.length);
  }

  // =========================================================================================
  // PART 2: the constant itself is sane (a days figure that actually derives the ms figure).
  // =========================================================================================
  ok("constant: RUN_HISTORY_MAX_AGE_MS derives from RUN_HISTORY_MAX_AGE_DAYS (400 days), not a drifted literal", RUN_HISTORY_MAX_AGE_MS === RUN_HISTORY_MAX_AGE_DAYS * 24 * 60 * 60 * 1000);
  ok("constant: the retention window is a positive, finite number of milliseconds", Number.isFinite(RUN_HISTORY_MAX_AGE_MS) && RUN_HISTORY_MAX_AGE_MS > 0);

  // =========================================================================================
  // PART 3: THE REAL DO ROUTE (POST /history-retention-pass, scheduler-do-routing.ts), driven end to end
  // over MockStorage -- proving the wiring, not a second copy of the policy.
  // =========================================================================================
  {
    const { storage, stub } = makeScheduler();
    // The route reads the wall clock (Date.now()) inside the DO, so the fixture's ages are expressed
    // relative to the REAL now rather than the fixed T0 the pure-function part above uses.
    const realNow = Date.now();
    await storage.put("dp:dpA", makeDownpipe("dpA"));
    await storage.put("dp:dpB", makeDownpipe("dpB"));
    // dpA: a mixed ring (one old, one recent) -> the DO must rewrite it to just the recent row.
    await storage.put("hist:dpA", [row("a-old", realNow - 500 * DAY), row("a-recent", realNow - 5 * DAY)]);
    // dpB: every row already inside the window -> the DO must NOT rewrite this ring at all.
    const bRing = [row("b-recent-1", realNow - 1 * DAY), row("b-recent-2", realNow - 2 * DAY)];
    await storage.put("hist:dpB", bRing);

    const passResp = await fetchDO(stub, "POST", "/history-retention-pass", { maxAgeMs: RUN_HISTORY_MAX_AGE_MS });
    ok("DO route: POST /history-retention-pass answers 200", passResp.status === 200);
    const passBody = (await passResp.json()) as { downpipesScanned: number; entriesPurged: number };
    ok("DO route: scanned both downpipes' rings", passBody.downpipesScanned === 2);
    ok("DO route: purged exactly the one expired entry", passBody.entriesPurged === 1);

    const aAfter = storage.rawGet<RunHistoryEntry[]>("hist:dpA");
    ok("DO route: dpA's ring lost the expired entry", aAfter !== undefined && aAfter.length === 1 && aAfter[0]?.runId === "a-recent");
    const bAfter = storage.rawGet<RunHistoryEntry[]>("hist:dpB");
    ok("DO route: dpB's fully-unexpired ring is untouched (same length, same rows)", bAfter !== undefined && bAfter.length === 2 && bAfter.every((e) => bRing.some((r) => r.runId === e.runId)));

    // A second, immediate pass is idempotent: nothing left to purge.
    const secondResp = await fetchDO(stub, "POST", "/history-retention-pass", { maxAgeMs: RUN_HISTORY_MAX_AGE_MS });
    const secondBody = (await secondResp.json()) as { downpipesScanned: number; entriesPurged: number };
    ok("DO route: a second pass is idempotent (nothing left to purge)", secondBody.entriesPurged === 0);

    // A legacy caller with NO body (or a malformed maxAgeMs) falls back to the module's own default
    // window rather than throwing or purging with a bogus value.
    const { storage: storage2, stub: stub2 } = makeScheduler();
    await storage2.put("dp:dpC", makeDownpipe("dpC"));
    await storage2.put("hist:dpC", [row("c-recent", realNow - 5 * DAY)]);
    const bareResp = await fetchDO(stub2, "POST", "/history-retention-pass", {});
    ok("DO route: an omitted maxAgeMs falls back to the default window rather than purging everything", bareResp.status === 200 && ((await bareResp.json()) as { entriesPurged: number }).entriesPurged === 0);
  }

  console.log(failures === 0 ? "\nALL RUN-HISTORY RETENTION VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
