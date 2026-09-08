// Prove the ON-DEMAND FLEET DRILL: a bulk restore-test campaign that fans the existing
// per-downpipe restore-test machinery across cron ticks under a per-tick cap, instead of waiting weeks
// for each downpipe's weekly cadence to fall due. In-memory doubles only; no network, no deploy, no cost.
// Run:
//   node test/validate-fleet-drill.ts
//
// What this proves (all against the REAL SchedulerDO routes, with a PagingStorage that honours
// startAfter + limit exactly like the platform, so the campaign works at fleet scale):
//
//  start (POST /admin/drill-all -> POST /fleet-drill/start):
//    - gates on drill.run: a viewer caller is refused 403; an owner caller starts a campaign;
//    - the campaign's total equals the fleet size (the whole fleet across list pages);
//    - a second start while one is active REFUSES to clobber it (alreadyActive, same campaignId);
//    - a downpipeIds subset restricts the campaign to those ids.
//
//  drain (POST /fleet-drill/next) + advance (POST /restore-test-complete):
//    - each batch returns at most `cap` members and never the same id twice (no double-dispatch);
//    - feeding the completion callback back (as the cron does) advances passed/failed and drains the
//      campaign across batches until it FINISHES, with progress visible via GET /fleet-drill/status;
//    - a downpipe DELETED mid-campaign is counted (failed) so the campaign still converges;
//    - a dispatched-but-never-completed member is RE-QUEUED after the in-flight timeout (self-heal),
//      so the campaign always converges even if a completion callback is lost.
//
// The MockStorage is the same paginating shape validate-fleet-scale.ts uses (ascending key order,
// page capped at `limit`, startAfter honoured), so the campaign's listDownpipes over the whole fleet
// is exercised for real rather than hidden by a one-page mock.

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { DownpipeConfig, DownpipeState, FleetDrillProgress } from "../src/sched/scheduler-do.ts";
import { encodeCaller, CALLER_HEADER, type Caller } from "../src/admin/identity.ts";
import { FLEET_DRILL_INFLIGHT_TIMEOUT_MS } from "../src/sched/scheduler-do-limits.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- In-memory DO storage that HONOURS startAfter + limit (paginates like the platform) -------
const PLATFORM_LIST_PAGE = 1000;
class PagingStorage {
  private map = new Map<string, unknown>();
  async get<T>(key: string): Promise<T | undefined>;
  async get<T>(keys: string[]): Promise<Map<string, T>>;
  async get<T>(keyOrKeys: string | string[]): Promise<T | undefined | Map<string, T>> {
    if (Array.isArray(keyOrKeys)) {
      const out = new Map<string, T>();
      for (const k of keyOrKeys) {
        const v = this.map.get(k);
        if (v !== undefined) out.set(k, JSON.parse(JSON.stringify(v)) as T);
      }
      return out;
    }
    const v = this.map.get(keyOrKeys);
    return v === undefined ? undefined : (JSON.parse(JSON.stringify(v)) as T);
  }
  async put<T>(key: string, value: T): Promise<void> {
    this.map.set(key, JSON.parse(JSON.stringify(value)));
  }
  async delete(key: string): Promise<boolean> {
    return this.map.delete(key);
  }
  async list<T>(opts?: { prefix?: string; start?: string; startAfter?: string; limit?: number }): Promise<Map<string, T>> {
    const prefix = opts?.prefix ?? "";
    let keys = [...this.map.keys()].filter((k) => k.startsWith(prefix)).sort();
    if (opts?.startAfter !== undefined) keys = keys.filter((k) => k > opts.startAfter!);
    if (opts?.start !== undefined) keys = keys.filter((k) => k >= opts.start!);
    const cap = Math.min(opts?.limit ?? PLATFORM_LIST_PAGE, PLATFORM_LIST_PAGE);
    const page = keys.slice(0, cap);
    const out = new Map<string, T>();
    for (const k of page) out.set(k, this.map.get(k) as T);
    return out;
  }
  async setAlarm(_t: number): Promise<void> {}
  async deleteAlarm(): Promise<void> {}
  async getAlarm(): Promise<number | null> {
    return null;
  }
}

function makeScheduler(): { storage: PagingStorage; stub: SchedulerDO } {
  const storage = new PagingStorage();
  const state = { storage } as unknown as DurableObjectState;
  return { storage, stub: new SchedulerDO(state) };
}

function stubFetch(dobj: SchedulerDO, method: string, path: string, body?: unknown, headers?: Record<string, string>): Promise<Response> {
  const url = `https://scheduler.internal${path}`;
  const init: RequestInit = {
    method,
    headers: { ...(headers ?? {}), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  };
  return dobj.fetch(new Request(url, init));
}

const BASE_SOURCE = { type: "kv" as const, binding: "KV_test", include: [], exclude: [] };
function makeConfig(id: string, overrides: Partial<DownpipeConfig> = {}): DownpipeConfig {
  return { id, name: `pipe ${id}`, cadenceSeconds: 3600, enabled: true, source: BASE_SOURCE, ...overrides };
}
function dueState(id: string, overrides: Partial<DownpipeState> = {}): DownpipeState {
  return { config: makeConfig(id), inFlight: false, lastRunId: "01ARZ3NDEKTSV4RRFFQ69G5FAV", nextRunAt: Date.now() - 60_000, ...overrides } as DownpipeState;
}
async function seedFleet(storage: PagingStorage, n: number): Promise<string[]> {
  const ids: string[] = [];
  for (let i = 0; i < n; i++) {
    const id = "dp_" + String(i).padStart(6, "0");
    ids.push(id);
    await storage.put(`dp:${id}`, dueState(id));
  }
  return ids;
}

const OWNER: Caller = { method: "token", email: "owner@example.com", subject: null, role: "owner", groups: [] };
const VIEWER: Caller = { method: "passkey", email: "viewer@example.com", subject: "viewer", role: "viewer", groups: [] };
function callerHeader(c: Caller): Record<string, string> {
  return { [CALLER_HEADER]: encodeCaller(c) };
}

async function status(stub: SchedulerDO): Promise<{ active: boolean; campaign: FleetDrillProgress | null }> {
  return (await (await stubFetch(stub, "GET", "/fleet-drill/status")).json()) as { active: boolean; campaign: FleetDrillProgress | null };
}

// Drain the active campaign exactly as the cron does: ask for a capped batch, then post a completion for
// each member, looping until the campaign is gone. `outcome(id)` decides pass/fail; `onBatch` lets a test
// mutate storage (e.g. delete a downpipe) before completions are posted. Returns how many ticks it took.
async function drainCampaign(
  stub: SchedulerDO,
  cap: number,
  outcome: (id: string) => boolean,
  opts: { maxTicks?: number; onBatch?: (ids: string[], tick: number) => Promise<void>; completeIds?: (ids: string[]) => string[] } = {},
): Promise<{ ticks: number; maxBatch: number; dispatched: string[] }> {
  const maxTicks = opts.maxTicks ?? 10_000;
  let ticks = 0;
  let maxBatch = 0;
  const dispatched: string[] = [];
  for (; ticks < maxTicks; ticks++) {
    const r = (await (await stubFetch(stub, "POST", "/fleet-drill/next", { cap })).json()) as { due: DownpipeState[]; campaignId: string | null; done: boolean };
    if (r.campaignId === null) break; // no active campaign -> finished
    const ids = r.due.map((d) => d.config.id);
    maxBatch = Math.max(maxBatch, ids.length);
    dispatched.push(...ids);
    if (opts.onBatch) await opts.onBatch(ids, ticks);
    const toComplete = opts.completeIds ? opts.completeIds(ids) : ids;
    for (const id of toComplete) {
      await stubFetch(stub, "POST", "/restore-test-complete", { id, ok: outcome(id), at: Date.now() });
    }
    if (ids.length === 0 && toComplete.length === 0) {
      // Nothing dispatched and nothing to complete: only safe to stop if the campaign is truly done.
      const s = await status(stub);
      if (!s.active) break;
    }
  }
  return { ticks, maxBatch, dispatched };
}

async function main(): Promise<void> {
  // ---- start: gating, total, no-clobber, subset ----------------------------------------------
  {
    const { storage, stub } = makeScheduler();
    const FLEET = 1100; // just over one list page, so listDownpipes must page the whole fleet
    const ids = await seedFleet(storage, FLEET);

    // A viewer (no drill.run) is refused 403; nothing is started.
    const refused = await stubFetch(stub, "POST", "/fleet-drill/start", {}, callerHeader(VIEWER));
    ok("start is REFUSED 403 for a caller without drill.run (viewer)", refused.status === 403);
    const afterRefuse = await status(stub);
    ok("a refused start leaves NO active campaign", afterRefuse.active === false && afterRefuse.campaign === null);

    // An owner starts a campaign over the WHOLE fleet (across list pages).
    const startResp = await stubFetch(stub, "POST", "/fleet-drill/start", {}, callerHeader(OWNER));
    const start = (await startResp.json()) as { ok: boolean; campaignId?: string; total?: number };
    ok("owner start succeeds (drill.run held)", startResp.status === 200 && start.ok === true);
    ok("the campaign total equals the WHOLE fleet across list pages", start.total === FLEET);
    const s1 = await status(stub);
    ok("status shows the campaign ACTIVE with total = fleet and nothing completed yet", s1.active === true && s1.campaign?.total === FLEET && s1.campaign?.completed === 0);
    ok("status carries the starter's verified email (redaction-safe attribution)", s1.campaign?.startedBy === "owner@example.com");

    // A second start while one is active REFUSES to clobber it (returns the existing campaign).
    const second = (await (await stubFetch(stub, "POST", "/fleet-drill/start", {}, callerHeader(OWNER))).json()) as { ok: boolean; alreadyActive?: boolean; campaignId?: string };
    ok("a second start while one is active refuses (alreadyActive)", second.ok === false && second.alreadyActive === true);
    ok("the refused second start names the SAME in-progress campaign", second.campaignId === start.campaignId);

    // Subset start (after draining the first): a downpipeIds subset restricts the campaign.
    await drainCampaign(stub, 50, () => true);
    const sDone = await status(stub);
    ok("the first campaign FINISHED after draining (no longer active)", sDone.active === false && sDone.campaign?.done === true && sDone.campaign?.passed === FLEET);

    const subsetIds = [ids[0]!, ids[500]!, ids[FLEET - 1]!, "dp_does_not_exist"];
    const subset = (await (await stubFetch(stub, "POST", "/fleet-drill/start", { downpipeIds: subsetIds }, callerHeader(OWNER))).json()) as { ok: boolean; total?: number };
    ok("a downpipeIds subset restricts the campaign to the EXISTING matching ids (unknown id dropped)", subset.ok === true && subset.total === 3);
  }

  // ---- drain: cap respected, no double-dispatch, convergence, progress ------------------------
  {
    const { storage, stub } = makeScheduler();
    const FLEET = 137; // not a multiple of the cap, so the last batch is short
    await seedFleet(storage, FLEET);
    await stubFetch(stub, "POST", "/fleet-drill/start", {}, callerHeader(OWNER));

    const CAP = 5;
    // Make every 11th downpipe "fail" its drill, the rest pass, to exercise both counters.
    const fails = (id: string) => Number(id.slice(3)) % 11 === 0;
    const { ticks, maxBatch, dispatched } = await drainCampaign(stub, CAP, (id) => !fails(id));

    ok("no batch ever exceeds the per-tick cap", maxBatch <= CAP);
    ok("every downpipe was dispatched exactly once (no double-dispatch)", dispatched.length === FLEET && new Set(dispatched).size === FLEET);
    ok("draining took ceil(fleet/cap) ticks (the fleet sweeps in a bounded number of ticks, not weeks)", ticks === Math.ceil(FLEET / CAP));

    const s = await status(stub);
    const expectedFailed = [...Array(FLEET).keys()].filter((i) => i % 11 === 0).length;
    ok("the finished campaign counted every downpipe (passed + failed = total)", s.campaign?.completed === FLEET && s.campaign?.total === FLEET);
    ok("the finished campaign split pass/fail by drill outcome", s.campaign?.failed === expectedFailed && s.campaign?.passed === FLEET - expectedFailed);
    ok("the finished campaign is done with nothing remaining", s.campaign?.done === true && s.campaign?.remaining === 0 && s.active === false);
  }

  // ---- convergence when a downpipe is DELETED mid-campaign ------------------------------------
  {
    const { storage, stub } = makeScheduler();
    const ids = await seedFleet(storage, 20);
    await stubFetch(stub, "POST", "/fleet-drill/start", {}, callerHeader(OWNER));
    // Delete a chunk of downpipes after the campaign started but before they are dispatched.
    const deleted = new Set([ids[5]!, ids[6]!, ids[7]!, ids[18]!]);
    let removed = false;
    const { dispatched } = await drainCampaign(stub, 3, () => true, {
      onBatch: async () => {
        if (!removed) {
          for (const id of deleted) await storage.delete(`dp:${id}`);
          removed = true;
        }
      },
    });
    const s = await status(stub);
    ok("a downpipe deleted mid-campaign is NOT dispatched (the dp: state is gone)", !dispatched.some((id) => deleted.has(id)) === true);
    ok("a deleted downpipe is still COUNTED so the campaign converges", s.campaign?.completed === 20 && s.campaign?.done === true);
    ok("the campaign finished despite the deletions (no stuck campaign)", s.active === false && s.campaign?.remaining === 0);
  }

  // ---- self-heal: a dispatched-but-never-completed member is re-queued after the timeout ------
  {
    const { storage, stub } = makeScheduler();
    await seedFleet(storage, 4);
    await stubFetch(stub, "POST", "/fleet-drill/start", {}, callerHeader(OWNER));

    // Dispatch a batch but DO NOT complete it (a lost completion callback / budget-exhausted tick).
    const first = (await (await stubFetch(stub, "POST", "/fleet-drill/next", { cap: 4 })).json()) as { due: DownpipeState[] };
    ok("the first batch dispatched the whole small fleet", first.due.length === 4);
    const sStuck = await status(stub);
    ok("with completions withheld, every member is in flight and none completed", sStuck.campaign?.inFlight === 4 && sStuck.campaign?.completed === 0);

    // Immediately asking again returns nothing (all in flight, none stale yet) and does NOT finish.
    const noop = (await (await stubFetch(stub, "POST", "/fleet-drill/next", { cap: 4 })).json()) as { due: DownpipeState[]; done: boolean };
    ok("a follow-up batch returns nothing while members are in flight and not yet stale", noop.due.length === 0 && noop.done === false);

    // Age the in-flight dispatch times past the timeout (simulate the clock advancing a tick window).
    const active = (await storage.get<{ inFlight: Record<string, number> }>("fleetdrill:active"))!;
    const stale = Date.now() - FLEET_DRILL_INFLIGHT_TIMEOUT_MS - 1;
    for (const id of Object.keys(active.inFlight)) active.inFlight[id] = stale;
    await storage.put("fleetdrill:active", active);

    // Now the next batch RE-QUEUES the stale members (self-heal); complete them this time.
    const requeued = (await (await stubFetch(stub, "POST", "/fleet-drill/next", { cap: 4 })).json()) as { due: DownpipeState[] };
    ok("stale in-flight members are RE-QUEUED after the timeout (self-heal)", requeued.due.length === 4);
    for (const d of requeued.due) await stubFetch(stub, "POST", "/restore-test-complete", { id: d.config.id, ok: true, at: Date.now() });
    const healed = await status(stub);
    ok("after re-queue + completion the campaign converges (no permanently stuck campaign)", healed.active === false && healed.campaign?.done === true && healed.campaign?.passed === 4);
  }

  // ---- a fleet-drill completion does NOT spuriously advance for a non-campaign downpipe -------
  {
    const { storage, stub } = makeScheduler();
    await seedFleet(storage, 6);
    await stubFetch(stub, "POST", "/fleet-drill/start", {}, callerHeader(OWNER));
    // Post a completion for an id that was NEVER dispatched by the campaign (a plain cadence-due test).
    await stubFetch(stub, "POST", "/restore-test-complete", { id: "dp_000003", ok: true, at: Date.now() });
    const s = await status(stub);
    ok("a completion for a NOT-in-flight downpipe does not advance the campaign", s.campaign?.completed === 0 && s.campaign?.total === 6 && s.active === true);
  }

  console.log(failures === 0 ? "\nfleet-drill: ALL PASS" : `\nfleet-drill: ${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
