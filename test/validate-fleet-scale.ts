// Prove the FLEET-SCALE scheduling fixes end to end with in-memory doubles only. No network, no
// deploy, no cost. Run:
//   node test/validate-fleet-scale.ts
//
// What this proves:
//
//  listDownpipes / the scheduling scan PAGE past the DO list page limit.
//    The Cloudflare Durable Object storage list() returns at most one page (the platform caps it
//    at ~1000 keys). listDownpipes previously did a single storage.list({prefix:"dp:"}), so an
//    account with MORE than one page of downpipes silently TRUNCATED: every downpipe past the
//    first page was never returned, hence never scheduled by due(). This suite seeds >1000
//    downpipes into a MockStorage whose list() FAITHFULLY honours { startAfter, limit } (it caps
//    every page at the page limit, exactly like the platform), then asserts:
//      - listDownpipes (GET /downpipes) enumerates ALL of them (not just the first page);
//      - due() (GET /due) returns EVERY enabled, not-in-flight, due downpipe across all pages, so
//        a downpipe beyond the page limit is genuinely scheduled, not dropped;
//      - restoreTestsDue (POST /restore-tests-due) likewise sees the whole fleet;
//      - destinationForRun resolves a run owned by a downpipe BEYOND the first page (the restore /
//        drill read path also pages the dp: scan).
//
//  the drill-evidence log is BOUNDED (DRILL_EVIDENCE_CAP) and the read is bounded.
//    Every other record family in the DO has a cap (audit AUDIT_CAP, history RING_CAP); the
//    drill-evidence log previously grew without bound. This suite records MORE than the cap's worth
//    of evidence rows through the real POST /drill-evidence route and asserts:
//      - the retained count never exceeds the cap (the oldest rows roll over, mirroring AUDIT_CAP);
//      - the rollover keeps the NEWEST rows (it drops oldest-first), so recent evidence survives;
//      - the read (GET /drill-evidence) returns at most the cap, newest-first, and is therefore
//        bounded regardless of how many drills have ever run.
//
// The MockStorage here is the same shape the other DO validators use, with ONE deliberate
// difference: its list() implements { start? , startAfter, prefix, limit } the way the platform
// does (ascending key order, capped at `limit`), so the pagination loop in listAllByPrefix is
// exercised for REAL rather than hidden by a mock that returns everything in one page.

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { DownpipeConfig, DownpipeState, DrillEvidenceEntry } from "../src/sched/scheduler-do.ts";
import type { SchedulerDOSurface } from "../src/sched/scheduler-do-base.ts";
import { DUE_INDEX_PREFIX, pad16 } from "../src/sched/scheduler-do-limits.ts";
import { encodeCaller, CALLER_HEADER, type Caller } from "../src/admin/identity.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- In-memory DO storage that HONOURS startAfter + limit (paginates like the platform) -------
// The key difference from the other validators' mocks: list() caps each page at `limit` and
// respects `startAfter` (exclusive lower bound), so a prefix with more than one page's worth of
// keys is returned ACROSS pages, exactly as the real DurableObjectStorage does. This is what makes
// the pagination loop in listAllByPrefix testable: a mock that returns the whole set in one page
// would pass even the OLD, truncating code.
const PLATFORM_LIST_PAGE = 1000; // the platform's default/maximum keys-per-list page
class PagingStorage {
  private map = new Map<string, unknown>();
  // Faithful to the platform: get() deserialises a fresh copy each call (mutating the result does not
  // change storage until a put()), so the DO's read-mutate-repersist paths (e.g. the due-time index
  // advance in completeRun) behave as in production rather than aliasing a live reference. Supports BOTH
  // overloads: a single key, and an ARRAY of keys returning a Map of the present keys (the batch form the
  // DO's findRunRing reads the hist: rings through), each value a fresh copy.
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
    return (v === undefined ? undefined : (JSON.parse(JSON.stringify(v)) as T));
  }
  async put<T>(key: string, value: T): Promise<void> {
    this.map.set(key, JSON.parse(JSON.stringify(value)));
  }
  async delete(key: string): Promise<boolean> {
    return this.map.delete(key);
  }
  // The platform contract: ascending key order, optional prefix, optional startAfter (exclusive)
  // / start (inclusive), and a page capped at min(limit, platform page). A caller that wants the
  // whole set MUST loop with startAfter until a short page comes back, which is exactly what the
  // DO's listAllByPrefix does.
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
  async setAlarm(_t: number): Promise<void> {
    /* no-op */
  }
  async deleteAlarm(): Promise<void> {
    /* no-op */
  }
  rawCountPrefix(prefix: string): number {
    return [...this.map.keys()].filter((k) => k.startsWith(prefix)).length;
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

// Seed the DO with N downpipes by writing the dp: state directly into storage (the same shape
// addDownpipe persists), so the suite can stand up a >1000 fleet cheaply without N HTTP round
// trips. Each is enabled and DUE (nextRunAt in the past) unless overridden. id is zero-padded so
// the ascending key order is deterministic and the "beyond the page" downpipe is well-defined.
async function seedFleet(storage: PagingStorage, n: number, makeState: (i: number, id: string) => DownpipeState): Promise<string[]> {
  const ids: string[] = [];
  for (let i = 0; i < n; i++) {
    const id = "dp_" + String(i).padStart(6, "0");
    ids.push(id);
    await storage.put(`dp:${id}`, makeState(i, id));
  }
  return ids;
}

function dueState(id: string, overrides: Partial<DownpipeState> = {}): DownpipeState {
  return {
    config: makeConfig(id),
    inFlight: false,
    lastRunId: null,
    nextRunAt: Date.now() - 60_000, // due (in the past)
    ...overrides,
  } as DownpipeState;
}

async function main(): Promise<void> {
  // ---- >1000 downpipes are ALL enumerated and ALL scheduled --------------------
  {
    const { storage, stub } = makeScheduler();
    const FLEET = 2500; // >2 full pages, so the loop must page at least 3 times
    const ids = await seedFleet(storage, FLEET, (_i, id) => dueState(id));
    ok("precondition: the fleet exceeds two list pages (a single list() would truncate it)", FLEET > PLATFORM_LIST_PAGE * 2 && storage.rawCountPrefix("dp:") === FLEET);

    // A single un-paged list() returns at most one page: prove the mock truncates, so the test is
    // meaningful (the OLD code would have seen only this).
    const onePage = await storage.list<DownpipeState>({ prefix: "dp:" });
    ok("a single un-paged list() returns only ONE page (the truncation the fix repairs)", onePage.size === PLATFORM_LIST_PAGE);

    // listDownpipes (GET /downpipes) must enumerate the WHOLE fleet across pages.
    const listResp = await stubFetch(stub, "GET", "/downpipes");
    const list = (await listResp.json()) as DownpipeState[];
    ok("listDownpipes enumerates EVERY downpipe across all pages (no truncation)", list.length === FLEET);
    const seen = new Set(list.map((d) => d.config.id));
    ok("listDownpipes includes the FIRST downpipe", seen.has(ids[0]!));
    ok("listDownpipes includes a downpipe in the SECOND page (index 1500)", seen.has(ids[1500]!));
    ok("listDownpipes includes the LAST downpipe (index 2499, well past the page limit)", seen.has(ids[FLEET - 1]!));
    ok("listDownpipes returns each downpipe exactly once (no overlap across pages)", seen.size === FLEET);

    // due() (GET /due) must return EVERY due downpipe: the scheduling decision the cron drives.
    const dueResp = await stubFetch(stub, "GET", "/due");
    const { due } = (await dueResp.json()) as { due: DownpipeState[] };
    ok("due() returns EVERY due downpipe across all pages (the whole fleet is scheduled)", due.length === FLEET);
    ok("due() includes a downpipe BEYOND the first page (it would otherwise never be scheduled)", due.some((d) => d.config.id === ids[FLEET - 1]!));
  }

  // ---- due-filtering still correct at scale (enabled/in-flight/not-due excluded) ---
  {
    const { storage, stub } = makeScheduler();
    const FLEET = 1200; // just over one page
    let expectedDue = 0;
    await seedFleet(storage, FLEET, (i, id) => {
      // Mix the fleet: every 3rd disabled, every 5th in-flight (leased), every 7th not-yet-due.
      if (i % 3 === 0) return dueState(id, { config: makeConfig(id, { enabled: false }) });
      if (i % 5 === 0) return dueState(id, { inFlight: true, inFlightSince: Date.now() }); // leased
      if (i % 7 === 0) return dueState(id, { nextRunAt: Date.now() + 3_600_000 }); // future
      expectedDue++;
      return dueState(id);
    });
    const dueResp = await stubFetch(stub, "GET", "/due");
    const { due } = (await dueResp.json()) as { due: DownpipeState[] };
    ok("due() applies the enabled/lease/nextRunAt filter correctly ACROSS pages", due.length === expectedDue);
    ok("due() excludes disabled downpipes even beyond the first page", !due.some((d) => d.config.enabled === false));
    ok("due() never returns a downpipe twice at scale", new Set(due.map((d) => d.config.id)).size === due.length);

    // restoreTestsDue across pages: turn the cadence on for a subset spanning both pages.
    const { storage: s2, stub: st2 } = makeScheduler();
    let expectedTests = 0;
    await seedFleet(s2, FLEET, (i, id) => {
      const on = i % 4 === 0; // a quarter have the restore-test cadence on, spanning both pages
      if (on) expectedTests++;
      // A never-tested downpipe is due only once it HAS a run to drill (the pre-first-backup
      // deferral false alarm fix), so the pagination fixture gives each one a completed run.
      return dueState(id, { config: makeConfig(id, on ? { restoreTestCadenceSeconds: 86_400 } : {}), lastRunId: "01ARZ3NDEKTSV4RRFFQ69G5FAV" });
    });
    const rtResp = await stubFetch(st2, "POST", "/restore-tests-due");
    const { due: testsDue } = (await rtResp.json()) as { due: DownpipeState[] };
    ok("restoreTestsDue sees the whole fleet across pages (cadence-on subset, both pages)", testsDue.length === expectedTests);
    ok("restoreTestsDue includes a cadence-on downpipe beyond the first page", testsDue.some((d) => Number(d.config.id.slice(3)) >= PLATFORM_LIST_PAGE));
  }

  // ---- destinationForRun pages the dp: scan (restore/drill read path) -----------
  {
    const { storage, stub } = makeScheduler();
    const FLEET = 1100;
    const ids = await seedFleet(storage, FLEET, (_i, id) => dueState(id, { config: makeConfig(id, { destinationId: `bucket-${id}` }) }));
    // Put a run-history ring on a downpipe BEYOND the first page, naming a runId; destinationForRun
    // must page the dp: scan to find it (it would miss it with a single un-paged list).
    const farId = ids[FLEET - 1]!;
    const farRunId = "01ARZ3NDEKTSV4RRFFQ69G5FZZ";
    await storage.put(`hist:${farId}`, [{ runId: farRunId, index: 1, startedAt: new Date().toISOString(), status: "ok", destinationId: `bucket-${farId}` }]);
    const resp = await stubFetch(stub, "GET", `/downpipes/dest-for-run?runId=${farRunId}`);
    const body = (await resp.json()) as { destinationId: string | null };
    ok("destinationForRun resolves a run owned by a downpipe BEYOND the first page", body.destinationId === `bucket-${farId}`);
  }

  // ---- the drill-evidence log is CAPPED and the read is bounded -----------------
  {
    const { storage, stub } = makeScheduler();
    // The DO re-checks drill.run on the forwarded caller; an owner caller passes (the same authority
    // the engine's own scheduled-drill recording uses).
    const owner: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };
    const hdr = { [CALLER_HEADER]: encodeCaller(owner) };

    // Discover the cap empirically: record a few rows and read them back, then keep recording until the
    // retained count stops growing. We assert the cap is a sane few-hundred and that the read is bounded
    // by it no matter how many we record. (The cap lives as a module constant in the DO; this proves its
    // EFFECT (rollover plus a bounded read) without coupling to the literal.)
    const OVERSHOOT = 650; // record more than any sane few-hundred cap so a rollover MUST occur
    let allOk = true;
    for (let i = 0; i < OVERSHOOT; i++) {
      const r = await stubFetch(stub, "POST", "/drill-evidence", { runId: `run-${String(i).padStart(5, "0")}`, kind: "in-account", note: `drill ${i}` }, hdr);
      if (r.status !== 200) allOk = false;
    }
    ok(`all ${OVERSHOOT} drill-evidence rows recorded (200)`, allOk);

    const stored = storage.rawCountPrefix("drill-evidence:");
    ok("the stored drill-evidence count is BOUNDED (it did not grow to the overshoot)", stored < OVERSHOOT);
    ok("the stored count is a sane few-hundred cap (>=100, <=600)", stored >= 100 && stored <= 600);

    // The READ (GET /drill-evidence) is bounded by the cap and newest-first.
    const readResp = await stubFetch(stub, "GET", "/drill-evidence");
    const rows = (await readResp.json()) as DrillEvidenceEntry[];
    ok("GET /drill-evidence returns at most the cap's worth of rows (bounded read)", rows.length === stored && rows.length < OVERSHOOT);
    // Newest-first: the FIRST returned row is the most recent we recorded; the oldest were rolled over.
    ok("the read is newest-first (the most recently recorded row is first)", rows[0]!.runId === `run-${String(OVERSHOOT - 1).padStart(5, "0")}`);
    ok("the OLDEST recorded rows were rolled over (not present anymore)", !rows.some((r) => r.runId === "run-00000"));
    // Continuity: the retained set is the NEWEST `stored` rows, contiguous from (OVERSHOOT-stored).
    const retainedRunIds = new Set(rows.map((r) => r.runId));
    const expectedNewest = `run-${String(OVERSHOOT - 1).padStart(5, "0")}`;
    const expectedOldestRetained = `run-${String(OVERSHOOT - stored).padStart(5, "0")}`;
    ok("the retained set keeps the newest row", retainedRunIds.has(expectedNewest));
    ok("the retained set's oldest is exactly (overshoot - cap), a clean oldest-first rollover", retainedRunIds.has(expectedOldestRetained));

    // Recording one MORE keeps the count pinned at the cap (steady-state rollover of exactly one).
    await stubFetch(stub, "POST", "/drill-evidence", { runId: "run-extra", kind: "in-account" }, hdr);
    const after = storage.rawCountPrefix("drill-evidence:");
    ok("one more record keeps the count pinned at the cap (steady-state rollover)", after === stored);
    const readResp2 = await stubFetch(stub, "GET", "/drill-evidence");
    const rows2 = (await readResp2.json()) as DrillEvidenceEntry[];
    ok("the newest row is now the just-added one", rows2[0]!.runId === "run-extra");
  }

  // ---- rebuildDueIndex FULLY clears a >1-page stale due: index (no leaked tail) -
  {
    // rebuildDueIndex is the reconciliation backstop: it drops EVERY existing due: key, then re-writes
    // an entry per current enabled dp: state. The OLD cleanup dropped the existing keys with a single
    // un-paged storage.list({ prefix: DUE_INDEX_PREFIX }), which returns at most ONE page (~1000 keys),
    // so a drifted index holding MORE than a page of stale entries (downpipes since deleted/disabled)
    // had only its first page deleted and the tail LEAKED past the rebuild, so the index never
    // converged to the dp: truth at fleet scale. The fix pages the deletion via listAllByPrefix.
    const { storage, stub } = makeScheduler();
    // Seed MORE than one full page of STALE due: keys whose downpipes do NOT exist in dp: (every one
    // must be deleted by the rebuild). pad16 over distinct times so the keys sort ascending, exactly
    // the order the paged cursor advances through.
    const STALE_DUE = PLATFORM_LIST_PAGE + 60; // > one full page (1000), so the cleanup MUST page twice
    for (let i = 0; i < STALE_DUE; i++) {
      await storage.put(`${DUE_INDEX_PREFIX}${pad16(1_000_000 + i)}:gone-${String(i).padStart(6, "0")}`, 1);
    }
    const seededStale = storage.rawCountPrefix(DUE_INDEX_PREFIX);
    ok(`the drifted index holds MORE than one list page of stale due: keys (got ${seededStale}, page is ${PLATFORM_LIST_PAGE})`, seededStale > PLATFORM_LIST_PAGE);
    // Confirm the truncation premise: a single un-paged list() (the OLD cleanup) sees only ONE page.
    const onePage = await storage.list<unknown>({ prefix: DUE_INDEX_PREFIX });
    ok("a single un-paged list() returns only ONE page of the stale due: keys (the OLD code's silent truncation)", onePage.size === PLATFORM_LIST_PAGE && onePage.size < seededStale);
    // Add ONE real enabled downpipe so the rebuild re-writes exactly one fresh due: entry from dp: truth.
    await storage.put("dp:dp-live", dueState("dp-live"));

    await (stub as unknown as SchedulerDOSurface).rebuildDueIndex();

    // The decisive assertion: NOT ONE stale "gone-*" due: key survives. The OLD un-paged cleanup would
    // have deleted only the first page and left the >1000th..tail stale keys behind.
    const remaining = await (stub as unknown as { listAllByPrefix<T>(p: string): Promise<Map<string, T>> }).listAllByPrefix<unknown>(DUE_INDEX_PREFIX);
    const survivingStale = [...remaining.keys()].filter((k) => k.includes(":gone-"));
    ok(`every stale due: key was cleared across ALL pages (0 leaked, OLD code would leak ${seededStale - PLATFORM_LIST_PAGE})`, survivingStale.length === 0);
    // And the rebuild re-wrote exactly the one live downpipe's due: entry from the dp: truth.
    ok("rebuildDueIndex re-wrote exactly the live downpipe's due: entry (index converged to dp: truth)", remaining.size === 1 && [...remaining.keys()][0]!.endsWith(":dp-live"));
  }

  console.log(failures === 0 ? "\nFLEET-SCALE VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
