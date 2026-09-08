// Shared fixtures for the SchedulerDO validator suite.
// A thin orchestrator imports and calls a run() from each area module. Every area module shares the
// in-memory doubles, the ok() assertion sink and the config builders defined here.
//
// The ok() sink keeps a module-level failure count. Each area module
// imports ok and calls it; the orchestrator reads getFailures() at the end to decide the exit code.

import type { Role } from "../src/admin/identity.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { DownpipeConfig } from "../src/sched/scheduler-do.ts";

// Re-export the config type so area modules import their fixtures and the type from one place.
export type { DownpipeConfig } from "../src/sched/scheduler-do.ts";
// Re-export the production lease window so the index parity suite computes its brute-force reference
// set with the EXACT same constant the DO uses: no mirror copy that can diverge.
import { INFLIGHT_LEASE_MS } from "../src/sched/scheduler-do-records.ts";
export { INFLIGHT_LEASE_MS };

// LEASE_EXPIRED_MS is one minute past the DO's INFLIGHT_LEASE_MS, the age a back-dated inFlightSince must
// reach for a lease to read as EXPIRED. Deriving it from the production constant means a change to the
// lease window flows through automatically and the test intent ("expired") is named, not encoded in a literal.
const ONE_MINUTE_MS = 60 * 1000;
export const LEASE_EXPIRED_MS = INFLIGHT_LEASE_MS + ONE_MINUTE_MS;

let failures = 0;
export function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
// getFailures returns the running failure count so the orchestrator can set the process exit code
// after every area has run (the count is module-level, shared across every area that calls ok()).
export function getFailures(): number {
  return failures;
}

// ---- In-memory DO storage (same pattern as validate-rbac.ts / validate-audit.ts) --------
// Backed by a Map, structured-clones values on put (simulating the platform) so a stored
// object is not a live reference a later mutation could corrupt. Keys are returned in
// ascending lexicographic order from list() so the ring ordering is preserved.
export class MockStorage {
  private map = new Map<string, unknown>();
  // lastAlarmAt records the most recent setAlarm() argument so a test can assert the scheduled
  // time (the rearm-clamp test confirms rearmAlarm never arms an alarm in the past). It is null
  // until the DO arms an alarm for the first time. Recording it does not change behaviour for the
  // other tests, which never read it.
  lastAlarmAt: number | null = null;
  async get<T>(key: string): Promise<T | undefined>;
  async get<T>(keys: string[]): Promise<Map<string, T>>;
  async get<T>(keyOrKeys: string | string[]): Promise<T | undefined | Map<string, T>> {
    // Faithful to the platform: storage.get() DESERIALISES a fresh copy on every call, so mutating the
    // returned object does NOT alter what is on disk until a put(). The DO relies on this (e.g.
    // completeRun mutates the state it read, then persistDownpipeState re-reads the PRIOR on-disk state
    // to advance the due-time index); a mock that returned a live reference would alias the two reads and
    // hide a real bug. Returning undefined (not a clone of undefined) for a missing key.
    // BOTH platform overloads are supported (matching test/mock-storage.ts): an ARRAY of keys returns a
    // Map of the PRESENT keys to their values (absent keys omitted), the batch form the DO's ring
    // readers (findRunRing, rosterHygiene) use.
    if (Array.isArray(keyOrKeys)) {
      const out = new Map<string, T>();
      for (const k of keyOrKeys) {
        const hit = this.map.get(k);
        if (hit !== undefined) out.set(k, JSON.parse(JSON.stringify(hit)) as T);
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
  // listCalls counts list() invocations so a test can assert a hot path does NOT scan the fleet
  // (completeRun must not do the O(N) rearm-on-completion: sched-rearmalarm-on-every-completion).
  listCalls = 0;
  // listKeysScanned records, per list() call, how many keys the page actually RETURNED. The due-index
  // O(due) test reads it to assert due() touches only the due candidates, not the whole fleet (a key
  // count, the storage-cost proxy the platform bills on, independent of wall-clock).
  listKeysScanned: number[] = [];
  // list honours the platform contract this DO relies on: an optional `prefix`, an optional half-open
  // [start, end) byte range (start inclusive, end exclusive), and an optional `limit` page cap, all over
  // keys returned in ascending lexicographic order. The original mock honoured only `prefix`; the
  // due-time index (due()) lists a { start, end } RANGE with no prefix, so the range/limit support is
  // required for the index scan to be exercised faithfully (and for the O(due) cost assertion to mean
  // anything). Existing call sites pass only `prefix` or nothing, so they are unaffected.
  async list<T>(opts?: { prefix?: string; start?: string; end?: string; limit?: number }): Promise<Map<string, T>> {
    this.listCalls++;
    let keys = [...this.map.keys()].sort();
    if (opts?.prefix !== undefined) keys = keys.filter((k) => k.startsWith(opts.prefix!));
    if (opts?.start !== undefined) keys = keys.filter((k) => k >= opts.start!);
    if (opts?.end !== undefined) keys = keys.filter((k) => k < opts.end!); // end is EXCLUSIVE
    if (opts?.limit !== undefined) keys = keys.slice(0, opts.limit);
    const out = new Map<string, T>();
    for (const k of keys) out.set(k, this.map.get(k) as T);
    this.listKeysScanned.push(out.size);
    return out;
  }
  async setAlarm(t: number): Promise<void> {
    // Record the armed time so the rearm-clamp test can assert it is never in the past.
    this.lastAlarmAt = t;
  }
  // getAlarm returns the currently-armed time (or null when none is pending), mirroring the platform.
  // completeRun reads it for its O(1) alarm safety-net (it no longer does the O(N) rearm on completion).
  async getAlarm(): Promise<number | null> {
    return this.lastAlarmAt;
  }
  // Raw access for test inspection of the ring without going through the DO route.
  rawGet<T>(key: string): T | undefined {
    return this.map.get(key) as T | undefined;
  }
  // rawListKeys returns every stored key (for due-index inspection in the index suite, e.g. asserting
  // how many due: entries exist). It does not go through list() so it never perturbs listCalls.
  rawListKeys(): string[] {
    return [...this.map.keys()];
  }
}

// makeScheduler builds a SchedulerDO over MockStorage and returns the DO and a thin
// stub so tests can also call via the HTTP surface when convenient.
export function makeScheduler(): { storage: MockStorage; stub: SchedulerDO } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  return { storage, stub: dobj };
}

// bindApprovalPrincipals seeds the DO's OWN role table with a grant per principal and then binds each
// grant to its stable subject the way a first authentication does.
//
// It exists because a restore (or prune) approval rests on TWO things a caller header cannot supply. The
// request and the approve trust the router-resolved role on the forwarded caller (the documented FROM THE
// ROUTER ONLY trust), but the SPEND re-resolves both recorded principals LIVE from these tables
// (approvalSpendVerdict -> resolveStoredIdentityAuthority) and refuses an approval whose maker no longer
// holds restore.request or whose checker no longer holds restore.approve. A fixture that asserted a role
// on the header alone would therefore drive an estate where NEITHER principal existed, so every gate and
// every reserve would read authority-lapsed. Seeding through the real setRole (an owner-token break-glass
// caller, the engine's own internal owner authority) plus a real bind keeps the fixture on the production
// path rather than writing role:sub: keys by hand.
export async function bindApprovalPrincipals(dobj: SchedulerDO, principals: readonly { email: string; subject: string; role: Role }[]): Promise<void> {
  const bootstrap = { method: "token" as const, email: null, subject: null, role: "owner" as Role, groups: [] };
  for (const p of principals) {
    await dobj.setRole({ email: p.email, role: p.role }, bootstrap);
    await dobj.roleForCaller({ method: "access", email: p.email, subject: p.subject, groups: [] });
  }
}

// ---- Due-time index helpers (mirror the DO's private index maintenance) --------------------
// The DO maintains a SECONDARY due-time index (due:<pad16(nextRunAt)>:<id>) so due() reads only the
// due candidates (O(due), not O(N)). pad16 is the SAME left-pad the DO uses; the keys sort
// lexicographically == chronologically. These mirror the DO's private logic so a TEST that sets up
// state by writing dp: DIRECTLY (the existing backdate pattern) keeps the index consistent, exactly
// as the production write path (persistDownpipeState) would. Using putState everywhere a test mutates a
// dp: record means the tests exercise the index the way production drives it, rather than injecting
// drift the reconcile would have to mask. (Drift injection is exercised explicitly, on purpose, in the
// reconciliation test below.)
export const DUE_INDEX_PREFIX = "due:";
export function pad16(epochMs: number): string {
  return String(epochMs).padStart(16, "0");
}
type IndexableState = { config: { id: string; enabled: boolean }; nextRunAt: number };
function dueIndexKeyFor(ds: IndexableState): string | null {
  if (!ds.config.enabled) return null;
  if (typeof ds.nextRunAt !== "number" || !Number.isFinite(ds.nextRunAt)) return null;
  return `${DUE_INDEX_PREFIX}${pad16(ds.nextRunAt)}:${ds.config.id}`;
}
// syncDueIndex re-derives a downpipe's due: index entry from its CURRENT stored dp: state, deleting any
// other due:*:<id> entry first so a backdated nextRunAt does not leave a stale future-keyed entry. It is
// what a test calls AFTER mutating a dp: record directly in storage, so the index stays consistent with
// the dp: truth exactly as the production write path (persistDownpipeState) keeps it. Without this, a raw
// storage.put("dp:...") that changes nextRunAt would leave the index pointing at the OLD time (injected
// drift), which the reconcile would eventually heal but which would make a single-tick due() check flaky.
export async function syncDueIndex(storage: MockStorage, id: string): Promise<void> {
  // Drop EVERY existing index entry for this id (there is at most one, but a range delete is robust to
  // a prior backdate that wrote a different-timed key).
  const existing = await storage.list<unknown>({ prefix: DUE_INDEX_PREFIX });
  for (const k of existing.keys()) {
    if (k.endsWith(`:${id}`)) await storage.delete(k);
  }
  const ds = storage.rawGet<IndexableState>(`dp:${id}`);
  if (!ds) return;
  const key = dueIndexKeyFor(ds);
  if (key !== null) await storage.put(key, 1);
}

// seedDueIndex writes a downpipe's due: index entry DIRECTLY from its stored dp: state, WITHOUT the
// list-scan-and-delete that syncDueIndex does. It is for the initial seeding of a fresh fleet (no prior
// index entry exists, so there is nothing to delete), and it avoids the O(N^2) cost of calling
// syncDueIndex once per id in a large seed loop (each syncDueIndex call would prefix-scan the whole due:
// index seeded so far). The result is identical to syncDueIndex on a fresh fleet.
export async function seedDueIndex(storage: MockStorage, id: string): Promise<void> {
  const ds = storage.rawGet<IndexableState>(`dp:${id}`);
  if (!ds) return;
  const key = dueIndexKeyFor(ds);
  if (key !== null) await storage.put(key, 1);
}

// stubFetch is a thin wrapper so tests can drive the HTTP surface of the DO the same way
// the router would, without any network.
export function stubFetch(dobj: SchedulerDO, method: string, path: string, body?: unknown): Promise<Response> {
  const url = `https://scheduler.internal${path}`;
  const init: RequestInit = {
    method,
    headers: body !== undefined ? { "content-type": "application/json" } : {},
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  };
  return dobj.fetch(new Request(url, init));
}

// ---- Config helpers -----------------------------------------------------------------------
export const BASE_SOURCE = { type: "kv" as const, binding: "KV_test", include: [], exclude: [] };

export function makeConfig(id: string, overrides: Partial<DownpipeConfig> = {}): DownpipeConfig {
  return {
    id,
    name: `Test pipe ${id}`,
    cadenceSeconds: 3600,
    enabled: true,
    source: BASE_SOURCE,
    ...overrides,
  };
}
