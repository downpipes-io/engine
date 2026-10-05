// Site faults: one recorder a catch calls, so a caught fault always reaches the support pack.
//
//   catch (e) { noteSiteFault("sched.replica-floor-write", e); }
//
// noteSiteFault is synchronous, does no I/O and never throws. It adds the fault to a ledger held in this
// isolate: per site id, a count, the first and last time, and the last fault class. The ledger is drained at
// the entry point, not at the catch:
//   - the scheduler DO drains into its own storage when each fetch() ends (drainSiteFaultsToStorage);
//   - every other DO, and the Worker, drains to the scheduler DO with one POST /diag/site-faults
//     (drainSiteFaultsToScheduler), from a finally at its fetch() or alarm() entry;
//   - the pack build drains first, then reads GET /site-faults and adds what this isolate still holds.
// A drain writes at most once per SITE_FAULT_FLUSH_MIN_MS per isolate, except when the batch holds a site
// this isolate has not sent before: a first sighting always goes out at the next entry exit.
//
// What is stored: the site id (a key of SITE_FAULT_LEGEND, a constant in engine code), a class from
// SITE_FAULT_CLASSES, two clamped millisecond times and a clamped count. The caught error is read only for
// `name` (compared for equality against a fixed table) and the platform's `overloaded`, `retryable` and
// `remote` booleans. Its message, stack, cause and every other property are never read. The stored map is
// bounded by the size of the legend, because an id outside the legend is dropped at every step.

import { doURL } from "../do-url.ts";
import { isSiteFaultId, SITE_FAULT_LEGEND, type SiteFaultFixClass, type SiteFaultId } from "./site-fault-legend.ts";

export const SITE_FAULT_CLASSES = ["error", "type", "range", "syntax", "abort", "timeout", "quota", "do-overloaded", "do-retryable", "do-remote", "other", "non-error"] as const;
export type SiteFaultClass = (typeof SITE_FAULT_CLASSES)[number];
const SITE_FAULT_CLASS_SET: ReadonlySet<string> = new Set(SITE_FAULT_CLASSES);

export const SITE_FAULTS_KEY = "diag:sitefaults";
export const SITE_FAULT_FLUSH_MIN_MS = 30_000;
const COUNT_CAP = 1_000_000_000;
const TIME_MAX = 8_640_000_000_000_000;

const NAME_CLASS: Readonly<Record<string, SiteFaultClass>> = {
  Error: "error",
  TypeError: "type",
  RangeError: "range",
  SyntaxError: "syntax",
  AbortError: "abort",
  TimeoutError: "timeout",
  QuotaExceededError: "quota",
};

export interface SiteFaultRow {
  count: number;
  firstAt: number;
  lastAt: number;
  lastCls: SiteFaultClass;
}
export type SiteFaults = Partial<Record<SiteFaultId, SiteFaultRow>>;

// classifySiteFault maps a caught value to a closed class. It reads `name` only to compare it with the
// keys of NAME_CLASS, and three platform booleans. Nothing is copied from the error.
export function classifySiteFault(e: unknown): SiteFaultClass {
  if (typeof e !== "object" || e === null) return "non-error";
  const r = e as { overloaded?: unknown; retryable?: unknown; remote?: unknown; name?: unknown };
  if (r.overloaded === true) return "do-overloaded";
  if (r.retryable === true) return "do-retryable";
  const name = r.name;
  if (typeof name === "string" && Object.hasOwn(NAME_CLASS, name)) return NAME_CLASS[name] as SiteFaultClass;
  if (r.remote === true) return "do-remote";
  return "other";
}

const clampTime = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.min(Math.floor(v), TIME_MAX) : null);
const clampCount = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) && v >= 1 ? Math.min(Math.floor(v), COUNT_CAP) : null);

function cleanRow(v: unknown): SiteFaultRow | null {
  if (typeof v !== "object" || v === null) return null;
  const r = v as Record<string, unknown>;
  const count = clampCount(r.count);
  const firstAt = clampTime(r.firstAt);
  const lastAt = clampTime(r.lastAt);
  if (count === null || firstAt === null || lastAt === null) return null;
  if (typeof r.lastCls !== "string" || !SITE_FAULT_CLASS_SET.has(r.lastCls)) return null;
  return { count, firstAt: Math.min(firstAt, lastAt), lastAt, lastCls: r.lastCls as SiteFaultClass };
}

// applySiteFaults merges a batch into a stored map. Both inputs are untrusted: an id outside the legend, a
// class outside SITE_FAULT_CLASSES or a malformed number drops that row. Pure; the DO route and the tests use it.
export function applySiteFaults(prior: unknown, batch: unknown): SiteFaults {
  const out: SiteFaults = {};
  const fold = (src: unknown): void => {
    if (typeof src !== "object" || src === null) return;
    for (const [id, v] of Object.entries(src)) {
      if (!isSiteFaultId(id)) continue;
      const row = cleanRow(v);
      if (row === null) continue;
      const cur = out[id];
      out[id] =
        cur === undefined
          ? row
          : {
              count: Math.min(COUNT_CAP, cur.count + row.count),
              firstAt: Math.min(cur.firstAt, row.firstAt),
              lastAt: Math.max(cur.lastAt, row.lastAt),
              lastCls: row.lastAt >= cur.lastAt ? row.lastCls : cur.lastCls,
            };
    }
  };
  fold(prior);
  fold(batch);
  return out;
}

// ---- the isolate ledger ------------------------------------------------------------------------------

const pending = new Map<SiteFaultId, SiteFaultRow>();
const sentFromIsolate = new Set<SiteFaultId>();
let firstSightingPending = false;
let lastFlushAt = 0;
let drainFailedAt = 0;

// noteSiteFault is the recorder a catch calls. Synchronous, no I/O, never throws.
export function noteSiteFault(id: SiteFaultId, err: unknown, cls?: SiteFaultClass): void {
  let c: SiteFaultClass = "other";
  try {
    c = cls !== undefined && SITE_FAULT_CLASS_SET.has(cls) ? cls : classifySiteFault(err);
  } catch {
    // site-fault-waiver: src/admin/site-faults.ts:noteSiteFault:catch:1 -- a throwing getter on the caught value must not stop the count, so the row still lands with class other
  }
  const now = Date.now();
  const cur = pending.get(id);
  pending.set(id, cur === undefined ? { count: 1, firstAt: now, lastAt: now, lastCls: c } : { count: Math.min(COUNT_CAP, cur.count + 1), firstAt: cur.firstAt, lastAt: now, lastCls: c });
  if (!sentFromIsolate.has(id)) firstSightingPending = true;
}

// takeSiteFaultBatch hands the pending rows to a drain and clears them, or returns null when there is nothing
// to send or the flush window is still closed. force opens the window (the pack build uses it).
function takeSiteFaultBatch(now: number, force: boolean): SiteFaults | null {
  if (pending.size === 0) return null;
  const windowOpen = now - lastFlushAt >= SITE_FAULT_FLUSH_MIN_MS;
  // A first sighting skips the window, unless a drain failed inside it: a failing scheduler gets at most one
  // attempt per window from each isolate.
  const firstSighting = firstSightingPending && now - drainFailedAt >= SITE_FAULT_FLUSH_MIN_MS;
  if (!force && !windowOpen && !firstSighting) return null;
  const batch: SiteFaults = Object.fromEntries(pending);
  pending.clear();
  firstSightingPending = false;
  lastFlushAt = now;
  for (const id of Object.keys(batch)) if (isSiteFaultId(id)) sentFromIsolate.add(id);
  return batch;
}

// returnSiteFaultBatch puts a batch back after a failed drain, so the next entry exit retries it.
function returnSiteFaultBatch(batch: SiteFaults, now: number): void {
  const merged = applySiteFaults(Object.fromEntries(pending), batch);
  pending.clear();
  for (const [id, row] of Object.entries(merged)) if (isSiteFaultId(id) && row !== undefined) pending.set(id, row);
  for (const id of Object.keys(batch)) if (isSiteFaultId(id)) sentFromIsolate.delete(id);
  firstSightingPending = true;
  drainFailedAt = now;
}

// hasPendingSiteFaults lets an entry point skip the drain (and the stub lookup) when nothing is held.
export function hasPendingSiteFaults(): boolean {
  return pending.size > 0;
}

// peekSiteFaults is what this isolate holds and has not yet drained. The pack build adds it to the stored rows.
export function peekSiteFaults(): SiteFaults {
  return Object.fromEntries(pending);
}

interface SiteFaultStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
}

// drainSiteFaultsToStorage is the scheduler DO's own drain: one read and one write of SITE_FAULTS_KEY.
export async function drainSiteFaultsToStorage(storage: SiteFaultStorage, force = false, now = Date.now()): Promise<void> {
  const batch = takeSiteFaultBatch(now, force);
  if (batch === null) return;
  try {
    await storage.put(SITE_FAULTS_KEY, applySiteFaults(await storage.get(SITE_FAULTS_KEY), batch));
  } catch (e) {
    returnSiteFaultBatch(batch, now);
    noteSiteFault("diag.site-fault-drain-storage", e);
  }
}

// drainSiteFaultsToScheduler is the drain for every other DO and for the Worker. One POST when there is
// something to send and the window is open; a failed POST keeps the batch for the next entry exit.
export async function drainSiteFaultsToScheduler(scheduler: DurableObjectStub | null, force = false, now = Date.now()): Promise<void> {
  if (scheduler === null) return;
  const batch = takeSiteFaultBatch(now, force);
  if (batch === null) return;
  try {
    const r = await scheduler.fetch(doURL("/diag/site-faults"), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ faults: batch }) });
    if (!r.ok) {
      returnSiteFaultBatch(batch, now);
      noteSiteFault("diag.site-fault-drain-post", null, "do-remote");
    }
  } catch (e) {
    returnSiteFaultBatch(batch, now);
    noteSiteFault("diag.site-fault-drain-post", e);
  }
}

// schedulerOf resolves the scheduler stub from a DO's env, or null when the binding is absent (tests, and
// deployments that have not bound it). Kept here so a DO does not import the admin router helpers.
export function schedulerOf(env: { SCHEDULER?: DurableObjectNamespace }): DurableObjectStub | null {
  const ns = env.SCHEDULER;
  if (ns === undefined || ns === null) return null;
  return ns.get(ns.idFromName("account-scheduler"));
}

// ---- the scheduler DO routes -------------------------------------------------------------------------

export async function handleSiteFaultPost(storage: SiteFaultStorage, req: Request): Promise<{ ok: boolean }> {
  let body: unknown;
  try {
    body = await req.json();
  } catch (e) {
    noteSiteFault("diag.site-fault-post-body", e);
    return { ok: false };
  }
  const faults = typeof body === "object" && body !== null ? (body as { faults?: unknown }).faults : undefined;
  await storage.put(SITE_FAULTS_KEY, applySiteFaults(await storage.get(SITE_FAULTS_KEY), faults));
  return { ok: true };
}

export async function readSiteFaults(storage: SiteFaultStorage): Promise<{ faults: SiteFaults }> {
  return { faults: applySiteFaults(await storage.get(SITE_FAULTS_KEY), undefined) };
}

// ---- the pack section --------------------------------------------------------------------------------

export interface SiteFaultPackRow {
  id: SiteFaultId;
  subsystem: string;
  what: string;
  fixClass: SiteFaultFixClass;
  cls: SiteFaultClass;
  count: number;
  firstAt: string;
  lastAt: string;
}

// fetchSiteFaults reads the stored rows, adds what this isolate still holds, and joins each id to its legend
// entry. Newest first.
export async function fetchSiteFaults(scheduler: DurableObjectStub): Promise<SiteFaultPackRow[]> {
  const r = await scheduler.fetch(doURL("/site-faults"), { method: "GET" });
  const j = (await r.json()) as { faults?: unknown };
  const merged = applySiteFaults(j?.faults, peekSiteFaults());
  const rows: SiteFaultPackRow[] = [];
  for (const [id, row] of Object.entries(merged)) {
    if (!isSiteFaultId(id) || row === undefined) continue;
    const legend = SITE_FAULT_LEGEND[id];
    rows.push({ id, subsystem: legend.subsystem, what: legend.what, fixClass: legend.fixClass, cls: row.lastCls, count: row.count, firstAt: new Date(row.firstAt).toISOString(), lastAt: new Date(row.lastAt).toISOString() });
  }
  return rows.sort((a, b) => (a.lastAt < b.lastAt ? 1 : a.lastAt > b.lastAt ? -1 : 0));
}
