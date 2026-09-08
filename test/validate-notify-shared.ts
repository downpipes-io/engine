// Shared fixtures and helpers for the validate-notify suite (split out of validate-notify.ts so each area
// module stays under the size cap). Every helper here is byte-identical to the original; the only addition
// is a shared failure counter so the orchestrator can report the aggregate pass/fail across the extracted
// groups.

import {
  ALERT_COOLDOWN_MS,
  STALE_CADENCE_MULTIPLE,
  DIGEST_WINDOW_MS,
  type DetectionInput,
  type MinRun,
  type AlertState,
  type PendingDigestEntry,
} from "../src/notify.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { DownpipeConfig } from "../src/sched/scheduler-do.ts";
import { encodeCaller, type Caller, type Role } from "../src/admin/identity.ts";

// The shared failure counter. Each extracted group calls ok(); the orchestrator reads
// getFailures() at the end to decide the suite verdict (preserving the original exit behaviour).
let failures = 0;
export function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
export function getFailures(): number {
  return failures;
}

import { MockStorage } from "./mock-storage.ts";
export { MockStorage };

export function makeScheduler(): { storage: MockStorage; stub: SchedulerDO } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  return { storage, stub: new SchedulerDO(state) };
}

// OWNER_CALLER is the caller header payload the DO's Owner-gated routes accept. The DO
// treats a caller with role "owner" as authorised for Owner-gated mutations (requireOwner
// checks the decoded caller, not the route auth -- defence-in-depth). This mirrors the
// internal header the router sets after verifying an Owner's Access JWT.
export const OWNER_CALLER: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };
export const OWNER_CALLER_HEADER = encodeCaller(OWNER_CALLER);

export function stubFetch(dobj: SchedulerDO, method: string, path: string, body?: unknown, extraHeaders?: Record<string, string>): Promise<Response> {
  const url = `https://scheduler.internal${path}`;
  const headers: Record<string, string> = {
    ...(body !== undefined ? { "content-type": "application/json" } : {}),
    ...(extraHeaders ?? {}),
  };
  const init: RequestInit = {
    method,
    headers,
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  };
  return dobj.fetch(new Request(url, init));
}

// ownerFetch sends a DO fetch that includes the Owner caller header so Owner-gated routes
// (addNotifyChannel, deleteNotifyChannel, setRole, etc.) accept the request.
export function ownerFetch(dobj: SchedulerDO, method: string, path: string, body?: unknown): Promise<Response> {
  return stubFetch(dobj, method, path, body, { "x-downpipe-caller": OWNER_CALLER_HEADER });
}

// callerFetch sends a DO fetch with an arbitrary-role caller header, so the notify DO re-check
// (requireNotifyConfig) can be exercised for a role that lacks notify.config (viewer) and one that
// holds it (operator). The token-fallback method is irrelevant here; only the role drives the cap.
export function callerFetch(dobj: SchedulerDO, role: Role, method: string, path: string, body?: unknown): Promise<Response> {
  const header = encodeCaller({ method: "access", email: `${role}@example.com`, subject: `subject-${role}@example.com`, role, groups: [] });
  return stubFetch(dobj, method, path, body, { "x-downpipe-caller": header });
}

// ---- Config helpers -------------------------------------------------------------------------
export const BASE_SOURCE = { type: "kv" as const, binding: "KV_test", include: [], exclude: [] };

export function makeConfig(id: string, overrides: Partial<DownpipeConfig> = {}): DownpipeConfig {
  return { id, name: `Test pipe ${id}`, cadenceSeconds: 3600, enabled: true, source: BASE_SOURCE, ...overrides };
}

// makeDI builds a DetectionInput for pure classify/shouldAlert tests, accepting only the relevant
// fields and letting the caller focus on the scenario under test.
export function makeDI(opts: {
  enabled?: boolean;
  cadenceSeconds?: number;
  history: MinRun[];
  lastAlertedState?: AlertState;
  lastAlertedAt?: number;
}): DetectionInput {
  return {
    config: {
      id: "test-pipe",
      name: "Test Pipe",
      cadenceSeconds: opts.cadenceSeconds ?? 3600,
      enabled: opts.enabled ?? true,
    },
    history: opts.history,
    ...(opts.lastAlertedState !== undefined ? { lastAlertedState: opts.lastAlertedState } : {}),
    ...(opts.lastAlertedAt !== undefined ? { lastAlertedAt: opts.lastAlertedAt } : {}),
  };
}

// nowMs and a fixed reference epoch used across tests. Captured once at module load: the stale window is
// STALE_THRESHOLD_MS (hours), so even an extremely slow runner cannot push a freshStart() timestamp past
// the stale boundary, which keeps the stale/fresh boundary tests deterministic.
export const NOW = Date.now();
// One hour ago in ms.
export const ONE_HOUR_AGO = NOW - ALERT_COOLDOWN_MS;
// Just inside the stale window: STALE_CADENCE_MULTIPLE * cadence + 1 second.
export const CADENCE = 3600; // seconds, matching makeConfig default
export const STALE_THRESHOLD_MS = CADENCE * 1000 * STALE_CADENCE_MULTIPLE;
// A startedAt that is just barely stale.
export function staleStart(): string {
  return new Date(NOW - STALE_THRESHOLD_MS - 1000).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}
// A startedAt that is fresh (well within cadence).
export function freshStart(): string {
  return new Date(NOW - 60_000).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}

// ---- Digest helpers (shared by the crud and digest groups) ----------------------------------
// DAY_MS / WEEK_MS mirror DIGEST_WINDOW_MS for readability in the window tests.
export const DAY_MS = DIGEST_WINDOW_MS.daily;
export const WEEK_MS = DIGEST_WINDOW_MS.weekly;

// isoAt formats an epoch-ms as the RFC-3339 millis form the emissions use, so a seeded `at` round-trips
// through Date.parse in the flush exactly as a real deferral would.
export function isoAt(ms: number): string {
  return new Date(ms).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}

// mkPending builds a PendingDigestEntry literal for the PURE groupDigestDue/summariseDigest tests
// (no storage needed; these functions are storage-free).
export function mkPending(over: Partial<PendingDigestEntry> & { seq: number; atMs: number }): PendingDigestEntry {
  const { atMs, ...rest } = over;
  return {
    channelId: "c1",
    channelKind: "email",
    period: "daily",
    event: "backup-success",
    severity: "info",
    downpipeId: "p1",
    downpipeName: "Prod KV",
    detail: "Prod KV backup succeeded",
    at: isoAt(atMs),
    ...rest,
  };
}
