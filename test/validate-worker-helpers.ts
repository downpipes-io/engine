// Shared fixtures for the validate-worker suite (split out of test/validate-worker.ts). These
// builders are imported by each area module (http / cron / adapter /
// digest) AND by the thin orchestrator; the assertions themselves live in the area modules. No
// network, no deploy. The `ok` counter is shared so the orchestrator can report one total.

import type { Env } from "../src/env.d.ts";
import type { DownpipeState } from "../src/sched/scheduler-do.ts";

let failures = 0;
export function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
export function failureCount(): number {
  return failures;
}

// ---- minimal stub types -------------------------------------------------------------------

// A minimal DurableObjectStub whose fetch() returns a predefined Response.
export function makeSchedulerStub(fetchFn: (url: string, init?: RequestInit) => Promise<Response>): DurableObjectStub {
  return {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      return fetchFn(url, init);
    },
  } as unknown as DurableObjectStub;
}

// Build a minimal Env with a SCHEDULER namespace that returns the given stub for any
// idFromName/get call.
export function makeEnv(stub: DurableObjectStub, extra?: Partial<Env>): Env {
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  return {
    SCHEDULER: namespace,
    ...extra,
  } as unknown as Env;
}

// A scheduler stub that simply echoes the /health-like response the router uses; enough to
// let handleAdmin respond to the /admin/health path without auth.
export function healthStub(): DurableObjectStub {
  return makeSchedulerStub(async (_url: string) => new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } }));
}

// dueState builds a structurally-valid DownpipeState (the shape the DO returns from /due and the
// run driver consumes). The source binding name is parameterised so a test can point it at a real
// (absent) binding for the cron happy-path, or at a RESERVED_BINDINGS member for the guard test.
export function dueState(id: string, sourceBinding: string): DownpipeState {
  return {
    config: {
      id,
      name: `dp ${id}`,
      cadenceSeconds: 3600,
      enabled: true,
      source: { type: "kv", binding: sourceBinding, include: [], exclude: [] },
    },
    nextRunAt: 0,
    lastRunId: null,
    inFlight: false,
  };
}

// A recorded call to the scheduler DO: the path the worker fetched and the parsed JSON body (if any).
export interface RecordedCall {
  path: string;
  body: unknown;
}

// makeCronScheduler returns a scheduler stub that drives ONE due downpipe through the real cron
// reconciliation and RECORDS every path the driver touches (so a test can assert the ordered
// /tick -> /due -> /trigger -> /complete sequence). It answers exactly the routes drive() reaches:
//  - POST /tick           -> ok (the DO advances its timers)
//  - GET  /due            -> { due: [the one due downpipe] }
//  - GET  /dest-config    -> { config: null } (no console-set destination -> env fallback; drive()
//                            reads it once per tick and passes it to every archive-touching pass)
//  - POST /trigger        -> { runId, index, prevRunId } (allocates the run, so the seal is reached;
//                            a { skipped } here would make runDownpipe early-return and never seal)
//  - POST /complete       -> ok (the terminal reconciliation drive() or sealRun posts)
//  - POST /reconcile-alerts -> { alerts: [], pendingTransitionIds: [] } (no alertable downpipe ->
//                            the routing loop makes NO fetch, and the /alerts-delivered feedback
//                            call is skipped, so the whole drive() promise resolves network-free)
//  - POST /reconcile-replication-alerts -> { emissions: [], pendingTransitionIds: [] } (3-2-1: no
//                            fan-out downpipe, so no replication-health alert and no two-phase
//                            /replication-alerts-delivered feedback call this tick)
//  - POST /expiry/reconcile -> { emissions: [] } (contract section 4: no tracked expiry items ->
//                            no credential-expiry notifications this tick, so no further round-trip)
//  - POST /restore-tests-due -> { due: [] } (contract section 5: no downpipe due for a scheduled
//                            restore test this tick, so the drill path is not reached)
//  - POST /notify/digest-due -> { batches: [] } (contract section 2: no digest window has elapsed this
//                            tick, so the flush delivers nothing and posts NO /notify/digest-sent and
//                            fetches NO /notify/channel, keeping the cron network-free)
// - GET  /push-config    -> { record: null } (SIEM-PUSH-DESIGN.md: no push destination
//                            configured -> the drain is a silent opt-in no-op, no further push round-trip)
// The `path` recorded is the URL pathname (doURL builds https://scheduler.internal<path>), so the
// assertions match on "/trigger" etc. without caring about the ignored host.
export function makeCronScheduler(due: DownpipeState[], trigger: { runId: string; index: number; prevRunId: string | null }): {
  stub: DurableObjectStub;
  calls: RecordedCall[];
} {
  const calls: RecordedCall[] = [];
  const stub = makeSchedulerStub(async (url: string, init?: RequestInit) => {
    const path = new URL(url).pathname;
    let body: unknown = undefined;
    if (typeof init?.body === "string") {
      try {
        body = JSON.parse(init.body);
      } catch {
        body = init.body;
      }
    }
    calls.push({ path, body });
    // Single-flight tick lease: drive() acquires it at the top of the tick and releases it at the end.
    // This stub grants the lease (a fresh single-flight tick) and accepts the release, so the tick proceeds
    // through the full pass sequence below exactly as before the lease existed.
    if (path === "/tick-lease/acquire") return new Response(JSON.stringify({ acquired: true, token: "tick-lease-test" }), { headers: { "content-type": "application/json" } });
    if (path === "/tick-lease/release") return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
    if (path === "/tick") return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
    if (path === "/due") return new Response(JSON.stringify({ due }), { headers: { "content-type": "application/json" } });
    // The console-set destination read (one per tick): null = no console destination, so the env
    // configuration applies, exactly the pre-feature behaviour the rest of this stub models.
    if (path === "/dest-config") return new Response(JSON.stringify({ config: null }), { headers: { "content-type": "application/json" } });
    if (path === "/trigger") return new Response(JSON.stringify(trigger), { headers: { "content-type": "application/json" } });
    if (path === "/complete") return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
    if (path === "/reconcile-alerts") {
      return new Response(JSON.stringify({ alerts: [], pendingTransitionIds: [] }), { headers: { "content-type": "application/json" } });
    }
    // 3-2-1 replication health: after the alert stream the cron asks for the fan-out downpipes whose
    // proven copy set has degraded or whose lagging copy is about to be evicted. With no replicas
    // configured the DO returns an empty batch (one read), so no notification or two-phase
    // /replication-alerts-delivered feedback round-trip follows.
    if (path === "/reconcile-replication-alerts") {
      return new Response(JSON.stringify({ emissions: [], pendingTransitionIds: [] }), { headers: { "content-type": "application/json" } });
    }
    // Contract section 4: the cron asks for expiry threshold transitions after the alert stream. With
    // no tracked items the DO returns an empty batch (one read), so no notification round-trip follows.
    if (path === "/expiry/reconcile") {
      return new Response(JSON.stringify({ emissions: [] }), { headers: { "content-type": "application/json" } });
    }
    // Contract section 5: the cron asks for downpipes whose scheduled restore test is due. With none
    // due this tick the DO returns an empty list, so the in-account drill path is not reached.
    if (path === "/restore-tests-due") {
      return new Response(JSON.stringify({ due: [] }), { headers: { "content-type": "application/json" } });
    }
    // Contract section 2 (digest flush): the cron asks for the per-channel digest batches whose window
    // has elapsed, passing in nowMs (the DO has no wall clock). With nothing due this tick the DO
    // returns an empty batch list, so the flush delivers nothing and posts no digest-sent.
    if (path === "/notify/digest-due") {
      return new Response(JSON.stringify({ batches: [] }), { headers: { "content-type": "application/json" } });
    }
    // ASVS V14.2.7 (retention prune): the cron asks for the full downpipe list to find those with a
    // retention policy. The test downpipe has NO retention configured, so the pass filters to an empty
    // set and returns after this one list read (no planner, no apply, no audit round-trip).
    if (path === "/downpipes") {
      return new Response(JSON.stringify(due), { headers: { "content-type": "application/json" } });
    }
    // Proactive source-drift pass: the cron computes the missing source set (live env vs roster) and posts
    // it for the edge-trigger. The test env binds no real source, so the due downpipe's binding reads as
    // missing; the DO edge-trigger returns no NEWLY detached here (already-alerted / nothing new), so no
    // alert-routing round-trip (/notify/resolve) follows this tick.
    if (path === "/source-drift/reconcile") {
      return new Response(JSON.stringify({ newlyDetached: [] }), { headers: { "content-type": "application/json" } });
    }
    // Canary backup: the cron asks whether the integrity canary is due (one read per tick). With the
    // bird not due this tick the DO returns due:false, so no flight runs and no /canary/complete
    // round-trip follows (the heavy seal/read/restore stays out of the DO, like the run loop).
    if (path === "/canary/due") {
      return new Response(JSON.stringify({ due: false }), { headers: { "content-type": "application/json" } });
    }
    // cf-config discovery refresh (read-cost control): the cron asks which auto-mode cf-config downpipes
    // have a stale surface-discovery cache. With none due this tick the DO returns an empty list, so the
    // pass probes nothing (no /sources/discovery-config or /cf-config/discovery round-trip follows).
    if (path === "/cf-config/discovery-due") {
      return new Response(JSON.stringify({ due: [] }), { headers: { "content-type": "application/json" } });
    }
    // SIEM audit-log push destination (SIEM-PUSH-DESIGN.md): the drain's config read, one per
    // tick regardless of whether a destination is configured (mirroring the /dest-config read above). null
    // = not configured, so the pass is a silent opt-in no-op and no further push round-trip (/push,
    // /audit/export, /push-record) follows this tick.
    if (path === "/push-config") {
      return new Response(JSON.stringify({ record: null }), { headers: { "content-type": "application/json" } });
    }
    // Any other path is unexpected on the cron seal path; surface it loudly so a future change that
    // adds a DO round-trip does not pass silently with a stale assumption about the call sequence.
    return new Response(JSON.stringify({ unexpected: path }), { status: 500, headers: { "content-type": "application/json" } });
  });
  return { stub, calls };
}

// runScheduled drives the REAL worker.scheduled(event, env, ctx) and awaits the drive() promise the
// handler hands to ctx.waitUntil, returning whether that promise rejected. scheduled() must never
// throw synchronously, and the captured drive() promise must RESOLVE (a rejection would be an
// unhandled crash of the cron invocation), even though the seal itself fails in the test env.
export async function runScheduled(env: Env, worker: { scheduled: (e: ScheduledController, env: Env, ctx: ExecutionContext) => Promise<void> }): Promise<{ scheduledThrew: boolean; waitUntilCaptured: boolean; waitUntilRejected: boolean }> {
  let captured: Promise<unknown> | undefined;
  const ctx = {
    waitUntil: (p: Promise<unknown>) => {
      captured = p;
    },
    passThroughOnException: () => {},
  } as unknown as ExecutionContext;
  let scheduledThrew = false;
  try {
    await worker.scheduled({} as unknown as ScheduledController, env, ctx);
  } catch {
    scheduledThrew = true;
  }
  let waitUntilRejected = false;
  if (captured !== undefined) {
    try {
      await captured;
    } catch {
      waitUntilRejected = true;
    }
  }
  return { scheduledThrew, waitUntilCaptured: captured !== undefined, waitUntilRejected };
}

// ---- helper: call the worker fetch() ----------------------------------------------------
export async function workerFetch(
  path: string,
  init: RequestInit,
  env: Env,
  worker: { fetch: (req: Request, env: Env, ctx: ExecutionContext) => Promise<Response> },
): Promise<Response> {
  // A no-op ExecutionContext stub (the same convention this file uses elsewhere): the fetch paths this
  // helper drives only ever forward to ctx.waitUntil for the background seal, which these cases do not assert.
  const ctx = { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext;
  return worker.fetch(new Request(`https://engine.example${path}`, init), env, ctx);
}

// ---- SECURITY_HEADERS the worker must apply on every admin response --------------------
// cache-control is included here (ASVS V14.3.2): every admin response is authenticated and must
// carry no-store, so it is asserted alongside the transport/content-type headers on every case
// below (preflight, normal reads, the immutable-headers regression, and the 500 error channel).
export const SEC_HEADERS = [
  "strict-transport-security",
  "x-content-type-options",
  "referrer-policy",
  "x-frame-options",
  "cache-control",
] as const;

// ---- BASE_SEC_HEADERS the worker must apply on the NON-/admin responses (root + 404) ----------
// The static root banner and the 404 are unauthenticated and carry no account state,
// so they do not need the /admin set's cache-control:no-store or HSTS, but the content-sniffing,
// framing and referrer guards still apply to EVERY response the Worker emits so a non-/admin path is
// never a hole in the hardening. These three are asserted on root + 404 below.
export const BASE_SEC_HEADERS = [
  "x-content-type-options",
  "referrer-policy",
  "x-frame-options",
] as const;
