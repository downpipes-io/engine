import { CHANGE_HEADER } from "./admin/change-ref.ts";
import { flushDroppedWrites, noteDroppedWrite } from "./admin/diag-writer.ts";
import { classifyDestProbeError, recordCorsRejection, recordDestProbeFaults, recordDispatchFault, routeFamilyOf } from "./admin/dispatch-faults.ts";
import { handleMetricsRoute } from "./admin/metrics.ts";
import { errId } from "./admin/passkey.ts";
import { type AdminRuntime, doURL, handleAdmin, schedulerStub } from "./admin/router.ts";
import { STEPUP_HEADER } from "./admin/router-core.ts";
import { handleScim } from "./admin/scim.ts";
import { handleSupportPull } from "./admin/support-ingest.ts";
import { drainCronDestProbeFaults } from "./cron/cron-fault-ledger.ts";
import { drive } from "./cron/drive.ts";
import { runCanaryIfDue } from "./cron/notify-passes.ts";
import { sealRun, selectSealDestination } from "./cron/seal-dispatch.ts";
import type { Env } from "./env.d.ts";
import { ENGINE_VERSION } from "./format/version.ts";
import { configureLog, log } from "./log.ts";
import { RateLimitDO } from "./sched/ratelimit-do.ts";
import { type DownpipeState, SchedulerDO } from "./sched/scheduler-do.ts";
import { buildAdapter } from "./seal/adapters.ts";
import { budgetFromEnv } from "./seal/budget.ts";
import { RunSealDO } from "./seal/runstate.ts";

// The engine Worker entry. fetch serves the in-account admin API the console calls;
// scheduled is the cron driver that runs due downpipes out of the scheduler Durable
// Object (the seal never runs inside the DO, design F11). The cron driver body (drive)
// and its per-pass helpers live in ./cron/* (moved out to keep this entry thin); this
// module keeps the default export, the fetch/scheduled wiring, the request chrome, and
// the re-exports the wrangler entry + the validators depend on.

// corsHeaders allowlists exactly the configured console origin (no wildcard), so the
// in-account SPA can call the admin API cross-origin while no other origin can. The
// allow-list of headers must include every custom header the console's client actually
// sets (sourced from their own exported constants, not re-literalled here, so the two
// can't drift apart again): STEPUP_HEADER on the gatedFetch step-up retry and CHANGE_HEADER
// on a change-controlled mutation. Omitting either silently blocks that request in the
// browser's own preflight before it ever reaches this Worker.
// HEALTH_CORS is the ONE exemption from the origin allowlist, and it exists to make a CONSOLE_ORIGIN
// misconfiguration DIAGNOSABLE (G122/G145).
//
// THE BUG IT FIXES. /admin/health is the console's independent liveness probe, and the console's whole CORS
// fingerprint rests on it: "the unauthenticated health probe was reachable WHILE the data call was blocked" is
// what separates "set CONSOLE_ORIGIN on the engine" from "your engine is down". But /admin/health was behind the
// SAME single origin-equality gate as every data route. So when CONSOLE_ORIGIN was wrong -- THE EXACT SCENARIO --
// the browser blocked the health probe too, the probe threw, and the console recorded engine-unreachable, which is
// byte-identical to what a genuinely dead engine records. The one class that tells support to fix CONSOLE_ORIGIN
// was UNREACHABLE IN THE STATE THAT NEEDS IT, and reachable only in a state where the advice is wrong.
//
// WHY THIS IS SAFE. /admin/health is the single UNAUTHENTICATED route on the surface: it is answered above the
// authorise() gate, it reads no request state, it touches no DO, and its entire body is the constant
// {ok:true, service:"downpipe-engine"}. There is no credential to steal and no customer value to leak, so a
// wildcard origin discloses exactly one bit that a TCP connect already discloses: this engine is up. Crucially it
// carries NO access-control-allow-credentials, so the browser will not attach the session cookie to it and it
// cannot be used as a confused-deputy read of any authenticated state. Wildcard and credentials are mutually
// exclusive by the CORS spec, which is precisely the property being relied on here.
const HEALTH_CORS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, OPTIONS",
  // Deliberately NO access-control-allow-credentials, and deliberately no `vary: Origin` (the answer does not
  // vary by origin). The console probes this route WITHOUT credentials for the same reason.
};

// isHealthPath is the exact-match test for the one exempt route. An exact compare, never a prefix: a prefix would
// hand the wildcard to any future /admin/health-* route that might not deserve it.
function isHealthPath(pathname: string): boolean {
  return pathname === "/admin/health";
}

// corsHeaders allowlists exactly the configured console origin (no wildcard) for every route but the health probe.
function corsHeaders(req: Request, env: Env): Record<string, string> {
  if (isHealthPath(new URL(req.url).pathname)) return HEALTH_CORS;
  const origin = env.CONSOLE_ORIGIN;
  if (!origin || req.headers.get("Origin") !== origin) return {};
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": `authorization, content-type, ${STEPUP_HEADER}, ${CHANGE_HEADER}`,
    "access-control-allow-credentials": "true",
    // Cache the preflight result for a day (§12): the allowed methods/headers/origin for the admin
    // API are static, so the browser need not re-issue an OPTIONS preflight on every cross-origin
    // call. 86400 is the common upper bound browsers honour; it only caches the preflight, never a
    // credentialed response (those still carry cache-control:no-store via SECURITY_HEADERS).
    "access-control-max-age": "86400",
    vary: "Origin",
  };
}

// securityHeaders returns the standard hardening headers for engine admin responses (NC-09,
// NC-10, NC-17). These are applied in addition to CORS, not instead of it: CORS governs
// cross-origin access; these govern transport and content-type safety. They do not change
// the CORS model or the two-channel error shape (401 plaintext / 403 JSON / 200 JSON).
//
// cache-control:no-store + pragma:no-cache cover ASVS V14.3.2: every /admin response is
// authenticated and may carry sensitive data (whoami returns the verified email + role; audit,
// history and status return account state), so a browser back-button, a disk cache, or any
// intermediary must never retain it. Applying them to the whole SECURITY_HEADERS set means every
// admin route (including the OPTIONS preflight and the 401/403 error channels) carries them
// uniformly, the same way the existing transport/content-type headers do.
const SECURITY_HEADERS: Record<string, string> = {
  "strict-transport-security": "max-age=63072000; includeSubDomains",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "cache-control": "no-store",
  pragma: "no-cache",
};

// BASE_SECURITY_HEADERS is the subset applied to the NON-/admin responses: the static root
// banner and the 404 (NC-09/NC-17). These responses are unauthenticated and carry no account
// state, so they do not need the /admin set's cache-control:no-store + HSTS (HSTS is governed at
// the edge/CF for the whole host anyway); but the content-type-sniffing, framing and referrer
// guards still apply to EVERY response the Worker emits, so a non-/admin path is never a hole in
// the hardening. They are applied via the same copy-into-a-fresh-Headers + new-Response pattern
// the /admin path uses, so the rule is uniform even though these responses are built inline.
const BASE_SECURITY_HEADERS: Record<string, string> = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
};

// withBaseSecurity copies a freshly-built response into a new Response carrying the base hardening
// headers. The root/404 responses are constructed inline (their headers are already mutable), but
// routing them through the same fresh-Headers pattern as the /admin path keeps one way of applying
// the headers and is robust if either response is ever changed to forward an immutable-headers body.
function withBaseSecurity(resp: Response): Response {
  const headers = new Headers(resp.headers);
  for (const [k, v] of Object.entries(BASE_SECURITY_HEADERS)) headers.set(k, v);
  return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers });
}

// withSecurity is withBaseSecurity's counterpart for non-/admin responses that ARE authenticated and
// DO carry account state (the /support/* pull routes): it copies the FULL SECURITY_HEADERS set, the
// same one /admin/* gets, so cache-control:no-store + pragma:no-cache cover these responses too
// (ASVS V14.3.2) instead of leaving them on the weaker base set whose rationale does not apply to them.
function withSecurity(resp: Response): Response {
  const headers = new Headers(resp.headers);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
  return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers });
}

// problemBody builds an RFC 9457 (application/problem+json) error body. It carries the standard
// `type`/`title`/`status` members AND keeps the legacy `error` field so existing console parsing and
// the validators (which assert body.error) are UNCHANGED: RFC 9457 explicitly permits extension
// members, so `error` rides alongside the standard ones. `type` is a stable urn the engine owns; it is
// NOT a dereferenceable URL (the admin API is private/no-public-hostname), which RFC 9457 allows.
function problemBody(status: number, error: string, title: string, extra?: Record<string, unknown>): string {
  return JSON.stringify({ type: `urn:downpipe:error:${error.replace(/\s+/g, "-")}`, title, status, error, ...(extra ?? {}) });
}

// OBS-1: the request-correlation header the engine echoes on EVERY response. The coarse `err:XXXXXXXX`
// id in the operational log is FNV-1a of ClassName:message and is irreversible, so on its own an operator
// staring at a 500 in the browser has no thread back to the matching `wrangler tail` line. RESPONSE_ID
// is a per-request correlation id that is (a) echoed as a response header on every path and (b) logged
// alongside the err-id on the catch paths, so a 500 the operator sees can be tied to exactly one log line.
// It is deliberately NON-SENSITIVE: it is the Cloudflare edge ray id when present (cf-ray, which is already
// in the response headers and CF's own logs, so it correlates the engine log to the platform's request log
// for free), else a freshly minted opaque `dpr-<uuid>` for local/dev where there is no edge ray. It carries
// no account state, no token, no member identity -- only a request handle -- so echoing it leaks nothing.
const RESPONSE_ID_HEADER = "x-downpipe-request-id";
function correlationId(req: Request): string {
  const ray = req.headers.get("cf-ray");
  return ray !== null && ray.length > 0 ? ray : `dpr-${crypto.randomUUID()}`;
}

// withCorrelation rebuilds a response carrying the correlation header without disturbing the existing body,
// status or any header a route already set. It mirrors the fresh-Headers + new-Response pattern the chrome
// already uses so a response forwarded from the DO (immutable headers) can still receive the header.
function withCorrelation(resp: Response, cid: string): Response {
  const headers = new Headers(resp.headers);
  headers.set(RESPONSE_ID_HEADER, cid);
  return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers });
}

// noteDispatchFault is the ONE guarded sink for the last-resort dispatch recorders (G072). It exists because a
// recorder that can throw is worse than no recorder: schedulerStub(env) THROWS when the SCHEDULER binding is
// absent (a partially-bound env), and these call sites are inside CATCH blocks -- so an unguarded throw here
// escapes the last-resort handler as an unhandled crash, i.e. the observation breaking the exact fault it
// exists to observe. Everything (the stub resolution, the post, and ctx.waitUntil itself) is wrapped, and the
// caller's response is never touched.
function noteDispatchFault(env: Env, ctx: ExecutionContext, row: Parameters<typeof recordDispatchFault>[1]): void {
  try {
    ctx.waitUntil(recordDispatchFault(schedulerStub(env), row));
  } catch {
    /* best-effort: a diagnostic write must never break, delay or fail the request path it is observing */
  }
}

// handleReady serves GET /ready: a fast, unauthenticated liveness-plus-readiness signal the platform/uptime
// checks can poll without touching the authenticated /admin surface. It carries the base hardening headers
// and reports the service + version; it never reads state. The version is disclosed deliberately: the engine
// runs in the customer's own account (not a shared multi-tenant host), so the version is an operability aid for
// the operator's own uptime checks rather than a fingerprinting aid for an external attacker.
function handleReady(): Response {
  return withBaseSecurity(
    new Response(JSON.stringify({ status: "ok", service: "downpipe-engine", version: ENGINE_VERSION }), {
      headers: { "content-type": "application/json" },
    }),
  );
}

// handleScimRoute serves /scim/v2: the minimal SCIM 2.0 deprovision facade (admin/scim.ts). It has its OWN
// dedicated bearer (SCIM_BEARER_TOKEN), separate from the console auth model, so it runs with no CORS
// (server-to-server) and the base hardening headers. A throw is caught and logged coarsely (no member email
// or secret reaches the client), returning a generic hardened 500.
async function handleScimRoute(req: Request, env: Env, cid: string, ctx: ExecutionContext): Promise<Response> {
  try {
    return withBaseSecurity(await handleScim(req, env, (task: Promise<unknown>) => ctx.waitUntil(task)));
  } catch (e) {
    log("error", `scim request failed [err:${errId(e)} scim-dispatch] cid=${cid}`);
    // G072: "our IdP SCIM deprovision keeps 500ing" -- an offboarding that silently does not happen is a
    // SECURITY event, and the pack carried no trace of it whatsoever.
    noteDispatchFault(env, ctx, { surface: "scim", routeFamily: "identity", errId: errId(e), httpStatus: 500 });
    return withBaseSecurity(new Response(problemBody(500, "internal error", "Internal error", { requestId: cid }), { status: 500, headers: { "content-type": "application/problem+json" } }));
  }
}

// postFailedCompletion resolves a manual (run-now) run that failed BEFORE sealing: it posts the FAILED
// /complete that records the honest cause and frees the in-flight lease. It is the single completion sink for
// both pre-seal failure arms below (a destination-config read that threw; every destination unreachable).
//
// G224. When the scheduler DO is unavailable -- which is usually the very reason the dispatch failed -- a
// failure here must not vanish silently: a downpipe dangling in flight until the 30-minute lease expires
// would otherwise show only a STALL (downpipes[].stalled) with no recorded cause, indistinguishable from a
// genuinely wedged seal.
//
// This post is CHECKED (admin/diag-writer.ts, the G100/G331 protocol): a throw or a non-2xx NOTES the closed
// kind "run-completion" in the isolate-local pending tally, which is flushed to the DO's bounded
// droppedWrites aggregate on the next diagnostic write that succeeds -- i.e. the moment the DO comes back,
// which is when the pack is generated. It stays FAIL-OPEN (it never throws, and the caller's path is
// unchanged); it only stops the loss from being invisible.
//
// NO-CUSTODY: the only thing recorded is {kind: count}. The rejection text, the destination, the bucket and the
// downpipe id are never carried by the record -- this notes THAT a completion was lost, never what was in it.
export async function postFailedCompletion(scheduler: DurableObjectStub, body: { id: string; index: number; error: string }): Promise<void> {
  try {
    const resp = await scheduler.fetch(doURL("/complete"), {
      method: "POST",
      body: JSON.stringify({ id: body.id, runId: "", index: body.index, status: "failed", error: body.error }),
    });
    if (resp.ok) {
      // The completion landed. Piggy-back the flush of any EARLIER loss this isolate is still holding, so a
      // gap recorded during an outage is reported as soon as the DO is healthy again.
      await flushDroppedWrites(scheduler);
      return;
    }
  } catch {
    // a transport throw is the same loss as a non-2xx: counted below
  }
  noteDroppedWrite("run-completion");
  await flushDroppedWrites(scheduler);
}

// buildAdminRuntime assembles the run-now capabilities the admin handler closes over. sealNow drives a manual
// POST /admin/trigger seal in this invocation's background (ctx.waitUntil), so a manual run genuinely writes
// bytes instead of stranding the downpipe in flight (XC-B1/B2); canaryNow flies the canary immediately for
// POST /admin/canary/run. The seal path lives here (not the router) so the admin module needs no seal wiring
// and there is no import cycle.
//
// waitUntil is the raw ctx.waitUntil capability, exposed here rather than only through the
// task-specific sealNow/canaryNow closures: the pre-auth passkey ceremony runs before RouterCtx exists and
// needs to keep its own diagnostic writes (recordPasskeyOutcome, fireSignInContextCheck) alive past the
// response, the same way sealNow and canaryNow already keep THEIR background work alive. It is a straight
// pass-through of ctx.waitUntil, bound so a caller need not know ctx exists.
function buildAdminRuntime(env: Env, ctx: ExecutionContext): AdminRuntime {
  return {
    waitUntil: (task: Promise<unknown>) => ctx.waitUntil(task),
    // The console-set destination is resolved INSIDE the background task (one DO read) so the manual run
    // writes through exactly the destination a cron run would. A read fault must fail the run LOUDLY here
    // (posting the failed completion to free the lease) rather than silently writing to the env fallback and
    // splitting the archive across stores.
    sealNow: (state: DownpipeState, t: { runId: string; index: number; prevRunId: string | null }) =>
      ctx.waitUntil(
        (async () => {
          // Same FAILOVER selection the cron driver uses, so a manual run also falls over to a healthy
          // destination. The run was already triggered (the in-flight row exists), so a resolution fault or
          // an all-down result resolves THAT row failed rather than leaving it dangling.
          let sel: Awaited<ReturnType<typeof selectSealDestination>>;
          try {
            sel = await selectSealDestination(env, schedulerStub(env), state);
          } catch (e) {
            log("error", `run ${state.config.id} (${t.runId}) failed before sealing: ${(e as Error).message}`);
            // G151: the run row says only "destination configuration unreadable" and names no destination and
            // no cause. The throw KNOWS which it was (a destination record deleted under a live downpipe, a
            // rotated CONFIG_WRAP_KEY that no credential will open under, a DO read that faulted): classify it
            // to a closed reason and file it against the downpipe's PINNED destination, so support can tell a
            // healthy-but-unreadable destination from a genuinely broken one. The message is discarded.
            const pinned = state.config.destinationId;
            if (typeof pinned === "string" && pinned !== "") {
              await recordDestProbeFaults(schedulerStub(env), [{ id: pinned, reason: classifyDestProbeError(e) }]);
            }
            await postFailedCompletion(schedulerStub(env), { id: state.config.id, index: t.index, error: "destination configuration unreadable" });
            return;
          }
          if ("allDown" in sel) {
            // G151/G133 (the ALL-DOWN half): recording a GUESSED reason would be worse than recording none
            // (support would chase the wrong system with confidence), so G133 captures the reason AT the
            // probe, into the cron ledger's isolate-local rows; this drains them so the RUN-NOW path records
            // the same per-destination causes the cron tick does, instead of leaving them to be discarded by
            // the next tick's reset.
            // The drain carries the accumulator's own refusal count out with the rows (G325): on a fleet
            // wider than DEST_PROBE_MAX the destinations it refused are the ones this very message --
            // "all destinations unreachable" -- is about, and they never reach the DO by any other route.
            const drained = drainCronDestProbeFaults();
            await recordDestProbeFaults(schedulerStub(env), drained.rows, drained.refusedUpstream);
            await postFailedCompletion(schedulerStub(env), { id: state.config.id, index: t.index, error: "all destinations unreachable" });
            return;
          }
          await sealRun(env, state, t, budgetFromEnv(env), sel.destConfig, sel.destinationId);
        })(),
      ),
    // canaryNow drives the flight in this invocation's background so the operator sees a fresh result without
    // waiting for the next cron tick. It is fully fail-open (runCanaryIfDue never throws past this guard) and
    // touches only the isolated _CANARY/ namespace, so a manual flight can never affect a real backup.
    canaryNow: () =>
      ctx.waitUntil(
        runCanaryIfDue(env, schedulerStub(env)).catch(async (e) => {
          log("error", `canary fly-now failed: ${(e as Error).message}`);
          // G072: a manual canary that dies leaves the operator staring at a stale bird with no cause anywhere.
          await recordDispatchFault(schedulerStub(env), { surface: "canary-manual", errId: errId(e) });
        }),
      ),
  };
}

// handleAdminRoute serves the /admin surface: it resolves CORS, answers the OPTIONS preflight, builds the
// run-now runtime, and dispatches to handleAdmin under a last-resort try/catch (ASVS V16.3.4 + V16.5.4) so an
// unexpected throw never escapes to the Cloudflare runtime unlogged. The success and error paths both rebuild
// the response into a fresh, mutable Headers carrying CORS + the hardening headers uniformly (V14.3.2
// cache-control:no-store), and the success path appends the idle-slide cookie (V7.3.1) when one was minted.
async function handleAdminRoute(req: Request, env: Env, ctx: ExecutionContext, cid: string): Promise<Response> {
  const cors = corsHeaders(req, env);
  // G193: an Origin was PRESENT and did not match CONSOLE_ORIGIN, so corsHeaders returned {} and the browser
  // will refuse this response before the console sees it. That is the entire console going dead after a
  // hostname move, and the pack could not see it at all (browser-side CORS errors are not engine state, and
  // section 6 is explicit that no browser-side state is ever collected). Count it against the EXISTING
  // authSignals aggregate. The Origin VALUE and the configured CONSOLE_ORIGIN never leave this function.
  // Fired in the background (ctx.waitUntil): observing a rejection must not add latency to the request.
  if (req.headers.get("Origin") !== null && Object.keys(cors).length === 0) {
    try {
      ctx.waitUntil(recordCorsRejection(schedulerStub(env)));
    } catch {
      /* best-effort: an unbound SCHEDULER must never turn a CORS rejection into a crash */
    }
  }
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: { ...cors, ...SECURITY_HEADERS } });
  const runtime = buildAdminRuntime(env, ctx);
  try {
    // slide is the idle-slide cookie sink (ASVS V7.3.1): handleAdmin's passkey verifier stashes a refreshed
    // Set-Cookie here when the DO re-mints a stale-lastSeen session, and we append it to the rebuilt response
    // below. It is the single chokepoint every /admin response passes through, so the dispatch needs no change.
    const slide: { cookie: string | null } = { cookie: null };
    const resp = await handleAdmin(req, env, runtime, slide);
    // Rebuild the response so the headers are mutable: a response returned straight from a scheduler.fetch()
    // (the DO) carries IMMUTABLE headers, so resp.headers.set() would throw for every forwarded route. Copying
    // into a fresh Headers applies CORS + the hardening headers uniformly, whether the route built its own
    // response or forwarded the DO's.
    const headers = new Headers(resp.headers);
    for (const [k, v] of Object.entries(cors)) headers.set(k, v);
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
    // Append the refreshed session cookie if the session was slid this request (idle-slide). append (not set)
    // so it never clobbers a Set-Cookie a route already emitted (e.g. a fresh login / terminate).
    if (slide.cookie !== null) headers.append("set-cookie", slide.cookie);
    return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers });
  } catch (e) {
    // Coarse log for the operator's console.error stream (no stack reaches the client); the body is a generic
    // 500 so a malformed request or an internal fault never leaks a detail. The log carries a stable err-id
    // (FNV-1a of the error) + a coarse category, NEVER the raw message, matching validate-errlog's discipline.
    log("error", `admin request failed [err:${errId(e)} admin-dispatch] cid=${cid}`);
    // G072: the ring carries the closed surface, the closed route family (derived from the path PREFIX --
    // never the path, the query string or an id in it) and the SAME irreversible 8-hex errId the log line
    // carries, which is the one join key between a customer's "the console 500s on Notifications" and the
    // log the customer can export.
    noteDispatchFault(env, ctx, { surface: "admin", routeFamily: routeFamilyOf(new URL(req.url).pathname), errId: errId(e), httpStatus: 500 });
    const headers = new Headers({ "content-type": "application/problem+json" });
    for (const [k, v] of Object.entries(cors)) headers.set(k, v);
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
    return new Response(problemBody(500, "internal error", "Internal error", { requestId: cid }), { status: 500, headers });
  }
}

// handleNonAdminRoute serves the remaining surfaces (/support, /metrics, "/" and the 404 fall-through) under
// a last-resort try/catch (ASVS V16.5.4): a throw here (e.g. from handleSupportPull or handleMetricsRoute)
// would otherwise escape to the Cloudflare runtime unlogged. It logs a coarse err-id (never the raw message
// or a stack) and returns a generic hardened 500 -- which also means an unexpected DO fault while gathering
// /metrics fails the SCRAPE (a 500), never a healthy-looking empty page, so Prometheus's own per-target `up`
// correctly reflects an outage rather than masking it as "nothing configured". The support and metrics
// surfaces are server-to-server (no CORS), plain 401 on a failed bearer presentation. Both carry account
// state, so they get withSecurity (the full SECURITY_HEADERS set) below, not withBaseSecurity -- unlike the
// genuinely-unauthenticated "/" and 404.
async function handleNonAdminRoute(req: Request, env: Env, url: URL, cid: string, ctx: ExecutionContext): Promise<Response> {
  try {
    if (url.pathname === "/support/diagnostics" || url.pathname === "/support/audit-feed") {
      return withSecurity(await handleSupportPull(req, env, schedulerStub(env)));
    }
    if (url.pathname === "/metrics") {
      return withSecurity(await handleMetricsRoute(req, schedulerStub(env)));
    }
    if (url.pathname === "/") return withBaseSecurity(new Response("downpipe engine: in-account backup writer. The console talks to /admin."));
    return withBaseSecurity(new Response("not found", { status: 404 }));
  } catch (e) {
    log("error", `engine non-admin request failed [err:${errId(e)} fetch-dispatch] cid=${cid}`);
    // G072, the SELF-REFERENTIAL one: this catch covers /support/diagnostics itself. A support endpoint that
    // 500s cannot report itself into a pack that never gets built -- but the ring records it, so the NEXT
    // successful pull carries the evidence of every pull that failed. Same for a /metrics scrape that throws.
    noteDispatchFault(env, ctx, { surface: "fetch", routeFamily: routeFamilyOf(url.pathname), errId: errId(e), httpStatus: 500 });
    return withBaseSecurity(new Response(problemBody(500, "internal error", "Internal error", { requestId: cid }), { status: 500, headers: { "content-type": "application/problem+json" } }));
  }
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    configureLog(env);
    const url = new URL(req.url);
    // OBS-1: one correlation id per request, echoed on EVERY response (withCorrelation) so an operator's
    // 500 carries a handle (cf-ray when present, else a minted dpr-<uuid>) that ties it to the matching
    // log line, and minted once here so the dispatch-catch logs and the response header agree.
    const cid = correlationId(req);
    if (url.pathname === "/ready") return withCorrelation(handleReady(), cid);
    if (url.pathname.startsWith("/scim/v2")) return withCorrelation(await handleScimRoute(req, env, cid, ctx), cid);
    if (url.pathname.startsWith("/admin")) return withCorrelation(await handleAdminRoute(req, env, ctx, cid), cid);
    return withCorrelation(await handleNonAdminRoute(req, env, url, cid, ctx), cid);
  },

  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    configureLog(env);
    ctx.waitUntil(drive(env));
  },
};

export { flushDigests } from "./cron/notify-passes.ts";
export { runScheduledRestoreTest } from "./cron/restore-test-pass.ts";
export { destinationReachable, selectSealDestination } from "./cron/seal-dispatch.ts";
// buildAdapter (now in seal/adapters.ts) is re-exported as the unchanged behaviour-neutral test
// seam so the reserved-binding guard (RESERVED_BINDINGS, the defence-in-depth check that a downpipe
// source can never name one of the engine's own bindings) can be exercised directly.
//
// destinationReachable + selectSealDestination (now in cron/seal-dispatch.ts), flushDigests +
// runScheduledRestoreTest (now in cron/notify-passes.ts and cron/restore-test-pass.ts) are re-exported
// as behaviour-neutral test seams so the failover, digest-flush and scheduled-restore-test validators
// that import them from ../src/index.ts keep working unchanged. They are the same private functions the
// cron driver calls; re-exporting them adds no runtime behaviour and no new code path.
//
// SchedulerDO + RunSealDO + RateLimitDO are the Durable Object classes; the platform requires every DO
// class exported from the entry module (wrangler.toml binds them as SCHEDULER, RUNSEAL and RATELIMIT_DO,
// migrations v1/v2/v3). RateLimitDO is the account-global CF API token bucket DistributedPacer fronts; the
// binding is drafted but its live cross-isolate go-live is deferred (accountPacer falls back to the
// per-isolate CfPacer until the binding is present).
export { buildAdapter, RateLimitDO, RunSealDO, SchedulerDO };
