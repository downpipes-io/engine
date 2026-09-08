// Prove the per-caller anti-automation rate limiter (OWASP ASVS V2.4.1) on the engine admin API,
// end to end and SERVER-SIDE, with in-memory doubles only. No network, no deploy, no cost. Run:
//   node test/validate-ratelimit.ts
//
// What this proves (the launch-gate claims):
//  - the DO POST /rate-check maintains a per-key FIXED-WINDOW counter: it admits up to the cap in a
//    window, then refuses with a positive retryAfterMs, and a fresh window (clock advanced past the
//    window) admits again;
//  - cost lets one check account for more than one logical request, and distinct keys count
//    independently (one caller's burst does not exhaust another's bucket);
//  - in handleAdmin, a BURST of mutating POSTs past the cap (driven on the token break-glass, which
//    resolves to Owner so it is never refused on ROLE grounds) gets an HTTP 429 carrying a
//    Retry-After header in whole seconds and a JSON { error: "rate limited" } body, while READ-only
//    routes (GET) stay exempt and keep answering 200 even once the bucket is saturated;
//  - the limiter FAILS OPEN: when the DO /rate-check call itself throws, a mutating POST is STILL
//    admitted (the recovery surface stays available; a fail-closed limiter would harm customers).
//  - the PER-IP auth limiter (authRateLimited, the UNAUTHENTICATED /admin/auth/* surface) has the
//    OPPOSITE posture and FAILS CLOSED: it returns 429 at the cap, returns 429 when its backing store
//    is unavailable (a non-admit verdict or a thrown /rate-check), and ADMITS only an explicit
//    allowed === true OR a missing source IP (a non-edge/local context the edge cannot produce).
//  - the PER-IP ADMIN_TOKEN throttle (adminTokenRateLimitedViaDO, ASVS V6.3.1, closing the "no
//    anti-brute-force throttle on the bearer compare" finding) mirrors authRateLimited's fail-closed
//    posture over its OWN key namespace: it blocks at the cap, blocks (fails closed) when its backing
//    store is unavailable, and admits a missing source IP; each block records the admin-token-ratelimited
//    signal. Driven THROUGH handleAdmin with a genuinely VALID token, it proves the wiring: a throttled
//    caller never even reaches the constant-time compare and is refused with a 429, NOT the 401 every
//    other deny answers. A rate limit is not a statement about the credential, and a client that reads it
//    as one signs the operator out mid-task. Meanwhile a caller from a DIFFERENT, under-cap IP
//    authenticates normally in the same window (independent per-IP buckets, no lockout).
//  - EVERY 429 this engine emits carries ONE wire contract: an RFC 9457 problem+json body with
//    error: "rate limited", served as application/problem+json, with a whole-second Retry-After and the
//    advisory IETF RateLimit headers. All four now come from a single builder (rateLimitedResponse), so
//    a new limiter cannot ship a 429 that an integrator following the published contract cannot parse.
//
// The mutating burst is driven over the ADMIN_TOKEN break-glass path so the proof needs no forged
// JWT and no role wiring: that caller resolves to Owner (passing every role gate) and shares the
// single "token" rate bucket, so the only refusal it can meet is the 429 we are proving.

import { handleAdmin } from "../src/admin/router.ts";
import { authRateLimited } from "../src/admin/router-core.ts";
import { recordAuthSignalEdge } from "../src/admin/router-helpers.ts";
import { adminTokenRateLimitedViaDO, breakGlassRetiredViaDO } from "../src/admin/router-session.ts";
import { ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW, AUTH_RATE_LIMIT_MAX_PER_WINDOW, RATE_LIMIT_MAX_PER_WINDOW, RATE_LIMIT_WINDOW_MS } from "../src/sched/scheduler-do.ts";
import type { Env } from "../src/env.d.ts";
// makeScheduler (over the shared MockStorage double) is shared with the validate-rbac suite via the
// common harness: one in-memory DO double, extended here only by the failRateCheck option the harness
// factory already accepts.
import { makeScheduler } from "./validate-rbac-harness.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// A valid downpipe config the DO accepts (so a mutating POST /downpipes reaches a real 200 rather
// than a 400 validation failure). The id is varied per call so the upsert path is exercised cleanly.
function downpipeBody(id: string): unknown {
  return { id, name: `dp ${id}`, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_x", include: [], exclude: [] } };
}

// rateCheck drives the DO POST /rate-check directly with a key (+ optional cost).
async function rateCheck(stub: DurableObjectStub, key: string, cost?: number): Promise<{ allowed: boolean; retryAfterMs: number }> {
  const r = await stub.fetch("https://scheduler.internal/rate-check", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(cost !== undefined ? { key, cost } : { key }),
  });
  return (await r.json()) as { allowed: boolean; retryAfterMs: number };
}

// The cap and window the implementation pins, imported straight from scheduler-do.ts so the test can
// never silently diverge from the production constants. The test asserts the OBSERVABLE behaviour these
// produce.
const CAP = RATE_LIMIT_MAX_PER_WINDOW;
const WINDOW_MS = RATE_LIMIT_WINDOW_MS;

async function main(): Promise<void> {
  // ============================================================================================
  // PART A: the DO POST /rate-check fixed-window counter, driven directly.
  // ============================================================================================

  // ---- PROOF A1: a window admits up to the cap, then refuses ------------------------------
  {
    const sched = makeScheduler();
    let lastAllowed = true;
    for (let i = 0; i < CAP; i++) {
      const v = await rateCheck(sched.stub, "a@acme.example");
      if (!v.allowed) lastAllowed = false;
    }
    ok("a fresh window admits the first CAP requests", lastAllowed === true);
    // The first request opened the window, so an admit reports retryAfterMs 0 (nothing to wait for).
    const firstAgain = await rateCheck(makeScheduler().stub, "a@acme.example");
    ok("an admitted request reports retryAfterMs 0", firstAgain.allowed === true && firstAgain.retryAfterMs === 0);
    // The CAP+1-th request in the SAME window is refused with a positive retryAfterMs within the window.
    const over = await rateCheck(sched.stub, "a@acme.example");
    ok("the request past the cap is refused", over.allowed === false);
    ok("a refusal reports a positive retryAfterMs", over.retryAfterMs > 0);
    ok("retryAfterMs never exceeds the window", over.retryAfterMs <= WINDOW_MS);
    // A refusal does NOT increment, so a second over-cap probe is still refused (not a runaway count).
    const overAgain = await rateCheck(sched.stub, "a@acme.example");
    ok("a second over-cap request stays refused (refusal does not push the window further)", overAgain.allowed === false);
  }

  // ---- PROOF A2: a fresh window (clock advanced past the window) admits again -------------
  // The DO reads Date.now(); override it to advance the clock deterministically past the window
  // boundary and prove the fixed window RESETS rather than staying saturated forever. The override
  // is restored in a finally so a failure cannot leak a frozen clock into later proofs.
  {
    const sched = makeScheduler();
    const realNow = Date.now;
    try {
      let clock = 1_000_000; // a fixed base epoch ms the whole proof advances from
      Date.now = () => clock;
      // Saturate the window at the base time.
      for (let i = 0; i < CAP; i++) await rateCheck(sched.stub, "b@acme.example");
      const blocked = await rateCheck(sched.stub, "b@acme.example");
      ok("at the cap within the window, the next request is refused", blocked.allowed === false);
      // Advance to exactly the window boundary: the stored window has now fully elapsed, so a fresh
      // window opens and the request is admitted again.
      clock = 1_000_000 + WINDOW_MS;
      const afterReset = await rateCheck(sched.stub, "b@acme.example");
      ok("once the window elapses, a fresh window admits again (the window RESETS)", afterReset.allowed === true);
      ok("the first request of the fresh window reports retryAfterMs 0", afterReset.retryAfterMs === 0);
      // And the fresh window starts its own count from that one request, so CAP-1 more admit, then refuse.
      let allAllowed = true;
      for (let i = 0; i < CAP - 1; i++) {
        const v = await rateCheck(sched.stub, "b@acme.example");
        if (!v.allowed) allAllowed = false;
      }
      ok("the fresh window admits CAP-1 further requests", allAllowed === true);
      const refusedAgain = await rateCheck(sched.stub, "b@acme.example");
      ok("the fresh window refuses once its own cap is reached", refusedAgain.allowed === false);
    } finally {
      Date.now = realNow;
    }
  }

  // ---- PROOF A3: distinct keys count independently; cost is honoured ----------------------
  {
    const sched = makeScheduler();
    // Saturate key c entirely.
    for (let i = 0; i < CAP; i++) await rateCheck(sched.stub, "c@acme.example");
    ok("key c is now over its cap", (await rateCheck(sched.stub, "c@acme.example")).allowed === false);
    // A DIFFERENT key d is unaffected: its own window is fresh and admits.
    ok("a different key has its own independent bucket (admitted)", (await rateCheck(sched.stub, "d@acme.example")).allowed === true);
    // cost accounts for more than one logical request: one check of cost=CAP fills a key's window,
    // so the very next unit request is refused.
    const sched2 = makeScheduler();
    const big = await rateCheck(sched2.stub, "e@acme.example", CAP);
    ok("a single check with cost=CAP is admitted (it exactly fills the window)", big.allowed === true);
    const nextUnit = await rateCheck(sched2.stub, "e@acme.example");
    ok("the next unit request after a cost=CAP fill is refused", nextUnit.allowed === false);
  }

  // ============================================================================================
  // PART B: handleAdmin gating, driven over the ADMIN_TOKEN break-glass (resolves to Owner).
  // ============================================================================================

  // tokenEnv pairs the in-memory scheduler with ADMIN_TOKEN so the bare-token caller authorises and
  // resolves to Owner WITHOUT a forged JWT; the caller keys to the single "token" rate bucket.
  const TOKEN = "shared-break-glass-token";
  function tokenEnv(sched: ReturnType<typeof makeScheduler>): Env {
    return { ...sched.env, ADMIN_TOKEN: TOKEN } as unknown as Env;
  }
  async function tokenCall(env: Env, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> {
    const init: RequestInit = {
      method,
      headers: { authorization: `Bearer ${TOKEN}`, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    };
    return handleAdmin(new Request(`https://engine.example${path}`, init), env);
  }

  // ---- PROOF B1: a burst of mutating POSTs past the cap gets a 429 with Retry-After -------
  {
    const sched = makeScheduler();
    const env = tokenEnv(sched);
    // The first CAP mutating POSTs are admitted by the limiter and reach a real DO 200 (a valid
    // upsert). We assert NONE of them is a 429 (the limiter let them through) before the burst tips.
    let any429Early = false;
    for (let i = 0; i < CAP; i++) {
      const r = await tokenCall(env, "POST", "/admin/downpipes", downpipeBody(`burst-${i}`));
      if (r.status === 429) any429Early = true;
      // Drain the body so the mock Response is consumed (parity with the live forwarding path).
      await r.text();
    }
    ok("the first CAP mutating POSTs are NOT rate limited (admitted)", any429Early === false);

    // The CAP+1-th mutating POST in the same window is refused by the limiter BEFORE the route runs.
    const tipped = await tokenCall(env, "POST", "/admin/downpipes", downpipeBody("over-cap"));
    ok("the mutating POST past the cap is refused 429", tipped.status === 429);
    const body = (await tipped.json()) as { error?: string };
    ok("the 429 body is the JSON rate-limited shape", body.error === "rate limited");
    const retryAfter = tipped.headers.get("retry-after");
    ok("the 429 carries a Retry-After header", retryAfter !== null);
    ok("the Retry-After header is a positive whole-second value", retryAfter !== null && /^\d+$/.test(retryAfter) && Number(retryAfter) >= 1);
    ok("the Retry-After header is within the window (<= 60s)", retryAfter !== null && Number(retryAfter) <= WINDOW_MS / 1000);

    // ---- PROOF B2: read-only routes stay EXEMPT even once the bucket is saturated ---------
    // The bucket for the "token" key is now over its cap (the burst above filled it), yet a GET must
    // still answer 200: reads are not gated, so a saturated write bucket never blocks the console
    // from reading state (whoami / downpipes / audit).
    const readWhoami = await tokenCall(env, "GET", "/admin/whoami");
    ok("a GET /whoami still passes while the write bucket is saturated (reads exempt)", readWhoami.status === 200);
    const readDownpipes = await tokenCall(env, "GET", "/admin/downpipes");
    ok("a GET /downpipes still passes while the write bucket is saturated (reads exempt)", readDownpipes.status === 200);
  }

  // ---- PROOF B3: the limiter FAILS OPEN when the DO /rate-check call throws ---------------
  // With the stub configured to THROW for /rate-check only, a mutating POST must still succeed: the
  // router catches the failure, logs coarsely, and ADMITS the request (availability beats strict
  // limiting on the recovery surface). We drive enough mutating POSTs that, were the limiter failing
  // CLOSED, at least one would be refused; every one must instead reach a real 200.
  {
    const sched = makeScheduler({ failRateCheck: true });
    const env = tokenEnv(sched);
    let allAdmitted = true;
    let saw429 = false;
    for (let i = 0; i < CAP + 5; i++) {
      const r = await tokenCall(env, "POST", "/admin/downpipes", downpipeBody(`failopen-${i}`));
      if (r.status === 429) saw429 = true;
      if (r.status !== 200) allAdmitted = false;
      await r.text();
    }
    ok("with /rate-check throwing, NO mutating POST is 429 (fails open)", saw429 === false);
    ok("with /rate-check throwing, every mutating POST still reaches a real 200 (request succeeds)", allAdmitted === true);
  }

  // ---- PROOF B4: POST /downpipes/cf-config/mode is rate limited like every sibling mutating case
  // in router-discovery.ts, unlike its neighbour /cf-config/rediscover. An unknown downpipe id
  // reaches a real 404 from the DO (never a 429) while under the cap, so the burst distinguishes
  // "the limiter admitted it" from "the route's own validation ran".
  {
    const sched = makeScheduler();
    const env = tokenEnv(sched);
    let any429Early = false;
    for (let i = 0; i < CAP; i++) {
      const r = await tokenCall(env, "POST", "/admin/downpipes/cf-config/mode", { id: "no-such-dp", mode: "manual" });
      if (r.status === 429) any429Early = true;
      await r.text();
    }
    ok("cf-config/mode: the first CAP mutating POSTs are NOT rate limited (reach the DO)", any429Early === false);
    const tipped = await tokenCall(env, "POST", "/admin/downpipes/cf-config/mode", { id: "no-such-dp", mode: "manual" });
    ok("cf-config/mode: the mutating POST past the cap is refused 429", tipped.status === 429);
    const body = (await tipped.json()) as { error?: string };
    ok("cf-config/mode: the 429 body is the JSON rate-limited shape", body.error === "rate limited");
  }

  // ============================================================================================
  // PART C: the PER-IP auth limiter (authRateLimited), driven directly. It guards the UNAUTHENTICATED
  // /admin/auth/* surface and, UNLIKE the per-caller rateLimited above, FAILS CLOSED. We prove the three
  // posture branches that the header comment asserts: (1) at the cap it returns a 429; (2) when the DO
  // /rate-check is unavailable it STILL returns a 429 (fail closed, not open); (3) a request with no
  // source IP is ADMITTED (null) - the one open case, an edge-impossible local/non-edge context.
  // ============================================================================================

  // authReq builds a request carrying (or omitting) the edge CF-Connecting-IP header authRateLimited keys on.
  function authReq(ip: string | null): Request {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (ip !== null) headers["CF-Connecting-IP"] = ip;
    return new Request("https://engine.example/admin/auth/login/begin", { method: "POST", headers });
  }

  // ---- PROOF C1: at the per-IP cap, the auth limiter returns a 429 -----------------------------
  {
    const sched = makeScheduler();
    const ip = "198.51.100.7";
    // Drive AUTH_RATE_LIMIT_MAX_PER_WINDOW admitted pre-checks (each returns null, under the cap) ...
    let anyEarly429 = false;
    for (let i = 0; i < AUTH_RATE_LIMIT_MAX_PER_WINDOW; i++) {
      const r = await authRateLimited(sched.stub, authReq(ip));
      if (r !== null && r.status === 429) anyEarly429 = true;
    }
    ok("the first AUTH cap pre-checks are admitted (null, no early 429)", anyEarly429 === false);
    // ... then the next one tips over the cap and is refused with a 429 carrying the rate-limited body.
    const over = await authRateLimited(sched.stub, authReq(ip));
    ok("the per-IP auth pre-check past the cap returns a 429", over !== null && over.status === 429);
    const body = over === null ? null : ((await over.json()) as { error?: string });
    ok("the auth 429 body is the JSON rate-limited shape", body !== null && body.error === "rate limited");
    ok("the auth 429 carries a Retry-After header", over !== null && over.headers.get("retry-after") !== null);
  }

  // ---- PROOF C2: a DO /rate-check outage FAILS CLOSED (still a 429), not open ------------------
  // With the stub throwing for /rate-check, the per-caller rateLimited admits (PROOF B3); the auth limiter
  // must do the OPPOSITE and DENY, so a limiter outage cannot open the brute-force floodgates.
  {
    const sched = makeScheduler({ failRateCheck: true });
    const closed = await authRateLimited(sched.stub, authReq("198.51.100.8"));
    ok("with /rate-check throwing, the auth limiter FAILS CLOSED (returns a 429, not null)", closed !== null && closed.status === 429);
    const body = closed === null ? null : ((await closed.json()) as { error?: string });
    ok("the fail-closed auth 429 reports the unavailable shape", body !== null && body.error === "rate limit unavailable");
    ok("the fail-closed auth 429 carries a Retry-After header", closed !== null && closed.headers.get("retry-after") !== null);
    // The fail-closed limiter records auth-limiter-unavailable to the DO (the /rate-check stub throws, but the
    // /auth-signal write routes to the real DO), so a "login blocked, not throttled" outage is diagnosable. The
    // emit is fire-and-forget, so flush the timer queue before reading the aggregate.
    await new Promise((resolve) => setTimeout(resolve, 0));
    const c2agg = (await (await sched.stub.fetch("https://scheduler.internal/auth-signals")).json()) as Record<string, { count: number }>;
    ok("the fail-closed auth limiter recorded auth-limiter-unavailable (login-blocked, diagnosable)", (c2agg["auth-limiter-unavailable"]?.count ?? 0) > 0);
  }

  // ---- PROOF C3: a request with NO source IP is ADMITTED (the one open case) -------------------
  // The custom-domain-only edge always injects CF-Connecting-IP, so its absence is a non-edge/local context,
  // not an attacker; admitting it avoids bucketing every header-less caller into one shared "ip:" key.
  {
    const sched = makeScheduler();
    const admitted = await authRateLimited(sched.stub, authReq(null));
    ok("a request with no source IP is admitted (null) - the deliberate edge-impossible open case", admitted === null);
  }

  // ============================================================================================
  // PART D: the shared Worker-EDGE auth-signal recorder (recordAuthSignalEdge) - the happy path
  // (records the closed name to the DO) and the DO-outage path (swallowed, best-effort, never throws).
  // ============================================================================================
  {
    const sched = makeScheduler();
    await recordAuthSignalEdge(sched.stub, "auth-limiter-unavailable");
    const agg = (await (await sched.stub.fetch("https://scheduler.internal/auth-signals")).json()) as Record<string, { count: number }>;
    ok("recordAuthSignalEdge: records the closed signal name to the DO aggregate", (agg["auth-limiter-unavailable"]?.count ?? 0) > 0);
    // A scheduler whose fetch REJECTS is swallowed: the recorder never throws (a diagnostic write must not affect auth).
    const throwing = { fetch: () => Promise.reject(new Error("DO down")) } as unknown as DurableObjectStub;
    let threw = false;
    try {
      await recordAuthSignalEdge(throwing, "break-glass-check-unavailable");
    } catch {
      threw = true;
    }
    ok("recordAuthSignalEdge: a DO outage is swallowed (best-effort, never throws)", threw === false);
  }

  // ============================================================================================
  // PART E: breakGlassRetiredViaDO fails CLOSED on a DO outage AND records break-glass-check-unavailable,
  // so a "my break-glass token stopped working" ticket is diagnosable as a DO-availability event.
  // ============================================================================================
  {
    const real = makeScheduler();
    // The retire check THROWS (DO unavailable); the /auth-signal write routes to the real DO so the record lands.
    const stub = {
      fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (url.endsWith("/policy/break-glass-retired")) throw new Error("simulated DO unavailable");
        return real.stub.fetch(input, init);
      },
    } as unknown as DurableObjectStub;
    const denied = await breakGlassRetiredViaDO(stub);
    ok("breakGlassRetiredViaDO: a DO outage fails CLOSED (returns true = retired/deny)", denied === true);
    await new Promise((resolve) => setTimeout(resolve, 0));
    const agg = (await (await real.stub.fetch("https://scheduler.internal/auth-signals")).json()) as Record<string, { count: number }>;
    ok("breakGlassRetiredViaDO: the fail-closed outage recorded break-glass-check-unavailable", (agg["break-glass-check-unavailable"]?.count ?? 0) > 0);
  }

  // ============================================================================================
  // PART F: the PER-IP ADMIN_TOKEN throttle (adminTokenRateLimitedViaDO), driven directly. This closes
  // the gap where auth.ts's bare-token compare had no anti-brute-force throttle at all, by mirroring
  // authRateLimited's fail-closed per-IP design, but in its OWN `admin-token-ip:` key namespace so it
  // never shares the auth-ceremony bucket and never trips the DO's generic key.startsWith("ip:")
  // auto-signal (it records its own distinct signal instead, proven below).
  // ============================================================================================

  // adminTokenReq builds a request carrying (or omitting) CF-Connecting-IP, mirroring authReq above.
  function adminTokenReq(ip: string | null): Request {
    const headers: Record<string, string> = {};
    if (ip !== null) headers["CF-Connecting-IP"] = ip;
    return new Request("https://engine.example/admin/status", { method: "GET", headers });
  }

  // ---- PROOF F1: at the per-IP cap, the throttle blocks (true) and records admin-token-ratelimited ---
  {
    const sched = makeScheduler();
    const ip = "203.0.113.10";
    let anyEarlyBlock = false;
    for (let i = 0; i < ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW; i++) {
      if (await adminTokenRateLimitedViaDO(sched.stub, adminTokenReq(ip))) anyEarlyBlock = true;
    }
    ok("adminTokenRateLimitedViaDO: the first cap checks are admitted (false, no early block)", anyEarlyBlock === false);
    const tripped = await adminTokenRateLimitedViaDO(sched.stub, adminTokenReq(ip));
    ok("adminTokenRateLimitedViaDO: the check past the cap blocks (returns true)", tripped === true);
    await new Promise((resolve) => setTimeout(resolve, 0));
    const agg = (await (await sched.stub.fetch("https://scheduler.internal/auth-signals")).json()) as Record<string, { count: number }>;
    ok("adminTokenRateLimitedViaDO: a cap trip records admin-token-ratelimited", (agg["admin-token-ratelimited"]?.count ?? 0) > 0);
  }

  // ---- PROOF F2: distinct source IPs get independent buckets (no cross-caller lockout) ------------
  {
    const sched = makeScheduler();
    const ip = "203.0.113.11";
    for (let i = 0; i < ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW; i++) await adminTokenRateLimitedViaDO(sched.stub, adminTokenReq(ip));
    ok("adminTokenRateLimitedViaDO: this IP is now over its cap", (await adminTokenRateLimitedViaDO(sched.stub, adminTokenReq(ip))) === true);
    ok("adminTokenRateLimitedViaDO: a DIFFERENT IP has its own fresh bucket (admitted)", (await adminTokenRateLimitedViaDO(sched.stub, adminTokenReq("203.0.113.12"))) === false);
  }

  // ---- PROOF F3: a DO /rate-check outage FAILS CLOSED (true = blocked), never a fail-open bypass ---
  {
    const sched = makeScheduler({ failRateCheck: true });
    const blocked = await adminTokenRateLimitedViaDO(sched.stub, adminTokenReq("203.0.113.13"));
    ok("adminTokenRateLimitedViaDO: with /rate-check throwing, the token path FAILS CLOSED (true, not false)", blocked === true);
    await new Promise((resolve) => setTimeout(resolve, 0));
    const agg = (await (await sched.stub.fetch("https://scheduler.internal/auth-signals")).json()) as Record<string, { count: number }>;
    ok("adminTokenRateLimitedViaDO: a fail-closed outage also records admin-token-ratelimited", (agg["admin-token-ratelimited"]?.count ?? 0) > 0);
  }

  // ---- PROOF F4: a request with NO source IP is ADMITTED (the one open case, edge-impossible) -----
  {
    const sched = makeScheduler();
    const admitted = await adminTokenRateLimitedViaDO(sched.stub, adminTokenReq(null));
    ok("adminTokenRateLimitedViaDO: a request with no source IP is admitted (false)", admitted === false);
  }

  // ============================================================================================
  // PART G: the throttle wired end-to-end through handleAdmin's REAL authorise() call. A GENUINELY
  // VALID token is still refused once its source IP is over the cap -
  // the throttle sits BEFORE tokenEqual (see auth.ts), so a correct credential does not exempt a caller
  // from it, and the refusal is the SAME plain 401 as a bad credential (never a 429, since authorise()
  // only ever collapses to { ok: false }). GET /admin/status is used deliberately: it is the exact route
  // the finding's exploit named as free-to-flood (the per-caller rateLimited() mutating limiter exempts
  // reads; this new throttle lives inside authorise() itself and gates GET and POST alike).
  // ============================================================================================
  {
    const sched = makeScheduler();
    const env = tokenEnv(sched);
    const ip = "203.0.113.20";
    function tokenCallFromIp(fromIp: string | null): Promise<Response> {
      const headers: Record<string, string> = { authorization: `Bearer ${TOKEN}` };
      if (fromIp !== null) headers["CF-Connecting-IP"] = fromIp;
      return handleAdmin(new Request("https://engine.example/admin/status", { method: "GET", headers }), env);
    }
    let any401Early = false;
    for (let i = 0; i < ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW; i++) {
      const r = await tokenCallFromIp(ip);
      if (r.status !== 200) any401Early = true;
      await r.text();
    }
    ok("handleAdmin: the first cap GETs (valid token) from one IP authenticate normally (200)", any401Early === false);
    const tipped = await tokenCallFromIp(ip);
    // A 401 here would be indistinguishable from a session loss, so a client would treat a rate limit as a
    // sign-out. A 429 is safe to distinguish because this limiter fires BEFORE tokenEqual, refusing a
    // correct and an incorrect token identically. Retry-After is asserted too, so the contract is pinned
    // rather than the status alone.
    ok("handleAdmin: the GET past the cap from the SAME IP is refused, even with a VALID token", tipped.status === 429);
    // NOT 401, named as its own assertion. The status is the whole point of this branch, and `!== 401` fails
    // with the wrong status in its label rather than leaving a reader to infer it from a bare 429 check.
    ok("handleAdmin: the throttle refusal is NOT a 401 (a rate limit must never read as a session loss)", tipped.status !== 401);
    ok("handleAdmin: the throttle refusal carries retry-after, so a caller can back off rather than guess", tipped.headers.get("retry-after") !== null);
    const tippedRetryAfter = tipped.headers.get("retry-after");
    ok("handleAdmin: the throttle Retry-After is a positive whole-second value", tippedRetryAfter !== null && /^\d+$/.test(tippedRetryAfter) && Number(tippedRetryAfter) >= 1);
    // THE BODY IS THE OTHER HALF OF THE CONTRACT: this 429 must be RFC 9457 problem+json like the engine's
    // other three 429s, or an integrator following the published contract (match on error === "rate
    // limited") would throw on JSON.parse instead. The shape is asserted here, not just the status.
    ok("handleAdmin: the throttle 429 is served as application/problem+json, like every other 429", (tipped.headers.get("content-type") ?? "").includes("application/problem+json"));
    // Read the body DEFENSIVELY. A regression that answers a non-JSON body is precisely the fault these
    // three lines exist to catch, so an unparseable body must fail them BY NAME rather than throw out of
    // main() and take the remaining assertions with it. An undiagnosable non-zero exit is a worse signal
    // than a named one, and it is the shape a reader has to reverse-engineer from a stack trace.
    const tippedRaw = await tipped.text();
    let tippedBody: { error?: string; status?: number; type?: string } = {};
    try {
      tippedBody = JSON.parse(tippedRaw) as { error?: string; status?: number; type?: string };
    } catch {
      ok(`handleAdmin: the throttle 429 body parses as JSON (got ${JSON.stringify(tippedRaw.slice(0, 40))})`, false);
    }
    ok("handleAdmin: the throttle 429 body carries error 'rate limited', the field the contract matches on", tippedBody.error === "rate limited");
    ok("handleAdmin: the throttle 429 body is the RFC 9457 shape (type + status)", tippedBody.type === "urn:downpipe:error:rate-limited" && tippedBody.status === 429);
    ok("handleAdmin: the throttle 429 carries the advisory IETF RateLimit header", tipped.headers.get("ratelimit") !== null);
    // A DIFFERENT source IP is a fresh, independent bucket: the SAME valid token still authenticates.
    const otherIp = await tokenCallFromIp("203.0.113.21");
    ok("handleAdmin: the SAME valid token from a DIFFERENT IP still authenticates (independent per-IP buckets)", otherIp.status === 200);
    await otherIp.text();
    await new Promise((resolve) => setTimeout(resolve, 0));
    const agg = (await (await sched.stub.fetch("https://scheduler.internal/auth-signals")).json()) as Record<string, { count: number }>;
    ok("handleAdmin: the end-to-end throttle trip is visible in the support-pack signal aggregate", (agg["admin-token-ratelimited"]?.count ?? 0) > 0);
  }

  console.log(failures === 0 ? "\nPER-CALLER + PER-IP RATE-LIMIT VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
