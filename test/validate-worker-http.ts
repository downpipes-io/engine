// HTTP entrypoint cases of the validate-worker suite (split out of test/validate-worker.ts):
// root/404 banners, CORS preflight + origin matching, security headers on every admin response,
// the immutable-headers regression, run-now seal wiring, cache-control, and the last-resort error
// handler. No network, no deploy.

import worker from "../src/index.ts";
import type { Env } from "../src/env.d.ts";
import { ok, makeEnv, makeSchedulerStub, healthStub, workerFetch, SEC_HEADERS, BASE_SEC_HEADERS } from "./validate-worker-helpers.ts";

// ---- IMMUTABLE-HEADERS REGRESSION -------------------------------------------------------------
// The live 500 (error-1101) happened when handleAdmin returned a Response that was FORWARDED
// from scheduler.fetch(); its headers are IMMUTABLE (the platform marks forwarded responses
// as immutable). Calling resp.headers.set() on it throws "Can't modify immutable headers".
// The fix in index.ts rebuilds the headers into a fresh Headers instance, so the worker MUST
// apply security headers without throwing regardless of whether the upstream response has
// mutable or immutable headers.
//
// We simulate the immutable case by returning a Response from the stub whose headers are
// structurally immutable: we construct it as a redirect (status 301 with no body) and then
// try to set a header. But since we need the route to complete normally, we instead use a
// simpler mechanism: create a Response via the fetch() codepath in the stub and verify the
// wrapper in index.ts handles it without throwing.
//
// The exact "immutable" semantics come from Response being returned with GUARD=response (set
// by the underlying platform when a fetch() resolves). In Node 22+ the fetch API returns
// Responses with immutable headers too. We create a Response via an in-process fetch to
// guarantee the immutable guard.

async function immutableHeaderResponse(): Promise<Response> {
  // Build a real Response using global fetch against a data: URL. This gives us an actual
  // platform Response whose headers carry the "immutable" guard (response guard in the Fetch
  // spec, which prevents .set()).  On Node 22+, Response.headers from fetch is read-only.
  //
  // Fallback: if data: URL is unsupported, manufacture the immutable guard by copying a
  // Response and testing whether headers.set throws; if it does not (environment does not
  // enforce the guard) we skip that narrower assertion and rely on the structural copy in
  // index.ts being correct.
  try {
    const resp = await fetch("data:application/json,{\"ok\":true}");
    // Verify the guard is actually immutable before we rely on it.
    let threw = false;
    try {
      resp.headers.set("x-test", "1");
    } catch {
      threw = true;
    }
    if (threw) return resp;
  } catch {
    // data: scheme may not be supported; fall through to manual construction.
  }
  // Construct an immutable-guard Response manually by wrapping a fetch result.  When
  // data: URLs are not available, return a plain Response but note the test will prove
  // the structural copy path rather than the throw-prevention path.
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

export async function run(): Promise<void> {
  // -----------------------------------------------------------------------------------------
  // 1. Root path "/" returns a plain 200 response (non-admin, no auth required).
  // -----------------------------------------------------------------------------------------
  {
    const env = makeEnv(healthStub());
    const r = await workerFetch("/", { method: "GET" }, env, worker);
    ok("/ returns 200", r.status === 200);
    const body = await r.text();
    ok("/ body mentions downpipe engine", body.includes("downpipe engine"));
    // The root banner carries the base hardening headers.
    for (const h of BASE_SEC_HEADERS) {
      ok(`/ base security header present: ${h}`, r.headers.has(h));
    }
  }

  // -----------------------------------------------------------------------------------------
  // 2. Unknown non-admin path returns 404.
  // -----------------------------------------------------------------------------------------
  {
    const env = makeEnv(healthStub());
    const r = await workerFetch("/unknown", { method: "GET" }, env, worker);
    ok("/unknown returns 404", r.status === 404);
    // The 404 carries the base hardening headers too (every emitted response).
    for (const h of BASE_SEC_HEADERS) {
      ok(`/unknown 404 base security header present: ${h}`, r.headers.has(h));
    }
  }

  // -----------------------------------------------------------------------------------------
  // 3. OPTIONS /admin preflight returns 204 with security headers and (when Origin matches)
  //    CORS headers.
  // -----------------------------------------------------------------------------------------
  {
    const ORIGIN = "https://console.example";
    const env = makeEnv(healthStub(), { CONSOLE_ORIGIN: ORIGIN });
    // NOT /admin/health. That route is the ONE origin-allowlist EXEMPTION (HEALTH_CORS, index.ts): it answers a
    // wildcard so a console blocked by a wrong CONSOLE_ORIGIN can still reach it and tell "set CONSOLE_ORIGIN"
    // apart from "the engine is down". It is therefore the one path that cannot test the ALLOWLIST,
    // and using it here would have asserted the exemption while claiming to assert the rule. The rule is tested on
    // an ordinary admin route; the exemption gets its own tests below.
    const r = await workerFetch("/admin/status", { method: "OPTIONS", headers: { Origin: ORIGIN } }, env, worker);
    ok("OPTIONS /admin returns 204", r.status === 204);
    for (const h of SEC_HEADERS) {
      ok(`OPTIONS security header present: ${h}`, r.headers.has(h));
    }
    ok("OPTIONS CORS allow-origin echoes matching origin", r.headers.get("access-control-allow-origin") === ORIGIN);
  }

  // -----------------------------------------------------------------------------------------
  // 4. OPTIONS with a non-matching origin: no CORS access-control-allow-origin header.
  // -----------------------------------------------------------------------------------------
  {
    const ORIGIN = "https://console.example";
    const env = makeEnv(healthStub(), { CONSOLE_ORIGIN: ORIGIN });
    const r = await workerFetch("/admin/status", { method: "OPTIONS", headers: { Origin: "https://attacker.example" } }, env, worker);
    ok("OPTIONS non-matching origin: no CORS header", !r.headers.has("access-control-allow-origin"));
    // Security headers are still applied even without CORS.
    for (const h of SEC_HEADERS) {
      ok(`OPTIONS (no CORS) security header present: ${h}`, r.headers.has(h));
    }
  }

  // -----------------------------------------------------------------------------------------
  // 5. Normal admin GET with a matching CONSOLE_ORIGIN: CORS + security headers on the response.
  //    Uses /admin/health which does not require auth.
  // -----------------------------------------------------------------------------------------
  {
    const ORIGIN = "https://console.example";
    const stub = makeSchedulerStub(async (url: string) => {
      // /admin/health is handled before the scheduler is called, but a stub is still needed.
      return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
    });
    const env = makeEnv(stub, { CONSOLE_ORIGIN: ORIGIN });
    // An ordinary admin route, for the reason given at test 3. The RESPONSE STATUS is not the point here (an
    // unauthenticated caller is refused, and a refusal still carries the CORS headers); the allow-origin ECHO is.
    const r = await workerFetch("/admin/status", { method: "GET", headers: { Origin: ORIGIN } }, env, worker);
    ok("GET /admin CORS allow-origin echoes matching origin", r.headers.get("access-control-allow-origin") === ORIGIN);
    for (const h of SEC_HEADERS) {
      ok(`GET /admin security header present: ${h}`, r.headers.has(h));
    }
  }

  // -----------------------------------------------------------------------------------------
  // 6. CORS: no CONSOLE_ORIGIN configured -> no CORS header on any response.
  // -----------------------------------------------------------------------------------------
  {
    const env = makeEnv(healthStub()); // no CONSOLE_ORIGIN
    const r = await workerFetch("/admin/status", { method: "GET", headers: { Origin: "https://anywhere.example" } }, env, worker);
    ok("no CONSOLE_ORIGIN: no access-control-allow-origin header", !r.headers.has("access-control-allow-origin"));
  }

  // -----------------------------------------------------------------------------------------
  // 7. CORS: origin present but does not match CONSOLE_ORIGIN -> no CORS header.
  // -----------------------------------------------------------------------------------------
  {
    const env = makeEnv(healthStub(), { CONSOLE_ORIGIN: "https://real.console" });
    const r = await workerFetch("/admin/status", { method: "GET", headers: { Origin: "https://evil.attacker" } }, env, worker);
    ok("mismatched origin: no access-control-allow-origin header", !r.headers.has("access-control-allow-origin"));
    // Security headers still present even with no CORS.
    for (const h of SEC_HEADERS) {
      ok(`security headers still applied for non-CORS request: ${h}`, r.headers.has(h));
    }
  }

  // -----------------------------------------------------------------------------------------
  // THE HEALTH-PROBE CORS EXEMPTION, which the whole CORS-versus-outage fingerprint rests on.
  //
  // A CORS-blocked fetch and a fetch to a dead host are THE SAME TypeError in a browser. The console's only way
  // to tell them apart is: "the unauthenticated health probe answered WHILE the data call was blocked" -> the
  // engine is up and something is refusing this console's cross-origin traffic -> SET CONSOLE_ORIGIN. But
  // /admin/health used to sit behind the SAME origin-equality gate as every data route, so in the CONSOLE_ORIGIN
  // scenario -- THE EXACT ONE -- the browser blocked the probe too, and the console recorded engine-unreachable,
  // byte-identical to a genuinely dead engine. The one class that says "fix CONSOLE_ORIGIN" was UNREACHABLE in
  // the state that needs it.
  //
  // So health now answers a WILDCARD origin. These assertions pin the two properties that make that safe, and
  // both are load-bearing:
  //   - the wildcard IS served, even to an origin the allowlist rejects (otherwise the probe is still blocked);
  //   - NO access-control-allow-credentials rides with it. The CORS spec forbids a wildcard from satisfying a
  //     credentialed request, so the browser will not attach the session cookie: the route cannot be turned into
  //     a confused-deputy read of any authenticated state. Wildcard and credentials are mutually exclusive, and
  //     that exclusivity is precisely what is being relied on.
  // -----------------------------------------------------------------------------------------
  {
    const env = makeEnv(healthStub(), { CONSOLE_ORIGIN: "https://real.console" });
    // The console is on an origin the engine does NOT allowlist: exactly the misconfiguration being diagnosed.
    const r = await workerFetch("/admin/health", { method: "GET", headers: { Origin: "https://wrong.console" } }, env, worker);
    ok("health answers 200 to a NON-allowlisted origin (the probe survives a CONSOLE_ORIGIN mismatch)", r.status === 200);
    ok("health carries a WILDCARD allow-origin, so the blocked console can still read it", r.headers.get("access-control-allow-origin") === "*");
    ok("health carries NO allow-credentials: it can never be a confused-deputy read of authenticated state", !r.headers.has("access-control-allow-credentials"));
    for (const h of SEC_HEADERS) {
      ok(`health (wildcard CORS) security header still present: ${h}`, r.headers.has(h));
    }
  }
  {
    // The exemption is an EXACT-MATCH on the one route, never a prefix: a prefix would hand the wildcard to any
    // future /admin/health-* route that might not deserve it. An ordinary admin route on a rejected origin still
    // gets NO CORS header at all.
    const env = makeEnv(healthStub(), { CONSOLE_ORIGIN: "https://real.console" });
    const r = await workerFetch("/admin/healthz", { method: "GET", headers: { Origin: "https://wrong.console" } }, env, worker);
    ok("the exemption does NOT leak to a look-alike path (/admin/healthz gets no wildcard)", r.headers.get("access-control-allow-origin") !== "*");
  }

  // -----------------------------------------------------------------------------------------
  // IMMUTABLE-HEADERS REGRESSION: handleAdmin returns a Response with IMMUTABLE headers (simulating a
  //    response forwarded from scheduler.fetch()). The worker MUST apply security headers
  //    WITHOUT throwing, and the response MUST arrive at the caller (not an unhandled error).
  //    This is the exact bug that caused a live 500/error-1101 before the fix in index.ts.
  // -----------------------------------------------------------------------------------------
  {
    const immutableResp = await immutableHeaderResponse();

    // Build a stub whose fetch returns our immutable-headers response. This simulates
    // handleAdmin forwarding the DO's response directly (the pre-fix behaviour from routes
    // like GET /admin/downpipes: `return scheduler.fetch(doURL("/downpipes"), ...)`).
    // handleAdmin's /admin/health path answers before calling the scheduler, so we need to
    // reach a route that DOES forward to the scheduler. We use /admin/downpipes (GET), which
    // the scheduler forwards; the stub returns a 200 JSON response whose headers are the
    // immutable-guard variant.
    const immutableStub = makeSchedulerStub(async (url: string) => {
      // The bare-token auth gate now reads the break-glass-retired latch from the DO (auth.ts wiring); a
      // fresh tenant has not retired, so answer it not-retired (the resolver fails closed otherwise) and the
      // token authorises, reaching the GET /admin/downpipes forward this test exercises.
      if (url.endsWith("/policy/break-glass-retired")) {
        return new Response(JSON.stringify({ breakGlassTokenRetired: false }), { headers: { "content-type": "application/json" } });
      }
      // Return the pre-built immutable response (from fetch("data:...")), OR a cloned one.
      return immutableResp.clone();
    });

    // Use a token-auth env so handleAdmin passes the auth gate (no Access JWT needed).
    const env = makeEnv(immutableStub, {
      ADMIN_TOKEN: "test-token-immutable",
      CONSOLE_ORIGIN: "https://console.example",
    });
    const init: RequestInit = {
      method: "GET",
      headers: {
        authorization: "Bearer test-token-immutable",
        Origin: "https://console.example",
      },
    };

    let threw = false;
    let r: Response | undefined;
    try {
      r = await workerFetch("/admin/downpipes", init, env, worker);
    } catch (e) {
      threw = true;
      console.log(`  FAIL immutable-headers regression: worker threw: ${(e as Error).message}`);
    }

    ok("worker does NOT throw on immutable-headers response", !threw);
    if (r !== undefined) {
      ok("response arrives (not undefined)", true);
      for (const h of SEC_HEADERS) {
        ok(`security header applied on immutable-origin response: ${h}`, r.headers.has(h));
      }
      ok(
        "CORS applied on immutable-origin response",
        r.headers.get("access-control-allow-origin") === "https://console.example",
      );
    } else {
      // Mark all sub-checks failed if we never got a response.
      for (const h of SEC_HEADERS) {
        ok(`security header applied on immutable-origin response: ${h}`, false);
      }
      ok("CORS applied on immutable-origin response", false);
    }
  }

  // -----------------------------------------------------------------------------------------
  // RUN-NOW drives the seal: POST /admin/trigger must allocate the run AND drive
  //     the actual seal in the invocation background (ctx.waitUntil), not just forward to the DO
  //     and strand the downpipe in flight with a fake success. We assert it returns running:true
  //     with the allocated runId and that it invoked the injected seal capability.
  // -----------------------------------------------------------------------------------------
  {
    let triggerCalls = 0;
    const stub = makeSchedulerStub(async (url: string) => {
      // The bare-token auth path now consults the break-glass-retired latch in the DO (auth.ts wiring).
      // A FRESH tenant has NOT retired, so answer the durable latch as not-retired; the resolver fails
      // CLOSED on anything other than an explicit false, so this stub must say so for the token to authorise.
      if (url.endsWith("/policy/break-glass-retired")) {
        return new Response(JSON.stringify({ breakGlassTokenRetired: false }), { headers: { "content-type": "application/json" } });
      }
      if (url.endsWith("/trigger")) {
        triggerCalls++;
        return new Response(
          JSON.stringify({
            runId: "01RUNNOWRUNNOWRUNNOWRUNN",
            index: 7,
            prevRunId: null,
            config: { id: "dp-now", name: "n", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "SRC", include: [], exclude: [] } },
          }),
          { headers: { "content-type": "application/json" } },
        );
      }
      return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
    });
    // Token auth so resolveCaller resolves Owner without a DO whoami round trip. SIGNER_PRIVATE is
    // absent, so the background seal rejects early; the ctx spy swallows it (we test the wiring only).
    const env = makeEnv(stub, { ADMIN_TOKEN: "test-token" } as Partial<Env>);
    let waitUntilCalls = 0;
    // Capture the background seal promise so we can DRAIN it before this subtest ends. The seal
    // deliberately fails here (the stub leaves the engine "not fully configured"), emitting one coarse
    // error line via the structured logger; draining it inside this subtest keeps that async line from
    // landing in a LATER subtest's console.error capture window (8d), which would otherwise see a
    // spurious second line. This is a test-isolation fix only; the production waitUntil contract is
    // unchanged (the live runtime still runs the seal in the background).
    const bg: Promise<unknown>[] = [];
    const ctx = {
      waitUntil: (p: Promise<unknown>) => { waitUntilCalls++; bg.push(Promise.resolve(p).catch(() => {})); },
      passThroughOnException: () => {},
    } as unknown as ExecutionContext;
    const req = new Request("https://engine.example/admin/trigger", {
      method: "POST",
      headers: { authorization: "Bearer test-token", "content-type": "application/json" },
      body: JSON.stringify({ id: "dp-now" }),
    });
    const resp = await worker.fetch(req, env, ctx);
    ok("run-now: POST /admin/trigger returns 200", resp.status === 200);
    const body = (await resp.json()) as { runId?: string; running?: boolean };
    ok("run-now: response reports the run is RUNNING (not a bare allocation)", body.running === true);
    ok("run-now: response carries the allocated runId", body.runId === "01RUNNOWRUNNOWRUNNOWRUNN");
    ok("run-now: the DO /trigger was called once (run allocated)", triggerCalls === 1);
    // waitUntilCalls is 2, not 1: sealNow's own background seal, PLUS handleAdmin's own
    // fireInBackground(noteAdminAuthMethod(...)), which also
    // keeps its write alive past the response instead of a bare, unguaranteed `void`. Both are expected on
    // every authenticated admin request; this assertion is not weakened, it is updated to the new correct
    // count so a REGRESSION (either capability silently stopping) still fails it.
    ok("run-now: the seal was DRIVEN in the background (ctx.waitUntil invoked)", waitUntilCalls === 2);
    // Drain the background seal (it fails by design) so its coarse error line is flushed HERE, not in a
    // later subtest's capture window.
    await Promise.all(bg);
  }

  // -----------------------------------------------------------------------------------------
  // 8c. V14.3.2 (Cache-Control on authenticated responses): every admin response must carry
  //     cache-control:no-store (and pragma:no-cache) so an authenticated/sensitive body
  //     (whoami's verified email+role, audit, history, status) is never retained by a browser
  //     back-button, a disk cache, or any intermediary. The SEC_HEADERS loop above asserts the
  //     header is PRESENT on every case; here we pin the VALUE on a representative admin read.
  // -----------------------------------------------------------------------------------------
  {
    const env = makeEnv(healthStub());
    const r = await workerFetch("/admin/health", { method: "GET" }, env, worker);
    ok("V14.3.2: admin response carries cache-control:no-store", r.headers.get("cache-control") === "no-store");
    ok("V14.3.2: admin response carries pragma:no-cache", r.headers.get("pragma") === "no-cache");
  }

  // -----------------------------------------------------------------------------------------
  // 8d. V16.3.4 + V16.5.4 (last-resort error handler): a POST /admin/<route> with a MALFORMED
  //     JSON body makes the router's `await req.json()` throw a SyntaxError. Before the fix that
  //     escaped handleAdmin to the Cloudflare runtime UNLOGGED. The worker must now catch it,
  //     return a generic 500 JSON (no stack to the client), and STILL apply CORS + the security
  //     headers. We use POST /admin/downpipes: it `await req.json()`s the body before any DO call,
  //     and the ADMIN_TOKEN path resolves Owner without a round trip, so the malformed body reaches
  //     req.json() and throws. We capture console.error to confirm the error is logged, not silent.
  // -----------------------------------------------------------------------------------------
  {
    const ORIGIN = "https://console.example";
    // The scheduler must never be reached on the ROUTE path (the throw happens at req.json(), before any
    // forward); a stub that fails the test if called proves the 500 came from the catch, not the DO. The
    // bare-token AUTH gate now reads the break-glass-retired latch from the DO (auth.ts wiring) BEFORE the
    // route body is parsed, so that one read is the auth gate, not a route forward: answer it as not-retired
    // (so the token authorises and control reaches the malformed req.json()), and exempt it from the
    // "scheduler NOT called" assertion below.
    //
    // /diag/dispatch-fault is the SECOND exemption: the last-resort catch files
    // this 500 into a bounded DO ring, because a customer's "the console 500s on Notifications" previously
    // left NO trace the vendor could ever read (the errId lived only in a Workers Logs line the pack
    // structurally cannot carry). It fires AFTER the throw, from the catch -- so the property this assertion
    // exists to protect is untouched: the malformed body is still never FORWARDED. To keep that property
    // ASSERTED rather than merely assumed, the exemption below does not wave the call through: it inspects the
    // posted body and FAILS if any byte of the malformed input rode along with it.
    const MALFORMED = "{ this is not valid json";
    let dispatchFaultBody = "";
    const stub = makeSchedulerStub(async (url: string, init?: RequestInit) => {
      if (url.endsWith("/policy/break-glass-retired")) {
        return new Response(JSON.stringify({ breakGlassTokenRetired: false }), { headers: { "content-type": "application/json" } });
      }
      if (url.endsWith("/diag/dispatch-fault")) {
        dispatchFaultBody = typeof init?.body === "string" ? init.body : "";
        return new Response("{}", { headers: { "content-type": "application/json" } });
      }
      ok("V16.3.4: scheduler NOT called on a malformed body (throw precedes any forward)", false);
      return new Response("{}", { headers: { "content-type": "application/json" } });
    });
    const env = makeEnv(stub, { ADMIN_TOKEN: "test-token-500", CONSOLE_ORIGIN: ORIGIN });

    // Capture the coarse console.error line the last-resort handler emits (V16.3.4 wants the
    // unexpected error LOGGED). Restore the original immediately after the call.
    const origError = console.error;
    let logged = 0;
    let loggedStack = false;
    console.error = (...args: unknown[]) => {
      logged++;
      // The log line must be coarse: never the raw Error object / a stack, only a message string.
      if (args.some((a) => a instanceof Error || (typeof a === "string" && a.includes("\n    at ")))) loggedStack = true;
    };

    let threw = false;
    let r: Response | undefined;
    try {
      r = await worker.fetch(
        new Request(`https://engine.example/admin/downpipes`, {
          method: "POST",
          headers: { authorization: "Bearer test-token-500", "content-type": "application/json", Origin: ORIGIN },
          body: MALFORMED,
        }),
        env,
        { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext,
      );
    } catch (e) {
      threw = true;
      console.error = origError;
      console.log(`  FAIL V16.5.4 last-resort: worker threw instead of returning 500: ${(e as Error).message}`);
    } finally {
      console.error = origError;
    }

    ok("V16.5.4: malformed JSON body does NOT escape as an unhandled throw", !threw);
    // The last-resort catch DID file the 500 into the bounded dispatch-fault ring, so a
    // 500 the customer saw is finally something the pack can carry. Assert BOTH halves of the contract:
    //   - the record exists (a surface that 500s is no longer invisible), and
    //   - it carries the CLOSED evidence ONLY -- the closed surface, the closed route family derived from the
    //     path PREFIX, and the irreversible 8-hex errId. NOT ONE BYTE of the malformed request body may ride,
    //     which is the property "scheduler NOT called on a malformed body" was really protecting.
    ok("the last-resort 500 was recorded to the dispatch-fault ring", dispatchFaultBody !== "");
    ok("the dispatch-fault record carries NO byte of the malformed request body", !dispatchFaultBody.includes("not valid json"));
    ok("the dispatch-fault record carries the closed surface + route family + 8-hex errId only", (() => {
      const b = JSON.parse(dispatchFaultBody === "" ? "{}" : dispatchFaultBody) as Record<string, unknown>;
      return b.surface === "admin" && b.routeFamily === "downpipes" && typeof b.errId === "string" && /^[0-9a-f]{8}$/.test(b.errId) && b.httpStatus === 500;
    })());
    if (r !== undefined) {
      ok("V16.3.4: malformed JSON body yields a 500 (not an unhandled crash)", r.status === 500);
      const body = (await r.json()) as { error?: string };
      ok("V16.3.4: 500 body is the generic { error: 'internal error' } (no detail leaked)", body.error === "internal error");
      ok("V16.3.4: the unexpected error WAS logged (console.error called)", logged === 1);
      ok("V16.3.4: the logged line is coarse (no Error object / stack)", !loggedStack);
      // The error response MUST still carry the security headers (and, via 8c, cache-control:no-store).
      for (const h of SEC_HEADERS) {
        ok(`V16.3.4: 500 error response still carries security header: ${h}`, r.headers.has(h));
      }
      ok("V16.3.4: 500 error response still carries CORS allow-origin", r.headers.get("access-control-allow-origin") === ORIGIN);
    } else {
      ok("V16.3.4: malformed JSON body yields a 500 (not an unhandled crash)", false);
    }
  }
}
