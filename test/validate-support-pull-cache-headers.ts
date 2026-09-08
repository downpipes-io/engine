// ASVS V4 (14.3.2): prove the two credentialed /support/* pull routes carry the full
// SECURITY_HEADERS set (cache-control:no-store + pragma:no-cache, the same set /admin/* gets) instead
// of the weaker BASE_SECURITY_HEADERS -- and that the genuinely-unauthenticated "/" and 404 branches
// are UNCHANGED, so the fix is scoped to the two authenticated routes and not a blanket regression.
//
// The bug this guards: handleNonAdminRoute dispatched /support/diagnostics and /support/audit-feed
// through withBaseSecurity() (the same wrapper as "/" and 404), so a bearer-authenticated response
// carrying real account state (a signed diagnostics bundle / hash-chained audit events) had no
// cache-control or pragma header -- exactly the class of response SECURITY_HEADERS exists to protect,
// per its own ASVS V14.3.2 comment. The fix routes those two branches through withSecurity() instead,
// which covers the success AND error paths (401/503/404) uniformly since it wraps the dispatch, not
// handleSupportPull's individual return statements.
//
// Driven through the REAL default export (src/index.ts fetch), with a stub SCHEDULER whose fetch()
// answers the one DO route handleSupportPull needs (GET /ingest-credential?scope=...) with a null
// grant, so an unauthenticated presentation resolves to a clean 401 with no other DO traffic required.
//
// Run: node test/validate-support-pull-cache-headers.ts

import worker from "../src/index.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// A no-op ExecutionContext: this path never awaits background work.
const ctx = { waitUntil: (_p: Promise<unknown>) => {}, passThroughOnException: () => {} } as unknown as ExecutionContext;

// A minimal scheduler stub: answers /ingest-credential with a null grant (no credential ever
// granted), which is enough for handleSupportPull to resolve a clean 401 -- no other DO route is
// touched on this path.
function bareSchedulerEnv(): Env {
  const stub = {
    fetch: async (input: RequestInfo | URL): Promise<Response> => {
      const u = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (u.includes("/ingest-credential")) {
        return new Response(JSON.stringify({ grant: null }), { headers: { "content-type": "application/json" } });
      }
      return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  return { SCHEDULER: namespace } as unknown as Env;
}

async function main(): Promise<void> {
  const env = bareSchedulerEnv();

  // (a) /support/diagnostics, no Authorization -> 401, WITH cache-control:no-store + pragma:no-cache.
  {
    const resp = await worker.fetch(new Request("https://engine.example/support/diagnostics"), env, ctx);
    ok("GET /support/diagnostics with no bearer -> 401", resp.status === 401);
    ok("/support/diagnostics 401 carries cache-control:no-store", resp.headers.get("cache-control") === "no-store");
    ok("/support/diagnostics 401 carries pragma:no-cache", resp.headers.get("pragma") === "no-cache");
  }

  // (b) /support/audit-feed, no Authorization -> the same two header assertions.
  {
    const resp = await worker.fetch(new Request("https://engine.example/support/audit-feed"), env, ctx);
    ok("GET /support/audit-feed with no bearer -> 401", resp.status === 401);
    ok("/support/audit-feed 401 carries cache-control:no-store", resp.headers.get("cache-control") === "no-store");
    ok("/support/audit-feed 401 carries pragma:no-cache", resp.headers.get("pragma") === "no-cache");
  }

  // (c) negative control: "/" and the 404 fallback are UNTOUCHED -- no cache-control/pragma leaks onto
  // the genuinely-unauthenticated branches, proving the fix is scoped to the two /support/* routes.
  {
    const root = await worker.fetch(new Request("https://engine.example/"), env, ctx);
    ok("GET / has no cache-control header (base security unchanged)", root.headers.get("cache-control") === null);
    ok("GET / has no pragma header (base security unchanged)", root.headers.get("pragma") === null);

    const notFound = await worker.fetch(new Request("https://engine.example/nope-404"), env, ctx);
    ok("GET /nope-404 is a 404", notFound.status === 404);
    ok("GET /nope-404 has no cache-control header (base security unchanged)", notFound.headers.get("cache-control") === null);
    ok("GET /nope-404 has no pragma header (base security unchanged)", notFound.headers.get("pragma") === null);
  }

  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nSUPPORT-PULL CACHE-HEADERS VECTORS PASS");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
