// Prove the admin CORS preflight allow-list actually covers every header the console's
// own client sends, so the browser never silently blocks a real request before it reaches us.
//
// The bug this guards: corsHeaders() in src/index.ts hardcoded "authorization, content-type" as
// access-control-allow-headers. router-core.ts's STEPUP_HEADER (the step-up re-auth retry,
// client-transport.ts's gatedFetch) and change-ref.ts's CHANGE_HEADER (the opt-in change-
// management header) were both added later and never folded into that list. In the documented
// cross-origin (split) deployment this makes the browser's OWN preflight reject the real request
// client-side -- the step-up retry after a stale-session 401, and every change-controlled
// mutation once "Require Change Number" is on, would never even reach the engine, with no
// server-side log of the attempt. The fix sources the allow-list from the same exported
// constants the console's client and the engine's own gates use, so the two can't drift apart
// again the way they did here.
//
// Driven through the REAL default export (src/index.ts fetch), in-memory only; no network, no
// deploy, no cost. Run: node test/validate-cors-headers.ts.

import worker from "../src/index.ts";
import type { Env } from "../src/env.d.ts";
import { STEPUP_HEADER } from "../src/admin/router-core.ts";
import { CHANGE_HEADER } from "../src/admin/change-ref.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ORIGIN = "https://console.downpipes.example";

// A no-op ExecutionContext: a preflight OPTIONS never reaches the background-work paths.
const ctx = { waitUntil: (_p: Promise<unknown>) => {}, passThroughOnException: () => {} } as unknown as ExecutionContext;

function envWithOrigin(): Env {
  return { CONSOLE_ORIGIN: ORIGIN } as unknown as Env;
}

// allowedTokens parses access-control-allow-headers the way a browser does: comma-split,
// trimmed, case-INsensitive (RFC 7230 token comparison), as a Set for membership checks.
function allowedTokens(resp: Response): Set<string> {
  const raw = resp.headers.get("access-control-allow-headers") ?? "";
  return new Set(raw.split(",").map((s) => s.trim().toLowerCase()).filter((s) => s.length > 0));
}

// preflight fires the exact OPTIONS request a browser sends ahead of a cross-origin admin call:
// the configured console Origin, plus the Access-Control-Request-Headers the real request will
// carry (a browser computes this from the headers the actual fetch() call sets).
async function preflight(requestHeaders: string): Promise<Response> {
  return worker.fetch(
    new Request("https://engine.example/admin/keys/rotate", {
      method: "OPTIONS",
      headers: {
        Origin: ORIGIN,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": requestHeaders,
      },
    }),
    envWithOrigin(),
    ctx,
  );
}

async function main(): Promise<void> {
  // 1. The pre-existing pair (authorization, content-type) must keep working -- this is the
  // regression guard for the two headers every admin call already relied on.
  {
    const resp = await preflight("authorization, content-type");
    ok("preflight for authorization+content-type answers 204", resp.status === 204);
    const allowed = allowedTokens(resp);
    ok("authorization stays allowed", allowed.has("authorization"));
    ok("content-type stays allowed", allowed.has("content-type"));
  }

  // 2. The step-up re-auth retry header (client-transport.ts gatedFetch): must be allowed, or the
  // console's own compensating control for a stale session can never complete in the split topology.
  {
    const resp = await preflight(STEPUP_HEADER);
    ok(`preflight for ${STEPUP_HEADER} answers 204`, resp.status === 204);
    ok(`${STEPUP_HEADER} is in access-control-allow-headers`, allowedTokens(resp).has(STEPUP_HEADER.toLowerCase()));
  }

  // 3. The change-management header (change-ref.ts): must be allowed, or every change-controlled
  // mutation is blocked client-side once the owner opts into "Require Change Number".
  {
    const resp = await preflight(CHANGE_HEADER);
    ok(`preflight for ${CHANGE_HEADER} answers 204`, resp.status === 204);
    ok(`${CHANGE_HEADER} is in access-control-allow-headers`, allowedTokens(resp).has(CHANGE_HEADER.toLowerCase()));
  }

  // 4. The combined case: a step-up retry of a change-controlled mutation carries BOTH custom
  // headers on the one request (client-transport.ts sets both from the same headers() builder).
  {
    const resp = await preflight(`${STEPUP_HEADER}, ${CHANGE_HEADER}`);
    ok("preflight for the combined step-up + change-ref case answers 204", resp.status === 204);
    const allowed = allowedTokens(resp);
    ok("combined case: both custom headers are allowed together", allowed.has(STEPUP_HEADER.toLowerCase()) && allowed.has(CHANGE_HEADER.toLowerCase()));
  }

  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nCORS-HEADERS VECTORS PASS");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
