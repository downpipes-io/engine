// B-093: the three unauthenticated routes (/admin/health, /ready, /) answer GET and HEAD only.
// Any other method gets 405 with `Allow: GET, HEAD`. OPTIONS keeps its existing behaviour, and
// GET and HEAD stay 200. A path the engine does not serve still answers 404.
//
// Driven through the REAL default export (src/index.ts fetch), in-memory only.
// Run: node test/validate-method-not-allowed.ts

import worker from "../src/index.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ctx = { waitUntil: (_p: Promise<unknown>) => {}, passThroughOnException: () => {} } as unknown as ExecutionContext;
const env = {} as unknown as Env;

async function call(method: string, path: string): Promise<Response> {
  return worker.fetch(new Request(`https://engine.example${path}`, { method }), env, ctx);
}

async function main(): Promise<void> {
  const routes = ["/admin/health", "/ready", "/"];
  for (const path of routes) {
    for (const method of ["DELETE", "POST", "PUT", "PATCH"]) {
      const r = await call(method, path);
      ok(`${method} ${path} answers 405`, r.status === 405);
      ok(`${method} ${path} carries Allow: GET, HEAD`, r.headers.get("allow") === "GET, HEAD");
    }
    for (const method of ["GET", "HEAD"]) {
      const r = await call(method, path);
      ok(`${method} ${path} stays 200`, r.status === 200);
    }
    const opt = await call("OPTIONS", path);
    ok(`OPTIONS ${path} is not 405`, opt.status !== 405);
    ok(`OPTIONS ${path} answers 200 or 204`, opt.status === 200 || opt.status === 204);
  }
  ok("an unserved path still answers 404", (await call("GET", "/nope")).status === 404);
  ok("a POST to an authenticated route is not 405", (await call("POST", "/admin/roles")).status !== 405);

  verdictReached(failures);
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nMETHOD-NOT-ALLOWED (B-093) VECTORS PASS");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
