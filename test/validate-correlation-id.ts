// Prove the engine Worker echoes a request-CORRELATION id on every response so an operator's 500
// can be tied to the matching `wrangler tail` log line.
//
// The bug this guards: the coarse operational error id is FNV-1a of ClassName:message (irreversible) and
// lived ONLY in the logs -- the HTTP response carried no cf-ray / x-request-id, so a 500 the operator saw
// in the browser had no thread back to the log. The fix mints one correlation id per request (the cf-ray
// when the edge supplies one, else a freshly minted dpr-<uuid>), echoes it on EVERY response as
// `x-downpipe-request-id`, logs it alongside the err-id on the catch paths, and includes it as `requestId`
// in the RFC 9457 problem body of a 500 so even a body-only operator has the handle.
//
// Driven through the REAL default export (src/index.ts fetch), in-memory only; no network, no deploy, no
// cost. Run: node test/validate-correlation-id.ts.

import worker from "../src/index.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const HEADER = "x-downpipe-request-id";

// A no-op ExecutionContext: the chrome only ever ctx.waitUntil()s background work, never awaits it here.
const ctx = { waitUntil: (_p: Promise<unknown>) => {}, passThroughOnException: () => {} } as unknown as ExecutionContext;

function bareEnv(extra?: Partial<Env>): Env {
  return { ...extra } as unknown as Env;
}

async function main(): Promise<void> {
  // 1. /ready (unauthenticated liveness) echoes a correlation id, and with NO cf-ray it is a minted dpr-<uuid>.
  {
    const resp = await worker.fetch(new Request("https://engine.example/ready"), bareEnv(), ctx);
    const cid = resp.headers.get(HEADER);
    ok("/ready echoes the x-downpipe-request-id header", cid !== null && cid.length > 0);
    ok("/ready with no cf-ray mints a dpr-<uuid> correlation id", (cid ?? "").startsWith("dpr-"));
    ok("/ready still returns 200 with its body intact", resp.status === 200 && (await resp.json() as { status: string }).status === "ok");
  }

  // 2. When the edge supplies a cf-ray, the echoed id IS that ray (free correlation to the platform log).
  {
    const ray = "8b1234567890abcd-SYD";
    const resp = await worker.fetch(new Request("https://engine.example/ready", { headers: { "cf-ray": ray } }), bareEnv(), ctx);
    ok("the echoed correlation id is the cf-ray when the edge supplies one", resp.headers.get(HEADER) === ray);
  }

  // 3. Two requests with no cf-ray get DISTINCT minted ids (a real per-request handle, not a constant).
  {
    const a = await worker.fetch(new Request("https://engine.example/ready"), bareEnv(), ctx);
    const b = await worker.fetch(new Request("https://engine.example/ready"), bareEnv(), ctx);
    ok("two ray-less requests mint distinct correlation ids", a.headers.get(HEADER) !== b.headers.get(HEADER));
  }

  // 4. A non-admin 404 also carries the correlation header (every path is covered, not just /admin).
  {
    const resp = await worker.fetch(new Request("https://engine.example/nope"), bareEnv(), ctx);
    ok("a 404 carries the correlation header", resp.status === 404 && (resp.headers.get(HEADER) ?? "").length > 0);
  }

  // 5. The 500 catch path: the RFC 9457 problem body carries `requestId` and it MATCHES the response header,
  // so an operator with only the JSON body (or only the header) can correlate to the one logged line. We
  // force a dispatch throw on the (unauthenticated) /support surface by leaving SCHEDULER unset: the chrome
  // resolves schedulerStub(env) inside the try and the undefined namespace throws, landing in the catch.
  {
    const ray = "8bdeadbeefcafe00-SYD";
    const resp = await worker.fetch(
      new Request("https://engine.example/support/diagnostics", { headers: { "cf-ray": ray } }),
      bareEnv(), // SCHEDULER is undefined -> schedulerStub() throws -> the last-resort catch fires
      ctx,
    );
    ok("a forced dispatch fault returns 500", resp.status === 500);
    const header = resp.headers.get(HEADER);
    ok("the 500 carries the correlation header (= the cf-ray)", header === ray);
    ok("the 500 is the RFC 9457 problem+json shape", (resp.headers.get("content-type") ?? "").includes("application/problem+json"));
    const body = (await resp.json()) as { error?: string; requestId?: string };
    ok("the 500 problem body still carries the coarse error field (unchanged contract)", body.error === "internal error");
    ok("the 500 problem body carries requestId matching the header", body.requestId === header);
  }

  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nCORRELATION-ID VECTORS PASS");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
