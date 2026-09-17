// validate-plaintext-refused: the engine never serves a request that arrived over http:// (ASVS V12.3.1).
// A credentialed or sensitive request is refused with a 400 naming the zone setting (a redirect would have
// carried the bearer or cookie in clear already); a credential-free navigation is sent to https; the loopback
// hosts are the wrangler dev seam. Every refusal is paired with the same route served over https.
import worker from "../src/index.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
let failures = 0;
function ok(label: string, cond: boolean): void { console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`); if (!cond) failures++; }
const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
const go = (url: string, init?: RequestInit) => worker.fetch(new Request(url, init), {} as Env, ctx);
async function main(): Promise<void> {
  console.log("\nplaintext, credentialed or sensitive: refused, never served, never redirected with the credential");
  for (const [label, url, init] of [
    ["a bearer on /admin over http", "http://engine.example/admin/status", { headers: { authorization: "Bearer t" } }],
    ["a cookie on a plain path over http", "http://engine.example/ready", { headers: { cookie: "__Host-downpipes_session=x" } }],
    ["/admin with no credential over http", "http://engine.example/admin/status", undefined],
    ["/scim over http", "http://engine.example/scim/v2/Users", undefined],
    ["a POST over http", "http://engine.example/ready", { method: "POST" }],
  ] as [string, string, RequestInit | undefined][]) {
    const r = await go(url, init); const body = await r.text();
    ok(`${label}: 400 https required`, r.status === 400 && body.includes("https required"));
    ok(`${label}: not a redirect (no location header carrying anything onward)`, !r.headers.has("location"));
  }
  console.log("\nplaintext, credential-free navigation: sent to https, same path and query");
  {
    const r = await go("http://engine.example/ready?x=1");
    ok("308 to the https form", r.status === 308 && r.headers.get("location") === "https://engine.example/ready?x=1");
  }
  console.log("\ncontrols: https is served; loopback plaintext is the dev seam");
  ok("https /ready is served (200)", (await go("https://engine.example/ready")).status === 200);
  ok("http://localhost /ready is served (dev seam)", (await go("http://localhost:8787/ready")).status === 200);
  ok("http://127.0.0.1 /ready is served (dev seam)", (await go("http://127.0.0.1:8787/ready")).status === 200);
  console.log(failures === 0 ? "\nPLAINTEXT REFUSED VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures); if (failures > 0) process.exit(1);
}
void main();
