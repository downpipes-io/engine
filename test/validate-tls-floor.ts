// validate-tls-floor: a request that arrived over TLS 1.1 or older is refused before any route sees it
// (ASVS V12.1.1), and everything the floor cannot positively read as below it passes through.
//
// The engine deploys into the customer's zone, which starts on Cloudflare's 1.0 floor, and the product holds
// no zone-write credential, so the in-band refusal with the remedy named is the control the product can own.
// Every refusal below is paired with a pass-through control on the same route, so a 426 is the floor and not a
// route that happened to fail.

import worker from "../src/index.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

function reqWithTls(tlsVersion: string | undefined): Request {
  const r = new Request("https://engine.example/ready");
  if (tlsVersion !== undefined) Object.defineProperty(r, "cf", { value: { tlsVersion }, enumerable: true });
  return r;
}
const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;

async function main(): Promise<void> {
  console.log("\nbelow the floor: refused with the remedy named, before /ready is reached");
  for (const v of ["SSLv3", "TLSv1", "TLSv1.1"]) {
    const resp = await worker.fetch(reqWithTls(v), {} as Env, ctx);
    const body = await resp.text();
    ok(`${v}: 426 Upgrade Required`, resp.status === 426);
    ok(`${v}: the body names the version and the dashboard setting`, body.includes(v) && body.includes("Minimum TLS Version"));
    ok(`${v}: the correlation id still rides on the refusal`, resp.headers.has("x-downpipe-request-id"));
  }
  console.log("\ncontrols: at or above the floor, and with no signal at all, the route is served");
  for (const [label, v] of [["TLS 1.2", "TLSv1.2"], ["TLS 1.3", "TLSv1.3"], ["an unknown version string", "TLSv9"], ["no cf object (local dev, tests)", undefined]] as [string, string | undefined][]) {
    const resp = await worker.fetch(reqWithTls(v), {} as Env, ctx);
    ok(`${label}: /ready is served (${resp.status})`, resp.status === 200);
  }
  console.log(failures === 0 ? "\nTLS FLOOR VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}
void main();
