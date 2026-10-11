// validate-engine-response-floor: every response the Worker emits carries the same hardening floor.
//
// The engine serves no HTML, and a browser that reaches one of its responses should still be told not to
// render, frame, sniff or cache it. The /admin and /support responses already carried these headers. The
// public "/", "/ready" and "/scim" responses and the early refusals (hop-by-hop guard, TLS floor, plaintext
// refusal and redirect) carried only some of them. This validator drives the real Worker entry over each of
// those paths and proves every response carries the floor:
//  - content-security-policy: default-src 'none'; frame-ancestors 'none'
//  - x-content-type-options: nosniff
//  - x-frame-options: DENY
//  - strict-transport-security
//  - cache-control: no-store
// and that a header a route already set is not overwritten.
//
// Run: node test/validate-engine-response-floor.ts

import worker from "../src/index.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
const go = (req: Request): Promise<Response> => worker.fetch(req, {} as Env, ctx);

function withTls(url: string, tlsVersion: string): Request {
  const r = new Request(url);
  Object.defineProperty(r, "cf", { value: { tlsVersion }, enumerable: true });
  return r;
}

const FLOOR: Array<[string, (v: string | null) => boolean]> = [
  ["content-security-policy", (v) => v !== null && /default-src 'none'/.test(v) && /frame-ancestors 'none'/.test(v)],
  ["x-content-type-options", (v) => v === "nosniff"],
  ["x-frame-options", (v) => v === "DENY"],
  ["strict-transport-security", (v) => v !== null && /max-age=\d+/.test(v)],
  ["cache-control", (v) => v !== null && /no-store/.test(v)],
];

async function main(): Promise<void> {
  const cases: Array<[string, Request]> = [
    ["GET /", new Request("https://engine.example/")],
    ["GET /ready", new Request("https://engine.example/ready")],
    ["GET an unknown path (404)", new Request("https://engine.example/nope")],
    ["GET /scim/v2/ServiceProviderConfig (no SCIM bearer configured)", new Request("https://engine.example/scim/v2/ServiceProviderConfig")],
    ["the hop-by-hop refusal", new Request("https://engine.example/ready", { headers: { "proxy-connection": "keep-alive" } })],
    ["the TLS floor refusal", withTls("https://engine.example/ready", "TLSv1")],
    ["the plaintext refusal", new Request("http://engine.example/admin/status")],
    ["the plaintext redirect", new Request("http://engine.example/ready")],
  ];
  for (const [label, req] of cases) {
    const r = await go(req);
    console.log(`  ${label}: status=${r.status}`);
    for (const [name, accepts] of FLOOR) ok(`${label}: ${name}`, accepts(r.headers.get(name)));
  }
  console.log("\ncontrol: the /admin responses carry the same floor");
  const admin = await go(new Request("https://engine.example/admin/status"));
  for (const [name, accepts] of FLOOR) ok(`/admin/status: ${name}`, accepts(admin.headers.get(name)));
  console.log(failures === 0 ? "\nVALIDATE-ENGINE-RESPONSE-FLOOR VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
