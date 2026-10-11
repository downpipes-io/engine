// validate-scim-access-offboarding: the SCIM capability advertisement says what a SCIM offboarding reaches.
//
// A SCIM DELETE removes the member's role row and ends their sessions on this engine. A person who signs in
// through Cloudflare Access carries an Access JWT that Cloudflare Access issues and this engine verifies; the
// engine cannot end it. Access keeps authorising that person until Access itself stops, so the offboarding
// has to include the Access policy. ServiceProviderConfig.documentationUri is what an identity provider's
// operator reads, so it names that limit.
//
// This validator reads the real handleScim answer and proves the documentationUri:
//  - still says the surface is deprovision-only;
//  - names Cloudflare Access and says a member who signs in through it must be removed in Cloudflare Access.
//
// Run: node test/validate-scim-access-offboarding.ts

import { handleScim } from "../src/admin/scim.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const TOKEN = "scim-access-offboarding-bearer";
const stub = { fetch: async (): Promise<Response> => new Response(JSON.stringify({ allowed: true }), { headers: { "content-type": "application/json" } }) } as unknown as DurableObjectStub;
const env = {
  SCHEDULER: { idFromName: () => ({}) as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace,
  SCIM_BEARER_TOKEN: TOKEN,
} as unknown as Env;

async function main(): Promise<void> {
  const r = await handleScim(new Request("https://engine.example/scim/v2/ServiceProviderConfig", { headers: { authorization: `Bearer ${TOKEN}` } }), env);
  ok("GET ServiceProviderConfig answers 200", r.status === 200);
  const doc = ((await r.json()) as { documentationUri?: unknown }).documentationUri;
  const text = typeof doc === "string" ? doc : "";
  console.log(`  documentationUri: ${text}`);
  ok("documentationUri still says deprovision-only", /deprovision-only/.test(text));
  ok("documentationUri names Cloudflare Access", /Cloudflare Access/.test(text));
  ok("documentationUri says an Access sign-in must be removed in Access", /removed in Cloudflare Access/.test(text));
  console.log(failures === 0 ? "\nVALIDATE-SCIM-ACCESS-OFFBOARDING VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
