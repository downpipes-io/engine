// Validates the inbound body cap on the pre-auth routes (ASVS v5.0.0-15.2.2, CWE-770).
//
// The recovery sign-in (POST /admin/auth/recovery), the passkey ceremonies (POST /admin/auth/login/finish and
// its siblings) and the SAML ACS (POST /admin/saml/acs/<conn>) run before the authorise() gate. Before the cap
// each one read the whole body and forwarded it to the single SchedulerDO, so a 20 MB unauthenticated body was
// held in the Worker and parsed again in the DO. This suite drives the real router with a stub DO and checks
// three things for each route:
//   - an over-cap body with a Content-Length is refused and never reaches the DO;
//   - an over-cap body with NO Content-Length (a chunked stream) is refused as well, because the cap counts
//     the bytes read and does not trust the header;
//   - a normal body still reaches the DO unchanged (negative control).
//
// Run with `node test/validate-inbound-body-cap.ts`.

import { handleAdmin } from "../src/admin/router.ts";
import { PRE_AUTH_MAX_BODY_BYTES, readBoundedRequestText, SAML_ACS_MAX_BODY_BYTES } from "../src/admin/inbound-body.ts";
import type { AdminRuntime } from "../src/admin/router-helpers.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
function section(title: string): void {
  console.log(`\n-- ${title} --`);
}

// The stub DO records every call and admits every rate-limit check, so the only thing between the body and
// the DO is the code under test.
const doCalls: { path: string; bodyLen: number }[] = [];
const stub = {
  async fetch(input: string | Request, init?: RequestInit): Promise<Response> {
    const u = new URL(typeof input === "string" ? input : input.url);
    const body = typeof init?.body === "string" ? init.body : "";
    doCalls.push({ path: u.pathname, bodyLen: body.length });
    return new Response(JSON.stringify({ allowed: true, ok: false, alert: null }), { headers: { "content-type": "application/json" } });
  },
};
const env = {
  CONSOLE_ORIGIN: "https://console.example",
  SCHEDULER: { idFromName: () => "id", get: () => stub },
} as unknown as Env;
const runtime: AdminRuntime = { sealNow: () => {}, waitUntil: (p: Promise<unknown>) => void p.catch(() => {}) };

// streamOf returns a body stream that declares no length: the chunked shape a hostile caller would send.
function streamOf(text: string, chunk = 64 * 1024): ReadableStream<Uint8Array> {
  const bytes = new TextEncoder().encode(text);
  let off = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (off >= bytes.byteLength) {
        controller.close();
        return;
      }
      controller.enqueue(bytes.slice(off, off + chunk));
      off += chunk;
    },
  });
}

function post(path: string, body: string | ReadableStream<Uint8Array>, contentType: string): Request {
  const headers: Record<string, string> = { "content-type": contentType, "CF-Connecting-IP": "203.0.113.9" };
  if (typeof body === "string") headers["content-length"] = String(new TextEncoder().encode(body).byteLength);
  return new Request(`https://engine.example${path}`, { method: "POST", headers, body, duplex: "half" } as RequestInit);
}

async function drive(req: Request): Promise<{ status: number; location: string | null; doPaths: { path: string; bodyLen: number }[] }> {
  const n0 = doCalls.length;
  let status = 0;
  let location: string | null = null;
  try {
    const resp = await handleAdmin(req, env, runtime);
    status = resp.status;
    location = resp.headers.get("location");
  } catch {
    status = 500;
  }
  return { status, location, doPaths: doCalls.slice(n0) };
}

const BIG = "A".repeat(20 * 1024 * 1024);

section("1. POST /admin/auth/recovery");
{
  const withLen = await drive(post("/admin/auth/recovery", JSON.stringify({ email: "a@example.com", code: BIG }), "application/json"));
  ok(`a 20 MB body with Content-Length is refused 413 (got ${withLen.status})`, withLen.status === 413);
  ok("the 20 MB body never reaches the DO recovery route", !withLen.doPaths.some((c) => c.path === "/recovery/recover"));
  const chunked = await drive(post("/admin/auth/recovery", streamOf(JSON.stringify({ email: "a@example.com", code: BIG })), "application/json"));
  ok(`a 20 MB chunked body with no Content-Length is refused 413 (got ${chunked.status})`, chunked.status === 413);
  ok("the chunked body never reaches the DO recovery route", !chunked.doPaths.some((c) => c.path === "/recovery/recover"));
  const small = await drive(post("/admin/auth/recovery", JSON.stringify({ email: "a@example.com", code: "abcd-efgh" }), "application/json"));
  ok(`negative control: a normal body reaches the DO recovery route (status ${small.status})`, small.doPaths.some((c) => c.path === "/recovery/recover"));
}

section("2. POST /admin/auth/login/finish (passkey ceremony)");
{
  const withLen = await drive(post("/admin/auth/login/finish", JSON.stringify({ email: "a@example.com", credential: BIG }), "application/json"));
  ok(`a 20 MB body with Content-Length is refused 413 (got ${withLen.status})`, withLen.status === 413);
  ok("the 20 MB body never reaches the DO ceremony route", !withLen.doPaths.some((c) => c.path.startsWith("/passkey/")));
  const chunked = await drive(post("/admin/auth/login/finish", streamOf(JSON.stringify({ email: "a@example.com", credential: BIG })), "application/json"));
  ok(`a 20 MB chunked body is refused 413 (got ${chunked.status})`, chunked.status === 413);
  ok("the chunked body never reaches the DO ceremony route", !chunked.doPaths.some((c) => c.path.startsWith("/passkey/")));
  const small = await drive(post("/admin/auth/login/begin", JSON.stringify({ email: "a@example.com" }), "application/json"));
  ok("negative control: a normal login/begin body reaches the DO ceremony route", small.doPaths.some((c) => c.path === "/passkey/login/begin"));
}

section("3. POST /admin/saml/acs/<conn>");
{
  const form = (saml: string) => `SAMLResponse=${saml}&RelayState=rs-1`;
  const withLen = await drive(post("/admin/saml/acs/conn1", form(BIG), "application/x-www-form-urlencoded"));
  ok(`a 20 MB ACS body with Content-Length is answered with the generic failure redirect (got ${withLen.status})`, withLen.status === 302 && (withLen.location ?? "").startsWith("https://console.example"));
  ok("the 20 MB ACS body never reaches the DO ACS route", !withLen.doPaths.some((c) => c.path === "/idp/saml/acs"));
  const chunked = await drive(post("/admin/saml/acs/conn1", streamOf(form(BIG)), "application/x-www-form-urlencoded"));
  ok(`a 20 MB chunked ACS body gets the failure redirect (got ${chunked.status})`, chunked.status === 302);
  ok("the chunked ACS body never reaches the DO ACS route", !chunked.doPaths.some((c) => c.path === "/idp/saml/acs"));
  const small = await drive(post("/admin/saml/acs/conn1", form("PHNhbWw+"), "application/x-www-form-urlencoded"));
  ok("negative control: a normal ACS body reaches the DO ACS route", small.doPaths.some((c) => c.path === "/idp/saml/acs"));
}

section("4. readBoundedRequestText at the boundary");
{
  const at = "x".repeat(PRE_AUTH_MAX_BODY_BYTES);
  ok("a body of exactly the cap is read whole", (await readBoundedRequestText(post("/x", at, "text/plain"), PRE_AUTH_MAX_BODY_BYTES)) === at);
  ok("a chunked body of exactly the cap is read whole", (await readBoundedRequestText(post("/x", streamOf(at, 1000), "text/plain"), PRE_AUTH_MAX_BODY_BYTES)) === at);
  ok("one byte over the cap is refused", (await readBoundedRequestText(post("/x", `${at}x`, "text/plain"), PRE_AUTH_MAX_BODY_BYTES)) === null);
  ok("one chunked byte over the cap is refused", (await readBoundedRequestText(post("/x", streamOf(`${at}x`, 1000), "text/plain"), PRE_AUTH_MAX_BODY_BYTES)) === null);
  const lying = new Request("https://engine.example/x", { method: "POST", headers: { "content-length": "10" }, body: streamOf(`${at}x`, 1000), duplex: "half" } as RequestInit);
  ok("a body that sends more than its Content-Length declares is refused", (await readBoundedRequestText(lying, PRE_AUTH_MAX_BODY_BYTES)) === null);
  ok("an empty body reads as the empty string", (await readBoundedRequestText(new Request("https://engine.example/x", { method: "POST" }), PRE_AUTH_MAX_BODY_BYTES)) === "");
  ok("multi-byte UTF-8 split across chunks decodes intact", (await readBoundedRequestText(post("/x", streamOf("é".repeat(10), 3), "text/plain"), PRE_AUTH_MAX_BODY_BYTES)) === "é".repeat(10));
  ok("the SAML cap is larger than the pre-auth cap", SAML_ACS_MAX_BODY_BYTES > PRE_AUTH_MAX_BODY_BYTES);
}

console.log(failures === 0 ? "\nINBOUND BODY CAP PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures);
if (failures > 0) process.exit(1);
