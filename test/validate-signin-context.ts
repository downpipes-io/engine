// Prove the R6 unusual-location sign-in notification (ASVS V6.3.5) end to end:
//   1. the PURE pieces: coarseSignInPrefix (IPv4 /24, IPv6 /48, malformed/mapped -> null) and
//      evaluateSignInContext (first context = baseline never an alert; a different prefix IS new; a
//      returning prefix refreshes its TTL; expired entries prune; the set caps at the newest ten);
//   2. the DO + ROUTER surface: the owner-only POST /admin/config/signin-context-policy toggle applies
//      immediately and shows in GET /admin/config/approval-policy; POST /signin-context (the passkey
//      path's check) is a policy-gated no-op by default, baselines on the first sign-in, flags a new
//      coarse context, and NEVER stores a raw IP (the storage is scanned to prove it);
//   3. the WIRING LOCKSTEP: the OIDC and SAML success blocks in scheduler-do-idp.ts call
//      recordSignInContext and surface newSignInContext on their returns, and the router's OIDC
//      callback, SAML ACS and passkey finish paths reference routeSignInContextAlert, so the feature
//      cannot be silently unwired by a later refactor (the repo's structural-guard idiom).
// No network, no deploy. Run:
//   node test/validate-signin-context.ts

import { readFileSync } from "node:fs";
import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/index.ts";
import type { Env } from "../src/env.d.ts";
import { coarseSignInPrefix, evaluateSignInContext, SEEN_CONTEXT_CAP, SEEN_CONTEXT_TTL_MS, type SeenContext } from "../src/admin/sign-in-context.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const TOKEN = "signin-context-test-admin-token";

function makeStack(): { env: Env; storage: MockStorage; stub: DurableObjectStub } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  return { env: { SCHEDULER: namespace, ADMIN_TOKEN: TOKEN } as unknown as Env, storage, stub };
}

async function call(env: Env, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> {
  const init: RequestInit = {
    method,
    headers: { authorization: `Bearer ${TOKEN}`, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  };
  return handleAdmin(new Request(`https://engine.example${path}`, init), env);
}

// doPost drives the DO's INTERNAL /signin-context route directly (the router's passkey finish path
// reaches it via its own scheduler.fetch; there is no public route to it).
async function doPost(stub: DurableObjectStub, body: unknown): Promise<{ newContext?: boolean }> {
  const r = await stub.fetch("https://do/signin-context", { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json" } });
  return (await r.json()) as { newContext?: boolean };
}

async function main(): Promise<void> {
  // ---- 1a. coarseSignInPrefix -------------------------------------------------------------------
  ok("v4 -> /24 (last octet zeroed)", coarseSignInPrefix("203.0.113.87") === "203.0.113.0/24");
  ok("v4 invalid octet -> null", coarseSignInPrefix("203.0.113.999") === null);
  ok("v4 garbage -> null", coarseSignInPrefix("not-an-ip") === null);
  ok("v6 full -> /48 (first three hextets, normalised)", coarseSignInPrefix("2001:0db8:85a3:0000:0000:8a2e:0370:7334") === "2001:db8:85a3::/48");
  ok("v6 :: expansion -> /48", coarseSignInPrefix("2001:db8::1") === "2001:db8:0::/48");
  ok("v6 double :: -> null", coarseSignInPrefix("2001::db8::1") === null);
  ok("v6 IPv4-mapped tail -> null (fail safe)", coarseSignInPrefix("::ffff:192.0.2.1") === null);
  ok("null/empty -> null", coarseSignInPrefix(null) === null && coarseSignInPrefix("") === null && coarseSignInPrefix(undefined) === null);

  // ---- 1b. evaluateSignInContext ----------------------------------------------------------------
  const now = 1_800_000_000_000;
  {
    const first = evaluateSignInContext([], "203.0.113.0/24", now);
    ok("first context is the baseline, never an alert", first.isNew === false && first.updated.length === 1 && first.updated[0]?.prefix === "203.0.113.0/24");
    const same = evaluateSignInContext(first.updated, "203.0.113.0/24", now + 1000);
    ok("a returning context is not new and refreshes lastAt", same.isNew === false && same.updated[0]?.lastAt === now + 1000);
    const other = evaluateSignInContext(first.updated, "198.51.100.0/24", now + 2000);
    ok("a different coarse context IS new", other.isNew === true && other.updated.length === 2);
    // An expired baseline (every row aged out) is a LAPSE, not a re-baseline: it alerts AND is flagged as a
    // lapse. See validate-signin-baseline-lapse.ts for the full lapse-detection coverage.
    const expired = evaluateSignInContext([{ prefix: "203.0.113.0/24", lastAt: now - SEEN_CONTEXT_TTL_MS - 1 }], "198.51.100.0/24", now);
    ok("a LAPSED baseline (every row aged out) alerts and is flagged, and the set re-baselines", expired.isNew === true && expired.baselineLapsed === true && expired.updated.length === 1);
    const neverSeen = evaluateSignInContext([], "198.51.100.0/24", now);
    ok("a genuinely first-ever context is NOT a lapse and does not alert", neverSeen.isNew === false && neverSeen.baselineLapsed === false);
    const many: SeenContext[] = Array.from({ length: SEEN_CONTEXT_CAP }, (_v, i) => ({ prefix: `10.${i}.0.0/24`, lastAt: now - i * 1000 }));
    const capped = evaluateSignInContext(many, "198.51.100.0/24", now + 5000);
    ok("the set caps at the newest ten (oldest evicted)", capped.isNew === true && capped.updated.length === SEEN_CONTEXT_CAP && capped.updated.some((c) => c.prefix === "198.51.100.0/24") && !capped.updated.some((c) => c.prefix === `10.${SEEN_CONTEXT_CAP - 1}.0.0/24`));
    const dup = evaluateSignInContext([{ prefix: "203.0.113.0/24", lastAt: now }, { prefix: "203.0.113.0/24", lastAt: now - 1 }], "203.0.113.0/24", now + 1);
    ok("duplicate stored prefixes de-dupe defensively", dup.updated.filter((c) => c.prefix === "203.0.113.0/24").length === 1);
  }

  // ---- 2. the DO + router surface ----------------------------------------------------------------
  {
    const { env, storage, stub } = makeStack();
    // Default OFF: the check is a policy-gated no-op and stores nothing.
    const off = await doPost(stub, { email: "op@acme.example", sourceIp: "203.0.113.87" });
    ok("policy off: newContext false", off.newContext === false);
    ok("policy off: nothing stored", (await storage.list({ prefix: "signinctx:" })).size === 0);
    // The policy view carries the flag (off).
    const view0 = (await (await call(env, "GET", "/admin/config/approval-policy")).json()) as { notifyNewSignInContext?: boolean };
    ok("policy view carries notifyNewSignInContext=false by default", view0.notifyNewSignInContext === false);
    // Owner toggles it on (immediate apply), and the view reflects it.
    const arm = await call(env, "POST", "/admin/config/signin-context-policy", { notifyNewSignInContext: true });
    ok("owner toggle applies (200)", arm.status === 200);
    const view1 = (await (await call(env, "GET", "/admin/config/approval-policy")).json()) as { notifyNewSignInContext?: boolean };
    ok("policy view reflects the opt-in", view1.notifyNewSignInContext === true);
    // First sign-in establishes the baseline; a second from the SAME /24 is not new; a DIFFERENT /24 is.
    const first = await doPost(stub, { email: "op@acme.example", sourceIp: "203.0.113.87" });
    ok("first sign-in is the baseline (no alert)", first.newContext === false);
    const sameNet = await doPost(stub, { email: "op@acme.example", sourceIp: "203.0.113.200" });
    ok("same /24 (different low octet) is not new (NAT churn absorbed)", sameNet.newContext === false);
    const newNet = await doPost(stub, { email: "op@acme.example", sourceIp: "198.51.100.9" });
    ok("a different /24 IS a new context", newNet.newContext === true);
    // Privacy: the stored record holds coarse prefixes only, never a raw IP.
    const stored = JSON.stringify([...(await storage.list({ prefix: "signinctx:" })).values()]);
    ok("storage holds coarse prefixes", stored.includes("203.0.113.0/24") && stored.includes("198.51.100.0/24"));
    ok("storage NEVER holds a raw IP", !stored.includes("203.0.113.87") && !stored.includes("203.0.113.200") && !stored.includes("198.51.100.9"));
    // Per-operator isolation: a different email has its own baseline (no alert on ITS first sign-in).
    const otherOp = await doPost(stub, { email: "other@acme.example", sourceIp: "198.51.100.9" });
    ok("a different operator baselines independently", otherOp.newContext === false);
    // An uncomputable prefix skips the check (never alerts, never stores).
    const bad = await doPost(stub, { email: "op@acme.example", sourceIp: "not-an-ip" });
    ok("an uncomputable prefix skips (fail safe)", bad.newContext === false);
    // A malformed toggle value is refused.
    const badToggle = await call(env, "POST", "/admin/config/signin-context-policy", { notifyNewSignInContext: "yes" });
    ok("a non-boolean toggle is a 400", badToggle.status === 400);
  }

  // ---- 3. wiring lockstep (structural guards) ----------------------------------------------------
  {
    const idp = readFileSync(new URL("../src/sched/scheduler-do-idp.ts", import.meta.url), "utf8");
    const oidcBlock = idp.slice(idp.indexOf('"oidc", nowMs'));
    ok("OIDC success block records the sign-in context", oidcBlock.includes("recordSignInContext"));
    ok("OIDC success return surfaces newSignInContext", oidcBlock.includes("newSignInContext: true"));
    const saml = readFileSync(new URL("../src/sched/scheduler-do-idp-saml.ts", import.meta.url), "utf8");
    const samlBlock = saml.slice(saml.indexOf('"saml", nowMs'));
    ok("SAML success block records the sign-in context", samlBlock.includes("recordSignInContext"));
    ok("SAML success return surfaces newSignInContext", samlBlock.includes("newSignInContext: true"));
    const idpWeb = readFileSync(new URL("../src/admin/router-idp-web.ts", import.meta.url), "utf8");
    ok("the OIDC callback + SAML ACS fire the alert", (idpWeb.match(/routeSignInContextAlert\(env, scheduler\)/g) ?? []).length >= 2);
    const authFlow = readFileSync(new URL("../src/admin/router-auth-flow.ts", import.meta.url), "utf8");
    ok("the passkey finish path runs the check", authFlow.includes("fireSignInContextCheck(env, scheduler"));
    ok("the passkey check fires the same alert", authFlow.includes("routeSignInContextAlert(env, scheduler)"));
  }

  console.log(failures === 0 ? "\nSIGN-IN-CONTEXT (R6 / V6.3.5) VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  process.exit(failures === 0 ? 0 : 1);
}

void main();
