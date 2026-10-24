// The CSRF Origin gate for a Cloudflare Access caller. The admin body parser ignores Content-Type, so a
// cross-site simple POST (text/plain, no preflight) can reach a write route. An Access request that carries an
// Origin header (any value, including "null") must match CONSOLE_ORIGIN, else 403; with CONSOLE_ORIGIN unset
// it is refused 403 and records csrf-origin-unset. An Access request with no Origin header (a script that
// sends the assertion header) passes the gate, and so does the bare bearer. A cookie-borne session keeps its
// strict check. isCookieBorneMethod("access") stays false.
//
// Driven through the REAL router (handleAdmin), the REAL authorise() with a real RS256 assertion, and the REAL
// scheduler DO, in memory only. Run: node test/validate-access-csrf.ts

import { handleAdmin } from "../src/admin/router.ts";
import { isCookieBorneMethod } from "../src/admin/identity-roles.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ORIGIN = "https://console.example";
const FOREIGN = "https://evil.example";
const TEAM = "maelstrom";
const AUD = "csrf-test-aud";
const KID = "csrf-test-kid";
const TOKEN = "break-glass-token-value";
const REFUSAL = "csrf origin check failed";

function jwtPart(obj: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}

// makeEnv builds a real scheduler DO and records every auth-signal name the router posts to it.
function makeEnv(extra: Partial<Env>, signals: string[]): Env {
  const state = { storage: new MockStorage() } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.endsWith("/auth-signal") && typeof init?.body === "string") {
        try {
          signals.push((JSON.parse(init.body) as { name: string }).name);
        } catch {
          /* not JSON */
        }
      }
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
  return { SCHEDULER: namespace, ADMIN_TOKEN: TOKEN, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, ...extra } as unknown as Env;
}

async function main(): Promise<void> {
  const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const pub = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
  const certsUrl = `https://${TEAM}.cloudflareaccess.com/cdn-cgi/access/certs`;
  const origFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
    const u = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (u === certsUrl) return new Response(JSON.stringify({ keys: [{ kid: KID, kty: "RSA", n: pub.n, e: pub.e }] }), { status: 200, headers: { "content-type": "application/json" } });
    throw new Error(`unexpected fetch in test: ${u}`);
  }) as typeof fetch;
  try {
    const now = Math.floor(Date.now() / 1000);
    const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
    const body = jwtPart({ iss: `https://${TEAM}.cloudflareaccess.com`, aud: AUD, exp: now + 3600, iat: now, email: "owner@example.com", sub: "sub-of-owner" });
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
    const assertion = `${header}.${body}.${b64urlEncode(sig)}`;

    // A cross-site simple POST: text/plain, so no preflight; the JSON body still parses.
    async function write(env: Env, opts: { origin?: string; access?: boolean; bearer?: boolean; cookie?: string; path?: string }): Promise<{ status: number; error: string }> {
      const headers: Record<string, string> = { "content-type": "text/plain" };
      if (opts.access === true) headers["cf-access-jwt-assertion"] = assertion;
      if (opts.bearer === true) headers["authorization"] = `Bearer ${TOKEN}`;
      if (opts.cookie !== undefined) headers["cookie"] = opts.cookie;
      if (opts.origin !== undefined) headers["origin"] = opts.origin;
      const resp = await handleAdmin(new Request(`https://engine.example${opts.path ?? "/admin/roles"}`, { method: "POST", body: JSON.stringify({ email: "new@example.com", role: "viewer" }), headers }), env, undefined, { cookie: null });
      const text = await resp.text();
      let error = "";
      try {
        error = String((JSON.parse(text) as { error?: unknown }).error ?? "");
      } catch {
        /* not JSON */
      }
      return { status: resp.status, error };
    }

    const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 20));
    {
      const sig1: string[] = [];
      const env = makeEnv({ CONSOLE_ORIGIN: ORIGIN }, sig1);
      const a = await write(env, { access: true, origin: FOREIGN });
      ok(`(a) Access write, text/plain, cross-site Origin -> 403 "${REFUSAL}"`, a.status === 403 && a.error === REFUSAL);
      const b = await write(env, { access: true, origin: "null" });
      ok('(b) Access write with Origin "null" -> 403 csrf refusal', b.status === 403 && b.error === REFUSAL);
      const c = await write(env, { access: true, origin: ORIGIN });
      ok("(c) Access write with Origin = CONSOLE_ORIGIN passes the gate", c.error !== REFUSAL && c.status === 200);
      const e = await write(env, { access: true });
      ok("(e) Access write with NO Origin (script shape) passes the gate and lands", e.error !== REFUSAL && e.status === 200);
      const f = await write(env, { bearer: true });
      ok("(f) bare bearer, no Origin, passes the gate", f.error !== REFUSAL);
      // (h) control: a cookie-borne session (the exchanged token session) with no Origin keeps its strict refusal.
      const boot = await handleAdmin(new Request("https://engine.example/admin/session/bootstrap", { method: "POST", headers: { authorization: `Bearer ${TOKEN}`, origin: ORIGIN } }), env, undefined, { cookie: null });
      const cookie = (boot.headers.get("set-cookie") ?? "").split(";")[0] ?? "";
      ok("(h) setup: the bearer bootstrap minted a session cookie", boot.status === 200 && cookie.includes("="));
      const h = await write(env, { cookie });
      ok(`(h) control: cookie session, no Origin -> 403 "${REFUSAL}"`, h.status === 403 && h.error === REFUSAL);
      const h2 = await write(env, { cookie, origin: ORIGIN });
      ok("(h) control: cookie session, Origin = CONSOLE_ORIGIN passes the gate", h2.error !== REFUSAL);
      // (i)/(j) the recovery-code writes dispatch before the main gate and run their own Origin check: same rule.
      for (const [tag, path] of [["(i)", "/admin/auth/recovery-codes/regenerate"], ["(j)", "/admin/auth/recovery-codes/confirm"]] as const) {
        const x = await write(env, { access: true, origin: FOREIGN, path });
        ok(`${tag} Access POST ${path} with a cross-site Origin -> 403 "${REFUSAL}"`, x.status === 403 && x.error === REFUSAL);
        const y = await write(env, { access: true, origin: ORIGIN, path });
        ok(`${tag} Access POST ${path} with Origin = CONSOLE_ORIGIN passes the Origin check`, y.error !== REFUSAL);
        const z = await write(env, { access: true, path });
        ok(`${tag} Access POST ${path} with no Origin passes the Origin check`, z.error !== REFUSAL);
      }
    }
    {
      const sig2: string[] = [];
      const env = makeEnv({}, sig2);
      const d = await write(env, { access: true, origin: ORIGIN });
      await settle();
      ok("(d) Access write with a present Origin and CONSOLE_ORIGIN unset -> 403 csrf refusal", d.status === 403 && d.error === REFUSAL);
      ok("(d) the csrf-origin-unset signal is recorded", sig2.includes("csrf-origin-unset"));
      const e2 = await write(env, { access: true });
      ok("(e) Access write with no Origin and CONSOLE_ORIGIN unset passes the gate", e2.error !== REFUSAL);
    }
    ok('(g) isCookieBorneMethod("access") stays false', isCookieBorneMethod("access") === false);
  } finally {
    globalThis.fetch = origFetch;
  }
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
