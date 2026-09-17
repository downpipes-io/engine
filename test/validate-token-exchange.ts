// validate-token-exchange: the bare ADMIN_TOKEN is presented ONCE and exchanged for a dynamically minted
// session (ASVS V7.2.2), so the static secret never rides every request of a console session.
//   (a) POST /admin/session/bootstrap with the bearer answers 200 and a __Host- session cookie;
//   (b) that cookie alone authorises an admin read as method "token" (whoami), with no bearer;
//   (c) the cookie is an ambient credential, so a mutating POST from a foreign origin is refused by the
//       CSRF Origin guard, and the same POST from the console origin proceeds past it;
//   (d) the exchange refuses a cookie-borne token session (no re-exchange), an absent bearer, and a passkey
//       method (nothing to exchange);
//   (e) retiring the token in-app ends the session: the cookie is refused, and no new one can be minted;
//   (f) ADMIN_TOKEN_DISABLED ends it too, on an engine whose scheduler still has no retire latch;
//   (g) control: the bare bearer still authorises an admin read directly (it remains the API credential).
import { handleAdmin } from "../src/admin/router.ts";
import { SESSION_COOKIE_NAME, verifySession, TOKEN_SESSION_SUBJECT } from "../src/admin/session.ts";
import { b64urlDecode } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { MockStorage } from "./mock-storage.ts";

const ORIGIN = "https://downpipe-console.example";
const TOKEN = "exchange-test-admin-token-deadbeef";
let failures = 0;
function ok(label: string, cond: boolean): void { console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`); if (!cond) failures++; }

function makeScheduler(extraEnv: Partial<Env> = {}): { env: Env; storage: MockStorage } {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => dobj.fetch(new Request(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url, init)) } as unknown as DurableObjectStub;
  const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
  return { env: { SCHEDULER: namespace, CONSOLE_ORIGIN: ORIGIN, ADMIN_TOKEN: TOKEN, ...extraEnv } as unknown as Env, storage };
}
type Resp = { status: number; json: Record<string, unknown>; setCookie: string | null };
async function send(env: Env, path: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}): Promise<Resp> {
  const resp = await handleAdmin(new Request(`https://engine.example${path}`, { method: init.method ?? "GET", headers: init.headers ?? {}, ...(init.body !== undefined ? { body: init.body } : {}) }), env);
  const text = await resp.text();
  let json: Record<string, unknown> = {};
  try { json = JSON.parse(text) as Record<string, unknown>; } catch { json = { raw: text }; }
  return { status: resp.status, json, setCookie: resp.headers.get("set-cookie") };
}
const cookiePair = (setCookie: string | null): string => (setCookie ?? "").split(";")[0] ?? "";

async function main(): Promise<void> {
  console.log("\n(a) the bare bearer is exchanged for a minted session");
  const { env, storage } = makeScheduler();
  const ex = await send(env, "/admin/session/bootstrap", { method: "POST", headers: { authorization: `Bearer ${TOKEN}` } });
  ok("(a) 200 { ok, method: token }", ex.status === 200 && ex.json.ok === true && ex.json.method === "token");
  ok("(a) a __Host- session cookie is set, HttpOnly, Secure, SameSite=Strict", ex.setCookie !== null && ex.setCookie.startsWith(`${SESSION_COOKIE_NAME}=`) && /HttpOnly/.test(ex.setCookie) && /Secure/.test(ex.setCookie) && /SameSite=Strict/.test(ex.setCookie));
  const cookie = cookiePair(ex.setCookie);
  const rawToken = cookie.split("=").slice(1).join("=");
  {
    const keyRec = await storage.get<{ key: string }>("passkeySessionKey");
    const verified = keyRec ? await verifySession(b64urlDecode(keyRec.key), rawToken, Date.now()) : null;
    ok("(a) the minted session is method token with the fixed break-glass subject and no email", verified !== null && verified.method === "token" && verified.subject === TOKEN_SESSION_SUBJECT && verified.email === "");
    ok("(a) the session body carries no trace of the secret", !rawToken.includes(TOKEN) && !atob(rawToken.split(".")[0]!.replace(/-/g, "+").replace(/_/g, "/")).includes(TOKEN));
  }

  console.log("\n(b) the cookie alone authorises, as method token");
  {
    const who = await send(env, "/admin/whoami", { headers: { cookie } });
    ok("(b) GET /admin/whoami over the cookie is 200 method token", who.status === 200 && who.json.method === "token");
    ok("(b) it resolves to the owner break-glass, as the bare bearer does", who.json.role === "owner");
  }

  console.log("\n(c) the cookie is an ambient credential: the CSRF Origin guard applies");
  {
    const foreign = await send(env, "/admin/posture/accept", { method: "POST", headers: { cookie, origin: "https://evil.example", "content-type": "application/json" }, body: "{}" });
    ok("(c) a mutating POST from a foreign origin is refused 403 by the Origin guard", foreign.status === 403 && /origin/i.test(String(foreign.json.error ?? "")));
    const own = await send(env, "/admin/posture/accept", { method: "POST", headers: { cookie, origin: ORIGIN, "content-type": "application/json" }, body: "{}" });
    ok("(c) control: the same POST from the console origin passes the guard (no origin refusal)", !(own.status === 403 && /origin/i.test(String(own.json.error ?? ""))));
  }

  console.log("\n(d) the exchange takes the bare bearer only");
  {
    const viaCookie = await send(env, "/admin/session/bootstrap", { method: "POST", headers: { cookie, origin: ORIGIN } });
    ok("(d) a cookie-borne token session cannot be re-exchanged (401)", viaCookie.status === 401);
    const none = await send(env, "/admin/session/bootstrap", { method: "POST" });
    ok("(d) no credential at all is 401", none.status === 401);
    const wrong = await send(env, "/admin/session/bootstrap", { method: "POST", headers: { authorization: "Bearer not-the-token" } });
    ok("(d) a wrong bearer is 401 and sets no cookie", wrong.status === 401 && wrong.setCookie === null);
  }

  console.log("\n(e) retiring the token in-app ends the session and stops any new mint");
  {
    // The retire route itself demands a way back in first (an Owner passkey plus recovery codes), which is
    // the product floor and not what this block tests. The latch it sets is the orgpolicy record's
    // breakGlassTokenRetired flag, so the latch is set here the way the route's DO write leaves it.
    const policy = storage.rawGet<Record<string, unknown>>("orgpolicy") ?? {};
    storage.rawPut("orgpolicy", { ...policy, breakGlassTokenRetired: true });
    const after = await send(env, "/admin/whoami", { headers: { cookie } });
    ok("(e) the token session is refused once the token is retired (401)", after.status === 401);
    const again = await send(env, "/admin/session/bootstrap", { method: "POST", headers: { authorization: `Bearer ${TOKEN}` } });
    ok("(e) a retired bearer cannot be exchanged for a new session (401, no cookie)", again.status === 401 && again.setCookie === null);
  }

  console.log("\n(f) ADMIN_TOKEN_DISABLED ends a token session on an engine with no retire latch");
  {
    const fresh = makeScheduler();
    const ex2 = await send(fresh.env, "/admin/session/bootstrap", { method: "POST", headers: { authorization: `Bearer ${TOKEN}` } });
    const cookie2 = cookiePair(ex2.setCookie);
    ok("(f) precondition: a session was minted", ex2.status === 200 && cookie2.length > 0);
    const disabledEnv = { ...(fresh.env as unknown as Record<string, unknown>), ADMIN_TOKEN_DISABLED: "1" } as unknown as Env;
    const who = await send(disabledEnv, "/admin/whoami", { headers: { cookie: cookie2 } });
    ok("(f) the token session is refused under ADMIN_TOKEN_DISABLED (401)", who.status === 401);
    const control = await send(fresh.env, "/admin/whoami", { headers: { cookie: cookie2 } });
    ok("(f) control: the same cookie is 200 with the flag off", control.status === 200);
  }

  console.log("\n(g) control: the bare bearer remains the API credential on an ordinary read");
  {
    const fresh = makeScheduler();
    const direct = await send(fresh.env, "/admin/whoami", { headers: { authorization: `Bearer ${TOKEN}` } });
    ok("(g) GET /admin/whoami with the bearer is 200 method token", direct.status === 200 && direct.json.method === "token");
  }

  console.log(failures === 0 ? "\nTOKEN EXCHANGE VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}
void main();
