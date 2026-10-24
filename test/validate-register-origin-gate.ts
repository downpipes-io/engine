// validate-register-origin-gate: /admin/auth/register/begin and /register/finish run BEFORE the admin CSRF
// gate, so they apply the gate's Origin rule themselves to a Cloudflare Access caller: when the request
// carries an Origin header (any value, "null" included) it must equal CONSOLE_ORIGIN, or the route answers
// 403 {"error":"csrf origin check failed"} and the ceremony never reaches the scheduler. An Access request
// with no Origin header skips the check, as it does at the main gate. A passkey COOKIE-session caller is held
// to the stricter rule of the sibling routes (regenerate, confirm): its Origin must equal CONSOLE_ORIGIN, and
// a cookie request with no Origin is refused too.
//
// Drives the real handleAdmin over a real SchedulerDO on in-memory storage, with a correctly signed Access
// JWT. NEGATIVE CONTROLS: the same-console Origin passes on begin (a challenge is stored) and is not refused
// on finish; an Access request with no Origin header is not refused; a bearer-token caller is not refused for
// its Origin by this rule. Run:
//   node test/validate-register-origin-gate.ts

import { handleAdmin } from "../src/admin/router.ts";
import { b64urlDecode, b64urlEncode } from "../src/crypto/bytes.ts";
import { roleSubjectKey } from "../src/admin/identity.ts";
import { signSession } from "../src/admin/session.ts";
import { CONN_PREFIX } from "../src/admin/oidc-store-kv.ts";
import { OIDC_GROUPS_PREFIX, PASSKEY_SESSION_KEY_KEY } from "../src/sched/scheduler-do-base.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { ADMIN_TOKEN, buildAttestation, challengeFor, enrolBootstrapOwner, extractSessionCookie, makeAuthenticator, makeScheduler, ok, post, failureCount, ORIGIN, registerBegin } from "./validate-passkey-harness.ts";

const TEAM = "maelstrom";
const ISS = `https://${TEAM}.cloudflareaccess.com`;
const AUD = "register-origin-gate-aud";
const KID = "register-origin-gate-kid";
const EMAIL = "owner@example.com";
const CSRF_BODY = "csrf origin check failed";

const jwtPart = (obj: unknown): string => b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));

async function main(): Promise<void> {
  const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const pub = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
  const jwks = { keys: [{ kid: KID, kty: "RSA", n: pub.n, e: pub.e }] };
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url === `${ISS}/cdn-cgi/access/certs`) return new Response(JSON.stringify(jwks), { headers: { "content-type": "application/json" } });
    throw new Error(`unexpected network fetch in test: ${url}`);
  }) as typeof fetch;

  try {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const accessJwt = async (): Promise<string> => {
      const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
      const body = jwtPart({ iss: ISS, aud: AUD, exp, iat: exp - 60, email: EMAIL, sub: `sub-of-${EMAIL}` });
      const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
      return `${header}.${body}.${b64urlEncode(sig)}`;
    };

    const { env: baseEnv, storage } = makeScheduler();
    const env = { ...baseEnv, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD } as unknown as Env;
    // The Owner is enrolled by the bootstrap path, so the Access caller below is a known member adding to its own email.
    const enrolled = await enrolBootstrapOwner(env, await makeAuthenticator("ES256"), EMAIL);
    const sessionCookie = extractSessionCookie(enrolled.setCookie);
    ok("setup: the bootstrap enrolment minted a passkey session cookie", sessionCookie !== null);

    const asAccess = async (sub: "register/begin" | "register/finish", body: unknown, origin: string | undefined): Promise<{ status: number; text: string }> => {
      const headers: Record<string, string> = { "content-type": "application/json", "cf-access-jwt-assertion": await accessJwt(), "CF-Connecting-IP": "203.0.113.9" };
      if (origin !== undefined) headers.origin = origin;
      const resp = await handleAdmin(new Request(`https://engine.example/admin/auth/${sub}`, { method: "POST", headers, body: JSON.stringify(body) }), env);
      return { status: resp.status, text: await resp.text() };
    };
    const refused = (r: { status: number; text: string }): boolean => r.status === 403 && r.text.includes(CSRF_BODY);

    const challengesBefore = storage.countPrefix("passkeyChallenge:");
    const credsBefore = storage.countPrefix("passkeyCred:");

    // ---- begin ----
    for (const [label, origin] of [["a cross-site Origin", "https://evil.example"], ['Origin "null"', "null"]] as const) {
      const r = await asAccess("register/begin", { email: EMAIL }, origin);
      ok(`register/begin: ${label} is refused for an Access caller (status ${r.status})`, refused(r));
    }
    ok("register/begin: the refused requests stored no challenge", storage.countPrefix("passkeyChallenge:") === challengesBefore);
    const okBegin = await asAccess("register/begin", { email: EMAIL }, ORIGIN);
    ok(`negative control: register/begin with the console Origin passes for an Access caller (status ${okBegin.status})`, okBegin.status === 200 && !okBegin.text.includes(CSRF_BODY));
    ok("negative control: the console-Origin begin stored a challenge", storage.countPrefix("passkeyChallenge:") === challengesBefore + 1);
    const noOrigin = await asAccess("register/begin", { email: EMAIL }, undefined);
    ok(`negative control: register/begin with no Origin header is not refused for the Origin rule (status ${noOrigin.status})`, !refused(noOrigin));

    // ---- finish ----
    const challenge = challengeFor({ status: 200, json: JSON.parse(okBegin.text) });
    const att = await buildAttestation(await makeAuthenticator("ES256"), challenge);
    for (const [label, origin] of [["a cross-site Origin", "https://evil.example"], ['Origin "null"', "null"]] as const) {
      const r = await asAccess("register/finish", { email: EMAIL, credential: att }, origin);
      ok(`register/finish: ${label} is refused for an Access caller (status ${r.status})`, refused(r));
    }
    ok("register/finish: the refused requests stored no credential", storage.countPrefix("passkeyCred:") === credsBefore);
    const okFinish = await asAccess("register/finish", { email: EMAIL, credential: att }, ORIGIN);
    ok(`negative control: register/finish with the console Origin is not refused for the Origin rule (status ${okFinish.status})`, !refused(okFinish));

    // ---- passkey cookie-session caller: the sibling routes' rule (Origin must equal CONSOLE_ORIGIN) ----
    const asCookie = (sub: "register/begin" | "register/finish", body: unknown, origin: string | undefined) =>
      post(env, `/admin/auth/${sub}`, body, { cookie: sessionCookie ?? "", ...(origin !== undefined ? { origin } : {}) });
    const cookieRefused = (r: { status: number; text: string }): boolean => r.status === 403 && r.text.includes(CSRF_BODY);
    const challengesBeforeCookie = storage.countPrefix("passkeyChallenge:");
    const credsBeforeCookie = storage.countPrefix("passkeyCred:");
    for (const [label, origin] of [["a cross-site Origin", "https://evil.example"], ['Origin "null"', "null"], ["no Origin header", undefined]] as const) {
      const r = await asCookie("register/begin", { email: EMAIL }, origin);
      ok(`register/begin: ${label} is refused for a passkey cookie-session caller (status ${r.status})`, cookieRefused(r));
    }
    ok("register/begin: the refused cookie requests stored no challenge", storage.countPrefix("passkeyChallenge:") === challengesBeforeCookie);
    const cookieBegin = await asCookie("register/begin", { email: EMAIL }, ORIGIN);
    ok(`negative control: register/begin with the console Origin passes for a passkey cookie-session caller (status ${cookieBegin.status})`, cookieBegin.status === 200 && !cookieBegin.text.includes(CSRF_BODY));
    const cookieAtt = await buildAttestation(await makeAuthenticator("ES256"), challengeFor({ status: 200, json: cookieBegin.json }));
    for (const [label, origin] of [["a cross-site Origin", "https://evil.example"], ['Origin "null"', "null"], ["no Origin header", undefined]] as const) {
      const r = await asCookie("register/finish", { email: EMAIL, credential: cookieAtt }, origin);
      ok(`register/finish: ${label} is refused for a passkey cookie-session caller (status ${r.status})`, cookieRefused(r));
    }
    ok("register/finish: the refused cookie requests added no credential", storage.countPrefix("passkeyCred:") === credsBeforeCookie);
    const cookieFinish = await asCookie("register/finish", { email: EMAIL, credential: cookieAtt }, ORIGIN);
    ok(`negative control: register/finish with the console Origin is not refused for a passkey cookie-session caller (status ${cookieFinish.status})`, !cookieRefused(cookieFinish));

    // ---- native OIDC and SAML cookie-session callers: isCookieBorneMethod holds for all three cookie methods ----
    // The sessions are signed with the scheduler's own session key (signSession, as the scheduler session tests
    // do) over the state a real sign-in leaves: an enabled connection, a group snapshot and a role row.
    const cookieName = (sessionCookie ?? "").split("=")[0] ?? "";
    const keyRec = await storage.get<{ key: string }>(PASSKEY_SESSION_KEY_KEY);
    const sessionKey = b64urlDecode(keyRec?.key ?? "");
    const nativeCookie = async (method: "oidc" | "saml", connId: string, subject: string, email: string): Promise<string> => {
      await storage.put(`${CONN_PREFIX}${connId}`, { id: connId, kind: method, enabled: true });
      await storage.put(`${OIDC_GROUPS_PREFIX}${subject}`, ["staff"]);
      await storage.put(roleSubjectKey(subject), { subject, email, role: "viewer", grantedBy: "system", grantedAt: "2026-01-01T00:00:00.000Z" });
      return `${cookieName}=${await signSession(sessionKey, { method, email, subject, connId, epoch: 0 }, Date.now())}`;
    };
    const nativeCallers = [
      { method: "oidc" as const, cookie: await nativeCookie("oidc", "entra", "oidc:entra|iss|sub1", "oidc-user@example.com") },
      { method: "saml" as const, cookie: await nativeCookie("saml", "work", "saml:work|idp|nameid", "saml-user@example.com") },
    ];
    for (const caller of nativeCallers) {
      const asNative = (sub: "register/begin" | "register/finish", body: unknown, origin: string | undefined) =>
        post(env, `/admin/auth/${sub}`, body, { cookie: caller.cookie, ...(origin !== undefined ? { origin } : {}) });
      const challengesBeforeNative = storage.countPrefix("passkeyChallenge:");
      const credsBeforeNative = storage.countPrefix("passkeyCred:");
      for (const sub of ["register/begin", "register/finish"] as const) {
        const body = sub === "register/begin" ? { email: EMAIL } : { email: EMAIL, credential: cookieAtt };
        for (const [label, origin] of [["a cross-site Origin", "https://evil.example"], ['Origin "null"', "null"], ["no Origin header", undefined]] as const) {
          const r = await asNative(sub, body, origin);
          ok(`${sub}: ${label} is refused for a ${caller.method} cookie-session caller (status ${r.status})`, cookieRefused(r));
        }
        const control = await asNative(sub, body, ORIGIN);
        ok(`negative control: ${sub} with the console Origin is not refused for the Origin rule for a ${caller.method} cookie-session caller (status ${control.status})`, !cookieRefused(control) && control.status !== 401);
      }
      ok(`register: the refused ${caller.method} cookie requests stored no challenge and no credential`, storage.countPrefix("passkeyChallenge:") === challengesBeforeNative && storage.countPrefix("passkeyCred:") === credsBeforeNative);
    }

    // ---- token caller: the rule is the Access rule, so the bearer path keeps its behaviour ----
    const tokenBegin = await registerBegin(env, EMAIL, { authorization: `Bearer ${ADMIN_TOKEN}`, origin: "https://evil.example" });
    ok(`negative control: a bearer-token caller is not refused by the Access Origin rule (status ${tokenBegin.status})`, !JSON.stringify(tokenBegin.json).includes(CSRF_BODY) && tokenBegin.status !== 403);
  } finally {
    globalThis.fetch = realFetch;
  }

  const failures = failureCount();
  console.log(failures === 0 ? "\nREGISTER ORIGIN GATE PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
