// Prove that a native (OIDC) session is keyed on its signed-in SUBJECT, not on the email it asserts, driven
// through the real router (handleAdmin) and the real SchedulerDO on MockStorage with the IdP stubbed.
// Run: node test/validate-session-subject-keyed.ts
//
// THE FINDING (ASVS v5.0.0-10.5.2, 6.8.1, 7.5.2, 7.4.1). OIDC keeps the asserted email
// whatever email_verified says, and the session rows and the email epoch were keyed on that email. So an
// ADMITTED user (any grant) who asserted a victim's email could list the victim's sessions (network prefix,
// browser), end one by id, and sign the victim out of everything with a logout or "end my other sessions".
//
// Nine cases: the attacker is admitted three ways (a group mapping on the victim's connection, a group mapping on
// a SECOND connection, an explicit Viewer row on its own subject), each with email_verified false, absent and
// true. In every case the attacker asserts the victim's email and must not see, end or sign out the victim's
// session. Controls: the attacker's own session is listed and its logout ends it; the victim's own list shows
// the victim's session; an Owner ending the victim's sessions by email still works.

import { oidcSubject, passkeySubject, roleSubjectKey } from "../src/admin/identity.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { verifySession } from "../src/admin/session.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { SESSION_REVOKED_PREFIX } from "../src/sched/scheduler-do-records.ts";
import { dohReply } from "./lib/doh-stub.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ORIGIN = "https://console.acme.example";
const ADMIN_TOKEN = "test-admin-token-subject-keyed";
const SESS = "__Host-downpipes_session";
const OIDC_TXN = "__Host-downpipes_oidc_txn";
const CSRF = "csrf-double-submit-token";
const FOUNDER = { subject: "passkey|founder@acme.example", email: "founder@acme.example", role: "owner", grantedBy: "system", grantedAt: "2026-06-13T00:00:00.000Z" };
const VICTIM = "victim@acme.example";

// ---------------- the stubbed IdPs (two issuers, one per connection) ----------------
interface OidcWho { sub: string; email: string; emailVerified: boolean | undefined; groups: string[] }
const idp = { who: null as OidcWho | null, issuer: "", client: "", nonce: "" };
const ISSUERS: Record<string, string> = { corp: "https://sso.acme.example", corp2: "https://sso2.acme.example" };

const kp = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
const jwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
function b64u(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const enc = (o: unknown) => b64u(new TextEncoder().encode(JSON.stringify(o)));
async function idToken(): Promise<string> {
  const w = idp.who!;
  const now = Math.floor(Date.now() / 1000);
  const h = enc({ alg: "RS256", kid: "k1", typ: "JWT" });
  // email_verified is left OUT of the token when the case says "absent".
  const claims: Record<string, unknown> = { iss: idp.issuer, sub: w.sub, aud: idp.client, nonce: idp.nonce, iat: now, exp: now + 300, email: w.email, groups: w.groups };
  if (w.emailVerified !== undefined) claims.email_verified = w.emailVerified;
  const p = enc(claims);
  const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${h}.${p}`)));
  return `${h}.${p}.${b64u(sig)}`;
}
const json = (o: unknown) => new Response(JSON.stringify(o), { status: 200, headers: { "content-type": "application/json" } });

const realFetch = globalThis.fetch;
process.on("exit", () => {
  globalThis.fetch = realFetch;
});
globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
  const d = dohReply(input);
  if (d) return d;
  const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
  for (const iss of Object.values(ISSUERS)) {
    if (url === `${iss}/jwks`) return json({ keys: [{ kid: "k1", kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", use: "sig" }] });
    if (url === `${iss}/token`) return json({ id_token: await idToken(), access_token: "at", token_type: "Bearer" });
  }
  throw new Error(`unexpected fetch in test: ${url}`);
}) as typeof fetch;

// ---------------- the engine under test ----------------
function makeEnv(): { env: Env; storage: MockStorage } {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = { fetch: (i: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(typeof i === "string" ? i : i instanceof URL ? i.toString() : i.url, init)) } as unknown as DurableObjectStub;
  const ns = { idFromName: () => ({}), get: () => stub } as unknown as DurableObjectNamespace;
  return { env: { SCHEDULER: ns, CONSOLE_ORIGIN: ORIGIN, ADMIN_TOKEN } as unknown as Env, storage };
}
function setCookies(r: Response): string[] {
  const h = r.headers as Headers & { getSetCookie?: () => string[] };
  return typeof h.getSetCookie === "function" ? h.getSetCookie() : r.headers.get("set-cookie") ? [r.headers.get("set-cookie")!] : [];
}
function cookie(r: Response, name: string): string | null {
  for (const c of setCookies(r)) {
    const m = c.match(new RegExp(`^${name}=([^;]*)`));
    if (m && m[1] !== "") return m[1]!;
  }
  return null;
}
async function admin(env: Env, method: string, path: string, body?: unknown): Promise<Response> {
  const headers: Record<string, string> = { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" };
  return handleAdmin(new Request(`${ORIGIN}${path}`, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) }), env);
}
async function get(env: Env, path: string, cookieHeader?: string): Promise<Response> {
  return handleAdmin(new Request(`${ORIGIN}${path}`, { method: "GET", headers: { "CF-Connecting-IP": "198.51.100.9", ...(cookieHeader ? { cookie: cookieHeader } : {}) } }), env);
}
async function post(env: Env, path: string, token: string, body: unknown): Promise<Response> {
  const headers = { cookie: `${SESS}=${token}; __Host-downpipes_csrf=${CSRF}`, "x-downpipes-csrf": CSRF, origin: ORIGIN, "content-type": "application/json", "CF-Connecting-IP": "198.51.100.9" };
  return handleAdmin(new Request(`${ORIGIN}${path}`, { method: "POST", headers, body: JSON.stringify(body) }), env);
}
async function alive(env: Env, token: string): Promise<boolean> {
  return (await get(env, "/admin/whoami", `${SESS}=${token}`)).status === 200;
}
async function listSids(env: Env, token: string): Promise<string[]> {
  const r = await get(env, "/admin/sessions", `${SESS}=${token}`);
  if (r.status !== 200) return [];
  const b = (await r.json()) as { sessions?: Array<{ sid?: string }> };
  return (b.sessions ?? []).map((s) => s.sid ?? "");
}
async function signIn(env: Env, connId: string, who: OidcWho): Promise<string | null> {
  idp.who = who;
  idp.issuer = ISSUERS[connId]!;
  idp.client = `cid-${connId}`;
  const st = await get(env, `/admin/oidc/start/${connId}`);
  const u = new URL(st.headers.get("location") ?? "about:blank");
  idp.nonce = u.searchParams.get("nonce") ?? "";
  const state = u.searchParams.get("state") ?? "";
  const txn = cookie(st, OIDC_TXN) ?? "";
  const cb = await get(env, `/admin/oidc/callback/${connId}?code=c${Math.random()}&state=${encodeURIComponent(state)}`, `${OIDC_TXN}=${txn}`);
  return cookie(cb, SESS);
}
async function createConn(env: Env, connId: string): Promise<void> {
  const iss = ISSUERS[connId]!;
  const proposal = {
    id: connId, kind: "oidc", label: connId, presetId: "generic-oidc", enabled: true, issuer: iss, clientId: `cid-${connId}`, secretRef: { mode: "do-plaintext" },
    scopes: ["openid", "email", "profile"], idTokenSigAlgs: ["RS256"], pkce: "required", clientAuth: "client_secret_post", requireNonce: true, groupsClaim: "groups",
    authorizationEndpoint: `${iss}/authorize`, tokenEndpoint: `${iss}/token`, jwksUri: `${iss}/jwks`,
  };
  const r = await admin(env, "POST", "/admin/idp/connections", { proposal, secret: "s" });
  if (r.status !== 200) throw new Error(`connection ${connId} not created: ${r.status} ${await r.text()}`);
}

type Route = "same-connection" | "second-connection" | "viewer-row";
type Verified = "false" | "absent" | "true";

async function oneCase(route: Route, verified: Verified): Promise<void> {
  const label = `[${route}, email_verified ${verified}]`;
  const { env, storage } = makeEnv();
  await storage.put(roleSubjectKey(FOUNDER.subject), FOUNDER);
  await createConn(env, "corp");
  await createConn(env, "corp2");
  // The victim: invited by email, signs in on corp with a verified email, and binds the invite.
  const inv = await admin(env, "POST", "/admin/roles", { email: VICTIM, role: "operator" });
  if (inv.status !== 200) throw new Error("the victim invite failed");
  const victim = await signIn(env, "corp", { sub: "victim-sub", email: VICTIM, emailVerified: true, groups: [] });
  if (victim === null) throw new Error("the victim did not get a session");
  const victimSids = await listSids(env, victim);
  ok(`${label} control: the victim's own list shows the victim's session`, victimSids.length === 1);

  // The attacker: admitted by its own grant, asserting the VICTIM's email.
  const attConn = route === "second-connection" ? "corp2" : "corp";
  if (route === "viewer-row") {
    const s = oidcSubject("corp", ISSUERS.corp!, "attacker-sub");
    await storage.put(roleSubjectKey(s), { subject: s, email: "attacker@elsewhere.example", role: "viewer", grantedBy: FOUNDER.email, grantedAt: "2026-06-13T00:00:00.000Z" });
  } else {
    const m = await admin(env, "POST", "/admin/group-roles", { group: "staff", role: "viewer", connId: attConn });
    if (m.status !== 200) throw new Error("the group mapping failed");
  }
  const emailVerified = verified === "absent" ? undefined : verified === "true";
  const attacker = await signIn(env, attConn, { sub: "attacker-sub", email: VICTIM, emailVerified, groups: route === "viewer-row" ? [] : ["staff"] });
  ok(`${label} precondition: the admitted attacker gets a session`, attacker !== null);
  if (attacker === null) return;

  const attackerList = await listSids(env, attacker);
  ok(`${label} the attacker's list does NOT show the victim's session`, victimSids.every((sid) => !attackerList.includes(sid)));
  ok(`${label} control: the attacker's list shows its own session`, attackerList.length === 1);

  const t = await post(env, "/admin/sessions/terminate", attacker, { sid: victimSids[0] });
  ok(`${label} ending the victim's session by id is refused (404)`, t.status === 404);
  ok(`${label} the victim's session survives the terminate attempt`, await alive(env, victim));

  const others = await post(env, "/admin/sessions/terminate-others", attacker, {});
  ok(`${label} the attacker's "end my other sessions" succeeds for itself`, others.status === 200);
  const attackerNext = cookie(others, SESS) ?? attacker;
  ok(`${label} the victim's session survives the attacker's "end my other sessions"`, await alive(env, victim));

  const lo = await post(env, "/admin/auth/logout", attackerNext, {});
  ok(`${label} the attacker's logout is 200`, lo.status === 200);
  ok(`${label} control: the attacker's own session is ended by its logout`, !(await alive(env, attackerNext)));
  ok(`${label} the victim's session survives the attacker's logout`, await alive(env, victim));

  // The admin path keeps the email axis: an Owner ending the victim's sessions by email still works.
  const tu = await admin(env, "POST", "/admin/sessions/terminate-user", { email: VICTIM });
  ok(`${label} control: the Owner's terminate-user by email is 200`, tu.status === 200);
  ok(`${label} control: the Owner's terminate-user ends the victim's session`, !(await alive(env, victim)));
}

console.log("Native sessions are keyed on the signed-in subject, not the asserted email\n");
for (const route of ["same-connection", "second-connection", "viewer-row"] as const) {
  for (const verified of ["false", "absent", "true"] as const) await oneCase(route, verified);
}

// ---------------- the scope of each sign-in method, at the DO ----------------
// The router hands the DO the verified caller, so the scope rule lives in listOwnSessions, terminateOneSession and
// terminateOwnOtherSessions. A victim holds one native session under an email. A second identity of each method,
// on its own subject and asserting the same email, then tries to list it, end it by id, and end its own others.
// An oidc or saml caller is held to its own subject. A passkey or access caller (a recovery sign-in mints a
// passkey session) is scoped to the email, so it lists and ends every session recorded under that email. A
// token caller carries no email and is refused.
async function methodScope(victimMethod: "oidc" | "saml", callerMethod: "oidc" | "saml" | "passkey" | "access" | "token"): Promise<void> {
  const label = `[${victimMethod} victim, ${callerMethod} caller]`;
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const key = await dobj.sessionSigningKey();
  const now = Date.now();
  const epoch0 = await dobj.getSessionEpoch(VICTIM);
  const victimSubject = `${victimMethod}|corp|victim-sub`;
  const victimToken = await dobj.mintSessionRecorded(key, { method: victimMethod, email: VICTIM, subject: victimSubject, connId: "corp", epoch: epoch0 }, now);
  const victimSid = (await verifySession(key, victimToken, now))?.sid ?? "";
  ok(`${label} precondition: the victim session has an id`, victimSid.length === 22);
  const victimRevoked = async () => (await storage.get(`${SESSION_REVOKED_PREFIX}${victimSid}`)) !== undefined;

  const native = callerMethod === "oidc" || callerMethod === "saml";
  const subject = native ? `${callerMethod}|corp2|other-sub` : callerMethod === "passkey" ? passkeySubject(VICTIM) : callerMethod === "access" ? "access|https://team.example|other-sub" : "token";
  const email = callerMethod === "token" ? "" : VICTIM;
  const caller = { method: callerMethod, email, subject, groups: [] as string[], ...(native ? { connId: "corp2" } : {}) };
  const own = callerMethod === "passkey" ? await dobj.passkeySessionIssue({ email: VICTIM }) : null;
  const ownToken = own?.ok ? own.token : native ? await dobj.mintSessionRecorded(key, { method: callerMethod, email, subject, connId: "corp2", epoch: epoch0 }, now) : null;

  const list = await dobj.listOwnSessions(caller, {});
  const sees = list.ok && list.sessions.some((r) => r.sid === victimSid);
  if (callerMethod === "token") {
    ok(`${label} a caller with no email lists nothing`, !list.ok);
    const t = await dobj.terminateOneSession(caller, { sid: victimSid });
    ok(`${label} a caller with no email cannot end the session`, !t.ok && !(await victimRevoked()));
    return;
  }
  if (native) {
    ok(`${label} the list does NOT show the other subject's session`, list.ok && !sees);
    const t = await dobj.terminateOneSession(caller, { sid: victimSid });
    ok(`${label} ending the session by id is refused as not-found`, !t.ok && t.reason === "not-found" && !(await victimRevoked()));
    const o = await dobj.terminateOwnOtherSessions(caller, { token: ownToken });
    ok(`${label} "end my other sessions" succeeds for itself`, o.ok);
    ok(`${label} the victim's session survives: not revoked, email epoch unchanged`, !(await victimRevoked()) && (await dobj.getSessionEpoch(VICTIM)) === epoch0);
    return;
  }
  ok(`${label} the email-scoped list shows the session of the other subject`, sees);
  const t = await dobj.terminateOneSession(caller, { sid: victimSid });
  ok(`${label} ending the other subject's session by id succeeds`, t.ok && (await victimRevoked()));
  if (callerMethod === "passkey") {
    const o = await dobj.terminateOwnOtherSessions(caller, { token: ownToken });
    ok(`${label} "end my other sessions" moves the email epoch past the victim's session`, o.ok && (await dobj.getSessionEpoch(VICTIM)) > epoch0);
  }
}

console.log("\nThe scope of each sign-in method over the sessions recorded under one email\n");
for (const victimMethod of ["oidc", "saml"] as const) {
  for (const callerMethod of ["oidc", "saml", "passkey", "access", "token"] as const) await methodScope(victimMethod, callerMethod);
}

console.log(failures === 0 ? "\nSESSION SUBJECT-KEYED VECTORS PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures);
if (failures > 0) process.exit(1);
