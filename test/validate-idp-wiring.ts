// Prove the NATIVE OIDC wiring end to end THROUGH THE ROUTER (handleAdmin) and the scheduler DO, with
// in-memory doubles only and a stubbed global fetch standing in for the IdP. No network, no deploy, no cost.
// Run: node test/validate-idp-wiring.ts
//
// What this proves (the glue the per-module validators do not cover, since they stop at the pure cores):
//  - an Owner (the ADMIN_TOKEN break-glass) creates an OIDC connection via POST /admin/idp/connections, the
//    keys.ceremony gate admits it, the do-plaintext client secret is stored WRITE-ONLY, and the response is
//    REDACTED (only a {mode} secretRef, never the value);
//  - GET /admin/oidc/providers is the PRE-AUTH display DTO: the connection appears with NO issuer/clientId/
//    secret/endpoints;
//  - GET /admin/oidc/start/<id> mints state+nonce+PKCE in the DO, sets the __Host- txn cookie and 302s to the
//    IdP authorize URL (state + nonce + S256 challenge + the pre-registered redirect_uri all present);
//  - GET /admin/oidc/callback/<id> runs the guarded exchange + REAL id_token verification INSIDE the DO
//    (a stubbed IdP serves the token endpoint with a real RS256 id_token and the JWKS), mints the v3 oidc
//    session, sets the session cookie + clears the txn cookie, and 302s to the relative-only returnTo;
//  - the email_verified-gated pending-invite BIND fires (the verified email claims its "approver" invite), so
//    GET /admin/whoami over the oidc cookie reports method "oidc", the immutable oidc:<id>|<iss>|<sub> subject,
//    the bound role, and the GROUPS re-read from the server-side snapshot (never carried in the cookie);
//  - DISABLING the connection bumps the per-connection idpEpoch, so the SAME oidc cookie is then rejected
//    (401) on the next request - the revocation axis the v3 session adds;
//  - the management list (GET /admin/idp/connections) is redacted (no secret value).
//
// The IdP id_token is a REAL RS256 JWT verified against a controlled JWKS the stubbed fetch serves, so the DO
// runs its PRODUCTION verification path (exchangeCode -> verifyIdTokenWithRotation -> completeOidcLogin), not a
// shim. The nonce is read back out of the authorize URL the /start step produced, exactly as a real IdP echoes it.

import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { oidcSubject, roleSubjectKey } from "../src/admin/identity.ts";
import { AUDIT_PREFIX, type AuditEvent } from "../src/admin/audit.ts";
import { PRESETS } from "../src/admin/oidc-presets.ts";
import { MockStorage } from "./mock-storage.ts";
// The pre-auth IdP web edge under direct test for the defensive / error branches that the happy-path router
// wiring above never reaches (malformed cookies, the relative-only returnTo guard, the no-oracle failure
// paths, the DO-down catches and the non-ok DO replies). These are exported, acyclic helpers, so driving
// them directly is the production code path (handleAdmin only slices the prefix off and forwards verbatim).
import { handleOidc, handleSaml, safeReturnTo, readOidcTxnCookie, readSamlTxnCookie, OIDC_TXN_COOKIE, SAML_TXN_COOKIE } from "../src/admin/router-idp-web.ts";
import { AUTH_RATE_LIMIT_MAX_PER_WINDOW } from "../src/sched/scheduler-do.ts";
import type { Env } from "../src/env.d.ts";
import type { JWK, JWKS } from "../src/admin/oidc-verify.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// in-memory DO storage (the subset SchedulerDO uses): the shared test double, so a fix to its
// semantics lands in one place rather than in diverging copies.

const CONSOLE_ORIGIN = "https://console.downpipes.io";
const ADMIN_TOKEN = "test-admin-token";

function makeEnv(): { env: Env; storage: MockStorage } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  const env = { SCHEDULER: namespace, CONSOLE_ORIGIN, ADMIN_TOKEN } as unknown as Env;
  return { env, storage };
}

// ---- the stubbed IdP (real RS256 id_token + JWKS), served by the global fetch override ----
const ISSUER = "https://idp.example.com";
const AUTH_URL = "https://idp.example.com/authorize";
const TOKEN_URL = "https://idp.example.com/token";
const JWKS_URL = "https://idp.example.com/jwks";
const CLIENT = "client-abc";
const USER_SUB = "user-1";
const USER_EMAIL = "alice@acme.example";
// OAuth2 (GitHub-class) stub endpoints + identity.
const GH_AUTH = "https://github.example/login/oauth/authorize";
const GH_TOKEN = "https://github.example/login/oauth/access_token";
const GH_API = "https://api.github.example";
const GH_ID = 583231;
const GH_EMAIL = "octo@github.example";

function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlJSON(o: unknown): string {
  return b64url(new TextEncoder().encode(JSON.stringify(o)));
}
const rsa = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
const rsaPub = (await crypto.subtle.exportKey("jwk", rsa.publicKey)) as JsonWebKey;
const JWK_PUB: JWK = { kid: "rsa-1", kty: "RSA", n: rsaPub.n!, e: rsaPub.e!, alg: "RS256" };
const JWKS_GOOD: JWKS = { keys: [JWK_PUB] };
async function signIdToken(payload: Record<string, unknown>): Promise<string> {
  const head = b64urlJSON({ alg: "RS256", kid: "rsa-1", typ: "JWT" });
  const body = b64urlJSON(payload);
  const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", rsa.privateKey, new TextEncoder().encode(`${head}.${body}`)));
  return `${head}.${body}.${b64url(sig)}`;
}

// The id_token claims the stubbed token endpoint mints. nonce + emailVerified are mutated per-vector before
// the callback so the token echoes the authorize-request nonce (as a real IdP does) and we can exercise both
// the verified and unverified email paths.
let currentNonce = "";
let currentEmailVerified = true;
let currentSub = USER_SUB;
let currentEmail = USER_EMAIL;
const now = Math.floor(Date.now() / 1000);

const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: RequestInfo | URL, _init?: RequestInit): Promise<Response> => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
  if (url === JWKS_URL) {
    return new Response(JSON.stringify(JWKS_GOOD), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url === TOKEN_URL) {
    // Include the advisory (V6.8.4) acr/amr/auth_time so the DO's sign-in audit exercises the advisory-present
    // path end to end (they are non-gating: they never change the resolved subject/email/groups/role).
    const idToken = await signIdToken({ iss: ISSUER, sub: currentSub, aud: CLIENT, nonce: currentNonce, exp: now + 300, iat: now, email: currentEmail, email_verified: currentEmailVerified, roles: ["admins"], acr: "urn:mfa", amr: ["pwd", "otp"], auth_time: now - 30 });
    return new Response(JSON.stringify({ id_token: idToken, access_token: "at-value", token_type: "Bearer" }), { status: 200, headers: { "content-type": "application/json" } });
  }
  // The OAuth2 (GitHub-class) endpoints: an opaque token, then userinfo (immutable numeric id, NEVER the
  // login), the primary+verified email, and the team/org membership.
  if (url === GH_TOKEN) {
    return new Response(JSON.stringify({ access_token: "gho_opaque", token_type: "bearer" }), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url === `${GH_API}/user`) {
    return new Response(JSON.stringify({ id: GH_ID, login: "octocat", name: "The Octocat" }), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url === `${GH_API}/user/emails`) {
    return new Response(JSON.stringify([{ email: GH_EMAIL, primary: true, verified: true }]), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url === `${GH_API}/user/teams`) {
    return new Response(JSON.stringify([{ slug: "engineers", organization: { login: "acme" } }]), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url === `${GH_API}/user/orgs`) {
    return new Response(JSON.stringify([{ login: "acme" }]), { status: 200, headers: { "content-type": "application/json" } });
  }
  throw new Error(`unexpected fetch in test: ${url}`);
}) as typeof fetch;
// Restore the real fetch on process exit as well, so a throw in the module-level setup below (before the
// try/finally is entered) cannot leak the stub into any other test sharing the process.
process.on("exit", () => {
  globalThis.fetch = realFetch;
});

// ---- helpers to drive handleAdmin ----
const { env, storage } = makeEnv();

function adminUrl(path: string): string {
  return `${CONSOLE_ORIGIN}${path}`;
}
function tokenHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json", ...extra };
}
function getSetCookie(resp: Response): string[] {
  const h = resp.headers as Headers & { getSetCookie?: () => string[] };
  if (typeof h.getSetCookie === "function") return h.getSetCookie();
  const one = resp.headers.get("set-cookie");
  return one ? [one] : [];
}
function cookieValue(setCookies: string[], name: string): string | null {
  for (const sc of setCookies) {
    const first = sc.split(";")[0] ?? "";
    const eq = first.indexOf("=");
    if (eq <= 0) continue;
    if (first.slice(0, eq).trim() !== name) continue;
    const v = first.slice(eq + 1).trim();
    return v.length > 0 ? v : null;
  }
  return null;
}

console.log("Native OIDC end-to-end wiring (router + DO + stubbed IdP)\n");

try {
  // Seed a bound Owner so the first-caller bootstrap does not claim the OIDC user as Owner (this test wants
  // the OIDC user to resolve to their INVITED role, not the bootstrap Owner). The ADMIN_TOKEN break-glass is
  // not a table entry, so without this the role:sub table would be empty at the oidc bind.
  await storage.put(roleSubjectKey("passkey|founder@acme.example"), { subject: "passkey|founder@acme.example", email: "founder@acme.example", role: "owner", grantedBy: "system", grantedAt: "2026-06-13T00:00:00.000Z" });

  const proposal = {
    id: "entra", kind: "oidc", label: "Microsoft Entra ID", presetId: "entra", enabled: true,
    issuer: ISSUER, clientId: CLIENT, secretRef: { mode: "do-plaintext" },
    scopes: ["openid", "email", "profile"], idTokenSigAlgs: ["RS256"], pkce: "required",
    clientAuth: "client_secret_post", requireNonce: true, rolesClaim: "roles",
    authorizationEndpoint: AUTH_URL, tokenEndpoint: TOKEN_URL, jwksUri: JWKS_URL,
  };

  // 1. Owner creates the connection (keys.ceremony admits the ADMIN_TOKEN owner). Secret supplied separately.
  {
    const r = await handleAdmin(new Request(adminUrl("/admin/idp/connections"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ proposal, secret: "super-secret-value" }) }), env);
    const body = (await r.json()) as { ok?: boolean; conn?: { secretRef?: { mode?: string; value?: unknown }; issuer?: unknown } };
    ok("create connection: 200", r.status === 200);
    ok("create connection: ok + redacted secretRef (mode only, no value)", body.ok === true && body.conn?.secretRef?.mode === "do-plaintext" && !(body.conn?.secretRef !== undefined && "value" in body.conn.secretRef));
    // The do-plaintext secret VALUE is stored write-only under idpsecret:<id>, never in the record.
    const secretStored = await storage.get<string>("idpsecret:entra");
    ok("create connection: secret stored write-only under idpsecret:<id>", secretStored === "super-secret-value");
    const record = await storage.get<{ secretRef?: { value?: unknown } }>("idpconn:entra");
    ok("create connection: stored RECORD holds no secret value", record !== undefined && !(record.secretRef !== undefined && "value" in (record.secretRef as object)));
  }

  // 1b. Owner invites alice as approver (a PENDING invite that must bind on her first VERIFIED oidc sign-in).
  {
    const r = await handleAdmin(new Request(adminUrl("/admin/roles"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ email: USER_EMAIL, role: "approver" }) }), env);
    ok("invite alice as approver (pending): 200", r.status === 200);
  }

  // 2. Pre-auth providers DTO: the connection appears with NO internal fields.
  {
    const r = await handleAdmin(new Request(adminUrl("/admin/oidc/providers"), { method: "GET" }), env);
    const body = (await r.json()) as { ok?: boolean; providers?: Array<Record<string, unknown>> };
    const p = body.providers?.find((x) => x["id"] === "entra");
    ok("providers: connection visible", p !== undefined && p["label"] === "Microsoft Entra ID" && p["kind"] === "oidc");
    ok("providers: NO issuer/clientId/secret/endpoints leak", p !== undefined && !("issuer" in p) && !("clientId" in p) && !("secretRef" in p) && !("tokenEndpoint" in p));
  }

  // 3. /start: 302 to the authorize URL + the __Host- txn cookie. Read state + nonce back out of the URL.
  let state = "";
  let txnId = "";
  {
    const r = await handleAdmin(new Request(adminUrl("/admin/oidc/start/entra?returnTo=%2Fdashboard"), { method: "GET" }), env);
    ok("start: 302", r.status === 302);
    const loc = r.headers.get("location") ?? "";
    ok("start: Location is the IdP authorize URL", loc.startsWith(AUTH_URL));
    const u = new URL(loc);
    state = u.searchParams.get("state") ?? "";
    currentNonce = u.searchParams.get("nonce") ?? "";
    ok("start: authorize URL carries state + nonce + S256 challenge + client_id + the pre-registered redirect_uri", state.length > 0 && currentNonce.length > 0 && u.searchParams.get("code_challenge_method") === "S256" && u.searchParams.get("client_id") === CLIENT && u.searchParams.get("redirect_uri") === `${CONSOLE_ORIGIN}/admin/oidc/callback/entra`);
    txnId = cookieValue(getSetCookie(r), "__Host-downpipes_oidc_txn") ?? "";
    ok("start: __Host- txn cookie set (SameSite=Lax)", txnId.length > 0 && getSetCookie(r).some((c) => c.includes("__Host-downpipes_oidc_txn") && /SameSite=Lax/i.test(c)));
    ok("start: Referrer-Policy no-referrer on the 302", (r.headers.get("referrer-policy") ?? "").toLowerCase() === "no-referrer");
  }

  // 4. /callback with the txn cookie: real exchange + verify inside the DO, mint, 302 to returnTo, session cookie.
  let sessionCookie = "";
  {
    currentEmailVerified = true;
    const r = await handleAdmin(new Request(adminUrl(`/admin/oidc/callback/entra?code=the-code&state=${encodeURIComponent(state)}&iss=${encodeURIComponent(ISSUER)}`), { method: "GET", headers: { cookie: `__Host-downpipes_oidc_txn=${txnId}` } }), env);
    ok("callback: 302", r.status === 302);
    ok("callback: Location is the relative-only returnTo", (r.headers.get("location") ?? "") === "/dashboard");
    const cookies = getSetCookie(r);
    sessionCookie = cookieValue(cookies, "__Host-downpipes_session") ?? "";
    ok("callback: session cookie minted", sessionCookie.length > 0);
    ok("callback: txn cookie cleared (Max-Age=0)", cookies.some((c) => c.includes("__Host-downpipes_oidc_txn") && /Max-Age=0/i.test(c)));
    ok("callback: Referrer-Policy no-referrer on the 302", (r.headers.get("referrer-policy") ?? "").toLowerCase() === "no-referrer");
  }

  // 5. whoami over the oidc cookie: method oidc, the immutable subject, the bound role, the snapshot groups.
  const expectSubject = oidcSubject("entra", ISSUER, USER_SUB);
  {
    const r = await handleAdmin(new Request(adminUrl("/admin/whoami"), { method: "GET", headers: { cookie: `__Host-downpipes_session=${sessionCookie}` } }), env);
    ok("whoami: 200 over the oidc session cookie", r.status === 200);
    const body = (await r.json()) as { method?: string; subject?: string; role?: string; groups?: string[]; connId?: string };
    ok("whoami: method is oidc", body.method === "oidc");
    ok("whoami: subject is oidc:<connId>|<issuer>|<sub> (verbatim, never re-derived)", body.subject === expectSubject);
    ok("whoami: connId is the connection", body.connId === "entra");
    ok("whoami: the email_verified-gated pending invite BOUND (role == approver)", body.role === "approver");
    ok("whoami: groups re-read from the server-side snapshot (NOT the cookie)", JSON.stringify(body.groups) === JSON.stringify(["admins"]));
  }

  // 5b. The email_verified gate, NEGATIVELY: an UNVERIFIED email must NOT bind a pending invite. Invite bob as
  //     approver, sign bob in with email_verified=false -> he authenticates as his own oidc subject, but the
  //     invite does NOT bind, so he resolves to the viewer default (the open-bind / account-takeover defence).
  {
    const BOB = "bob@acme.example";
    await handleAdmin(new Request(adminUrl("/admin/roles"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ email: BOB, role: "approver" }) }), env);
    currentSub = "user-2";
    currentEmail = BOB;
    currentEmailVerified = false;
    const s = await handleAdmin(new Request(adminUrl("/admin/oidc/start/entra"), { method: "GET" }), env);
    const su = new URL(s.headers.get("location") ?? "https://x/");
    const st = su.searchParams.get("state") ?? "";
    currentNonce = su.searchParams.get("nonce") ?? "";
    const tx = cookieValue(getSetCookie(s), "__Host-downpipes_oidc_txn") ?? "";
    const cb = await handleAdmin(new Request(adminUrl(`/admin/oidc/callback/entra?code=c&state=${encodeURIComponent(st)}&iss=${encodeURIComponent(ISSUER)}`), { method: "GET", headers: { cookie: `__Host-downpipes_oidc_txn=${tx}` } }), env);
    const bobCookie = cookieValue(getSetCookie(cb), "__Host-downpipes_session") ?? "";
    ok("unverified-email sign-in still mints a session (authenticated as the subject)", cb.status === 302 && bobCookie.length > 0);
    const w = await handleAdmin(new Request(adminUrl("/admin/whoami"), { method: "GET", headers: { cookie: `__Host-downpipes_session=${bobCookie}` } }), env);
    const wb = (await w.json()) as { role?: string; method?: string };
    ok("unverified email did NOT bind the pending invite (role == viewer, NOT approver)", wb.method === "oidc" && wb.role === "viewer");
    // The failed bind must NOT consume or discard bob's pending invite: a later VERIFIED sign-in for the
    // same email must still find the invite and bind it to approver. Sign bob back in with email_verified=true.
    currentEmailVerified = true;
    const s2 = await handleAdmin(new Request(adminUrl("/admin/oidc/start/entra"), { method: "GET" }), env);
    const su2 = new URL(s2.headers.get("location") ?? "https://x/");
    const st2 = su2.searchParams.get("state") ?? "";
    currentNonce = su2.searchParams.get("nonce") ?? "";
    const tx2 = cookieValue(getSetCookie(s2), "__Host-downpipes_oidc_txn") ?? "";
    const cb2 = await handleAdmin(new Request(adminUrl(`/admin/oidc/callback/entra?code=c&state=${encodeURIComponent(st2)}&iss=${encodeURIComponent(ISSUER)}`), { method: "GET", headers: { cookie: `__Host-downpipes_oidc_txn=${tx2}` } }), env);
    const bobCookie2 = cookieValue(getSetCookie(cb2), "__Host-downpipes_session") ?? "";
    const w2 = await handleAdmin(new Request(adminUrl("/admin/whoami"), { method: "GET", headers: { cookie: `__Host-downpipes_session=${bobCookie2}` } }), env);
    const w2Body = (await w2.json()) as { role?: string; method?: string };
    ok("the pending invite survived the unverified attempt and BOUND on the verified sign-in (role == approver)", w2Body.method === "oidc" && w2Body.role === "approver");
    currentSub = USER_SUB;
    currentEmail = USER_EMAIL;
    currentEmailVerified = true;
  }

  // 5c. A callback with NO txn cookie is refused (the login-CSRF binding): generic fail redirect, NO session.
  {
    const s = await handleAdmin(new Request(adminUrl("/admin/oidc/start/entra"), { method: "GET" }), env);
    const su = new URL(s.headers.get("location") ?? "https://x/");
    const st = su.searchParams.get("state") ?? "";
    currentNonce = su.searchParams.get("nonce") ?? "";
    const cb = await handleAdmin(new Request(adminUrl(`/admin/oidc/callback/entra?code=c&state=${encodeURIComponent(st)}&iss=${encodeURIComponent(ISSUER)}`), { method: "GET" }), env);
    ok("callback with NO txn cookie -> generic fail redirect, no session minted", cb.status === 302 && (cb.headers.get("location") ?? "").includes("oidc=failed") && cookieValue(getSetCookie(cb), "__Host-downpipes_session") === null);
  }

  // 6. Disable the connection -> the SAME oidc cookie is rejected on the next request (the idpEpoch axis).
  {
    const d = await handleAdmin(new Request(adminUrl("/admin/idp/connections/enabled"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ connId: "entra", enabled: false }) }), env);
    ok("disable connection: 200", d.status === 200);
    const r = await handleAdmin(new Request(adminUrl("/admin/whoami"), { method: "GET", headers: { cookie: `__Host-downpipes_session=${sessionCookie}` } }), env);
    ok("revocation: the oidc cookie is now rejected (401) - idpEpoch axis killed the live session", r.status === 401);
    // While disabled, /start is refused (no new sign-ins through a disabled connection) - generic fail redirect.
    const ds = await handleAdmin(new Request(adminUrl("/admin/oidc/start/entra"), { method: "GET" }), env);
    ok("disabled connection: /start refused (generic fail redirect, NOT an authorize URL)", ds.status === 302 && (ds.headers.get("location") ?? "").includes("oidc=failed"));
  }

  // 7. Management list (re-enable first so the list shows it): redacted, no secret value.
  {
    await handleAdmin(new Request(adminUrl("/admin/idp/connections/enabled"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ connId: "entra", enabled: true }) }), env);
    const r = await handleAdmin(new Request(adminUrl("/admin/idp/connections"), { method: "GET", headers: tokenHeaders() }), env);
    const body = (await r.json()) as { ok?: boolean; connections?: Array<{ id?: string; secretRef?: { mode?: string; value?: unknown } }> };
    const c = body.connections?.find((x) => x.id === "entra");
    ok("management list: connection present, secretRef redacted (mode only, no value)", c !== undefined && c.secretRef?.mode === "do-plaintext" && !(c.secretRef !== undefined && "value" in c.secretRef));
  }

  // 8. Non-owner cannot manage connections: a viewer (an Access caller would resolve to viewer by default) is
  //    refused. We simulate the gate by calling with NO credential at all -> 401 (handleAdmin authorise gate),
  //    proving the management surface is behind authentication (the keys.ceremony gate is unit-tested in the DO).
  {
    const r = await handleAdmin(new Request(adminUrl("/admin/idp/connections"), { method: "GET" }), env);
    ok("management list: unauthenticated request is refused (401)", r.status === 401);
  }

  // 9. OAuth2 (GitHub-class, NO id_token): create a github connection, sign in through the SAME /admin/oidc/*
  //    flow (the DO dispatches by kind), and assert the userinfo-derived IMMUTABLE-numeric-id subject (never
  //    the login) + the team/org groups. Proves the GitHub piece of the named set, reusing the shared v3 mint.
  {
    const ghProposal = {
      id: "github", kind: "oauth2", label: "GitHub", presetId: "github", enabled: true,
      authorizeUrl: GH_AUTH, tokenUrl: GH_TOKEN, tokenAuthStyle: "post_json",
      clientId: "gh-client", secretRef: { mode: "do-plaintext" },
      scopes: ["read:user", "user:email", "read:org"], apiBase: GH_API,
      profileUrl: `${GH_API}/user`, subjectPath: "id", subjectPrefix: "github",
      emailUrl: `${GH_API}/user/emails`, groupsUrls: [`${GH_API}/user/teams`, `${GH_API}/user/orgs`], pkce: "none",
    };
    const cr = await handleAdmin(new Request(adminUrl("/admin/idp/connections"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ proposal: ghProposal, secret: "gh-secret" }) }), env);
    ok("oauth2: create github connection -> 200", cr.status === 200);
    const s = await handleAdmin(new Request(adminUrl("/admin/oidc/start/github"), { method: "GET" }), env);
    const su = new URL(s.headers.get("location") ?? "https://x/");
    const st = su.searchParams.get("state") ?? "";
    ok("oauth2: start 302 to the github authorize URL, state + client_id present, NO nonce (no id_token)", s.status === 302 && (s.headers.get("location") ?? "").startsWith(GH_AUTH) && st.length > 0 && su.searchParams.get("client_id") === "gh-client" && su.searchParams.get("nonce") === null);
    const tx = cookieValue(getSetCookie(s), "__Host-downpipes_oidc_txn") ?? "";
    const cb = await handleAdmin(new Request(adminUrl(`/admin/oidc/callback/github?code=ghcode&state=${encodeURIComponent(st)}`), { method: "GET", headers: { cookie: `__Host-downpipes_oidc_txn=${tx}` } }), env);
    const ghCookie = cookieValue(getSetCookie(cb), "__Host-downpipes_session") ?? "";
    ok("oauth2: callback mints a session (no id_token; trust is the TLS exchange + userinfo)", cb.status === 302 && ghCookie.length > 0);
    const w = await handleAdmin(new Request(adminUrl("/admin/whoami"), { method: "GET", headers: { cookie: `__Host-downpipes_session=${ghCookie}` } }), env);
    const wb = (await w.json()) as { method?: string; subject?: string; groups?: string[]; connId?: string };
    const expectGh = oidcSubject("github", `github:${GH_API}`, String(GH_ID));
    ok("oauth2: whoami method oidc, subject is the IMMUTABLE numeric id (never the renameable login)", wb.method === "oidc" && wb.subject === expectGh && !(wb.subject ?? "").includes("octocat"));
    ok("oauth2: groups are the team + org from userinfo (org/team + org)", JSON.stringify(wb.groups) === JSON.stringify(["acme/engineers", "acme"]));
    ok("oauth2: connId is github", wb.connId === "github");
  }

  // 10. CRITICAL regression: terminate-others must NOT launder a native oidc/saml
  //     session into a passkey session. Exploit (now blocked): invite carol as OWNER (pending); sign carol in
  //     UNVERIFIED (no bind -> viewer); have her click "sign out other devices". Pre-fix the re-mint collapsed
  //     her to passkey|carol and the NEXT request bound the owner invite to that passkey subject (escalation).
  //     Post-fix the re-mint keeps her oidc method + signed subject + connId, so the invite stays unbound and
  //     she stays viewer.
  {
    const CAROL = "carol@acme.example";
    await handleAdmin(new Request(adminUrl("/admin/roles"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ email: CAROL, role: "owner" }) }), env);
    currentSub = "user-3";
    currentEmail = CAROL;
    currentEmailVerified = false;
    const s = await handleAdmin(new Request(adminUrl("/admin/oidc/start/entra"), { method: "GET" }), env);
    const su = new URL(s.headers.get("location") ?? "https://x/");
    const st = su.searchParams.get("state") ?? "";
    currentNonce = su.searchParams.get("nonce") ?? "";
    const tx = cookieValue(getSetCookie(s), "__Host-downpipes_oidc_txn") ?? "";
    const cb = await handleAdmin(new Request(adminUrl(`/admin/oidc/callback/entra?code=c&state=${encodeURIComponent(st)}&iss=${encodeURIComponent(ISSUER)}`), { method: "GET", headers: { cookie: `__Host-downpipes_oidc_txn=${tx}` } }), env);
    const carolCookie = cookieValue(getSetCookie(cb), "__Host-downpipes_session") ?? "";
    // (V6.8.4) end to end: the sign-in AUDIT event carries the IdP's advisory acr/amr/auth_time. Read the
    // chain and assert the most recent idp-sign-in bears the (non-gating) advisory the mock id_token asserted.
    {
      const rows = [...(await storage.list<AuditEvent>({ prefix: AUDIT_PREFIX })).values()];
      const signIn = rows.reverse().find((e) => e.action === "idp-sign-in");
      ok("idp-sign-in audit carries the advisory acr/amr/auth_time (V6.8.4, non-gating)",
        signIn !== undefined && signIn.advisory?.acr === "urn:mfa" && JSON.stringify(signIn.advisory?.amr) === JSON.stringify(["pwd", "otp"]) && typeof signIn.advisory?.authTime === "number");
    }
    const w1 = await handleAdmin(new Request(adminUrl("/admin/whoami"), { method: "GET", headers: { cookie: `__Host-downpipes_session=${carolCookie}` } }), env);
    const wb1 = (await w1.json()) as { role?: string; method?: string };
    ok("laundering setup: unverified carol is viewer (the owner invite is NOT bound)", wb1.method === "oidc" && wb1.role === "viewer");
    // "Sign out other devices": a mutating cookie-borne POST, so it carries the Origin the CSRF guard requires
    // AND the double-submit CSRF token (a matching x-downpipes-csrf header + __Host-downpipes_csrf cookie).
    const term = await handleAdmin(new Request(adminUrl("/admin/sessions/terminate-others"), { method: "POST", headers: { cookie: `__Host-downpipes_session=${carolCookie}; __Host-downpipes_csrf=csrf-idp-1`, origin: CONSOLE_ORIGIN, "x-downpipes-csrf": "csrf-idp-1" } }), env);
    ok("terminate-others: 200 + re-issues a cookie", term.status === 200);
    const reminted = cookieValue(getSetCookie(term), "__Host-downpipes_session") ?? "";
    const w2 = await handleAdmin(new Request(adminUrl("/admin/whoami"), { method: "GET", headers: { cookie: `__Host-downpipes_session=${reminted}` } }), env);
    const w2Body = (await w2.json()) as { role?: string; method?: string; connId?: string };
    ok("NO LAUNDERING: the re-minted session is STILL oidc (not passkey), connId preserved", w2Body.method === "oidc" && w2Body.connId === "entra");
    ok("NO ESCALATION: carol is STILL viewer (the owner invite never bound through a laundered passkey subject)", w2Body.role === "viewer");
    currentSub = USER_SUB;
    currentEmail = USER_EMAIL;
    currentEmailVerified = true;
  }

  // 11. Preset-based create + the catalogue route (the console flow): the engine owns the preset templates and
  //     builds + validates the proposal server-side; the console only supplies {presetId, vars, id, clientId,
  //     secret}. No customer ever constructs a connection or runs a CLI.
  {
    const pr = await handleAdmin(new Request(adminUrl("/admin/idp/presets"), { method: "GET", headers: tokenHeaders() }), env);
    const pb = (await pr.json()) as { ok?: boolean; presets?: Array<{ id?: string }> };
    // Count is checked against the source catalogue length (so adding a preset does not fail this test for
    // the wrong reason), kept separate from the security property (no secret fields leak into the catalogue).
    ok("presets: catalogue returns every source template", pr.status === 200 && Array.isArray(pb.presets) && pb.presets.length === PRESETS.length);
    ok("presets: catalogue carries no secret fields", !JSON.stringify(pb.presets).includes("secretRef") && !JSON.stringify(pb.presets).includes("clientId"));
    const cr = await handleAdmin(new Request(adminUrl("/admin/idp/connections"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ presetId: "keycloak", vars: { host: "sso.acme.example", realm: "employees" }, id: "kc1", clientId: "kc-client", secret: "kc-secret" }) }), env);
    const cb = (await cr.json()) as { ok?: boolean; conn?: { id?: string; kind?: string; issuer?: string } };
    ok("presets: a connection BUILT from a preset server-side validates + stores (issuer substituted)", cr.status === 200 && cb.ok === true && cb.conn?.id === "kc1" && cb.conn?.kind === "oidc" && cb.conn?.issuer === "https://sso.acme.example/realms/employees");
    const lr = await handleAdmin(new Request(adminUrl("/admin/idp/connections"), { method: "GET", headers: tokenHeaders() }), env);
    const lb = (await lr.json()) as { connections?: Array<{ id?: string }> };
    ok("presets: the preset-built connection appears in the management list", Array.isArray(lb.connections) && lb.connections.some((c) => c.id === "kc1"));
    const miss = await handleAdmin(new Request(adminUrl("/admin/idp/connections"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ presetId: "keycloak", vars: { host: "sso.acme.example" }, id: "kc2", clientId: "x", secret: "y" }) }), env);
    ok("presets: a missing required var is a clean refusal (no half-built connection)", ((await miss.json()) as { ok?: boolean }).ok === false);
  }

  // 12. RATE LIMITING (ASVS V10, the "no throttle on the pre-auth OIDC/SAML front door" fix): providers,
  //     start and callback (and the SAML metadata/start/acs analogues) now share the SAME per-IP
  //     authRateLimited pre-check /admin/auth/* already used, so a flood is capped rather than running
  //     unbounded DO round trips (and, for a discovery-based connection, unbounded outbound fetches to the
  //     customer's real IdP). Driven on the REAL DO behind `env` (this file's shared fixture), from a
  //     source IP never used elsewhere in this file so the bucket starts at zero.
  {
    const FLOOD_IP = "203.0.113.50";
    const floodReq = (path: string): Request => new Request(adminUrl(path), { method: "GET", headers: { "CF-Connecting-IP": FLOOD_IP } });
    // Spend the shared per-IP bucket on the cheapest guarded route (providers: no connId, no txn cookie).
    let any429Early = false;
    for (let i = 0; i < AUTH_RATE_LIMIT_MAX_PER_WINDOW; i++) {
      const r = await handleAdmin(floodReq("/admin/oidc/providers"), env);
      if (r.status === 429) any429Early = true;
    }
    ok("rate limit: the first AUTH_RATE_LIMIT_MAX_PER_WINDOW oidc/providers calls from one IP are admitted", any429Early === false);
    const tippedOidc = await handleAdmin(floodReq("/admin/oidc/providers"), env);
    ok("rate limit: the NEXT oidc/providers call from the same IP is 429", tippedOidc.status === 429);
    // The SAME bucket (keyed on IP alone, not per-route) also refuses a DIFFERENT guarded OIDC route...
    const tippedStart = await handleAdmin(floodReq("/admin/oidc/start/entra"), env);
    ok("rate limit: the SAME per-IP bucket also refuses oidc/start (shared cap, not per-route)", tippedStart.status === 429);
    // ...and the SAML analogue, proving handleSaml is wired to the identical limiter, not a copy.
    const tippedSaml = await handleAdmin(floodReq("/admin/saml/start/entra"), env);
    ok("rate limit: the SAME per-IP bucket also refuses saml/start (handleSaml wired too)", tippedSaml.status === 429);
    // A DIFFERENT source IP is a SEPARATE bucket (keyed on IP, not global) and is still admitted.
    const otherIp = await handleAdmin(new Request(adminUrl("/admin/oidc/providers"), { method: "GET", headers: { "CF-Connecting-IP": "203.0.113.51" } }), env);
    ok("rate limit: a DIFFERENT source IP is a separate bucket and is still admitted", otherIp.status === 200);
    // An unmatched sub-path under a rate-limited IP stays a cheap plain 404 (the check is per-branch, AFTER
    // the route match, mirroring handlePasskey's discipline: a probe never pays for a rate-check it cannot
    // even reach a real branch from).
    const bogus = await handleAdmin(floodReq("/admin/oidc/bogus"), env);
    ok("rate limit: an unmatched oidc sub-path under the SAME capped IP is still a plain 404, not 429", bogus.status === 404);
  }

  // ==========================================================================================================
  // Defensive / error-path coverage for the pre-auth IdP web edge. The wiring vectors above drive only the
  // happy path through a real SchedulerDO; the guards below need malformed cookies, hostile returnTo values
  // and a DO that is down or replies not-ok, so they call the exported edge functions directly with bespoke
  // doubles. Each case still asserts the OBSERVABLE security outcome (the safe fallback, the generic 302, the
  // 404 / 503), never just that a line ran.
  // ==========================================================================================================

  // fakeEnv builds a minimal Env whose scheduler stub is wholly under our control: it either throws (the DO is
  // unreachable) or returns a caller-supplied Response (a not-ok DO reply), and records the last request body
  // so we can assert what the edge forwarded. CONSOLE_ORIGIN is overridable to exercise the missing-config arm.
  // The stub auto-admits the authRateLimited pre-check's own /rate-check call (ahead of the caller's handler)
  // so every existing single-purpose double below stays focused on the ENDPOINT it names, exactly as before
  // the pre-throttle was wired in; the limiter primitive itself is proven separately in validate-ratelimit.ts,
  // and its wiring onto this router is proven above in section 12.
  function fakeEnv(handler: (req: Request) => Promise<Response>, consoleOrigin: unknown = CONSOLE_ORIGIN): Env {
    const stub = {
      fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const req = new Request(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url, init);
        if (req.url === "https://scheduler.internal/rate-check") return Promise.resolve(jsonResp({ allowed: true }));
        return handler(req);
      },
    } as unknown as DurableObjectStub;
    const namespace = { idFromName: (_n: string) => ({}) as unknown as DurableObjectId, get: (_id: DurableObjectId) => stub } as unknown as DurableObjectNamespace;
    return { SCHEDULER: namespace, CONSOLE_ORIGIN: consoleOrigin } as unknown as Env;
  }
  const throwingEnv = (consoleOrigin: unknown = CONSOLE_ORIGIN): Env => fakeEnv(() => { throw new Error("DO unreachable"); }, consoleOrigin);
  const jsonResp = (o: unknown): Response => new Response(JSON.stringify(o), { headers: { "content-type": "application/json" } });

  // ---- safeReturnTo: the relative-only, same-origin landing guard (open-redirect + code-leak defence) ----
  {
    ok("safeReturnTo: a clean relative path is kept verbatim", safeReturnTo("/dashboard/runs") === "/dashboard/runs");
    // raw[1] === "/" -> a protocol-relative URL ("//evil.example") a browser reads as a FOREIGN origin: rejected.
    ok("safeReturnTo: a protocol-relative //host is refused (falls back to /)", safeReturnTo("//evil.example/steal") === "/");
    // raw[1] === "\\" -> "/\\evil" which some browsers normalise to a backslash-host foreign origin: rejected.
    ok("safeReturnTo: a /\\backslash-host is refused (falls back to /)", safeReturnTo("/\\evil.example") === "/");
    // The per-character scan: a control char (here a tab, 0x09) anywhere is refused (header / redirect smuggling).
    ok("safeReturnTo: a control character in the path is refused", safeReturnTo("/ok\there") === "/");
    // A literal backslash mid-path (not just at index 1) is refused by the same per-character scan.
    ok("safeReturnTo: a mid-path backslash is refused", safeReturnTo("/ok\\here") === "/");
    // The non-string / empty / over-length and bad-first-char arms (defence in depth around the guard).
    ok("safeReturnTo: null and a non-/ first char both fall back to /", safeReturnTo(null) === "/" && safeReturnTo("https://evil.example") === "/");
  }

  // ---- the __Host- txn cookie readers: the per-part parse branches ----
  {
    // eq <= 0: a malformed part with no name before "=" ("=junk") is skipped, and a flag part with no "=" too.
    ok("readOidcTxnCookie: skips a nameless (=value) and a flagless part, finds the real cookie", readOidcTxnCookie(new Request("https://x/", { headers: { cookie: `=junk; flagonly; ${OIDC_TXN_COOKIE}=abc123` } })) === "abc123");
    // The name-mismatch continue: an unrelated cookie present, ours absent -> the loop runs to the end -> null.
    ok("readOidcTxnCookie: an unrelated cookie with ours absent yields null (loop falls through)", readOidcTxnCookie(new Request("https://x/", { headers: { cookie: "other=1; __Host-downpipes_session=zzz" } })) === null);
    // The empty-value arm: the cookie name matches but the value is "" -> null (not the empty string).
    ok("readOidcTxnCookie: a present-but-empty value reads as null", readOidcTxnCookie(new Request("https://x/", { headers: { cookie: `${OIDC_TXN_COOKIE}=` } })) === null);
    // No cookie header at all -> the early null.
    ok("readOidcTxnCookie: a request with no cookie header reads as null", readOidcTxnCookie(new Request("https://x/")) === null);
    // The SAML reader shares the identical shape; drive the same four arms so its branches are real, not copied.
    ok("readSamlTxnCookie: skips a nameless / flagless part, finds the real cookie", readSamlTxnCookie(new Request("https://x/", { headers: { cookie: `=junk; flagonly; ${SAML_TXN_COOKIE}=bind99` } })) === "bind99");
    ok("readSamlTxnCookie: an unrelated cookie with ours absent yields null", readSamlTxnCookie(new Request("https://x/", { headers: { cookie: "foo=bar" } })) === null);
    ok("readSamlTxnCookie: a present-but-empty value reads as null", readSamlTxnCookie(new Request("https://x/", { headers: { cookie: `${SAML_TXN_COOKIE}=` } })) === null);
    ok("readSamlTxnCookie: a request with no cookie header reads as null", readSamlTxnCookie(new Request("https://x/")) === null);
  }

  // ---- handleOidc: the no-oracle failure and DO-down branches ----
  {
    // providers with the DO down -> an EMPTY provider list (the sign-in screen shows no buttons), never a 500.
    const r = await handleOidc(new Request("https://x/admin/oidc/providers", { method: "GET" }), throwingEnv(), "providers");
    const body = (await r.json()) as { ok?: boolean; providers?: unknown[] };
    ok("handleOidc providers: a DO hiccup yields ok+empty providers, status 200 (no oracle, no 500)", r.status === 200 && body.ok === true && Array.isArray(body.providers) && body.providers.length === 0);
  }
  {
    // start with the DO down -> the generic fail redirect (no authorize URL, never a stack trace).
    const r = await handleOidc(new Request("https://x/admin/oidc/start/entra", { method: "GET" }), throwingEnv(), "start/entra");
    ok("handleOidc start: a DO-down catch -> generic 302 to ?oidc=failed", r.status === 302 && (r.headers.get("location") ?? "").includes("oidc=failed"));
  }
  {
    // callback with NO code -> refused as a generic failure, the txn cookie cleared (clearTxn=true), no oracle.
    const r = await handleOidc(new Request("https://x/admin/oidc/callback/entra?state=s", { method: "GET", headers: { cookie: `${OIDC_TXN_COOKIE}=t` } }), throwingEnv(), "callback/entra");
    ok("handleOidc callback: a missing code is a generic 302 and clears the txn cookie", r.status === 302 && (r.headers.get("location") ?? "").includes("oidc=failed") && getSetCookie(r).some((c) => c.includes(OIDC_TXN_COOKIE) && /Max-Age=0/i.test(c)));
  }
  {
    // callback with a missing state (code + txn present) -> same generic failure (the no-distinguish guard).
    const r = await handleOidc(new Request("https://x/admin/oidc/callback/entra?code=c", { method: "GET", headers: { cookie: `${OIDC_TXN_COOKIE}=t` } }), throwingEnv(), "callback/entra");
    ok("handleOidc callback: a missing state is the same generic 302 (no oracle for which check failed)", r.status === 302 && (r.headers.get("location") ?? "").includes("oidc=failed"));
  }
  {
    // callback that reaches the DO but the DO replies NOT ok (no token): a generic failure, no session minted.
    const r = await handleOidc(new Request("https://x/admin/oidc/callback/entra?code=c&state=s", { method: "GET", headers: { cookie: `${OIDC_TXN_COOKIE}=t`, "CF-Connecting-IP": "203.0.113.9" } }), fakeEnv(() => Promise.resolve(jsonResp({ ok: false }))), "callback/entra");
    ok("handleOidc callback: a not-ok DO reply -> generic 302, no session cookie", r.status === 302 && (r.headers.get("location") ?? "").includes("oidc=failed") && cookieValue(getSetCookie(r), "__Host-downpipes_session") === null);
  }
  {
    // callback that reaches the DO and the DO THROWS after the pre-checks pass: the inner catch (clearTxn=true).
    const r = await handleOidc(new Request("https://x/admin/oidc/callback/entra?code=c&state=s", { method: "GET", headers: { cookie: `${OIDC_TXN_COOKIE}=t` } }), throwingEnv(), "callback/entra");
    ok("handleOidc callback: a DO-throw after the pre-checks -> generic 302, txn cleared", r.status === 302 && (r.headers.get("location") ?? "").includes("oidc=failed") && getSetCookie(r).some((c) => c.includes(OIDC_TXN_COOKIE) && /Max-Age=0/i.test(c)));
  }
  {
    // The CF-Connecting-IP header IS present here so the sourceIp-forward arm fires: assert the edge forwarded it
    // in the DO request body (the body-forward audit pattern) AND minted the session the DO returned.
    let forwarded: { sourceIp?: string; code?: string } = {};
    const env2 = fakeEnv(async (req) => { forwarded = (await req.json()) as { sourceIp?: string; code?: string }; return jsonResp({ ok: true, token: "v3.session.token", returnTo: "/home" }); });
    const r = await handleOidc(new Request("https://x/admin/oidc/callback/entra?code=cc&state=ss", { method: "GET", headers: { cookie: `${OIDC_TXN_COOKIE}=t`, "CF-Connecting-IP": "198.51.100.7" } }), env2, "callback/entra");
    ok("handleOidc callback: the edge forwards the edge-read CF-Connecting-IP into the DO body", forwarded.sourceIp === "198.51.100.7" && forwarded.code === "cc");
    ok("handleOidc callback: an ok DO reply mints the session cookie + 302s to the safe returnTo", r.status === 302 && (r.headers.get("location") ?? "") === "/home" && (cookieValue(getSetCookie(r), "__Host-downpipes_session") ?? "") === "v3.session.token");
  }
  {
    // start that reaches the DO but the DO replies NOT ok (no authorizeUrl) -> the generic failure 302.
    const r = await handleOidc(new Request("https://x/admin/oidc/start/entra", { method: "GET" }), fakeEnv(() => Promise.resolve(jsonResp({ ok: true }))), "start/entra");
    ok("handleOidc start: a DO reply missing authorizeUrl -> generic 302 to ?oidc=failed", r.status === 302 && (r.headers.get("location") ?? "").includes("oidc=failed"));
  }
  {
    // An unknown /admin/oidc/<sub> (neither providers nor start/ nor callback/) -> the trailing 404.
    const r = await handleOidc(new Request("https://x/admin/oidc/bogus", { method: "GET" }), throwingEnv(), "bogus");
    ok("handleOidc: an unknown sub-route is a 404 (not a redirect, not a 500)", r.status === 404);
    // A missing CONSOLE_ORIGIN (the env var literally absent) makes the origin "" (the typeof guard fails
    // closed), so the failure redirect is origin-relative. The env is built inline with NO CONSOLE_ORIGIN key
    // at all: passing undefined into fakeEnv/throwingEnv would re-trigger their default parameter and mask it.
    const noOriginStub = { fetch: (): Promise<Response> => { throw new Error("DO unreachable"); } } as unknown as DurableObjectStub;
    const noOriginEnv = { SCHEDULER: { idFromName: (_n: string) => ({}) as unknown as DurableObjectId, get: (_id: DurableObjectId) => noOriginStub } as unknown as DurableObjectNamespace } as unknown as Env;
    const r2 = await handleOidc(new Request("https://x/admin/oidc/start/entra", { method: "GET" }), noOriginEnv, "start/entra");
    ok("handleOidc: a missing CONSOLE_ORIGIN degrades to an origin-relative fail redirect", r2.status === 302 && (r2.headers.get("location") ?? "").startsWith("/?oidc=failed"));
  }

  // ---- handleSaml: metadata / start / acs failure and DO-down branches ----
  {
    // metadata when the DO replies not-ok (no metadata) -> 404 not found (the connection is unknown).
    const r = await handleSaml(new Request("https://x/admin/saml/metadata/work-idp", { method: "GET" }), fakeEnv(() => Promise.resolve(jsonResp({ ok: false }))), "metadata/work-idp");
    ok("handleSaml metadata: a not-ok DO reply -> 404", r.status === 404);
    // metadata when the DO is down -> 503 (the catch), distinct from the 404 not-found.
    const r2 = await handleSaml(new Request("https://x/admin/saml/metadata/work-idp", { method: "GET" }), throwingEnv(), "metadata/work-idp");
    ok("handleSaml metadata: a DO-down catch -> 503 metadata unavailable", r2.status === 503);
    // metadata happy path: the DO returns XML -> 200 with the SAML metadata content type.
    const r3 = await handleSaml(new Request("https://x/admin/saml/metadata/work-idp", { method: "GET" }), fakeEnv(() => Promise.resolve(jsonResp({ ok: true, metadata: "<EntityDescriptor/>" }))), "metadata/work-idp");
    ok("handleSaml metadata: an ok DO reply -> 200 application/samlmetadata+xml", r3.status === 200 && (r3.headers.get("content-type") ?? "").includes("application/samlmetadata+xml") && (await r3.text()) === "<EntityDescriptor/>");
  }
  {
    // start when the DO is down -> the generic fail redirect (no IdP SSO URL leaked).
    const r = await handleSaml(new Request("https://x/admin/saml/start/work-idp", { method: "GET" }), throwingEnv(), "start/work-idp");
    ok("handleSaml start: a DO-down catch -> generic 302 to ?oidc=failed", r.status === 302 && (r.headers.get("location") ?? "").includes("oidc=failed"));
    // start when the DO replies not-ok (no redirectUrl / browserBind) -> the same generic failure.
    const r2 = await handleSaml(new Request("https://x/admin/saml/start/work-idp", { method: "GET" }), fakeEnv(() => Promise.resolve(jsonResp({ ok: true }))), "start/work-idp");
    ok("handleSaml start: a DO reply missing redirectUrl/browserBind -> generic 302", r2.status === 302 && (r2.headers.get("location") ?? "").includes("oidc=failed"));
  }
  {
    // acs with a body that has neither SAMLResponse nor RelayState (the ?? "" arms + the length-0 guard).
    const r = await handleSaml(new Request("https://x/admin/saml/acs/work-idp", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "foo=bar" }), throwingEnv(), "acs/work-idp");
    ok("handleSaml acs: a body with no SAMLResponse/RelayState -> generic 302 (no DO call)", r.status === 302 && (r.headers.get("location") ?? "").includes("oidc=failed") && !getSetCookie(r).some((c) => c.includes("__Host-downpipes_session")));
    // acs where reading the body itself FAILS (a truncated / broken POST stream): the await req.text() catch ->
    // a generic 302, never an unhandled rejection. A bespoke request-like double whose text() rejects drives it;
    // handleSaml only touches method, text(), headers.get, so the double covers exactly what the edge reads.
    const brokenReq = { method: "POST", url: "https://x/admin/saml/acs/work-idp", headers: new Headers({ "content-type": "application/x-www-form-urlencoded" }), text: (): Promise<string> => Promise.reject(new Error("stream truncated")) } as unknown as Request;
    const rBroken = await handleSaml(brokenReq, throwingEnv(), "acs/work-idp");
    ok("handleSaml acs: a body-read failure (broken POST stream) -> generic 302, no crash", rBroken.status === 302 && (rBroken.headers.get("location") ?? "").includes("oidc=failed"));
    // acs that reaches the DO but the DO replies not-ok (no token) -> generic 302, no session.
    const r2 = await handleSaml(new Request("https://x/admin/saml/acs/work-idp", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", cookie: `${SAML_TXN_COOKIE}=bind` }, body: "SAMLResponse=PHNhbWw%2B&RelayState=rs" }), fakeEnv(() => Promise.resolve(jsonResp({ ok: false }))), "acs/work-idp");
    ok("handleSaml acs: a not-ok DO reply -> generic 302, no session cookie", r2.status === 302 && (r2.headers.get("location") ?? "").includes("oidc=failed") && cookieValue(getSetCookie(r2), "__Host-downpipes_session") === null);
    // acs that reaches the DO and the DO THROWS -> the inner catch (generic 302).
    const r3 = await handleSaml(new Request("https://x/admin/saml/acs/work-idp", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", cookie: `${SAML_TXN_COOKIE}=bind` }, body: "SAMLResponse=PHNhbWw%2B&RelayState=rs" }), throwingEnv(), "acs/work-idp");
    ok("handleSaml acs: a DO-throw after parse -> generic 302", r3.status === 302 && (r3.headers.get("location") ?? "").includes("oidc=failed"));
  }
  {
    // acs happy path WITH a CF-Connecting-IP header so the sourceIp-forward arm fires: assert the edge forwarded
    // the edge-read IP and the browser-binding cookie into the DO body, minted the session and cleared the txn.
    let body: { sourceIp?: string; browserBind?: string; samlResponse?: string } = {};
    const env2 = fakeEnv(async (req) => { body = (await req.json()) as typeof body; return jsonResp({ ok: true, token: "saml.v3.token", returnTo: "/secure" }); });
    const r = await handleSaml(new Request("https://x/admin/saml/acs/work-idp", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", cookie: `${SAML_TXN_COOKIE}=bind77`, "CF-Connecting-IP": "192.0.2.44" }, body: "SAMLResponse=PHNhbWw%2B&RelayState=rs" }), env2, "acs/work-idp");
    // URLSearchParams turns the form-encoded %2B back into the base64 "+"; the edge forwards that RAW base64
    // verbatim (it never base64-decodes the assertion - the DO does), so PHNhbWw%2B arrives as "PHNhbWw+".
    ok("handleSaml acs: the edge forwards the CF-Connecting-IP, browser-bind cookie and raw base64 into the DO body", body.sourceIp === "192.0.2.44" && body.browserBind === "bind77" && body.samlResponse === "PHNhbWw+");
    ok("handleSaml acs: an ok DO reply mints the session, clears the txn cookie, 302s to the safe returnTo", r.status === 302 && (r.headers.get("location") ?? "") === "/secure" && (cookieValue(getSetCookie(r), "__Host-downpipes_session") ?? "") === "saml.v3.token" && getSetCookie(r).some((c) => c.includes(SAML_TXN_COOKIE) && /Max-Age=0/i.test(c)));
  }
  {
    // An unknown /admin/saml/<sub> (none of metadata/start/acs) -> the trailing 404.
    const r = await handleSaml(new Request("https://x/admin/saml/bogus", { method: "GET" }), throwingEnv(), "bogus");
    ok("handleSaml: an unknown sub-route is a 404", r.status === 404);
    // A non-string CONSOLE_ORIGIN: the metadata acsUrl is built off "" but the route still answers (404 here as
    // the DO is down -> wait, this drives the missing-config arm at the top of handleSaml, then the catch -> 503).
    const r2 = await handleSaml(new Request("https://x/admin/saml/metadata/work-idp", { method: "GET" }), throwingEnv(123), "metadata/work-idp");
    ok("handleSaml: a non-string CONSOLE_ORIGIN still resolves the route (503 here as the DO is down)", r2.status === 503);
  }
} finally {
  globalThis.fetch = realFetch;
}

if (failures > 0) process.exitCode = 1;
if (failures === 0) console.log("\nNATIVE OIDC WIRING VECTORS PASS");
else {
  console.log(`\n${failures} FAILURE(S)`);
  process.exitCode = 1;
}
