// validate-cov-sched-scheduler-do-idp: branch-coverage proof for the native external-IdP mixin
// (src/sched/scheduler-do-idp.ts) - the OIDC storage adapter, the revocation axes, the v3 session mint,
// and the OIDC / OAuth2 / SAML route handlers. It drives the REAL SchedulerDO through its production
// routeIdp dispatch (router-bypassed direct DO fetch with a method:"token" break-glass caller, which
// resolves to owner without a table lookup) and through handleAdmin for the session-validation reads, plus
// a handful of defence-in-depth method calls. Every assertion checks a real outcome: an {ok} body, a stored
// effect (idpEpoch / observed-expiry rows), a minted session token, or a revoked-session 401.
//
// The OIDC IdP (token + JWKS), the OAuth2 (GitHub-class) endpoints and the JWKS are served by a stubbed
// global fetch (the only network); the SAML assertion is a REAL enveloped XML-DSig signed under a pinned
// self-signed cert, built with the shared SAML fixtures, so the DO runs its genuine verify pipeline.
//
// Run: node test/validate-cov-sched-scheduler-do-idp.ts

import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { SSO_FAIL_CODES } from "../src/admin/sso-failure-class.ts";
import { encodeCaller, roleSubjectKey, CALLER_HEADER, type Caller } from "../src/admin/identity.ts";
import type { Env } from "../src/env.d.ts";
import type { XmlElement } from "../src/admin/saml/xml-node.ts";
import {
  el, a, t, signAssertion, buildSelfSignedCertPem, encodeResponse, buildAssertion, buildResponse,
  IDP_ENTITY, SP_ENTITY, ACS_URL, CONN_ID as SAML_CONN, NAMEID_PERSISTENT,
} from "./saml-response-fixtures.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

// ---- OIDC IdP fixtures (a real RS256 id_token verified against a controlled JWKS the stub serves) ----
const ISSUER = "https://oidc.example.com";
const AUTH_URL = `${ISSUER}/authorize`;
const TOKEN_URL = `${ISSUER}/token`;
const JWKS_URL = `${ISSUER}/jwks`;
const CLIENT = "client-abc";
const OIDC_SUB = "user-1";
const OIDC_EMAIL = "oidc-user@acme.example";
const OIDC_REDIRECT = "https://console.downpipes.io/admin/oidc/callback/entra";
// OAuth2 (GitHub-class) fixtures (an opaque token, then userinfo: immutable numeric id, email, team/org).
const GH_AUTH = "https://github.example/login/oauth/authorize";
const GH_TOKEN = "https://github.example/login/oauth/access_token";
const GH_API = "https://api.github.example";
const GH_ID = 583231;
const GH_EMAIL = "octo@github.example";
const GH_REDIRECT = "https://console.downpipes.io/admin/oidc/callback/github";
// Entra MULTITENANT fixtures: a {tenantid} issuer template with issuerSubstitution 'tid' + an acceptedTenantIds
// allowlist. The token endpoint returns an id_token whose tid is NOT in the allowlist, so verifyIdToken returns
// the tenant_not_accepted code (oidc-entra-multitenant-misconfig) rather than a coarse "issuer" failure.
const MT_ISSUER_TEMPLATE = "https://login.microsoftonline.com/{tenantid}/v2.0";
const MT_AUTH = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
const MT_TOKEN = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
const MT_CLIENT = "mt-client-abc";
const MT_ACCEPTED_TID = "11111111-1111-1111-1111-111111111111";
const MT_BAD_TID = "99999999-9999-9999-9999-999999999999";
// SAML fixtures reuse the shared constants so the assertion Issuer / Audience / Recipient line up.
const SAML_EMAIL = "saml-user@acme.example";
const IDP_SSO_URL = "https://idp.example.com/sso";

function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlJSON(o: unknown): string {
  return b64url(new TextEncoder().encode(JSON.stringify(o)));
}
const isoAt = (ms: number): string => new Date(ms).toISOString();

async function main(): Promise<void> {
  // ---- build the real DO over MockStorage; expose the env (for handleAdmin) + the raw instance. ----
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
  const env = { SCHEDULER: namespace, CONSOLE_ORIGIN: "https://console.downpipes.io", ADMIN_TOKEN: "bg-token-idpcov" } as unknown as Env;

  // Seed a bound founder Owner so sign-ins resolve to their real (default) role, never a bootstrap claim.
  await storage.put(roleSubjectKey("passkey|founder@acme.example"), { subject: "passkey|founder@acme.example", email: "founder@acme.example", role: "owner", grantedBy: "system", grantedAt: "2026-06-13T00:00:00.000Z" });

  // ---- the owner caller for the gated connection-management ops (token break-glass -> owner-token). ----
  const owner: Caller = { method: "token", email: "founder@acme.example", subject: null, role: "owner", groups: [] };
  const viewer: Caller = { method: "access", email: "viewer@acme.example", subject: `${ISSUER}|viewer`, role: "viewer", groups: [] };

  // ---- the SAML pinned signing key + its self-signed cert (the trust root the SP pins). ----
  const samlKp = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const samlSpki = new Uint8Array(await crypto.subtle.exportKey("spki", samlKp.publicKey));
  const samlCert = await buildSelfSignedCertPem(samlSpki, samlKp.privateKey, "idp.example");

  // ---- the OIDC id_token signing key + JWKS; the stub serves the token + JWKS endpoints. ----
  const oidcKp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const oidcPub = (await crypto.subtle.exportKey("jwk", oidcKp.publicKey)) as { n: string; e: string };
  const jwks = { keys: [{ kid: "rsa-1", kty: "RSA", n: oidcPub.n, e: oidcPub.e, alg: "RS256" }] };
  let currentNonce = "";
  let currentEmailVerified = true;
  async function signIdToken(payload: Record<string, unknown>): Promise<string> {
    const head = b64urlJSON({ alg: "RS256", kid: "rsa-1", typ: "JWT" });
    const body = b64urlJSON(payload);
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", oidcKp.privateKey, new TextEncoder().encode(`${head}.${body}`)));
    return `${head}.${body}.${b64url(sig)}`;
  }
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const now = Math.floor(Date.now() / 1000);
    if (url === JWKS_URL) return new Response(JSON.stringify(jwks), { headers: { "content-type": "application/json" } });
    if (url === TOKEN_URL) {
      const idToken = await signIdToken({ iss: ISSUER, sub: OIDC_SUB, aud: CLIENT, nonce: currentNonce, exp: now + 300, iat: now, email: OIDC_EMAIL, email_verified: currentEmailVerified, roles: ["admins"] });
      return new Response(JSON.stringify({ id_token: idToken, access_token: "at", token_type: "Bearer" }), { headers: { "content-type": "application/json" } });
    }
    if (url === MT_TOKEN) {
      // A multitenant token whose tid is NOT in acceptedTenantIds: verifyIdToken -> tenant_not_accepted.
      const idToken = await signIdToken({ iss: `https://login.microsoftonline.com/${MT_BAD_TID}/v2.0`, sub: "mt-user", aud: MT_CLIENT, nonce: currentNonce, exp: now + 300, iat: now, email: "mt-user@acme.example", email_verified: true, tid: MT_BAD_TID });
      return new Response(JSON.stringify({ id_token: idToken, access_token: "at", token_type: "Bearer" }), { headers: { "content-type": "application/json" } });
    }
    if (url === GH_TOKEN) return new Response(JSON.stringify({ access_token: "gho_opaque", token_type: "bearer" }), { headers: { "content-type": "application/json" } });
    if (url === `${GH_API}/user`) return new Response(JSON.stringify({ id: GH_ID, login: "octocat", name: "The Octocat" }), { headers: { "content-type": "application/json" } });
    if (url === `${GH_API}/user/emails`) return new Response(JSON.stringify([{ email: GH_EMAIL, primary: true, verified: true }]), { headers: { "content-type": "application/json" } });
    if (url === `${GH_API}/user/teams`) return new Response(JSON.stringify([{ slug: "engineers", organization: { login: "acme" } }]), { headers: { "content-type": "application/json" } });
    if (url === `${GH_API}/user/orgs`) return new Response(JSON.stringify([{ login: "acme" }]), { headers: { "content-type": "application/json" } });
    throw new Error(`unexpected fetch in test: ${url}`);
  }) as typeof fetch;

  // ---- drive helpers: direct DO route (routeIdp), and a whoami over a session cookie. ----
  async function doReq(method: "GET" | "POST", path: string, body?: unknown, caller?: Caller): Promise<Response> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers["content-type"] = "application/json";
    if (caller !== undefined) headers[CALLER_HEADER] = encodeCaller(caller);
    return dobj.fetch(new Request(`https://scheduler.internal${path}`, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) }));
  }
  async function doJson(method: "GET" | "POST", path: string, body?: unknown, caller?: Caller): Promise<Record<string, unknown>> {
    return (await (await doReq(method, path, body, caller)).json()) as Record<string, unknown>;
  }
  async function whoami(token: string): Promise<Response> {
    return handleAdmin(new Request("https://console.downpipes.io/admin/whoami", { method: "GET", headers: { cookie: `__Host-downpipes_session=${token}` } }), env);
  }

  // a samlp:Response carrying ONE real enveloped-signed assertion, bound to requestId, in a window around now.
  async function buildSamlResp(opts: { requestId: string; assertionId: string; withSession?: boolean }): Promise<string> {
    const nowMs = Date.now();
    const assertion: XmlElement = buildAssertion({
      inResponseTo: opts.requestId, recipient: ACS_URL, audience: SP_ENTITY, email: SAML_EMAIL, nameId: SAML_EMAIL,
      assertionId: opts.assertionId, notBefore: isoAt(nowMs - 5 * 60_000), notOnOrAfter: isoAt(nowMs + 10 * 60_000), scdNotOnOrAfter: isoAt(nowMs + 10 * 60_000),
    });
    if (opts.withSession === true) {
      const authn = el("saml:AuthnStatement", [a("AuthnInstant", isoAt(nowMs - 60_000)), a("SessionNotOnOrAfter", isoAt(nowMs + 30 * 60_000))], [el("saml:AuthnContext", [], [el("saml:AuthnContextClassRef", [], [t("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")])])]);
      assertion.children.splice(3, 0, authn);
    }
    const signed = await signAssertion(assertion, opts.assertionId, samlKp.privateKey);
    return encodeResponse(buildResponse([signed], { destination: ACS_URL, inResponseTo: opts.requestId }));
  }

  // OIDC + OAuth2 + SAML connection proposals.
  const oidcProposal = { id: "entra", kind: "oidc", label: "Microsoft Entra ID", presetId: "entra", enabled: true, issuer: ISSUER, clientId: CLIENT, secretRef: { mode: "do-plaintext" }, scopes: ["openid", "email", "profile"], idTokenSigAlgs: ["RS256"], pkce: "required", clientAuth: "client_secret_post", requireNonce: true, rolesClaim: "roles", authorizationEndpoint: AUTH_URL, tokenEndpoint: TOKEN_URL, jwksUri: JWKS_URL };
  const ghProposal = { id: "github", kind: "oauth2", label: "GitHub", presetId: "github", enabled: true, authorizeUrl: GH_AUTH, tokenUrl: GH_TOKEN, tokenAuthStyle: "post_json", clientId: "gh-client", secretRef: { mode: "do-plaintext" }, scopes: ["read:user", "user:email", "read:org"], apiBase: GH_API, profileUrl: `${GH_API}/user`, subjectPath: "id", subjectPrefix: "github", emailUrl: `${GH_API}/user/emails`, groupsUrls: [`${GH_API}/user/teams`, `${GH_API}/user/orgs`], pkce: "none" };
  const samlProposal = { id: SAML_CONN, kind: "saml", label: "Work IdP", presetId: "generic-saml", enabled: true, idpEntityId: IDP_ENTITY, idpSsoUrl: IDP_SSO_URL, idpSigningCerts: [samlCert], spEntityId: SP_ENTITY, nameIdFormat: NAMEID_PERSISTENT, wantAssertionsSigned: true, allowIdpInitiated: false, clockSkewSec: 120, emailVerifiedPolicy: "trust-idp", emailAttr: "email", groupsAttr: "groups", secretExpiresAt: undefined };

  try {
    // ============================================================================================
    // SECTION A - OIDC connection: create (proposal), providers, list, presets, start, callback,
    //   session validation (getIdpEpoch / getSessionEpochSub), logout + disable revocation axes.
    // ============================================================================================
    {
      const cr = await doJson("POST", "/idp/conn/create", { proposal: oidcProposal, secret: "super-secret" }, owner);
      ok("oidc create: ok + redacted secretRef (mode only, no value)", cr.ok === true && (cr.conn as { secretRef?: { mode?: string; value?: unknown } }).secretRef?.mode === "do-plaintext" && !("value" in ((cr.conn as { secretRef?: object }).secretRef ?? {})));
      ok("oidc create: do-plaintext secret stored write-only under idpsecret:<id>", (await storage.get<string>("idpsecret:entra")) === "super-secret");

      const provs = await doJson("GET", "/idp/providers");
      ok("idpProviders: the enabled connection is exposed with no internal config", (provs.providers as Array<{ id?: string; issuer?: unknown }>).some((p) => p.id === "entra" && !("issuer" in p)));

      const list = await doJson("GET", "/idp/conn/list", undefined, owner);
      ok("idpConnList: the connection appears, redacted", (list.connections as Array<{ id?: string }>).some((c) => c.id === "entra"));
      const presets = await doJson("GET", "/idp/presets", undefined, owner);
      ok("idpPresets: the display catalogue is returned, no secrets", Array.isArray(presets.presets) && !JSON.stringify(presets.presets).includes("secretRef"));

      // start -> {authorizeUrl, state, txnId}; read the nonce the IdP must echo out of the authorize URL.
      const start = await doJson("POST", "/idp/oidc/start", { connId: "entra", redirectUri: OIDC_REDIRECT, returnTo: "/dash" });
      ok("idpOidcStart (oidc): mints state + txnId + an authorize URL", start.ok === true && typeof start.state === "string" && typeof start.txnId === "string" && String(start.authorizeUrl).startsWith(AUTH_URL));
      currentNonce = new URL(String(start.authorizeUrl)).searchParams.get("nonce") ?? "";

      // callback (verified email): real exchange + verify in the DO -> a v3 oidc session token.
      currentEmailVerified = true;
      const cb = await doJson("POST", "/idp/oidc/callback", { connId: "entra", code: "the-code", state: start.state, txnId: start.txnId, iss: ISSUER, sourceIp: "198.51.100.7" });
      ok("idpOidcCallback (oidc, verified): mints a session token", cb.ok === true && typeof cb.token === "string" && (cb.token as string).length > 0);
      const token1 = cb.token as string;

      // whoami over the cookie validates the session (resolvePrincipal reads getSessionEpochSub + getIdpEpoch).
      const w1 = await whoami(token1);
      const w1b = (await w1.json()) as { method?: string; connId?: string };
      ok("whoami (oidc cookie): 200, method oidc, connId entra (session-validation axes read)", w1.status === 200 && w1b.method === "oidc" && w1b.connId === "entra");

      // logout bumps the per-subject revocation axis (bumpSessionEpochSub) -> the cookie is dead next request.
      const lo = await doJson("POST", "/passkey/session/logout", { token: token1, sourceIp: "198.51.100.7" });
      ok("logout: ok (best-effort server-side revoke)", lo.ok === true);
      ok("logout: the oidc cookie is revoked on the next request (sessionEpochSub axis)", (await whoami(token1)).status === 401);

      // a fresh sign-in, then DISABLE the connection: the per-connection idpEpoch kills the live session.
      const s2 = await doJson("POST", "/idp/oidc/start", { connId: "entra", redirectUri: OIDC_REDIRECT, returnTo: "/" });
      currentNonce = new URL(String(s2.authorizeUrl)).searchParams.get("nonce") ?? "";
      const cb2 = await doJson("POST", "/idp/oidc/callback", { connId: "entra", code: "c2", state: s2.state, txnId: s2.txnId, iss: ISSUER });
      const token2 = cb2.token as string;
      ok("idpOidcCallback (oidc, no sourceIp): still mints a session", cb2.ok === true && token2.length > 0);
      const dis = await doJson("POST", "/idp/conn/enabled", { connId: "entra", enabled: false }, owner);
      ok("idpConnSetEnabled (disable): ok", dis.ok === true);
      ok("disable: idpEpoch:<id> stamped (bumpIdpEpoch)", typeof (await storage.get<number>("idpEpoch:entra")) === "number" && (await storage.get<number>("idpEpoch:entra"))! > 0);
      ok("disable: the live oidc cookie is now rejected (idpEpoch revocation axis)", (await whoami(token2)).status === 401);
      const ena = await doJson("POST", "/idp/conn/enabled", { connId: "entra", enabled: true }, owner);
      ok("idpConnSetEnabled (re-enable): ok", ena.ok === true);

      // unverified email: the email_verified bind gate is skipped, but a session still mints (authenticated).
      const s3 = await doJson("POST", "/idp/oidc/start", { connId: "entra", redirectUri: OIDC_REDIRECT, returnTo: "/" });
      currentNonce = new URL(String(s3.authorizeUrl)).searchParams.get("nonce") ?? "";
      currentEmailVerified = false;
      const cb3 = await doJson("POST", "/idp/oidc/callback", { connId: "entra", code: "c3", state: s3.state, txnId: s3.txnId, iss: ISSUER });
      ok("idpOidcCallback (unverified email): still mints a session (bind gate skipped)", cb3.ok === true && typeof cb3.token === "string");
      currentEmailVerified = true;

      // a callback whose state does not resolve -> handleOidcCallback fails -> a clean not-ok (no mint).
      const cbBad = await doJson("POST", "/idp/oidc/callback", { connId: "entra", code: "x", state: "bogus", txnId: "bogus", iss: ISSUER });
      ok("idpOidcCallback: an unresolvable state is a clean refusal (no session)", cbBad.ok === false && !("token" in cbBad));
    }

    // ============================================================================================
    // SECTION B - OAuth2 (GitHub-class, no id_token): create, start (no nonce), callback (userinfo).
    // ============================================================================================
    {
      const cr = await doJson("POST", "/idp/conn/create", { proposal: ghProposal, secret: "gh-secret" }, owner);
      ok("oauth2 create: ok", cr.ok === true && (cr.conn as { kind?: string }).kind === "oauth2");
      const start = await doJson("POST", "/idp/oidc/start", { connId: "github", redirectUri: GH_REDIRECT, returnTo: "/" });
      ok("idpOidcStart (oauth2): a github authorize URL + state, NO nonce", start.ok === true && String(start.authorizeUrl).startsWith(GH_AUTH) && new URL(String(start.authorizeUrl)).searchParams.get("nonce") === null);
      const cb = await doJson("POST", "/idp/oidc/callback", { connId: "github", code: "ghcode", state: start.state, txnId: start.txnId, sourceIp: "203.0.113.9" });
      ok("idpOidcCallback (oauth2): mints a session from userinfo (no id_token)", cb.ok === true && typeof cb.token === "string" && (cb.token as string).length > 0);
    }

    // ============================================================================================
    // SECTION C - SAML: create (cert-expiry observed), metadata, start, ACS happy + the negatives.
    // ============================================================================================
    {
      const cr = await doJson("POST", "/idp/conn/create", { proposal: samlProposal }, owner);
      ok("saml create: ok + kind saml", cr.ok === true && (cr.conn as { kind?: string }).kind === "saml");
      const obs = await storage.get<{ kind?: string; source?: string }>(`expiry:idp-cert-${SAML_CONN}`);
      ok("saml create: the signing-cert expiry row is auto-observed (kind certificate)", obs !== undefined && obs.kind === "certificate" && obs.source === "observed");

      // metadata: the SP EntityDescriptor (public, carries our ACS URL).
      const meta = await doJson("POST", "/idp/saml/metadata", { connId: SAML_CONN, acsUrl: ACS_URL });
      ok("idpSamlMetadata: returns the SP metadata carrying our ACS URL", meta.ok === true && String(meta.metadata).includes(`Location="${ACS_URL}"`));

      // start (mints the single-use request record); read relayState off the redirect, requestId off the store.
      async function samlStart(): Promise<{ relayState: string; requestId: string; browserBind: string }> {
        const s = await doJson("POST", "/idp/saml/start", { connId: SAML_CONN, returnTo: "/dash", acsUrl: ACS_URL });
        const relayState = new URL(String(s.redirectUrl)).searchParams.get("RelayState") ?? "";
        const rec = await storage.get<{ requestId: string }>(`samlreq:${relayState}`);
        return { relayState, requestId: rec?.requestId ?? "", browserBind: String(s.browserBind) };
      }

      // happy ACS: a real signed assertion -> a v3 saml session + the assertion-replay cache entry.
      const h = await samlStart();
      const acs = await doJson("POST", "/idp/saml/acs", { connId: SAML_CONN, samlResponse: await buildSamlResp({ requestId: h.requestId, assertionId: "_a_happy" }), relayState: h.relayState, acsUrl: ACS_URL, browserBind: h.browserBind, sourceIp: "192.0.2.44" });
      ok("idpSamlAcs (happy): mints a saml session, returnTo /dash", acs.ok === true && typeof acs.token === "string" && (acs.token as string).length > 0 && acs.returnTo === "/dash");
      ok("idpSamlAcs (happy): the assertion-replay cache recorded the assertion id", typeof (await storage.get<number>(`seenassertion:${SAML_CONN}:_a_happy`)) === "number");

      // happy ACS WITH a SessionNotOnOrAfter so nativeSessionIssue caps exp at the IdP session bound (idpExp).
      const hs = await samlStart();
      const acsSess = await doJson("POST", "/idp/saml/acs", { connId: SAML_CONN, samlResponse: await buildSamlResp({ requestId: hs.requestId, assertionId: "_a_sess", withSession: true }), relayState: hs.relayState, acsUrl: ACS_URL, browserBind: hs.browserBind });
      ok("idpSamlAcs (with AuthnStatement SessionNotOnOrAfter): mints a session capped at the IdP bound", acsSess.ok === true && typeof acsSess.token === "string");

      // assertion replay: a FRESH request, but the response reuses an already-consumed assertion id.
      const hr = await samlStart();
      const replay = await doJson("POST", "/idp/saml/acs", { connId: SAML_CONN, samlResponse: await buildSamlResp({ requestId: hr.requestId, assertionId: "_a_happy" }), relayState: hr.relayState, acsUrl: ACS_URL, browserBind: hr.browserBind });
      ok("idpSamlAcs: re-using a consumed assertion id within its window is refused (replay)", replay.ok === false && String(replay.reason).includes("replay"));

      // verify failure: a valid record + browser bind, but a malformed SAMLResponse.
      const hv = await samlStart();
      const bad = await doJson("POST", "/idp/saml/acs", { connId: SAML_CONN, samlResponse: "not-a-valid-saml-response", relayState: hv.relayState, acsUrl: ACS_URL, browserBind: hv.browserBind });
      ok("idpSamlAcs: a malformed SAMLResponse fails the verify pipeline (no session)", bad.ok === false && !("token" in bad));

      // browser-binding mismatch (forced-login): the right record, the wrong cookie value.
      const hb = await samlStart();
      const wrongBind = await doJson("POST", "/idp/saml/acs", { connId: SAML_CONN, samlResponse: "x", relayState: hb.relayState, acsUrl: ACS_URL, browserBind: "wrong-bind" });
      ok("idpSamlAcs: a browser-binding mismatch is refused (forced-login defence)", wrongBind.ok === false && String(wrongBind.reason).includes("binding"));

      // RelayState connId mismatch: a work-idp record, but the ACS connId is a different valid id.
      const hm = await samlStart();
      const mismatch = await doJson("POST", "/idp/saml/acs", { connId: "other-conn", samlResponse: "x", relayState: hm.relayState, acsUrl: ACS_URL, browserBind: hm.browserBind });
      ok("idpSamlAcs: a RelayState whose connId differs from the ACS connId is refused", mismatch.ok === false && String(mismatch.reason).includes("connId"));

      // unknown / never-minted RelayState (replay / IdP-initiated): no record -> refused.
      const noRec = await doJson("POST", "/idp/saml/acs", { connId: SAML_CONN, samlResponse: "x", relayState: "never-minted-relaystate", acsUrl: ACS_URL, browserBind: "b" });
      ok("idpSamlAcs: a RelayState the SP never minted is refused (SP-initiated only)", noRec.ok === false);

      // invalid connId at the ACS.
      const badConn = await doJson("POST", "/idp/saml/acs", { connId: "BAD!!", samlResponse: "x", relayState: "r", acsUrl: ACS_URL, browserBind: "b" });
      ok("idpSamlAcs: an invalid connId is refused", badConn.ok === false && String(badConn.reason).includes("connId"));

      // DISABLED connection: a valid record minted while enabled, then disabled -> the ACS refuses.
      const hd = await samlStart();
      await doJson("POST", "/idp/conn/enabled", { connId: SAML_CONN, enabled: false }, owner);
      const disabledAcs = await doJson("POST", "/idp/saml/acs", { connId: SAML_CONN, samlResponse: "x", relayState: hd.relayState, acsUrl: ACS_URL, browserBind: hd.browserBind });
      ok("idpSamlAcs: a disabled connection refuses the ACS", disabledAcs.ok === false && String(disabledAcs.reason).includes("disabled"));
      const startDisabled = await doJson("POST", "/idp/saml/start", { connId: SAML_CONN, returnTo: "/", acsUrl: ACS_URL });
      ok("idpSamlStart: a disabled connection refuses /start", startDisabled.ok === false && String(startDisabled.reason).includes("disabled"));
      await doJson("POST", "/idp/conn/enabled", { connId: SAML_CONN, enabled: true }, owner);
    }

    // ============================================================================================
    // SECTION D - SAML signing-cert rollover (idpConnSamlCertUpdate): append, replace, refusals.
    // ============================================================================================
    {
      const kp2 = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
      const spki2 = new Uint8Array(await crypto.subtle.exportKey("spki", kp2.publicKey));
      const certB = await buildSelfSignedCertPem(spki2, kp2.privateKey, "idp.example.next");

      const epochBefore = await storage.get<number>(`idpEpoch:${SAML_CONN}`);
      const ap = await doJson("POST", "/idp/conn/cert", { connId: SAML_CONN, addCerts: [certB] }, owner);
      ok("cert rollover (append): ok + the redacted connection returned", ap.ok === true && (ap.conn as { kind?: string }).kind === "saml");
      const recAp = await storage.get<{ idpSigningCerts?: string[] }>(`idpconn:${SAML_CONN}`);
      ok("cert rollover (append): the stored set now holds BOTH certs (overlap)", (recAp?.idpSigningCerts ?? []).length === 2);
      ok("cert rollover (append): the idpEpoch was NOT bumped (zero-downtime)", (await storage.get<number>(`idpEpoch:${SAML_CONN}`)) === epochBefore);

      const rp = await doJson("POST", "/idp/conn/cert", { connId: SAML_CONN, certs: [certB] }, owner);
      ok("cert rollover (replace): ok", rp.ok === true);
      const recRp = await storage.get<{ idpSigningCerts?: string[] }>(`idpconn:${SAML_CONN}`);
      ok("cert rollover (replace): the stored set is exactly the one new cert", (recRp?.idpSigningCerts ?? []).length === 1);

      const noField = await doJson("POST", "/idp/conn/cert", { connId: SAML_CONN }, owner);
      ok("cert rollover: neither addCerts nor certs is refused", noField.ok === false);
      const notArr = await doJson("POST", "/idp/conn/cert", { connId: SAML_CONN, addCerts: "nope" }, owner);
      ok("cert rollover: a non-array addCerts is refused", notArr.ok === false && String(notArr.reason).includes("array"));
      const nonPem = await doJson("POST", "/idp/conn/cert", { connId: SAML_CONN, addCerts: ["not a cert"] }, owner);
      ok("cert rollover: a non-PEM cert is refused by the shared validator", nonPem.ok === false);
      const nonSaml = await doJson("POST", "/idp/conn/cert", { connId: "entra", addCerts: [certB] }, owner);
      ok("cert rollover: a non-SAML connection is refused (SAML-only)", nonSaml.ok === false && String(nonSaml.reason).includes("SAML"));
      const certBadConn = await doJson("POST", "/idp/conn/cert", { connId: "BAD!!", addCerts: [certB] }, owner);
      ok("cert rollover: an invalid connId is refused", certBadConn.ok === false && String(certBadConn.reason).includes("connId"));
      const certNoConn = await doJson("POST", "/idp/conn/cert", { connId: "no-such-conn", addCerts: [certB] }, owner);
      ok("cert rollover: an unknown connection is refused", certNoConn.ok === false && String(certNoConn.reason).includes("not found"));

      // ===== APPENDING A CERT ALREADY PINNED IS REFUSED, NOT SILENTLY COLLAPSED. =====
      //
      // (.) strArray de-duped, so [...pinned, samePinned]
      // collapsed to the pinned array, the identical set was written back and the DO answered ok:true. The
      // operator was told the rollover certificate was now trusted; nothing had changed, and the cutover
      // would fail at the IdP's switch, which is the one moment nobody can log in to fix it. Asserted on the
      // RETURNED REASON and on the STORED SET, because a collapse and a refusal both leave one cert behind
      // and only the answer tells them apart.
      const dupR = await doJson("POST", "/idp/conn/cert", { connId: SAML_CONN, addCerts: [certB] }, owner);
      ok("cert rollover: appending an ALREADY-PINNED certificate is REFUSED, not answered ok:true", dupR.ok === false);
      ok("cert rollover: the refusal says the same certificate appears twice", String(dupR.reason).includes("same signing certificate appears twice"));
      // The state after the refusal is the SAME single cert, so the refusal changed nothing either.
      const recDup = await storage.get<{ idpSigningCerts?: string[] }>(`idpconn:${SAML_CONN}`);
      ok("cert rollover: the refused duplicate append left the pinned set untouched (still one cert)", (recDup?.idpSigningCerts ?? []).length === 1);
      // POSITIVE CONTROL that must DISCRIMINATE: appending a genuinely DIFFERENT cert still succeeds and the
      // set grows to two. Without it, a validator that refused every append would pass the three above.
      const kp3 = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
      const certC = await buildSelfSignedCertPem(new Uint8Array(await crypto.subtle.exportKey("spki", kp3.publicKey)), kp3.privateKey, "idp.example.third");
      const freshR = await doJson("POST", "/idp/conn/cert", { connId: SAML_CONN, addCerts: [certC] }, owner);
      ok("cert rollover CONTROL: appending a DIFFERENT certificate still succeeds and the set grows to two", freshR.ok === true && ((await storage.get<{ idpSigningCerts?: string[] }>(`idpconn:${SAML_CONN}`))?.idpSigningCerts ?? []).length === 2);
    }

    // ============================================================================================
    // SECTION E - create edge branches: preset path (good / unknown / missing var / secretMode / clientAuth),
    //   and OIDC client-secret-expiry observe; delete (existing -> audit + observed cleanup, and absent).
    // ============================================================================================
    {
      // preset-built connection (the console flow): the engine owns the preset + builds the proposal.
      const good = await doJson("POST", "/idp/conn/create", { presetId: "keycloak", vars: { host: "sso.acme.example", realm: "employees" }, id: "kc1", label: "KC One", clientId: "kc-client", secret: "kc-secret" }, owner);
      ok("create (preset): a server-built connection validates + stores (issuer substituted)", good.ok === true && (good.conn as { issuer?: string }).issuer === "https://sso.acme.example/realms/employees");
      const unknown = await doJson("POST", "/idp/conn/create", { presetId: "no-such-preset", vars: {} }, owner);
      ok("create (preset): an unknown preset is a clean refusal", unknown.ok === false && String(unknown.reason).includes("unknown preset"));
      const missing = await doJson("POST", "/idp/conn/create", { presetId: "keycloak", vars: { host: "sso.acme.example" }, id: "kc2", clientId: "x", secret: "y" }, owner);
      ok("create (preset): a missing required var is refused", missing.ok === false && String(missing.reason).includes("required"));
      // a pkce-public preset connection (secretMode pkce-public, clientAuth pkce_public): no secret stored.
      const pub = await doJson("POST", "/idp/conn/create", { presetId: "keycloak", vars: { host: "sso2.acme.example", realm: "r2" }, id: "kc3", clientId: "kc3", secretMode: "pkce-public", clientAuth: "pkce_public" }, owner);
      ok("create (preset, pkce-public): stored with a pkce-public secretRef", pub.ok === true && (pub.conn as { secretRef?: { mode?: string } }).secretRef?.mode === "pkce-public");
      ok("create (preset, pkce-public): NO secret value stored", (await storage.get("idpsecret:kc3")) === undefined);
      // client_secret_basic auth variant (the third clientAuth arm).
      const basic = await doJson("POST", "/idp/conn/create", { presetId: "keycloak", vars: { host: "sso3.acme.example", realm: "r3" }, id: "kc4", clientId: "kc4", clientAuth: "client_secret_basic", secret: "kc4-secret" }, owner);
      ok("create (preset, client_secret_basic): stored", basic.ok === true);

      // ===== A PRESENT-BUT-WRONG-SHAPE FIELD IS REFUSED, NOT REPLACED BY THE PRESET DEFAULT. =====
      //
      // (.) Every one of these was a `typeof x === "string" ?
      // x : <default>` or a chained ternary, so a value of the wrong shape fell through to the preset's own.
      // {"label": 42} saved a connection called "Okta"; a clientAuth of "hmac" saved one authenticating with
      // client_secret_post -- an AUTH-ROOT setting the operator did not choose, which the console then showed
      // back to them as though it were theirs. Asserted on the RETURNED REASON, which names the field.
      const badLabel = await doJson("POST", "/idp/conn/create", { presetId: "okta", vars: { oktaDomain: "acme.okta.com", authServerId: "default" }, id: "ok-badlabel", label: 42, clientId: "c", secret: "s" }, owner);
      ok("create (preset): a NON-STRING label is refused, never replaced by the preset label", badLabel.ok === false && String(badLabel.reason).includes("label must be a string"));
      const badClientAuth = await doJson("POST", "/idp/conn/create", { presetId: "okta", vars: { oktaDomain: "acme.okta.com", authServerId: "default" }, id: "ok-badauth", clientId: "c", clientAuth: "hmac", secret: "s" }, owner);
      ok("create (preset): an UNKNOWN clientAuth is refused, never silently client_secret_post", badClientAuth.ok === false && String(badClientAuth.reason).includes("clientAuth must be"));
      const badSecretMode = await doJson("POST", "/idp/conn/create", { presetId: "okta", vars: { oktaDomain: "acme.okta.com", authServerId: "default" }, id: "ok-badmode", clientId: "c", secretMode: "vault", secret: "s" }, owner);
      ok("create (preset): an UNKNOWN secretMode is refused, never silently do-plaintext", badSecretMode.ok === false && String(badSecretMode.reason).includes("secretMode must be"));
      const badId = await doJson("POST", "/idp/conn/create", { presetId: "okta", vars: { oktaDomain: "acme.okta.com", authServerId: "default" }, id: 7, clientId: "c", secret: "s" }, owner);
      ok("create (preset): a NON-STRING id is refused, never silently the preset id", badId.ok === false && String(badId.reason).includes("id must be a string"));
      ok("create (preset): NONE of the four refused bodies stored anything", (await storage.get("idpconn:ok-badlabel")) === undefined && (await storage.get("idpconn:ok-badauth")) === undefined && (await storage.get("idpconn:ok-badmode")) === undefined && (await storage.get("idpconn:okta")) === undefined);
      // POSITIVE CONTROL that must DISCRIMINATE: the SAME body with a string label stores, and stores the
      // operator's label rather than the preset's. Without it, a create that refused every okta preset would
      // pass all four above, and the label assertion would be checking nothing about the substitution.
      const goodLabel = await doJson("POST", "/idp/conn/create", { presetId: "okta", vars: { oktaDomain: "acme.okta.com", authServerId: "default" }, id: "ok-goodlabel", label: "Okta, Sydney tenant", clientId: "c", secret: "s" }, owner);
      ok("create (preset) CONTROL: the same body with a STRING label stores it verbatim, not the preset's 'Okta'", goodLabel.ok === true && (goodLabel.conn as { label?: string }).label === "Okta, Sydney tenant");

      // OIDC connection with a declared client-secret expiry -> an observed idp-secret-<id> row.
      const expProposal = { ...oidcProposal, id: "entra-exp", label: "Entra Exp", secretExpiresAt: "2027-03-01T00:00:00Z" };
      const crExp = await doJson("POST", "/idp/conn/create", { proposal: expProposal, secret: "s" }, owner);
      ok("create (oidc with secretExpiresAt): ok", crExp.ok === true);
      const secRow = await storage.get<{ kind?: string; expiresAt?: string }>("expiry:idp-secret-entra-exp");
      ok("a confidential client-secret expiry row is observed (kind credential)", secRow !== undefined && secRow.kind === "credential" && secRow.expiresAt === "2027-03-01T00:00:00Z");

      // delete an existing connection: removes records, drops the observed rows, bumps idpEpoch, audits.
      const del = await doJson("POST", "/idp/conn/delete", { connId: "entra-exp" }, owner);
      ok("idpConnDelete (existing): ok", del.ok === true);
      ok("idpConnDelete (existing): it reports deleted:true, so the caller can tell this from a no-op", del.deleted === true);
      ok("delete: the connection record is gone", (await storage.get("idpconn:entra-exp")) === undefined);
      ok("delete: the observed client-secret row is dropped", (await storage.get("expiry:idp-secret-entra-exp")) === undefined);
      // Delete an absent connection (valid id, no record). It is NOT a refusal -- it passes every gate and every
      // validator, so `ok` stays true and the call stays idempotent -- and it is not a change either: nothing was
      // removed and the audit is deliberately SKIPPED. `deleted:false` is the only thing that separates the two,
      // and without it router-identity.ts:890 raised an IdP-connection-removal alert over a connection that never
      // existed. Both halves are asserted here, the answer AND the silence in the audit trail, because the field
      // is only worth anything if it agrees with what the method actually did.
      const auditBefore = (await storage.get<{ count?: number }>("auditHead"))?.count ?? 0;
      const delAbsent = await doJson("POST", "/idp/conn/delete", { connId: "no-such-conn" }, owner);
      ok("idpConnDelete (absent): an idempotent ok (no record existed)", delAbsent.ok === true);
      ok("idpConnDelete (absent): it reports deleted:false, so a no-op is not announceable as a removal", delAbsent.deleted === false);
      ok(
        "idpConnDelete (absent): and the audit trail agrees -- no row was appended for a delete that removed nothing",
        ((await storage.get<{ count?: number }>("auditHead"))?.count ?? 0) === auditBefore && auditBefore > 0,
      );
    }

    // ============================================================================================
    // SECTION F - the absent-config / invalid-input refusal branches across the remaining methods.
    // ============================================================================================
    {
      ok("idpSamlMetadata: an invalid connId is refused", (await doJson("POST", "/idp/saml/metadata", { connId: "BAD!!", acsUrl: ACS_URL })).ok === false);
      ok("idpSamlMetadata: an unknown SAML connection is refused", (await doJson("POST", "/idp/saml/metadata", { connId: "no-such-conn", acsUrl: ACS_URL })).ok === false);
      ok("idpSamlStart: an invalid connId is refused", (await doJson("POST", "/idp/saml/start", { connId: "BAD!!", acsUrl: ACS_URL })).ok === false);
      ok("idpSamlStart: an unknown SAML connection is refused", (await doJson("POST", "/idp/saml/start", { connId: "no-such-conn", acsUrl: ACS_URL })).ok === false);
      ok("idpOidcStart: an invalid connId is refused", (await doJson("POST", "/idp/oidc/start", { connId: "BAD!!" })).ok === false);
      ok("idpOidcStart: an unknown connection is refused", (await doJson("POST", "/idp/oidc/start", { connId: "no-such-conn" })).ok === false);
      // a SAML connection through the OIDC start/callback: the unsupported-kind arm.
      ok("idpOidcStart: a SAML connection does not support interactive OIDC start", String((await doJson("POST", "/idp/oidc/start", { connId: SAML_CONN })).reason).includes("does not support"));
      ok("idpOidcCallback: a SAML connection does not support the OIDC callback", String((await doJson("POST", "/idp/oidc/callback", { connId: SAML_CONN, code: "c", state: "s", txnId: "t" })).reason).includes("does not support"));
      ok("idpOidcCallback: an invalid connId is refused", (await doJson("POST", "/idp/oidc/callback", { connId: "BAD!!" })).ok === false);
      ok("idpOidcCallback: an unknown connection is refused", (await doJson("POST", "/idp/oidc/callback", { connId: "no-such-conn", code: "c", state: "s", txnId: "t" })).ok === false);
      ok("idpConnSetEnabled: an invalid connId is refused", (await doJson("POST", "/idp/conn/enabled", { connId: "BAD!!", enabled: true }, owner)).ok === false);
      ok("idpConnSetEnabled: an unknown connection is refused", (await doJson("POST", "/idp/conn/enabled", { connId: "no-such-conn", enabled: true }, owner)).ok === false);
      ok("idpConnDelete: an invalid connId is refused", (await doJson("POST", "/idp/conn/delete", { connId: "BAD!!" }, owner)).ok === false);
    }

    // ============================================================================================
    // SECTION G - nativeSessionIssue defence-in-depth refusals (no usable email / no usable subject),
    //   reached directly because the OIDC/SAML verifiers guarantee a usable principal on the live paths.
    // ============================================================================================
    {
      const mint = dobj as unknown as {
        nativeSessionIssue(p: { subject: string; email: string | null; emailVerified: boolean; groups: string[] }, connId: string, method: "oidc" | "saml", nowMs: number, sNooa?: number | null): Promise<{ ok: boolean; reason?: string }>;
      };
      const noEmail = await mint.nativeSessionIssue({ subject: "oidc:entra|x|y", email: null, emailVerified: true, groups: [] }, "entra", "oidc", Date.now());
      ok("nativeSessionIssue: a principal with no usable email is refused", noEmail.ok === false && String(noEmail.reason).includes("email"));
      const noSubject = await mint.nativeSessionIssue({ subject: "   ", email: "x@y.example", emailVerified: true, groups: [] }, "entra", "oidc", Date.now());
      ok("nativeSessionIssue: a principal with no usable subject is refused", noSubject.ok === false && String(noSubject.reason).includes("subject"));
      // A verified principal whose groups include an over-long name: the mint SUCCEEDS (the bad group is dropped
      // by boundGroupList) and records the group-name-dropped auth-signal (P2, asserted in SECTION M).
      const droppedGroup = await mint.nativeSessionIssue({ subject: "oidc:entra|grp|user", email: "grp@acme.example", emailVerified: true, groups: ["good-group", "x".repeat(500)] }, "entra", "oidc", Date.now());
      ok("nativeSessionIssue: a login with an over-long group name still mints (the bad group is dropped)", droppedGroup.ok === true);
    }

    // ============================================================================================
    // SECTION: owner-invite hardening - a pending OWNER invite binds ONLY on a GENUINELY-verified email. A
    //   trust-idp SAML connection (verified-by-policy, no flag) must NOT bind owner; a require-flag one must.
    // ============================================================================================
    {
      const mintT = dobj as unknown as {
        nativeSessionIssue(p: { subject: string; email: string | null; emailVerified: boolean; groups: string[] }, connId: string, method: "oidc" | "saml", nowMs: number, sNooa?: number | null): Promise<{ ok: boolean; token?: string; reason?: string }>;
      };
      // A require-flag SAML connection alongside the existing trust-idp SAML_CONN.
      await doJson("POST", "/idp/conn/create", { proposal: { ...samlProposal, id: "saml-rf-g3", label: "RF IdP", emailVerifiedPolicy: "require-flag" } }, owner);
      const inviteEmail = "cfo-g3@acme.example";
      // Plant a pending OWNER invite for the email (the bind-on-first-auth target).
      await storage.put(`role:pending:${inviteEmail}`, { email: inviteEmail, role: "owner", grantedBy: "owner@acme.example", grantedAt: new Date(0).toISOString() });
      // (a) a trust-idp SAML login asserting the invite email mints a session but does NOT bind owner (the email
      // is verified-by-policy, not by a real flag -- not strong enough for the highest-privilege role).
      const weak = await mintT.nativeSessionIssue({ subject: `saml:${SAML_CONN}|${IDP_ENTITY}|cfo-weak`, email: inviteEmail, emailVerified: true, groups: [] }, SAML_CONN, "saml", Date.now());
      ok("a trust-idp SAML login still mints a session", weak.ok === true && typeof weak.token === "string");
      const weakWho = (await (await whoami(weak.token as string)).json()) as { role?: string };
      ok("a trust-idp SAML connection does NOT bind a pending OWNER invite (not owner)", weakWho.role !== "owner");
      ok("the owner invite is still pending after the refused weak bind (not consumed)", (await storage.get(`role:pending:${inviteEmail}`)) !== undefined);
      // (b) a require-flag SAML connection asserting the SAME invite email DOES bind owner (genuine verification).
      const strong = await mintT.nativeSessionIssue({ subject: `saml:saml-rf-g3|${IDP_ENTITY}|cfo-strong`, email: inviteEmail, emailVerified: true, groups: [] }, "saml-rf-g3", "saml", Date.now());
      const strongWho = (await (await whoami(strong.token as string)).json()) as { role?: string };
      ok("a require-flag SAML connection DOES bind the pending OWNER invite (owner)", strongWho.role === "owner");
    }

    // ============================================================================================
    // SECTION: lockout-guard preflight - connectionRemovalPreflight reports whether removing/disabling a
    //   connection would leave ZERO enabled connections (the DO fact the router combines with CF Access + the
    //   token-disabled/retired state to refuse a removal that would strand the tenant). Fresh isolated DO so
    //   the enabled-connection count is controlled.
    // ============================================================================================
    {
      const g5storage = new MockStorage();
      const g5dobj = new SchedulerDO({ storage: g5storage } as unknown as DurableObjectState);
      const g5owner: Caller = { method: "token", email: "f-g5@acme.example", subject: null, role: "owner", groups: [] };
      const g5do = (path: string, body: unknown): Promise<Response> => g5dobj.fetch(new Request(`https://scheduler.internal${path}`, { method: "POST", headers: { "content-type": "application/json", [CALLER_HEADER]: encodeCaller(g5owner) }, body: JSON.stringify(body) }));
      const pf = async (connId: string): Promise<{ lastEnabledConnection?: boolean }> => (await (await g5do("/idp/conn/removal-preflight", { connId })).json()) as { lastEnabledConnection?: boolean };
      await g5do("/idp/conn/create", { proposal: { ...samlProposal, id: "g5-a", label: "A" } });
      await g5do("/idp/conn/create", { proposal: { ...samlProposal, id: "g5-b", label: "B" } });
      ok("with two enabled connections, one is NOT the last sign-in path (lastEnabledConnection false)", (await pf("g5-a")).lastEnabledConnection === false);
      // Disable g5-b -> g5-a is the SOLE enabled connection, so removing/disabling it would leave zero.
      await g5do("/idp/conn/enabled", { connId: "g5-b", enabled: false });
      ok("when a connection is the SOLE enabled one, lastEnabledConnection is true (the router guard engages)", (await pf("g5-a")).lastEnabledConnection === true);
      ok("a DISABLED connection is not itself flagged as the last sign-in path", (await pf("g5-b")).lastEnabledConnection === false);
    }

    // ============================================================================================
    // SECTION H - the keys.ceremony gate (defence in depth): a non-owner caller is refused at the DO.
    // ============================================================================================
    {
      const r = await doReq("GET", "/idp/conn/list", undefined, viewer);
      ok("idpConnList: a non-owner caller is refused at the DO (403, keys.ceremony)", r.status === 403);
    }

    // ============================================================================================
    // SECTION I - audit-attribution arms (a break-glass caller carrying NO email but a sourceIp), plus the
    //   create-time cert observe loop across TWO certs (the max-notAfter comparison arm).
    // ============================================================================================
    {
      // The bare-token break-glass resolves to owner (no table lookup) yet carries no attributable email; it
      // DOES carry the edge sourceIp. This exercises the audit createdBy/actorEmail null arms + the sourceIp arm.
      const ownerN: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [], sourceIp: "203.0.113.77" };
      const kp = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
      const cert2 = await buildSelfSignedCertPem(new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey)), kp.privateKey, "idp.example.two");

      const cN = await doJson("POST", "/idp/conn/create", { proposal: { ...oidcProposal, id: "entra-n", label: "N" }, secret: "s" }, ownerN);
      ok("create (break-glass caller, no email + sourceIp): ok, createdBy null", cN.ok === true);
      ok("idpConnSetEnabled (break-glass caller): ok", (await doJson("POST", "/idp/conn/enabled", { connId: "entra-n", enabled: false }, ownerN)).ok === true);
      ok("idpConnDelete (break-glass caller): ok", (await doJson("POST", "/idp/conn/delete", { connId: "entra-n" }, ownerN)).ok === true);

      // a SAML connection created with TWO distinct certs: the observe loop now evaluates the na>max arm.
      const samlN = await doJson("POST", "/idp/conn/create", { proposal: { ...samlProposal, id: "saml-n", idpSigningCerts: [samlCert, cert2] } }, ownerN);
      ok("create (saml, two certs, break-glass caller): ok + the max-notAfter observe arm runs", samlN.ok === true);
      ok("cert rollover (break-glass caller): ok (audit attribution arms)", (await doJson("POST", "/idp/conn/cert", { connId: "saml-n", certs: [cert2] }, ownerN)).ok === true);
      await doJson("POST", "/idp/conn/delete", { connId: "saml-n" }, owner);
    }

    // ============================================================================================
    // SECTION J - absent-field default arms: a non-string field defaults to "" (refused), and a valid
    //   connId with the rest omitted exercises the per-field defaults further down each handler.
    // ============================================================================================
    {
      // idpConnCreate: an invalid proposal makes createIdpConnection refuse (the created-not-ok early return).
      ok("create: an invalid proposal is a clean refusal (created not ok)", (await doJson("POST", "/idp/conn/create", { proposal: { kind: "oidc", id: "bad" } }, owner)).ok === false);
      // idpConnCreate preset path with NO clientId: clientId defaults to "" (the validator then refuses it).
      ok("create (preset, no clientId): the empty-clientId default is refused by the validator", (await doJson("POST", "/idp/conn/create", { presetId: "keycloak", vars: { host: "sso9.acme.example", realm: "r9" }, id: "kc9" }, owner)).ok === false);

      // Non-string connId -> the "" default -> invalid, across every handler.
      ok("idpOidcStart: a non-string connId defaults to invalid", (await doJson("POST", "/idp/oidc/start", {})).ok === false);
      ok("idpOidcCallback: a non-string connId defaults to invalid", (await doJson("POST", "/idp/oidc/callback", {})).ok === false);
      ok("idpSamlMetadata: a non-string connId defaults to invalid", (await doJson("POST", "/idp/saml/metadata", {})).ok === false);
      ok("idpSamlStart: a non-string connId defaults to invalid", (await doJson("POST", "/idp/saml/start", {})).ok === false);
      ok("idpSamlAcs: a non-string connId defaults to invalid", (await doJson("POST", "/idp/saml/acs", {})).ok === false);
      ok("idpConnDelete: a non-string connId defaults to invalid", (await doJson("POST", "/idp/conn/delete", {}, owner)).ok === false);
      ok("idpConnSetEnabled: a non-string connId defaults to invalid", (await doJson("POST", "/idp/conn/enabled", {}, owner)).ok === false);
      ok("idpConnSamlCertUpdate: a non-string connId defaults to invalid", (await doJson("POST", "/idp/conn/cert", {}, owner)).ok === false);

      // A VALID connId with every other field omitted: the downstream string defaults ("" / "/" ) are taken.
      ok("idpOidcCallback: a valid connId with no code/state/txnId/iss is refused (string defaults)", (await doJson("POST", "/idp/oidc/callback", { connId: "entra" })).ok === false);
      ok("idpSamlMetadata: a valid connId with no acsUrl still builds metadata (acsUrl default)", (await doJson("POST", "/idp/saml/metadata", { connId: SAML_CONN })).ok === true);
      ok("idpSamlStart: a valid connId with no returnTo/acsUrl still mints (defaults)", (await doJson("POST", "/idp/saml/start", { connId: SAML_CONN })).ok === true);
      ok("idpSamlAcs: a valid connId with no response/relayState/browserBind is refused (defaults)", (await doJson("POST", "/idp/saml/acs", { connId: SAML_CONN })).ok === false);
    }

    // ============================================================================================
    // SECTION K - a SAML request whose connection is DELETED before the ACS POST arrives: the record is
    //   consumed and binds, but samlConnFor then finds no connection (the conn-undefined-after-consume arm).
    // ============================================================================================
    {
      await doJson("POST", "/idp/conn/create", { proposal: { ...samlProposal, id: "saml-tmp" } }, owner);
      const sTmp = await doJson("POST", "/idp/saml/start", { connId: "saml-tmp", returnTo: "/", acsUrl: ACS_URL });
      const rsTmp = new URL(String(sTmp.redirectUrl)).searchParams.get("RelayState") ?? "";
      await doJson("POST", "/idp/conn/delete", { connId: "saml-tmp" }, owner);
      const acsTmp = await doJson("POST", "/idp/saml/acs", { connId: "saml-tmp", samlResponse: "x", relayState: rsTmp, acsUrl: ACS_URL, browserBind: String(sTmp.browserBind) });
      ok("idpSamlAcs: a consumed record whose connection was since deleted is refused (conn undefined)", acsTmp.ok === false && String(acsTmp.reason).includes("not found"));
    }

    // ============================================================================================
    // SECTION L - SSO-FAILURE AGGREGATE: every refused sign-in above funnelled through the wrapper's
    //   recordSsoFail, so the bounded per-code aggregate reflects them. Proves the END-TO-END round-trip
    //   (failure -> classified code -> bounded DO storage -> GET /sso-failures route -> readSsoFailures) that
    //   the support pack reads, AND the no-custody property: each stored entry is a CLOSED code -> {count,lastAt}
    //   only, never a raw reason or any interpolated issuer/connId/error message.
    // ============================================================================================
    {
      const aggResp = await doReq("GET", "/sso-failures");
      const agg = (await aggResp.json()) as Record<string, { count: number; lastAt: string }>;
      ok("sso-failures: GET /sso-failures routes to the aggregate (route wired end-to-end)", aggResp.status === 200 && typeof agg === "object" && agg !== null);
      ok("sso-failures: the many refused sign-ins were recorded (replay bucket non-empty)", typeof agg.replay?.count === "number" && agg.replay.count > 0);
      ok("sso-failures: a malformed SAML/OIDC input recorded the `malformed` code", typeof agg.malformed?.count === "number" && agg.malformed.count > 0);
      ok("sso-failures: a disabled/deleted connection recorded the `connection` code", typeof agg.connection?.count === "number" && agg.connection.count > 0);
      const entries = Object.entries(agg);
      ok("sso-failures: EVERY stored entry is a closed code -> {count,lastAt} only (no raw reason / no interpolated data)",
        entries.length > 0 && entries.every(([code, v]) => (SSO_FAIL_CODES as readonly string[]).includes(code) && Object.keys(v).sort().join(",") === "count,lastAt" && typeof v.count === "number" && typeof v.lastAt === "string"));
      ok("sso-failures: no stored value contains a raw reason / interpolated issuer/connId (redaction-safe by construction)",
        !JSON.stringify(agg).match(/reason|issuer|connId|disabled|not found|mismatch/i));
      ok("sso-failures: every count is capped (<= 1000) so a flood of failures cannot grow it unboundedly", Object.values(agg).every((v) => v.count <= 1000));
    }

    // ============================================================================================
    // SECTION M - per-connection-KIND SSO breakdown + a bounded auth-signal aggregate. The refused
    //   sign-ins above ALSO funnelled their connKind into the by-kind aggregate (SAML ACS failures -> saml,
    //   OIDC callback failures on a valid connId -> oidc), and the nativeSessionIssue refusals + the
    //   unverified-email bind-skip recorded bounded auth-signals. Proves both new reader routes, the record
    //   round-trip, and the closed-vocabulary drop on the POST /auth-signal record path — all redaction-safe.
    // ============================================================================================
    {
      const byKind = (await (await doReq("GET", "/sso-failures-by-kind")).json()) as Record<string, Record<string, { count: number; lastAt: string }>>;
      ok("sso-failures-by-kind: GET routes to the per-kind aggregate (route wired end-to-end)", typeof byKind === "object" && byKind !== null);
      ok("sso-failures-by-kind: SAML ACS failures are bucketed under the saml kind", typeof byKind.saml === "object" && Object.values(byKind.saml ?? {}).some((v) => v.count > 0));
      ok("sso-failures-by-kind: OIDC callback failures on a valid connId are bucketed under the oidc kind", typeof byKind.oidc === "object" && Object.values(byKind.oidc ?? {}).some((v) => v.count > 0));
      ok("sso-failures-by-kind: every outer key is a closed connKind and every inner key a closed classifier code",
        Object.entries(byKind).every(([k, sub]) => ["oidc", "oauth2", "saml"].includes(k) && Object.entries(sub).every(([code, v]) => (SSO_FAIL_CODES as readonly string[]).includes(code) && typeof v.count === "number" && typeof v.lastAt === "string")));
      ok("sso-failures-by-kind: no connId slug or raw reason is stored (redaction-safe by construction)",
        !JSON.stringify(byKind).match(/entra|work-idp|github|reason|disabled|not found|mismatch|-slug/i));

      // ---- exercise the finer idp-auth signals BEFORE reading the aggregate. ----
      // (a) private-key-jwt-unsupported: a connection requesting private_key_jwt client auth is refused at config.
      const pkj = await doJson("POST", "/idp/conn/create", { proposal: { ...oidcProposal, id: "pkj", clientAuth: "private_key_jwt", secretRef: { mode: "do-plaintext" } } }, owner);
      ok("create (private_key_jwt): refused at config time (not wired in this build)", pkj.ok === false && String(pkj.reason).includes("private_key_jwt"));
      // (b) oidc-entra-multitenant-misconfig: a multitenant connection whose token tid is not in acceptedTenantIds.
      const mtCr = await doJson("POST", "/idp/conn/create", { proposal: { id: "entra-mt", kind: "oidc", label: "Entra Multitenant", presetId: "entra", enabled: true, issuer: MT_ISSUER_TEMPLATE, issuerSubstitution: "tid", acceptedTenantIds: [MT_ACCEPTED_TID], clientId: MT_CLIENT, secretRef: { mode: "do-plaintext" }, scopes: ["openid", "email", "profile"], idTokenSigAlgs: ["RS256"], pkce: "required", clientAuth: "client_secret_post", requireNonce: true, authorizationEndpoint: MT_AUTH, tokenEndpoint: MT_TOKEN, jwksUri: JWKS_URL }, secret: "mt-secret" }, owner);
      ok("create (multitenant): a {tenantid} issuer + issuerSubstitution 'tid' + acceptedTenantIds validates", mtCr.ok === true);
      const mtStart = await doJson("POST", "/idp/oidc/start", { connId: "entra-mt", redirectUri: OIDC_REDIRECT, returnTo: "/" });
      currentNonce = new URL(String(mtStart.authorizeUrl)).searchParams.get("nonce") ?? "";
      const mtCb = await doJson("POST", "/idp/oidc/callback", { connId: "entra-mt", code: "mt-code", state: mtStart.state, txnId: mtStart.txnId });
      ok("idpOidcCallback (multitenant, unaccepted tenant): refused with no session", mtCb.ok === false && !("token" in mtCb));
      // (c) subject-rekey-role-loss: seed a role for an email under an OLD subject, then a verified login under a
      // NEW subject for the SAME email (an IdP subject rekey) mints but records the orphaned-role signal.
      await storage.put(roleSubjectKey("oidc:entra|iss|old-sub"), { subject: "oidc:entra|iss|old-sub", email: "rekey-user@acme.example", role: "operator", grantedBy: "system", grantedAt: "2026-06-13T00:00:00.000Z" });
      const rekeyMint = await (dobj as unknown as { nativeSessionIssue(p: { subject: string; email: string | null; emailVerified: boolean; groups: string[] }, connId: string, method: "oidc" | "saml", nowMs: number): Promise<{ ok: boolean }> }).nativeSessionIssue({ subject: "oidc:entra|iss|new-sub", email: "rekey-user@acme.example", emailVerified: true, groups: [] }, "entra", "oidc", Date.now());
      ok("nativeSessionIssue: a verified login for a rekeyed subject still mints (role loss does not block auth)", rekeyMint.ok === true);
      // (d) caller-header-undecodable: a PRESENT but undecodable router-internal caller header at a DO route. The
      // route() observation is fire-and-forget, so flush the microtask/timer queue before reading the aggregate.
      await dobj.fetch(new Request("https://scheduler.internal/downpipes", { method: "GET", headers: { [CALLER_HEADER]: b64urlJSON({ method: "bogus" }) } }));
      await new Promise((resolve) => setTimeout(resolve, 0));

      const sig = (await (await doReq("GET", "/auth-signals")).json()) as Record<string, { count: number; lastAt: string }>;
      ok("auth-signals: GET routes to the aggregate (route wired end-to-end)", typeof sig === "object" && sig !== null);
      ok("auth-signals: a verified-but-emailless mint refusal was recorded (nativeSessionIssue)", (sig["emailless-assertion"]?.count ?? 0) > 0);
      ok("auth-signals: an unusable-subject mint refusal was recorded", (sig["subject-unusable"]?.count ?? 0) > 0);
      ok("auth-signals: an unverified-email bind-skip was recorded (email_verified gate, the SECTION-A cb3 path)", (sig["email-verified-bind-blocked"]?.count ?? 0) > 0);
      ok("auth-signals: a login that dropped an over-long group name recorded group-name-dropped", (sig["group-name-dropped"]?.count ?? 0) > 0);
      // The newly-wired finer signals.
      ok("auth-signals: a SAML ACS with no server-minted RelayState recorded saml-relaystate-missing (SP-initiated)", (sig["saml-relaystate-missing"]?.count ?? 0) > 0);
      ok("auth-signals: a login asserting groups with no matching mapping recorded zero-role-groups", (sig["zero-role-groups"]?.count ?? 0) > 0);
      ok("auth-signals: a rekeyed-subject verified login recorded subject-rekey-role-loss", (sig["subject-rekey-role-loss"]?.count ?? 0) > 0);
      ok("auth-signals: a multitenant token with an unaccepted tenant recorded oidc-tenant-not-accepted", (sig["oidc-tenant-not-accepted"]?.count ?? 0) > 0);
      ok("auth-signals: a private_key_jwt connection refusal recorded private-key-jwt-unsupported", (sig["private-key-jwt-unsupported"]?.count ?? 0) > 0);
      ok("auth-signals: a present-but-undecodable caller header recorded caller-header-undecodable", (sig["caller-header-undecodable"]?.count ?? 0) > 0);
      // The entry carries a TEMPORAL SHAPE (a 14-slot day ring of COUNTS, a firstAt, a capSaturated latch), so
      // a 10,000-failure burst an hour ago and a month-long trickle are distinguishable. The assertion this
      // test exists to make is the REDACTION one -- no ip, e-mail, connId or subject may ever appear -- so it
      // pins the closed FIELD SET and each field's type: a new key must be a number, a boolean, an ISO stamp
      // or a ring of ints, and nothing else can enter.
      const ALLOWED_ENTRY_KEYS = new Set(["count", "lastAt", "firstAt", "capSaturated", "dayEpoch", "days"]);
      ok("auth-signals: every stored entry is a closed name -> counts/timestamps only (no ip/email/connId/subject)",
        Object.entries(sig).every(([, v]) => {
          const e = v as unknown as Record<string, unknown>;
          if (!Object.keys(e).every((k) => ALLOWED_ENTRY_KEYS.has(k))) return false;
          if (typeof e.count !== "number" || typeof e.lastAt !== "string") return false;
          if (e.firstAt !== undefined && typeof e.firstAt !== "string") return false;
          if (e.capSaturated !== undefined && typeof e.capSaturated !== "boolean") return false;
          if (e.dayEpoch !== undefined && typeof e.dayEpoch !== "number") return false;
          if (e.days !== undefined && !(Array.isArray(e.days) && e.days.every((n) => typeof n === "number"))) return false;
          return true;
        }));

      // POST /auth-signal records a closed-vocabulary name; an out-of-vocabulary or non-string name is DROPPED.
      const before = sig["scim-unauthorised"]?.count ?? 0;
      await doReq("POST", "/auth-signal", { name: "scim-unauthorised" });
      await doReq("POST", "/auth-signal", { name: "totally-made-up-signal" });
      await doReq("POST", "/auth-signal", {}); // non-string name -> "" -> dropped by the closed-set guard
      const sig2 = (await (await doReq("GET", "/auth-signals")).json()) as Record<string, { count: number }>;
      ok("auth-signals: POST /auth-signal bumps a closed-vocabulary counter", (sig2["scim-unauthorised"]?.count ?? 0) === before + 1);
      ok("auth-signals: POST /auth-signal DROPS an out-of-vocabulary name (no injected key)", !("totally-made-up-signal" in sig2) && !("" in sig2));

      // auth posture: create a confidential do-plaintext OIDC connection WITHOUT a secret so its idpsecret:<id>
      // is absent, then read /auth-posture. The session signing key exists (the many logins above minted it) with a
      // real age (never the key itself), and the missing do-plaintext-secret count is >= 1.
      await doJson("POST", "/idp/conn/create", { proposal: { ...oidcProposal, id: "entra-nosecret", label: "No Secret" } }, owner);
      const posture = (await (await doReq("GET", "/auth-posture")).json()) as { sessionSigningKey?: { present: boolean; ageMs?: number; adequateLength?: boolean }; doPlaintextSecretsMissing?: number; adminCredentialPaths?: { passkeyCredentials?: number; enabledIdpConnections?: number } };
      ok("auth-posture: the session signing key is present with a real age (never the key itself)", posture.sessionSigningKey?.present === true && typeof posture.sessionSigningKey?.ageMs === "number" && posture.sessionSigningKey.ageMs >= 0);
      ok("auth-posture: the session signing key reports adequateLength true (recovery-key-too-short is false)", posture.sessionSigningKey?.adequateLength === true);
      ok("auth-posture: a confidential do-plaintext connection missing its stored secret is counted", (posture.doPlaintextSecretsMissing ?? 0) >= 1);
      // (token-fallback-disabled-lockout cross-check): the alternative admin-credential-path counts. No passkeys
      // are registered in this suite (0) and at least one IdP connection is enabled (>= 1); both are clamped ints.
      ok("auth-posture: adminCredentialPaths reports the passkey + enabled-IdP-connection counts (lockout cross-check)",
        typeof posture.adminCredentialPaths?.passkeyCredentials === "number" && posture.adminCredentialPaths.passkeyCredentials >= 0 && typeof posture.adminCredentialPaths?.enabledIdpConnections === "number" && posture.adminCredentialPaths.enabledIdpConnections >= 1);
    }
  } finally {
    globalThis.fetch = realFetch;
  }

  console.log(failures === 0 ? "\nVALIDATE-COV-SCHED-SCHEDULER-DO-IDP VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
