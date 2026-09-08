// Drive the native OIDC flow engine (src/admin/oidc.ts) end to end with a STUB IdP (an injected fetch) and
// REAL signed id_tokens: PKCE S256 correctness, the authorize-URL shape, discovery parsing + endpoint
// screening, the SSRF-guarded fetch (unsafe-URL reject, redirect:"manual" with a 3xx refused, size cap), the code->token
// exchange (client_secret_post/basic), the kid-rotation refetch, group extraction (rolesClaim preferred,
// nested path, claimNamespace, the Entra overflow fail-closed), and completeOidcLogin happy + sad paths.
// No network. Run: node test/validate-oidc.ts
//
// Node 25 strip-types; Web Crypto only.

import {
  mintPkce,
  mintOpaque,
  buildAuthorizeUrl,
  discoveryUrlFor,
  endpointsFromConnection,
  parseDiscovery,
  guardedOidcFetch,
  fetchJwksGuarded,
  exchangeCode,
  verifyIdTokenWithRotation,
  extractGroups,
  completeOidcLogin,
  enforceHostedDomain,
} from "../src/admin/oidc.ts";
import type { FlowEndpoints } from "../src/admin/oidc.ts";
import type { OidcConnection } from "../src/admin/idpconn.ts";
import type { JWKS, JWK } from "../src/admin/oidc-verify.ts";
import { oidcSubject } from "../src/admin/identity.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ISSUER = "https://idp.example.com";
const CLIENT = "downpipes-client";
const NONCE = "nonce-xyz";
const REDIRECT = "https://console.downpipes.io/admin/oidc/callback/entra";
const TOKEN_URL = "https://idp.example.com/token";
const JWKS_URL = "https://idp.example.com/jwks";
const AUTH_URL = "https://idp.example.com/authorize";
const now = Math.floor(Date.now() / 1000);

// ---- base64url + JWT minting (RS256) ----
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
const jwk: JWK = { kid: "rsa-1", kty: "RSA", n: rsaPub.n!, e: rsaPub.e!, alg: "RS256" };
const JWKS_GOOD: JWKS = { keys: [jwk] };
async function signIdToken(payload: Record<string, unknown>): Promise<string> {
  const head = b64urlJSON({ alg: "RS256", kid: "rsa-1", typ: "JWT" });
  const body = b64urlJSON(payload);
  const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", rsa.privateKey, new TextEncoder().encode(`${head}.${body}`)));
  return `${head}.${body}.${b64url(sig)}`;
}
function idClaims(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { iss: ISSUER, sub: "user-1", aud: CLIENT, nonce: NONCE, exp: now + 300, iat: now, email: "a@b.com", email_verified: true, ...over };
}

const baseConn: OidcConnection = {
  id: "entra",
  kind: "oidc",
  label: "Entra",
  presetId: "entra",
  enabled: true,
  issuer: ISSUER,
  clientId: CLIENT,
  secretRef: { mode: "do-plaintext" },
  scopes: ["openid", "email", "profile"],
  idTokenSigAlgs: ["RS256"],
  pkce: "required",
  clientAuth: "client_secret_post",
  requireNonce: true,
  rolesClaim: "roles",
  createdBy: "owner@example.com",
  createdAt: "2026-06-13T00:00:00.000Z",
};
// connWith returns baseConn with the membership-claim fields set EXACTLY as given: a claim left out of
// overrides is OMITTED from the result (baseConn sets rolesClaim, so the extractGroups fallback vectors
// need to express "no rolesClaim" by absence rather than an explicit undefined, which exactOptionalPropertyTypes
// forbids for an optional field). Behaviour is unchanged: an omitted optional claim reads the same at runtime
// as one set to undefined.
function connWith(overrides: { rolesClaim?: string; groupsClaim?: string; claimNamespace?: string }): OidcConnection {
  const { rolesClaim: _rc, groupsClaim: _gc, claimNamespace: _cn, ...rest } = baseConn;
  return {
    ...rest,
    ...(overrides.rolesClaim !== undefined ? { rolesClaim: overrides.rolesClaim } : {}),
    ...(overrides.groupsClaim !== undefined ? { groupsClaim: overrides.groupsClaim } : {}),
    ...(overrides.claimNamespace !== undefined ? { claimNamespace: overrides.claimNamespace } : {}),
  };
}
const EP: FlowEndpoints = { issuer: ISSUER, authorizationEndpoint: AUTH_URL, tokenEndpoint: TOKEN_URL, jwksUri: JWKS_URL };

// A stub fetch over the IdP token endpoint. `opts` lets a vector override the token response + assert the
// request. It records the last request so the exchange-shape checks can inspect it.
interface StubOpts {
  idTokenClaims?: Record<string, unknown>;
  status?: number;
  rawBody?: string; // override the JSON body (for non-JSON / no-id_token vectors)
}
let lastReq: { url: string; init: RequestInit } | null = null;
// lastRequest returns the request the stub fetch last captured, asserting one was made. lastReq is only
// ever assigned inside the makeFetch closure, so TypeScript's straight-line flow narrows the bare variable
// to null at a read site (and `lastReq?.init` would touch `init` on the impossible non-null branch). Reading
// through this accessor restores the declared type and asserts the call actually happened.
function lastRequest(): { url: string; init: RequestInit } {
  if (lastReq === null) throw new Error("no request was captured by the stub fetch");
  return lastReq;
}
function makeFetch(opts: StubOpts = {}): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
    lastReq = { url, init: init ?? {} };
    if (url === TOKEN_URL) {
      const status = opts.status ?? 200;
      const body = opts.rawBody ?? JSON.stringify({ id_token: await signIdToken(opts.idTokenClaims ?? idClaims()), access_token: "at-value" });
      return new Response(body, { status, headers: { "content-type": "application/json" } });
    }
    throw new Error(`unexpected fetch in test: ${url}`);
  }) as typeof fetch;
}
const getJwks = (_force: boolean): Promise<JWKS> => Promise.resolve(JWKS_GOOD);

console.log("OIDC flow engine\n");

// 1. PKCE S256
{
  const p = await mintPkce();
  ok("mintPkce method is S256", p.method === "S256");
  const expectChallenge = b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(p.verifier))));
  ok("mintPkce challenge == base64url(SHA-256(verifier))", p.challenge === expectChallenge);
  ok("mintOpaque returns distinct >=128-bit tokens", mintOpaque() !== mintOpaque() && mintOpaque().length >= 22);
}

// 2. buildAuthorizeUrl
{
  const conn: OidcConnection = { ...baseConn, hdDomain: "example.com", extraAuthParams: { prompt: "select_account" } };
  const url = new URL(buildAuthorizeUrl(conn, EP, { state: "ST", nonce: "NO", challenge: "CH", redirectUri: REDIRECT }));
  ok("authorize: response_type=code", url.searchParams.get("response_type") === "code");
  ok("authorize: client_id", url.searchParams.get("client_id") === CLIENT);
  ok("authorize: redirect_uri", url.searchParams.get("redirect_uri") === REDIRECT);
  ok("authorize: scope joined", url.searchParams.get("scope") === "openid email profile");
  ok("authorize: state + nonce", url.searchParams.get("state") === "ST" && url.searchParams.get("nonce") === "NO");
  ok("authorize: PKCE S256 challenge", url.searchParams.get("code_challenge") === "CH" && url.searchParams.get("code_challenge_method") === "S256");
  ok("authorize: Google hd + extraAuthParams", url.searchParams.get("hd") === "example.com" && url.searchParams.get("prompt") === "select_account");
}

// 3. parseDiscovery
{
  const good = parseDiscovery({ issuer: ISSUER, authorization_endpoint: AUTH_URL, token_endpoint: TOKEN_URL, jwks_uri: JWKS_URL }, ISSUER);
  ok("parseDiscovery accepts a valid document", good.ok === true && good.endpoints.tokenEndpoint === TOKEN_URL);
  ok("parseDiscovery rejects an http jwks_uri (SSRF screen)", parseDiscovery({ issuer: ISSUER, authorization_endpoint: AUTH_URL, token_endpoint: TOKEN_URL, jwks_uri: "http://idp.example.com/jwks" }, ISSUER).ok === false);
  ok("parseDiscovery rejects a missing endpoint", parseDiscovery({ issuer: ISSUER, authorization_endpoint: AUTH_URL, token_endpoint: TOKEN_URL }, ISSUER).ok === false);
  ok("parseDiscovery rejects an IP-literal token_endpoint", parseDiscovery({ issuer: ISSUER, authorization_endpoint: AUTH_URL, token_endpoint: "https://169.254.169.254/token", jwks_uri: JWKS_URL }, ISSUER).ok === false);
  ok("parseDiscovery rejects a doc whose issuer != the configured issuer (discovery-trust bind)", parseDiscovery({ issuer: "https://evil.example.com", authorization_endpoint: AUTH_URL, token_endpoint: TOKEN_URL, jwks_uri: JWKS_URL }, ISSUER).ok === false);
}

// 4. guardedOidcFetch
{
  let threwUnsafe = false;
  try {
    await guardedOidcFetch("http://idp.example.com/x", {}, makeFetch());
  } catch {
    threwUnsafe = true;
  }
  ok("guardedOidcFetch refuses an http URL before fetching", threwUnsafe);
  // (a) 2xx PASS-THROUGH + the mechanism: it must set redirect:"manual" (not "error") so a 3xx is handed back
  // as a non-ok response we refuse ourselves, WITHOUT the redirect:"error" edge-throw that broke real Entra
  // discovery. A normal 2xx (the common OIDC-discovery case) returns cleanly with its body.
  let sawRedirectManual = false;
  const probeFetch = (async (_u: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    sawRedirectManual = init?.redirect === "manual";
    return new Response('{"ok":1}', { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  const passed = await guardedOidcFetch(JWKS_URL, { method: "GET" }, probeFetch);
  ok("guardedOidcFetch sets redirect:'manual' (no redirect following)", sawRedirectManual);
  ok("guardedOidcFetch passes a 2xx straight through (no redirect:'error' edge-throw)", passed.status === 200 && passed.bodyText === '{"ok":1}');
  // (b) SSRF GUARD INTACT: a 3xx whose Location points at an INTERNAL host (169.254.169.254 cloud-metadata)
  // is REFUSED, never chased. redirect:"manual" hands the 3xx back; guardedOidcFetch throws BEFORE the Location
  // is read, so the internal host is never fetched (the stub is called EXACTLY once, and never with the
  // metadata URL). This is the same refusal the old redirect:"error" gave, minus the edge-throw on 2xx.
  let refusedRedirect = false;
  let internalFollowed = false;
  let calls = 0;
  const redirectFetch = (async (input: RequestInfo | URL, _init?: RequestInit): Promise<Response> => {
    calls++;
    const u = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
    if (u.includes("169.254.169.254")) internalFollowed = true;
    return new Response(null, { status: 302, headers: { location: "https://169.254.169.254/latest/meta-data/" } });
  }) as typeof fetch;
  try {
    await guardedOidcFetch(JWKS_URL, { method: "GET" }, redirectFetch);
  } catch {
    refusedRedirect = true;
  }
  ok("guardedOidcFetch REFUSES a 3xx (SSRF guard: an internal-host redirect is never chased)", refusedRedirect);
  ok("guardedOidcFetch never fetches the redirect Location (internal host not chased)", internalFollowed === false && calls === 1);
  // (b2) The opaque-redirect status 0 that redirect:"manual" surfaces on a spec-strict runtime is refused
  // identically (the Response constructor rejects status 0, so drive the branch with a minimal stub response).
  let refusedOpaque = false;
  const opaqueFetch = (async (): Promise<Response> => ({ status: 0, body: null }) as unknown as Response) as typeof fetch;
  try {
    await guardedOidcFetch(JWKS_URL, { method: "GET" }, opaqueFetch);
  } catch {
    refusedOpaque = true;
  }
  ok("guardedOidcFetch refuses the opaque status-0 redirect redirect:'manual' can surface", refusedOpaque);
  // size cap enforced on the BYTES READ (not content-length, which a chunked response omits): a body over the
  // cap throws. Use a small explicit cap for a fast, deterministic check; the body (5000 bytes) exceeds it.
  let capped = false;
  const bigFetch = (async (): Promise<Response> => new Response("x".repeat(5000), { status: 200 })) as typeof fetch;
  try {
    await guardedOidcFetch(JWKS_URL, {}, bigFetch, 1000);
  } catch {
    capped = true;
  }
  ok("guardedOidcFetch caps an oversized response by streamed bytes (chunked-safe)", capped);
}

// 5. exchangeCode
{
  const r = await exchangeCode(baseConn, EP, { code: "the-code", codeVerifier: "the-verifier", redirectUri: REDIRECT, clientSecret: "sek" }, makeFetch());
  ok("exchangeCode returns the id_token + access_token", r.ok === true && r.tokens.idToken.split(".").length === 3 && r.tokens.accessToken === "at-value");
  const sent = new URLSearchParams((lastRequest().init.body as string) ?? "");
  ok("exchangeCode posts grant_type/code/verifier/redirect_uri/client_id", sent.get("grant_type") === "authorization_code" && sent.get("code") === "the-code" && sent.get("code_verifier") === "the-verifier" && sent.get("redirect_uri") === REDIRECT && sent.get("client_id") === CLIENT);
  ok("client_secret_post puts the secret in the body", sent.get("client_secret") === "sek");
  // client_secret_basic puts it in the Authorization header instead
  const rb = await exchangeCode({ ...baseConn, clientAuth: "client_secret_basic" }, EP, { code: "c", codeVerifier: "v", redirectUri: REDIRECT, clientSecret: "sek" }, makeFetch());
  ok("client_secret_basic uses HTTP Basic auth", rb.ok === true && (lastRequest().init.headers as Record<string, string>)["authorization"] === `Basic ${btoa(`${CLIENT}:sek`)}` && !new URLSearchParams((lastRequest().init.body as string) ?? "").has("client_secret"));
  ok("exchangeCode rejects a non-200 token response", (await exchangeCode(baseConn, EP, { code: "c", codeVerifier: "v", redirectUri: REDIRECT, clientSecret: "sek" }, makeFetch({ status: 400 }))).ok === false);
  ok("exchangeCode rejects a response with no id_token", (await exchangeCode(baseConn, EP, { code: "c", codeVerifier: "v", redirectUri: REDIRECT, clientSecret: "sek" }, makeFetch({ rawBody: JSON.stringify({ access_token: "x" }) }))).ok === false);
  ok("client_secret_post without a resolved secret is refused", (await exchangeCode(baseConn, EP, { code: "c", codeVerifier: "v", redirectUri: REDIRECT }, makeFetch())).ok === false);
  // private_key_jwt is a deterministic not-implemented stub in this build; pin the contract so it
  // cannot silently break if the path is later implemented.
  ok("exchangeCode returns not-implemented for private_key_jwt", (await exchangeCode({ ...baseConn, clientAuth: "private_key_jwt" }, EP, { code: "c", codeVerifier: "v", redirectUri: REDIRECT }, makeFetch())).ok === false);
}

// 6. verifyIdTokenWithRotation: a kid-miss triggers exactly one refetch
{
  const idt = await signIdToken(idClaims());
  let calls = 0;
  const rotatingGetJwks = (force: boolean): Promise<JWKS> => {
    calls++;
    return Promise.resolve(force ? JWKS_GOOD : { keys: [] }); // cache miss first, real keys on force-refetch
  };
  const res = await verifyIdTokenWithRotation(idt, baseConn, rotatingGetJwks, { nonce: NONCE, now });
  ok("verifyIdTokenWithRotation refetches the JWKS once on a kid-miss and then verifies", res.ok === true && calls === 2);
}

// 7. extractGroups
{
  ok("extractGroups reads the rolesClaim (preferred)", JSON.stringify((extractGroups(baseConn, { roles: ["a", "b"] }) as { groups: string[] }).groups) === JSON.stringify(["a", "b"]));
  ok("extractGroups walks a nested path (Keycloak realm_access.roles)", JSON.stringify((extractGroups({ ...baseConn, rolesClaim: "realm_access.roles" }, { realm_access: { roles: ["x"] } }) as { groups: string[] }).groups) === JSON.stringify(["x"]));
  ok("extractGroups falls back to groupsClaim", JSON.stringify((extractGroups(connWith({ groupsClaim: "groups" }), { groups: ["g"] }) as { groups: string[] }).groups) === JSON.stringify(["g"]));
  ok("extractGroups honours claimNamespace (Auth0)", JSON.stringify((extractGroups({ ...baseConn, claimNamespace: "https://downpipes/", rolesClaim: "roles" }, { "https://downpipes/roles": ["r"] }) as { groups: string[] }).groups) === JSON.stringify(["r"]));
  ok("extractGroups coerces a single-group STRING to a one-element array (JumpCloud memberOf one-group user)", JSON.stringify((extractGroups(connWith({ groupsClaim: "memberOf" }), { memberOf: "Admins" }) as { groups: string[] }).groups) === JSON.stringify(["Admins"]));
  ok("extractGroups reads a memberOf ARRAY (multi-group JumpCloud user)", JSON.stringify((extractGroups(connWith({ groupsClaim: "memberOf" }), { memberOf: ["Admins", "Eng"] }) as { groups: string[] }).groups) === JSON.stringify(["Admins", "Eng"]));
  const overflow = extractGroups(connWith({ groupsClaim: "groups" }), { _claim_names: { groups: "src1" } });
  ok("extractGroups FAILS CLOSED on the Entra groups-overflow marker", "overflow" in overflow && overflow.overflow === true);
  const overflowRoles = extractGroups(connWith({ rolesClaim: "groups" }), { _claim_names: { groups: "src1" } });
  ok("extractGroups FAILS CLOSED on overflow even when membership maps via rolesClaim", "overflow" in overflowRoles && overflowRoles.overflow === true);
  ok("extractGroups honours a dotted-URL claimNamespace (Auth0) as a literal key", JSON.stringify((extractGroups({ ...baseConn, claimNamespace: "https://downpipes.example.com/", rolesClaim: "roles" }, { "https://downpipes.example.com/roles": ["r1"] }) as { groups: string[] }).groups) === JSON.stringify(["r1"]));
  ok("extractGroups returns [] when no claim and no overflow", JSON.stringify((extractGroups(connWith({}), {}) as { groups: string[] }).groups) === "[]");
}

// 8. completeOidcLogin: happy path -> principal
{
  const r = await completeOidcLogin(baseConn, EP, { code: "c", codeVerifier: "v", nonce: NONCE, redirectUri: REDIRECT, clientSecret: "sek" }, { doFetch: makeFetch({ idTokenClaims: idClaims({ roles: ["admins"] }) }), getJwks }, now);
  ok("completeOidcLogin succeeds and derives the principal", r.ok === true);
  if (r.ok) {
    ok("  -> subject is oidc:<connId>|<iss>|<sub> (prefixed, collision-proof)", r.principal.subject === oidcSubject("entra", ISSUER, "user-1") && r.principal.subject === `oidc:entra|${ISSUER}|user-1`);
    ok("  -> email + emailVerified surfaced", r.principal.email === "a@b.com" && r.principal.emailVerified === true);
    ok("  -> groups from the roles claim", JSON.stringify(r.principal.groups) === JSON.stringify(["admins"]));
    // V6.8.4: a plain happy path (no acr/amr/auth_time claims) surfaces NO advisory context (not a shell).
    ok("  -> no acr/amr/auth_time claims -> authContext undefined", r.principal.authContext === undefined);
  }
}
// 8b. completeOidcLogin V6.8.4: the IdP's ADVISORY acr/amr/auth_time surface on the principal, STRICTLY
// NON-GATING (they never change the resolved subject/email/groups).
{
  const AUTH_TIME = now - 60;
  const r = await completeOidcLogin(baseConn, EP, { code: "c", codeVerifier: "v", nonce: NONCE, redirectUri: REDIRECT, clientSecret: "sek" }, { doFetch: makeFetch({ idTokenClaims: idClaims({ acr: "urn:x:mfa", amr: ["pwd", "otp"], auth_time: AUTH_TIME, roles: ["admins"] }) }), getJwks }, now);
  ok("completeOidcLogin: advisory acr/amr/auth_time surface on principal.authContext", r.ok === true && r.ok && r.principal.authContext?.acr === "urn:x:mfa" && JSON.stringify(r.principal.authContext?.amr) === JSON.stringify(["pwd", "otp"]) && r.principal.authContext?.authTime === AUTH_TIME);
  // NON-GATING: identity + groups are UNCHANGED by the advisory being present (identical to the plain path).
  ok("completeOidcLogin: identity/groups unaffected by the advisory (non-gating)", r.ok === true && r.ok && r.principal.subject === oidcSubject("entra", ISSUER, "user-1") && r.principal.email === "a@b.com" && JSON.stringify(r.principal.groups) === JSON.stringify(["admins"]));
}
// 9. completeOidcLogin: a bad nonce is rejected (replay/injection)
{
  const r = await completeOidcLogin(baseConn, EP, { code: "c", codeVerifier: "v", nonce: "WRONG", redirectUri: REDIRECT, clientSecret: "sek" }, { doFetch: makeFetch(), getJwks }, now);
  ok("completeOidcLogin rejects an id_token whose nonce != the stored nonce", r.ok === false);
}
// 10. completeOidcLogin: an email_verified:false id_token still resolves but surfaces the flag
{
  const r = await completeOidcLogin(baseConn, EP, { code: "c", codeVerifier: "v", nonce: NONCE, redirectUri: REDIRECT, clientSecret: "sek" }, { doFetch: makeFetch({ idTokenClaims: idClaims({ email_verified: false }) }), getJwks }, now);
  ok("completeOidcLogin surfaces emailVerified:false (gates the pending-invite bind upstream)", r.ok === true && r.principal.emailVerified === false);
}

// 10b. completeOidcLogin ENFORCES hdDomain (DV-017): a verified sign-in outside the configured hosted domain
// is refused in the login flow; one inside it succeeds. (idClaims defaults email to a@b.com, domain b.com.)
{
  const outside = await completeOidcLogin({ ...baseConn, hdDomain: "example.com" }, EP, { code: "c", codeVerifier: "v", nonce: NONCE, redirectUri: REDIRECT, clientSecret: "sek" }, { doFetch: makeFetch({ idTokenClaims: idClaims() }), getJwks }, now);
  ok("completeOidcLogin REFUSES a verified sign-in outside the configured hd domain", outside.ok === false && outside.reason.includes("hosted domain"));
  const inside = await completeOidcLogin({ ...baseConn, hdDomain: "b.com" }, EP, { code: "c", codeVerifier: "v", nonce: NONCE, redirectUri: REDIRECT, clientSecret: "sek" }, { doFetch: makeFetch({ idTokenClaims: idClaims() }), getJwks }, now);
  ok("completeOidcLogin ALLOWS a verified sign-in inside the configured hd domain", inside.ok === true);
}

// 11. discoveryUrlFor: explicit discoveryUrl wins, else issuer + well-known suffix (with a single-slash join)
{
  ok("discoveryUrlFor returns the explicit discoveryUrl verbatim", discoveryUrlFor({ ...baseConn, discoveryUrl: "https://idp.example.com/custom/openid" }) === "https://idp.example.com/custom/openid");
  ok("discoveryUrlFor derives the well-known URL from a bare issuer", discoveryUrlFor(baseConn) === `${ISSUER}/.well-known/openid-configuration`);
  // A trailing slash on the issuer is stripped so the suffix is not double-slashed.
  ok("discoveryUrlFor strips a trailing slash before the well-known suffix", discoveryUrlFor({ ...baseConn, issuer: `${ISSUER}/` }) === `${ISSUER}/.well-known/openid-configuration`);
}

// 12. endpointsFromConnection: all three explicit endpoints present -> FlowEndpoints; any absent -> null
{
  const full = endpointsFromConnection({ ...baseConn, authorizationEndpoint: AUTH_URL, tokenEndpoint: TOKEN_URL, jwksUri: JWKS_URL });
  ok("endpointsFromConnection returns endpoints when all three are explicit", full !== null && full.tokenEndpoint === TOKEN_URL && full.jwksUri === JWKS_URL && full.authorizationEndpoint === AUTH_URL);
  ok("endpointsFromConnection returns null when the jwksUri is missing (must fall back to discovery)", endpointsFromConnection({ ...baseConn, authorizationEndpoint: AUTH_URL, tokenEndpoint: TOKEN_URL }) === null);
}

// 13. parseDiscovery: the remaining reject branches (null doc, array doc, empty issuer)
{
  ok("parseDiscovery rejects a null document", parseDiscovery(null, ISSUER).ok === false);
  ok("parseDiscovery rejects an array document", parseDiscovery([1, 2, 3], ISSUER).ok === false);
  ok("parseDiscovery rejects an empty-string issuer", parseDiscovery({ issuer: "", authorization_endpoint: AUTH_URL, token_endpoint: TOKEN_URL, jwks_uri: JWKS_URL }, "").ok === false);
}

// 14. buildAuthorizeUrl: a connection with NO hdDomain and NO extraAuthParams (the nullish-fallback path)
{
  const bare: OidcConnection = { ...baseConn };
  delete (bare as { hdDomain?: string }).hdDomain;
  delete (bare as { extraAuthParams?: Record<string, string> }).extraAuthParams;
  const url = new URL(buildAuthorizeUrl(bare, EP, { state: "ST", nonce: "NO", challenge: "CH", redirectUri: REDIRECT }));
  ok("buildAuthorizeUrl omits hd when no hdDomain is set", url.searchParams.has("hd") === false);
  ok("buildAuthorizeUrl tolerates an absent extraAuthParams (the ?? {} fallback) and still builds the core query", url.searchParams.get("response_type") === "code" && url.searchParams.get("client_id") === CLIENT);
}

// 15. guardedOidcFetch: a body-less response (204) yields an empty bodyText (the reader-undefined branch)
{
  const noBodyFetch = (async (): Promise<Response> => new Response(null, { status: 204 })) as typeof fetch;
  const resp = await guardedOidcFetch(JWKS_URL, { method: "GET" }, noBodyFetch);
  ok("guardedOidcFetch returns empty bodyText for a body-less response", resp.status === 204 && resp.bodyText === "");
}

// 16. fetchJwksGuarded: dedup-rejecting parser end to end (good set, duplicate kid, non-200, non-JSON, no keys array)
{
  const jwksFetch = (body: string, status = 200): typeof fetch =>
    (async (): Promise<Response> => new Response(body, { status, headers: { "content-type": "application/json" } })) as typeof fetch;
  const good = await fetchJwksGuarded(JWKS_URL, jwksFetch(JSON.stringify({ keys: [{ kid: "rsa-1", kty: "RSA", n: "n", e: "AQAB" }] })));
  ok("fetchJwksGuarded parses a well-formed JWKS", good.ok === true && good.jwks.keys.length === 1);
  // A keyless entry (no kty) is skipped; an entry with no kid is still kept (kty present); only DUPLICATE kids fail the set.
  const mixed = await fetchJwksGuarded(JWKS_URL, jwksFetch(JSON.stringify({ keys: [null, { foo: "bar" }, { kty: "RSA", n: "n", e: "AQAB" }, { kid: "k2", kty: "EC", crv: "P-256", x: "x", y: "y" }] })));
  ok("fetchJwksGuarded keeps typed keys and skips non-object / kty-less entries", mixed.ok === true && mixed.jwks.keys.length === 2);
  const dup = await fetchJwksGuarded(JWKS_URL, jwksFetch(JSON.stringify({ keys: [{ kid: "dup", kty: "RSA", n: "n", e: "AQAB" }, { kid: "dup", kty: "RSA", n: "m", e: "AQAB" }] })));
  ok("fetchJwksGuarded REJECTS a set carrying a duplicate kid (fail closed against a shadowing key)", dup.ok === false);
  ok("fetchJwksGuarded rejects a non-200 jwks response", (await fetchJwksGuarded(JWKS_URL, jwksFetch("{}", 503))).ok === false);
  ok("fetchJwksGuarded rejects a non-JSON jwks body", (await fetchJwksGuarded(JWKS_URL, jwksFetch("<html>not json", 200))).ok === false);
  ok("fetchJwksGuarded rejects a body with no keys array", (await fetchJwksGuarded(JWKS_URL, jwksFetch(JSON.stringify({ keys: "nope" }), 200))).ok === false);
  // A throwing transport (the fetch itself rejects) is mapped to a clean { ok:false } rather than propagating.
  const throwingFetch = (async (): Promise<Response> => {
    throw new Error("connection reset");
  }) as typeof fetch;
  ok("fetchJwksGuarded maps a thrown transport error to a clean failure", (await fetchJwksGuarded(JWKS_URL, throwingFetch)).ok === false);
  // A transport that throws a NON-Error value still resolves to a clean failure (the other ternary arm).
  const throwsNonError = (async (): Promise<Response> => {
    throw "reset";
  }) as typeof fetch;
  ok("fetchJwksGuarded maps a non-Error transport throw to a clean failure", (await fetchJwksGuarded(JWKS_URL, throwsNonError)).ok === false);
}

// 17. exchangeCode: the remaining client-auth and body-shape branches
{
  // client_secret_basic with NO resolved secret is refused (mirrors the client_secret_post guard).
  ok("client_secret_basic without a resolved secret is refused", (await exchangeCode({ ...baseConn, clientAuth: "client_secret_basic" }, EP, { code: "c", codeVerifier: "v", redirectUri: REDIRECT }, makeFetch())).ok === false);
  // private_key_jwt is not implemented in this build and fails closed before any network call.
  const pkj = await exchangeCode({ ...baseConn, clientAuth: "private_key_jwt" }, EP, { code: "c", codeVerifier: "v", redirectUri: REDIRECT }, makeFetch());
  ok("private_key_jwt client authentication is refused (not implemented in this build)", pkj.ok === false && pkj.reason.includes("private_key_jwt"));
  // A transport that throws a NON-Error value still resolves to a clean failure (the e instanceof Error else).
  const throwsString = (async (): Promise<Response> => {
    // Deliberately throw a bare string (not an Error) to drive the `e instanceof Error` else arm.
    throw "kaboom";
  }) as typeof fetch;
  ok("exchangeCode maps a non-Error transport throw to a clean failure", (await exchangeCode(baseConn, EP, { code: "c", codeVerifier: "v", redirectUri: REDIRECT, clientSecret: "s" }, throwsString)).ok === false);
  // And the Error arm of the same catch: a transport rejecting with a real Error surfaces its message.
  const throwsError = (async (): Promise<Response> => {
    throw new Error("dns failure");
  }) as typeof fetch;
  const exErr = await exchangeCode(baseConn, EP, { code: "c", codeVerifier: "v", redirectUri: REDIRECT, clientSecret: "s" }, throwsError);
  ok("exchangeCode surfaces a thrown Error message from the token fetch", exErr.ok === false && exErr.reason.includes("dns failure"));
  // A non-JSON token body is rejected.
  ok("exchangeCode rejects a non-JSON token body", (await exchangeCode(baseConn, EP, { code: "c", codeVerifier: "v", redirectUri: REDIRECT, clientSecret: "s" }, makeFetch({ rawBody: "<html>" }))).ok === false);
  // A token body that is valid JSON but the literal null is rejected (the json === null guard).
  ok("exchangeCode rejects a token body that is JSON null", (await exchangeCode(baseConn, EP, { code: "c", codeVerifier: "v", redirectUri: REDIRECT, clientSecret: "s" }, makeFetch({ rawBody: "null" }))).ok === false);
  // A successful exchange with an id_token but NO access_token omits accessToken from the result (the undefined branch).
  const noAt = await exchangeCode(baseConn, EP, { code: "c", codeVerifier: "v", redirectUri: REDIRECT, clientSecret: "s" }, makeFetch({ rawBody: JSON.stringify({ id_token: await signIdToken(idClaims()) }) }));
  ok("exchangeCode omits accessToken when the token response carries none", noAt.ok === true && noAt.tokens.accessToken === undefined && noAt.tokens.idToken.split(".").length === 3);
}

// 18. completeOidcLogin: Entra multitenant (issuerSubstitution 'tid') drives verifyOptionsFor's tid path
{
  const tidTemplate = "https://login.microsoftonline.com/{tenantid}/v2.0";
  const TENANT = "tenant-abc";
  const entraConn: OidcConnection = {
    ...baseConn,
    issuer: tidTemplate,
    issuerSubstitution: "tid",
    acceptedTenantIds: [TENANT],
    clientAuth: "pkce_public",
    secretRef: { mode: "pkce-public" },
    rolesClaim: "roles",
  };
  const tidIss = tidTemplate.replace("{tenantid}", TENANT);
  const tidClaims = idClaims({ iss: tidIss, tid: TENANT, roles: ["app-admin"] });
  const r = await completeOidcLogin(entraConn, EP, { code: "c", codeVerifier: "v", nonce: NONCE, redirectUri: REDIRECT }, { doFetch: makeFetch({ idTokenClaims: tidClaims }), getJwks }, now);
  ok("completeOidcLogin verifies an Entra multitenant token via the tid-substituted issuer (no client secret)", r.ok === true && r.ok && r.principal.issuer === tidIss && JSON.stringify(r.principal.groups) === JSON.stringify(["app-admin"]));
  // A tid connection with NO acceptedTenantIds drives verifyOptionsFor's `?? []` fallback to an EMPTY allowlist,
  // which then refuses the tid at verify time (fail closed), even though the issuer would otherwise substitute.
  const noAllowlist: OidcConnection = { ...entraConn };
  delete (noAllowlist as { acceptedTenantIds?: string[] }).acceptedTenantIds;
  const refused = await completeOidcLogin(noAllowlist, EP, { code: "c", codeVerifier: "v", nonce: NONCE, redirectUri: REDIRECT }, { doFetch: makeFetch({ idTokenClaims: tidClaims }), getJwks }, now);
  ok("completeOidcLogin fails closed for a tid connection with an empty tenant allowlist (the ?? [] fallback)", refused.ok === false);
}

// 19. completeOidcLogin: acceptIssuerVariants drives verifyOptionsFor's variants path (Google bare-form spelling)
{
  const variantConn: OidcConnection = { ...baseConn, issuer: "https://accounts.google.com", acceptIssuerVariants: ["accounts.google.com"] };
  // The token presents the BARE-host variant; verify must accept it via acceptIssuerVariants.
  const claims = idClaims({ iss: "accounts.google.com" });
  const r = await completeOidcLogin(variantConn, EP, { code: "c", codeVerifier: "v", nonce: NONCE, redirectUri: REDIRECT, clientSecret: "s" }, { doFetch: makeFetch({ idTokenClaims: claims }), getJwks }, now);
  ok("completeOidcLogin accepts an issuer-variant spelling (Google bare host) via acceptIssuerVariants", r.ok === true && r.ok && r.principal.issuer === "accounts.google.com");
}

// 20. completeOidcLogin: the precise sad paths (exchange fails, verify throws, no email, groups overflow)
{
  // Exchange failure short-circuits and returns the exchange reason verbatim (the !ex.ok branch).
  const exFail = await completeOidcLogin(baseConn, EP, { code: "c", codeVerifier: "v", nonce: NONCE, redirectUri: REDIRECT, clientSecret: "s" }, { doFetch: makeFetch({ status: 502 }), getJwks }, now);
  ok("completeOidcLogin returns the exchange failure when the token endpoint errors", exFail.ok === false && exFail.reason.includes("502"));
  // A getJwks that THROWS is caught and mapped to an id_token verification error (the try/catch branch).
  const jwksThrows = (_force: boolean): Promise<JWKS> => Promise.reject(new Error("jwks unavailable"));
  const verifyThrew = await completeOidcLogin(baseConn, EP, { code: "c", codeVerifier: "v", nonce: NONCE, redirectUri: REDIRECT, clientSecret: "s" }, { doFetch: makeFetch(), getJwks: jwksThrows }, now);
  ok("completeOidcLogin maps a thrown verification error to a clean failure", verifyThrew.ok === false && verifyThrew.reason.includes("verification error"));
  // The same catch's non-Error arm: getJwks rejecting with a bare string still yields a clean failure.
  const jwksThrowsString = (_force: boolean): Promise<JWKS> => Promise.reject("boom");
  const verifyThrewStr = await completeOidcLogin(baseConn, EP, { code: "c", codeVerifier: "v", nonce: NONCE, redirectUri: REDIRECT, clientSecret: "s" }, { doFetch: makeFetch(), getJwks: jwksThrowsString }, now);
  ok("completeOidcLogin maps a non-Error verification throw to a clean failure", verifyThrewStr.ok === false && verifyThrewStr.reason.includes("verification error"));
  // A verified token with NO email claim surfaces email:null (the ?? null branch) and no access_token in the flow.
  const noEmailClaims = idClaims();
  delete (noEmailClaims as { email?: string }).email;
  const noEmail = await completeOidcLogin(baseConn, EP, { code: "c", codeVerifier: "v", nonce: NONCE, redirectUri: REDIRECT, clientSecret: "s" }, { doFetch: makeFetch({ rawBody: JSON.stringify({ id_token: await signIdToken(noEmailClaims) }) }), getJwks }, now);
  ok("completeOidcLogin yields email:null when the id_token carries no email (and the response has no access_token)", noEmail.ok === true && noEmail.ok && noEmail.principal.email === null);
  // The Entra groups-overflow marker FAILS the whole login closed (rather than silently downgrading authorization).
  const overflowClaims = idClaims({ _claim_names: { groups: "src1" } });
  const overflow = await completeOidcLogin(baseConn, EP, { code: "c", codeVerifier: "v", nonce: NONCE, redirectUri: REDIRECT, clientSecret: "s" }, { doFetch: makeFetch({ idTokenClaims: overflowClaims }), getJwks }, now);
  ok("completeOidcLogin refuses a login whose groups claim overflowed (fails closed)", overflow.ok === false && overflow.reason.includes("withheld"));
}

// 21. extractGroups + boundGroups: the normalisation reject branches (non-object path step, non-string entry,
// blank/over-long entry, control char, dedup, the >GROUPS_MAX cap).
{
  // getByPath: a dotted path whose intermediate segment is a NON-object yields undefined -> [] (no groups).
  ok("extractGroups returns [] when a dotted path traverses a non-object intermediate", JSON.stringify((extractGroups({ ...baseConn, rolesClaim: "realm_access.roles" }, { realm_access: "not-an-object" }) as { groups: string[] }).groups) === "[]");
  // boundGroups skips a non-string array entry while keeping the valid ones.
  ok("extractGroups drops non-string group entries", JSON.stringify((extractGroups({ ...baseConn, rolesClaim: "roles" }, { roles: [123, "keep", null] }) as { groups: string[] }).groups) === JSON.stringify(["keep"]));
  // boundGroups drops a blank-after-trim entry and an over-long entry (> 256 chars).
  const longName = "x".repeat(257);
  ok("extractGroups drops blank and over-long group entries", JSON.stringify((extractGroups({ ...baseConn, rolesClaim: "roles" }, { roles: ["   ", longName, "ok"] }) as { groups: string[] }).groups) === JSON.stringify(["ok"]));
  // boundGroups drops an entry carrying an ASCII control character (here a TAB, 0x09).
  ok("extractGroups drops a group carrying a control character", JSON.stringify((extractGroups({ ...baseConn, rolesClaim: "roles" }, { roles: ["a\tb", "clean"] }) as { groups: string[] }).groups) === JSON.stringify(["clean"]));
  // boundGroups dedupes (first wins) so a repeated group appears once.
  ok("extractGroups dedupes repeated groups (first wins)", JSON.stringify((extractGroups({ ...baseConn, rolesClaim: "roles" }, { roles: ["dup", "dup", "other"] }) as { groups: string[] }).groups) === JSON.stringify(["dup", "other"]));
  // boundGroups caps the carried set at GROUPS_MAX (200): 250 distinct groups in -> exactly 200 out.
  const many: string[] = [];
  for (let i = 0; i < 250; i++) many.push(`g${i}`);
  const capped = extractGroups({ ...baseConn, rolesClaim: "roles" }, { roles: many }) as { groups: string[] };
  ok("extractGroups caps the carried groups at GROUPS_MAX (200)", capped.groups.length === 200 && capped.groups[0] === "g0" && capped.groups[199] === "g199");
}

// 8. enforceHostedDomain (DV-017): the Google Workspace hd restriction, enforced on the verified identity.
{
  const V = (extra: { email?: string; emailVerified?: boolean; hd?: string }): { email?: string; emailVerified: boolean; claims: Record<string, unknown> } => ({
    ...(extra.email !== undefined ? { email: extra.email } : {}),
    emailVerified: extra.emailVerified ?? false,
    claims: extra.hd !== undefined ? { hd: extra.hd } : {},
  });
  // No hdDomain configured: nothing to enforce, always null (a connection without it is unaffected).
  ok("no hdDomain -> not enforced (null)", enforceHostedDomain(baseConn, V({ email: "a@anywhere.com", emailVerified: true })) === null);
  const g = { ...baseConn, hdDomain: "example.com" };
  // The Google-signed hd claim in the domain passes, even without a verified email.
  ok("hd claim in domain -> allowed", enforceHostedDomain(g, V({ hd: "example.com" })) === null);
  ok("hd claim match is case-insensitive", enforceHostedDomain(g, V({ hd: "Example.COM" })) === null);
  // A verified email in the domain passes (provider without an hd claim).
  ok("verified email in domain -> allowed", enforceHostedDomain(g, V({ email: "user@example.com", emailVerified: true })) === null);
  // An UNVERIFIED email in the domain does NOT pass on the email path (fail-closed on an unverified signal).
  ok("unverified email in domain (no hd) -> refused", enforceHostedDomain(g, V({ email: "user@example.com", emailVerified: false })) !== null);
  // A verified email in a DIFFERENT domain is refused, and the reason names the configured domain.
  const wrong = enforceHostedDomain(g, V({ email: "user@evil.com", emailVerified: true }));
  ok("verified email in a different domain -> refused", wrong !== null && wrong.includes("example.com"));
  ok("the refusal names the offending domain, not the email (redaction-safe)", wrong !== null && wrong.includes("evil.com") && !wrong.includes("user@"));
  // An hd claim for a different domain is refused even if it is present.
  ok("hd claim for a different domain -> refused", enforceHostedDomain(g, V({ hd: "evil.com" })) !== null);
  // Neither signal present at all: refused (an unconfirmable domain must not satisfy a restriction).
  ok("no hd and no email -> refused (fail-closed)", enforceHostedDomain(g, V({})) !== null);

  // Lockout regression: a fat-fingered hdDomain must not refuse every legitimate in-domain sign-in. A trailing
  // dot, a leading "@", a pasted scheme or path all normalise to the bare domain and still ALLOW a real token.
  ok("hdDomain 'example.com.' (trailing dot) still ALLOWS an in-domain hd claim", enforceHostedDomain({ ...baseConn, hdDomain: "example.com." }, V({ hd: "example.com" })) === null);
  ok("hdDomain '@example.com' still ALLOWS an in-domain verified email", enforceHostedDomain({ ...baseConn, hdDomain: "@example.com" }, V({ email: "u@example.com", emailVerified: true })) === null);
  ok("hdDomain 'https://example.com/' still ALLOWS an in-domain hd claim", enforceHostedDomain({ ...baseConn, hdDomain: "https://example.com/" }, V({ hd: "example.com" })) === null);
  // The canonicalisation does NOT widen the gate: a subdomain is still refused under a decorated hdDomain.
  ok("normalisation does not open a subdomain bypass", enforceHostedDomain({ ...baseConn, hdDomain: "example.com." }, V({ hd: "evil.example.com" })) !== null);
  // Token-side path/scheme decoration must NOT collapse to the configured domain (the asymmetric-normalisation
  // bypass): a crafted "example.com/evil.com" in the hd claim or the email domain is refused, not allowed.
  ok("hd claim 'example.com/evil.com' is REFUSED (no token-side path strip)", enforceHostedDomain(g, V({ hd: "example.com/evil.com" })) !== null);
  ok("verified email '@example.com/evil.com' is REFUSED (no token-side path strip)", enforceHostedDomain(g, V({ email: "attacker@example.com/evil.com", emailVerified: true })) !== null);
  ok("hd claim 'https://example.com' (scheme) is REFUSED on the token side", enforceHostedDomain(g, V({ hd: "https://example.com" })) !== null);
  ok("hd claim 'example.com/.' is REFUSED", enforceHostedDomain(g, V({ hd: "example.com/." })) !== null);
  // A clean in-domain token with only a legitimate trailing root dot still ALLOWS (token-side dot strip is fine).
  ok("hd claim 'example.com.' (trailing root dot) still ALLOWS", enforceHostedDomain(g, V({ hd: "example.com." })) === null);
}

// 22. completeOidcLogin: Google hd (hosted-domain) gate is enforced end to end against the VERIFIED id_token
// claim (CR-03), including the hd_not_accepted code threaded through to the callback layer's auth signal
// - the outbound `hd` authorize param is a spoofable UI hint only, so a personal/other-domain Google account
// must be refused post-verification, not just steered away at the account chooser.
{
  const hdConn: OidcConnection = { ...baseConn, hdDomain: "example.com" };
  const wrongHd = await completeOidcLogin(hdConn, EP, { code: "c", codeVerifier: "v", nonce: NONCE, redirectUri: REDIRECT, clientSecret: "s" }, { doFetch: makeFetch({ idTokenClaims: idClaims({ hd: "attacker.example" }) }), getJwks }, now);
  ok("completeOidcLogin refuses a verified id_token whose hd claim != the connection's hdDomain", wrongHd.ok === false && wrongHd.code === "hd_not_accepted");
  // A plain consumer @gmail.com account's id_token carries NO hd claim at all - must be refused, not treated as a match.
  const noHd = await completeOidcLogin(hdConn, EP, { code: "c", codeVerifier: "v", nonce: NONCE, redirectUri: REDIRECT, clientSecret: "s" }, { doFetch: makeFetch({ idTokenClaims: idClaims() }), getJwks }, now);
  ok("completeOidcLogin refuses a verified id_token with NO hd claim (a personal Google account)", noHd.ok === false && noHd.code === "hd_not_accepted");
  // Case-insensitive: hdDomain is stored via a plain boundedStr with no lowercasing, Google's hd claim is lowercase.
  const caseConn: OidcConnection = { ...baseConn, hdDomain: "Example.COM" };
  const caseOk = await completeOidcLogin(caseConn, EP, { code: "c", codeVerifier: "v", nonce: NONCE, redirectUri: REDIRECT, clientSecret: "s" }, { doFetch: makeFetch({ idTokenClaims: idClaims({ hd: "example.com" }) }), getJwks }, now);
  ok("completeOidcLogin accepts a case-different hd match (operator casing vs Google's lowercase claim)", caseOk.ok === true);
  // A connection with no hdDomain configured (non-Google IdP, or a deliberately open Google connection) is unaffected.
  const noGate = await completeOidcLogin(baseConn, EP, { code: "c", codeVerifier: "v", nonce: NONCE, redirectUri: REDIRECT, clientSecret: "s" }, { doFetch: makeFetch({ idTokenClaims: idClaims() }), getJwks }, now);
  ok("completeOidcLogin does not gate on hd when the connection has no hdDomain configured", noGate.ok === true);
}

console.log("");
if (failures > 0) process.exitCode = 1;
if (failures > 0) {
  console.log(`OIDC FLOW VECTORS: ${failures} FAILED`);
  process.exit(1);
}
console.log("OIDC FLOW VECTORS PASS");
