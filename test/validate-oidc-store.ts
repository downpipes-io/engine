// Drive the DO-side OIDC store (src/admin/oidc-store.ts) over an INJECTED KvStorage mock (the same
// in-memory double validate-session.ts uses) and a stub IdP fetch with REAL signed id_tokens. This proves
// the store's storage discipline and the two flow orchestrators end to end, WITHOUT a real DO or network:
//   - createIdpConnection round-trips a connection through validateIdpConnection, stamps createdBy/createdAt,
//     persists it under idpconn:<id>, and returns a REDACTED view; a bad proposal returns its reason; an id
//     collision (against the existing-ids set the store derives from list) is refused;
//   - listIdpConnections returns REDACTED records; getIdpConnectionRaw returns the UNredacted record for the
//     flow; deleteIdpConnection removes BOTH idpconn:<id> and idpsecret:<id>; setIdpConnectionEnabled flips it;
//   - putIdpSecret/getIdpSecret/deleteIdpSecret are a write-only round trip under idpsecret:<id>;
//   - putOidcState then consumeOidcState returns the record ONCE (the second consume is null: delete-before-
//     return is the single-use guarantee in the single-threaded DO), and an expired record consumes to null;
//     sweepOidcStates drops expired records and keeps fresh ones;
//   - makeJwksGetter PINS the JWKS host: a discovery jwks_uri on a host != the issuer host is REFUSED, while a
//     connection-configured jwksUri (config-validated, trusted) is accepted even on a different host; the
//     closure caches and a force bypasses the cache;
//   - handleOidcStart mints state/nonce/pkce/txn, resolves endpoints, stores the state record, and returns an
//     authorize URL carrying the SAME state it stored;
//   - handleOidcCallback happy path consumes the stored state, exchanges the code, verifies the id_token and
//     returns the principal + the stored returnTo; a missing/consumed state is refused; a connId mismatch and a
//     txnId mismatch (login-CSRF) are refused; a 'secrets-store' secret mode is refused (not wired this build).
//   - resolveEndpoints PINS discovery-resolved authorization_endpoint/token_endpoint to the issuer host the
//     same way: a poisoned discovery document naming either on an attacker host is REFUSED, while a
//     connection-configured tokenEndpoint override (config-validated, trusted, e.g. Google's off-issuer-host
//     token endpoint) is actually used in place of the discovery value, not merely left unchecked.
// The negative controls are written so they would FAIL if the corresponding guard were removed.
// Run: node test/validate-oidc-store.ts
//
// Node 25 strip-types; Web Crypto only.

import {
  createIdpConnection,
  listIdpConnections,
  getIdpConnectionRaw,
  deleteIdpConnection,
  setIdpConnectionEnabled,
  putIdpSecret,
  getIdpSecret,
  deleteIdpSecret,
  putOidcState,
  consumeOidcState,
  sweepOidcStates,
  makeJwksGetter,
  handleOidcStart,
  handleOidcCallback,
} from "../src/admin/oidc-store.ts";
import type { OidcStateRecord } from "../src/admin/oidc-store.ts";
import { putSamlRequest, consumeSamlRequest, sweepSamlRequests } from "../src/admin/oidc-store.ts";
import { handleOauth2Start, handleOauth2Callback } from "../src/admin/oidc-store.ts";
import type { SamlRequestRecord } from "../src/admin/oidc-store.ts";
import type { IdpConnectionProposal, OidcConnection, Oauth2Connection } from "../src/admin/idpconn.ts";
import type { FlowEndpoints } from "../src/admin/oidc.ts";
import type { JWKS, JWK } from "../src/admin/oidc-verify.ts";
import { oidcSubject } from "../src/admin/identity.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// The injected KvStorage mock (the get/put/delete/list subset the store uses) is the shared
// test/mock-storage.ts double: it structurally satisfies KvStorage (src/admin/oidc-store-kv.ts) and
// additionally supports the array-of-keys batch get() form real DO storage carries, which this
// interface's callers never exercise.
import { MockStorage } from "./mock-storage.ts";

// ---- constants + the stub IdP (copied from validate-oidc.ts) -----------------------------------
const ISSUER = "https://idp.example.com";
const CLIENT = "downpipes-client";
const REDIRECT = "https://console.downpipes.io/admin/oidc/callback/entra";
const RETURN_TO = "/admin/whoami";
const TOKEN_URL = "https://idp.example.com/token";
const JWKS_URL = "https://idp.example.com/jwks";
const AUTH_URL = "https://idp.example.com/authorize";
const DISCOVERY_URL = "https://idp.example.com/.well-known/openid-configuration";
const nowSec = Math.floor(Date.now() / 1000);
const nowMs = Date.now();

// ---- base64url + RS256 id_token minting ----
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
// idClaims is parameterised by nonce so a callback vector can mint a token bound to the nonce the store
// actually stored (read out of the state record), the way a conformant IdP would echo it back.
function idClaims(nonce: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  return { iss: ISSUER, sub: "user-1", aud: CLIENT, nonce, exp: nowSec + 300, iat: nowSec, email: "a@b.com", email_verified: true, ...over };
}

// A stub fetch that serves discovery (so handleOidcStart can resolve endpoints when the connection carries
// none) and the token endpoint with a freshly-signed id_token bound to the per-request nonce. nonceFor lets
// the callback vector inject the nonce the store stored (it is read back from the state record by the test).
interface StubOpts {
  nonce?: string;
  status?: number;
  rawBody?: string;
  overClaims?: Record<string, unknown>;
}
let lastTokenReq: { url: string; init: RequestInit } | null = null;
// lastTokenRequest returns the token-endpoint request the stub fetch last captured, asserting one was made.
// lastTokenReq is only assigned inside the makeFetch closure, so straight-line flow narrows the bare variable
// to null at a read site; reading through this accessor restores the declared type and asserts the exchange ran.
function lastTokenRequest(): { url: string; init: RequestInit } {
  if (lastTokenReq === null) throw new Error("no token request was captured by the stub fetch");
  return lastTokenReq;
}
function makeFetch(opts: StubOpts = {}): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
    if (url === DISCOVERY_URL) {
      return new Response(JSON.stringify({ issuer: ISSUER, authorization_endpoint: AUTH_URL, token_endpoint: TOKEN_URL, jwks_uri: JWKS_URL }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (url === JWKS_URL) {
      return new Response(JSON.stringify({ keys: [jwk] }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (url === TOKEN_URL) {
      lastTokenReq = { url, init: init ?? {} };
      const status = opts.status ?? 200;
      const nonce = opts.nonce ?? "unused";
      const body = opts.rawBody ?? JSON.stringify({ id_token: await signIdToken(idClaims(nonce, opts.overClaims ?? {})), access_token: "at-value" });
      return new Response(body, { status, headers: { "content-type": "application/json" } });
    }
    throw new Error(`unexpected fetch in test: ${url}`);
  }) as typeof fetch;
}

// A valid OIDC connection proposal (the console shape) and the validated/stored connection we use for the
// flow vectors. do-plaintext secret mode (the floor) so the callback resolves the secret from idpsecret:<id>.
function proposal(over: Record<string, unknown> = {}): IdpConnectionProposal {
  return {
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
    ...over,
  };
}
// The stored connection for the flow vectors (mirrors the validated record, with explicit endpoints so a
// callback vector needs no discovery round trip; handleOidcStart vectors omit endpoints to exercise discovery).
const flowConn: OidcConnection = {
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
  authorizationEndpoint: AUTH_URL,
  tokenEndpoint: TOKEN_URL,
  jwksUri: JWKS_URL,
  createdBy: "owner@example.com",
  createdAt: "2026-06-13T00:00:00.000Z",
};
const EP: FlowEndpoints = { issuer: ISSUER, authorizationEndpoint: AUTH_URL, tokenEndpoint: TOKEN_URL, jwksUri: JWKS_URL };

// ---- the OAuth2 (no id_token, GitHub-class) flow scaffolding -----------------------------------
// handleOauth2Start / handleOauth2Callback drive a confidential or public OAuth2 provider through the SAME
// single-use state store, so we reuse MockStorage and add a GitHub-shaped connection + a stub provider fetch
// (the same endpoint shapes validate-oauth2.ts uses). There is no id_token and no discovery here: the
// authorize/token endpoints are explicit on the connection and trust is the TLS exchange plus the userinfo
// call. The stub answers the token, profile, email and membership endpoints so the REAL completeOauth2Login
// runs end to end. github.com / api.github.com pass the SSRF screen (a public, categorised host).
const GH_API = "https://api.github.com";
const GH_AUTHORIZE = "https://github.com/login/oauth/authorize";
const GH_TOKEN = "https://github.com/login/oauth/access_token";
const GH_PROFILE = "https://api.github.com/user";
const GH_EMAIL = "https://api.github.com/user/emails";
const GH_TEAMS = "https://api.github.com/user/teams";
const GH_ORGS = "https://api.github.com/user/orgs";
const GH_REDIRECT = "https://console.downpipes.io/admin/oauth2/callback/github";
const GH_CLIENT = "Iv1.github-client";
const GH_NUMERIC_ID = 583231; // octocat's immutable numeric id (a number on the wire)
const oauth2Conn: Oauth2Connection = {
  id: "github",
  kind: "oauth2",
  label: "GitHub",
  presetId: "github",
  enabled: true,
  authorizeUrl: GH_AUTHORIZE,
  tokenUrl: GH_TOKEN,
  tokenAuthStyle: "post_json",
  clientId: GH_CLIENT,
  secretRef: { mode: "do-plaintext" },
  scopes: ["read:user", "user:email", "read:org"],
  apiBase: GH_API,
  profileUrl: GH_PROFILE,
  subjectPath: "id",
  subjectPrefix: "github",
  emailUrl: GH_EMAIL,
  groupsUrls: [GH_TEAMS, GH_ORGS],
  pkce: "none",
  createdBy: "owner@example.com",
  createdAt: "2026-06-13T00:00:00.000Z",
};
// The stable subject + issuer the GitHub connection resolves to (issuer = subjectPrefix:apiBase).
const GH_EXPECT_ISSUER = `github:${GH_API}`;
const GH_EXPECT_SUBJECT = `oidc:github|${GH_EXPECT_ISSUER}|${GH_NUMERIC_ID}`;
let lastOauth2TokenReq: { url: string; init: RequestInit } | null = null;
// lastOauth2TokenRequest mirrors lastTokenRequest for the GitHub/OAuth2 stub: it asserts the exchange ran
// and restores the declared type past the closure-assignment null narrowing.
function lastOauth2TokenRequest(): { url: string; init: RequestInit } {
  if (lastOauth2TokenReq === null) throw new Error("no OAuth2 token request was captured by the stub fetch");
  return lastOauth2TokenReq;
}
function makeGhFetch(): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
    const json = (v: unknown): Response => new Response(JSON.stringify(v), { status: 200, headers: { "content-type": "application/json" } });
    if (url === GH_TOKEN) {
      lastOauth2TokenReq = { url, init: init ?? {} };
      return json({ access_token: "gho_opaque_token", token_type: "bearer", scope: "read:user,user:email" });
    }
    if (url === GH_PROFILE) return json({ id: GH_NUMERIC_ID, login: "octocat", name: "The Octocat" });
    if (url === GH_EMAIL) return json([{ email: "octocat@github.com", primary: true, verified: true }]);
    if (url === GH_TEAMS) return json([{ slug: "engineers", organization: { login: "acme" } }]);
    if (url === GH_ORGS) return json([{ login: "acme" }]);
    throw new Error(`unexpected fetch in test: ${url}`);
  }) as typeof fetch;
}

// Each numbered section is its own async function so a failure's section is obvious and no single
// function breaches the length limit. run() calls them in order. Every section
// scopes its own MockStorage, so they share no mutable state.

// 1. CRUD round-trip + redaction + id collision.
async function testCrudRoundTrip(): Promise<void> {
  {
    const storage = new MockStorage();
    const created = await createIdpConnection(storage, proposal(), "owner@example.com", "2026-06-13T01:00:00.000Z");
    ok("createIdpConnection accepts a valid proposal", created.ok === true);
    if (created.ok) {
      ok("  -> stamps createdBy + createdAt", created.conn.createdBy === "owner@example.com" && created.conn.createdAt === "2026-06-13T01:00:00.000Z");
      ok("  -> returns the OIDC kind redacted (secretRef is {mode} only)", created.conn.kind === "oidc" && JSON.stringify((created.conn as OidcConnection).secretRef) === JSON.stringify({ mode: "do-plaintext" }));
    }
    ok("the connection persisted under idpconn:<id>", storage.has("idpconn:entra") && storage.countPrefix("idpconn:") === 1);

    // A bad proposal returns the validator's reason (no openid scope), and nothing is stored.
    const bad = await createIdpConnection(storage, proposal({ id: "bad", scopes: ["email"] }), null, "2026-06-13T01:00:00.000Z");
    ok("createIdpConnection rejects a proposal that fails validation (returns the reason)", bad.ok === false && typeof bad.reason === "string" && bad.reason.includes("openid"));
    ok("  -> the rejected proposal was NOT stored", !storage.has("idpconn:bad"));

    // An id COLLISION (same id as the already-stored one) is refused against the existing-ids set the store
    // derives by LISTING the stored connections (so the rule comes from the live store, not the caller).
    const dup = await createIdpConnection(storage, proposal(), "owner@example.com", "2026-06-13T02:00:00.000Z");
    ok("createIdpConnection refuses an id collision against the live store", dup.ok === false && /already exists/.test(dup.ok === false ? dup.reason : ""));

    // A second, distinct connection so list has two.
    await createIdpConnection(storage, proposal({ id: "okta", label: "Okta", presetId: "okta" }), "owner@example.com", "2026-06-13T03:00:00.000Z");
    const list = await listIdpConnections(storage);
    ok("listIdpConnections returns every stored connection", list.length === 2 && list.some((c) => c.id === "entra") && list.some((c) => c.id === "okta"));
    ok("listIdpConnections returns REDACTED records (secretRef is {mode} only)", list.every((c) => c.kind !== "oidc" || JSON.stringify((c as OidcConnection).secretRef) === JSON.stringify({ mode: "do-plaintext" })));

    // getIdpConnectionRaw returns the UNredacted stored record (it is the flow's source of truth). The
    // record never holds a secret VALUE anyway, but it is the authoritative read for the callback.
    const raw = await getIdpConnectionRaw(storage, "entra");
    ok("getIdpConnectionRaw returns the stored connection", raw !== undefined && raw.id === "entra" && raw.kind === "oidc");
    ok("getIdpConnectionRaw returns undefined for an unknown id", (await getIdpConnectionRaw(storage, "nope")) === undefined);

    // setIdpConnectionEnabled flips the stored flag (disable then re-enable).
    const dis = await setIdpConnectionEnabled(storage, "entra", false);
    ok("setIdpConnectionEnabled disables a connection", dis === true && (await getIdpConnectionRaw(storage, "entra"))?.enabled === false);
    ok("setIdpConnectionEnabled on an unknown id returns false", (await setIdpConnectionEnabled(storage, "nope", false)) === false);
    await setIdpConnectionEnabled(storage, "entra", true);

    // deleteIdpConnection removes BOTH the connection and its secret entry.
    await putIdpSecret(storage, "okta", "okta-secret");
    ok("a secret was stored for okta", storage.has("idpsecret:okta"));
    const del = await deleteIdpConnection(storage, "okta");
    ok("deleteIdpConnection removes the connection record", del === true && !storage.has("idpconn:okta"));
    ok("deleteIdpConnection also removes the paired secret (idpsecret:<id>)", !storage.has("idpsecret:okta"));
  }
}

// 2. The write-only secret entry: put / get (internal) / delete round trip under idpsecret:<id>.
async function testSecretRoundTrip(): Promise<void> {
  {
    const storage = new MockStorage();
    await putIdpSecret(storage, "entra", "the-client-secret");
    ok("getIdpSecret reads back the stored secret (internal-only, for the flow)", (await getIdpSecret(storage, "entra")) === "the-client-secret");
    ok("the secret is keyed under idpsecret:<id>", storage.has("idpsecret:entra"));
    ok("getIdpSecret returns undefined for an id with no stored secret", (await getIdpSecret(storage, "okta")) === undefined);
    const overwritten = await putIdpSecret(storage, "entra", "rotated-secret");
    void overwritten;
    ok("putIdpSecret overwrites (rotation)", (await getIdpSecret(storage, "entra")) === "rotated-secret");
    await deleteIdpSecret(storage, "entra");
    ok("deleteIdpSecret removes the secret entry", !storage.has("idpsecret:entra") && (await getIdpSecret(storage, "entra")) === undefined);
  }
}

// 3. State single-use (consume-twice -> 2nd null) + TTL expiry + sweep.
async function testStateSingleUse(): Promise<void> {
  {
    const storage = new MockStorage();
    const record: OidcStateRecord = { connId: "entra", codeVerifier: "verifier-1", nonce: "nonce-1", redirectUri: REDIRECT, returnTo: RETURN_TO, txnId: "txn-1", createdAt: nowMs };
    await putOidcState(storage, "state-1", record);
    ok("putOidcState persists under oidcstate:<state>", storage.has("oidcstate:state-1") && storage.countPrefix("oidcstate:") === 1);

    const first = await consumeOidcState(storage, "state-1", nowMs, 600000);
    ok("consumeOidcState returns the record on first use", first !== null && first.connId === "entra" && first.codeVerifier === "verifier-1" && first.nonce === "nonce-1" && first.txnId === "txn-1" && first.returnTo === RETURN_TO);
    ok("  -> the record is DELETED on consume (single-use: delete-before-return)", !storage.has("oidcstate:state-1"));
    const second = await consumeOidcState(storage, "state-1", nowMs, 600000);
    ok("consumeOidcState returns null on the SECOND use (replay refused)", second === null);

    // TTL: a record older than the ttl consumes to null (and is still deleted, so a stale record cannot be
    // retried later by waiting out a clock change).
    const stale: OidcStateRecord = { connId: "entra", codeVerifier: "v", nonce: "n", redirectUri: REDIRECT, returnTo: RETURN_TO, txnId: "t", createdAt: nowMs - 700000 };
    await putOidcState(storage, "state-stale", stale);
    const expired = await consumeOidcState(storage, "state-stale", nowMs, 600000);
    ok("consumeOidcState returns null for a record past its TTL", expired === null);
    ok("  -> the expired record is deleted by the consume (no later retry)", !storage.has("oidcstate:state-stale"));

    // consume of a never-stored state is null.
    ok("consumeOidcState returns null for an unknown state", (await consumeOidcState(storage, "ghost", nowMs, 600000)) === null);

    // sweepOidcStates: drop the expired, keep the fresh.
    await putOidcState(storage, "fresh", { connId: "entra", codeVerifier: "v", nonce: "n", redirectUri: REDIRECT, returnTo: RETURN_TO, txnId: "t", createdAt: nowMs });
    await putOidcState(storage, "old", { connId: "entra", codeVerifier: "v", nonce: "n", redirectUri: REDIRECT, returnTo: RETURN_TO, txnId: "t", createdAt: nowMs - 700000 });
    const swept = await sweepOidcStates(storage, nowMs, 600000);
    ok("sweepOidcStates removes the expired state and reports the count", swept === 1 && !storage.has("oidcstate:old"));
    ok("sweepOidcStates keeps a fresh state", storage.has("oidcstate:fresh"));
  }
}

// 4. makeJwksGetter: PIN the JWKS host to the issuer host (reject a mismatch), accept a config-
//    validated connection jwksUri on a different host, cache, and force-bypass the cache.
async function testJwksGetter(): Promise<void> {
  {
    // (a) Discovery jwks_uri on a DIFFERENT host than the issuer, and the connection carries NO explicit
    //     jwksUri: the getter MUST refuse (the discovery-supplied host is not trusted past the issuer host).
    const connNoJwks: OidcConnection = { ...flowConn };
    delete (connNoJwks as Partial<OidcConnection>).jwksUri;
    const epEvil: FlowEndpoints = { ...EP, jwksUri: "https://evil.example.com/jwks" };
    const getterEvil = makeJwksGetter(connNoJwks, epEvil, makeFetch());
    let rejected = false;
    try {
      await getterEvil(false);
    } catch {
      rejected = true;
    }
    ok("makeJwksGetter REJECTS a discovery jwks_uri whose host != the issuer host", rejected);

    // (b) Discovery jwks_uri on the SAME host as the issuer: accepted, and a real JWKS comes back.
    const epSame: FlowEndpoints = { ...EP, jwksUri: JWKS_URL };
    const getterSame = makeJwksGetter(connNoJwks, epSame, makeFetch());
    const jwksSame = await getterSame(false);
    ok("makeJwksGetter accepts a discovery jwks_uri on the issuer host", jwksSame.keys.length === 1 && jwksSame.keys[0]?.kid === "rsa-1");

    // (c) The connection carries an EXPLICIT, config-validated jwksUri on a DIFFERENT host (a real provider
    //     legitimately serves its JWKS off-issuer, e.g. Google). Because it was validated at config time it is
    //     TRUSTED: the getter uses it even though the host differs from the issuer. The stub serves JWKS_URL,
    //     so point the connection jwksUri at JWKS_URL while the issuer host stays idp.example.com; the host
    //     differs only conceptually here (both are idp.example.com), so use a distinct host the stub knows.
    //     We make the stub answer a googleapis-style host to prove the off-issuer trusted path is taken.
    const OFFHOST_JWKS = "https://www.googleapis.com/oauth2/v3/certs";
    const offFetch = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (url === OFFHOST_JWKS) return new Response(JSON.stringify({ keys: [jwk] }), { status: 200, headers: { "content-type": "application/json" } });
      throw new Error(`unexpected fetch: ${url}`);
    }) as typeof fetch;
    const connOffJwks: OidcConnection = { ...flowConn, jwksUri: OFFHOST_JWKS };
    const epOff: FlowEndpoints = { ...EP, jwksUri: OFFHOST_JWKS };
    const getterOff = makeJwksGetter(connOffJwks, epOff, offFetch);
    const jwksOff = await getterOff(false);
    ok("makeJwksGetter trusts a config-validated connection jwksUri on a DIFFERENT host", jwksOff.keys.length === 1 && jwksOff.keys[0]?.kid === "rsa-1");

    // (d) Caching: a getter over a fetch that counts calls serves the cache on the second non-force call and
    //     refetches on a force call.
    let calls = 0;
    const countingFetch = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (url === JWKS_URL) {
        calls++;
        return new Response(JSON.stringify({ keys: [jwk] }), { status: 200, headers: { "content-type": "application/json" } });
      }
      throw new Error(`unexpected fetch: ${url}`);
    }) as typeof fetch;
    const getterCache = makeJwksGetter(connNoJwks, epSame, countingFetch);
    await getterCache(false);
    await getterCache(false);
    ok("makeJwksGetter caches (a second non-force call does NOT refetch)", calls === 1);
    await getterCache(true);
    ok("makeJwksGetter force-refetches (force bypasses the cache)", calls === 2);

    // (e) The host-pin URL parse is defensive: when the connection carries NO explicit jwksUri and the
    //     discovery-resolved ep.jwksUri is not a parseable URL, new URL(...) throws and the getter surfaces the
    //     pin error (rather than fetching a garbage URL). A throwing fetch proves no fetch was even attempted.
    const epBadUrl: FlowEndpoints = { ...EP, jwksUri: "not-a-valid-url" };
    let pinThrew = false;
    let pinReason = "";
    const neverFetch = (async (): Promise<Response> => {
      throw new Error("fetch must not be reached when the jwks_uri fails to parse");
    }) as typeof fetch;
    const getterBadUrl = makeJwksGetter(connNoJwks, epBadUrl, neverFetch);
    try {
      await getterBadUrl(false);
    } catch (e) {
      pinThrew = true;
      pinReason = e instanceof Error ? e.message : "";
    }
    ok("makeJwksGetter throws the host-pin error when the discovery jwks_uri is not a valid URL", pinThrew && /jwks-host pin: the jwks_uri or issuer is not a valid URL/.test(pinReason));

    // (f) The pinned-and-trusted host passes, but the JWKS fetch itself FAILS (a non-200): fetchJwksGuarded
    //     returns not-ok and the getter throws "jwks fetch failed" (it never caches a failed fetch).
    let jwksThrew = false;
    let jwksReason = "";
    const failJwksFetch = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (url === JWKS_URL) return new Response("upstream down", { status: 503, headers: { "content-type": "text/plain" } });
      throw new Error(`unexpected fetch: ${url}`);
    }) as typeof fetch;
    const getterFail = makeJwksGetter(connNoJwks, epSame, failJwksFetch);
    try {
      await getterFail(false);
    } catch (e) {
      jwksThrew = true;
      jwksReason = e instanceof Error ? e.message : "";
    }
    ok("makeJwksGetter throws when the JWKS fetch fails (non-200)", jwksThrew && /jwks fetch failed/.test(jwksReason));
  }
}

// 5. handleOidcStart: mint state/nonce/pkce/txn, resolve endpoints (here via DISCOVERY, since the
//    connection carries none), store the state record, and return an authorize URL with that state.
async function testHandleOidcStart(): Promise<void> {
  {
    const storage = new MockStorage();
    // A connection with NO explicit endpoints so start must fetch + parse discovery.
    const connDisc: OidcConnection = { ...flowConn };
    delete (connDisc as Partial<OidcConnection>).authorizationEndpoint;
    delete (connDisc as Partial<OidcConnection>).tokenEndpoint;
    delete (connDisc as Partial<OidcConnection>).jwksUri;
    const started = await handleOidcStart(storage, connDisc, REDIRECT, RETURN_TO, makeFetch(), nowMs);
    ok("handleOidcStart succeeds (resolving endpoints via discovery)", started.ok === true);
    if (started.ok) {
      const url = new URL(started.authorizeUrl);
      ok("  -> the authorize URL targets the discovered authorization_endpoint", `${url.origin}${url.pathname}` === AUTH_URL);
      ok("  -> the authorize URL carries response_type=code + the client_id", url.searchParams.get("response_type") === "code" && url.searchParams.get("client_id") === CLIENT);
      ok("  -> the authorize URL's state EQUALS the returned state", url.searchParams.get("state") === started.state);
      ok("  -> the authorize URL carries the redirect_uri + an S256 PKCE challenge", url.searchParams.get("redirect_uri") === REDIRECT && url.searchParams.get("code_challenge_method") === "S256" && (url.searchParams.get("code_challenge") ?? "").length > 0);
      ok("  -> a txnId was returned (the login-CSRF cookie binding)", typeof started.txnId === "string" && started.txnId.length >= 22);
      // The state record was stored under oidcstate:<state> and binds the connId + the SAME nonce the
      // authorize URL carries (so the IdP echo will match) + the returnTo.
      const stored = await storage.get<OidcStateRecord>(`oidcstate:${started.state}`);
      ok("  -> a state record was persisted under oidcstate:<state>", stored !== undefined && stored.connId === "entra" && stored.returnTo === RETURN_TO && stored.redirectUri === REDIRECT && stored.txnId === started.txnId);
      ok("  -> the stored nonce matches the authorize URL nonce (id_token replay bind)", stored !== undefined && stored.nonce === url.searchParams.get("nonce"));
      ok("  -> the stored codeVerifier hashes to the authorize URL's S256 challenge", stored !== undefined && stored.codeVerifier !== undefined && b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(stored.codeVerifier)))) === url.searchParams.get("code_challenge"));
    }

    // resolveEndpoints discovery FAILURE paths (driven through handleOidcStart, which calls resolveEndpoints).
    // A connection with no explicit endpoints must resolve via discovery; we make discovery fail two ways.
    const connDisc2: OidcConnection = { ...flowConn };
    delete (connDisc2 as Partial<OidcConnection>).authorizationEndpoint;
    delete (connDisc2 as Partial<OidcConnection>).tokenEndpoint;
    delete (connDisc2 as Partial<OidcConnection>).jwksUri;

    // (a) The discovery fetch THROWS (a transport error): start returns the wrapped reason and stores no state.
    const storeThrow = new MockStorage();
    const throwFetch = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (url === DISCOVERY_URL) throw new Error("connection reset");
      throw new Error(`unexpected fetch: ${url}`);
    }) as typeof fetch;
    const discThrew = await handleOidcStart(storeThrow, connDisc2, REDIRECT, RETURN_TO, throwFetch, nowMs);
    ok("handleOidcStart surfaces a discovery fetch transport failure", discThrew.ok === false && /discovery fetch failed/.test(discThrew.ok === false ? discThrew.reason : ""));
    ok("  -> and no orphaned state was stored on a failed start", storeThrow.countPrefix("oidcstate:") === 0);

    // (a2) The discovery fetch throws a NON-Error value (a thrown string): the reason ternary's else arm is
    //      taken, surfacing the generic "error" tail rather than a message. This drives the defensive non-Error
    //      branch of the catch (a hostile/odd injected fetch could reject with a non-Error).
    const storeThrowStr = new MockStorage();
    const throwStrFetch = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      // Reject with a non-Error value on purpose to drive the catch's else arm (the false branch of the
      // `e instanceof Error` reason ternary); a conformant fetch throws an Error, this proves the fallback.
      if (url === DISCOVERY_URL) return Promise.reject("not-an-error-object");
      throw new Error(`unexpected fetch: ${url}`);
    }) as typeof fetch;
    const discThrewStr = await handleOidcStart(storeThrowStr, connDisc2, REDIRECT, RETURN_TO, throwStrFetch, nowMs);
    ok("handleOidcStart surfaces a non-Error discovery throw via the generic reason tail", discThrewStr.ok === false && /discovery fetch failed: error/.test(discThrewStr.ok === false ? discThrewStr.reason : ""));

    // (b) Discovery returns 200 with a NON-JSON body: start returns the "not JSON" reason.
    const storeBad = new MockStorage();
    const nonJsonFetch = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (url === DISCOVERY_URL) return new Response("<html>not json</html>", { status: 200, headers: { "content-type": "text/html" } });
      throw new Error(`unexpected fetch: ${url}`);
    }) as typeof fetch;
    const discBad = await handleOidcStart(storeBad, connDisc2, REDIRECT, RETURN_TO, nonJsonFetch, nowMs);
    ok("handleOidcStart surfaces a non-JSON discovery document", discBad.ok === false && /not JSON/.test(discBad.ok === false ? discBad.reason : ""));

    // (c) Discovery returns a non-200 status: start surfaces the status code.
    const storeStatus = new MockStorage();
    const status500Fetch = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (url === DISCOVERY_URL) return new Response("upstream error", { status: 503, headers: { "content-type": "text/plain" } });
      throw new Error(`unexpected fetch: ${url}`);
    }) as typeof fetch;
    const discStatus = await handleOidcStart(storeStatus, connDisc2, REDIRECT, RETURN_TO, status500Fetch, nowMs);
    ok("handleOidcStart surfaces a non-200 discovery status", discStatus.ok === false && /returned 503/.test(discStatus.ok === false ? discStatus.reason : ""));

    // (d) Discovery returns valid JSON but parseDiscovery REJECTS it (the doc's issuer does not match the
    //     connection issuer): start surfaces parseDiscovery's reason. This drives the resolveEndpoints arm that
    //     forwards a parse failure (the discovery-trust bind: a doc claiming a different issuer is refused).
    const storeWrongIss = new MockStorage();
    const wrongIssFetch = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (url === DISCOVERY_URL) {
        return new Response(JSON.stringify({ issuer: "https://someone-else.example.com", authorization_endpoint: AUTH_URL, token_endpoint: TOKEN_URL, jwks_uri: JWKS_URL }), { status: 200, headers: { "content-type": "application/json" } });
      }
      throw new Error(`unexpected fetch: ${url}`);
    }) as typeof fetch;
    const discWrongIss = await handleOidcStart(storeWrongIss, connDisc2, REDIRECT, RETURN_TO, wrongIssFetch, nowMs);
    ok("handleOidcStart surfaces a discovery document whose issuer does not match the connection", discWrongIss.ok === false && typeof (discWrongIss.ok === false ? discWrongIss.reason : "") === "string" && (discWrongIss.ok === false ? discWrongIss.reason : "").length > 0);
    ok("  -> and a rejected discovery document leaves no orphaned state", storeWrongIss.countPrefix("oidcstate:") === 0);
  }
}

// 6. handleOidcCallback: happy path. Start (storing the state), read the stored nonce, mint a token
//    bound to it, then drive the callback through the REAL completeOidcLogin -> principal + returnTo.
async function testHandleOidcCallbackHappy(): Promise<void> {
  {
    const storage = new MockStorage();
    await putIdpSecret(storage, "entra", "the-secret"); // do-plaintext: resolved at the callback
    const started = await handleOidcStart(storage, flowConn, REDIRECT, RETURN_TO, makeFetch(), nowMs);
    ok("callback setup: start stored a state", started.ok === true);
    if (started.ok) {
      const stored = await storage.get<OidcStateRecord>(`oidcstate:${started.state}`);
      const nonce = stored!.nonce ?? "";
      const getConn = async (id: string): Promise<OidcConnection | undefined> => (id === "entra" ? flowConn : undefined);
      const cb = await handleOidcCallback(
        storage,
        { connId: "entra", code: "the-code", state: started.state, txnId: started.txnId },
        getConn,
        makeFetch({ nonce, overClaims: { roles: ["admins"] } }),
        nowMs,
      );
      ok("handleOidcCallback succeeds and returns the principal + returnTo", cb.ok === true);
      if (cb.ok) {
        ok("  -> the principal subject is oidc:<connId>|<iss>|<sub>", cb.principal.subject === oidcSubject("entra", ISSUER, "user-1"));
        ok("  -> email + emailVerified surfaced", cb.principal.email === "a@b.com" && cb.principal.emailVerified === true);
        ok("  -> groups from the roles claim", JSON.stringify(cb.principal.groups) === JSON.stringify(["admins"]));
        ok("  -> returnTo is the stored returnTo", cb.returnTo === RETURN_TO);
      }
      // The token POST carried the client secret resolved from idpsecret:<id> (do-plaintext), proving the
      // store resolved it just-in-time and passed it to the exchange.
      const sentBody = new URLSearchParams((lastTokenRequest().init.body as string) ?? "");
      ok("  -> the do-plaintext secret was resolved and sent in the token exchange", sentBody.get("client_secret") === "the-secret");
      // The state record is gone (consumed), so a replay of the SAME callback now fails.
      ok("  -> the state was consumed (the record is deleted)", !storage.has(`oidcstate:${started.state}`));
      const replay = await handleOidcCallback(storage, { connId: "entra", code: "the-code", state: started.state, txnId: started.txnId }, getConn, makeFetch({ nonce }), nowMs);
      ok("  -> a replay of the consumed callback is refused", replay.ok === false);
    }
  }
}

// 7. handleOidcCallback negative controls: missing state, connId mismatch, txnId mismatch (login-CSRF),
//    and the not-wired 'secrets-store' secret mode.
async function testHandleOidcCallbackNegative(): Promise<void> {
  {
    const storage = new MockStorage();
    await putIdpSecret(storage, "entra", "the-secret");
    const getConn = async (id: string): Promise<OidcConnection | undefined> => (id === "entra" ? flowConn : undefined);

    // (a) A state that was never stored -> refused (the single-use guarantee covers "no such state" too).
    const missing = await handleOidcCallback(storage, { connId: "entra", code: "c", state: "never-stored", txnId: "t" }, getConn, makeFetch(), nowMs);
    ok("handleOidcCallback refuses a missing/unknown state", missing.ok === false);

    // (b) connId mismatch: the callback claims a different connId than the state record bound.
    const s1 = await handleOidcStart(storage, flowConn, REDIRECT, RETURN_TO, makeFetch(), nowMs);
    if (s1.ok) {
      const stored = await storage.get<OidcStateRecord>(`oidcstate:${s1.state}`);
      const otherConnGetter = async (id: string): Promise<OidcConnection | undefined> => (id === "entra" || id === "okta" ? { ...flowConn, id } : undefined);
      const mism = await handleOidcCallback(storage, { connId: "okta", code: "c", state: s1.state, txnId: s1.txnId }, otherConnGetter, makeFetch({ nonce: stored!.nonce ?? "" }), nowMs);
      ok("handleOidcCallback refuses a connId that does not match the state record", mism.ok === false);
      ok("  -> and it still consumed the state (a tampered callback cannot be retried)", !storage.has(`oidcstate:${s1.state}`));
    }

    // (c) txnId mismatch (login-CSRF): the callback's txnId (from the cookie) does not match the record's.
    //     The txnId is compared in constant time via crypto.subtle.timingSafeEqual; the wrapper must
    //     short-circuit a length mismatch and return false rather than letting the primitive throw.
    const s2 = await handleOidcStart(storage, flowConn, REDIRECT, RETURN_TO, makeFetch(), nowMs);
    if (s2.ok) {
      const stored = await storage.get<OidcStateRecord>(`oidcstate:${s2.state}`);
      // A length-mismatched txnId (the real one is >=22 base64url chars): exercises the length guard.
      const wrongTxn = await handleOidcCallback(storage, { connId: "entra", code: "c", state: s2.state, txnId: "attacker-txn" }, getConn, makeFetch({ nonce: stored!.nonce ?? "" }), nowMs);
      ok("handleOidcCallback refuses a length-mismatched txnId without throwing (login-CSRF)", wrongTxn.ok === false && /login CSRF/.test(wrongTxn.ok === false ? wrongTxn.reason : ""));
    }
    // (c2) An EQUAL-LENGTH but different txnId: the constant-time path runs end to end and still refuses.
    const s2b = await handleOidcStart(storage, flowConn, REDIRECT, RETURN_TO, makeFetch(), nowMs);
    if (s2b.ok) {
      const stored = await storage.get<OidcStateRecord>(`oidcstate:${s2b.state}`);
      const sameLenWrong = s2b.txnId.slice(0, -1) + (s2b.txnId.endsWith("A") ? "B" : "A");
      const wrongTxn2 = await handleOidcCallback(storage, { connId: "entra", code: "c", state: s2b.state, txnId: sameLenWrong }, getConn, makeFetch({ nonce: stored!.nonce ?? "" }), nowMs);
      ok("handleOidcCallback refuses an equal-length but different txnId (login-CSRF)", wrongTxn2.ok === false && /login CSRF/.test(wrongTxn2.ok === false ? wrongTxn2.reason : ""));
    }

    // (d) A 'secrets-store' secret mode is not wired in this build: the callback refuses with that reason
    //     (it does not try to fetch a secret it cannot resolve).
    const ssConn: OidcConnection = { ...flowConn, secretRef: { mode: "secrets-store", ref: "DP_OIDC_SECRET" } };
    const ssGetter = async (id: string): Promise<OidcConnection | undefined> => (id === "entra" ? ssConn : undefined);
    const s3 = await handleOidcStart(storage, ssConn, REDIRECT, RETURN_TO, makeFetch(), nowMs);
    if (s3.ok) {
      const stored = await storage.get<OidcStateRecord>(`oidcstate:${s3.state}`);
      const ss = await handleOidcCallback(storage, { connId: "entra", code: "c", state: s3.state, txnId: s3.txnId }, ssGetter, makeFetch({ nonce: stored!.nonce ?? "" }), nowMs);
      ok("handleOidcCallback refuses a 'secrets-store' secret mode (not wired this build)", ss.ok === false && /secrets-store/.test(ss.ok === false ? ss.reason : ""));
    }

    // (e) ENABLED gate: handleOidcStart refuses a DISABLED connection (before any network/state work).
    const disabledConn: OidcConnection = { ...flowConn, enabled: false };
    const disStart = await handleOidcStart(storage, disabledConn, REDIRECT, RETURN_TO, makeFetch(), nowMs);
    ok("handleOidcStart refuses a disabled connection", disStart.ok === false && /disabled/.test(disStart.ok === false ? disStart.reason : ""));

    // (f) ENABLED gate: a connection DISABLED between /start and /callback cannot mint a session, and the
    //     state is still consumed (the disable cannot be bypassed by retrying the callback).
    const s5 = await handleOidcStart(storage, flowConn, REDIRECT, RETURN_TO, makeFetch(), nowMs);
    if (s5.ok) {
      const stored = await storage.get<OidcStateRecord>(`oidcstate:${s5.state}`);
      const disabledGetter = async (id: string): Promise<OidcConnection | undefined> => (id === "entra" ? { ...flowConn, enabled: false } : undefined);
      const cbDisabled = await handleOidcCallback(storage, { connId: "entra", code: "c", state: s5.state, txnId: s5.txnId }, disabledGetter, makeFetch({ nonce: stored!.nonce ?? "" }), nowMs);
      ok("handleOidcCallback refuses a connection disabled mid-flight", cbDisabled.ok === false && /disabled/.test(cbDisabled.ok === false ? cbDisabled.reason : ""));
      ok("  -> and the state was still consumed (no retry)", !storage.has(`oidcstate:${s5.state}`));
    }

    // (f2) An unknown connId at the callback (the connection was deleted between start and callback) -> refused.
    const s4 = await handleOidcStart(storage, flowConn, REDIRECT, RETURN_TO, makeFetch(), nowMs);
    if (s4.ok) {
      const stored = await storage.get<OidcStateRecord>(`oidcstate:${s4.state}`);
      const goneGetter = async (): Promise<OidcConnection | undefined> => undefined;
      const gone = await handleOidcCallback(storage, { connId: "entra", code: "c", state: s4.state, txnId: s4.txnId }, goneGetter, makeFetch({ nonce: stored!.nonce ?? "" }), nowMs);
      ok("handleOidcCallback refuses when the connection no longer exists", gone.ok === false);
    }

    // (g) WRONG KIND at the callback: the stored connId resolves to a non-OIDC (oauth2) connection. The OIDC
    //     callback must refuse it (a kind confusion cannot be smuggled through the OIDC path).
    const s6 = await handleOidcStart(storage, flowConn, REDIRECT, RETURN_TO, makeFetch(), nowMs);
    if (s6.ok) {
      const wrongKindGetter = async (id: string): Promise<OidcConnection | undefined> =>
        // Cast: we deliberately hand the OIDC callback a non-OIDC record to drive the kind guard; the union
        // is narrowed by conn.kind at the call site, which is exactly the branch under test.
        id === "entra" ? ({ ...oauth2Conn, id: "entra" } as unknown as OidcConnection) : undefined;
      const wrongKind = await handleOidcCallback(storage, { connId: "entra", code: "c", state: s6.state, txnId: s6.txnId }, wrongKindGetter, makeFetch(), nowMs);
      ok("handleOidcCallback refuses a connId that resolves to a non-OIDC connection", wrongKind.ok === false && /not an OIDC connection/.test(wrongKind.ok === false ? wrongKind.reason : ""));
    }

    // (h) RFC 9207 mix-up defence: the IdP returned an `iss` authorization-response parameter that does NOT
    //     equal this connection's issuer (and the connection does not substitute its issuer). The callback
    //     must refuse BEFORE any token exchange. We assert no token POST was made for this attempt.
    lastTokenReq = null;
    const s7 = await handleOidcStart(storage, flowConn, REDIRECT, RETURN_TO, makeFetch(), nowMs);
    if (s7.ok) {
      const issMism = await handleOidcCallback(storage, { connId: "entra", code: "c", state: s7.state, txnId: s7.txnId, iss: "https://attacker.example.com" }, getConn, makeFetch(), nowMs);
      ok("handleOidcCallback refuses an RFC 9207 iss that does not match the connection issuer", issMism.ok === false && /RFC 9207/.test(issMism.ok === false ? issMism.reason : ""));
      ok("  -> the iss mismatch is rejected BEFORE any token exchange", lastTokenReq === null);
    }

    // (i) RFC 9207: a MATCHING `iss` falls through the check (it equals conn.issuer) and the login completes
    //     the happy path. This is the true-branch partner of (h): the guard does not refuse a conformant iss.
    await putIdpSecret(storage, "entra", "the-secret");
    const s8 = await handleOidcStart(storage, flowConn, REDIRECT, RETURN_TO, makeFetch(), nowMs);
    if (s8.ok) {
      const stored = await storage.get<OidcStateRecord>(`oidcstate:${s8.state}`);
      const issOk = await handleOidcCallback(storage, { connId: "entra", code: "c", state: s8.state, txnId: s8.txnId, iss: ISSUER }, getConn, makeFetch({ nonce: stored!.nonce ?? "" }), nowMs);
      ok("handleOidcCallback accepts a matching RFC 9207 iss and completes the login", issOk.ok === true);
    }

    // (j) PKCE-public OIDC client (no client secret): secretRef.mode is 'pkce-public', clientAuth is
    //     'pkce_public', so the callback resolves NO secret and the token exchange is PKCE-only. The login
    //     completes, and the token POST carried NO client_secret (the public-client invariant).
    const pubConn: OidcConnection = { ...flowConn, secretRef: { mode: "pkce-public" }, clientAuth: "pkce_public" };
    const pubGetter = async (id: string): Promise<OidcConnection | undefined> => (id === "entra" ? pubConn : undefined);
    lastTokenReq = null;
    const s9 = await handleOidcStart(storage, pubConn, REDIRECT, RETURN_TO, makeFetch(), nowMs);
    if (s9.ok) {
      const stored = await storage.get<OidcStateRecord>(`oidcstate:${s9.state}`);
      const pub = await handleOidcCallback(storage, { connId: "entra", code: "the-code", state: s9.state, txnId: s9.txnId }, pubGetter, makeFetch({ nonce: stored!.nonce ?? "" }), nowMs);
      ok("handleOidcCallback completes a PKCE-public OIDC client with no stored secret", pub.ok === true);
      const sentBody = new URLSearchParams((lastTokenRequest().init.body as string) ?? "");
      ok("  -> the PKCE-public token exchange carried NO client_secret", sentBody.get("client_secret") === null && (sentBody.get("code_verifier") ?? "").length > 0);
    }

    // (k) The 'private-key-jwt' secret mode is not wired in this build: the callback refuses with that exact
    //     reason (it must not attempt an exchange it cannot authenticate).
    const pkjConn: OidcConnection = { ...flowConn, secretRef: { mode: "private-key-jwt", ref: "engine-key-1" }, clientAuth: "private_key_jwt" };
    const pkjGetter = async (id: string): Promise<OidcConnection | undefined> => (id === "entra" ? pkjConn : undefined);
    const s10 = await handleOidcStart(storage, pkjConn, REDIRECT, RETURN_TO, makeFetch(), nowMs);
    if (s10.ok) {
      const pkj = await handleOidcCallback(storage, { connId: "entra", code: "c", state: s10.state, txnId: s10.txnId }, pkjGetter, makeFetch(), nowMs);
      ok("handleOidcCallback refuses a 'private-key-jwt' secret mode (not wired this build)", pkj.ok === false && /private-key-jwt/.test(pkj.ok === false ? pkj.reason : ""));
    }

    // (l) An UNSUPPORTED secret mode (a record whose secretRef.mode is none of the four recognised values)
    //     hits the default branch and is refused with the verbatim mode in the reason. We hand-craft such a
    //     record (it could only arise from a corrupt store, never the validator) to drive that defensive arm.
    const badModeConn = { ...flowConn, secretRef: { mode: "totally-bogus" } } as unknown as OidcConnection;
    const badModeGetter = async (id: string): Promise<OidcConnection | undefined> => (id === "entra" ? badModeConn : undefined);
    const s11 = await handleOidcStart(storage, flowConn, REDIRECT, RETURN_TO, makeFetch(), nowMs);
    if (s11.ok) {
      const badMode = await handleOidcCallback(storage, { connId: "entra", code: "c", state: s11.state, txnId: s11.txnId }, badModeGetter, makeFetch(), nowMs);
      ok("handleOidcCallback refuses an unrecognised secret mode (default arm) with the verbatim mode", badMode.ok === false && /unsupported secret mode: totally-bogus/.test(badMode.ok === false ? badMode.reason : ""));
    }

    // (m) The callback passes the state + secret checks but ENDPOINT RESOLUTION fails: a discovery-only
    //     connection (no explicit endpoints) whose discovery fetch fails at the callback is refused with the
    //     resolveEndpoints reason. The state is consumed first (a tampered/unlucky callback cannot be retried).
    const discOnlyConn: OidcConnection = { ...flowConn };
    delete (discOnlyConn as Partial<OidcConnection>).authorizationEndpoint;
    delete (discOnlyConn as Partial<OidcConnection>).tokenEndpoint;
    delete (discOnlyConn as Partial<OidcConnection>).jwksUri;
    await putIdpSecret(storage, "entra", "the-secret");
    // Start over a working discovery so a state is stored, then fail discovery at the callback.
    const s12 = await handleOidcStart(storage, discOnlyConn, REDIRECT, RETURN_TO, makeFetch(), nowMs);
    if (s12.ok) {
      const discFailGetter = async (id: string): Promise<OidcConnection | undefined> => (id === "entra" ? discOnlyConn : undefined);
      const failDiscoveryFetch = (async (input: RequestInfo | URL): Promise<Response> => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
        if (url === DISCOVERY_URL) return new Response("gateway timeout", { status: 504, headers: { "content-type": "text/plain" } });
        throw new Error(`unexpected fetch: ${url}`);
      }) as typeof fetch;
      const epFail = await handleOidcCallback(storage, { connId: "entra", code: "c", state: s12.state, txnId: s12.txnId }, discFailGetter, failDiscoveryFetch, nowMs);
      ok("handleOidcCallback surfaces an endpoint-resolution failure at the callback", epFail.ok === false && /discovery endpoint returned 504/.test(epFail.ok === false ? epFail.reason : ""));
      ok("  -> and the state was consumed before the failed resolution (no retry)", !storage.has(`oidcstate:${s12.state}`));
    }

    // (n) The callback resolves endpoints and the secret, but the PURE completeOidcLogin FAILS (the token
    //     endpoint returns a non-200): handleOidcCallback forwards that reason. This is the false branch of the
    //     final completeOidcLogin success check.
    const s13 = await handleOidcStart(storage, flowConn, REDIRECT, RETURN_TO, makeFetch(), nowMs);
    if (s13.ok) {
      const stored = await storage.get<OidcStateRecord>(`oidcstate:${s13.state}`);
      const cbExchangeFail = await handleOidcCallback(storage, { connId: "entra", code: "c", state: s13.state, txnId: s13.txnId }, getConn, makeFetch({ nonce: stored!.nonce ?? "", status: 400, rawBody: JSON.stringify({ error: "invalid_grant" }) }), nowMs);
      ok("handleOidcCallback forwards a completeOidcLogin failure (token endpoint non-200)", cbExchangeFail.ok === false && (cbExchangeFail.ok === false ? cbExchangeFail.reason : "").length > 0);
    }

    // (o) A do-plaintext OIDC connection with NO stored secret: the callback fails closed (it refuses to
    //     exchange without a credential) rather than reaching the token endpoint. A fresh store with no
    //     idpsecret:<id> drives the do-plaintext missing-secret arm.
    const noSecretStore = new MockStorage();
    const s14 = await handleOidcStart(noSecretStore, flowConn, REDIRECT, RETURN_TO, makeFetch(), nowMs);
    if (s14.ok) {
      const cbNoSecret = await handleOidcCallback(noSecretStore, { connId: "entra", code: "c", state: s14.state, txnId: s14.txnId }, getConn, makeFetch(), nowMs);
      ok("handleOidcCallback refuses do-plaintext when no client secret is stored (fail-closed)", cbNoSecret.ok === false && /no stored client secret for this connection \(do-plaintext\)/.test(cbNoSecret.ok === false ? cbNoSecret.reason : ""));
    }
  }
}

// Discovery-derived authorization_endpoint/token_endpoint are PINNED to the issuer host exactly like
// makeJwksGetter already pins jwks_uri (resolveEndpoints, oidc-store.ts): a poisoned/mis-fetched discovery
// document naming an off-issuer-host endpoint is refused - closing the client_secret/code/verifier
// exfiltration an unpinned discovery response would otherwise allow - while a connection's own EXPLICIT, config-validated override
// (the Google-style off-issuer-host escape hatch) is trusted and actually SUBSTITUTED for the discovery
// value, not merely left unchecked.
async function testEndpointHostPin(): Promise<void> {
  const ATTACKER_TOKEN_ENDPOINT = "https://attacker.example/collect";
  const ATTACKER_AUTH_ENDPOINT = "https://attacker.example/authorize";
  const OFFHOST_TOKEN_ENDPOINT = "https://tokens.other-host.example/token";
  {
    // (a) The exploit itself: a discovery response whose token_endpoint has been rewritten to an attacker
    //     host, on a connection with NO explicit tokenEndpoint override. Pre-fix this sailed through
    //     assertSafeFetchEndpoint's host-CATEGORY screen untouched; resolveEndpoints must now refuse it before
    //     a later exchangeCode could POST the code/verifier/client_secret to that host.
    const connDisc: OidcConnection = { ...flowConn };
    delete (connDisc as Partial<OidcConnection>).authorizationEndpoint;
    delete (connDisc as Partial<OidcConnection>).tokenEndpoint;
    delete (connDisc as Partial<OidcConnection>).jwksUri;
    const storeA = new MockStorage();
    const poisonedTokenFetch = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (url === DISCOVERY_URL) {
        return new Response(JSON.stringify({ issuer: ISSUER, authorization_endpoint: AUTH_URL, token_endpoint: ATTACKER_TOKEN_ENDPOINT, jwks_uri: JWKS_URL }), { status: 200, headers: { "content-type": "application/json" } });
      }
      throw new Error(`unexpected fetch (the attacker token endpoint must never be reached): ${url}`);
    }) as typeof fetch;
    const poisoned = await handleOidcStart(storeA, connDisc, REDIRECT, RETURN_TO, poisonedTokenFetch, nowMs);
    ok("resolveEndpoints REFUSES a discovery token_endpoint whose host != the issuer host", poisoned.ok === false && /token_endpoint host/.test(poisoned.ok === false ? poisoned.reason : ""));
    ok("  -> and no orphaned state was stored on a refused start", storeA.countPrefix("oidcstate:") === 0);

    // (b) The same attack against authorization_endpoint.
    const storeB = new MockStorage();
    const poisonedAuthFetch = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (url === DISCOVERY_URL) {
        return new Response(JSON.stringify({ issuer: ISSUER, authorization_endpoint: ATTACKER_AUTH_ENDPOINT, token_endpoint: TOKEN_URL, jwks_uri: JWKS_URL }), { status: 200, headers: { "content-type": "application/json" } });
      }
      throw new Error(`unexpected fetch: ${url}`);
    }) as typeof fetch;
    const poisonedAuth = await handleOidcStart(storeB, connDisc, REDIRECT, RETURN_TO, poisonedAuthFetch, nowMs);
    ok("resolveEndpoints REFUSES a discovery authorization_endpoint whose host != the issuer host", poisonedAuth.ok === false && /authorization_endpoint host/.test(poisonedAuth.ok === false ? poisonedAuth.reason : ""));
    ok("  -> and no orphaned state was stored on a refused start", storeB.countPrefix("oidcstate:") === 0);

    // (c) The escape hatch (Google-shaped): the connection configures tokenEndpoint EXPLICITLY on a DIFFERENT
    //     host than the issuer (and than the discovery doc's own token_endpoint), so it must be TRUSTED. This
    //     proves the pin skip actually SUBSTITUTES the operator-asserted value for the discovery one - the real
    //     exchange must hit the explicit override, never the discovery-declared same-host value (the stub
    //     throws if that one is ever requested).
    const connOffHostToken: OidcConnection = { ...flowConn, tokenEndpoint: OFFHOST_TOKEN_ENDPOINT };
    delete (connOffHostToken as Partial<OidcConnection>).authorizationEndpoint;
    delete (connOffHostToken as Partial<OidcConnection>).jwksUri;
    const storeC = new MockStorage();
    await putIdpSecret(storeC, "entra", "the-secret");
    const discoveryOnlyFetch = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (url === DISCOVERY_URL) {
        return new Response(JSON.stringify({ issuer: ISSUER, authorization_endpoint: AUTH_URL, token_endpoint: TOKEN_URL, jwks_uri: JWKS_URL }), { status: 200, headers: { "content-type": "application/json" } });
      }
      throw new Error(`unexpected fetch during start: ${url}`);
    }) as typeof fetch;
    const started = await handleOidcStart(storeC, connOffHostToken, REDIRECT, RETURN_TO, discoveryOnlyFetch, nowMs);
    ok("handleOidcStart succeeds for a connection with an explicit off-host tokenEndpoint override", started.ok === true);
    if (started.ok) {
      const stored = await storeC.get<OidcStateRecord>(`oidcstate:${started.state}`);
      const nonce = stored!.nonce ?? "";
      // A const array (never reassigned) sidesteps the closure/narrowing gotcha lastTokenRequest() works
      // around above: reading a `let` mutated only inside a closure narrows to its initial type at the read
      // site, but push()-ing into a captured const array reads back fine after the intervening await.
      const offHostTokenUrls: string[] = [];
      const offHostFetch = (async (input: RequestInfo | URL): Promise<Response> => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
        if (url === DISCOVERY_URL) {
          return new Response(JSON.stringify({ issuer: ISSUER, authorization_endpoint: AUTH_URL, token_endpoint: TOKEN_URL, jwks_uri: JWKS_URL }), { status: 200, headers: { "content-type": "application/json" } });
        }
        if (url === JWKS_URL) return new Response(JSON.stringify({ keys: [jwk] }), { status: 200, headers: { "content-type": "application/json" } });
        if (url === OFFHOST_TOKEN_ENDPOINT) {
          offHostTokenUrls.push(url);
          return new Response(JSON.stringify({ id_token: await signIdToken(idClaims(nonce)) }), { status: 200, headers: { "content-type": "application/json" } });
        }
        throw new Error(`unexpected fetch during callback (the discovery-declared token endpoint must not be reached): ${url}`);
      }) as typeof fetch;
      const getConnOff = async (id: string): Promise<OidcConnection | undefined> => (id === "entra" ? connOffHostToken : undefined);
      const cb = await handleOidcCallback(storeC, { connId: "entra", code: "c", state: started.state, txnId: started.txnId }, getConnOff, offHostFetch, nowMs);
      ok("handleOidcCallback succeeds, trusting the config-validated off-host tokenEndpoint", cb.ok === true);
      ok("  -> the token exchange POSTed to the explicit override host, not the discovery-declared one", offHostTokenUrls.length === 1 && offHostTokenUrls[0] === OFFHOST_TOKEN_ENDPOINT);
    }
  }
}

// SAML SP-initiated request store: put -> single-use consume -> replay finds nothing -> expiry -> sweep.
async function testSamlStore(): Promise<void> {
  {
    const storage = new MockStorage();
    const rec: SamlRequestRecord = { connId: "okta", requestId: "_abc123", returnTo: "/dashboard", createdAt: 1000, browserBind: "bind-token-abc" };
    await putSamlRequest(storage, "relay-xyz", rec);
    const got = await consumeSamlRequest(storage, "relay-xyz", 2000);
    ok("SAML request: consume returns the record within TTL", got !== null && got.requestId === "_abc123" && got.returnTo === "/dashboard");
    const again = await consumeSamlRequest(storage, "relay-xyz", 2000);
    ok("SAML request: single-use - a replayed RelayState finds nothing (delete-before-return)", again === null);
    ok("SAML request: an unknown RelayState (IdP-initiated / forged) finds nothing", (await consumeSamlRequest(storage, "never-minted", 2000)) === null);
    await putSamlRequest(storage, "relay-old", { ...rec, createdAt: 0 });
    ok("SAML request: an expired record is refused", (await consumeSamlRequest(storage, "relay-old", 999999999, 600000)) === null);
    await putSamlRequest(storage, "relay-abandoned", { ...rec, createdAt: 0 });
    const swept = await sweepSamlRequests(storage, 999999999, 600000);
    ok("SAML request: sweep prunes abandoned records past TTL", swept >= 1);
  }
}

// 9. The OAuth2 (no id_token, GitHub-class) flow orchestrators: handleOauth2Start + handleOauth2Callback.
//    These share the single-use state store with the OIDC flow but have NO discovery, NO nonce and NO
//    RFC 9207 iss check; the single-use state IS the CSRF/replay defence. We drive both ends over the GitHub
//    stub fetch and the REAL completeOauth2Login.
async function testOauth2Flow(): Promise<void> {
  {
    const storage = new MockStorage();
    await putIdpSecret(storage, "github", "gh-secret-value"); // do-plaintext: resolved at the callback

    // (a) handleOauth2Start (pkce:"none", a confidential OAuth App): mints state + txnId, builds the authorize
    //     URL (no nonce, no PKCE challenge), and stores a state record whose codeVerifier is ABSENT.
    const started = await handleOauth2Start(storage, oauth2Conn, GH_REDIRECT, RETURN_TO, nowMs);
    ok("handleOauth2Start succeeds for a confidential OAuth App", started.ok === true);
    if (started.ok) {
      const url = new URL(started.authorizeUrl);
      ok("  -> the authorize URL targets the connection's authorize endpoint with response_type=code", `${url.origin}${url.pathname}` === GH_AUTHORIZE && url.searchParams.get("response_type") === "code" && url.searchParams.get("client_id") === GH_CLIENT);
      ok("  -> the authorize URL's state EQUALS the returned state and carries the redirect_uri", url.searchParams.get("state") === started.state && url.searchParams.get("redirect_uri") === GH_REDIRECT);
      ok("  -> a confidential OAuth App authorize URL carries NO PKCE challenge", url.searchParams.get("code_challenge") === null && url.searchParams.get("code_challenge_method") === null);
      const stored = await storage.get<OidcStateRecord>(`oidcstate:${started.state}`);
      ok("  -> a state record was persisted binding the connId + an ABSENT codeVerifier (no PKCE) + an absent nonce", stored !== undefined && stored.connId === "github" && stored.codeVerifier === undefined && stored.nonce === undefined && stored.txnId === started.txnId);
    }

    // (b) handleOauth2Callback happy path (do-plaintext): consume the stored state, exchange the code, read the
    //     profile, and return the principal (subject from the IMMUTABLE id) + the stored returnTo. The token
    //     POST carried the do-plaintext secret resolved from idpsecret:<id>.
    if (started.ok) {
      lastOauth2TokenReq = null;
      const getConn = async (id: string): Promise<Oauth2Connection | undefined> => (id === "github" ? oauth2Conn : undefined);
      const cb = await handleOauth2Callback(storage, { connId: "github", code: "the-code", state: started.state, txnId: started.txnId }, getConn, makeGhFetch(), nowMs);
      ok("handleOauth2Callback succeeds and returns the principal + returnTo", cb.ok === true);
      if (cb.ok) {
        ok("  -> the principal subject is folded from the IMMUTABLE id (never the login)", cb.principal.subject === GH_EXPECT_SUBJECT);
        ok("  -> issuer == subjectPrefix:apiBase and the primary+verified email surfaced", cb.principal.issuer === GH_EXPECT_ISSUER && cb.principal.email === "octocat@github.com" && cb.principal.emailVerified === true);
        ok("  -> groups fold the GitHub team + org shapes", JSON.stringify(cb.principal.groups) === JSON.stringify(["acme/engineers", "acme"]));
        ok("  -> returnTo is the stored returnTo", cb.returnTo === RETURN_TO);
      }
      const sentBody = new URLSearchParams((lastOauth2TokenRequest().init.body as string) ?? "");
      ok("  -> the do-plaintext secret was resolved and sent in the OAuth2 token exchange", sentBody.get("client_secret") === "gh-secret-value");
      ok("  -> the state was consumed (the record is deleted)", !storage.has(`oidcstate:${started.state}`));
      const replay = await handleOauth2Callback(storage, { connId: "github", code: "the-code", state: started.state, txnId: started.txnId }, getConn, makeGhFetch(), nowMs);
      ok("  -> a replay of the consumed OAuth2 callback is refused", replay.ok === false);
    }

    // (c) handleOauth2Start for a PKCE-public OAuth2 client (pkce:"supported"): the authorize URL carries an
    //     S256 challenge AND the stored record's codeVerifier is non-empty, so the callback can send it.
    const pubOauth2: Oauth2Connection = { ...oauth2Conn, pkce: "supported", secretRef: { mode: "pkce-public" } };
    const pubStart = await handleOauth2Start(storage, pubOauth2, GH_REDIRECT, RETURN_TO, nowMs);
    ok("handleOauth2Start mints PKCE for a pkce:'supported' client", pubStart.ok === true);
    if (pubStart.ok) {
      const url = new URL(pubStart.authorizeUrl);
      ok("  -> the authorize URL carries an S256 PKCE challenge", url.searchParams.get("code_challenge_method") === "S256" && (url.searchParams.get("code_challenge") ?? "").length > 0);
      const stored = await storage.get<OidcStateRecord>(`oidcstate:${pubStart.state}`);
      ok("  -> the stored record's codeVerifier is present and hashes to the challenge", stored !== undefined && stored.codeVerifier !== undefined && stored.codeVerifier.length > 0 && b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(stored.codeVerifier)))) === url.searchParams.get("code_challenge"));

      // (d) The PKCE-public callback drives the pkce-public secret arm: it resolves NO client secret and
      //     proceeds to the exchange. In THIS build both OAuth2 token-auth styles (post_json / post_form_basic)
      //     still require a resolved secret, so completeOauth2Login fails closed with that exact reason rather
      //     than exchanging without a credential. The negative outcome is the honest one (the public-PKCE-only
      //     exchange is not wired for the OAuth2 path), and the pkce-public arm is the path under test.
      const pubGetter = async (id: string): Promise<Oauth2Connection | undefined> => (id === "github" ? pubOauth2 : undefined);
      const pubCb = await handleOauth2Callback(storage, { connId: "github", code: "c", state: pubStart.state, txnId: pubStart.txnId }, pubGetter, makeGhFetch(), nowMs);
      ok("handleOauth2Callback takes the pkce-public arm (no secret resolved) and fails closed at the exchange (post_json needs a secret)", pubCb.ok === false && /token auth requires a resolved client secret/.test(pubCb.ok === false ? pubCb.reason : ""));
      ok("  -> the pkce-public OAuth2 callback consumed its single-use state", !storage.has(`oidcstate:${pubStart.state}`));
    }

    // (e) handleOauth2Start refuses a DISABLED connection before any state work.
    const disabledStart = await handleOauth2Start(storage, { ...oauth2Conn, enabled: false }, GH_REDIRECT, RETURN_TO, nowMs);
    ok("handleOauth2Start refuses a disabled connection", disabledStart.ok === false && /disabled/.test(disabledStart.ok === false ? disabledStart.reason : ""));

    // (f) Negative controls on the OAuth2 callback: a missing state, a connId mismatch, and a txnId mismatch
    //     (login-CSRF) are each refused, identically to the OIDC callback.
    const getConn = async (id: string): Promise<Oauth2Connection | undefined> => (id === "github" ? oauth2Conn : undefined);
    const cbMissing = await handleOauth2Callback(storage, { connId: "github", code: "c", state: "never-stored", txnId: "t" }, getConn, makeGhFetch(), nowMs);
    ok("handleOauth2Callback refuses a missing/unknown state", cbMissing.ok === false && /already-used state/.test(cbMissing.ok === false ? cbMissing.reason : ""));

    const sm1 = await handleOauth2Start(storage, oauth2Conn, GH_REDIRECT, RETURN_TO, nowMs);
    if (sm1.ok) {
      const otherGetter = async (id: string): Promise<Oauth2Connection | undefined> => (id === "github" || id === "gitlab" ? { ...oauth2Conn, id } : undefined);
      const connMism = await handleOauth2Callback(storage, { connId: "gitlab", code: "c", state: sm1.state, txnId: sm1.txnId }, otherGetter, makeGhFetch(), nowMs);
      ok("handleOauth2Callback refuses a connId that does not match the state record", connMism.ok === false && /connId/.test(connMism.ok === false ? connMism.reason : ""));
      ok("  -> and it still consumed the state (a tampered callback cannot be retried)", !storage.has(`oidcstate:${sm1.state}`));
    }
    const sm2 = await handleOauth2Start(storage, oauth2Conn, GH_REDIRECT, RETURN_TO, nowMs);
    if (sm2.ok) {
      // A length-mismatched txnId: the constant-time wrapper must short-circuit and refuse, not throw.
      const txnMism = await handleOauth2Callback(storage, { connId: "github", code: "c", state: sm2.state, txnId: "attacker-txn" }, getConn, makeGhFetch(), nowMs);
      ok("handleOauth2Callback refuses a length-mismatched txnId without throwing (login-CSRF)", txnMism.ok === false && /transaction id mismatch/.test(txnMism.ok === false ? txnMism.reason : ""));
    }
    const sm2b = await handleOauth2Start(storage, oauth2Conn, GH_REDIRECT, RETURN_TO, nowMs);
    if (sm2b.ok) {
      // An EQUAL-LENGTH but different txnId: the constant-time path runs end to end and still refuses.
      const sameLenWrong = sm2b.txnId.slice(0, -1) + (sm2b.txnId.endsWith("A") ? "B" : "A");
      const txnMism2 = await handleOauth2Callback(storage, { connId: "github", code: "c", state: sm2b.state, txnId: sameLenWrong }, getConn, makeGhFetch(), nowMs);
      ok("handleOauth2Callback refuses an equal-length but different txnId (login-CSRF)", txnMism2.ok === false && /transaction id mismatch/.test(txnMism2.ok === false ? txnMism2.reason : ""));
    }

    // (g) The connection was DELETED between start and callback -> not found.
    const sm3 = await handleOauth2Start(storage, oauth2Conn, GH_REDIRECT, RETURN_TO, nowMs);
    if (sm3.ok) {
      const goneGetter = async (): Promise<Oauth2Connection | undefined> => undefined;
      const gone = await handleOauth2Callback(storage, { connId: "github", code: "c", state: sm3.state, txnId: sm3.txnId }, goneGetter, makeGhFetch(), nowMs);
      ok("handleOauth2Callback refuses when the connection no longer exists", gone.ok === false && /not found/.test(gone.ok === false ? gone.reason : ""));
    }

    // (h) WRONG KIND: the connId resolves to a non-OAuth2 (oidc) connection -> refused.
    const sm4 = await handleOauth2Start(storage, oauth2Conn, GH_REDIRECT, RETURN_TO, nowMs);
    if (sm4.ok) {
      const wrongKindGetter = async (id: string): Promise<Oauth2Connection | undefined> =>
        // Cast: the OAuth2 callback's kind guard is exactly what is under test; hand it a non-OAuth2 record.
        id === "github" ? ({ ...flowConn, id: "github" } as unknown as Oauth2Connection) : undefined;
      const wrongKind = await handleOauth2Callback(storage, { connId: "github", code: "c", state: sm4.state, txnId: sm4.txnId }, wrongKindGetter, makeGhFetch(), nowMs);
      ok("handleOauth2Callback refuses a connId that resolves to a non-OAuth2 connection", wrongKind.ok === false && /not an OAuth2 connection/.test(wrongKind.ok === false ? wrongKind.reason : ""));
    }

    // (i) A connection DISABLED between start and callback cannot mint a session, and the state is consumed.
    const sm5 = await handleOauth2Start(storage, oauth2Conn, GH_REDIRECT, RETURN_TO, nowMs);
    if (sm5.ok) {
      const disabledGetter = async (id: string): Promise<Oauth2Connection | undefined> => (id === "github" ? { ...oauth2Conn, enabled: false } : undefined);
      const cbDisabled = await handleOauth2Callback(storage, { connId: "github", code: "c", state: sm5.state, txnId: sm5.txnId }, disabledGetter, makeGhFetch(), nowMs);
      ok("handleOauth2Callback refuses a connection disabled mid-flight", cbDisabled.ok === false && /disabled/.test(cbDisabled.ok === false ? cbDisabled.reason : ""));
      ok("  -> and the state was still consumed (no retry)", !storage.has(`oidcstate:${sm5.state}`));
    }

    // (j) The do-plaintext mode with NO stored secret: the callback refuses (fail-closed) rather than exchange
    //     without a credential. A fresh store with the connection but no idpsecret:<id> drives it.
    const noSecretStore = new MockStorage();
    const sm6 = await handleOauth2Start(noSecretStore, oauth2Conn, GH_REDIRECT, RETURN_TO, nowMs);
    if (sm6.ok) {
      const noSecretCb = await handleOauth2Callback(noSecretStore, { connId: "github", code: "c", state: sm6.state, txnId: sm6.txnId }, getConn, makeGhFetch(), nowMs);
      ok("handleOauth2Callback refuses do-plaintext when no client secret is stored (fail-closed)", noSecretCb.ok === false && /no stored client secret/.test(noSecretCb.ok === false ? noSecretCb.reason : ""));
    }

    // (k) A 'secrets-store' secret mode is a later wiring: the OAuth2 callback refuses with that reason.
    const ssStore = new MockStorage();
    const ssOauth2: Oauth2Connection = { ...oauth2Conn, secretRef: { mode: "secrets-store", ref: "DP_GH_SECRET" } };
    const ssGetter = async (id: string): Promise<Oauth2Connection | undefined> => (id === "github" ? ssOauth2 : undefined);
    const sm7 = await handleOauth2Start(ssStore, ssOauth2, GH_REDIRECT, RETURN_TO, nowMs);
    if (sm7.ok) {
      const ssCb = await handleOauth2Callback(ssStore, { connId: "github", code: "c", state: sm7.state, txnId: sm7.txnId }, ssGetter, makeGhFetch(), nowMs);
      ok("handleOauth2Callback refuses a 'secrets-store' secret mode (later wiring)", ssCb.ok === false && /secrets-store/.test(ssCb.ok === false ? ssCb.reason : ""));
    }

    // (l) An UNSUPPORTED secret mode for an OAuth2 connection (private-key-jwt is OIDC-only; here we drive the
    //     default arm with a bogus mode) is refused with the verbatim mode in the reason.
    const badStore = new MockStorage();
    const badOauth2 = { ...oauth2Conn, secretRef: { mode: "private-key-jwt", ref: "k" } } as unknown as Oauth2Connection;
    const badGetter = async (id: string): Promise<Oauth2Connection | undefined> => (id === "github" ? badOauth2 : undefined);
    const sm8 = await handleOauth2Start(badStore, oauth2Conn, GH_REDIRECT, RETURN_TO, nowMs);
    if (sm8.ok) {
      const badCb = await handleOauth2Callback(badStore, { connId: "github", code: "c", state: sm8.state, txnId: sm8.txnId }, badGetter, makeGhFetch(), nowMs);
      ok("handleOauth2Callback refuses an unsupported secret mode for OAuth2 (default arm) with the verbatim mode", badCb.ok === false && /unsupported secret mode for an OAuth2 connection: private-key-jwt/.test(badCb.ok === false ? badCb.reason : ""));
    }
  }
}

async function run(): Promise<void> {
  console.log("validate-oidc-store: the DO-side OIDC store (CRUD + secret + state single-use + flow)\n");

  await testCrudRoundTrip();
  await testSecretRoundTrip();
  await testStateSingleUse();
  await testJwksGetter();
  await testHandleOidcStart();
  await testHandleOidcCallbackHappy();
  await testHandleOidcCallbackNegative();
  await testEndpointHostPin();
  await testSamlStore();
  await testOauth2Flow();

  console.log(failures === 0 ? "\nvalidate-oidc-store: ALL PASS" : `\nvalidate-oidc-store: ${failures} FAILED`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
