// The native OIDC Relying Party flow engine. It turns a stored OidcConnection (idpconn.ts) into a complete,
// no-Cloudflare-Access sign-in: mint PKCE + state + nonce, build the authorize URL, then on the callback
// exchange the code for tokens server-side and verify the id_token with the Phase-1 verifier (oidc-verify.ts).
//
// Everything here is PURE or INJECTED: the network is passed in as a `doFetch` (so the validator drives the
// real flow with a stub IdP and forged-but-signed tokens), and the JWKS is supplied via a getter the caller
// caches. The DO owns discovery caching, the single-use state record, and resolving the client secret from
// its secretRef; this module never touches storage. SSRF is bounded by guardedOidcFetch (https-only, no
// redirect following, host screened by assertSafeFetchEndpoint, response size capped).
//
// Node 25 strip-types + Workers compatible: Web Crypto + fetch only, no Node builtins, no enums.

import { ab, b64urlEncode } from "../crypto/bytes.ts";
import { isInternalSinkHost } from "../notify.ts";
import { type AdvisoryAuthContext, extractOidcAuthContext } from "./auth-context.ts";
import { GROUP_NAME_MAX, GROUPS_MAX } from "./groups-bounds.ts";
import { oidcSubject } from "./identity.ts";
import type { OidcConnection } from "./idpconn.ts";
import type { JWK, JWKS, VerifyIdTokenOptions, VerifyIdTokenResult } from "./oidc-verify.ts";
import { assertSafeFetchEndpoint, verifyIdToken } from "./oidc-verify.ts";
import { type ClaimDropTally, claimDropCounter } from "./posture-counters.ts";
import { oauthErrorMark, oauthErrorMarkFromBody } from "./sso-failure-class.ts";

// ---- bounds ------------------------------------------------------------------------------------
const FETCH_MAX_BYTES = 256 * 1024; // discovery/jwks/token responses are small; cap to bound a hostile IdP
// GROUPS_MAX and GROUP_NAME_MAX are shared from groups-bounds.ts so the bound is identical on every IdP path.

// ---- PKCE + opaque single-use values -----------------------------------------------------------

export interface Pkce {
  verifier: string; // the high-entropy secret kept server-side in the state record
  challenge: string; // base64url(SHA-256(verifier)) sent to the IdP at /authorize
  method: "S256";
}

// mintPkce produces an RFC 7636 S256 PKCE pair. base64url(32 CSPRNG octets) is a 43-char verifier whose
// characters are all in the unreserved set RFC 7636 requires, so it is a valid code_verifier as-is.
export async function mintPkce(): Promise<Pkce> {
  const verifier = b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", ab(new TextEncoder().encode(verifier))));
  return { verifier, challenge: b64urlEncode(digest), method: "S256" };
}

// mintOpaque returns a base64url CSPRNG token (default 32 bytes = 256 bits, well above the >=128-bit bar for
// state and nonce). Used for the state (CSRF + lookup key for the single-use DO record), the nonce (id_token
// replay binding), and the login-CSRF txn cookie id.
export function mintOpaque(bytes = 32): string {
  return b64urlEncode(crypto.getRandomValues(new Uint8Array(bytes)));
}

// ---- discovery + endpoints ---------------------------------------------------------------------

export interface FlowEndpoints {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
}

// discoveryUrlFor returns the .well-known/openid-configuration URL for a connection: the explicit
// discoveryUrl if set, else the issuer + the well-known suffix (RFC 8414 / OIDC Discovery). The discovery
// FETCH is pinned to the issuer host by the caller (it builds the URL from the validated issuer), so a
// connection can never point discovery at an unrelated host.
export function discoveryUrlFor(conn: { issuer: string; discoveryUrl?: string }): string {
  if (conn.discoveryUrl !== undefined) return conn.discoveryUrl;
  const base = conn.issuer.endsWith("/") ? conn.issuer.slice(0, -1) : conn.issuer;
  return `${base}/.well-known/openid-configuration`;
}

// parseDiscovery validates a fetched discovery document into FlowEndpoints, or returns a reason. It requires
// the three endpoints we use and screens each as a safe fetch target (assertSafeFetchEndpoint: https, no
// IP/localhost/cloudflareaccess), which is the SSRF defence against a hostile discovery doc redirecting the
// jwks/token fetch to an internal host. The issuer is carried through for display; the SECURITY-critical
// exact-iss binding happens later in verifyIdToken against the connection config, not here.
export function parseDiscovery(doc: unknown, expectedIssuer: string): { ok: true; endpoints: FlowEndpoints } | { ok: false; reason: string } {
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) return { ok: false, reason: "discovery document is not a JSON object" };
  const d = doc as Record<string, unknown>;
  const issuer = d.issuer;
  const authorizationEndpoint = d.authorization_endpoint;
  const tokenEndpoint = d.token_endpoint;
  const jwksUri = d.jwks_uri;
  if (typeof issuer !== "string" || issuer.length === 0) return { ok: false, reason: "discovery: missing issuer" };
  // BIND the discovery document to the operator-configured issuer: the document's own `issuer` MUST equal the
  // connection issuer EXACTLY. This refuses a poisoned or mis-fetched discovery document for a DIFFERENT
  // issuer from supplying this connection's endpoints (one half of the discovery-trust chain; the other half
  // - pinning the JWKS host to the issuer host - is the caller's, see CALLER OBLIGATIONS at completeOidcLogin).
  if (issuer !== expectedIssuer) return { ok: false, reason: `discovery issuer "${issuer}" does not match the configured issuer "${expectedIssuer}"` };
  for (const [name, val] of [["authorization_endpoint", authorizationEndpoint], ["token_endpoint", tokenEndpoint], ["jwks_uri", jwksUri]] as const) {
    if (typeof val !== "string" || val.length === 0) return { ok: false, reason: `discovery: missing ${name}` };
    try {
      assertSafeFetchEndpoint(val);
    } catch (e) {
      return { ok: false, reason: `discovery ${name}: ${e instanceof Error ? e.message : "unsafe endpoint"}` };
    }
  }
  return { ok: true, endpoints: { issuer, authorizationEndpoint: authorizationEndpoint as string, tokenEndpoint: tokenEndpoint as string, jwksUri: jwksUri as string } };
}

// endpointsFromConnection returns FlowEndpoints when a connection carries all three explicit endpoints
// (no discovery round-trip needed), else null (the caller must fetch discovery). Each explicit endpoint was
// already assertSafeFetchEndpoint-validated at config time, so this is a straight read.
export function endpointsFromConnection(conn: OidcConnection): FlowEndpoints | null {
  if (conn.authorizationEndpoint && conn.tokenEndpoint && conn.jwksUri) {
    return { issuer: conn.issuer, authorizationEndpoint: conn.authorizationEndpoint, tokenEndpoint: conn.tokenEndpoint, jwksUri: conn.jwksUri };
  }
  return null;
}

// ---- the authorize redirect --------------------------------------------------------------------

// buildAuthorizeUrl assembles the IdP authorization URL for the authorization-code + PKCE(S256) flow. The
// state, nonce and code_challenge come from the caller (minted + stored single-use in the DO state record);
// redirectUri is the one pre-registered https://console.downpipes.io/admin/oidc/callback/<connId>. hd (Google)
// and any extraAuthParams (e.g. Entra prompt) are appended. response_type is always "code" (no implicit/hybrid).
export function buildAuthorizeUrl(conn: OidcConnection, ep: FlowEndpoints, p: { state: string; nonce: string; challenge: string; redirectUri: string }): string {
  const u = new URL(ep.authorizationEndpoint);
  const q = u.searchParams;
  q.set("response_type", "code");
  q.set("client_id", conn.clientId);
  q.set("redirect_uri", p.redirectUri);
  q.set("scope", conn.scopes.join(" "));
  q.set("state", p.state);
  q.set("nonce", p.nonce);
  q.set("code_challenge", p.challenge);
  q.set("code_challenge_method", "S256");
  if (conn.hdDomain !== undefined) q.set("hd", conn.hdDomain);
  for (const [k, v] of Object.entries(conn.extraAuthParams ?? {})) q.set(k, v);
  return u.toString();
}

// ---- guarded fetch -----------------------------------------------------------------------------

export interface GuardedResponse {
  status: number;
  bodyText: string;
}

// guardedOidcFetch is the SSRF-bounded fetch for the discovery / jwks / token endpoints. It screens the URL
// (assertSafeFetchEndpoint: https, no IP/localhost/cloudflareaccess), refuses to FOLLOW redirects
// (redirect:"manual" hands a 3xx back as a non-ok response that the guard below hard-fails, so a 302 to an
// internal host cannot be chased), and caps the body so a hostile IdP cannot return a multi-megabyte response.
// doFetch is injected (the real global fetch in prod, a stub in the validator). It NEVER throws out of an
// expected fault: any error resolves to a thrown Error the caller catches and maps to a clean failure.
export async function guardedOidcFetch(url: string, init: RequestInit, doFetch: typeof fetch, maxBytes = FETCH_MAX_BYTES): Promise<GuardedResponse> {
  assertSafeFetchEndpoint(url);
  // Defence in depth: apply the same host classifier the read-only idp-test probe uses, so the live login
  // path also catches the IPv6 ULA / link-local and obfuscated forms isInternalSinkHost enumerates beyond the
  // IP-literal screen, and the two screens cannot drift.
  if (isInternalSinkHost(new URL(url).hostname)) throw new Error("oidc endpoint resolves to a screened internal host");
  // SSRF guard - same intent, corrected mechanism. We MUST NOT chase a 3xx to an internal or otherwise
  // unvalidated host. redirect:"manual" is how EVERY other egress path in this engine enforces that (S3, STS,
  // webhooks, SIEM/OTLP push, the update channel, byte-fetch): the runtime returns the 3xx as an opaque, non-ok
  // response instead of following it. Unlike redirect:"error" it does not throw on the Cloudflare edge for a
  // legitimate 2xx, which is the fault that broke real Entra discovery / Test-connection / federated sign-in.
  // We then hard-fail ANY 3xx (and the opaque status 0 that redirect:"manual" can surface on a spec-strict
  // runtime) exactly as dest/sts.ts and sources/byte-fetch.ts do, so the refusal is IDENTICAL to the old
  // redirect:"error": a redirect is never followed, a 302 to 169.254.x / localhost / a private range or any
  // non-provider host is refused, not chased. A discovery / jwks / token endpoint answers 200 directly and
  // never legitimately redirects, so no same-origin follow is needed here; the common 2xx passes straight
  // through untouched.
  const resp = await doFetch(url, { ...init, redirect: "manual" });
  if (resp.status === 0 || (resp.status >= 300 && resp.status < 400)) {
    void resp.body?.cancel(); // release the socket; the redirect body is discarded, its Location never read
    throw new Error(`oidc endpoint returned an unexpected redirect (status ${resp.status}); a discovery, jwks, or token endpoint must not redirect`);
  }
  // STREAM the body with a hard byte cap, aborting the moment it is exceeded. We do NOT trust content-length
  // (a chunked response omits it), so the cap is enforced on the bytes actually read - which bounds memory
  // against a hostile or compromised IdP returning a huge/chunked body before any parse happens.
  const reader = resp.body?.getReader();
  if (reader === undefined) return { status: resp.status, bodyText: "" };
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value !== undefined) {
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error("oidc endpoint response exceeds the size cap");
      }
      chunks.push(value);
    }
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.byteLength;
  }
  return { status: resp.status, bodyText: new TextDecoder().decode(buf) };
}

// fetchJwksGuarded fetches + parses a JWKS over the guarded fetch and REJECTS a set carrying duplicate kids.
// The verifier's key lookup takes the first kid match, so a duplicate kid (a stale key shadowing a fresh one,
// or an attacker-planted key) would either self-DoS or pin verification to the wrong key; refusing the whole
// set fails closed. SSRF: the caller MUST pass a jwksUri already pinned to the issuer host (or the
// connection's explicit, config-validated jwksUri) - guardedOidcFetch additionally screens the host category.
export async function fetchJwksGuarded(jwksUri: string, doFetch: typeof fetch): Promise<{ ok: true; jwks: JWKS } | { ok: false; reason: string }> {
  let resp: GuardedResponse;
  try {
    resp = await guardedOidcFetch(jwksUri, { method: "GET", headers: { accept: "application/json" } }, doFetch);
  } catch (e) {
    return { ok: false, reason: `jwks fetch failed: ${e instanceof Error ? e.message : "error"}` };
  }
  if (resp.status !== 200) return { ok: false, reason: `jwks endpoint returned ${resp.status}` };
  let json: unknown;
  try {
    json = JSON.parse(resp.bodyText);
  } catch {
    return { ok: false, reason: "jwks is not JSON" };
  }
  if (typeof json !== "object" || json === null || !Array.isArray((json as { keys?: unknown }).keys)) return { ok: false, reason: "jwks has no keys array" };
  const kids = new Set<string>();
  const out: JWK[] = [];
  for (const k of (json as { keys: unknown[] }).keys) {
    if (typeof k !== "object" || k === null) continue;
    const kid = (k as { kid?: unknown }).kid;
    const kty = (k as { kty?: unknown }).kty;
    if (typeof kty !== "string") continue;
    if (typeof kid === "string") {
      if (kids.has(kid)) return { ok: false, reason: `jwks carries a duplicate kid: ${kid}` };
      kids.add(kid);
    }
    out.push(k as JWK);
  }
  return { ok: true, jwks: { keys: out } };
}

// ---- token exchange ----------------------------------------------------------------------------

export interface TokenResponse {
  idToken: string;
  accessToken?: string;
}

// exchangeCode performs the server-side authorization-code -> token exchange (RFC 6749 + PKCE). It sends the
// code, the one redirect_uri, the client_id and the code_verifier, with client authentication per the
// connection's clientAuth: client_secret_post (secret in the body), client_secret_basic (HTTP Basic), or
// pkce_public (no secret, PKCE only). private_key_jwt is a fast-follow (it needs the engine-held key). The
// clientSecret VALUE is passed in by the caller (the DO resolves it from secretRef just-in-time); it never
// lives in this module. Returns the id_token (+ optional access_token) or a reason.
export async function exchangeCode(
  conn: OidcConnection,
  ep: FlowEndpoints,
  params: { code: string; codeVerifier: string; redirectUri: string; clientSecret?: string },
  doFetch: typeof fetch,
): Promise<{ ok: true; tokens: TokenResponse } | { ok: false; reason: string }> {
  const body = new URLSearchParams();
  body.set("grant_type", "authorization_code");
  body.set("code", params.code);
  body.set("redirect_uri", params.redirectUri);
  body.set("client_id", conn.clientId);
  body.set("code_verifier", params.codeVerifier);
  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded", accept: "application/json" };
  if (conn.clientAuth === "client_secret_post") {
    if (params.clientSecret === undefined) return { ok: false, reason: "client_secret_post requires a resolved client secret" };
    body.set("client_secret", params.clientSecret);
  } else if (conn.clientAuth === "client_secret_basic") {
    if (params.clientSecret === undefined) return { ok: false, reason: "client_secret_basic requires a resolved client secret" };
    headers.authorization = `Basic ${btoa(`${conn.clientId}:${params.clientSecret}`)}`;
  } else if (conn.clientAuth === "private_key_jwt") {
    return { ok: false, reason: "private_key_jwt client authentication is not yet implemented in this build" };
  }
  // pkce_public: no client authentication beyond the PKCE verifier.
  let resp: GuardedResponse;
  try {
    resp = await guardedOidcFetch(ep.tokenEndpoint, { method: "POST", headers, body: body.toString() }, doFetch);
  } catch (e) {
    return { ok: false, reason: `token endpoint fetch failed: ${e instanceof Error ? e.message : "error"}` };
  }
  // A non-200 token response CARRIES THE ANSWER, in the RFC 6749 s5.2 `error` field: an expired or rotated
  // Entra client secret answers `invalid_client`, a re-submitted callback answers `invalid_grant`, a degraded IdP
  // answers `temporarily_unavailable`. That field was read by nobody and thrown away, which is why "SSO broke
  // overnight and we changed nothing" arrived with a pack saying only "connection". oauthErrorMarkFromBody parses
  // the body ONLY to pull that field, admits it ONLY if it is a member of the closed OAuth spec vocabulary, and
  // renders it as the fixed `[oauth:<code>]` mark; the error_description / AADSTS prose / trace ids in the same
  // body are discarded inside that helper and never ride. The mark leaves the coarse SSO code unchanged
  // (`connection`), and the edge classifies it to a `sso-sub-*` counter.
  if (resp.status !== 200) return { ok: false, reason: `token endpoint returned ${resp.status}${oauthErrorMarkFromBody(resp.bodyText)}` };
  let json: unknown;
  try {
    json = JSON.parse(resp.bodyText);
  } catch {
    return { ok: false, reason: "token endpoint returned non-JSON" };
  }
  if (typeof json !== "object" || json === null) return { ok: false, reason: "token response is not an object" };
  const t = json as Record<string, unknown>;
  const idToken = t.id_token;
  // The HTTP-200-with-error quirk (some providers answer 200 with an `error` field and no token). Mark it the
  // same allowlisted way, so a 200-clothed invalid_client is diagnosed identically to a 401 one.
  if (typeof idToken !== "string" || idToken.length === 0) return { ok: false, reason: `token response carried no id_token${oauthErrorMark(t.error)}` };
  const accessToken = typeof t.access_token === "string" ? (t.access_token as string) : undefined;
  return { ok: true, tokens: { idToken, ...(accessToken !== undefined ? { accessToken } : {}) } };
}

// ---- id_token verification (with kid-rotation refetch) ------------------------------------------

// verifyOptionsFor maps a connection + endpoints into the VerifyIdTokenOptions the Phase-1 verifier consumes.
// For an Entra multitenant connection (issuerSubstitution "tid") it builds the tid-substitution matcher from
// the issuer TEMPLATE + the tenant allowlist; otherwise it pins the exact configured issuer. acceptIssuer
// variants (e.g. the Google bare form) and the nonce/accessToken are threaded through.
function verifyOptionsFor(conn: OidcConnection, nonce: string, now: number, accessToken?: string): VerifyIdTokenOptions {
  const opts: VerifyIdTokenOptions = {
    expectedIssuer: conn.issuer,
    clientId: conn.clientId,
    allowedAlgs: conn.idTokenSigAlgs,
    nonce,
    now,
  };
  if (conn.issuerSubstitution === "tid") {
    opts.tenantIdSubstitution = { template: conn.issuer, acceptedTenantIds: conn.acceptedTenantIds ?? [] };
  }
  if (conn.acceptIssuerVariants !== undefined) opts.acceptIssuerVariants = conn.acceptIssuerVariants;
  if (accessToken !== undefined) opts.accessToken = accessToken;
  return opts;
}

// verifyIdTokenWithRotation drives the Phase-1 verifier and performs the ONE bounded JWKS refetch on a
// kid-miss (key rotation): getJwks(false) serves the cache; if verify returns code "kid_not_found", refetch
// once with getJwks(true) and re-verify, then fail closed. This is the only place the kid-rotation policy
// lives, so the verifier stays pure and the cache stays in the caller.
export async function verifyIdTokenWithRotation(
  idToken: string,
  conn: OidcConnection,
  getJwks: (force: boolean) => Promise<JWKS>,
  params: { nonce: string; now: number; accessToken?: string },
): Promise<VerifyIdTokenResult> {
  const opts = verifyOptionsFor(conn, params.nonce, params.now, params.accessToken);
  let res = await verifyIdToken(idToken, await getJwks(false), opts);
  if (!res.ok && res.code === "kid_not_found") {
    res = await verifyIdToken(idToken, await getJwks(true), opts);
  }
  return res;
}

// ---- groups + principal ------------------------------------------------------------------------

// getByPath resolves a dotted claim path (e.g. "realm_access.roles" for Keycloak) into the claims object.
// It walks the path with ordinary property reads; a non-object/array or missing intermediate yields
// undefined. An inherited key (e.g. a path through "constructor" or "__proto__") therefore resolves the
// prototype member, but the result is array-bounded by boundGroups, so an inherited value can never become a
// group: it is not an array of trimmed strings, so boundGroups returns [].
function getByPath(claims: Record<string, unknown>, path: string): unknown {
  let cur: unknown = claims;
  for (const seg of path.split(".")) {
    if (typeof cur !== "object" || cur === null || Array.isArray(cur)) return undefined;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur;
}

// boundGroups normalises a raw groups/roles claim into a trusted string[] with the SAME discipline as the
// Access path (access.ts): array-only, string entries trimmed, empties + over-long + control-char-bearing
// dropped, deduped (first wins), capped to GROUPS_MAX. Anything else yields []. This bounds the customer's
// own IdP data before it becomes a group->role lookup key, identically to the Access groups claim.
//
// `drops` records the closed KIND of every group this bound threw away (over-length, control-char, past
// the cap), never the name. On the native-OIDC boundary the cap is the one that bites: an Entra tenant whose
// users hold hundreds of groups can have the ONE mapped group fall past GROUPS_MAX and get the viewer floor,
// and present-but-dropped read exactly like the IdP asserting nothing.
function boundGroups(raw: unknown, drops?: ClaimDropTally): string[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const entry of raw) {
    if (typeof entry !== "string") continue;
    const g = entry.trim();
    if (g.length === 0) continue;
    if (g.length > GROUP_NAME_MAX) {
      drops?.add(claimDropCounter("oidc-token", "group-overlength"));
      continue;
    }
    let control = false;
    for (let i = 0; i < g.length; i++) {
      const c = g.charCodeAt(i);
      if (c < 0x20 || c === 0x7f) {
        control = true;
        break;
      }
    }
    if (control) {
      drops?.add(claimDropCounter("oidc-token", "group-control-char"));
      continue;
    }
    if (seen.has(g)) continue; // a duplicate is not a drop
    if (out.length >= GROUPS_MAX) {
      drops?.add(claimDropCounter("oidc-token", "groups-list-capped"));
      continue;
    }
    seen.add(g);
    out.push(g);
  }
  return out;
}

// extractGroups pulls the membership list from the verified claims using the connection's rolesClaim (PREFERRED
// when set, e.g. Entra App Roles "roles" or Keycloak "realm_access.roles") then groupsClaim, applying the
// claimNamespace prefix (Auth0) when configured. Either path may be absent (no groups), which keeps group
// mapping additive. The Entra >200-group overflow marker (_claim_names/_claim_sources present while the groups
// claim is absent) FAILS CLOSED on the group axis: it returns { overflow: true } so the caller does NOT trust a
// partial set (the caller turns this into a clear sign-in refusal rather than silently treating it as no groups).
export function extractGroups(conn: OidcConnection, claims: Record<string, unknown>, drops?: ClaimDropTally): { groups: string[] } | { overflow: true } {
  const tryClaim = (name?: string): string[] | undefined => {
    if (name === undefined) return undefined;
    // A claimNamespace (Auth0) is a LITERAL key prefix - the namespaced claim is a single top-level key,
    // often a URL containing dots (e.g. "https://downpipes/roles"), so it MUST NOT be split on ".". Without a
    // namespace, the name may be a dotted PATH (Keycloak "realm_access.roles"), walked by getByPath.
    const v = conn.claimNamespace !== undefined ? claims[conn.claimNamespace + name] : getByPath(claims, name);
    // Coerce a single membership emitted as a bare STRING (JumpCloud emits memberOf as a string for a
    // one-group user and an array for many; some IdPs emit a single role likewise) into a one-element array,
    // so a one-group user is NOT silently dropped to no groups (a real authorisation under-grant).
    if (Array.isArray(v)) return boundGroups(v, drops);
    if (typeof v === "string" && v.length > 0) return boundGroups([v], drops);
    return undefined;
  };
  const roles = tryClaim(conn.rolesClaim);
  if (roles !== undefined) return { groups: roles };
  const groups = tryClaim(conn.groupsClaim);
  if (groups !== undefined) return { groups };
  // Neither configured membership claim resolved to an array. If the IdP signalled a groups OVERFLOW (Entra:
  // the distributed-claim markers _claim_names/_claim_sources appear when the user has too many groups to
  // inline), the absence is NOT "no groups" - it is "groups were withheld", and trusting it would silently
  // drop a group-elevated user. So when EITHER membership claim is configured AND the overflow markers are
  // present, fail closed ({ overflow: true }), regardless of which slot (rolesClaim or groupsClaim) the
  // operator mapped membership into (the earlier groupsClaim-only check missed a roles-mapped connection).
  const membershipConfigured = conn.rolesClaim !== undefined || conn.groupsClaim !== undefined;
  if (membershipConfigured && ("_claim_names" in claims || "_claim_sources" in claims)) return { overflow: true };
  return { groups: [] };
}

export interface ResolvedPrincipal {
  subject: string; // oidc:<connId>|<issuer>|<sub>
  email: string | null; // null when the IdP asserted no email
  emailVerified: boolean; // gates pending-invite binding upstream
  groups: string[];
  issuer: string;
  // authContext (V6.8.4): the IdP's advisory acr/amr/auth_time, bounded + redaction-safe. STRICTLY
  // NON-GATING -- carried only so the sign-in audit event can record how the IdP said the user authenticated;
  // authorization never depends on it. Absent when the IdP asserted none of the three. See auth-context.ts.
  authContext?: AdvisoryAuthContext;
  // claimDrops (G271): the CLOSED counter names of the claims this id_token asserted and the engine bounded
  // away. Diagnostic only -- it never affects the principal, the groups or the role. The DO callback bumps
  // them into the admin-counter aggregate; the dropped values themselves never leave the bounder.
  claimDrops?: string[];
}

// CALLER (DO callback route) OBLIGATIONS - this engine TRUSTS its inputs; the DO MUST guarantee, all keyed
// off the single-use state record looked up by the callback's `state` param:
//   1. consume the state record ATOMICALLY (delete-before-exchange); reject a missing/replayed state;
//   2. pass codeVerifier + nonce FROM that record (never from the request);
//   3. pass redirectUri == the one pre-registered for this connId (the engine echoes it into the token POST);
//   4. check the RFC 9207 `iss` authorization-response param == conn.issuer when the IdP returns it;
//   5. pass now in epoch SECONDS (Math.floor(Date.now()/1000));
//   6. resolve clientSecret just-in-time from secretRef, pass it ONLY for client_secret_*, and never log it;
//   7. build getJwks to fetch the JWKS over guardedOidcFetch, PIN the jwks host to the issuer host (or a
//      per-connection allowlist), key the cache by conn.id / issuer (NEVER by the discovery-supplied jwks_uri),
//      and REJECT a JWKS carrying duplicate kids. parseDiscovery already binds the discovery doc to the issuer,
//      and resolveEndpoints (oidc-store.ts) already pins the discovery-resolved authorization_endpoint /
//      token_endpoint to the issuer host (or trusts an explicit, config-validated override) before `ep` ever
//      reaches this module - so the jwks host pin above is the only endpoint pin left as this caller's own.
//
// enforceHostedDomain applies a connection's Google Workspace hosted-domain (hd) restriction to a
// SIGNATURE-VERIFIED id_token result. It returns a refusal reason when the connection pins
// hdDomain and the sign-in does NOT belong to it, or null when there is nothing to enforce (no hdDomain
// configured) or the domain matches. The match accepts EITHER signal, whichever the id_token carries: the
// Google-signed `hd` claim, or the verified email's domain (email_verified true). So it holds for a Workspace
// id_token that carries hd and for a provider that only returns a verified email in the domain. When hdDomain
// is set but NEITHER signal confirms the domain, it refuses (fail-closed): a domain restriction must never be
// satisfied by an unconfirmable domain. Redaction-safe: the reason names the configured domain and the
// account's DOMAIN only, never an email address, subject or value. Pure + exported so it is unit-testable.
//
// The domain match is normalised ASYMMETRICALLY, and that asymmetry is load-bearing:
//
// normaliseConfiguredDomain is LENIENT, applied ONLY to the ADMIN-TYPED hdDomain (a trusted input). It forgives
// the paste/typo decoration an operator might enter -- a scheme, a leading "@", a trailing path or dot -- so a
// fat-fingered "example.com.", "@example.com", "https://example.com" or "example.com/x" does not lock out every
// legitimate in-domain sign-in. It is safe to be lenient here because the value is operator-supplied config.
function normaliseConfiguredDomain(d: string): string {
  return d.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/^@+/, "").replace(/\/.*$/, "").replace(/\.+$/, "");
}
// normaliseTokenDomain is STRICT, applied to a TOKEN-SUPPLIED domain (the signed hd claim, or the verified
// email's domain). It ONLY trims, lowercases and strips a trailing root dot (a legitimate FQDN spelling). It
// deliberately does NOT strip a scheme, a leading "@", or a path, because a real hd claim / email domain never
// carries those -- and stripping a path HERE would let a crafted claim "example.com/anything" collapse to
// "example.com" and BYPASS the restriction. A token value carrying such decoration simply fails the exact
// match (refused), which is correct: it is not the configured domain.
function normaliseTokenDomain(d: string): string {
  return d.trim().toLowerCase().replace(/\.+$/, "");
}
export function enforceHostedDomain(
  conn: OidcConnection,
  verified: { email?: string; emailVerified: boolean; claims: Record<string, unknown> },
): string | null {
  const want = normaliseConfiguredDomain(conn.hdDomain ?? "");
  if (want === "") return null; // not configured (or only decoration): nothing to enforce
  const hdClaim = typeof verified.claims.hd === "string" ? normaliseTokenDomain(verified.claims.hd) : "";
  const email = (verified.email ?? "").trim().toLowerCase();
  const at = email.lastIndexOf("@");
  const emailDomain = at >= 0 ? normaliseTokenDomain(email.slice(at + 1)) : "";
  const emailInDomain = verified.emailVerified === true && emailDomain === want;
  if (hdClaim === want || emailInDomain) return null;
  const seen = hdClaim !== "" ? hdClaim : emailDomain !== "" ? emailDomain : "no domain";
  return `sign-in is restricted to the ${conn.hdDomain} hosted domain; this account (${seen}) is not in it`;
}

// completeOidcLogin is the callback-side orchestrator: exchange the code, verify the id_token (with rotation),
// then derive the stable subject + email + groups into a ResolvedPrincipal. Returns the principal or a precise
// reason; it never throws.
export async function completeOidcLogin(
  conn: OidcConnection,
  ep: FlowEndpoints,
  params: { code: string; codeVerifier: string; nonce: string; redirectUri: string; clientSecret?: string },
  deps: { doFetch: typeof fetch; getJwks: (force: boolean) => Promise<JWKS> },
  now: number,
): Promise<{ ok: true; principal: ResolvedPrincipal } | { ok: false; reason: string; code?: "tenant_not_accepted" | "hd_not_accepted" }> {
  const ex = await exchangeCode(conn, ep, { code: params.code, codeVerifier: params.codeVerifier, redirectUri: params.redirectUri, ...(params.clientSecret !== undefined ? { clientSecret: params.clientSecret } : {}) }, deps.doFetch);
  if (!ex.ok) return ex;
  let verified: VerifyIdTokenResult;
  try {
    verified = await verifyIdTokenWithRotation(ex.tokens.idToken, conn, deps.getJwks, { nonce: params.nonce, now, ...(ex.tokens.accessToken !== undefined ? { accessToken: ex.tokens.accessToken } : {}) });
  } catch (e) {
    return { ok: false, reason: `id_token verification error: ${e instanceof Error ? e.message : "error"}` };
  }
  if (!verified.ok) {
    // Surface the tenant-not-accepted marker (an Entra multitenant tid not in the allowlist) so the callback
    // layer can project it as a bounded support signal; the prose reason is otherwise coarse "issuer".
    return { ok: false, reason: `id_token rejected: ${verified.reason}`, ...(verified.code === "tenant_not_accepted" ? { code: "tenant_not_accepted" as const } : {}) };
  }
  // Google Workspace hosted-domain (hd) restriction. hd is sent as a login HINT on the
  // authorize request, but a hint is not a gate (a user can ignore it and sign in with any account, edit the
  // authorize URL, "Use another account", or a personal @gmail.com account), so when the connection pins
  // hdDomain we ENFORCE it here on the RETURNED, SIGNATURE-VERIFIED identity, mirroring the Entra
  // acceptedTenantIds allowlist above. It matches on either signal, whichever is present: the Google-signed
  // `hd` claim in the id_token, or the verified email's domain (email_verified true) -- Google's issuer,
  // unlike Entra/Okta/Keycloak/Auth0/JumpCloud, is shared by every Google account on Earth, so hd (or the
  // verified email domain) is the ONLY mechanism that scopes a Google connection to one Workspace. A sign-in
  // that carries neither in the configured domain is refused, so a token from outside the intended Workspace
  // cannot pass. Only enforced when hdDomain is set; a connection without it is unaffected. The reason names
  // the domain only (an org label, no account/email leaks). The hd_not_accepted code lets the callback layer
  // (scheduler-do-idp.ts) record a bounded "oidc-hd-not-accepted" auth signal, same as the Entra tenant-mismatch
  // case, so a "why can't I sign in" report is diagnosable without an email/subject leak.
  const hdReject = enforceHostedDomain(conn, verified);
  if (hdReject !== null) return { ok: false, reason: hdReject, code: "hd_not_accepted" as const };

  const drops: ClaimDropTally = new Set<string>();
  const g = extractGroups(conn, verified.claims, drops);
  if ("overflow" in g) return { ok: false, reason: "the IdP withheld the groups claim (too many groups); configure App Roles or a groups filter so authorization is not silently downgraded" };
  // V6.8.4: read the IdP's advisory acr/amr/auth_time off the VERIFIED claims. Purely advisory + non-gating
  // (see auth-context.ts); omitted when the IdP asserted none. It never influences the subject/email/groups
  // resolved above, so a spoofed or absent value cannot change who the principal is or what they can do.
  const authContext = extractOidcAuthContext(verified.claims, drops);
  const principal: ResolvedPrincipal = {
    subject: oidcSubject(conn.id, verified.iss, verified.sub),
    email: verified.email ?? null,
    emailVerified: verified.emailVerified === true,
    groups: g.groups,
    issuer: verified.iss,
    ...(authContext !== undefined ? { authContext } : {}),
    ...(drops.size > 0 ? { claimDrops: [...drops] } : {}),
  };
  return { ok: true, principal };
}
