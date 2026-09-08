// The DO-side OIDC store: the thin, storage-bound layer that turns the PURE OIDC core (idpconn.ts validator,
// oidc.ts flow engine, oidc-verify.ts verifier) into a complete native sign-in inside the scheduler DO. It
// owns exactly the three things the pure core deliberately left to the caller (see the CALLER OBLIGATIONS
// block above completeOidcLogin in oidc.ts): durable storage of connections + the write-only client secret,
// the SINGLE-USE state record (delete-before-return, atomic in the single-threaded DO), and the per-issuer
// JWKS cache with the JWKS-host pin. It is written over an INJECTED KvStorage interface (the get/put/delete/
// list subset the DO's storage exposes), so the validator drives every path with an in-memory mock exactly
// like validate-session.ts, and the path under test is the production path.
//
// STORAGE KEYS (all DO-local; the id fragment is isConnId-bounded so it can carry no separator):
//   idpconn:<id>    the stored IdpConnection record (NEVER holds a secret value; only a secretRef descriptor)
//   idpsecret:<id>  the do-plaintext client secret VALUE (write-only; getIdpSecret is internal-only, for the
//                   token exchange; it is never read back to the console, exactly like the destination secret)
//   oidcstate:<state>  the single-use OidcStateRecord minted at /start, consumed (deleted) at the callback
//
// SECURITY DISCIPLINE (the hard invariants from the approved plan + the prior adversarial review):
//   - the subject is taken VERBATIM from the verified token (completeOidcLogin -> oidcSubject), never re-derived;
//   - a secret VALUE is never stored in the connection record (validateIdpConnection enforces it; the record
//     holds only a secretRef descriptor); the value lives under idpsecret:<id> for the do-plaintext floor;
//   - state + nonce are single-use: consumeOidcState DELETES the record BEFORE returning it, so even a double-
//     submit cannot replay it (the DO is single-threaded, so get-then-delete is atomic);
//   - the JWKS host is PINNED to the issuer host: if the connection carries an explicit jwksUri it is trusted
//     (it was assertSafeFetchEndpoint-validated AND issuer-host-checked at config time); otherwise the
//     discovery-supplied jwks_uri host MUST equal the issuer host, refusing a poisoned discovery document
//     pointing the JWKS trust at an unrelated host;
//   - the callback re-binds the connId AND the txnId to the state record (login-CSRF defence) before doing any
//     network work, and resolves the client secret JUST-IN-TIME from the secretRef.
//
// Role-binding (subject/groups -> role) and the session-cookie mint are DOWNSTREAM of this module (the DO
// route + the session core), not here: this store stops at the verified ResolvedPrincipal + the returnTo.
//
// Node 25 strip-types + Workers compatible: Web Crypto + fetch only, no Node builtins, no enums, explicit
// fields, error-as-value at the boundaries.

import { constantTimeEqual, utf8 } from "../crypto/bytes.ts";
import type { IdpConnection, IdpConnectionProposal, Oauth2Connection, OidcConnection } from "./idpconn.ts";
import { redactIdpConn, validateIdpConnection } from "./idpconn.ts";
import type { Oauth2Principal } from "./oauth2.ts";
import { buildOauth2AuthorizeUrl, completeOauth2Login } from "./oauth2.ts";
import type { FlowEndpoints, ResolvedPrincipal } from "./oidc.ts";
import {
  buildAuthorizeUrl,
  completeOidcLogin,
  discoveryUrlFor,
  endpointsFromConnection,
  guardedOidcFetch,
  mintOpaque,
  mintPkce,
  parseDiscovery,
} from "./oidc.ts";
import { makeJwksGetter } from "./oidc-store-jwks.ts";
import type { KvStorage } from "./oidc-store-kv.ts";
import { CONN_PREFIX, connKey, DEFAULT_STATE_TTL_MS, STATE_PREFIX, secretKey, stateKey } from "./oidc-store-kv.ts";

export { makeJwksGetter } from "./oidc-store-jwks.ts";
// The storage substrate (KvStorage interface, key prefixes/builders, the default TTL), the JWKS getter, and
// the SAML SP-initiated request record live in sibling modules; they are re-exported here so importers see
// the same public API on this module.
export type { KvStorage } from "./oidc-store-kv.ts";
export type { SamlRequestRecord } from "./oidc-store-saml.ts";
export {
  consumeSamlRequest,
  putSamlRequest,
  sweepSamlRequests,
} from "./oidc-store-saml.ts";

// ---- connection CRUD ---------------------------------------------------------------------------

// createIdpConnection is the DO create path. It LISTS the existing connections to derive the existing-ids set
// (so the id-collision rule comes from the live store, never the caller), runs the shared PURE validator, and
// on success stamps the createdBy/createdAt the pure validator deliberately omits (it has no identity/clock),
// persists the record under idpconn:<id>, and returns a REDACTED view (defence in depth: the record already
// holds no secret value). On a validation failure it returns the precise reason verbatim. It never throws.
export async function createIdpConnection(
  storage: KvStorage,
  proposal: IdpConnectionProposal,
  createdBy: string | null,
  createdAt: string,
): Promise<{ ok: true; conn: IdpConnection } | { ok: false; reason: string }> {
  const existingIds = new Set<string>();
  for (const conn of await listConnectionsRaw(storage)) existingIds.add(conn.id);
  const validated = validateIdpConnection(proposal, existingIds);
  if (!validated.ok) return { ok: false, reason: validated.reason };
  // Stamp the DO-owned provenance fields onto the validated (sans-provenance) record. The cast is sound: the
  // validated.conn is an Omit<IdpConnection, "createdBy"|"createdAt"> of one concrete kind, and adding the two
  // fields completes that same kind back into an IdpConnection.
  const stored = { ...validated.conn, createdBy, createdAt } as IdpConnection;
  await storage.put(connKey(stored.id), stored);
  return { ok: true, conn: redactIdpConn(stored) };
}

// listConnectionsRaw lists the stored connections UNredacted. Internal: createIdpConnection uses it for the
// id set and getIdpConnectionRaw-by-prefix would be wasteful, so the list path reads the records directly.
async function listConnectionsRaw(storage: KvStorage): Promise<IdpConnection[]> {
  const map = await storage.list<IdpConnection>({ prefix: CONN_PREFIX });
  return [...map.values()];
}

// listIdpConnections returns every stored connection REDACTED, for the console + audit. redactIdpConn is
// applied to each so a secretRef can only ever surface as {mode, ref?} (it already holds no value).
export async function listIdpConnections(storage: KvStorage): Promise<IdpConnection[]> {
  return (await listConnectionsRaw(storage)).map(redactIdpConn);
}

// getIdpConnectionRaw returns the stored connection UNredacted (or undefined). This is the FLOW's source of
// truth (handleOidcStart / handleOidcCallback read it): the record carries no secret value anyway, but the
// flow needs the exact stored config (issuer, endpoints, clientAuth, claim names) to drive verification.
export async function getIdpConnectionRaw(storage: KvStorage, id: string): Promise<IdpConnection | undefined> {
  return storage.get<IdpConnection>(connKey(id));
}

// deleteIdpConnection removes BOTH the connection record AND its paired secret entry (idpsecret:<id>), so a
// deleted connection leaves no orphaned client secret behind. Returns whether the connection record existed.
export async function deleteIdpConnection(storage: KvStorage, id: string): Promise<boolean> {
  const existed = await storage.delete(connKey(id));
  await storage.delete(secretKey(id));
  return existed;
}

// setIdpConnectionEnabled flips the stored enabled flag (disable kills the connection's ability to start a
// login; the DO's per-connection session epoch, keyed elsewhere, kills its LIVE sessions). Returns false for
// an unknown id (nothing to flip), true after a successful write.
export async function setIdpConnectionEnabled(storage: KvStorage, id: string, enabled: boolean): Promise<boolean> {
  const conn = await storage.get<IdpConnection>(connKey(id));
  if (conn === undefined) return false;
  await storage.put(connKey(id), { ...conn, enabled });
  return true;
}

// updateSamlSigningCerts replaces a SAML connection's pinned idpSigningCerts in place (the zero-downtime
// cert-rollover edit path). It get+narrows to kind "saml" (so a non-SAML id or an unknown id is a clean false,
// never a malformed write) and MERGE-writes only the certs, leaving every other field, the enabled flag and the
// provenance untouched. The caller has already validated the new array (validateSamlCerts: 1..8 PEMs); this is
// the storage commit. It does NOT touch the idpEpoch, so live sessions survive the rollover (the whole point).
// Returns false for an unknown / non-SAML id, true after the write.
export async function updateSamlSigningCerts(storage: KvStorage, id: string, certs: string[]): Promise<boolean> {
  const conn = await storage.get<IdpConnection>(connKey(id));
  if (conn === undefined || conn.kind !== "saml") return false;
  await storage.put(connKey(id), { ...conn, idpSigningCerts: certs });
  return true;
}

// ---- the write-only client secret (do-plaintext floor) -----------------------------------------

// putIdpSecret stores the do-plaintext client secret VALUE under idpsecret:<id>. It is WRITE-ONLY from the
// console's perspective: there is no list/read route to it; only the flow (getIdpSecret) reads it, just-in-
// time, at the token exchange. Overwriting rotates the secret. This mirrors the console-set destination secret.
export async function putIdpSecret(storage: KvStorage, id: string, value: string): Promise<void> {
  await storage.put(secretKey(id), value);
}

// getIdpSecret reads the stored client secret. INTERNAL-ONLY: the callback resolves the secret from here for
// the client_secret_* token exchange. It must NEVER be wired to a console-reachable route (that would read the
// secret back out). Returns undefined when no secret is stored (a misconfigured do-plaintext connection then
// fails closed at the exchange, which refuses an absent secret).
export async function getIdpSecret(storage: KvStorage, id: string): Promise<string | undefined> {
  return storage.get<string>(secretKey(id));
}

// deleteIdpSecret removes the stored client secret (rotation-clear, or paired with a connection delete).
export async function deleteIdpSecret(storage: KvStorage, id: string): Promise<boolean> {
  return storage.delete(secretKey(id));
}

// ---- the single-use state record ---------------------------------------------------------------

// OidcStateRecord is the single-use record minted at /start and consumed at the callback. It carries
// EVERYTHING the callback must take from the SERVER (never from the redirect request): the connId it was
// started for, the PKCE codeVerifier (the secret half of the S256 pair), the nonce (the id_token replay bind),
// the exact redirectUri (echoed into the token POST), the post-login returnTo, and the txnId (the login-CSRF
// binding the callback cross-checks against the browser's txn cookie). createdAt is the mint time in epoch
// millis, for the TTL check.
export interface OidcStateRecord {
  connId: string;
  // codeVerifier and nonce are absent (undefined) when the flow does not use them, rather than carrying a
  // sentinel empty string: the OIDC flow always sets both, the OAuth2 flow omits the nonce (no id_token to
  // bind) and omits the codeVerifier for a non-PKCE confidential client. A reader can therefore tell "not
  // applicable" from a real value without guessing.
  codeVerifier?: string;
  nonce?: string;
  redirectUri: string;
  returnTo: string;
  txnId: string;
  createdAt: number;
}

// putOidcState persists a state record under oidcstate:<state>. The state value is the high-entropy opaque
// token minted at /start; it is the lookup key AND the CSRF token in the authorize URL.
export async function putOidcState(storage: KvStorage, state: string, record: OidcStateRecord): Promise<void> {
  await storage.put(stateKey(state), record);
}

// consumeOidcState is the SINGLE-USE primitive. It reads the record, then DELETES it BEFORE returning anything
// (delete-before-return). In the single-threaded DO a get-then-delete is atomic, so this guarantees the record
// can be consumed at most ONCE: a replayed callback (or a double-submit) finds nothing on the second call. The
// TTL is checked AFTER the delete, so even an expired record is removed by the consume (it cannot be retried by
// waiting out a clock change). Returns the record only when it existed AND is within createdAt + ttl; else null.
export async function consumeOidcState(
  storage: KvStorage,
  state: string,
  nowMs: number,
  ttlMs: number = DEFAULT_STATE_TTL_MS,
): Promise<OidcStateRecord | null> {
  const key = stateKey(state);
  const record = await storage.get<OidcStateRecord>(key);
  // Delete unconditionally, BEFORE any return: this is the single-use guarantee. A missing record deletes a
  // no-op (delete returns false) and is treated as "no such state".
  await storage.delete(key);
  if (record === undefined) return null;
  if (record.createdAt + ttlMs <= nowMs) return null;
  return record;
}

// sweepOidcStates prunes abandoned state records (a user who started a login and never completed the callback
// leaves a record behind). It lists the state prefix and deletes every record past its TTL, returning the
// count removed. The DO calls this on its housekeeping alarm so stale records do not accumulate. A fresh
// record is kept. It is purely opportunistic cleanup: the single-use + TTL check in consumeOidcState is the
// security guarantee; this just stops storage from growing without bound.
export async function sweepOidcStates(
  storage: KvStorage,
  nowMs: number,
  ttlMs: number = DEFAULT_STATE_TTL_MS,
): Promise<number> {
  const map = await storage.list<OidcStateRecord>({ prefix: STATE_PREFIX });
  const expired: string[] = [];
  for (const [key, record] of map) {
    if (record.createdAt + ttlMs <= nowMs) expired.push(key);
  }
  // Each delete is independent, so run them in parallel rather than serialising one round-trip per
  // key, which would inflate the alarm-handler wall-clock time linearly with the abandoned-state count.
  await Promise.all(expired.map((key) => storage.delete(key)));
  return expired.length;
}

// ---- the flow orchestrators (start + callback) -------------------------------------------------

// resolveEndpoints returns the FlowEndpoints for a connection: the explicit endpoints when the connection
// carries all three (no discovery round trip), else it fetches discovery (pinned to the issuer host because
// discoveryUrlFor builds the URL from the validated issuer) over the guarded fetch and parses it (parseDiscovery
// binds the doc's issuer to the connection issuer). Returns the endpoints or a precise reason. It never throws.
async function resolveEndpoints(
  conn: OidcConnection,
  doFetch: typeof fetch,
): Promise<{ ok: true; ep: FlowEndpoints } | { ok: false; reason: string }> {
  const explicit = endpointsFromConnection(conn);
  if (explicit !== null) return { ok: true, ep: explicit };
  const discUrl = discoveryUrlFor(conn);
  let resp: { status: number; bodyText: string };
  try {
    resp = await guardedOidcFetch(discUrl, { method: "GET", headers: { accept: "application/json" } }, doFetch);
  } catch (e) {
    return { ok: false, reason: `discovery fetch failed: ${e instanceof Error ? e.message : "error"}` };
  }
  if (resp.status !== 200) return { ok: false, reason: `discovery endpoint returned ${resp.status}` };
  let doc: unknown;
  try {
    doc = JSON.parse(resp.bodyText);
  } catch {
    return { ok: false, reason: "discovery document is not JSON" };
  }
  const parsed = parseDiscovery(doc, conn.issuer);
  if (!parsed.ok) return { ok: false, reason: parsed.reason };
  // PIN authorization_endpoint/token_endpoint to the issuer host - the other half of the discovery-trust
  // chain makeJwksGetter already enforces for jwks_uri, mirrored here almost line for line. parseDiscovery
  // only screens these by host CATEGORY (assertSafeFetchEndpoint), so an unpinned discovery response could
  // otherwise redirect the code exchange (and, for a confidential client, the client_secret) to any ordinary
  // https host. An endpoint this connection configures EXPLICITLY is TRUSTED and used AS-IS in place of the
  // discovery value (it was assertSafeFetchEndpoint-validated at config time, the same operator-asserted
  // tier the jwksUri override uses - e.g. Google's real token_endpoint legitimately lives off-issuer-host,
  // see oidc-presets.ts tokenEndpointTemplate); otherwise the freshly-fetched value MUST match the issuer host.
  let issuerHost: string;
  try {
    issuerHost = new URL(conn.issuer).hostname.toLowerCase();
  } catch {
    return { ok: false, reason: "the connection issuer is not a valid URL" };
  }
  const pinToIssuer = (name: string, field: string, discovered: string, override: string | undefined): { ok: true; value: string } | { ok: false; reason: string } => {
    if (override !== undefined) return { ok: true, value: override };
    let epHost: string;
    try {
      epHost = new URL(discovered).hostname.toLowerCase();
    } catch {
      return { ok: false, reason: `discovery ${name} is not a valid URL` };
    }
    if (epHost !== issuerHost) {
      return { ok: false, reason: `discovery ${name} host "${epHost}" does not match the issuer host "${issuerHost}"; configure an explicit ${field} if this provider legitimately serves it off-issuer-host` };
    }
    return { ok: true, value: discovered };
  };
  const az = pinToIssuer("authorization_endpoint", "authorizationEndpoint", parsed.endpoints.authorizationEndpoint, conn.authorizationEndpoint);
  if (!az.ok) return az;
  const tok = pinToIssuer("token_endpoint", "tokenEndpoint", parsed.endpoints.tokenEndpoint, conn.tokenEndpoint);
  if (!tok.ok) return tok;
  return { ok: true, ep: { ...parsed.endpoints, authorizationEndpoint: az.value, tokenEndpoint: tok.value } };
}

// handleOidcStart is the /start orchestrator. It mints the PKCE pair + the single-use state + the nonce + the
// login-CSRF txnId, resolves the endpoints (explicit or via discovery), builds the authorize URL, and PERSISTS
// the state record (everything the callback must take from the server). It returns the authorize URL the
// console redirects the browser to, plus the state (the CSRF token) and the txnId (the value the console also
// drops in a short-TTL browser cookie so the callback can cross-check it). Returns a precise reason on any
// failure (it never throws). The state record is written LAST, after the authorize URL is successfully built,
// so a failed start leaves no orphaned state.
export async function handleOidcStart(
  storage: KvStorage,
  conn: OidcConnection,
  redirectUri: string,
  returnTo: string,
  doFetch: typeof fetch,
  nowMs: number,
): Promise<{ ok: true; authorizeUrl: string; state: string; txnId: string } | { ok: false; reason: string }> {
  if (!conn.enabled) return { ok: false, reason: `connection "${conn.id}" is disabled` };
  const resolved = await resolveEndpoints(conn, doFetch);
  if (!resolved.ok) return { ok: false, reason: resolved.reason };
  const ep = resolved.ep;

  const pkce = await mintPkce();
  const state = mintOpaque();
  const nonce = mintOpaque();
  const txnId = mintOpaque();

  const authorizeUrl = buildAuthorizeUrl(conn, ep, { state, nonce, challenge: pkce.challenge, redirectUri });

  const record: OidcStateRecord = {
    connId: conn.id,
    codeVerifier: pkce.verifier,
    nonce,
    redirectUri,
    returnTo,
    txnId,
    createdAt: nowMs,
  };
  await putOidcState(storage, state, record);
  return { ok: true, authorizeUrl, state, txnId };
}

// resolveOidcCallbackConnection resolves and validates the OIDC connection for the callback (step 3 of
// handleOidcCallback): it rejects a connection deleted between /start and /callback, one that is not an OIDC
// connection, or one disabled mid-flight, then runs the RFC 9207 mix-up check. That check requires the IdP's
// `iss` authorization-response parameter (when present) to equal this connection's issuer; the distinct
// per-connId callback path + the state.connId bind are the STRUCTURAL halves, this is the explicit parameter
// check. It is skipped only for a connection that SUBSTITUTES its issuer (Entra multitenant, where conn.issuer
// carries the {tenantid} template, not the concrete per-tenant issuer the IdP sends) - there the authoritative
// tid-substituted id_token `iss` check in completeOidcLogin plus the acceptedTenantIds allowlist remain the
// backstop. An IdP that omits `iss` likewise falls through to that authoritative id_token check.
async function resolveOidcCallbackConnection(
  getConn: (id: string) => Promise<OidcConnection | undefined>,
  params: { connId: string; iss?: string },
): Promise<{ ok: true; conn: OidcConnection } | { ok: false; reason: string }> {
  const conn = await getConn(params.connId);
  if (conn === undefined) return { ok: false, reason: `connection "${params.connId}" not found` };
  if (conn.kind !== "oidc") return { ok: false, reason: `connection "${params.connId}" is not an OIDC connection` };
  // Refuse a connection DISABLED between /start and /callback: a disabled connection must never mint a session.
  if (!conn.enabled) return { ok: false, reason: `connection "${params.connId}" is disabled` };
  if (params.iss !== undefined && conn.issuerSubstitution === undefined && params.iss !== conn.issuer) {
    return { ok: false, reason: "RFC 9207 iss mismatch (possible IdP mix-up)" };
  }
  return { ok: true, conn };
}

// resolveOidcClientSecret resolves the client secret just-in-time from the OIDC connection's secretRef (step 4
// of handleOidcCallback). do-plaintext reads idpsecret:<id> (failing closed when absent); pkce-public carries
// no secret (the exchange uses PKCE only); secrets-store and private-key-jwt are not wired in this build and
// are refused with a clear reason. Returns the resolved secret (or undefined for a public client) as a value.
async function resolveOidcClientSecret(
  storage: KvStorage,
  conn: OidcConnection,
): Promise<{ ok: true; clientSecret: string | undefined } | { ok: false; reason: string }> {
  const mode = conn.secretRef.mode;
  if (mode === "do-plaintext") {
    const clientSecret = await getIdpSecret(storage, conn.id);
    if (clientSecret === undefined) return { ok: false, reason: "no stored client secret for this connection (do-plaintext)" };
    return { ok: true, clientSecret };
  } else if (mode === "pkce-public") {
    return { ok: true, clientSecret: undefined }; // a public client carries no secret; the exchange uses PKCE only
  } else if (mode === "secrets-store") {
    return { ok: false, reason: "secrets-store secret resolution not wired in this build" };
  } else if (mode === "private-key-jwt") {
    return { ok: false, reason: "private-key-jwt secret resolution not wired in this build" };
  } else {
    return { ok: false, reason: `unsupported secret mode: ${mode}` };
  }
}

// handleOidcCallback is the callback orchestrator. It enforces the CALLER OBLIGATIONS (oidc.ts) end to end:
//   1. CONSUME the state record ATOMICALLY (delete-before-return) and reject a missing/replayed/expired one;
//   2. cross-check record.connId === the callback's connId AND record.txnId === the callback's txnId (the
//      login-CSRF defence: a forged callback for a session the victim did not start is refused) BEFORE any
//      network work;
//   3. resolve the connection (rejecting one deleted between start and callback);
//   4. resolve the client secret JUST-IN-TIME from the secretRef: from idpsecret:<id> for the do-plaintext
//      floor; the 'secrets-store' and 'private-key-jwt' modes are not wired in this build and are refused with
//      a clear reason (they need a Secrets Store binding / the engine-held key, both out of this module's scope);
//   5. resolve the endpoints (explicit or discovery), build the JWKS getter (with the host pin), and call the
//      PURE completeOidcLogin, passing the codeVerifier + nonce + redirectUri FROM THE RECORD (never the request).
// On success it returns the verified ResolvedPrincipal + the record's returnTo. Role-binding + the session mint
// are DOWNSTREAM. Returns a precise reason on any failure; it never throws.
export async function handleOidcCallback(
  storage: KvStorage,
  params: { connId: string; code: string; state: string; txnId: string; iss?: string },
  getConn: (id: string) => Promise<OidcConnection | undefined>,
  doFetch: typeof fetch,
  nowMs: number,
): Promise<{ ok: true; principal: ResolvedPrincipal; returnTo: string } | { ok: false; reason: string; code?: "tenant_not_accepted" | "hd_not_accepted" }> {
  // 1. Single-use state consume (atomic delete-before-return).
  const record = await consumeOidcState(storage, params.state, nowMs);
  if (record === null) return { ok: false, reason: "unknown, expired or already-used state" };

  // 2. Login-CSRF binds: the callback's connId AND txnId must match the record's. Checked BEFORE any network
  //    work so a forged callback is rejected without a token exchange.
  if (record.connId !== params.connId) return { ok: false, reason: "state connId does not match the callback connId" };
  // The txnId is a per-login CSRF token, so it is compared in constant time (length is not secret).
  if (!constantTimeEqual(utf8(record.txnId), utf8(params.txnId))) return { ok: false, reason: "transaction id mismatch (possible login CSRF)" };

  // 3. Resolve the connection (it may have been deleted between start and callback) and run the RFC 9207 check.
  const connResult = await resolveOidcCallbackConnection(getConn, params);
  if (!connResult.ok) return { ok: false, reason: connResult.reason };
  const conn = connResult.conn;

  // 4. Resolve the client secret just-in-time from the secretRef.
  const secret = await resolveOidcClientSecret(storage, conn);
  if (!secret.ok) return { ok: false, reason: secret.reason };
  const clientSecret = secret.clientSecret;

  // 5. Resolve the endpoints, build the JWKS getter (host-pinned), and complete the login via the pure core,
  //    taking the codeVerifier + nonce + redirectUri FROM THE RECORD.
  const resolved = await resolveEndpoints(conn, doFetch);
  if (!resolved.ok) return { ok: false, reason: resolved.reason };
  const ep = resolved.ep;
  const getJwks = makeJwksGetter(conn, ep, doFetch);

  const result = await completeOidcLogin(
    conn,
    ep,
    {
      code: params.code,
      // The OIDC start always persists both, so these are present here; the ?? "" keeps the string contract
      // of completeOidcLogin should a record ever arrive without them (it would then fail the nonce bind).
      codeVerifier: record.codeVerifier ?? "",
      nonce: record.nonce ?? "",
      redirectUri: record.redirectUri,
      ...(clientSecret !== undefined ? { clientSecret } : {}),
    },
    { doFetch, getJwks },
    Math.floor(nowMs / 1000),
  );
  if (!result.ok) return { ok: false, reason: result.reason, ...(result.code ? { code: result.code } : {}) };
  return { ok: true, principal: result.principal, returnTo: record.returnTo };
}

// ---- the OAuth2 (no id_token, GitHub-class) flow orchestrators --------------------------------

// handleOauth2Start is the /start orchestrator for a no-id_token provider: it mints the single-use state +
// the login-CSRF txnId (+ a PKCE pair ONLY when the connection opts in), builds the authorize URL, and
// persists the state record (everything the callback must take from the server). There is NO discovery and NO
// nonce (no id_token to bind one to); the single-use state IS the CSRF/replay defence. The record's verifier
// is empty for a confidential OAuth App (it relies on the state + the client secret). Returns the authorize
// URL + state + txnId, or a precise reason; it never throws. Unlike the OIDC start it needs no doFetch (no
// discovery): the authorize/token endpoints are explicit on the connection.
export async function handleOauth2Start(
  storage: KvStorage,
  conn: Oauth2Connection,
  redirectUri: string,
  returnTo: string,
  nowMs: number,
): Promise<{ ok: true; authorizeUrl: string; state: string; txnId: string } | { ok: false; reason: string }> {
  if (!conn.enabled) return { ok: false, reason: `connection "${conn.id}" is disabled` };
  const state = mintOpaque();
  const txnId = mintOpaque();
  const pkce = conn.pkce === "supported" ? await mintPkce() : null;
  const authorizeUrl = buildOauth2AuthorizeUrl(conn, { state, redirectUri, ...(pkce !== null ? { challenge: pkce.challenge } : {}) });
  const record: OidcStateRecord = {
    connId: conn.id,
    // OAuth2 has no id_token, so no nonce; the codeVerifier is present only for a PKCE-capable client. Both
    // stay absent (undefined) otherwise rather than a sentinel empty string.
    ...(pkce !== null ? { codeVerifier: pkce.verifier } : {}),
    redirectUri,
    returnTo,
    txnId,
    createdAt: nowMs,
  };
  await putOidcState(storage, state, record);
  return { ok: true, authorizeUrl, state, txnId };
}

// handleOauth2Callback is the callback orchestrator for a no-id_token provider. Like handleOidcCallback it
// consumes the single-use state ATOMICALLY (delete-before-exchange), binds connId + txnId BEFORE any network
// work, resolves the connection (rejecting one deleted/disabled mid-flight), resolves the client secret
// just-in-time from the secretRef, and calls the PURE completeOauth2Login with the codeVerifier + redirectUri
// FROM THE RECORD. There is NO nonce, NO id_token and NO RFC 9207 iss param here (an OAuth2 provider returns
// none); the single-use state IS the CSRF/replay defence. On success it returns the verified Oauth2Principal +
// the record's returnTo. Role binding + the v3 session mint are DOWNSTREAM (the DO). Returns a precise reason
// on any failure; it never throws.
export async function handleOauth2Callback(
  storage: KvStorage,
  params: { connId: string; code: string; state: string; txnId: string },
  getConn: (id: string) => Promise<Oauth2Connection | undefined>,
  doFetch: typeof fetch,
  nowMs: number,
): Promise<{ ok: true; principal: Oauth2Principal; returnTo: string } | { ok: false; reason: string }> {
  const record = await consumeOidcState(storage, params.state, nowMs);
  if (record === null) return { ok: false, reason: "unknown, expired or already-used state" };
  if (record.connId !== params.connId) return { ok: false, reason: "state connId does not match the callback connId" };
  // The txnId is a per-login CSRF token, so it is compared in constant time (length is not secret).
  if (!constantTimeEqual(utf8(record.txnId), utf8(params.txnId))) return { ok: false, reason: "transaction id mismatch (possible login CSRF)" };
  const conn = await getConn(params.connId);
  if (conn === undefined) return { ok: false, reason: `connection "${params.connId}" not found` };
  if (conn.kind !== "oauth2") return { ok: false, reason: `connection "${params.connId}" is not an OAuth2 connection` };
  if (!conn.enabled) return { ok: false, reason: `connection "${params.connId}" is disabled` };

  // Resolve the client secret just-in-time from the secretRef (mirrors handleOidcCallback). private-key-jwt is
  // an OIDC-only client-auth method and is not valid for an OAuth2 connection; secrets-store is a later wiring.
  const mode = conn.secretRef.mode;
  let clientSecret: string | undefined;
  if (mode === "do-plaintext") {
    clientSecret = await getIdpSecret(storage, conn.id);
    if (clientSecret === undefined) return { ok: false, reason: "no stored client secret for this connection (do-plaintext)" };
  } else if (mode === "pkce-public") {
    clientSecret = undefined; // a public client carries no secret; the exchange uses PKCE only
  } else if (mode === "secrets-store") {
    return { ok: false, reason: "secrets-store secret resolution not wired in this build" };
  } else {
    return { ok: false, reason: `unsupported secret mode for an OAuth2 connection: ${mode}` };
  }

  const result = await completeOauth2Login(
    conn,
    {
      code: params.code,
      redirectUri: record.redirectUri,
      ...(record.codeVerifier !== undefined ? { codeVerifier: record.codeVerifier } : {}),
      ...(clientSecret !== undefined ? { clientSecret } : {}),
    },
    doFetch,
  );
  if (!result.ok) return { ok: false, reason: result.reason };
  return { ok: true, principal: result.principal, returnTo: record.returnTo };
}
