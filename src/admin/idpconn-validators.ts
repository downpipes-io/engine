// Per-kind validators for the IdP-connection substrate, split out of idpconn.ts to keep that file under the
// structural size budget. This module is MOVED logic, not rewritten: the validateOidc / validateOauth2 /
// validateSaml functions, the validateSecretRef helper, the shared string-coercion primitives and the bounds
// constants live here verbatim. idpconn.ts keeps the public discriminated-union types and the
// validateIdpConnection dispatcher, and imports these per-kind validators at runtime. The type imports here
// are type-only (erased), so the runtime dependency is one-directional idpconn -> idpconn-validators.

import { isConnId } from "./identity.ts";
import type {
  IdpConnection,
  IdpConnectionProposal,
  Oauth2Connection,
  OidcClientAuth,
  OidcConnection,
  SamlConnection,
  SecretRef,
} from "./idpconn-types.ts";
import type { IdTokenAlg } from "./oidc-verify.ts";
import { assertSafeFetchEndpoint, assertSafeIssuer } from "./oidc-verify.ts";

// A distributive Omit. The built-in Omit<T, K> is Pick<T, Exclude<keyof T, K>>, and keyof over a UNION is
// only the keys common to every member, so a plain Omit<IdpConnection, ...> would collapse the three-variant
// union down to the shared IdpConnectionBase fields and lose every kind-specific field (issuer, secretRef,
// idpSigningCerts and the rest). Distributing over the union with a conditional preserves each member's own
// shape, so the validated record stays a proper discriminated union that narrows on `kind`.
type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;

export type ValidateResult =
  | { ok: true; conn: DistributiveOmit<IdpConnection, "createdBy" | "createdAt"> }
  | { ok: false; reason: string };

export interface Base { id: string; label: string; presetId: string; enabled: boolean }

// ---- bounds ------------------------------------------------------------------------------------
const LABEL_MAX = 128;
const CLIENT_ID_MAX = 512;
const SCOPE_MAX = 64;
const SCOPES_MAX = 32;
const CLAIM_NAME_MAX = 128;
const REF_MAX = 256;
const PRESET_ID_MAX = 64;
const TENANT_IDS_MAX = 32;
const ISSUER_VARIANTS_MAX = 4;
const EXTRA_PARAMS_MAX = 8;

// These bounds are consumed by the validateIdpConnection dispatcher in idpconn.ts (label / presetId / id).
export { LABEL_MAX, PRESET_ID_MAX };

function str(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}
function boundedStr(v: unknown, max: number): string | null {
  const s = str(v);
  if (s === null) return null;
  const t = s.trim();
  if (t.length < 1 || t.length > max) return null;
  // Reject ASCII control characters + DEL: none are valid in a label / id / claim-name / entityId / NameID
  // format, and an XML-illegal control char in a SAML field would otherwise be emitted verbatim into the SP
  // metadata (a document the operator pastes into their IdP), producing XML a strict parser refuses to load.
  // This hardens every boundedStr field (OIDC + OAuth2 + SAML) at the one input gate.
  for (let i = 0; i < t.length; i++) {
    const c = t.charCodeAt(i);
    if (c <= 0x08 || c === 0x0b || c === 0x0c || (c >= 0x0e && c <= 0x1f) || c === 0x7f) return null;
  }
  return t;
}
// strArray bounds an array of bounded strings. By default it DE-DUPES silently, which is right for a
// permissive set (scopes, tenant ids, issuer variants): asking for "openid" twice means asking for it once.
//
// rejectDuplicates is for the sets where the de-dupe HIDES the operator's question. A SAML signing cert is
// the trust root, and a rollover appends one to the pinned array; an append of a cert already in the array
// collapsed to the same array and answered ok:true, so the operator was told the new certificate was trusted
// when nothing had changed and the cutover would break at the IdP's switch
// . Nobody legitimately pins one certificate twice.
function strArray(v: unknown, maxItems: number, maxLen: number, rejectDuplicates = false): string[] | null {
  if (!Array.isArray(v)) return null;
  if (v.length > maxItems) return null;
  const out: string[] = [];
  for (const e of v) {
    const s = boundedStr(e, maxLen);
    if (s === null) return null;
    if (out.includes(s)) {
      if (rejectDuplicates) return null;
      continue;
    }
    out.push(s);
  }
  return out;
}

// The dispatcher validates the shared fields (id / label / presetId / enabled), so boundedStr is shared.
export { boundedStr, str };

// validateSecretRef enforces the consistency between the chosen client-auth method and how the secret is
// held: a public client holds nothing; a confidential client must name a store (secrets-store, with a
// reference) or use the do-plaintext floor (no ref, the value lives in idpsecret:<id>); private_key_jwt
// references the engine-held key. A value is NEVER accepted here (the record holds no value), so even a
// console that tried to POST a raw secret in the connection body has it ignored by construction.
function validateSecretRef(raw: unknown, clientAuth: OidcClientAuth): { ok: true; ref: SecretRef } | { ok: false; reason: string } {
  if (clientAuth === "pkce_public") return { ok: true, ref: { mode: "pkce-public" } };
  if (typeof raw !== "object" || raw === null) return { ok: false, reason: "secretRef must be an object for a confidential client" };
  const rec = raw as Record<string, unknown>;
  const mode = rec.mode;
  if (clientAuth === "private_key_jwt") {
    // private_key_jwt client authentication is not yet implemented (the engine-held signing key path is a
    // fast-follow). Reject it at CONFIG TIME so a connection can never be saved in a state that only fails
    // at first login. The runtime exchange carries a matching guard as defence in depth.
    return { ok: false, reason: "private_key_jwt client authentication is not yet supported; use client_secret_post, client_secret_basic, or pkce_public" };
  }
  // client_secret_post / client_secret_basic: do-plaintext is the supported floor (no ref; the value lives
  // in idpsecret:<id>). secrets-store resolution is not yet wired, so it is rejected here at config time
  // rather than failing closed at the token exchange.
  if (mode === "do-plaintext") return { ok: true, ref: { mode: "do-plaintext" } };
  if (mode === "secrets-store") {
    return { ok: false, reason: "secrets-store secret resolution is not yet supported; use the do-plaintext secret mode" };
  }
  return { ok: false, reason: "a confidential client secretRef.mode must be 'do-plaintext'" };
}

// validateSecretExpiresAt resolves the OPTIONAL operator-declared client-secret expiry. It is
// redaction-safe metadata (an RFC-3339 date the operator copies from their IdP), NEVER the secret value, so
// it is checked only for shape: absent -> undefined (no declared expiry); present -> a parseable RFC-3339
// timestamp, else a precise reason. It is meaningful only for a confidential client (a pkce-public client has
// no secret to expire), but it is accepted on any proposal and simply not OBSERVED for a public client, so
// the validator stays a pure shape gate and the create path decides whether to track it.
function validateSecretExpiresAt(raw: unknown): { ok: true; value: string | undefined } | { ok: false; reason: string } {
  if (raw === undefined) return { ok: true, value: undefined };
  if (typeof raw !== "string" || !Number.isFinite(Date.parse(raw))) return { ok: false, reason: "secretExpiresAt must be an RFC-3339 timestamp" };
  return { ok: true, value: raw };
}

// validateOidcEndpoints checks the optional discovery / authorization / token / jwks endpoints are safe fetch
// targets (https, not IP/localhost/cloudflareaccess) and pins an explicit discoveryUrl to the issuer host.
// It only validates; the caller copies the accepted values onto the connection.
function validateOidcEndpoints(p: IdpConnectionProposal, issuer: string): { ok: true } | { ok: false; reason: string } {
  for (const [name, val] of [["discoveryUrl", p.discoveryUrl], ["authorizationEndpoint", p.authorizationEndpoint], ["tokenEndpoint", p.tokenEndpoint], ["jwksUri", p.jwksUri]] as const) {
    if (val !== undefined) {
      const s = str(val);
      if (s === null) return { ok: false, reason: `${name} must be a string` };
      try {
        assertSafeFetchEndpoint(s);
      } catch (e) {
        return { ok: false, reason: `${name}: ${e instanceof Error ? e.message : "invalid endpoint"}` };
      }
    }
  }
  // Pin an explicit discoveryUrl to the ISSUER host: the .well-known document lives on the issuer's own host,
  // so a discoveryUrl on a different host is refused (it would let a connection point the discovery -> JWKS
  // trust chain at an unrelated host). A multitenant {tenantid} issuer template still has a fixed host part.
  if (p.discoveryUrl !== undefined) {
    try {
      if (new URL(p.discoveryUrl as string).hostname.toLowerCase() !== new URL(issuer).hostname.toLowerCase()) {
        return { ok: false, reason: "discoveryUrl host must match the issuer host" };
      }
    } catch {
      return { ok: false, reason: "discoveryUrl must be a valid URL" };
    }
  }
  return { ok: true };
}

// validateOidcClaims copies the optional, bounded claim / domain / tenant / endpoint / extra-param fields onto
// the connection, returning a reason on the first malformed field. The endpoints have already passed
// validateOidcEndpoints, so here they are only copied across.
function validateOidcClaims(p: IdpConnectionProposal, conn: Omit<OidcConnection, "createdBy" | "createdAt">): { ok: true } | { ok: false; reason: string } {
  const groupsClaim = p.groupsClaim !== undefined ? boundedStr(p.groupsClaim, CLAIM_NAME_MAX) : undefined;
  if (p.groupsClaim !== undefined && groupsClaim === null) return { ok: false, reason: "groupsClaim must be a short string" };
  if (groupsClaim) conn.groupsClaim = groupsClaim;
  const rolesClaim = p.rolesClaim !== undefined ? boundedStr(p.rolesClaim, CLAIM_NAME_MAX) : undefined;
  if (p.rolesClaim !== undefined && rolesClaim === null) return { ok: false, reason: "rolesClaim must be a short string" };
  if (rolesClaim) conn.rolesClaim = rolesClaim;
  const claimNamespace = p.claimNamespace !== undefined ? boundedStr(p.claimNamespace, CLAIM_NAME_MAX) : undefined;
  if (p.claimNamespace !== undefined && claimNamespace === null) return { ok: false, reason: "claimNamespace must be a short string" };
  if (claimNamespace) conn.claimNamespace = claimNamespace;
  const hdDomain = p.hdDomain !== undefined ? boundedStr(p.hdDomain, CLAIM_NAME_MAX) : undefined;
  if (p.hdDomain !== undefined && hdDomain === null) return { ok: false, reason: "hdDomain must be a short string" };
  if (hdDomain) conn.hdDomain = hdDomain;
  if (typeof p.checkAzp === "boolean") conn.checkAzp = p.checkAzp;
  if (p.issuerSubstitution !== undefined) {
    if (p.issuerSubstitution !== "tid") return { ok: false, reason: "issuerSubstitution, if set, must be 'tid'" };
    conn.issuerSubstitution = "tid";
  }
  if (p.acceptedTenantIds !== undefined) {
    const t = strArray(p.acceptedTenantIds, TENANT_IDS_MAX, CLAIM_NAME_MAX);
    if (t === null) return { ok: false, reason: "acceptedTenantIds must be an array of short strings" };
    conn.acceptedTenantIds = t;
  }
  if (p.acceptIssuerVariants !== undefined) {
    const v = strArray(p.acceptIssuerVariants, ISSUER_VARIANTS_MAX, CLIENT_ID_MAX);
    if (v === null) return { ok: false, reason: "acceptIssuerVariants must be a small array of strings" };
    conn.acceptIssuerVariants = v;
  }
  // Each entry pairs a candidate endpoint value with its setter; the leading field-name slot is not
  // needed in this loop, so we skip it with an empty destructure hole. `val as string` is safe here
  // because any defined endpoint has already passed assertSafeFetchEndpoint in the validation loop
  // above (line 112), which narrows it to a validated string before this assignment runs.
  for (const [, val, set] of [["discoveryUrl", p.discoveryUrl, (s: string) => (conn.discoveryUrl = s)], ["authorizationEndpoint", p.authorizationEndpoint, (s: string) => (conn.authorizationEndpoint = s)], ["tokenEndpoint", p.tokenEndpoint, (s: string) => (conn.tokenEndpoint = s)], ["jwksUri", p.jwksUri, (s: string) => (conn.jwksUri = s)]] as const) {
    if (val !== undefined) set(val as string);
  }
  if (p.extraAuthParams !== undefined) {
    if (typeof p.extraAuthParams !== "object" || p.extraAuthParams === null || Array.isArray(p.extraAuthParams)) return { ok: false, reason: "extraAuthParams must be an object" };
    const entries = Object.entries(p.extraAuthParams as Record<string, unknown>);
    if (entries.length > EXTRA_PARAMS_MAX) return { ok: false, reason: `extraAuthParams may have at most ${EXTRA_PARAMS_MAX} entries` };
    const out: Record<string, string> = {};
    for (const [k, val] of entries) {
      const kk = boundedStr(k, CLAIM_NAME_MAX);
      const vv = boundedStr(val, CLAIM_NAME_MAX);
      if (kk === null || vv === null) return { ok: false, reason: "extraAuthParams keys and values must be short strings" };
      out[kk] = vv;
    }
    conn.extraAuthParams = out;
  }
  return { ok: true };
}

// validateOidcMultitenantCrosscheck enforces the Entra multitenant invariants between issuerSubstitution,
// the {tenantid} placeholder and the acceptedTenantIds allowlist (see inline rationale).
function validateOidcMultitenantCrosscheck(conn: Omit<OidcConnection, "createdBy" | "createdAt">, issuer: string): { ok: true } | { ok: false; reason: string } {
  // 'tid' (Entra multitenant) needs the {tenantid} placeholder in the issuer AND a non-empty acceptedTenantIds
  // allowlist, else every login fails closed with an opaque "issuer not accepted"; conversely a {tenantid}
  // placeholder WITHOUT 'tid' would never exact-match a real token iss.
  if (conn.issuerSubstitution === "tid") {
    if (!issuer.includes("{tenantid}")) return { ok: false, reason: "issuerSubstitution:'tid' requires the issuer to contain the {tenantid} placeholder" };
    if (conn.acceptedTenantIds === undefined || conn.acceptedTenantIds.length === 0) return { ok: false, reason: "issuerSubstitution:'tid' requires a non-empty acceptedTenantIds allowlist" };
  } else if (issuer.includes("{tenantid}")) {
    return { ok: false, reason: "the issuer contains a {tenantid} placeholder but issuerSubstitution is not 'tid'" };
  }
  return { ok: true };
}

export function validateOidc(p: IdpConnectionProposal, base: Base): ValidateResult {
  const issuer = str(p.issuer);
  if (issuer === null) return { ok: false, reason: "issuer must be a string" };
  try {
    assertSafeIssuer(issuer);
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : "invalid issuer" };
  }
  const clientId = boundedStr(p.clientId, CLIENT_ID_MAX);
  if (clientId === null) return { ok: false, reason: "clientId must be a non-empty string" };
  const scopes = strArray(p.scopes, SCOPES_MAX, SCOPE_MAX);
  if (scopes === null) return { ok: false, reason: "scopes must be an array of short strings" };
  if (!scopes.includes("openid")) return { ok: false, reason: "scopes must include 'openid'" };
  // idTokenSigAlgs: non-empty subset of {RS256, ES256}
  if (!Array.isArray(p.idTokenSigAlgs) || p.idTokenSigAlgs.length === 0) return { ok: false, reason: "idTokenSigAlgs must be a non-empty array" };
  const algs: IdTokenAlg[] = [];
  for (const a of p.idTokenSigAlgs) {
    if (a !== "RS256" && a !== "ES256") return { ok: false, reason: `unsupported id_token signing alg: ${typeof a === "string" ? a : "<non-string>"} (only RS256, ES256)` };
    if (!algs.includes(a)) algs.push(a);
  }
  if (p.pkce !== "required" && p.pkce !== "supported") return { ok: false, reason: "pkce must be 'required' or 'supported'" };
  const clientAuth = p.clientAuth;
  if (clientAuth !== "client_secret_post" && clientAuth !== "client_secret_basic" && clientAuth !== "pkce_public" && clientAuth !== "private_key_jwt") {
    return { ok: false, reason: "clientAuth must be client_secret_post | client_secret_basic | pkce_public | private_key_jwt" };
  }
  // RFC 7617 2 forbids a colon in the Basic user-id. A clientId carrying a colon would split the
  // user/password fields wrong once base64-encoded, so reject it at save time when Basic is selected.
  if (clientAuth === "client_secret_basic" && clientId.includes(":")) {
    return { ok: false, reason: "clientId must not contain a colon when clientAuth is client_secret_basic (RFC 7617)" };
  }
  if (p.requireNonce !== true) return { ok: false, reason: "requireNonce must be true (the authorization-code flow always requires a nonce)" };
  const secret = validateSecretRef(p.secretRef, clientAuth);
  if (!secret.ok) return { ok: false, reason: secret.reason };

  const endpoints = validateOidcEndpoints(p, issuer);
  if (!endpoints.ok) return { ok: false, reason: endpoints.reason };

  const conn: Omit<OidcConnection, "createdBy" | "createdAt"> = {
    kind: "oidc",
    ...base,
    issuer,
    clientId,
    secretRef: secret.ref,
    scopes,
    idTokenSigAlgs: algs,
    pkce: p.pkce,
    clientAuth,
    requireNonce: true,
  };
  const claims = validateOidcClaims(p, conn);
  if (!claims.ok) return { ok: false, reason: claims.reason };
  const crosscheck = validateOidcMultitenantCrosscheck(conn, issuer);
  if (!crosscheck.ok) return { ok: false, reason: crosscheck.reason };
  const secretExpiry = validateSecretExpiresAt(p.secretExpiresAt);
  if (!secretExpiry.ok) return { ok: false, reason: secretExpiry.reason };
  if (secretExpiry.value !== undefined) conn.secretExpiresAt = secretExpiry.value;
  return { ok: true, conn };
}

// validateOauth2Urls checks the four required endpoints are strings and safe fetch targets, returning them as
// a tuple for the caller to place on the connection.
function validateOauth2Urls(p: IdpConnectionProposal): { ok: true; urls: { authorizeUrl: string; tokenUrl: string; profileUrl: string; apiBase: string } } | { ok: false; reason: string } {
  const authorizeUrl = str(p.authorizeUrl);
  const tokenUrl = str(p.tokenUrl);
  const profileUrl = str(p.profileUrl);
  const apiBase = str(p.apiBase);
  for (const [name, val] of [["authorizeUrl", authorizeUrl], ["tokenUrl", tokenUrl], ["profileUrl", profileUrl], ["apiBase", apiBase]] as const) {
    if (val === null) return { ok: false, reason: `${name} must be a string` };
    try {
      assertSafeFetchEndpoint(val);
    } catch (e) {
      return { ok: false, reason: `${name}: ${e instanceof Error ? e.message : "invalid endpoint"}` };
    }
  }
  return { ok: true, urls: { authorizeUrl: authorizeUrl as string, tokenUrl: tokenUrl as string, profileUrl: profileUrl as string, apiBase: apiBase as string } };
}

// validateOauth2OptionalFields copies the optional email / display-name / groups fields onto the connection,
// returning a reason on the first malformed field. The groups URLs are re-checked as safe fetch targets.
function validateOauth2OptionalFields(p: IdpConnectionProposal, conn: Omit<Oauth2Connection, "createdBy" | "createdAt">): { ok: true } | { ok: false; reason: string } {
  const emailUrl = p.emailUrl !== undefined ? str(p.emailUrl) : undefined;
  if (emailUrl !== undefined && emailUrl !== null) {
    try {
      assertSafeFetchEndpoint(emailUrl);
    } catch (e) {
      return { ok: false, reason: `emailUrl: ${e instanceof Error ? e.message : "invalid endpoint"}` };
    }
    conn.emailUrl = emailUrl;
  }
  // PRESENT-AND-UNUSABLE IS A REFUSAL, NOT A DROP. These four used to be a bare truthiness guard, so an
  // over-length or control-character-bearing path fell through the `if` and the connection saved 200 with the
  // mapping ABSENT. validateOidcClaims above already refuses on exactly this sentinel for its own claim
  // fields; the OAuth2 and SAML branches were the two that did not, and groupsPath is authorisation.
  const emailPath = p.emailPath !== undefined ? boundedStr(p.emailPath, CLAIM_NAME_MAX) : undefined;
  if (p.emailPath !== undefined && emailPath === null) return { ok: false, reason: "emailPath must be a short string" };
  if (emailPath) conn.emailPath = emailPath;
  const emailVerifiedPath = p.emailVerifiedPath !== undefined ? boundedStr(p.emailVerifiedPath, CLAIM_NAME_MAX) : undefined;
  if (p.emailVerifiedPath !== undefined && emailVerifiedPath === null) return { ok: false, reason: "emailVerifiedPath must be a short string" };
  if (emailVerifiedPath) conn.emailVerifiedPath = emailVerifiedPath;
  const displayNamePath = p.displayNamePath !== undefined ? boundedStr(p.displayNamePath, CLAIM_NAME_MAX) : undefined;
  if (p.displayNamePath !== undefined && displayNamePath === null) return { ok: false, reason: "displayNamePath must be a short string" };
  if (displayNamePath) conn.displayNamePath = displayNamePath;
  if (p.groupsUrls !== undefined) {
    const gu = strArray(p.groupsUrls, 8, REF_MAX);
    if (gu === null) return { ok: false, reason: "groupsUrls must be a small array of strings" };
    for (const u of gu) {
      try {
        assertSafeFetchEndpoint(u);
      } catch (e) {
        return { ok: false, reason: `groupsUrls: ${e instanceof Error ? e.message : "invalid endpoint"}` };
      }
    }
    conn.groupsUrls = gu;
  }
  const groupsPath = p.groupsPath !== undefined ? boundedStr(p.groupsPath, CLAIM_NAME_MAX) : undefined;
  if (p.groupsPath !== undefined && groupsPath === null) return { ok: false, reason: "groupsPath must be a short string" };
  if (groupsPath) conn.groupsPath = groupsPath;
  return { ok: true };
}

export function validateOauth2(p: IdpConnectionProposal, base: Base): ValidateResult {
  const urls = validateOauth2Urls(p);
  if (!urls.ok) return { ok: false, reason: urls.reason };
  if (p.tokenAuthStyle !== "post_json" && p.tokenAuthStyle !== "post_form_basic") return { ok: false, reason: "tokenAuthStyle must be post_json | post_form_basic" };
  const clientId = boundedStr(p.clientId, CLIENT_ID_MAX);
  if (clientId === null) return { ok: false, reason: "clientId must be a non-empty string" };
  // OAuth2 providers are confidential or PKCE-public; reuse the same secretRef discipline (mapping the
  // pkce setting onto pkce_public when there is no secret).
  const clientAuth: OidcClientAuth = p.pkce === "supported" && p.secretRef === undefined ? "pkce_public" : "client_secret_post";
  const secret = validateSecretRef(p.secretRef, clientAuth);
  if (!secret.ok) return { ok: false, reason: secret.reason };
  const scopes = strArray(p.scopes, SCOPES_MAX, SCOPE_MAX);
  if (scopes === null) return { ok: false, reason: "scopes must be an array of short strings" };
  const subjectPath = boundedStr(p.subjectPath, CLAIM_NAME_MAX);
  if (subjectPath === null) return { ok: false, reason: "subjectPath must be a short string (the immutable user id path)" };
  const subjectPrefix = boundedStr(p.subjectPrefix, CLAIM_NAME_MAX);
  if (subjectPrefix === null) return { ok: false, reason: "subjectPrefix must be a short string" };
  if (p.pkce !== "supported" && p.pkce !== "none") return { ok: false, reason: "pkce must be 'supported' or 'none'" };

  const conn: Omit<Oauth2Connection, "createdBy" | "createdAt"> = {
    kind: "oauth2",
    ...base,
    authorizeUrl: urls.urls.authorizeUrl,
    tokenUrl: urls.urls.tokenUrl,
    tokenAuthStyle: p.tokenAuthStyle,
    clientId,
    secretRef: secret.ref,
    scopes,
    apiBase: urls.urls.apiBase,
    profileUrl: urls.urls.profileUrl,
    subjectPath,
    subjectPrefix,
    pkce: p.pkce,
  };
  const optional = validateOauth2OptionalFields(p, conn);
  if (!optional.ok) return { ok: false, reason: optional.reason };
  const secretExpiry = validateSecretExpiresAt(p.secretExpiresAt);
  if (!secretExpiry.ok) return { ok: false, reason: secretExpiry.reason };
  if (secretExpiry.value !== undefined) conn.secretExpiresAt = secretExpiry.value;
  return { ok: true, conn };
}

// The transient NameID format: a per-session pseudonym that changes every login, so it can NEVER key a
// stable authorisation principal (a returning user would be a different subject each time). Rejected at
// config time AND re-rejected at assertion-consume time (saml/assertion.ts).
const NAMEID_TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
const CLOCK_SKEW_MAX = 600; // 10 minutes is generous for IdP/SP clock drift; more is a misconfiguration
// SAML_CERTS_MAX bounds the overlapping-rollover set; more than a handful is a config error. EXPORTED so
// the rollover edit path (scheduler-do-idp.ts idpConnSamlCertUpdate) can refuse an over-capacity APPEND
// with the pinned count in hand, rather than merging first and letting the shared gate answer about the
// merged array the operator never saw.
export const SAML_CERTS_MAX = 8;
const CERT_PEM_MAX = 8192; // a PEM X.509 cert is ~1-2 KiB; the cap bounds a pathological paste

// validateSamlCerts is the SINGLE bounds+shape gate for an idpSigningCerts array, shared by validateSaml (the
// create path) and the cert-rollover edit path so a zero-downtime cert append/replace can never store
// a cert the create path would have rejected. It enforces: an array of at most SAML_CERTS_MAX entries, each a
// bounded PEM that contains the X.509 BEGIN CERTIFICATE armour. strArray de-dupes and bounds each entry. It
// returns the normalised (de-duped) array or a precise reason; it NEVER throws and reads no secret (a signing
// cert is PUBLIC). The overlapping array (>=1, <=8) is exactly what the assertion verifier already iterates,
// so an append makes a new IdP cert trusted alongside the old one with no break-login window.
export function validateSamlCerts(raw: unknown): { ok: true; certs: string[] } | { ok: false; reason: string } {
  // OVER CAPACITY IS NOT A SHAPE FAULT, AND IT USED TO ANSWER AS ONE. strArray returns a single null for
  // "not an array", "an entry is not a bounded string" AND "more entries than maxItems", so an array of
  // perfectly valid PEMs that was merely one too long fell to the generic sentence below and told the
  // operator their certificates were not PEM X.509 certificates. Measured over a dose-response on the
  // APPEND arm (7 pinned + 2 pasted refuses; 7 + 1 accepts): the verdict is on LENGTH and is returned
  // before any entry is read, yet the sentence it borrowed was the EMPTY/wrong-shape one.
  //
  // Why it is worth its own branch rather than a better generic sentence. This refusal lands at IdP
  // CUT-OVER, the one moment every SSO sign-in depends on the new signing key being trusted, and the
  // remedy the old sentence implies (re-export the certificate from the provider) cannot work while the
  // remedy that does (Replace, which prunes the retired certificates) is the OTHER control on the same
  // screen and was named nowhere. The count only ever rises through Append, so a refusal that does not
  // point at the pruning step points away from the only way back.
  //
  // The residue is named rather than implied away: the SAME strArray null collapses the over-cap case for
  // every other bounded array here (scopes, tenantIds, extraParams and the rest), which was driven and
  // confirmed. Those are create-time config faults an operator retries immediately, not a rollover that
  // fails against a provider deadline, so this fix is deliberately local to the trust-root path.
  if (Array.isArray(raw) && raw.length > SAML_CERTS_MAX) {
    return {
      ok: false,
      reason: `the pinned set holds at most ${SAML_CERTS_MAX} signing certificates and this would make ${raw.length}. Take the Replace step to make the certificate(s) you pasted the whole pinned set, which prunes the retired ones, or remove certificates that are no longer in use first`,
    };
  }
  // rejectDuplicates: an append of an ALREADY-PINNED certificate used to collapse to the existing array and
  // answer ok:true, telling the operator a rollover cert was now trusted when nothing had been added. Named
  // separately from the generic array failure so the operator is told which mistake they made.
  if (Array.isArray(raw) && strArray(raw, SAML_CERTS_MAX, CERT_PEM_MAX, true) === null && strArray(raw, SAML_CERTS_MAX, CERT_PEM_MAX) !== null) {
    return { ok: false, reason: "the same signing certificate appears twice; a rollover appends a NEW certificate alongside the pinned one, and pinning the same certificate again would change nothing" };
  }
  const certs = strArray(raw, SAML_CERTS_MAX, CERT_PEM_MAX, true);
  if (certs === null || certs.length === 0) return { ok: false, reason: "idpSigningCerts must be a non-empty array of PEM X.509 certificates" };
  for (const c of certs) {
    if (!c.includes("BEGIN CERTIFICATE")) return { ok: false, reason: "each idpSigningCert must be a PEM-encoded X.509 certificate (-----BEGIN CERTIFICATE-----)" };
  }
  return { ok: true, certs };
}

// validateSaml turns an untrusted SAML proposal into a stored SamlConnection (minus createdBy/createdAt) or a
// reason. The SP is SIGN-ONLY and SP-INITIATED by default (allowIdpInitiated is an explicit owner opt-in,
// enforced at the ACS). The hard config gates: https-only IdP SSO URL (no private/loopback host), at least
// one PEM signing cert (the trust root - the SP pins these and IGNORES the assertion's own KeyInfo),
// wantAssertionsSigned must be true (an unsigned assertion is refused), the NameID format must NOT be
// transient (not stable enough to authorise), and an explicit emailVerifiedPolicy (no silent default for an
// auth-root trust decision). It NEVER throws.
export function validateSaml(p: IdpConnectionProposal, base: Base): ValidateResult {
  const idpEntityId = boundedStr(p.idpEntityId, REF_MAX);
  if (idpEntityId === null) return { ok: false, reason: "idpEntityId must be a non-empty string" };
  const idpSsoUrl = str(p.idpSsoUrl);
  if (idpSsoUrl === null) return { ok: false, reason: "idpSsoUrl must be a string" };
  try {
    // The IdP SSO URL is where the BROWSER is redirected (HTTP-Redirect binding); https-only + a public host
    // is still the right floor (an IdP is never on localhost / a private IP), reusing the same screen.
    assertSafeFetchEndpoint(idpSsoUrl);
  } catch (e) {
    return { ok: false, reason: `idpSsoUrl: ${e instanceof Error ? e.message : "invalid https URL"}` };
  }
  const certsR = validateSamlCerts(p.idpSigningCerts);
  if (!certsR.ok) return { ok: false, reason: certsR.reason };
  const idpSigningCerts = certsR.certs;
  const spEntityId = boundedStr(p.spEntityId, REF_MAX);
  if (spEntityId === null) return { ok: false, reason: "spEntityId must be a non-empty string" };
  const nameIdFormat = boundedStr(p.nameIdFormat, REF_MAX);
  if (nameIdFormat === null) return { ok: false, reason: "nameIdFormat must be a non-empty string" };
  if (nameIdFormat === NAMEID_TRANSIENT) return { ok: false, reason: "a transient NameID is not stable enough to key authorization; use persistent, emailAddress, unspecified, or a pinned stable attribute" };
  if (p.wantAssertionsSigned !== true) return { ok: false, reason: "wantAssertionsSigned must be true (the SP refuses an unsigned assertion)" };
  if (typeof p.allowIdpInitiated !== "boolean") return { ok: false, reason: "allowIdpInitiated must be a boolean (default false; true is an explicit owner opt-in)" };
  const clockSkewSec = typeof p.clockSkewSec === "number" && Number.isFinite(p.clockSkewSec) && p.clockSkewSec >= 0 && p.clockSkewSec <= CLOCK_SKEW_MAX ? p.clockSkewSec : null;
  if (clockSkewSec === null) return { ok: false, reason: `clockSkewSec must be a number from 0 to ${CLOCK_SKEW_MAX}` };
  if (p.emailVerifiedPolicy !== "require-flag" && p.emailVerifiedPolicy !== "trust-idp") return { ok: false, reason: "emailVerifiedPolicy must be 'require-flag' or 'trust-idp' (an explicit email-trust choice)" };

  const conn: Omit<SamlConnection, "createdBy" | "createdAt"> = {
    kind: "saml",
    ...base,
    idpEntityId,
    idpSsoUrl,
    idpSigningCerts,
    spEntityId,
    nameIdFormat,
    wantAssertionsSigned: true,
    allowIdpInitiated: p.allowIdpInitiated,
    clockSkewSec,
    emailVerifiedPolicy: p.emailVerifiedPolicy,
  };
  // PRESENT-AND-UNUSABLE IS A REFUSAL, NOT A DROP (see the same repair on the OAuth2 paths above). An
  // over-CLAIM_NAME_MAX groupsAttr used to store the connection ok:true with NO group mapping, so the
  // operator's groups-to-roles rules silently did not apply and every user landed with no groups. The
  // console omits a blank box rather than sending "", so refusing an empty value breaks no caller it has.
  const emailAttr = p.emailAttr !== undefined ? boundedStr(p.emailAttr, CLAIM_NAME_MAX) : undefined;
  if (p.emailAttr !== undefined && emailAttr === null) return { ok: false, reason: "emailAttr must be a short string" };
  if (emailAttr) conn.emailAttr = emailAttr;
  const groupsAttr = p.groupsAttr !== undefined ? boundedStr(p.groupsAttr, CLAIM_NAME_MAX) : undefined;
  if (p.groupsAttr !== undefined && groupsAttr === null) return { ok: false, reason: "groupsAttr must be a short string" };
  if (groupsAttr) conn.groupsAttr = groupsAttr;
  const emailVerifiedAttr = p.emailVerifiedAttr !== undefined ? boundedStr(p.emailVerifiedAttr, CLAIM_NAME_MAX) : undefined;
  if (p.emailVerifiedAttr !== undefined && emailVerifiedAttr === null) return { ok: false, reason: "emailVerifiedAttr must be a short string" };
  if (emailVerifiedAttr) conn.emailVerifiedAttr = emailVerifiedAttr;
  return { ok: true, conn };
}

// isConnId is re-exported for the dispatcher's id check, which previously imported it directly from identity.
export { isConnId };
