// The IdP-connection discriminated-union TYPES, split out of idpconn.ts so that both idpconn.ts (the
// redactor + dispatcher) and idpconn-validators.ts (the per-kind validators) can depend on them without a
// runtime cycle. These are pure type declarations (erased at build); the public re-export lives in
// idpconn.ts so importers see exactly the same surface as before.

import type { IdTokenAlg } from "./oidc-verify.ts";

// How a connection's client credential is held. "pkce-public" holds NOTHING (a public client, PKCE only);
// "secrets-store" references a Cloudflare Secrets Store binding by NAME (the engine reads the value at the
// token exchange, never holds it at rest); "do-plaintext" is the floor (the value lives in a separate
// write-only DO key, exactly like the console-set destination secret); "private-key-jwt" references the
// engine-held private key whose public half the operator registers at the IdP (no shared secret transits).
export type SecretMode = "pkce-public" | "secrets-store" | "do-plaintext" | "private-key-jwt";

// SecretRef is the only credential descriptor the record holds. `ref` is a NON-secret reference (a Secrets
// Store binding name, or a key id) for the modes that need one; it is absent for pkce-public, and for
// do-plaintext (the value is keyed by the connection id in its own DO entry, so no ref is needed here).
export interface SecretRef {
  mode: SecretMode;
  ref?: string;
}

export type OidcClientAuth = "client_secret_post" | "client_secret_basic" | "pkce_public" | "private_key_jwt";

// Fields common to every stored connection, whatever the kind.
interface IdpConnectionBase {
  id: string; // isConnId-bounded; the DO storage-key fragment and the subject's connId fold
  label: string; // human display name
  enabled: boolean;
  presetId: string; // which preset this was created from (e.g. "entra"|"okta"|"github"|"generic-oidc")
  createdBy: string | null; // the granting owner's email (null for the bare-token break-glass), display only
  createdAt: string; // RFC-3339 millis, stamped by the DO
}

export interface OidcConnection extends IdpConnectionBase {
  kind: "oidc";
  issuer: string; // the exact, assertSafeIssuer-validated issuer
  clientId: string;
  secretRef: SecretRef;
  scopes: string[]; // must include "openid"
  idTokenSigAlgs: IdTokenAlg[]; // non-empty subset of {RS256, ES256}
  pkce: "required" | "supported"; // S256 is always emitted regardless
  clientAuth: OidcClientAuth;
  requireNonce: true; // always true for the authorization-code flow
  checkAzp?: boolean;
  groupsClaim?: string; // the claim carrying group membership (provider-specific)
  rolesClaim?: string; // e.g. Entra App Roles "roles", Keycloak "realm_access.roles"
  claimNamespace?: string; // Auth0-style namespaced claim prefix
  hdDomain?: string; // Google: the hosted-domain restriction, ENFORCED at login (enforceHostedDomain refuses a sign-in whose signed hd claim / verified email domain is not this domain); also sent as an authorize-request hint
  issuerSubstitution?: "tid"; // Entra multitenant: substitute the token tid into the issuer template
  acceptedTenantIds?: string[]; // Entra multitenant allowlist
  acceptIssuerVariants?: string[]; // a small fixed set of additional accepted issuer spellings (e.g. Google bare form)
  // Endpoints: discovery is preferred; explicit overrides are validated as safe fetch endpoints.
  discoveryUrl?: string;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  jwksUri?: string;
  extraAuthParams?: Record<string, string>; // e.g. Google hd=, Entra prompt=
  // The operator-declared RFC-3339 expiry of the CONFIDENTIAL client secret. It is redaction-safe
  // METADATA, never the secret value itself: the engine holds the secret write-only (idpsecret:<id>) and can
  // never read an expiry off it, so the operator supplies the date their IdP shows for the secret (Entra/Okta
  // client secrets expire). It is OBSERVED into the credential-lifecycle registry on create so a lapse warns
  // BEFORE it surfaces as a login outage, exactly as a SAML signing cert's notAfter is. Absent for a
  // pkce-public client (no secret) or a secret with no declared expiry.
  secretExpiresAt?: string;
}

// An OAuth2 (no id_token) provider such as GitHub: trust derives from the TLS-protected token exchange, and
// identity from a userinfo call rather than a signed token. Shaped so a generic adapter can drive any such
// provider via path expressions.
export interface Oauth2Connection extends IdpConnectionBase {
  kind: "oauth2";
  authorizeUrl: string;
  tokenUrl: string;
  tokenAuthStyle: "post_json" | "post_form_basic";
  clientId: string;
  secretRef: SecretRef;
  scopes: string[];
  apiBase: string; // folded into the subject (GHES isolation)
  profileUrl: string;
  subjectPath: string; // path to the IMMUTABLE id (e.g. "id"); never the renameable login
  subjectPrefix: string; // e.g. "github"
  emailUrl?: string;
  emailPath?: string;
  emailVerifiedPath?: string;
  displayNamePath?: string;
  groupsUrls?: string[]; // e.g. ["/user/teams","/user/orgs"]
  groupsPath?: string;
  pkce: "supported" | "none";
  // The operator-declared RFC-3339 expiry of the confidential client secret (IDP-2); see OidcConnection.
  // Redaction-safe metadata, never the secret value. Observed into the lifecycle registry on create.
  secretExpiresAt?: string;
}

// SAML is the native SAML 2.0 SP (Phase S, SHIPPED): validateIdpConnection routes a kind:"saml" proposal to
// validateSaml, and the DO stores it like any connection - there is NO client secret, and the IdP signing
// certs are PUBLIC and live in the record. The SP is sign-only + SP-initiated in v1 (see validateSaml:
// https-only idpSsoUrl, >=1 PEM signing cert, wantAssertionsSigned, transient-NameID rejected, explicit
// emailVerifiedPolicy).
export interface SamlConnection extends IdpConnectionBase {
  kind: "saml";
  idpEntityId: string;
  idpSsoUrl: string;
  idpSigningCerts: string[]; // one or more pinned X.509 PEMs (overlapping rollover)
  spEntityId: string;
  nameIdFormat: string;
  wantAssertionsSigned: true;
  allowIdpInitiated: boolean;
  clockSkewSec: number;
  emailAttr?: string;
  groupsAttr?: string;
  // The email-trust posture for the pending-invite bind (SAML carries no standard email_verified claim):
  // 'require-flag' surfaces the email as verified ONLY when emailVerifiedAttr decodes to a true value;
  // 'trust-idp' trusts any well-formed email the assertion carries (an explicit owner choice the console
  // surfaces with a warning). Either way an untrusted email yields a subject-only resolution, never a bind.
  emailVerifiedPolicy: "require-flag" | "trust-idp";
  emailVerifiedAttr?: string; // the assertion attribute carrying a verified flag (consulted by 'require-flag')
}

export type IdpConnection = OidcConnection | Oauth2Connection | SamlConnection;

// A connection proposal as it arrives from the console (every field untrusted). validateIdpConnection turns
// it into a stored IdpConnection (minus createdBy/createdAt, stamped by the DO) or a precise reason.
export interface IdpConnectionProposal {
  id?: unknown;
  kind?: unknown;
  label?: unknown;
  presetId?: unknown;
  enabled?: unknown;
  [k: string]: unknown;
}
