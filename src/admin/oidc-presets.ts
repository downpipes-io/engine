// The provider PRESET registry: named templates the console uses to pre-fill an IdP connection so an
// operator types only a handful of provider-specific values (a tenant id, an Okta domain, a Keycloak realm)
// plus the client id + secret, and everything else (endpoints, scopes, claim names, the gotchas) is the
// vendor default baked in here. buildProposalFromPreset substitutes the operator's filled vars into the
// template and returns an IdpConnectionProposal, which validateIdpConnection (idpconn.ts) then validates and
// the DO stores. The presets carry NO secret; they are display-safe (listPresets returns the public view).
//
// The set: Entra, Okta, Google, GitHub, Keycloak, JumpCloud, Auth0, GitLab, plus Generic OIDC (any compliant
// .well-known - absorbs Ping, OneLogin, Authentik, Zitadel, ...) and Generic OAuth2 (the no-id_token hatch).
// Node 25 strip-types; pure data + a builder; no I/O.

import type { IdpConnectionProposal, OidcClientAuth, SecretRef } from "./idpconn.ts";
import type { IdTokenAlg } from "./oidc-verify.ts";

export interface PresetVar {
  key: string; // substituted as {key} in the templates
  label: string;
  example?: string;
  default?: string; // a sensible default the console pre-fills (e.g. Okta authServerId "default")
}

interface OidcDefaults {
  issuerTemplate: string;
  discoveryUrlTemplate?: string;
  scopes: string[];
  idTokenSigAlgs: IdTokenAlg[];
  pkce: "required" | "supported";
  groupsClaim?: string;
  rolesClaim?: string;
  acceptIssuerVariants?: string[];
  hdDomainVar?: string; // the requiredVar key whose value becomes the Google hd gate
  jwksUriTemplate?: string;
  tokenEndpointTemplate?: string;
  claimNamespaceVar?: string; // the requiredVar key whose value becomes conn.claimNamespace (Auth0 namespaced claims)
}
interface Oauth2Defaults {
  authorizeUrlTemplate: string;
  tokenUrlTemplate: string;
  tokenAuthStyle: "post_json" | "post_form_basic";
  profileUrlTemplate: string;
  subjectPath: string;
  subjectPrefix: string;
  apiBaseTemplate: string;
  emailUrlTemplate?: string;
  groupsUrlsTemplates?: string[];
  scopes: string[];
  pkce: "supported" | "none";
}

export interface IdpPreset {
  id: string;
  label: string;
  vendor: string;
  buttonLabel: string;
  kind: "oidc" | "oauth2";
  requiredVars: PresetVar[];
  notes: string[];
  docsUrl?: string;
  oidc?: OidcDefaults;
  oauth2?: Oauth2Defaults;
}

export const PRESETS: readonly IdpPreset[] = [
  {
    id: "entra",
    label: "Microsoft Entra ID",
    vendor: "Microsoft",
    buttonLabel: "Sign in with Microsoft",
    kind: "oidc",
    requiredVars: [{ key: "tenantId", label: "Directory (tenant) ID", example: "00000000-0000-0000-0000-000000000000" }],
    notes: [
      "Use the v2.0 endpoints (this preset does). Register a Web app; redirect URI is the console callback shown on the connection.",
      "Map authorization with APP ROLES (the 'roles' claim, set here) rather than group object-ids: App Roles avoid the >200-group overflow and the GUID-to-name problem.",
      "This is the single-tenant preset (issuer pinned to your tenant). Multitenant needs issuerSubstitution + a tenant allowlist.",
      "Grant the App Roles to the users or groups that should reach the console; a user with no assigned role signs in but maps to the viewer floor.",
    ],
    oidc: {
      issuerTemplate: "https://login.microsoftonline.com/{tenantId}/v2.0",
      discoveryUrlTemplate: "https://login.microsoftonline.com/{tenantId}/v2.0/.well-known/openid-configuration",
      scopes: ["openid", "email", "profile"],
      idTokenSigAlgs: ["RS256"],
      pkce: "required",
      rolesClaim: "roles",
    },
  },
  {
    id: "okta",
    label: "Okta",
    vendor: "Okta",
    buttonLabel: "Sign in with Okta",
    kind: "oidc",
    requiredVars: [
      { key: "oktaDomain", label: "Okta domain", example: "your-org.okta.com" },
      { key: "authServerId", label: "Authorization server id", example: "default", default: "default" },
    ],
    notes: [
      "Uses a CUSTOM authorization server (.../oauth2/{authServerId}; default 'default'). The org server cannot emit custom/filtered claims, which is the #1 Okta SSO support ticket - the custom server is required for a configurable groups claim.",
      "Add a 'groups' claim mapping on the custom server (Security > API > Authorization Servers > Claims > Add Claim, Value type Groups, filter 'Matches regex .*') so groups reach the id_token; values are group display names. Over ~100 matching groups fails the token request - use a tighter filter.",
      "Register the SAME client-auth method at Okta as the connection uses (this engine defaults to client_secret_post; Okta's own default is client_secret_basic) to avoid a token-endpoint 401.",
      "Assign the app to the users or groups that should reach the console; an unassigned user is refused at Okta before the engine ever sees the login.",
    ],
    oidc: {
      issuerTemplate: "https://{oktaDomain}/oauth2/{authServerId}",
      discoveryUrlTemplate: "https://{oktaDomain}/oauth2/{authServerId}/.well-known/openid-configuration",
      scopes: ["openid", "email", "profile", "groups"],
      idTokenSigAlgs: ["RS256"],
      pkce: "required",
      groupsClaim: "groups",
    },
  },
  {
    id: "google",
    label: "Google Workspace",
    vendor: "Google",
    buttonLabel: "Sign in with Google",
    kind: "oidc",
    requiredVars: [{ key: "hdDomain", label: "Workspace domain", example: "yourcompany.com" }],
    notes: [
      "The hd (hosted-domain) gate is MANDATORY: without it any Google consumer account could sign in. This preset sets it from your Workspace domain.",
      "Google does NOT put group membership in the id_token. This preset signs users in (no groups); per-person roles are assigned in the role table. Group sync via the Cloud Identity API is a later add-on.",
    ],
    oidc: {
      issuerTemplate: "https://accounts.google.com",
      discoveryUrlTemplate: "https://accounts.google.com/.well-known/openid-configuration",
      scopes: ["openid", "email", "profile"],
      idTokenSigAlgs: ["RS256"],
      pkce: "required",
      acceptIssuerVariants: ["accounts.google.com"],
      hdDomainVar: "hdDomain",
      // Google serves its JWKS on a SIBLING host (googleapis.com), not the issuer host; pin it explicitly
      // here so the discovery jwks_uri host-pin (which requires jwks-host == issuer-host) is satisfied by an
      // operator-trusted, config-validated value rather than trusting a cross-host discovery value.
      jwksUriTemplate: "https://www.googleapis.com/oauth2/v3/certs",
      // Google's real token_endpoint is ALSO off-issuer-host (oauth2.googleapis.com, not accounts.google.com)
      // for the same reason as its JWKS; pin it explicitly here so the discovery token_endpoint host-pin
      // (resolveEndpoints, oidc-store.ts) is satisfied by this operator-trusted value instead of refusing
      // Google's own conformant discovery response. authorization_endpoint stays on the issuer host, so it
      // needs no override.
      tokenEndpointTemplate: "https://oauth2.googleapis.com/token",
    },
  },
  {
    id: "keycloak",
    label: "Keycloak",
    vendor: "Keycloak / Red Hat",
    buttonLabel: "Sign in",
    kind: "oidc",
    requiredVars: [
      { key: "host", label: "Keycloak host", example: "sso.yourcompany.com" },
      { key: "realm", label: "Realm", example: "employees" },
    ],
    notes: [
      "CRITICAL: toggle 'Add to ID token' = ON on the realm-roles (and/or client-roles) mapper AND the Group Membership mapper. By default Keycloak puts roles/groups only in the ACCESS token, and this engine verifies the ID token, so without this you get sign-in but no roles/groups.",
      "Add a 'Group Membership' protocol mapper writing a 'groups' claim (this preset reads it). Client roles at resource_access.<client>.roles are the least-privilege alternative to realm_access.roles.",
      "Legacy installs serve discovery under /auth/realms/{realm}; this preset uses the modern /realms/{realm} path.",
      "This preset accepts RS256 and ES256 id_token signatures; confirm your realm's active key algorithm matches one of them.",
    ],
    oidc: {
      issuerTemplate: "https://{host}/realms/{realm}",
      discoveryUrlTemplate: "https://{host}/realms/{realm}/.well-known/openid-configuration",
      scopes: ["openid", "email", "profile", "roles", "groups"],
      idTokenSigAlgs: ["RS256", "ES256"],
      pkce: "required",
      groupsClaim: "groups",
      rolesClaim: "realm_access.roles",
    },
  },
  {
    id: "jumpcloud",
    label: "JumpCloud",
    vendor: "JumpCloud",
    buttonLabel: "Sign in with JumpCloud",
    kind: "oidc",
    requiredVars: [],
    notes: [
      "JumpCloud uses ONE shared issuer for all tenants, so the issuer does not identify your org; trust rests on the client id (the aud check) and the per-connection subject prefix.",
      "Groups: on the application's SSO > Attributes, enable the group attribute and set the Groups Attribute Name to 'memberOf' (an attribute mapping, NOT a scope). A one-group user's memberOf is a bare string and a multi-group user's is an array; the engine handles both.",
      "US region only (oauth.id.jumpcloud.com). EU/IN tenants use oauth.id.eu/in.jumpcloud.com - configure those via the Generic OIDC preset.",
      "Set the per-connection subject prefix to a value that identifies your org, since the shared issuer does not.",
    ],
    oidc: {
      issuerTemplate: "https://oauth.id.jumpcloud.com/",
      discoveryUrlTemplate: "https://oauth.id.jumpcloud.com/.well-known/openid-configuration",
      scopes: ["openid", "email", "profile"],
      idTokenSigAlgs: ["RS256"],
      pkce: "required",
      groupsClaim: "memberOf",
    },
  },
  {
    id: "auth0",
    label: "Auth0",
    vendor: "Auth0 (Okta)",
    buttonLabel: "Sign in with Auth0",
    kind: "oidc",
    requiredVars: [
      { key: "domain", label: "Auth0 domain", example: "your-tenant.us.auth0.com" },
      { key: "claimNamespace", label: "Roles claim namespace (optional, for role mapping)", example: "https://app.yourcompany.com/", default: "" },
    ],
    notes: [
      "The issuer has a MANDATORY trailing slash (https://<domain>/) - this preset adds it; dropping it is the classic Auth0 'issuer mismatch' failure.",
      "Domain is the FULL tenant host including region (your-tenant.us.auth0.com / .eu.auth0.com) or your custom domain (auth.yourcompany.com).",
      "Roles/groups are NOT emitted by default. Add a Post-Login Action: api.idToken.setCustomClaim(namespace + 'roles', event.authorization.roles). Set the namespace here WITH a trailing slash (the engine reads namespace+roles, so the claim key is namespace + 'roles', e.g. https://app.yourcompany.com/roles); leave blank for sign-in only.",
      "Register the application as Regular Web Application so the confidential-client token exchange (with PKCE) the engine performs is permitted.",
    ],
    oidc: {
      issuerTemplate: "https://{domain}/",
      discoveryUrlTemplate: "https://{domain}/.well-known/openid-configuration",
      scopes: ["openid", "profile", "email"],
      idTokenSigAlgs: ["RS256"],
      pkce: "required",
      rolesClaim: "roles",
      claimNamespaceVar: "claimNamespace",
    },
  },
  {
    id: "gitlab",
    label: "GitLab",
    vendor: "GitLab",
    buttonLabel: "Sign in with GitLab",
    kind: "oidc",
    requiredVars: [{ key: "host", label: "GitLab host", example: "gitlab.com", default: "gitlab.com" }],
    notes: [
      "Works for GitLab.com (host gitlab.com, the default) and self-managed / Dedicated (set your instance host).",
      "Group mapping reads the 'groups_direct' id_token claim (DIRECT memberships only). The richer 'groups' (direct + inherited) and the owner/maintainer/developer claims are emitted ONLY at /userinfo, which this id_token-based flow does not read - so 'groups_direct' is the correct claim here.",
    ],
    oidc: {
      issuerTemplate: "https://{host}",
      discoveryUrlTemplate: "https://{host}/.well-known/openid-configuration",
      scopes: ["openid", "profile", "email"],
      idTokenSigAlgs: ["RS256"],
      pkce: "required",
      groupsClaim: "groups_direct",
    },
  },
  {
    id: "generic-oidc",
    label: "Generic OIDC",
    vendor: "Any OIDC provider",
    buttonLabel: "Sign in",
    kind: "oidc",
    requiredVars: [
      { key: "issuer", label: "Issuer URL", example: "https://idp.yourcompany.com" },
      { key: "groupsClaim", label: "Groups/roles claim name (optional)", example: "groups", default: "" },
    ],
    notes: [
      "Point this at any spec-compliant .well-known/openid-configuration (Auth0, PingOne, OneLogin, GitLab, Authentik, Zitadel, Curity, ...).",
      "Set the groups/roles claim name if your IdP emits one; leave blank for sign-in only (per-person roles).",
    ],
    oidc: {
      issuerTemplate: "{issuer}",
      scopes: ["openid", "email", "profile"],
      idTokenSigAlgs: ["RS256", "ES256"],
      pkce: "required",
    },
  },
  {
    id: "github",
    label: "GitHub",
    vendor: "GitHub",
    buttonLabel: "Sign in with GitHub",
    kind: "oauth2",
    requiredVars: [],
    notes: [
      "GitHub is OAuth2 (no id_token): identity comes from the GitHub API, trust from the TLS-protected token exchange.",
      "The 'read:org' scope is required to read team/org membership for group-to-role mapping. The OAuth app may need org approval.",
      "Authorization keys on your immutable numeric GitHub user id, never the renameable login.",
      "Set the OAuth app callback to the console callback URL shown on the connection; a mismatch fails the authorize step at GitHub.",
    ],
    oauth2: {
      authorizeUrlTemplate: "https://github.com/login/oauth/authorize",
      tokenUrlTemplate: "https://github.com/login/oauth/access_token",
      tokenAuthStyle: "post_json",
      profileUrlTemplate: "https://api.github.com/user",
      subjectPath: "id",
      subjectPrefix: "github",
      apiBaseTemplate: "https://api.github.com",
      emailUrlTemplate: "https://api.github.com/user/emails",
      groupsUrlsTemplates: ["https://api.github.com/user/teams", "https://api.github.com/user/orgs"],
      scopes: ["read:org", "user:email"],
      pkce: "supported",
    },
  },
  {
    id: "generic-oauth2",
    label: "Generic OAuth2",
    vendor: "Any OAuth2 provider",
    buttonLabel: "Sign in",
    kind: "oauth2",
    requiredVars: [
      { key: "authorizeUrl", label: "Authorization URL", example: "https://provider.example/oauth/authorize" },
      { key: "tokenUrl", label: "Token URL", example: "https://provider.example/oauth/token" },
      { key: "apiBase", label: "API base URL", example: "https://api.provider.example" },
      { key: "profileUrl", label: "User-info URL", example: "https://api.provider.example/user" },
      { key: "subjectPath", label: "Immutable user-id field", example: "id", default: "id" },
    ],
    notes: [
      "The extensibility hatch for any OAuth2 provider with no id_token (Discord, Bitbucket, GitLab-OAuth, ...). Supply the endpoints and the immutable user-id field.",
    ],
    oauth2: {
      authorizeUrlTemplate: "{authorizeUrl}",
      tokenUrlTemplate: "{tokenUrl}",
      tokenAuthStyle: "post_json",
      profileUrlTemplate: "{profileUrl}",
      subjectPath: "{subjectPath}",
      subjectPrefix: "oauth2",
      apiBaseTemplate: "{apiBase}",
      scopes: [],
      pkce: "supported",
    },
  },
];

export function presetById(id: string): IdpPreset | undefined {
  return PRESETS.find((p) => p.id === id);
}

// missingRequiredVars returns the required-var keys the operator has not filled and that have no default.
// The DO connection-create route calls this BEFORE buildProposalFromPreset, so an unfilled var is a clean
// 400 ("provide: tenantId") rather than a connection that stores a literal "{tenantId}" placeholder and
// fails opaquely at the first login. A var with a default (e.g. Okta authServerId="default") is never missing.
export function missingRequiredVars(preset: IdpPreset, filledVars: Record<string, string>): string[] {
  const missing: string[] = [];
  for (const v of preset.requiredVars) {
    const val = filledVars[v.key];
    if ((val === undefined || val.length === 0) && v.default === undefined) missing.push(v.key);
  }
  return missing;
}

// listPresets returns the display-only catalogue for the console (no secrets, no internal fields beyond
// what the operator needs to choose + fill a provider). It is safe to return to an authenticated console.
export function listPresets(): Array<{ id: string; label: string; vendor: string; buttonLabel: string; kind: string; requiredVars: PresetVar[]; notes: string[]; docsUrl?: string }> {
  return PRESETS.map((p) => ({ id: p.id, label: p.label, vendor: p.vendor, buttonLabel: p.buttonLabel, kind: p.kind, requiredVars: p.requiredVars, notes: p.notes, ...(p.docsUrl !== undefined ? { docsUrl: p.docsUrl } : {}) }));
}

// subst replaces every {key} occurrence with vars[key]. A missing var leaves the placeholder, which then
// fails validation downstream (assertSafeIssuer / assertSafeFetchEndpoint reject a "{...}"-bearing URL), so
// an unfilled required var can never silently produce a usable connection.
function subst(template: string, vars: Record<string, string>): string {
  return template.replace(/\{([a-zA-Z0-9_]+)\}/g, (_m, k: string) => (Object.hasOwn(vars, k) ? vars[k]! : `{${k}}`));
}

export interface ConnectionCredentials {
  id?: string; // connection id (default: the preset id); an operator may run several of one provider
  label?: string;
  clientId: string;
  secretRef: SecretRef;
  clientAuth?: OidcClientAuth; // required for oidc; ignored for oauth2 (validateOauth2 derives it)
}

// ProposalBase is the kind-agnostic head of an IdpConnectionProposal (identity + credentials descriptor),
// shared by the oidc and oauth2 branches.
type ProposalBase = {
  id: string;
  label: string;
  presetId: string;
  enabled: boolean;
  clientId: string;
  secretRef: SecretRef;
};

// buildOidcProposal fills the oidc-kind proposal from the preset's oidc config and the substituted vars.
function buildOidcProposal(base: ProposalBase, o: NonNullable<IdpPreset["oidc"]>, vars: Record<string, string>, creds: ConnectionCredentials): IdpConnectionProposal {
  const proposal: IdpConnectionProposal = {
    ...base,
    kind: "oidc",
    issuer: subst(o.issuerTemplate, vars),
    scopes: o.scopes,
    idTokenSigAlgs: o.idTokenSigAlgs,
    pkce: o.pkce,
    clientAuth: creds.clientAuth ?? "client_secret_post",
    requireNonce: true,
  };
  if (o.discoveryUrlTemplate !== undefined) proposal.discoveryUrl = subst(o.discoveryUrlTemplate, vars);
  if (o.jwksUriTemplate !== undefined) proposal.jwksUri = subst(o.jwksUriTemplate, vars);
  if (o.tokenEndpointTemplate !== undefined) proposal.tokenEndpoint = subst(o.tokenEndpointTemplate, vars);
  if (o.acceptIssuerVariants !== undefined) proposal.acceptIssuerVariants = o.acceptIssuerVariants;
  if (o.rolesClaim !== undefined) proposal.rolesClaim = o.rolesClaim;
  // generic-oidc lets the operator name the groups claim via a var; an empty value means "sign-in only".
  const groupsClaim = o.groupsClaim ?? (vars.groupsClaim !== undefined && vars.groupsClaim.length > 0 ? vars.groupsClaim : undefined);
  if (groupsClaim !== undefined && groupsClaim.length > 0) proposal.groupsClaim = groupsClaim;
  if (o.hdDomainVar !== undefined && vars[o.hdDomainVar] !== undefined && vars[o.hdDomainVar]!.length > 0) proposal.hdDomain = vars[o.hdDomainVar]!;
  // claimNamespace (Auth0): the operator's Post-Login-Action namespace; the namespaced roles claim key is
  // then claimNamespace + rolesClaim (e.g. "https://app.example/" + "roles"). Blank => no namespace (sign-in).
  if (o.claimNamespaceVar !== undefined && vars[o.claimNamespaceVar] !== undefined && vars[o.claimNamespaceVar]!.length > 0) proposal.claimNamespace = vars[o.claimNamespaceVar]!;
  return proposal;
}

// buildOauth2Proposal fills the oauth2-kind proposal from the preset's oauth2 config and the substituted vars.
function buildOauth2Proposal(base: ProposalBase, o: NonNullable<IdpPreset["oauth2"]>, vars: Record<string, string>): IdpConnectionProposal {
  const proposal: IdpConnectionProposal = {
    ...base,
    kind: "oauth2",
    authorizeUrl: subst(o.authorizeUrlTemplate, vars),
    tokenUrl: subst(o.tokenUrlTemplate, vars),
    tokenAuthStyle: o.tokenAuthStyle,
    profileUrl: subst(o.profileUrlTemplate, vars),
    subjectPath: subst(o.subjectPath, vars),
    subjectPrefix: o.subjectPrefix,
    apiBase: subst(o.apiBaseTemplate, vars),
    scopes: o.scopes,
    pkce: o.pkce,
  };
  if (o.emailUrlTemplate !== undefined) proposal.emailUrl = subst(o.emailUrlTemplate, vars);
  if (o.groupsUrlsTemplates !== undefined) proposal.groupsUrls = o.groupsUrlsTemplates.map((t) => subst(t, vars));
  return proposal;
}

// buildProposalFromPreset substitutes the operator's filled vars into the preset and returns an
// IdpConnectionProposal for validateIdpConnection. It applies sensible defaults (a var's `default`) for any
// var the operator left blank. It NEVER embeds a secret value - only the secretRef descriptor is carried.
export function buildProposalFromPreset(preset: IdpPreset, filledVars: Record<string, string>, creds: ConnectionCredentials): IdpConnectionProposal {
  const vars: Record<string, string> = {};
  for (const v of preset.requiredVars) vars[v.key] = filledVars[v.key] ?? v.default ?? "";
  const base: ProposalBase = {
    id: creds.id ?? preset.id,
    label: creds.label ?? preset.label,
    presetId: preset.id,
    enabled: true,
    clientId: creds.clientId,
    secretRef: creds.secretRef,
  };
  return preset.kind === "oidc" && preset.oidc
    ? buildOidcProposal(base, preset.oidc, vars, creds)
    : buildOauth2Proposal(base, preset.oauth2!, vars);
}
