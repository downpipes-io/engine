// Prove every provider preset (oidc-presets.ts) builds a connection that PASSES validateIdpConnection
// (idpconn.ts) when filled with sample vars, that listPresets is display-safe (no secrets), and that an
// unfilled required var is detectable. Run: node test/validate-oidc-presets.ts
//
// Node 25 strip-types; pure, no I/O.

import { PRESETS, presetById, listPresets, buildProposalFromPreset, missingRequiredVars } from "../src/admin/oidc-presets.ts";
import type { ConnectionCredentials } from "../src/admin/oidc-presets.ts";
import { validateIdpConnection } from "../src/admin/idpconn.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
const NONE = new Set<string>();

const SAMPLE_VARS: Record<string, Record<string, string>> = {
  entra: { tenantId: "00000000-0000-0000-0000-000000000000" },
  okta: { oktaDomain: "your-org.okta.com", authServerId: "default" },
  google: { hdDomain: "yourcompany.com" },
  keycloak: { host: "sso.yourcompany.com", realm: "employees" },
  jumpcloud: {},
  auth0: { domain: "your-tenant.us.auth0.com", claimNamespace: "https://app.yourcompany.com/" },
  gitlab: { host: "gitlab.com" },
  "generic-oidc": { issuer: "https://idp.yourcompany.com", groupsClaim: "groups" },
  github: {},
  "generic-oauth2": { authorizeUrl: "https://p.example/oauth/authorize", tokenUrl: "https://p.example/oauth/token", apiBase: "https://api.p.example", profileUrl: "https://api.p.example/user", subjectPath: "id" },
};
const creds: ConnectionCredentials = { clientId: "the-client-id", secretRef: { mode: "do-plaintext" }, clientAuth: "client_secret_post" };

console.log("OIDC provider presets\n");

ok("the catalogue covers the 10 v1 providers", PRESETS.length === 10 && PRESETS.every((p) => p.id in SAMPLE_VARS));

// Each preset builds a VALID connection.
for (const p of PRESETS) {
  const proposal = buildProposalFromPreset(p, SAMPLE_VARS[p.id]!, creds);
  const r = validateIdpConnection(proposal, NONE);
  ok(`preset "${p.id}" builds a connection that validates`, r.ok === true);
  if (!r.ok) console.log(`     reason: ${r.reason}`);
  else ok(`  -> "${p.id}" kind is ${p.kind}`, r.conn.kind === p.kind);
}

// Spot-check a few provider specifics survived the build.
{
  const entra = buildProposalFromPreset(presetById("entra")!, SAMPLE_VARS.entra!, creds);
  const r = validateIdpConnection(entra, NONE);
  ok("entra: issuer pinned to the tenant + rolesClaim 'roles' (App Roles default)", r.ok === true && r.conn.kind === "oidc" && r.conn.issuer === "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0" && r.conn.rolesClaim === "roles");
}
{
  const google = buildProposalFromPreset(presetById("google")!, SAMPLE_VARS.google!, creds);
  const r = validateIdpConnection(google, NONE);
  ok("google: hd gate set + bare-issuer variant accepted", r.ok === true && r.conn.kind === "oidc" && r.conn.hdDomain === "yourcompany.com" && (r.conn.acceptIssuerVariants ?? []).includes("accounts.google.com"));
  // Google's real token_endpoint is off-issuer-host (oauth2.googleapis.com vs issuer accounts.google.com); the
  // preset must carry an explicit tokenEndpoint so the discovery token-endpoint host-pin (resolveEndpoints,
  // oidc-store.ts) trusts it instead of refusing Google's own conformant discovery response.
  ok("google: explicit off-issuer-host tokenEndpoint override set", r.ok === true && r.conn.kind === "oidc" && r.conn.tokenEndpoint === "https://oauth2.googleapis.com/token");
}
{
  const okta = buildProposalFromPreset(presetById("okta")!, SAMPLE_VARS.okta!, creds);
  const r = validateIdpConnection(okta, NONE);
  ok("okta: custom authz-server issuer + discovery on the same host", r.ok === true && r.conn.kind === "oidc" && r.conn.issuer === "https://your-org.okta.com/oauth2/default" && r.conn.discoveryUrl === "https://your-org.okta.com/oauth2/default/.well-known/openid-configuration");
}
{
  const gh = buildProposalFromPreset(presetById("github")!, {}, creds);
  const r = validateIdpConnection(gh, NONE);
  ok("github: oauth2, immutable numeric-id subject + read:org groups urls", r.ok === true && r.conn.kind === "oauth2" && r.conn.subjectPath === "id" && r.conn.subjectPrefix === "github" && (r.conn.groupsUrls ?? []).length === 2);
}
{
  const kc = buildProposalFromPreset(presetById("keycloak")!, SAMPLE_VARS.keycloak!, creds);
  const r = validateIdpConnection(kc, NONE);
  ok("keycloak: realm issuer + nested realm_access.roles", r.ok === true && r.conn.kind === "oidc" && r.conn.issuer === "https://sso.yourcompany.com/realms/employees" && r.conn.rolesClaim === "realm_access.roles");
}
{
  const a = buildProposalFromPreset(presetById("auth0")!, SAMPLE_VARS.auth0!, creds);
  const r = validateIdpConnection(a, NONE);
  ok("auth0: issuer has the MANDATORY trailing slash + namespaced rolesClaim wired", r.ok === true && r.conn.kind === "oidc" && r.conn.issuer === "https://your-tenant.us.auth0.com/" && r.conn.rolesClaim === "roles" && r.conn.claimNamespace === "https://app.yourcompany.com/");
  const blank = buildProposalFromPreset(presetById("auth0")!, { domain: "t.us.auth0.com" }, creds);
  const rb = validateIdpConnection(blank, NONE);
  ok("auth0: blank claimNamespace => no namespace (sign-in only), still valid", rb.ok === true && rb.conn.kind === "oidc" && rb.conn.claimNamespace === undefined);
}
{
  const g = buildProposalFromPreset(presetById("gitlab")!, SAMPLE_VARS.gitlab!, creds);
  const r = validateIdpConnection(g, NONE);
  ok("gitlab: host issuer + groups_direct claim + RS256 only", r.ok === true && r.conn.kind === "oidc" && r.conn.issuer === "https://gitlab.com" && r.conn.groupsClaim === "groups_direct" && JSON.stringify(r.conn.idTokenSigAlgs) === JSON.stringify(["RS256"]));
}

// PKCE-public build (no secret) also validates.
{
  const proposal = buildProposalFromPreset(presetById("entra")!, SAMPLE_VARS.entra!, { clientId: "cid", secretRef: { mode: "pkce-public" }, clientAuth: "pkce_public" });
  ok("a PKCE-public build (no secret) validates", validateIdpConnection(proposal, NONE).ok === true);
}

// listPresets is display-safe (no secret/credential fields).
{
  const list = listPresets();
  ok("listPresets returns the 10 providers", list.length === 10);
  const blob = JSON.stringify(list);
  ok("listPresets carries no secret/clientId/secretRef field", !blob.includes("secretRef") && !blob.includes("clientId") && !blob.includes("\"value\""));
  ok("listPresets entries carry requiredVars + notes for the console form", list.every((p) => Array.isArray(p.requiredVars) && Array.isArray(p.notes)));
}

// missingRequiredVars detects an unfilled required var (the route uses this before building).
{
  ok("missingRequiredVars flags an unfilled entra tenantId", JSON.stringify(missingRequiredVars(presetById("entra")!, {})) === JSON.stringify(["tenantId"]));
  ok("missingRequiredVars is empty when all required vars are filled", missingRequiredVars(presetById("okta")!, SAMPLE_VARS.okta!).length === 0);
  ok("okta authServerId default counts as filled when omitted", missingRequiredVars(presetById("okta")!, { oktaDomain: "x.okta.com" }).length === 0);
}

console.log("");
if (failures > 0) process.exitCode = 1;
if (failures > 0) {
  console.log(`OIDC PRESET VECTORS: ${failures} FAILED`);
  process.exit(1);
}
console.log("OIDC PRESET VECTORS PASS");
