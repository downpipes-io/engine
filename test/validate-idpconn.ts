// Validate the IdP-connection config authority boundary (src/admin/idpconn.ts): the pure validator turns an
// untrusted console proposal into a stored connection or a precise reason, the secret-mode consistency
// rules hold, unsafe issuers/endpoints are refused, the record never holds a secret value, and a SAML
// proposal is gated until Phase S. Run: node test/validate-idpconn.ts
//
// Node 25 strip-types; pure functions, no DO, no network.

import { validateIdpConnection, redactIdpConn } from "../src/admin/idpconn.ts";
import type { IdpConnection } from "../src/admin/idpconn.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
const NONE = new Set<string>();

const baseOidc = {
  id: "entra",
  kind: "oidc",
  label: "Microsoft Entra ID",
  presetId: "entra",
  enabled: true,
  issuer: "https://login.microsoftonline.com/TENANTID/v2.0",
  clientId: "client-abc",
  secretRef: { mode: "do-plaintext" },
  scopes: ["openid", "email", "profile"],
  idTokenSigAlgs: ["RS256"],
  pkce: "required",
  clientAuth: "client_secret_post",
  requireNonce: true,
};

console.log("IdP-connection config validator\n");

// 1. valid OIDC (confidential, do-plaintext floor)
{
  const r = validateIdpConnection({ ...baseOidc }, NONE);
  ok("valid OIDC connection accepted", r.ok === true);
  if (r.ok && r.conn.kind === "oidc") {
    ok("  -> issuer + clientId + scopes preserved", r.conn.issuer === baseOidc.issuer && r.conn.clientId === "client-abc" && r.conn.scopes.includes("openid"));
    ok("  -> secretRef is do-plaintext with NO value field", r.conn.secretRef.mode === "do-plaintext" && !("value" in (r.conn.secretRef as object)));
  }
}
// 2. id collision
ok("id collision rejected", validateIdpConnection({ ...baseOidc }, new Set(["entra"])).ok === false);
// 3. bad id (uppercase)
ok("uppercase id rejected", validateIdpConnection({ ...baseOidc, id: "Entra" }, NONE).ok === false);
// 4. bad id (separator)
ok("id with a subject separator rejected", validateIdpConnection({ ...baseOidc, id: "a|b" }, NONE).ok === false);
// 5. cloudflareaccess issuer
ok("cloudflareaccess issuer rejected", validateIdpConnection({ ...baseOidc, issuer: "https://team.cloudflareaccess.com" }, NONE).ok === false);
// 6. http issuer
ok("http issuer rejected", validateIdpConnection({ ...baseOidc, issuer: "http://idp.example.com" }, NONE).ok === false);
// 7. IP-literal issuer
ok("IP-literal issuer rejected", validateIdpConnection({ ...baseOidc, issuer: "https://10.0.0.1" }, NONE).ok === false);
// 8. scopes without openid
ok("scopes without openid rejected", validateIdpConnection({ ...baseOidc, scopes: ["email"] }, NONE).ok === false);
// 9. unsupported alg
ok("unsupported id_token alg rejected", validateIdpConnection({ ...baseOidc, idTokenSigAlgs: ["HS256"] }, NONE).ok === false);
// 10. requireNonce must be true
ok("requireNonce:false rejected", validateIdpConnection({ ...baseOidc, requireNonce: false }, NONE).ok === false);
// 11. PKCE-public (no secret)
{
  const r = validateIdpConnection({ ...baseOidc, clientAuth: "pkce_public", secretRef: undefined }, NONE);
  ok("PKCE-public client accepted with no secret", r.ok === true && r.conn.kind === "oidc" && r.conn.secretRef.mode === "pkce-public");
}
// 12. confidential without a secretRef
ok("confidential client without secretRef rejected", validateIdpConnection({ ...baseOidc, secretRef: undefined }, NONE).ok === false);
// 13. secrets-store is not yet wired: rejected at CONFIG TIME so a connection can never be saved in a state
// that only fails at first login. The OLD code accepted secrets-store-with-a-ref here.
{
  const r = validateIdpConnection({ ...baseOidc, secretRef: { mode: "secrets-store", ref: "ENTRA_CLIENT_SECRET" } }, NONE);
  ok("secrets-store rejected at config validation (not yet supported)", r.ok === false);
  ok("secrets-store rejection names the supported mode", r.ok === false && r.reason.includes("secrets-store") && r.reason.includes("do-plaintext"));
}
ok("secrets-store without a ref rejected too", validateIdpConnection({ ...baseOidc, secretRef: { mode: "secrets-store" } }, NONE).ok === false);
// 14. private_key_jwt client authentication is not yet wired: rejected at CONFIG TIME.
// The OLD code accepted private_key_jwt-with-a-key-ref here.
{
  const r = validateIdpConnection({ ...baseOidc, clientAuth: "private_key_jwt", secretRef: { mode: "private-key-jwt", ref: "entra-key-1" } }, NONE);
  ok("private_key_jwt rejected at config validation (not yet supported)", r.ok === false);
  ok("private_key_jwt rejection names the supported alternatives", r.ok === false && r.reason.includes("private_key_jwt"));
}
ok("private_key_jwt without a ref rejected too", validateIdpConnection({ ...baseOidc, clientAuth: "private_key_jwt", secretRef: { mode: "private-key-jwt" } }, NONE).ok === false);
// 15. unsafe jwksUri endpoint
ok("http jwksUri rejected", validateIdpConnection({ ...baseOidc, jwksUri: "http://idp.example.com/jwks" }, NONE).ok === false);
ok("cross-host https jwksUri accepted (Google-style)", validateIdpConnection({ ...baseOidc, jwksUri: "https://www.googleapis.com/oauth2/v3/certs" }, NONE).ok === true);
// 16. Entra App Roles + tid substitution extras (the issuer must be a {tenantid} TEMPLATE for 'tid')
{
  const ISS_TMPL = "https://login.microsoftonline.com/{tenantid}/v2.0";
  const r = validateIdpConnection({ ...baseOidc, issuer: ISS_TMPL, rolesClaim: "roles", issuerSubstitution: "tid", acceptedTenantIds: ["TENANT-1"] }, NONE);
  ok("Entra App Roles + tid substitution + tenant allowlist accepted", r.ok === true && r.conn.kind === "oidc" && r.conn.rolesClaim === "roles" && r.conn.issuerSubstitution === "tid");
  ok("tid substitution without the {tenantid} placeholder rejected", validateIdpConnection({ ...baseOidc, issuerSubstitution: "tid", acceptedTenantIds: ["T"] }, NONE).ok === false);
  ok("tid substitution with an empty tenant allowlist rejected", validateIdpConnection({ ...baseOidc, issuer: ISS_TMPL, issuerSubstitution: "tid", acceptedTenantIds: [] }, NONE).ok === false);
  ok("a {tenantid} issuer without tid substitution rejected", validateIdpConnection({ ...baseOidc, issuer: ISS_TMPL }, NONE).ok === false);
}
// 16b. discoveryUrl must be on the issuer host
{
  ok("discoveryUrl on the issuer host accepted", validateIdpConnection({ ...baseOidc, discoveryUrl: "https://login.microsoftonline.com/TENANTID/v2.0/.well-known/openid-configuration" }, NONE).ok === true);
  ok("discoveryUrl on a DIFFERENT host rejected", validateIdpConnection({ ...baseOidc, discoveryUrl: "https://evil.example.com/.well-known/openid-configuration" }, NONE).ok === false);
}

// 17. redaction: a stored record carries no secret value; redact is safe + idempotent on secretRef shape
{
  const r = validateIdpConnection({ ...baseOidc, secretRef: { mode: "do-plaintext" } }, NONE);
  ok("redaction fixture (do-plaintext) validates", r.ok === true);
  if (r.ok) {
    const stored: IdpConnection = { ...r.conn, createdBy: "owner@example.com", createdAt: "2026-06-13T00:00:00.000Z" } as IdpConnection;
    const red = redactIdpConn(stored);
    ok("redactIdpConn returns only {mode} on a do-plaintext secretRef", red.kind !== "saml" && JSON.stringify((red as { secretRef: object }).secretRef) === JSON.stringify({ mode: "do-plaintext" }));
    ok("redactIdpConn never surfaces a 'value' field anywhere", !JSON.stringify(red).includes("\"value\""));
  }
}

// 18. valid OAuth2 (GitHub-class)
{
  const gh = {
    id: "github",
    kind: "oauth2",
    label: "GitHub",
    presetId: "github",
    enabled: true,
    authorizeUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    tokenAuthStyle: "post_json",
    clientId: "gh-client",
    secretRef: { mode: "do-plaintext" },
    scopes: ["read:org", "user:email"],
    apiBase: "https://api.github.com",
    profileUrl: "https://api.github.com/user",
    subjectPath: "id",
    subjectPrefix: "github",
    emailUrl: "https://api.github.com/user/emails",
    groupsUrls: ["https://api.github.com/user/teams", "https://api.github.com/user/orgs"],
    pkce: "supported",
  };
  const r = validateIdpConnection({ ...gh }, NONE);
  ok("valid OAuth2 (GitHub) connection accepted", r.ok === true && r.conn.kind === "oauth2");
  ok("OAuth2 unsafe authorizeUrl (http) rejected", validateIdpConnection({ ...gh, authorizeUrl: "http://github.com/login/oauth/authorize" }, NONE).ok === false);
  ok("OAuth2 IP-literal apiBase rejected", validateIdpConnection({ ...gh, apiBase: "https://127.0.0.1" }, NONE).ok === false);
}

// 19. SAML (Phase S, un-gated): a complete proposal is accepted; the SAML-specific gates reject the unsafe ones.
// SCOPE: validateIdpConnection is the STORAGE-side config validator only. Its cert check is a PEM-format
// check (it requires the "-----BEGIN CERTIFICATE-----" header; see idpconn-validators.ts), not structural
// DER decoding, so the placeholder PEM below is intentional and sufficient for this layer. Structural cert
// parsing (X.509/DER, expiry) and the high-risk SAML response paths (assertion-wrapping/XSW, signature
// envelope, unsigned-assertion rejection, XXE) are exercised by the SAML response-processing validators:
// validate-saml-xsw.ts, validate-saml-dsig*.ts, validate-saml-response*.ts and validate-saml-assertion.ts.
{
  const CERT = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKxExampleExampleExampleExampleExampleExampleExampleEx\n-----END CERTIFICATE-----";
  const baseSaml = {
    id: "okta-saml", kind: "saml", label: "Okta SAML", presetId: "okta-saml", enabled: true,
    idpEntityId: "http://www.okta.com/exk123", idpSsoUrl: "https://acme.okta.com/app/sso/saml",
    idpSigningCerts: [CERT], spEntityId: "https://console.downpipes.io/saml",
    nameIdFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    wantAssertionsSigned: true, allowIdpInitiated: false, clockSkewSec: 120,
    emailVerifiedPolicy: "require-flag", emailAttr: "email", groupsAttr: "groups",
  };
  const r = validateIdpConnection({ ...baseSaml }, NONE);
  ok("valid SAML connection accepted", r.ok === true && r.conn.kind === "saml");
  if (r.ok && r.conn.kind === "saml") {
    ok("  -> certs + spEntityId preserved, wantAssertionsSigned true", r.conn.idpSigningCerts.length === 1 && r.conn.spEntityId === baseSaml.spEntityId && r.conn.wantAssertionsSigned === true);
    ok("  -> emailVerifiedPolicy preserved (explicit email-trust choice)", r.conn.emailVerifiedPolicy === "require-flag");
  }
  ok("SAML transient NameID rejected (not stable enough to authorise)", validateIdpConnection({ ...baseSaml, nameIdFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" }, NONE).ok === false);
  ok("SAML with no signing cert rejected", validateIdpConnection({ ...baseSaml, idpSigningCerts: [] }, NONE).ok === false);
  ok("SAML non-PEM signing cert rejected", validateIdpConnection({ ...baseSaml, idpSigningCerts: ["not-a-pem"] }, NONE).ok === false);
  ok("SAML http idpSsoUrl rejected", validateIdpConnection({ ...baseSaml, idpSsoUrl: "http://acme.okta.com/sso" }, NONE).ok === false);
  ok("SAML private-host idpSsoUrl rejected", validateIdpConnection({ ...baseSaml, idpSsoUrl: "https://127.0.0.1/sso" }, NONE).ok === false);
  ok("SAML wantAssertionsSigned:false rejected (the SP refuses an unsigned assertion)", validateIdpConnection({ ...baseSaml, wantAssertionsSigned: false }, NONE).ok === false);
  ok("SAML missing emailVerifiedPolicy rejected (an explicit trust choice is required)", validateIdpConnection({ ...baseSaml, emailVerifiedPolicy: undefined }, NONE).ok === false);
  ok("incomplete SAML proposal rejected (kind recognised, config invalid)", validateIdpConnection({ id: "s2", kind: "saml", label: "s", presetId: "s", enabled: true }, NONE).ok === false);
}
ok("unknown kind rejected", validateIdpConnection({ id: "x", kind: "ldap", label: "x", presetId: "x", enabled: true }, NONE).ok === false);

// 20. base-field input gates (boundedStr / strArray / kind discriminant) on the shared validateIdpConnection
// path. These drive the early reject arms before the kind branch, plus the non-string-kind fallback message.
{
  // label: a non-string is rejected (boundedStr str() null arm).
  ok("non-string label rejected", validateIdpConnection({ ...baseOidc, label: 123 }, NONE).ok === false);
  // label: an over-length string is rejected (boundedStr length-bound arm, L172).
  ok("over-length label rejected", validateIdpConnection({ ...baseOidc, label: "x".repeat(129) }, NONE).ok === false);
  // label: a whitespace-only string trims to empty and is rejected (the t.length < 1 half of the bound).
  ok("whitespace-only label rejected (trims to empty)", validateIdpConnection({ ...baseOidc, label: "   " }, NONE).ok === false);
  // label: an ASCII control character is rejected verbatim (the control-char scan, L179) so it can never
  // reach SAML SP metadata as XML-illegal text.
  ok("label with a control character rejected", validateIdpConnection({ ...baseOidc, label: "Ent\x07ra" }, NONE).ok === false);
  // presetId: a non-string is rejected (L209).
  ok("non-string presetId rejected", validateIdpConnection({ ...baseOidc, presetId: 7 }, NONE).ok === false);
  // enabled: a non-boolean is rejected (L211).
  ok("non-boolean enabled rejected", validateIdpConnection({ ...baseOidc, enabled: "yes" }, NONE).ok === false);
  // a non-string kind takes the "<non-string>" fallback in the unknown-kind reason (L219 ternary else arm).
  const rNum = validateIdpConnection({ ...baseOidc, kind: 42 }, NONE);
  ok("numeric kind rejected with the <non-string> fallback reason", rNum.ok === false && rNum.reason.includes("<non-string>"));
}

// 21. OIDC input-gate arms not yet exercised: a non-string issuer, a non-array scopes, a non-string clientId,
// a duplicate signing alg (the algs.includes dedup arm, L271), and an unknown clientAuth.
{
  ok("non-string OIDC issuer rejected", validateIdpConnection({ ...baseOidc, issuer: 5 }, NONE).ok === false);
  ok("non-array OIDC scopes rejected", validateIdpConnection({ ...baseOidc, scopes: "openid" }, NONE).ok === false);
  ok("non-string OIDC clientId rejected", validateIdpConnection({ ...baseOidc, clientId: 9 }, NONE).ok === false);
  // A scopes array longer than the cap (32 items) is rejected by strArray (the v.length > maxItems arm, L185).
  ok("over-long OIDC scopes array rejected", validateIdpConnection({ ...baseOidc, scopes: Array.from({ length: 33 }, (_unused, i) => `s${i}`) }, NONE).ok === false);
  // A scopes array whose element is a control-char string is rejected by strArray (the bad-element arm, L189).
  ok("OIDC scopes with a control-char element rejected", validateIdpConnection({ ...baseOidc, scopes: ["openid", "of\x01fline"] }, NONE).ok === false);
  // ES256-only is accepted (drives the second alg comparison so both arms of the RS256/ES256 check run).
  const rEs = validateIdpConnection({ ...baseOidc, idTokenSigAlgs: ["ES256"] }, NONE);
  ok("ES256-only id_token alg accepted", rEs.ok === true && rEs.conn.kind === "oidc" && rEs.conn.idTokenSigAlgs.length === 1 && rEs.conn.idTokenSigAlgs[0] === "ES256");
  // A duplicate alg in idTokenSigAlgs is accepted but de-duplicated (drives the algs.includes(a) short-circuit).
  const rDup = validateIdpConnection({ ...baseOidc, idTokenSigAlgs: ["RS256", "RS256", "ES256"] }, NONE);
  ok("duplicate id_token alg accepted and de-duplicated", rDup.ok === true && rDup.conn.kind === "oidc" && rDup.conn.idTokenSigAlgs.length === 2);
  ok("empty idTokenSigAlgs rejected", validateIdpConnection({ ...baseOidc, idTokenSigAlgs: [] }, NONE).ok === false);
  ok("bad OIDC pkce value rejected", validateIdpConnection({ ...baseOidc, pkce: "maybe" }, NONE).ok === false);
  ok("unknown OIDC clientAuth rejected", validateIdpConnection({ ...baseOidc, clientAuth: "mutual_tls" }, NONE).ok === false);
}

// 22. secretRef.ref shape gate: a confidential client whose secretRef.ref is present but not a string is
// rejected (validateSecretRef boundedStr-null arm, L238) before the mode is even consulted.
ok("secretRef.ref that is not a string rejected", validateIdpConnection({ ...baseOidc, secretRef: { mode: "secrets-store", ref: 123 } }, NONE).ok === false);
// A confidential client with an unknown secretRef.mode is rejected (the final fall-through, L251).
ok("unknown secretRef.mode rejected for a confidential client", validateIdpConnection({ ...baseOidc, secretRef: { mode: "vault" } }, NONE).ok === false);

// 23. OIDC explicit endpoints: a non-string endpoint and an unsafe (private-host) endpoint are each rejected
// at the safe-fetch gate. The discoveryUrl host-match catch at L303-305 (new URL throwing) is unreachable
// from any input because assertSafeFetchEndpoint already URL-parses the same discoveryUrl one step earlier
// and rejects an unparseable one there; a string that parses there parses here too. Left uncovered by design.
{
  ok("non-string OIDC tokenEndpoint rejected", validateIdpConnection({ ...baseOidc, tokenEndpoint: 12 }, NONE).ok === false);
  ok("private-host OIDC authorizationEndpoint rejected", validateIdpConnection({ ...baseOidc, authorizationEndpoint: "https://127.0.0.1/authorize" }, NONE).ok === false);
  ok("non-string OIDC discoveryUrl rejected", validateIdpConnection({ ...baseOidc, discoveryUrl: 99 }, NONE).ok === false);
}

// 24. OIDC optional extras: every optional field set to a valid value lands on the record (the "if (field)"
// assignment arms, L323/L329/L332 etc), checkAzp:true is carried, and a bad value for each optional claim
// name is rejected (the "=== null" reject arms). One proposal sets them all so the happy arms all run.
{
  const rich = validateIdpConnection({
    ...baseOidc,
    groupsClaim: "groups",
    rolesClaim: "roles",
    claimNamespace: "https://maelstrom.au/",
    hdDomain: "maelstrom.au",
    checkAzp: true,
    acceptIssuerVariants: ["https://sts.windows.net/TENANTID/"],
    extraAuthParams: { prompt: "select_account" },
  }, NONE);
  ok("OIDC optional claim names + checkAzp + variants + extraAuthParams all carried onto the record",
    rich.ok === true && rich.conn.kind === "oidc"
    && rich.conn.groupsClaim === "groups" && rich.conn.rolesClaim === "roles"
    && rich.conn.claimNamespace === "https://maelstrom.au/" && rich.conn.hdDomain === "maelstrom.au"
    && rich.conn.checkAzp === true
    && Array.isArray(rich.conn.acceptIssuerVariants) && rich.conn.acceptIssuerVariants.length === 1
    && rich.conn.extraAuthParams !== undefined && rich.conn.extraAuthParams.prompt === "select_account");
  // checkAzp:false is carried as false (the typeof boolean arm with the other value).
  const rAzpFalse = validateIdpConnection({ ...baseOidc, checkAzp: false }, NONE);
  ok("OIDC checkAzp:false carried onto the record", rAzpFalse.ok === true && rAzpFalse.conn.kind === "oidc" && rAzpFalse.conn.checkAzp === false);
  // Each optional claim-name rejects a bad (over-length) value via its "=== null" arm.
  ok("OIDC over-length groupsClaim rejected", validateIdpConnection({ ...baseOidc, groupsClaim: "g".repeat(129) }, NONE).ok === false);
  ok("OIDC over-length rolesClaim rejected", validateIdpConnection({ ...baseOidc, rolesClaim: "r".repeat(129) }, NONE).ok === false);
  ok("OIDC over-length claimNamespace rejected", validateIdpConnection({ ...baseOidc, claimNamespace: "c".repeat(129) }, NONE).ok === false);
  ok("OIDC over-length hdDomain rejected", validateIdpConnection({ ...baseOidc, hdDomain: "h".repeat(129) }, NONE).ok === false);
  // issuerSubstitution set to a value other than 'tid' is rejected (L335).
  ok("OIDC issuerSubstitution other than 'tid' rejected", validateIdpConnection({ ...baseOidc, issuerSubstitution: "oid" }, NONE).ok === false);
  // acceptedTenantIds that is not an array is rejected (the strArray-null arm, L340).
  ok("OIDC non-array acceptedTenantIds rejected", validateIdpConnection({ ...baseOidc, issuer: "https://login.microsoftonline.com/{tenantid}/v2.0", issuerSubstitution: "tid", acceptedTenantIds: "T" }, NONE).ok === false);
  // acceptIssuerVariants that is not an array is rejected.
  ok("OIDC non-array acceptIssuerVariants rejected", validateIdpConnection({ ...baseOidc, acceptIssuerVariants: "x" }, NONE).ok === false);
  // extraAuthParams must be an object, not an array, and may not exceed the entry cap, and rejects a bad value.
  ok("OIDC array extraAuthParams rejected", validateIdpConnection({ ...baseOidc, extraAuthParams: ["a"] }, NONE).ok === false);
  ok("OIDC too-many extraAuthParams rejected", validateIdpConnection({ ...baseOidc, extraAuthParams: { a: "1", b: "2", c: "3", d: "4", e: "5", f: "6", g: "7", h: "8", i: "9" } }, NONE).ok === false);
  ok("OIDC extraAuthParams with a non-string value rejected", validateIdpConnection({ ...baseOidc, extraAuthParams: { prompt: 1 } }, NONE).ok === false);
}

// 25. OAuth2 input-gate arms: a non-string URL, a bad tokenAuthStyle, a non-string clientId, a non-array
// scopes, a missing subjectPath / subjectPrefix, and a bad pkce value are each rejected. baseOauth2 is a
// valid GitHub-class proposal reused across these vectors.
const baseOauth2 = {
  id: "gh2",
  kind: "oauth2",
  label: "GitHub 2",
  presetId: "github",
  enabled: true,
  authorizeUrl: "https://github.com/login/oauth/authorize",
  tokenUrl: "https://github.com/login/oauth/access_token",
  tokenAuthStyle: "post_json",
  clientId: "gh-client",
  secretRef: { mode: "do-plaintext" },
  scopes: ["read:org", "user:email"],
  apiBase: "https://api.github.com",
  profileUrl: "https://api.github.com/user",
  subjectPath: "id",
  subjectPrefix: "github",
  pkce: "supported",
};
{
  ok("OAuth2 non-string tokenUrl rejected", validateIdpConnection({ ...baseOauth2, tokenUrl: 8 }, NONE).ok === false);
  ok("OAuth2 bad tokenAuthStyle rejected", validateIdpConnection({ ...baseOauth2, tokenAuthStyle: "header" }, NONE).ok === false);
  ok("OAuth2 non-string clientId rejected", validateIdpConnection({ ...baseOauth2, clientId: 0 }, NONE).ok === false);
  ok("OAuth2 non-array scopes rejected", validateIdpConnection({ ...baseOauth2, scopes: "read:org" }, NONE).ok === false);
  ok("OAuth2 missing subjectPath rejected", validateIdpConnection({ ...baseOauth2, subjectPath: undefined }, NONE).ok === false);
  ok("OAuth2 missing subjectPrefix rejected", validateIdpConnection({ ...baseOauth2, subjectPrefix: 5 }, NONE).ok === false);
  ok("OAuth2 bad pkce value rejected", validateIdpConnection({ ...baseOauth2, pkce: "required" }, NONE).ok === false);
  // pkce 'supported' with NO secretRef maps onto a pkce-public client (the clientAuth ternary then-arm, L395).
  const rPub = validateIdpConnection({ ...baseOauth2, secretRef: undefined }, NONE);
  ok("OAuth2 pkce-public (no secret) accepted as a public client", rPub.ok === true && rPub.conn.kind === "oauth2" && rPub.conn.secretRef.mode === "pkce-public");
  // A confidential OAuth2 client whose secretRef is malformed is rejected (the !secret.ok arm, L397): pkce
  // 'none' forces the confidential branch, and an unknown mode then fails validateSecretRef.
  ok("OAuth2 confidential client with a bad secretRef rejected", validateIdpConnection({ ...baseOauth2, pkce: "none", secretRef: { mode: "vault" } }, NONE).ok === false);
}

// 26. OAuth2 optional fields: an unsafe emailUrl is rejected (the safe-fetch catch, L425); an unsafe
// groupsUrls entry is rejected (L442); and a proposal that sets every optional path field to a valid value
// lands them on the record (the "if (field)" assignment arms, L431/L433/L435/L449).
{
  ok("OAuth2 unsafe emailUrl rejected", validateIdpConnection({ ...baseOauth2, emailUrl: "https://10.0.0.5/emails" }, NONE).ok === false);
  ok("OAuth2 unsafe groupsUrls entry rejected", validateIdpConnection({ ...baseOauth2, groupsUrls: ["https://127.0.0.1/teams"] }, NONE).ok === false);
  ok("OAuth2 non-array groupsUrls rejected", validateIdpConnection({ ...baseOauth2, groupsUrls: "teams" }, NONE).ok === false);
  const rich2 = validateIdpConnection({
    ...baseOauth2,
    emailUrl: "https://api.github.com/user/emails",
    emailPath: "email",
    emailVerifiedPath: "verified",
    displayNamePath: "name",
    groupsUrls: ["https://api.github.com/user/teams"],
    groupsPath: "slug",
  }, NONE);
  ok("OAuth2 optional email/display/groups path fields all carried onto the record",
    rich2.ok === true && rich2.conn.kind === "oauth2"
    && rich2.conn.emailUrl === "https://api.github.com/user/emails"
    && rich2.conn.emailPath === "email" && rich2.conn.emailVerifiedPath === "verified"
    && rich2.conn.displayNamePath === "name"
    && Array.isArray(rich2.conn.groupsUrls) && rich2.conn.groupsUrls.length === 1
    && rich2.conn.groupsPath === "slug");
}

// 27. SAML input-gate arms not yet exercised: a non-string idpSsoUrl, a missing spEntityId, a missing
// nameIdFormat, a non-boolean allowIdpInitiated, an out-of-range clockSkewSec, and the optional attributes
// (emailAttr/groupsAttr/emailVerifiedAttr) all landing on the record. CERT is a minimal PEM marker the
// validator only checks for the BEGIN CERTIFICATE token.
{
  const CERT = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKxExampleExampleExampleExampleExampleExampleExampleEx\n-----END CERTIFICATE-----";
  const baseSaml2 = {
    id: "saml2", kind: "saml", label: "SAML 2", presetId: "saml", enabled: true,
    idpEntityId: "http://www.okta.com/exk999", idpSsoUrl: "https://acme.okta.com/app/sso/saml",
    idpSigningCerts: [CERT], spEntityId: "https://console.downpipes.io/saml",
    nameIdFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    wantAssertionsSigned: true, allowIdpInitiated: true, clockSkewSec: 0,
    emailVerifiedPolicy: "trust-idp",
  };
  ok("SAML non-string idpSsoUrl rejected", validateIdpConnection({ ...baseSaml2, idpSsoUrl: 5 }, NONE).ok === false);
  ok("SAML non-string idpEntityId rejected", validateIdpConnection({ ...baseSaml2, idpEntityId: 5 }, NONE).ok === false);
  ok("SAML missing spEntityId rejected", validateIdpConnection({ ...baseSaml2, spEntityId: undefined }, NONE).ok === false);
  ok("SAML missing nameIdFormat rejected", validateIdpConnection({ ...baseSaml2, nameIdFormat: 7 }, NONE).ok === false);
  ok("SAML non-array idpSigningCerts rejected", validateIdpConnection({ ...baseSaml2, idpSigningCerts: "cert" }, NONE).ok === false);
  ok("SAML non-boolean allowIdpInitiated rejected", validateIdpConnection({ ...baseSaml2, allowIdpInitiated: "true" }, NONE).ok === false);
  ok("SAML out-of-range clockSkewSec rejected", validateIdpConnection({ ...baseSaml2, clockSkewSec: 601 }, NONE).ok === false);
  ok("SAML negative clockSkewSec rejected", validateIdpConnection({ ...baseSaml2, clockSkewSec: -1 }, NONE).ok === false);
  ok("SAML non-number clockSkewSec rejected", validateIdpConnection({ ...baseSaml2, clockSkewSec: "120" }, NONE).ok === false);
  ok("SAML bad emailVerifiedPolicy rejected", validateIdpConnection({ ...baseSaml2, emailVerifiedPolicy: "always" }, NONE).ok === false);
  // A minimal SAML proposal that OMITS every optional attr is accepted, and those fields stay absent on the
  // record (drives the ": undefined" arm of each optional-attr ternary, L509/L511/L513).
  const leanSaml = validateIdpConnection({ ...baseSaml2 }, NONE);
  ok("SAML with no optional attributes accepted; the attrs stay absent",
    leanSaml.ok === true && leanSaml.conn.kind === "saml"
    && leanSaml.conn.emailAttr === undefined && leanSaml.conn.groupsAttr === undefined && leanSaml.conn.emailVerifiedAttr === undefined);
  // A proposal that sets every optional attr lands them on the record (the "if (attr)" assignment arms).
  const richSaml = validateIdpConnection({ ...baseSaml2, emailAttr: "mail", groupsAttr: "memberOf", emailVerifiedAttr: "email_verified" }, NONE);
  ok("SAML optional email/groups/email-verified attributes all carried onto the record",
    richSaml.ok === true && richSaml.conn.kind === "saml"
    && richSaml.conn.emailAttr === "mail" && richSaml.conn.groupsAttr === "memberOf"
    && richSaml.conn.emailVerifiedAttr === "email_verified"
    && richSaml.conn.allowIdpInitiated === true && richSaml.conn.clockSkewSec === 0);
  // ===== A PRESENT-BUT-UNUSABLE ATTRIBUTE MAPPING IS REFUSED, NOT DROPPED ONTO A 200. =====
  //
  // These three fields were guarded by a bare truthiness
  // check over boundedStr's null, so an over-CLAIM_NAME_MAX value fell through the `if` and the connection
  // saved with the mapping ABSENT. groupsAttr is authorisation: the operator's groups-to-roles rules then
  // silently did not apply and every user landed with no groups, on a connection reported as saved. The
  // OIDC branch beside it already refused on the same sentinel; these two branches did not.
  //
  // Asserted on the REFUSAL and its reason, and each field is checked separately so one shared guard
  // cannot make all three pass. The lean and rich cases above are the discriminating controls: an omitted
  // attribute is still accepted, and a valid one is still carried onto the record.
  const LONG = "a".repeat(129); // CLAIM_NAME_MAX is 128
  for (const f of ["emailAttr", "groupsAttr", "emailVerifiedAttr"]) {
    const r = validateIdpConnection({ ...baseSaml2, [f]: LONG }, NONE);
    ok(`SAML an over-length ${f} is REFUSED, never dropped onto an ok:true connection`, r.ok === false && String((r as { reason: string }).reason).includes(`${f} must be a short string`));
  }
  // A control character is the other half of boundedStr's null, and it would have been dropped identically.
  // The other two halves of boundedStr's null sentinel, which the old truthiness guard dropped identically:
  // a control character, and an EMPTY string. Both assert the REASON and not merely ok===false, because a
  // bare ok===false is not evidence about the field named in the label: this file already refuses some of
  // these proposals for unrelated reasons, and a refusal is easy to get for the wrong one. The empty case is
  // also why it matters that the console OMITS a blank attribute box rather than posting an empty string
  // (console/src/screens/idp-connections/saml-form.ts builds the field conditionally).
  const ctrlAttr = validateIdpConnection({ ...baseSaml2, id: "saml-ctrl", groupsAttr: "mem\u0001berOf" }, NONE);
  ok("SAML a control character in groupsAttr is REFUSED with that field's own reason", ctrlAttr.ok === false && String((ctrlAttr as { reason: string }).reason).includes("groupsAttr must be a short string"));
  const emptyAttr = validateIdpConnection({ ...baseSaml2, id: "saml-empty", groupsAttr: "" }, NONE);
  ok("SAML an EMPTY groupsAttr is REFUSED with that field's own reason, not stored as an empty mapping", emptyAttr.ok === false && String((emptyAttr as { reason: string }).reason).includes("groupsAttr must be a short string"));
  // AND THE DISCRIMINATING CONTROL for the pair, at the same fresh id: the identical proposal with a plain
  // "memberOf" is ACCEPTED and the mapping lands. Without it the two refusals above prove nothing.
  const ctrlOk = validateIdpConnection({ ...baseSaml2, id: "saml-ctrlok", groupsAttr: "memberOf" }, NONE);
  ok("SAML CONTROL: the same proposal with a plain groupsAttr is accepted and the mapping lands", ctrlOk.ok === true && ctrlOk.conn.kind === "saml" && ctrlOk.conn.groupsAttr === "memberOf");
  // 28. redactIdpConn on a SAML record takes the kind === "saml" pass-through arm (L143): the record is
  // returned verbatim (SAML carries public certs and no client secret), and a do-plaintext OIDC record
  // takes the safeRef no-ref ternary arm (L142) so the redacted secretRef is exactly {mode}.
  if (richSaml.ok && richSaml.conn.kind === "saml") {
    const storedSaml: IdpConnection = { ...richSaml.conn, createdBy: null, createdAt: "2026-06-13T00:00:00.000Z" } as IdpConnection;
    const redSaml = redactIdpConn(storedSaml);
    ok("redactIdpConn passes a SAML record through verbatim", redSaml === storedSaml && redSaml.kind === "saml");
  }
}
{
  const rDo = validateIdpConnection({ ...baseOidc, secretRef: { mode: "do-plaintext" } }, NONE);
  if (rDo.ok && rDo.conn.kind === "oidc") {
    const storedDo: IdpConnection = { ...rDo.conn, createdBy: "owner@example.com", createdAt: "2026-06-13T00:00:00.000Z" } as IdpConnection;
    const redDo = redactIdpConn(storedDo);
    ok("redactIdpConn on a no-ref (do-plaintext) secretRef returns exactly {mode}",
      redDo.kind !== "saml" && JSON.stringify((redDo as { secretRef: object }).secretRef) === JSON.stringify({ mode: "do-plaintext" }));
  }
}

console.log("");
if (failures > 0) process.exitCode = 1;
if (failures > 0) {
  console.log(`IDPCONN CONFIG VECTORS: ${failures} FAILED`);
  process.exit(1);
}
console.log("IDPCONN CONFIG VECTORS PASS");
