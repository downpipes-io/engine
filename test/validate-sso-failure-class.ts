// Pins the SSO sign-in failure classifier (admin/sso-failure-class.ts): every free-text failure reason the
// codebase currently emits (oidc-verify.ts / oidc-store.ts / saml/response.ts / scheduler-do-idp.ts) maps to the
// intended CLOSED diagnostic code. This is the safety net for the classifier — a wording change upstream that
// would silently mis-route a failure is caught here (the same discipline the seal/dest classifiers use). It also
// asserts the no-custody property: an interpolated issuer / connId / error message in a reason never changes the
// code and never appears in the output (the output IS the code).

import { classifySsoFailure, SSO_FAIL_CODES, type SsoFailCode } from "../src/admin/sso-failure-class.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// [reason as emitted, expected code]. Interpolated fields use representative hostile-ish values to prove the
// classifier ignores them (they must not change the code, and — asserted separately — never leak).
const CASES: Array<[string, SsoFailCode]> = [
  // ---- OIDC id_token verify (oidc-verify.ts) ----
  ["id_token missing or too large", "malformed"],
  ["malformed JWT (expected three segments)", "malformed"],
  ["payload is not a JSON object", "malformed"],
  ["undecodable JWT", "malformed"],
  ["no algorithms allowed for this connection", "key"],
  ["unacceptable alg: HS256", "key"],
  ["alg RS384 is not enabled for this connection", "key"],
  ["missing kid", "key"],
  ["unexpected token type at+jwt", "malformed"],
  ["aud does not include the client_id", "audience"],
  ["azp must equal the client_id when aud is multi-valued or azp is present", "audience"],
  ["missing or non-numeric exp", "malformed"],
  ["token expired", "expired"],
  ["nbf present but not a finite number", "malformed"],
  ["token not yet valid (nbf)", "clock-skew"],
  ["iat present but not a finite number", "malformed"],
  ["token issued in the future (iat)", "clock-skew"],
  ["nonce mismatch", "replay"],
  ["signing key not found for kid", "key"],
  ["alg/key mismatch: RS256 requires an RSA key, got kty EC", "key"],
  ["ES256 requires a P-256 key, got crv P-384", "key"],
  ["signature segment is not base64url", "signature"],
  ["signature verification error", "signature"],
  ["bad signature", "signature"],
  ["missing sub", "malformed"],
  ["at_hash mismatch", "malformed"],
  ["issuer not accepted: https://evil.example/../%00", "issuer"],
  // ---- OIDC / OAuth2 flow + store (oidc-store.ts) ----
  ["discovery fetch failed: getaddrinfo ENOTFOUND idp.example", "connection"],
  ["discovery endpoint returned 503", "connection"],
  ["discovery document is not JSON", "connection"],
  ['connection "acme-oidc" is disabled', "connection"],
  ['connection "acme-oidc" not found', "connection"],
  ['connection "acme-oidc" is not an OIDC connection', "connection"],
  ["RFC 9207 iss mismatch (possible IdP mix-up)", "issuer"],
  ["no stored client secret for this connection (do-plaintext)", "connection"],
  ["secrets-store secret resolution not wired in this build", "connection"],
  ["unsupported secret mode: private-key-jwt", "connection"],
  ["unknown, expired or already-used state", "replay"],
  ["state connId does not match the callback connId", "replay"],
  ["transaction id mismatch (possible login CSRF)", "replay"],
  ['connection "acme-oauth" is not an OAuth2 connection', "connection"],
  ["unsupported secret mode for an OAuth2 connection: private-key-jwt", "connection"],
  // ---- SAML response (saml/response.ts) ----
  ["SAMLResponse is missing", "malformed"],
  ["SAMLResponse exceeds the maximum size", "malformed"],
  ["SAMLResponse is not valid base64", "malformed"],
  ["root element is not a samlp:Response", "malformed"],
  ["encrypted assertions not supported in this build", "malformed"],
  ["Response carries no saml:Assertion", "malformed"],
  ["Response carries more than one saml:Assertion (rejected: XML-Signature-Wrapping)", "signature"],
  ["SAML Response status is not Success", "other"],
  ["Response @Destination does not match our ACS URL", "malformed"],
  ["Response @InResponseTo does not match the request we sent", "replay"],
  ["IdP-initiated SAML Response is not permitted for this connection", "replay"],
  ["connection has no pinned IdP signing certificate", "signature"],
  // ---- SAML ACS (scheduler-do-idp.ts) ----
  ["invalid connId", "malformed"],
  ["unknown, expired or already-used SAML request (this SP is SP-initiated only)", "replay"],
  ["RelayState connId does not match the ACS connId", "replay"],
  ["SAML browser binding mismatch (possible forced-login)", "replay"],
  ["SAML connection not found", "connection"],
  ["connection is disabled", "connection"],
  ["SAML assertion already consumed (replay)", "replay"],
  ["this connection kind does not support interactive sign-in", "connection"],
  // ---- SAML assertion consume (saml/assertion.ts) ----
  ["assertion is not an element", "malformed"],
  ["verified node is not a saml:Assertion", "malformed"],
  ["assertion has no Issuer", "issuer"],
  ["assertion Issuer does not match the connection's idpEntityId", "issuer"],
  ["assertion has no ID", "malformed"],
  ["assertion has no Subject", "malformed"],
  ["assertion has no Conditions", "malformed"],
  ["Conditions NotBefore missing or unparseable", "malformed"],
  ["Conditions NotOnOrAfter missing or unparseable", "malformed"],
  ["assertion not yet valid (Conditions NotBefore)", "clock-skew"],
  ["assertion expired (Conditions NotOnOrAfter)", "expired"],
  ["no AudienceRestriction/Audience matches the SP entityId", "audience"],
  ["Subject has no NameID", "malformed"],
  ["transient NameID format is not acceptable (not stable enough to key authorisation)", "malformed"],
  ["NameID Format does not match the connection's pinned nameIdFormat", "malformed"],
  ["NameID is empty", "malformed"],
  ["Subject has no SubjectConfirmation", "malformed"],
  ["no bearer SubjectConfirmation satisfies Recipient/InResponseTo/NotOnOrAfter", "replay"],
  // ---- SAML dsig / certificate (saml/dsig.ts, response-cert.ts, response.ts) ----
  ["the IdP signing certificate is not yet valid (outside its validity window)", "signature"],
  ["the IdP signing certificate has expired (outside its validity window)", "signature"],
  ["malformed tbsCertificate (validity)", "signature"],
  ["neither the assertion nor the Response carried a verifiable signature (the assertion is unsigned and no accepted Response-level signature verified under a pinned certificate)", "signature"],
  // ---- HOSTILE INTERPOLATION: an attacker-chosen token in an interpolated tail must
  //      NOT hijack the classification. Each of these fails under a whole-string scan (the injected token steals the
  //      match) and passes only because the interpolating reason is anchored on its fixed prefix. ----
  ["SAMLResponse XML is malformed: undefined general entity reference &certificate;", "malformed"], // would steal -> signature
  ["SAMLResponse XML is malformed: mismatched tags: <audience>", "malformed"], // would steal -> audience
  ["SAMLResponse XML is malformed: undefined general entity reference &inresponseto;", "malformed"], // would steal -> replay
  ["SAMLResponse XML is malformed: mismatched tags: <expired>", "malformed"], // would steal -> expired
  ['connection "certificate-idp" is disabled', "connection"], // would steal -> signature
  ['connection "audience-conn" not found', "connection"], // would steal -> audience
  ['connection "inresponseto-idp" is not an OIDC connection', "connection"], // would steal -> replay
  ["discovery fetch failed: peer certificate has expired", "connection"], // would steal -> signature/expired
  ["unacceptable alg: certificate", "key"], // would steal -> signature
  ["issuer not accepted: https://idp.example/audience/certificate", "issuer"], // would steal -> audience/signature
  ["unexpected token type inresponseto", "malformed"], // would steal -> replay
  ["alg audience is not enabled for this connection", "key"], // would steal -> audience
  // The SAML sig-verify failure wraps the dsig reason, which interpolates the attacker's ds:Reference @URI /
  // @Algorithm. Without the anchor these hijack to `replay` via the injected token.
  ["assertion signature did not verify under any pinned certificate: Reference URI must be a same-document fragment #id - got: inresponseto", "signature"], // would steal -> replay
  ["assertion signature did not verify under any pinned certificate: Reference URI must be a same-document fragment #id - got: relaystate", "signature"], // would steal -> replay
  ["assertion signature did not verify under any pinned certificate: neither the assertion nor the Response carried a verifiable signature (the assertion is unsigned and no accepted Response-level signature verified under a pinned certificate)", "signature"],
  ["pinned certificate could not be parsed: malformed tbsCertificate (validity)", "signature"],
  ["discovery: missing issuer", "connection"], // the discovery:<colon> fidelity variant (was falling to `other`)
  ["discovery: missing token_endpoint", "connection"],
  // The OIDC callback WRAPS the id_token verify reason as "id_token rejected: <inner>" — the inner is the real
  // signal AND carries the attacker iss/alg. STRIP + reclassify keeps fidelity and defeats a hijack token in the
  // inner tail. Plus the jwks / token-endpoint / verification-error / discovery-issuer OIDC reasons.
  ["id_token rejected: issuer not accepted: https://evil.example/inresponseto", "issuer"], // strip -> issuer (would else steal -> replay)
  ["id_token rejected: token expired", "expired"],
  ["id_token rejected: nonce mismatch", "replay"],
  ["id_token rejected: bad signature", "signature"],
  ["id_token rejected: unacceptable alg: certificate", "key"], // strip -> key (would else steal -> signature)
  ["id_token verification error: getaddrinfo ENOTFOUND jwks.inresponseto.example", "key"], // would steal -> replay
  ["jwks fetch failed: peer certificate has expired", "key"], // would steal -> signature/expired
  ["jwks endpoint returned 503", "key"],
  ["jwks carries a duplicate kid: inresponseto", "key"], // would steal -> replay
  ["token endpoint returned 500", "connection"],
  ["token endpoint fetch failed: connect to inresponseto host failed", "connection"], // would steal -> replay
  ['discovery issuer "https://a/audience" does not match the configured issuer "https://b"', "issuer"], // would steal -> audience
  // ---- OAuth2 (oauth2.ts) -- fidelity coverage, not a hijack ----
  ["profile fetch: endpoint returned 500", "connection"],
  ["profile fetch: fetch failed: connect to inresponseto host failed", "connection"], // anchor holds even with a coincidental token
  ['profile carried no immutable id at "$.sub"', "malformed"],
  ["profile id is empty", "malformed"],
  ["token response is not an object", "connection"],
  ["token response carried no access_token", "connection"],
  ["post_json token auth requires a resolved client secret", "connection"],
  ["post_form_basic token auth requires a resolved client secret", "connection"],
  ["the IdP asserted no usable email; grant the email scope on this connection", "connection"],
  ["the resolved subject is not a usable key", "malformed"],
  // ---- fallback / edge ----
  ["something entirely novel we have never seen", "other"],
  ["", "other"],
];

function main(): void {
  console.log("SSO failure classifier truth table:");
  for (const [reason, expected] of CASES) {
    const got = classifySsoFailure(reason);
    ok(`${JSON.stringify(reason).slice(0, 64)} -> ${expected}${got === expected ? "" : ` (GOT ${got})`}`, got === expected);
  }

  console.log("\nclosed-vocabulary + no-custody properties:");
  ok("every classified code is a member of the closed SSO_FAIL_CODES set", CASES.every(([r]) => (SSO_FAIL_CODES as readonly string[]).includes(classifySsoFailure(r))));
  // The output is the CODE only — an interpolated issuer / connId / error message must never appear in it.
  ok("an interpolated hostile issuer never appears in the code", !classifySsoFailure("issuer not accepted: https://evil<script>").includes("evil"));
  ok("an interpolated connId never appears in the code", !classifySsoFailure('connection "SECRET-slug-xyz" is disabled').includes("SECRET"));
  ok("a non-string reason is tolerated and yields other", classifySsoFailure(undefined as unknown as string) === "other");

  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.log(`\nSSO FAILURE CLASSIFIER: ${failures} FAILED`);
    process.exit(1);
  }
  console.log("\nSSO FAILURE CLASSIFIER PASS");
}

main();
