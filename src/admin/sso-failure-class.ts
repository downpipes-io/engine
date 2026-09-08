// classifySsoFailure maps a free-text interactive-sign-in verification failure reason to a CLOSED diagnostic
// code, for the support pack's bounded SSO-failure aggregate.
//
// WHY a classifier (and not the raw reason): the failure reasons produced by oidc-verify.ts / saml/response.ts /
// oidc-store.ts are free text and SOME INTERPOLATE UNTRUSTED DATA, an issuer URL (`issuer not accepted: <iss>`),
// a connId (`connection "<id>" is disabled`), a network error message (`discovery fetch failed: <msg>`), an alg
// name. Persisting or projecting the raw reason would be a no-custody violation and an injection vector. So the
// reason is read HERE transiently, reduced to a fixed closed code, and then DISCARDED, only the code (plus a
// count and a timestamp) is ever stored or shipped.
//
// The rules are ORDERED, first-match-wins, matched against the lower-cased reason; an unrecognised reason yields
// "other" (never throws). The reasons the codebase emits are enumerated in test/validate-sso-failure-class.ts and
// pinned to their expected code, INCLUDING the INTERPOLATING reasons with HOSTILE injected tails (e.g. a SAML
// "malformed: <element name>" whose tail is `&certificate;`, or a connId literally named `certificate-idp`), which
// the anchored-prefix rules below must classify by their fixed prefix, not the attacker-chosen tail. A wording
// change that would silently mis-route is caught by the suite (the same discipline as the seal/dest classifiers).

export const SSO_FAIL_CODES = [
  "issuer", // the token/assertion issuer is not the configured one (OIDC iss / RFC 9207 / SAML issuer), check the IdP issuer URL
  "audience", // aud/azp does not match the configured client id, check the client/entity id
  "expired", // the token/assertion validity window has passed (exp / NotOnOrAfter), re-authenticate; check token lifetime
  "clock-skew", // the token is from the future relative to us (nbf/iat), the engine and IdP clocks disagree; sync time
  "signature", // signature did not verify / signature-wrapping / no pinned cert, check the IdP signing certificate / JWKS
  "key", // the signing key/alg could not be selected (kid not found, alg not enabled, key-type mismatch), JWKS rotation / enable the alg
  "replay", // a single-use flow artefact was reused/absent (state, nonce, InResponseTo, RelayState, assertion replay, forced-login, CSRF), usually a stale/duplicated login; if persistent, check clocks/session
  "connection", // the connection is disabled/missing/misconfigured, or a secret/discovery could not be resolved, check the connection config
  "malformed", // the token/response was structurally invalid or wrongly targeted (bad JWT/base64/XML, wrong Destination, missing claim), check the IdP is sending a well-formed response for THIS SP
  "groups-overflow", // the IdP WITHHELD the groups claim because the user is in too many groups (the Entra >200-group overage). Its own code because the remediation is unique and the consequence is a SILENT AUTHORIZATION DOWNGRADE: without this code the refusal fell to "other", which reads as an unclassified oddity rather than "configure App Roles or a groups filter".
  // The two SSO paths below are not produced by classifySsoFailure: the aggregate is written only by the
  // CALLBACK/ACS wrapper, so a sign-in that dies at /start or at metadata rendering never reaches it. Both are
  // recorded with an EXPLICIT code (they are known by their PATH, not by parsing a message), so they can ride
  // the same aggregate, the same by-kind axis and the same pack projection.
  "start-failure", // the sign-in died at /start: the connection is disabled, deleted, or the AuthnRequest could not be built.
  "metadata-failure", // the SP metadata document could not be produced (an unknown or non-SAML connId). The IdP-side import then fails and nothing engine-side records it.
  "other", // anything not matched (includes an IdP-side non-success status, the IdP declined the sign-in)
] as const;
export type SsoFailCode = (typeof SSO_FAIL_CODES)[number];

// Ordered [test, code]. The `test` runs against the LOWER-CASED reason. First match wins.
//
// ANCHORED-PREFIX RULES COME FIRST (adversarial-review fix). Several reasons INTERPOLATE untrusted text after a
// fixed prefix, an attacker-controlled JWT `iss`/`alg`/`typ`, a customer connId, a discovery error message, and
// (for SAML) attacker-chosen XML element/entity names surfaced by the parser as `SAMLResponse XML is malformed:
// <tail>`. A whole-string rule can be HIJACKED by an interpolated token (e.g. an `&certificate;` entity or an
// `inresponseto` element name steering a malformed-XML failure into `signature`/`replay`), which would poison the
// diagnosis and give wrong remediation. So each interpolating reason is matched on its FIXED PREFIX (`^…`) BEFORE
// any whole-string token rule; the interpolated tail can no longer change the code. Every interpolating reason has
// its interpolation strictly after a fixed prefix (or inside quotes after one), so this is complete.
//
// The whole-string rules that follow classify the reasons that carry NO interpolation (fixed strings). Their
// ordering still carries meaning: replay precedes `expired` (so "unknown, expired or already-used state" is
// replay); the certificate rule precedes clock-skew/expired/malformed (a signing-cert validity/parse failure
// shares the "not yet valid"/"malformed" wording); "missing or unparseable" precedes expired.
const RULES: Array<{ re: RegExp; code: SsoFailCode }> = [
  // --- anchored-prefix rules for the INTERPOLATING reasons (untrusted tail cannot hijack the match) ---
  { re: /^issuer not accepted/, code: "issuer" }, // issuer not accepted: <attacker iss>
  { re: /^discovery issuer/, code: "issuer" }, // discovery issuer "<x>" does not match the configured issuer "<y>" (BEFORE /^discovery/)
  { re: /^connection "/, code: "connection" }, // connection "<connId>" is disabled / not found / is not an oidc|oauth2 connection
  { re: /^discovery[ :]/, code: "connection" }, // discovery fetch failed: <err msg> / endpoint returned <n> / document is not JSON / discovery: missing <endpoint>
  { re: /^jwks /, code: "key" }, // jwks fetch failed: <msg> / endpoint returned <n> / carries a duplicate kid: <x>
  { re: /^token endpoint /, code: "connection" }, // token endpoint fetch failed: <msg> / returned <n>
  { re: /^id_token verification error/, code: "key" }, // id_token verification error: <thrown e.message> (the id_token verify threw, JWKS/crypto)
  { re: /^unacceptable alg/, code: "key" }, // unacceptable alg: <attacker alg>
  { re: /^alg\b/, code: "key" }, // alg <attacker alg> is not enabled... / alg/key mismatch: ... got kty <x>
  { re: /^(es256|rs256) requires/, code: "key" }, // ES256 requires a P-256 key, got crv <x>
  { re: /^unexpected token type/, code: "malformed" }, // unexpected token type <attacker typ>
  { re: /^unsupported secret mode/, code: "connection" }, // unsupported secret mode[ for an OAuth2 connection]: <mode>
  { re: /^samlresponse /, code: "malformed" }, // SAMLResponse is missing/exceeds/not base64 / XML is malformed: <attacker XML text>
  // The SAML signature-verification failure WRAPS the dsig reason, which interpolates ATTACKER-controlled XML (the
  // ds:Reference @URI and @Algorithm values), so it MUST be anchored (else a `#inresponseto` URI hijacks it to
  // `replay` via the whole-string replay rule below). The pinned-cert-parse reason wraps the operator's OWN cert
  // (not attacker text), anchored too for symmetry. (Residual found by the focused re-review of the first fix.)
  { re: /^assertion signature did not verify/, code: "signature" }, // ...under any pinned certificate: <dsig reason with attacker @URI/@Algorithm>
  { re: /^pinned certificate/, code: "signature" }, // pinned certificate could not be parsed: <operator cert parse reason>
  // OAuth2 (oauth2.ts), forwarded UNWRAPPED via the OAuth2 callback. `profile fetch: <inner>` is the interpolating
  // one (an ${e.message} tail, anchored for discipline, though its tail is a numeric status / runtime msg, never
  // an attacker-authored token); the rest are fixed strings classified off `other` for OAuth2 diagnosis fidelity.
  { re: /^profile fetch/, code: "connection" }, // profile fetch: <inner fetch reason> (the userinfo fetch failed)
  { re: /^profile (carried no|id)/, code: "malformed" }, // profile carried no immutable id / profile id is empty|not a safe integer
  { re: /^token response/, code: "connection" }, // token response is not an object / carried no access_token
  { re: /token auth requires a resolved client secret/, code: "connection" }, // post_json / post_form_basic token auth ...
  { re: /^the idp asserted no usable email/, code: "connection" }, // ...grant the email scope on this connection
  // The groups-overage refusal gets its OWN code (anchored, so the fixed prefix decides, never any tail),
  // rather than falling through to "other" and hiding a silent authorization downgrade in an unclassified bucket.
  { re: /^the idp withheld the groups claim/, code: "groups-overflow" },
  { re: /^the resolved subject is not a usable key/, code: "malformed" }, // the minted-session subject is unusable
  // --- whole-string rules for the FIXED (non-interpolating) reasons ---
  // Replay / single-use-flow family, the bearer SubjectConfirmation failure (Recipient/InResponseTo/NotOnOrAfter)
  // lands here via `inresponseto`, which is the intended anti-replay reading.
  { re: /already[- ]used|already consumed|used state|nonce mismatch|login csrf|\bcsrf\b|transaction id mismatch|inresponseto|relaystate|browser binding|forced-login|is not permitted|does not match the (callback|acs) connid|state connid does not match/, code: "replay" },
  // Any signing-CERTIFICATE problem (no pinned cert, cert not-yet-valid / expired, malformed tbsCertificate, an
  // unsigned assertion with no accepted Response signature), routed BEFORE clock-skew/expired/malformed so the
  // shared wording ("not yet valid", "expired", "malformed") does not steal a cert failure into the wrong bucket.
  { re: /certificate|verifiable signature/, code: "signature" },
  // Issuer (RFC 9207 / SAML assertion Issuer). ("issuer not accepted: <iss>" is claimed by the anchored rule above.)
  { re: /iss mismatch|issuer does not match|has no issuer/, code: "issuer" },
  // Audience / client-id / SP entity id.
  { re: /aud does not include|azp must equal|audience/, code: "audience" },
  // An unparseable/absent time condition is a MALFORMED conditions field, not a genuine skew or expiry. Precedes
  // clock-skew/expired so it is not misread as one.
  { re: /missing or unparseable/, code: "malformed" },
  // Clock skew, the token/assertion is from the future relative to us (nbf/iat / NotBefore), distinct from expiry.
  { re: /not yet valid|issued in the future|clock skew|too far from|time is too/, code: "clock-skew" },
  // Expired, validity window in the past. (The replay + certificate rules already claimed their phrasings.)
  { re: /expired|notonorafter|not on or after|validity window/, code: "expired" },
  // Signature (non-certificate): bad/absent signature, signature-wrapping, more-than-one-assertion.
  { re: /bad signature|signature verification|signature segment|signature-wrapping|more than one saml:assertion|invalid signature/, code: "signature" },
  // Key / algorithm selection. ("unacceptable alg"/"alg …"/"ES256 requires" are claimed by the anchored rules above.)
  { re: /\bkid\b|is not enabled for this connection|no algorithms allowed|alg\/key|requires an? (rsa|ec) key|requires a p-256|signing key not found/, code: "key" },
  // Connection configuration / secret. (The interpolating connection/discovery/secret-mode reasons are claimed above.)
  { re: /is disabled|not found|no stored client secret|secret resolution|does not support interactive|is not an oidc connection|is not an oauth2 connection/, code: "connection" },
  // Malformed / mistargeted / missing-element token or response.
  { re: /malformed|not valid base64|is not a json|not a json object|undecodable|is not a samlp|carries no saml:assertion|destination does not match|missing sub|missing or non-numeric|not a finite number|exceeds the maximum size|missing or too large|encrypted assertions|root element is not|at_hash|invalid connid|payload is not a json|assertion is not an element|verified node is not|assertion has no|subject has no|nameid|not stable enough/, code: "malformed" },
];

export function classifySsoFailure(reason: string): SsoFailCode {
  let r = (typeof reason === "string" ? reason : "").toLowerCase();
  // UNWRAP a "reclassify-the-inner" prefix: `id_token rejected: <the id_token verify reason>` wraps an inner
  // reason that IS the real, independently-classifiable signal (issuer / audience / expired / signature / …).
  // Strip it so the inner reason is classified on its own (anchored) rules, preserving fidelity AND defeating a
  // hijack token in the inner reason's own interpolated tail (e.g. an attacker `iss` of `https://x/inresponseto`,
  // which would otherwise steer the wrapped string to `replay`). One strip only, no wrapper nests another.
  r = r.replace(/^id_token rejected: /, "");
  for (const { re, code } of RULES) if (re.test(r)) return code;
  return "other";
}

// classifySsoStartFailure (G002) is the START-path sibling of classifySsoFailure. The SSO-failure aggregate is
// written only by the DO's CALLBACK wrapper, so a sign-in that dies at /start - the IdP's discovery host is down,
// the connection is disabled, an endpoint fails the issuer-host safety check - never reaches a recorder at all:
// the user sees "the SSO button just errors" and the pack shows ZERO SSO failures. The start route runs at the
// Worker edge (router-idp-web.ts), which cannot write the code+kind SSO aggregate, but CAN write the bounded
// auth-signal aggregate. So this maps a start-path reason to one of the closed `sso-start-*` AUTH-SIGNAL names.
//
// Same redaction discipline as classifySsoFailure, and for the same reason: these reasons INTERPOLATE untrusted
// text (a discovery error message, a connId, an endpoint host). The reason is read TRANSIENTLY here, reduced to a
// closed name, and DISCARDED; only the name is ever recorded. Every rule is an ANCHORED PREFIX, so an interpolated
// tail (an attacker-chosen host, a connId literally named "disabled") can never steer the classification.
export function classifySsoStartFailure(reason: string): string {
  const r = (typeof reason === "string" ? reason : "").toLowerCase();
  // The IdP's discovery host could not be reached at all: an IdP-side outage or a DNS/egress fault. Distinct from
  // a discovery document the IdP DID serve but we refused, because the remediation is "wait / check the IdP", not
  // "fix your connection". Anchored ahead of the generic discovery rule below.
  if (/^discovery fetch failed/.test(r)) return "sso-start-discovery-unreachable";
  // The IdP served discovery but it was unusable: a non-200 (often an auth/tenant error page) or a non-JSON body
  // (typically a captive portal or proxy interstitial in front of the IdP).
  if (/^discovery (endpoint returned|document is not json)/.test(r)) return "sso-start-discovery-refused";
  // WE refused an endpoint the IdP advertised (or the connection's own issuer): a bad URL, or an endpoint served
  // off a host that does not match the issuer host (the SSRF/mix-up safety check). An operator-fixable pin.
  if (/^discovery /.test(r) || /^the connection issuer is not a valid url/.test(r)) return "sso-start-endpoint-refused";
  // The connection itself cannot start a sign-in: disabled, deleted, an unknown connId, a kind with no interactive
  // flow, or a client secret that could not be resolved.
  if (/^connection "/.test(r) || /^invalid connid/.test(r) || /is disabled|not found|does not support interactive|no stored client secret|secret resolution|^unsupported secret mode/.test(r)) {
    return "sso-start-connection-refused";
  }
  return "sso-start-refused"; // residual: a start refusal we have not named
}

// ---------------------------------------------------------------------------------------------------------
// THE SSO FAILURE SUB-CAUSE (the remediation-bearing half of an SSO-outage report)
//
// The SSO_FAIL_CODES above name the STAGE that refused (issuer / key / signature / replay / malformed). They
// do not name the CAUSE, and the cause is what the operator has to fix, e.g.: an EXPIRED Entra client secret
// (the token endpoint answered `invalid_client`) versus any other token-endpoint failure; a kid-not-found
// after a JWKS rotation versus a duplicate-kid document that refuses the whole JWKS; state-missing (no
// cookie) versus state-replayed (a double-submitted callback) versus state-expired. Two SAML classes also
// need their own code rather than the coarse one: an IdP-initiated POST at an SP-initiated-only connection is
// a CONFIG toggle, not a replay attack, and the IdP's own non-Success StatusCode is the field that says "your
// IdP DECLINED this user" (unassigned app, MFA refused).
//
// The sub-code is recorded ALONGSIDE the coarse code (never instead of it) in the SAME bounded auth-signal
// aggregate the rest of the auth evidence uses, as the closed `sso-sub-*` names in auth-signals.ts. So this
// needs no new storage sink, no new DO route and no new pack section: it is counts keyed by a closed name.
//
// REDACTION: identical discipline to classifySsoFailure. The reason is read TRANSIENTLY to SELECT a member of
// the closed set below and is then DISCARDED. The two MARKS the reject sites now embed (`[oauth:<code>]` and
// `[saml-status:<class>]` / `[saml-bearer:<class>]`) are themselves closed vocabularies chosen at the site
// from a fixed allowlist (oauthErrorMark below is the single gate for the OAuth one), so even the mark cannot
// carry provider prose, an error_description, a tid, an hd domain, a URL or a cert.
// ---------------------------------------------------------------------------------------------------------

// The OAuth 2.0 / OIDC `error` codes we are willing to carry (RFC 6749 s5.2 + RFC 6750). A SPEC vocabulary:
// every member is one of a fixed handful of protocol tokens and carries no tenant, user or endpoint data. A
// provider that answers anything else (a vendor-specific code, or prose) is NOT carried at all.
export const OAUTH_ERROR_CODES = [
  "invalid_client", // the client id/secret was rejected: the EXPIRED-Entra-secret ticket (or a rotated secret the connection was never updated with)
  "invalid_grant", // the authorization code was rejected (already redeemed, expired, or issued to a different redirect_uri)
  "invalid_request", // the token request itself was malformed / missing a required parameter (typically a redirect_uri or PKCE mismatch)
  "unauthorized_client", // the client is not permitted to use this grant type (an app-registration / grant-type misconfiguration)
  "access_denied", // the IdP (or the user) declined the authorization
  "invalid_scope", // a requested scope is not granted to this client (the "no email claim" family, seen at the token endpoint)
  "server_error", // the IdP failed internally: wait / check the IdP's status page, do not touch the connection
  "temporarily_unavailable", // the IdP is throttling or degraded: same remediation as server_error
] as const;
const OAUTH_ERROR_CODE_SET: ReadonlySet<string> = new Set(OAUTH_ERROR_CODES);

/**
 * oauthErrorMark is the SINGLE gate through which a token/authorize error response's `error` field may reach a
 * failure reason. It accepts ONLY an exact member of the closed spec vocabulary above and renders it as the
 * fixed `[oauth:<code>]` mark; ANYTHING else (a vendor code, an error_description, prose, an object, a long
 * string) yields the empty string and is dropped at the site. So the untrusted body can never widen what the
 * reason -- and therefore what classifySsoSubCode can ever select -- carries.
 *
 * @param raw - the `error` field of the provider's error response (untrusted).
 * @returns " [oauth:<code>]" for an allowlisted code, else "".
 */
export function oauthErrorMark(raw: unknown): string {
  return typeof raw === "string" && OAUTH_ERROR_CODE_SET.has(raw) ? ` [oauth:${raw}]` : "";
}

/**
 * oauthErrorMarkFromBody is the reject-site helper: it parses a token/authorize ERROR body (which we have
 * already decided to fail on) purely to pull its `error` field, and returns the allowlisted mark for it. The
 * body is parsed and thrown away inside this function -- the error_description, the AADSTS prose, the trace
 * ids and the correlation ids in it are NEVER returned. A non-JSON, non-object or non-allowlisted body yields
 * "" (no mark), so the failure simply stays coarse rather than carrying anything unclosed.
 *
 * @param bodyText - the raw response body of a FAILED token/authorize exchange (untrusted, discarded).
 * @returns " [oauth:<code>]" for an allowlisted code, else "".
 */
export function oauthErrorMarkFromBody(bodyText: unknown): string {
  if (typeof bodyText !== "string" || bodyText.length === 0 || bodyText.length > 65_536) return "";
  try {
    const j: unknown = JSON.parse(bodyText);
    if (typeof j !== "object" || j === null) return "";
    return oauthErrorMark((j as Record<string, unknown>).error);
  } catch {
    return ""; // a non-JSON error body (a proxy interstitial, an HTML error page) carries no code we can trust
  }
}

// The closed SSO sub-cause vocabulary. Members are DISJOINT from AUTH_SIGNAL_NAMES' other families and from
// SSO_FAIL_CODES; each is recorded as the auth-signal name `sso-sub-<member>`.
export const SSO_SUB_CODES = [
  // --- the provider's own OAuth error code (the spec vocabulary above), read at the token endpoint ---
  "invalid-client", // [oauth:invalid_client]: the EXPIRED / rotated / wrong client secret. Fix the secret, not the connection
  "invalid-grant", // [oauth:invalid_grant]: the code was already redeemed, expired, or bound to a different redirect_uri
  "invalid-request", // [oauth:invalid_request]: a malformed token request (redirect_uri / PKCE mismatch)
  "unauthorized-client", // [oauth:unauthorized_client]: the app registration does not permit this grant
  "access-denied", // [oauth:access_denied]: the IdP or the user declined the authorization
  "invalid-scope", // [oauth:invalid_scope]: a requested scope is not granted to this client
  "idp-server-error", // [oauth:server_error] / [oauth:temporarily_unavailable]: the IdP failed or is throttling. WAIT; do not re-key the connection
  // --- key / JWKS selection (the post-rotation family) ---
  "kid-not-found", // the id_token names a kid the fetched JWKS does not carry: an IdP signing-key rotation our cache/fetch has not caught up with
  "duplicate-kid", // the JWKS carries the SAME kid twice, so NO key can be selected unambiguously and EVERY sign-in on the connection fails
  "jwks-unusable", // the JWKS could not be fetched / was non-200 / was not JSON / carried no usable keys
  "alg-unsupported", // the id_token's alg is not enabled for this connection (or is a type we do not implement)
  // --- discovery / endpoint safety (the proxy-interstitial + SSRF-guard family) ---
  "discovery-refused", // the IdP served discovery but it was unusable (non-200, or a non-JSON captive-portal / proxy interstitial)
  "endpoint-host-mismatch", // an advertised endpoint (or the issuer) failed our issuer-host safety check: an IdP mix-up / SSRF guard, an operator-fixable pin
  // --- token shape ---
  "no-id-token", // the token response succeeded but carried no id_token / access_token at all
  "token-oversize", // the token / response exceeded our size ceiling
  "subject-path-miss", // the verified token carried no usable subject / immutable id at the configured path
  // --- the single-use flow artefacts, split (today all one `replay` code) ---
  "state-missing", // no state record at all (the callback arrived with a state we never minted)
  "state-replayed", // the state record was already consumed: a double-submitted / re-opened callback, not an attack
  "state-expired", // the state record existed but its TTL had passed (a login left open too long)
  "txn-mismatch", // the login-CSRF txn cookie did not match the state record (a forged callback, or a cookie the browser dropped)
  "nonce-mismatch", // the id_token nonce did not match the one minted at /start
  // --- SAML: the IdP's OWN StatusCode (the field that says the IdP DECLINED) ---
  "idp-declined-responder", // urn:...:status:Responder -- the IdP itself failed to process the request
  "idp-declined-requester", // urn:...:status:Requester -- the IdP says OUR AuthnRequest was at fault
  "idp-declined-authnfailed", // urn:...:status:AuthnFailed -- the IdP DECLINED THE USER (unassigned app, MFA refused, blocked account). The commonest "SSO is broken for one user"
  "idp-declined-nopassive", // urn:...:status:NoPassive -- a passive request the IdP could not satisfy silently
  "idp-declined-other", // a non-Success StatusCode outside the four above (still an IdP decline, not our fault)
  // --- SAML: the config-toggle and out-of-scope refusals (distinct from replay / malformed) ---
  "idp-initiated-disallowed", // an IdP-initiated POST (an IdP "tile" launch) at an SP-initiated-only connection. A CONFIG TOGGLE, not a replay attack
  "encrypted-assertion-unsupported", // the IdP is ENCRYPTING assertions and this build is sign-only. A precise, actionable refusal
  "destination-mismatch", // the Response @Destination is not our ACS URL (the SP is pointed at the wrong app / the console origin moved)
  "audience-mismatch", // the assertion Audience is not our entity id (the classic trailing-slash / http-vs-https near miss)
  "nameid-unusable", // the NameID was absent / empty / of an unusable format
  "signature-wrapping", // more than one Assertion, or a signature that does not cover the located Assertion: an XML-Signature-Wrapping refusal (a POSTURE event, not a config fault)
  "assertion-replayed", // the assertion's ID was already consumed (a genuine replay)
  "cert-unusable", // the pinned signing certificate would not parse, is not yet valid, or has expired (the cert-rollover ticket)
  "parser-cap", // the SAMLResponse hit a parser ceiling (bytes / depth / nodes) rather than being syntactically bad
  // --- SAML: the bearer SubjectConfirmation blend, split at the site (one reason today, four causes) ---
  "bearer-recipient-mismatch", // every bearer confirmation named a @Recipient that is not our ACS URL (the wrong-SP / forwarded-assertion case)
  "bearer-inresponseto-mismatch", // a bearer confirmation's @InResponseTo did not match the AuthnRequest we sent
  "bearer-expired", // every bearer confirmation's @NotOnOrAfter was absent, unparseable or already past (clock drift, or a stale POST)
  "bearer-absent", // the Subject carried no usable bearer SubjectConfirmationData at all
  // --- residual ---
  "unclassified", // a failure we could not sub-classify. Recorded DELIBERATELY: a rising unclassified count is itself the signal that this vocabulary has a hole
] as const;
export type SsoSubCode = (typeof SSO_SUB_CODES)[number];

// The marks the reject sites embed, and the closed classes each may carry. Read here, never stored.
const SAML_STATUS_SUB: Record<string, SsoSubCode> = {
  responder: "idp-declined-responder",
  requester: "idp-declined-requester",
  authnfailed: "idp-declined-authnfailed",
  nopassive: "idp-declined-nopassive",
  other: "idp-declined-other",
};
const SAML_BEARER_SUB: Record<string, SsoSubCode> = {
  recipient: "bearer-recipient-mismatch",
  inresponseto: "bearer-inresponseto-mismatch",
  expired: "bearer-expired",
  absent: "bearer-absent",
};
const OAUTH_SUB: Record<string, SsoSubCode> = {
  invalid_client: "invalid-client",
  invalid_grant: "invalid-grant",
  invalid_request: "invalid-request",
  unauthorized_client: "unauthorized-client",
  access_denied: "access-denied",
  invalid_scope: "invalid-scope",
  server_error: "idp-server-error",
  temporarily_unavailable: "idp-server-error",
};

// Ordered [test, sub]. The MARK rules run FIRST (a mark is a site-chosen closed token, so it is the most
// trustworthy evidence in the string and no interpolated tail can out-rank it); the reason-text rules follow,
// each anchored or keyed on wording the engine itself owns.
const SUB_RULES: Array<{ re: RegExp; sub: SsoSubCode }> = [
  // --- key / JWKS ---
  { re: /carries a duplicate kid/, sub: "duplicate-kid" },
  { re: /signing key not found|\bkid\b .*not|no key with kid/, sub: "kid-not-found" },
  { re: /^jwks /, sub: "jwks-unusable" },
  { re: /^unacceptable alg|^alg\b|is not enabled for this connection|no algorithms allowed|alg\/key/, sub: "alg-unsupported" },
  // --- discovery / endpoint safety ---
  { re: /^discovery (endpoint returned|document is not json)/, sub: "discovery-refused" },
  { re: /^discovery |^the connection issuer is not a valid url|host does not match|is not a valid url/, sub: "endpoint-host-mismatch" },
  // --- token shape ---
  { re: /carried no id_token|carried no access_token|token response is not an object/, sub: "no-id-token" },
  { re: /exceeds the maximum size|missing or too large/, sub: "token-oversize" },
  { re: /^the resolved subject is not a usable key|profile carried no|profile id is/, sub: "subject-path-miss" },
  // --- the single-use flow artefacts ---
  { re: /transaction id mismatch|login csrf|browser binding/, sub: "txn-mismatch" },
  { re: /nonce mismatch/, sub: "nonce-mismatch" },
  { re: /already[- ]used|already consumed|used state/, sub: "state-replayed" },
  { re: /state (is )?expired|state has expired/, sub: "state-expired" },
  { re: /state (is )?missing|no state record|unknown state|state connid does not match|invalid connid/, sub: "state-missing" },
  // --- SAML ---
  { re: /encrypted assertions/, sub: "encrypted-assertion-unsupported" },
  { re: /idp-initiated saml response is not permitted/, sub: "idp-initiated-disallowed" },
  { re: /destination does not match/, sub: "destination-mismatch" },
  { re: /audience|aud does not include/, sub: "audience-mismatch" },
  { re: /nameid|subject has no/, sub: "nameid-unusable" },
  { re: /signature-wrapping|more than one saml:assertion|verified node is not/, sub: "signature-wrapping" },
  { re: /assertion (id )?(has been )?(already )?(replayed|seen)|is not permitted to be replayed/, sub: "assertion-replayed" },
  { re: /certificate/, sub: "cert-unusable" },
  { re: /exceeds|too many|too deep|depth|node cap/, sub: "parser-cap" },
];

/**
 * classifySsoSubCode reduces a free-text sign-in failure reason to ONE member of the closed SSO_SUB_CODES set,
 * for the `sso-sub-*` auth-signal counters (G009 / G018). PURE. The reason is read transiently and NEVER
 * returned or stored: only the enum member leaves this function. An unrecognised reason yields "unclassified"
 * (recorded deliberately -- a climbing unclassified count is the signal that this vocabulary has a hole), and
 * it never throws.
 *
 * The MARK rules (`[oauth:...]`, `[saml-status:...]`, `[saml-bearer:...]`) are checked first and matched
 * against fixed maps, so a mark can only ever resolve to a member those maps already name; an interpolated
 * tail (an attacker-chosen issuer, an XML element name, a connId) cannot forge one.
 *
 * @param reason - the free-text failure reason from the callback / ACS (untrusted, discarded).
 * @returns the closed sub-code.
 */
export function classifySsoSubCode(reason: string): SsoSubCode {
  const r = (typeof reason === "string" ? reason : "").toLowerCase();
  const oauth = /\[oauth:([a-z_]+)\]/.exec(r);
  if (oauth !== null) {
    const sub = OAUTH_SUB[oauth[1] ?? ""];
    if (sub !== undefined) return sub;
  }
  const status = /\[saml-status:([a-z]+)\]/.exec(r);
  if (status !== null) {
    const sub = SAML_STATUS_SUB[status[1] ?? ""];
    if (sub !== undefined) return sub;
  }
  const bearer = /\[saml-bearer:([a-z]+)\]/.exec(r);
  if (bearer !== null) {
    const sub = SAML_BEARER_SUB[bearer[1] ?? ""];
    if (sub !== undefined) return sub;
  }
  for (const { re, sub } of SUB_RULES) if (re.test(r)) return sub;
  return "unclassified";
}

/**
 * ssoSubSignalName maps a closed sub-code to its closed auth-signal name (`sso-sub-<code>`), which is the name
 * the bounded auth-signal aggregate stores. Kept here (rather than string-concatenated at the call site) so the
 * ONE place that builds the name is the one place that owns the vocabulary; the DO still drops any name that is
 * not a member of AUTH_SIGNAL_NAMES, which is the redaction boundary.
 *
 * @param sub - the closed sub-code.
 * @returns the closed auth-signal name.
 */
export function ssoSubSignalName(sub: SsoSubCode): string {
  return `sso-sub-${sub}`;
}

// ---- The ROUTER-LOCAL sign-in failures, and the IdP's OWN error code --------------------------------
//
// Every SSO failure the pack carries is classified BY THE DURABLE OBJECT, which means only failures that
// REACH the DO are counted. Four legs never do:
//   - the ACS form / callback query would not parse (a proxy that mangled the cross-origin POST);
//   - the DO round-trip from the ACS / callback / metadata handler faulted (an engine availability fault);
//   - the SP metadata endpoint could not render, so the customer's IdP cannot even IMPORT the connection;
//   - and the IdP's OWN `?error=` code on the callback, the field in which the IdP says WHY it declined.
// These router-local codes cover that gap so an outage in one of these legs is still visible.
//
// REDACTION: the OAuth/OIDC `error` parameter is a value from RFC 6749 / OIDC Core's FIXED registry, but it is
// still an ATTACKER-INFLUENCEABLE query string, so it is never carried as text: idpErrorSignalName maps it
// through a CLOSED set and everything unrecognised coarsens to `other`. error_description (free prose, and the
// one field IdPs put tenant names and email addresses in) is NEVER read at all.

export const IDP_ERROR_CODES = [
  "access_denied", // the IdP (or its user) DECLINED: a conditional-access policy, an MFA refusal, or a user who cancelled. The most common by far, and the one whose remediation is at the IdP
  "invalid_client", // the IdP does not accept this client: a wrong client_id, or -- far more often -- an EXPIRED client secret
  "invalid_request", // the IdP refused the request shape: a redirect_uri that is not registered, a missing/unsupported parameter
  "invalid_scope", // the IdP refused a requested scope (an admin removed the openid/email/profile grant)
  "unauthorized_client", // the client is not permitted to use this grant/flow at the IdP
  "unsupported_response_type", // the IdP does not permit the code flow for this application
  "consent_required", // interaction is required and the IdP was asked not to prompt
  "login_required", // the IdP has no session and was asked not to prompt
  "interaction_required", // the IdP needs an interaction it was not permitted to perform
  "server_error", // the IdP's own 5xx: wait, and check the IdP's status page (nothing to fix on this side)
  "temporarily_unavailable", // the IdP is throttling / degraded
  "other", // residual: an error code outside the registry (a vendor extension). NEVER the raw value
] as const;
const IDP_ERROR_CODE_SET: ReadonlySet<string> = new Set(IDP_ERROR_CODES);

/**
 * idpErrorSignalName maps the IdP's `?error=` parameter to its closed auth-signal name. TOTAL: an unrecognised
 * (or absent, or hostile, or 5,000-character) value coarsens to `sso-idp-error-other`. The input is read ONLY
 * to SELECT a member of the closed set and is never returned or stored, so an attacker-controlled query string
 * cannot inject a key into the bounded aggregate.
 *
 * @param raw - the raw `error` query parameter (untrusted).
 * @returns the closed auth-signal name.
 */
export function idpErrorSignalName(raw: unknown): string {
  const code = typeof raw === "string" && IDP_ERROR_CODE_SET.has(raw) ? raw : "other";
  // The registry spells its codes with underscores (access_denied); the auth-signal vocabulary is kebab-only
  // (a bare closed identifier, enforced by validate-support-auth-signals). Fold the ONE separator, so the
  // stored name stays a bare identifier and no registry value is ever carried verbatim.
  return `sso-idp-error-${code.replace(/_/g, "-")}`;
}

/** The router-local SSO failure legs, none of which can ever reach the DO's classifier. */
export const SSO_EDGE_CODES = [
  "edge-parse", // the ACS form body / callback query would not parse, or carried no assertion at all: the sign-in never became a DO request
  "edge-transport", // the DO round-trip from the ACS / callback handler faulted or answered a non-JSON body: an ENGINE availability fault, not a connection fault
  "edge-metadata-unavailable", // the SP metadata endpoint could not render: the customer's IdP cannot even IMPORT the connection ("our IdP cannot fetch your SP metadata URL")
  "edge-providers-unavailable", // the pre-auth provider list could not be read: EVERY sign-in button disappears from the console
] as const;
export type SsoEdgeCode = (typeof SSO_EDGE_CODES)[number];

/**
 * ssoEdgeSignalName maps a router-local leg to its closed auth-signal name (the `sso-edge-` family, disjoint
 * from `sso-start-`, `sso-sub-` and `sso-idp-error-`).
 *
 * @param code - the closed edge code.
 * @returns the closed auth-signal name.
 */
export function ssoEdgeSignalName(code: SsoEdgeCode): string {
  return `sso-edge-${code.slice("edge-".length)}`;
}
