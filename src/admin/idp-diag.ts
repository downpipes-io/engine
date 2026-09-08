// THE IdP SETUP-TIME EVIDENCE (the "we tried to add Okta SSO and it never saves" problem).
//
// THE GAP: everything the operator learns while WIRING an IdP connection evaporates with the browser tab. The
// "test connection" probe (idp-test*.ts) renders a rich structured result to the console and persists NOTHING;
// the pure validators (idpconn-validators.ts) refuse a proposal with a 400 before any write, so a dozen distinct
// refusals ("the issuer is not https", "no signing certificate", "private_key_jwt is not wired") leave no trace
// at all. Remotely, support sees an IdP that was never configured and cannot tell an operator who never tried
// from one who has been fighting a proxy interstitial for two days. Worse, the probe's BARE CATCH reports an
// ENGINE BUG ("The connection test could not be completed due to an unexpected error") in the same shape as a
// customer misconfiguration, so our own defects read as their mistakes.
//
// THE RECORD: closed COUNTS in the bounded auth-signal aggregate (auth-signals.ts) -- `idp-test-<failClass>` and
// `idp-validation-refused-<class>`. No per-connection row, because a per-connection key would be the operator's
// own connId slug, which the pack deliberately does not carry; the fail CLASS is what a remote diagnosis needs
// ("their JWKS fetch has been failing for two days" / "eleven probes died on a non-JSON body: they are behind a
// captive portal") and it is bounded by these sets.
//
// NO-CUSTODY (binding): the probe's `detail` strings INTERPOLATE the submitted URL, the discovery issuer, the
// parse reason and the cert count, and a validator's reason interpolates the offending field value. Neither is
// ever recorded. Both classifiers read the text TRANSIENTLY, ONLY to select a member of a closed set below, and
// RETURN that member; the text is discarded inside the classifier. The check ids are our OWN fixed product
// vocabulary (the probe's own headings), never customer data.
//
// This is a LEAF module (it imports nothing) for the same reason diag-records.ts is: the closed vocabulary must
// be shared by the probe, the router recorder and the pack projection without dragging any of their graphs into
// the others.

// The probe's fixed check headings (its own product vocabulary). An id outside this set is DROPPED.
export const IDP_TEST_CHECK_IDS = [
  "Issuer",
  "Discovery document",
  "Discovery endpoints",
  "Explicit endpoints",
  "Signing keys (JWKS)",
  "IdP entityID",
  "SingleSignOnService URL",
  "Signing certificate",
  "IdP metadata XML",
  "Connection kind",
  "Live exchange",
  "connection exists",
  "Test connection", // the bare-catch check: an ENGINE fault, not a customer misconfiguration (see internal-error)
] as const;
export type IdpTestCheckId = (typeof IDP_TEST_CHECK_IDS)[number];
const IDP_TEST_CHECK_ID_SET: ReadonlySet<string> = new Set(IDP_TEST_CHECK_IDS);

// The closed fail categories. Each is a DIFFERENT remediation, which is the whole reason for the split.
export const IDP_TEST_FAIL_CLASSES = [
  "not-set", // a required field is simply empty (the operator has not finished): NOT a fault, and it must not be counted as one
  "unsafe-url", // the URL failed the engine's SSRF / https / internal-host screen: an operator-fixable pin, and never an outbound fetch
  "unreachable", // the fetch did not complete (DNS, egress, TLS, connection refused): the IdP host is not reachable FROM the engine
  "timeout", // the fetch was still running at the probe's time bound: a slow or black-holed IdP
  "non-200", // the endpoint ANSWERED but with a non-200: the host is up and is refusing us (a wrong issuer path, an auth-gated metadata URL)
  "non-json", // the endpoint answered 200 with a body that is not JSON / not an object: the classic corporate PROXY or captive-portal interstitial standing in front of the IdP
  "issuer-mismatch", // discovery resolved but its published issuer is not the configured one: every token would be rejected at sign-in (the check that saves the lockout)
  "no-usable-keys", // the JWKS fetched but carried no key this build can use: sign-in cannot verify a single token
  "metadata-unusable", // the pasted SAML metadata XML did not parse, or advertises no entityID / SSO endpoint / signing cert
  "cert-unparseable", // no pasted PEM parsed as an X.509 certificate (a partial paste, missing BEGIN/END lines)
  "cert-out-of-window", // certificates parsed but NONE is currently valid (expired, or a pre-pinned rollover cert that is not yet valid): SSO is or will be dead
  "cert-expiring", // a valid cert is in use but the soonest expiry is near: the pack's advance warning of the next SSO outage
  "oauth2-untestable", // an OAuth2 (GitHub-class) connection has no discovery/JWKS to probe read-only: an HONEST limit of the probe, not a fault
  "kind-unknown", // the proposal carried no recognised connection kind
  "connection-absent", // /idp/test-saved named a connId that is not stored
  "internal-error", // the probe's own BARE CATCH fired: an ENGINE DEFECT. Its own class so our bugs stop reading as the customer's misconfiguration
  "other", // residual: a failed check we could not categorise (a rising count says this vocabulary has a hole)
] as const;
export type IdpTestFailClass = (typeof IDP_TEST_FAIL_CLASSES)[number];

// The closed classes of a PRE-WRITE validator refusal (idpconn-validators.ts / oidc-store.ts / oidc-presets.ts).
// These 400 before any storage write, so the connection never exists and nothing else records them.
export const IDP_VALIDATION_CLASSES = [
  "id-shape", // the connection id / label failed its shape gate
  "url-unsafe", // an issuer / endpoint is not an https URL, or is an internal-host / SSRF-screened target
  "cert-invalid", // the pinned SAML signing cert set was empty, over the 8-cert ceiling, or held a PEM that will not parse
  "secret-mode-unsupported", // the requested client-secret custody mode is not wired in this build (secrets-store / private_key_jwt)
  "field-missing", // a required field for the chosen preset / kind was not supplied
  "duplicate-id", // a connection with this id already exists
  "other", // residual
] as const;
export type IdpValidationClass = (typeof IDP_VALIDATION_CLASSES)[number];

/**
 * idpTestSignalName / idpValidationSignalName build the CLOSED auth-signal names from the classes above. Kept
 * here (not concatenated at the call site) so the one module that owns the vocabulary is the one that owns the
 * names; the DO independently drops any name outside AUTH_SIGNAL_NAMES, which is the redaction boundary.
 *
 * @param cls - the closed class.
 * @returns the closed auth-signal name.
 */
export function idpTestSignalName(cls: IdpTestFailClass): string {
  return `idp-test-${cls}`;
}
export function idpValidationSignalName(cls: IdpValidationClass): string {
  return `idp-validation-refused-${cls}`;
}

// Ordered [test, class], run against the LOWER-CASED detail. First match wins. Every phrase matched here is one
// the ENGINE ITSELF writes (idp-test-oidc.ts / idp-test-saml.ts / idp-test-shared.ts); the interpolated tails in
// those details (a URL, an issuer, a parse reason) are never matched on and never leave this module.
const DETAIL_RULES: Array<{ re: RegExp; cls: IdpTestFailClass }> = [
  { re: /is not set|no pinned signing certificate|no idp entityid is set|no idp sso url is set|missing its `issuer` field/, cls: "not-set" },
  { re: /not safe to fetch|not a usable https endpoint/, cls: "unsafe-url" },
  { re: /timed out|timeout/, cls: "timeout" },
  { re: /could not fetch/, cls: "unreachable" },
  { re: /returned http|expected 200/, cls: "non-200" },
  { re: /did not return json|is not a json object/, cls: "non-json" },
  { re: /does not match the configured issuer/, cls: "issuer-mismatch" },
  { re: /no usable|carries no|no signing keys|empty jwks/, cls: "no-usable-keys" },
  { re: /did not parse as an x\.509|none of the .* certificate\(s\) parsed/, cls: "cert-unparseable" },
  { re: /none is currently within its validity window/, cls: "cert-out-of-window" },
  { re: /expires in about/, cls: "cert-expiring" },
  { re: /metadata xml did not parse|metadata is missing/, cls: "metadata-unusable" },
  { re: /providers carry no discovery or jwks/, cls: "oauth2-untestable" },
  { re: /unknown connection kind/, cls: "kind-unknown" },
  { re: /no stored connection with id/, cls: "connection-absent" },
  { re: /unexpected error/, cls: "internal-error" },
];

// The check id alone decides the class when the detail does not (a heading is our own fixed vocabulary, so it is
// the safest fallback of the two).
const CHECK_FALLBACK: Partial<Record<IdpTestCheckId, IdpTestFailClass>> = {
  "Test connection": "internal-error",
  "Connection kind": "kind-unknown",
  "connection exists": "connection-absent",
  "Signing certificate": "cert-unparseable",
  "IdP metadata XML": "metadata-unusable",
  "Signing keys (JWKS)": "no-usable-keys",
};

/**
 * classifyIdpTestFailure reduces a "test connection" RESULT to the closed {checkId, failClass} of its FIRST
 * failing check (or a lone cert-expiring warning, which is the pack's advance warning of the next SSO outage).
 * PURE, and the single redaction chokepoint for the probe: the check `detail` -- which interpolates the
 * submitted URL, the discovery issuer, the pasted metadata's parse reason -- is read TRANSIENTLY to select a
 * member of IDP_TEST_FAIL_CLASSES and is then DISCARDED. Only the closed heading and the closed class are ever
 * returned. Returns null when the probe passed with nothing worth recording. Never throws.
 *
 * @param result - the probe result (untrusted shape: it is re-read from a JSON round trip in some paths).
 * @returns the closed {checkId, failClass}, or null when there is nothing to record.
 */
export function classifyIdpTestFailure(result: unknown): { checkId: IdpTestCheckId; failClass: IdpTestFailClass } | null {
  const checks = (result as { checks?: unknown } | null)?.checks;
  if (!Array.isArray(checks)) return null;
  // A "fail" outranks a "warn": a failed check is the reason the connection does not work, a warn is advisory.
  for (const status of ["fail", "warn"] as const) {
    for (const raw of checks) {
      const c = raw as { name?: unknown; status?: unknown; detail?: unknown };
      if (c.status !== status) continue;
      const name = typeof c.name === "string" ? c.name : "";
      if (!IDP_TEST_CHECK_ID_SET.has(name)) continue; // defence in depth: never a caller-injected heading
      const checkId = name as IdpTestCheckId;
      const detail = (typeof c.detail === "string" ? c.detail : "").toLowerCase();
      for (const { re, cls } of DETAIL_RULES) if (re.test(detail)) return { checkId, failClass: cls };
      const fallback = CHECK_FALLBACK[checkId];
      // A bare "warn" we cannot name is advisory noise, not evidence: only a FAIL falls through to "other".
      if (fallback !== undefined) return { checkId, failClass: fallback };
      if (status === "fail") return { checkId, failClass: "other" };
    }
  }
  return null;
}

// Ordered [test, class] for a PRE-WRITE validator refusal reason. Same discipline: the reason interpolates the
// operator's own field values, so it is read transiently and only the class is returned.
const VALIDATION_RULES: Array<{ re: RegExp; cls: IdpValidationClass }> = [
  { re: /private_key_jwt|secrets[- ]store|unsupported secret mode|secret mode/, cls: "secret-mode-unsupported" },
  { re: /certificate|\bpem\b/, cls: "cert-invalid" },
  { re: /https|is not a valid url|internal host|not a usable url|loopback|private/, cls: "url-unsafe" },
  { re: /already exists|duplicate/, cls: "duplicate-id" },
  { re: /must be 1 to|invalid connid|id must|label must|must match/, cls: "id-shape" },
  { re: /required|provide the required|is missing|must be set|unknown preset/, cls: "field-missing" },
];

/**
 * classifyIdpValidationRefusal reduces a pre-write connection-validation refusal reason to ONE member of the
 * closed IDP_VALIDATION_CLASSES set. PURE. The reason interpolates the operator's submitted values (an issuer
 * URL, a preset id, a connId), so it is read TRANSIENTLY here and DISCARDED: only the class leaves. Never throws;
 * an unrecognised reason yields "other".
 *
 * @param reason - the refusal reason from the validator (untrusted, discarded).
 * @returns the closed class.
 */
export function classifyIdpValidationRefusal(reason: unknown): IdpValidationClass {
  const r = (typeof reason === "string" ? reason : "").toLowerCase();
  for (const { re, cls } of VALIDATION_RULES) if (re.test(r)) return cls;
  return "other";
}
