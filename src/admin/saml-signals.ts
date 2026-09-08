// G316 / G276 / G203: THE SAML PIPELINE'S ISOLATE-LOCAL SIGNAL LEDGER.
//
// THE PROBLEM: the whole SAML pipeline (parser.ts, c14n.ts, dsig.ts, assertion.ts, response.ts,
// authn-request.ts) is PURE by design -- no env, no DO stub, no network. That is exactly right for the
// security core, and it is why none of it can record anything. So three families of evidence die at the
// call site:
//
//   G316 (the SOC question): "was last week's SSO failure spike an ATTACK?" XML-Signature-Wrapping (a second
//     top-level element, a second Assertion, a duplicate ID the Reference resolves to twice), a DTD/XXE probe,
//     an attribute-pollution attempt and a void-canon shape ALL land in the same `malformed` / `signature`
//     counters as a pretty-printer glitch or a cert rotation. The evidence needed to answer was discarded at
//     classification. parser.ts's second-root refusal is the sharpest case: its reason explicitly NAMES
//     signature-wrapping, and the classifier's anchored `^samlresponse ` prefix rule routes it to `malformed`.
//     These signals are recorded AT THE SITE, which KNOWS the shape, so no text classification is involved and
//     no ordering rule can misroute them.
//
//   G276 (the silent degradation of a SUCCESSFUL sign-in): a misspelt verified-flag attribute silently drops
//     the asserted email (the sign-in SUCCEEDS, so no failure record exists anywhere and the customer's
//     email-bound role never applies); an unparseable SessionNotOnOrAfter is silently read as "no bound", so
//     the native session outlives the IdP session.
//
//   G203 (the start path): a sign-in that dies while BUILDING the AuthnRequest never reaches the ACS, so it
//     never reaches recordSsoFail at all -- the pack shows ZERO SSO failures while no user can even reach the
//     IdP, and support rules SSO out on a clean aggregate.
//
// THE MECHANISM: the pure module NOTES a CLOSED auth-signal name in an isolate-local set; the DO wrapper (which
// already calls recordSsoFail on the same result) DRAINS it and folds each name into the bounded auth-signal
// aggregate the pack already carries. The same idiom as format/integrity-fault-ledger.ts and the G053 cert
// ledger, and for the same reason.
//
// NO-CUSTODY (binding): the ONLY thing that ever crosses this boundary is a member of the closed name set
// below. The hostile document, the XML element names, the attacker-chosen entity names, the attribute values,
// the asserted email, the SessionNotOnOrAfter text and the SSO URL are NEVER passed in and structurally cannot
// be: noteSamlSignal's parameter type is the union, and the DO drops any name outside AUTH_SIGNAL_NAMES.
//
// This is a LEAF module (it imports NOTHING), for the same reason diag-records.ts is.

// ---------------------------------------------------------------------------------------------------------
// The closed SAML signal vocabulary. Every member is spread into AUTH_SIGNAL_NAMES (auth-signals.ts), so the
// recorder, the DO's redaction gate and the pack projection all read ONE list and cannot drift apart.
// ---------------------------------------------------------------------------------------------------------

// G316: the ATTACK SHAPES. Each is recorded at the refusal site that KNOWS the shape -- never inferred from a
// reason string -- so an attacker-chosen element name can never steer its own classification. A non-zero count
// here beside a spike in `signature` / `malformed` is the difference between "your IdP changed its formatter"
// and "someone is probing your SP", which is the question the SOC actually asks.
export const SAML_ATTACK_SHAPES = [
  "saml-shape-xsw-multi-root", // a SECOND top-level element after the Response (the classic wrapping envelope). parser.ts's own reason names signature-wrapping and the coarse classifier files it under `malformed`: this is the fix
  "saml-shape-xsw-multi-assertion", // the Response carried MORE THAN ONE saml:Assertion: the attacker's assertion rides beside the signed one
  "saml-shape-xsw-duplicate-id", // the ds:Reference URI resolved to MORE THAN ONE element: the duplicate-ID wrapping vector, refused inside dsig
  "saml-shape-xsw-multi-signature", // more than one ds:Signature (multi-signature confusion), or more than one Reference in a SignedInfo
  "saml-shape-attr-pollution", // the same Attribute @Name was asserted MORE THAN ONCE: an attempt to have the SP read a different value than the one the IdP intended (a groups/email pollution probe)
  "saml-shape-dtd-entity", // a DOCTYPE or an ENTITY declaration was present: an XXE / billion-laughs probe. There is NO benign reason for either in a SAMLResponse
  "saml-shape-void-canon", // canonicalisation produced EMPTY output for a non-empty element: a hostile shape that reached the digest layer's pre-image
  "saml-shape-verified-wrong-target", // a signature VERIFIED but over the WRONG NODE (the verified element is not the assertion we would consume). Previously swallowed entirely -- and it is the single most alarming shape in the list
  "saml-shape-parser-cap", // the SAMLResponse hit a parser ceiling (bytes, depth, node count) rather than being syntactically bad: a resource-exhaustion probe, or a genuinely enormous assertion
] as const;
export type SamlAttackShape = (typeof SAML_ATTACK_SHAPES)[number];

// G276: the SILENT DEGRADATIONS of a sign-in that SUCCEEDED. No failure record exists for any of these today
// precisely BECAUSE the sign-in worked -- which is what makes them invisible and what makes the tickets
// ("my email-bound role never applies after SSO", "our sessions outlive the IdP's") undiagnosable.
export const SAML_DEGRADE_SIGNALS = [
  "sso-session-cap-dropped", // AuthnStatement/@SessionNotOnOrAfter was PRESENT and did not parse, so it was read as "no bound": the native session now OUTLIVES the IdP session (a security regression that reports success)
  "sso-email-untrusted-flag-absent", // require-flag policy: the configured verified-flag Attribute was NOT ASSERTED AT ALL, so a perfectly good email was dropped and the principal minted subject-only. Nine times in ten this is a MISSPELT attribute name in the connection: the sign-in works and the email-bound role never applies
  "sso-email-untrusted-flag-false", // require-flag policy: the flag WAS asserted and was FALSY. The IdP is genuinely telling us the address is unverified -- a real posture signal, and the OPPOSITE diagnosis from the one above
] as const;
export type SamlDegradeSignal = (typeof SAML_DEGRADE_SIGNALS)[number];

// G203: the START path. recordSsoFail is written only by the ACS (callback) wrapper, so a sign-in that dies
// while building the AuthnRequest is invisible: "the sign-in button for our SAML connection dead-ends with a
// 500" while ssoFailures reads zero. sso-start-compression-failed already exists in the auth-signal vocabulary
// (it was declared and never wired -- the exact failure mode this campaign exists to end); the URL class is new.
export const SAML_START_SIGNALS = [
  "sso-start-saml-url-invalid", // the connection's stored idpSsoUrl is not a usable URL, so no redirect can be built AT ALL: every sign-in on this connection 500s before the user ever reaches the IdP
] as const;
export type SamlStartSignal = (typeof SAML_START_SIGNALS)[number];

/** The union every noteSamlSignal caller must pass. A free string cannot be passed: that is the redaction gate. */
export type SamlSignalName = SamlAttackShape | SamlDegradeSignal | SamlStartSignal | "sso-start-compression-failed";

// ---------------------------------------------------------------------------------------------------------
// The isolate-local ledger.
// ---------------------------------------------------------------------------------------------------------

// A SET, not a list: one hostile document that trips the same gate a thousand times must not be able to make
// the DO wrapper issue a thousand storage writes. The AGGREGATE counts events (once per sign-in attempt), which
// is the granularity every question here is asked at.
const pending = new Set<SamlSignalName>();

/**
 * noteSamlSignal records ONE closed signal in the isolate-local ledger. Called by the (pure) SAML pipeline at
 * the site that KNOWS the shape. The parameter is the closed union, so no free text can be passed.
 *
 * @param name - the closed signal name.
 */
export function noteSamlSignal(name: SamlSignalName): void {
  pending.add(name);
}

/**
 * drainSamlSignals takes the pending signals and clears the ledger, so one sign-in's shapes can never be
 * re-attributed to the next.
 *
 * @returns the closed names noted since the last drain (deduped, bounded by the vocabulary).
 */
export function drainSamlSignals(): SamlSignalName[] {
  const out = [...pending];
  pending.clear();
  return out;
}

/** resetSamlSignalLedger clears the ledger. Test-only, so one validator case cannot leak into the next. */
export function resetSamlSignalLedger(): void {
  pending.clear();
}
