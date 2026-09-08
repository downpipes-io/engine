// THE PINNED IdP SIGNING-CERTIFICATE HEALTH RECORD (the DATA-LOSS gap in the SAML sign-in path).
//
// THE PROBLEM: "SSO died the day our old IdP cert expired." The replacement certificate was pasted CORRUPT
// during a rollover and then silently skipped for weeks -- because saml/response.ts's cert pre-extraction loop
// OVERWRITES its `parseReason` on every bad PEM and DISCARDS it entirely the moment ANY cert parses (rollover
// is meant to tolerate one bad cert, so a usable one masks a broken one). The connection therefore runs on a
// single cert with no redundancy, nobody is told, and the day that cert lapses every sign-in stops.
//
// Its companions are the same blindness in three other places:
//   - a P-521 (or Ed25519, or RSA-PSS-only) certificate fails EVERY sign-in with a generic import error, and
//     nothing anywhere names the curve -- so a one-line diagnosis ("this build imports P-256/P-384/RSA") is
//     invisible and support hunts a signature bug instead;
//   - an UNREADABLE validity window silently DISABLES the cert-freshness check (dsig.ts enforces the
//     window only when certValidity() returned one: an unreadable window is fail-OPEN by design, correctly --
//     but the fact that it fired is diagnostic gold and was never recorded);
//   - the expiry registry only ever OBSERVES a cert whose notAfter parsed, so a connection whose certs cannot
//     be read is never enrolled for an expiry warning at all: status.expiryWarnings counts rows that were
//     never created, and reads a doomed connection as a healthy one.
//
// THE RECORD: ONE bounded, AGGREGATED health record. It is deliberately NOT keyed by connection: a connId is
// the operator's own slug ("okta", "entra-prod") and the pack does not carry connIds anywhere (ssoFailuresByKind
// is keyed by PROTOCOL for exactly this reason). Hashing it would be worse, not better -- a short guessable slug
// under an 8-hex digest is not a redaction. Every question in the ticket is answerable without it: "is a pinned
// cert unparseable?", "is a cert about to lapse?", "is an unsupported curve in play?", "is the freshness check
// silently off?" The console names the connection locally; the pack carries the FACT.
//
// NO-CUSTODY (binding): counts, clamped integers, booleans, a closed curve class, and notAfter -- a timestamp
// from a PUBLIC X.509 certificate the IdP publishes. NEVER the PEM, the DER, the SPKI bytes, the subject, the
// issuer, the serial, the connId, the operator's label, or a parse-reason string. The parse reason is read by
// NOBODY here: the caller passes only the already-computed booleans and counts.
//
// This is a LEAF module (it imports NOTHING), for the same reason diag-records.ts and sso-failure-class.ts are:
// the closed vocabulary is shared by the SAML verify path (a pure module), the DO recorder and the pack
// projection, and a shared import would close a cycle through the DO base.

// ---------------------------------------------------------------------------------------------------------
// The closed KEY CLASS vocabulary.
//
// This is the "why does every sign-in fail with a generic import error" answer. The engine's dsig verifier
// imports ECDSA P-256 / P-384 and RSA; anything else is refused by crypto.subtle.importKey with a message that
// says nothing useful and is (correctly) never carried. The class is derived from the SPKI's own algorithm OID
// bytes -- a FIXED, PUBLIC, standards-registered identifier, not a customer value.
// ---------------------------------------------------------------------------------------------------------

export const IDP_CURVE_CLASSES = [
  "rsa", // rsaEncryption: supported
  "p256", // prime256v1 / secp256r1: supported (the overwhelming default for SAML signing)
  "p384", // secp384r1: supported
  "p521", // secp521r1: NOT imported by this build -- every sign-in on this connection fails, and this is the only place that says so
  "unsupported", // an EC curve or a key algorithm outside the four above (Ed25519, an unknown OID): same consequence, same diagnosis
] as const;
export type IdpCurveClass = (typeof IDP_CURVE_CLASSES)[number];
const IDP_CURVE_CLASS_SET: ReadonlySet<string> = new Set(IDP_CURVE_CLASSES);

// The algorithm OIDs, as their DER-encoded OBJECT IDENTIFIER TLV byte strings (tag 0x06, length, content). We
// match on the encoded TLV rather than the bare content so a length-prefix coincidence inside an unrelated
// field cannot produce a false positive. All five are public constants from the X.509 / SEC / PKCS registries.
const OID_RSA_ENCRYPTION = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]; // 1.2.840.113549.1.1.1
const OID_EC_PUBLIC_KEY = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]; // 1.2.840.10045.2.1
const OID_PRIME256V1 = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]; // 1.2.840.10045.3.1.7
const OID_SECP384R1 = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]; // 1.3.132.0.34
const OID_SECP521R1 = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]; // 1.3.132.0.35

// containsBytes is a bounded forward scan for a fixed byte pattern. The SPKI is a few hundred bytes and the
// patterns are 7-11 bytes, so this is trivially bounded; it reads the DER and returns a BOOLEAN.
function containsBytes(hay: Uint8Array, needle: number[]): boolean {
  const n = needle.length;
  if (n === 0 || hay.length < n) return false;
  outer: for (let i = 0; i + n <= hay.length; i++) {
    for (let j = 0; j < n; j++) if (hay[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
}

/**
 * classifyCertKeyClass reduces a certificate's SubjectPublicKeyInfo DER to ONE member of the closed
 * IDP_CURVE_CLASSES set, by matching the PUBLIC, standards-registered algorithm OIDs its header carries. PURE,
 * total, and never throwing.
 *
 * It reads the SPKI bytes ONLY to select an enum member and RETURNS that member: no byte of the key, the
 * subject, the issuer or the serial ever leaves this function. (The SPKI is public key material in a public
 * certificate in any case -- but the discipline is the discipline.)
 *
 * @param spki - the certificate's SubjectPublicKeyInfo DER (as pemToSpki returns it).
 * @returns the closed key class; "unsupported" for anything outside the four the engine imports.
 */
export function classifyCertKeyClass(spki: Uint8Array): IdpCurveClass {
  if (containsBytes(spki, OID_RSA_ENCRYPTION)) return "rsa";
  if (containsBytes(spki, OID_EC_PUBLIC_KEY)) {
    // An EC key's named curve rides as the algorithm PARAMETERS OID, immediately after the id-ecPublicKey OID.
    if (containsBytes(spki, OID_PRIME256V1)) return "p256";
    if (containsBytes(spki, OID_SECP384R1)) return "p384";
    if (containsBytes(spki, OID_SECP521R1)) return "p521";
    return "unsupported"; // an EC curve this build does not import (secp256k1, brainpool, ...)
  }
  return "unsupported"; // Ed25519, RSA-PSS-only, or an OID outside the registry we accept
}

// ---------------------------------------------------------------------------------------------------------
// The OBSERVATION: what the SAML verify path computed and used to throw away.
// ---------------------------------------------------------------------------------------------------------

/**
 * One cert-health observation, produced by the SAML verify path's cert pre-extraction (saml/response.ts) at
 * every sign-in, and by the connection-save probe. Every field is already a count, a boolean or a closed class
 * at the point it is constructed: no reason string, no PEM and no connId is ever passed in, so none can leak.
 */
export interface IdpCertObservation {
  readonly certCount: number; // how many certificates are pinned on the connection
  readonly parseableCount: number; // how many of them yielded an SPKI (the rest are SILENTLY SKIPPED today)
  readonly windowReadableCount: number; // how many of the parseable ones yielded a readable notBefore..notAfter
  readonly curves: readonly IdpCurveClass[]; // the closed key class of each PARSEABLE cert
  readonly nearestNotAfter: number | null; // the SOONEST expiry among the parseable certs (epoch ms), or null if no window was readable
  readonly windowUnenforced: boolean; // at least one usable cert has NO readable window, so the IDP-4 freshness check ran DISARMED for it
  readonly noUsableCert: boolean; // EVERY pinned cert failed to parse: the connection cannot verify a single sign-in
}

// ---------------------------------------------------------------------------------------------------------
// The ISOLATE-LOCAL LEDGER.
//
// verifySamlResponse is a PURE module (no env, no DO stub, no network -- deliberately: it is the security
// core, and giving it a storage handle would be a mistake). So it cannot write the observation itself. It
// NOTES the observation here, in an isolate-local slot, and the DO's ACS wrapper -- which already calls
// recordSsoFail on the same result -- DRAINS it one line later and folds it into storage.
//
// Exactly the idiom format/integrity-fault-ledger.ts uses, and for exactly the same reason.
// ---------------------------------------------------------------------------------------------------------

let pendingObservation: IdpCertObservation | null = null;

/**
 * noteIdpCertObservation records the cert-health observation of ONE sign-in in the isolate-local slot. Called
 * by the SAML verify path's cert pre-extraction. Last write wins (an isolate serving two ACS posts back to
 * back records the second; both are folded into the same cumulative counters by the DO, and the SNAPSHOT half
 * of the record is a last-observation view by design).
 *
 * @param obs - the observation (counts, booleans and closed classes only).
 */
export function noteIdpCertObservation(obs: IdpCertObservation): void {
  pendingObservation = obs;
}

/**
 * drainIdpCertObservation takes the pending observation and clears the slot, so an ACS post that verified no
 * signature at all (a malformed envelope, a replayed RelayState) cannot re-report the PREVIOUS sign-in's certs.
 *
 * @returns the observation, or null when the verify path did not reach its cert pre-extraction.
 */
export function drainIdpCertObservation(): IdpCertObservation | null {
  const o = pendingObservation;
  pendingObservation = null;
  return o;
}

/**
 * resetIdpCertLedger clears the slot. Test-only (a fresh isolate starts empty); it exists so one validator case
 * cannot leak an observation into the next.
 */
export function resetIdpCertLedger(): void {
  pendingObservation = null;
}

// ---------------------------------------------------------------------------------------------------------
// The BOUNDED DO RECORD + its single redaction chokepoint.
// ---------------------------------------------------------------------------------------------------------

/**
 * The standing pinned-certificate health record. The CUMULATIVE counters are the fault history (they are what
 * says "a cert has been failing to parse for weeks"); the SNAPSHOT fields are the most recent observation (they
 * are what says "and here is what the connection looks like right now").
 */
export interface IdpCertHealth {
  // ---- the last observation (the "what does it look like now" half) ----
  readonly certCount: number;
  readonly parseableCount: number;
  readonly windowReadableCount: number;
  readonly curves: Record<string, number>; // closed curve class -> how many certs of that class were seen in the LAST observation
  readonly nearestNotAfter?: number; // the soonest expiry among usable certs (epoch ms); absent when no window was readable
  readonly expiryObserved: boolean; // a notAfter WAS readable, so the expiry registry can enrol this connection. FALSE is the silent "no expiry warning will ever fire" state
  // ---- the cumulative counters (the "how long has this been wrong" half) ----
  readonly unparseableCertsTotal: number; // cumulative certs that would NOT parse: THE corrupt-rollover-paste signal
  readonly windowUnreadableTotal: number; // cumulative certs whose validity window could not be read
  readonly windowUnenforcedVerifies: number; // cumulative sign-ins whose signature check ran with the IDP-4 freshness window DISARMED
  readonly noUsableCertRefusals: number; // cumulative sign-ins refused because NOT ONE pinned cert parsed: SSO is dead and this is the count of the outage
  readonly unsupportedCurveSeen: number; // cumulative certs whose key class this build cannot import (the P-521 fleet)
  readonly observations: number; // how many sign-ins/probes have refreshed this record at all
  readonly lastAt: number; // epoch ms of the most recent observation
}

export const IDP_CERT_HEALTH_KEY = "diag:idpcerthealth";
const IDP_CERT_COUNT_CAP = 1_000_000;
// A connection may pin at most 8 certs (idpconn-validators.ts's ceiling); the clamp is deliberately generous
// so a validator change cannot silently truncate the record, and tight enough to bound it.
const IDP_CERT_MAX = 64;

// intClamp is the numeric gate: a NaN, an Infinity, a negative or a non-number is DROPPED to 0.
function intClamp(n: unknown, cap: number): number {
  if (typeof n !== "number" || !Number.isFinite(n) || n < 0) return 0;
  return Math.min(cap, Math.floor(n));
}

/**
 * applyIdpCertHealth folds ONE observation into the standing record. PURE, and the SINGLE REDACTION CHOKEPOINT
 * for this aggregate: every count is re-clamped to a bounded non-negative integer DO-side, every curve class is
 * re-checked against the closed set (an out-of-vocabulary class is DROPPED, so the key space is exactly
 * IDP_CURVE_CLASSES), nearestNotAfter is accepted only as a finite positive integer, and every other field is
 * coerced to a boolean. NOTHING else on the posted body is read -- so a PEM, an SPKI, a subject DN, a connId, a
 * parse-reason string or an operator label structurally cannot enter the record even if a future call site were
 * to post one.
 *
 * @param prior - the stored record, if any.
 * @param obs - the posted observation (untrusted).
 * @param now - the DO clock (injected, so the validator is deterministic).
 * @returns the new record.
 */
export function applyIdpCertHealth(prior: IdpCertHealth | undefined, obs: unknown, now: number): IdpCertHealth {
  const base: IdpCertHealth = prior ?? {
    certCount: 0,
    parseableCount: 0,
    windowReadableCount: 0,
    curves: {},
    expiryObserved: false,
    unparseableCertsTotal: 0,
    windowUnreadableTotal: 0,
    windowUnenforcedVerifies: 0,
    noUsableCertRefusals: 0,
    unsupportedCurveSeen: 0,
    observations: 0,
    lastAt: 0,
  };
  if (typeof obs !== "object" || obs === null || Array.isArray(obs)) return base;
  const o = obs as Record<string, unknown>;

  const certCount = intClamp(o.certCount, IDP_CERT_MAX);
  const parseableCount = Math.min(certCount, intClamp(o.parseableCount, IDP_CERT_MAX));
  const windowReadableCount = Math.min(parseableCount, intClamp(o.windowReadableCount, IDP_CERT_MAX));

  // The curve tally of THIS observation. An out-of-vocabulary class is DROPPED (defence in depth: no caller can
  // inject a key), and the list is capped, so a hostile body cannot grow the record.
  const curves: Record<string, number> = {};
  let unsupportedThisObs = 0;
  for (const raw of (Array.isArray(o.curves) ? o.curves : []).slice(0, IDP_CERT_MAX)) {
    if (typeof raw !== "string" || !IDP_CURVE_CLASS_SET.has(raw)) continue;
    curves[raw] = (curves[raw] ?? 0) + 1;
    if (raw === "p521" || raw === "unsupported") unsupportedThisObs++;
  }

  const na = typeof o.nearestNotAfter === "number" && Number.isFinite(o.nearestNotAfter) && o.nearestNotAfter > 0 ? Math.floor(o.nearestNotAfter) : null;
  const unparseableThisObs = certCount - parseableCount;
  const windowUnreadableThisObs = parseableCount - windowReadableCount;

  return {
    certCount,
    parseableCount,
    windowReadableCount,
    curves,
    ...(na !== null ? { nearestNotAfter: na } : {}),
    // expiryObserved is the fact status.expiryWarnings cannot express: a connection whose certs have no
    // readable notAfter is NEVER enrolled in the expiry registry, so no warning can ever fire for it.
    expiryObserved: na !== null,
    unparseableCertsTotal: Math.min(IDP_CERT_COUNT_CAP, base.unparseableCertsTotal + unparseableThisObs),
    windowUnreadableTotal: Math.min(IDP_CERT_COUNT_CAP, base.windowUnreadableTotal + windowUnreadableThisObs),
    windowUnenforcedVerifies: Math.min(IDP_CERT_COUNT_CAP, base.windowUnenforcedVerifies + (o.windowUnenforced === true ? 1 : 0)),
    noUsableCertRefusals: Math.min(IDP_CERT_COUNT_CAP, base.noUsableCertRefusals + (o.noUsableCert === true ? 1 : 0)),
    unsupportedCurveSeen: Math.min(IDP_CERT_COUNT_CAP, base.unsupportedCurveSeen + unsupportedThisObs),
    observations: Math.min(IDP_CERT_COUNT_CAP, base.observations + 1),
    lastAt: now,
  };
}
