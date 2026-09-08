// SAML assertion CONSUMPTION: turn an ALREADY-signature-verified <saml:Assertion> element into a stable
// principal, or a typed rejection. This is the last gate of the native SAML Service Provider's ACS pipeline
// and it is the place every SAML profile rule that is NOT a signature rule is enforced (Status is the one
// exception, see the caller obligations below). It is PURE: it does NO fetch, NO crypto, NO Durable Object
// access, NO clock read. It only walks the verified tree and compares decoded text against the pinned
// connection config and the injected context. Everything time/identity/transport related is INJECTED so the
// validator can drive every branch with a fixed clock and hand-built trees.
//
// ---- WHAT THE CALLER MUST HAVE DONE BEFORE CALLING (caller obligations) ----
// This function consumes claims ONLY from the verified Assertion. Several SAML rules live on the RESPONSE
// envelope (samlp:Response), which is the OUTER element, NOT the Assertion handed in here. The ACS handler
// (saml/endpoints.ts) MUST enforce these BEFORE calling consumeAssertion, because they cannot be checked from
// inside the signed Assertion subtree:
//   1. SIGNATURE: the Assertion passed in MUST be the element returned by verifyXmlSignature (dsig.ts) under
//      the connection's PINNED IdP cert (conn.idpSigningCerts). We never re-verify here, and we never read a
//      sibling/unsigned part of the tree. wantAssertionsSigned is therefore satisfied structurally by the
//      caller handing us a verified node, not by a flag check in here.
//   2. STATUS: samlp:Status/StatusCode/@Value MUST equal urn:oasis:names:tc:SAML:2.0:status:Success. Status
//      lives on the Response, not the Assertion, and a non-Success Response usually carries NO Assertion at
//      all, so it is the caller's job to reject a non-Success Response before it ever extracts an Assertion to
//      pass here. (A caller that holds the Response can call assertStatusSuccess() below as a helper.)
//   3. DESTINATION: a Response-level @Destination, when present, MUST equal ctx.acsUrl. It is a Response
//      attribute, so the caller compares it; we enforce the equivalent SP-binding here via the
//      SubjectConfirmationData/@Recipient check (which IS inside the signed Assertion and is the stronger,
//      per-assertion binding).
// These mirror how the OIDC modules document their caller obligations (oidc.ts completeOidcLogin assumes the
// state/nonce were stored and the callback path was per-connId): the security-critical preconditions are
// stated, not silently assumed.
//
// ---- THE "verify == read" LINCHPIN ----
// txml does NOT decode XML entities. The digest path (dsig.ts) routes every signed byte through
// decodeXmlText (canonical-text.ts). So EVERY text value this module reads out of the tree - a NameID, an
// Attribute value, an Audience URI, a Recipient / InResponseTo / NotBefore / NotOnOrAfter / Format - is read
// through that SAME decodeXmlText, NEVER raw .value. Reading raw would let "what the IdP signed" diverge from
// "what the SP authorises on", which is the assertion-substitution exploit the shared decoder exists to kill.
//
// Node 25 strip-types + Workers compatible: pure functions, no DOM, no Node builtins, no enums, explicit
// fields, error-as-value (never throws out of consumeAssertion). Australian English; no em dashes.

import { type AdvisoryAuthContext, buildAuthContext } from "../auth-context.ts";
import { claimDropCounter, type ClaimDropTally } from "../posture-counters.ts";
import { canonicalEmail, samlSubject } from "../identity.ts";
import type { SamlConnection } from "../idpconn.ts";
// G276 / G316: the SAML signal ledger. Every branch below reports SUCCESS to the caller while quietly dropping
// something the operator configured -- which is precisely why no failure record exists for any of them, and why
// "my email-bound role never applies after SSO" was undiagnosable.
import { noteSamlSignal } from "../saml-signals.ts";
// The tree, namespace and XSD-dateTime helpers live in assertion-helpers.ts (a sibling split out so each
// module stays under 500 lines). They are internal to the consumer; the public surface (consumeAssertion,
// assertStatusSuccess + the principal/context types) stays here, so nothing from the helpers is re-exported.
// SAML_ASSERTION_NS is imported back for the consumer's own root-node namespace assertion.
import {
  decAttr,
  findChildInNs,
  findChildInSamlNs,
  findChildrenInSamlNs,
  mergeInherited,
  ownXmlnsBindings,
  parseSamlInstantMs,
  resolveNamespace,
  SAML_ASSERTION_NS,
  trimmedDecodedText,
} from "./assertion-helpers.ts";
import type { XmlElement } from "./xml-node.ts";
import { localName } from "./xml-node.ts";

// ---- SAML constant URIs (string-exact; anything not listed is treated as not-that-thing) ----
const STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
const NAMEID_TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
const SAML_PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
const BEARER_METHOD = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

// emailVerifiedPolicy is the per-connection trust posture for the email an assertion carries. SAML has no
// standard "email_verified" claim, so the SP must decide whether a signed email is trustworthy:
//   - "trust-idp": the IdP is trusted to only assert emails it has verified (the plan's default, intended to
//     sit behind an explicit owner acknowledgement at config time). A present, well-formed email is treated
//     as verified.
//   - "require-flag": the email is trusted ONLY when the assertion carries a verified flag attribute (named
//     by ctx.emailVerifiedAttr) whose decoded value is a truthy boolean ("true"/"1"). Otherwise the email is
//     NOT trusted and the principal is minted subject-only (email:null, emailVerified:false) rather than
//     rejecting the whole sign-in - a verified subject is enough to authenticate; the email is a display/bind
//     convenience, and an unverifiable one is simply dropped.
// It lives in AssertionContext (the caller supplies it) rather than on SamlConnection because the committed
// SamlConnection type does not carry it; this keeps the module pure and this file the single place the policy
// is interpreted, and lets the ACS handler source the policy from wherever config evolves to hold it.
export type EmailVerifiedPolicy = "trust-idp" | "require-flag";

// The injected, request-scoped inputs. NOTHING here is read from the network or the clock by this module: the
// caller resolves all of it and passes it in, exactly as completeOidcLogin receives its nonce/now.
export interface AssertionContext {
  // OUR Assertion Consumer Service URL. Compared byte-for-byte (after entity-decode) to
  // SubjectConfirmationData/@Recipient. This is the configured/derived SP endpoint, NEVER req.url (an attacker
  // controls req.url's host via Host/X-Forwarded-* headers, so trusting it would defeat the wrong-SP defence).
  acsUrl: string;
  // The id of the AuthnRequest WE sent and stored (samlreq:<connId>:<id>). SubjectConfirmationData/@InResponseTo
  // MUST equal this exactly. An assertion with NO InResponseTo is IdP-initiated and is rejected unless
  // conn.allowIdpInitiated is true (then this binding is skipped, since there was no request to bind to).
  expectedInResponseTo: string;
  // The injected clock as epoch milliseconds. Tests pass a fixed value; this module NEVER calls Date.now() or
  // new Date() (both are forbidden here - they break determinism). All time comparisons use this.
  nowMs: number;
  // The email-verified trust posture for this connection (see EmailVerifiedPolicy). Defaults conceptually to
  // "trust-idp" but is supplied explicitly by the caller so the policy decision is auditable at the call site.
  emailVerifiedPolicy: EmailVerifiedPolicy;
  // The Attribute Name that carries the IdP's email-verified boolean, consulted ONLY under the "require-flag"
  // policy. Absent means "no such attribute is configured", which under require-flag yields email:null.
  emailVerifiedAttr?: string;
}

// The principal a successful consumption yields. subject is the stable, collision-proof authorisation key
// (samlSubject). email is the canonicalised IdP email or null (subject-only) when it cannot be trusted.
// emailVerified reflects the policy outcome. groups is every value of the configured groups attribute (may be
// empty). nameId is the decoded NameID text (the raw principal name the subject was folded from).
export interface SamlPrincipal {
  subject: string;
  email: string | null;
  emailVerified: boolean;
  groups: string[];
  nameId: string;
  // claimDrops (G271): the CLOSED counter names of the ADVISORY claims this assertion asserted and the engine
  // bounded away: an over-length AuthnContextClassRef (claim-drop-saml-acr), and an AuthnInstant that was
  // asserted and could not be used (claim-drop-saml-auth-time -- unparseable, empty, or outside the usable
  // NumericDate range, all recorded HERE, where the raw attribute is still in hand). Diagnostic only: it never
  // affects the subject, the email, the groups or the role. The DO's ACS handler bumps them into the
  // admin-counter aggregate; the dropped values themselves never leave the bounder. SAML GROUP drops are not
  // here: this module carries groups verbatim, and they are bounded and tallied downstream in the DO
  // (scheduler-do-idp.ts, the ACS handler), under the claim-drop-saml-groups-* / -group-* names.
  claimDrops?: string[];
  // authContext (V6.8.4): the IdP's advisory AuthnContextClassRef (as acr) + AuthnInstant (as authTime),
  // bounded + redaction-safe. STRICTLY NON-GATING -- carried only for the sign-in audit record; authorization
  // never depends on it. Absent when the assertion carries no AuthnStatement/AuthnContext. See auth-context.ts.
  authContext?: AdvisoryAuthContext;
}

export type ConsumeAssertionResult =
  | { ok: true; principal: SamlPrincipal; assertionId: string; notOnOrAfter: number; sessionNotOnOrAfter: number | null }
  | { ok: false; reason: string };

function fail(reason: string): { ok: false; reason: string } {
  return { ok: false, reason };
}

// ---- the Status helper a Response-holding caller may use ----
// assertStatusSuccess checks samlp:Status/StatusCode/@Value === Success on a RESPONSE element. It is exported
// for the ACS handler to call on the Response (Status is NOT on the Assertion - see the caller obligations at
// the top). It is NAMESPACE-GATED to the SAML PROTOCOL namespace (exactly like every assertion-element lookup),
// so a PREPENDED foreign-namespace or no-namespace decoy <Status><StatusCode Value=Success/> cannot MASK a real
// samlp:Status failure: a first-direct-child-by-local-name match would otherwise read the decoy and wrongly pass
// this Status==Success precondition. It decodes the
// @Value before comparing. Returns true ONLY for an exact Success; any other or missing status is false.
export function assertStatusSuccess(response: XmlElement): boolean {
  const inResponse = mergeInherited(response, new Map<string, string>());
  const status = findChildInNs(response, "Status", SAML_PROTOCOL_NS, inResponse);
  if (status === null) return false;
  const inStatus = mergeInherited(status, inResponse);
  const code = findChildInNs(status, "StatusCode", SAML_PROTOCOL_NS, inStatus);
  if (code === null) return false;
  return decAttr(code, "Value") === STATUS_SUCCESS;
}

// SAML_STATUS_CLASSES is the CLOSED coarse class of a non-Success samlp:StatusCode (G018). The StatusCode is the
// one field in the whole Response that says WHY the IdP refused, and until now NOTHING read it: a declined
// sign-in (an unassigned enterprise app, a blocked account, an MFA the user would not complete) produced the
// same anonymous "status is not Success" as an IdP-side outage, and the support pack filed BOTH under `other`.
//
// The class is derived from the top-level StatusCode @Value, which is a SPEC URI from a fixed registry -- never
// the IdP's StatusMessage (free prose that can name a user, a tenant or an internal host) and never a
// second-level code (vendor-extensible, so not a closed vocabulary). Anything outside the four named URIs is
// "other": still an IdP decline, still recorded, but honestly unnamed.
const SAML_STATUS_CLASSES = {
  "urn:oasis:names:tc:SAML:2.0:status:Responder": "responder", // the IdP itself failed to process the request
  "urn:oasis:names:tc:SAML:2.0:status:Requester": "requester", // the IdP says OUR AuthnRequest was at fault
  "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed": "authnfailed", // the IdP DECLINED THE USER (unassigned app, blocked account, refused MFA)
  "urn:oasis:names:tc:SAML:2.0:status:NoPassive": "nopassive", // a passive request the IdP could not satisfy without interaction
} as const;

/**
 * samlStatusClass coarsens a Response's non-Success samlp:StatusCode into ONE member of the closed class set
 * above, for the `[saml-status:<class>]` mark the ACS failure reason carries (and which the edge reduces to a
 * bounded `sso-sub-idp-declined-*` counter). PURE. It reads ONLY the top-level StatusCode @Value and compares it
 * against the four fixed spec URIs; the StatusMessage and any second-level code are never read, so no IdP prose,
 * user id or tenant can leave this function. An absent / unrecognised code yields "other".
 *
 * @param response - the parsed samlp:Response element.
 * @returns the closed status class.
 */
export function samlStatusClass(response: XmlElement): string {
  const inResponse = mergeInherited(response, new Map<string, string>());
  const status = findChildInNs(response, "Status", SAML_PROTOCOL_NS, inResponse);
  if (status === null) return "other";
  const code = findChildInNs(status, "StatusCode", SAML_PROTOCOL_NS, mergeInherited(status, inResponse));
  if (code === null) return "other";
  const value = decAttr(code, "Value");
  return (value !== null && value in SAML_STATUS_CLASSES ? SAML_STATUS_CLASSES[value as keyof typeof SAML_STATUS_CLASSES] : "other");
}

// ---- the consumer ----
export function consumeAssertion(assertion: XmlElement, conn: SamlConnection, ctx: AssertionContext): ConsumeAssertionResult {
  // Defensive shape guard (the caller hands us the verified node, but fail closed on anything odd).
  if (assertion === null || assertion === undefined || assertion.type !== "element") return fail("assertion is not an element");

  // The verified node MUST itself be a saml:Assertion in the SAML assertion namespace. The signature gate
  // proved SOME element authentic; here we assert it is the Assertion we expect (not, say, a signed Response
  // wrapper handed in by mistake), and we establish the namespace context for every descendant match.
  const rootScope = ownXmlnsBindings(assertion);
  if (localName(assertion.name) !== "Assertion" || resolveNamespace(assertion, new Map()) !== SAML_ASSERTION_NS) {
    return fail("verified node is not a saml:Assertion");
  }
  const inAssertion = rootScope; // bindings in scope for the Assertion's direct children
  const skewMs = Math.max(0, Math.trunc(conn.clockSkewSec)) * 1000;
  const now = ctx.nowMs;

  // ===================== ISSUER (federation binding) =====================
  // saml:Issuer (a direct child of the Assertion) MUST equal the connection's pinned idpEntityId. The cert
  // pin already stops a different IdP signing a valid assertion, but the explicit Issuer check is the
  // required belt-and-suspenders binding (ASVS V2.7, SAML 2.0 Core 3.4): an Assertion that names a different
  // Issuer than the one this connection trusts is rejected even if it somehow carried a valid signature.
  const issuerEl = findChildInSamlNs(assertion, "Issuer", inAssertion);
  if (issuerEl === null) return fail("assertion has no Issuer");
  if (trimmedDecodedText(issuerEl) !== conn.idpEntityId) {
    return fail("assertion Issuer does not match the connection's idpEntityId");
  }

  // assertionId: the Assertion's ID attribute (decoded). The caller dedupes replays on it together with
  // notOnOrAfter, so it must be present.
  const assertionId = decAttr(assertion, "ID");
  if (assertionId === null || assertionId.length === 0) return fail("assertion has no ID");

  // ===================== CONDITIONS (validity window + audience) =====================
  const conditionsResult = validateConditions(assertion, inAssertion, conn, now, skewMs);
  if (!conditionsResult.ok) return conditionsResult;

  // ===================== SUBJECT + SUBJECTCONFIRMATION (bearer) =====================
  const subject = findChildInSamlNs(assertion, "Subject", inAssertion);
  if (subject === null) return fail("assertion has no Subject");
  const inSubject = mergeInherited(subject, inAssertion);

  // NameID: read the Subject/NameID (in the SAML namespace). Its Format must not be transient; if the
  // connection pins a nameIdFormat, the assertion's Format must match it; the decoded text is the principal
  // name. Missing NameID = reject (no principal to key on).
  const nameIdResult = readSubjectNameId(subject, inSubject, conn);
  if (!nameIdResult.ok) return nameIdResult;
  const nameId = nameIdResult.nameId;

  // SubjectConfirmation with Method bearer. There may be several SubjectConfirmation elements; we require at
  // least ONE bearer confirmation whose SubjectConfirmationData satisfies Recipient + InResponseTo +
  // NotOnOrAfter. We track the bearer confirmation's NotOnOrAfter to return (the replay-dedupe upper bound).
  const bearerResult = confirmBearer(subject, inSubject, conn, ctx, now, skewMs);
  if (!bearerResult.ok) return bearerResult;
  const scNotOnOrAfterMs = bearerResult.notOnOrAfter;

  // ===================== SUBJECT (stable principal) =====================
  // Use the shared helper so the prefix shape is never hand-formatted here (saml:<connId>|<entityId>|<NameID>).
  const principalSubject = samlSubject(conn.id, conn.idpEntityId, nameId);

  // ===================== ATTRIBUTES (email + groups) =====================
  const { email, emailVerified, groups } = collectIdentity(assertion, inAssertion, conn, ctx);

  // ===================== AUTHNSTATEMENT (IdP session bound, ASVS V7.6.1) =====================
  // The IdP's session upper bound: saml:AuthnStatement/@SessionNotOnOrAfter (epoch ms), read off the SAME
  // signature-verified Assertion node via the namespace-gated child match, exactly like Conditions/Subject.
  // It is an OPTIONAL attribute per SAML core, so absent / unparseable yields null (no bound) and is NEVER a
  // failure. The caller caps the native session's exp at this instant when present, so a downpipes session
  // cannot outlive the IdP session. Because it is matched DOWN from the verified Assertion (findChildInSamlNs
  // + inherited namespace), a forged or foreign-namespace <AuthnStatement> smuggled elsewhere is ignored.
  let sessionNotOnOrAfter: number | null = null;
  // V6.8.4 advisory (NON-GATING): the SAML analogues of OIDC acr/auth_time -- AuthnContextClassRef (the class
  // reference) and AuthnInstant (when the IdP authenticated the user) -- read DOWN from the SAME verified
  // AuthnStatement node via the namespace-gated descent, so a forged/foreign-namespace node is ignored. Both
  // are OPTIONAL; absent yields an undefined authContext and is never a failure. It is carried only onto the
  // sign-in audit record; nothing here influences the subject/email/groups resolved above.
  let authContext: AdvisoryAuthContext | undefined;
  // G271: the bounded tally the advisory bounder fills as it drops. Closed counter names only.
  const claimDrops: ClaimDropTally = new Set<string>();
  const authnStmt = findChildInSamlNs(assertion, "AuthnStatement", inAssertion);
  if (authnStmt !== null) {
    const sessionNooaRaw = decAttr(authnStmt, "SessionNotOnOrAfter");
    sessionNotOnOrAfter = parseSamlInstantMs(sessionNooaRaw);
    // G276: the attribute is OPTIONAL, so ABSENT is legitimately "no bound". But PRESENT-and-unparseable is
    // silently read as the same thing -- and the consequence is a security regression that reports success: the
    // native session is no longer capped at the IdP's session end, so it OUTLIVES it. Absent stays silent (it is
    // not a fault); present-but-unreadable is now recorded. The attribute VALUE never rides, only the fact.
    if (sessionNooaRaw !== null && sessionNotOnOrAfter === null) noteSamlSignal("sso-session-cap-dropped");
    const inAuthn = mergeInherited(authnStmt, inAssertion);
    let acr: string | undefined;
    const authnContext = findChildInSamlNs(authnStmt, "AuthnContext", inAuthn);
    if (authnContext !== null) {
      const classRef = findChildInSamlNs(authnContext, "AuthnContextClassRef", mergeInherited(authnContext, inAuthn));
      if (classRef !== null) {
        const t = trimmedDecodedText(classRef);
        if (t.length > 0) acr = t;
      }
    }
    // AuthnInstant is an ISO instant; normalise to epoch SECONDS so authTime is consistent with OIDC auth_time.
    const authnInstantRaw = decAttr(authnStmt, "AuthnInstant");
    const authnInstantMs = parseSamlInstantMs(authnInstantRaw);
    // R6: RECORD THE DROP WHERE THE FACT IS ESTABLISHED. parseSamlInstantMs folds an unreadable instant to null,
    // and null reached buildAuthContext as `undefined` -- the SAME input as an IdP that asserted no AuthnInstant
    // at all -- so buildAuthContext could only ever see ABSENT, and the one state claim-drop-saml-auth-time is
    // named for ("an AuthnInstant was asserted and would not parse") recorded nothing. The only thing that could
    // reach the member was a NEGATIVE-epoch instant, which is a different fact. The presence test belongs here,
    // where the raw attribute is still in hand. The attribute VALUE never rides, only the closed counter name.
    if (authnInstantRaw !== null && authnInstantMs === null) claimDrops.add(claimDropCounter("saml", "auth-time"));
    // G271: the SAML front door tallied NOTHING. buildAuthContext was called with no tally, so an over-length
    // AuthnContextClassRef or an AuthnInstant that would not parse was dropped in silence and read exactly like
    // an IdP asserting neither -- and "prove this session was MFA'd / when did they actually authenticate?" had
    // no honest answer either way. The boundary is passed explicitly ("saml"), because this constructor is
    // shared with the OIDC path and defaulting it would file the drop under a boundary this assertion never
    // crossed. The dropped VALUE never rides.
    authContext = buildAuthContext({ acr, authTime: authnInstantMs !== null ? Math.floor(authnInstantMs / 1000) : undefined }, claimDrops, "saml");
  }

  // notOnOrAfter: the bearer SubjectConfirmationData NotOnOrAfter as epoch ms (the tighter, per-confirmation
  // bound), which together with assertionId the caller uses to dedupe replays.
  return {
    ok: true,
    principal: { subject: principalSubject, email, emailVerified, groups, nameId, ...(authContext !== undefined ? { authContext } : {}), ...(claimDrops.size > 0 ? { claimDrops: [...claimDrops] } : {}) },
    assertionId,
    notOnOrAfter: scNotOnOrAfterMs,
    sessionNotOnOrAfter,
  };
}

// validateConditions enforces the saml:Conditions stage of consumeAssertion: the validity window (NotBefore
// <= now + skew, NotOnOrAfter > now - skew, BOTH required, a parse failure is a hard reject) and the
// AudienceRestriction (at least one Audience equals conn.spEntityId, the wrong-SP defence). Missing
// Conditions is a reject (fail closed). Pure; extracted verbatim so consumeAssertion stays under the ceiling.
function validateConditions(
  assertion: XmlElement,
  inAssertion: Map<string, string>,
  conn: SamlConnection,
  now: number,
  skewMs: number,
): { ok: true } | { ok: false; reason: string } {
  // Exactly the saml:Conditions on the Assertion. Missing Conditions = reject (fail closed): we will not
  // consume an assertion that declares no validity window or audience restriction.
  const conditions = findChildInSamlNs(assertion, "Conditions", inAssertion);
  if (conditions === null) return fail("assertion has no Conditions");
  const inConditions = mergeInherited(conditions, inAssertion);

  // NotBefore <= now + skew, NotOnOrAfter > now - skew. BOTH bounds are required (a one-sided window is
  // rejected). A bound that fails to parse is a hard reject (fail closed).
  const condNotBefore = parseSamlInstantMs(decAttr(conditions, "NotBefore"));
  const condNotOnOrAfter = parseSamlInstantMs(decAttr(conditions, "NotOnOrAfter"));
  if (condNotBefore === null) return fail("Conditions NotBefore missing or unparseable");
  if (condNotOnOrAfter === null) return fail("Conditions NotOnOrAfter missing or unparseable");
  if (condNotBefore > now + skewMs) return fail("assertion not yet valid (Conditions NotBefore)");
  if (condNotOnOrAfter <= now - skewMs) return fail("assertion expired (Conditions NotOnOrAfter)");

  // AudienceRestriction: at least one Audience (in any AudienceRestriction) whose decoded text equals
  // conn.spEntityId exactly. No matching audience = reject (the assertion was minted for a different SP, the
  // audience-restriction defence). There may be multiple AudienceRestriction / Audience elements; we accept
  // if ANY Audience matches our entityId (SAML semantics: the SP must appear among the audiences).
  let audienceOk = false;
  for (const ar of findChildrenInSamlNs(conditions, "AudienceRestriction", inConditions)) {
    const inAr = mergeInherited(ar, inConditions);
    for (const aud of findChildrenInSamlNs(ar, "Audience", inAr)) {
      if (trimmedDecodedText(aud) === conn.spEntityId) {
        audienceOk = true;
        break;
      }
    }
    if (audienceOk) break;
  }
  if (!audienceOk) return fail("no AudienceRestriction/Audience matches the SP entityId");
  return { ok: true };
}

// readSubjectNameId reads Subject/NameID (in the SAML namespace) and returns its decoded text, or a typed
// rejection. The Format must not be transient; if the connection pins a non-empty nameIdFormat, the
// assertion's Format must match it exactly (a pinned format with a null/absent assertion Format is a
// mismatch). A missing NameID, or an empty decoded value, is a reject (no principal to key on).
function readSubjectNameId(
  subject: XmlElement,
  inSubject: Map<string, string>,
  conn: SamlConnection,
): { ok: true; nameId: string } | { ok: false; reason: string } {
  const nameIdEl = findChildInSamlNs(subject, "NameID", inSubject);
  if (nameIdEl === null) return fail("Subject has no NameID");
  const nameIdFormat = decAttr(nameIdEl, "Format"); // may be null (unspecified)
  if (nameIdFormat === NAMEID_TRANSIENT) {
    return fail("transient NameID format is not acceptable (not stable enough to key authorisation)");
  }
  if (conn.nameIdFormat.length > 0) {
    if (nameIdFormat === null || nameIdFormat !== conn.nameIdFormat) {
      return fail("NameID Format does not match the connection's pinned nameIdFormat");
    }
  }
  const nameId = trimmedDecodedText(nameIdEl);
  if (nameId.length === 0) return fail("NameID is empty");
  return { ok: true, nameId };
}

// confirmBearer enforces the SubjectConfirmation (bearer) stage: it requires at least ONE bearer confirmation
// whose SubjectConfirmationData satisfies @Recipient == ctx.acsUrl, a present/parseable/unexpired
// @NotOnOrAfter, and the @InResponseTo binding (equal to ctx.expectedInResponseTo when present; absent is
// IdP-initiated, rejected unless conn.allowIdpInitiated). It returns the satisfying confirmation's
// NotOnOrAfter (the replay-dedupe upper bound) or a typed rejection. Pure; extracted verbatim.
function confirmBearer(
  subject: XmlElement,
  inSubject: Map<string, string>,
  conn: SamlConnection,
  ctx: AssertionContext,
  now: number,
  skewMs: number,
): { ok: true; notOnOrAfter: number } | { ok: false; reason: string } {
  const subjectConfirmations = findChildrenInSamlNs(subject, "SubjectConfirmation", inSubject);
  if (subjectConfirmations.length === 0) return fail("Subject has no SubjectConfirmation");

  // G018: WHICH binding blocked the last examined bearer confirmation. The refusal below is a SEVEN-WAY BLEND
  // ("no bearer SubjectConfirmation satisfies Recipient/InResponseTo/NotOnOrAfter"), and the three causes it
  // blends need three different answers: a @Recipient mismatch is the console origin / SP entity moving under
  // the IdP (fix the IdP's ACS URL), an expired @NotOnOrAfter is clock drift or a stale POST (check NTP), and an
  // @InResponseTo mismatch is a genuine replay/injection signal. The blend was decided HERE, at the site that
  // knows, and then thrown away. Track the LAST blocker (a closed token, not a value) and carry it as the
  // `[saml-bearer:<class>]` mark, which the edge reduces to a bounded sso-sub-bearer-* counter. The reason's
  // FIXED PREFIX is unchanged, so the coarse SSO code it classifies to (replay) is unchanged too, and the
  // client-facing response was already generic. No URL, instant or InResponseTo value ever rides.
  let blocked = "absent"; // no bearer confirmation carried usable SubjectConfirmationData at all
  for (const sc of subjectConfirmations) {
    if (decAttr(sc, "Method") !== BEARER_METHOD) continue; // only the bearer method is in scope for web SSO
    const inSc = mergeInherited(sc, inSubject);
    const scd = findChildInSamlNs(sc, "SubjectConfirmationData", inSc);
    if (scd === null) continue; // a bearer confirmation with no data cannot satisfy the bindings

    // @Recipient (decoded) MUST equal ctx.acsUrl exactly (the wrong-SP / assertion-forwarding defence).
    const recipient = decAttr(scd, "Recipient");
    if (recipient === null || recipient !== ctx.acsUrl) {
      blocked = "recipient";
      continue;
    }

    // @NotOnOrAfter (decoded) MUST be present, parseable, and > now - skew (the bearer assertion's own
    // freshness bound). A missing/unparseable/expired bound disqualifies this confirmation.
    const scdNooaMs = parseSamlInstantMs(decAttr(scd, "NotOnOrAfter"));
    if (scdNooaMs === null || scdNooaMs <= now - skewMs) {
      blocked = "expired";
      continue;
    }

    // @InResponseTo: the anti-replay/anti-injection binding for SP-initiated SSO. When PRESENT it MUST equal
    // ctx.expectedInResponseTo exactly. When ABSENT the assertion is IdP-initiated, which is rejected unless
    // conn.allowIdpInitiated is true (then the binding is skipped, there being no request to bind to).
    const inResponseTo = decAttr(scd, "InResponseTo");
    if (inResponseTo === null) {
      if (!conn.allowIdpInitiated) {
        blocked = "inresponseto"; // IdP-initiated not allowed: this confirmation cannot satisfy
        continue;
      }
      // allowed IdP-initiated: skip the InResponseTo check for this confirmation
    } else if (inResponseTo !== ctx.expectedInResponseTo) {
      blocked = "inresponseto"; // wrong InResponseTo (replay/injection): this confirmation cannot satisfy
      continue;
    }

    // This bearer confirmation satisfies every binding.
    return { ok: true, notOnOrAfter: scdNooaMs };
  }
  return fail(`no bearer SubjectConfirmation satisfies Recipient/InResponseTo/NotOnOrAfter [saml-bearer:${blocked}]`);
}

// collectIdentity reads the email + groups attributes off the Assertion and applies the email-verified
// policy. email: conn.emailAttr's FIRST value, canonicalised, then trusted per ctx.emailVerifiedPolicy
// (trust-idp = a present canonical email is verified; require-flag = trusted only when the verified-flag
// attribute is truthy). An untrusted/missing email drops to subject-only (email:null) rather than rejecting
// the sign-in. groups: every value of conn.groupsAttr in document order (the caller dedupes). Pure.
function collectIdentity(
  assertion: XmlElement,
  inAssertion: Map<string, string>,
  conn: SamlConnection,
  ctx: AssertionContext,
): { email: string | null; emailVerified: boolean; groups: string[] } {
  // Attributes live in saml:AttributeStatement/saml:Attribute (matched by @Name), each with one or more
  // saml:AttributeValue children. We collect them once into a name -> decoded values map, reading every value
  // through the shared decoder. An IdP may emit multiple AttributeStatement elements; we scan all of them.
  const attrValues = collectAttributes(assertion, inAssertion);

  let email: string | null = null;
  let emailVerified = false;
  if (conn.emailAttr !== undefined && conn.emailAttr.length > 0) {
    const vals = attrValues.get(conn.emailAttr);
    const rawEmail = vals !== undefined && vals.length > 0 ? vals[0]! : null;
    const canon = canonicalEmail(rawEmail);
    if (canon !== null) {
      if (ctx.emailVerifiedPolicy === "trust-idp") {
        // The IdP is trusted (behind the owner's acknowledgement at config time) to assert only verified
        // emails: a present, canonicalisable email is treated as verified.
        email = canon;
        emailVerified = true;
      } else {
        // require-flag: trust the email ONLY when the configured verified-flag attribute is present and truthy.
        const verified = readVerifiedFlag(attrValues, ctx.emailVerifiedAttr);
        if (verified) {
          email = canon;
          emailVerified = true;
        } else {
          // G276: a GOOD email is being DROPPED here and the sign-in still succeeds, so nothing anywhere records
          // it -- the user signs in, their email-bound role never applies, and the pack is silent. The two causes
          // need OPPOSITE remediations and are split accordingly:
          //   flag-absent: the configured attribute was not asserted at all. Nine times in ten a MISSPELT
          //     attribute name in the connection (or an IdP that was never asked to emit it). WE fix this.
          //   flag-false: the IdP asserted the flag and it is falsy. The IdP is genuinely telling us the address
          //     is unverified. THE IdP fixes this, and dropping the email is the correct behaviour.
          // The attribute name, the flag value and the email itself never ride: the closed name only.
          const flagPresent = ctx.emailVerifiedAttr !== undefined && ctx.emailVerifiedAttr.length > 0 && (attrValues.get(ctx.emailVerifiedAttr)?.length ?? 0) > 0;
          noteSamlSignal(flagPresent ? "sso-email-untrusted-flag-false" : "sso-email-untrusted-flag-absent");
          // Unverified under require-flag: drop to subject-only rather than rejecting.
          email = null;
          emailVerified = false;
        }
      }
    }
  }

  // groups: every value of the configured groups attribute (decoded), in document order, deduped is NOT
  // required by the contract (callers fold them through boundGroups which dedupes), so we return them as-is.
  // An absent groups attribute or no values yields [].
  let groups: string[] = [];
  if (conn.groupsAttr !== undefined && conn.groupsAttr.length > 0) {
    const vals = attrValues.get(conn.groupsAttr);
    if (vals !== undefined) groups = vals.slice();
  }
  return { email, emailVerified, groups };
}

// collectAttributes walks every saml:AttributeStatement under the Assertion and builds a map from the
// Attribute @Name (decoded) to its list of decoded AttributeValue texts (in document order). Values are read
// through the shared decoder (verify == read). An Attribute with no values contributes an empty list under
// its name; a repeated Name accumulates (an IdP that splits a multi-valued attribute across two Attribute
// elements is handled). Only AttributeValue children in the SAML namespace contribute a value.
function collectAttributes(assertion: XmlElement, inAssertion: Map<string, string>): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const stmt of findChildrenInSamlNs(assertion, "AttributeStatement", inAssertion)) {
    const inStmt = mergeInherited(stmt, inAssertion);
    for (const attrEl of findChildrenInSamlNs(stmt, "Attribute", inStmt)) {
      const name = decAttr(attrEl, "Name");
      if (name === null || name.length === 0) continue;
      const inAttr = mergeInherited(attrEl, inStmt);
      const list = out.get(name) ?? [];
      // G316: the SAME Attribute @Name asserted MORE THAN ONCE. A conforming IdP emits each attribute once; a
      // repeat is an attempt to have the SP read a different value than the one the IdP intended (an email or
      // groups pollution probe -- which value wins depends on the consumer's merge order). We keep the existing
      // merge behaviour (every value in document order) and RECORD the shape. The attribute NAME never rides.
      if (list.length > 0) noteSamlSignal("saml-shape-attr-pollution");
      for (const valEl of findChildrenInSamlNs(attrEl, "AttributeValue", inAttr)) {
        list.push(trimmedDecodedText(valEl));
      }
      out.set(name, list);
    }
  }
  return out;
}

// readVerifiedFlag returns true iff the email-verified flag attribute (named verifiedAttr) is present with a
// truthy decoded value. SAML xs:boolean is "true"/"false"/"1"/"0"; we accept "true" (case-insensitively) or
// "1" as truthy, everything else (including absent or an empty list) as false. Under "require-flag" this
// gates whether the email is trusted.
function readVerifiedFlag(attrValues: Map<string, string[]>, verifiedAttr: string | undefined): boolean {
  if (verifiedAttr === undefined || verifiedAttr.length === 0) return false;
  const vals = attrValues.get(verifiedAttr);
  if (vals === undefined || vals.length === 0) return false;
  const v = vals[0]!.trim().toLowerCase();
  return v === "true" || v === "1";
}
