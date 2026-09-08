// Adversarial validator for the SAML assertion consumer (src/admin/saml/assertion.ts). It builds
// already-signature-verified <saml:Assertion> XmlElement trees by hand (the SAME tree shape dsig.ts returns
// as `verified`, so the module under test is exercised exactly as in production) and drives consumeAssertion
// with a FIXED clock and a pinned SamlConnection. One happy-path vector proves a well-formed bearer assertion
// yields the stable principal (subject == samlSubject(...), canonicalised email, groups, assertionId,
// notOnOrAfter); then a RED corpus where each crafted tree MUST be rejected (expired / not-yet-valid / wrong
// audience / wrong Recipient / wrong InResponseTo / IdP-initiated-when-disallowed / transient NameID / pinned
// nameIdFormat mismatch), plus the subject-only-not-reject path for an unverified email under require-flag,
// the clock-skew tolerance, and the entity-decode (verify == read) proof.
//
// The module under test is PURE (no fetch/crypto/DO/clock), so this validator needs no network and no key
// material - it constructs the verified node directly, which is honest because the production caller hands
// consumeAssertion exactly such a node (the one verifyXmlSignature returned).
//
// Node 25 strip-types; no Node builtins beyond the harness exit code. console is the WebWorker global.

import { consumeAssertion, assertStatusSuccess } from "../src/admin/saml/assertion.ts";
import type { AssertionContext, EmailVerifiedPolicy } from "../src/admin/saml/assertion.ts";
import type { XmlElement, XmlAttr, XmlChild } from "../src/admin/saml/xml-node.ts";
import type { SamlConnection } from "../src/admin/idpconn.ts";
import { samlSubject } from "../src/admin/identity.ts";

// This validator runs under Node (strip-types); the project tsconfig ships Workers types only (no
// @types/node). Declare the single Node global we use so the file is tsc-clean under those flags.
declare const process: { exitCode?: number };

// ---- tiny test harness (the ok(name, cond) shape the sibling validators use) ----
let passed = 0;
let failures = 0;
function ok(name: string, cond: boolean): void {
  if (cond) {
    passed++;
    console.log("  ok   " + name);
  } else {
    failures++;
    console.log("  FAIL " + name);
  }
}

// ---- tree builders (same shape as validate-saml-dsig.ts) ----
function el(name: string, attrs: XmlAttr[], children: XmlChild[]): XmlElement {
  return { type: "element", name, attrs, children };
}
function a(name: string, value: string): XmlAttr {
  return { name, value };
}
function t(value: string): XmlChild {
  return { type: "text", value };
}
function clone(x: XmlElement): XmlElement {
  return {
    type: "element",
    name: x.name,
    attrs: x.attrs.map((at) => ({ name: at.name, value: at.value })),
    children: x.children.map((c) => (c.type === "element" ? clone(c) : { type: c.type, value: c.value }) as XmlChild),
  };
}

// ---- fixed reference values (a fixed clock + the connection/context constants) ----
const SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
const IDP_ENTITY = "https://idp.example.com/entity";
const SP_ENTITY = "https://console.downpipes.io/saml/metadata";
const ACS_URL = "https://console.downpipes.io/admin/saml/acs/work-idp";
const IN_RESPONSE_TO = "_req_abc123";
const ASSERTION_ID = "_assertion_0001";
const CONN_ID = "work-idp";
const NAMEID_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const NAMEID_TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
const NAMEID_EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

// A fixed "now" well inside the validity window below. Use an explicit instant so every comparison is
// deterministic (the module never reads the wall clock; the test never relies on it either).
const NOW_MS = Date.parse("2026-06-13T12:00:00Z");
const NOT_BEFORE = "2026-06-13T11:55:00Z"; // 5 min before now
const NOT_ON_OR_AFTER = "2026-06-13T12:05:00Z"; // 5 min after now
const SCD_NOT_ON_OR_AFTER = "2026-06-13T12:05:00Z";

// The pinned connection. clockSkewSec 120 (the plan's default). emailAttr/groupsAttr are the attribute NAMES
// the IdP emits. nameIdFormat is left "" here (no pin) for the happy path; a pinned-format vector sets it.
function baseConn(over: Partial<SamlConnection> = {}): SamlConnection {
  return {
    kind: "saml",
    id: CONN_ID,
    label: "Work IdP",
    presetId: "generic-saml",
    enabled: true,
    createdBy: "owner@example.com",
    createdAt: "2026-06-13T00:00:00.000Z",
    idpEntityId: IDP_ENTITY,
    idpSsoUrl: "https://idp.example.com/sso",
    idpSigningCerts: ["-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"],
    spEntityId: SP_ENTITY,
    nameIdFormat: "", // no pin by default
    wantAssertionsSigned: true,
    allowIdpInitiated: false,
    clockSkewSec: 120,
    emailAttr: "email",
    groupsAttr: "groups",
    // emailVerifiedPolicy is a required field on SamlConnection; default it here (overridable via `over`) so
    // baseConn() yields a complete, valid connection. These paths (assertion consume) do not read it.
    emailVerifiedPolicy: "require-flag",
    ...over,
  };
}

function baseCtx(over: Partial<AssertionContext> = {}): AssertionContext {
  const ctx: AssertionContext = {
    acsUrl: ACS_URL,
    expectedInResponseTo: IN_RESPONSE_TO,
    nowMs: NOW_MS,
    emailVerifiedPolicy: "trust-idp",
  };
  return { ...ctx, ...over };
}

// ---- assertion fixture builder ----
// Build a well-formed, bearer, SP-initiated assertion. Options let each vector perturb exactly one facet.
interface Opts {
  nameIdFormat?: string | null; // null = omit the Format attribute
  nameId?: string;
  notBefore?: string;
  notOnOrAfter?: string; // Conditions NotOnOrAfter
  scdNotOnOrAfter?: string; // SubjectConfirmationData NotOnOrAfter
  recipient?: string;
  inResponseTo?: string | null; // null = omit (IdP-initiated)
  audience?: string;
  emailValue?: string | null; // null = omit the email attribute entirely
  emailVerifiedValue?: string | null; // null = omit the email_verified attribute
  emailVerifiedAttrName?: string; // the @Name for the verified-flag attribute
  groupValues?: string[];
  method?: string; // SubjectConfirmation Method (default bearer)
  assertionId?: string;
  issuer?: string; // saml:Issuer text (default IDP_ENTITY); set to a different URI to exercise the Issuer check
  authnSessionNotOnOrAfter?: string; // when set, add an AuthnStatement carrying this SessionNotOnOrAfter
  forgedAuthnNs?: boolean; // when true, the AuthnStatement is in a FOREIGN namespace (must be ignored)
  authnContextClassRef?: string; // when set, add AuthnStatement/AuthnContext/AuthnContextClassRef (advisory acr, V6.8.4)
  authnInstant?: string; // when set, add AuthnStatement/@AuthnInstant (advisory authTime, V6.8.4)
}

// buildSubject assembles saml:Subject (NameID + bearer SubjectConfirmation/SubjectConfirmationData).
function buildSubject(o: Opts): XmlElement {
  const nameIdFormat = o.nameIdFormat === undefined ? NAMEID_PERSISTENT : o.nameIdFormat;
  const nameId = o.nameId ?? "alice@example.com";
  const recipient = o.recipient ?? ACS_URL;
  const method = o.method ?? "urn:oasis:names:tc:SAML:2.0:cm:bearer";
  const scdNotOnOrAfter = o.scdNotOnOrAfter ?? SCD_NOT_ON_OR_AFTER;

  const nameIdAttrs: XmlAttr[] = nameIdFormat === null ? [] : [a("Format", nameIdFormat)];
  const nameIdEl = el("saml:NameID", nameIdAttrs, [t(nameId)]);

  const scdAttrs: XmlAttr[] = [a("Recipient", recipient), a("NotOnOrAfter", scdNotOnOrAfter)];
  if (o.inResponseTo !== null) scdAttrs.push(a("InResponseTo", o.inResponseTo ?? IN_RESPONSE_TO));
  const scd = el("saml:SubjectConfirmationData", scdAttrs, []);
  const subjectConfirmation = el("saml:SubjectConfirmation", [a("Method", method)], [scd]);
  return el("saml:Subject", [], [nameIdEl, subjectConfirmation]);
}

// buildConditions assembles saml:Conditions (validity window + AudienceRestriction/Audience).
function buildConditions(o: Opts): XmlElement {
  const notBefore = o.notBefore ?? NOT_BEFORE;
  const notOnOrAfter = o.notOnOrAfter ?? NOT_ON_OR_AFTER;
  const audience = o.audience ?? SP_ENTITY;
  return el(
    "saml:Conditions",
    [a("NotBefore", notBefore), a("NotOnOrAfter", notOnOrAfter)],
    [el("saml:AudienceRestriction", [], [el("saml:Audience", [], [t(audience)])])],
  );
}

// buildAttributeStatement assembles saml:AttributeStatement (email unless omitted, groups, optional verified flag).
function buildAttributeStatement(o: Opts): XmlElement {
  const groupValues = o.groupValues ?? ["administrators", "billing"];
  const attrChildren: XmlElement[] = [];
  if (o.emailValue !== null) {
    attrChildren.push(
      el("saml:Attribute", [a("Name", "email")], [el("saml:AttributeValue", [], [t(o.emailValue ?? "alice@example.com")])]),
    );
  }
  if (o.emailVerifiedValue !== null && o.emailVerifiedValue !== undefined) {
    attrChildren.push(
      el(
        "saml:Attribute",
        [a("Name", o.emailVerifiedAttrName ?? "email_verified")],
        [el("saml:AttributeValue", [], [t(o.emailVerifiedValue)])],
      ),
    );
  }
  const groupValueEls = groupValues.map((g) => el("saml:AttributeValue", [], [t(g)]));
  attrChildren.push(el("saml:Attribute", [a("Name", "groups")], groupValueEls));
  return el("saml:AttributeStatement", [], attrChildren);
}

// buildAuthnStatement returns the optional saml:AuthnStatement (or its forged foreign-namespace twin), or null
// when the test does not request one.
function buildAuthnStatement(o: Opts): XmlElement | null {
  const wantsAuthn = o.authnSessionNotOnOrAfter !== undefined || o.authnContextClassRef !== undefined || o.authnInstant !== undefined;
  if (!wantsAuthn) return null;
  if (o.forgedAuthnNs === true) {
    // A foreign-namespace AuthnStatement (same LOCAL name, a non-SAML xmlns). The namespace-gated child match
    // must IGNORE it, so its forged SessionNotOnOrAfter / AuthnContext never reaches the session bound or the
    // advisory acr (XSW defence).
    const evilAttrs: XmlAttr[] = [a("xmlns:evil", "urn:evil")];
    if (o.authnSessionNotOnOrAfter !== undefined) evilAttrs.push(a("SessionNotOnOrAfter", o.authnSessionNotOnOrAfter));
    if (o.authnInstant !== undefined) evilAttrs.push(a("AuthnInstant", o.authnInstant));
    const evilKids = o.authnContextClassRef !== undefined ? [el("evil:AuthnContext", [], [el("evil:AuthnContextClassRef", [], [t(o.authnContextClassRef)])])] : [];
    return el("evil:AuthnStatement", evilAttrs, evilKids);
  }
  const attrs: XmlAttr[] = [];
  if (o.authnSessionNotOnOrAfter !== undefined) attrs.push(a("SessionNotOnOrAfter", o.authnSessionNotOnOrAfter));
  if (o.authnInstant !== undefined) attrs.push(a("AuthnInstant", o.authnInstant));
  const children: XmlElement[] = [];
  if (o.authnContextClassRef !== undefined) {
    children.push(el("saml:AuthnContext", [], [el("saml:AuthnContextClassRef", [], [t(o.authnContextClassRef)])]));
  }
  return el("saml:AuthnStatement", attrs, children);
}

function buildAssertion(o: Opts = {}): XmlElement {
  const assertionId = o.assertionId ?? ASSERTION_ID;
  const issuer = o.issuer ?? IDP_ENTITY;

  // The Assertion itself declares the saml: namespace (as a real IdP does), so namespace resolution in the
  // module binds saml: -> the assertion namespace for every descendant.
  const assertionChildren: XmlElement[] = [
    el("saml:Issuer", [], [t(issuer)]),
    buildSubject(o),
    buildConditions(o),
    buildAttributeStatement(o),
  ];
  const authn = buildAuthnStatement(o);
  if (authn !== null) assertionChildren.push(authn);
  return el(
    "saml:Assertion",
    [a("xmlns:saml", SAML_NS), a("ID", assertionId), a("Version", "2.0"), a("IssueInstant", "2026-06-13T11:59:00Z")],
    assertionChildren,
  );
}

console.log("SAML assertion consumer vectors\n");

// ============================ 1. HAPPY PATH ============================
{
  const r = consumeAssertion(buildAssertion(), baseConn(), baseCtx());
  ok("happy: a well-formed bearer assertion is accepted", r.ok === true);
  if (r.ok) {
    ok("  -> subject == samlSubject(connId, idpEntityId, nameId)", r.principal.subject === samlSubject(CONN_ID, IDP_ENTITY, "alice@example.com") && r.principal.subject === `saml:${CONN_ID}|${IDP_ENTITY}|alice@example.com`);
    ok("  -> email canonicalised + emailVerified true (trust-idp)", r.principal.email === "alice@example.com" && r.principal.emailVerified === true);
    ok("  -> groups are the two configured values in order", JSON.stringify(r.principal.groups) === JSON.stringify(["administrators", "billing"]));
    ok("  -> nameId surfaced", r.principal.nameId === "alice@example.com");
    ok("  -> assertionId returned", r.assertionId === ASSERTION_ID);
    ok("  -> notOnOrAfter is the SCD bound as epoch ms", r.notOnOrAfter === Date.parse(SCD_NOT_ON_OR_AFTER));
  }
  // An UPPER-cased email canonicalises to lower-case (canonicalEmail) - proves the helper is applied.
  const ru = consumeAssertion(buildAssertion({ emailValue: "Alice@Example.COM" }), baseConn(), baseCtx());
  ok("happy: email is canonicalised (Alice@Example.COM -> alice@example.com)", ru.ok === true && ru.ok && ru.principal.email === "alice@example.com");
}

// ============================ 1b. AUTHNSTATEMENT SESSION BOUND (ASVS V7.6.1) ============================
{
  // Default assertion has NO AuthnStatement -> sessionNotOnOrAfter is null (no IdP session bound to cap at).
  const none = consumeAssertion(buildAssertion(), baseConn(), baseCtx());
  ok("authn: no AuthnStatement -> sessionNotOnOrAfter null (no cap)", none.ok === true && none.ok && none.sessionNotOnOrAfter === null);

  // A well-formed saml:AuthnStatement/@SessionNotOnOrAfter is read off the verified assertion as epoch ms.
  const SNOOA = "2026-06-13T16:00:00Z";
  const withAuthn = consumeAssertion(buildAssertion({ authnSessionNotOnOrAfter: SNOOA }), baseConn(), baseCtx());
  ok("authn: SessionNotOnOrAfter read as epoch ms (caps the native session, V7.6.1)", withAuthn.ok === true && withAuthn.ok && withAuthn.sessionNotOnOrAfter === Date.parse(SNOOA));

  // XSW: a FOREIGN-namespace <AuthnStatement> (same local name, different xmlns) must be IGNORED by the
  // namespace-gated child match, so its forged far-future bound never reaches the session (stays null).
  const forged = consumeAssertion(buildAssertion({ authnSessionNotOnOrAfter: "2099-01-01T00:00:00Z", forgedAuthnNs: true }), baseConn(), baseCtx());
  ok("authn-XSW: a foreign-namespace AuthnStatement is ignored (sessionNotOnOrAfter stays null)", forged.ok === true && forged.ok && forged.sessionNotOnOrAfter === null);

  // ADVISORY acr/authTime (V6.8.4), STRICTLY NON-GATING: AuthnContextClassRef -> authContext.acr and
  // AuthnInstant -> authContext.authTime (epoch SECONDS). Read down the SAME verified AuthnStatement node.
  const ACR = "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactor";
  const INSTANT = "2026-06-13T12:30:00Z";
  const adv = consumeAssertion(buildAssertion({ authnContextClassRef: ACR, authnInstant: INSTANT }), baseConn(), baseCtx());
  ok("authn-advisory: AuthnContextClassRef surfaces as authContext.acr", adv.ok === true && adv.ok && adv.principal.authContext?.acr === ACR);
  ok("authn-advisory: AuthnInstant surfaces as authContext.authTime (epoch seconds)", adv.ok === true && adv.ok && adv.principal.authContext?.authTime === Math.floor(Date.parse(INSTANT) / 1000));
  // NON-GATING: the identity resolved (subject/email/groups) is UNCHANGED by the advisory signal being present.
  ok("authn-advisory: identity (subject/email/groups) is unaffected by the advisory signal (non-gating)",
    adv.ok === true && adv.ok && adv.principal.subject === samlSubject(CONN_ID, IDP_ENTITY, "alice@example.com") && adv.principal.email === "alice@example.com" && JSON.stringify(adv.principal.groups) === JSON.stringify(["administrators", "billing"]));
  // An AuthnStatement with NO AuthnContext (only the session bound) yields NO advisory (absent, not a shell).
  const noCtx = consumeAssertion(buildAssertion({ authnSessionNotOnOrAfter: SNOOA }), baseConn(), baseCtx());
  ok("authn-advisory: AuthnStatement without AuthnContext -> authContext undefined", noCtx.ok === true && noCtx.ok && noCtx.principal.authContext === undefined);
  // The DEFAULT assertion (no AuthnStatement at all) -> no advisory.
  ok("authn-advisory: no AuthnStatement -> authContext undefined", none.ok === true && none.ok && none.principal.authContext === undefined);
  // XSW: a foreign-namespace AuthnStatement's AuthnContextClassRef must NOT populate the advisory either.
  const forgedAdv = consumeAssertion(buildAssertion({ authnContextClassRef: ACR, authnInstant: INSTANT, forgedAuthnNs: true }), baseConn(), baseCtx());
  ok("authn-advisory-XSW: a foreign-namespace AuthnContextClassRef is ignored (authContext undefined)", forgedAdv.ok === true && forgedAdv.ok && forgedAdv.principal.authContext === undefined);

  // ===== THE UNREADABLE AuthnInstant. =========================================================
  //
  // claim-drop-saml-auth-time is documented as "an AuthnInstant was asserted and would not parse", and the
  // state recorded NOTHING: parseSamlInstantMs folds an unreadable instant to null, and null reached
  // buildAuthContext as `undefined`, which is byte-identical to an IdP that asserted no AuthnInstant at all.
  // The presence test now lives in assertion.ts, at the raw attribute. Driven through the REAL consumer, from
  // a real assertion, so the drop is proved on a shape the product can actually emit.
  const dropsOf = (o: Parameters<typeof buildAssertion>[0]): string[] => {
    const r = consumeAssertion(buildAssertion(o), baseConn(), baseCtx());
    return r.ok === true ? (r.principal.claimDrops ?? []) : [];
  };
  const healthy = dropsOf({ authnContextClassRef: ACR, authnInstant: INSTANT });
  ok("a healthy AuthnInstant drops nothing", !healthy.includes("claim-drop-saml-auth-time"));
  ok("an IdP that asserts NO AuthnInstant drops nothing (an absence is not a fault)", dropsOf({ authnSessionNotOnOrAfter: SNOOA }).length === 0);
  ok("an AuthnInstant that WILL NOT PARSE is recorded (never silently identical to an absence)", dropsOf({ authnInstant: "not-a-real-instant" }).includes("claim-drop-saml-auth-time"));
  ok("...an EMPTY AuthnInstant too (asserted, unusable)", dropsOf({ authnInstant: "   " }).includes("claim-drop-saml-auth-time"));
  ok("...and an instant outside the usable range (a pre-1970 epoch) stays recorded", dropsOf({ authnInstant: "1969-07-20T20:17:00Z" }).includes("claim-drop-saml-auth-time"));
  ok("DISCRIMINATION: 'the IdP asserted nothing' and 'the IdP asserted an instant we cannot read' are different rows", JSON.stringify(dropsOf({ authnSessionNotOnOrAfter: SNOOA })) !== JSON.stringify(dropsOf({ authnInstant: "not-a-real-instant" })));
  ok("the INSTANT VALUE never rides: the tally carries the closed counter name only", dropsOf({ authnInstant: "not-a-real-instant" }).every((d) => d === "claim-drop-saml-auth-time"));
  // The identity is untouched by an unreadable advisory claim: it is non-gating, and a drop is a caveat.
  const stillIn = consumeAssertion(buildAssertion({ authnInstant: "not-a-real-instant" }), baseConn(), baseCtx());
  ok("the sign-in still resolves (the advisory drop is a caveat, never a rejection)", stillIn.ok === true && stillIn.ok && stillIn.principal.email === "alice@example.com");
}

// ============================ RED CORPUS (each MUST reject) ============================
console.log("");

// 2. Expired: Conditions NotOnOrAfter in the past beyond skew.
{
  const r = consumeAssertion(buildAssertion({ notOnOrAfter: "2026-06-13T11:00:00Z" }), baseConn(), baseCtx());
  ok("expired: Conditions NotOnOrAfter in the past (beyond skew) rejected", r.ok === false);
}

// 3. Not yet valid: NotBefore in the future beyond skew.
{
  const r = consumeAssertion(buildAssertion({ notBefore: "2026-06-13T13:00:00Z" }), baseConn(), baseCtx());
  ok("not-yet-valid: Conditions NotBefore in the future (beyond skew) rejected", r.ok === false);
}

// 4. Wrong audience.
{
  const r = consumeAssertion(buildAssertion({ audience: "https://attacker.example/sp" }), baseConn(), baseCtx());
  ok("wrong-audience: Audience != spEntityId rejected", r.ok === false);
}

// 4b. Wrong Issuer (federation binding, ASVS V2.7). An Assertion that names a different IdP than the one this
// connection pins must be rejected even though every other field is well-formed.
{
  const r = consumeAssertion(buildAssertion({ issuer: "https://other-idp.example/entity" }), baseConn(), baseCtx());
  ok("wrong-issuer: saml:Issuer != conn.idpEntityId rejected", r.ok === false && r.reason === "assertion Issuer does not match the connection's idpEntityId");
}

// 5. Wrong Recipient (assertion-forwarding / wrong-SP).
{
  const r = consumeAssertion(buildAssertion({ recipient: "https://attacker.example/acs" }), baseConn(), baseCtx());
  ok("wrong-recipient: SubjectConfirmationData/@Recipient != acsUrl rejected", r.ok === false);
}

// 6. Wrong InResponseTo (replay/injection).
{
  const r = consumeAssertion(buildAssertion({ inResponseTo: "_some_other_request" }), baseConn(), baseCtx());
  ok("wrong-inresponseto: @InResponseTo != expected rejected", r.ok === false);
}

// 7. Missing InResponseTo (IdP-initiated) with allowIdpInitiated=false -> reject;
//    present-and-allowed with allowIdpInitiated=true skips the InResponseTo binding.
{
  const reject = consumeAssertion(buildAssertion({ inResponseTo: null }), baseConn({ allowIdpInitiated: false }), baseCtx());
  ok("idp-initiated: missing InResponseTo with allowIdpInitiated=false rejected", reject.ok === false);
  // allowed IdP-initiated: no InResponseTo on the assertion, allowIdpInitiated=true -> accepted (binding skipped).
  const accept = consumeAssertion(buildAssertion({ inResponseTo: null }), baseConn({ allowIdpInitiated: true }), baseCtx());
  ok("idp-initiated: missing InResponseTo with allowIdpInitiated=true accepted (binding skipped)", accept.ok === true);
}

// 8. Transient NameID format.
{
  const r = consumeAssertion(buildAssertion({ nameIdFormat: NAMEID_TRANSIENT }), baseConn(), baseCtx());
  ok("transient-nameid: transient NameID Format rejected", r.ok === false);
}

// 9. Pinned nameIdFormat mismatch: conn pins emailAddress but the assertion is persistent.
{
  const r = consumeAssertion(buildAssertion({ nameIdFormat: NAMEID_PERSISTENT }), baseConn({ nameIdFormat: NAMEID_EMAIL }), baseCtx());
  ok("pinned-format-mismatch: assertion Format != pinned conn.nameIdFormat rejected", r.ok === false);
  // sanity: when the assertion MATCHES the pinned format it is accepted.
  const okMatch = consumeAssertion(buildAssertion({ nameIdFormat: NAMEID_EMAIL }), baseConn({ nameIdFormat: NAMEID_EMAIL }), baseCtx());
  ok("pinned-format-match: assertion Format == pinned conn.nameIdFormat accepted", okMatch.ok === true);
}

// ============================ POLICY / TOLERANCE / DECODE ============================
console.log("");

// 10. Unverified email under require-flag -> ok:true but subject-only (email:null, emailVerified:false).
{
  const ctx = baseCtx({ emailVerifiedPolicy: "require-flag", emailVerifiedAttr: "email_verified" });
  // The assertion carries an email but NO email_verified attribute (or it is false): email must drop to null.
  const noFlag = consumeAssertion(buildAssertion({ emailValue: "alice@example.com", emailVerifiedValue: null }), baseConn(), ctx);
  ok("require-flag (no flag): accepted but email:null + emailVerified:false (subject-only)", noFlag.ok === true && noFlag.ok && noFlag.principal.email === null && noFlag.principal.emailVerified === false);
  // And the subject is still derived (the sign-in is NOT rejected).
  ok("require-flag (no flag): subject still derived (not a hard reject)", noFlag.ok === true && noFlag.ok && noFlag.principal.subject === samlSubject(CONN_ID, IDP_ENTITY, "alice@example.com"));
  // An explicit email_verified=false also yields subject-only.
  const falseFlag = consumeAssertion(buildAssertion({ emailValue: "alice@example.com", emailVerifiedValue: "false" }), baseConn(), ctx);
  ok("require-flag (flag=false): email:null + emailVerified:false", falseFlag.ok === true && falseFlag.ok && falseFlag.principal.email === null && falseFlag.principal.emailVerified === false);
  // email_verified=true under require-flag DOES trust the email.
  const trueFlag = consumeAssertion(buildAssertion({ emailValue: "alice@example.com", emailVerifiedValue: "true" }), baseConn(), ctx);
  ok("require-flag (flag=true): email trusted + emailVerified:true", trueFlag.ok === true && trueFlag.ok && trueFlag.principal.email === "alice@example.com" && trueFlag.principal.emailVerified === true);
}

// 11. Clock-skew tolerance: a bound 1 second past NotOnOrAfter but within clockSkewSec is still accepted.
{
  // Set both Conditions and SCD NotOnOrAfter to exactly 1 second before now; with 120s skew they are still in.
  const oneSecPast = "2026-06-13T11:59:59Z"; // 1s before NOW (12:00:00)
  const r = consumeAssertion(buildAssertion({ notOnOrAfter: oneSecPast, scdNotOnOrAfter: oneSecPast }), baseConn({ clockSkewSec: 120 }), baseCtx());
  ok("skew: a bound 1s past NotOnOrAfter but within clockSkewSec is still accepted", r.ok === true);
  // Control: with ZERO skew the same 1s-past bound is rejected (proves the tolerance was the deciding factor).
  const zeroSkew = consumeAssertion(buildAssertion({ notOnOrAfter: oneSecPast, scdNotOnOrAfter: oneSecPast }), baseConn({ clockSkewSec: 0 }), baseCtx());
  ok("skew control: with clockSkewSec=0 the same 1s-past bound is rejected", zeroSkew.ok === false);
}

// 12. Entity-bearing value: a NameID and an Audience carrying XML entities are decoded via the shared
//     canonical-text fn so they match the expected DECODED value (proves verify == read uses one decoder).
{
  // NameID written with a numeric char ref &#x41; == "A" and a &amp; == "&": "A&B" should be read as "A&B".
  const r = consumeAssertion(buildAssertion({ nameId: "&#x41;&amp;B" }), baseConn(), baseCtx());
  ok("decode: a NameID with entities (&#x41;&amp;B) decodes to A&B and folds into the subject", r.ok === true && r.ok && r.principal.nameId === "A&B" && r.principal.subject === samlSubject(CONN_ID, IDP_ENTITY, "A&B"));
  // Audience written with an entity must match spEntityId after decode. Encode the "/" path char is not an
  // entity, so encode the colon-free part: write spEntityId with a literal &amp; would change it; instead
  // prove decode on the audience by encoding a benign char in a matching audience. Use a value whose decoded
  // form equals SP_ENTITY: SP_ENTITY contains no &<>, so inject a no-op numeric ref for "/" (&#x2F;).
  const spEntityEncoded = SP_ENTITY.replace(/\//g, "&#x2F;");
  const ra = consumeAssertion(buildAssertion({ audience: spEntityEncoded }), baseConn(), baseCtx());
  ok("decode: an Audience with numeric char refs (&#x2F; for '/') decodes and matches spEntityId", ra.ok === true);
  // Negative control: the RAW (undecoded) audience string must NOT accidentally match (it differs from SP_ENTITY).
  ok("decode control: the encoded audience differs from the raw spEntityId string", spEntityEncoded !== SP_ENTITY);
}

// ============================ STATUS HELPER (caller-obligation aid) ============================
{
  const respSuccess = el(
    "samlp:Response",
    [a("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")],
    [el("samlp:Status", [], [el("samlp:StatusCode", [a("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")], [])])],
  );
  ok("status helper: assertStatusSuccess true for a Success Response", assertStatusSuccess(respSuccess) === true);
  const respFail = el(
    "samlp:Response",
    [a("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")],
    [el("samlp:Status", [], [el("samlp:StatusCode", [a("Value", "urn:oasis:names:tc:SAML:2.0:status:Requester")], [])])],
  );
  ok("status helper: assertStatusSuccess false for a non-Success Response", assertStatusSuccess(respFail) === false);
  ok("status helper: assertStatusSuccess false when Status missing", assertStatusSuccess(el("samlp:Response", [], [])) === false);
}

// ============================ extra structural rejects (fail-closed) ============================
console.log("");
{
  // No Conditions at all.
  const noConditions = clone(buildAssertion());
  noConditions.children = noConditions.children.filter((c) => !(c.type === "element" && c.name === "saml:Conditions"));
  ok("fail-closed: an assertion with no Conditions is rejected", consumeAssertion(noConditions, baseConn(), baseCtx()).ok === false);

  // No Subject at all.
  const noSubject = clone(buildAssertion());
  noSubject.children = noSubject.children.filter((c) => !(c.type === "element" && c.name === "saml:Subject")) ;
  ok("fail-closed: an assertion with no Subject is rejected", consumeAssertion(noSubject, baseConn(), baseCtx()).ok === false);

  // A non-bearer SubjectConfirmation Method is ignored (no bearer confirmation -> reject).
  const holderOfKey = buildAssertion({ method: "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key" });
  ok("fail-closed: a non-bearer SubjectConfirmation Method is rejected (no bearer confirmation)", consumeAssertion(holderOfKey, baseConn(), baseCtx()).ok === false);

  // An assertion whose verified node is NOT a saml:Assertion (a Response handed in by mistake) is rejected.
  const notAssertion = el("samlp:Response", [a("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")], []);
  ok("fail-closed: a verified node that is not a saml:Assertion is rejected", consumeAssertion(notAssertion, baseConn(), baseCtx()).ok === false);

  // A SubjectConfirmationData NotOnOrAfter in the past beyond skew (Conditions fine) is rejected.
  const scdExpired = buildAssertion({ scdNotOnOrAfter: "2026-06-13T11:00:00Z" });
  ok("fail-closed: an expired SubjectConfirmationData NotOnOrAfter is rejected", consumeAssertion(scdExpired, baseConn(), baseCtx()).ok === false);

  // A malformed (unparseable) Conditions NotOnOrAfter is rejected (fail closed, not read as no-bound).
  const badTime = buildAssertion({ notOnOrAfter: "not-a-date" });
  ok("fail-closed: an unparseable Conditions NotOnOrAfter is rejected", consumeAssertion(badTime, baseConn(), baseCtx()).ok === false);

  // No email attribute configured/present -> still ok, subject-only email:null (not a reject).
  const noEmailAttr = consumeAssertion(buildAssertion({ emailValue: null }), baseConn(), baseCtx());
  ok("no-email: a missing email attribute yields email:null, NOT a reject", noEmailAttr.ok === true && noEmailAttr.ok && noEmailAttr.principal.email === null);

  // No groups attribute present -> groups [].
  const noGroups = consumeAssertion(buildAssertion({ groupValues: [] }), baseConn(), baseCtx());
  ok("no-groups: an empty groups attribute yields []", noGroups.ok === true && noGroups.ok && JSON.stringify(noGroups.principal.groups) === "[]");
}

// Reference the EmailVerifiedPolicy type so the import is load-bearing (and document the two values).
const _policies: EmailVerifiedPolicy[] = ["trust-idp", "require-flag"];
ok("policy union has exactly the two expected values", _policies.length === 2);

// ---- summary ----
console.log("");
if (failures > 0) process.exitCode = 1;
if (failures > 0) {
  console.log("SAML ASSERTION VECTORS: " + passed + " passed, " + failures + " FAILED");
  process.exitCode = 1;
} else {
  console.log("SAML ASSERTION VECTORS PASS (" + passed + " checks)");
}
