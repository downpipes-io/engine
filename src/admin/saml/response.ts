// THE security-critical SAML Assertion Consumer Service (ACS) verifier: the ONE place the native SAML 2.0
// Service Provider ties the hardened parser -> the XML-DSig verifier -> the assertion consumer together in the
// correct order, fail-closed at every step. A mistake here is a SILENT SAML authentication bypass, so this
// module does the minimum, in a fixed order, and returns an error-as-value at the first failure - it NEVER
// throws out of verifySamlResponse.
//
// The SP is SIGN-ONLY (no EncryptedAssertion in v1), SP-INITIATED by default (allowIdpInitiated is an explicit
// owner opt-in), and PINS the IdP signing certs (conn.idpSigningCerts): the assertion's own ds:KeyInfo is
// IGNORED entirely (dsig.ts never reads it). The pipeline, in order:
//   1. base64-decode the raw SAMLResponse POST value (standard base64) to bytes - reject non-base64 / oversized.
//      RelayState is NEVER decoded here (it is opaque round-trip state, handled by the caller).
//   2. parseXml(bytes) - the hardened parser's raw-byte gates fire (no DTD, single root, no entity expansion).
//   3. the root MUST be a samlp:Response (local name "Response" in the SAML PROTOCOL namespace); locate EXACTLY
//      ONE saml:Assertion child. An EncryptedAssertion is out of scope and rejected with a clear reason; more
//      than one Assertion is an XML-Signature-Wrapping smell and rejected.
//   4. Status: assertStatusSuccess(response) MUST be true (no oracle detail in the reason).
//   5. Response-level binds (defence in depth; the assertion-level Recipient/InResponseTo are RE-checked inside
//      consumeAssertion): @Destination (decoded) MUST equal ctx.acsUrl when present; @InResponseTo MUST equal
//      ctx.expectedInResponseTo when present; and when conn.allowIdpInitiated is false an assertion with NO
//      InResponseTo anywhere on the Response is rejected (IdP-initiated denied).
//   6. extract the verifying KEY (SubjectPublicKeyInfo / SPKI) from EACH pinned PEM cert by a minimal DER walk
//      (rollover: any current cert is acceptable).
//   7. verifyXmlSignature(assertion, spki, { idAttribute:"ID", requireReferenceIsTarget:true }) for each pinned
//      cert until one returns ok - the signature MUST be the ENVELOPED signature whose Reference covers EXACTLY
//      the located Assertion (wantAssertionsSigned). Claims are then consumed ONLY from the VERIFIED node dsig
//      returns, never the pre-verify tree.
//   8. consumeAssertion(verifiedAssertion, conn, ctx-derived) - return its principal on ok, else its reason.
//
// Node 25 strip-types + Workers compatible: Web Crypto (via dsig) + the shared helpers only, no DOM, no Node
// builtins, no enums, explicit fields, error-as-value. Australian English; no em dashes.

import type { SamlConnection } from "../idpconn.ts";
import type { SamlPrincipal } from "./assertion.ts";
import { assertStatusSuccess, consumeAssertion, samlStatusClass } from "./assertion.ts";
import { decodeXmlText } from "./canonical-text.ts";
import { verifyXmlSignature } from "./dsig.ts";
import type { ParseLimits } from "./parser.ts";
import { parseXml } from "./parser.ts";
// The standard-base64 decoder + the X.509/DER certificate extractors live in response-cert.ts (a sibling
// split out so each module stays a coherent unit under 500 lines). decodeBase64Std is used below to decode
// the SAMLResponse POST value; pemToSpki/certValidity drive the pinned-cert verify path. pemToSpki,
// PemToSpkiResult, certNotAfter, certValidity and CertValidity are RE-EXPORTED here so every existing
// importer of response.ts (idp-test.ts, scheduler-do.ts) keeps working unchanged.
import { certValidity, decodeBase64Std, pemToSpki } from "./response-cert.ts";
import type { XmlElement } from "./xml-node.ts";
import { isElement, localName } from "./xml-node.ts";

export type { CertValidity, PemToSpkiResult } from "./response-cert.ts";
export { certNotAfter, certValidity, pemToSpki } from "./response-cert.ts";

// G053: the pinned-cert health ledger. This module is PURE (no env, no DO stub, no network -- deliberately: it
// is the security core), so it cannot persist its own observation. It NOTES the already-computed counts,
// booleans and closed key classes in an isolate-local slot, and the DO's ACS wrapper drains them one line after
// it calls us. No PEM, SPKI, subject, issuer, parse reason or connId is ever passed across that boundary.
import { classifyCertKeyClass, type IdpCurveClass, noteIdpCertObservation } from "../idp-cert-health.ts";
// G316: the attack-shape ledger. Recorded AT the refusal site, which knows the shape; never inferred from the
// reason text (which interpolates attacker-chosen XML) by a classifier whose ordering could misroute it.
import { noteSamlSignal } from "../saml-signals.ts";

// ---- SAML constant URIs (string-exact; anything not listed is treated as not-that-thing) ----
const SAML_PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
const SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

// A SAML Response POST body is small (an HTTP-form-posted, base64-encoded XML document). The base64 STRING cap
// bounds a hostile paste before we even decode it; the decoded bytes are then bounded again by the parser's own
// maxBytes (default 1 MiB). 4/3 of a megabyte of base64 is ~1.34 MB of text; we cap the base64 input at 2 MB so
// the decode itself cannot be turned into a memory-exhaustion lever, and let the parser's byte cap govern the
// decoded size.
const SAML_RESPONSE_B64_MAX = 2_000_000;

// VerifyContext is the request-scoped, INJECTED input. NOTHING here is read from the network or the clock by
// this module: the caller (the ACS HTTP handler) resolves all of it and passes it in. acsUrl is OUR configured
// Assertion Consumer Service URL (NEVER req.url - an attacker controls req.url's host via Host/X-Forwarded-*
// headers, so trusting it would defeat the wrong-SP defence). expectedInResponseTo is the id of the AuthnRequest
// WE sent and stored (samlreq:<connId>:<id>). nowMs is the injected clock as epoch milliseconds (tests pass a
// fixed value; this module performs no time comparison itself, it only forwards nowMs to consumeAssertion).
export interface VerifyContext {
  acsUrl: string;
  expectedInResponseTo: string;
  nowMs: number;
}

// VerifyResult is the error-as-value the ACS handler maps to a session (ok) or a 4xx (the reason is for logs;
// it carries no decryption/padding oracle detail, only which gate failed).
export type VerifyResult = { ok: true; principal: SamlPrincipal; assertionId: string; notOnOrAfter: number; sessionNotOnOrAfter: number | null } | { ok: false; reason: string };

function fail(reason: string): { ok: false; reason: string } {
  return { ok: false, reason };
}

// ---- namespace resolution for the load-bearing elements (Response, Assertion, EncryptedAssertion) ----
// We match by LOCAL name AND namespace URI, never by a hard-coded prefix: an IdP may emit samlp:, saml2p:, or a
// default namespace, and an attacker gains nothing by renaming a prefix. ownXmlnsBindings reads the xmlns /
// xmlns:prefix declarations on an element (decoded, since a hostile document could entity-encode them).
function ownXmlnsBindings(el: XmlElement): Map<string, string> {
  const m = new Map<string, string>();
  for (const a of el.attrs) {
    if (a.name === "xmlns") m.set("", decodeXmlText(a.value));
    else if (a.name.startsWith("xmlns:")) m.set(a.name.slice("xmlns:".length), decodeXmlText(a.value));
  }
  return m;
}

// resolveNamespace returns the effective namespace URI of `el` given the bindings inherited from its ancestors
// (inherited), applying el's own declarations first (nearer wins). Returns null when the prefix is unbound.
function resolveNamespace(el: XmlElement, inherited: Map<string, string>): string | null {
  const i = el.name.indexOf(":");
  const prefix = i === -1 ? "" : el.name.slice(0, i);
  const own = ownXmlnsBindings(el);
  if (own.has(prefix)) return own.get(prefix)!;
  if (inherited.has(prefix)) return inherited.get(prefix)!;
  return null;
}

// mergeInherited returns a new map = inherited overlaid with el's own xmlns declarations (for descent into
// children, so a child that does not re-declare the namespace is still resolved against an ancestor binding).
function mergeInherited(el: XmlElement, inherited: Map<string, string>): Map<string, string> {
  const next = new Map(inherited);
  for (const [k, v] of ownXmlnsBindings(el)) next.set(k, v);
  return next;
}

// decAttr reads an attribute and decodes it through the SHARED entity decoder, so a Response-level @Destination
// / @InResponseTo is compared as the value the IdP wrote (the verify == read discipline, mirroring assertion.ts).
// Returns null when the attribute is absent.
function decAttr(el: XmlElement, name: string): string | null {
  for (const a of el.attrs) {
    if (a.name === name) return decodeXmlText(a.value);
  }
  return null;
}

// ---- direct-child helpers over the parser-agnostic XmlElement ----
// directChildrenInNs returns the direct ELEMENT children of `el` with the given local name that resolve to
// `wantNs` in the namespace scope `inScope` (el's own + inherited bindings). Matching the whole-document
// children by namespace is the structural defence: a same-local-name element in a DIFFERENT namespace cannot be
// mistaken for the SAML one.
function directChildrenInNs(el: XmlElement, local: string, wantNs: string, inScope: Map<string, string>): XmlElement[] {
  const out: XmlElement[] = [];
  for (const c of el.children) {
    if (!isElement(c)) continue;
    if (localName(c.name) !== local) continue;
    if (resolveNamespace(c, inScope) === wantNs) out.push(c);
  }
  return out;
}

// ---- the ACS verifier ----
export async function verifySamlResponse(
  samlResponseB64: string,
  conn: SamlConnection,
  ctx: VerifyContext,
  parseLimits?: ParseLimits,
): Promise<VerifyResult> {
  // ===== 1. base64-decode the raw SAMLResponse POST value (standard base64) to bytes =====
  if (typeof samlResponseB64 !== "string" || samlResponseB64.length === 0) {
    return fail("SAMLResponse is missing");
  }
  if (samlResponseB64.length > SAML_RESPONSE_B64_MAX) {
    return fail("SAMLResponse exceeds the maximum size");
  }
  const decoded = decodeBase64Std(samlResponseB64);
  if (!decoded.ok) return fail("SAMLResponse is not valid base64");
  const bytes = decoded.bytes;

  // ===== 2. parse the XML through the hardened, raw-byte-gated parser =====
  const parsed = parseXml(bytes, parseLimits);
  if (!parsed.ok) return fail(`SAMLResponse XML is malformed: ${parsed.reason}`);
  const responseRoot = parsed.root;

  // ===== 3. the root MUST be a samlp:Response; locate EXACTLY ONE saml:Assertion child =====
  const rootScope = ownXmlnsBindings(responseRoot);
  // The document root has no ancestor namespace scope, so the inherited map passed here is empty; the root's
  // own bindings are all that can resolve its namespace.
  if (localName(responseRoot.name) !== "Response" || resolveNamespace(responseRoot, new Map()) !== SAML_PROTOCOL_NS) {
    return fail("root element is not a samlp:Response");
  }
  const inResponse = mergeInherited(responseRoot, rootScope); // bindings in scope for the Response's children

  // EncryptedAssertion is explicitly OUT OF SCOPE for this build (sign-only, no decryption). Reject it clearly
  // (BEFORE looking for a plaintext Assertion) so a deployment that points an encrypting IdP at us gets a
  // precise message rather than a confusing "no Assertion".
  const encrypted = directChildrenInNs(responseRoot, "EncryptedAssertion", SAML_ASSERTION_NS, inResponse);
  if (encrypted.length > 0) return fail("encrypted assertions not supported in this build");

  // Exactly one saml:Assertion. Zero -> nothing to consume (a non-Success Response usually carries none, but we
  // check Status next regardless). More than one -> an XML-Signature-Wrapping smell (a second Assertion is how
  // an attacker smuggles an unsigned principal alongside a signed one); reject outright.
  const assertions = directChildrenInNs(responseRoot, "Assertion", SAML_ASSERTION_NS, inResponse);
  if (assertions.length === 0) {
    // A DECLINED sign-in is exactly the case that carries no Assertion (the IdP refused the user, so it minted
    // none). Check Status FIRST when there is no assertion, so the decline is distinguishable from a malformed
    // response (an unassigned enterprise app, a blocked account, an MFA the user would not complete). A Success
    // response with no assertion keeps its exact original reason.
    if (!assertStatusSuccess(responseRoot)) return fail(`SAML Response status is not Success [saml-status:${samlStatusClass(responseRoot)}]`);
    return fail("Response carries no saml:Assertion");
  }
  if (assertions.length > 1) {
    // G316: a second Assertion beside the signed one is the textbook XSW envelope. Recorded at the site (which
    // KNOWS the shape) rather than inferred from the reason text, so no classifier ordering rule can misroute it.
    noteSamlSignal("saml-shape-xsw-multi-assertion");
    return fail("Response carries more than one saml:Assertion (rejected: XML-Signature-Wrapping)");
  }
  const assertion = assertions[0]!;

  // ===== 4. Status MUST be Success (no oracle detail in the reason) =====
  // The refusal carries the CLOSED class of the IdP's own StatusCode (samlStatusClass: one of responder /
  // requester / authnfailed / nopassive / other, derived ONLY from the fixed spec URIs, never from the
  // free-prose StatusMessage). This is the field that distinguishes "the IdP DECLINED this user" (an unassigned
  // enterprise app, a blocked account, a refused MFA) from an IdP-side outage. The mark is a closed token; the
  // client-facing redirect stays generic, so no detail is oracled back to the caller.
  if (!assertStatusSuccess(responseRoot)) return fail(`SAML Response status is not Success [saml-status:${samlStatusClass(responseRoot)}]`);

  // ===== 5. Response-level binds (defence in depth; assertion-level re-checked inside consumeAssertion) =====
  // @Destination, when present, MUST equal ctx.acsUrl (the wrong-SP / response-forwarding defence at the
  // envelope). An ABSENT Destination is permitted at this level (the per-assertion @Recipient binding inside
  // consumeAssertion is the stronger, always-required check).
  const destination = decAttr(responseRoot, "Destination");
  if (destination !== null && destination !== ctx.acsUrl) {
    return fail("Response @Destination does not match our ACS URL");
  }

  // @InResponseTo (SP-initiated): when PRESENT it MUST equal ctx.expectedInResponseTo exactly (the
  // anti-injection binding). When ABSENT the Response is IdP-initiated; reject unless conn.allowIdpInitiated.
  const inResponseTo = decAttr(responseRoot, "InResponseTo");
  if (inResponseTo !== null) {
    if (inResponseTo !== ctx.expectedInResponseTo) return fail("Response @InResponseTo does not match the request we sent");
  } else if (!conn.allowIdpInitiated) {
    // No InResponseTo anywhere on the Response envelope, and IdP-initiated is not allowed -> reject. (The
    // assertion-level InResponseTo is also re-checked under allowIdpInitiated inside consumeAssertion; this is
    // the envelope-level instance of the same gate.)
    return fail("IdP-initiated SAML Response is not permitted for this connection");
  }

  // ===== 6 + 7. extract each pinned cert's SPKI and verify the SIGNATURE; consume the VERIFIED Assertion =====
  // Rollover: ANY current pinned cert verifying the signature is acceptance. The "signed" requirement is met by
  // EITHER an assertion-level signature OR a Response-level (envelope) signature - never by a wrapping that lets
  // an attacker-chosen assertion ride a signature over different content.
  //
  // We try the ASSERTION-level signature first (the historical default, and Shibboleth/some configs): we hand
  // verifyXmlSignature the located Assertion node and require the Reference to cover EXACTLY that node
  // (requireReferenceIsTarget), so the signature must be the enveloped Assertion signature (wantAssertionsSigned)
  // and a wrapped/sibling signed element can never stand in for the Assertion we are about to consume. We take
  // the VERIFIED node dsig returns and consume claims ONLY from it.
  //
  // If no assertion-level signature verifies, we try a RESPONSE-level signature (Okta / Entra / OneLogin default:
  // they sign the samlp:Response element, not the inner Assertion). See the binding rule documented at that step.
  if (conn.idpSigningCerts.length === 0) return fail("connection has no pinned IdP signing certificate");

  // Pre-extract each pinned cert's SPKI and validity window once. A malformed PEM is remembered but skipped
  // (rollover may carry a good one); the window is best-effort (an unreadable window means "not enforced",
  // fail-open on the freshness check only - never on the signature). The clock-skew tolerance reuses the
  // connection's configured clockSkewSec, the SAME tolerance applied to the assertion's own time bounds.
  interface UsableCert { spki: Uint8Array; validity: { notBefore: number; notAfter: number } | undefined }
  const usableCerts: UsableCert[] = [];
  let parseReason = "no usable pinned certificate";
  // The health of the pinned set, computed from the values this loop already has. A corrupt certificate pasted
  // during a rollover can otherwise sit unnoticed until the good one lapses. These are counts, booleans and
  // closed key classes ONLY: the PEM, the SPKI bytes, the subject and the parse reason never cross into the
  // ledger.
  const curves: IdpCurveClass[] = [];
  let windowReadableCount = 0;
  let nearestNotAfter: number | null = null;
  for (const pem of conn.idpSigningCerts) {
    const spkiRes = pemToSpki(pem);
    if (!spkiRes.ok) {
      parseReason = `pinned certificate could not be parsed: ${spkiRes.reason}`;
      continue;
    }
    const cv = certValidity(pem);
    // The key class is derived from the SPKI's PUBLIC algorithm OID: this is what names the P-521 (or Ed25519)
    // certificate whose every sign-in dies inside crypto.subtle.importKey with a message nobody can read.
    curves.push(classifyCertKeyClass(spkiRes.spki));
    if (cv !== null) {
      windowReadableCount++;
      // The SOONEST expiry across the rollover set: "SSO stops working on this date" (and, when the set has
      // only one usable cert because the other was pasted corrupt, that date is the whole outage).
      if (nearestNotAfter === null || cv.notAfter < nearestNotAfter) nearestNotAfter = cv.notAfter;
    }
    usableCerts.push({ spki: spkiRes.spki, validity: cv === null ? undefined : cv });
  }
  noteIdpCertObservation({
    certCount: conn.idpSigningCerts.length,
    parseableCount: usableCerts.length,
    windowReadableCount,
    curves,
    nearestNotAfter,
    // An unreadable window makes dsig.ts skip the IDP-4 freshness check for that cert (fail-OPEN by design, and
    // correct -- a DER quirk must not lock out a working IdP).
    windowUnenforced: usableCerts.some((c) => c.validity === undefined),
    // Every pinned cert failed to parse: this connection cannot verify a single sign-in.
    noUsableCert: usableCerts.length === 0,
  });
  if (usableCerts.length === 0) return fail(parseReason);
  const clockSkewMs = Math.max(0, Math.trunc(conn.clockSkewSec)) * 1000;

  // ----- 7a. ASSERTION-level signature -----
  let verifiedAssertion: XmlElement | null = null;
  let lastSigReason = "no pinned certificate verified the assertion signature";
  for (const c of usableCerts) {
    const v = await verifyXmlSignature(assertion, c.spki, {
      idAttribute: "ID",
      requireReferenceIsTarget: true,
      ...(c.validity !== undefined ? { signingCertValidity: c.validity, nowMs: ctx.nowMs, clockSkewMs } : {}),
    });
    if (v.ok) {
      verifiedAssertion = v.verified;
      break;
    }
    lastSigReason = v.reason;
  }

  // ----- 7b. RESPONSE-level (envelope) signature, when the assertion itself is not signed -----
  // THE ANTI-XSW BINDING RULE (the critical part of IDP-1):
  //   1. We verify the signature over the RESPONSE ROOT itself: verifyXmlSignature(responseRoot, spki,
  //      requireReferenceIsTarget:true). dsig.ts thereby enforces - over the WHOLE Response subtree - that there
  //      is EXACTLY ONE ds:Signature, EXACTLY ONE Reference, the Reference URI resolves (by the unique-ID walk,
  //      so NO duplicate IDs) to a SINGLE element, and (requireReferenceIsTarget) that element is the Response
  //      ROOT. The digest is taken over exc-c14n#(enveloped(Response)), i.e. the ENTIRE Response minus only its
  //      own enveloped Signature. So a Response-level signature cryptographically covers every byte of every
  //      assertion inside it: an attacker cannot add, remove, swap or mutate any assertion without breaking the
  //      Response digest.
  //   2. The assertion we consume is the ALREADY-LOCATED single direct-child saml:Assertion of the Response
  //      (the `assertion` bound at step 3, where we already rejected zero-or-more-than-one direct Assertion).
  //      Because it is a genuine direct child of the VERIFIED Response root (object identity - we never re-locate
  //      it after verifying), it is unambiguously the single assertion covered by the verified Response
  //      signature. A wrapped/injected sibling cannot exist (exactly-one-direct-Assertion) and a nested
  //      decoy assertion is not the direct child we consume and could not have been added without breaking the
  //      Response digest anyway.
  //   3. A signed Response with an UNSIGNED assertion is therefore acceptable ONLY here, where the assertion is
  //      the single direct child unambiguously covered by the Response signature.
  // This never accepts a wrapping that lets an attacker-chosen assertion ride a signature over different content.
  if (verifiedAssertion === null) {
    let responseVerified = false;
    let lastRespReason = lastSigReason;
    for (const c of usableCerts) {
      const v = await verifyXmlSignature(responseRoot, c.spki, {
        idAttribute: "ID",
        requireReferenceIsTarget: true,
        ...(c.validity !== undefined ? { signingCertValidity: c.validity, nowMs: ctx.nowMs, clockSkewMs } : {}),
      });
      if (v.ok && v.verified === responseRoot) {
        responseVerified = true;
        break;
      }
      // A signature that VERIFIED over the WRONG NODE. dsig returned ok, but the element it verified is NOT the
      // Response root we asked it to cover, so a valid signature exists over some other subtree. The guard is
      // correct (we refuse); this is recorded here, at the site that knows it.
      if (v.ok) noteSamlSignal("saml-shape-verified-wrong-target");
      if (!v.ok) lastRespReason = v.reason;
    }
    if (responseVerified) {
      // The Response signature covers the whole Response; the single direct-child assertion is the one it covers.
      verifiedAssertion = assertion;
    } else {
      lastSigReason = lastRespReason;
    }
  }

  if (verifiedAssertion === null) {
    // Neither an assertion-level nor a Response-level signature verified. The reason is for LOGS only (no
    // attacker-usable oracle; a flat rejection to the caller). When the message would otherwise be opaque
    // ("no ds:Signature found", because the assertion carried none and the Response either was not signed or
    // was signed but did not verify), make the failure ACTIONABLE for the operator.
    let reason = lastSigReason;
    if (reason === "no ds:Signature found") {
      reason = "neither the assertion nor the Response carried a verifiable signature (the assertion is unsigned and no accepted Response-level signature verified under a pinned certificate)";
    }
    return fail(`assertion signature did not verify under any pinned certificate: ${reason}`);
  }

  // ===== 8. consume the VERIFIED assertion =====
  // consumeAssertion enforces every non-signature SAML rule (validity window, audience, NameID format, the
  // per-assertion bearer SubjectConfirmation Recipient/InResponseTo/NotOnOrAfter, attributes) against the pinned
  // connection and the injected context. We forward emailVerifiedPolicy from the connection (the committed
  // SamlConnection carries it) and, only when set, emailVerifiedAttr (exactOptionalPropertyTypes: never pass an
  // explicit undefined).
  const result = consumeAssertion(verifiedAssertion, conn, {
    acsUrl: ctx.acsUrl,
    expectedInResponseTo: ctx.expectedInResponseTo,
    nowMs: ctx.nowMs,
    emailVerifiedPolicy: conn.emailVerifiedPolicy,
    ...(conn.emailVerifiedAttr !== undefined ? { emailVerifiedAttr: conn.emailVerifiedAttr } : {}),
  });
  if (!result.ok) return fail(result.reason);
  // assertionId + notOnOrAfter are surfaced so the ACS can enforce a one-time-use assertion cache (replay
  // defence in depth), keyed by the assertion id and pruned at notOnOrAfter.
  return { ok: true, principal: result.principal, assertionId: result.assertionId, notOnOrAfter: result.notOnOrAfter, sessionNotOnOrAfter: result.sessionNotOnOrAfter };
}
