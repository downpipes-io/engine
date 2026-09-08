// IDP-1 group of the real-world-IdP interop corpus: RESPONSE-LEVEL (envelope) signature (Okta / Entra / OneLogin
// default). Split out of validate-saml-interop.ts; the orchestrator imports run() and calls it with the shared
// harness + keys. Every assertion here runs in the original order.

import { verifySamlResponse } from "../src/admin/saml/response.ts";
import type { XmlElement } from "../src/admin/saml/xml-node.ts";
import { samlSubject } from "../src/admin/identity.ts";
import {
  type Harness,
  type Keys,
  ASSERTION_ID,
  CONN_ID,
  EVIL_NAMEID,
  IDP_ENTITY,
  LEGIT_NAMEID,
  a,
  baseConn,
  baseCtx,
  buildAssertion,
  buildResponse,
  encodeResponse,
  signElement,
  signResponse,
  t,
} from "./saml-interop-fixtures.ts";

export async function run(h: Harness, keys: Keys): Promise<void> {
  const { rsa, certPem, rsaAtk } = keys;

  // ========================= IDP-1: RESPONSE-LEVEL (envelope) SIGNATURE =========================
  console.log("IDP-1 Response-level signature (Okta / Entra / OneLogin default):\n");

  // CONTROL: a Response-signed message (signature on the Response, assertion UNSIGNED) now verifies, and the
  // consumed principal is the legit one.
  {
    const unsignedAssertion = buildAssertion();
    const resp = buildResponse([unsignedAssertion]);
    const signedResp = await signResponse(resp, rsa.privateKey);
    const r = await verifySamlResponse(encodeResponse(signedResp), baseConn([certPem]), baseCtx());
    h.ok("IDP-1 CONTROL: a Response-signed message with an unsigned assertion is ACCEPTED", r.ok === true);
    if (r.ok) {
      h.ok("  -> consumed principal is the legit one (covered by the Response signature)", r.principal.subject === samlSubject(CONN_ID, IDP_ENTITY, LEGIT_NAMEID) && r.principal.nameId === LEGIT_NAMEID);
    } else {
      console.log("       (reason: " + r.reason + ")");
    }
  }

  // IDP-1 negative 1: a Response-signed message + a SECOND unsigned sibling assertion. The exactly-one-direct-
  // Assertion rule rejects BEFORE any signature step, so an attacker cannot ride the Response signature with a
  // second assertion.
  {
    const a1 = buildAssertion({ assertionId: "_a1", nameId: LEGIT_NAMEID });
    const evil = buildAssertion({ assertionId: "_evil", nameId: EVIL_NAMEID, email: EVIL_NAMEID });
    const resp = buildResponse([a1, evil]);
    const signedResp = await signResponse(resp, rsa.privateKey);
    const r = await verifySamlResponse(encodeResponse(signedResp), baseConn([certPem]), baseCtx());
    h.ok("IDP-1 neg: Response-signed + a second sibling assertion is rejected (exactly-one-Assertion)", r.ok === false);
  }

  // IDP-1 negative 2: take a VALIDLY Response-signed message and MUTATE the assertion's NameID afterwards. The
  // Response signature covers the whole Response, so the digest no longer matches -> reject. Proves the Response
  // signature genuinely binds the assertion bytes (no swap behind a valid envelope signature).
  {
    const resp = buildResponse([buildAssertion({ nameId: LEGIT_NAMEID })]);
    const signedResp = await signResponse(resp, rsa.privateKey);
    // signedResp children: [Status, ds:Signature, Assertion]. Mutate the assertion's NameID post-signing.
    const assertion = signedResp.children.find((c) => c.type === "element" && c.name === "saml:Assertion") as XmlElement;
    const subject = assertion.children.find((c) => c.type === "element" && c.name === "saml:Subject") as XmlElement;
    const nameIdEl = subject.children.find((c) => c.type === "element" && c.name === "saml:NameID") as XmlElement;
    nameIdEl.children = [t(EVIL_NAMEID)];
    const r = await verifySamlResponse(encodeResponse(signedResp), baseConn([certPem]), baseCtx());
    h.ok("IDP-1 neg: mutating the assertion under a valid Response signature is rejected (Response digest mismatch)", r.ok === false);
  }

  // IDP-1 negative 3: the classic XSW against the envelope path - a forged unsigned assertion in the canonical
  // slot, with a SEPARATELY Response-signed (different) Response's signature spliced in. We model it as: build a
  // legitimately Response-signed message over assertion A, then ADD a second assertion B as a sibling. Already
  // covered by neg 1; here we instead try the WRAPPING shape: the forged assertion WRAPS nothing but the signed
  // Response is over a DIFFERENT response id than the document root. Concretely: sign a Response with id _r1,
  // then change the ROOT Response id to _r2 (so the Reference #_r1 no longer resolves to the root). The
  // requireReferenceIsTarget + unique-ID walk reject (Reference resolves to no element / not the root).
  {
    const resp = buildResponse([buildAssertion()], { responseId: "_r1" });
    const signedResp = await signResponse(resp, rsa.privateKey);
    // Rewrite the root Response ID so the Reference #_r1 dangles.
    signedResp.attrs = signedResp.attrs.map((at) => (at.name === "ID" ? { name: "ID", value: "_r2" } : at));
    const r = await verifySamlResponse(encodeResponse(signedResp), baseConn([certPem]), baseCtx());
    h.ok("IDP-1 neg: a Response signature whose Reference no longer resolves to the root is rejected", r.ok === false);
  }

  // IDP-1 negative 4: Response signed by a NON-pinned (attacker) key -> reject (the pinned cert governs; KeyInfo
  // is ignored just as for the assertion path).
  {
    const resp = buildResponse([buildAssertion()]);
    const signedResp = await signResponse(resp, rsaAtk.privateKey);
    const r = await verifySamlResponse(encodeResponse(signedResp), baseConn([certPem]), baseCtx());
    h.ok("IDP-1 neg: a Response signed by a non-pinned key is rejected", r.ok === false);
  }

  // IDP-1 negative 5: a Response-signed message whose Status is NOT Success still rejects (Status gate runs
  // before the signature step, so the envelope path does not bypass it). We mutate Status post-signing; the
  // Status block is OUTSIDE the assertion but INSIDE the Response, so the Response digest also breaks - either
  // way it must reject.
  {
    const resp = buildResponse([buildAssertion()]);
    const signedResp = await signResponse(resp, rsa.privateKey);
    const status = signedResp.children.find((c) => c.type === "element" && c.name === "samlp:Status") as XmlElement;
    const code = status.children[0] as XmlElement;
    code.attrs = [a("Value", "urn:oasis:names:tc:SAML:2.0:status:Responder")];
    const r = await verifySamlResponse(encodeResponse(signedResp), baseConn([certPem]), baseCtx());
    h.ok("IDP-1 neg: a non-Success Status on a Response-signed message is rejected", r.ok === false);
  }

  // IDP-1 negative 6: a Response-signed message with the wrong @Destination -> reject (envelope wrong-SP gate).
  {
    const resp = buildResponse([buildAssertion()], { destination: "https://attacker.example/acs" });
    const signedResp = await signResponse(resp, rsa.privateKey);
    const r = await verifySamlResponse(encodeResponse(signedResp), baseConn([certPem]), baseCtx());
    h.ok("IDP-1 neg: a wrong @Destination on a Response-signed message is rejected", r.ok === false);
  }

  // IDP-1 mixed: an assertion-level signature ALSO works when present (the OR semantics) - this is the
  // pre-existing path; we sign the ASSERTION (not the Response) and confirm it still verifies through the same
  // pipeline (regression guard that adding the Response path did not break the assertion path).
  {
    const assertion = buildAssertion();
    const refId = (assertion.attrs.find((at) => at.name === "ID")?.value) ?? ASSERTION_ID;
    const signedAssertion = await signElement(assertion, refId, rsa.privateKey);
    const resp = buildResponse([signedAssertion]);
    const r = await verifySamlResponse(encodeResponse(resp), baseConn([certPem]), baseCtx());
    h.ok("IDP-1 mixed: an assertion-level signature still verifies (OR semantics preserved)", r.ok === true);
  }

  // IDP-1 belt-and-braces: a doc with BOTH an assertion-level AND a Response-level signature is ACCEPTED via the
  // assertion path (the assertion's own signature genuinely covers it; the extra Response signature is irrelevant).
  // We build it by signing the assertion, putting it in a Response, then signing the Response too.
  {
    const assertion = buildAssertion();
    const refId = (assertion.attrs.find((at) => at.name === "ID")?.value) ?? ASSERTION_ID;
    const signedAssertion = await signElement(assertion, refId, rsa.privateKey);
    const resp = buildResponse([signedAssertion]);
    // Now also sign the Response (a second Signature, a child of the Response, outside the assertion).
    const doubleSigned = await signResponse(resp, rsa.privateKey);
    const r = await verifySamlResponse(encodeResponse(doubleSigned), baseConn([certPem]), baseCtx());
    // The assertion-level path: verifyXmlSignature(assertion,...) finds exactly ONE signature in the assertion
    // subtree (the assertion's own) and would verify it -> ACCEPTED via the assertion path. That is SAFE: the
    // assertion's own signature genuinely covers it. So this is ACCEPTED (the assertion is properly signed). We
    // assert it is accepted AND the legit principal is consumed (the extra Response signature changes nothing).
    h.ok("IDP-1 both-signed: accepted via the assertion-level signature (its own signature genuinely covers it)", r.ok === true && r.principal.nameId === LEGIT_NAMEID);
  }
}
