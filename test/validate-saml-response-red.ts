// Red-corpus group of the SAML ACS response verifier suite (every vector here MUST reject). Split out of
// validate-saml-response.ts; the orchestrator imports run() and calls it with the shared harness + keys.

import { verifySamlResponse } from "../src/admin/saml/response.ts";
import type { XmlElement } from "../src/admin/saml/xml-node.ts";
import {
  type Harness,
  type Keys,
  ASSERTION_ID,
  SAML_ASSERTION_NS,
  STATUS_REQUESTER,
  a,
  baseConn,
  baseCtx,
  buildAssertion,
  buildResponse,
  clone,
  el,
  encodeResponse,
  signAssertion,
  t,
} from "./saml-response-fixtures.ts";

export async function run(h: Harness, keys: Keys): Promise<void> {
  const { rsa, rsaOther, certPem, certOtherPem } = keys;

  // ========================= RED CORPUS (each MUST reject) =========================
  console.log("\nred corpus (each MUST reject):\n");

  // 1. UNSIGNED assertion (no ds:Signature at all).
  {
    const resp = encodeResponse(buildResponse([buildAssertion()]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    h.ok("unsigned assertion (no ds:Signature) rejected", r.ok === false);
  }

  // 2. Signature by a NON-pinned key: sign with rsaOther, pin only the legit cert.
  {
    const signedByOther = await signAssertion(buildAssertion(), ASSERTION_ID, rsaOther.privateKey);
    const resp = encodeResponse(buildResponse([signedByOther]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    h.ok("signature by a non-pinned key rejected", r.ok === false);
    // Sanity: the SAME document verifies when the actual signer's cert is the pinned one (proves the reject is
    // the pinned-key mismatch, not a structural fault).
    const rOk = await verifySamlResponse(resp, baseConn([certOtherPem]), baseCtx());
    h.ok("  -> the same document verifies when the signer's cert is pinned (KeyInfo is ignored, pin governs)", rOk.ok === true);
  }

  // 3. TWO Assertions (XSW): two signed assertions side by side -> reject (more than one Assertion).
  {
    const s1 = await signAssertion(buildAssertion({ assertionId: "_a1" }), "_a1", rsa.privateKey);
    const s2 = await signAssertion(buildAssertion({ assertionId: "_a2" }), "_a2", rsa.privateKey);
    const resp = encodeResponse(buildResponse([s1, s2]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    h.ok("two saml:Assertion children rejected (XML-Signature-Wrapping)", r.ok === false);
  }

  // 3b. The classic XSW: ONE legitimately-signed assertion + a SECOND UNSIGNED evil assertion injected as a
  //     sibling (the attacker hopes the SP consumes the evil one). More-than-one-Assertion catches it.
  {
    const signed = await signAssertion(buildAssertion({ nameId: "alice@example.com" }), ASSERTION_ID, rsa.privateKey);
    const evil = buildAssertion({ assertionId: "_evil", nameId: "attacker@evil.example", email: "attacker@evil.example" });
    const resp = encodeResponse(buildResponse([signed, evil]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    h.ok("XSW: a signed assertion + an injected unsigned sibling assertion is rejected (never consume the wrapper)", r.ok === false);
  }

  // 3c. XSW by WRAPPING: the signed assertion embedded INSIDE an outer (unsigned) assertion that becomes the
  //     single Response child. requireReferenceIsTarget forces the located (outer) assertion to BE the signed
  //     one; the Reference covers the INNER assertion, not the outer -> reject.
  {
    const signed = await signAssertion(buildAssertion({ assertionId: "_inner", nameId: "alice@example.com" }), "_inner", rsa.privateKey);
    // An outer evil assertion that carries the signed assertion as a child (plus its own evil Subject).
    const outer = buildAssertion({ assertionId: "_outer", nameId: "attacker@evil.example", email: "attacker@evil.example" });
    outer.children.push(signed); // wrap the signed assertion inside
    const resp = encodeResponse(buildResponse([outer]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    h.ok("XSW: a signed assertion wrapped inside an outer unsigned assertion is rejected (Reference != located assertion)", r.ok === false);
  }

  // 3d. XSW by ID-confusion: the outer wrapper carries the SAME ID as the inner signed assertion, hoping the
  //     Reference resolves to the wrapper. The dsig unique-ID walk sees TWO elements with that ID -> reject
  //     (duplicate-ID wrapping), so the SP never has to choose.
  {
    const signed = await signAssertion(buildAssertion({ assertionId: ASSERTION_ID, nameId: "alice@example.com" }), ASSERTION_ID, rsa.privateKey);
    const outer = buildAssertion({ assertionId: ASSERTION_ID, nameId: "attacker@evil.example", email: "attacker@evil.example" });
    outer.children.push(signed); // inner shares the outer's ID -> duplicate ID in the located subtree
    const resp = encodeResponse(buildResponse([outer]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    h.ok("XSW: an outer wrapper sharing the inner signed assertion's ID is rejected (duplicate-ID resolution)", r.ok === false);
  }

  // 3e. A SECOND ds:Signature inside the single located assertion (multi-signature confusion) -> reject.
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    const sig = signed.children.find((c) => c.type === "element" && c.name === "ds:Signature") as XmlElement;
    signed.children.push(clone(sig)); // a second Signature subtree
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    h.ok("a second ds:Signature inside the assertion is rejected (multi-signature confusion)", r.ok === false);
  }

  // 4. Status != Success.
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    const resp = encodeResponse(buildResponse([signed], { statusValue: STATUS_REQUESTER }));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    h.ok("a non-Success Status rejected", r.ok === false);
  }

  // 5. Wrong @Destination.
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    const resp = encodeResponse(buildResponse([signed], { destination: "https://attacker.example/acs" }));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    h.ok("a wrong Response @Destination rejected", r.ok === false);
  }

  // 6. Wrong @InResponseTo (Response-level).
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    const resp = encodeResponse(buildResponse([signed], { inResponseTo: "_some_other_request" }));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    h.ok("a wrong Response @InResponseTo rejected", r.ok === false);
  }

  // 6b. Absent @InResponseTo (Response + SCD) with allowIdpInitiated=false -> reject (IdP-initiated denied).
  {
    const signed = await signAssertion(buildAssertion({ inResponseTo: null }), ASSERTION_ID, rsa.privateKey);
    const resp = encodeResponse(buildResponse([signed], { inResponseTo: null }));
    const r = await verifySamlResponse(resp, baseConn([certPem], { allowIdpInitiated: false }), baseCtx());
    h.ok("an absent InResponseTo with allowIdpInitiated=false rejected", r.ok === false);
  }

  // 7. EncryptedAssertion present -> the explicit out-of-scope reject.
  {
    // A samlp:Response whose only assertion-shaped child is a saml:EncryptedAssertion.
    const enc = el("saml:EncryptedAssertion", [a("xmlns:saml", SAML_ASSERTION_NS)], [
      el("xenc:EncryptedData", [a("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")], [t("...ciphertext...")]),
    ]);
    const resp = encodeResponse(buildResponse([enc]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    h.ok("an EncryptedAssertion is rejected with the out-of-scope reason", r.ok === false && r.reason.includes("encrypted assertions not supported"));
  }

  // 8. TAMPERED assertion (post-sign mutation): change the NameID text after signing -> digest mismatch.
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    // Mutate the NameID text after the signature was computed (Subject is index 2: Issuer, Signature, Subject...).
    const subject = signed.children.find((c) => c.type === "element" && c.name === "saml:Subject") as XmlElement;
    const nameId = subject.children.find((c) => c.type === "element" && c.name === "saml:NameID") as XmlElement;
    nameId.children = [t("attacker@evil.example")];
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    h.ok("a tampered assertion (NameID changed post-signing) rejected via digest mismatch", r.ok === false);
  }

  // 8b. TAMPERED attribute (post-sign): change the email AttributeValue after signing -> digest mismatch.
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    const stmt = signed.children.find((c) => c.type === "element" && c.name === "saml:AttributeStatement") as XmlElement;
    const emailAttr = stmt.children.find((c) => c.type === "element" && (c as XmlElement).attrs.some((at) => at.name === "Name" && at.value === "email")) as XmlElement;
    const av = emailAttr.children.find((c) => c.type === "element") as XmlElement;
    av.children = [t("attacker@evil.example")];
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    h.ok("a tampered email AttributeValue (post-signing) rejected via digest mismatch", r.ok === false);
  }
}
