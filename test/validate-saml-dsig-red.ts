// Red-corpus vectors for the SAML XML-DSig verifier: each crafted document MUST reject. Extracted from
// test/validate-saml-dsig.ts. Same assertions, same order as the original main().

import {
  type Harness,
  type VectorKeys,
  buildAssertion,
  expectOk,
  expectFail,
  signAssertion,
  el,
  a,
  t,
  clone,
  C14N_EXC,
  TRANSFORM_ENVELOPED,
  SIG_RSA_SHA256,
  SIG_RSA_SHA1,
  DIGEST_SHA1,
} from "./validate-saml-dsig-shared.ts";
import type { XmlElement } from "../src/admin/saml/xml-node.ts";

export async function runRedCorpus(h: Harness, k: VectorKeys): Promise<void> {
  const { rsa, rsaSpki, rsaOther, rsaOtherSpki, ID } = k;

  console.log("\nred corpus (each MUST reject):\n");

  // 1. TWO ds:Signature elements.
  {
    const signed = await signAssertion(buildAssertion(ID), ID, rsa.privateKey, "RSA", "SHA-256", SIG_RSA_SHA256);
    const second = clone(signed.children[1] as XmlElement); // a second Signature copy
    signed.children.push(second);
    await expectFail(h, signed, rsaSpki, undefined, "two ds:Signature elements rejected (multi-signature confusion)");
  }

  // 2. SignedInfo with TWO References.
  {
    const signed = await signAssertion(buildAssertion(ID), ID, rsa.privateKey, "RSA", "SHA-256", SIG_RSA_SHA256);
    const sig = signed.children[1] as XmlElement;
    const si = sig.children[0] as XmlElement;
    const ref = si.children.find((c) => c.type === "element" && c.name === "ds:Reference") as XmlElement;
    si.children.push(clone(ref)); // a second Reference
    await expectFail(h, signed, rsaSpki, undefined, "SignedInfo with two References rejected");
  }

  // 3. DUPLICATE ID: a second element carrying the same ID as the referenced assertion.
  {
    const signed = await signAssertion(buildAssertion(ID), ID, rsa.privateKey, "RSA", "SHA-256", SIG_RSA_SHA256);
    // Inject an evil element with the SAME ID elsewhere in the tree.
    const evil = el("saml:Assertion", [a("ID", ID)], [el("saml:Issuer", [], [t("evil")])]);
    signed.children.push(evil);
    await expectFail(h, signed, rsaSpki, undefined, "duplicate ID (two elements share the referenced ID) rejected (XSW)");
  }

  // 4. SignatureMethod rsa-sha1 (banned). We must rebuild SignedInfo with the banned method; the signature
  //    itself need not be valid because the allowlist rejects BEFORE crypto.
  {
    const signed = await signAssertion(buildAssertion(ID), ID, rsa.privateKey, "RSA", "SHA-256", SIG_RSA_SHA256);
    const sig = signed.children[1] as XmlElement;
    const si = sig.children[0] as XmlElement;
    const sm = si.children.find((c) => c.type === "element" && c.name === "ds:SignatureMethod") as XmlElement;
    sm.attrs = [a("Algorithm", SIG_RSA_SHA1)];
    await expectFail(h, signed, rsaSpki, undefined, "SignatureMethod rsa-sha1 rejected by the allowlist");
  }

  // 4b. DigestMethod sha1 (banned).
  {
    const signed = await signAssertion(buildAssertion(ID), ID, rsa.privateKey, "RSA", "SHA-256", SIG_RSA_SHA256);
    const sig = signed.children[1] as XmlElement;
    const si = sig.children[0] as XmlElement;
    const ref = si.children.find((c) => c.type === "element" && c.name === "ds:Reference") as XmlElement;
    const dmEl = ref.children.find((c) => c.type === "element" && c.name === "ds:DigestMethod") as XmlElement;
    dmEl.attrs = [a("Algorithm", DIGEST_SHA1)];
    await expectFail(h, signed, rsaSpki, undefined, "DigestMethod sha1 rejected by the allowlist");
  }

  // 5. UNKNOWN / EXTRA transform (a third transform not on the whitelist).
  {
    const evilTransforms = [
      el("ds:Transform", [a("Algorithm", TRANSFORM_ENVELOPED)], []),
      el("ds:Transform", [a("Algorithm", "http://www.w3.org/TR/1999/REC-xslt-19991116")], []),
      el("ds:Transform", [a("Algorithm", C14N_EXC)], []),
    ];
    const signed = await signAssertion(buildAssertion(ID), ID, rsa.privateKey, "RSA", "SHA-256", SIG_RSA_SHA256, { extraTransforms: evilTransforms });
    await expectFail(h, signed, rsaSpki, undefined, "an unknown/extra Transform (XSLT) rejected by the whitelist");
  }

  // 5b. Missing enveloped-signature transform (only exc-c14n#) -> rejected for our enveloped profile.
  {
    const onlyC14n = [el("ds:Transform", [a("Algorithm", C14N_EXC)], [])];
    const signed = await signAssertion(buildAssertion(ID), ID, rsa.privateKey, "RSA", "SHA-256", SIG_RSA_SHA256, { extraTransforms: onlyC14n });
    await expectFail(h, signed, rsaSpki, undefined, "missing enveloped-signature transform rejected");
  }

  // 6. UNSIGNED assertion (no Signature at all).
  {
    const bare = buildAssertion(ID);
    await expectFail(h, bare, rsaSpki, undefined, "unsigned assertion (no ds:Signature) rejected");
  }

  // 7. TAMPERED assertion (digest mismatch): alter a claim AFTER signing.
  {
    const signed = await signAssertion(buildAssertion(ID), ID, rsa.privateKey, "RSA", "SHA-256", SIG_RSA_SHA256);
    // Mutate the NameID text after the signature was computed.
    const subject = signed.children.find((c) => c.type === "element" && c.name === "saml:Subject") as XmlElement;
    const nameId = subject.children[0] as XmlElement;
    nameId.children = [t("attacker@evil.example")];
    await expectFail(h, signed, rsaSpki, undefined, "tampered assertion (NameID changed post-signing) rejected via digest mismatch");
  }

  // 8. KeyInfo carrying a DIFFERENT cert than the pinned key: the document's KeyInfo must be IGNORED, and
  //    verification proceeds against the PINNED key. We sign with rsaOther.privateKey, embed a KeyInfo (whose
  //    content is irrelevant - the verifier never reads it), and pin the UNRELATED rsa public key -> the
  //    SignedInfo signature does not verify under the pinned key, so it rejects. This proves there is no
  //    "trust the embedded cert" fallback.
  {
    const keyInfo = el("ds:KeyInfo", [], [el("ds:X509Data", [], [el("ds:X509Certificate", [], [t("MIIB...attacker-cert-bytes...")])])]);
    const signedByOther = await signAssertion(buildAssertion(ID), ID, rsaOther.privateKey, "RSA", "SHA-256", SIG_RSA_SHA256, { keyInfo });
    // Pin the DIFFERENT (legitimate) key; the embedded KeyInfo must NOT be used to switch keys.
    await expectFail(h, signedByOther, rsaSpki, undefined, "KeyInfo with a different cert is IGNORED; verify against the pinned key fails");
    // Sanity: the very same document DOES verify when the CORRECT key (the one that actually signed) is pinned,
    // proving the rejection above is specifically the pinned-key mismatch, not a structural fault.
    await expectOk(h, signedByOther, rsaOtherSpki, undefined, "the KeyInfo document verifies only when the actual signer's key is the pinned key");
  }

  // 9. VOID / EMPTY-CANON attempt: a Reference URI pointing at an element that does not exist (#missing) ->
  //    resolves to no element -> reject (the verifier never digests an empty/absent node-set). This is the
  //    structural face of the void-canon defence at the verifier boundary.
  {
    const signed = await signAssertion(buildAssertion(ID), ID, rsa.privateKey, "RSA", "SHA-256", SIG_RSA_SHA256);
    const sig = signed.children[1] as XmlElement;
    const si = sig.children[0] as XmlElement;
    const ref = si.children.find((c) => c.type === "element" && c.name === "ds:Reference") as XmlElement;
    ref.attrs = [a("URI", "#does-not-exist")];
    await expectFail(h, signed, rsaSpki, undefined, "Reference URI to a missing id rejected (no node-set to digest)");
  }

  // 9b. A non-fragment Reference URI (external/whole-document) rejected.
  {
    const signed = await signAssertion(buildAssertion(ID), ID, rsa.privateKey, "RSA", "SHA-256", SIG_RSA_SHA256);
    const sig = signed.children[1] as XmlElement;
    const si = sig.children[0] as XmlElement;
    const ref = si.children.find((c) => c.type === "element" && c.name === "ds:Reference") as XmlElement;
    ref.attrs = [a("URI", "https://evil.example/x")];
    await expectFail(h, signed, rsaSpki, undefined, "non-fragment Reference URI rejected (only same-document #id accepted)");
  }

  // 10. CanonicalizationMethod not exclusive (inclusive c14n banned).
  {
    const signed = await signAssertion(buildAssertion(ID), ID, rsa.privateKey, "RSA", "SHA-256", SIG_RSA_SHA256);
    const sig = signed.children[1] as XmlElement;
    const si = sig.children[0] as XmlElement;
    const cm = si.children.find((c) => c.type === "element" && c.name === "ds:CanonicalizationMethod") as XmlElement;
    cm.attrs = [a("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315")];
    await expectFail(h, signed, rsaSpki, undefined, "inclusive (non-exclusive) CanonicalizationMethod rejected");
  }

  // 11. requireReferenceIsTarget MISMATCH: hand in a wrapper element whose subtree contains the signed
  //     assertion, but require the Reference to cover the TARGET (the wrapper). The Reference covers the
  //     assertion, not the wrapper -> reject under requireReferenceIsTarget.
  {
    const signed = await signAssertion(buildAssertion(ID), ID, rsa.privateKey, "RSA", "SHA-256", SIG_RSA_SHA256);
    const wrapper = el("samlp:Response", [a("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")], [signed]);
    // Without the flag, the verifier still finds the single Signature + resolves the ID inside the subtree and
    // verifies (a Response carrying a signed Assertion). WITH the flag it must reject (Reference != wrapper).
    await expectOk(h, wrapper, rsaSpki, undefined, "a wrapper carrying a signed assertion verifies (Reference resolves within the subtree)");
    await expectFail(h, wrapper, rsaSpki, { requireReferenceIsTarget: true }, "requireReferenceIsTarget rejects when the Reference does not cover the handed-in element");
  }

  // 12. SignatureValue corrupted (flip a byte) -> reject even though structure + digest are fine.
  {
    const signed = await signAssertion(buildAssertion(ID), ID, rsa.privateKey, "RSA", "SHA-256", SIG_RSA_SHA256);
    const sig = signed.children[1] as XmlElement;
    const svEl = sig.children.find((c) => c.type === "element" && c.name === "ds:SignatureValue") as XmlElement;
    const txt = (svEl.children[0] as { type: "text"; value: string }).value;
    // Flip the first base64 character to a different valid one (decodes to different bytes).
    const flipped = (txt[0] === "A" ? "B" : "A") + txt.slice(1);
    svEl.children = [t(flipped)];
    await expectFail(h, signed, rsaSpki, undefined, "corrupted SignatureValue rejected");
  }

  // 13. Malformed/invalid base64 in DigestValue -> reject.
  {
    const signed = await signAssertion(buildAssertion(ID), ID, rsa.privateKey, "RSA", "SHA-256", SIG_RSA_SHA256);
    const sig = signed.children[1] as XmlElement;
    const si = sig.children[0] as XmlElement;
    const ref = si.children.find((c) => c.type === "element" && c.name === "ds:Reference") as XmlElement;
    const dvEl = ref.children.find((c) => c.type === "element" && c.name === "ds:DigestValue") as XmlElement;
    dvEl.children = [t("!!!not base64!!!")];
    await expectFail(h, signed, rsaSpki, undefined, "non-base64 DigestValue rejected");
  }
}
