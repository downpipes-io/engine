// IDP-2 group of the real-world-IdP interop corpus: ec:InclusiveNamespaces PrefixList + inherited namespaces
// (ADFS / Shibboleth). Split out of validate-saml-interop.ts; the orchestrator imports run() and calls it with
// the shared harness + keys. Every assertion here runs in the original order.

import { verifySamlResponse } from "../src/admin/saml/response.ts";
import type { XmlElement } from "../src/admin/saml/xml-node.ts";
import {
  type Harness,
  type Keys,
  ASSERTION_ID,
  C14N_EXC,
  LEGIT_NAMEID,
  RESPONSE_ID,
  a,
  baseConn,
  baseCtx,
  buildAssertion,
  buildResponse,
  el,
  encodeResponse,
  signElement,
} from "./saml-interop-fixtures.ts";

export async function run(h: Harness, keys: Keys): Promise<void> {
  const { rsa, certPem } = keys;

  // ========================= IDP-2: ec:InclusiveNamespaces PrefixList =========================
  console.log("\nIDP-2 ec:InclusiveNamespaces PrefixList + inherited namespaces (ADFS / Shibboleth):\n");

  // CONTROL: an ADFS/Shibboleth-shaped assertion (xsi:type="xs:string" AttributeValues, xsi:/xs: declared on
  // the Assertion) signed at the ASSERTION level with an exc-c14n# Transform carrying InclusiveNamespaces
  // PrefixList="xs" now VERIFIES. Without honouring the list, the recomputed digest would mismatch (the xs
  // value-only prefix would be dropped) and a genuine assertion would be wrongly rejected.
  {
    const assertion = buildAssertion({ xsiTypedEmail: true });
    const refId = (assertion.attrs.find((at) => at.name === "ID")?.value) ?? ASSERTION_ID;
    const signed = await signElement(assertion, refId, rsa.privateKey, "xs");
    const resp = buildResponse([signed]);
    const r = await verifySamlResponse(encodeResponse(resp), baseConn([certPem]), baseCtx());
    h.ok("IDP-2 CONTROL: an ADFS-style xsi:type assertion signed with InclusiveNamespaces PrefixList=xs verifies", r.ok === true);
    if (r.ok) {
      h.ok("  -> the email AttributeValue is consumed correctly through the inclusive-c14n digest", r.principal.email === LEGIT_NAMEID);
    } else {
      console.log("       (reason: " + r.reason + ")");
    }
  }

  // IDP-2 also at the RESPONSE level: a Response-signed ADFS-style message (Response signature, InclusiveNamespaces
  // PrefixList="xs", unsigned assertion carrying the xsi:type values) verifies via the combined IDP-1+IDP-2 path.
  {
    const assertion = buildAssertion({ xsiTypedEmail: true });
    const resp = buildResponse([assertion]);
    const refId = (resp.attrs.find((at) => at.name === "ID")?.value) ?? RESPONSE_ID;
    const signedResp = await signElement(resp, refId, rsa.privateKey, "xs");
    const r = await verifySamlResponse(encodeResponse(signedResp), baseConn([certPem]), baseCtx());
    h.ok("IDP-2+IDP-1: a Response-signed ADFS-style message with PrefixList=xs verifies", r.ok === true);
  }

  // IDP-2 negative: the SAME ADFS-style assertion, but the digest was computed over the INCLUSIVE form while the
  // document's Transform OMITS the PrefixList. The verifier recomputes WITHOUT the list (plain exclusive),
  // dropping xs -> digest mismatch -> reject. Proves a mismatched/forged list cannot be smuggled and the
  // inclusive digest is honoured exactly as declared.
  {
    const assertion = buildAssertion({ xsiTypedEmail: true });
    const refId = (assertion.attrs.find((at) => at.name === "ID")?.value) ?? ASSERTION_ID;
    // Sign the digest using the inclusive form (prefixList xs) ...
    const signed = await signElement(assertion, refId, rsa.privateKey, "xs");
    // ... then STRIP the InclusiveNamespaces element from the document's Transform, leaving a plain exc-c14n#.
    const sig = signed.children.find((c) => c.type === "element" && c.name === "ds:Signature") as XmlElement;
    const si = sig.children[0] as XmlElement;
    const ref = si.children.find((c) => c.type === "element" && c.name === "ds:Reference") as XmlElement;
    const transforms = ref.children.find((c) => c.type === "element" && c.name === "ds:Transforms") as XmlElement;
    for (const tr of transforms.children) {
      if (tr.type === "element" && tr.name === "ds:Transform" && tr.attrs.some((at) => at.name === "Algorithm" && at.value === C14N_EXC)) {
        tr.children = []; // drop the <ec:InclusiveNamespaces/> child
      }
    }
    const resp = buildResponse([signed]);
    const r = await verifySamlResponse(encodeResponse(resp), baseConn([certPem]), baseCtx());
    h.ok("IDP-2 neg: an inclusive-form digest with the PrefixList stripped from the document is rejected (digest mismatch)", r.ok === false);
  }

  // IDP-2 negative 2: a forged PrefixList listing a DIFFERENT prefix than the one the digest was computed with.
  // Digest computed with xs; document declares PrefixList="bogus" -> the verifier renders nothing extra for the
  // unbound 'bogus' and drops xs -> mismatch -> reject.
  {
    const assertion = buildAssertion({ xsiTypedEmail: true });
    const refId = (assertion.attrs.find((at) => at.name === "ID")?.value) ?? ASSERTION_ID;
    const signed = await signElement(assertion, refId, rsa.privateKey, "xs");
    const sig = signed.children.find((c) => c.type === "element" && c.name === "ds:Signature") as XmlElement;
    const si = sig.children[0] as XmlElement;
    const ref = si.children.find((c) => c.type === "element" && c.name === "ds:Reference") as XmlElement;
    const transforms = ref.children.find((c) => c.type === "element" && c.name === "ds:Transforms") as XmlElement;
    for (const tr of transforms.children) {
      if (tr.type === "element" && tr.name === "ds:Transform" && tr.attrs.some((at) => at.name === "Algorithm" && at.value === C14N_EXC)) {
        tr.children = [el("ec:InclusiveNamespaces", [a("xmlns:ec", C14N_EXC), a("PrefixList", "bogus")], [])];
      }
    }
    const resp = buildResponse([signed]);
    const r = await verifySamlResponse(encodeResponse(resp), baseConn([certPem]), baseCtx());
    h.ok("IDP-2 neg: a forged PrefixList (different prefix than signed) is rejected (digest mismatch)", r.ok === false);
  }

  // IDP-2 compatibility: an xsi:type assertion signed WITHOUT any InclusiveNamespaces list (the other ADFS/Entra
  // variant - plain exclusive c14n on BOTH sides, the value-only xs prefix dropped consistently) still verifies.
  // This guards that adding PrefixList support did not break the no-list xsi:type case (it was, and stays, fine
  // because the IdP digest and the SP digest both drop xs under pure exclusive rules).
  {
    const assertion = buildAssertion({ xsiTypedEmail: true });
    const refId = (assertion.attrs.find((at) => at.name === "ID")?.value) ?? ASSERTION_ID;
    const signed = await signElement(assertion, refId, rsa.privateKey); // no PrefixList
    const resp = buildResponse([signed]);
    const r = await verifySamlResponse(encodeResponse(resp), baseConn([certPem]), baseCtx());
    h.ok("IDP-2 compat: an xsi:type assertion signed with NO PrefixList (plain exclusive) still verifies", r.ok === true);
  }
}
