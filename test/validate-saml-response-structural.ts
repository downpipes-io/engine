// Input + structural rejects group of the SAML ACS response verifier suite. Split out of
// validate-saml-response.ts; the orchestrator imports run() and calls it with the shared harness + keys.

import { verifySamlResponse } from "../src/admin/saml/response.ts";
import {
  type Harness,
  type Keys,
  ASSERTION_ID,
  RESPONSE_ID,
  SAML_PROTOCOL_NS,
  STATUS_SUCCESS,
  a,
  b64std,
  baseConn,
  baseCtx,
  buildAssertion,
  buildResponse,
  el,
  encodeResponse,
  signAssertion,
} from "./saml-response-fixtures.ts";

export async function run(h: Harness, keys: Keys): Promise<void> {
  const { rsa, certPem } = keys;

  // ========================= INPUT / STRUCTURAL REJECTS =========================
  console.log("\ninput + structural rejects:\n");

  // 9. Non-base64 SAMLResponse.
  {
    const r = await verifySamlResponse("@@@not base64@@@", baseConn([certPem]), baseCtx());
    h.ok("a non-base64 SAMLResponse rejected", r.ok === false);
  }
  // 9b. Empty SAMLResponse.
  {
    const r = await verifySamlResponse("", baseConn([certPem]), baseCtx());
    h.ok("an empty SAMLResponse rejected", r.ok === false);
  }
  // 9c. Valid base64 of NON-XML bytes.
  {
    const r = await verifySamlResponse(b64std(new TextEncoder().encode("this is not xml at all")), baseConn([certPem]), baseCtx());
    h.ok("valid base64 of non-XML rejected", r.ok === false);
  }
  // 9d. Base64 of a DTD-bearing document (the parser's raw-byte gate fires).
  {
    const dtd = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><samlp:Response xmlns:samlp="' + SAML_PROTOCOL_NS + '"/>';
    const r = await verifySamlResponse(b64std(new TextEncoder().encode(dtd)), baseConn([certPem]), baseCtx());
    h.ok("a DOCTYPE/DTD-bearing document rejected by the parser gate", r.ok === false);
  }
  // 10. Root is NOT a samlp:Response (a bare Assertion posted as the document).
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    const r = await verifySamlResponse(encodeResponse(signed), baseConn([certPem]), baseCtx());
    h.ok("a non-Response root (a bare Assertion) rejected", r.ok === false);
  }
  // 10b. A samlp:Response whose local name matches but is in the WRONG namespace.
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    const wrongNs = el("samlp:Response", [a("xmlns:samlp", "urn:not:the:protocol:ns"), a("ID", RESPONSE_ID)], [
      el("samlp:Status", [], [el("samlp:StatusCode", [a("Value", STATUS_SUCCESS)], [])]),
      signed,
    ]);
    const r = await verifySamlResponse(encodeResponse(wrongNs), baseConn([certPem]), baseCtx());
    h.ok("a Response in the wrong (non-protocol) namespace rejected", r.ok === false);
  }
  // 11. No Assertion at all (Status Success but empty) -> reject.
  {
    const resp = encodeResponse(buildResponse([]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    h.ok("a Response with no Assertion rejected", r.ok === false);
  }
  // 12. acsUrl mismatch surfaces via the per-assertion Recipient check too: even with a correct Response that
  //     ctx.acsUrl differs from -> consumeAssertion's Recipient gate rejects (defence in depth across layers).
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    // Omit the Response @Destination so the envelope check is a no-op; the assertion Recipient is ACS_URL but
    // ctx.acsUrl is a different URL -> the inner Recipient gate must reject.
    const resp = encodeResponse(buildResponse([signed], { destination: null }));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx({ acsUrl: "https://console.downpipes.io/admin/saml/acs/OTHER" }));
    h.ok("a ctx.acsUrl that mismatches the assertion Recipient is rejected by the inner gate", r.ok === false);
  }
  // 13. Expired assertion (Conditions NotOnOrAfter in the past, beyond skew) reaches consumeAssertion and is
  //     rejected (the signature is over the expired assertion, so it must re-sign to keep the digest valid).
  {
    const signed = await signAssertion(buildAssertion({ notOnOrAfter: "2026-06-13T11:00:00Z", scdNotOnOrAfter: "2026-06-13T11:00:00Z" }), ASSERTION_ID, rsa.privateKey);
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    h.ok("an expired (signed) assertion is rejected by consumeAssertion's validity window", r.ok === false);
  }
  // 14. A connection with NO pinned certs rejects (cannot establish a trust root).
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([]), baseCtx());
    h.ok("a connection with no pinned certificate rejects", r.ok === false);
  }
}
