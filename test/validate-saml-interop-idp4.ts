// Real-world-IdP interop corpus: signing-cert validity window. Split out of
// validate-saml-interop.ts; the orchestrator imports run() and calls it with the shared harness + keys. Every
// assertion here runs in the original order.

import { verifySamlResponse } from "../src/admin/saml/response.ts";
import { verifyXmlSignature } from "../src/admin/saml/dsig.ts";
import type { XmlElement } from "../src/admin/saml/xml-node.ts";
import {
  type Harness,
  type Keys,
  ASSERTION_ID,
  EVIL_NAMEID,
  NOW_MS,
  baseConn,
  baseCtx,
  buildAssertion,
  buildCertPem,
  buildResponse,
  clone,
  encodeResponse,
  signElement,
  t,
} from "./saml-interop-fixtures.ts";

export async function run(h: Harness, keys: Keys): Promise<void> {
  const { rsa, rsaSpki, certPem } = keys;

  // ========================= SIGNING-CERT VALIDITY WINDOW =========================
  console.log("\nSigning-cert validity window:\n");

  // An EXPIRED cert (window ended before NOW) over an otherwise-valid signature -> reject. Sign with the legit
  // key, but pin a cert (same key) whose validity window is 2020..2021 (NOW = 2026 is past notAfter).
  {
    const expiredCert = await buildCertPem(rsaSpki, rsa.privateKey, "idp.example.com", "20200101000000Z", "20210101000000Z");
    const assertion = buildAssertion();
    const refId = (assertion.attrs.find((at) => at.name === "ID")?.value) ?? ASSERTION_ID;
    const signed = await signElement(assertion, refId, rsa.privateKey);
    const resp = buildResponse([signed]);
    const r = await verifySamlResponse(encodeResponse(resp), baseConn([expiredCert]), baseCtx());
    h.ok("A valid signature under an EXPIRED pinned cert is rejected (validity window)", r.ok === false);
  }

  // A NOT-YET-VALID cert (window begins after NOW) over an otherwise-valid signature -> reject. Window 2030..2031.
  {
    const futureCert = await buildCertPem(rsaSpki, rsa.privateKey, "idp.example.com", "20300101000000Z", "20310101000000Z");
    const assertion = buildAssertion();
    const refId = (assertion.attrs.find((at) => at.name === "ID")?.value) ?? ASSERTION_ID;
    const signed = await signElement(assertion, refId, rsa.privateKey);
    const resp = buildResponse([signed]);
    const r = await verifySamlResponse(encodeResponse(resp), baseConn([futureCert]), baseCtx());
    h.ok("A valid signature under a NOT-YET-VALID pinned cert is rejected (validity window)", r.ok === false);
  }

  // A cert whose window comfortably CONTAINS now verifies (the baseline certPem, 2026..2036).
  {
    const assertion = buildAssertion();
    const refId = (assertion.attrs.find((at) => at.name === "ID")?.value) ?? ASSERTION_ID;
    const signed = await signElement(assertion, refId, rsa.privateKey);
    const resp = buildResponse([signed]);
    const r = await verifySamlResponse(encodeResponse(resp), baseConn([certPem]), baseCtx());
    h.ok("A signature under an in-window pinned cert verifies", r.ok === true);
  }

  // Rollover: an EXPIRED cert listed first + an in-window cert second -> the in-window one verifies
  // (try-each tolerates an expired rollover cert, exactly as it tolerates a malformed PEM).
  {
    const expiredCert = await buildCertPem(rsaSpki, rsa.privateKey, "idp.example.com", "20200101000000Z", "20210101000000Z");
    const assertion = buildAssertion();
    const refId = (assertion.attrs.find((at) => at.name === "ID")?.value) ?? ASSERTION_ID;
    const signed = await signElement(assertion, refId, rsa.privateKey);
    const resp = buildResponse([signed]);
    const r = await verifySamlResponse(encodeResponse(resp), baseConn([expiredCert, certPem]), baseCtx());
    h.ok("Rollover: an expired first cert is skipped and the in-window second cert verifies", r.ok === true);
  }

  // Clock-skew at the boundary: a cert that expired 60s ago, with clockSkewSec=120 (so the +skew widen
  // covers it) -> ACCEPTED; with clockSkewSec=0 -> REJECTED. Build a cert whose notAfter is NOW - 60s. NOW is
  // 2026-06-13T12:00:00Z, so notAfter = 2026-06-13T11:59:00Z.
  {
    const justExpired = await buildCertPem(rsaSpki, rsa.privateKey, "idp.example.com", "20260101000000Z", "20260613115900Z");
    const assertion = buildAssertion();
    const refId = (assertion.attrs.find((at) => at.name === "ID")?.value) ?? ASSERTION_ID;
    const signed = await signElement(assertion, refId, rsa.privateKey);
    const resp = buildResponse([signed]);
    const rSkew = await verifySamlResponse(encodeResponse(resp), baseConn([justExpired], { clockSkewSec: 120 }), baseCtx());
    h.ok("Skew: a cert that expired 60s ago is accepted within a 120s clock-skew tolerance", rSkew.ok === true);
    const rNoSkew = await verifySamlResponse(encodeResponse(resp), baseConn([justExpired], { clockSkewSec: 0 }), baseCtx());
    h.ok("Skew: the SAME just-expired cert is rejected with zero clock-skew tolerance", rNoSkew.ok === false);
  }

  // Unit test on dsig directly: verifyXmlSignature honours the signingCertValidity option. We round-trip a
  // signed assertion and pass a window that has ended -> reject; a window that contains nowMs -> accept.
  {
    const assertion = buildAssertion();
    const refId = (assertion.attrs.find((at) => at.name === "ID")?.value) ?? ASSERTION_ID;
    const signed = await signElement(assertion, refId, rsa.privateKey);
    const past = { notBefore: Date.parse("2020-01-01T00:00:00Z"), notAfter: Date.parse("2021-01-01T00:00:00Z") };
    const ok1 = await verifyXmlSignature(signed, rsaSpki, { idAttribute: "ID", requireReferenceIsTarget: true, signingCertValidity: past, nowMs: NOW_MS });
    h.ok("dsig unit: verifyXmlSignature rejects a valid signature when nowMs is past the cert window", ok1.ok === false);
    const live = { notBefore: Date.parse("2026-01-01T00:00:00Z"), notAfter: Date.parse("2036-01-01T00:00:00Z") };
    const ok2 = await verifyXmlSignature(signed, rsaSpki, { idAttribute: "ID", requireReferenceIsTarget: true, signingCertValidity: live, nowMs: NOW_MS });
    h.ok("dsig unit: verifyXmlSignature accepts when nowMs is inside the cert window", ok2.ok === true);
    // The window check must NOT short-circuit before the crypto gate: a TAMPERED signature with an in-window
    // cert still rejects on the signature, not silently pass the window.
    const tampered = clone(signed);
    const subj = tampered.children.find((c) => c.type === "element" && c.name === "saml:Subject") as XmlElement;
    const nid = subj.children.find((c) => c.type === "element" && c.name === "saml:NameID") as XmlElement;
    nid.children = [t(EVIL_NAMEID)];
    const ok3 = await verifyXmlSignature(tampered, rsaSpki, { idAttribute: "ID", requireReferenceIsTarget: true, signingCertValidity: live, nowMs: NOW_MS });
    h.ok("dsig unit: a tampered signature still rejects on the signature even with an in-window cert", ok3.ok === false);
  }
}
