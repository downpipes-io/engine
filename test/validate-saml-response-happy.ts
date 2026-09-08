// Happy-path (full pipeline) group of the SAML ACS response verifier suite. Split out of
// validate-saml-response.ts; the orchestrator imports run() and calls it with the shared harness + keys.

import { verifySamlResponse } from "../src/admin/saml/response.ts";
import { samlSubject } from "../src/admin/identity.ts";
import {
  type Harness,
  type Keys,
  ASSERTION_ID,
  CONN_ID,
  IDP_ENTITY,
  baseConn,
  baseCtx,
  buildAssertion,
  buildResponse,
  encodeResponse,
  signAssertion,
} from "./saml-response-fixtures.ts";

export async function run(h: Harness, keys: Keys): Promise<void> {
  const { rsa, certPem, certOtherPem } = keys;

  // ========================= HAPPY PATH (end to end) =========================
  console.log("\nhappy path (full pipeline):\n");
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    h.ok("a valid signed Response yields the principal", r.ok === true);
    if (r.ok) {
      h.ok("  -> subject == samlSubject(connId, idpEntityId, nameId)", r.principal.subject === samlSubject(CONN_ID, IDP_ENTITY, "alice@example.com"));
      h.ok("  -> email canonicalised + emailVerified true (trust-idp)", r.principal.email === "alice@example.com" && r.principal.emailVerified === true);
      h.ok("  -> groups are the configured values in order", JSON.stringify(r.principal.groups) === JSON.stringify(["administrators", "billing"]));
      h.ok("  -> nameId surfaced", r.principal.nameId === "alice@example.com");
    }
  }
  // Rollover: the signing cert listed SECOND among the pinned certs still verifies (try-each).
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certOtherPem, certPem]), baseCtx());
    h.ok("rollover: a Response verified by the SECOND pinned cert is accepted", r.ok === true);
  }
  // A malformed FIRST pinned PEM does not block a good SECOND one (try-each tolerance).
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    const resp = encodeResponse(buildResponse([signed]));
    const conn = baseConn(["-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----", certPem]);
    const r = await verifySamlResponse(resp, conn, baseCtx());
    h.ok("rollover: a malformed first PEM is skipped and a good second PEM verifies", r.ok === true);
  }
  // IdP-initiated, EXPLICITLY allowed: no Response-level @InResponseTo and no SCD InResponseTo, allowIdpInitiated.
  {
    const signed = await signAssertion(buildAssertion({ inResponseTo: null }), ASSERTION_ID, rsa.privateKey);
    const resp = encodeResponse(buildResponse([signed], { inResponseTo: null }));
    const r = await verifySamlResponse(resp, baseConn([certPem], { allowIdpInitiated: true }), baseCtx());
    h.ok("idp-initiated allowed: a Response with no InResponseTo is accepted when allowIdpInitiated=true", r.ok === true);
  }
}
