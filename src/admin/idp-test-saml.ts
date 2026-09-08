// The SAML half of the IdP/SSO "test connection" pre-save probe. Split out of
// idp-test.ts purely to keep that file under the structural line limit; the logic is unchanged and the public
// symbols (SamlTestConfig, testSamlConnection) are re-exported from idp-test.ts so importers are unaffected.
// The probe does NO network for SAML (the SSO URL is a browser redirect, never fetched server-side) - it is
// pure parse + validity, so it cannot SSRF; the only screen needed is the https/host shape of idpSsoUrl. It
// never throws. Australian English; no em dashes.

import type { IdpTestCheck, IdpTestResult } from "./idp-test-shared.ts";
import { CERT_EXPIRY_WARN_MS, finalise, MS_PER_DAY, screenFetchUrl } from "./idp-test-shared.ts";
import { parseXml } from "./saml/parser.ts";
import { certValidity } from "./saml/response.ts";
import type { XmlChild, XmlElement } from "./saml/xml-node.ts";
import { isElement } from "./saml/xml-node.ts";

// The SAML config the test reads. These are the discrete fields idpconn stores (the operator enters the
// IdP entityID, the SSO URL and the pinned signing cert PEM(s) directly - the connection does NOT carry a raw
// metadata blob). idpMetadataXml is an OPTIONAL convenience: when the operator pastes the IdP's published
// metadata XML, the test ALSO parses it (with the hardened SAML parser) and confirms it advertises an
// entityID, a SingleSignOnService and a signing certificate, so a paste error is caught before they copy the
// fields across. Everything here is operator-held PUBLIC data (signing certs are public); no secret is read.
export interface SamlTestConfig {
  idpEntityId?: string;
  idpSsoUrl?: string;
  idpSigningCerts?: string[];
  idpMetadataXml?: string;
}

// SAML namespace + element local-names the metadata walk looks for (namespace-prefix-agnostic: we match on
// the LOCAL name after any "prefix:", because IdPs vary the prefix - md:, saml2:, or none).
const SSO_SERVICE_LOCAL = "SingleSignOnService";
const ENTITY_DESCRIPTOR_LOCAL = "EntityDescriptor";

function localName(name: string): string {
  const i = name.indexOf(":");
  return i === -1 ? name : name.slice(i + 1);
}
function attrValue(el: XmlElement, local: string): string | undefined {
  for (const a of el.attrs) {
    if (localName(a.name) === local) return a.value;
  }
  return undefined;
}
// walk yields every element in the tree (depth-first), so the metadata scan is robust to nesting/prefix
// variation without hard-coding the EntityDescriptor -> IDPSSODescriptor -> SingleSignOnService path.
function* walk(node: XmlChild): Generator<XmlElement> {
  if (!isElement(node)) return;
  yield node;
  for (const c of node.children) yield* walk(c);
}

// testSamlConnection runs the SAML validity checks. With the discrete-field config it checks:
//   1. entityID present (the IdP's entityID; the assertion Issuer is matched against it at sign-in);
//   2. a SingleSignOnService endpoint present + https-safe (idpSsoUrl - where the browser is redirected);
//   3. at least one pinned signing certificate that PARSES and is WITHIN its notBefore..notAfter window
//      (certValidity from response.ts) - an expired/not-yet-valid/garbage cert would make the dsig verifier
//      reject every assertion. A cert valid now but expiring soon is a "warn".
// When idpMetadataXml is supplied it ALSO parses that document (hardened parser) and confirms it advertises an
// entityID + a SingleSignOnService + a signing cert, catching a paste/transcription error pre-save. The probe
// does NO network for SAML (the SSO URL is a browser redirect, never fetched server-side) - it is pure parse +
// validity, so it cannot SSRF; the only screen needed is the https/host shape of idpSsoUrl. It never throws.
// validateSamlCerts checks the pinned signing certificate(s): at least one that parses AND is within
// its notBefore..notAfter window (certValidity). A cert valid now but expiring soon is a "warn". An
// expired/not-yet-valid/garbage cert would make the dsig verifier reject every assertion.
function validateSamlCerts(idpSigningCerts: string[] | undefined, now: number): IdpTestCheck {
  const certs = Array.isArray(idpSigningCerts) ? idpSigningCerts.filter((c): c is string => typeof c === "string" && c.length > 0) : [];
  if (certs.length === 0) {
    return { name: "Signing certificate", status: "fail", detail: "No pinned signing certificate. Paste the IdP's X.509 signing certificate PEM (the SP refuses an unsigned or wrong-signed assertion)." };
  }
  let inWindow = 0;
  let parsed = 0;
  let soonestExpiryWithinWarn: number | null = null;
  for (const pem of certs) {
    const cv = certValidity(pem);
    if (cv === null) continue; // unparseable / malformed window
    parsed++;
    if (now >= cv.notBefore && now <= cv.notAfter) {
      inWindow++;
      const msToExpiry = cv.notAfter - now;
      if (msToExpiry <= CERT_EXPIRY_WARN_MS && (soonestExpiryWithinWarn === null || cv.notAfter < soonestExpiryWithinWarn)) {
        soonestExpiryWithinWarn = cv.notAfter;
      }
    }
  }
  if (parsed === 0) {
    return { name: "Signing certificate", status: "fail", detail: `None of the ${certs.length} pasted certificate(s) parsed as an X.509 certificate. Confirm you pasted the full PEM, including the BEGIN/END lines.` };
  }
  if (inWindow === 0) {
    return { name: "Signing certificate", status: "fail", detail: `${parsed} certificate(s) parsed but none is currently within its validity window (expired or not yet valid). Upload the IdP's current signing certificate.` };
  }
  if (soonestExpiryWithinWarn !== null) {
    const days = Math.max(0, Math.floor((soonestExpiryWithinWarn - now) / MS_PER_DAY));
    return { name: "Signing certificate", status: "warn", detail: `A valid signing certificate is in use, but the soonest expires in about ${days} day(s). Plan a rollover (pin the next cert alongside this one).` };
  }
  return { name: "Signing certificate", status: "pass", detail: `${inWindow} of ${certs.length} pinned certificate(s) parse and are within their validity window.` };
}

// parseAndCheckSamlMetadata parses the OPTIONAL pasted IdP metadata XML (hardened parser) and confirms
// it advertises an entityID + a SingleSignOnService + a signing certificate, catching a paste error
// pre-save. The cert window is NOT re-validated here (the pinned-cert check is the authority).
function parseAndCheckSamlMetadata(idpMetadataXml: string): IdpTestCheck {
  const parsedXml = parseXml(idpMetadataXml);
  if (!parsedXml.ok) {
    return { name: "IdP metadata XML", status: "fail", detail: `The pasted IdP metadata XML did not parse: ${parsedXml.reason}.` };
  }
  const elements = [...walk(parsedXml.root)];
  const entityDesc = elements.find((e) => localName(e.name) === ENTITY_DESCRIPTOR_LOCAL);
  const hasEntityId = entityDesc !== undefined && typeof attrValue(entityDesc, "entityID") === "string" && attrValue(entityDesc, "entityID")!.length > 0;
  const ssoEl = elements.find((e) => localName(e.name) === SSO_SERVICE_LOCAL);
  const hasSso = ssoEl !== undefined && typeof attrValue(ssoEl, "Location") === "string" && attrValue(ssoEl, "Location")!.length > 0;
  let hasCert = false;
  for (const e of elements) {
    if (localName(e.name) === "X509Certificate") {
      const text = e.children.map((c) => (c.type === "text" ? c.value : "")).join("").trim();
      if (text.length > 0) {
        hasCert = true;
        break;
      }
    }
  }
  const missing: string[] = [];
  if (!hasEntityId) missing.push("an EntityDescriptor entityID");
  if (!hasSso) missing.push("a SingleSignOnService Location");
  if (!hasCert) missing.push("a signing certificate (ds:X509Certificate)");
  if (missing.length === 0) {
    return { name: "IdP metadata XML", status: "pass", detail: "The pasted IdP metadata advertises an entityID, a SingleSignOnService endpoint and a signing certificate." };
  }
  return { name: "IdP metadata XML", status: "fail", detail: `The pasted IdP metadata is missing ${missing.join(", ")}.` };
}

export function testSamlConnection(cfg: SamlTestConfig, opts?: { now?: number }): IdpTestResult {
  const now = opts?.now ?? Date.now();
  const checks: IdpTestCheck[] = [];

  // 1. entityID.
  if (typeof cfg.idpEntityId === "string" && cfg.idpEntityId.trim().length > 0) {
    checks.push({ name: "IdP entityID", status: "pass", detail: "An IdP entityID is set (the assertion Issuer is matched against it)." });
  } else {
    checks.push({ name: "IdP entityID", status: "fail", detail: "No IdP entityID is set. Copy the entityID from your IdP's SAML metadata." });
  }

  // 2. SingleSignOnService (idpSsoUrl) present + https-safe.
  if (typeof cfg.idpSsoUrl === "string" && cfg.idpSsoUrl.trim().length > 0) {
    const p = screenFetchUrl(cfg.idpSsoUrl);
    if (p !== null) {
      checks.push({ name: "SingleSignOnService URL", status: "fail", detail: `The IdP SSO URL is not a usable https endpoint: ${p}.` });
    } else {
      checks.push({ name: "SingleSignOnService URL", status: "pass", detail: "The IdP SSO (SingleSignOnService) URL is a valid https endpoint." });
    }
  } else {
    checks.push({ name: "SingleSignOnService URL", status: "fail", detail: "No IdP SSO URL is set. Copy the HTTP-Redirect SingleSignOnService Location from your IdP's metadata." });
  }

  // 3. Pinned signing certificate(s): at least one that parses AND is in-window.
  checks.push(validateSamlCerts(cfg.idpSigningCerts, now));

  // 4. OPTIONAL: parse the pasted IdP metadata XML (when supplied) and confirm it advertises the essentials.
  if (typeof cfg.idpMetadataXml === "string" && cfg.idpMetadataXml.trim().length > 0) {
    checks.push(parseAndCheckSamlMetadata(cfg.idpMetadataXml));
  }

  return finalise(checks);
}
