// Validator for the SP-initiated AuthnRequest builder + HTTP-Redirect binding encoder
// (src/admin/saml/authn-request.ts). It proves four things, test-first:
//   1. SHAPE: buildAuthnRequestXml emits XML that PARSES via the hardened parser (parseXml) and carries the
//      right ID / Destination / AssertionConsumerServiceURL / ProtocolBinding on the root, the spEntityId in
//      saml:Issuer, and a samlp:NameIDPolicy with the connection's Format + AllowCreate="true".
//   2. ROUND-TRIP: deflateRedirectParam's output, base64-decoded (standard base64) and inflated via
//      DecompressionStream("deflate-raw"), is BYTE-IDENTICAL to the original AuthnRequest XML - proving raw
//      DEFLATE (not zlib "deflate") + standard base64 were used.
//   3. REDIRECT: buildRedirectUrl returns <idpSsoUrl>?SAMLRequest=..&RelayState=.. as proper URL-encoded query
//      parameters on the configured SSO URL, and the SAMLRequest param decodes+inflates back to the same XML.
//   4. ESCAPING: a hostile spEntityId / nameIdFormat cannot inject markup (the document still parses to ONE
//      AuthnRequest with the literal value preserved after entity-decode), and a hostile relayState cannot
//      inject a SECOND query parameter (URLSearchParams percent-encodes '&' and '='); the base64 '+' is
//      percent-encoded so the IdP cannot misread it as a space.
//
// The builder is exercised exactly as in production (the DO hands it a minted id + issueInstant; we pass fixed
// ones). The parser used to assert the shape is the same hardened parseXml the inbound path trusts.
//
// Node 25 strip-types; Web Streams + parseXml only, no Node builtins beyond the harness exit code. console is
// the WebWorker global.

import { buildAuthnRequestXml, deflateRedirectParam, buildRedirectUrl } from "../src/admin/saml/authn-request.ts";
import type { AuthnRequestParams } from "../src/admin/saml/authn-request.ts";
import { parseXml } from "../src/admin/saml/parser.ts";
import type { XmlElement } from "../src/admin/saml/xml-node.ts";
import { childElements, localName, findElements } from "../src/admin/saml/xml-node.ts";
import { decodeXmlText } from "../src/admin/saml/canonical-text.ts";
import { ab } from "../src/crypto/bytes.ts";
import type { SamlConnection } from "../src/admin/idpconn.ts";

// This validator runs under Node (strip-types); the project tsconfig ships Workers types only (no @types/node).
// Declare the single Node global we use so the file is tsc-clean under those flags.
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

// ---- fixed reference values (deterministic; the builder is pure and reads no clock) ----
const IDP_SSO_URL = "https://idp.example.com/sso/redirect";
const SP_ENTITY = "https://console.downpipes.io/saml/metadata";
const ACS_URL = "https://console.downpipes.io/admin/saml/acs/work-idp";
const NAMEID_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const REQ_ID = "_a1b2c3d4e5f60718293a4b5c6d7e8f90";
const ISSUE_INSTANT = "2026-06-13T12:00:00Z";
const RELAY_STATE = "work-idp:/#/govern/identity";

const NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
const NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
const PROTOCOL_BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

// The pinned connection. Only the fields the builder reads (idpSsoUrl, spEntityId, nameIdFormat) matter here;
// the rest satisfy the SamlConnection type.
function baseConn(over: Partial<SamlConnection> = {}): SamlConnection {
  return {
    kind: "saml",
    id: "work-idp",
    label: "Work IdP",
    presetId: "generic-saml",
    enabled: true,
    createdBy: "owner@example.com",
    createdAt: "2026-06-13T00:00:00.000Z",
    idpEntityId: "https://idp.example.com/entity",
    idpSsoUrl: IDP_SSO_URL,
    idpSigningCerts: ["-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"],
    spEntityId: SP_ENTITY,
    nameIdFormat: NAMEID_PERSISTENT,
    wantAssertionsSigned: true,
    allowIdpInitiated: false,
    clockSkewSec: 120,
    emailAttr: "email",
    groupsAttr: "groups",
    // emailVerifiedPolicy is a required field on SamlConnection; default it here (overridable via `over`) so
    // baseConn() yields a complete, valid connection. The authn-request paths do not read it.
    emailVerifiedPolicy: "require-flag",
    ...over,
  };
}

function baseParams(over: Partial<AuthnRequestParams> = {}): AuthnRequestParams {
  return { id: REQ_ID, issueInstant: ISSUE_INSTANT, acsUrl: ACS_URL, ...over };
}

// ---- helpers ----
// attrOf reads a root attribute's DECODED value (the builder escapes, so we decode to compare the true value).
function attrOf(el: XmlElement, name: string): string | null {
  for (const at of el.attrs) {
    if (at.name === name) return decodeXmlText(at.value);
  }
  return null;
}

// decodedText returns the decoded concatenated text of an element's direct text children.
function decodedText(el: XmlElement): string {
  let s = "";
  for (const c of el.children) {
    if (c.type === "text") s += decodeXmlText(c.value);
  }
  return s;
}

// firstByLocal returns the first descendant (incl. el) with the given local name, or null.
function firstByLocal(el: XmlElement, local: string): XmlElement | null {
  const all = findElements(el, (e) => localName(e.name) === local);
  return all.length > 0 ? all[0]! : null;
}

// ---- standard base64 decode (inverse of the builder's encoder), for the round trip ----
const B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function base64StdDecode(s: string): Uint8Array {
  const lut = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64_STD.length; i++) lut[B64_STD.charCodeAt(i)] = i;
  const body = s.replace(/=+$/, "");
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const ch of body) {
    const v = lut[ch.charCodeAt(0)] ?? -1;
    if (v < 0) throw new Error("non-base64 char in SAMLRequest: " + JSON.stringify(ch));
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

// inflateRaw decompresses RFC 1951 raw DEFLATE bytes via DecompressionStream("deflate-raw").
async function inflateRaw(bytes: Uint8Array): Promise<Uint8Array> {
  const ds = new DecompressionStream("deflate-raw");
  const writer = ds.writable.getWriter();
  void writer.write(ab(bytes));
  void writer.close();
  const reader = ds.readable.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      chunks.push(value);
      total += value.length;
    }
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

async function main(): Promise<void> {
  console.log("SAML AuthnRequest + HTTP-Redirect binding vectors\n");

  // ============================ 1. SHAPE ============================
  console.log("shape (the AuthnRequest XML parses and carries the right values):\n");
  const xml = buildAuthnRequestXml(baseConn(), baseParams());
  const parsed = parseXml(xml);
  ok("AuthnRequest XML parses via the hardened parseXml", parsed.ok === true);
  if (parsed.ok) {
    const root = parsed.root;
    ok("root local-name is AuthnRequest", localName(root.name) === "AuthnRequest");
    ok("root resolves to the samlp protocol namespace", attrOf(root, "xmlns:samlp") === NS_SAMLP);
    ok("the saml assertion namespace is declared", attrOf(root, "xmlns:saml") === NS_SAML);
    ok("ID == the minted request id", attrOf(root, "ID") === REQ_ID);
    ok("Version == 2.0", attrOf(root, "Version") === "2.0");
    ok("IssueInstant == the minted instant", attrOf(root, "IssueInstant") === ISSUE_INSTANT);
    ok("Destination == conn.idpSsoUrl", attrOf(root, "Destination") === IDP_SSO_URL);
    ok("ProtocolBinding == HTTP-POST", attrOf(root, "ProtocolBinding") === PROTOCOL_BINDING_POST);
    ok("AssertionConsumerServiceURL == p.acsUrl", attrOf(root, "AssertionConsumerServiceURL") === ACS_URL);

    // Issuer (saml namespace) carries the spEntityId.
    const issuer = firstByLocal(root, "Issuer");
    ok("saml:Issuer present", issuer !== null && localName(issuer.name) === "Issuer");
    ok("Issuer text == conn.spEntityId", issuer !== null && decodedText(issuer) === SP_ENTITY);

    // NameIDPolicy (samlp namespace) carries the connection's Format + AllowCreate="true".
    const nidp = firstByLocal(root, "NameIDPolicy");
    ok("samlp:NameIDPolicy present", nidp !== null && localName(nidp.name) === "NameIDPolicy");
    ok("NameIDPolicy Format == conn.nameIdFormat", nidp !== null && attrOf(nidp, "Format") === NAMEID_PERSISTENT);
    ok("NameIDPolicy AllowCreate == true", nidp !== null && attrOf(nidp, "AllowCreate") === "true");

    // Exactly two direct child elements (Issuer, NameIDPolicy); no Signature is emitted (sign-only SP).
    const kids = childElements(root);
    ok("root has exactly two child elements (Issuer, NameIDPolicy)", kids.length === 2);
    ok("no ds:Signature is emitted (sign-only SP does not sign its AuthnRequest)", findElements(root, (e) => localName(e.name) === "Signature").length === 0);
  }

  // ============================ 2. DEFLATE ROUND-TRIP ============================
  console.log("\ndeflate round-trip (raw DEFLATE + standard base64 -> back to the exact XML bytes):\n");
  {
    const param = await deflateRedirectParam(xml);
    ok("deflateRedirectParam returns a non-empty string", typeof param === "string" && param.length > 0);
    // It must be STANDARD base64 (only the standard alphabet + '=' padding), NOT base64url (no '-' or '_').
    ok("the param is standard base64 (no '-' or '_' from base64url)", /^[A-Za-z0-9+/]+={0,2}$/.test(param));
    // Base64-decode then raw-inflate; the bytes must equal the original UTF-8 XML exactly.
    const deflatedBytes = base64StdDecode(param);
    const inflated = await inflateRaw(deflatedBytes);
    const originalBytes = new TextEncoder().encode(xml);
    ok("base64-decode + inflate(deflate-raw) reproduces the EXACT XML bytes", bytesEqual(inflated, originalBytes));
    // Cross-check: the inflated text re-parses to the same root local name (the bytes really are the AuthnRequest).
    const reparsed = parseXml(inflated);
    ok("the inflated bytes re-parse to an AuthnRequest", reparsed.ok === true && localName(reparsed.root.name) === "AuthnRequest");
    // Negative: feeding the deflate bytes to a zlib reader would need a 2-byte header; assert the first byte is
    // NOT a zlib CMF (0x78 is the usual zlib header). Raw DEFLATE starts with a block header, not 0x78 0x9c/0xda.
    // (This is a heuristic guard that "deflate" was not used; the authoritative proof is the byte round trip.)
    ok("deflate bytes do not begin with a zlib header (0x78 ..) - raw DEFLATE was used", !(deflatedBytes.length >= 2 && deflatedBytes[0] === 0x78 && (deflatedBytes[1] === 0x9c || deflatedBytes[1] === 0xda || deflatedBytes[1] === 0x01 || deflatedBytes[1] === 0x5e)));
  }

  // ============================ 3. REDIRECT URL ============================
  console.log("\nredirect URL (SAMLRequest + RelayState as proper query params on the SSO URL):\n");
  {
    const redirect = await buildRedirectUrl(baseConn(), { id: REQ_ID, issueInstant: ISSUE_INSTANT, acsUrl: ACS_URL, relayState: RELAY_STATE });
    const u = new URL(redirect);
    ok("redirect origin+path == the configured idpSsoUrl", u.origin + u.pathname === IDP_SSO_URL);
    ok("redirect carries a SAMLRequest query param", u.searchParams.has("SAMLRequest"));
    ok("redirect carries a RelayState query param", u.searchParams.has("RelayState"));
    ok("RelayState round-trips to the exact value", u.searchParams.get("RelayState") === RELAY_STATE);
    // The SAMLRequest param, URL-decoded by the URL API, must base64-decode + inflate back to the XML the
    // builder produced for these exact params.
    const expectedXml = buildAuthnRequestXml(baseConn(), { id: REQ_ID, issueInstant: ISSUE_INSTANT, acsUrl: ACS_URL });
    const sr = u.searchParams.get("SAMLRequest");
    ok("SAMLRequest is present (non-null)", sr !== null);
    if (sr !== null) {
      const inflated = await inflateRaw(base64StdDecode(sr));
      ok("SAMLRequest decodes+inflates to the AuthnRequest XML", new TextDecoder().decode(inflated) === expectedXml);
    }
    // The RAW redirect string must percent-encode the base64 '+' as %2B (so the IdP's form-decode does not turn
    // it into a space). Only assert when the base64 actually contains a '+'.
    const rawParam = await deflateRedirectParam(expectedXml);
    if (rawParam.includes("+")) {
      ok("the '+' in the base64 is percent-encoded (%2B) in the raw redirect URL", redirect.includes("%2B") && !redirect.includes("SAMLRequest=" + rawParam.slice(0, 1) + "+"));
    } else {
      ok("(base64 contained no '+' for this vector; '+'-encoding check skipped)", true);
    }
    // An IdP SSO URL that ALREADY carries an unrelated query param keeps it and still gains the two SAML params.
    const redirect2 = await buildRedirectUrl(baseConn({ idpSsoUrl: "https://idp.example.com/sso?tenant=acme" }), {
      id: REQ_ID,
      issueInstant: ISSUE_INSTANT,
      acsUrl: ACS_URL,
      relayState: RELAY_STATE,
    });
    const u2 = new URL(redirect2);
    ok("a pre-existing SSO-URL query param is preserved", u2.searchParams.get("tenant") === "acme");
    ok("the SAML params are added alongside it", u2.searchParams.has("SAMLRequest") && u2.searchParams.has("RelayState"));
  }

  // ============================ 4. ESCAPING / INJECTION ============================
  console.log("\nescaping (a hostile entityId / nameIdFormat / relayState cannot inject markup or a param):\n");
  {
    // 4a. A hostile spEntityId that tries to close Issuer and inject a second element + a forged AllowCreate.
    const evilEntity = `me</saml:Issuer><saml:Issuer>evil</saml:Issuer><Inject foo="bar">x`;
    const evilXml = buildAuthnRequestXml(baseConn({ spEntityId: evilEntity }), baseParams());
    const evilParsed = parseXml(evilXml);
    ok("XML with a hostile spEntityId still parses (escaping kept it well-formed)", evilParsed.ok === true);
    if (evilParsed.ok) {
      // Exactly ONE Issuer; its DECODED text equals the literal hostile string (the markup was neutralised to text).
      const issuers = findElements(evilParsed.root, (e) => localName(e.name) === "Issuer");
      ok("there is exactly ONE Issuer (no injected second Issuer element)", issuers.length === 1);
      ok("the hostile spEntityId is preserved as literal TEXT, not parsed as markup", issuers.length === 1 && decodedText(issuers[0]!) === evilEntity);
      // No injected element leaked into the tree.
      ok("no <Inject> element was created from the hostile value", findElements(evilParsed.root, (e) => localName(e.name) === "Inject").length === 0);
      // Still exactly two child elements of the root (Issuer + NameIDPolicy).
      ok("the root still has exactly two children after the escaping attempt", childElements(evilParsed.root).length === 2);
    }

    // 4b. A hostile nameIdFormat that tries to break out of the attribute and add a new attribute / element.
    const evilFormat = `urn:x" AllowCreate="false"><Evil/><x y="`;
    const evilFmtXml = buildAuthnRequestXml(baseConn({ nameIdFormat: evilFormat }), baseParams());
    const efParsed = parseXml(evilFmtXml);
    ok("XML with a hostile nameIdFormat still parses (attribute escaping held)", efParsed.ok === true);
    if (efParsed.ok) {
      const nidp = firstByLocal(efParsed.root, "NameIDPolicy");
      ok("NameIDPolicy Format decodes back to the literal hostile string", nidp !== null && attrOf(nidp, "Format") === evilFormat);
      ok("AllowCreate is still 'true' (the injected AllowCreate=\"false\" did not take effect)", nidp !== null && attrOf(nidp, "AllowCreate") === "true");
      ok("no <Evil> element was injected via the Format value", findElements(efParsed.root, (e) => localName(e.name) === "Evil").length === 0);
    }

    // 4c. A hostile relayState that tries to add a second query parameter (&Evil=1) or overwrite SAMLRequest.
    const evilRelay = `legit&SAMLRequest=FORGED&Evil=1`;
    const redirect = await buildRedirectUrl(baseConn(), { id: REQ_ID, issueInstant: ISSUE_INSTANT, acsUrl: ACS_URL, relayState: evilRelay });
    const u = new URL(redirect);
    ok("the hostile relayState round-trips as a SINGLE opaque value (the '&' was percent-encoded)", u.searchParams.get("RelayState") === evilRelay);
    ok("no injected 'Evil' query parameter exists", u.searchParams.get("Evil") === null);
    // The genuine SAMLRequest (the deflate+base64 of the real XML) was NOT overwritten by the forged value.
    const expectedXml = buildAuthnRequestXml(baseConn(), { id: REQ_ID, issueInstant: ISSUE_INSTANT, acsUrl: ACS_URL });
    const sr = u.searchParams.get("SAMLRequest");
    ok("SAMLRequest is the genuine value, not the forged 'FORGED' string", sr !== null && sr !== "FORGED");
    if (sr !== null) {
      const inflated = await inflateRaw(base64StdDecode(sr));
      ok("the genuine SAMLRequest still inflates to the real AuthnRequest XML", new TextDecoder().decode(inflated) === expectedXml);
    }
    // The raw redirect string must contain exactly one 'SAMLRequest=' and one 'RelayState=' occurrence.
    ok("the raw URL contains exactly one 'SAMLRequest=' occurrence", (redirect.match(/SAMLRequest=/g) ?? []).length === 1);
    ok("the raw URL contains exactly one 'RelayState=' occurrence", (redirect.match(/RelayState=/g) ?? []).length === 1);
  }

  // ---- summary ----
  console.log("");
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.log("SAML AUTHN-REQUEST VECTORS: " + passed + " passed, " + failures + " FAILED");
    process.exitCode = 1;
  } else {
    console.log("SAML AUTHN-REQUEST VECTORS PASS (" + passed + " checks)");
  }
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
