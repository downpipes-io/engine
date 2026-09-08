// Validator for the SP SAML metadata builder (src/admin/saml/metadata.ts). buildSpMetadata produces the
// EntityDescriptor XML the customer uploads to their IdP for a SIGN-ONLY, SP-initiated SP. This validator
// proves three things:
//   1. WELL-FORMEDNESS: the output PARSES via the hardened parser (parseXml) - it is exactly one
//      EntityDescriptor with no DTD, no second root, no malformed markup.
//   2. ROUND-TRIP: entityID, the ACS Location, and the NameIDFormat survive intact (escape -> parse -> decode
//      yields the original value back), WantAssertionsSigned is "true", AuthnRequestsSigned is "false", the
//      single AssertionConsumerService uses the HTTP-POST binding with index="0" isDefault="true".
//   3. THE ESCAPING VECTOR: a hostile spEntityId / nameIdFormat / acsUrl carrying '"/><evil>' and raw & < > '
//      cannot break out of the markup - parseXml still yields exactly ONE EntityDescriptor and NO <evil>
//      element appears anywhere in the tree, and the hostile value round-trips through decodeXmlText verbatim.
//
// The module under test is a PURE string builder (no clock, no crypto, no fetch); this validator needs only
// parseXml + the shared decodeXmlText (so "what was escaped" is read back through the SAME character model the
// rest of the SP uses). Run: node --no-warnings test/validate-saml-metadata.ts
//
// Node 25 strip-types; the project ships Workers types only (no @types/node), so we declare the one Node
// global we touch. console is the WebWorker global.

import { buildSpMetadata } from "../src/admin/saml/metadata.ts";
import type { SamlConnection } from "../src/admin/idpconn.ts";
import { parseXml } from "../src/admin/saml/parser.ts";
import { decodeXmlText } from "../src/admin/saml/canonical-text.ts";
import { childElements, findElements, localName } from "../src/admin/saml/xml-node.ts";
import type { XmlElement } from "../src/admin/saml/xml-node.ts";

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

// ---- SAML metadata namespace constants (match metadata.ts) ----
const MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata";
const PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
const BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

// ---- small tree helpers (read RAW attr/text through decodeXmlText, like the production reader) ----
// attrRaw returns the RAW (entity-encoded) attribute value as the parser stored it, or undefined.
function attrRaw(el: XmlElement, name: string): string | undefined {
  for (const at of el.attrs) if (at.name === name) return at.value;
  return undefined;
}
// attr returns the DECODED attribute value (verify == read: decode through the shared model), or undefined.
function attr(el: XmlElement, name: string): string | undefined {
  const r = attrRaw(el, name);
  return r === undefined ? undefined : decodeXmlText(r);
}
// firstChildLocal returns the first child element whose LOCAL name matches (prefix-agnostic).
function firstChildLocal(el: XmlElement, local: string): XmlElement | undefined {
  for (const c of childElements(el)) if (localName(c.name) === local) return c;
  return undefined;
}
// textOf returns the concatenated DECODED text content of an element (its direct text children).
function textOf(el: XmlElement): string {
  let raw = "";
  for (const c of el.children) if (c.type === "text") raw += c.value;
  return decodeXmlText(raw);
}

// ---- a base connection (the SamlConnection shape from idpconn.ts) ----
const NAMEID_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
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
    idpSsoUrl: "https://idp.example.com/sso",
    idpSigningCerts: ["-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"],
    spEntityId: "https://console.downpipes.io/saml/metadata",
    nameIdFormat: NAMEID_PERSISTENT,
    wantAssertionsSigned: true,
    allowIdpInitiated: false,
    clockSkewSec: 120,
    // emailVerifiedPolicy is a required field on SamlConnection; default it here (overridable via `over`) so
    // baseConn() yields a complete, valid connection. The metadata path does not read it.
    emailVerifiedPolicy: "require-flag",
    ...over,
  };
}

// parseOrFail parses XML and returns the root, recording a FAIL (and returning null) when it does not parse.
function parseRoot(xml: string, label: string): XmlElement | null {
  const r = parseXml(xml);
  if (!r.ok) {
    ok(label + " parses via parseXml", false);
    console.log("       parse reason: " + r.reason);
    return null;
  }
  return r.root;
}

// =================================================================================================
// 1. HAPPY PATH: a benign connection - well-formed, all the required shapes present and round-tripping.
// =================================================================================================
{
  const conn = baseConn();
  const acsUrl = "https://console.downpipes.io/admin/saml/acs/work-idp";
  const xml = buildSpMetadata(conn, acsUrl);

  const root = parseRoot(xml, "happy");
  if (root) {
    ok("happy: parses via parseXml (well-formed)", true);
    // The document element is EntityDescriptor (in the metadata namespace, via the md: prefix).
    ok("happy: root local name is EntityDescriptor", localName(root.name) === "EntityDescriptor");
    // The md prefix is bound to the metadata namespace.
    const mdDecl = attrRaw(root, "xmlns:md");
    ok("happy: xmlns:md declares the metadata namespace", mdDecl === MD_NS);
    // entityID round-trips.
    ok("happy: entityID round-trips", attr(root, "entityID") === conn.spEntityId);

    // SPSSODescriptor present with the right flags.
    const spsso = firstChildLocal(root, "SPSSODescriptor");
    ok("happy: SPSSODescriptor present", spsso !== undefined);
    if (spsso) {
      ok("happy: protocolSupportEnumeration is the SAML 2.0 protocol", attr(spsso, "protocolSupportEnumeration") === PROTOCOL_NS);
      ok("happy: AuthnRequestsSigned is 'false' (SP does not sign AuthnRequests in v1)", attr(spsso, "AuthnRequestsSigned") === "false");
      ok("happy: WantAssertionsSigned is 'true'", attr(spsso, "WantAssertionsSigned") === "true");

      // NameIDFormat element text round-trips.
      const nif = firstChildLocal(spsso, "NameIDFormat");
      ok("happy: NameIDFormat element present", nif !== undefined);
      if (nif) ok("happy: NameIDFormat text round-trips", textOf(nif) === conn.nameIdFormat);

      // AssertionConsumerService: HTTP-POST, the ACS location, index 0, default.
      const acs = firstChildLocal(spsso, "AssertionConsumerService");
      ok("happy: AssertionConsumerService present", acs !== undefined);
      if (acs) {
        ok("happy: ACS Binding is HTTP-POST", attr(acs, "Binding") === BINDING_POST);
        ok("happy: ACS Location round-trips", attr(acs, "Location") === acsUrl);
        ok("happy: ACS index is 0", attr(acs, "index") === "0");
        ok("happy: ACS isDefault is true", attr(acs, "isDefault") === "true");
      }
      // Exactly ONE AssertionConsumerService (v1 has a single ACS).
      const acsAll = childElements(spsso).filter((e) => localName(e.name) === "AssertionConsumerService");
      ok("happy: exactly one AssertionConsumerService", acsAll.length === 1);
    }

    // SIGN-ONLY: there is NO KeyDescriptor (the SP holds no signing/decrypt key in v1).
    const keyDescs = findElements(root, (e) => localName(e.name) === "KeyDescriptor");
    ok("happy: no KeyDescriptor (sign-only SP, no SP key)", keyDescs.length === 0);
    // And no AuthnRequestsSigned="true" leak anywhere.
    const spssoAll = findElements(root, (e) => localName(e.name) === "SPSSODescriptor");
    ok("happy: exactly one SPSSODescriptor", spssoAll.length === 1);
  }
}

// =================================================================================================
// 2. THE ESCAPING VECTOR: a hostile spEntityId, nameIdFormat AND acsUrl. None may break out of markup.
// =================================================================================================
{
  // Each payload tries to: close the current attribute (" / '), close the start tag (>), and inject a child
  // element (<evil>...</evil>), plus carries raw & < > to exercise every escaped character. If ANY interpolated
  // value were emitted unescaped, parseXml would either fail (malformed) or yield an injected <evil> element /
  // extra attributes / a second root.
  const EVIL_ENTITY = 'urn:x"/><evil id="a">pwn</evil><md:KeyDescriptor use="signing"/>';
  const EVIL_NAMEID = "transient\"><evil2/>&<>'-not-really"; // raw quote, angle brackets, ampersand, apostrophe
  const EVIL_ACS = "https://evil.example/'\"><evil3 onload=x>&amp;already&<>";

  const conn = baseConn({ spEntityId: EVIL_ENTITY, nameIdFormat: EVIL_NAMEID });
  const xml = buildSpMetadata(conn, EVIL_ACS);

  const root = parseRoot(xml, "escape");
  if (root) {
    ok("escape: hostile values still parse to well-formed XML", true);
    // STILL exactly one EntityDescriptor document element.
    ok("escape: document element is a single EntityDescriptor", localName(root.name) === "EntityDescriptor");
    // NO injected element anywhere in the tree (the whole point).
    const evil = findElements(root, (e) => {
      const ln = localName(e.name).toLowerCase();
      return ln === "evil" || ln === "evil2" || ln === "evil3";
    });
    ok("escape: NO injected <evil*> element anywhere", evil.length === 0);
    // NO injected KeyDescriptor (the entity payload tried to smuggle one in - escaping must defeat it).
    const keyDescs = findElements(root, (e) => localName(e.name) === "KeyDescriptor");
    ok("escape: NO injected KeyDescriptor element", keyDescs.length === 0);
    // The hostile values must round-trip VERBATIM through the parse + shared decoder (verify == read).
    ok("escape: hostile spEntityId round-trips verbatim", attr(root, "entityID") === EVIL_ENTITY);

    const spsso = firstChildLocal(root, "SPSSODescriptor");
    ok("escape: SPSSODescriptor still present and well-formed", spsso !== undefined);
    if (spsso) {
      // The flags are untouched by the injection attempt.
      ok("escape: WantAssertionsSigned still 'true'", attr(spsso, "WantAssertionsSigned") === "true");
      const nif = firstChildLocal(spsso, "NameIDFormat");
      ok("escape: NameIDFormat present", nif !== undefined);
      if (nif) ok("escape: hostile nameIdFormat round-trips verbatim", textOf(nif) === EVIL_NAMEID);
      const acs = firstChildLocal(spsso, "AssertionConsumerService");
      ok("escape: AssertionConsumerService present", acs !== undefined);
      if (acs) ok("escape: hostile acsUrl round-trips verbatim", attr(acs, "Location") === EVIL_ACS);
    }
    // Exactly one SPSSODescriptor, one ACS - no structural duplication from injection.
    ok("escape: still exactly one SPSSODescriptor", findElements(root, (e) => localName(e.name) === "SPSSODescriptor").length === 1);
    ok("escape: still exactly one AssertionConsumerService", findElements(root, (e) => localName(e.name) === "AssertionConsumerService").length === 1);
  }
}

// =================================================================================================
// 3. EXTRA ATTRIBUTE-BREAKOUT vectors: a value that is JUST a closing quote + new attribute, and one with a
//    raw ampersand that is NOT a valid entity (a forgiving builder that did not escape & would emit invalid
//    XML the hardened parser rejects). These prove every position is escaped, not only the obvious payload.
// =================================================================================================
{
  // A spEntityId that, unescaped, would inject an extra attribute onto EntityDescriptor.
  const conn1 = baseConn({ spEntityId: 'x" evilAttr="1' });
  const root1 = parseRoot(buildSpMetadata(conn1, "https://acs.example/x"), "attr-breakout");
  if (root1) {
    ok("attr-breakout: parses (quote in entityID did not open a new attribute)", true);
    ok("attr-breakout: no injected evilAttr on EntityDescriptor", attrRaw(root1, "evilAttr") === undefined);
    ok("attr-breakout: entityID round-trips with the embedded quote", attr(root1, "entityID") === 'x" evilAttr="1');
  }

  // A raw ampersand (NOT part of any entity) in the acsUrl. An unescaped & is invalid XML; escaping to &amp;
  // keeps it well-formed and round-tripping. (validateEntityRefs in the parser would reject a bare '&'.)
  const conn2 = baseConn();
  const acs2 = "https://acs.example/cb?a=1&b=2&x=<y>";
  const root2 = parseRoot(buildSpMetadata(conn2, acs2), "raw-amp");
  if (root2) {
    ok("raw-amp: parses (raw '&' and angle brackets in acsUrl were escaped)", true);
    const spsso = firstChildLocal(root2, "SPSSODescriptor");
    const acs = spsso ? firstChildLocal(spsso, "AssertionConsumerService") : undefined;
    ok("raw-amp: acsUrl with '&' and '<>' round-trips verbatim", acs !== undefined && attr(acs, "Location") === acs2);
  }

  // An apostrophe in entityID: harmless in a double-quoted attribute, but we escape it anyway (&apos;) for the
  // single-quote-context defence; either way it must round-trip.
  const conn3 = baseConn({ spEntityId: "o'brien & sons <co>" });
  const root3 = parseRoot(buildSpMetadata(conn3, "https://acs.example/x"), "apos");
  if (root3) {
    ok("apos: parses with apostrophe + ampersand + angle brackets in entityID", true);
    ok("apos: entityID round-trips verbatim", attr(root3, "entityID") === "o'brien & sons <co>");
  }
}

// =================================================================================================
// final tally (the sibling-validator convention)
// =================================================================================================
if (failures > 0) process.exitCode = 1;
if (failures > 0) {
  console.log("SAML METADATA VECTORS: " + passed + " passed, " + failures + " FAILED");
  process.exitCode = 1;
} else {
  console.log("SAML METADATA VECTORS PASS (" + passed + " checks)");
}
