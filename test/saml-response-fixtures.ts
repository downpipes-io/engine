// Shared fixtures + helpers for the SAML ACS response verifier validator suite (split out of
// validate-saml-response.ts so each group module is under the size budget). This module holds the tree builders,
// the enveloped XML-DSig signer, the self-signed cert builder, the fixed reference constants and the connection
// /context factories. The group modules (spki / happy / red / structural) import from here and each export a
// `run(h, keys)` function; the orchestrator (validate-saml-response.ts) owns the harness state and calls each
// group in order, so the full suite still executes when that one file is run.
//
// Node 25 strip-types; Web Crypto only (global crypto.subtle), no Node builtins.

import { canonicalize, envelopedCopy } from "../src/admin/saml/c14n.ts";
import type { XmlElement, XmlAttr, XmlChild } from "../src/admin/saml/xml-node.ts";
import type { SamlConnection } from "../src/admin/idpconn.ts";
import type { VerifyContext } from "../src/admin/saml/response.ts";
import { ab } from "../src/crypto/bytes.ts";
import { derSeq, derTlv, derInt, derOid, derNull, derGeneralizedTime, derUtf8, derExplicit0, derBitString, OID_SHA256_RSA, OID_CN } from "./saml-der.ts";

// ---- tiny test harness (ok(name, cond) shape the sibling validators use) ----
// The orchestrator owns the counters; each group module receives this object and calls h.ok(...).
export interface Harness {
  ok(name: string, cond: boolean): void;
}

export function makeHarness(state: { passed: number; fails: string[] }): Harness {
  return {
    ok(name: string, cond: boolean): void {
      if (cond) {
        state.passed++;
        console.log("  ok   " + name);
      } else {
        state.fails.push(name);
        console.log("  FAIL " + name);
      }
    },
  };
}

// ---- the real key material every group shares (generated once by the orchestrator) ----
export interface Keys {
  rsa: CryptoKeyPair;
  rsaSpki: Uint8Array;
  certPem: string;
  rsaOther: CryptoKeyPair;
  rsaOtherSpki: Uint8Array;
  certOtherPem: string;
}

// ---- tree builders (same shape as validate-saml-dsig.ts / validate-saml-assertion.ts) ----
export function el(name: string, attrs: XmlAttr[], children: XmlChild[]): XmlElement {
  return { type: "element", name, attrs, children };
}
export function a(name: string, value: string): XmlAttr {
  return { name, value };
}
export function t(value: string): XmlChild {
  return { type: "text", value };
}
export function clone(x: XmlElement): XmlElement {
  return {
    type: "element",
    name: x.name,
    attrs: x.attrs.map((at) => ({ name: at.name, value: at.value })),
    children: x.children.map((c) => (c.type === "element" ? clone(c) : { type: c.type, value: c.value }) as XmlChild),
  };
}

// ---- standard base64 (with padding) ----
export function b64std(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

// ---- a faithful, c14n-aware XML serialiser for an XmlElement tree (raw values verbatim) ----
// We serialise the hand-built tree to an XML string so the PRODUCTION parser re-parses it (string -> parseXml),
// exercising the real byte-gated path. Attribute and text values are written VERBATIM (they are already RAW /
// entity-encoded in the tree, exactly as the parser preserves them), so a round trip is byte-faithful for the
// signature. Element/attribute order is preserved. This is a SERIALISER for the test only.
export function serialise(node: XmlChild): string {
  if (node.type === "text") return node.value;
  if (node.type === "comment") return "<!--" + node.value + "-->";
  let s = "<" + node.name;
  for (const at of node.attrs) s += " " + at.name + '="' + at.value + '"';
  if (node.children.length === 0) {
    s += "/>";
    return s;
  }
  s += ">";
  for (const c of node.children) s += serialise(c);
  s += "</" + node.name + ">";
  return s;
}

// ---- algorithm URIs (match dsig.ts) ----
const C14N_EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
const TRANSFORM_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const SIG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";

// ---- fixed reference constants (a fixed clock + connection/context values) ----
export const SAML_PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
export const SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
export const STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
export const STATUS_REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester";
export const NAMEID_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
export const BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

export const IDP_ENTITY = "https://idp.example.com/entity";
export const SP_ENTITY = "https://console.downpipes.io/saml/metadata";
export const ACS_URL = "https://console.downpipes.io/admin/saml/acs/work-idp";
export const IN_RESPONSE_TO = "_req_abc123";
export const ASSERTION_ID = "_assertion_0001";
export const RESPONSE_ID = "_response_0001";
export const CONN_ID = "work-idp";

export const NOW_MS = Date.parse("2026-06-13T12:00:00Z");
const NOT_BEFORE = "2026-06-13T11:55:00Z";
const NOT_ON_OR_AFTER = "2026-06-13T12:05:00Z";
const SCD_NOT_ON_OR_AFTER = "2026-06-13T12:05:00Z";

export function baseConn(certs: string[], over: Partial<SamlConnection> = {}): SamlConnection {
  return {
    kind: "saml",
    id: CONN_ID,
    label: "Work IdP",
    presetId: "generic-saml",
    enabled: true,
    createdBy: "owner@example.com",
    createdAt: "2026-06-13T00:00:00.000Z",
    idpEntityId: IDP_ENTITY,
    idpSsoUrl: "https://idp.example.com/sso",
    idpSigningCerts: certs,
    spEntityId: SP_ENTITY,
    nameIdFormat: "",
    wantAssertionsSigned: true,
    allowIdpInitiated: false,
    clockSkewSec: 120,
    emailAttr: "email",
    groupsAttr: "groups",
    emailVerifiedPolicy: "trust-idp",
    ...over,
  };
}

export function baseCtx(over: Partial<VerifyContext> = {}): VerifyContext {
  return { acsUrl: ACS_URL, expectedInResponseTo: IN_RESPONSE_TO, nowMs: NOW_MS, ...over };
}

// ---- assertion + response fixture builders ----
export interface AOpts {
  assertionId?: string;
  nameId?: string;
  nameIdFormat?: string;
  recipient?: string;
  inResponseTo?: string | null; // null = omit the SCD InResponseTo (IdP-initiated)
  audience?: string;
  notBefore?: string;
  notOnOrAfter?: string;
  scdNotOnOrAfter?: string;
  email?: string;
  groups?: string[];
}

// buildAssertion builds a well-formed bearer, SP-initiated saml:Assertion that declares the saml: namespace
// itself (as a real IdP does), so every descendant resolves to the assertion namespace.
export function buildAssertion(o: AOpts = {}): XmlElement {
  const assertionId = o.assertionId ?? ASSERTION_ID;
  const nameId = o.nameId ?? "alice@example.com";
  const nameIdFormat = o.nameIdFormat ?? NAMEID_PERSISTENT;
  const recipient = o.recipient ?? ACS_URL;
  const audience = o.audience ?? SP_ENTITY;
  const notBefore = o.notBefore ?? NOT_BEFORE;
  const notOnOrAfter = o.notOnOrAfter ?? NOT_ON_OR_AFTER;
  const scdNotOnOrAfter = o.scdNotOnOrAfter ?? SCD_NOT_ON_OR_AFTER;
  const email = o.email ?? "alice@example.com";
  const groups = o.groups ?? ["administrators", "billing"];

  const scdAttrs: XmlAttr[] = [a("Recipient", recipient), a("NotOnOrAfter", scdNotOnOrAfter)];
  if (o.inResponseTo !== null) scdAttrs.push(a("InResponseTo", o.inResponseTo ?? IN_RESPONSE_TO));
  const scd = el("saml:SubjectConfirmationData", scdAttrs, []);
  const subjectConfirmation = el("saml:SubjectConfirmation", [a("Method", BEARER)], [scd]);
  const nameIdEl = el("saml:NameID", [a("Format", nameIdFormat)], [t(nameId)]);
  const subject = el("saml:Subject", [], [nameIdEl, subjectConfirmation]);

  const conditions = el(
    "saml:Conditions",
    [a("NotBefore", notBefore), a("NotOnOrAfter", notOnOrAfter)],
    [el("saml:AudienceRestriction", [], [el("saml:Audience", [], [t(audience)])])],
  );

  const groupValueEls = groups.map((g) => el("saml:AttributeValue", [], [t(g)]));
  const attributeStatement = el("saml:AttributeStatement", [], [
    el("saml:Attribute", [a("Name", "email")], [el("saml:AttributeValue", [], [t(email)])]),
    el("saml:Attribute", [a("Name", "groups")], groupValueEls),
  ]);

  return el(
    "saml:Assertion",
    [a("xmlns:saml", SAML_ASSERTION_NS), a("ID", assertionId), a("Version", "2.0"), a("IssueInstant", "2026-06-13T11:59:00Z")],
    [el("saml:Issuer", [], [t(IDP_ENTITY)]), subject, conditions, attributeStatement],
  );
}

// buildResponse wraps assertion children in a samlp:Response, with a Status (Success by default) and the
// Response-level @Destination + @InResponseTo by default. Pass statusValue / destination / inResponseTo to
// perturb them; inResponseTo:null omits the Response-level attribute (envelope IdP-initiated).
export interface ROpts {
  statusValue?: string;
  destination?: string | null; // null = omit @Destination
  inResponseTo?: string | null; // null = omit @InResponseTo
  responseId?: string;
}
export function buildResponse(assertionChildren: XmlElement[], o: ROpts = {}): XmlElement {
  const statusValue = o.statusValue ?? STATUS_SUCCESS;
  const responseId = o.responseId ?? RESPONSE_ID;
  const attrs: XmlAttr[] = [
    a("xmlns:samlp", SAML_PROTOCOL_NS),
    a("ID", responseId),
    a("Version", "2.0"),
    a("IssueInstant", "2026-06-13T11:59:30Z"),
  ];
  if (o.destination !== null) attrs.push(a("Destination", o.destination ?? ACS_URL));
  if (o.inResponseTo !== null) attrs.push(a("InResponseTo", o.inResponseTo ?? IN_RESPONSE_TO));
  const status = el("samlp:Status", [], [el("samlp:StatusCode", [a("Value", statusValue)], [])]);
  return el("samlp:Response", attrs, [status, ...assertionChildren]);
}

// ---- the enveloped XML-DSig signer (mirrors validate-saml-dsig.ts signAssertion) ----
function buildSignedInfo(refId: string, digestB64: string): XmlElement {
  return el(
    "ds:SignedInfo",
    [a("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")],
    [
      el("ds:CanonicalizationMethod", [a("Algorithm", C14N_EXC)], []),
      el("ds:SignatureMethod", [a("Algorithm", SIG_RSA_SHA256)], []),
      el(
        "ds:Reference",
        [a("URI", "#" + refId)],
        [
          el("ds:Transforms", [], [
            el("ds:Transform", [a("Algorithm", TRANSFORM_ENVELOPED)], []),
            el("ds:Transform", [a("Algorithm", C14N_EXC)], []),
          ]),
          el("ds:DigestMethod", [a("Algorithm", DIGEST_SHA256)], []),
          el("ds:DigestValue", [], [t(digestB64)]),
        ],
      ),
    ],
  );
}

// signAssertion inserts a real enveloped ds:Signature into a COPY of the assertion: it computes the Reference
// digest over exc-c14n#(enveloped(assertion)) with the SAME c14n the verifier uses, builds + canonicalises
// SignedInfo, signs it with the RSA private key, and embeds the SignatureValue. Returns the signed assertion.
export async function signAssertion(assertion: XmlElement, refId: string, privateKey: CryptoKey): Promise<XmlElement> {
  const placeholderSi = buildSignedInfo(refId, "");
  const signature = el("ds:Signature", [a("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")], [
    placeholderSi,
    el("ds:SignatureValue", [], [t("")]),
  ]);

  const signed = clone(assertion);
  signed.children.splice(1, 0, signature); // after Issuer, like real IdPs
  const insertedSig = signed.children[1] as XmlElement;

  const enveloped = envelopedCopy(signed, insertedSig);
  const refCanon = canonicalize(enveloped);
  if (!refCanon.ok) throw new Error("test setup: ref canon failed: " + refCanon.reason);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", ab(new TextEncoder().encode(refCanon.canonical))));
  const digestB64 = b64std(digest);

  const realSi = buildSignedInfo(refId, digestB64);
  insertedSig.children[0] = realSi;

  const siCanon = canonicalize(realSi);
  if (!siCanon.ok) throw new Error("test setup: SignedInfo canon failed: " + siCanon.reason);
  const sigBytes = new Uint8Array(
    await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, ab(new TextEncoder().encode(siCanon.canonical))),
  );
  insertedSig.children[1] = el("ds:SignatureValue", [], [t(b64std(sigBytes))]);
  return signed;
}

// The minimal DER encoders (derLen/derTlv/derSeq/.../OID_SHA256_RSA/OID_CN) used to build a real self-signed
// X.509 cert wrapping an RSA public key live in saml-der.ts (imported at the top), shared with the other SAML
// validators that build the same fixtures.

// buildSelfSignedCertPem builds a real, structurally-valid, self-signed X.509 v3 certificate around the given
// public key's exported SPKI, signs the TBS with `signerPrivate`, and returns the PEM. We splice the already-DER
// SPKI bytes straight in (it is itself a DER SEQUENCE).
export async function buildSelfSignedCertPem(spkiDer: Uint8Array, signerPrivate: CryptoKey, cn: string): Promise<string> {
  // Name ::= SEQUENCE OF RelativeDistinguishedName; RDN ::= SET OF AttributeTypeAndValue.
  const atv = derSeq(derOid(OID_CN), derUtf8(cn)); // AttributeTypeAndValue { type, value }
  const rdn = derTlv(0x31, atv); // SET
  const name = derSeq(rdn);

  const sigAlg = derSeq(derOid(OID_SHA256_RSA), derNull());
  const version = derExplicit0(derInt([0x02])); // v3
  const serial = derInt([0x01]);
  const validity = derSeq(
    derGeneralizedTime("20260101000000Z"),
    derGeneralizedTime("20360101000000Z"),
  );

  const tbs = derSeq(
    version,
    serial,
    sigAlg,
    name, // issuer
    validity,
    name, // subject
    Array.from(spkiDer), // subjectPublicKeyInfo (already a DER SEQUENCE)
  );

  const tbsBytes = new Uint8Array(tbs);
  const certSig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", signerPrivate, ab(tbsBytes)));

  const cert = derSeq(tbs, sigAlg, derBitString(certSig));
  const certBytes = new Uint8Array(cert);
  const b64 = b64std(certBytes);
  // Wrap to 64-char lines (the canonical PEM shape) to also prove the PEM parser strips line breaks.
  let lines = "";
  for (let i = 0; i < b64.length; i += 64) lines += b64.slice(i, i + 64) + "\n";
  return "-----BEGIN CERTIFICATE-----\n" + lines + "-----END CERTIFICATE-----\n";
}

// encodeResponse serialises a samlp:Response tree and base64-encodes it as the POST SAMLResponse field value.
export function encodeResponse(response: XmlElement): string {
  return b64std(new TextEncoder().encode(serialise(response)));
}
