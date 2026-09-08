// Shared fixtures + helpers for the real-world-IdP interop + anti-regression corpus (split out of
// validate-saml-interop.ts so each group module is under the size budget). This module holds the tiny harness,
// the tree builders, the faithful XML serialiser, the enveloped XML-DSig signer (with the IDP-2 InclusiveNamespaces
// PrefixList option), the self-signed cert builder with a controllable validity window (IDP-4), and the fixed
// reference constants and the connection/context factories. The group modules (idp1 / idp2 / idp4) import from
// here and each export a `run(h, keys)` function; the orchestrator (validate-saml-interop.ts) owns the harness
// state and calls each group in order, so the full suite still executes when that one file is run.
//
// The signing machinery mirrors validate-saml-xsw.ts / validate-saml-response.ts EXACTLY (envelopedCopy + c14n
// digest + SignedInfo sign + a real self-signed cert), so the GREEN controls are honest (a c14n/signing bug
// breaks a control, never hides a red).
//
// Node 25 strip-types; Web Crypto only (global crypto.subtle), no Node builtins beyond the harness exit code.

import type { VerifyContext } from "../src/admin/saml/response.ts";
import { canonicalize, envelopedCopy } from "../src/admin/saml/c14n.ts";
import type { XmlElement, XmlAttr, XmlChild } from "../src/admin/saml/xml-node.ts";
import type { SamlConnection } from "../src/admin/idpconn.ts";
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
  rsaAtk: CryptoKeyPair;
}

// ---- tree builders (same shape as the sibling validators) ----
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

// ---- faithful XML serialiser (raw values verbatim), so the production parser re-parses the bytes ----
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

// ---- algorithm + SAML URIs (match dsig.ts) ----
// The exclusive-c14n namespace URI and algorithm URI are the same string per the exc-c14n# spec, so a
// single constant serves both the Algorithm attribute and the xmlns:ec declaration.
export const C14N_EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
const TRANSFORM_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const SIG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#";

const SAML_PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
export const SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
const STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
const NAMEID_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const XSI_NS = "http://www.w3.org/2001/XMLSchema-instance";
const XSD_NS = "http://www.w3.org/2001/XMLSchema";

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
export const LEGIT_NAMEID = "alice@example.com";
export const EVIL_NAMEID = "attacker@evil.example";

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
  email?: string;
  // xsiTypedEmail: render the email AttributeValue with xsi:type="xs:string" (the ADFS/Shibboleth shape) and
  // declare xsi:/xs: on the ASSERTION root (an ancestor of the value), exercising IDP-2's inherited-namespace +
  // PrefixList path.
  xsiTypedEmail?: boolean;
}
export function buildAssertion(o: AOpts = {}): XmlElement {
  const assertionId = o.assertionId ?? ASSERTION_ID;
  const nameId = o.nameId ?? LEGIT_NAMEID;
  const email = o.email ?? LEGIT_NAMEID;

  const scd = el("saml:SubjectConfirmationData", [a("Recipient", ACS_URL), a("NotOnOrAfter", SCD_NOT_ON_OR_AFTER), a("InResponseTo", IN_RESPONSE_TO)], []);
  const subjectConfirmation = el("saml:SubjectConfirmation", [a("Method", BEARER)], [scd]);
  const nameIdEl = el("saml:NameID", [a("Format", NAMEID_PERSISTENT)], [t(nameId)]);
  const subject = el("saml:Subject", [], [nameIdEl, subjectConfirmation]);
  const conditions = el(
    "saml:Conditions",
    [a("NotBefore", NOT_BEFORE), a("NotOnOrAfter", NOT_ON_OR_AFTER)],
    [el("saml:AudienceRestriction", [], [el("saml:Audience", [], [t(SP_ENTITY)])])],
  );

  // The email AttributeValue: plain, or xsi:type="xs:string" (xs: declared only on the Assertion -> the
  // value-only xs prefix is the one the InclusiveNamespaces PrefixList must rescue).
  const typedValueAttrs = (): XmlAttr[] => (o.xsiTypedEmail ? [a("xsi:type", "xs:string")] : []);
  const attributeStatement = el("saml:AttributeStatement", [], [
    el("saml:Attribute", [a("Name", "email")], [el("saml:AttributeValue", typedValueAttrs(), [t(email)])]),
    el("saml:Attribute", [a("Name", "groups")], [
      el("saml:AttributeValue", typedValueAttrs(), [t("administrators")]),
      el("saml:AttributeValue", typedValueAttrs(), [t("billing")]),
    ]),
  ]);

  // The Assertion declares saml: always; for the xsi:type shape it ALSO declares xsi: and xs: on the root (as a
  // real ADFS assertion does), so they are inherited by the AttributeValue descendants.
  const assertionAttrs: XmlAttr[] = [a("xmlns:saml", SAML_ASSERTION_NS)];
  if (o.xsiTypedEmail) {
    assertionAttrs.push(a("xmlns:xsi", XSI_NS));
    assertionAttrs.push(a("xmlns:xs", XSD_NS));
  }
  assertionAttrs.push(a("ID", assertionId), a("Version", "2.0"), a("IssueInstant", "2026-06-13T11:59:00Z"));

  return el("saml:Assertion", assertionAttrs, [el("saml:Issuer", [], [t(IDP_ENTITY)]), subject, conditions, attributeStatement]);
}

export interface ROpts {
  destination?: string | null;
  inResponseTo?: string | null;
  responseId?: string;
}
export function buildResponse(assertionChildren: XmlElement[], o: ROpts = {}): XmlElement {
  const responseId = o.responseId ?? RESPONSE_ID;
  const attrs: XmlAttr[] = [a("xmlns:samlp", SAML_PROTOCOL_NS), a("ID", responseId), a("Version", "2.0"), a("IssueInstant", "2026-06-13T11:59:30Z")];
  if (o.destination !== null) attrs.push(a("Destination", o.destination ?? ACS_URL));
  if (o.inResponseTo !== null) attrs.push(a("InResponseTo", o.inResponseTo ?? IN_RESPONSE_TO));
  const status = el("samlp:Status", [], [el("samlp:StatusCode", [a("Value", STATUS_SUCCESS)], [])]);
  return el("samlp:Response", attrs, [status, ...assertionChildren]);
}

// ---- SignedInfo builder; `inclusivePrefixList`, when set, adds <ec:InclusiveNamespaces PrefixList=.../> to
// the exc-c14n# Transform (the IDP-2 shape). ----
function buildSignedInfo(refId: string, digestB64: string, inclusivePrefixList?: string): XmlElement {
  const c14nTransformChildren: XmlChild[] = inclusivePrefixList !== undefined
    ? [el("ec:InclusiveNamespaces", [a("xmlns:ec", C14N_EXC), a("PrefixList", inclusivePrefixList)], [])]
    : [];
  return el(
    "ds:SignedInfo",
    [a("xmlns:ds", XMLDSIG_NS)],
    [
      el("ds:CanonicalizationMethod", [a("Algorithm", C14N_EXC)], []),
      el("ds:SignatureMethod", [a("Algorithm", SIG_RSA_SHA256)], []),
      el(
        "ds:Reference",
        [a("URI", "#" + refId)],
        [
          el("ds:Transforms", [], [
            el("ds:Transform", [a("Algorithm", TRANSFORM_ENVELOPED)], []),
            el("ds:Transform", [a("Algorithm", C14N_EXC)], c14nTransformChildren),
          ]),
          el("ds:DigestMethod", [a("Algorithm", DIGEST_SHA256)], []),
          el("ds:DigestValue", [], [t(digestB64)]),
        ],
      ),
    ],
  );
}

// signElement inserts a real enveloped ds:Signature into a COPY of `host` (the element that becomes signed),
// computing the digest over the SAME exc-c14n#(enveloped(host)) the verifier recomputes - WITH the same
// InclusiveNamespaces PrefixList when supplied (so the ADFS digest is honest). The Signature is inserted at
// child index 1 (after Issuer for an Assertion; after Status for a Response - both are "after the first
// child", which is where real IdPs place it). `refId` is the host's own ID (the Reference covers the host).
export async function signElement(host: XmlElement, refId: string, privateKey: CryptoKey, inclusivePrefixList?: string): Promise<XmlElement> {
  const placeholderSi = buildSignedInfo(refId, "", inclusivePrefixList);
  const signature = el("ds:Signature", [a("xmlns:ds", XMLDSIG_NS)], [placeholderSi, el("ds:SignatureValue", [], [t("")])]);

  const signed = clone(host);
  signed.children.splice(1, 0, signature); // after the first child
  const insertedSig = signed.children[1] as XmlElement;

  const enveloped = envelopedCopy(signed, insertedSig);
  const inclusiveOpt = inclusivePrefixList !== undefined ? { inclusiveNamespacePrefixes: inclusivePrefixList.split(/[ \t\r\n]+/).filter((s) => s.length > 0) } : {};
  const refCanon = canonicalize(enveloped, inclusiveOpt);
  if (!refCanon.ok) throw new Error("test setup: ref canon failed: " + refCanon.reason);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", ab(new TextEncoder().encode(refCanon.canonical))));
  const digestB64 = b64std(digest);

  const realSi = buildSignedInfo(refId, digestB64, inclusivePrefixList);
  insertedSig.children[0] = realSi;

  const siCanon = canonicalize(realSi);
  if (!siCanon.ok) throw new Error("test setup: SignedInfo canon failed: " + siCanon.reason);
  const sigBytes = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, ab(new TextEncoder().encode(siCanon.canonical))));
  insertedSig.children[1] = el("ds:SignatureValue", [], [t(b64std(sigBytes))]);
  return signed;
}

// signResponse is signElement applied to a samlp:Response (IDP-1: the envelope signature). The Response's
// children become [Status, ds:Signature, ...assertions]; the Reference covers the Response root (refId =
// RESPONSE_ID). The contained assertion is UNSIGNED.
export async function signResponse(response: XmlElement, privateKey: CryptoKey): Promise<XmlElement> {
  const refId = (response.attrs.find((at) => at.name === "ID")?.value) ?? RESPONSE_ID;
  return signElement(response, refId, privateKey);
}

// The minimal DER encoders (derLen/derTlv/derSeq/.../OID_SHA256_RSA/OID_CN) used to build a real self-signed
// X.509 cert with a CONTROLLABLE validity window (IDP-4) live in saml-der.ts (imported at the top), shared with
// the other SAML validators that build the same fixtures.

// buildCertPem builds a real self-signed X.509 cert whose validity window is [notBeforeZ, notAfterZ]
// (GeneralizedTime YYYYMMDDHHMMSSZ). The SP only walks out the SPKI + the validity window, but the TBS is
// signed for real so the DER walk steps past a genuine signature.
export async function buildCertPem(spkiDer: Uint8Array, signerPrivate: CryptoKey, cn: string, notBeforeZ: string, notAfterZ: string): Promise<string> {
  const atv = derSeq(derOid(OID_CN), derUtf8(cn));
  const rdn = derTlv(0x31, atv);
  const name = derSeq(rdn);
  const sigAlg = derSeq(derOid(OID_SHA256_RSA), derNull());
  const version = derExplicit0(derInt([0x02]));
  const serial = derInt([0x01]);
  const validity = derSeq(derGeneralizedTime(notBeforeZ), derGeneralizedTime(notAfterZ));
  const tbs = derSeq(version, serial, sigAlg, name, validity, name, Array.from(spkiDer));
  const tbsBytes = new Uint8Array(tbs);
  const certSig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", signerPrivate, ab(tbsBytes)));
  const cert = derSeq(tbs, sigAlg, derBitString(certSig));
  const b64 = b64std(new Uint8Array(cert));
  let lines = "";
  for (let i = 0; i < b64.length; i += 64) lines += b64.slice(i, i + 64) + "\n";
  return "-----BEGIN CERTIFICATE-----\n" + lines + "-----END CERTIFICATE-----\n";
}

export function encodeResponse(response: XmlElement): string {
  return b64std(new TextEncoder().encode(serialise(response)));
}
