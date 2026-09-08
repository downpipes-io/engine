// THE SAML XSW / XML-DSig attack RED corpus - the "literal merge gate" for the native SAML Service
// Provider. Where validate-saml-response.ts proves the happy path AND a first tranche of rejects, THIS file is
// the adversarial twin: it builds a single VALID enveloped-signed baseline (the control - it MUST pass, which
// proves the harness drives the real pipeline) and then fires the full published attack catalogue at the REAL
// production verifier verifySamlResponse(), asserting EVERY malicious payload is REJECTED (ok === false). A
// payload that is wrongly ACCEPTED is a real SAML auth bypass; the assertion for it is LEFT IN (so the red is
// visible) and the failure is reported, never deleted.
//
// The attack families (each a published XML-Signature-Wrapping / SAMLStorm / ruby-saml-CVE-class vector):
//   1. Signature wrapping (XSW): a second unsigned sibling Assertion; the signed Assertion relocated into a
//      wrapper with a forged Assertion in the canonical position; the forged Assertion WRAPPING the signed one
//      (signed becomes a descendant); a forged Assertion sharing the signed one's ID (duplicate ID).
//   2. Comment injection (SAMLStorm): an XML comment spliced into a SIGNED NameID / Attribute value AFTER
//      signing (<NameID>admin<!---->@evil</NameID>) - either the digest breaks (reject) or, if it still
//      verifies, the consumed identity is the canonical-decoded one (no text-splitting privilege change).
//   3. DOCTYPE / XXE: a <!DOCTYPE>/<!ENTITY> document - the parser raw-byte gate fires.
//   4. Multiple Signatures: two ds:Signature elements - reject.
//   5. Transform smuggling: a Reference Transform off the whitelist (XPath; an extra transform) - reject.
//   6. Algorithm downgrade: SignatureMethod rsa-sha1, or DigestMethod sha1 - reject (the allowlist is
//      pre-crypto).
//   7. KeyInfo substitution: an attacker cert/key embedded in ds:KeyInfo, signed with the attacker key - reject
//      (KeyInfo is ignored; only the pinned cert verifies).
//   8. Unsigned assertion: a well-formed Response/Assertion with NO Signature - reject (wantAssertionsSigned).
//   9. Status masking (namespace confusion): a real samlp:Status of Responder (failure) with a prepended
//      foreign-/no-namespace <Status><StatusCode Value=Success/> decoy first - reject (Status is NS-gated).
//  10. Wrong audience / Recipient / InResponseTo / expired: a VALIDLY-signed assertion perturbed on each
//      consumeAssertion gate - each rejects.
//  11. Multiple top-level roots / trailing junk after the Response - the parser rejects.
//
// The signing machinery (signAssertion: exc-c14n# digest over enveloped(assertion), real SignedInfo signature)
// and the self-signed-cert builder are the SAME ones validate-saml-response.ts uses, so the baseline is HONEST
// (a c14n/signing bug would break the GREEN control, not hide a RED vector). Each malicious tree is built by
// signing a real baseline FIRST and then MUTATING it, so every reject is a reject of an otherwise-cryptograph-
// ically-valid document - exactly the threat model.
//
// Node 25 strip-types; Web Crypto only (global crypto.subtle), no Node builtins beyond the harness exit code.

import { verifySamlResponse } from "../src/admin/saml/response.ts";
import type { VerifyContext } from "../src/admin/saml/response.ts";
import { canonicalize, envelopedCopy } from "../src/admin/saml/c14n.ts";
import type { XmlElement, XmlAttr, XmlChild } from "../src/admin/saml/xml-node.ts";
import type { SamlConnection } from "../src/admin/idpconn.ts";
import { samlSubject } from "../src/admin/identity.ts";
import { ab } from "../src/crypto/bytes.ts";
// el/a/t/clone/b64std and the test XML serialiser are the shared tree builders from saml-response-fixtures.ts
// (the response harness uses the SAME ones), so this red corpus and the happy-path suite cannot drift apart.
// The serialiser already round-trips comment nodes, which this file exercises.
import { el, a, t, clone, b64std, serialise } from "./saml-response-fixtures.ts";

// This validator runs under Node (strip-types); the project tsconfig ships Workers types only (no @types/node).
// Declare the single Node global we use so the file is tsc-clean under those flags. console is the WebWorker
// global.
declare const process: { exit(code?: number): never; exitCode?: number };

// ---- tiny test harness (the ok(name, cond) shape the sibling validators use) ----
let passed = 0;
const fails: string[] = [];
function ok(name: string, cond: boolean): void {
  if (cond) {
    passed++;
    console.log("  ok   " + name);
  } else {
    fails.push(name);
    console.log("  FAIL " + name);
  }
}

// ---- the one tree builder this file adds on top of the shared set ----
// comment() is unique to this red corpus (the SAMLStorm comment-injection vectors); el/a/t/clone/b64std and
// the serialiser are imported from saml-response-fixtures.ts above.
function comment(value: string): XmlChild {
  return { type: "comment", value };
}

// ---- algorithm URIs (match dsig.ts) ----
const C14N_EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
const TRANSFORM_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const SIG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SIG_RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const DIGEST_SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
const TRANSFORM_XPATH = "http://www.w3.org/TR/1999/REC-xpath-19991116";
const XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#";

// ---- fixed reference constants (a fixed clock + connection/context values) ----
const SAML_PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
const SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
const STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
const STATUS_RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder";
const NAMEID_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

const IDP_ENTITY = "https://idp.example.com/entity";
const SP_ENTITY = "https://console.downpipes.io/saml/metadata";
const ACS_URL = "https://console.downpipes.io/admin/saml/acs/work-idp";
const IN_RESPONSE_TO = "_req_abc123";
const ASSERTION_ID = "_assertion_0001";
const RESPONSE_ID = "_response_0001";
const CONN_ID = "work-idp";

const NOW_MS = Date.parse("2026-06-13T12:00:00Z");
const NOT_BEFORE = "2026-06-13T11:55:00Z";
const NOT_ON_OR_AFTER = "2026-06-13T12:05:00Z";
const SCD_NOT_ON_OR_AFTER = "2026-06-13T12:05:00Z";

const LEGIT_NAMEID = "alice@example.com";
const EVIL_NAMEID = "attacker@evil.example";

function baseConn(certs: string[], over: Partial<SamlConnection> = {}): SamlConnection {
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

function baseCtx(over: Partial<VerifyContext> = {}): VerifyContext {
  return { acsUrl: ACS_URL, expectedInResponseTo: IN_RESPONSE_TO, nowMs: NOW_MS, ...over };
}

// ---- assertion + response fixture builders (mirror validate-saml-response.ts) ----
interface AOpts {
  assertionId?: string;
  nameId?: string;
  nameIdFormat?: string;
  recipient?: string;
  inResponseTo?: string | null; // null = omit the SCD InResponseTo (IdP-initiated)
  audience?: string;
  notBefore?: string;
  issuer?: string;
  notOnOrAfter?: string;
  scdNotOnOrAfter?: string;
  email?: string;
  groups?: string[];
  // nameIdChildren overrides the NameID's child nodes verbatim (used by the comment-injection vector to splice
  // a comment into the NameID text). When set it REPLACES the single text child.
  nameIdChildren?: XmlChild[];
}

// buildAssertion builds a well-formed bearer, SP-initiated saml:Assertion that declares the saml: namespace
// itself (as a real IdP does), so every descendant resolves to the assertion namespace.
function buildAssertion(o: AOpts = {}): XmlElement {
  const assertionId = o.assertionId ?? ASSERTION_ID;
  const nameId = o.nameId ?? LEGIT_NAMEID;
  const nameIdFormat = o.nameIdFormat ?? NAMEID_PERSISTENT;
  const recipient = o.recipient ?? ACS_URL;
  const audience = o.audience ?? SP_ENTITY;
  const notBefore = o.notBefore ?? NOT_BEFORE;
  const notOnOrAfter = o.notOnOrAfter ?? NOT_ON_OR_AFTER;
  const scdNotOnOrAfter = o.scdNotOnOrAfter ?? SCD_NOT_ON_OR_AFTER;
  const email = o.email ?? LEGIT_NAMEID;
  const groups = o.groups ?? ["administrators", "billing"];

  const scdAttrs: XmlAttr[] = [a("Recipient", recipient), a("NotOnOrAfter", scdNotOnOrAfter)];
  if (o.inResponseTo !== null) scdAttrs.push(a("InResponseTo", o.inResponseTo ?? IN_RESPONSE_TO));
  const scd = el("saml:SubjectConfirmationData", scdAttrs, []);
  const subjectConfirmation = el("saml:SubjectConfirmation", [a("Method", BEARER)], [scd]);
  const nameIdEl = el("saml:NameID", [a("Format", nameIdFormat)], o.nameIdChildren ?? [t(nameId)]);
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
    [el("saml:Issuer", [], [t(o.issuer ?? IDP_ENTITY)]), subject, conditions, attributeStatement],
  );
}

// buildResponse wraps assertion children in a samlp:Response, with a Status (Success by default) and the
// Response-level @Destination + @InResponseTo by default.
interface ROpts {
  statusValue?: string;
  destination?: string | null; // null = omit @Destination
  inResponseTo?: string | null; // null = omit @InResponseTo
  responseId?: string;
  // statusChildrenOverride replaces the Status block's contents entirely (used by the status-masking vector to
  // inject a foreign-namespace decoy StatusCode before the real one). When set it REPLACES the default
  // samlp:Status child of the Response.
  statusElementOverride?: XmlElement;
}
function buildResponse(assertionChildren: XmlElement[], o: ROpts = {}): XmlElement {
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
  const status = o.statusElementOverride ?? el("samlp:Status", [], [el("samlp:StatusCode", [a("Value", statusValue)], [])]);
  return el("samlp:Response", attrs, [status, ...assertionChildren]);
}

// ---- the enveloped XML-DSig signer (mirrors validate-saml-response.ts signAssertion EXACTLY) ----
// buildSignedInfo can be perturbed for the algorithm-downgrade and transform-smuggling vectors via overrides.
interface SiOpts {
  c14nAlg?: string;
  sigAlg?: string;
  digestAlg?: string;
  // transforms overrides the Transform list entirely (used by the smuggling vector). When set it REPLACES the
  // default [enveloped, exc-c14n#] list.
  transforms?: XmlElement[];
}
function buildSignedInfo(refId: string, digestB64: string, o: SiOpts = {}): XmlElement {
  const transforms = o.transforms ?? [
    el("ds:Transform", [a("Algorithm", TRANSFORM_ENVELOPED)], []),
    el("ds:Transform", [a("Algorithm", C14N_EXC)], []),
  ];
  return el(
    "ds:SignedInfo",
    [a("xmlns:ds", XMLDSIG_NS)],
    [
      el("ds:CanonicalizationMethod", [a("Algorithm", o.c14nAlg ?? C14N_EXC)], []),
      el("ds:SignatureMethod", [a("Algorithm", o.sigAlg ?? SIG_RSA_SHA256)], []),
      el(
        "ds:Reference",
        [a("URI", "#" + refId)],
        [
          el("ds:Transforms", [], transforms),
          el("ds:DigestMethod", [a("Algorithm", o.digestAlg ?? DIGEST_SHA256)], []),
          el("ds:DigestValue", [], [t(digestB64)]),
        ],
      ),
    ],
  );
}

// signAssertion inserts a real enveloped ds:Signature into a COPY of the assertion. It computes the Reference
// digest over exc-c14n#(enveloped(assertion)) with the SAME c14n the verifier uses, builds + canonicalises
// SignedInfo, signs it with the RSA private key, and embeds the SignatureValue. signedInfoOpts perturbs the
// SignedInfo (algorithm-downgrade / transform-smuggling vectors); extraSignatureChildren appends extra children
// to the ds:Signature (e.g. a forged ds:KeyInfo). The digest+signature are still computed honestly over the
// perturbed SignedInfo, so a downgrade/smuggle vector is a genuinely-signed-but-disallowed document.
async function signAssertion(
  assertion: XmlElement,
  refId: string,
  privateKey: CryptoKey,
  signedInfoOpts: SiOpts = {},
  extraSignatureChildren: XmlChild[] = [],
): Promise<XmlElement> {
  const placeholderSi = buildSignedInfo(refId, "", signedInfoOpts);
  const signatureChildren: XmlChild[] = [placeholderSi, el("ds:SignatureValue", [], [t("")]), ...extraSignatureChildren.map((c) => (c.type === "element" ? clone(c) : { type: c.type, value: c.value }) as XmlChild)];
  const signature = el("ds:Signature", [a("xmlns:ds", XMLDSIG_NS)], signatureChildren);

  const signed = clone(assertion);
  signed.children.splice(1, 0, signature); // after Issuer, like real IdPs
  const insertedSig = signed.children[1] as XmlElement;

  const enveloped = envelopedCopy(signed, insertedSig);
  const refCanon = canonicalize(enveloped);
  if (!refCanon.ok) throw new Error("test setup: ref canon failed: " + refCanon.reason);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", ab(new TextEncoder().encode(refCanon.canonical))));
  const digestB64 = b64std(digest);

  const realSi = buildSignedInfo(refId, digestB64, signedInfoOpts);
  insertedSig.children[0] = realSi;

  const siCanon = canonicalize(realSi);
  if (!siCanon.ok) throw new Error("test setup: SignedInfo canon failed: " + siCanon.reason);
  const sigBytes = new Uint8Array(
    await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, ab(new TextEncoder().encode(siCanon.canonical))),
  );
  insertedSig.children[1] = el("ds:SignatureValue", [], [t(b64std(sigBytes))]);
  return signed;
}

// ---- minimal DER encoders to build a real self-signed X.509 cert wrapping an RSA public key ----
// The SP does NOT verify the cert's self-signature, but it does extract and enforce the notBefore/notAfter
// validity window (IDP-4). This section exercises pemToSpki and the DER structural walk; we sign the TBS for
// real so the walk steps past a genuine signature-algorithm/issuer/validity/subject to the SPKI. Cert
// validity-window testing is covered in validate-saml-interop.ts.
function derLen(len: number): number[] {
  if (len < 0x80) return [len];
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n = n >>> 8;
  }
  return [0x80 | bytes.length, ...bytes];
}
function derTlv(tag: number, content: number[]): number[] {
  return [tag, ...derLen(content.length), ...content];
}
function derSeq(...items: number[][]): number[] {
  const content: number[] = [];
  for (const it of items) content.push(...it);
  return derTlv(0x30, content);
}
function derInt(bytes: number[]): number[] {
  const b = bytes.length === 0 ? [0] : bytes.slice();
  if ((b[0]! & 0x80) !== 0) b.unshift(0x00);
  return derTlv(0x02, b);
}
function derOid(bytes: number[]): number[] {
  return derTlv(0x06, bytes);
}
function derNull(): number[] {
  return [0x05, 0x00];
}
function derGeneralizedTime(s: string): number[] {
  const bytes: number[] = [];
  for (let i = 0; i < s.length; i++) bytes.push(s.charCodeAt(i));
  return derTlv(0x18, bytes);
}
function derUtf8(s: string): number[] {
  const enc = new TextEncoder().encode(s);
  return derTlv(0x0c, Array.from(enc));
}
function derExplicit0(content: number[]): number[] {
  return derTlv(0xa0, content);
}
function derBitString(bytes: Uint8Array): number[] {
  return derTlv(0x03, [0x00, ...Array.from(bytes)]); // 0 unused bits
}

const OID_SHA256_RSA = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]; // 1.2.840.113549.1.1.11
const OID_CN = [0x55, 0x04, 0x03]; // 2.5.4.3 commonName

async function buildSelfSignedCertPem(spkiDer: Uint8Array, signerPrivate: CryptoKey, cn: string): Promise<string> {
  const atv = derSeq(derOid(OID_CN), derUtf8(cn));
  const rdn = derTlv(0x31, atv); // SET
  const name = derSeq(rdn);

  const sigAlg = derSeq(derOid(OID_SHA256_RSA), derNull());
  const version = derExplicit0(derInt([0x02])); // v3
  const serial = derInt([0x01]);
  const validity = derSeq(derGeneralizedTime("20260101000000Z"), derGeneralizedTime("20360101000000Z"));

  const tbs = derSeq(version, serial, sigAlg, name, validity, name, Array.from(spkiDer));
  const tbsBytes = new Uint8Array(tbs);
  const certSig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", signerPrivate, ab(tbsBytes)));

  const cert = derSeq(tbs, sigAlg, derBitString(certSig));
  const b64 = b64std(new Uint8Array(cert));
  let lines = "";
  for (let i = 0; i < b64.length; i += 64) lines += b64.slice(i, i + 64) + "\n";
  return "-----BEGIN CERTIFICATE-----\n" + lines + "-----END CERTIFICATE-----\n";
}

// encodeResponse serialises a samlp:Response tree and base64-encodes it as the POST SAMLResponse field value.
function encodeResponse(response: XmlElement): string {
  return b64std(new TextEncoder().encode(serialise(response)));
}
// encodeRaw base64-encodes a raw XML string as the POST SAMLResponse field value (for DOCTYPE / multi-root /
// trailing-junk payloads that are not a single XmlElement tree).
function encodeRaw(xml: string): string {
  return b64std(new TextEncoder().encode(xml));
}

// Keys carries the legit (pinned) key + cert and the attacker (non-pinned) key + cert every family reuses.
interface Keys {
  rsa: CryptoKeyPair;
  certPem: string;
  rsaAtk: CryptoKeyPair;
  certAtkPem: string;
}

// setupKeys generates the legit + attacker key material and their self-signed certs.
async function setupKeys(): Promise<Keys> {
  const rsa = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const rsaSpki = new Uint8Array(await crypto.subtle.exportKey("spki", rsa.publicKey));
  const certPem = await buildSelfSignedCertPem(rsaSpki, rsa.privateKey, "idp.example.com");

  const rsaAtk = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const rsaAtkSpki = new Uint8Array(await crypto.subtle.exportKey("spki", rsaAtk.publicKey));
  const certAtkPem = await buildSelfSignedCertPem(rsaAtkSpki, rsaAtk.privateKey, "attacker.example.com");
  return { rsa, certPem, rsaAtk, certAtkPem };
}

// CONTROL: the VALID signed baseline MUST pass. This proves the harness drives the real pipeline: if the
// control failed, every red below would be a false pass (rejecting because the harness is broken).
async function testControl({ rsa, certPem }: Keys): Promise<void> {
  console.log("control (the baseline MUST pass - proves the harness is real):\n");
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("CONTROL: a valid enveloped-signed Response is ACCEPTED", r.ok === true);
    if (r.ok) {
      ok("  -> CONTROL subject is the legit principal (not the attacker)", r.principal.subject === samlSubject(CONN_ID, IDP_ENTITY, LEGIT_NAMEID) && r.principal.nameId === LEGIT_NAMEID);
    } else {
      console.log("       (control reason: " + r.reason + ")");
    }
  }
}

// ========================= 1. SIGNATURE WRAPPING / XSW FAMILY =========================
async function testXswFamily({ rsa, certPem, rsaAtk }: Keys): Promise<void> {
  console.log("\n1. signature wrapping / XSW family (each MUST reject):\n");

  // 1a. A SECOND UNSIGNED Assertion as a SIBLING of the signed one. The attacker hopes the SP reads the evil
  //     sibling. The engine requires EXACTLY ONE Assertion child of the Response -> reject.
  {
    const signed = await signAssertion(buildAssertion({ nameId: LEGIT_NAMEID }), ASSERTION_ID, rsa.privateKey);
    const evil = buildAssertion({ assertionId: "_evil", nameId: EVIL_NAMEID, email: EVIL_NAMEID });
    const resp = encodeResponse(buildResponse([signed, evil]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("1a XSW: signed Assertion + a second UNSIGNED sibling Assertion is rejected (exactly-one-Assertion)", r.ok === false);
  }

  // 1b. The signed Assertion RELOCATED into a wrapper element, with a NEW forged unsigned Assertion in the
  //     canonical (first-Assertion) position. The Response then carries TWO saml:Assertion-namespace elements
  //     at top level (the forged one + ... wait: the signed one is now nested inside a non-Assertion wrapper, so
  //     it is NOT a direct Assertion child). We model the classic shape: a forged Assertion sits as the direct
  //     child, and the genuine signed Assertion is moved into an <Extensions>-style wrapper that is ALSO a child
  //     of the Response. The verifier locates the single direct Assertion (the forged one), and its signature
  //     check fails (the forged Assertion is unsigned / its Reference resolves to the nested signed assertion's
  //     ID which is not the located element). Either way -> reject.
  {
    const signed = await signAssertion(buildAssertion({ assertionId: "_signed", nameId: LEGIT_NAMEID }), "_signed", rsa.privateKey);
    const wrapper = el("samlp:Extensions", [], [signed]); // the signed assertion hidden in a wrapper sibling
    const forged = buildAssertion({ assertionId: "_forged", nameId: EVIL_NAMEID, email: EVIL_NAMEID }); // unsigned, canonical position
    // Response children: [Status, forged Assertion (direct), wrapper carrying the signed Assertion].
    const resp = encodeResponse(buildResponse([forged, wrapper]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("1b XSW: signed Assertion moved into a wrapper + a forged Assertion in the canonical slot is rejected", r.ok === false);
  }

  // 1c. The forged Assertion WRAPS the signed one (the signed Assertion becomes a DESCENDANT of the forged,
  //     unsigned outer Assertion which is the single Response child). The verifier locates the outer (forged)
  //     Assertion; requireReferenceIsTarget forces the Reference to cover the LOCATED element, but the signature
  //     covers the INNER assertion -> reject.
  {
    const signed = await signAssertion(buildAssertion({ assertionId: "_inner", nameId: LEGIT_NAMEID }), "_inner", rsa.privateKey);
    const outer = buildAssertion({ assertionId: "_outer", nameId: EVIL_NAMEID, email: EVIL_NAMEID });
    outer.children.push(signed); // signed becomes a descendant of the forged outer assertion
    const resp = encodeResponse(buildResponse([outer]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("1c XSW: a forged outer Assertion WRAPPING the signed one is rejected (Reference != located assertion)", r.ok === false);
  }

}

// 1d/1e: duplicate-ID wrapping and two independently-signed siblings (the exactly-one-Assertion rule).
async function testXswDuplicateAndSiblings({ rsa, certPem }: Keys): Promise<void> {
  // 1d. The forged outer Assertion carries the SAME ID as the signed inner one (duplicate ID). The dsig
  //     unique-ID walk sees TWO elements with that ID under the located subtree -> reject (duplicate-ID
  //     wrapping), so the SP never has to choose which the Reference meant.
  {
    const signed = await signAssertion(buildAssertion({ assertionId: ASSERTION_ID, nameId: LEGIT_NAMEID }), ASSERTION_ID, rsa.privateKey);
    const outer = buildAssertion({ assertionId: ASSERTION_ID, nameId: EVIL_NAMEID, email: EVIL_NAMEID });
    outer.children.push(signed); // inner shares the outer's ID
    const resp = encodeResponse(buildResponse([outer]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("1d XSW: a forged wrapper sharing the inner signed assertion's ID is rejected (duplicate-ID resolution)", r.ok === false);
  }

  // 1e. (defensive sibling) TWO independently, legitimately signed Assertions side by side. Even though BOTH
  //     verify in isolation, the engine's exactly-one rule rejects: an attacker who captured two real assertions
  //     cannot staple them to confuse which principal is consumed.
  {
    const s1 = await signAssertion(buildAssertion({ assertionId: "_a1", nameId: LEGIT_NAMEID }), "_a1", rsa.privateKey);
    const s2 = await signAssertion(buildAssertion({ assertionId: "_a2", nameId: EVIL_NAMEID, email: EVIL_NAMEID }), "_a2", rsa.privateKey);
    const resp = encodeResponse(buildResponse([s1, s2]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("1e XSW: two independently-signed Assertions side by side is rejected (exactly-one-Assertion)", r.ok === false);
  }

}

// ========================= 2. COMMENT INJECTION (SAMLStorm class) =========================
async function testCommentInjection({ rsa, certPem }: Keys): Promise<void> {
  // The SAMLStorm / "comment-injection" exploit (CVE-2017-11427 lineage, re-broken in 2024-25): inject an XML
  // comment INTO a signed text value so the digest path and the claim-reader path disagree on the value. The
  // dangerous SP is one whose reader SPLITS on the comment node and reads only ONE text run (e.g. "admin" out
  // of "admin<!---->@evil.com"), authenticating a DIFFERENT principal than the signature actually covered. We
  // attack BOTH halves of the disagreement surface:
  //   - 2a/2b: a splice that CHANGES the canonical bytes (the surrounding text differs from what was signed) ->
  //     digest mismatch -> reject. Proves you cannot smuggle a different value behind a comment.
  //   - 2c/2d: the SHARPER case - a splice that PRESERVES the canonical bytes exactly (base exc-c14n# drops the
  //     comment and rejoins the two text runs, so "alice<!---->@example.com" canonicalises identically to the
  //     signed "alice@example.com"). The signature therefore STILL verifies. The attack succeeds ONLY if the
  //     reader then splits on the comment and consumes a truncated identity. We assert the signature verifies
  //     AND the consumed identity is the FULL canonical value (never the truncated first run) - the real
  //     text-splitting defence, exercised on a document the signature legitimately accepts.
  console.log("\n2. comment injection (SAMLStorm): no text-splitting identity change:\n");

  // 2a. Comment splice into the SIGNED NameID that CHANGES the canonical value (signed "alice@example.com",
  //     spliced to "alice" + comment + "@evil.example" whose canonical join is "alice@evil.example") -> the
  //     digest no longer matches -> reject. A different trusted NameID cannot be smuggled behind a comment.
  {
    const signed = await signAssertion(buildAssertion({ nameId: LEGIT_NAMEID }), ASSERTION_ID, rsa.privateKey);
    const subject = signed.children.find((c) => c.type === "element" && c.name === "saml:Subject") as XmlElement;
    const nameIdEl = subject.children.find((c) => c.type === "element" && c.name === "saml:NameID") as XmlElement;
    nameIdEl.children = [t("alice"), comment("x"), t("@evil.example")]; // canonical join "alice@evil.example" != signed
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("2a comment splice that CHANGES the signed NameID canonical value is rejected (digest mismatch)", r.ok === false);
  }

  // 2b. The same canonical-changing splice inside the SIGNED email AttributeValue -> digest mismatch -> reject.
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    const stmt = signed.children.find((c) => c.type === "element" && c.name === "saml:AttributeStatement") as XmlElement;
    const emailAttr = stmt.children.find((c) => c.type === "element" && (c as XmlElement).attrs.some((at) => at.name === "Name" && at.value === "email")) as XmlElement;
    const av = emailAttr.children.find((c) => c.type === "element") as XmlElement;
    av.children = [t("alice"), comment("x"), t("@evil.example")];
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("2b comment splice that CHANGES the signed email canonical value is rejected (digest mismatch)", r.ok === false);
  }
}

// 2c/2d: the SHARPER canonical-PRESERVING comment splices (base exc-c14n# drops the comment and rejoins the
// runs, so the signature STILL verifies); the attack lands only if the reader splits on the comment, so we
// assert the FULL canonical identity is consumed, never the truncated first run.
async function testCommentInjectionPreserving({ rsa, certPem }: Keys): Promise<void> {
  // 2c. THE CORE SAMLStorm DIFFERENTIAL: sign over the single-text NameID "alice@example.com", then splice a
  //     comment so the value becomes "alice<!---->@example.com". Base exc-c14n# drops the comment and rejoins
  //     the runs, so the canonical bytes are UNCHANGED and the signature STILL verifies. The attack lands ONLY
  //     if the reader splits on the comment and authenticates "alice". We assert: the Response is ACCEPTED
  //     (the signature legitimately holds) AND the consumed NameID is the FULL "alice@example.com", never the
  //     truncated "alice". If it were truncated, that is a real SAMLStorm bypass -> the assertion fails loudly.
  {
    const signed = await signAssertion(buildAssertion({ nameId: LEGIT_NAMEID }), ASSERTION_ID, rsa.privateKey);
    const subject = signed.children.find((c) => c.type === "element" && c.name === "saml:Subject") as XmlElement;
    const nameIdEl = subject.children.find((c) => c.type === "element" && c.name === "saml:NameID") as XmlElement;
    nameIdEl.children = [t("alice"), comment(""), t("@example.com")]; // canonical join "alice@example.com" == signed
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    const accepted = r.ok === true;
    const fullIdentity = r.ok === true && r.principal.nameId === LEGIT_NAMEID;
    ok("2c canonical-preserving comment splice in NameID: signature still verifies AND the FULL NameID is consumed (no text split)", accepted && fullIdentity);
    if (r.ok === true && r.principal.nameId !== LEGIT_NAMEID) {
      console.log("       CRITICAL SAMLStorm: comment-split NameID consumed as '" + r.principal.nameId + "' (a text-splitting identity change)");
    } else if (r.ok === false) {
      // Not a security failure (rejecting is safe), but it means c14n did NOT rejoin as expected; surface it.
      console.log("       (note: rejected rather than verified - canonical bytes were not preserved; reason: " + r.reason + ")");
    }
  }

  // 2d. The same canonical-preserving splice inside the SIGNED email AttributeValue: signed "alice@example.com",
  //     spliced to "alice<!---->@example.com". Signature still verifies; the consumed EMAIL must be the full
  //     "alice@example.com", never the truncated "alice".
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    const stmt = signed.children.find((c) => c.type === "element" && c.name === "saml:AttributeStatement") as XmlElement;
    const emailAttr = stmt.children.find((c) => c.type === "element" && (c as XmlElement).attrs.some((at) => at.name === "Name" && at.value === "email")) as XmlElement;
    const av = emailAttr.children.find((c) => c.type === "element") as XmlElement;
    av.children = [t("alice"), comment(""), t("@example.com")];
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    const accepted = r.ok === true;
    const fullEmail = r.ok === true && r.principal.email === LEGIT_NAMEID;
    ok("2d canonical-preserving comment splice in email AttributeValue: verifies AND the FULL email is consumed (no text split)", accepted && fullEmail);
    if (r.ok === true && r.principal.email !== LEGIT_NAMEID) {
      console.log("       CRITICAL SAMLStorm: comment-split email consumed as '" + String(r.principal.email) + "'");
    }
  }

}

// ========================= 3. DOCTYPE / XXE =========================
async function testDoctypeXxe({ certPem }: Keys): Promise<void> {
  console.log("\n3. DOCTYPE / XXE (parser raw-byte gate MUST fire):\n");

  // 3a. A DOCTYPE-bearing Response with an internal ENTITY (the billion-laughs / XXE staging shape). The parser
  //     scanForbiddenConstructs gate rejects on "<!DOCTYPE" before a single tag is parsed.
  {
    const doc =
      '<?xml version="1.0"?><!DOCTYPE samlp:Response [<!ENTITY xxe "evil">]>' +
      '<samlp:Response xmlns:samlp="' + SAML_PROTOCOL_NS + '" ID="' + RESPONSE_ID + '">' +
      '<samlp:Status><samlp:StatusCode Value="' + STATUS_SUCCESS + '"/></samlp:Status>' +
      '</samlp:Response>';
    const r = await verifySamlResponse(encodeRaw(doc), baseConn([certPem]), baseCtx());
    ok("3a a DOCTYPE + internal ENTITY document is rejected by the parser gate (XXE/billion-laughs)", r.ok === false);
  }
  // 3b. A bare <!ENTITY ...> without DOCTYPE is also gated (the second forbidden-construct substring).
  {
    const doc =
      '<samlp:Response xmlns:samlp="' + SAML_PROTOCOL_NS + '" ID="' + RESPONSE_ID + '">' +
      '<!ENTITY x "y"><samlp:Status><samlp:StatusCode Value="' + STATUS_SUCCESS + '"/></samlp:Status>' +
      '</samlp:Response>';
    const r = await verifySamlResponse(encodeRaw(doc), baseConn([certPem]), baseCtx());
    ok("3b a stray <!ENTITY ...> declaration is rejected by the parser gate", r.ok === false);
  }

}

// ========================= 4. MULTIPLE SIGNATURES =========================
async function testMultipleSignatures({ rsa, certPem, rsaAtk }: Keys): Promise<void> {
  console.log("\n4. multiple signatures (MUST reject):\n");

  // 4a. TWO ds:Signature elements inside the single located Assertion. The dsig layer requires exactly one
  //     ds:Signature in the target subtree -> reject (multi-signature confusion).
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    const sig = signed.children.find((c) => c.type === "element" && c.name === "ds:Signature") as XmlElement;
    signed.children.push(clone(sig)); // a second Signature subtree
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("4a two ds:Signature elements in the Assertion is rejected (multi-signature confusion)", r.ok === false);
  }
  // 4b. A second ds:Signature signed by the ATTACKER key alongside the legit one. Still a >1-Signature reject
  //     (the count is checked before any crypto, so the forged signature never even gets a chance to be chosen).
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    // Build a separate genuinely-signed (by the attacker) assertion just to lift a real attacker Signature out.
    const atkSigned = await signAssertion(buildAssertion({ assertionId: "_atk" }), "_atk", rsaAtk.privateKey);
    const atkSig = atkSigned.children.find((c) => c.type === "element" && c.name === "ds:Signature") as XmlElement;
    signed.children.push(clone(atkSig)); // append the attacker's Signature as a second one
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("4b a legit Signature + an attacker-key Signature (two ds:Signature) is rejected", r.ok === false);
  }

}

// ========================= 5. TRANSFORM SMUGGLING =========================
async function testTransformSmuggling({ rsa, certPem }: Keys): Promise<void> {
  console.log("\n5. transform smuggling (a non-whitelisted Reference Transform MUST reject):\n");

  // 5a. An XPath transform in the Reference Transforms (a classic way to make the digest cover a SUBSET of the
  //     element). The transform whitelist is enveloped-signature + exc-c14n# ONLY -> reject. The signature is
  //     computed honestly over the declared transforms, so this is a genuinely-signed-but-disallowed document.
  {
    const transforms = [
      el("ds:Transform", [a("Algorithm", TRANSFORM_ENVELOPED)], []),
      el("ds:Transform", [a("Algorithm", TRANSFORM_XPATH)], [el("ds:XPath", [], [t("/*[local-name()='Assertion']")])]),
      el("ds:Transform", [a("Algorithm", C14N_EXC)], []),
    ];
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey, { transforms });
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("5a an XPath Reference Transform is rejected (only enveloped-signature + exc-c14n# are whitelisted)", r.ok === false);
  }
  // 5b. The enveloped-signature transform OMITTED entirely (only exc-c14n#). The dsig layer requires the
  //     enveloped transform to be present for our profile -> reject. (Signed honestly over these transforms.)
  {
    const transforms = [el("ds:Transform", [a("Algorithm", C14N_EXC)], [])];
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey, { transforms });
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("5b omitting the enveloped-signature transform is rejected (our profile requires it)", r.ok === false);
  }
  // 5c. A non-exclusive canonicalisation smuggled as the only c14n transform (inclusive C14N). Off the
  //     whitelist -> reject.
  {
    const transforms = [
      el("ds:Transform", [a("Algorithm", TRANSFORM_ENVELOPED)], []),
      el("ds:Transform", [a("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315")], []), // inclusive C14N
    ];
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey, { transforms });
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("5c inclusive (non-exclusive) C14N as the Reference transform is rejected", r.ok === false);
  }

}

// ========================= 6. ALGORITHM DOWNGRADE =========================
async function testAlgorithmDowngrade({ rsa, certPem }: Keys): Promise<void> {
  console.log("\n6. algorithm downgrade (the allowlist is enforced BEFORE any crypto):\n");

  // 6a. SignatureMethod rsa-sha1. We SIGN honestly (the SignedInfo canon is still signed with the legit key), so
  //     this is a real signature whose declared method is banned -> reject pre-crypto on the allowlist.
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey, { sigAlg: SIG_RSA_SHA1 });
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("6a SignatureMethod rsa-sha1 is rejected (not on the pre-crypto allowlist)", r.ok === false);
  }
  // 6b. DigestMethod sha1. The digest is computed honestly with sha1 here... but the verifier's allowlist
  //     rejects the sha1 DigestMethod BEFORE digesting -> reject. (We compute the digest with SHA-256 in
  //     signAssertion regardless; the point is the DECLARED sha1 DigestMethod must be refused, so even a
  //     matching sha1 digest would never be accepted.)
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey, { digestAlg: DIGEST_SHA1 });
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("6b DigestMethod sha1 is rejected (allowlist requires sha256 or stronger)", r.ok === false);
  }
  // 6c. CanonicalizationMethod set to inclusive C14N (not exc-c14n#). Rejected on the c14n allowlist.
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey, { c14nAlg: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" });
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("6c CanonicalizationMethod = inclusive C14N is rejected (must be exclusive c14n#)", r.ok === false);
  }

}

// ========================= 7. KEYINFO SUBSTITUTION =========================
async function testKeyInfoSubstitution({ rsaAtk, certPem, certAtkPem }: Keys): Promise<void> {
  console.log("\n7. KeyInfo substitution (KeyInfo is IGNORED; only the pinned cert verifies):\n");

  // 7a. The assertion is signed by the ATTACKER key, and the attacker's own cert is embedded in ds:KeyInfo/
  //     X509Certificate, hoping the SP trusts the in-message cert. The SP pins ONLY the legit cert and never
  //     reads KeyInfo -> the attacker signature does not verify under the pinned key -> reject.
  {
    // Build the attacker cert as bare base64 (PEM body) to embed in X509Certificate.
    const atkCertBody = certAtkPem.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace(/\s+/g, "");
    const keyInfo = el("ds:KeyInfo", [], [
      el("ds:X509Data", [], [el("ds:X509Certificate", [], [t(atkCertBody)])]),
    ]);
    const signed = await signAssertion(buildAssertion({ nameId: EVIL_NAMEID, email: EVIL_NAMEID }), ASSERTION_ID, rsaAtk.privateKey, {}, [keyInfo]);
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("7a attacker-signed assertion with the attacker cert in ds:KeyInfo is rejected (KeyInfo ignored, pin governs)", r.ok === false);
    // Differential proof: the EXACT SAME document verifies when the attacker's cert is the PINNED one, proving
    // the reject above is the pinned-key mismatch (KeyInfo was never the deciding factor in either direction).
    const rPinnedAtk = await verifySamlResponse(resp, baseConn([certAtkPem]), baseCtx());
    ok("7a' the SAME document verifies only when the SIGNER's cert is pinned (so KeyInfo never selected the key)", rPinnedAtk.ok === true);
  }

}

// ========================= 8. UNSIGNED ASSERTION =========================
async function testUnsignedAssertion({ certPem }: Keys): Promise<void> {
  console.log("\n8. unsigned assertion (wantAssertionsSigned MUST reject):\n");

  // 8a. A perfectly-formed Response/Assertion with NO ds:Signature anywhere -> reject (no signature to verify).
  {
    const resp = encodeResponse(buildResponse([buildAssertion()]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("8a a well-formed but UNSIGNED assertion is rejected (wantAssertionsSigned)", r.ok === false);
  }

}

// ========================= 9. STATUS MASKING (namespace confusion) =========================
// statusMaskResponse assembles a samlp:Response BY HAND so a decoy Status is the FIRST child (before the real
// samlp:Status + the signed assertion); buildResponse always puts its Status first, so we assemble manually.
function statusMaskResponse(children: XmlChild[]): XmlElement {
  return el("samlp:Response", [
    a("xmlns:samlp", SAML_PROTOCOL_NS),
    a("ID", RESPONSE_ID),
    a("Version", "2.0"),
    a("IssueInstant", "2026-06-13T11:59:30Z"),
    a("Destination", ACS_URL),
    a("InResponseTo", IN_RESPONSE_TO),
  ], children);
}

async function testStatusMasking({ rsa, certPem }: Keys): Promise<void> {
  console.log("\n9. status masking (a foreign-namespace Success decoy MUST NOT mask a real failure):\n");

  // 9a. The REAL samlp:Status is Responder (a failure). We PREPEND a no-namespace Success decoy as the FIRST
  //     child. assertStatusSuccess is namespace-gated to the SAML protocol NS, so it ignores the decoy and reads
  //     the real samlp:Status (Responder) -> reject. The assertion is validly signed (only the Status gate stands).
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    const realStatus = el("samlp:Status", [], [el("samlp:StatusCode", [a("Value", STATUS_RESPONDER)], [])]);
    const decoyStatus = el("Status", [], [el("StatusCode", [a("Value", STATUS_SUCCESS)], [])]); // no xmlns -> NO namespace
    const r = await verifySamlResponse(encodeResponse(statusMaskResponse([decoyStatus, realStatus, signed])), baseConn([certPem]), baseCtx());
    ok("9a a no-namespace Success Status decoy does NOT mask the real samlp:Status=Responder failure (rejected)", r.ok === false);
  }
  // 9b. A foreign-NAMESPACE Success decoy prepended before the real failing samlp:Status -> still rejected.
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    const realStatus = el("samlp:Status", [], [el("samlp:StatusCode", [a("Value", STATUS_RESPONDER)], [])]);
    const decoyStatus = el("ev:Status", [a("xmlns:ev", "urn:evil:not-saml")], [el("ev:StatusCode", [a("Value", STATUS_SUCCESS)], [])]);
    const r = await verifySamlResponse(encodeResponse(statusMaskResponse([decoyStatus, realStatus, signed])), baseConn([certPem]), baseCtx());
    ok("9b a foreign-namespace Success Status decoy does NOT mask the real failure (NS-gated; rejected)", r.ok === false);
  }
  // 9c. Plain non-Success Status with no decoy (the baseline failure case) -> reject.
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    const resp = encodeResponse(buildResponse([signed], { statusValue: STATUS_RESPONDER }));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("9c a plain samlp:Status != Success is rejected", r.ok === false);
  }
}

// ========================= 10. WRONG AUDIENCE / RECIPIENT / INRESPONSETO / EXPIRED =========================
async function testPerturbedGates({ rsa, certPem }: Keys): Promise<void> {
  console.log("\n10. validly-signed but perturbed consumeAssertion gates (each MUST reject):\n");

  // 10a. Wrong Audience: signed over a different SP entityId -> no AudienceRestriction matches our spEntityId.
  {
    const signed = await signAssertion(buildAssertion({ audience: "https://some-other-sp.example/metadata" }), ASSERTION_ID, rsa.privateKey);
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("10a a wrong Audience (signed) is rejected (audience-restriction gate)", r.ok === false);
  }
  // 10b. Wrong SubjectConfirmationData @Recipient: signed over a different ACS URL -> the per-assertion
  //      Recipient gate rejects. (Omit the Response @Destination so the inner Recipient check is the gate.)
  {
    const signed = await signAssertion(buildAssertion({ recipient: "https://attacker.example/acs" }), ASSERTION_ID, rsa.privateKey);
    const resp = encodeResponse(buildResponse([signed], { destination: null }));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("10b a wrong SubjectConfirmationData @Recipient (signed) is rejected (per-assertion bearer gate)", r.ok === false);
  }
  // 10c. Wrong SCD @InResponseTo: signed with an InResponseTo that is not the request we sent -> reject. (Omit
  //      the Response-level InResponseTo so the assertion-level binding is the gate.)
  {
    const signed = await signAssertion(buildAssertion({ inResponseTo: "_a_different_request_id" }), ASSERTION_ID, rsa.privateKey);
    const resp = encodeResponse(buildResponse([signed], { inResponseTo: null }));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("10c a wrong SubjectConfirmationData @InResponseTo (signed) is rejected (anti-injection binding)", r.ok === false);
  }
  // 10d. ABSENT InResponseTo everywhere (Response + SCD) with allowIdpInitiated=false -> reject (IdP-initiated
  //      denied). The assertion is validly signed over the no-InResponseTo shape.
  {
    const signed = await signAssertion(buildAssertion({ inResponseTo: null }), ASSERTION_ID, rsa.privateKey);
    const resp = encodeResponse(buildResponse([signed], { inResponseTo: null }));
    const r = await verifySamlResponse(resp, baseConn([certPem], { allowIdpInitiated: false }), baseCtx());
    ok("10d an absent InResponseTo with allowIdpInitiated=false is rejected (IdP-initiated denied)", r.ok === false);
  }
  // 10e. Expired: Conditions + SCD NotOnOrAfter well in the past (beyond skew), signed over the expired bounds
  //      -> reject (validity window). Re-signed so the digest stays valid; only time fails it.
  {
    const signed = await signAssertion(buildAssertion({ notOnOrAfter: "2026-06-13T11:00:00Z", scdNotOnOrAfter: "2026-06-13T11:00:00Z" }), ASSERTION_ID, rsa.privateKey);
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("10e an expired (validly-signed) assertion is rejected (Conditions/SCD NotOnOrAfter)", r.ok === false);
  }
  // 10f. Wrong Response @Destination (envelope-level), validly signed assertion -> reject at the envelope gate.
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    const resp = encodeResponse(buildResponse([signed], { destination: "https://attacker.example/acs" }));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("10f a wrong Response @Destination (signed assertion) is rejected (envelope wrong-SP gate)", r.ok === false);
  }
  // 10g. Not-yet-valid: Conditions NotBefore set one hour AFTER now (beyond skew), validly signed over those
  //      bounds -> reject (the validity window has not opened). Only time fails it; the digest stays valid.
  {
    const signed = await signAssertion(buildAssertion({ notBefore: "2026-06-13T13:00:00Z" }), ASSERTION_ID, rsa.privateKey);
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("10g a not-yet-valid (Conditions NotBefore in the future) assertion is rejected (validity window)", r.ok === false);
  }
  // 10h. Wrong assertion Issuer: signed (with the pinned key) but the Issuer claims a different IdP entity ->
  //      reject. Binds the assertion Issuer to the connection idpEntityId, blocking cross-IdP impersonation
  //      should a cert ever be reused across connections.
  {
    const signed = await signAssertion(buildAssertion({ issuer: "https://attacker.example/entity" }), ASSERTION_ID, rsa.privateKey);
    const resp = encodeResponse(buildResponse([signed]));
    const r = await verifySamlResponse(resp, baseConn([certPem]), baseCtx());
    ok("10h a wrong assertion Issuer (signed with the pinned key) is rejected (Issuer-to-idpEntityId binding)", r.ok === false);
  }
}

// ========================= 11. MULTIPLE ROOTS / TRAILING JUNK =========================
async function testMultipleRoots({ rsa, certPem }: Keys): Promise<void> {
  console.log("\n11. multiple top-level roots / trailing junk (parser MUST reject):\n");

  // 11a. A SECOND top-level Response after the first (the classic second-root wrapping at the document level).
  //      The parser's epilog gate names this exact vector and rejects.
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    const one = serialise(buildResponse([signed]));
    const evilSigned = buildAssertion({ assertionId: "_evil2", nameId: EVIL_NAMEID, email: EVIL_NAMEID });
    const two = serialise(buildResponse([evilSigned], { responseId: "_response_evil" }));
    const r = await verifySamlResponse(encodeRaw(one + two), baseConn([certPem]), baseCtx());
    ok("11a two top-level samlp:Response roots is rejected (second-root XSW at the document level)", r.ok === false);
  }
  // 11b. A single valid Response with trailing NON-markup junk after the close tag -> parser rejects the
  //      unexpected trailing content.
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    const one = serialise(buildResponse([signed]));
    const r = await verifySamlResponse(encodeRaw(one + "trailing-junk-not-a-comment"), baseConn([certPem]), baseCtx());
    ok("11b trailing non-markup junk after the Response is rejected (parser epilog gate)", r.ok === false);
  }
  // 11c. A bare second Assertion element appended after the Response root (a second root that is an Assertion).
  {
    const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
    const one = serialise(buildResponse([signed]));
    const strayAssertion = serialise(buildAssertion({ assertionId: "_stray", nameId: EVIL_NAMEID }));
    const r = await verifySamlResponse(encodeRaw(one + strayAssertion), baseConn([certPem]), baseCtx());
    ok("11c a stray second top-level Assertion after the Response is rejected (second-root)", r.ok === false);
  }
}

async function main(): Promise<void> {
  console.log("SAML XSW / XML-DSig attack corpus\n");
  const keys = await setupKeys();
  await testControl(keys);
  await testXswFamily(keys);
  await testXswDuplicateAndSiblings(keys);
  await testCommentInjection(keys);
  await testCommentInjectionPreserving(keys);
  await testDoctypeXxe(keys);
  await testMultipleSignatures(keys);
  await testTransformSmuggling(keys);
  await testAlgorithmDowngrade(keys);
  await testKeyInfoSubstitution(keys);
  await testUnsignedAssertion(keys);
  await testStatusMasking(keys);
  await testPerturbedGates(keys);
  await testMultipleRoots(keys);

  // ---- summary ----
  console.log("");
  if (fails.length > 0) process.exitCode = 1;
  if (fails.length > 0) {
    console.log("SAML XSW/CVE CORPUS: " + passed + " passed, " + fails.length + " FAILED");
    for (const f of fails) console.log("   FAILED (a payload that should REJECT was ACCEPTED, or a control broke): " + f);
    process.exit(1);
  }
  console.log("SAML XSW/CVE CORPUS PASS (" + passed + " checks)");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
