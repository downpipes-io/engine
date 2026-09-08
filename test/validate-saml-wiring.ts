// Prove the NATIVE SAML 2.0 Service Provider wiring end to end THROUGH THE ROUTER (handleAdmin) and the
// scheduler DO, with an in-memory DO double and a REAL RSA-signed SAMLResponse. No network, no deploy, no cost.
// Run: node --no-warnings test/validate-saml-wiring.ts
//
// What this proves (the glue the per-module validators - validate-saml-response.ts / -dsig.ts / -assertion.ts -
// do NOT cover, since they stop at the pure cores: they call verifySamlResponse directly, never the router + DO):
//  - an Owner (the ADMIN_TOKEN break-glass) creates a SAML connection via POST /admin/idp/connections carrying a
//    REAL self-signed X.509 PEM in idpSigningCerts (the trust root the SP pins); the keys.ceremony gate admits it;
//  - GET /admin/saml/metadata/<id> serves the SP EntityDescriptor (the document the customer uploads to the IdP),
//    carrying our ACS URL and WantAssertionsSigned="true";
//  - GET /admin/saml/start/<id>?returnTo=/dash mints the AuthnRequest + opaque single-use RelayState in the DO and
//    302s to the IdP SSO URL with SAMLRequest + RelayState query params; the SAMLRequest INFLATES (raw-DEFLATE)
//    back to the AuthnRequest XML, out of which we read the minted ID (the InResponseTo the SP will bind to);
//  - we build a samlp:Response wrapping a saml:Assertion, SIGN the Assertion with a genuine ENVELOPED XML-DSig
//    under the pinned key (mirroring validate-saml-response.ts's proven c14n+digest+sign machinery), and POST it
//    form-encoded to /admin/saml/acs/<id> with the RelayState. The DO consumes the single-use RelayState, runs the
//    PRODUCTION verifySamlResponse pipeline (parser -> pinned-cert signature -> consumeAssertion, with InResponseTo
//    bound to the minted request id and Recipient/Destination bound to our ACS URL), mints the v3 saml session, and
//    302s to the relative-only returnTo with a __Host-downpipes_session cookie;
//  - the email_verified-gated pending-invite BIND fires (the trust-idp email claims its "approver" invite), so
//    GET /admin/whoami over the saml cookie reports method "saml", the immutable saml:<connId>|<entityId>|<NameID>
//    subject, the connId, the bound role, and the GROUPS re-read from the server-side snapshot;
//  - the NEGATIVES each fail closed: a replay of the SAME ACS POST (RelayState is single-use), a TAMPERED assertion
//    (a claim mutated after signing), a RelayState the SP never minted, and a /start against a DISABLED connection.
//
// The signature is REAL (the same enveloped XML-DSig shape dsig.ts accepts, computed with the SAME c14n module the
// verifier uses), so the DO runs its genuine verification path, not a shim. The InResponseTo is read back out of
// the inflated AuthnRequest exactly as a real IdP echoes it. The audit-log JSON the DO prints to console is noise.

import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { samlSubject, roleSubjectKey } from "../src/admin/identity.ts";
import { ADMIN_COUNTER_NAMES, ADMIN_COUNTERS_KEY } from "../src/admin/diag-records.ts";
import { canonicalize, envelopedCopy } from "../src/admin/saml/c14n.ts";
import { ab } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";
import type { XmlElement, XmlAttr, } from "../src/admin/saml/xml-node.ts";
import { el, a, t, clone, b64std, serialise } from "./saml-response-fixtures.ts";
import { derSeq, derOid, derUtf8, derNull, derExplicit0, derInt, derGeneralizedTime, derBitString, derTlv, OID_SHA256_RSA, OID_CN } from "./saml-der.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

const CONSOLE_ORIGIN = "https://console.downpipes.io";
const ADMIN_TOKEN = "test-admin-token";
const CONN_ID = "work-idp";
const IDP_ENTITY = "https://idp.example/entity";
const IDP_SSO_URL = "https://idp.example/sso";
const SP_ENTITY = "https://console.downpipes.io/saml";
const NAMEID_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
// The canonical ACS the router serves for this connection (origin + the per-connection path). The DO pins the
// assertion Recipient + the Response Destination against THIS, so the fixtures must use it verbatim.
const ACS_URL = `${CONSOLE_ORIGIN}/admin/saml/acs/${CONN_ID}`;
// A plain, already-canonical email so the assertion attribute and the invited approver email are the one string
// (canonicalEmail lower-cases + trims; using a lowercase address keeps the bind target identical on both sides).
const USER_EMAIL = "samluser@acme.example";
const USER_NAMEID = "samluser@acme.example";
const USER_GROUPS = ["administrators", "billing"];

function makeEnv(): { env: Env; storage: MockStorage } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  const env = { SCHEDULER: namespace, CONSOLE_ORIGIN, ADMIN_TOKEN } as unknown as Env;
  return { env, storage };
}

// ---- helpers to drive handleAdmin (copied from validate-idp-wiring.ts) ----
function adminUrl(path: string): string {
  return `${CONSOLE_ORIGIN}${path}`;
}
function tokenHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json", ...extra };
}
function getSetCookie(resp: Response): string[] {
  const h = resp.headers as Headers & { getSetCookie?: () => string[] };
  if (typeof h.getSetCookie === "function") return h.getSetCookie();
  const one = resp.headers.get("set-cookie");
  return one ? [one] : [];
}
function cookieValue(setCookies: string[], name: string): string | null {
  for (const sc of setCookies) {
    const first = sc.split(";")[0] ?? "";
    const eq = first.indexOf("=");
    if (eq <= 0) continue;
    if (first.slice(0, eq).trim() !== name) continue;
    const v = first.slice(eq + 1).trim();
    return v.length > 0 ? v : null;
  }
  return null;
}

// XML tree builders (el/a/t/clone), standard padded base64 (b64std) and the faithful serialiser are the
// shared SAML fixture helpers, imported above from saml-response-fixtures.ts so a fix lands in one place.

// ---- a standard-base64 DECODE for inflating the SAMLRequest (wiring-only, not in the shared fixtures) ----
function b64stdDecode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---- algorithm URIs (match dsig.ts) ----
const C14N_EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
const TRANSFORM_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const SIG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";

// ---- SAML namespace + token constants ----
const SAML_PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
const SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
const STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
const BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

// ---- the enveloped XML-DSig signer (mirrors validate-saml-response.ts / validate-saml-dsig.ts signAssertion) ----
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
async function signAssertion(assertion: XmlElement, refId: string, privateKey: CryptoKey): Promise<XmlElement> {
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

// ---- minimal DER encoders to build a real self-signed X.509 cert wrapping an RSA public key (mirrors
//      validate-saml-response.ts buildSelfSignedCertPem; the SP only walks out the SPKI, but a genuine
//      self-signed cert proves the DER walk steps PAST a real sig-alg/issuer/validity/subject to the SPKI). ----
// The DER encoders and the cert OID constants are the shared SAML helpers, imported above from saml-der.ts.

async function buildSelfSignedCertPem(spkiDer: Uint8Array, signerPrivate: CryptoKey, cn: string): Promise<string> {
  const atv = derSeq(derOid(OID_CN), derUtf8(cn));
  const rdn = derTlv(0x31, atv);
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

// ---- assertion + response fixture builders (bearer, SP-initiated; the assertion declares its own saml: ns) ----
interface AOpts {
  assertionId?: string;
  nameId?: string;
  recipient?: string;
  inResponseTo?: string;
  audience?: string;
  notBefore?: string;
  notOnOrAfter?: string;
  scdNotOnOrAfter?: string;
  email?: string;
  groups?: string[];
  issueInstant?: string;
}
function buildAssertion(o: AOpts): XmlElement {
  const assertionId = o.assertionId ?? "_assertion_0001";
  const nameId = o.nameId ?? USER_NAMEID;
  const recipient = o.recipient ?? ACS_URL;
  const audience = o.audience ?? SP_ENTITY;
  const inResponseTo = o.inResponseTo!;
  const email = o.email ?? USER_EMAIL;
  const groups = o.groups ?? USER_GROUPS;

  const scd = el("saml:SubjectConfirmationData", [a("Recipient", recipient), a("NotOnOrAfter", o.scdNotOnOrAfter!), a("InResponseTo", inResponseTo)], []);
  const subjectConfirmation = el("saml:SubjectConfirmation", [a("Method", BEARER)], [scd]);
  const nameIdEl = el("saml:NameID", [a("Format", NAMEID_PERSISTENT)], [t(nameId)]);
  const subject = el("saml:Subject", [], [nameIdEl, subjectConfirmation]);

  const conditions = el(
    "saml:Conditions",
    [a("NotBefore", o.notBefore!), a("NotOnOrAfter", o.notOnOrAfter!)],
    [el("saml:AudienceRestriction", [], [el("saml:Audience", [], [t(audience)])])],
  );

  const groupValueEls = groups.map((g) => el("saml:AttributeValue", [], [t(g)]));
  const attributeStatement = el("saml:AttributeStatement", [], [
    el("saml:Attribute", [a("Name", "email")], [el("saml:AttributeValue", [], [t(email)])]),
    el("saml:Attribute", [a("Name", "groups")], groupValueEls),
  ]);

  return el(
    "saml:Assertion",
    [a("xmlns:saml", SAML_ASSERTION_NS), a("ID", assertionId), a("Version", "2.0"), a("IssueInstant", o.issueInstant!)],
    [el("saml:Issuer", [], [t(IDP_ENTITY)]), subject, conditions, attributeStatement],
  );
}

function buildResponse(assertion: XmlElement, inResponseTo: string, issueInstant: string): XmlElement {
  const attrs: XmlAttr[] = [
    a("xmlns:samlp", SAML_PROTOCOL_NS),
    a("ID", "_response_0001"),
    a("Version", "2.0"),
    a("IssueInstant", issueInstant),
    a("Destination", ACS_URL),
    a("InResponseTo", inResponseTo),
  ];
  const status = el("samlp:Status", [], [el("samlp:StatusCode", [a("Value", STATUS_SUCCESS)], [])]);
  return el("samlp:Response", attrs, [status, assertion]);
}

function encodeResponse(response: XmlElement): string {
  return b64std(new TextEncoder().encode(serialise(response)));
}

// ---- inflate a SAMLRequest (standard base64 -> raw DEFLATE) back to the AuthnRequest XML ----
async function inflateRaw(input: Uint8Array): Promise<Uint8Array> {
  const ds = new DecompressionStream("deflate-raw");
  const writer = ds.writable.getWriter();
  void writer.write(ab(input));
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

// extractAuthnRequestId reads the ID attribute off the (inflated) AuthnRequest XML. The minted id is the
// InResponseTo the assertion must echo; the SP mints it as "_<32hex>", so a tight, anchored match is honest.
function extractAuthnRequestId(xml: string): string | null {
  const m = /\bID="([^"]+)"/.exec(xml);
  return m ? (m[1] ?? null) : null;
}

console.log("Native SAML SP end-to-end wiring (router + DO + a real signed SAMLResponse)\n");

// Ctx carries the seeded env/storage, the legit IdP key + pinned cert, the in-window time constants, the
// per-response signer (buildSignedResponseB64) and the mutable round-trip tokens the ordered steps thread.
interface Ctx {
  env: Env;
  storage: MockStorage;
  rsa: CryptoKeyPair;
  certPem: string;
  notBefore: string;
  notOnOrAfter: string;
  scdNotOnOrAfter: string;
  issueInstant: string;
  buildSignedResponseB64: (opts: { inResponseTo: string; signerKey: CryptoKey; tamper?: boolean; groups?: string[] }) => Promise<string>;
  relayState: string;
  authnRequestId: string;
  samlTxn: string;
  sessionCookie: string;
  goodResponseB64: string;
}

// createConnection seeds a bound Owner + creates the SAML connection and returns the Ctx skeleton (the
// key material, the pinned cert and the time constants the rest of the flow reuses).
async function createConnection(): Promise<Ctx> {
  const { env, storage } = makeEnv();

  // The legit IdP signing key + its self-signed cert PEM (the pinned trust root). A SECOND, unrelated key + cert
  // is the attacker / non-pinned key, used in a negative below.
  const rsa = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const rsaSpki = new Uint8Array(await crypto.subtle.exportKey("spki", rsa.publicKey));
  const certPem = await buildSelfSignedCertPem(rsaSpki, rsa.privateKey, "idp.example");

  // Seed a bound Owner so the first-caller bootstrap does not claim the SAML user as Owner (this test wants the
  // SAML user to resolve to their INVITED approver role, not the bootstrap Owner). The ADMIN_TOKEN break-glass is
  // not a table entry, so without this the role table would be empty at the saml bind. Mirrors the OIDC validator.
  await storage.put(roleSubjectKey("passkey|founder@acme.example"), { subject: "passkey|founder@acme.example", email: "founder@acme.example", role: "owner", grantedBy: "system", grantedAt: "2026-06-13T00:00:00.000Z" });

  // The SAML connection proposal: pinned cert, persistent NameID, wantAssertionsSigned, SP-initiated only,
  // trust-idp email policy (so a well-formed assertion email is treated as verified and binds the invite).
  const proposal = {
    id: CONN_ID, kind: "saml", label: "Work IdP", presetId: "generic-saml", enabled: true,
    idpEntityId: IDP_ENTITY, idpSsoUrl: IDP_SSO_URL, idpSigningCerts: [certPem],
    spEntityId: SP_ENTITY, nameIdFormat: NAMEID_PERSISTENT, wantAssertionsSigned: true,
    allowIdpInitiated: false, clockSkewSec: 120, emailVerifiedPolicy: "trust-idp",
    emailAttr: "email", groupsAttr: "groups",
  };

  // 0a. Owner creates the SAML connection (keys.ceremony admits the ADMIN_TOKEN owner).
  {
    const r = await handleAdmin(new Request(adminUrl("/admin/idp/connections"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ proposal }) }), env);
    const body = (await r.json()) as { ok?: boolean; conn?: { kind?: string; idpSigningCerts?: unknown } };
    ok("create SAML connection: 200", r.status === 200);
    ok("create SAML connection: ok + kind saml", body.ok === true && body.conn?.kind === "saml");
    const record = await storage.get<{ kind?: string }>(`idpconn:${CONN_ID}`);
    ok("create SAML connection: stored under idpconn:<id>", record !== undefined && record.kind === "saml");
  }

  // 0b. Owner invites the assertion's email as APPROVER (a PENDING invite that must bind on first VERIFIED sign-in).
  {
    const r = await handleAdmin(new Request(adminUrl("/admin/roles"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ email: USER_EMAIL, role: "approver" }) }), env);
    ok("invite the SAML user as approver (pending): 200", r.status === 200);
  }

  const { notBefore, notOnOrAfter, scdNotOnOrAfter, issueInstant, buildSignedResponseB64 } = buildResponseSigner();
  return { env, storage, rsa, certPem, notBefore, notOnOrAfter, scdNotOnOrAfter, issueInstant, buildSignedResponseB64, relayState: "", authnRequestId: "", samlTxn: "", sessionCookie: "", goodResponseB64: "" };
}

// buildResponseSigner pins a fixed in-window clock (the DO injects Date.now() as the verify clock, so the
// bounds must straddle "now") and returns the per-response signer: each call mints a UNIQUE assertion id
// (on both the ID attr and the signature Reference URI) so a distinct sign-in is not refused by the
// one-time-use cache, and an optional tamper flips the NameID after signing (a digest-mismatch vector).
function buildResponseSigner(): Pick<Ctx, "notBefore" | "notOnOrAfter" | "scdNotOnOrAfter" | "issueInstant" | "buildSignedResponseB64"> {
  const nowMs = Date.now();
  const iso = (ms: number) => new Date(ms).toISOString();
  const notBefore = iso(nowMs - 5 * 60_000);
  const notOnOrAfter = iso(nowMs + 10 * 60_000);
  const scdNotOnOrAfter = iso(nowMs + 10 * 60_000);
  const issueInstant = iso(nowMs - 30_000);

  let assertionSeq = 0;
  const buildSignedResponseB64 = async (opts: { inResponseTo: string; signerKey: CryptoKey; tamper?: boolean; groups?: string[] }): Promise<string> => {
    const aid = `_assertion_${++assertionSeq}`;
    const assertion = buildAssertion({ inResponseTo: opts.inResponseTo, notBefore, notOnOrAfter, scdNotOnOrAfter, issueInstant, assertionId: aid, ...(opts.groups !== undefined ? { groups: opts.groups } : {}) });
    const signed = await signAssertion(assertion, aid, opts.signerKey);
    if (opts.tamper) {
      const subject = signed.children.find((c) => c.type === "element" && (c as XmlElement).name === "saml:Subject") as XmlElement;
      const nameIdEl = subject.children.find((c) => c.type === "element" && (c as XmlElement).name === "saml:NameID") as XmlElement;
      nameIdEl.children = [t("attacker@evil.example")];
    }
    return encodeResponse(buildResponse(signed, opts.inResponseTo, issueInstant));
  };
  return { notBefore, notOnOrAfter, scdNotOnOrAfter, issueInstant, buildSignedResponseB64 };
}

// 1. GET /admin/saml/metadata/<id> -> 200, the SP EntityDescriptor with our ACS URL + WantAssertionsSigned.
async function verifyMetadata(ctx: Ctx): Promise<void> {
  const { env } = ctx;
  {
    const r = await handleAdmin(new Request(adminUrl(`/admin/saml/metadata/${CONN_ID}`), { method: "GET" }), env);
    ok("metadata: 200", r.status === 200);
    ok("metadata: content-type is application/samlmetadata+xml", (r.headers.get("content-type") ?? "").includes("application/samlmetadata+xml"));
    ok("metadata: content-type carries charset=utf-8 (V4.1.1)", (r.headers.get("content-type") ?? "").toLowerCase().includes("charset=utf-8"));
    const body = await r.text();
    ok("metadata: carries our ACS URL", body.includes(`Location="${ACS_URL}"`));
    ok('metadata: WantAssertionsSigned="true"', body.includes('WantAssertionsSigned="true"'));
    ok("metadata: SP entityID is the configured spEntityId", body.includes(`entityID="${SP_ENTITY}"`));
  }
}

// 2. GET /admin/saml/start/<id>?returnTo=/dash -> 302 to the IdP SSO URL carrying SAMLRequest + RelayState.
//    Inflate the SAMLRequest and read the minted AuthnRequest ID (the InResponseTo to bind to).
async function verifyStart(ctx: Ctx): Promise<void> {
  const { env } = ctx;
  {
    const r = await handleAdmin(new Request(adminUrl(`/admin/saml/start/${CONN_ID}?returnTo=%2Fdash`), { method: "GET" }), env);
    ok("start: 302", r.status === 302);
    const loc = r.headers.get("location") ?? "";
    ok("start: Location is the IdP SSO URL", loc.startsWith(IDP_SSO_URL));
    ok("start: Referrer-Policy no-referrer on the 302", (r.headers.get("referrer-policy") ?? "").toLowerCase() === "no-referrer");
    const u = new URL(loc);
    const samlRequest = u.searchParams.get("SAMLRequest") ?? "";
    ctx.relayState = u.searchParams.get("RelayState") ?? "";
    ok("start: SAMLRequest + RelayState query params present", samlRequest.length > 0 && ctx.relayState.length > 0);
    ctx.samlTxn = cookieValue(getSetCookie(r), "__Host-downpipes_saml_txn") ?? "";
    // The SAML browser-binding cookie MUST be SameSite=None; Secure (NOT Lax like OIDC): the IdP returns the
    // assertion via the HTTP-POST binding as a cross-site FORM POST to the ACS, and a Lax cookie is NOT sent on
    // a cross-site POST (only on a top-level cross-site GET), so a Lax cookie would arrive empty and the binding
    // check would always fail. None lets it ride the cross-site POST; the __Host- prefix + Secure are retained.
    const samlSetCookie = getSetCookie(r).find((c) => c.includes("__Host-downpipes_saml_txn")) ?? "";
    ok("start: the __Host- saml browser-binding cookie is set (SameSite=None; Secure, survives the cross-site ACS POST)", ctx.samlTxn.length > 0 && /SameSite=None/i.test(samlSetCookie) && /Secure/i.test(samlSetCookie) && !/SameSite=Lax/i.test(samlSetCookie));
    // Inflate: standard-base64-decode (URLSearchParams already percent-decoded the value) then raw-DEFLATE.
    const inflated = new TextDecoder().decode(await inflateRaw(b64stdDecode(samlRequest)));
    ok("start: SAMLRequest inflates to a samlp:AuthnRequest", inflated.includes("AuthnRequest") && inflated.includes(`Destination="${IDP_SSO_URL}"`));
    ok("start: AuthnRequest advertises our ACS as AssertionConsumerServiceURL", inflated.includes(`AssertionConsumerServiceURL="${ACS_URL}"`));
    ctx.authnRequestId = extractAuthnRequestId(inflated) ?? "";
    ok("start: extracted the minted AuthnRequest ID (the InResponseTo binding)", /^_[0-9a-f]{32}$/.test(ctx.authnRequestId));
  }
}

// 4. POST /admin/saml/acs/<id> with SAMLResponse + RelayState -> 302 + __Host-downpipes_session cookie + /dash.
async function verifyAcs(ctx: Ctx): Promise<void> {
  const { env, rsa, samlTxn, relayState, authnRequestId } = ctx;
  // Capture the genuine (untampered) Response so the REPLAY negative re-POSTs the exact same bytes.
  ctx.goodResponseB64 = await ctx.buildSignedResponseB64({ inResponseTo: authnRequestId, signerKey: rsa.privateKey });
  {
    const body = `SAMLResponse=${encodeURIComponent(ctx.goodResponseB64)}&RelayState=${encodeURIComponent(relayState)}`;
    const r = await handleAdmin(new Request(adminUrl(`/admin/saml/acs/${CONN_ID}`), { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", cookie: `__Host-downpipes_saml_txn=${samlTxn}` }, body }), env);
    ok("acs: 302", r.status === 302);
    ok("acs: Location is the relative-only returnTo (/dash)", (r.headers.get("location") ?? "") === "/dash");
    const cookies = getSetCookie(r);
    ctx.sessionCookie = cookieValue(cookies, "__Host-downpipes_session") ?? "";
    ok("acs: __Host-downpipes_session cookie minted", ctx.sessionCookie.length > 0);
    ok("acs: Referrer-Policy no-referrer on the 302", (r.headers.get("referrer-policy") ?? "").toLowerCase() === "no-referrer");
  }
}

// 5. GET /admin/whoami over the saml cookie: method saml, the immutable subject, connId, the bound role, groups.
async function verifyWhoami(ctx: Ctx): Promise<void> {
  const { env, sessionCookie } = ctx;
  const expectSubject = samlSubject(CONN_ID, IDP_ENTITY, USER_NAMEID);
  {
    const r = await handleAdmin(new Request(adminUrl("/admin/whoami"), { method: "GET", headers: { cookie: `__Host-downpipes_session=${sessionCookie}` } }), env);
    ok("whoami: 200 over the saml session cookie", r.status === 200);
    const body = (await r.json()) as { method?: string; subject?: string; role?: string; groups?: string[]; connId?: string };
    ok("whoami: method is saml", body.method === "saml");
    ok("whoami: subject is saml:<connId>|<idpEntityId>|<NameID> (verbatim, never re-derived)", body.subject === expectSubject);
    ok("whoami: subject starts with saml:<id>|", (body.subject ?? "").startsWith(`saml:${CONN_ID}|`));
    ok("whoami: connId is the connection", body.connId === CONN_ID);
    ok("whoami: the email_verified-gated pending invite BOUND (role == approver)", body.role === "approver");
    ok("whoami: groups re-read from the server-side snapshot (NOT the cookie)", JSON.stringify(body.groups) === JSON.stringify(USER_GROUPS));
  }
}

// 6a. REPLAY the SAME ACS POST: the RelayState was single-use (consumed + deleted at the first ACS), so the
//     second POST finds no request record and is rejected (this is also what enforces SP-initiated-only).
async function testReplay(ctx: Ctx): Promise<void> {
  const { env, goodResponseB64, relayState } = ctx;
  {
    const body = `SAMLResponse=${encodeURIComponent(goodResponseB64)}&RelayState=${encodeURIComponent(relayState)}`;
    const r = await handleAdmin(new Request(adminUrl(`/admin/saml/acs/${CONN_ID}`), { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body }), env);
    ok("replay: a second ACS POST with the SAME single-use RelayState is rejected (no session)", r.status === 302 && (r.headers.get("location") ?? "").includes("oidc=failed") && cookieValue(getSetCookie(r), "__Host-downpipes_session") === null);
  }
}

// 6g. ASSERTION REPLAY (the DO-level SEEN_ASSERTION_PREFIX one-time-use cache, ASVS V3.5): a FRESH /start gives
//     a NEW single-use RelayState + AuthnRequest id, but the Response REUSES an assertionId already consumed by
//     the step-4 sign-in. The RelayState/InResponseTo are all valid, so ONLY the assertion-replay cache can
//     reject it; the second use within the validity window MUST be refused (no session minted).
async function testAssertionReplay(ctx: Ctx): Promise<void> {
  const { env, rsa } = ctx;
  {
    const s = await handleAdmin(new Request(adminUrl(`/admin/saml/start/${CONN_ID}`), { method: "GET" }), env);
    const su = new URL(s.headers.get("location") ?? "https://x/");
    const rs = su.searchParams.get("RelayState") ?? "";
    const sr = su.searchParams.get("SAMLRequest") ?? "";
    const reqId = extractAuthnRequestId(new TextDecoder().decode(await inflateRaw(b64stdDecode(sr)))) ?? "";
    const st = cookieValue(getSetCookie(s), "__Host-downpipes_saml_txn") ?? "";
    // Re-sign a Response with the SAME assertionId the step-4 sign-in consumed ("_assertion_1"), but bound to the
    // fresh AuthnRequest id (so the InResponseTo + RelayState are both valid and only the seen-assertion check fires).
    const assertion = buildAssertion({ inResponseTo: reqId, notBefore: ctx.notBefore, notOnOrAfter: ctx.notOnOrAfter, scdNotOnOrAfter: ctx.scdNotOnOrAfter, issueInstant: ctx.issueInstant, assertionId: "_assertion_1" });
    const signed = await signAssertion(assertion, "_assertion_1", rsa.privateKey);
    const replayBytes = encodeResponse(buildResponse(signed, reqId, ctx.issueInstant));
    const body = `SAMLResponse=${encodeURIComponent(replayBytes)}&RelayState=${encodeURIComponent(rs)}`;
    const r = await handleAdmin(new Request(adminUrl(`/admin/saml/acs/${CONN_ID}`), { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", cookie: `__Host-downpipes_saml_txn=${st}` }, body }), env);
    ok("assertion-replay: re-using an already-consumed assertionId within its window is rejected (no session)", r.status === 302 && (r.headers.get("location") ?? "").includes("oidc=failed") && cookieValue(getSetCookie(r), "__Host-downpipes_session") === null);
  }
}

// 6b. TAMPERED assertion: a FRESH /start (new RelayState + new AuthnRequest id), then a Response whose NameID was
//     flipped AFTER signing -> the enveloped-signature digest no longer matches -> rejected at the dsig step.
async function testTamper(ctx: Ctx): Promise<void> {
  const { env, rsa, buildSignedResponseB64 } = ctx;
  {
    const s = await handleAdmin(new Request(adminUrl(`/admin/saml/start/${CONN_ID}`), { method: "GET" }), env);
    const su = new URL(s.headers.get("location") ?? "https://x/");
    const rs = su.searchParams.get("RelayState") ?? "";
    const sr = su.searchParams.get("SAMLRequest") ?? "";
    const reqId = extractAuthnRequestId(new TextDecoder().decode(await inflateRaw(b64stdDecode(sr)))) ?? "";
    const st = cookieValue(getSetCookie(s), "__Host-downpipes_saml_txn") ?? "";
    const tampered = await buildSignedResponseB64({ inResponseTo: reqId, signerKey: rsa.privateKey, tamper: true });
    const body = `SAMLResponse=${encodeURIComponent(tampered)}&RelayState=${encodeURIComponent(rs)}`;
    const r = await handleAdmin(new Request(adminUrl(`/admin/saml/acs/${CONN_ID}`), { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", cookie: `__Host-downpipes_saml_txn=${st}` }, body }), env);
    ok("tamper: a post-signing NameID mutation is rejected via digest mismatch (no session)", r.status === 302 && (r.headers.get("location") ?? "").includes("oidc=failed") && cookieValue(getSetCookie(r), "__Host-downpipes_session") === null);
  }
}

// 6c. A RelayState the SP NEVER minted: a well-formed, correctly-signed Response (fresh start to get a real
//     AuthnRequest id) but POSTed under a bogus RelayState -> no request record -> rejected. This isolates the
//     RelayState binding (the assertion itself is valid; only the round-trip token is forged).
async function testForgedRelayState(ctx: Ctx): Promise<void> {
  const { env, rsa, buildSignedResponseB64 } = ctx;
  {
    const s = await handleAdmin(new Request(adminUrl(`/admin/saml/start/${CONN_ID}`), { method: "GET" }), env);
    const su = new URL(s.headers.get("location") ?? "https://x/");
    const sr = su.searchParams.get("SAMLRequest") ?? "";
    const reqId = extractAuthnRequestId(new TextDecoder().decode(await inflateRaw(b64stdDecode(sr)))) ?? "";
    const resp = await buildSignedResponseB64({ inResponseTo: reqId, signerKey: rsa.privateKey });
    const bogusRelay = "this-relaystate-was-never-minted";
    const body = `SAMLResponse=${encodeURIComponent(resp)}&RelayState=${encodeURIComponent(bogusRelay)}`;
    const r = await handleAdmin(new Request(adminUrl(`/admin/saml/acs/${CONN_ID}`), { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body }), env);
    ok("forged-relaystate: an ACS POST under a RelayState the SP never minted is rejected (no session)", r.status === 302 && (r.headers.get("location") ?? "").includes("oidc=failed") && cookieValue(getSetCookie(r), "__Host-downpipes_session") === null);
  }
}

// 6d. Signature by a NON-pinned key: a fresh start, then a Response signed with the ATTACKER key while the
//     connection pins only the legit cert -> the signature does not verify under any pinned cert -> rejected.
async function testNonPinnedKey(ctx: Ctx): Promise<void> {
  const { env, buildSignedResponseB64 } = ctx;
  {
    const rsaOther = (await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const s = await handleAdmin(new Request(adminUrl(`/admin/saml/start/${CONN_ID}`), { method: "GET" }), env);
    const su = new URL(s.headers.get("location") ?? "https://x/");
    const rs = su.searchParams.get("RelayState") ?? "";
    const sr = su.searchParams.get("SAMLRequest") ?? "";
    const reqId = extractAuthnRequestId(new TextDecoder().decode(await inflateRaw(b64stdDecode(sr)))) ?? "";
    const st = cookieValue(getSetCookie(s), "__Host-downpipes_saml_txn") ?? "";
    const resp = await buildSignedResponseB64({ inResponseTo: reqId, signerKey: rsaOther.privateKey });
    const body = `SAMLResponse=${encodeURIComponent(resp)}&RelayState=${encodeURIComponent(rs)}`;
    const r = await handleAdmin(new Request(adminUrl(`/admin/saml/acs/${CONN_ID}`), { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", cookie: `__Host-downpipes_saml_txn=${st}` }, body }), env);
    ok("non-pinned-key: an assertion signed by an unpinned key is rejected (no session)", r.status === 302 && (r.headers.get("location") ?? "").includes("oidc=failed") && cookieValue(getSetCookie(r), "__Host-downpipes_session") === null);
  }
}

// 6e. FORCED-LOGIN / session fixation (CWE-384): a fresh start + a VALID signed Response + the correct
//     RelayState, but POSTed WITHOUT the __Host- saml browser-binding cookie (exactly what a foreign browser
//     into which an attacker replays a captured assertion would carry) -> rejected before any session mints.
async function testForcedLogin(ctx: Ctx): Promise<void> {
  const { env, rsa, buildSignedResponseB64 } = ctx;
  {
    const s = await handleAdmin(new Request(adminUrl(`/admin/saml/start/${CONN_ID}`), { method: "GET" }), env);
    const su = new URL(s.headers.get("location") ?? "https://x/");
    const rs = su.searchParams.get("RelayState") ?? "";
    const sr = su.searchParams.get("SAMLRequest") ?? "";
    const reqId = extractAuthnRequestId(new TextDecoder().decode(await inflateRaw(b64stdDecode(sr)))) ?? "";
    const resp = await buildSignedResponseB64({ inResponseTo: reqId, signerKey: rsa.privateKey });
    const body = `SAMLResponse=${encodeURIComponent(resp)}&RelayState=${encodeURIComponent(rs)}`;
    const r = await handleAdmin(new Request(adminUrl(`/admin/saml/acs/${CONN_ID}`), { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body }), env);
    ok("forced-login: a valid assertion + RelayState but NO browser-binding cookie is rejected (no session)", r.status === 302 && (r.headers.get("location") ?? "").includes("oidc=failed") && cookieValue(getSetCookie(r), "__Host-downpipes_session") === null);
    // Positive control: the SAME flow WITH the matching browser-binding cookie mints a session (the defence binds, not breaks).
    const s2 = await handleAdmin(new Request(adminUrl(`/admin/saml/start/${CONN_ID}`), { method: "GET" }), env);
    const su2 = new URL(s2.headers.get("location") ?? "https://x/");
    const rs2 = su2.searchParams.get("RelayState") ?? "";
    const sr2 = su2.searchParams.get("SAMLRequest") ?? "";
    const reqId2 = extractAuthnRequestId(new TextDecoder().decode(await inflateRaw(b64stdDecode(sr2)))) ?? "";
    const st2 = cookieValue(getSetCookie(s2), "__Host-downpipes_saml_txn") ?? "";
    const resp2 = await buildSignedResponseB64({ inResponseTo: reqId2, signerKey: rsa.privateKey });
    const body2 = `SAMLResponse=${encodeURIComponent(resp2)}&RelayState=${encodeURIComponent(rs2)}`;
    const r2 = await handleAdmin(new Request(adminUrl(`/admin/saml/acs/${CONN_ID}`), { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", cookie: `__Host-downpipes_saml_txn=${st2}` }, body: body2 }), env);
    ok("forced-login: the same flow WITH the matching browser-binding cookie mints a session", r2.status === 302 && cookieValue(getSetCookie(r2), "__Host-downpipes_session") !== null);
  }
}

// 6f. /start while the connection is DISABLED -> generic fail redirect (no new sign-ins through a disabled conn).
async function testDisabled(ctx: Ctx): Promise<void> {
  const { env } = ctx;
  {
    const d = await handleAdmin(new Request(adminUrl("/admin/idp/connections/enabled"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ connId: CONN_ID, enabled: false }) }), env);
    ok("disable connection: 200", d.status === 200);
    const s = await handleAdmin(new Request(adminUrl(`/admin/saml/start/${CONN_ID}`), { method: "GET" }), env);
    ok("disabled: /start refused (generic fail redirect, NOT an IdP SSO URL)", s.status === 302 && (s.headers.get("location") ?? "").includes("oidc=failed"));
    // Re-enable so the connection is left in a clean state (harmless; the test is otherwise done).
    await handleAdmin(new Request(adminUrl("/admin/idp/connections/enabled"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ connId: CONN_ID, enabled: true }) }), env);
  }
}

// 7. THE SAML GROUP BOUNDING DROPS, through the REAL front door.
//
// SAML groups ride VERBATIM out of the assertion (collectIdentity returns every value of the configured groups
// attribute, unbounded) and are first bounded inside the native session mint. That bound used to record only the
// coarse group-name-dropped count -- which names neither the KIND nor the boundary -- so "the user is in the
// right AD group and gets viewer" had no answer for the one interactive sign-in kind whose groups this engine
// bounds itself. Driven end to end: a REAL /start, a REAL signed assertion carrying 260 groups plus an over-long
// name plus a control-char name, a REAL ACS POST, and the counters read back OUT OF THE DO.
async function testSamlClaimDrops(ctx: Ctx): Promise<void> {
  const { env, storage, rsa, buildSignedResponseB64 } = ctx;
  const counters = async (): Promise<Record<string, { count: number }>> => {
    await new Promise((r) => setTimeout(r, 5)); // the recorder is fire-and-forget by contract (it must never block a sign-in)
    return ((await storage.get(ADMIN_COUNTERS_KEY)) ?? {}) as Record<string, { count: number }>;
  };
  const signIn = async (groups: string[]): Promise<boolean> => {
    const s = await handleAdmin(new Request(adminUrl(`/admin/saml/start/${CONN_ID}`), { method: "GET" }), env);
    const su = new URL(s.headers.get("location") ?? "https://x/");
    const rs = su.searchParams.get("RelayState") ?? "";
    const sr = su.searchParams.get("SAMLRequest") ?? "";
    const reqId = extractAuthnRequestId(new TextDecoder().decode(await inflateRaw(b64stdDecode(sr)))) ?? "";
    const st = cookieValue(getSetCookie(s), "__Host-downpipes_saml_txn") ?? "";
    const resp = await buildSignedResponseB64({ inResponseTo: reqId, signerKey: rsa.privateKey, groups });
    const body = `SAMLResponse=${encodeURIComponent(resp)}&RelayState=${encodeURIComponent(rs)}`;
    const r = await handleAdmin(new Request(adminUrl(`/admin/saml/acs/${CONN_ID}`), { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", cookie: `__Host-downpipes_saml_txn=${st}` }, body }), env);
    return r.status === 302 && cookieValue(getSetCookie(r), "__Host-downpipes_session") !== null;
  };

  // STATE 1: an ordinary sign-in, two well-formed groups. A legitimate state must never cry wolf.
  const minted1 = await signIn(["administrators", "billing"]);
  const afterClean = await counters();
  ok("an ordinary SAML sign-in mints a session", minted1);
  ok("a clean group list records NO claim-drop row (a legitimate state must never cry wolf)", Object.keys(afterClean).every((k) => !k.startsWith("claim-drop-")));

  // STATE 2: the mapped group is PAST THE CAP, and the assertion also carries an over-long name and a
  // control-char name. Three different bounds, three different remedies, three different rows.
  // The over-long and control-char names sit INSIDE the cap (an IdP asserts them in whatever order it likes);
  // the mapped group is the one that falls PAST it, which is the gap's own ticket.
  const many = Array.from({ length: 260 }, (_, i) => `grp-${i}`);
  const minted2 = await signIn(["x".repeat(300), "bad\tgroup", ...many, "the-mapped-group"]);
  const after = await counters();
  ok("the sign-in with a hostile group list still SUCCEEDS (the drop is silent by design, which is the whole gap)", minted2);
  ok("the group list past the cap -> claim-drop-saml-groups-list-capped", (after["claim-drop-saml-groups-list-capped"]?.count ?? 0) >= 1);
  ok("an over-length group name -> claim-drop-saml-group-overlength", (after["claim-drop-saml-group-overlength"]?.count ?? 0) >= 1);
  ok("a control-char group name -> claim-drop-saml-group-control-char", (after["claim-drop-saml-group-control-char"]?.count ?? 0) >= 1);
  ok("the three rows are DISTINCT (the kind and the boundary do not coalesce)", new Set(["claim-drop-saml-groups-list-capped", "claim-drop-saml-group-overlength", "claim-drop-saml-group-control-char"]).size === 3);
  ok("no group NAME rides in any counter key", !JSON.stringify(after).includes("the-mapped-group") && !JSON.stringify(after).includes("grp-1"));
  // The caller-header boundary is GONE: every producer of a Caller pre-bounds with identical limits, so it
  // could never drop anything a real request carries. Nothing may re-introduce a member for it.
  ok("no claim-drop-caller-header-* member exists in the closed vocabulary", !(ADMIN_COUNTER_NAMES as readonly string[]).some((n) => n.startsWith("claim-drop-caller-header-")));
}

async function main(): Promise<void> {
  const ctx = await createConnection();
  await verifyMetadata(ctx);
  await verifyStart(ctx);
  await verifyAcs(ctx);
  await verifyWhoami(ctx);
  // 6. NEGATIVES (each MUST fail closed: 302 to oidc=failed, NO session cookie).
  await testReplay(ctx);
  await testAssertionReplay(ctx);
  await testTamper(ctx);
  await testForgedRelayState(ctx);
  await testNonPinnedKey(ctx);
  await testForcedLogin(ctx);
  await testDisabled(ctx);
  await testSamlClaimDrops(ctx);
}

await main();

if (failures > 0) process.exitCode = 1;
if (failures === 0) console.log("\nNATIVE SAML WIRING VECTORS PASS");
else {
  console.log(`\n${failures} FAILURE(S)`);
  process.exitCode = 1;
}
