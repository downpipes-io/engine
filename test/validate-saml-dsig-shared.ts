// Shared harness, tree builders and the signing helper for the SAML XML-DSig verifier vectors. The vector
// suite was split out of test/validate-saml-dsig.ts (the single main() exceeded a line-count limit). The
// happy-path and red-corpus groups each live in a sibling module and call the
// helpers here, so the orchestrator runs the same assertions in the same order.
//
// Node 25 strip-types; Web Crypto only (global crypto.subtle), no Node builtins.

import { verifyXmlSignature } from "../src/admin/saml/dsig.ts";
import type { VerifyXmlSignatureOptions } from "../src/admin/saml/dsig.ts";
import { canonicalize, envelopedCopy } from "../src/admin/saml/c14n.ts";
import type { XmlElement, XmlAttr, XmlChild } from "../src/admin/saml/xml-node.ts";
import { ab } from "../src/crypto/bytes.ts";

// ---- tiny test harness ----
// A single shared harness instance accumulates passes/failures across the extracted groups so the orchestrator
// can print one summary and set the exit code.
export interface Harness {
  passed: number;
  fails: string[];
}

export function newHarness(): Harness {
  return { passed: 0, fails: [] };
}

export function check(h: Harness, cond: boolean, desc: string): void {
  if (cond) {
    h.passed++;
    console.log("  ok   " + desc);
  } else {
    h.fails.push(desc);
    console.log("  FAIL " + desc);
  }
}

export async function expectOk(h: Harness, target: XmlElement, key: Uint8Array | CryptoKey, opts: VerifyXmlSignatureOptions | undefined, desc: string) {
  const r = await verifyXmlSignature(target, key, opts);
  check(h, r.ok === true, desc + (r.ok ? "" : " -unexpectedly REJECTED: " + r.reason));
  return r;
}

export async function expectFail(h: Harness, target: XmlElement, key: Uint8Array | CryptoKey, opts: VerifyXmlSignatureOptions | undefined, desc: string) {
  const r = await verifyXmlSignature(target, key, opts);
  check(h, r.ok === false, desc + (r.ok ? " -UNEXPECTEDLY ACCEPTED" : ""));
  return r;
}

// ---- tree builders ----
export function el(name: string, attrs: XmlAttr[], children: XmlChild[]): XmlElement {
  return { type: "element", name, attrs, children };
}
export function a(name: string, value: string): XmlAttr {
  return { name, value };
}
export function t(value: string): XmlChild {
  return { type: "text", value };
}
// deep clone so each test mutates an independent tree
export function clone(x: XmlElement): XmlElement {
  return {
    type: "element",
    name: x.name,
    attrs: x.attrs.map((at) => ({ name: at.name, value: at.value })),
    children: x.children.map((c) => (c.type === "element" ? clone(c) : { type: c.type, value: c.value }) as XmlChild),
  };
}

// ---- base64 (standard, with padding) for embedding DigestValue / SignatureValue ----
export function b64std(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

// ---- algorithm URIs (match dsig.ts) ----
export const C14N_EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
export const TRANSFORM_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
export const SIG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
export const SIG_RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
export const SIG_ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
export const DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
export const DIGEST_SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";

// buildAssertion makes a SAML-Assertion-shaped element with the given ID and a couple of claim children.
export function buildAssertion(id: string): XmlElement {
  return el(
    "saml:Assertion",
    [a("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion"), a("ID", id), a("Version", "2.0")],
    [
      el("saml:Issuer", [], [t("https://idp.example.com")]),
      el("saml:Subject", [], [el("saml:NameID", [], [t("alice@example.com")])]),
      el("saml:Conditions", [a("NotOnOrAfter", "2030-01-01T00:00:00Z")], []),
    ],
  );
}

// buildSignedInfo assembles a SignedInfo carrying the given digest, with the standard transform pair. The
// SignedInfo declares the ds: namespace itself so it canonicalises self-containedly (matching what real
// signers emit and what the verifier's inherited-context handling must also accept).
export function buildSignedInfo(refId: string, digestB64: string, sigMethod: string, digestMethod: string, transforms: XmlElement[]): XmlElement {
  return el(
    "ds:SignedInfo",
    [a("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")],
    [
      el("ds:CanonicalizationMethod", [a("Algorithm", C14N_EXC)], []),
      el("ds:SignatureMethod", [a("Algorithm", sigMethod)], []),
      el(
        "ds:Reference",
        [a("URI", "#" + refId)],
        [
          el("ds:Transforms", [], transforms),
          el("ds:DigestMethod", [a("Algorithm", digestMethod)], []),
          el("ds:DigestValue", [], [t(digestB64)]),
        ],
      ),
    ],
  );
}

export function standardTransforms(): XmlElement[] {
  return [
    el("ds:Transform", [a("Algorithm", TRANSFORM_ENVELOPED)], []),
    el("ds:Transform", [a("Algorithm", C14N_EXC)], []),
  ];
}

// signAssertion builds a fully-signed assertion: it computes the Reference digest over
// exc-c14n#(enveloped(assertion)) using the SAME c14n the verifier uses, builds the SignedInfo + Signature,
// canonicalises SignedInfo, signs it, and embeds the SignatureValue. The Signature is inserted as a child of
// the Assertion (enveloped). Returns the signed Assertion. `placeholderSig` is a Signature element built
// WITHOUT a SignatureValue yet so envelopedCopy removes exactly the right subtree during digest computation
// (the digest is over the assertion MINUS the whole Signature element, signature value included or not - and
// since the digest excises the entire Signature subtree by identity, its eventual SignatureValue content does
// not affect the digest).
export async function signAssertion(
  assertion: XmlElement,
  refId: string,
  privateKey: CryptoKey,
  family: "RSA" | "EC",
  hash: "SHA-256" | "SHA-384",
  sigMethod: string,
  opts?: { keyInfo?: XmlElement; extraTransforms?: XmlElement[]; digestMethod?: string; digestHash?: AlgorithmIdentifier },
): Promise<XmlElement> {
  const digestMethod = opts?.digestMethod ?? DIGEST_SHA256;
  const digestHash = opts?.digestHash ?? "SHA-256";
  const transforms = opts?.extraTransforms ?? standardTransforms();

  // Build the Signature element FIRST (without SignatureValue) so we can excise it by identity for the digest.
  // We compute the digest over the assertion with this exact Signature object removed.
  const signedInfoPlaceholder = buildSignedInfo(refId, "", sigMethod, digestMethod, transforms.map((x) => clone(x)));
  const sigChildren: XmlChild[] = [signedInfoPlaceholder, el("ds:SignatureValue", [], [t("")])];
  if (opts?.keyInfo) sigChildren.push(opts.keyInfo);
  const signature = el("ds:Signature", [a("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")], sigChildren);

  // Insert the Signature as a child of the assertion (enveloped). Place it after Issuer, like real IdPs.
  const signed = clone(assertion);
  signed.children.splice(1, 0, signature);

  // Find the referenced element (the assertion itself here) and the inserted signature object inside `signed`.
  const insertedSig = signed.children[1] as XmlElement;
  // Compute digest = hash(exc-c14n#(enveloped(referenced))). The referenced element is the assertion (signed).
  const enveloped = envelopedCopy(signed, insertedSig);
  const refCanon = canonicalize(enveloped);
  if (!refCanon.ok) throw new Error("test setup: ref canon failed: " + refCanon.reason);
  const digest = new Uint8Array(await crypto.subtle.digest(digestHash, ab(new TextEncoder().encode(refCanon.canonical))));
  const digestB64 = b64std(digest);

  // Now write the real digest into the SignedInfo's DigestValue.
  const realSignedInfo = buildSignedInfo(refId, digestB64, sigMethod, digestMethod, transforms.map((x) => clone(x)));
  insertedSig.children[0] = realSignedInfo;

  // Canonicalise SignedInfo in the inherited context of its ancestors, then sign.
  // The verifier builds the inherited context from the document; here SignedInfo declares its own ds:, and the
  // ancestor saml: prefix is not used inside SignedInfo, so an empty/derived context yields the same bytes.
  // We canonicalise with NO inherited context to mirror a self-contained SignedInfo; the verifier derives the
  // ancestor context but since SignedInfo re-declares ds: and uses no ancestor prefixes, the bytes match.
  const siCanon = canonicalize(realSignedInfo);
  if (!siCanon.ok) throw new Error("test setup: SignedInfo canon failed: " + siCanon.reason);
  const siBytes = new TextEncoder().encode(siCanon.canonical);

  let sigBytes: Uint8Array;
  if (family === "RSA") {
    sigBytes = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, ab(siBytes)));
  } else {
    sigBytes = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash }, privateKey, ab(siBytes)));
  }
  // Write the SignatureValue.
  insertedSig.children[1] = el("ds:SignatureValue", [], [t(b64std(sigBytes))]);
  return signed;
}

// exportSpki exports a public key as raw X.509 SPKI bytes (what the verifier imports).
export async function exportSpki(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("spki", key));
}

// Keys and a fixed assertion ID shared by both vector groups. The keys are generated once and threaded through.
export interface VectorKeys {
  rsa: CryptoKeyPair;
  rsaSpki: Uint8Array;
  ec: CryptoKeyPair;
  ecSpki: Uint8Array;
  rsaOther: CryptoKeyPair;
  rsaOtherSpki: Uint8Array;
  ID: string;
}

export async function generateVectorKeys(): Promise<VectorKeys> {
  const rsa = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const rsaSpki = await exportSpki(rsa.publicKey);

  const ec = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const ecSpki = await exportSpki(ec.publicKey);

  // A SECOND, unrelated RSA key (the "wrong"/attacker cert).
  const rsaOther = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const rsaOtherSpki = await exportSpki(rsaOther.publicKey);

  return { rsa, rsaSpki, ec, ecSpki, rsaOther, rsaOtherSpki, ID: "_assertion_1" };
}
