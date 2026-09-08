// XML-DSig ENVELOPED-signature verification over a SAML node, VERIFY-BY-IDENTITY. Given a target element (a
// SAML Response or Assertion) and the SP's PINNED IdP signing certificate, it returns the verified element or
// a reject reason. It is the gate the whole native SAML SP trusts: if it returns ok, the bytes the SP then
// reads claims from were signed by the pinned key over the resolved element, MINUS exactly its own enveloped
// signature. Every known XML-DSig wrapping/confusion attack class is closed by construction here:
//
//  - ONE Signature, ONE Reference, ONE element bearing the referenced ID. >1 of any -> reject (XML Signature
//    Wrapping needs a duplicate ID or a second Signature/Reference to smuggle a second tree; we refuse all).
//  - The referenced element is resolved to an OBJECT by a hand-rolled unique-ID walk over the SAML ID
//    attribute, and the digest is taken over THAT object's canonical form; we never digest "whatever the
//    parser thinks #id points at" or trust document order.
//  - An ALGORITHM ALLOWLIST is enforced BEFORE any crypto: c14n must be exc-c14n#; signature must be
//    rsa-sha256 or ecdsa P-256/384 + SHA-256/384; digest must be sha256+. rsa-sha1, dsa-sha1, hmac-*, md5 and
//    minimal/inclusive canonicalisation are banned. Transforms are whitelisted to enveloped-signature +
//    exc-c14n# only.
//  - KeyInfo in the document is IGNORED entirely - there is no "try the embedded certificate" fallback - so a
//    forged cert in the message cannot select the verifying key. The key is the one the caller pinned.
//  - The c14n void-canon defence (a non-empty element must not canonicalise to "") is asserted on every
//    digest input.
//  - The DigestValue/SignatureValue comparison is constant-time.
//
// Node 25 strip-types + Workers compatible: Web Crypto + the shared byte helpers only, no DOM, no Node
// builtins, no enums, explicit fields, error-as-value (never throws out of verifyXmlSignature).

import { ab, constantTimeEqual } from "../../crypto/bytes.ts";
// G316: the attack-shape ledger. dsig is where the two WRAPPING shapes that need a signature to be interesting
// are refused -- a duplicate ID the Reference resolves to twice, and a second ds:Signature -- and both used to
// coarsen into the same `signature` counter as an ordinary cert rotation.
import { noteSamlSignal } from "../saml-signals.ts";
import type { C14nOptions } from "./c14n.ts";
import { canonicalize, envelopedCopy } from "./c14n.ts";
import { decodeXmlText } from "./canonical-text.ts";
import type { SigSpec } from "./dsig-helpers.ts";
// The non-orchestration helpers (the DigestValue/SignatureValue base64 decoder, the small tree accessors, the
// InclusiveNamespaces PrefixList reader, the inherited-namespace-context walk, the signature/digest allowlist
// resolvers, and the pinned-key import + verify primitives) live in dsig-helpers.ts (a sibling split out so
// each module stays under 500 lines). They are internal to the verifier; the public surface (verifyXmlSignature
// + its option/result types) stays here, so nothing from the helpers is re-exported.
import {
  algAttr,
  attrValue,
  buildInheritedContext,
  childrenByLocalName,
  decodeBase64Std,
  digestHashName,
  importPinnedKey,
  onlyChild,
  parseInclusiveNamespacePrefixes,
  signatureSpec,
  textContent,
  verifyWithKey,
} from "./dsig-helpers.ts";
import type { XmlElement } from "./xml-node.ts";
import { findElements, localName } from "./xml-node.ts";

// algorithm allowlists (string-exact URIs; anything not listed is rejected)

// C14N_EXC is the exclusive-c14n algorithm URI AND (per the spec) the namespace the ec: prefix of an
// <ec:InclusiveNamespaces PrefixList="..."/> Transform child is bound to. We match that element by LOCAL name
// (prefix-agnostic, like everything else here); the PrefixList tokens are the only thing that affect the
// canonical bytes, so a renamed prefix gains nothing.
const C14N_EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
const C14N_EXC_WC = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
const TRANSFORM_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

// The XML-DSig namespace; we match elements by LOCAL name within this namespace conceptually, but because the
// tree is parser-agnostic and may carry any prefix (ds:, dsig:, none) we match by local name and rely on the
// structural single-Signature / single-Reference constraints plus the signature itself for soundness. The
// local-name match is intentional: an attacker cannot gain anything by RENAMING the prefix, and requiring a
// specific prefix would be brittle across IdPs.

export interface VerifyXmlSignatureOptions {
  // The SAML ID attribute name carrying the referenceable identifier. SAML 2.0 assertions/responses use the
  // unqualified attribute "ID"; this is overridable only for tests/other dialects. The Reference URI "#x"
  // resolves to the UNIQUE element whose this-named attribute equals "x".
  idAttribute?: string;
  // When true, ALSO require that the resolved Reference element is the `target` itself (the signature must
  // cover the very element handed in, not merely some element in its subtree). SAML SP profiles generally
  // want this for the top-level signed object; default false so a Response carrying a signed Assertion (where
  // the caller hands in the Assertion) still verifies. The caller chooses based on what it handed in.
  requireReferenceIsTarget?: boolean;
  // The validity window (epoch ms) of the PINNED signing certificate this call is verifying under, used to
  // REJECT a signature made under a cert that is outside its notBefore..notAfter window (IDP-4: a freshness
  // check layered on top of the signature). It is checked ONLY AFTER the signature itself verifies, so the
  // window never short-circuits the crypto gate and an out-of-window reason is only ever reached for an
  // otherwise-valid signature. ABSENT (undefined) means "do not enforce a window" - the caller could not
  // read the cert's window, and an unreadable window must not turn a valid signature into a reject. The
  // window is widened by `clockSkewMs` on BOTH ends for IdP/SP clock drift.
  signingCertValidity?: { notBefore: number; notAfter: number };
  // The injected clock as epoch milliseconds, used ONLY for the signingCertValidity window check. Tests pass
  // a fixed value. When signingCertValidity is set, nowMs MUST be supplied; if it is absent the window is not
  // enforced (fail-open on the window, never on the signature).
  nowMs?: number;
  // The clock-skew tolerance (ms) applied to BOTH ends of the signingCertValidity window. Defaults to 0.
  clockSkewMs?: number;
}

export interface VerifyOk {
  ok: true;
  // The signature-verified element: the element the (single) Reference resolved to, whose canonical digest
  // matched and whose SignedInfo signature verified under the pinned key. The caller reads claims from THIS.
  verified: XmlElement;
}
export interface VerifyFail {
  ok: false;
  reason: string;
}
export type VerifyResult = VerifyOk | VerifyFail;

function fail(reason: string): VerifyFail {
  return { ok: false, reason };
}

// the verifier

export async function verifyXmlSignature(
  target: XmlElement,
  pinnedCertSpki: Uint8Array | CryptoKey,
  opts?: VerifyXmlSignatureOptions,
): Promise<VerifyResult> {
  if (target === null || target === undefined || target.type !== "element") return fail("target is not an element");
  const idAttr = opts?.idAttribute ?? "ID";

  // 1. EXACTLY ONE ds:Signature anywhere in the target subtree. (We search the whole subtree, not just direct
  //    children, because a Response signs an enveloped Signature that sits as a child of the signed element;
  //    but the COUNT must be one - a second Signature is an immediate reject, closing the
  //    multiple-signature confusion vector.) We match by local name "Signature".
  const signatures = findElements(target, (e) => localName(e.name) === "Signature");
  if (signatures.length === 0) return fail("no ds:Signature found");
  if (signatures.length > 1) {
    noteSamlSignal("saml-shape-xsw-multi-signature");
    return fail("more than one ds:Signature (rejected: multi-signature confusion)");
  }
  const signature = signatures[0]!;

  // 2. SignedInfo: exactly one, with exactly one Reference.
  const signedInfo = onlyChild(signature, "SignedInfo");
  if (signedInfo === null) return fail("Signature must have exactly one SignedInfo");
  const references = childrenByLocalName(signedInfo, "Reference");
  if (references.length > 1) {
    // More than one Reference in a single SignedInfo is the other half of the multi-signature confusion vector.
    noteSamlSignal("saml-shape-xsw-multi-signature");
    return fail("SignedInfo must have exactly one Reference");
  }
  if (references.length !== 1) return fail("SignedInfo must have exactly one Reference");
  const reference = references[0]!;

  // 3. ALGORITHM ALLOWLIST (before any crypto): c14n + signature + digest methods.
  const algs = resolveAlgorithms(signedInfo, reference);
  if (!algs.ok) return algs;
  const { spec, hashName, signedInfoWithComments } = algs;

  // 3d. TRANSFORMS whitelist: enveloped-signature + exc-c14n# only (both required).
  const transforms = walkTransforms(reference);
  if (!transforms.ok) return transforms;
  const { referenceWithComments, referenceInclusivePrefixes } = transforms;

  // 4. RESOLVE the Reference URI by a HAND-ROLLED unique-ID walk. The URI MUST be a same-document fragment
  //    "#id"; a bare "" (whole document) or an external URI is rejected (we only verify same-document
  //    fragment references for SAML). The id is matched against the SAML ID attribute, and EXACTLY ONE
  //    element in the whole target subtree must carry that id value - 0 (dangling) or >1 (duplicate-ID XSW)
  //    both reject.
  const uriRaw = attrValue(reference, "URI");
  if (uriRaw === null) return fail("Reference has no URI (only same-document #id references are accepted)");
  const uri = decodeXmlText(uriRaw);
  if (!uri.startsWith("#") || uri.length < 2) return fail(`Reference URI must be a same-document fragment #id - got: ${uri}`);
  const wantId = uri.slice(1);
  const idMatches = findElements(target, (e) => {
    const v = attrValue(e, idAttr);
    return v !== null && decodeXmlText(v) === wantId;
  });
  if (idMatches.length === 0) return fail(`Reference URI #${wantId} resolves to no element`);
  if (idMatches.length > 1) {
    // The duplicate-ID wrapping vector: two elements answer to the same ID, so the digest can be taken over one
    // while the consumer reads the other. Recorded at the site; the refusal is unchanged.
    noteSamlSignal("saml-shape-xsw-duplicate-id");
    return fail(`Reference URI #${wantId} resolves to MORE THAN ONE element (duplicate-ID wrapping)`);
  }
  const referenced = idMatches[0]!;

  if (opts?.requireReferenceIsTarget === true && referenced !== target) {
    return fail("the Reference does not cover the target element");
  }

  // 5. PER-REFERENCE DIGEST: transform, canonicalise, hash and constant-time compare to the DigestValue.
  const digestResult = await verifyReferenceDigest(target, referenced, signature, reference, hashName, referenceWithComments, referenceInclusivePrefixes);
  if (!digestResult.ok) return digestResult;

  // 6. SIGNEDINFO SIGNATURE. Canonicalise SignedInfo with its declared CanonicalizationMethod, in the
  //    namespace context of its ancestors (so a ds: prefix declared on the enclosing Signature/Response is in
  //    scope), then verify crypto.subtle.verify over the canonical bytes with the PINNED key. KeyInfo in the
  //    document is never consulted.
  const signedInfoInherited = buildInheritedContext(target, signedInfo);
  const siCanon = canonicalize(signedInfo, { withComments: signedInfoWithComments, inheritedContext: signedInfoInherited });
  if (!siCanon.ok) return fail(`SignedInfo canonicalisation failed: ${siCanon.reason}`);
  const siBytes = new TextEncoder().encode(siCanon.canonical);

  const sigValueEl = onlyChild(signature, "SignatureValue");
  if (sigValueEl === null) return fail("Signature must have exactly one SignatureValue");
  const sv = decodeBase64Std(textContent(sigValueEl));
  if (!sv.ok) return fail("SignatureValue is not valid base64");

  let key: CryptoKey;
  try {
    key = await importPinnedKey(pinnedCertSpki, spec);
  } catch {
    return fail("pinned certificate/key could not be imported");
  }
  let sigOk = false;
  try {
    sigOk = await verifyWithKey(key, spec, sv.bytes, siBytes);
  } catch {
    return fail("signature verification error");
  }
  if (!sigOk) return fail("SignedInfo signature does not verify under the pinned key");

  // 7. SIGNING-CERT VALIDITY WINDOW (IDP-4). Only reached for an otherwise-VALID signature (so the window
  //    check never leaks before the crypto gate). When the caller supplied the pinned cert's window AND a
  //    clock, reject a signature made under a cert outside [notBefore - skew, notAfter + skew]. An absent
  //    window or clock means "not enforced" (fail-open on the window only: an unreadable cert window must
  //    never turn a cryptographically-valid signature into a reject). This is a defence-in-depth freshness
  //    check; the SAML assertion's own Conditions/SCD NotOnOrAfter remain the primary time bounds.
  const certValidity = opts?.signingCertValidity;
  if (certValidity !== undefined && typeof opts?.nowMs === "number") {
    const skew = typeof opts?.clockSkewMs === "number" && opts.clockSkewMs > 0 ? opts.clockSkewMs : 0;
    const now = opts.nowMs;
    if (now < certValidity.notBefore - skew) {
      return fail("the IdP signing certificate is not yet valid (outside its validity window)");
    }
    if (now > certValidity.notAfter + skew) {
      return fail("the IdP signing certificate has expired (outside its validity window)");
    }
  }

  // Both the Reference digest and the SignedInfo signature verified under the pinned key, and (when supplied)
  // the signing cert is within its validity window. The referenced element is authentic.
  return { ok: true, verified: referenced };
}

// resolveAlgorithms enforces the algorithm allowlist BEFORE any crypto (phases 3a-3c): the SignedInfo
// CanonicalizationMethod (exclusive c14n#, with/without comments), the SignatureMethod (rsa-sha256 or
// ecdsa P-256/384) and the Reference DigestMethod (sha256+). It returns the resolved SigSpec, the Web Crypto
// hash name and whether SignedInfo c14n keeps comments, or a typed rejection. Pure; extracted verbatim.
function resolveAlgorithms(
  signedInfo: XmlElement,
  reference: XmlElement,
): { ok: true; spec: SigSpec; hashName: string; signedInfoWithComments: boolean } | VerifyFail {
  // 3a. CanonicalizationMethod for SignedInfo.
  const cm = onlyChild(signedInfo, "CanonicalizationMethod");
  if (cm === null) return fail("SignedInfo must have exactly one CanonicalizationMethod");
  const cmAlg = algAttr(cm);
  if (cmAlg !== C14N_EXC && cmAlg !== C14N_EXC_WC) {
    return fail(`CanonicalizationMethod must be exclusive c14n (#) - got: ${String(cmAlg)}`);
  }
  const signedInfoWithComments = cmAlg === C14N_EXC_WC;

  // 3b. SignatureMethod.
  const sm = onlyChild(signedInfo, "SignatureMethod");
  if (sm === null) return fail("SignedInfo must have exactly one SignatureMethod");
  const smAlg = algAttr(sm);
  const spec = smAlg === null ? null : signatureSpec(smAlg);
  if (spec === null) return fail(`SignatureMethod not on the allowlist (need rsa-sha256 or ecdsa-sha2-256/384) - got: ${String(smAlg)}`);

  // 3c. DigestMethod (sha256+).
  const dm = onlyChild(reference, "DigestMethod");
  if (dm === null) return fail("Reference must have exactly one DigestMethod");
  const dmAlg = algAttr(dm);
  const hashName = dmAlg === null ? null : digestHashName(dmAlg);
  if (hashName === null) return fail(`DigestMethod not on the allowlist (need sha256 or stronger) - got: ${String(dmAlg)}`);

  return { ok: true, spec, hashName, signedInfoWithComments };
}

// walkTransforms enforces the Reference Transforms whitelist (phase 3d): enveloped-signature + exc-c14n#
// only, and BOTH must be listed (their absence is always a malformed/forged signature for our enveloped SAML
// profile). It captures whether the c14n keeps comments and the InclusiveNamespaces PrefixList (IDP-2) the
// digest must force-render. Any URI off the whitelist is an immediate reject. Pure; extracted verbatim.
function walkTransforms(
  reference: XmlElement,
): { ok: true; referenceWithComments: boolean; referenceInclusivePrefixes: string[] } | VerifyFail {
  const transformsEl = onlyChild(reference, "Transforms");
  let sawEnveloped = false;
  let sawExcC14n = false;
  let referenceWithComments = false;
  // The InclusiveNamespaces PrefixList carried on the exc-c14n# Transform (IDP-2). Captured from the c14n
  // Transform element; passed to the Reference digest so the listed ancestor-declared prefixes are rendered
  // on the canonical apex (the standard exclusive-c14n-with-InclusiveNamespaces behaviour ADFS/Shibboleth use).
  let referenceInclusivePrefixes: string[] = [];
  if (transformsEl !== null) {
    const transforms = childrenByLocalName(transformsEl, "Transform");
    for (const t of transforms) {
      const tAlg = algAttr(t);
      if (tAlg === TRANSFORM_ENVELOPED) {
        sawEnveloped = true;
      } else if (tAlg === C14N_EXC) {
        sawExcC14n = true;
        referenceInclusivePrefixes = parseInclusiveNamespacePrefixes(t);
      } else if (tAlg === C14N_EXC_WC) {
        sawExcC14n = true;
        referenceWithComments = true;
        referenceInclusivePrefixes = parseInclusiveNamespacePrefixes(t);
      } else {
        return fail(`Reference Transform not on the whitelist (only enveloped-signature + exc-c14n#) - got: ${String(tAlg)}`);
      }
    }
  }
  if (!sawEnveloped) return fail("Reference must declare the enveloped-signature transform");
  if (!sawExcC14n) return fail("Reference must declare the exclusive-c14n transform");
  return { ok: true, referenceWithComments, referenceInclusivePrefixes };
}

// verifyReferenceDigest applies the Reference transforms in order (enveloped-signature REMOVES the single
// Signature subtree from the referenced element's copy, then exc-c14n# canonicalises in the inherited
// namespace context of its ancestors), hashes the canonical UTF-8 bytes and constant-time-compares to the
// decoded DigestValue. The void-canon defence lives inside canonicalize(). Returns ok or a typed rejection.
async function verifyReferenceDigest(
  target: XmlElement,
  referenced: XmlElement,
  signature: XmlElement,
  reference: XmlElement,
  hashName: string,
  referenceWithComments: boolean,
  referenceInclusivePrefixes: string[],
): Promise<{ ok: true } | VerifyFail> {
  const referencedInherited = buildInheritedContext(target, referenced);
  const enveloped = envelopedCopy(referenced, signature);
  const digestOpts: C14nOptions = {
    withComments: referenceWithComments,
    inheritedContext: referencedInherited,
    // The InclusiveNamespaces PrefixList (IDP-2): force-render the listed in-scope ancestor prefixes on the
    // canonical apex. Empty for a plain exc-c14n# Reference (pure exclusive behaviour, unchanged).
    inclusiveNamespacePrefixes: referenceInclusivePrefixes,
  };
  const refCanon = canonicalize(enveloped, digestOpts);
  if (!refCanon.ok) return fail(`Reference canonicalisation failed: ${refCanon.reason}`);
  const refBytes = new TextEncoder().encode(refCanon.canonical);
  let computedDigest: Uint8Array;
  try {
    computedDigest = new Uint8Array(await crypto.subtle.digest(hashName, ab(refBytes)));
  } catch {
    return fail("digest computation failed");
  }

  const digestValueEl = onlyChild(reference, "DigestValue");
  if (digestValueEl === null) return fail("Reference must have exactly one DigestValue");
  const dv = decodeBase64Std(textContent(digestValueEl));
  if (!dv.ok) return fail("DigestValue is not valid base64");
  if (!constantTimeEqual(computedDigest, dv.bytes)) return fail("Reference digest mismatch (the signed element was altered)");
  return { ok: true };
}
