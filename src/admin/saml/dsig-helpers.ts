// The non-orchestration helpers of the XML-DSig verifier, split out of dsig.ts so each module stays a coherent
// unit under 500 lines. This holds: the standard-base64 decoder for DigestValue / SignatureValue; the small
// tree accessors over the parser-agnostic XmlElement (childrenByLocalName / onlyChild / attrValue / algAttr /
// textContent); the InclusiveNamespaces PrefixList reader (IDP-2); the inherited-namespace-context walk; the
// signature-method and digest-method allowlist resolvers; and the pinned-key import + Web Crypto verify
// primitives. The orchestration (verifyXmlSignature, which ties the single-Signature / single-Reference /
// unique-ID structural constraints together with these) stays in dsig.ts and imports these.
//
// Node 25 strip-types + Workers compatible: Web Crypto + the shared byte helpers only, no DOM, no Node
// builtins, no enums, explicit fields, error-as-value.

import { ab } from "../../crypto/bytes.ts";
import { decodeXmlText } from "./canonical-text.ts";
import type { XmlElement } from "./xml-node.ts";
import { isNamespaceDecl, localName, nsDeclPrefix } from "./xml-node.ts";

// algorithm allowlists (string-exact URIs; anything not listed is rejected)

// Signature methods: RSASSA-PKCS1-v1_5 + SHA-256, and ECDSA over P-256/P-384 with SHA-256/384. rsa-sha1,
// dsa-*, hmac-*, rsa-md5 and the SHA-1 ECDSA variants are deliberately ABSENT.
const SIG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SIG_ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
const SIG_ECDSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";

// Digest methods: SHA-256 and stronger (SHA-384, SHA-512). SHA-1 and MD5 digests are ABSENT.
const DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const DIGEST_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
const DIGEST_SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";

// standard base64 (NOT base64url) decode for DigestValue / SignatureValue
// XML-DSig encodes binary with RFC 2045 / standard base64 (alphabet + and /, with = padding). The shared
// bytes.ts decoder is base64url (- and _, no padding), so we decode standard base64 here. We are STRICT:
// after stripping XML whitespace (which is legal inside the base64 element content and must be ignored), only
// the standard alphabet + correct padding is accepted; anything else fails closed. atob is available in the
// Workers runtime and Node 25.
const B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function decodeBase64Std(raw: string): { ok: true; bytes: Uint8Array } | { ok: false } {
  // Strip the whitespace XML permits inside base64 content (space, tab, CR, LF). Everything else must be in
  // the alphabet or be padding.
  let s = "";
  for (const ch of raw) {
    if (ch === " " || ch === "\t" || ch === "\r" || ch === "\n") continue;
    s += ch;
  }
  if (s.length === 0) return { ok: false };
  if (s.length % 4 !== 0) return { ok: false }; // standard base64 is always a multiple of 4 with padding
  // Validate alphabet + padding placement: '=' only at the end, at most two.
  const body = s.replace(/=+$/, "");
  const pad = s.length - body.length;
  if (pad > 2) return { ok: false };
  // Decode via the index table (avoid atob's lax acceptance of some malformed inputs across runtimes). The
  // table doubles as the alphabet check: any character outside the alphabet maps to -1 and fails closed in the
  // single pass below, so a separate O(n * 64) validation scan is not needed.
  const lut = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64_STD.length; i++) lut[B64_STD.charCodeAt(i)] = i;
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const ch of body) {
    const v = lut[ch.charCodeAt(0)] ?? -1;
    if (v < 0) return { ok: false };
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  // Non-canonical trailing bits (bits that pad the last partial group) must be zero, matching a strict decoder.
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) return { ok: false };
  return { ok: true, bytes: new Uint8Array(out) };
}

// small tree accessors over the parser-agnostic XmlElement

// childrenByLocalName returns the direct element children of `el` whose local name equals `local`.
export function childrenByLocalName(el: XmlElement, local: string): XmlElement[] {
  const out: XmlElement[] = [];
  for (const c of el.children) {
    if (c.type === "element" && localName(c.name) === local) out.push(c);
  }
  return out;
}

// onlyChild returns the single direct child element with the given local name, or null when the count is not
// exactly one (0 or >1). Used for the "exactly one" structural constraints whose violation is an XSW vector.
export function onlyChild(el: XmlElement, local: string): XmlElement | null {
  const m = childrenByLocalName(el, local);
  return m.length === 1 ? m[0]! : null;
}

// attrValue returns the RAW value of `el`'s attribute named exactly `name`, or null. (For algorithm-URI
// attributes the value is taken verbatim - URIs do not carry XML entities in practice - but we decode where a
// value is semantically text, e.g. DigestValue base64 has whitespace stripped by the base64 decoder anyway.)
export function attrValue(el: XmlElement, name: string): string | null {
  for (const a of el.attrs) {
    if (a.name === name) return a.value;
  }
  return null;
}

// algAttr reads an Algorithm attribute and decodes XML entities defensively (a hostile document could write
// the URI with character references to dodge a naive string compare; decoding first makes the allowlist
// match the true URI). URIs themselves contain no entities, so on a benign document this is a no-op.
export function algAttr(el: XmlElement): string | null {
  const v = attrValue(el, "Algorithm");
  return v === null ? null : decodeXmlText(v);
}

// parseInclusiveNamespacePrefixes reads the InclusiveNamespaces PrefixList from an exc-c14n# Transform (IDP-2).
// A Transform may carry a child <ec:InclusiveNamespaces PrefixList="a b #default"/> (ec: bound to the
// exc-c14n# namespace) that lists the namespace prefixes whose ancestor-declared bindings must be rendered on
// the canonical apex even though exclusive c14n would otherwise drop them as not-visibly-utilised - the
// standard escape hatch ADFS / Shibboleth (and some Entra configs) use, notably for xsi:type AttributeValues
// whose prefix lives in an attribute VALUE (which exc-c14n# does NOT count as visibly utilised). We look for
// the (at most one) direct child whose LOCAL name is "InclusiveNamespaces" in the exc-c14n# namespace, read
// its decoded PrefixList, and split on XML whitespace into the token list the c14n engine already consumes
// (the token "#default" denotes the default namespace, handled by c14n.ts). An absent element or empty list
// yields [] (pure exclusive behaviour). We do NOT fabricate prefixes - only the genuinely-listed ones are
// force-rendered, and only their ANCESTOR-IN-SCOPE binding is rendered (an unbound listed prefix renders
// nothing, per c14n.ts), so this cannot be used to inject a namespace the document did not declare.
//
// SECURITY: this only ever ADDS in-scope ancestor namespace declarations to the apex of the canonical form.
// It cannot relocate, drop, or alter any element or claim. The Reference still resolves to exactly one
// element (the unique-ID walk), the enveloped Signature is still excised by identity, and the digest is still
// taken over that one element's canonical bytes - the only change is which (already-in-scope) xmlns
// declarations appear on its apex, which is precisely what makes a genuine ADFS/Shibboleth digest match.
export function parseInclusiveNamespacePrefixes(transform: XmlElement): string[] {
  // Match the (first) InclusiveNamespaces child by LOCAL name, prefix-agnostic. A namespace gate is NOT needed
  // for soundness here: a PrefixList only ever ADDS in-scope ANCESTOR namespace declarations to the canonical
  // apex (an unbound listed prefix renders nothing, per c14n.ts), so even a mis-namespaced lookalike element
  // cannot smuggle bytes or move/alter any claim - it can at most force-render a declaration the document
  // already had in scope, which the genuine signer's digest either accounted for (then it matches) or did not
  // (then it mismatches and rejects). The signature over the resolved element governs in every case.
  let incl: XmlElement | null = null;
  for (const c of transform.children) {
    if (c.type === "element" && localName(c.name) === "InclusiveNamespaces") {
      incl = c;
      break;
    }
  }
  if (incl === null) return [];
  const raw = attrValue(incl, "PrefixList");
  if (raw === null) return [];
  const decoded = decodeXmlText(raw);
  const out: string[] = [];
  // Split on the four XML whitespace characters (space, tab, CR, LF), the PrefixList token separator.
  for (const tok of decoded.split(/[ \t\r\n]+/)) {
    if (tok.length > 0 && !out.includes(tok)) out.push(tok);
  }
  return out;
}

// textContent concatenates the DECODED text of all direct text children of `el` (DigestValue / SignatureValue
// carry their base64 as text; some serialisers split it or surround it with whitespace). Element children are
// ignored (these leaf elements should have none; if one does, the base64 decode of the surrounding text still
// governs and an injected child cannot contribute bytes).
export function textContent(el: XmlElement): string {
  let s = "";
  for (const c of el.children) {
    if (c.type === "text") s += decodeXmlText(c.value);
  }
  return s;
}

// buildInheritedContext walks from the document `target` down to `el` (exclusive of `el`) collecting the
// in-scope namespace bindings declared on the ANCESTORS of `el`, so SignedInfo can be canonicalised in the
// namespace context its ds:Signature / Response ancestors establish (the DSig requirement that SignedInfo is
// canonicalised "in the context in which it appears"). Returns a prefix->URI map ("" = default ns). If `el`
// is not found under `target`, returns an empty map (the apex is then treated as having no inherited context,
// which for a self-contained SignedInfo that declares its own ds: prefix is still correct).
export function buildInheritedContext(target: XmlElement, el: XmlElement): Map<string, string> {
  const ctx = new Map<string, string>();
  // Find the ancestor chain target -> ... -> parent(el). We search recursively, accumulating declarations.
  const path: XmlElement[] = [];
  const found = (function search(node: XmlElement): boolean {
    if (node === el) return true;
    for (const c of node.children) {
      if (c.type === "element") {
        path.push(node);
        if (search(c)) return true;
        path.pop();
      }
    }
    return false;
  })(target);
  if (!found) return ctx;
  // path now holds target ... parent(el) in order; apply their xmlns declarations so nearer ancestors win.
  for (const anc of path) {
    for (const a of anc.attrs) {
      if (isNamespaceDecl(a)) ctx.set(nsDeclPrefix(a), decodeXmlText(a.value));
    }
  }
  return ctx;
}

// the digest algorithm + its hash name

export function digestHashName(uri: string): "SHA-256" | "SHA-384" | "SHA-512" | null {
  if (uri === DIGEST_SHA256) return "SHA-256";
  if (uri === DIGEST_SHA384) return "SHA-384";
  if (uri === DIGEST_SHA512) return "SHA-512";
  return null;
}

// signatureSpec maps an allowlisted SignatureMethod URI to the Web Crypto verify parameters and the SPKI
// import algorithm. RSA is RSASSA-PKCS1-v1_5 with SHA-256; ECDSA is the named curve + matching SHA. The curve
// for an ECDSA method is NOT taken from the document; it is fixed by the method URI (sha256 -> we accept P-256
// or P-384 keys, verifying with the URI's hash), and the imported key's own curve governs - a mismatched key
// simply fails to verify. We pin the HASH from the URI and let the key's curve be whatever the pinned cert is.
export interface SigSpec {
  family: "RSA" | "EC";
  hash: "SHA-256" | "SHA-384";
}
export function signatureSpec(uri: string): SigSpec | null {
  if (uri === SIG_RSA_SHA256) return { family: "RSA", hash: "SHA-256" };
  if (uri === SIG_ECDSA_SHA256) return { family: "EC", hash: "SHA-256" };
  if (uri === SIG_ECDSA_SHA384) return { family: "EC", hash: "SHA-384" };
  return null;
}

// the pinned key import

// importPinnedKey accepts either an already-imported CryptoKey (the caller imported it) or raw X.509
// SubjectPublicKeyInfo (SPKI / DER) bytes, which we import via crypto.subtle.importKey('spki', ...). The
// import algorithm must MATCH the SignatureMethod family/hash, so we import lazily once the method is known.
// A CryptoKey is used as-is (the caller is trusted to have imported the right algorithm); we still verify with
// the method-derived parameters, and a key/method mismatch fails the verify rather than being silently
// coerced. importKey throws on malformed SPKI, which the caller maps to a clean reject.
export async function importPinnedKey(pinned: Uint8Array | CryptoKey, spec: SigSpec): Promise<CryptoKey> {
  if (pinned instanceof CryptoKey) return pinned;
  if (spec.family === "RSA") {
    return crypto.subtle.importKey("spki", ab(pinned), { name: "RSASSA-PKCS1-v1_5", hash: spec.hash }, false, ["verify"]);
  }
  // For EC the curve must be supplied to importKey. We try P-256 first then P-384; the correct one imports and
  // the other throws (SPKI carries the curve OID, so only the matching namedCurve succeeds). This lets one
  // ecdsa method URI work for both surveyed curve sizes without the caller pre-declaring the curve.
  try {
    return await crypto.subtle.importKey("spki", ab(pinned), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  } catch {
    return crypto.subtle.importKey("spki", ab(pinned), { name: "ECDSA", namedCurve: "P-384" }, false, ["verify"]);
  }
}

export async function verifyWithKey(key: CryptoKey, spec: SigSpec, signature: Uint8Array, signedBytes: Uint8Array): Promise<boolean> {
  if (spec.family === "RSA") {
    return crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, ab(signature), ab(signedBytes));
  }
  // ECDSA in XML-DSig is the raw fixed-width R||S concatenation (NOT DER), which is exactly what Web Crypto's
  // ECDSA verify consumes. A DER-wrapped signature therefore fails here, which is the correct rejection.
  return crypto.subtle.verify({ name: "ECDSA", hash: spec.hash }, key, ab(signature), ab(signedBytes));
}
