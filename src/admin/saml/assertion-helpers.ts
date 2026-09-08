// The tree, namespace and time helpers for the SAML assertion consumer, split out of assertion.ts so each
// module stays a coherent unit under 500 lines. This holds the parser-agnostic XmlElement accessors (attr /
// decAttr / decodedText / trimmedDecodedText), the namespace resolution (ownXmlnsBindings / resolveNamespace
// / mergeInherited) and the namespace-gated child matches (findChildInSamlNs / findChildrenInSamlNs /
// findChildInNs) the consumer uses, plus the XSD dateTime parser. The consumer logic (consumeAssertion,
// assertStatusSuccess, the attribute collection) stays in assertion.ts and imports these.
//
// THE "verify == read" LINCHPIN still holds here: every text/attribute value is read through decodeXmlText
// (the shared canonical-text decoder), NEVER raw .value, so "what the IdP signed" never diverges from "what
// the SP authorises on".
//
// Node 25 strip-types + Workers compatible: pure functions, no DOM, no Node builtins, no enums, explicit
// fields, error-as-value. Australian English; no em dashes.

import { decodeXmlText } from "./canonical-text.ts";
import type { XmlElement } from "./xml-node.ts";
import { isElement, localName } from "./xml-node.ts";

// The SAML assertion namespace, matched by the namespace-gated helpers below AND by the consumer's root-node
// assertion. Kept here with the helpers that gate on it; assertion.ts imports it back for its own root check.
export const SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

// ---- tree helpers over the parser-agnostic XmlElement ----
// We match by LOCAL name and (where it matters) the SAML assertion namespace URI, never by a hard-coded
// prefix: an IdP may emit saml:, saml2:, or a default namespace, and an attacker gains nothing by renaming a
// prefix. namespaceUriOf resolves the effective namespace of an element by walking its own and (via the
// caller-passed ancestry) inherited xmlns declarations; because we always search DOWN from a known-namespace
// root and assert the root's namespace, a child matched by local name within that subtree is in-namespace by
// construction for the elements we care about. To stay robust without a full namespace resolver, the helpers
// below additionally accept an element only when its own-or-inherited default/prefix binding for its prefix
// resolves to the SAML assertion namespace OR the element declares no conflicting binding - in practice we
// gate the few security-load-bearing matches (Assertion, Conditions, Subject) on the namespace and match the
// rest by local name within those already-namespace-gated subtrees.

// attr returns the RAW (entity-encoded) value of the attribute named exactly `name`, or null. Callers that
// read it as TEXT must route it through decodeXmlText (see decAttr); callers comparing a URI/format token also
// decode defensively (a hostile document could entity-encode a URI to dodge a naive compare).
function attr(el: XmlElement, name: string): string | null {
  for (const a of el.attrs) {
    if (a.name === name) return a.value;
  }
  return null;
}

// decAttr reads an attribute and decodes it through the SHARED entity decoder, so the value the SP compares
// is the value the IdP signed (the verify == read linchpin). Returns null when the attribute is absent.
export function decAttr(el: XmlElement, name: string): string | null {
  const raw = attr(el, name);
  return raw === null ? null : decodeXmlText(raw);
}

// decodedText concatenates the DECODED text of all DIRECT text children of `el` (an element's value, e.g. an
// Audience URI or a NameID, is its text content). Element children are ignored. The decode is the shared one,
// so the text matches the signed bytes. Leading/trailing/whitespace is preserved verbatim (SAML values are
// compared exactly; the IdP and SP must agree on the exact string, and trimming could mask a mismatch) -
// EXCEPT we do trim the outer whitespace some serialisers add around a value, see trimmedDecodedText.
function decodedText(el: XmlElement): string {
  let s = "";
  for (const c of el.children) {
    if (c.type === "text") s += decodeXmlText(c.value);
  }
  return s;
}

// trimmedDecodedText is decodedText with surrounding ASCII whitespace stripped. SAML string values (an
// Audience, a NameID, an attribute value) are routinely pretty-printed with surrounding newlines/indentation
// by IdP toolchains, and the SAML spec treats element content whitespace around such values as insignificant
// for these comparisons; trimming the OUTER whitespace makes the exact-compare robust to formatting without
// altering the inner value. Internal whitespace is preserved.
export function trimmedDecodedText(el: XmlElement): string {
  return decodedText(el).trim();
}

// ---- namespace gating for the load-bearing elements ----
// inScopeNamespaceForPrefix resolves the namespace URI bound to `prefix` ("" for the default ns) using the
// xmlns declarations on `el` itself, falling back to the inherited bindings the caller accumulated from the
// ancestors. We pass the inherited map down as we descend from the verified Assertion so a Conditions/Subject
// that does not re-declare the namespace is still resolved against the Assertion's binding.
export function ownXmlnsBindings(el: XmlElement): Map<string, string> {
  const m = new Map<string, string>();
  for (const a of el.attrs) {
    if (a.name === "xmlns") m.set("", decodeXmlText(a.value));
    else if (a.name.startsWith("xmlns:")) m.set(a.name.slice("xmlns:".length), decodeXmlText(a.value));
  }
  return m;
}

// resolveNamespace returns the effective namespace URI of `el` given the bindings inherited from its
// ancestors (inherited), applying el's own declarations first (nearer wins). Returns null when the prefix is
// unbound (no default ns and no matching xmlns:prefix in scope).
export function resolveNamespace(el: XmlElement, inherited: Map<string, string>): string | null {
  const prefix = (() => {
    const i = el.name.indexOf(":");
    return i === -1 ? "" : el.name.slice(0, i);
  })();
  const own = ownXmlnsBindings(el);
  if (own.has(prefix)) return own.get(prefix)!;
  if (inherited.has(prefix)) return inherited.get(prefix)!;
  // No binding in scope for this prefix (or no default-ns declaration for an unprefixed name): in NO namespace.
  return null;
}

// mergeInherited returns a new map = inherited overlaid with el's own xmlns declarations (for descent).
export function mergeInherited(el: XmlElement, inherited: Map<string, string>): Map<string, string> {
  const next = new Map(inherited);
  for (const [k, v] of ownXmlnsBindings(el)) next.set(k, v);
  return next;
}

// findChildInSamlNs returns the first direct child of `el` with local name `local` that resolves to the SAML
// assertion namespace, given the namespace bindings in scope at `el` (inheritedAtParent merged with el's own).
// This is the namespace-gated match used for the structurally load-bearing elements (Conditions, Subject,
// AudienceRestriction, Audience, SubjectConfirmation, NameID...), so a same-local-name element injected in a
// DIFFERENT namespace cannot be mistaken for the SAML one.
export function findChildInSamlNs(el: XmlElement, local: string, inScope: Map<string, string>): XmlElement | null {
  for (const c of el.children) {
    if (!isElement(c)) continue;
    if (localName(c.name) !== local) continue;
    if (resolveNamespace(c, inScope) === SAML_ASSERTION_NS) return c;
  }
  return null;
}

// findChildrenInSamlNs is the multi-match form of findChildInSamlNs.
export function findChildrenInSamlNs(el: XmlElement, local: string, inScope: Map<string, string>): XmlElement[] {
  const out: XmlElement[] = [];
  for (const c of el.children) {
    if (!isElement(c)) continue;
    if (localName(c.name) !== local) continue;
    if (resolveNamespace(c, inScope) === SAML_ASSERTION_NS) out.push(c);
  }
  return out;
}

// findChildInNs is findChildInSamlNs generalised to an arbitrary namespace, used for the samlp: PROTOCOL
// elements (Status, StatusCode) so the Status-success check is namespace-gated exactly like every assertion
// element - a foreign-namespace or no-namespace decoy <Status> cannot mask a real samlp:Status failure.
export function findChildInNs(el: XmlElement, local: string, ns: string, inScope: Map<string, string>): XmlElement | null {
  for (const c of el.children) {
    if (!isElement(c)) continue;
    if (localName(c.name) !== local) continue;
    if (resolveNamespace(c, inScope) === ns) return c;
  }
  return null;
}

// ---- ISO 8601 / XSD dateTime parsing ----
// SAML uses XSD dateTime (e.g., optionally with fractional seconds and/or a timezone
// offset). We decode the value, then Date.parse the explicit string. Date.parse on an EXPLICIT string is
// permitted (it is deterministic for a given string); new Date()/Date.now() are NOT (they read the wall
// clock). A value Date.parse cannot understand yields NaN, which we treat as a hard parse failure (fail
// closed): a malformed time bound must never be read as "no bound" or as a far-future time.
export function parseSamlInstantMs(decoded: string | null): number | null {
  if (decoded === null) return null;
  const t = decoded.trim();
  if (t.length === 0) return null;
  const ms = Date.parse(t);
  return Number.isFinite(ms) ? ms : null;
}
