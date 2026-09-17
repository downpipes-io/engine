// The lexical layer of the hardened SAML XML parser, split out of parser.ts so each module stays a coherent
// unit under 500 lines. This holds the character predicates (the conservative XML 1.0 Name rules + the XML
// whitespace set), the input decoder + the two raw-byte gates that fire BEFORE tokenising (UTF-8 enforcement
// with a fatal decoder, the no-DOCTYPE / no-ENTITY substring scan), and the entity-reference validator that
// asserts every "&...;" is one of the five predefined entities or a numeric character reference. The
// tokeniser / tree builder (parseElement, parseXml) stays in parser.ts and imports these.
//
// A bug in this layer is a SILENT signature-bypass (the XSW / SAMLStorm / ruby-saml CVE class), so it
// FAILS CLOSED on anything ambiguous or malformed and PRESERVES attribute/text values RAW (still
// entity-encoded) for the single canonical-text decoder downstream.
//
// Node 25 strip-types + Workers compatible: pure functions, no DOM, no Node builtins, no enums, explicit
// fields, error-as-value. Australian English; no em dashes.

import type { XmlAttr } from "./xml-node.ts";

// character predicates (XML 1.0 name rules, kept conservative)
// We do NOT implement the full Unicode NameStartChar / NameChar production; we accept the ASCII letter / digit
// / "_" / "-" / "." / ":" set plus any code point >= 0x80 (so namespaced names with non-ASCII letters parse),
// and we forbid the structural metacharacters. This is conservative: it never ACCEPTS a structurally dangerous
// name, and any benign SAML element/attribute name (which are ASCII in practice) parses. A name must not be
// empty and must not start with a digit, "-" or ".".

export function isNameStartChar(cp: number): boolean {
  // ":" is permitted in a qualified name (prefix separator); "_" too. Letters A-Z a-z. Code points >= 0x80 are
  // allowed (covers Unicode letters used in some IdPs' attribute names without a full table).
  if (cp === 0x5f || cp === 0x3a) return true;
  if (cp >= 0x41 && cp <= 0x5a) return true; // A-Z
  if (cp >= 0x61 && cp <= 0x7a) return true; // a-z
  if (cp >= 0x80) return true;
  return false;
}

export function isNameChar(cp: number): boolean {
  if (isNameStartChar(cp)) return true;
  if (cp >= 0x30 && cp <= 0x39) return true; // 0-9
  if (cp === 0x2d || cp === 0x2e) return true;
  return false;
}

// isXmlWhitespace matches the four XML whitespace characters (space, tab, CR, LF). Used for tag-internal
// separators and for the leading/trailing whitespace permitted around the document element.
export function isXmlWhitespace(cp: number): boolean {
  return cp === 0x20 || cp === 0x09 || cp === 0x0d || cp === 0x0a;
}

// isDisallowedControlCodePoint flags the code points XML 1.0's Char production excludes below U+0020: every
// C0 control except the three whitespace ones (TAB/LF/CR, already legal via isXmlWhitespace above), plus DEL
// (0x7F). This is the WFC: Legal Character rule - a numeric character reference or a literal raw byte naming
// one of these is malformed XML, not just an unusual one, and must be rejected at the parse boundary rather
// than trusted to a downstream consumer's own character-class check.
export function isDisallowedControlCodePoint(cp: number): boolean {
  return (cp < 0x20 && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d) || cp === 0x7f;
}

// input decoding + the raw-byte gates

// decodeInput turns the input into a string, enforcing UTF-8. Given bytes, it decodes with a FATAL decoder so
// any non-UTF-8 byte sequence is rejected (a SAML POST is UTF-8; a UTF-16/UTF-32 or mojibake body is hostile
// or broken). A leading UTF-8 BOM (EF BB BF, which decodes to U+FEFF) is stripped. A string input is assumed
// already-decoded but we still strip a leading U+FEFF and reject a stray U+FFFD only if it was the decoder's
// replacement marker - for a string we cannot know that, so we accept it (a caller passing a string has
// already chosen its decoder; the bytes path is the security-relevant one for an HTTP body).
export function decodeInput(input: string | Uint8Array): { ok: true; text: string } | { ok: false; reason: string } {
  if (typeof input === "string") {
    // Strip a leading BOM if present (U+FEFF), so the XML declaration check sees "<?xml" at index 0.
    const text = input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
    return { ok: true, text };
  }
  // Bytes: strip a leading UTF-8 BOM (EF BB BF) so the fatal decode does not carry a U+FEFF into the body, then
  // decode with fatal:true so any invalid UTF-8 (including UTF-16/UTF-32 bodies, which are not valid UTF-8) is
  // rejected rather than silently producing replacement characters.
  let bytes = input;
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    bytes = bytes.subarray(3);
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return { ok: false, reason: "input is not valid UTF-8" };
  }
  // A BOM in the MIDDLE (or a leftover leading U+FEFF after a UTF-16-mislabelled body) - strip a single leading
  // U+FEFF the decoder may yield (some inputs carry it as data); anything else is handled by the tokeniser.
  const cleaned = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  return { ok: true, text: cleaned };
}

// scanForbiddenConstructs runs the cheap, decisive substring gates BEFORE tokenising: NO DOCTYPE and NO DTD/
// entity subset, ever. These kill entity-expansion (billion-laughs), XXE and external-DTD fetches at the door,
// before a single tag is parsed. The checks are case-SENSITIVE per the XML grammar ("<!DOCTYPE" and "<!ENTITY"
// are fixed keywords); a lowercase "<!doctype" is not a valid DTD declaration and would be rejected later as a
// malformed "<!" construct anyway. We scan the whole text (a DOCTYPE may, hostilely, be placed unusually).
export function scanForbiddenConstructs(text: string): { ok: true } | { ok: false; reason: string } {
  if (text.includes("<!DOCTYPE")) return { ok: false, reason: "DOCTYPE is rejected (no DTD, ever)" };
  if (text.includes("<!ENTITY")) return { ok: false, reason: "entity declaration is rejected (no DTD, ever)" };
  return { ok: true };
}

// the entity-reference validator (preserve raw, reject the dangerous ones)
// validateEntityRefs scans a RAW attribute or text value and asserts that every "&...;" it contains is one of
// the FIVE XML predefined entities or a numeric character reference (&#DDD; / &#xHH;). A general entity such as
// "&foo;" is REJECTED: there is no DTD to define it (we banned DTDs), so it is malformed, and silently passing
// it through would let an attacker stage an entity the c14n decoder leaves literal while some other consumer
// might expand it. A bare "&" that does not begin a well-formed reference is also rejected (a literal & must be
// written &amp; in XML). We do NOT decode here - the value is preserved RAW - we only VALIDATE the references.
export function validateEntityRefs(raw: string): { ok: true } | { ok: false; reason: string } {
  let i = 0;
  while (i < raw.length) {
    const ch = raw.charCodeAt(i);
    if (ch !== 0x26) {
      i++;
      continue;
    }
    // Found "&": it must start a well-formed reference ending in ";".
    const semi = raw.indexOf(";", i + 1);
    if (semi === -1) return { ok: false, reason: "unterminated entity reference (a literal '&' must be written &amp;)" };
    const body = raw.slice(i + 1, semi);
    if (body.length === 0) return { ok: false, reason: "empty entity reference '&;'" };
    if (body[0] === "#") {
      // Numeric character reference: &#DDD; (decimal) or &#xHH; / &#XHH; (hex). Digits only in the body.
      const hex = body[1] === "x" || body[1] === "X";
      const digits = hex ? body.slice(2) : body.slice(1);
      if (digits.length === 0) return { ok: false, reason: "malformed numeric character reference" };
      const re = hex ? /^[0-9a-fA-F]+$/ : /^[0-9]+$/;
      if (!re.test(digits)) return { ok: false, reason: "malformed numeric character reference" };
      // WFC: Legal Character - well-formed DIGIT syntax is not enough; the code point it NAMES must not be
      // one of the control bytes XML 1.0 bans (a syntactically fine &#x0; / &#x1B; / &#x7F; is still an
      // illegal character reference). Reject here, at the single hardened parse boundary.
      const cp = hex ? parseInt(digits, 16) : parseInt(digits, 10);
      if (isDisallowedControlCodePoint(cp)) return { ok: false, reason: "numeric character reference names a disallowed control character" };
    } else {
      // A named entity: ONLY the five predefined names are allowed (no DTD means no others can be defined).
      if (body !== "amp" && body !== "lt" && body !== "gt" && body !== "quot" && body !== "apos") {
        return { ok: false, reason: `undefined general entity reference &${body}; (only the 5 predefined entities + numeric refs are allowed)` };
      }
    }
    i = semi + 1;
  }
  return { ok: true };
}

// namespace-aware attribute dedupe (the XSW attribute-pollution defence)

// checkExpandedNameDupes performs the NAMESPACE-AWARE duplicate-attribute check the XSW threat model wants: two
// attributes that resolve to the SAME expanded name (namespace URI + local name) are a forbidden duplicate even
// when their qualified names differ (e.g. p1:x and p2:x where p1 and p2 are bound to the same URI). It is given
// the element's own attribute list plus the inherited prefix->URI scope (from ancestors) so prefixes declared
// higher up resolve. Unprefixed attributes are in NO namespace (attributes do NOT inherit the default xmlns),
// so two unprefixed attributes with the same name were already caught by the qualified-name dedupe; here we
// focus on prefixed attributes. The reserved "xml" / "xmlns" prefixes are handled per the Namespaces REC.
export function checkExpandedNameDupes(attrs: XmlAttr[], inheritedScope: Map<string, string>): { ok: true } | { ok: false; reason: string } {
  // Build the in-scope prefix->URI map: inherited, overlaid with THIS element's own xmlns declarations (a
  // declaration on the element is in scope for that element's attributes).
  const scope = new Map(inheritedScope);
  for (const a of attrs) {
    if (a.name === "xmlns") {
      // The default namespace does NOT apply to attributes, so a bare xmlns binding is irrelevant to attribute
      // expanded names; we still record it (harmless) but never use the "" key below for an attribute.
      scope.set("", a.value);
    } else if (a.name.startsWith("xmlns:")) {
      scope.set(a.name.slice("xmlns:".length), a.value);
    }
  }
  const seen = new Set<string>();
  for (const a of attrs) {
    // Namespace-declaration attributes are themselves deduped by qualified name (xmlns / xmlns:foo are unique
    // already via the qualified-name set); they have a special status and are not "in a namespace" the way an
    // ordinary attribute is, so skip them here.
    if (a.name === "xmlns" || a.name.startsWith("xmlns:")) continue;
    const colon = a.name.indexOf(":");
    let key: string;
    if (colon === -1) {
      // Unprefixed attribute: NO namespace. Its expanded name is just the local name in the "no-namespace"
      // partition. (Two such with the same local name were already rejected by the qualified-name dedupe, but
      // we still record it so a prefixed attribute bound to "" - which cannot happen for a real URI - would not
      // collide. Use a partition tag that a real URI can never equal.)
      key = ` nons ${a.name}`;
    } else {
      const prefix = a.name.slice(0, colon);
      const local = a.name.slice(colon + 1);
      // The reserved "xml" prefix is bound to the XML namespace always.
      const uri = prefix === "xml" ? "http://www.w3.org/XML/1998/namespace" : scope.get(prefix);
      if (uri === undefined) {
        // A prefixed attribute whose prefix is not bound is a namespace error - fail closed (a forgiving parser
        // would accept it, but an unbound prefix is malformed per the Namespaces REC and a smell).
        return { ok: false, reason: `attribute prefix '${prefix}:' is not bound to a namespace` };
      }
      key = `${uri} ${local}`;
    }
    if (seen.has(key)) {
      return { ok: false, reason: "duplicate attribute by expanded name (two attributes resolve to the same namespace + local name)" };
    }
    seen.add(key);
  }
  return { ok: true };
}

// scopeFromAttrs extracts the xmlns declarations on an element's attributes into a prefix->URI map fragment
// (for threading the in-scope namespace context down to children for the expanded-name dedupe). "" is the
// default-namespace key.
export function scopeFromAttrs(attrs: XmlAttr[]): Map<string, string> {
  const m = new Map<string, string>();
  for (const a of attrs) {
    if (a.name === "xmlns") m.set("", a.value);
    else if (a.name.startsWith("xmlns:")) m.set(a.name.slice("xmlns:".length), a.value);
  }
  return m;
}
