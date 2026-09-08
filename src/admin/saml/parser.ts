// A HAND-ROLLED, hardened XML parser - the SOLE pre-parse defence for the native SAML 2.0 Service Provider.
// The exc-c14n# canonicaliser (c14n.ts), the XML-DSig verifier (dsig.ts) and the assertion consumer
// (assertion.ts) all TRUST the tree this produces. A parser bug here is a SILENT signature-bypass /
// assertion-injection (the 2025 XSW / SAMLStorm / ruby-saml CVE class), so this parser FAILS CLOSED on
// anything ambiguous or malformed, and it deliberately does NONE of the dangerous things a forgiving parser
// does (no DTD, no entity expansion, no second root, no last-value-wins attribute dedupe, no PI content).
//
// It produces EXACTLY the XmlElement tree shape in xml-node.ts: { type:"element", name, attrs, children },
// XmlAttr { name, value }, XmlText { type:"text", value }, XmlComment { type:"comment", value }. The CRITICAL
// invariant is that attribute and text VALUES are stored RAW - still entity-encoded as they appeared in the
// document - because the canonical-text layer (canonical-text.ts) is the SINGLE place that decodes entities
// (the "verify == read" linchpin). This parser therefore NEVER decodes &amp; / &#x41; / etc; it PRESERVES
// them verbatim in the value. Namespace declarations (xmlns / xmlns:prefix) are kept as ordinary attributes,
// exactly as xml-node.ts and c14n.ts expect (c14n re-derives the in-scope namespace set itself).
//
// Why hand-rolled: the runtime is Cloudflare workerd, which has NO Node builtins, NO DOMParser and NO XML
// library. Only standard JS + TextEncoder / TextDecoder are available. So we tokenise the UTF-8 text ourselves.
//
// Node 25 strip-types + Workers compatible: pure functions, no DOM, no Node builtins, no enums (string-literal
// unions), explicit fields, error-as-value (parseXml NEVER throws). Australian English; no em dashes.

// The attack-shape ledger (a leaf that imports nothing). The parser is the FIRST gate a hostile document
// meets, so it is where the DTD probe, the second root and the resource ceilings are seen, and each is
// recorded under its own distinguishable signal rather than one generic `malformed` counter.
import { noteSamlSignal } from "../saml-signals.ts";
// The lexical layer (char predicates, the UTF-8 input decoder + raw-byte gates, the entity-reference
// validator) lives in parser-lex.ts (a sibling split out so each module stays under 500 lines). These are
// internal helpers the tokeniser below drives; none are part of the public parser surface (only parseXml +
// ParseLimits/ParseResult are), so nothing is re-exported.
import {
  checkExpandedNameDupes,
  decodeInput,
  isDisallowedControlCodePoint,
  isNameChar,
  isNameStartChar,
  isXmlWhitespace,
  scanForbiddenConstructs,
  scopeFromAttrs,
  validateEntityRefs,
} from "./parser-lex.ts";
import type { XmlAttr, XmlChild, XmlElement } from "./xml-node.ts";

// ParseLimits bound a hostile document. All are overridable; the defaults below are sized for a SAML POST (an
// HTTP-form-posted Response is well under a megabyte, a handful of namespaces deep, a few thousand nodes).
export interface ParseLimits {
  // Maximum number of BYTES (UTF-8) of input. A larger input is rejected before tokenising. Default 1_000_000.
  maxBytes?: number;
  // Maximum element nesting DEPTH (the document element is depth 1). Bounds a deeply-nested document that
  // could exhaust the stack or a downstream recursive walk. Default 100.
  maxDepth?: number;
  // Maximum total number of NODES produced (elements + text + comments). Bounds a wide/huge document.
  // Default 50_000.
  maxNodes?: number;
}

// ParseOk carries the single document element. ParseFail carries a short, stable-ish reason for logs. The
// result is an error-as-value: parseXml never throws, so a malformed/hostile input is a clean reject, never an
// exception the caller might forget to catch (an uncaught throw on a security boundary is a fail-OPEN risk).
export interface ParseOk {
  ok: true;
  root: XmlElement;
}
export interface ParseFail {
  ok: false;
  reason: string;
}
export type ParseResult = ParseOk | ParseFail;

const DEFAULT_MAX_BYTES = 1_000_000;
const DEFAULT_MAX_DEPTH = 100;
const DEFAULT_MAX_NODES = 50_000;

function fail(reason: string): ParseFail {
  return { ok: false, reason };
}

// ---- the tokeniser / tree builder ----
// We walk the decoded string with a single cursor `pos`. The grammar we accept around the document element is:
//   prolog := ( S | Comment | XMLDecl-at-start )*  -- only ONE XMLDecl, only at the very start
//   document := prolog element prolog              -- exactly ONE element; comments/whitespace either side
// Inside an element: child content is text | element | comment | CDATA. PIs other than the leading XMLDecl are
// rejected. DOCTYPE/ENTITY are already gated out. We fail closed on every malformed construct.

interface ParseState {
  text: string;
  pos: number;
  maxDepth: number;
  maxNodes: number;
  nodes: number; // running count of produced nodes (elements + text + comments)
}

// bumpNodes increments the node count and signals when the cap is exceeded.
function bumpNodes(st: ParseState): boolean {
  st.nodes++;
  return st.nodes <= st.maxNodes;
}

// readName reads an XML Name starting at st.pos (which must be a NameStartChar). Returns the name and advances
// past it, or null when st.pos is not a valid name start. Uses code points so a >= 0x80 multi-unit name char is
// handled (codePointAt + width advance).
function readName(st: ParseState): string | null {
  const start = st.pos;
  const first = st.text.codePointAt(st.pos);
  if (first === undefined || !isNameStartChar(first)) return null;
  st.pos += first > 0xffff ? 2 : 1;
  while (st.pos < st.text.length) {
    const cp = st.text.codePointAt(st.pos)!;
    if (!isNameChar(cp)) break;
    st.pos += cp > 0xffff ? 2 : 1;
  }
  return st.text.slice(start, st.pos);
}

// skipWhitespace advances st.pos over XML whitespace, returning the count skipped (so callers can require that
// a separator was present, e.g. between attributes).
function skipWhitespace(st: ParseState): number {
  let n = 0;
  while (st.pos < st.text.length && isXmlWhitespace(st.text.charCodeAt(st.pos))) {
    st.pos++;
    n++;
  }
  return n;
}

// parseAttributes reads zero or more Attribute productions of the form  Name S? = S? ("..."|'...') , each
// separated by whitespace, until it reaches ">" , "/>" or "?>" (the caller decides which terminators are
// valid). It enforces: a whitespace separator before each attribute; a quoted value (single or double); NO "<"
// inside the value; the raw value passes validateEntityRefs (so only the predefined/numeric refs survive RAW);
// and NO DUPLICATE qualified attribute name on the element (the attribute-pollution / last-value-wins XSW
// vector). Namespace-aware dedupe is layered on top by the caller via checkExpandedNameDupes.
function parseAttributes(st: ParseState, requireLeadingWs: boolean): { ok: true; attrs: XmlAttr[] } | { ok: false; reason: string } {
  const attrs: XmlAttr[] = [];
  const seenQNames = new Set<string>();
  let firstAttr = true;
  for (;;) {
    const ws = skipWhitespace(st);
    const c = st.text.charCodeAt(st.pos);
    // Terminators: ">" (0x3e), "/" (start of "/>", 0x2f), "?" (start of "?>", 0x3f). The caller validates which
    // close token actually follows; here we just stop consuming attributes.
    if (Number.isNaN(c) || c === 0x3e || c === 0x2f || c === 0x3f) {
      return { ok: true, attrs };
    }
    // An attribute must be separated from the tag name / previous attribute by whitespace.
    if (firstAttr) {
      if (requireLeadingWs && ws === 0) return { ok: false, reason: "expected whitespace before the first attribute" };
    } else if (ws === 0) {
      return { ok: false, reason: "expected whitespace between attributes" };
    }
    firstAttr = false;

    const name = readName(st);
    if (name === null) return { ok: false, reason: "malformed attribute name" };
    skipWhitespace(st);
    if (st.text.charCodeAt(st.pos) !== 0x3d) return { ok: false, reason: `expected '=' after attribute name '${name}'` };
    st.pos++; // consume '='
    skipWhitespace(st);
    const q = st.text.charCodeAt(st.pos);
    if (q !== 0x22 && q !== 0x27) {
      return { ok: false, reason: `attribute value for '${name}' must be quoted (unquoted values are rejected)` };
    }
    st.pos++; // consume the opening quote
    const valStart = st.pos;
    // Scan to the matching closing quote. A "<" inside an attribute value is forbidden in XML and is a classic
    // injection smell, so we reject it. The other quote char is allowed inside (only the matching one closes).
    for (;;) {
      if (st.pos >= st.text.length) return { ok: false, reason: `unterminated attribute value for '${name}'` };
      const vc = st.text.charCodeAt(st.pos);
      if (vc === q) break;
      if (vc === 0x3c) return { ok: false, reason: `'<' is not allowed in an attribute value ('${name}')` };
      // A literal control byte typed straight into the value (no entity encoding at all, so validateEntityRefs
      // below never sees it) is equally a WFC: Legal Character violation - reject it here.
      if (isDisallowedControlCodePoint(vc)) return { ok: false, reason: `attribute '${name}': disallowed control character in value` };
      st.pos++;
    }
    const rawValue = st.text.slice(valStart, st.pos);
    st.pos++; // consume the closing quote

    // The value is preserved RAW (entity-encoded), but we VALIDATE its references: only predefined + numeric.
    const ev = validateEntityRefs(rawValue);
    if (!ev.ok) return { ok: false, reason: `attribute '${name}': ${ev.reason}` };

    // Reject a duplicate QUALIFIED name outright (the minimum dedupe). Namespace-aware dedupe is added later.
    if (seenQNames.has(name)) return { ok: false, reason: `duplicate attribute '${name}' on one element` };
    seenQNames.add(name);

    attrs.push({ name, value: rawValue });
  }
}

// parseComment parses "<!-- ... -->" with st.pos positioned just AFTER the "<!--". It returns the inner text
// (delimiters excluded), rejecting an unterminated comment and the illegal "--" inside a comment (XML forbids
// "--" except as part of the closing "-->"). The inner text is stored verbatim as the XmlComment value, which
// matches what c14n.ts emits for the WithComments form (<!--value-->) so the digest path is faithful.
function parseComment(st: ParseState): { ok: true; value: string } | { ok: false; reason: string } {
  const start = st.pos;
  const end = st.text.indexOf("-->", start);
  if (end === -1) return { ok: false, reason: "unterminated comment (no '-->')" };
  const inner = st.text.slice(start, end);
  // "--" is illegal inside a comment (only "-->" may close it). This is the SAMLStorm-adjacent rule: a sloppy
  // parser that allowed "--" could be desynced by a crafted comment; we reject.
  if (inner.includes("--")) return { ok: false, reason: "'--' is not allowed inside a comment" };
  st.pos = end + 3; // consume "-->"
  return { ok: true, value: inner };
}

// parseCData parses "<![CDATA[ ... ]]>" with st.pos just AFTER the "<![CDATA[". The content is LITERAL text
// (entities are NOT recognised inside CDATA). To keep the single raw-value discipline that c14n.ts relies on
// (it does escapeC14nText(decodeXmlText(value))), we store the literal content RE-ESCAPED into entity form so
// that decodeXmlText(storedValue) === the literal characters. Concretely "<b> & </b>" inside CDATA is stored
// as "&lt;b&gt; &amp; &lt;/b&gt;": decoding that yields back the literal, identical to how an ordinary text run
// carrying those same characters would have been authored and stored. This is the documented CDATA
// representation (see the module report): CDATA becomes an ordinary text node whose raw value re-escapes to the
// same bytes, so the c14n digest is byte-identical whether the IdP used CDATA or plain escaped text.
function parseCData(st: ParseState): { ok: true; value: string } | { ok: false; reason: string } {
  const start = st.pos;
  const end = st.text.indexOf("]]>", start);
  if (end === -1) return { ok: false, reason: "unterminated CDATA section (no ']]>')" };
  const literal = st.text.slice(start, end);
  st.pos = end + 3; // consume "]]>"
  // Re-escape the literal to entity form so the stored RAW value decodes back to exactly these characters.
  // Order matters: escape & first, then < and >, so a literal "&" does not become part of a spurious entity.
  let escaped = "";
  for (const ch of literal) {
    if (ch === "&") escaped += "&amp;";
    else if (ch === "<") escaped += "&lt;";
    else if (ch === ">") escaped += "&gt;";
    else escaped += ch;
  }
  return { ok: true, value: escaped };
}

// rejectBareGtInText guards the rule that a literal ">" in character data, while tolerated by some parsers, is
// in fact only required to be escaped as part of "]]>"; XML 1.0 forbids the literal sequence "]]>" in content
// (it must be written "]]&gt;"). We reject that exact sequence in text to avoid a CDATA-close confusion, and we
// reject a stray "<" handling elsewhere. A lone ">" is otherwise permitted in text by XML, so we allow it.
function textContainsIllegalSequence(text: string): boolean {
  return text.includes("]]>");
}

// parseElement parses one element starting at st.pos === position of "<". It recursively parses children and
// returns the XmlElement, threading the inherited namespace scope for the namespace-aware attribute dedupe and
// enforcing the depth + node caps. `depth` is 1 for the document element.
function parseElement(
  st: ParseState,
  inheritedScope: Map<string, string>,
  depth: number,
): { ok: true; el: XmlElement } | { ok: false; reason: string } {
  if (depth > st.maxDepth) return { ok: false, reason: "maximum element nesting depth exceeded" };
  if (st.text.charCodeAt(st.pos) !== 0x3c) return { ok: false, reason: "expected '<' to start an element" };
  st.pos++; // consume '<'

  const name = readName(st);
  if (name === null) return { ok: false, reason: "malformed element name after '<'" };

  const attrRes = parseAttributes(st, /* requireLeadingWs */ true);
  if (!attrRes.ok) return attrRes;
  const attrs = attrRes.attrs;

  // Namespace-aware duplicate-attribute check in the scope visible to THIS element (inherited + own decls).
  const dupRes = checkExpandedNameDupes(attrs, inheritedScope);
  if (!dupRes.ok) return dupRes;

  if (!bumpNodes(st)) return { ok: false, reason: "maximum node count exceeded" };

  // The scope visible to this element's CHILDREN = inherited overlaid with this element's own xmlns decls.
  const childScope = new Map(inheritedScope);
  for (const [k, v] of scopeFromAttrs(attrs)) childScope.set(k, v);

  // After attributes we are at ">" or "/>".
  const c = st.text.charCodeAt(st.pos);
  if (c === 0x2f) {
    // Self-closing "/>": no children.
    if (st.text.charCodeAt(st.pos + 1) !== 0x3e) return { ok: false, reason: `expected '/>' to self-close element '${name}'` };
    st.pos += 2;
    return { ok: true, el: { type: "element", name, attrs, children: [] } };
  }
  if (c !== 0x3e) return { ok: false, reason: `expected '>' or '/>' after the attributes of '${name}'` };
  st.pos++; // consume '>'

  // Parse children until the matching close tag.
  const children: XmlChild[] = [];
  let pendingText = ""; // accumulates a contiguous run of character data (between markup)

  // flushText emits any accumulated character-data run as a single XmlText node, after validating its entity
  // refs and the illegal "]]>" sequence. We accumulate so that markup which DOES split a text run (a comment
  // between two characters) produces SEPARATE text nodes around the comment exactly as the document had them -
  // we never MERGE text across a comment (which would diverge from the document and is the SAMLStorm class).
  const flushText = (): { ok: true } | { ok: false; reason: string } => {
    if (pendingText.length === 0) return { ok: true };
    if (textContainsIllegalSequence(pendingText)) return { ok: false, reason: "the sequence ']]>' is not allowed in character data" };
    // A literal control byte is a WFC: Legal Character violation whether it was typed directly as plain text
    // or carried in verbatim from a CDATA section (parseCData only re-escapes &, < and >, so a raw control
    // byte inside CDATA reaches pendingText unchanged) - one scan here closes both paths at once.
    for (let i = 0; i < pendingText.length; i++) {
      if (isDisallowedControlCodePoint(pendingText.charCodeAt(i))) return { ok: false, reason: "disallowed control character in character data" };
    }
    const ev = validateEntityRefs(pendingText);
    if (!ev.ok) return { ok: false, reason: `text content: ${ev.reason}` };
    if (!bumpNodes(st)) return { ok: false, reason: "maximum node count exceeded" };
    children.push({ type: "text", value: pendingText });
    pendingText = "";
    return { ok: true };
  };

  for (;;) {
    if (st.pos >= st.text.length) return { ok: false, reason: `unexpected end of input inside element '${name}' (unclosed tag)` };
    const ch = st.text.charCodeAt(st.pos);
    if (ch === 0x3c) {
      // Some markup. Distinguish: close tag "</", comment "<!--", CDATA "<![CDATA[", a "<!" that is anything
      // else (rejected - DOCTYPE was already gated, so any other "<!" here is malformed), a PI "<?" (rejected -
      // only the leading XML declaration is allowed, and that cannot appear inside an element), or a child
      // element "<name".
      const n1 = st.text.charCodeAt(st.pos + 1);
      if (n1 === 0x2f) {
        // Close tag: flush pending text, then match the name and consume "</name S? >".
        const ft = flushText();
        if (!ft.ok) return ft;
        st.pos += 2; // consume "</"
        const closeName = readName(st);
        if (closeName === null) return { ok: false, reason: "malformed close tag" };
        if (closeName !== name) return { ok: false, reason: `mismatched tags: <${name}> closed by </${closeName}>` };
        skipWhitespace(st);
        if (st.text.charCodeAt(st.pos) !== 0x3e) return { ok: false, reason: `expected '>' to end close tag </${name}>` };
        st.pos++; // consume '>'
        return { ok: true, el: { type: "element", name, attrs, children } };
      }
      if (n1 === 0x21) {
        // "<!..." : comment "<!--", CDATA "<![CDATA[", or something malformed (DOCTYPE already gated globally).
        if (st.text.startsWith("<!--", st.pos)) {
          const ft = flushText();
          if (!ft.ok) return ft;
          st.pos += 4; // consume "<!--"
          const cm = parseComment(st);
          if (!cm.ok) return cm;
          if (!bumpNodes(st)) return { ok: false, reason: "maximum node count exceeded" };
          children.push({ type: "comment", value: cm.value });
          continue;
        }
        if (st.text.startsWith("<![CDATA[", st.pos)) {
          // CDATA content joins the SURROUNDING character-data run (it is character data), so we append to
          // pendingText rather than flushing - a value split as text + CDATA + text is one logical text value,
          // and joining keeps the digest identical to the equivalent fully-escaped single text run. (Note this
          // is the ONE case we deliberately concatenate, because CDATA is literally character data, NOT markup
          // like a comment.)
          // A bare '&' dangling at the end of the plain text immediately before this CDATA must NOT be
          // "completed" using characters borrowed from the CDATA content about to be appended (e.g.
          // `&<![CDATA[lt;]]>` is not well-formed XML even though the merged bytes read '&lt;'). This is already
          // closed below, in the character-data branch: every plain-text span is validated for a dangling
          // entity reference THE MOMENT it is scanned off the immutable source text, before it ever reaches
          // pendingText - so whatever is already in pendingText by the time we get here is proven clean, and
          // merging in CDATA content cannot retroactively "complete" a reference that was not already complete
          // on its own. (An earlier version of this fix re-validated a slice of pendingText itself at this
          // point; that reintroduces O(n^2) cost on many chained CDATA sections, because slicing a string that
          // is also repeatedly grown by "+=" forces a full re-flatten of the accumulated-so-far run at every
          // boundary. Validating the span against st.text - which is never mutated - avoids that entirely.)
          st.pos += 9; // consume "<![CDATA["
          const cd = parseCData(st);
          if (!cd.ok) return cd;
          pendingText += cd.value;
          continue;
        }
        return { ok: false, reason: "unsupported '<!' construct (only comments and CDATA are allowed; DOCTYPE/DTD are banned)" };
      }
      if (n1 === 0x3f) {
        return { ok: false, reason: "processing instructions are not allowed (only the leading XML declaration)" };
      }
      // Otherwise it is a child element. Flush pending text, recurse.
      const ft = flushText();
      if (!ft.ok) return ft;
      const childRes = parseElement(st, childScope, depth + 1);
      if (!childRes.ok) return childRes;
      children.push(childRes.el);
      continue;
    }
    // Character data: accumulate until the next "<". (A bare ">" is legal in text; "<" always starts markup; a
    // stray "<" that does not form valid markup is caught by the markup branches above failing.) indexOf+slice
    // is O(n) over the text node, matching how comment and CDATA sections are scanned (vs an O(n^2)
    // character-by-character append).
    const textEnd = st.text.indexOf("<", st.pos);
    const span = textEnd === -1 ? st.text.slice(st.pos) : st.text.slice(st.pos, textEnd);
    // Validate THIS span's entity references now, as a fresh slice of the immutable source text (st.text is
    // never mutated) rather than of pendingText (which a CDATA merge, above, can turn into a repeatedly-grown
    // accumulator): a dangling '&' at the end of the span is rejected here regardless of what follows it (CDATA,
    // a comment, a child element or the close tag), so it can never be "completed" by content merged in
    // afterwards (ML-44). Checking each span once against st.text, instead of re-slicing the ever-growing
    // pendingText at every CDATA boundary, keeps this O(n) total: slicing a string that is also repeatedly
    // grown by "+=" forces a full re-flatten of the accumulated-so-far run at every slice, which is quadratic in
    // the number of boundaries. flushText's existing whole-run check (below) is unaffected - it already ran
    // once per completed run, not once per boundary - and remains the final safety net.
    const ev = validateEntityRefs(span);
    if (!ev.ok) return { ok: false, reason: `text content: ${ev.reason}` };
    pendingText += span;
    st.pos = textEnd === -1 ? st.text.length : textEnd;
  }
}

// skipXmlDeclaration consumes a leading XML declaration "<?xml ... ?>" if present AT st.pos. The declaration is
// only valid at the very start of the document; we do not retain it in the tree (it is not a node). We accept
// the standard shape "<?xml" + attributes + "?>". A processing instruction that is NOT the XML declaration
// (any other "<?target") at the start is rejected (only the XML declaration PI is allowed). Returns ok with
// `present` indicating whether a declaration was consumed.
function skipXmlDeclaration(st: ParseState): { ok: true; present: boolean } | { ok: false; reason: string } {
  if (!st.text.startsWith("<?", st.pos)) return { ok: true, present: false };
  // It is a PI. Only "<?xml" followed by whitespace or "?>" is the XML declaration; anything else is rejected.
  // XML reserves the target "xml" (any case) so we match case-insensitively for the reject, but a real
  // declaration is lowercase "xml".
  const after = st.text.slice(st.pos + 2);
  const isXmlDecl = /^xml(\s|\?)/.test(after);
  if (!isXmlDecl) {
    return { ok: false, reason: "processing instructions are not allowed (only the leading XML declaration <?xml ... ?>)" };
  }
  const end = st.text.indexOf("?>", st.pos);
  if (end === -1) return { ok: false, reason: "unterminated XML declaration (no '?>')" };
  st.pos = end + 2; // consume through "?>"
  return { ok: true, present: true };
}

// skipMisc consumes whitespace and comments in the prolog/epilog (the regions OUTSIDE the document element).
// Comments and whitespace are allowed there; a PI other than (an already-consumed) XML declaration is rejected;
// any other non-whitespace content is the caller's problem (it signals a second root / stray markup). Returns
// It does not return a count; the return type is a simple ok/fail (advancing the cursor is the side effect,
// and the caller only needs to know whether an illegal construct was found).
function skipMisc(st: ParseState): { ok: true } | { ok: false; reason: string } {
  for (;;) {
    skipWhitespace(st);
    if (st.pos >= st.text.length) return { ok: true };
    if (st.text.startsWith("<!--", st.pos)) {
      st.pos += 4;
      const cm = parseComment(st);
      if (!cm.ok) return cm;
      // A comment in the prolog/epilog is well-formed but we do NOT add it to the tree: the tree root is a
      // single element, and exc-c14n# only ever canonicalises that connected element subtree, so a
      // document-level comment outside the root has no node to attach to and never affects a digest. Dropping
      // it is faithful (the base transform drops comments anyway).
      continue;
    }
    if (st.text.startsWith("<?", st.pos)) {
      // A PI in the epilog (or a second XML declaration) is rejected: only the single leading XML declaration
      // is permitted, and it was handled before the document element.
      return { ok: false, reason: "processing instructions are not allowed outside the leading XML declaration" };
    }
    // Any other content here is not permitted (it is either a second root element or stray non-markup).
    return { ok: true };
  }
}

// parseXml is the public entry point. It decodes + gates the raw bytes, then tokenises EXACTLY ONE document
// element with comments/whitespace permitted around it, returning the tree or a typed reject. It NEVER throws.
export function parseXml(input: string | Uint8Array, limits?: ParseLimits): ParseResult {
  const maxBytes = limits?.maxBytes ?? DEFAULT_MAX_BYTES;
  const maxDepth = limits?.maxDepth ?? DEFAULT_MAX_DEPTH;
  const maxNodes = limits?.maxNodes ?? DEFAULT_MAX_NODES;

  // BYTE cap first (on the raw input, before decoding), so a huge body is rejected as cheaply as possible. For a
  // string input we bound its UTF-8 byte length WITHOUT materialising the bytes: a BMP code unit encodes to at
  // most 3 UTF-8 bytes, so input.length * 3 is a conservative upper bound. decodeInput re-encodes only when the
  // input is actually within the cap, avoiding a full throwaway encode (up to maxBytes of temporary allocation).
  const BMP_MAX_UTF8_BYTES_PER_CODE_UNIT = 3;
  const byteLen = typeof input === "string" ? input.length * BMP_MAX_UTF8_BYTES_PER_CODE_UNIT : input.length;
  if (byteLen > maxBytes) {
    // A document over the byte ceiling is a RESOURCE shape, not a syntax one, so it is recorded distinctly
    // from an ordinary malformed-document reject.
    noteSamlSignal("saml-shape-parser-cap");
    return fail(`input exceeds maxBytes (${byteLen} > ${maxBytes})`);
  }

  // Decode + enforce UTF-8 (fatal on bytes), strip a BOM.
  const dec = decodeInput(input);
  if (!dec.ok) return fail(dec.reason);
  const text = dec.text;

  // The decisive substring gates: NO DOCTYPE, NO ENTITY declaration, ever. (Done on the decoded text so a
  // multi-byte-obfuscated keyword cannot slip past - after a fatal UTF-8 decode the keyword is plain text.)
  const gate = scanForbiddenConstructs(text);
  if (!gate.ok) {
    // A DOCTYPE or an ENTITY declaration in a SAMLResponse has NO benign explanation. It is an XXE /
    // billion-laughs probe, and is the single most unambiguous attack signal the SAML surface can produce.
    noteSamlSignal("saml-shape-dtd-entity");
    return fail(gate.reason);
  }

  const st: ParseState = { text, pos: 0, maxDepth, maxNodes, nodes: 0 };

  // PROLOG: an optional XML declaration at the very start, then whitespace/comments.
  const decl = skipXmlDeclaration(st);
  if (!decl.ok) return fail(decl.reason);
  const m1 = skipMisc(st);
  if (!m1.ok) return fail(m1.reason);

  // The document element MUST be present now.
  if (st.pos >= st.text.length) return fail("no document element");
  if (st.text.charCodeAt(st.pos) !== 0x3c) return fail("expected the document element, found character data at the top level");
  // Guard the specific top-level markup kinds that are not a start tag.
  if (st.text.startsWith("</", st.pos)) return fail("unexpected close tag at the top level");
  if (st.text.startsWith("<!", st.pos)) return fail("unexpected '<!' at the top level (DOCTYPE/DTD are banned; comments are handled separately)");
  if (st.text.startsWith("<?", st.pos)) return fail("processing instructions are not allowed outside the leading XML declaration");

  const rootRes = parseElement(st, new Map<string, string>(), 1);
  if (!rootRes.ok) {
    // G316: the depth / node ceilings are the parser's resource guards. Separate them from a syntax error, for
    // the same reason as the byte ceiling above.
    if (rootRes.reason === "maximum element nesting depth exceeded" || rootRes.reason === "maximum node count exceeded") noteSamlSignal("saml-shape-parser-cap");
    return fail(rootRes.reason);
  }

  // EPILOG: only whitespace/comments may follow. ANY further element is a SECOND ROOT - the classic XSW
  // wrapping vector - and is rejected.
  const m2 = skipMisc(st);
  if (!m2.ok) return fail(m2.reason);
  if (st.pos < st.text.length) {
    // Something other than whitespace/comment remains. If it is another "<" element, name the vector.
    if (st.text.charCodeAt(st.pos) === 0x3c) {
      // The sharpest attack signal the parser can raise, recorded distinctly rather than folded into a
      // generic malformed-document reject.
      noteSamlSignal("saml-shape-xsw-multi-root");
      return fail("more than one root element (a second top-level element is rejected: XML-Signature-Wrapping vector)");
    }
    return fail("unexpected trailing content after the document element");
  }

  return { ok: true, root: rootRes.el };
}
