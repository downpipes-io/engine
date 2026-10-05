// PARSER-AGNOSTIC XML tree type for the native SAML Service Provider's exc-c14n# canonicaliser and
// XML-DSig verifier. The c14n serialiser and the signature verifier consume THIS type, never a concrete
// parser's AST, so both are exercisable directly by their validators with HAND-BUILT trees (the path under
// test is the same production path since the handrolled parser.ts produces this exact shape).
//
// The model is deliberately minimal and EXPLICIT: an element carries its qualified name exactly as written
// (e.g. "ds:Signature"), its attributes in document order with their RAW (entity-encoded) values, and its
// children (elements, text, comments) in document order. Namespace declarations are NOT a distinct node kind:
// an xmlns / xmlns:prefix declaration is simply an attribute whose name starts with "xmlns" (this is what a
// non-namespace-aware parser like txml yields, and it is exactly what exc-c14n# needs to re-derive the
// in-scope namespace set itself rather than trusting a parser's namespace resolution). The c14n layer is the
// single place that interprets those xmlns attributes, so there is one namespace model in the codebase.
//
// Node 25 strip-types + Workers compatible: a pure data type plus small pure helpers, no DOM, no Node
// builtins, no enums, explicit fields, type-only where possible.

// An element node. `name` is the qualified name as written in the source ("ds:Signature", "Assertion"); the
// c14n layer splits prefix/local. `attrs` preserves document order (c14n re-sorts; other readers may want the
// authored order). `children` is the ordered child list.
export interface XmlElement {
  type: "element";
  name: string;
  attrs: XmlAttr[];
  children: XmlChild[];
}

// An attribute as parsed. `value` is RAW - still entity-encoded as it appeared in the document (e.g. an
// attribute written value="a&amp;b" has value === "a&amp;b" here). The c14n serialiser DECODES then RE-ESCAPES
// per the canonical attribute character model, and any claim reader must route the value through
// decodeXmlText (canonical-text.ts) so the signed bytes and the consumed value share one character model.
// An xmlns / xmlns:prefix namespace declaration is represented as one of these (name "xmlns" or "xmlns:foo").
export interface XmlAttr {
  name: string;
  value: string;
}

// A text node. `value` is RAW (entity-encoded as parsed); the c14n serialiser decodes then re-escapes per the
// text-node character model. Whitespace is significant and preserved verbatim.
export interface XmlText {
  type: "text";
  value: string;
}

// A comment node. `value` is the comment's inner text (without the <!-- --> delimiters). Base exc-c14n# DROPS
// comments; the WithComments variant emits them as <!--value-->. Parsers that discard comments simply never
// produce this kind, which is fine for the base transform.
export interface XmlComment {
  type: "comment";
  value: string;
}

export type XmlChild = XmlElement | XmlText | XmlComment;

// isElement narrows an XmlChild to an element (the c14n walk and the dsig tree walks lean on this).
export function isElement(c: XmlChild): c is XmlElement {
  return c.type === "element";
}

// childElements returns the element children of `el` in document order, skipping text and comment nodes.
export function childElements(el: XmlElement): XmlElement[] {
  const out: XmlElement[] = [];
  for (const c of el.children) {
    if (c.type === "element") out.push(c);
  }
  return out;
}

// localName returns the part of a qualified name after the colon, or the whole name when there is no prefix.
// "ds:Signature" -> "Signature"; "Assertion" -> "Assertion". A name with more than one colon is malformed XML
// per the Namespaces spec; we split on the FIRST colon so the remainder (whatever it is) is the local part,
// which keeps the function total rather than throwing on hostile input.
export function localName(qname: string): string {
  const i = qname.indexOf(":");
  return i === -1 ? qname : qname.slice(i + 1);
}

// prefixOf returns the namespace prefix of a qualified name, or "" when the name is unprefixed.
// "ds:Signature" -> "ds"; "Assertion" -> "". Splits on the FIRST colon (see localName).
export function prefixOf(qname: string): string {
  const i = qname.indexOf(":");
  return i === -1 ? "" : qname.slice(0, i);
}

// isNamespaceDecl reports whether an attribute is a namespace declaration ("xmlns" or "xmlns:prefix"), the
// nodes exc-c14n# treats specially. A bare "xmlns" declares the default namespace; "xmlns:foo" declares the
// prefix "foo". An attribute merely BEGINNING with the letters "xmlns" but continuing differently (e.g.
// "xmlnsfoo") is an ordinary attribute, so we require either exact "xmlns" or an "xmlns:" prefix.
export function isNamespaceDecl(attr: XmlAttr): boolean {
  return attr.name === "xmlns" || attr.name.startsWith("xmlns:");
}

// nsDeclPrefix returns the prefix a namespace-declaration attribute binds: "" for a bare "xmlns" (the default
// namespace), or the text after "xmlns:" for "xmlns:foo". Caller must have checked isNamespaceDecl first.
export function nsDeclPrefix(attr: XmlAttr): string {
  return attr.name === "xmlns" ? "" : attr.name.slice("xmlns:".length);
}

// findElements walks the tree rooted at `el` in document order and returns every element for which `pred`
// holds (including `el` itself). Used by the dsig layer for the unique-ID walk and the Signature search,
// where finding ALL matches (then asserting the count) is the XSW defence, not stopping at the first.
export function findElements(el: XmlElement, pred: (e: XmlElement) => boolean): XmlElement[] {
  const out: XmlElement[] = [];
  const visit = (node: XmlElement): void => {
    if (pred(node)) out.push(node);
    for (const c of node.children) {
      if (c.type === "element") visit(c);
    }
  };
  visit(el);
  return out;
}
