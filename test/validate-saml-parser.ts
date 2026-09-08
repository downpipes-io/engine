// Adversarial validator for the hand-rolled hardened XML parser (src/admin/saml/parser.ts), the SOLE pre-parse
// defence for the native SAML 2.0 Service Provider. It proves two things:
//   1. The production parser produces EXACTLY the XmlElement tree shape the dsig / assertion consumers expect:
//      a parsed SAML-Assertion-shaped string DEEP-EQUALS the equivalent HAND-BUILT tree (the same shape
//      validate-saml-dsig.ts / validate-saml-assertion.ts construct), and entity-bearing attribute/text values
//      are preserved RAW (still encoded), the canonical-text layer being the single decoder ("verify == read").
//   2. Every hostile / malformed construct in the XSW / SAMLStorm / XXE / billion-laughs CVE class FAILS CLOSED
//      (ok:false): DOCTYPE / ENTITY / external+general entity refs, two roots / a wrapped second Assertion,
//      duplicate attributes (qualified AND namespace-aliased), oversize / too-deep / too-many-nodes, mismatched
//      tags, unclosed tags, unquoted attributes, a stray '<', an unterminated comment, '--' inside a comment, a
//      non-declaration PI, and non-UTF-8 bytes.
//
// Harness style mirrors validate-saml-dsig.ts (the check(cond, desc) helper, the final "... VECTORS PASS (N
// checks)" line, process.exitCode on failure). Run: node --no-warnings test/validate-saml-parser.ts
//
// Node 25 strip-types; no Node builtins beyond the harness exit code. console is the WebWorker global.

import { parseXml } from "../src/admin/saml/parser.ts";
import type { ParseResult } from "../src/admin/saml/parser.ts";
import type { XmlElement, XmlAttr, XmlChild } from "../src/admin/saml/xml-node.ts";

// This validator runs under Node (strip-types); the project tsconfig ships Workers types only (no @types/node).
// Declare the single Node global we use so the file is tsc-clean under those flags. console is the WebWorker lib.
declare const process: { exitCode?: number };

// ---- tiny test harness ----
let passed = 0;
const fails: string[] = [];
function check(cond: boolean, desc: string): void {
  if (cond) {
    passed++;
    console.log("  ok   " + desc);
  } else {
    fails.push(desc);
    console.log("  FAIL " + desc);
  }
}

// expectOk parses and asserts success, returning the root (or a dummy on failure so callers can keep going).
function expectOk(input: string | Uint8Array, desc: string): XmlElement | null {
  const r: ParseResult = parseXml(input);
  if (r.ok) {
    passed++;
    console.log("  ok   " + desc);
    return r.root;
  }
  fails.push(desc + " -unexpectedly REJECTED: " + r.reason);
  console.log("  FAIL " + desc + " -unexpectedly REJECTED: " + r.reason);
  return null;
}

// expectFail parses and asserts an ok:false reject (the security boundary). The reason is printed for insight.
function expectFail(input: string | Uint8Array, desc: string, limits?: { maxBytes?: number; maxDepth?: number; maxNodes?: number }): void {
  const r: ParseResult = parseXml(input, limits);
  if (!r.ok) {
    passed++;
    console.log("  ok   " + desc + "  (reason: " + r.reason + ")");
  } else {
    fails.push(desc + " -UNEXPECTEDLY ACCEPTED");
    console.log("  FAIL " + desc + " -UNEXPECTEDLY ACCEPTED");
  }
}

// ---- hand-built tree builders (the SAME shape validate-saml-dsig.ts uses) ----
function el(name: string, attrs: XmlAttr[], children: XmlChild[]): XmlElement {
  return { type: "element", name, attrs, children };
}
function a(name: string, value: string): XmlAttr {
  return { name, value };
}
function t(value: string): XmlChild {
  return { type: "text", value };
}
function comment(value: string): XmlChild {
  return { type: "comment", value };
}

// ---- deep structural equality over the XmlElement tree ----
// Compares name, attrs (name+value, IN ORDER) and children (kind + value/recursion, IN ORDER). Order matters:
// the parser must preserve document order for attributes and children, which the c14n attribute sort and the
// dsig walks both assume as the authored baseline.
function attrsEqual(x: XmlAttr[], y: XmlAttr[]): boolean {
  if (x.length !== y.length) return false;
  for (let i = 0; i < x.length; i++) {
    if (x[i]!.name !== y[i]!.name || x[i]!.value !== y[i]!.value) return false;
  }
  return true;
}
function childEqual(x: XmlChild, y: XmlChild): boolean {
  if (x.type !== y.type) return false;
  if (x.type === "element" && y.type === "element") return elementEqual(x, y);
  // text or comment: compare value
  return (x as { value: string }).value === (y as { value: string }).value;
}
function elementEqual(x: XmlElement, y: XmlElement): boolean {
  if (x.name !== y.name) return false;
  if (!attrsEqual(x.attrs, y.attrs)) return false;
  if (x.children.length !== y.children.length) return false;
  for (let i = 0; i < x.children.length; i++) {
    if (!childEqual(x.children[i]!, y.children[i]!)) return false;
  }
  return true;
}

console.log("hardened XML parser vectors\n");

// ============================ GREEN: a realistic SAML Response/Assertion ============================
console.log("green - realistic SAML + shape oracle:\n");

// A SAML-Assertion-shaped document that mirrors buildAssertion() in validate-saml-dsig.ts EXACTLY, so we can
// deep-compare the parsed tree to the hand-built one (proving the production parser feeds dsig/assertion the
// identical shape). Note the xmlns:saml declaration is an ordinary attribute on the element, as xml-node.ts +
// c14n.ts require. The NameID carries an &amp; to prove RAW preservation (the value stays "a&amp;b").
{
  const xml =
    '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion_1" Version="2.0">' +
    "<saml:Issuer>https://idp.example.com</saml:Issuer>" +
    "<saml:Subject><saml:NameID>a&amp;b</saml:NameID></saml:Subject>" +
    '<saml:Conditions NotOnOrAfter="2030-01-01T00:00:00Z"></saml:Conditions>' +
    "</saml:Assertion>";

  const hand = el(
    "saml:Assertion",
    [a("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion"), a("ID", "_assertion_1"), a("Version", "2.0")],
    [
      el("saml:Issuer", [], [t("https://idp.example.com")]),
      el("saml:Subject", [], [el("saml:NameID", [], [t("a&amp;b")])]),
      el("saml:Conditions", [a("NotOnOrAfter", "2030-01-01T00:00:00Z")], []),
    ],
  );

  const root = expectOk(xml, "a realistic SAML Assertion parses");
  check(root !== null && elementEqual(root, hand), "parsed tree DEEP-EQUALS the equivalent hand-built XmlElement (dsig/assertion shape oracle)");
  if (root !== null) {
    // Spot-checks called out explicitly.
    check(root.name === "saml:Assertion", "  -> root element name is 'saml:Assertion' (qualified, as written)");
    check(root.attrs.length === 3 && root.attrs[0]!.name === "xmlns:saml", "  -> xmlns:saml is the first attribute (namespace decl kept as an ordinary attr)");
    const subject = root.children.find((c) => c.type === "element" && c.name === "saml:Subject") as XmlElement;
    const nameId = subject.children[0] as XmlElement;
    const nameIdText = nameId.children[0] as { type: "text"; value: string };
    check(nameIdText.value === "a&amp;b", "  -> NameID text is preserved RAW as 'a&amp;b' (NOT decoded to 'a&b')");
  }
}

// An attribute value carrying entities is preserved RAW.
{
  const root = expectOk('<r x="a&amp;b&lt;c&#x2F;d" y="plain"/>', "an entity-bearing ATTRIBUTE value parses (self-closing root)");
  if (root !== null) {
    check(root.attrs[0]!.value === "a&amp;b&lt;c&#x2F;d", "  -> attribute value preserved RAW (a&amp;b&lt;c&#x2F;d, undecoded)");
    check(root.children.length === 0, "  -> self-closing element has no children");
  }
}

// Self-closing element nested among siblings.
{
  const root = expectOk("<root><a/><b>text</b><c/></root>", "self-closing elements <a/> and <c/> nested among siblings");
  if (root !== null) {
    check(root.children.length === 3, "  -> three child elements");
    check((root.children[0] as XmlElement).children.length === 0 && (root.children[2] as XmlElement).children.length === 0, "  -> <a/> and <c/> are empty");
    check(((root.children[1] as XmlElement).children[0] as { value: string }).value === "text", "  -> <b> carries its text");
  }
}

// Numeric char refs (decimal + hex) preserved RAW in text.
{
  const root = expectOk("<r>&#65;&#x42;&amp;&apos;&quot;&lt;&gt;</r>", "numeric (decimal + hex) and predefined char refs in text");
  if (root !== null) {
    const txt = (root.children[0] as { value: string }).value;
    check(txt === "&#65;&#x42;&amp;&apos;&quot;&lt;&gt;", "  -> all refs preserved RAW (decoding is the canonical-text layer's job)");
  }
}

// CDATA: stored as a text node whose RAW value RE-ESCAPES the literal content, so it decodes back identically.
{
  const root = expectOk("<r><![CDATA[<b> & </b>]]></r>", "a CDATA section parses to a text node");
  if (root !== null) {
    const txt = (root.children[0] as { type: "text"; value: string });
    check(txt.type === "text", "  -> CDATA becomes a TEXT node (not a distinct kind)");
    // Literal "<b> & </b>" is stored re-escaped so decodeXmlText(value) yields the literal back.
    check(txt.value === "&lt;b&gt; &amp; &lt;/b&gt;", "  -> CDATA literal stored re-escaped to entity form (digest-identical to plain escaped text)");
  }
}

// CDATA adjacent to plain text joins into one logical text run (CDATA is character data, not markup).
{
  const root = expectOk("<r>x<![CDATA[<y>]]>z</r>", "CDATA adjacent to text joins one character-data run");
  if (root !== null) {
    check(root.children.length === 1 && root.children[0]!.type === "text", "  -> a single text node spans text+CDATA+text");
    check((root.children[0] as { value: string }).value === "x&lt;y&gt;z", "  -> joined value re-escapes the CDATA portion (x&lt;y&gt;z)");
  }
}

// Comments are captured as XmlComment nodes and do NOT merge/split the surrounding text wrongly.
{
  const root = expectOk("<r>before<!-- a comment -->after</r>", "a comment between text yields SEPARATE text nodes around an XmlComment");
  if (root !== null) {
    check(root.children.length === 3, "  -> three children: text, comment, text (text not merged across the comment)");
    check(root.children[0]!.type === "text" && (root.children[0] as { value: string }).value === "before", "  -> first text is 'before'");
    check(root.children[1]!.type === "comment" && (root.children[1] as { value: string }).value === " a comment ", "  -> the comment node carries its inner text");
    check(root.children[2]!.type === "text" && (root.children[2] as { value: string }).value === "after", "  -> last text is 'after'");
  }
}

// A comment-bearing tree deep-equals its hand-built equivalent (comment node shape confirmed for c14n).
{
  const root = expectOk("<r><a>x</a><!--c--><b>y</b></r>", "a tree with an element-level comment parses");
  const hand = el("r", [], [el("a", [], [t("x")]), comment("c"), el("b", [], [t("y")])]);
  check(root !== null && elementEqual(root, hand), "  -> comment-bearing tree DEEP-EQUALS the hand-built equivalent");
}

// Nested namespaces: each xmlns decl is an attribute on its element; children inherit nothing structurally (the
// parser keeps decls as attrs; c14n re-derives scope). Deep-compare confirms the attr placement.
{
  const xml =
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">' +
    '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>idp</saml:Issuer></saml:Assertion>' +
    "</samlp:Response>";
  const hand = el(
    "samlp:Response",
    [a("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")],
    [
      el(
        "saml:Assertion",
        [a("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")],
        [el("saml:Issuer", [], [t("idp")])],
      ),
    ],
  );
  const root = expectOk(xml, "nested namespace declarations parse (each xmlns as an attr on its element)");
  check(root !== null && elementEqual(root, hand), "  -> nested-namespace tree DEEP-EQUALS the hand-built equivalent");
}

// Default-namespace declaration (bare xmlns) kept as an attribute named "xmlns".
{
  const root = expectOk('<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1"/>', "a default-namespace (bare xmlns) declaration parses");
  if (root !== null) {
    check(root.attrs[0]!.name === "xmlns" && root.attrs[0]!.value === "urn:oasis:names:tc:SAML:2.0:assertion", "  -> bare xmlns kept as attr name 'xmlns'");
  }
}

// Leading XML declaration + leading/trailing whitespace + a prolog comment are all tolerated around the root.
{
  const xml = '<?xml version="1.0" encoding="UTF-8"?>\n<!-- prolog comment -->\n  <root>ok</root>\n  ';
  const root = expectOk(xml, "XML declaration + prolog comment + surrounding whitespace tolerated");
  check(root !== null && root.name === "root" && (root.children[0] as { value: string } | undefined)?.value === "ok", "  -> document element is the single <root>");
}

// A UTF-8 BOM prefix on a byte input is stripped, not rejected.
{
  const bytes = new TextEncoder().encode("<root>bom</root>");
  const withBom = new Uint8Array(bytes.length + 3);
  withBom.set([0xef, 0xbb, 0xbf], 0);
  withBom.set(bytes, 3);
  const r = parseXml(withBom);
  check(r.ok === true && r.root.name === "root", "a leading UTF-8 BOM on bytes is stripped and the document parses");
}

// Astral (>0xFFFF) character in text survives (surrogate pair handled by the code-point scan).
{
  const root = expectOk("<r>\u{1F600}</r>", "an astral code point in text parses (surrogate-safe scan)");
  if (root !== null) check((root.children[0] as { value: string }).value === "\u{1F600}", "  -> the astral character is preserved");
}

// A non-ASCII element/attribute name (>=0x80 name chars) parses (some IdPs use Unicode names).
{
  const root = expectOk("<café réf=\"1\">x</café>", "a non-ASCII element + attribute name parses");
  if (root !== null) check(root.name === "café" && root.attrs[0]!.name === "réf", "  -> Unicode name + attr name preserved");
}

// ============================ RED: XXE / DTD / entity class ============================
console.log("\nred - DTD / entity (XXE / billion-laughs):\n");

expectFail('<!DOCTYPE foo><root/>', "a DOCTYPE declaration is rejected");
expectFail('<!DOCTYPE foo SYSTEM "http://evil/x.dtd"><root/>', "a DOCTYPE with an external SYSTEM id is rejected");
expectFail('<!DOCTYPE foo [ <!ENTITY x "y"> ]><root>&x;</root>', "an internal DTD subset with <!ENTITY is rejected");
expectFail('<!ENTITY x "y"><root/>', "a bare <!ENTITY declaration is rejected");
expectFail("<root>&xxe;</root>", "an undefined general entity reference &xxe; is rejected (no DTD to define it)");
expectFail('<root x="&xxe;"/>', "an undefined general entity reference in an attribute is rejected");
// Billion-laughs: even the DECLARATIONS are rejected by the DTD gate, long before any expansion is attempted.
expectFail(
  '<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>',
  "a billion-laughs-style nested-entity document is rejected at the DTD gate (before any expansion)",
);
// A literal '&' that does not begin a well-formed reference is rejected (must be &amp;).
expectFail("<root>a & b</root>", "a bare '&' in text (not a well-formed reference) is rejected");
expectFail('<root x="a & b"/>', "a bare '&' in an attribute value is rejected");
// A malformed numeric char ref is rejected.
expectFail("<root>&#zz;</root>", "a malformed numeric character reference (&#zz;) is rejected");
expectFail("<root>&#x;</root>", "an empty hex character reference (&#x;) is rejected");

// ============================ RED: illegal characters (WFC: Legal Character) ============================
console.log("\nred - illegal characters (WFC: Legal Character - NUL/control bytes):\n");

// A numeric character reference naming a C0 control (other than tab/LF/CR) or DEL is rejected even though its
// DIGIT syntax is well-formed - a SAML email-attribute value carrying &#x0; must never reach the SP as a
// literal NUL (an embedded NUL surviving into an audit-log actorEmail / session cookie).
expectFail("<root>&#0;</root>", "a decimal numeric ref naming NUL (&#0;) is rejected");
expectFail("<root>&#x0;</root>", "a hex numeric ref naming NUL (&#x0;) is rejected");
expectFail("<root>&#x1B;</root>", "a hex numeric ref naming ESC (&#x1B;) is rejected");
expectFail("<root>&#127;</root>", "a decimal numeric ref naming DEL (&#127;) is rejected");
expectFail('<root x="eve&#x0;il@example.com"/>', "a NUL numeric ref inside an ATTRIBUTE value is rejected (the SAML email-claim vector)");
// The three XML whitespace controls named numerically are still legal XML 1.0 Char values, so this is NOT
// over-broad: tab/LF/CR survive exactly as before.
{
  const root = expectOk("<r>&#9;&#10;&#13;</r>", "numeric refs naming tab/LF/CR (legal XML 1.0 Char) are still accepted");
  if (root !== null) check((root.children[0] as { value: string }).value === "&#9;&#10;&#13;", "  -> preserved RAW as usual");
}
// A LITERAL (non-entity-encoded) control byte needs no entity syntax at all, so validateEntityRefs alone would
// never see it; the attribute-value scan and the flushed-text scan must each catch it independently.
expectFail('<root x="eve\u0000il@example.com"/>', "a LITERAL raw NUL byte inside an attribute value is rejected (no entity encoding needed)");
expectFail("<root>eve\u0000il</root>", "a LITERAL raw NUL byte inside text content is rejected");
// parseCData re-escapes only &, < and > - a literal control byte inside CDATA reaches pendingText unchanged,
// so the flushText scan (which runs on the fully merged text+CDATA run) must catch it too.
expectFail("<root><![CDATA[eve\u0000il]]></root>", "a LITERAL raw NUL byte inside a CDATA section is rejected");

// ============================ RED: XSW wrapping ============================
console.log("\nred - XML Signature Wrapping (multiple roots / dupe attrs):\n");

expectFail("<a/><b/>", "two root elements are rejected");
expectFail("<root>one</root><root>two</root>", "two document elements with content are rejected");
// A wrapped SECOND Assertion as a second root - the classic XSW second-tree smuggle.
expectFail(
  '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1"><saml:Issuer>idp</saml:Issuer></saml:Assertion>' +
    '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a2"><saml:Issuer>evil</saml:Issuer></saml:Assertion>',
  "a wrapped SECOND top-level Assertion (second root) is rejected (XSW)",
);
// Trailing non-whitespace junk after the root is rejected.
expectFail("<root/> trailing-text", "trailing character data after the document element is rejected");

// Duplicate attribute, identical qualified name.
expectFail('<root id="a" id="b"/>', "a duplicate attribute (same qualified name) is rejected (attribute-pollution XSW)");
expectFail('<root ns:x="1" ns:x="2" xmlns:ns="urn:x"/>', "a duplicate PREFIXED attribute (same qualified name) is rejected");
// Namespace-aliased duplicate: two DIFFERENT prefixes bound to the SAME URI, same local name -> same expanded
// name -> rejected (the expanded-name dedupe, beyond bare qualified-name dedupe).
expectFail(
  '<root xmlns:p1="urn:same" xmlns:p2="urn:same" p1:attr="1" p2:attr="2"/>',
  "a namespace-ALIASED duplicate attribute (two prefixes, same URI + local) is rejected (expanded-name dedupe)",
);
// Sanity: two prefixes bound to DIFFERENT URIs with the same local name are NOT a duplicate (must be accepted).
{
  const root = expectOk(
    '<root xmlns:p1="urn:one" xmlns:p2="urn:two" p1:attr="1" p2:attr="2"/>',
    "two prefixes bound to DIFFERENT URIs, same local name, are NOT a duplicate (accepted)",
  );
  check(root !== null && root.attrs.length === 4, "  -> all four attributes retained");
}
// An unbound attribute prefix is a namespace error -> rejected (fail closed).
expectFail('<root foo:attr="1"/>', "an attribute with an UNBOUND prefix is rejected (namespace error, fail closed)");

// ============================ RED: caps ============================
console.log("\nred - resource caps (oversize / deep / wide):\n");

// Oversize: a body just over a tiny maxBytes.
expectFail("<root>" + "x".repeat(200) + "</root>", "an input exceeding maxBytes is rejected", { maxBytes: 50 });
// Too deep: nest deeper than maxDepth.
{
  let deep = "";
  for (let i = 0; i < 60; i++) deep += "<a>";
  deep += "z";
  for (let i = 0; i < 60; i++) deep += "</a>";
  expectFail(deep, "an input nested deeper than maxDepth is rejected", { maxDepth: 10 });
}
// Too many nodes: many sibling elements over maxNodes.
{
  let wide = "<root>";
  for (let i = 0; i < 100; i++) wide += "<a/>";
  wide += "</root>";
  expectFail(wide, "an input with more nodes than maxNodes is rejected", { maxNodes: 10 });
}

// ============================ RED: malformed well-formedness ============================
console.log("\nred - malformed (well-formedness, fail closed):\n");

expectFail("<a></b>", "mismatched tags (<a> closed by </b>) are rejected");
expectFail("<a><b></a>", "a mis-nested child (<b> not closed before </a>) is rejected");
expectFail("<a>", "an unclosed tag (no close) is rejected");
expectFail("<a><b></b>", "an unclosed PARENT tag is rejected");
expectFail("<a x=1/>", "an unquoted attribute value is rejected");
expectFail("<a x=y>z</a>", "an unquoted attribute value (bareword) is rejected");
expectFail("<a><</a>", "a stray '<' inside content is rejected");
expectFail("<a b=\"c\"d=\"e\"/>", "missing whitespace between attributes is rejected");
expectFail('<a x="<">y</a>', "a '<' inside an attribute value is rejected");
expectFail("<a>text", "text with no closing tag is rejected");
expectFail("", "an empty input (no document element) is rejected");
expectFail("   \n  ", "whitespace-only input (no document element) is rejected");
expectFail("not xml at all", "non-markup top-level content is rejected");
expectFail("<a>x</a><!-- ok --><b>y</b>", "a second root after a valid root+comment is rejected");

// Comments.
expectFail("<a><!-- unterminated </a>", "an unterminated comment is rejected");
expectFail("<a><!-- bad -- comment --></a>", "a '--' inside a comment is rejected");
expectFail("<!-- only a comment, no element -->", "a document that is only a comment (no element) is rejected");

// CDATA.
expectFail("<a><![CDATA[ unterminated </a>", "an unterminated CDATA section is rejected");
expectFail("<a>]]></a>", "a literal ']]>' in character data is rejected");

// A bare '&' immediately before a CDATA section must be rejected as a dangling/incomplete Reference,
// not "completed" using characters borrowed from the CDATA content merged in after it. Entity refs are now
// validated on each plain-text span the moment it is scanned off the source text - before it ever reaches
// pendingText, so a CDATA merge can never retroactively "complete" a reference that wasn't already complete on
// its own - in addition to the pre-existing final-flush check over the whole accumulated run.
console.log("\nred/green - bare '&' vs CDATA merge (per-span pre-CDATA entity validation):\n");

// The PoC: a bare '&' directly followed by a CDATA section spelling 'lt;' must NOT be "completed" into a
// well-formed &lt; by borrowing the CDATA's literal characters - the document is not well-formed XML.
expectFail("<a>&<![CDATA[lt;]]></a>", "PoC: a bare '&' immediately before CDATA is rejected (not completed by borrowed CDATA content)");
// Not just the 'lt;' shape - any CDATA content following a dangling '&' must be rejected.
expectFail("<a>&<![CDATA[amp;]]></a>", "a bare '&' before CDATA spelling 'amp;' is rejected too (not special-cased to 'lt;')");
// Other plain text may precede the dangling '&'; it is still dangling.
expectFail("<a>x&<![CDATA[lt;]]></a>", "a bare '&' preceded by other plain text, still immediately before CDATA, is rejected");
// A SECOND CDATA boundary (after an earlier, already-merged CDATA plus more plain text) must be checked too -
// every plain-text span is validated as it is scanned, not just the very first one in the run.
expectFail(
  "<a><![CDATA[x]]>y&<![CDATA[lt;]]></a>",
  "a bare '&' before a SECOND CDATA boundary (after an earlier CDATA + plain text) is also rejected",
);

// Legitimate CDATA usage must keep working (no false positives from the new pre-merge check).
{
  const root = expectOk("<a>&amp;<![CDATA[x]]></a>", "a COMPLETE entity ref immediately before CDATA is accepted (nothing dangling)");
  if (root !== null) check((root.children[0] as { value: string }).value === "&amp;x", "  -> raw value preserved as '&amp;x'");
}
{
  const root = expectOk("<a><![CDATA[x]]><![CDATA[y]]></a>", "two back-to-back CDATA sections with no separating text are accepted");
  if (root !== null) check((root.children[0] as { value: string }).value === "xy", "  -> merged value is 'xy'");
}
{
  const root = expectOk("<a><![CDATA[x]]>y&amp;z</a>", "CDATA followed by plain text containing a complete entity ref is accepted (other direction from the PoC)");
  if (root !== null) check((root.children[0] as { value: string }).value === "xy&amp;z", "  -> merged value is 'xy&amp;z'");
}
{
  // Exercises validation across TWO boundaries (CDATA, then a checked plain-text span, then a second CDATA),
  // not just a single one.
  const root = expectOk("<a><![CDATA[x]]>&amp;<![CDATA[y]]></a>", "a complete entity ref sandwiched between two CDATA sections is accepted");
  if (root !== null) check((root.children[0] as { value: string }).value === "x&amp;y", "  -> merged value is 'x&amp;y'");
}
{
  // The genuinely well-formed straddling case (independently checked against xml.dom.minidom / xmllint): a ']'
  // right before a CDATA section starting with '>' decodes to a literal ']]>' and IS valid XML. This is NOT
  // the bug the fix targets ('&' vs CDATA, not ']]>' vs CDATA) and must remain accepted.
  const root = expectOk("<a>]<![CDATA[]>]]></a>", "a ']' immediately before a CDATA section starting with '>' is accepted (decodes to literal ']]>', genuinely well-formed)");
  if (root !== null) check((root.children[0] as { value: string }).value === "]]&gt;", "  -> raw value is ']]&gt;' (decodes to the literal ']]>')");
}

// Many chained small text+CDATA pairs in one run must stay O(n), not reintroduce the O(n^2) cost an
// earlier version of this fix carried (validated on this exact PoC shape: it re-checked entity refs by slicing
// pendingText - the CDATA-merge accumulator - at every boundary; slicing a string that is ALSO grown by
// repeated "+=" forces a full re-flatten of the accumulated-so-far run on every slice, which is quadratic in
// the number of boundaries). This is a live pre-signature-check cost on the SAMLResponse ACS path
// (response.ts -> parser.ts), so a reintroduced quadratic here is a real CPU-exhaustion regression, not just an
// abstract complexity concern. Measured on this machine: 150,000 chained pairs (~2.1 MB, comfortably above a
// real SAML Response but well under this test's raised maxBytes) take ~20-30ms with a linear implementation
// versus 3+ SECONDS against the vulnerable slice-based checkpoint (a ~130x gap) - the bound below sits with wide
// margin under the quadratic case and well over the linear case, so this is decisive without being sensitive
// to ordinary machine-to-machine noise.
console.log("\nred/green - many chained CDATA sections must parse in O(n), not O(n^2):\n");
{
  let body = "";
  for (let i = 0; i < 150_000; i++) body += "x<![CDATA[y]]>";
  // Encode to bytes (as the real ACS path does: response.ts decodes the SAMLResponse POST body to a
  // Uint8Array before calling parseXml) rather than passing a string, whose byte cap is a conservative x3
  // estimate over an all-ASCII document and would reject this size well before parsing even starts.
  const doc = new TextEncoder().encode(`<a>${body}</a>`);
  const start = performance.now();
  const r = parseXml(doc, { maxBytes: 3_000_000 });
  const elapsedMs = performance.now() - start;
  check(r.ok === true, "150,000 chained tiny text+CDATA pairs (~2.1 MB) still parse successfully");
  check(elapsedMs < 1500, `parses in well under a second, nowhere near the 3s+ an O(n^2) re-check would take (took ${elapsedMs.toFixed(1)}ms)`);
}

// Processing instructions other than the XML declaration.
expectFail('<?xml-stylesheet href="x.xsl"?><root/>', "a non-declaration PI in the prolog is rejected");
expectFail("<root><?php evil() ?></root>", "a PI inside an element is rejected");
expectFail('<root/><?pi after?>', "a PI in the epilog is rejected");
expectFail('<?notxml version="1.0"?><root/>', "a leading PI that is not the XML declaration is rejected");

// A malformed '<!' that is neither comment nor CDATA nor (the banned) DOCTYPE.
expectFail("<root><!bogus></root>", "a malformed '<!' construct inside an element is rejected");
expectFail("<!bogus><root/>", "a malformed '<!' construct at the top level is rejected");

// ============================ RED: encoding ============================
console.log("\nred - encoding (UTF-8 only):\n");

// Non-UTF-8 bytes: a lone 0xFF is never valid UTF-8.
{
  const bad = new Uint8Array([0x3c, 0x72, 0x3e, 0xff, 0xfe, 0x3c, 0x2f, 0x72, 0x3e]); // <r> + invalid bytes + </r>
  const r = parseXml(bad);
  check(r.ok === false, "non-UTF-8 bytes (a stray 0xFF/0xFE) are rejected by the fatal decoder");
}
// A truncated multi-byte UTF-8 sequence (0xC3 with no continuation) is rejected.
{
  const bad = new Uint8Array([0x3c, 0x72, 0x3e, 0xc3, 0x3c, 0x2f, 0x72, 0x3e]); // <r> + 0xC3 (lead, no cont) + </r>
  const r = parseXml(bad);
  check(r.ok === false, "a truncated UTF-8 multi-byte sequence is rejected");
}
// A UTF-16-looking byte stream (NUL-interleaved ASCII) is not valid UTF-8 -> rejected.
{
  // "<r/>" as UTF-16LE: 3c 00 72 00 2f 00 3e 00. The 0x00 bytes are valid UTF-8 (NUL) but parse as control
  // chars; however the real defence is that a genuinely non-UTF-8 sequence is rejected - test a UTF-16BE BOM
  // body which begins FE FF (invalid UTF-8 lead bytes).
  const utf16be = new Uint8Array([0xfe, 0xff, 0x00, 0x3c, 0x00, 0x72, 0x00, 0x2f, 0x00, 0x3e]);
  const r = parseXml(utf16be);
  check(r.ok === false, "a UTF-16 (BE BOM) body is rejected as non-UTF-8");
}

// ---- summary ----
console.log("");
if (fails.length > 0) process.exitCode = 1;
if (fails.length > 0) {
  console.log("SAML PARSER VECTORS: " + passed + " passed, " + fails.length + " FAILED");
  for (const f of fails) console.log("   FAILED: " + f);
  process.exitCode = 1;
} else {
  console.log("SAML PARSER VECTORS PASS (" + passed + " checks)");
}
