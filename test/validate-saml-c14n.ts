// Adversarial + conformance validator for the exc-c14n# canonicaliser (src/admin/saml/c14n.ts). It
// hand-builds XmlElement trees and asserts the EXACT canonical byte string for: a simple element; nested
// elements with inherited-but-UNUSED namespaces (the exclusive behaviour - they must NOT be pulled down); a
// USED namespace rendered once and NOT re-rendered on a descendant that re-uses the same prefix->value;
// attribute sort by (namespace-URI, local-name); namespace-before-attribute ordering; an empty element ->
// <a></a> (never self-closing); entity-bearing text and attributes (round-tripped through canonical-text);
// an InclusiveNamespaces PrefixList case; the xmlns="" reset condition; and the void-canon non-empty
// assertion. One vector is cross-checked against the W3C exc-c14n# specification's worked example.
//
// A c14n bug is a SILENT signature bypass, so every expectation is a byte-exact string equality, not a
// structural check. Run: node test/validate-saml-c14n.ts
//
// Node 25 strip-types; pure strings, no Node builtins beyond the test harness exit code.

import { canonicalize, envelopedCopy } from "../src/admin/saml/c14n.ts";
import type { XmlElement, XmlAttr, XmlChild } from "../src/admin/saml/xml-node.ts";

// This validator runs under Node (strip-types), but the project tsconfig ships Workers types only (no
// @types/node). Declare the single Node global we use so the file is tsc-clean under those flags without
// pulling in a node-types dependency. Matches the runtime: Node provides process.exit.
declare const process: { exit(code?: number): never; exitCode?: number };

// ---- tiny test harness ----
let passed = 0;
const fails: string[] = [];
function eq(got: string, want: string, desc: string): void {
  if (got === want) {
    passed++;
    console.log("  ok   " + desc);
  } else {
    fails.push(desc);
    console.log("  FAIL " + desc);
    console.log("        got  " + JSON.stringify(got));
    console.log("        want " + JSON.stringify(want));
  }
}
function check(cond: boolean, desc: string): void {
  if (cond) {
    passed++;
    console.log("  ok   " + desc);
  } else {
    fails.push(desc);
    console.log("  FAIL " + desc);
  }
}

// ---- tree builders ----
function el(name: string, attrs: XmlAttr[], children: XmlChild[]): XmlElement {
  return { type: "element", name, attrs, children };
}
function a(name: string, value: string): XmlAttr {
  return { name, value };
}
function text(value: string): XmlChild {
  return { type: "text", value };
}
function comment(value: string): XmlChild {
  return { type: "comment", value };
}
// canon: canonicalise and return the string, FAILING the test loudly if the canonicaliser errored (so a
// void-canon or guard rejection surfaces as a visible failure rather than an empty string).
function canon(root: XmlElement, opts?: Parameters<typeof canonicalize>[1]): string {
  const r = canonicalize(root, opts);
  if (!r.ok) {
    fails.push("canonicalize errored: " + r.reason);
    console.log("  FAIL canonicalize errored: " + r.reason);
    return "\x00<ERROR>";
  }
  return r.canonical;
}

console.log("exc-c14n# canonicaliser vectors\n");

// 1. SIMPLE element with one attribute and text.
eq(
  canon(el("doc", [a("x", "1")], [text("hello")])),
  '<doc x="1">hello</doc>',
  "simple element with attribute and text",
);

// 2. EMPTY element serialises as explicit <a></a>, never self-closing.
eq(canon(el("a", [], [])), "<a></a>", "empty element -> <a></a> (not self-closing)");

// 3. NESTED elements, inherited-but-UNUSED namespace must NOT be pulled down (the exclusive behaviour). The
//    outer declares xmlns:unused but neither it nor the inner uses that prefix; exclusive c14n must drop it.
eq(
  canon(el("outer", [a("xmlns:unused", "urn:never")], [el("inner", [], [text("y")])])),
  "<outer><inner>y</inner></outer>",
  "inherited-but-unused namespace is NOT pulled into the canonical form (exclusivity)",
);

// 4. USED namespace rendered ONCE on the element that uses it, and NOT re-rendered on a descendant that
//    re-uses the SAME prefix->value (no-redundant-declaration). Here ds: is used by both outer and inner;
//    it must appear only on outer.
eq(
  canon(
    el("ds:outer", [a("xmlns:ds", "urn:ds")], [el("ds:inner", [], [text("z")])]),
  ),
  '<ds:outer xmlns:ds="urn:ds"><ds:inner>z</ds:inner></ds:outer>',
  "used namespace rendered once, not re-rendered on a descendant reusing the same prefix->value",
);

// 4b. The SAME tree but the inner element ALSO declares the identical xmlns:ds: still only one declaration in
//     the output (the redundant inner declaration is suppressed by exclusivity).
eq(
  canon(
    el("ds:outer", [a("xmlns:ds", "urn:ds")], [el("ds:inner", [a("xmlns:ds", "urn:ds")], [text("z")])]),
  ),
  '<ds:outer xmlns:ds="urn:ds"><ds:inner>z</ds:inner></ds:outer>',
  "redundant identical descendant declaration is suppressed",
);

// 4c. A descendant that REBINDS the same prefix to a DIFFERENT value DOES render (it is not redundant).
eq(
  canon(
    el("ds:outer", [a("xmlns:ds", "urn:ds")], [el("ds:inner", [a("xmlns:ds", "urn:ds2")], [text("z")])]),
  ),
  '<ds:outer xmlns:ds="urn:ds"><ds:inner xmlns:ds="urn:ds2">z</ds:inner></ds:outer>',
  "a descendant rebinding the prefix to a different value renders the new declaration",
);

// 5. ATTRIBUTE SORT by (namespace-URI, then local-name). Attributes are given out of order with prefixes
//    bound to URIs; expected order: namespaceless attrs first (empty URI), among themselves by local name,
//    then namespaced attrs by URI then local. We also confirm namespace declarations precede all attributes.
//    Build: element <e> with xmlns:p="urn:p" xmlns:q="urn:q", attrs (authored order): q:b, a2, p:a, a1, q:a.
//    Sort keys: a1 (uri "", local "a1"), a2 (uri "", local "a2"), p:a (uri "urn:p", local "a"),
//    q:a (uri "urn:q", local "a"), q:b (uri "urn:q", local "b"). Namespaces (p,q) come before all of them and
//    are sorted by prefix (p before q).
eq(
  canon(
    el(
      "e",
      [
        a("xmlns:p", "urn:p"),
        a("xmlns:q", "urn:q"),
        a("q:b", "1"),
        a("a2", "2"),
        a("p:a", "3"),
        a("a1", "4"),
        a("q:a", "5"),
      ],
      [],
    ),
  ),
  '<e xmlns:p="urn:p" xmlns:q="urn:q" a1="4" a2="2" p:a="3" q:a="5" q:b="1"></e>',
  "attributes sorted by (namespace-URI, local-name); namespaces precede attributes, sorted by prefix",
);

// 5b. DEFAULT namespace declaration sorts BEFORE prefixed declarations. Both must be VISIBLY USED to render
//     under exclusive c14n: the element name is unprefixed (uses the default ns) AND carries a z:-prefixed
//     attribute (uses the z prefix), so both declarations render, default first.
eq(
  canon(
    el(
      "e",
      [a("xmlns:z", "urn:z"), a("xmlns", "urn:def"), a("z:k", "v")],
      [],
    ),
  ),
  '<e xmlns="urn:def" xmlns:z="urn:z" z:k="v"></e>',
  "default-namespace declaration sorts before prefixed declarations (both visibly used)",
);
// 5c. EXCLUSIVITY check on the same shape: if the z prefix is NOT used by name or attribute, exclusive c14n
//     DROPS the xmlns:z declaration even though it is declared on the element.
eq(
  canon(el("e", [a("xmlns:z", "urn:z"), a("xmlns", "urn:def")], [])),
  '<e xmlns="urn:def"></e>',
  "an unused prefixed declaration on the apex is dropped (only the visibly-used default ns renders)",
);

// 6. ENTITY-bearing text and attributes round-trip through the canonical-text model. Raw text "a < b & c > d"
//    is given pre-encoded as the parser would store it; the canonical form re-escapes <,&,> (but not the
//    apostrophe/quote in text). Attribute raw value with a quote and a tab.
eq(
  canon(el("t", [], [text("a &lt; b &amp; c &gt; d")])),
  "<t>a &lt; b &amp; c &gt; d</t>",
  "text entities decoded then re-escaped per the text model (< & > escaped)",
);
eq(
  canon(el("t", [a("v", 'x &quot;y&quot; &amp; z\tw')], [])),
  '<t v="x &quot;y&quot; &amp; z&#x9;w"></t>',
  "attribute entities decoded then re-escaped per the attribute model (quote, &, tab #x9)",
);
// 6b. A literal '>' in text MUST be escaped to &gt; (text model), but a literal '>' in an attribute is left
//     as '>'; a literal newline in an attribute becomes &#xA;.
eq(canon(el("t", [], [text("1 > 2")])), "<t>1 &gt; 2</t>", "literal > in text escaped to &gt;");
eq(canon(el("t", [a("v", "a>b")], [])), '<t v="a>b"></t>', "literal > in attribute is NOT escaped");
eq(canon(el("t", [a("v", "line1\nline2")], [])), '<t v="line1&#xA;line2"></t>', "newline in attribute -> &#xA;");

// 7. COMMENTS dropped in the base form; emitted in WithComments.
eq(
  canon(el("d", [], [comment(" hi "), text("x")])),
  "<d>x</d>",
  "base exc-c14n# drops comments",
);
eq(
  canon(el("d", [], [comment(" hi "), text("x")]), { withComments: true }),
  "<d><!-- hi -->x</d>",
  "WithComments emits comments verbatim",
);

// 8. xmlns="" RESET: an output ancestor establishes a non-empty default namespace; a descendant whose name is
//    UNPREFIXED but does NOT inherit (it explicitly undeclares with xmlns="") must emit xmlns="" to reset.
//    Build: <a xmlns="urn:d"><b xmlns=""><c/></b></a>. Per exc-c14n#: a renders xmlns="urn:d"; b is
//    unprefixed and visibly uses the default ns, its scope default is "" (undeclared), and the nearest output
//    ancestor (a) rendered a non-empty default -> b emits xmlns="". c is unprefixed, default is "" and the
//    nearest output ancestor that rendered a non-empty default is a, but b already reset to "" so the output
//    default in scope is "" -> c emits nothing.
eq(
  canon(
    el("a", [a("xmlns", "urn:d")], [el("b", [a("xmlns", "")], [el("c", [], [])])]),
  ),
  '<a xmlns="urn:d"><b xmlns=""><c></c></b></a>',
  'xmlns="" reset emitted exactly once where the default-ns context must be cleared',
);

// 8b. An unprefixed element with NO default namespace anywhere emits NO xmlns="" (nothing to reset).
eq(
  canon(el("a", [], [el("b", [], [])])),
  "<a><b></b></a>",
  'no spurious xmlns="" when there is no default namespace to reset',
);

// 9. INCLUSIVENAMESPACES PrefixList: a prefix that is IN SCOPE but NOT visibly utilised would be dropped by
//    pure exclusive c14n; listing it in the PrefixList forces it to render on the apex. Build outer with
//    xmlns:soap and xmlns:keep where only soap is used by the element name; without the list, keep is
//    dropped; with PrefixList ["keep"], keep is rendered on the apex too.
const inclTree = el(
  "soap:Envelope",
  [a("xmlns:soap", "urn:soap"), a("xmlns:keep", "urn:keep")],
  [el("soap:Body", [], [text("b")])],
);
eq(
  canon(inclTree),
  '<soap:Envelope xmlns:soap="urn:soap"><soap:Body>b</soap:Body></soap:Envelope>',
  "without a PrefixList, an in-scope-but-unused namespace (keep) is dropped (exclusive)",
);
eq(
  canon(inclTree, { inclusiveNamespacePrefixes: ["keep"] }),
  '<soap:Envelope xmlns:keep="urn:keep" xmlns:soap="urn:soap"><soap:Body>b</soap:Body></soap:Envelope>',
  "InclusiveNamespaces PrefixList [keep] forces the unused 'keep' declaration to render on the apex",
);
// 9b. The PrefixList override applies only at the APEX; a descendant that uses 'keep' would still render it
//     normally, but an UNUSED 'keep' below the apex is not force-rendered (exclusive below the apex). Confirm
//     the inclusive 'keep' is not duplicated onto the Body.
eq(
  canon(
    el("soap:Envelope", [a("xmlns:soap", "urn:soap"), a("xmlns:keep", "urn:keep")], [el("soap:Body", [], [el("soap:Inner", [], [])])]),
    { inclusiveNamespacePrefixes: ["keep"] },
  ),
  '<soap:Envelope xmlns:keep="urn:keep" xmlns:soap="urn:soap"><soap:Body><soap:Inner></soap:Inner></soap:Body></soap:Envelope>',
  "PrefixList override is apex-only; 'keep' not re-rendered on descendants",
);

// 10. The 'xml' reserved prefix is always in scope and is NEVER emitted as xmlns:xml, but an xml:lang
//     attribute is kept and sorted by the XML-namespace URI.
eq(
  canon(el("p", [a("xml:lang", "en"), a("id", "7")], [])),
  '<p id="7" xml:lang="en"></p>',
  "xml:lang kept (xml prefix never declared); sorted after the no-namespace 'id' by URI",
);

// 11. VOID-CANON / non-empty assertion: a well-formed named element ALWAYS yields non-empty output. We also
//     confirm the canonicaliser REJECTS a malformed root (empty name) rather than returning "".
{
  const r = canonicalize({ type: "element", name: "", attrs: [], children: [] });
  check(r.ok === false, "canonicaliser rejects a nameless root (void-canon guard) instead of returning empty");
}
// And a real (even empty) element is asserted non-empty by canonicalize() itself returning ok with content.
{
  const r = canonicalize(el("x", [], []));
  check(r.ok === true && r.canonical.length > 0, "a real empty element canonicalises to non-empty (<x></x>)");
}

// 12. ENVELOPED-signature transform: removing the Signature subtree before canonicalising drops exactly that
//     subtree (by object identity) and nothing else. Build an assertion with a child Signature; envelopedCopy
//     it out; canonicalise; the Signature content must be gone but siblings remain.
{
  const sig = el("ds:Signature", [a("xmlns:ds", "urn:ds")], [el("ds:SignedInfo", [], [text("SI")])]);
  const assertion = el(
    "Assertion",
    [a("ID", "_a1")],
    [el("Issuer", [], [text("idp")]), sig, el("Subject", [], [text("alice")])],
  );
  const stripped = envelopedCopy(assertion, sig);
  eq(
    canon(stripped),
    '<Assertion ID="_a1"><Issuer>idp</Issuer><Subject>alice</Subject></Assertion>',
    "enveloped-signature transform removes exactly the Signature subtree (by identity), siblings preserved",
  );
  // The original tree is untouched (envelopedCopy is non-mutating): the assertion still has 3 children.
  check(assertion.children.length === 3, "envelopedCopy does not mutate the original tree");
  // A DIFFERENT Signature object with the same QName is NOT removed (identity, not name match) - the XSW
  // defence. Here we pass a freshly-built lookalike; nothing is stripped.
  const lookalike = el("ds:Signature", [], []);
  const notStripped = envelopedCopy(assertion, lookalike);
  check(notStripped.children.length === 3, "envelopedCopy removes by object identity, not by QName (a lookalike Signature is kept)");
}

// 13. W3C exc-c14n# SPEC CROSS-CHECK. The specification's illustrative example canonicalises the element
//     <n2:elem2> (with default ns "http://example.org" in scope from an ancestor, and n1 declared-but-unused)
//     to exactly: <n2:elem2 xmlns:n2="http://www.bar.org">  ...content...  </n2:elem2> with the default and
//     n1 namespaces NOT pulled down (they are not visibly utilised by elem2's subtree). We reproduce the
//     visibly-relevant core: an element n2:elem2 that uses only the n2 prefix, nested under ancestors that
//     declared a default ns and an unused n1; canonicalising the elem2 subtree alone (with that inherited
//     context) must render ONLY xmlns:n2 and drop the inherited default + n1. inheritedContext supplies the
//     ancestor scope.
{
  const inherited = new Map<string, string>([
    ["", "http://example.org"], // default ns in scope from ancestor (unused by elem2's subtree)
    ["n1", "http://example.net"], // n1 declared by ancestor (unused)
  ]);
  const elem2 = el(
    "n2:elem2",
    [a("xmlns:n2", "http://www.bar.org")],
    [text("   ")], // whitespace content as in the spec example
  );
  eq(
    canon(elem2, { inheritedContext: inherited }),
    '<n2:elem2 xmlns:n2="http://www.bar.org">   </n2:elem2>',
    "W3C exc-c14n# spec cross-check: only the visibly-used n2 namespace is rendered; inherited default + n1 dropped",
  );
}

// 14. An attribute that REBINDS sorting via its namespace: two attributes with the same local name but
//     different namespace URIs sort by URI. Confirms the primary key is the URI, not the prefix string.
//     p->urn:zzz, q->urn:aaa; attrs p:x and q:x; URI order puts q:x (urn:aaa) before p:x (urn:zzz).
eq(
  canon(el("e", [a("xmlns:p", "urn:zzz"), a("xmlns:q", "urn:aaa"), a("p:x", "1"), a("q:x", "2")], [])),
  '<e xmlns:p="urn:zzz" xmlns:q="urn:aaa" q:x="2" p:x="1"></e>',
  "attribute primary sort key is the namespace URI, not the prefix (q:x before p:x because urn:aaa < urn:zzz)",
);

// 15. IDP-2: xsi:type AttributeValue + an ANCESTOR-DECLARED prefix used only inside the value. The real
//     ADFS/Shibboleth shape: an AttributeValue carries xsi:type="xs:string" where xsi: and xs: are declared
//     on an ANCESTOR (here supplied via inheritedContext, as if on the Assertion). When the AttributeValue
//     subtree is canonicalised alone:
//       - xsi IS visibly utilised (it is the prefix of the real xsi:type ATTRIBUTE) -> exclusive c14n renders
//         xmlns:xsi on the apex.
//       - xs is NOT visibly utilised (it appears ONLY inside the attribute VALUE "xs:string"; exclusive c14n
//         never inspects attribute values) -> WITHOUT the PrefixList, xmlns:xs is DROPPED. This is exactly the
//         digest-mismatch that wrongly rejects a genuine ADFS assertion until InclusiveNamespaces is honoured.
//     Attribute sort: xmlns declarations precede attrs; xsi:type sorts under the xsi namespace URI.
{
  const inherited = new Map<string, string>([
    ["xsi", "http://www.w3.org/2001/XMLSchema-instance"],
    ["xs", "http://www.w3.org/2001/XMLSchema"],
  ]);
  const av = el("saml:AttributeValue", [a("xsi:type", "xs:string")], [text("alice@example.com")]);
  // 15a WITHOUT the PrefixList: xsi rendered (visibly used by the attribute), xs dropped (only in the value).
  eq(
    canon(av, { inheritedContext: inherited }),
    '<saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">alice@example.com</saml:AttributeValue>',
    "IDP-2: xsi:type renders xmlns:xsi (visibly used) but DROPS the value-only xs prefix WITHOUT a PrefixList",
  );
  // 15b WITH PrefixList ["xs"]: the value-only xs prefix is force-rendered from the ancestor context too.
  eq(
    canon(av, { inheritedContext: inherited, inclusiveNamespacePrefixes: ["xs"] }),
    '<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">alice@example.com</saml:AttributeValue>',
    "IDP-2: InclusiveNamespaces PrefixList [xs] force-renders the ancestor-declared, value-only xs prefix",
  );
  // 15c the saml: prefix of the element name is itself ancestor-declared and visibly used (the element name),
  //     so it renders even without the list; confirm a saml: binding in the inherited context is rendered.
  const inherited2 = new Map<string, string>([
    ["saml", "urn:oasis:names:tc:SAML:2.0:assertion"],
    ["xsi", "http://www.w3.org/2001/XMLSchema-instance"],
    ["xs", "http://www.w3.org/2001/XMLSchema"],
  ]);
  eq(
    canon(av, { inheritedContext: inherited2, inclusiveNamespacePrefixes: ["xs"] }),
    '<saml:AttributeValue xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">alice@example.com</saml:AttributeValue>',
    "IDP-2: ancestor-declared saml: (element-name prefix, visibly used) renders alongside the PrefixList xs",
  );
}

// ---- summary ----
console.log("");
if (fails.length > 0) process.exitCode = 1;
if (fails.length > 0) {
  console.log("SAML c14n VECTORS: " + passed + " passed, " + fails.length + " FAILED");
  for (const f of fails) console.log("   FAILED: " + f);
  process.exit(1);
}
console.log("SAML c14n VECTORS PASS (" + passed + " checks)");
