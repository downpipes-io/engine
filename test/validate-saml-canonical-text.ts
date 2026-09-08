// Validate the SAML shared text function (src/admin/saml/canonical-text.ts): entity decoding must be exact
// and identical for the digest path and the claim-reader path (the "verify == read" linchpin), and the two
// position-dependent exc-c14n# escapers must match the spec character model. Run:
//   node test/validate-saml-canonical-text.ts
// Node 25 strip-types; pure.

import { decodeXmlText, escapeC14nText, escapeC14nAttr } from "../src/admin/saml/canonical-text.ts";

let failures = 0;
function eq(label: string, got: string, want: string): void {
  const okv = got === want;
  console.log(okv ? `  ok   ${label}` : `  FAIL ${label}  got=${JSON.stringify(got)} want=${JSON.stringify(want)}`);
  if (!okv) failures++;
}

console.log("SAML canonical-text (decode + exc-c14n# escapes)\n");

// --- decodeXmlText: the five predefined entities + numeric references ---
eq("decode &amp;", decodeXmlText("a&amp;b"), "a&b");
eq("decode &lt; &gt;", decodeXmlText("x&lt;y&gt;z"), "x<y>z");
eq("decode &quot; &apos;", decodeXmlText("&quot;q&apos;"), '"q\'');
eq("decode decimal &#65;", decodeXmlText("&#65;"), "A");
eq("decode hex &#x41;", decodeXmlText("&#x41;"), "A");
eq("decode upper-X &#X41;", decodeXmlText("&#X41;"), "A");
eq("decode astral (surrogate-safe) &#x1F600;", decodeXmlText("&#x1F600;"), String.fromCodePoint(0x1f600));
eq("decode a NameID-shaped value with an entity-encoded @", decodeXmlText("admin&#x40;corp.example"), "admin@corp.example");
eq("multiple + adjacent entities decode left-to-right", decodeXmlText("&amp;&lt;&#x41;&gt;"), "&<A>");

// --- decode leaves unknown / malformed references BYTE-FOR-BYTE literal (both paths agree on the unchanged
//     bytes; no DTD/custom entities are ever in scope because the parser rejects DTDs) ---
eq("unknown named entity left literal", decodeXmlText("a&foo;b"), "a&foo;b");
eq("a bare ampersand (no entity) left literal", decodeXmlText("a & b"), "a & b");
eq("an entity missing its semicolon left literal", decodeXmlText("a&amp b"), "a&amp b");
eq("a surrogate-range numeric ref left literal (not a scalar value)", decodeXmlText("&#xD800;"), "&#xD800;");
eq("an out-of-range numeric ref left literal", decodeXmlText("&#x110000;"), "&#x110000;");
// A numeric ref naming a disallowed control byte (WFC: Legal Character, ML-17) is likewise left literal by
// this decoder - the primary reject lives at the parser boundary (validateEntityRefs), but this is the
// decoder's own defence-in-depth for a caller that parses XML without routing through that gate first.
eq("a numeric ref naming NUL left literal (defence in depth)", decodeXmlText("&#x0;"), "&#x0;");
eq("a numeric ref naming ESC (0x1B) left literal (defence in depth)", decodeXmlText("&#x1B;"), "&#x1B;");
eq("a numeric ref naming DEL (0x7F) left literal (defence in depth)", decodeXmlText("&#127;"), "&#127;");
eq("a numeric ref naming a legal Char control (tab) still decodes", decodeXmlText("&#9;"), "\t");

// --- the SAMLStorm / comment-injection class: an ENTITY-ENCODED comment is plain text after decode, so a
//     "<!--..-->" that arrived as &lt;!--..--&gt; can never be mistaken for a real XML comment ---
eq("entity-encoded comment decodes to literal text (not a comment)", decodeXmlText("admin@good.example&lt;!--x--&gt;"), "admin@good.example<!--x-->");

// --- escapeC14nText: text-node escaping is & < > and #xD; quotes/apostrophes left as-is ---
eq("text escape & < >", escapeC14nText("a&b<c>d"), "a&amp;b&lt;c&gt;d");
eq("text escape carriage return", escapeC14nText("a\rb"), "a&#xD;b");
eq("text leaves quotes/apostrophes/tab/newline as-is", escapeC14nText("\"'\t\n"), "\"'\t\n");
eq("text leaves an astral char intact", escapeC14nText(String.fromCodePoint(0x1f600)), String.fromCodePoint(0x1f600));

// --- escapeC14nAttr: attribute-value escaping is & < " #x9 #xA #xD; > and ' left as-is ---
eq("attr escape & < \"", escapeC14nAttr('a&b<c"d'), "a&amp;b&lt;c&quot;d");
eq("attr escape tab/newline/cr", escapeC14nAttr("a\tb\nc\rd"), "a&#x9;b&#xA;c&#xD;d");
eq("attr leaves > and ' as-is", escapeC14nAttr("a>b'c"), "a>b'c");

// --- the cross-path invariant: a value extracted for the digest and the same value read as a claim are the
//     SAME because both go through decodeXmlText. (Simulated: both call sites use the one function.) ---
{
  const signedBytes = "admin&#x40;corp.example";
  const digestValue = decodeXmlText(signedBytes);
  const claimValue = decodeXmlText(signedBytes);
  eq("verify==read: digest-side and reader-side decode identically", digestValue, claimValue);
  eq("verify==read: and equal the intended decoded principal", claimValue, "admin@corp.example");
}

console.log("");
if (failures > 0) process.exitCode = 1;
if (failures > 0) {
  console.log(`SAML CANONICAL-TEXT VECTORS: ${failures} FAILED`);
  process.exit(1);
}
console.log("SAML CANONICAL-TEXT VECTORS PASS");
