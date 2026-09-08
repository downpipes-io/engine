// THE single shared XML text-normalisation function for the native SAML Service Provider. This is the
// load-bearing "verify == read" control against the most likely real exploit: the
// chosen pure-JS parser (txml) does NOT decode XML entities and stores comments as plain strings, so if the
// Reference-digest path and the claim-reader path (NameID / Issuer / Audience / attributes) decoded text
// differently, an attacker could sign one byte-sequence and have the SP CONSUME a different principal. Both
// paths MUST route every text value through decodeXmlText() here, so the bytes that were signed and the value
// the SP authorises on are derived identically.
//
// It also provides the two position-dependent escapers exc-c14n# requires when SERIALISING a node for the
// digest (text-node escaping differs from attribute-value escaping). Keeping decode + both escapes in one
// module means the c14n serialiser and the claim reader share exactly one character model.
//
// Node 25 strip-types + Workers compatible: pure string functions, no DOM, no Node builtins.

import { isDisallowedControlCodePoint } from "./parser-lex.ts";

// decodeXmlText decodes the FIVE predefined XML entities (&amp; &lt; &gt; &quot; &apos;) and numeric
// character references (&#DDD; decimal, &#xHH; hex, including astral code points via surrogate-safe
// String.fromCodePoint). It does NOT decode any other named entity: a SAML SP rejects DTDs (saml/parser.ts
// raw-byte gate), so no custom entities are ever in scope, and an unknown "&foo;" is left BYTE-FOR-BYTE
// literal - which keeps both the digest path and the reader path consistent (they leave the same thing
// alone). An out-of-range or malformed numeric reference is likewise left literal rather than guessed.
export function decodeXmlText(raw: string): string {
  return raw.replace(/&(#[xX][0-9a-fA-F]+|#[0-9]+|amp|lt|gt|quot|apos);/g, (match: string, body: string): string => {
    switch (body) {
      case "amp":
        return "&";
      case "lt":
        return "<";
      case "gt":
        return ">";
      case "quot":
        return '"';
      case "apos":
        return "'";
      default: {
        // A numeric character reference: body is "#DDD" or "#xHH".
        const hex = body[1] === "x" || body[1] === "X";
        const cp = hex ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
        // Reject anything outside the Unicode scalar range, and the surrogate range (D800-DFFF, which is not a
        // valid scalar value), leaving it literal so the two paths agree on the unchanged bytes.
        if (!Number.isFinite(cp) || cp < 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return match;
        // Defence in depth: validateEntityRefs (parser-lex.ts) is the primary gate for this, but this decoder
        // is reachable directly by other callers that parse XML without necessarily routing through that gate
        // first, so refuse to MATERIALISE a disallowed control byte here too, leaving it literal like the
        // out-of-range/surrogate cases above (both paths still agree on the unchanged bytes).
        if (isDisallowedControlCodePoint(cp)) return match;
        try {
          return String.fromCodePoint(cp);
        } catch {
          return match;
        }
      }
    }
  });
}

// The & and < escapes are shared by both the text and attribute character models; a fix here applies to
// both. The per-mode escapes are supplied as the extras map. Iteration is over code points so an astral
// character is never split.
function escapeC14n(s: string, extras: Map<string, string>): string {
  let out = "";
  for (const ch of s) {
    if (ch === "&") out += "&amp;";
    else if (ch === "<") out += "&lt;";
    else out += extras.get(ch) ?? ch;
  }
  return out;
}

// TEXT_EXTRAS adds the text-node escapes on top of the shared & and < : the close-angle and a carriage
// return (#xD). Quotes and apostrophes are NOT special in text content and are left as-is.
const TEXT_EXTRAS = new Map<string, string>([
  [">", "&gt;"],
  ["\r", "&#xD;"],
]);

// ATTR_EXTRAS adds the attribute-value escapes on top of the shared & and < : the double quote and the
// whitespace controls tab (#x9), newline (#xA) and carriage return (#xD). It does NOT escape > or ' (they
// are not special inside a double-quoted attribute in canonical form).
const ATTR_EXTRAS = new Map<string, string>([
  ['"', "&quot;"],
  ["\t", "&#x9;"],
  ["\n", "&#xA;"],
  ["\r", "&#xD;"],
]);

// escapeXmlMarkup escapes a string for safe interpolation into XML MARKUP, covering both the attribute-value
// and text-node positions in one pass by encoding all five predefined entities (& < > " '). It is the exact
// inverse, for those five entities, of decodeXmlText above, so a value escaped here round-trips verbatim when
// the SP reads it back (verify == read). This is the single shared markup escaper: metadata.ts and any other
// markup builder import it rather than re-implementing the same character loop, so a fix here cannot drift from
// a private copy. It is conservative: it over-escapes harmlessly (' and > in a double-quoted attribute, or " in
// text, need not be escaped) but can never under-escape, so no interpolated value can break out of an attribute
// or element content. Order is implicit in the map literal but & must be handled before producing other
// entities; the character-by-character scan guarantees a literal '&' is encoded as &amp; and never becomes part
// of a spurious entity.
export function escapeXmlMarkup(s: string): string {
  let out = "";
  for (const ch of s) {
    if (ch === "&") out += "&amp;";
    else if (ch === "<") out += "&lt;";
    else if (ch === ">") out += "&gt;";
    else if (ch === '"') out += "&quot;";
    else if (ch === "'") out += "&apos;";
    else out += ch;
  }
  return out;
}

// escapeC14nText applies the C14N / exc-c14n# character model for a TEXT node. Used by the c14n serialiser
// when emitting a text node for the Reference digest.
export function escapeC14nText(s: string): string {
  return escapeC14n(s, TEXT_EXTRAS);
}

// escapeC14nAttr applies the exc-c14n# character model for an ATTRIBUTE VALUE. Used by the c14n serialiser
// for attributes.
export function escapeC14nAttr(s: string): string {
  return escapeC14n(s, ATTR_EXTRAS);
}
