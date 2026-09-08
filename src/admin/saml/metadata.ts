// The SP SAML metadata document the customer uploads to their IdP, built for a SIGN-ONLY, SP-INITIATED-by-
// default Service Provider. It is a small, fixed-shape <md:EntityDescriptor> describing a single SPSSODescriptor
// with one HTTP-POST AssertionConsumerService - exactly what an IdP needs to register the SP and direct a
// signed assertion back to the engine's ACS.
//
// SECURITY (the load-bearing reason this is its own audited module): every value interpolated into the markup -
// the SP entityID, the NameID format, and the ACS URL - originates (transitively) from operator-supplied
// connection config. They are escaped here for BOTH the attribute and text character models (& < > " '), so a
// hostile spEntityId / nameIdFormat / acsUrl such as '"/><evil>' CANNOT close an attribute, close the start
// tag, or inject an element. The validator proves the output still parses (via the hardened parser) to exactly
// one EntityDescriptor with no injected node, and that each value round-trips verbatim through the shared
// decodeXmlText (so "what we escaped" reads back identically under the SP's one character model).
//
// SIGN-ONLY (v1): the SP does NOT sign AuthnRequests (AuthnRequestsSigned="false") and holds no decryption key,
// so the descriptor carries NO <md:KeyDescriptor> at all. WantAssertionsSigned="true" tells the IdP the SP
// refuses an unsigned assertion (it pins the IdP signing certs out-of-band and ignores the assertion's own
// KeyInfo). EncryptedAssertion is out of scope in v1, so there is nothing to advertise a public key for.
//
// PURE: a deterministic string builder - no clock, no crypto, no fetch, no I/O. Node 25 strip-types + Workers
// compatible: pure string functions, no DOM, no Node builtins, no enums. Australian English; no em dashes.

import type { SamlConnection } from "../idpconn.ts";
import { escapeXmlMarkup } from "./canonical-text.ts";

// SAML 2.0 metadata + protocol + binding URIs. Fixed constants (never interpolated from input).
const MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata";
const PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
const BINDING_HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

// XML markup escaping is provided by the shared escapeXmlMarkup in canonical-text.ts: it covers both the
// attribute-value and text-node positions in one pass (& < > " ') and is the exact inverse, for those five
// predefined entities, of the SP's decodeXmlText. Importing the shared escaper keeps the encoder paired with
// the canonical decoder so every interpolated value round-trips verbatim (verify == read) and a fix cannot
// drift from a private copy here.

// buildSpMetadata returns the EntityDescriptor XML for the SIGN-ONLY SP described by `conn`, with the single
// HTTP-POST AssertionConsumerService at `acsUrl` (the engine's per-connection ACS endpoint). The caller passes
// the resolved ACS URL because it is route-derived (origin + the connection id), not stored on the connection.
//
// Shape (md: prefix bound to the metadata namespace; no default namespace, so a reader's prefix resolution is
// unambiguous and the document carries no unintended namespace inheritance):
//   <md:EntityDescriptor xmlns:md="..." entityID="<spEntityId>">
//     <md:SPSSODescriptor protocolSupportEnumeration="...:protocol"
//         AuthnRequestsSigned="false" WantAssertionsSigned="true">
//       <md:NameIDFormat><nameIdFormat></md:NameIDFormat>
//       <md:AssertionConsumerService Binding="...:HTTP-POST"
//         Location="<acsUrl>" index="0" isDefault="true"/>
//     </md:SPSSODescriptor>
//   </md:EntityDescriptor>
//
// No <md:KeyDescriptor>: v1 is sign-only - the SP neither signs AuthnRequests nor decrypts assertions, so it
// advertises no key. Pure string; deterministic; no clock.
export function buildSpMetadata(conn: SamlConnection, acsUrl: string): string {
  const entityId = escapeXmlMarkup(conn.spEntityId);
  const nameIdFormat = escapeXmlMarkup(conn.nameIdFormat);
  const acs = escapeXmlMarkup(acsUrl);

  // Built with a leading XML declaration and 2-space indentation. The parser tolerates (and ignores) the
  // declaration and the surrounding whitespace; the indentation is purely for the human who pastes this into
  // an IdP admin console. Every interpolated value above is already escaped for attribute + text contexts.
  return (
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<md:EntityDescriptor xmlns:md="' + MD_NS + '" entityID="' + entityId + '">\n' +
    '  <md:SPSSODescriptor protocolSupportEnumeration="' + PROTOCOL_NS + '"' +
    ' AuthnRequestsSigned="false" WantAssertionsSigned="true">\n' +
    "    <md:NameIDFormat>" + nameIdFormat + "</md:NameIDFormat>\n" +
    '    <md:AssertionConsumerService Binding="' + BINDING_HTTP_POST + '"' +
    ' Location="' + acs + '" index="0" isDefault="true"/>\n' +
    "  </md:SPSSODescriptor>\n" +
    "</md:EntityDescriptor>\n"
  );
}
