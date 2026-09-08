// The SP-INITIATED <samlp:AuthnRequest> builder and the HTTP-Redirect binding encoder for the native SAML 2.0
// Service Provider. This is the OUTBOUND half of the SP: the engine mints a request id + issue instant, builds
// the AuthnRequest XML, DEFLATE+base64+URL-encodes it per the HTTP-Redirect binding, and redirects the browser
// to the IdP's SSO URL with SAMLRequest + RelayState query parameters. The matching INBOUND half (the ACS that
// receives, verifies and consumes the signed Response/Assertion) is dsig.ts + assertion.ts.
//
// SECURITY / SCOPE NOTES:
//  - The SP does NOT sign its own AuthnRequest in this build (no Signature, no SigAlg/Signature query
//    params on the redirect). The request is integrity-bound only by the InResponseTo round-trip (the IdP echoes
//    our request ID into SubjectConfirmationData/@InResponseTo, which assertion.ts pins). So nothing here touches
//    crypto or a private key.
//  - Every interpolated value is XML-escaped (the same escaping discipline the metadata builder uses): a hostile
//    spEntityId / nameIdFormat / acsUrl / Destination cannot inject markup or a second element. p.id is escaped
//    too; the DO that MINTS the id is responsible for emitting a syntactically valid XML ID (a SAML id is
//    "_<hex>" - it starts with '_' or a letter, never a digit), so this pure builder only escapes, never mints.
//  - The HTTP-Redirect binding uses RAW DEFLATE (RFC 1951), i.e. CompressionStream("deflate-raw"), NOT "deflate"
//    (which prepends a 2-byte zlib header + trailing Adler-32 that the SAML binding forbids). The DEFLATE output
//    is then STANDARD base64 (RFC 2045 alphabet, '+' '/' '='), per the binding - NOT base64url. The returned
//    base64 string is the value to URL-encode; buildRedirectUrl does that encoding via URLSearchParams.
//  - PURE / deterministic: this module reads NO clock and mints NO id/nonce. The request id and the issue
//    instant are ARGUMENTS (the validator passes fixed values; the DO passes a freshly minted id + new Date()).
//
// Node 25 strip-types + Workers compatible: Web Crypto-adjacent only (CompressionStream / TextEncoder /
// URL / btoa), no DOM, no Node builtins, no enums, explicit fields. Australian English; no em dashes.

import { ab } from "../../crypto/bytes.ts";
import type { SamlConnection } from "../idpconn.ts";
// G203: the SSO START-path signal ledger. recordSsoFail is written ONLY by the ACS (callback) wrapper, so a
// sign-in that dies while BUILDING the AuthnRequest reaches NO recorder at all: the user sees "the sign-in
// button dead-ends with a 500" and the pack shows ZERO SSO failures, so support rules SSO out on a clean
// aggregate while not one user can even reach the IdP.
import { noteSamlSignal } from "../saml-signals.ts";

// The SAML namespaces. samlp is the protocol namespace (the AuthnRequest / NameIDPolicy elements); saml is the
// assertion namespace (the Issuer element, which is in the assertion namespace even inside a protocol message).
const NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
const NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
// The SP consumes the assertion over HTTP-POST (the inbound binding the ACS implements); the AuthnRequest
// advertises that as the ProtocolBinding so the IdP POSTs its Response back rather than redirecting it.
const PROTOCOL_BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

// The request parameters the caller (the DO) supplies. id + issueInstant are MINTED by the caller (kept out of
// this pure builder for determinism); acsUrl is the SP's own Assertion Consumer Service URL (the same value the
// ACS later pins as ctx.acsUrl, so the redirect and the inbound check agree on one string).
export interface AuthnRequestParams {
  id: string; // a syntactically valid XML ID ("_<hex>"); minted by the DO, only escaped here
  issueInstant: string; // RFC-3339 / XSD dateTime; minted by the DO
  acsUrl: string; // the SP's AssertionConsumerServiceURL (must equal the ctx.acsUrl the ACS pins)
}

// escapeXml is the single conservative escaper used for both attribute values and element text. In "attr" mode it
// escapes the five characters that could break out of a double-quoted attribute or inject markup (& < > " '); in
// "text" mode it escapes only the three significant in text content (& < >). (> is not strictly required in an
// attribute, and ' is not required inside a double-quoted value, but escaping both is harmless and matches the
// metadata builder's discipline.) This is the ONLY way a value reaches the XML, so a hostile entityId/url cannot
// inject a tag or a stray attribute. Order matters: escape & FIRST so an already-present "&" does not get
// double-encoded into a spurious entity, then the angle brackets and quotes.
function escapeXml(s: string, mode: "attr" | "text"): string {
  let out = "";
  for (const ch of s) {
    if (ch === "&") out += "&amp;";
    else if (ch === "<") out += "&lt;";
    else if (ch === ">") out += "&gt;";
    else if (mode === "attr" && ch === '"') out += "&quot;";
    else if (mode === "attr" && ch === "'") out += "&apos;";
    else out += ch;
  }
  return out;
}

// escapeXmlAttr and escapeXmlText are named wrappers that keep the intent (attribute vs text) explicit at each
// call site while delegating to the single escapeXml loop.
function escapeXmlAttr(s: string): string {
  return escapeXml(s, "attr");
}

function escapeXmlText(s: string): string {
  return escapeXml(s, "text");
}

// buildAuthnRequestXml builds the SP-initiated AuthnRequest XML string. It is PURE: every value is taken from
// the connection (already validated by validateIdpConnection) or the caller-minted params, and EVERY
// interpolated value is XML-escaped. The element shape is fixed:
//
//   <samlp:AuthnRequest ID=".." Version="2.0" IssueInstant=".." Destination="<idpSsoUrl>"
//       ProtocolBinding="..:HTTP-POST" AssertionConsumerServiceURL="<acsUrl>">
//     <saml:Issuer><spEntityId></saml:Issuer>
//     <samlp:NameIDPolicy Format="<nameIdFormat>" AllowCreate="true"/>
//   </samlp:AuthnRequest>
//
// No XML declaration is emitted (the HTTP-Redirect binding DEFLATEs the bare element; an XML declaration is
// optional and many IdPs dislike one inside a redirect payload). No SP signature is added (sign-only SP).
export function buildAuthnRequestXml(conn: SamlConnection, p: AuthnRequestParams): string {
  const id = escapeXmlAttr(p.id);
  const issueInstant = escapeXmlAttr(p.issueInstant);
  const destination = escapeXmlAttr(conn.idpSsoUrl);
  const acsUrl = escapeXmlAttr(p.acsUrl);
  const issuer = escapeXmlText(conn.spEntityId);
  const nameIdFormat = escapeXmlAttr(conn.nameIdFormat);

  // Built as a single string with the namespace declarations on the root element. Attributes are emitted in a
  // fixed order; the IdP does not care about attribute order (and the SP never signs this request, so no
  // canonical form is needed). The Issuer is in the saml: (assertion) namespace; NameIDPolicy and the root are
  // in the samlp: (protocol) namespace.
  return (
    `<samlp:AuthnRequest xmlns:samlp="${NS_SAMLP}" xmlns:saml="${NS_SAML}"` +
    ` ID="${id}" Version="2.0" IssueInstant="${issueInstant}"` +
    ` Destination="${destination}"` +
    ` ProtocolBinding="${PROTOCOL_BINDING_POST}"` +
    ` AssertionConsumerServiceURL="${acsUrl}">` +
    `<saml:Issuer>${issuer}</saml:Issuer>` +
    `<samlp:NameIDPolicy Format="${nameIdFormat}" AllowCreate="true"/>` +
    `</samlp:AuthnRequest>`
  );
}

// ---- standard base64 (RFC 2045 alphabet, with '=' padding) ----
// The HTTP-Redirect binding encodes the DEFLATE bytes with STANDARD base64 (alphabet '+' '/', '=' padded), NOT
// the base64url the shared bytes.ts helper produces. We implement it locally (no new dependency) over the bytes.
// btoa is available in workerd and Node 25; we feed it a binary string built byte-by-byte (so a high byte is not
// mis-decoded as a multi-byte char). This is encode-only; the inbound base64 decode for the ACS lives in dsig.ts.
const B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function base64StdEncode(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  // Process full 3-byte groups -> 4 base64 chars.
  for (; i + 3 <= bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = bytes[i + 1]!;
    const b2 = bytes[i + 2]!;
    out += B64_STD[b0 >> 2];
    out += B64_STD[((b0 & 0x03) << 4) | (b1 >> 4)];
    out += B64_STD[((b1 & 0x0f) << 2) | (b2 >> 6)];
    out += B64_STD[b2 & 0x3f];
  }
  // Tail: 1 or 2 remaining bytes, padded with '='.
  const rem = bytes.length - i;
  if (rem === 1) {
    const b0 = bytes[i]!;
    out += B64_STD[b0 >> 2];
    out += B64_STD[(b0 & 0x03) << 4];
    out += "==";
  } else if (rem === 2) {
    const b0 = bytes[i]!;
    const b1 = bytes[i + 1]!;
    out += B64_STD[b0 >> 2];
    out += B64_STD[((b0 & 0x03) << 4) | (b1 >> 4)];
    out += B64_STD[(b1 & 0x0f) << 2];
    out += "=";
  }
  return out;
}

// ---- raw DEFLATE via the Web Streams CompressionStream ----
// deflateRaw runs the input bytes through CompressionStream("deflate-raw") - RFC 1951 raw DEFLATE with NO zlib
// wrapper (the "deflate" format would add a 2-byte header + Adler-32 trailer the SAML binding forbids). It reads
// the whole compressed stream into one Uint8Array. workerd and Node 25 both implement "deflate-raw".
async function deflateRaw(input: Uint8Array): Promise<Uint8Array> {
  const cs = new CompressionStream("deflate-raw");
  const writer = cs.writable.getWriter();
  // Await the write then the close so a write rejection (e.g. an internal CompressionStream error) surfaces
  // here synchronously rather than only via the readable side. ab() narrows to the ArrayBuffer-backed Uint8Array
  // the stream writer's BufferSource parameter requires (the same boundary coercion the crypto port uses; every
  // buffer here is ArrayBuffer-backed, never SharedArrayBuffer).
  await writer.write(ab(input));
  await writer.close();
  const reader = cs.readable.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      chunks.push(value);
      total += value.length;
    }
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

// deflateRedirectParam takes the AuthnRequest XML and produces the SAMLRequest VALUE for the HTTP-Redirect
// binding: raw-DEFLATE the UTF-8 XML, then STANDARD base64. The returned string is NOT yet URL-encoded - it is
// the value the caller (buildRedirectUrl, via URLSearchParams) URL-encodes into the query string. Keeping the
// URL-encoding out of here means the same base64 value can be embedded by any binding/transport that does its
// own escaping, and the round-trip test can base64-decode + inflate this exact string back to the XML bytes.
export async function deflateRedirectParam(xml: string): Promise<string> {
  const xmlBytes = new TextEncoder().encode(xml);
  const deflated = await deflateRaw(xmlBytes);
  return base64StdEncode(deflated);
}

// The full redirect parameters: the request id/issueInstant/acsUrl plus the RelayState (opaque round-trip state
// the IdP echoes back, e.g. an encoding of the connId + the post-login return path). RelayState is UNTRUSTED
// from this builder's perspective (a caller could pass anything); it is URL-encoded as an opaque value and can
// NEVER inject a second query parameter because URLSearchParams percent-encodes '&' and '='.
export interface RedirectParams extends AuthnRequestParams {
  relayState: string;
}

// buildRedirectUrl builds the full HTTP-Redirect URL the browser is sent to:
//   <conn.idpSsoUrl>?SAMLRequest=<urlencoded deflate+base64>&RelayState=<urlencoded relayState>
// It parses idpSsoUrl with the URL API (idpSsoUrl was validated https-only at config time) and SETS the two
// query parameters via URLSearchParams, so:
//   - a value containing '&' or '=' cannot smuggle a second parameter (it is percent-encoded);
//   - '+' in the base64 is percent-encoded to %2B (URLSearchParams encodes '+'), so the IdP does not misread it
//     as a space when it form-decodes the query (a classic SAML-redirect base64 corruption that we avoid).
// If idpSsoUrl already carries a query string, the new parameters are appended (set() adds them); we do not
// blindly overwrite an unrelated existing query, but a same-named existing SAMLRequest/RelayState would be
// replaced (a configured SSO URL should not carry those, so this is the safe behaviour).
export async function buildRedirectUrl(conn: SamlConnection, p: RedirectParams): Promise<string> {
  // G203: the stored idpSsoUrl is the start path's first killer, so it is checked FIRST -- fail fast, before any
  // XML is built. `new URL()` THROWS on an unusable value, and the throw propagates out of the start route as a
  // bare 500: "the sign-in button for our SAML connection dead-ends", with ZERO SSO failures in the pack because
  // recordSsoFail is only ever written by the ACS. The connection was accepted at SAVE time, so an unusable URL
  // here is a stored-record corruption or a validator drift -- and every sign-in on the connection dies on it.
  // The URL VALUE never rides; only the closed class. The throw is re-raised unchanged.
  let url: URL;
  try {
    url = new URL(conn.idpSsoUrl);
  } catch (e) {
    noteSamlSignal("sso-start-saml-url-invalid");
    throw e;
  }
  const xml = buildAuthnRequestXml(conn, { id: p.id, issueInstant: p.issueInstant, acsUrl: p.acsUrl });
  // G203: the DEFLATE leg. A CompressionStream fault (or a runtime without "deflate-raw") means NO redirect URL
  // can be built at all, and the throw again reaches the browser as a bare 500. Record the closed class BEFORE
  // re-throwing, so the caller's behaviour is byte-identical and the evidence survives the browser tab.
  let samlRequest: string;
  try {
    samlRequest = await deflateRedirectParam(xml);
  } catch (e) {
    noteSamlSignal("sso-start-compression-failed");
    throw e;
  }
  // set() replaces any existing same-named param; for the SAML redirect params this is exactly right (the SSO
  // URL must not pre-carry a SAMLRequest/RelayState). Other pre-existing query params on the SSO URL are kept.
  url.searchParams.set("SAMLRequest", samlRequest);
  url.searchParams.set("RelayState", p.relayState);
  return url.toString();
}
