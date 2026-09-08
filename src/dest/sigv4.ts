import { ab, hexEncode, sha256Hex, utf8 } from "../crypto/bytes.ts";

// AWS Signature Version 4, ported from the Go reference internal/source/sigv4.go and
// validated against the AWS SigV4 test-suite get-vanilla vector. Used to write archive
// objects to the customer's S3-compatible destination (AWS S3, R2's S3 endpoint, Google Cloud
// Storage's S3-interoperable endpoint, B2, Wasabi, MinIO). Azure Blob is NOT signed here: it
// speaks its own Shared Key scheme, in dest/azure-sharedkey.ts.
// SHA-256 and HMAC-SHA-256 come from Web Crypto.

/** The SigV4 algorithm identifier used in the Authorization header and the string-to-sign. */
export const SIGV4_ALGORITHM = "AWS4-HMAC-SHA256";
/** The SHA-256 hex of the empty payload, the x-amz-content-sha256 value for a body-less request. */
export const EMPTY_PAYLOAD_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/** The credentials and scope for SigV4 signing: the access key id, secret key, region and service
 * name. */
export interface SigV4Creds {
  accessKeyID: string;
  secretKey: string;
  region: string;
  service: string;
}

async function hmac(key: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", ab(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, ab(msg)));
}

async function hmacChain(key: Uint8Array, parts: string[]): Promise<Uint8Array> {
  let k = key;
  for (const p of parts) k = await hmac(k, utf8(p));
  return k;
}

/**
 * Computes the AWS SigV4 Authorization header value for a request, building the canonical request,
 * the string-to-sign and the derived signing key (validated against the AWS get-vanilla vector).
 *
 * @param method - the HTTP method.
 * @param canonicalURI - the canonical (encoded) request path.
 * @param canonicalQuery - the canonical query string (sorted, encoded), or empty.
 * @param headers - the request headers to sign; must include host, x-amz-date and
 *   x-amz-content-sha256.
 * @param payloadHash - the x-amz-content-sha256 value (the body hash or UNSIGNED-PAYLOAD).
 * @param amzDate - the ISO basic timestamp, YYYYMMDDTHHMMSSZ.
 * @param creds - the SigV4 credentials and scope.
 * @returns the Authorization header value.
 */
export async function signV4(method: string, canonicalURI: string, canonicalQuery: string, headers: Record<string, string>, payloadHash: string, amzDate: string, creds: SigV4Creds): Promise<string> {
  const dateStamp = amzDate.slice(0, 8);

  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v.trim();
  const sortedKeys = Object.keys(lower).sort();

  let canonicalHeaders = "";
  for (const k of sortedKeys) canonicalHeaders += `${k}:${lower[k]}\n`;
  const signedHeaders = sortedKeys.join(";");

  const canonicalRequest = [method, canonicalURI, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash].join("\n");
  const scope = `${dateStamp}/${creds.region}/${creds.service}/aws4_request`;
  const stringToSign = [SIGV4_ALGORITHM, amzDate, scope, await sha256Hex(utf8(canonicalRequest))].join("\n");

  const signingKey = await hmacChain(utf8(`AWS4${creds.secretKey}`), [dateStamp, creds.region, creds.service, "aws4_request"]);
  const signature = hexEncode(await hmac(signingKey, utf8(stringToSign)));

  return `${SIGV4_ALGORITHM} Credential=${creds.accessKeyID}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
}

/**
 * URI-encodes a string per AWS rules (only A-Za-z0-9-._~ left unescaped, the rest percent-encoded
 * with uppercase hex), matching the Go reference so object keys and query values with special
 * characters sign correctly.
 *
 * @param s - the string to encode (encoded as UTF-8 bytes first).
 * @returns the AWS-uri-encoded string.
 */
export function awsUriEncode(s: string): string {
  const bytes = utf8(s);
  let out = "";
  for (const c of bytes) {
    if ((c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39) || c === 0x2d || c === 0x2e || c === 0x5f || c === 0x7e) {
      out += String.fromCharCode(c);
    } else {
      out += `%${c.toString(16).toUpperCase().padStart(2, "0")}`;
    }
  }
  return out;
}

/**
 * Encodes an object key as a request path, AWS-uri-encoding each slash-separated segment while
 * keeping the slashes literal.
 *
 * HI-09: awsUriEncode deliberately leaves '.' unescaped (correct per the SigV4 spec), so a '.' or
 * '..' segment survives encoding unchanged; every caller then hands the result to `new URL(...)`
 * before signing, and that parser dot-segment-collapses (RFC 3986) such a segment, which can walk
 * the signed path outside the bucket segment entirely for path-style addressing. No object key this
 * format ever mints has a literal '.' or '..' PATH SEGMENT (a dotted segment like
 * "root.manifest.json" or ".write-probe" is unaffected -- only a segment that IS "." or ".."
 * triggers the collapse), so rejecting the shape here is safe and closes the collapse for every
 * S3Destination operation that funnels a key through this function, not just the restore path.
 *
 * @param key - the object key (may contain slashes).
 * @returns the encoded path, slashes preserved.
 * @throws Error when any '/'-separated segment is exactly "." or "..".
 */
export function encodePath(key: string): string {
  const segments = key.split("/");
  if (segments.some((s) => s === "." || s === "..")) {
    throw new Error(`object key must not contain a '.' or '..' path segment: ${key}`);
  }
  return segments.map(awsUriEncode).join("/");
}
