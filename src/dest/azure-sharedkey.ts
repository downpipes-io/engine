// Azure Storage Shared Key authentication, for the Azure Blob destination.
//
// WHY THIS EXISTS AT ALL, when every other destination this engine writes to is reached with SigV4.
// Azure Blob Storage does not speak the S3 API. It is not an S3-compatible store behind a different host,
// the way Cloudflare R2 and Google Cloud Storage are: it is a different wire protocol with a different
// authentication scheme, a different request shape and a different object model. Pointing the
// S3-compatible destination at an Azure endpoint answers 403 AuthenticationFailed on the first call,
// measured against a real storage account. So Azure needs its own signer, and this is it.
//
// THE SCHEME. Azure builds a canonical string from a FIXED-POSITION list of eleven standard headers, then
// every x-ms-* header sorted, then a canonicalised resource path with its query parameters sorted. The
// signature is HMAC-SHA256 over that string, keyed by the account key (which is base64, and must be
// DECODED before use, not hashed as text). The result rides in `Authorization: SharedKey <account>:<sig>`.
//
// THE TRAP THAT MAKES THIS WORTH KNOWN-ANSWER VECTORS. The eleven standard fields are POSITIONAL: an
// absent Content-Length is an empty line, not an omitted line, so a signer that skips empty headers
// produces a string that is the right shape and the wrong length, and every request fails with a 403 that
// says nothing about which line was dropped. Microsoft publishes worked examples of the string-to-sign,
// and azure-sharedkey.knownAnswer.ts checks this implementation against them character for character
// rather than checking that some signature was produced.
//
// CONTENT-LENGTH IS THE SPECIFIC ONE. Azure's own rule changed with the API version: a zero
// content length is signed as an EMPTY string, not as "0". A signer that writes "0" authenticates every
// body-bearing request correctly and fails every GET, HEAD and DELETE, which reads like a permission
// problem rather than a signing one.

import { base64Encode, utf8 } from "../crypto/bytes.ts";

/** The Azure storage account and its key. accountKeyBase64 is the key exactly as the Azure portal shows
 *  it: standard base64, which this module decodes before use. */
export interface AzureSharedKeyCreds {
  account: string;
  accountKeyBase64: string;
}

/** One request to sign. `path` is the resource path WITHOUT the account (Azure's canonicalised resource
 *  prepends it), and `query` is the request's query parameters, unsorted. */
export interface AzureSignInput {
  method: string;
  path: string;
  query?: Record<string, string>;
  /** Headers to sign and send. Every x-ms-* header is signed; the eleven standard fields below are read
   *  from here where present. `x-ms-date` is added by this module when absent. */
  headers: Record<string, string>;
  /* * The request body length. Signed as an EMPTY line when zero, per the rule. */
  contentLength?: number;
}

/** The API version this module signs for. It is part of every request as `x-ms-version` and it is not a
 *  cosmetic header: the empty-string rule for a zero Content-Length below is specific to and
 *  later, so changing this constant without re-reading that rule silently breaks every body-less call. */
export const AZURE_API_VERSION = "2021-12-02";

/** THE STANDARD_FIELD_ORDER is positional and its length is load-bearing. Azure's string-to-sign is the
 *  VERB followed by exactly these eleven lines, present or not: an absent header contributes an empty
 *  line rather than disappearing. Named here rather than inlined so the count cannot drift silently. */
const STANDARD_FIELDS = [
  "content-encoding",
  "content-language",
  "content-length",
  "content-md5",
  "content-type",
  "date",
  "if-modified-since",
  "if-match",
  "if-none-match",
  "if-unmodified-since",
  "range",
] as const;

/** decodeBase64 turns the portal's account key into bytes. STANDARD base64, not base64url: an account key
 *  contains "+" and "/" and a url-safe decoder would silently produce different key bytes and a 403 that
 *  names nothing. atob is available in workerd and in Node. */
function decodeBase64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * canonicalizedHeaders builds the x-ms-* half of the string to sign: every header whose name begins
 * `x-ms-`, lower-cased, sorted by name, one `name:value` line each, with internal whitespace collapsed.
 *
 * The sort is by the LOWER-CASED name, and it is an ordinal sort on the string rather than a locale one:
 * a locale-aware comparison orders some characters differently from Azure's own and produces a canonical
 * string that differs only in line order, which is invisible in a diff and fatal on the wire.
 */
function canonicalizedHeaders(headers: Record<string, string>): string {
  const rows = Object.entries(headers)
    .map(([k, v]) => [k.toLowerCase(), String(v).replace(/\s+/g, " ").trim()] as const)
    .filter(([k]) => k.startsWith("x-ms-"))
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return rows.map(([k, v]) => `${k}:${v}\n`).join("");
}

/**
 * canonicalizedResource builds the resource half: `/<account><path>`, then one line per query parameter
 * as `name:value`, lower-cased and sorted.
 *
 * A parameter with no value still contributes its line with an empty value, for the same positional
 * reason the standard fields do.
 */
function canonicalizedResource(account: string, path: string, query?: Record<string, string>): string {
  const base = `/${account}${path.startsWith("/") ? path : `/${path}`}`;
  if (query === undefined) return base;
  const names = Object.keys(query)
    .map((k) => k.toLowerCase())
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  if (names.length === 0) return base;
  const lines = names.map((n) => {
    const raw = Object.entries(query).find(([k]) => k.toLowerCase() === n)?.[1] ?? "";
    return `${n}:${raw}`;
  });
  return `${base}\n${lines.join("\n")}`;
}

/** What signAzureSharedKey produced: the canonical string (returned so a known-answer test can grade the
 *  STRING rather than only the signature), and the headers to send. */
export interface AzureSigned {
  stringToSign: string;
  authorization: string;
  headers: Record<string, string>;
}

/**
 * signAzureSharedKey builds the Shared Key Authorization header for one request.
 *
 * It returns the string it signed as well as the header, because a signature that disagrees is
 * undiagnosable without it: two signers that differ by one empty line produce two opaque base64 strings
 * and no way to see which line moved. Every vector in azure-sharedkey.knownAnswer.ts grades the string.
 *
 * @param input - the request to sign.
 * @param creds - the storage account and its base64 key.
 * @param now - the timestamp for x-ms-date, injectable so a vector can pin it.
 * @returns the canonical string, the Authorization header value, and the full header set to send.
 */
export async function signAzureSharedKey(input: AzureSignInput, creds: AzureSharedKeyCreds, now: () => Date = () => new Date()): Promise<AzureSigned> {
  const headers: Record<string, string> = { ...input.headers };
  // x-ms-date carries the timestamp and the standard `Date` line stays EMPTY. Both are documented and
  // Azure accepts either, but signing both is a mismatch: the Date line would then have to carry the same
  // instant, and any skew between the two produces a 403 nothing explains.
  if (!Object.keys(headers).some((k) => k.toLowerCase() === "x-ms-date")) headers["x-ms-date"] = now().toUTCString();
  if (!Object.keys(headers).some((k) => k.toLowerCase() === "x-ms-version")) headers["x-ms-version"] = AZURE_API_VERSION;

  const lookup = (name: string): string => {
    const hit = Object.entries(headers).find(([k]) => k.toLowerCase() === name);
    return hit === undefined ? "" : String(hit[1]);
  };

  const fields = STANDARD_FIELDS.map((f) => {
    if (f === "content-length") {
      // The rule: a zero length signs as EMPTY, never "0". See this module's header for why
      // getting this wrong looks exactly like a permission problem.
      const n = input.contentLength ?? 0;
      return n === 0 ? "" : String(n);
    }
    // `date` is deliberately always empty: x-ms-date carries the timestamp and is signed among the
    // x-ms-* headers instead.
    if (f === "date") return "";
    return lookup(f);
  });

  const stringToSign = `${input.method.toUpperCase()}\n${fields.join("\n")}\n${canonicalizedHeaders(headers)}${canonicalizedResource(creds.account, input.path, input.query)}`;

  const key = await crypto.subtle.importKey("raw", decodeBase64(creds.accountKeyBase64) as unknown as ArrayBuffer, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, utf8(stringToSign) as unknown as ArrayBuffer));
  const authorization = `SharedKey ${creds.account}:${base64Encode(sig)}`;
  return { stringToSign, authorization, headers: { ...headers, Authorization: authorization } };
}
