// Generalized OpenID Connect ID-token verifier. This is the cryptographic core of the native OIDC
// Relying Party (the Cloudflare-free federated front door): given an id_token and the IdP's JWKS, it
// verifies the signature and EVERY security-relevant claim, then returns the verified claims. It is a
// deliberate generalization of access.ts (the Cloudflare Access JWT verifier), widened from RS256-only
// to an RS256+ES256 allowlist and from a single fixed issuer/audience to per-connection config, plus the
// OIDC-specific checks Access never needed (nonce, azp, at_hash, issuer substitution). It is PURE and
// INJECTED: it takes the already-fetched JWKS (the caller owns discovery, the per-issuer JWKS cache,
// kid-rotation and the guarded fetch), so this module is exercisable directly by the validator with
// crafted tokens and stub keys. The path under test is the production path.
//
// SECURITY DISCIPLINE (the validator encodes the attacks):
//  - ALG is chosen from the CONNECTION's allowlist and the matched JWK's kty, NEVER from the token
//    header. The header alg is only checked for MEMBERSHIP in the allowlist; the actual verify algorithm
//    is derived from the key type. This defeats alg:none, RS256<->HS256 confusion (an attacker HMACing
//    with the RSA public key) and key-type confusion: HS* and "none" are never in an asymmetric
//    connection's allowlist, and an RS256 header against an EC key (or vice versa) is rejected.
//  - ES256 signatures are raw R||S (IEEE P1363, 64 bytes) exactly as JWS specifies; Web Crypto's ECDSA
//    verify consumes that format directly. A DER-encoded signature (the WebAuthn/COSE shape passkey.ts
//    handles) simply fails to verify, which is the correct rejection. There is NO DER path here.
//  - aud must include our client_id; and azp MUST equal our client_id whenever aud is multi-valued or an
//    azp claim is present (the audience-injection defence access.ts's bare auds.includes lacked).
//  - nonce MUST equal the single-use value minted at /start (replay/id-token-injection defence).
//  - iss is matched EXACTLY against the connection's configured issuer, with two explicit, bounded
//    exceptions: Entra multitenant (substitute the token's tid into the template, then exact-match, and
//    gate the tid against an allowlist) and a small fixed set of accepted issuer spellings (Google emits
//    a bare and an https form). A cloudflareaccess.com / IP-literal / localhost / non-https issuer is
//    rejected at BOTH config and verify time (assertSafeIssuer), so a native subject can never collide
//    with the bare issuer|sub of a Cloudflare Access subject.
//  - exp/nbf/iat are checked with a small symmetric clock skew; sub must be a non-empty string.
//
// Node 25 strip-types + Workers-runtime compatible: Web Crypto only, no Node builtins, no enums,
// explicit field declarations, type-only imports.

import { ab, b64urlDecode, constantTimeEqual, utf8 } from "../crypto/bytes.ts";

// A JWK as it appears in an IdP JWKS. RSA keys carry n/e; EC (P-256) keys carry crv/x/y. Only the fields
// this verifier reads are typed; anything else on the key is ignored.
export interface JWK {
  kid?: string;
  kty: string;
  alg?: string;
  use?: string;
  // RSA
  n?: string;
  e?: string;
  // EC
  crv?: string;
  x?: string;
  y?: string;
}
export interface JWKS {
  keys: JWK[];
}

// The acceptable signing algorithms. Deliberately a CLOSED two-value set: RS256 (RSASSA-PKCS1-v1_5 +
// SHA-256, the OIDC baseline every provider supports) and ES256 (ECDSA P-256 + SHA-256, common at Okta,
// Auth0, others). RS384/512 and ES384/512 are intentionally NOT here in v1 (no surveyed top-10 IdP
// requires them); adding one is a one-line allowlist + a Web Crypto hash/curve change, gated by a test.
export type IdTokenAlg = "RS256" | "ES256";

export interface VerifyIdTokenOptions {
  // The exact issuer this connection expects (already assertSafeIssuer-validated at config time). For a
  // single-tenant provider this is the whole story. For Entra multitenant use tenantIdSubstitution; for
  // a provider that emits more than one issuer spelling use acceptIssuerVariants.
  expectedIssuer: string;
  // Our OAuth client_id; the token's aud must include it and azp (when applicable) must equal it.
  clientId: string;
  // The connection's signing-algorithm allowlist. The verify algorithm is derived from the matched JWK's
  // kty; the header alg is only checked for membership here. Must be non-empty.
  allowedAlgs: readonly IdTokenAlg[];
  // The single-use nonce minted at /start and stored in the DO state record. The id_token's nonce claim
  // must equal it exactly. Pass null ONLY for flows that genuinely carry no nonce (none of the OIDC
  // presets do; the value is always set for the authorization-code flow).
  nonce: string | null;
  // Epoch SECONDS (the JWT time base). The caller passes Math.floor(Date.now()/1000).
  now: number;
  // Symmetric clock-skew tolerance in seconds (default 60). Applied to exp (token valid until exp+skew),
  // nbf (valid from nbf-skew) and a future-iat sanity check.
  maxSkewSec?: number;
  // Entra multitenant (/common, /organizations): the token carries a tid claim; substitute it into the
  // template (which must contain the literal "{tenantid}") and exact-match the result against iss, and
  // require tid to be in acceptedTenantIds. When set, expectedIssuer is ignored in favour of the
  // substituted template. This is the ONLY way iss validation accepts a value not fixed at config time,
  // and it is still an exact match plus a tenant allowlist.
  tenantIdSubstitution?: { template: string; acceptedTenantIds: readonly string[] };
  // A small fixed set of additional accepted issuer spellings (e.g. Google emits both
  // "https://accounts.google.com" and the bare "accounts.google.com"). Each is matched EXACTLY; this is
  // not a wildcard. Ignored when tenantIdSubstitution is set.
  acceptIssuerVariants?: readonly string[];
  // When the matching authorization-code response also returned an access_token AND the id_token carries
  // an at_hash claim, bind them: at_hash must equal base64url(SHA-256(access_token)[0..15]). When the
  // claim is absent, or no access token is supplied, this check is skipped (at_hash is optional in the
  // plain code flow). Supplying the token never makes a missing claim fail.
  accessToken?: string;
}

// VerifyIdTokenResult is a DISCRIMINATED UNION on ok so callers get TypeScript narrowing: on the ok:true
// branch sub/iss/emailVerified/claims are mandatory (the verifier only returns success once they are known),
// and on the ok:false branch only the failure fields are present. This removes the need for non-null
// assertions in callers gating session minting and gives compile-time protection if a caller forgets the
// check. On success: the immutable subject identifier (becomes oidc:<connId>|<iss>|<sub>), the verified
// issuer, the optional email + email_verified flag (the adapter gates pending-invite binding on the flag),
// and the full verified claims object so the provider adapter can extract groups/roles by the connection's
// configured claim name. Everything on the success branch comes from the SIGNATURE-VERIFIED payload only.
// On failure: a prose reason and an optional stable, switchable code. "kid_not_found" drives the Phase-2
// caller's ONE JWKS refetch on key rotation (without matching the prose reason); "tenant_not_accepted" is a
// diagnostic marker the callback layer projects into the support pack (an Entra multitenant id_token whose
// tid is not in acceptedTenantIds), so it never has to string-match a wrong-issuer prose reason.
export type VerifyIdTokenResult =
  | {
      ok: true;
      sub: string;
      iss: string;
      email?: string;
      emailVerified: boolean;
      claims: Record<string, unknown>;
    }
  | { ok: false; reason: string; code?: "kid_not_found" | "tenant_not_accepted" };

// MAX_ID_TOKEN_LENGTH bounds the id_token this verifier will decode (DoS). 32 KiB is far above any real
// token, including ones carrying group/role claims, and far below a memory-pressure threat.
const MAX_ID_TOKEN_LENGTH = 32768;

function fail(reason: string): VerifyIdTokenResult {
  return { ok: false, reason };
}

function decodeJSON(part: string): unknown {
  return JSON.parse(new TextDecoder().decode(b64urlDecode(part)));
}

// The issuer and fetch-endpoint safety screens (isIpLiteral / canonicalHost / assertSafeIssuer /
// assertSafeFetchEndpoint / issuerLooksUnsafe) live in oidc-issuer-safety.ts. The two public guards are
// re-exported here so existing importers keep importing them from this module.
export { assertSafeFetchEndpoint, assertSafeIssuer } from "./oidc-issuer-safety.ts";

import { issuerLooksUnsafe } from "./oidc-issuer-safety.ts";

// matchIssuer returns the canonical accepted issuer string the token presented, or null when the token's
// iss is not accepted. The three modes are mutually exclusive and all reduce to an EXACT string match:
//  - tenantIdSubstitution (Entra /common): build the expected issuer by substituting the token's tid into
//    the template, require tid to be in the allowlist, then require iss to equal the built string.
//  - acceptIssuerVariants (e.g. Google): iss must be the configured issuer OR one of the listed spellings.
//  - default: iss must equal expectedIssuer.
// The matched value is then screened by issuerLooksUnsafe (defence in depth on top of the config-time
// assertSafeIssuer and the oidc:<connId>| subject prefix).
function matchIssuer(rawIss: unknown, payload: Record<string, unknown>, opts: VerifyIdTokenOptions): string | null {
  if (typeof rawIss !== "string" || rawIss.length === 0) return null;
  let accepted: string | null = null;
  if (opts.tenantIdSubstitution) {
    const tid = payload.tid;
    if (typeof tid !== "string" || tid.length === 0) return null;
    if (!opts.tenantIdSubstitution.acceptedTenantIds.includes(tid)) return null;
    if (!opts.tenantIdSubstitution.template.includes("{tenantid}")) return null;
    const expected = opts.tenantIdSubstitution.template.replace("{tenantid}", tid);
    accepted = rawIss === expected ? rawIss : null;
  } else if (opts.acceptIssuerVariants && opts.acceptIssuerVariants.length > 0) {
    accepted = rawIss === opts.expectedIssuer || opts.acceptIssuerVariants.includes(rawIss) ? rawIss : null;
  } else {
    accepted = rawIss === opts.expectedIssuer ? rawIss : null;
  }
  if (accepted === null || issuerLooksUnsafe(accepted)) return null;
  return accepted;
}

// importVerifyKey imports a JWK as a non-extractable Web Crypto verify key, selecting the algorithm from
// the FAMILY (derived from the matched key's kty), not from the token header. An RSA key is imported for
// RSASSA-PKCS1-v1_5/SHA-256; an EC key for ECDSA P-256. importKey throws on a malformed key, which the
// caller maps to a clean rejection.
async function importVerifyKey(jwk: JWK, family: "RSA" | "EC"): Promise<CryptoKey> {
  if (family === "RSA") {
    // Narrow n/e to definite strings (exactOptionalPropertyTypes: an explicit undefined is not a valid
    // JsonWebKey field). A key matched as RSA but missing n/e is malformed and fails closed.
    if (typeof jwk.n !== "string" || typeof jwk.e !== "string") throw new Error("RSA JWK missing n/e");
    return crypto.subtle.importKey(
      "jwk",
      { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
  }
  if (typeof jwk.x !== "string" || typeof jwk.y !== "string") throw new Error("EC JWK missing x/y");
  return crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, ext: true },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
}

// verifySignature verifies the JWS signing input (`<header>.<payload>` ASCII bytes) against the signature
// bytes using the family-derived algorithm. For EC the signature is the raw R||S that JWS ES256 carries
// and that Web Crypto ECDSA verify expects directly; a DER signature fails here (correct rejection).
// NOTE: ES256 signatures are MALLEABLE (Web Crypto accepts both the low-S and high-S = R||(N-S) forms),
// so two valid encodings exist for one IdP signature. Replay/uniqueness protection therefore keys on the
// single-use nonce claim, NEVER on the raw token bytes.
async function verifySignature(jwk: JWK, family: "RSA" | "EC", signingInput: Uint8Array, sig: Uint8Array): Promise<boolean> {
  const key = await importVerifyKey(jwk, family);
  if (family === "RSA") {
    return crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, ab(sig), ab(signingInput));
  }
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, ab(sig), ab(signingInput));
}

// b64url(no padding) of bytes, for the at_hash comparison.
function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// verifyAtHash returns true when at_hash equals base64url(SHA-256(accessToken)[0..15]) (the left-most
// half of the digest, per OIDC core for an alg whose hash is SHA-256). Only called when both an access
// token and an at_hash claim are present.
async function verifyAtHash(atHash: string, accessToken: string): Promise<boolean> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", ab(new TextEncoder().encode(accessToken))));
  return b64url(digest.slice(0, 16)) === atHash;
}

// The decoded JWT segments: the parsed header, the parsed payload object, and the three base64url segment
// strings (the header/payload pair is the ASCII signing input; the third is the signature). decodeToken
// returns this on success or a VerifyIdTokenResult failure on any structural error.
interface DecodedToken {
  header: { alg?: unknown; kid?: unknown; typ?: unknown };
  payload: Record<string, unknown>;
  h64: string;
  p64: string;
  s64: string;
}

// decodeToken applies the DoS length bound, splits the three segments and JSON-decodes the header and
// payload. It returns the decoded parts, or a fail() result for an oversized/empty/malformed/undecodable
// token. The payload must be a plain JSON object (not an array or null).
function decodeToken(idToken: string): DecodedToken | VerifyIdTokenResult {
  // DoS bound: a real id_token is a few KB at most (even with group claims); refuse an oversized or
  // empty one before any split/decode/parse work.
  if (typeof idToken !== "string" || idToken.length === 0 || idToken.length > MAX_ID_TOKEN_LENGTH) return fail("id_token missing or too large");

  const parts = idToken.split(".");
  if (parts.length !== 3) return fail("malformed JWT (expected three segments)");
  const [h64, p64, s64] = parts as [string, string, string];

  let header: { alg?: unknown; kid?: unknown; typ?: unknown };
  let payload: Record<string, unknown>;
  try {
    const h = decodeJSON(h64);
    // Mirror the payload guard below: a syntactically valid segment can decode to any JSON value (a
    // bare "null", a number, a string), and validateHeader dereferences header.alg unconditionally, so
    // an unguarded cast would let a null header throw instead of failing closed.
    if (typeof h !== "object" || h === null || Array.isArray(h)) return fail("header is not a JSON object");
    header = h as typeof header;
    const p = decodeJSON(p64);
    if (typeof p !== "object" || p === null || Array.isArray(p)) return fail("payload is not a JSON object");
    payload = p as Record<string, unknown>;
  } catch {
    return fail("undecodable JWT");
  }
  return { header, payload, h64, p64, s64 };
}

// validateHeader screens the JWT header: the alg must be a member of the connection's closed {RS256,ES256}
// allowlist (the verify algorithm is the key family, never the header alg), the kid must be a non-empty
// string and a present typ must be "JWT". On success it returns the narrowed alg; otherwise a fail()
// result. The allowlist non-emptiness is checked here too (a connection with no enabled algs verifies nothing).
function validateHeader(header: { alg?: unknown; kid?: unknown; typ?: unknown }, opts: VerifyIdTokenOptions): IdTokenAlg | VerifyIdTokenResult {
  if (opts.allowedAlgs.length === 0) return fail("no algorithms allowed for this connection");
  // ALG: membership in the connection allowlist ONLY. The verify algorithm is the key family below; the
  // header alg never selects the crypto. alg:"none", "HS256", "RS384" etc. are rejected here because they
  // are not in the closed {RS256,ES256} allowlist a connection can hold.
  const alg = header.alg;
  if (alg !== "RS256" && alg !== "ES256") return fail(`unacceptable alg: ${String(alg)}`);
  if (!opts.allowedAlgs.includes(alg)) return fail(`alg ${alg} is not enabled for this connection`);
  if (typeof header.kid !== "string" || header.kid.length === 0) return fail("missing kid");
  // A present-but-wrong typ signals a different token structure (e.g. an access token, a JWE); tokens
  // with NO typ are accepted (some IdPs omit it) since the signature + iss + aud + nonce pin the meaning.
  if (header.typ !== undefined && header.typ !== "JWT") return fail(`unexpected token type ${String(header.typ)}`);
  return alg;
}

// validateAudience checks the aud + azp claims. aud may be a string or an array; our client_id must be
// present. When aud is multi-valued OR an azp claim is present, azp MUST equal our client_id (the
// audience-injection defence: a token minted for a sibling client that merely lists our id in aud is
// rejected). Returns a fail() result on rejection, or null when the claims pass.
function validateAudience(payload: Record<string, unknown>, opts: VerifyIdTokenOptions): VerifyIdTokenResult | null {
  // These aud/azp checks run on the UNVERIFIED payload as cheap early-rejects before the signature
  // verification (standard JWT order). includes() does a strict ===, so a non-string element never
  // spuriously matches the string clientId, and the later signature check gates the ok return.
  const audRaw = payload.aud;
  const auds = Array.isArray(audRaw) ? audRaw : audRaw !== undefined && audRaw !== null ? [audRaw] : [];
  if (!auds.includes(opts.clientId)) return fail("aud does not include the client_id");
  if (auds.length > 1 || payload.azp !== undefined) {
    if (payload.azp !== opts.clientId) return fail("azp must equal the client_id when aud is multi-valued or azp is present");
  }
  return null;
}

// validateTime checks exp/nbf/iat against now with a symmetric skew. exp is required and must be in the
// future (with skew); nbf and iat are optional but, when PRESENT, must be finite numbers and within bounds
// (a present-but-non-numeric value is a malformed token and is rejected, in symmetry with the mandatory
// exp). Returns a fail() result on rejection, or null when the claims pass.
function validateTime(payload: Record<string, unknown>, now: number, skew: number): VerifyIdTokenResult | null {
  const exp = payload.exp;
  if (typeof exp !== "number" || !Number.isFinite(exp)) return fail("missing or non-numeric exp");
  if (now >= exp + skew) return fail("token expired");
  const nbf = payload.nbf;
  if (nbf !== undefined) {
    if (typeof nbf !== "number" || !Number.isFinite(nbf)) return fail("nbf present but not a finite number");
    if (nbf - skew > now) return fail("token not yet valid (nbf)");
  }
  const iat = payload.iat;
  if (iat !== undefined) {
    if (typeof iat !== "number" || !Number.isFinite(iat)) return fail("iat present but not a finite number");
    if (iat - skew > now) return fail("token issued in the future (iat)");
  }
  return null;
}

// validateNonce enforces the single-use nonce binding. When opts.nonce is set (every real flow) the
// payload nonce must be a string equal to it, compared in constant time (it is a per-login secret; length
// is not secret). A null option is only for a (currently nonexistent) nonceless flow. Returns a fail()
// result on mismatch, or null when the nonce passes.
function validateNonce(payload: Record<string, unknown>, opts: VerifyIdTokenOptions): VerifyIdTokenResult | null {
  if (opts.nonce !== null) {
    if (typeof payload.nonce !== "string" || !constantTimeEqual(utf8(payload.nonce), utf8(opts.nonce))) return fail("nonce mismatch");
  }
  return null;
}

// verifyKeyAndSignature finds the kid in the JWKS, derives the family from the KEY's kty (not the header),
// requires the header alg and the key family to agree, then verifies the signature over the signing input.
// A kid miss returns the distinct kid_not_found code so the caller can refetch the JWKS once (key rotation)
// before failing closed. The caller supplies the JWKS from a TLS-pinned, assertSafeFetchEndpoint-guarded
// fetch of the IdP's jwks_uri, and is responsible for rejecting a JWKS that carries a DUPLICATE kid (find()
// takes the first match, so a stale key shadowing a fresh one would otherwise self-DoS). Returns a fail()
// result on any rejection, or null when the signature is valid.
async function verifyKeyAndSignature(jwks: JWKS, header: { kid?: unknown }, alg: IdTokenAlg, h64: string, p64: string, s64: string): Promise<VerifyIdTokenResult | null> {
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) return { ok: false, reason: "signing key not found for kid", code: "kid_not_found" };
  const family: "RSA" | "EC" = alg === "RS256" ? "RSA" : "EC";
  if (family === "RSA" && jwk.kty !== "RSA") return fail(`alg/key mismatch: RS256 requires an RSA key, got kty ${jwk.kty}`);
  if (family === "EC" && jwk.kty !== "EC") return fail(`alg/key mismatch: ES256 requires an EC key, got kty ${jwk.kty}`);
  if (family === "EC" && jwk.crv !== "P-256") return fail(`ES256 requires a P-256 key, got crv ${String(jwk.crv)}`);

  let sig: Uint8Array;
  try {
    sig = b64urlDecode(s64);
  } catch {
    return fail("signature segment is not base64url");
  }
  const signingInput = new TextEncoder().encode(`${h64}.${p64}`);
  let valid = false;
  try {
    valid = await verifySignature(jwk, family, signingInput, sig);
  } catch {
    return fail("signature verification error");
  }
  if (!valid) return fail("bad signature");
  return null;
}

// buildVerifiedResult assembles the success result from the SIGNATURE-VERIFIED payload. sub is mandatory
// (it is the stable subject component); at_hash is bound only when both the claim and an access token are
// present; email is optional (retained for display/audit) and email_verified MUST be the JSON boolean true
// (a string "true" is NOT honoured, which would let a hostile or misconfigured IdP's string claim
// masquerade as a verified boolean, which the pending-invite bind upstream trusts). Returns a fail() result
// on a missing sub / at_hash mismatch, or the ok result.
async function buildVerifiedResult(payload: Record<string, unknown>, iss: string, opts: VerifyIdTokenOptions): Promise<VerifyIdTokenResult> {
  const sub = payload.sub;
  if (typeof sub !== "string" || sub.length === 0) return fail("missing sub");

  if (opts.accessToken !== undefined && typeof payload.at_hash === "string") {
    let atOk = false;
    try {
      atOk = await verifyAtHash(payload.at_hash, opts.accessToken);
    } catch {
      atOk = false;
    }
    if (!atOk) return fail("at_hash mismatch");
  }

  const email = typeof payload.email === "string" ? (payload.email as string) : undefined;
  const emailVerified = payload.email_verified === true;
  return {
    ok: true,
    sub,
    iss,
    ...(email !== undefined ? { email } : {}),
    emailVerified,
    claims: payload,
  };
}

// verifyIdToken is the entry point: it returns ok only for a token whose signature verifies under a key in
// the supplied JWKS and whose alg/iss/aud/azp/exp/nbf/nonce (and at_hash when applicable) all check out.
// The JWKS is passed in already-fetched: the caller owns discovery, the per-issuer cache, the single
// kid-rotation refetch and the guarded fetch (assertSafeFetchEndpoint). This function performs NO I/O.
// The body orchestrates the staged checks (each a named helper that returns a fail() result, or null/the
// narrowed value on pass); the ordering and the cheap-rejection-first discipline are unchanged.
export async function verifyIdToken(idToken: string, jwks: JWKS, opts: VerifyIdTokenOptions): Promise<VerifyIdTokenResult> {
  const skew = opts.maxSkewSec ?? 60;

  const decoded = decodeToken(idToken);
  if ("ok" in decoded) return decoded;
  const { header, payload, h64, p64, s64 } = decoded;

  const alg = validateHeader(header, opts);
  if (typeof alg !== "string") return alg;

  // ISSUER (exact, with the two bounded exceptions). Done before fetching/selecting a key so a wrong-iss
  // token is cheap to reject.
  const iss = matchIssuer(payload.iss, payload, opts);
  if (iss === null) {
    // FINER (oidc-entra-multitenant-misconfig): distinguish a TENANT-not-accepted rejection - an Entra /common
    // or /organizations token whose tid is a well-formed value NOT in the connection's acceptedTenantIds
    // allowlist - from a generic wrong-issuer. This is the single most common Entra multitenant misconfiguration
    // (the app was not scoped to the customer's tenant, or the accepted set is stale), and it is invisible in a
    // coarse "issuer" bucket. The tid itself is NEVER put in the reason (it is tenant data); only the stable code
    // is set, which the callback layer maps to a bounded support signal.
    if (opts.tenantIdSubstitution) {
      const tid = payload.tid;
      if (typeof tid === "string" && tid.length > 0 && !opts.tenantIdSubstitution.acceptedTenantIds.includes(tid)) {
        return { ok: false, reason: "issuer not accepted: token tenant is not in the accepted tenant list", code: "tenant_not_accepted" };
      }
    }
    return fail(`issuer not accepted: ${String(payload.iss)}`);
  }

  const audFail = validateAudience(payload, opts);
  if (audFail) return audFail;

  const timeFail = validateTime(payload, opts.now, skew);
  if (timeFail) return timeFail;

  const nonceFail = validateNonce(payload, opts);
  if (nonceFail) return nonceFail;

  const sigFail = await verifyKeyAndSignature(jwks, header, alg, h64, p64, s64);
  if (sigFail) return sigFail;

  // The signature has verified; the payload is authentic.
  return buildVerifiedResult(payload, iss, opts);
}
