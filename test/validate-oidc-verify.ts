// Adversarial validator for the generalized OIDC ID-token verifier (src/admin/oidc-verify.ts).
// It mints REAL RS256 and ES256 tokens with freshly-generated keys and asserts that every legitimate
// token verifies and every attack the design must defeat is rejected: alg:none, alg/key (HS) confusion,
// RS-header-against-EC-key family confusion, a DER-encoded ES256 signature (we accept only raw R||S),
// wrong issuer, audience injection (multi-aud without azp), expiry/nbf, nonce replay/omission, a tampered
// payload, an unknown kid, the Entra tid-substitution path, Google bare-issuer variants, the
// cloudflareaccess issuer screen, and the optional at_hash binding. The path under test is the production
// path (the same verifyIdToken the engine calls). Run: node test/validate-oidc-verify.ts
//
// Node 25 strip-types; Web Crypto only (global crypto.subtle), no Node builtins.

import { verifyIdToken, assertSafeIssuer, assertSafeFetchEndpoint } from "../src/admin/oidc-verify.ts";
import type { JWK, JWKS, VerifyIdTokenOptions, VerifyIdTokenResult } from "../src/admin/oidc-verify.ts";

// The two arms of the discriminated result, so the helpers can return the NARROWED arm the callers
// read (.sub/.email on success, .reason on failure) without each call site re-narrowing on .ok.
type VerifyOk = Extract<VerifyIdTokenResult, { ok: true }>;
type VerifyFail = Extract<VerifyIdTokenResult, { ok: false }>;

const ISSUER = "https://idp.example.com";
const CLIENT = "downpipes-client";
const NONCE = "nonce-abc-123";
const now = Math.floor(Date.now() / 1000);

// ---- test helpers ----
let passed = 0;
const fails: string[] = [];
function check(cond: boolean, desc: string): void {
  if (cond) {
    passed++;
    console.log("  ok   " + desc);
  } else {
    console.log("  FAIL " + desc);
    fails.push(desc);
  }
}
async function expectOk(token: string, opts: VerifyIdTokenOptions, jwks: JWKS, desc: string): Promise<VerifyOk> {
  const r = await verifyIdToken(token, jwks, opts);
  check(r.ok === true, desc + (r.ok ? "" : " -unexpectedly rejected: " + r.reason));
  // The check above asserts success; if it did not hold the suite has already recorded the failure.
  // Returning the success arm (its fields are read by the caller) requires a fallback for the type when
  // the verifier unexpectedly rejected, so callers still get a well-typed VerifyOk to read.
  if (r.ok) return r;
  return { ok: true, sub: "", iss: "", emailVerified: false, claims: {} };
}
async function expectFail(token: string, opts: VerifyIdTokenOptions, jwks: JWKS, desc: string): Promise<VerifyFail> {
  const r = await verifyIdToken(token, jwks, opts);
  check(r.ok === false, desc + (r.ok ? " -UNEXPECTEDLY ACCEPTED" : ""));
  if (!r.ok) return r;
  return { ok: false, reason: "" };
}
function expectThrow(fn: () => void, desc: string): void {
  try {
    fn();
    check(false, desc + " -did not throw");
  } catch {
    check(true, desc);
  }
}
function expectNoThrow(fn: () => void, desc: string): void {
  try {
    fn();
    check(true, desc);
  } catch (e) {
    check(false, desc + " -threw " + (e instanceof Error ? e.message : String(e)));
  }
}

// ---- base64url + JWT minting ----
function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlJSON(obj: unknown): string {
  return b64url(new TextEncoder().encode(JSON.stringify(obj)));
}

// rawToDer converts a P-256 raw R||S (64-byte) signature to the DER ECDSA-Sig-Value the verifier must
// REJECT (JWS ES256 is raw, not DER). seqLen stays below 128 for P-256, so single-byte lengths suffice.
function rawToDer(raw: Uint8Array): Uint8Array {
  const trim = (b: Uint8Array): Uint8Array => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v = b.slice(i);
    if ((v[0]! & 0x80) !== 0) {
      const w = new Uint8Array(v.length + 1);
      w[0] = 0;
      w.set(v, 1);
      v = w;
    }
    return v;
  };
  const R = trim(raw.slice(0, 32));
  const S = trim(raw.slice(32, 64));
  const body = new Uint8Array(2 + R.length + 2 + S.length);
  let o = 0;
  body[o++] = 0x02;
  body[o++] = R.length;
  body.set(R, o);
  o += R.length;
  body[o++] = 0x02;
  body[o++] = S.length;
  body.set(S, o);
  o += S.length;
  const out = new Uint8Array(2 + body.length);
  out[0] = 0x30;
  out[1] = body.length;
  out.set(body, 2);
  return out;
}

interface SignOpts {
  kid?: string | null; // null => omit kid
  headerAlg?: string; // header alg distinct from the signing alg (for confusion vectors)
  typ?: string; // override typ
  derSig?: boolean; // encode an ES256 sig as DER (must be rejected)
}
async function signJwt(privKey: CryptoKey | null, signAlg: "RS256" | "ES256" | "none", payload: unknown, opts: SignOpts = {}): Promise<string> {
  const header: Record<string, unknown> = { alg: opts.headerAlg ?? signAlg, typ: opts.typ ?? "JWT" };
  if (opts.kid !== null) header["kid"] = opts.kid ?? "rsa-1";
  const signingInput = `${b64urlJSON(header)}.${b64urlJSON(payload)}`;
  if (signAlg === "none" || privKey === null) return `${signingInput}.`;
  const algo: AlgorithmIdentifier | EcdsaParams = signAlg === "RS256" ? "RSASSA-PKCS1-v1_5" : { name: "ECDSA", hash: "SHA-256" };
  const raw = new Uint8Array(await crypto.subtle.sign(algo, privKey, new TextEncoder().encode(signingInput)));
  const sig = opts.derSig ? rawToDer(raw) : raw;
  return `${signingInput}.${b64url(sig)}`;
}

// ---- keys + JWKS ----
const rsa = await crypto.subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true,
  ["sign", "verify"],
);
const ec = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const rsaPub = (await crypto.subtle.exportKey("jwk", rsa.publicKey)) as JsonWebKey;
const ecPub = (await crypto.subtle.exportKey("jwk", ec.publicKey)) as JsonWebKey;
// The exported coordinates are always present for a freshly generated key; pin them as definite strings so
// the test-vector JWK literals below (which copy these into JWK fields typed string | undefined as optional)
// stay assignable under exactOptionalPropertyTypes without re-asserting at every site.
const rsaN: string = rsaPub.n!;
const rsaE: string = rsaPub.e!;
const ecX: string = ecPub.x!;
const ecY: string = ecPub.y!;
const rsaJwk: JWK = { kid: "rsa-1", kty: "RSA", n: rsaN, e: rsaE, alg: "RS256" };
const ecJwk: JWK = { kid: "ec-1", kty: "EC", crv: "P-256", x: ecX, y: ecY, alg: "ES256" };
const jwks: JWKS = { keys: [rsaJwk, ecJwk] };

const base = { iss: ISSUER, sub: "user-123", aud: CLIENT, nonce: NONCE, exp: now + 300, iat: now, email: "alice@example.com", email_verified: true };
const baseOpts: VerifyIdTokenOptions = { expectedIssuer: ISSUER, clientId: CLIENT, allowedAlgs: ["RS256", "ES256"], nonce: NONCE, now };

console.log("OIDC ID-TOKEN VERIFIER -adversarial vectors\n");

// 1. valid RS256
{
  const t = await signJwt(rsa.privateKey, "RS256", base, { kid: "rsa-1" });
  const r = await expectOk(t, baseOpts, jwks, "valid RS256 token verifies");
  check(r.sub === "user-123", "  -> subject surfaced from the signed payload");
  check(r.email === "alice@example.com" && r.emailVerified === true, "  -> email + email_verified surfaced");
  check(r.iss === ISSUER, "  -> issuer surfaced");
}
// 2. valid ES256
{
  const t = await signJwt(ec.privateKey, "ES256", base, { kid: "ec-1" });
  await expectOk(t, baseOpts, jwks, "valid ES256 (raw R||S) token verifies");
}
// 3. RS256 token but connection only allows ES256
{
  const t = await signJwt(rsa.privateKey, "RS256", base, { kid: "rsa-1" });
  await expectFail(t, { ...baseOpts, allowedAlgs: ["ES256"] }, jwks, "RS256 rejected when only ES256 is enabled for the connection");
}
// 4. alg:none
{
  const t = await signJwt(null, "none", base, { kid: "rsa-1", headerAlg: "none" });
  await expectFail(t, baseOpts, jwks, "alg:none rejected");
}
// 5. HS256 alg-confusion (header says HS256; never in the asymmetric allowlist)
{
  const t = await signJwt(rsa.privateKey, "RS256", base, { kid: "rsa-1", headerAlg: "HS256" });
  await expectFail(t, baseOpts, jwks, "HS256 header rejected (alg confusion)");
}
// 6. RS256 header against an EC key (family/kty mismatch)
{
  const t = await signJwt(ec.privateKey, "ES256", base, { kid: "ec-1", headerAlg: "RS256" });
  await expectFail(t, baseOpts, jwks, "RS256 header against an EC key rejected (family/kty mismatch)");
}
// 7. ES256 with a DER-encoded signature (we accept only raw R||S)
{
  const t = await signJwt(ec.privateKey, "ES256", base, { kid: "ec-1", derSig: true });
  await expectFail(t, baseOpts, jwks, "ES256 DER signature rejected (only raw R||S accepted)");
}
// 8. wrong issuer
{
  const t = await signJwt(rsa.privateKey, "RS256", { ...base, iss: "https://evil.example.com" }, { kid: "rsa-1" });
  await expectFail(t, baseOpts, jwks, "wrong issuer rejected");
}
// 9. aud does not include the client
{
  const t = await signJwt(rsa.privateKey, "RS256", { ...base, aud: ["someone-else"] }, { kid: "rsa-1" });
  await expectFail(t, baseOpts, jwks, "aud without the client_id rejected");
}
// 10. audience injection: multi-aud without azp / with right azp / with wrong azp
{
  const noAzp = await signJwt(rsa.privateKey, "RS256", { ...base, aud: [CLIENT, "other-client"] }, { kid: "rsa-1" });
  await expectFail(noAzp, baseOpts, jwks, "multi-aud without azp rejected (audience injection)");
  const rightAzp = await signJwt(rsa.privateKey, "RS256", { ...base, aud: [CLIENT, "other-client"], azp: CLIENT }, { kid: "rsa-1" });
  await expectOk(rightAzp, baseOpts, jwks, "multi-aud with azp == client_id accepted");
  const wrongAzp = await signJwt(rsa.privateKey, "RS256", { ...base, aud: [CLIENT, "other-client"], azp: "other-client" }, { kid: "rsa-1" });
  await expectFail(wrongAzp, baseOpts, jwks, "multi-aud with azp != client_id rejected");
}
// 11. expired
{
  const t = await signJwt(rsa.privateKey, "RS256", { ...base, exp: now - 3600 }, { kid: "rsa-1" });
  await expectFail(t, baseOpts, jwks, "expired token rejected");
}
// 12. nbf in the future
{
  const t = await signJwt(rsa.privateKey, "RS256", { ...base, nbf: now + 3600 }, { kid: "rsa-1" });
  await expectFail(t, baseOpts, jwks, "not-yet-valid (nbf) token rejected");
}
// 13. nonce mismatch / omission. The nonce is now compared in constant time via
//     crypto.subtle.timingSafeEqual, so both a length-mismatched nonce (the primitive would throw
//     without the wrapper's length guard) and an equal-length but different nonce (the constant-time
//     path runs end to end) must be refused rather than accepted or thrown.
{
  // "attacker-nonce" (14 chars) differs in length from NONCE "nonce-abc-123" (13 chars): the length
  // guard short-circuits and the verifier fails closed rather than the primitive throwing.
  const wrong = await signJwt(rsa.privateKey, "RS256", { ...base, nonce: "attacker-nonce" }, { kid: "rsa-1" });
  await expectFail(wrong, baseOpts, jwks, "length-mismatched nonce rejected without throwing (replay/injection)");
  // An equal-length but different nonce (13 chars, matching NONCE's length) drives the constant-time
  // comparison to completion and must still be refused.
  const sameLen = await signJwt(rsa.privateKey, "RS256", { ...base, nonce: "wrong-abc-123" }, { kid: "rsa-1" });
  await expectFail(sameLen, baseOpts, jwks, "equal-length but different nonce rejected (replay/injection)");
  const { nonce: _drop, ...noNonceClaims } = base;
  const missing = await signJwt(rsa.privateKey, "RS256", noNonceClaims, { kid: "rsa-1" });
  await expectFail(missing, baseOpts, jwks, "missing nonce rejected when a nonce is expected");
}
// 14. tampered payload (signature over a different body)
{
  const good = await signJwt(rsa.privateKey, "RS256", base, { kid: "rsa-1" });
  const parts = good.split(".");
  const evil = b64urlJSON({ ...base, sub: "attacker" });
  const tampered = `${parts[0]}.${evil}.${parts[2]}`;
  await expectFail(tampered, baseOpts, jwks, "tampered payload rejected (bad signature)");
}
// 15. unknown kid
{
  const t = await signJwt(rsa.privateKey, "RS256", base, { kid: "no-such-kid" });
  await expectFail(t, baseOpts, jwks, "unknown kid rejected (signing key not found)");
}
// 16. Entra tid substitution
{
  const tmpl = "https://login.microsoftonline.com/{tenantid}/v2.0";
  const optsTid: VerifyIdTokenOptions = { ...baseOpts, expectedIssuer: "ignored", tenantIdSubstitution: { template: tmpl, acceptedTenantIds: ["TENANT-1"] } };
  const okTid = await signJwt(rsa.privateKey, "RS256", { ...base, iss: "https://login.microsoftonline.com/TENANT-1/v2.0", tid: "TENANT-1" }, { kid: "rsa-1" });
  await expectOk(okTid, optsTid, jwks, "Entra: tid-substituted issuer with allow-listed tenant accepted");
  const badTenant = await signJwt(rsa.privateKey, "RS256", { ...base, iss: "https://login.microsoftonline.com/TENANT-2/v2.0", tid: "TENANT-2" }, { kid: "rsa-1" });
  const badTenantRes = await expectFail(badTenant, optsTid, jwks, "Entra: tenant not in the allowlist rejected");
  // The tenant-not-accepted rejection carries a stable code, so the callback layer can project a distinct
  // bounded signal (oidc-tenant-not-accepted) instead of a coarse "issuer" failure.
  check(badTenantRes.code === "tenant_not_accepted", "Entra: tenant-not-in-allowlist carries the tenant_not_accepted code");
  // A plain wrong-issuer (tid IS accepted, but the built issuer does not match) is NOT tagged tenant_not_accepted.
  const issMis = await expectFail(await signJwt(rsa.privateKey, "RS256", { ...base, iss: "https://login.microsoftonline.com/TENANT-1/WRONG/v2.0", tid: "TENANT-1" }, { kid: "rsa-1" }), optsTid, jwks, "Entra: an accepted tenant with a mismatched issuer is rejected");
  check(issMis.code === undefined, "Entra: a plain issuer mismatch is NOT tagged tenant_not_accepted (only the tenant-allowlist miss is)");
  const issMismatch = await signJwt(rsa.privateKey, "RS256", { ...base, iss: "https://login.microsoftonline.com/TENANT-1/v1.0", tid: "TENANT-1" }, { kid: "rsa-1" });
  await expectFail(issMismatch, optsTid, jwks, "Entra: iss not matching the substituted template rejected");
}
// 17. Google bare-issuer variant
{
  const optsG: VerifyIdTokenOptions = { ...baseOpts, expectedIssuer: "https://accounts.google.com", acceptIssuerVariants: ["accounts.google.com"] };
  const httpsForm = await signJwt(rsa.privateKey, "RS256", { ...base, iss: "https://accounts.google.com" }, { kid: "rsa-1" });
  await expectOk(httpsForm, optsG, jwks, "Google: https issuer form accepted");
  const bareForm = await signJwt(rsa.privateKey, "RS256", { ...base, iss: "accounts.google.com" }, { kid: "rsa-1" });
  await expectOk(bareForm, optsG, jwks, "Google: bare issuer form accepted");
}
// 18. cloudflareaccess issuer screened at verify
{
  const optsCf: VerifyIdTokenOptions = { ...baseOpts, expectedIssuer: "https://team.cloudflareaccess.com" };
  const t = await signJwt(rsa.privateKey, "RS256", { ...base, iss: "https://team.cloudflareaccess.com" }, { kid: "rsa-1" });
  await expectFail(t, optsCf, jwks, "cloudflareaccess issuer rejected at verify (cross-method collision screen)");
}
// 19. at_hash binding
{
  const at = "an-access-token-value";
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(at)));
  const atHash = b64url(digest.slice(0, 16));
  const good = await signJwt(rsa.privateKey, "RS256", { ...base, at_hash: atHash }, { kid: "rsa-1" });
  await expectOk(good, { ...baseOpts, accessToken: at }, jwks, "at_hash matching the access token accepted");
  const bad = await signJwt(rsa.privateKey, "RS256", { ...base, at_hash: "wrong-hash" }, { kid: "rsa-1" });
  await expectFail(bad, { ...baseOpts, accessToken: at }, jwks, "at_hash not matching the access token rejected");
}
// 20. email_verified flag surfaced honestly
{
  const t = await signJwt(rsa.privateKey, "RS256", { ...base, email_verified: false }, { kid: "rsa-1" });
  const r = await expectOk(t, baseOpts, jwks, "token with email_verified:false still verifies");
  check(r.emailVerified === false, "  -> emailVerified surfaced as false (gates pending-invite binding upstream)");
}
// 21. missing sub
{
  const { sub: _s, ...noSub } = base;
  const t = await signJwt(rsa.privateKey, "RS256", noSub, { kid: "rsa-1" });
  await expectFail(t, baseOpts, jwks, "missing sub rejected");
}
// 22. wrong typ
{
  const t = await signJwt(rsa.privateKey, "RS256", base, { kid: "rsa-1", typ: "at+jwt" });
  await expectFail(t, baseOpts, jwks, "present-but-wrong typ rejected");
}
// 23. missing kid header
{
  const t = await signJwt(rsa.privateKey, "RS256", base, { kid: null });
  await expectFail(t, baseOpts, jwks, "missing kid header rejected");
}

// 24. email_verified as the STRING "true" must NOT be treated as verified (anti-spoof on the bind gate)
{
  const t = await signJwt(rsa.privateKey, "RS256", { ...base, email_verified: "true" }, { kid: "rsa-1" });
  const r = await expectOk(t, baseOpts, jwks, 'token with email_verified:"true" (string) still verifies');
  check(r.emailVerified === false, '  -> string "true" is NOT honoured as verified (only the JSON boolean is)');
}
// 25. obfuscated IP issuer screened at verify
{
  const optsDec: VerifyIdTokenOptions = { ...baseOpts, expectedIssuer: "https://2130706433" };
  const t = await signJwt(rsa.privateKey, "RS256", { ...base, iss: "https://2130706433" }, { kid: "rsa-1" });
  await expectFail(t, optsDec, jwks, "decimal-IP issuer rejected at verify (127.0.0.1 obfuscation)");
}
// 26. duplicate-kid JWKS with the wrong key first (caller-dedupe invariant; verifier fails closed)
{
  const wrongRsa = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const wrongPub = (await crypto.subtle.exportKey("jwk", wrongRsa.publicKey)) as JsonWebKey;
  const dupJwks: JWKS = { keys: [{ kid: "rsa-1", kty: "RSA", n: wrongPub.n!, e: wrongPub.e!, alg: "RS256" }, rsaJwk] };
  const t = await signJwt(rsa.privateKey, "RS256", base, { kid: "rsa-1" });
  await expectFail(t, baseOpts, dupJwks, "duplicate-kid JWKS (wrong key first) rejected");
}
// 27. at_hash claim present but no access token supplied => the check is skipped
{
  const t = await signJwt(rsa.privateKey, "RS256", { ...base, at_hash: "irrelevant" }, { kid: "rsa-1" });
  await expectOk(t, baseOpts, jwks, "at_hash claim ignored when no access token is supplied");
}
// 28. P-384 key rejected for ES256 (crv guard, before any importKey)
{
  const p384Jwks: JWKS = { keys: [{ kid: "ec-1", kty: "EC", crv: "P-384", x: ecX, y: ecY, alg: "ES256" }] };
  const t = await signJwt(ec.privateKey, "ES256", base, { kid: "ec-1" });
  await expectFail(t, baseOpts, p384Jwks, "P-384 key rejected for ES256 (only P-256)");
}
// 29. JSON-array header rejected
{
  const t = `${b64urlJSON(["RS256"])}.${b64urlJSON(base)}.${"x".repeat(8)}`;
  await expectFail(t, baseOpts, jwks, "JSON-array header rejected");
}
// 30. valid token with no nbf and no iat (both optional)
{
  const { iat: _i, ...noIat } = base;
  const t = await signJwt(rsa.privateKey, "RS256", noIat, { kid: "rsa-1" });
  await expectOk(t, baseOpts, jwks, "token with no nbf/iat verifies");
}
// 31. nbf present but non-numeric rejected (symmetry with exp)
{
  const t = await signJwt(rsa.privateKey, "RS256", { ...base, nbf: "9999999999" }, { kid: "rsa-1" });
  await expectFail(t, baseOpts, jwks, "present-but-non-numeric nbf rejected");
}
// 32. missing exp rejected
{
  const { exp: _e, ...noExp } = base;
  const t = await signJwt(rsa.privateKey, "RS256", noExp, { kid: "rsa-1" });
  await expectFail(t, baseOpts, jwks, "missing exp rejected");
}
// 33. empty allowedAlgs rejected
{
  const t = await signJwt(rsa.privateKey, "RS256", base, { kid: "rsa-1" });
  await expectFail(t, { ...baseOpts, allowedAlgs: [] }, jwks, "empty allowedAlgs rejected");
}
// 34. oversized id_token rejected (DoS length cap)
{
  const t = await signJwt(rsa.privateKey, "RS256", { ...base, pad: "z".repeat(40000) }, { kid: "rsa-1" });
  await expectFail(t, baseOpts, jwks, "oversized id_token rejected (length cap)");
}
// 35. Entra template missing {tenantid} rejected
{
  const optsBad: VerifyIdTokenOptions = { ...baseOpts, expectedIssuer: "ignored", tenantIdSubstitution: { template: "https://login.microsoftonline.com/common/v2.0", acceptedTenantIds: ["TENANT-1"] } };
  const t = await signJwt(rsa.privateKey, "RS256", { ...base, iss: "https://login.microsoftonline.com/common/v2.0", tid: "TENANT-1" }, { kid: "rsa-1" });
  await expectFail(t, optsBad, jwks, "Entra template without {tenantid} rejected");
}

// 36. wrong segment count (a two-part string) rejected before any decode (malformed JWT guard)
{
  const twoParts = `${b64urlJSON({ alg: "RS256", typ: "JWT", kid: "rsa-1" })}.${b64urlJSON(base)}`;
  const r = await expectFail(twoParts, baseOpts, jwks, "two-segment token rejected (expected three segments)");
  check(r.reason === "malformed JWT (expected three segments)", "  -> reason names the three-segment guard");
}
// 37. undecodable header (valid base64url, not JSON) rejected (decodeJSON throws -> undecodable JWT)
{
  const badHeader = b64url(new TextEncoder().encode("{not valid json"));
  const t = `${badHeader}.${b64urlJSON(base)}.${"x".repeat(8)}`;
  const r = await expectFail(t, baseOpts, jwks, "header that is not JSON rejected (undecodable JWT)");
  check(r.reason === "undecodable JWT", "  -> reason names the undecodable-JWT catch");
}
// 38. payload decoding to a JSON array (not an object) rejected
{
  const t = `${b64urlJSON({ alg: "RS256", typ: "JWT", kid: "rsa-1" })}.${b64urlJSON([1, 2, 3])}.${"x".repeat(8)}`;
  const r = await expectFail(t, baseOpts, jwks, "array payload rejected (payload is not a JSON object)");
  check(r.reason === "payload is not a JSON object", "  -> reason names the non-object payload guard");
}
// 39. payload decoding to a JSON null (the typeof object && === null arm) rejected
{
  const t = `${b64urlJSON({ alg: "RS256", typ: "JWT", kid: "rsa-1" })}.${b64urlJSON(null)}.${"x".repeat(8)}`;
  await expectFail(t, baseOpts, jwks, "null payload rejected (payload is not a JSON object)");
}
// 39a. header decoding to a JSON null rejected (mirrors 39: the same guard, now symmetric on the header)
{
  const t = `${b64urlJSON(null)}.${b64urlJSON(base)}.${"x".repeat(8)}`;
  const r = await expectFail(t, baseOpts, jwks, "null header rejected (header is not a JSON object)");
  check(r.reason === "header is not a JSON object", "  -> reason names the non-object header guard");
}
// 40. non-string iss claim rejected at matchIssuer (typeof rawIss guard)
{
  const t = await signJwt(rsa.privateKey, "RS256", { ...base, iss: 12345 }, { kid: "rsa-1" });
  const r = await expectFail(t, baseOpts, jwks, "numeric iss rejected (issuer not accepted)");
  check(r.reason?.startsWith("issuer not accepted") === true, "  -> reason names the issuer guard");
}
// 41. acceptIssuerVariants present but the token's iss matches neither the configured issuer nor a variant
{
  const optsG: VerifyIdTokenOptions = { ...baseOpts, expectedIssuer: "https://accounts.google.com", acceptIssuerVariants: ["accounts.google.com"] };
  const t = await signJwt(rsa.privateKey, "RS256", { ...base, iss: "https://accounts.evil.com" }, { kid: "rsa-1" });
  await expectFail(t, optsG, jwks, "variant mode: an iss that is neither the issuer nor a listed variant rejected");
}
// 42. Entra tid-substitution mode but the token carries no tid claim
{
  const tmpl = "https://login.microsoftonline.com/{tenantid}/v2.0";
  const optsTid: VerifyIdTokenOptions = { ...baseOpts, expectedIssuer: "ignored", tenantIdSubstitution: { template: tmpl, acceptedTenantIds: ["TENANT-1"] } };
  const t = await signJwt(rsa.privateKey, "RS256", { ...base, iss: "https://login.microsoftonline.com/TENANT-1/v2.0" }, { kid: "rsa-1" });
  await expectFail(t, optsTid, jwks, "Entra: a token with no tid claim rejected");
}
// 43. localhost issuer screened at verify (issuerLooksUnsafe localhost arm)
{
  const optsLocal: VerifyIdTokenOptions = { ...baseOpts, expectedIssuer: "https://localhost" };
  const t = await signJwt(rsa.privateKey, "RS256", { ...base, iss: "https://localhost" }, { kid: "rsa-1" });
  await expectFail(t, optsLocal, jwks, "localhost issuer rejected at verify (cross-method collision screen)");
}
// 44. a bare-host issuer variant the URL parser cannot parse falls back to the best-effort host screen and,
// being neither localhost nor an IP literal, is accepted (issuerLooksUnsafe URL-parse catch -> safe verdict).
{
  const oddVariant = "exa mple.com"; // a space makes new URL("https://exa mple.com") throw
  const optsOdd: VerifyIdTokenOptions = { ...baseOpts, expectedIssuer: "https://idp.example.com", acceptIssuerVariants: [oddVariant] };
  const t = await signJwt(rsa.privateKey, "RS256", { ...base, iss: oddVariant }, { kid: "rsa-1" });
  const r = await expectOk(t, optsOdd, jwks, "unparseable bare-host variant accepted via the best-effort host fallback");
  check(r.iss === oddVariant, "  -> the matched (and screened) variant is surfaced");
}
// 45. iat present but non-numeric rejected (symmetry with the nbf and exp numeric guards)
{
  const t = await signJwt(rsa.privateKey, "RS256", { ...base, iat: "1700000000" }, { kid: "rsa-1" });
  const r = await expectFail(t, baseOpts, jwks, "present-but-non-numeric iat rejected");
  check(r.reason === "iat present but not a finite number", "  -> reason names the iat numeric guard");
}
// 46. iat far in the future rejected (issued-in-the-future guard)
{
  const t = await signJwt(rsa.privateKey, "RS256", { ...base, iat: now + 3600 }, { kid: "rsa-1" });
  const r = await expectFail(t, baseOpts, jwks, "future iat rejected (token issued in the future)");
  check(r.reason === "token issued in the future (iat)", "  -> reason names the future-iat guard");
}
// 47. aud claim entirely absent reaches the empty-aud path and is rejected (does not include the client_id)
{
  const { aud: _a, ...noAud } = base;
  const t = await signJwt(rsa.privateKey, "RS256", noAud, { kid: "rsa-1" });
  const r = await expectFail(t, baseOpts, jwks, "token with no aud claim rejected (aud does not include the client_id)");
  check(r.reason === "aud does not include the client_id", "  -> reason names the aud guard");
}
// 48. ES256 header whose matched kid resolves to a non-EC key rejected (alg/key family mismatch, the EC arm)
{
  const mismatchJwks: JWKS = { keys: [{ kid: "ec-1", kty: "RSA", n: rsaN, e: rsaE, alg: "RS256" }] };
  const t = await signJwt(ec.privateKey, "ES256", base, { kid: "ec-1" });
  const r = await expectFail(t, baseOpts, mismatchJwks, "ES256 against a kid whose key is RSA rejected (family/kty mismatch)");
  check(r.reason?.startsWith("alg/key mismatch: ES256") === true, "  -> reason names the ES256/EC mismatch");
}
// 49. signature segment that is not base64url rejected (b64urlDecode throws -> clean rejection)
{
  const t = `${b64urlJSON({ alg: "RS256", typ: "JWT", kid: "rsa-1" })}.${b64urlJSON(base)}.@@@not-base64@@@`;
  const r = await expectFail(t, baseOpts, jwks, "non-base64url signature segment rejected");
  check(r.reason === "signature segment is not base64url", "  -> reason names the signature-decode guard");
}
// 50. an RSA-typed JWK missing n reaches importVerifyKey, which throws and is caught as a verification error
{
  const noN: JWKS = { keys: [{ kid: "rsa-1", kty: "RSA", e: rsaE, alg: "RS256" }] };
  const t = await signJwt(rsa.privateKey, "RS256", base, { kid: "rsa-1" });
  const r = await expectFail(t, baseOpts, noN, "RSA JWK missing n rejected (import throws -> signature verification error)");
  check(r.reason === "signature verification error", "  -> reason names the verification-error catch");
}
// 51. an EC-typed JWK (correct kty + P-256 crv) missing x reaches the EC import guard and is rejected
{
  const noX: JWKS = { keys: [{ kid: "ec-1", kty: "EC", crv: "P-256", y: ecY, alg: "ES256" }] };
  const t = await signJwt(ec.privateKey, "ES256", base, { kid: "ec-1" });
  const r = await expectFail(t, baseOpts, noX, "EC JWK missing x rejected (import throws -> signature verification error)");
  check(r.reason === "signature verification error", "  -> reason names the verification-error catch");
}
// 52. an EC JWK with a structurally invalid (off-curve, valid string) x makes Web Crypto importKey reject
// inside verifySignature, exercising the verify-time catch rather than the pre-import string guards.
{
  const offCurve: JWKS = { keys: [{ kid: "ec-1", kty: "EC", crv: "P-256", x: "A".repeat(43), y: "A".repeat(43), alg: "ES256" }] };
  const t = await signJwt(ec.privateKey, "ES256", base, { kid: "ec-1" });
  const r = await expectFail(t, baseOpts, offCurve, "EC JWK with an off-curve point rejected (importKey rejects -> verification error)");
  check(r.reason === "signature verification error", "  -> reason names the verification-error catch");
}
// 53. a verified token that carries no email surfaces no email field and an unverified flag (optional-email arm)
{
  const { email: _e, ...noEmail } = base;
  const t = await signJwt(rsa.privateKey, "RS256", { ...noEmail, email_verified: false }, { kid: "rsa-1" });
  const r = await expectOk(t, baseOpts, jwks, "token with no email claim still verifies");
  check(r.email === undefined, "  -> no email field is surfaced when the claim is absent");
  check(r.emailVerified === false, "  -> emailVerified is false when no verified email is present");
}
// 54. a verified token with a non-string email claim surfaces no email (the optional-email typeof arm)
{
  const t = await signJwt(rsa.privateKey, "RS256", { ...base, email: 42 }, { kid: "rsa-1" });
  const r = await expectOk(t, baseOpts, jwks, "token with a non-string email still verifies");
  check(r.email === undefined, "  -> a non-string email claim is not surfaced");
}

console.log("\nassertSafeFetchEndpoint URL + cloudflareaccess + assertSafeIssuer URL guards\n");
// assertSafeFetchEndpoint: an unparseable endpoint string throws (the URL-parse catch).
expectThrow(() => assertSafeFetchEndpoint("not a url"), "assertSafeFetchEndpoint rejects an unparseable endpoint");
// assertSafeFetchEndpoint: a cloudflareaccess host throws (the cross-namespace endpoint screen).
expectThrow(() => assertSafeFetchEndpoint("https://team.cloudflareaccess.com/cdn-cgi/access/certs"), "assertSafeFetchEndpoint rejects a cloudflareaccess host");
// assertSafeIssuer: an unparseable issuer string throws (the URL-parse catch).
expectThrow(() => assertSafeIssuer("not a url"), "assertSafeIssuer rejects an unparseable issuer");

console.log("\nassertSafeIssuer (config-time) + assertSafeFetchEndpoint (SSRF) guards\n");
expectNoThrow(() => assertSafeIssuer("https://idp.example.com"), "assertSafeIssuer accepts a normal https issuer");
expectThrow(() => assertSafeIssuer("http://idp.example.com"), "assertSafeIssuer rejects http");
expectThrow(() => assertSafeIssuer("https://team.cloudflareaccess.com"), "assertSafeIssuer rejects a cloudflareaccess host");
expectThrow(() => assertSafeIssuer("https://127.0.0.1"), "assertSafeIssuer rejects an IPv4 literal");
expectThrow(() => assertSafeIssuer("https://[::1]"), "assertSafeIssuer rejects an IPv6 literal");
expectThrow(() => assertSafeIssuer("https://localhost"), "assertSafeIssuer rejects localhost");
expectThrow(() => assertSafeIssuer("https://localhost."), "assertSafeIssuer rejects localhost. (trailing-dot bypass)");
expectThrow(() => assertSafeFetchEndpoint("https://localhost./jwks"), "assertSafeFetchEndpoint rejects localhost. (trailing-dot bypass)");
expectThrow(() => assertSafeIssuer("https://user:pass@idp.example.com"), "assertSafeIssuer rejects embedded credentials");
expectThrow(() => assertSafeIssuer("https://2130706433"), "assertSafeIssuer rejects a decimal-IP literal");
expectThrow(() => assertSafeIssuer("https://0x7f.0.0.1"), "assertSafeIssuer rejects a hex-IP literal");
expectNoThrow(() => assertSafeFetchEndpoint("https://www.googleapis.com/oauth2/v3/certs"), "assertSafeFetchEndpoint allows a cross-host https JWKS (Google)");
expectThrow(() => assertSafeFetchEndpoint("http://www.googleapis.com/certs"), "assertSafeFetchEndpoint rejects http");
expectThrow(() => assertSafeFetchEndpoint("https://169.254.169.254/latest/meta-data/"), "assertSafeFetchEndpoint rejects the link-local metadata IP");

console.log("");
if (fails.length > 0) process.exitCode = 1;
if (fails.length > 0) {
  console.log(`OIDC VERIFIER VECTORS: ${passed} passed, ${fails.length} FAILED`);
  for (const f of fails) console.log("   FAILED: " + f);
  process.exit(1);
}
console.log(`OIDC VERIFIER VECTORS PASS (${passed} checks)`);
