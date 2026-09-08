// Validate the Cloudflare Access JWT verification: a valid RS256 token signed by a key in
// the JWKS passes, and a tampered signature, wrong audience, wrong issuer or expired token
// all fail. Uses a self-generated RSA key and a controlled JWKS (no network). Run with
// `node test/validate-access.ts`.

import { accessDenySignal, verifyAccessJWT } from "../src/admin/access.ts";
// The deny sink type is AuthDenySink in auth.ts: the sink was widened from Access-only denials to every
// deny class (passkey session, bare token), so the name lost its "Access" prefix. The Access-side signals
// asserted below are the same closed cf-access-* vocabulary.
import { authorise, type AuthDenySink, type BreakGlassRetiredResolver, type PasskeySessionVerifier } from "../src/admin/auth.ts";
import type { Env } from "../src/env.d.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { flipBit } from "./memdest.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const TEAM = "acme-corp";
const ISS = `https://${TEAM}.cloudflareaccess.com`;
const AUD = "test-aud-tag";
const KID = "test-kid-1";
const NOW = 1780000000;

function jwtPart(obj: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}

// The signed-token fixtures shared across the JWT proof groups: a controlled RSA key, its JWKS, a
// token minter, and the base claim + verify options. Built once and threaded into each proof helper.
interface AccessFixture {
  pubJwk: { n: string; e: string };
  makeToken: (payload: Record<string, unknown>, headerOverrides?: Record<string, unknown>, opts?: { tamper?: boolean }) => Promise<string>;
  base: Record<string, unknown>;
  opts: { teamDomain: string; aud: string; fetchCerts: () => Promise<{ keys: { kid: string; kty: string; n: string; e: string }[] }>; now: number };
}

async function buildFixture(): Promise<AccessFixture> {
  const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const pubJwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
  const jwks = { keys: [{ kid: KID, kty: "RSA", n: pubJwk.n, e: pubJwk.e }] };
  const fetchCerts = async () => jwks;
  const makeToken = async (payload: Record<string, unknown>, headerOverrides: Record<string, unknown> = {}, opts: { tamper?: boolean } = {}): Promise<string> => {
    const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT", ...headerOverrides });
    const body = jwtPart(payload);
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
    if (opts.tamper) flipBit(sig, 0, 0x01);
    return `${header}.${body}.${b64urlEncode(sig)}`;
  };
  const base = { iss: ISS, aud: AUD, exp: NOW + 3600, iat: NOW, email: "user@test.example", sub: "u-abc-123" };
  const opts = { teamDomain: TEAM, aud: AUD, fetchCerts, now: NOW };
  return { pubJwk, makeToken, base, opts };
}

// Happy path plus the SIGNED-subject (iss|sub) extraction and recycle-resistance vectors.
async function proveHappyAndSubject(f: AccessFixture): Promise<void> {
  const { makeToken, base, opts } = f;
  ok("valid token passes", (await verifyAccessJWT(await makeToken(base), opts)).ok);
  ok("valid token carries the email", (await verifyAccessJWT(await makeToken(base), opts)).email === "user@test.example");

  // ASVS V10.3.3 / V10.5.2: the STABLE subject (iss+"|"+sub) is extracted from the SIGNED payload, so the
  // role table can key authorisation on the immutable principal rather than the mutable email.
  ok("valid token carries the stable subject (iss|sub)", (await verifyAccessJWT(await makeToken(base), opts)).subject === `${ISS}|u-abc-123`);
  // A token with NO sub still VERIFIES (the signature/iss/aud/exp are valid), but carries no subject:
  // honestly absent, exactly like an absent email. auth.ts then rejects a subjectless assertion (proved
  // in validate-rbac); verifyAccessJWT itself does not reject it, mirroring its emailless handling.
  const noSub = await verifyAccessJWT(await makeToken({ iss: ISS, aud: AUD, exp: NOW + 3600, iat: NOW, email: "x@example.com" }), opts);
  ok("a token with no sub still verifies (signature/claims valid)", noSub.ok === true);
  ok("a token with no sub carries NO subject (honestly absent)", noSub.subject === undefined);
  // Two DIFFERENT subs under the same email yield DIFFERENT subjects (the recycle-resistant key): a
  // recycled email reassigned to a new Access user is a different subject, so it cannot inherit a role.
  const a = await verifyAccessJWT(await makeToken({ ...base, sub: "u-first" }), opts);
  const b = await verifyAccessJWT(await makeToken({ ...base, sub: "u-second" }), opts);
  ok("same email, different sub -> different subject (recycle-resistant)", a.subject !== b.subject && a.subject === `${ISS}|u-first` && b.subject === `${ISS}|u-second`);
  // A sub carrying an ASCII control char is rejected as a key fragment (no subject), failing closed.
  const ctrl = await verifyAccessJWT(await makeToken({ ...base, sub: "u\x01evil" }), opts);
  ok("a sub with a control character yields no subject (key-safe)", ctrl.ok === true && ctrl.subject === undefined);
  // The sub becomes a DO storage-key fragment, so its length is bounded to GROUP_NAME_MAX (256): a sub
  // EXACTLY at the bound is accepted, a sub ONE over is rejected with no subject. This pins the maker
  // axis of dual-control to the same boundary the DO normaliser enforces.
  const atMax = await verifyAccessJWT(await makeToken({ ...base, sub: "s".repeat(256) }), opts);
  ok("a sub exactly at GROUP_NAME_MAX (256) yields a subject", atMax.ok === true && atMax.subject === `${ISS}|${"s".repeat(256)}`);
  const overMax = await verifyAccessJWT(await makeToken({ ...base, sub: "s".repeat(257) }), opts);
  ok("a sub one over GROUP_NAME_MAX (257) yields no subject (bounded)", overMax.ok === true && overMax.subject === undefined);
  // A sub that is whitespace-only trims to empty and yields no subject (honestly absent).
  const blank = await verifyAccessJWT(await makeToken({ ...base, sub: "   " }), opts);
  ok("a whitespace-only sub yields no subject (empty after trim)", blank.ok === true && blank.subject === undefined);
}

// Signature/claim/forged-key rejection vectors.
async function proveRejections(f: AccessFixture): Promise<void> {
  const { makeToken, base, opts } = f;
  ok("tampered signature fails", !(await verifyAccessJWT(await makeToken(base, {}, { tamper: true }), opts)).ok);
  ok("wrong audience fails", !(await verifyAccessJWT(await makeToken({ ...base, aud: "other" }), opts)).ok);
  ok("wrong issuer fails", !(await verifyAccessJWT(await makeToken({ ...base, iss: "https://evil.cloudflareaccess.com" }), opts)).ok);
  ok("expired token fails", !(await verifyAccessJWT(await makeToken({ ...base, exp: NOW - 1 }), opts)).ok);
  ok("not-before in the future fails", !(await verifyAccessJWT(await makeToken({ ...base, nbf: NOW + 100 }), opts)).ok);
  ok("malformed token fails", !(await verifyAccessJWT("not.a.jwt", opts)).ok);

  // Malformed signature segments must FAIL CLOSED without THROWING (live-caught: a non-base64url
  // signature 500'd instead of 401'ing — b64urlDecode and crypto.subtle.verify throw on bad input).
  {
    const hb = `${jwtPart({ alg: "RS256", kid: KID, typ: "JWT" })}.${jwtPart(base)}`;
    for (const [label, badSig] of [["non-base64", "@@@not-base64@@@"], ["wrong-length", b64urlEncode(new Uint8Array(7))]] as const) {
      let threw = false;
      let res: Awaited<ReturnType<typeof verifyAccessJWT>> | undefined;
      try {
        res = await verifyAccessJWT(`${hb}.${badSig}`, opts);
      } catch {
        threw = true;
      }
      ok(`${label} signature does not throw`, !threw);
      ok(`${label} signature is rejected (ok:false)`, res !== undefined && !res.ok);
    }
  }

  // A token signed by a key NOT in the JWKS must fail (forged issuer key). Note: signed by `other`,
  // not the fixture key, so it cannot use makeToken.
  const other = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign"]);
  const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
  const body = jwtPart(base);
  const forgedSig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", other.privateKey, new TextEncoder().encode(`${header}.${body}`)));
  ok("token signed by an unknown key fails", !(await verifyAccessJWT(`${header}.${body}.${b64urlEncode(forgedSig)}`, opts)).ok);
}

// V9.2.2 typ-header guard vectors.
async function proveTypHeader(f: AccessFixture): Promise<void> {
  const { makeToken, base, opts } = f;
  // A token with typ absent is accepted (some IdPs omit it; the alg/iss/aud/sig checks are sufficient).
  ok("token with no typ header passes", (await verifyAccessJWT(await makeToken(base, { typ: undefined }), opts)).ok);
  // A token with typ:"JWT" (Cloudflare Access standard) is accepted.
  ok("token with typ:JWT passes", (await verifyAccessJWT(await makeToken(base, { typ: "JWT" }), opts)).ok);
  // A token with typ:"JWE" (encrypted, a different token class) must be rejected.
  ok("token with typ:JWE fails", !(await verifyAccessJWT(await makeToken(base, { typ: "JWE" }), opts)).ok);
  // Any other non-JWT typ must be rejected.
  ok("token with typ:at+JWT fails", !(await verifyAccessJWT(await makeToken(base, { typ: "at+JWT" }), opts)).ok);
}

// V1.3.6 team-domain SSRF guard vectors.
async function proveTeamDomainGuard(f: AccessFixture): Promise<void> {
  const { makeToken, base, opts } = f;
  // A fully-qualified non-cloudflareaccess.com team domain must be rejected before fetching certs.
  const tokenForBadDomain = await makeToken({ ...base, iss: "https://evil.example.com" });
  ok("non-cloudflareaccess team domain fails", !(await verifyAccessJWT(tokenForBadDomain, { ...opts, teamDomain: "evil.example.com" })).ok);
  // A bare "cloudflareaccess.com" (no subdomain label) must be rejected.
  const tokenForBareDomain = await makeToken({ ...base, iss: "https://cloudflareaccess.com" });
  ok("bare cloudflareaccess.com team domain fails", !(await verifyAccessJWT(tokenForBareDomain, { ...opts, teamDomain: "cloudflareaccess.com" })).ok);
  // A valid single-label team domain (the normal case) must continue to pass.
  ok("valid single-label team domain passes", (await verifyAccessJWT(await makeToken(base), opts)).ok);
}

// XC-L4: a JWKS entry whose kty is not "RSA" must be rejected before reaching importKey.
async function proveKtyGuard(f: AccessFixture): Promise<void> {
  const { makeToken, base, opts, pubJwk } = f;
  // The token itself is validly signed; the JWKS is the attack surface: an EC or oct key whose kid
  // matches the token's kid must never be coerced into an RS256 import.
  const ecJwks = { keys: [{ kid: KID, kty: "EC", n: pubJwk.n, e: pubJwk.e }] };
  ok("JWKS key with kty:EC fails", !(await verifyAccessJWT(await makeToken(base), { ...opts, fetchCerts: async () => ecJwks })).ok);
  const octJwks = { keys: [{ kid: KID, kty: "oct", n: pubJwk.n, e: pubJwk.e }] };
  ok("JWKS key with kty:oct fails", !(await verifyAccessJWT(await makeToken(base), { ...opts, fetchCerts: async () => octJwks })).ok);
}

// groups claim bounding (boundGroups, exercised through verifyAccessJWT).
async function proveGroupsBounding(f: AccessFixture): Promise<void> {
  const { makeToken, base, opts } = f;
  // groups drives group-to-role resolution when configured, so its normalisation is security-relevant
  // and must agree with the DO's normaliseGroup. These vectors pin the seven contract cases by passing a
  // crafted SIGNED groups claim through the real verifier and reading the bounded result.
  const groupsOf = async (groups: unknown): Promise<string[] | undefined> =>
    (await verifyAccessJWT(await makeToken({ ...base, groups }), opts)).groups;
  // (1) a non-array claim yields no groups key at all (honestly absent).
  ok("groups: a non-array claim yields undefined", (await groupsOf("not-an-array")) === undefined);
  ok("groups: an object claim yields undefined", (await groupsOf({ a: 1 })) === undefined);
  // (2) a mixed-type array keeps only the string entries.
  const mixed = await groupsOf(["eng", 42, null, { x: 1 }, "ops"]);
  ok("groups: a mixed-type array keeps only strings", JSON.stringify(mixed) === JSON.stringify(["eng", "ops"]));
  // (3) a group over GROUP_NAME_MAX (256) is dropped; a sane sibling survives.
  const withOversize = await groupsOf(["g".repeat(257), "keep"]);
  ok("groups: a group over GROUP_NAME_MAX is dropped", JSON.stringify(withOversize) === JSON.stringify(["keep"]));
  // (4) a group carrying an ASCII control character is dropped (key-safety, matches normaliseGroup).
  const withControl = await groupsOf(["ok-group", "bad\x01group"]);
  ok("groups: a control-character group is dropped", JSON.stringify(withControl) === JSON.stringify(["ok-group"]));
  // (5) duplicates are deduped, first occurrence wins, order preserved.
  const deduped = await groupsOf(["eng", "ops", "eng", "ops", "sec"]);
  ok("groups: duplicates are deduped (first wins, order preserved)", JSON.stringify(deduped) === JSON.stringify(["eng", "ops", "sec"]));
  // (6) a list longer than GROUPS_MAX (200) is capped to GROUPS_MAX.
  const capped = await groupsOf(Array.from({ length: 250 }, (_v, i) => `g${i}`));
  ok("groups: a list over GROUPS_MAX is capped to GROUPS_MAX (200)", capped !== undefined && capped.length === 200 && capped[0] === "g0" && capped[199] === "g199");
  // (7) a valid groups array is returned verbatim (trimmed, in order).
  const verbatim = await groupsOf(["alpha", "beta", "gamma"]);
  ok("groups: a valid array is returned verbatim", JSON.stringify(verbatim) === JSON.stringify(["alpha", "beta", "gamma"]));
  // A claim that bounds down to nothing (all entries dropped) yields undefined, not an empty array.
  ok("groups: an all-dropped claim yields undefined (not an empty array)", (await groupsOf([42, "", "  "])) === undefined);
}

// The identityProvider (idp) claim is surfaced verbatim to the customer console as the honest basis of a
// role, so its trim/length-cap path is pinned here: a valid idp is carried through, an oversized or
// non-string idp yields no identityProvider key (honestly absent, never fabricated).
async function proveIdpBounding(f: AccessFixture): Promise<void> {
  const { makeToken, base, opts } = f;
  const idpOf = async (idp: unknown): Promise<string | undefined> =>
    (await verifyAccessJWT(await makeToken({ ...base, idp }), opts)).identityProvider;
  // (1) a valid idp is carried through verbatim (trimmed).
  ok("idp: a valid claim yields identityProvider", (await idpOf("okta")) === "okta");
  ok("idp: a padded claim is trimmed", (await idpOf("  okta  ")) === "okta");
  // (2) an idp over GROUP_NAME_MAX (256) yields no identityProvider key.
  ok("idp: an over-GROUP_NAME_MAX claim yields undefined", (await idpOf("i".repeat(257))) === undefined);
  ok("idp: an at-GROUP_NAME_MAX claim is carried through", (await idpOf("i".repeat(256)))?.length === 256);
  // (3) a non-string idp yields no identityProvider key.
  ok("idp: a non-string claim yields undefined", (await idpOf(42)) === undefined);
  ok("idp: an empty/blank claim yields undefined", (await idpOf("   ")) === undefined);
}

// authorise(): the break-glass-retired resolver precedence (unit).
async function proveAuthorisePrecedence(): Promise<void> {
  // The effective "token fallback OFF" predicate is envFlagEnabled(ADMIN_TOKEN_DISABLED) OR breakGlassRetired.
  // The resolver is consulted ONLY on the bare-token path (after Access + passkey), ONLY when a token is
  // configured and a bearer is presented, and a true verdict refuses the token exactly as the env flag does.
  // When omitted, the predicate is the env flag alone (the prior behaviour). These drive authorise() directly
  // with stub resolvers (no DO), pinning the precedence contract the router relies on.
  const TOKEN = "unit-break-glass-token";
  const tokenEnv = { ADMIN_TOKEN: TOKEN } as unknown as Env;
  const tokenReq = (): Request => new Request("https://e.example/admin/x", { method: "GET", headers: { authorization: `Bearer ${TOKEN}` } });
  const noCredReq = (): Request => new Request("https://e.example/admin/x", { method: "GET" });
  const retiredTrue: BreakGlassRetiredResolver = async () => true;
  const retiredFalse: BreakGlassRetiredResolver = async () => false;

  // Baseline: a valid token with no resolver authorises to the token method (unchanged default).
  const base1 = await authorise(tokenReq(), tokenEnv);
  ok("authorise: a valid token with no retire resolver authorises (token method)", base1.ok && base1.method === "token");
  // A FALSE resolver leaves the token working (the predicate is env-flag OR retired; both false here).
  const okFalse = await authorise(tokenReq(), tokenEnv, undefined, retiredFalse);
  ok("authorise: a false retire resolver still admits the token", okFalse.ok && okFalse.method === "token");
  // A TRUE resolver refuses the token exactly as ADMIN_TOKEN_DISABLED would (fail closed, no downgrade).
  const okRetired = await authorise(tokenReq(), tokenEnv, undefined, retiredTrue);
  ok("authorise: a true retire resolver refuses the token (fail closed)", !okRetired.ok);
  // The resolver is NOT consulted when no bearer is presented (a no-credential request is denied WITHOUT
  // ever calling the resolver, so it adds no DO read to the no-credential path).
  let called = 0;
  const counting: BreakGlassRetiredResolver = async () => {
    called++;
    return true;
  };
  const noCred = await authorise(noCredReq(), tokenEnv, undefined, counting);
  ok("authorise: a no-credential request is denied", !noCred.ok);
  ok("authorise: the retire resolver is NOT consulted without a presented bearer", called === 0);
  // The resolver is NOT consulted when no token is configured (env has no ADMIN_TOKEN): the token branch
  // returns before the resolver, so the Access/passkey/no-token paths never trigger the DO read.
  called = 0;
  const noTokenEnv = {} as unknown as Env;
  await authorise(tokenReq(), noTokenEnv, undefined, counting);
  ok("authorise: the retire resolver is NOT consulted when no token is configured", called === 0);
  // Precedence: a present-but-invalid passkey session still fails closed and never reaches the token path,
  // so the retire resolver is not consulted (the anti-downgrade rule is preserved). A passkey verifier that
  // returns null for a present cookie denies WITHOUT trying the token.
  called = 0;
  const denyPasskey: PasskeySessionVerifier = async () => null;
  const reqWithCookie = new Request("https://e.example/admin/x", { method: "GET", headers: { authorization: `Bearer ${TOKEN}`, cookie: "__Host-downpipes_session=whatever" } });
  const pk = await authorise(reqWithCookie, tokenEnv, denyPasskey, counting);
  ok("authorise: a present-but-invalid passkey session fails closed (not downgraded to token)", !pk.ok);
  ok("authorise: the retire resolver is NOT consulted when a passkey cookie pre-empts the token path", called === 0);
}

// AUTH-06 / AUTH-08: the same-isolate Access JWKS cache (auth.ts fetchCertsCached) is module-private, so it is
// driven THROUGH authorise() with a STUBBED global fetch, exercising the REAL certsCache + the real
// `fetch(url, { redirect: "manual" })` boundary (the fixture's injected fetchCerts never touches either).
//   AUTH-06: a 302 from the certs endpoint MUST surface as 'Access certs fetch failed' (the 3xx is NOT
//            followed to the attacker Location, so no off-surface key is ever loaded).
//   AUTH-08: a signing-key rotation WITHIN the 1h TTL hits the STALE cache (no refetch), so the new kid is
//            absent from the cached JWKS and the assertion is denied with reason 'signing key not found'.
// RESIDUAL: stubbing global fetch bypasses the workerd runtime's own redirect:'manual' handling; the test
// asserts the source REQUESTS redirect:'manual' and that a 3xx response yields a throw, which is the closest
// faithful offline proof of "the redirect is not followed".
async function proveCertsCacheAndRedirect(f: AccessFixture): Promise<void> {
  const { makeToken } = f;
  const realFetch = globalThis.fetch;
  // authorise() stamps `now` from the real clock, so the token exp must be in the real future (the fixture's
  // NOW constant is in the past relative to Date.now()); mint with a real-time claim set.
  const nowS = Math.floor(Date.now() / 1000);
  const claims = (iss: string): Record<string, unknown> => ({ iss, aud: AUD, exp: nowS + 3600, iat: nowS, email: "user@test.example", sub: "u-cache-1" });
  try {
    // ---- AUTH-06: a 302 from the certs endpoint is a failure, not followed. ----------------------------
    {
      const team = "access06test";
      const certsUrl = `https://${team}.cloudflareaccess.com/cdn-cgi/access/certs`;
      const evil = "https://evil.example/certs"; // the attacker Location the redirect would point at
      const calls: { url: string; redirect: unknown }[] = [];
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        calls.push({ url, redirect: init?.redirect });
        return new Response(null, { status: 302, headers: { Location: evil } });
      }) as typeof fetch;
      const env = { CF_ACCESS_TEAM_DOMAIN: team, CF_ACCESS_AUD: AUD } as unknown as Env;
      const req = new Request("https://e.example/admin/x", { method: "GET", headers: { "cf-access-jwt-assertion": await makeToken(claims(`https://${team}.cloudflareaccess.com`)) } });
      // A 3xx from the certs endpoint is a classified, fail-closed DENY: the security property (the redirect
      // is never followed, no off-surface key is ever loaded) is asserted below, and the deny leaves EVIDENCE.
      const signals: string[] = [];
      const sink: AuthDenySink = (s) => signals.push(s);
      let threw = "";
      let denied = false;
      try {
        denied = (await authorise(req, env, undefined, undefined, sink)).ok === false;
      } catch (e) {
        threw = e instanceof Error ? e.message : String(e);
      }
      ok("AUTH-06: a 302 from the certs endpoint DENIES (fail-closed) and no longer throws a 500 (G200)", threw === "" && denied);
      ok("AUTH-06: the 302 is recorded as cf-access-jwks-non-2xx, so the outage is visible in the pack (G200)", signals.includes("cf-access-jwks-non-2xx"));
      ok("AUTH-06: the certs fetch was issued with redirect:'manual' (the runtime never follows the 3xx)", calls.length === 1 && calls[0]!.redirect === "manual");
      ok("AUTH-06: only the cloudflareaccess.com certs URL was fetched (no off-surface key load)", calls.length === 1 && calls[0]!.url === certsUrl && !calls.some((c) => c.url === evil));
    }

    // ---- AUTH-08: a kid rotation within the 1h TTL hits the STALE cache -> 'signing key not found'. ------
    {
      const team = "access08test";
      const iss = `https://${team}.cloudflareaccess.com`;
      const jwksKID = { keys: [{ kid: KID, kty: "RSA", n: f.pubJwk.n, e: f.pubJwk.e }] };
      let fetchCount = 0;
      globalThis.fetch = (async (): Promise<Response> => {
        fetchCount++;
        return new Response(JSON.stringify(jwksKID), { status: 200, headers: { "content-type": "application/json" } });
      }) as typeof fetch;
      const env = { CF_ACCESS_TEAM_DOMAIN: team, CF_ACCESS_AUD: AUD } as unknown as Env;
      // Prime the cache: a kid=KID token authorises and populates certsCache for this URL (exactly one fetch).
      const primeReq = new Request("https://e.example/admin/x", { method: "GET", headers: { "cf-access-jwt-assertion": await makeToken(claims(iss)) } });
      const primed = await authorise(primeReq, env);
      ok("AUTH-08: the priming token authorises and populates the certs cache (one fetch)", primed.ok === true && fetchCount === 1);
      // Rotate: a NEW kid within the 1h TTL. The cache is NOT refreshed (no second fetch), so the new kid is
      // absent from the cached JWKS and the assertion is denied.
      const rotatedReq = new Request("https://e.example/admin/x", { method: "GET", headers: { "cf-access-jwt-assertion": await makeToken(claims(iss), { kid: "rotated-kid-2" }) } });
      const rotated = await authorise(rotatedReq, env);
      ok("AUTH-08: a token with a new kid within the 1h TTL is denied (stale cache, key absent)", rotated.ok === false);
      ok("AUTH-08: the stale cache was used (no refetch on the rotated kid within the TTL)", fetchCount === 1);
      // Pin the exact internal reason via verifyAccessJWT against the same (stale) cached JWKS: the missing
      // kid resolves to 'signing key not found' in fetchAndImportKey, the reason authorise() collapses to ok:false.
      const direct = await verifyAccessJWT(await makeToken(claims(iss), { kid: "rotated-kid-2" }), { teamDomain: team, aud: AUD, fetchCerts: async () => jwksKID, now: nowS });
      ok("AUTH-08: the rotated kid against the stale JWKS yields reason 'signing key not found'", direct.ok === false && direct.reason === "signing key not found");
    }
  } finally {
    globalThis.fetch = realFetch;
  }
}

// P3: the Cloudflare Access DENIAL diagnostic - the closed classifier (accessDenySignal) and authorise()'s
// injected best-effort onAuthDeny sink that records WHY a present-but-invalid assertion was refused, without
// ever altering the fail-closed deny. Covers cf-access-aud-wrong / -team-domain-typo / -jwks-cache-stale.
async function proveAccessDenySignal(f: AccessFixture): Promise<void> {
  // (1) the pure classifier: each verifyAccessJWT reason family maps to its closed cf-access-* signal.
  ok("accessDenySignal: an aud mismatch maps to cf-access-aud-mismatch", accessDenySignal("aud mismatch") === "cf-access-aud-mismatch");
  ok("accessDenySignal: an issuer mismatch maps to cf-access-issuer-mismatch", accessDenySignal("issuer https://a != https://b") === "cf-access-issuer-mismatch");
  ok("accessDenySignal: a team-domain error maps to cf-access-issuer-mismatch", accessDenySignal('team domain resolves to "x", which is not a *.cloudflareaccess.com host') === "cf-access-issuer-mismatch");
  ok("accessDenySignal: a signing-key miss maps to cf-access-key-unknown (stale-JWKS rotation)", accessDenySignal("signing key not found") === "cf-access-key-unknown" && accessDenySignal('signing key has unexpected kty "EC"; expected RSA') === "cf-access-key-unknown");
  // The Access verify-failure sub-causes (a clock skew, an alg downgrade, a wrong typ, a bad signature and a
  // corrupt token) each classify separately. cf-access-verify-failed survives as the residual for anything
  // unnamed. The full sub-cause table + the anchored-rule hijack proofs live in test/validate-admin-auth-diag.ts.
  ok("accessDenySignal: a bad signature maps to cf-access-verify-failed-signature (G231)", accessDenySignal("bad signature") === "cf-access-verify-failed-signature");
  ok("accessDenySignal: a malformed JWT maps to cf-access-verify-failed-malformed-jwt (G231)", accessDenySignal("malformed JWT") === "cf-access-verify-failed-malformed-jwt");
  ok("accessDenySignal: an UNNAMED reason still maps to cf-access-verify-failed (the residual bucket survives)", accessDenySignal("something nobody named") === "cf-access-verify-failed");

  // (2) the authorise() sink: a PRESENT-but-invalid Access assertion emits the classified signal to the injected
  // best-effort sink AND is still denied (never downgraded). aud / issuer / malformed all resolve PRE-crypto, so
  // no global fetch / certs cache is touched by this proof.
  const nowS = Math.floor(Date.now() / 1000);
  const env = { CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD } as unknown as Env;
  const drive = async (assertion: string): Promise<{ ok: boolean; signals: string[] }> => {
    const signals: string[] = [];
    const sink: AuthDenySink = (s) => signals.push(s);
    const req = new Request("https://e.example/admin/x", { method: "GET", headers: { "cf-access-jwt-assertion": assertion } });
    const v = await authorise(req, env, undefined, undefined, sink);
    return { ok: v.ok, signals };
  };
  const audRes = await drive(await f.makeToken({ iss: ISS, aud: "WRONG-AUD", exp: nowS + 3600, iat: nowS, email: "u@test.example", sub: "s1" }));
  ok("authorise: a wrong-aud Access assertion is denied AND emits cf-access-aud-mismatch to the sink", audRes.ok === false && audRes.signals.includes("cf-access-aud-mismatch"));
  const issRes = await drive(await f.makeToken({ iss: "https://someoneelse.cloudflareaccess.com", aud: AUD, exp: nowS + 3600, iat: nowS, email: "u@test.example", sub: "s2" }));
  ok("authorise: a wrong-issuer (team-domain typo) Access assertion emits cf-access-issuer-mismatch", issRes.ok === false && issRes.signals.includes("cf-access-issuer-mismatch"));
  const malRes = await drive("not-a-valid-jwt");
  ok("authorise: a malformed Access assertion emits cf-access-verify-failed-malformed-jwt (G231)", malRes.ok === false && malRes.signals.includes("cf-access-verify-failed-malformed-jwt"));
  // With NO sink wired (the default, every non-router caller), a denial emits nothing and behaviour is unchanged.
  const noSink = await authorise(new Request("https://e.example/admin/x", { method: "GET", headers: { "cf-access-jwt-assertion": "not-a-valid-jwt" } }), env);
  ok("authorise: with no onAuthDeny sink a denied assertion is still denied (no emit, unchanged behaviour)", noSink.ok === false);
}

async function main(): Promise<void> {
  const f = await buildFixture();
  await proveHappyAndSubject(f);
  await proveAccessDenySignal(f);
  await proveRejections(f);
  await proveTypHeader(f);
  await proveTeamDomainGuard(f);
  await proveKtyGuard(f);
  await proveGroupsBounding(f);
  await proveIdpBounding(f);
  await proveAuthorisePrecedence();
  await proveCertsCacheAndRedirect(f);

  console.log(failures === 0 ? "\nACCESS JWT VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
