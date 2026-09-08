// Prove the IdP/SSO "test connection" pre-save probe (engine/src/admin/idp-test.ts + the POST /admin/idp/test
// route in router.ts) end to end with in-memory doubles only. No network: every outbound fetch is a stub.
// Run:
//   node test/validate-idp-test.ts
//
// This is the engine half of the fix for a misconfiguration that was only discovered at the first
// sign-in. The probe is READ-ONLY (it only fetches the discovery doc + JWKS an IdP publishes, and parses the
// SAML config/metadata the operator holds), SSRF-disciplined (https + the engine's internal-host classifier +
// redirect:"manual" with a 3xx refused + a byte cap + a per-fetch timeout), and TOLERANT (any fault is a failed CHECK, never a
// throw / 500). What this proves:
//   OIDC (pure core, stubbed fetch):
//     - a healthy config returns ALL checks pass (discovery 200 + issuer match + endpoints + a usable JWKS);
//     - a MISSING discovery field (jwks_uri) returns ok:false with the specific failing discovery check;
//     - an EMPTY JWKS returns ok:false with the specific "no usable signing key" check;
//     - a NON-200 discovery returns ok:false with the specific discovery check (not a throw);
//     - an INTERNAL-HOST issuer/jwks URL returns ok:false with the SSRF check AND performs NO fetch.
//   SAML (pure core, no network):
//     - a healthy config (entityID + https SSO URL + an in-window pinned cert) passes;
//     - an EXPIRED pinned cert fails the validity check; an UNPARSEABLE cert fails it too;
//     - a pasted IdP metadata XML missing a SingleSignOnService fails the metadata check.
//   Route (real handleAdmin, real SchedulerDO over in-memory storage):
//     - a NON-OWNER caller (a bootstrapped viewer) is REFUSED with a 403 and NO outbound IdP fetch occurs;
//     - an OWNER (ADMIN_TOKEN break-glass) reaches the probe and gets the structured { ok, checks } result.
//
// Node 25 strip-types; Web Crypto only.

import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { testOidcConnection, testSamlConnection, runIdpConnectionTest } from "../src/admin/idp-test.ts";
import type { IdpTestResult, IdpTestCheck, IdpTestProposal } from "../src/admin/idp-test.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// findCheck returns the first check whose name contains the substring (case-insensitive), or undefined.
function findCheck(r: IdpTestResult, nameContains: string): IdpTestCheck | undefined {
  return r.checks.find((c) => c.name.toLowerCase().includes(nameContains.toLowerCase()));
}
function allPass(r: IdpTestResult): boolean {
  return r.ok && r.checks.length > 0 && r.checks.every((c) => c.status === "pass");
}

// ---- a usable JWKS (real RSA + EC public keys) --------------------------------------------------
const ISSUER = "https://idp.example.com";
const DISCO_URL = `${ISSUER}/.well-known/openid-configuration`;
const JWKS_URL = "https://idp.example.com/jwks";
const AUTH_URL = "https://idp.example.com/authorize";
const TOKEN_URL = "https://idp.example.com/token";

const rsa = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
const rsaPub = (await crypto.subtle.exportKey("jwk", rsa.publicKey)) as { n: string; e: string };
const ec = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const ecPub = (await crypto.subtle.exportKey("jwk", ec.publicKey)) as { x: string; y: string };
const JWKS_GOOD = { keys: [{ kid: "rsa-1", kty: "RSA", alg: "RS256", use: "sig", n: rsaPub.n, e: rsaPub.e }, { kid: "ec-1", kty: "EC", crv: "P-256", x: ecPub.x, y: ecPub.y }] };
// A JWKS with keys present but NONE usable (an oct/HMAC key has no n/e or x/y a verifier can import).
const JWKS_UNUSABLE = { keys: [{ kid: "oct-1", kty: "oct", k: "c2VjcmV0" }, { kid: "rsa-bad", kty: "RSA" /* no n/e */ }] };

// A standard discovery document for the healthy case; omitField drops one key to prove the missing-field path.
function discoveryDoc(omitField?: string): Record<string, unknown> {
  const d: Record<string, unknown> = {
    issuer: ISSUER,
    authorization_endpoint: AUTH_URL,
    token_endpoint: TOKEN_URL,
    jwks_uri: JWKS_URL,
  };
  if (omitField !== undefined) delete d[omitField];
  return d;
}

// makeStubFetch builds an injected fetch that serves a scripted route table and COUNTS calls, so a test can
// assert WHICH URLs were hit (and that an SSRF-blocked probe made none). A route may return a Response or
// throw (to simulate DNS/connection failure). Any URL not in the table throws a loud error.
function makeStubFetch(routes: Record<string, () => Response>): { fetch: typeof fetch; calls: string[] } {
  const calls: string[] = [];
  const fn = (async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
    calls.push(url);
    const r = routes[url];
    if (r === undefined) throw new Error(`unexpected fetch in test: ${url}`);
    return r();
  }) as typeof fetch;
  return { fetch: fn, calls };
}
function jsonResp(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

// ---- minimal DER cert builder (borrowed from validate-cert-notafter.ts) so we control the window ----
function derLen(n: number): number[] {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  let x = n;
  while (x > 0) {
    bytes.unshift(x & 0xff);
    x = Math.floor(x / 256);
  }
  return [0x80 | bytes.length, ...bytes];
}
function tlv(tag: number, content: number[]): number[] {
  return [tag, ...derLen(content.length), ...content];
}
function ascii(s: string): number[] {
  return Array.from(s).map((c) => c.charCodeAt(0));
}
const genTime = (s: string): number[] => tlv(0x18, ascii(s)); // GeneralizedTime YYYYMMDDHHMMSSZ
function toPem(b64: string): string {
  const wrapped = b64.replace(/(.{64})/g, "$1\n");
  return `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----\n`;
}
// buildCert assembles a minimal cert DER with a chosen notBefore..notAfter (both GeneralizedTime) and PEM-wraps
// it. certValidity walks Certificate -> tbs -> serial -> sigAlg -> issuer -> validity, so nothing past validity
// is needed. The two args are "YYYYMMDDHHMMSSZ" strings.
function buildCert(nb: string, na: string): string {
  const serial = tlv(0x02, [0x01]);
  const sigAlg = tlv(0x30, []);
  const issuer = tlv(0x30, []);
  const validity = tlv(0x30, [...genTime(nb), ...genTime(na)]);
  const tbs = tlv(0x30, [...serial, ...sigAlg, ...issuer, ...validity]);
  return toPem(Buffer.from(tlv(0x30, tbs)).toString("base64"));
}
// A GeneralizedTime string N days from `from` (epoch ms).
function gtFrom(fromMs: number, days: number): string {
  const d = new Date(fromMs + days * 24 * 60 * 60 * 1000);
  const p = (n: number, w = 2): string => String(n).padStart(w, "0");
  return `${p(d.getUTCFullYear(), 4)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
}

const NOW = Date.UTC(2026, 5, 17, 12, 0, 0); // a fixed clock so the cert windows are deterministic
const CERT_VALID = buildCert(gtFrom(NOW, -30), gtFrom(NOW, 300)); // valid now, ~300 days left (no warn)
const CERT_SOON = buildCert(gtFrom(NOW, -30), gtFrom(NOW, 10)); // valid now, 10 days left (warn)
const CERT_EXPIRED = buildCert(gtFrom(NOW, -400), gtFrom(NOW, -30)); // expired 30 days ago
const CERT_GARBAGE = "-----BEGIN CERTIFICATE-----\n@@@ not base64 @@@\n-----END CERTIFICATE-----\n";

// A small but well-formed IdP SAML metadata document (good) and one missing the SingleSignOnService (bad).
const META_GOOD =
  '<?xml version="1.0"?>' +
  '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/entity">' +
  '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">' +
  '<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data>' +
  "<ds:X509Certificate>MIIBdummyBase64CertContent==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>" +
  '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>' +
  "</md:IDPSSODescriptor></md:EntityDescriptor>";
const META_NO_SSO =
  '<?xml version="1.0"?>' +
  '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/entity">' +
  '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">' +
  '<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data>' +
  "<ds:X509Certificate>MIIBdummyBase64CertContent==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>" +
  "</md:IDPSSODescriptor></md:EntityDescriptor>";

import { MockStorage } from "./mock-storage.ts";

function makeScheduler(): { env: Pick<Env, "SCHEDULER">; storage: MockStorage } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  return { env: { SCHEDULER: namespace }, storage };
}

// ---- forged Access JWT (real RS256 verification, controlled JWKS) for the non-owner route test ----
const TEAM = "maelstrom";
const ACCESS_ISS = `https://${TEAM}.cloudflareaccess.com`;
const ACCESS_AUD = "idp-test-aud";
const ACCESS_KID = "idp-test-kid";
function jwtPart(obj: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}

async function main(): Promise<void> {
  // ============================ OIDC PURE-CORE CHECKS ============================
  // 1. Healthy OIDC: discovery 200 + matching issuer + endpoints + a usable JWKS -> ALL pass.
  {
    const { fetch, calls } = makeStubFetch({
      [DISCO_URL]: () => jsonResp(discoveryDoc()),
      [JWKS_URL]: () => jsonResp(JWKS_GOOD),
    });
    const r = await testOidcConnection({ issuer: ISSUER }, fetch, { timeoutMs: 1000 });
    ok("OIDC healthy: result.ok is true", r.ok === true);
    ok("OIDC healthy: every check passes", allPass(r));
    ok("OIDC healthy: a JWKS check reports usable signing keys", findCheck(r, "JWKS")?.status === "pass");
    ok("OIDC healthy: fetched discovery then JWKS (two calls)", calls.length === 2 && calls[0] === DISCO_URL && calls[1] === JWKS_URL);
  }

  // 2. Missing discovery field (jwks_uri absent): the specific discovery-endpoints check fails, no throw.
  {
    const { fetch } = makeStubFetch({
      [DISCO_URL]: () => jsonResp(discoveryDoc("jwks_uri")),
    });
    const r = await testOidcConnection({ issuer: ISSUER }, fetch, { timeoutMs: 1000 });
    ok("OIDC missing jwks_uri: result.ok is false", r.ok === false);
    const c = findCheck(r, "Discovery endpoints");
    ok("OIDC missing jwks_uri: the discovery-endpoints check FAILS", c?.status === "fail");
    ok("OIDC missing jwks_uri: the detail names jwks_uri", (c?.detail ?? "").includes("jwks_uri"));
    ok("OIDC missing jwks_uri: the JWKS check is skipped (not attempted)", findCheck(r, "Signing keys (JWKS)")?.status === "fail");
  }

  // 3. Empty / unusable JWKS: discovery is fine but no usable signing key -> the JWKS check fails.
  {
    const { fetch } = makeStubFetch({
      [DISCO_URL]: () => jsonResp(discoveryDoc()),
      [JWKS_URL]: () => jsonResp({ keys: [] }),
    });
    const r = await testOidcConnection({ issuer: ISSUER }, fetch, { timeoutMs: 1000 });
    ok("OIDC empty JWKS: result.ok is false", r.ok === false);
    ok("OIDC empty JWKS: the discovery check still passed", findCheck(r, "Discovery document")?.status === "pass");
    ok("OIDC empty JWKS: the JWKS check fails with the no-usable-key reason", findCheck(r, "JWKS")?.status === "fail" && /usable/i.test(findCheck(r, "JWKS")!.detail));
  }
  {
    // A JWKS that returns keys but NONE importable (oct + an RSA without n/e) is also a fail.
    const { fetch } = makeStubFetch({
      [DISCO_URL]: () => jsonResp(discoveryDoc()),
      [JWKS_URL]: () => jsonResp(JWKS_UNUSABLE),
    });
    const r = await testOidcConnection({ issuer: ISSUER }, fetch, { timeoutMs: 1000 });
    ok("OIDC unusable JWKS keys: result.ok is false", r.ok === false);
    ok("OIDC unusable JWKS keys: the JWKS check fails", findCheck(r, "JWKS")?.status === "fail");
  }

  // 4. Non-200 discovery: the discovery check fails with the status, no throw, JWKS skipped.
  {
    const { fetch, calls } = makeStubFetch({
      [DISCO_URL]: () => new Response("nope", { status: 404 }),
    });
    const r = await testOidcConnection({ issuer: ISSUER }, fetch, { timeoutMs: 1000 });
    ok("OIDC non-200 discovery: result.ok is false", r.ok === false);
    const c = findCheck(r, "Discovery document");
    ok("OIDC non-200 discovery: the discovery check fails and names the status", c?.status === "fail" && c.detail.includes("404"));
    ok("OIDC non-200 discovery: the JWKS was never fetched", !calls.includes(JWKS_URL));
  }
  {
    // A discovery fetch that THROWS (DNS/connect failure) is a clean failed check, not a 500.
    const { fetch } = makeStubFetch({
      [DISCO_URL]: () => {
        throw new Error("getaddrinfo ENOTFOUND idp.example.com");
      },
    });
    const r = await testOidcConnection({ issuer: ISSUER }, fetch, { timeoutMs: 1000 });
    ok("OIDC discovery DNS failure: result.ok is false (no throw)", r.ok === false);
    ok("OIDC discovery DNS failure: the discovery check fails", findCheck(r, "Discovery document")?.status === "fail");
    // The coarse detail must NOT leak the raw upstream error text.
    ok("OIDC discovery DNS failure: the detail is coarse (no raw error text)", !/ENOTFOUND/.test(findCheck(r, "Discovery document")!.detail));
  }

  {
    // An oversized upstream `issuer` in the discovery doc must be capped before being echoed into the detail
    // (the body is only size-limited to 256 KiB, so the detail must stay coarse: see idp-test-oidc.ts).
    const huge = "https://evil.example.com/" + "a".repeat(10000);
    const { fetch } = makeStubFetch({
      [DISCO_URL]: () => jsonResp({ ...discoveryDoc(), issuer: huge }),
    });
    const r = await testOidcConnection({ issuer: ISSUER }, fetch, { timeoutMs: 1000 });
    const c = findCheck(r, "Discovery document");
    ok("OIDC oversized issuer: the discovery check FAILS", c?.status === "fail");
    ok("OIDC oversized issuer: result.ok is false", r.ok === false);
    // The detail must not embed the full attacker-controlled string; it caps the echoed issuer at 256 chars.
    ok("OIDC oversized issuer: the detail does not embed the full oversized issuer", !c!.detail.includes(huge));
    ok("OIDC oversized issuer: the detail is bounded", c!.detail.length < huge.length);
  }

  // 5. Internal-host issuer (SSRF): refused as a failed check, and NO fetch is performed.
  {
    const { fetch, calls } = makeStubFetch({}); // any fetch would throw "unexpected fetch"
    const r = await testOidcConnection({ issuer: "https://169.254.169.254/oidc" }, fetch, { timeoutMs: 1000 });
    ok("OIDC internal-host issuer: result.ok is false", r.ok === false);
    ok("OIDC internal-host issuer: the issuer check fails", findCheck(r, "Issuer")?.status === "fail");
    ok("OIDC internal-host issuer: NO outbound fetch was made", calls.length === 0);
  }
  {
    // An internal jwks_uri advertised by an (otherwise fine) discovery doc is caught at the JWKS screen
    // BEFORE any JWKS fetch (the discovery-endpoints screen rejects it, so the probe stops there).
    const internalDisco = { issuer: ISSUER, authorization_endpoint: AUTH_URL, token_endpoint: TOKEN_URL, jwks_uri: "https://127.0.0.1/jwks" };
    const { fetch, calls } = makeStubFetch({
      [DISCO_URL]: () => jsonResp(internalDisco),
    });
    const r = await testOidcConnection({ issuer: ISSUER }, fetch, { timeoutMs: 1000 });
    ok("OIDC internal jwks_uri: result.ok is false", r.ok === false);
    ok("OIDC internal jwks_uri: a check fails for the unsafe endpoint", r.checks.some((c) => c.status === "fail" && /internal|https|endpoint/i.test(c.detail)));
    ok("OIDC internal jwks_uri: the loopback JWKS was never fetched", !calls.includes("https://127.0.0.1/jwks"));
  }

  // 5b. Explicit endpoints (no discovery): the live flow skips discovery; the JWKS is still proven.
  {
    const { fetch, calls } = makeStubFetch({
      [JWKS_URL]: () => jsonResp(JWKS_GOOD),
    });
    const r = await testOidcConnection({ issuer: ISSUER, authorizationEndpoint: AUTH_URL, tokenEndpoint: TOKEN_URL, jwksUri: JWKS_URL }, fetch, { timeoutMs: 1000 });
    ok("OIDC explicit endpoints: result.ok is true", r.ok === true);
    ok("OIDC explicit endpoints: discovery was NOT fetched (only the JWKS)", calls.length === 1 && calls[0] === JWKS_URL);
    ok("OIDC explicit endpoints: an 'explicit endpoints' check is present and passes", findCheck(r, "Explicit endpoints")?.status === "pass");
  }

  // ============================ SAML PURE-CORE CHECKS ============================
  // 6. Healthy SAML: entityID + https SSO URL + an in-window pinned cert -> passes.
  {
    const r = testSamlConnection({ idpEntityId: "https://idp.example.com/entity", idpSsoUrl: "https://idp.example.com/sso", idpSigningCerts: [CERT_VALID] }, { now: NOW });
    ok("SAML healthy: result.ok is true", r.ok === true);
    ok("SAML healthy: entityID check passes", findCheck(r, "entityID")?.status === "pass");
    ok("SAML healthy: SSO URL check passes", findCheck(r, "SingleSignOnService")?.status === "pass");
    ok("SAML healthy: signing-cert check passes", findCheck(r, "Signing certificate")?.status === "pass");
  }

  // 6b. A valid cert nearing expiry is a WARN (still ok:true) - it does not fail the test.
  {
    const r = testSamlConnection({ idpEntityId: "e", idpSsoUrl: "https://idp.example.com/sso", idpSigningCerts: [CERT_SOON] }, { now: NOW });
    ok("SAML soon-expiring cert: result.ok stays true (warn, not fail)", r.ok === true);
    ok("SAML soon-expiring cert: the cert check is a warn", findCheck(r, "Signing certificate")?.status === "warn");
  }

  // 7. Expired pinned cert fails the validity check.
  {
    const r = testSamlConnection({ idpEntityId: "e", idpSsoUrl: "https://idp.example.com/sso", idpSigningCerts: [CERT_EXPIRED] }, { now: NOW });
    ok("SAML expired cert: result.ok is false", r.ok === false);
    const c = findCheck(r, "Signing certificate");
    ok("SAML expired cert: the cert check fails on the validity window", c?.status === "fail" && /validity window|expired|not yet valid/i.test(c.detail));
  }
  // 7b. Unparseable cert fails too.
  {
    const r = testSamlConnection({ idpEntityId: "e", idpSsoUrl: "https://idp.example.com/sso", idpSigningCerts: [CERT_GARBAGE] }, { now: NOW });
    ok("SAML unparseable cert: result.ok is false", r.ok === false);
    ok("SAML unparseable cert: the cert check fails on parse", findCheck(r, "Signing certificate")?.status === "fail");
  }
  // 7c. An internal-host SSO URL fails the SSO check.
  {
    const r = testSamlConnection({ idpEntityId: "e", idpSsoUrl: "http://localhost/sso", idpSigningCerts: [CERT_VALID] }, { now: NOW });
    ok("SAML internal SSO URL: result.ok is false", r.ok === false);
    ok("SAML internal SSO URL: the SSO check fails", findCheck(r, "SingleSignOnService")?.status === "fail");
  }
  // 7d. Missing entityID + missing cert each fail.
  {
    const r = testSamlConnection({ idpSsoUrl: "https://idp.example.com/sso" }, { now: NOW });
    ok("SAML missing entityID+cert: result.ok is false", r.ok === false);
    ok("SAML missing entityID: the entityID check fails", findCheck(r, "entityID")?.status === "fail");
    ok("SAML missing cert: the signing-cert check fails", findCheck(r, "Signing certificate")?.status === "fail");
  }

  // 8. SAML IdP metadata XML: a good document passes its check; one missing SSO fails it.
  {
    const good = testSamlConnection({ idpEntityId: "https://idp.example.com/entity", idpSsoUrl: "https://idp.example.com/sso", idpSigningCerts: [CERT_VALID], idpMetadataXml: META_GOOD }, { now: NOW });
    ok("SAML metadata good: result.ok is true", good.ok === true);
    ok("SAML metadata good: the metadata check passes", findCheck(good, "metadata")?.status === "pass");

    const noSso = testSamlConnection({ idpEntityId: "https://idp.example.com/entity", idpSsoUrl: "https://idp.example.com/sso", idpSigningCerts: [CERT_VALID], idpMetadataXml: META_NO_SSO }, { now: NOW });
    ok("SAML metadata missing SSO: result.ok is false", noSso.ok === false);
    const c = findCheck(noSso, "metadata");
    ok("SAML metadata missing SSO: the metadata check fails and names the SingleSignOnService", c?.status === "fail" && /SingleSignOnService/i.test(c.detail));

    const badXml = testSamlConnection({ idpEntityId: "e", idpSsoUrl: "https://idp.example.com/sso", idpSigningCerts: [CERT_VALID], idpMetadataXml: "<not><well-formed>" }, { now: NOW });
    ok("SAML metadata unparseable: result.ok is false", badXml.ok === false);
    ok("SAML metadata unparseable: the metadata check fails", findCheck(badXml, "metadata")?.status === "fail");
  }

  // 9. An unknown kind is a clean failed check (never a throw).
  {
    const r = await runIdpConnectionTest({ kind: "ldap" }, makeStubFetch({}).fetch);
    ok("unknown kind: result.ok is false", r.ok === false);
    ok("unknown kind: a single failing 'Connection kind' check", r.checks.length === 1 && r.checks[0]!.status === "fail" && /kind/i.test(r.checks[0]!.name));
  }
  {
    // A non-string kind (and a wholly absent kind) takes the OTHER arm of the kind-naming ternary: the detail
    // says "(none supplied)" rather than quoting a string, and it is still a single clean failed check.
    const numericKind = await runIdpConnectionTest({ kind: 7 } as never, makeStubFetch({}).fetch);
    ok("numeric kind: result.ok is false", numericKind.ok === false);
    ok("numeric kind: the detail says (none supplied), not a quoted string", numericKind.checks[0]!.detail.includes("(none supplied)"));
    const noKind = await runIdpConnectionTest({}, makeStubFetch({}).fetch);
    ok("absent kind: result.ok is false with the (none supplied) detail", noKind.ok === false && noKind.checks[0]!.detail.includes("(none supplied)"));
  }
  {
    // An UNEXPECTED fault inside the probe (here a proposal whose `kind` getter throws) is swallowed into a
    // single failed "Test connection" check, never propagated as a throw, so the route still returns a result.
    const exploding = {} as IdpTestProposal;
    Object.defineProperty(exploding, "kind", {
      get() {
        throw new Error("simulated unexpected fault reading the proposal");
      },
    });
    const r = await runIdpConnectionTest(exploding, makeStubFetch({}).fetch);
    ok("unexpected fault: runIdpConnectionTest resolves (does not throw)", r.ok === false);
    ok("unexpected fault: it collapses to the coarse 'Test connection' failed check", findCheck(r, "Test connection")?.status === "fail");
    // The coarse detail must not leak the underlying error message.
    ok("unexpected fault: the detail is secret-free (no raw error text)", !/simulated unexpected fault/.test(findCheck(r, "Test connection")!.detail));
  }

  // ============================ DISPATCHER: every kind + its optional fields ============================
  // runIdpConnectionTest copies each optional field from the untrusted body only when it is a string. Drive the
  // oidc path WITH every optional field present (so each `!== undefined` copy arm runs), then the oauth2 path,
  // then the saml path with its optional fields, all through the real dispatcher.
  {
    // 9a. OIDC via the dispatcher carrying discoveryUrl + the three explicit endpoints (every copy arm taken).
    // With all three explicit endpoints set, the live flow skips discovery, so only the JWKS is fetched.
    const { fetch, calls } = makeStubFetch({ [JWKS_URL]: () => jsonResp(JWKS_GOOD) });
    const r = await runIdpConnectionTest(
      { kind: "oidc", issuer: ISSUER, discoveryUrl: DISCO_URL, authorizationEndpoint: AUTH_URL, tokenEndpoint: TOKEN_URL, jwksUri: JWKS_URL },
      fetch,
      { timeoutMs: 1000 },
    );
    ok("dispatcher oidc (all explicit endpoints): result.ok is true", r.ok === true);
    ok("dispatcher oidc (all explicit endpoints): only the JWKS was fetched (discovery skipped)", calls.length === 1 && calls[0] === JWKS_URL);
    ok("dispatcher oidc (all explicit endpoints): the explicit-endpoints check passes", findCheck(r, "Explicit endpoints")?.status === "pass");
  }
  {
    // 9b. OAuth2 (GitHub-class): no discovery + no JWKS, so the probe only screens endpoint SHAPE and emits an
    // honest "Live exchange" warn. A healthy set of https endpoints leaves ok:true (the warn does not fail it),
    // and NO outbound fetch is made (the empty stub would throw on any fetch).
    const { fetch, calls } = makeStubFetch({});
    const r = await runIdpConnectionTest(
      { kind: "oauth2", authorizeUrl: "https://gh.example.com/login/oauth/authorize", tokenUrl: "https://gh.example.com/login/oauth/access_token", profileUrl: "https://api.gh.example.com/user", apiBase: "https://api.gh.example.com" },
      fetch,
    );
    ok("dispatcher oauth2 (healthy): result.ok stays true (only a warn)", r.ok === true);
    ok("dispatcher oauth2 (healthy): each endpoint check passes", ["authorizeUrl", "tokenUrl", "profileUrl", "apiBase"].every((n) => findCheck(r, n)?.status === "pass"));
    ok("dispatcher oauth2 (healthy): a 'Live exchange' warn is surfaced", findCheck(r, "Live exchange")?.status === "warn");
    ok("dispatcher oauth2 (healthy): NO outbound fetch was made (pure shape screen)", calls.length === 0);
  }
  {
    // 9c. OAuth2 with a MISSING endpoint and an UNSAFE one: the missing field fails with "is not set", the
    // internal-host field fails the https screen, and both arms of the endpoint loop are exercised.
    const r = await runIdpConnectionTest(
      { kind: "oauth2", authorizeUrl: "https://gh.example.com/authorize", tokenUrl: "", profileUrl: "http://localhost/user", apiBase: "https://api.gh.example.com" },
      makeStubFetch({}).fetch,
    );
    ok("dispatcher oauth2 (bad): result.ok is false", r.ok === false);
    ok("dispatcher oauth2 (bad): the empty tokenUrl fails with 'is not set'", findCheck(r, "tokenUrl")?.status === "fail" && /is not set/.test(findCheck(r, "tokenUrl")!.detail));
    ok("dispatcher oauth2 (bad): the internal profileUrl fails the https screen", findCheck(r, "profileUrl")?.status === "fail" && /https endpoint/.test(findCheck(r, "profileUrl")!.detail));
    ok("dispatcher oauth2 (bad): the healthy authorizeUrl still passes", findCheck(r, "authorizeUrl")?.status === "pass");
  }
  {
    // 9d. SAML via the dispatcher carrying every optional field (entityID + SSO + certs + metadata XML), so each
    // string-copy arm in the saml branch runs and the saml probe gets the full config.
    const r = await runIdpConnectionTest(
      { kind: "saml", idpEntityId: "https://idp.example.com/entity", idpSsoUrl: "https://idp.example.com/sso", idpSigningCerts: [CERT_VALID], idpMetadataXml: META_GOOD },
      makeStubFetch({}).fetch,
      { now: NOW },
    );
    ok("dispatcher saml (full config): result.ok is true", r.ok === true);
    ok("dispatcher saml (full config): the metadata-XML check passes", findCheck(r, "metadata")?.status === "pass");
    ok("dispatcher saml (full config): the signing-cert check passes", findCheck(r, "Signing certificate")?.status === "pass");
  }
  {
    // 9e. The dispatcher reads only string-typed fields from the untrusted body. An OIDC proposal whose issuer
    // is the WRONG type (a number) is coerced by str() to undefined, then the `?? ""` fallback hands the probe
    // an empty issuer, which fails as a missing issuer. This drives the non-string arm of str(proposal.issuer).
    const r = await runIdpConnectionTest({ kind: "oidc", issuer: 12345 } as never, makeStubFetch({}).fetch, { timeoutMs: 1000 });
    ok("dispatcher oidc (non-string issuer): result.ok is false", r.ok === false);
    ok("dispatcher oidc (non-string issuer): it is treated as a missing issuer", findCheck(r, "Issuer")?.detail.includes("the issuer is missing") === true);
  }
  {
    // 9f. A SAML proposal whose idpSigningCerts is the WRONG type (not an array) is coerced by strArr() to
    // undefined, so the probe sees no pinned certs and fails the signing-certificate check. This drives the
    // non-array arm of strArr(); a sibling non-string entry inside a real array is also dropped.
    const r = await runIdpConnectionTest({ kind: "saml", idpEntityId: "e", idpSsoUrl: "https://idp.example.com/sso", idpSigningCerts: "not-an-array" } as never, makeStubFetch({}).fetch, { now: NOW });
    ok("dispatcher saml (non-array certs): result.ok is false", r.ok === false);
    ok("dispatcher saml (non-array certs): the signing-cert check fails for no pinned cert", findCheck(r, "Signing certificate")?.status === "fail" && /No pinned signing certificate/.test(findCheck(r, "Signing certificate")!.detail));
  }

  // ============================ OIDC: the remaining failure + screen branches ============================
  {
    // 10a. A non-empty but malformed issuer trips the URL parser inside the screen (not the empty-issuer guard):
    // the detail says the URL is not a valid absolute URL, and the dependent checks are skipped.
    const r = await testOidcConnection({ issuer: "definitely not a url" }, makeStubFetch({}).fetch, { timeoutMs: 1000 });
    ok("OIDC malformed issuer: result.ok is false", r.ok === false);
    const c = findCheck(r, "Issuer");
    ok("OIDC malformed issuer: the issuer check fails on a not-a-valid-URL detail", c?.status === "fail" && /not a valid absolute URL/.test(c.detail));
    ok("OIDC malformed issuer: discovery + JWKS are reported as skipped", findCheck(r, "Discovery document")?.detail.includes("Skipped") === true);
  }
  {
    // 10b. An EMPTY issuer takes the other arm of the issuer guard: "the issuer is missing" (no URL parse at all).
    const r = await testOidcConnection({ issuer: "" }, makeStubFetch({}).fetch, { timeoutMs: 1000 });
    ok("OIDC empty issuer: result.ok is false", r.ok === false);
    ok("OIDC empty issuer: the issuer check fails with 'the issuer is missing'", findCheck(r, "Issuer")?.detail.includes("the issuer is missing") === true);
  }
  {
    // 10c. Explicit endpoints where ONE is unsafe (an internal token_endpoint): the explicit-endpoints check
    // fails naming that endpoint, the JWKS is skipped, and NO fetch is attempted (the empty stub would throw).
    const { fetch, calls } = makeStubFetch({});
    const r = await testOidcConnection({ issuer: ISSUER, authorizationEndpoint: AUTH_URL, tokenEndpoint: "http://localhost/token", jwksUri: JWKS_URL }, fetch, { timeoutMs: 1000 });
    ok("OIDC explicit bad endpoint: result.ok is false", r.ok === false);
    const c = findCheck(r, "Explicit endpoints");
    ok("OIDC explicit bad endpoint: the check fails and names token_endpoint", c?.status === "fail" && /token_endpoint/.test(c.detail));
    ok("OIDC explicit bad endpoint: the JWKS check is skipped", findCheck(r, "Signing keys (JWKS)")?.detail.includes("Skipped") === true);
    ok("OIDC explicit bad endpoint: NO outbound fetch was made", calls.length === 0);
  }
  {
    // 10d. An explicit discoveryUrl pointing at an internal host (no explicit endpoints, so the discovery path
    // runs): discoveryUrlFor returns the explicit URL, which the re-screen refuses before any fetch.
    const { fetch, calls } = makeStubFetch({});
    const r = await testOidcConnection({ issuer: ISSUER, discoveryUrl: "https://127.0.0.1/.well-known/openid-configuration" }, fetch, { timeoutMs: 1000 });
    ok("OIDC unsafe discoveryUrl: result.ok is false", r.ok === false);
    ok("OIDC unsafe discoveryUrl: the discovery check fails on the unsafe-to-fetch reason", findCheck(r, "Discovery document")?.status === "fail" && /not safe to fetch/.test(findCheck(r, "Discovery document")!.detail));
    ok("OIDC unsafe discoveryUrl: NO discovery fetch was attempted", calls.length === 0);
  }
  {
    // 10e. Discovery returns NON-JSON (an HTML error page): the JSON.parse fails and is reported as such.
    const { fetch } = makeStubFetch({ [DISCO_URL]: () => new Response("<html>not json</html>", { status: 200, headers: { "content-type": "text/html" } }) });
    const r = await testOidcConnection({ issuer: ISSUER }, fetch, { timeoutMs: 1000 });
    ok("OIDC discovery non-JSON: result.ok is false", r.ok === false);
    ok("OIDC discovery non-JSON: the discovery check fails naming JSON", findCheck(r, "Discovery document")?.status === "fail" && /did not return JSON/.test(findCheck(r, "Discovery document")!.detail));
  }
  {
    // 10f. Discovery returns a JSON ARRAY (valid JSON, wrong shape): the not-an-object guard fails it.
    const { fetch } = makeStubFetch({ [DISCO_URL]: () => jsonResp([1, 2, 3]) });
    const r = await testOidcConnection({ issuer: ISSUER }, fetch, { timeoutMs: 1000 });
    ok("OIDC discovery array body: result.ok is false", r.ok === false);
    ok("OIDC discovery array body: the discovery check fails naming a JSON object", findCheck(r, "Discovery document")?.status === "fail" && /not a JSON object/.test(findCheck(r, "Discovery document")!.detail));
  }
  {
    // 10g. Discovery JSON object MISSING its own `issuer` field: the missing-issuer-field check fails.
    const { fetch } = makeStubFetch({ [DISCO_URL]: () => jsonResp(discoveryDoc("issuer")) });
    const r = await testOidcConnection({ issuer: ISSUER }, fetch, { timeoutMs: 1000 });
    ok("OIDC discovery no issuer field: result.ok is false", r.ok === false);
    ok("OIDC discovery no issuer field: the check fails naming the missing issuer field", findCheck(r, "Discovery document")?.status === "fail" && /missing its .?issuer/.test(findCheck(r, "Discovery document")!.detail));
  }
  {
    // 10h. Discovery issuer MISMATCH (the doc advertises a different issuer than the configured one): the
    // discovery check fails (at sign-in every token would be refused), which makes the whole result ok:false.
    // The mismatch is NOT short-circuiting: the probe records the failed discovery check then keeps validating
    // the rest of the (otherwise complete) doc, so the JWKS is still fetched. We serve it so the stub does not
    // throw, and assert the overall failure comes from the issuer-mismatch discovery check.
    const mismatch = { ...discoveryDoc(), issuer: "https://attacker.example.com" };
    const { fetch } = makeStubFetch({ [DISCO_URL]: () => jsonResp(mismatch), [JWKS_URL]: () => jsonResp(JWKS_GOOD) });
    const r = await testOidcConnection({ issuer: ISSUER }, fetch, { timeoutMs: 1000 });
    ok("OIDC discovery issuer mismatch: result.ok is false", r.ok === false);
    const c = findCheck(r, "Discovery document");
    ok("OIDC discovery issuer mismatch: the check fails naming both issuers", c?.status === "fail" && c.detail.includes("attacker.example.com") && c.detail.includes(ISSUER));
    ok("OIDC discovery issuer mismatch: the JWKS itself still verified (the failure is the issuer, not the keys)", findCheck(r, "JWKS")?.status === "pass");
  }
  {
    // 10i. JWKS fetch THROWS (DNS/connect failure) after a healthy discovery: a clean failed JWKS check, no 500.
    const { fetch } = makeStubFetch({
      [DISCO_URL]: () => jsonResp(discoveryDoc()),
      [JWKS_URL]: () => {
        throw new Error("getaddrinfo ENOTFOUND idp.example.com");
      },
    });
    const r = await testOidcConnection({ issuer: ISSUER }, fetch, { timeoutMs: 1000 });
    ok("OIDC JWKS fetch failure: result.ok is false (no throw)", r.ok === false);
    ok("OIDC JWKS fetch failure: the JWKS check fails", findCheck(r, "JWKS")?.status === "fail" && /Could not fetch the JWKS/.test(findCheck(r, "JWKS")!.detail));
    ok("OIDC JWKS fetch failure: the detail is coarse (no raw error text)", !/ENOTFOUND/.test(findCheck(r, "JWKS")!.detail));
  }
  {
    // 10j. JWKS returns NON-200: the JWKS check fails naming the status.
    const { fetch } = makeStubFetch({
      [DISCO_URL]: () => jsonResp(discoveryDoc()),
      [JWKS_URL]: () => new Response("err", { status: 503 }),
    });
    const r = await testOidcConnection({ issuer: ISSUER }, fetch, { timeoutMs: 1000 });
    ok("OIDC JWKS non-200: result.ok is false", r.ok === false);
    ok("OIDC JWKS non-200: the JWKS check fails naming HTTP 503", findCheck(r, "JWKS")?.status === "fail" && findCheck(r, "JWKS")!.detail.includes("503"));
  }
  {
    // 10k. JWKS returns NON-JSON: the JSON.parse of the JWKS body fails and is reported.
    const { fetch } = makeStubFetch({
      [DISCO_URL]: () => jsonResp(discoveryDoc()),
      [JWKS_URL]: () => new Response("<html>nope</html>", { status: 200, headers: { "content-type": "text/html" } }),
    });
    const r = await testOidcConnection({ issuer: ISSUER }, fetch, { timeoutMs: 1000 });
    ok("OIDC JWKS non-JSON: result.ok is false", r.ok === false);
    ok("OIDC JWKS non-JSON: the JWKS check fails naming JSON", findCheck(r, "JWKS")?.status === "fail" && /did not return JSON/.test(findCheck(r, "JWKS")!.detail));
  }
  {
    // 10l. JWKS is valid JSON but has NO `keys` array (an empty object): the no-keys-array check fails. This is
    // distinct from the existing empty-array and unusable-keys cases (it never enters the per-key loop at all).
    const { fetch } = makeStubFetch({
      [DISCO_URL]: () => jsonResp(discoveryDoc()),
      [JWKS_URL]: () => jsonResp({ not_keys: [] }),
    });
    const r = await testOidcConnection({ issuer: ISSUER }, fetch, { timeoutMs: 1000 });
    ok("OIDC JWKS no keys array: result.ok is false", r.ok === false);
    ok("OIDC JWKS no keys array: the JWKS check fails naming the missing keys array", findCheck(r, "JWKS")?.status === "fail" && /no .?keys.? array/.test(findCheck(r, "JWKS")!.detail));
  }
  {
    // 10m. A JWKS whose `keys` array carries non-object entries (null, a string, a number) takes the per-key
    // skip arm, leaving usable === 0, so it fails for the same "no usable key" reason but via a different branch.
    const { fetch } = makeStubFetch({
      [DISCO_URL]: () => jsonResp(discoveryDoc()),
      [JWKS_URL]: () => jsonResp({ keys: [null, "not-a-key", 42] }),
    });
    const r = await testOidcConnection({ issuer: ISSUER }, fetch, { timeoutMs: 1000 });
    ok("OIDC JWKS non-object keys: result.ok is false", r.ok === false);
    ok("OIDC JWKS non-object keys: the JWKS check fails on no usable signing key", findCheck(r, "JWKS")?.status === "fail" && /usable/.test(findCheck(r, "JWKS")!.detail));
  }
  {
    // 10n. The per-fetch TIMEOUT: a discovery route that NEVER resolves trips the AbortController, which the
    // bounded fetch surfaces as a clean "timed out" failed check, never a hang or a throw. A 1ms budget makes
    // the test fast; the stub returns a never-settling promise so only the abort can end the await.
    const calls: string[] = [];
    const hangingFetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      calls.push(url);
      return await new Promise<Response>((_resolve, reject) => {
        const sig = init?.signal;
        // Honour the AbortController the bounded fetch installs, exactly as a real fetch does: reject with an
        // AbortError when it fires, and never resolve otherwise (a black-holed host).
        if (sig) sig.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
      });
    }) as typeof fetch;
    const r = await testOidcConnection({ issuer: ISSUER }, hangingFetch, { timeoutMs: 1 });
    ok("OIDC discovery timeout: result.ok is false (no hang, no throw)", r.ok === false);
    ok("OIDC discovery timeout: the discovery check fails on a timed-out reason", findCheck(r, "Discovery document")?.status === "fail" && /timed out/.test(findCheck(r, "Discovery document")!.detail));
    ok("OIDC discovery timeout: the discovery URL was attempted then aborted", calls.includes(DISCO_URL));
  }

  // ============================ SAML: the remaining branches ============================
  {
    // 11a. testSamlConnection with NO opts: the now defaults to Date.now(). A cert valid for a wide window around
    // the real clock passes, proving the default-clock arm (every other SAML test pins now via opts).
    const wideStart = gtFrom(Date.now(), -3650);
    const wideEnd = gtFrom(Date.now(), 3650);
    const r = testSamlConnection({ idpEntityId: "e", idpSsoUrl: "https://idp.example.com/sso", idpSigningCerts: [buildCert(wideStart, wideEnd)] });
    ok("SAML default clock: result.ok is true", r.ok === true);
    ok("SAML default clock: the signing-cert check passes against the real clock", findCheck(r, "Signing certificate")?.status === "pass");
  }
  {
    // 11b. NO idpSsoUrl at all (the field is absent, not internal): the SSO check fails with the "No IdP SSO URL"
    // message, the other arm of the SSO presence guard (the existing tests all supply an SSO URL).
    const r = testSamlConnection({ idpEntityId: "e", idpSigningCerts: [CERT_VALID] }, { now: NOW });
    ok("SAML absent SSO URL: result.ok is false", r.ok === false);
    ok("SAML absent SSO URL: the SSO check fails with 'No IdP SSO URL'", findCheck(r, "SingleSignOnService")?.detail.includes("No IdP SSO URL") === true);
  }
  {
    // 11c. TWO soon-expiring certs where the second expires SOONER than the first: the warn must report the
    // soonest of the two, which exercises the `cv.notAfter < soonestExpiryWithinWarn` comparison arm (the first
    // cert sets soonestExpiryWithinWarn from null; the second, expiring earlier, must replace it).
    const certLater = buildCert(gtFrom(NOW, -30), gtFrom(NOW, 25)); // 25 days left
    const certSooner = buildCert(gtFrom(NOW, -30), gtFrom(NOW, 5)); // 5 days left -> the soonest
    const r = testSamlConnection({ idpEntityId: "e", idpSsoUrl: "https://idp.example.com/sso", idpSigningCerts: [certLater, certSooner] }, { now: NOW });
    ok("SAML two soon certs: result.ok stays true (warn)", r.ok === true);
    const c = findCheck(r, "Signing certificate");
    ok("SAML two soon certs: the cert check is a warn", c?.status === "warn");
    ok("SAML two soon certs: the warn reports the SOONEST expiry (about 5 days)", /about 5 day/.test(c?.detail ?? ""));
  }
  {
    // 11d. Pasted metadata MISSING its entityID attribute: the metadata check fails and the missing-list names
    // the EntityDescriptor entityID (the other branch of the per-field missing push).
    const metaNoEntity =
      '<?xml version="1.0"?>' +
      '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">' +
      "<md:IDPSSODescriptor>" +
      '<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data>' +
      "<ds:X509Certificate>MIIBdummyBase64CertContent==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>" +
      '<md:SingleSignOnService Location="https://idp.example.com/sso"/>' +
      "</md:IDPSSODescriptor></md:EntityDescriptor>";
    const r = testSamlConnection({ idpEntityId: "e", idpSsoUrl: "https://idp.example.com/sso", idpSigningCerts: [CERT_VALID], idpMetadataXml: metaNoEntity }, { now: NOW });
    ok("SAML metadata no entityID: result.ok is false", r.ok === false);
    ok("SAML metadata no entityID: the metadata check names the missing EntityDescriptor entityID", findCheck(r, "metadata")?.status === "fail" && /EntityDescriptor entityID/.test(findCheck(r, "metadata")!.detail));
  }
  {
    // 11e. Pasted metadata whose <ds:X509Certificate> holds ONLY a comment (no text node): the cert-text scan
    // takes the non-text arm of `c.type === "text" ? c.value : ""`, so hasCert stays false and the metadata is
    // reported as missing a signing certificate.
    const metaCommentCert =
      '<?xml version="1.0"?>' +
      '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/entity">' +
      "<md:IDPSSODescriptor>" +
      '<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data>' +
      "<ds:X509Certificate><!-- placeholder, no cert text --></ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>" +
      '<md:SingleSignOnService Location="https://idp.example.com/sso"/>' +
      "</md:IDPSSODescriptor></md:EntityDescriptor>";
    const r = testSamlConnection({ idpEntityId: "e", idpSsoUrl: "https://idp.example.com/sso", idpSigningCerts: [CERT_VALID], idpMetadataXml: metaCommentCert }, { now: NOW });
    ok("SAML metadata comment-only cert: result.ok is false", r.ok === false);
    ok("SAML metadata comment-only cert: the metadata check names the missing signing certificate", findCheck(r, "metadata")?.status === "fail" && /signing certificate/.test(findCheck(r, "metadata")!.detail));
  }

  // ============================ ROUTE: OWNER vs NON-OWNER ============================
  // The route is gated EXACTLY like the other IdP-management routes (keys.ceremony, owner-exclusive). We drive
  // the REAL handleAdmin + a REAL SchedulerDO. For the non-owner test the global fetch is a SPY that serves the
  // Access certs URL (so authorise() verifies the viewer's JWT for real) and counts any OTHER (i.e. IdP-bound)
  // fetch as a violation: a refused caller must trigger NO outbound probe fetch.
  {
    const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
    const pub = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
    const accessJwks = { keys: [{ kid: ACCESS_KID, kty: "RSA", n: pub.n, e: pub.e }] };
    const futureExp = Math.floor(Date.now() / 1000) + 3600;
    async function accessToken(email: string): Promise<string> {
      const header = jwtPart({ alg: "RS256", kid: ACCESS_KID, typ: "JWT" });
      const body = jwtPart({ iss: ACCESS_ISS, aud: ACCESS_AUD, exp: futureExp, iat: futureExp - 3600, email, sub: `sub-of-${email}` });
      const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
      return `${header}.${body}.${b64urlEncode(sig)}`;
    }

    const sched = makeScheduler();
    const accessEnv = (): Env => ({ ...sched.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: ACCESS_AUD }) as unknown as Env;

    // Install a fetch spy: serve ONLY the Access certs URL; any IdP-bound fetch is recorded as a violation.
    const certsUrl = `${ACCESS_ISS}/cdn-cgi/access/certs`;
    const idpFetches: string[] = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (url === certsUrl) return new Response(JSON.stringify(accessJwks), { headers: { "content-type": "application/json" } });
      idpFetches.push(url);
      throw new Error(`unexpected outbound fetch in non-owner route test: ${url}`);
    }) as typeof fetch;

    try {
      // Bootstrap the FIRST Access caller as Owner (empty role table -> first caller is Owner).
      const ownerEmail = "owner@acme.example";
      const bootReq = new Request("https://engine.example/admin/whoami", { method: "GET", headers: { "cf-access-jwt-assertion": await accessToken(ownerEmail) } });
      const bootResp = await handleAdmin(bootReq, accessEnv());
      ok("route setup: owner bootstrap whoami is 200", bootResp.status === 200);

      // A SECOND Access caller now defaults to viewer (no keys.ceremony). They POST /admin/idp/test.
      const viewerEmail = "viewer@acme.example";
      const oidcProposal = { kind: "oidc", id: "probe-conn", issuer: ISSUER };
      const testReq = new Request("https://engine.example/admin/idp/test", {
        method: "POST",
        headers: { "cf-access-jwt-assertion": await accessToken(viewerEmail), "content-type": "application/json" },
        body: JSON.stringify({ proposal: oidcProposal }),
      });
      const refused = await handleAdmin(testReq, accessEnv());
      ok("non-owner route: POST /admin/idp/test is refused with 403", refused.status === 403);
      const refusedBody = (await refused.json()) as { error?: string; required?: string };
      ok("non-owner route: the 403 names the keys.ceremony requirement", refusedBody.error === "forbidden" && refusedBody.required === "keys.ceremony");
      ok("non-owner route: NO IdP-bound outbound fetch was attempted", idpFetches.length === 0);

      // The denied attempt is recorded in the audit trail as an idp-connection-change/denied (op: test).
      const auditReq = new Request("https://engine.example/admin/audit?limit=20", { method: "GET", headers: { "cf-access-jwt-assertion": await accessToken(ownerEmail) } });
      const auditResp = await handleAdmin(auditReq, accessEnv());
      ok("non-owner route: the owner can read the audit feed (200)", auditResp.status === 200);
      const auditBody = (await auditResp.json()) as { events?: Array<{ action?: string; outcome?: string; target?: { kind?: string; op?: string } }> };
      const events = Array.isArray(auditBody.events) ? auditBody.events : [];
      const denied = events.find((e) => e.action === "idp-connection-change" && e.outcome === "denied" && e.target?.op === "test");
      ok("non-owner route: a denied idp-connection-change (op:test) audit event is recorded", denied !== undefined);

      // 10. The OWNER (here via the ADMIN_TOKEN break-glass on a SEPARATE env) reaches the probe and gets a
      // structured result. We serve the discovery + JWKS off the global fetch spy for this leg.
      const ADMIN_TOKEN = "idp-test-owner-token";
      const sched2 = makeScheduler();
      const tokenEnv = { ...sched2.env, ADMIN_TOKEN } as unknown as Env;
      globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
        if (url === DISCO_URL) return jsonResp(discoveryDoc());
        if (url === JWKS_URL) return jsonResp(JWKS_GOOD);
        throw new Error(`unexpected fetch in owner route test: ${url}`);
      }) as typeof fetch;
      const ownerReq = new Request("https://engine.example/admin/idp/test", {
        method: "POST",
        headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" },
        body: JSON.stringify({ proposal: { kind: "oidc", id: "probe-conn", issuer: ISSUER } }),
      });
      const ownerResp = await handleAdmin(ownerReq, tokenEnv);
      ok("owner route: POST /admin/idp/test returns 200", ownerResp.status === 200);
      const ownerResult = (await ownerResp.json()) as IdpTestResult;
      ok("owner route: the structured result is all-pass for the healthy config", allPass(ownerResult));
      ok("owner route: the result carries a JWKS check", findCheck(ownerResult, "JWKS") !== undefined);
    } finally {
      globalThis.fetch = realFetch;
    }
  }

  console.log(failures === 0 ? "\nIDP-TEST (test-connection probe) VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
