// Validates the in-product KEY INSTALL route (the no-customer-CLI ceremony): the engine installs
// the in-browser key ceremony's output as its OWN worker secrets via the Cloudflare dedicated
// secrets endpoint, using a console-collected scoped "Edit Cloudflare Workers" token. The route is
// the replacement for `wrangler secret put SIGNER_PRIVATE` etc., so the security-critical
// properties are the point of this test:
//   1. VALIDATE BEFORE WRITE: a malformed signerPrivate / breakGlassPublic returns 400 having made
//      ZERO fetch calls and set NOTHING.
//   2. GOOD KEYS: exactly the right PUTs by NAME (SIGNER_PRIVATE / BREAK_GLASS_PUBLIC, plus the
//      optional OPERATIONAL_*), each with type secret_text, the correct value, and Authorization
//      Bearer <token>.
//   3. NO LEAK: no private value and no token appears in any audit detail or console output.
//   4. NON-OWNER REFUSED: a caller without keys.ceremony is denied with NO Cloudflare fetch.
//   5. The returned signerPublic matches loadSigner's public (the recovery-sheet pin).
//   6. supplying the operational pair ALSO clears the durable OPERATIONAL_RETIRED marker (best-effort);
//      OMITTING it (a strict re-key) leaves any existing marker untouched, so a deliberate break-glass-only
//      choice survives a re-key that stays strict.
// No real network and no real deploy: a stubbed fetch records the PUTs (and a stubbed JWKS lets the
// non-owner refusal run through the REAL handleAdmin gate). Run: node test/validate-keys-install.ts

import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { installEngineSecrets } from "../src/admin/attach.ts";
import { loadSigner } from "../src/keys-env.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/index.ts";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

// ---- Build a VALID ceremony key set (the exact encodings the in-browser ceremony emits) ----------
// signer private = ed25519 seed(32) || ML-DSA-87 seed(32) = 64 bytes.
const edSeed = randomBytes(32);
const mldsaSeed = randomBytes(32);
const mldsa = ml_dsa87.keygen(mldsaSeed);
const SIGNER_PRIVATE = b64urlEncode(concat(edSeed, mldsaSeed));
// the signer PUBLIC the recovery sheet pins = ed25519 public(32) || ML-DSA-87 public.
const SIGNER_PUBLIC_EXPECTED = b64urlEncode(concat(ed25519.getPublicKey(edSeed), mldsa.publicKey));
// a recipient public = x25519 public(32) || ML-KEM-1024 ek(1568) = 1600 bytes (break-glass + operational).
const bgKp = x25519.keygen();
const BREAK_GLASS_PUBLIC = b64urlEncode(concat(bgKp.publicKey, ml_kem1024.keygen(randomBytes(64)).publicKey));
const opKp = x25519.keygen();
const OPERATIONAL_PUBLIC = b64urlEncode(concat(opKp.publicKey, ml_kem1024.keygen(randomBytes(64)).publicKey));
// an operational PRIVATE identity = x25519 scalar(32) || ML-KEM seed(64) = 96 bytes.
const OPERATIONAL_PRIVATE = b64urlEncode(concat(randomBytes(32), randomBytes(64)));

const TOKEN = "cfat-test-edit-workers-token-1234567890";

// A recording fetch stub for the secrets endpoint. Every PUT to .../secrets succeeds and is
// recorded (url, the Authorization header, and the parsed JSON body). Any other call is recorded
// too, so the test can assert the EXACT set of calls.
interface Put { name: string; text: string; type: string; auth: string; url: string }
function makeSecretsStub(): { fetch: typeof fetch; puts: Put[]; calls: string[] } {
  const puts: Put[] = [];
  const calls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    calls.push(`${method} ${url}`);
    if (method === "PUT" && /\/secrets$/.test(url)) {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      const auth = headers["authorization"] ?? headers["Authorization"] ?? "";
      const parsed = JSON.parse(String(init?.body ?? "{}")) as { name?: string; text?: string; type?: string };
      puts.push({ name: parsed.name ?? "", text: parsed.text ?? "", type: parsed.type ?? "", auth, url });
      return new Response(JSON.stringify({ success: true, result: { name: parsed.name } }), { status: 200 });
    }
    return new Response(JSON.stringify({ success: false, errors: [{ code: 0, message: "unexpected" }] }), { status: 500 });
  }) as typeof fetch;
  return { fetch: fetchImpl, puts, calls };
}

// routeEnv builds a real-SchedulerDO-backed Env for a route-level test (the already-provisioned guard cases
// below drive the REAL handleAdmin, so they need a DO for the audit append and the ADMIN_TOKEN owner path).
function routeEnv(adminToken: string, extra: Record<string, unknown>): Env {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(typeof input === "string" ? input : (input as URL).toString(), init)) } as unknown as DurableObjectStub;
  const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
  return { SCHEDULER: namespace, ADMIN_TOKEN: adminToken, WORKER_NAME: "downpipe-engine", ...extra } as unknown as Env;
}

async function main(): Promise<void> {
  console.log("-- installEngineSecrets: VALIDATE BEFORE WRITE (a bad key sets nothing, no fetch) --");
  {
    // Malformed signerPrivate -> 400-class throw, ZERO fetch calls.
    const s1 = makeSecretsStub();
    let threw = "";
    try { await installEngineSecrets("acct1", "downpipe-engine", { token: TOKEN, signerPrivate: "not-base64url!!", breakGlassPublic: BREAK_GLASS_PUBLIC }, s1.fetch); } catch (e) { threw = (e as Error).message; }
    ok("a malformed signerPrivate is refused before any network call", threw !== "" && /signer private/.test(threw));
    ok("a malformed signerPrivate made ZERO fetch calls", s1.calls.length === 0);
    ok("the refusal reason carries NO private value and NO token", !threw.includes(SIGNER_PRIVATE) && !threw.includes(TOKEN));

    // Malformed breakGlassPublic (a valid signer, a junk recipient) -> 400, ZERO fetch.
    const s2 = makeSecretsStub();
    threw = "";
    try { await installEngineSecrets("acct1", "downpipe-engine", { token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: "deadbeef" }, s2.fetch); } catch (e) { threw = (e as Error).message; }
    ok("a malformed breakGlassPublic is refused before any network call", threw !== "" && /recipient public/.test(threw));
    ok("a malformed breakGlassPublic made ZERO fetch calls", s2.calls.length === 0);

    // A half operational pair (public without private) is refused before any write.
    const s3 = makeSecretsStub();
    threw = "";
    try { await installEngineSecrets("acct1", "downpipe-engine", { token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS_PUBLIC, operationalPublic: OPERATIONAL_PUBLIC }, s3.fetch); } catch (e) { threw = (e as Error).message; }
    ok("a half operational pair (public, no private) is refused with no fetch", /operational pair is incomplete/.test(threw) && s3.calls.length === 0);
  }

  console.log("\n-- installEngineSecrets: GOOD KEYS -> exactly the right PUTs (signer + break-glass only) --");
  {
    const stub = makeSecretsStub();
    const result = await installEngineSecrets("acct-xyz", "downpipe-engine", { token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS_PUBLIC }, stub.fetch);
    ok("exactly two secrets are PUT (no operational pair supplied)", stub.puts.length === 2);
    const byName = new Map(stub.puts.map((p) => [p.name, p]));
    ok("SIGNER_PRIVATE was PUT with type secret_text and the correct value", byName.get("SIGNER_PRIVATE")?.type === "secret_text" && byName.get("SIGNER_PRIVATE")?.text === SIGNER_PRIVATE);
    ok("BREAK_GLASS_PUBLIC was PUT with type secret_text and the correct value", byName.get("BREAK_GLASS_PUBLIC")?.type === "secret_text" && byName.get("BREAK_GLASS_PUBLIC")?.text === BREAK_GLASS_PUBLIC);
    ok("every PUT carried Authorization: Bearer <token>", stub.puts.every((p) => p.auth === `Bearer ${TOKEN}`));
    ok("every PUT hit the dedicated secrets endpoint for the engine's account + script", stub.puts.every((p) => /\/accounts\/acct-xyz\/workers\/scripts\/downpipe-engine\/secrets$/.test(p.url)));
    ok("NO operational secret was set", !byName.has("OPERATIONAL_PUBLIC") && !byName.has("OPERATIONAL_PRIVATE"));
    ok("configured reports signer+break-glass true, operational false", result.configured.signer === true && result.configured.breakGlass === true && result.configured.operational === false);
    ok("a strict re-key (operational omitted) does NOT touch OPERATIONAL_RETIRED (a prior deliberate marker must survive)", !stub.calls.some((c) => c.includes("OPERATIONAL_RETIRED")));

    // (5) the returned signerPublic equals loadSigner's public AND the independently-derived public.
    const signer = await loadSigner(SIGNER_PRIVATE);
    const fromLoader = b64urlEncode(concat(signer.edPublic, signer.mldsaPublic));
    ok("the returned signerPublic matches loadSigner's public", result.signerPublic === fromLoader && result.signerPublic === SIGNER_PUBLIC_EXPECTED);
  }

  console.log("\n-- installEngineSecrets: GOOD KEYS with the operational pair -> four PUTs --");
  {
    const stub = makeSecretsStub();
    const result = await installEngineSecrets("acct-xyz", "downpipe-engine", {
      token: TOKEN,
      signerPrivate: SIGNER_PRIVATE,
      breakGlassPublic: BREAK_GLASS_PUBLIC,
      operationalPublic: OPERATIONAL_PUBLIC,
      operationalPrivate: OPERATIONAL_PRIVATE,
    }, stub.fetch);
    const names = stub.puts.map((p) => p.name);
    ok("exactly four secrets are PUT in the expected order", names.join(",") === "SIGNER_PRIVATE,BREAK_GLASS_PUBLIC,OPERATIONAL_PUBLIC,OPERATIONAL_PRIVATE");
    const byName = new Map(stub.puts.map((p) => [p.name, p]));
    ok("OPERATIONAL_PUBLIC value is correct", byName.get("OPERATIONAL_PUBLIC")?.text === OPERATIONAL_PUBLIC);
    ok("OPERATIONAL_PRIVATE value is correct and type secret_text", byName.get("OPERATIONAL_PRIVATE")?.text === OPERATIONAL_PRIVATE && byName.get("OPERATIONAL_PRIVATE")?.type === "secret_text");
    ok("configured.operational is true when the pair is installed", result.configured.operational === true);
    ok("installing the operational pair ALSO clears the OPERATIONAL_RETIRED marker (best-effort, as call #5)", stub.calls.length === 5 && (stub.calls[4] ?? "").startsWith("DELETE") && (stub.calls[4] ?? "").includes("/secrets/OPERATIONAL_RETIRED"));
  }

  console.log("\n-- installEngineSecrets: a failed PUT names the Edit Cloudflare Workers scope and stops --");
  {
    // The secrets PUT is rejected (a scope-less token): the throw names the template and the install
    // does NOT continue to the next secret.
    const calls: string[] = [];
    const denyStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push(`${init?.method ?? "GET"} ${String(input)}`);
      return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }), { status: 403 });
    }) as typeof fetch;
    let threw = "";
    try { await installEngineSecrets("acct-xyz", "downpipe-engine", { token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS_PUBLIC, operationalPublic: OPERATIONAL_PUBLIC, operationalPrivate: OPERATIONAL_PRIVATE }, denyStub); } catch (e) { threw = (e as Error).message; }
    ok("a failed PUT throws naming the Edit Cloudflare Workers template", /Edit Cloudflare Workers/.test(threw) && /SIGNER_PRIVATE/.test(threw));
    ok("the install STOPS on the first failed PUT (only one PUT attempted)", calls.filter((c) => c.startsWith("PUT")).length === 1);
    ok("the failure reason carries no token and no private value", !threw.includes(TOKEN) && !threw.includes(SIGNER_PRIVATE));
  }

  console.log("\n-- the route never leaks the token or a private value into the audit or console output --");
  {
    // Drive the full route through handleAdmin with the ADMIN_TOKEN owner break-glass (so the gate
    // passes and the install runs), a stubbed secrets fetch, and a CAPTURED console + a real
    // SchedulerDO so the audit append actually runs. Then assert the token and the private values
    // appear NOWHERE in the audit feed or the captured console lines.
    const ADMIN_TOKEN = "keys-install-admin-token";
    const storage = new MockStorage();
    const state = { storage } as unknown as DurableObjectState;
    const dobj = new SchedulerDO(state);
    const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(typeof input === "string" ? input : (input as URL).toString(), init)) } as unknown as DurableObjectStub;
    const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
    const env = { SCHEDULER: namespace, ADMIN_TOKEN, CF_ACCOUNT_ID: "acct-audit", WORKER_NAME: "downpipe-engine" } as unknown as Env;

    // Capture every console line so we can prove no secret/token is logged.
    const logged: string[] = [];
    const realLog = console.log, realWarn = console.warn, realErr = console.error;
    console.log = (...a: unknown[]) => { logged.push(a.map(String).join(" ")); };
    console.warn = (...a: unknown[]) => { logged.push(a.map(String).join(" ")); };
    // Capture error output for the no-leak assertion, but ALSO forward it to the real
    // console so a genuine error logged from inside the engine code under test stays
    // visible rather than being silently swallowed.
    console.error = (...a: unknown[]) => { logged.push(a.map(String).join(" ")); realErr(...a); };

    // Stub global fetch for the duration: the secrets PUTs succeed (the route writes via the default
    // fetch since the router calls installEngineSecrets with no fetchImpl), and any Access JWKS or
    // stray call is irrelevant here (the owner uses the ADMIN_TOKEN bearer, no JWKS needed).
    const secretsStub = makeSecretsStub();
    const realFetch = globalThis.fetch;
    globalThis.fetch = secretsStub.fetch;

    let auditText = "";
    let installStatus = 0;
    let respBody = "";
    try {
      const resp = await handleAdmin(new Request("https://engine.example/admin/keys/install", {
        method: "POST",
        headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" },
        body: JSON.stringify({ token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS_PUBLIC, operationalPublic: OPERATIONAL_PUBLIC, operationalPrivate: OPERATIONAL_PRIVATE }),
      }), env);
      installStatus = resp.status;
      respBody = await resp.text();
      // Read the audit feed (the owner can read it).
      const auditResp = await handleAdmin(new Request("https://engine.example/admin/audit?limit=50", {
        method: "GET", headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
      }), env);
      auditText = await auditResp.text();
    } finally {
      console.log = realLog; console.warn = realWarn; console.error = realErr;
      globalThis.fetch = realFetch;
    }

    ok("the install route returns 200 for the owner with good keys", installStatus === 200);
    ok("the response carries the PUBLIC signerPublic and configured booleans", respBody.includes(SIGNER_PUBLIC_EXPECTED) && /"signer":true/.test(respBody) && /"operational":true/.test(respBody));
    ok("the response body does NOT contain the token or any private value", !respBody.includes(TOKEN) && !respBody.includes(SIGNER_PRIVATE) && !respBody.includes(OPERATIONAL_PRIVATE));
    ok("the AUDIT feed records the install but contains NO token and NO private value", /keys-installed/.test(auditText) && !auditText.includes(TOKEN) && !auditText.includes(SIGNER_PRIVATE) && !auditText.includes(OPERATIONAL_PRIVATE) && !auditText.includes(BREAK_GLASS_PUBLIC));
    const allLogs = logged.join("\n");
    ok("NO console line contains the token", !allLogs.includes(TOKEN));
    ok("NO console line contains a private value", !allLogs.includes(SIGNER_PRIVATE) && !allLogs.includes(OPERATIONAL_PRIVATE));
    ok("the engine DID set the secrets via the secrets endpoint (4 PUTs)", secretsStub.puts.length === 4 && secretsStub.puts.every((p) => p.auth === `Bearer ${TOKEN}`));
  }

  console.log("\n-- a NON-OWNER caller is refused with NO Cloudflare fetch --");
  {
    // Drive the REAL handleAdmin with a forged-but-valid Cloudflare Access JWT for a NON-owner email
    // (a second distinct email that did not bootstrap, so it resolves to viewer). The fetch stub
    // serves ONLY the Access JWKS; ANY api.cloudflare.com call is recorded as a forbidden leak.
    const TEAM = "maelstrom";
    const ISS = `https://${TEAM}.cloudflareaccess.com`;
    const AUD = "keys-install-aud";
    const KID = "keys-install-kid";
    const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
    const pubJwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
    const jwks = { keys: [{ kid: KID, kty: "RSA", n: pubJwk.n, e: pubJwk.e }] };
    const cfApiCalls: string[] = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : (input as URL).toString();
      if (url === `${ISS}/cdn-cgi/access/certs`) return new Response(JSON.stringify(jwks), { headers: { "content-type": "application/json" } });
      if (url.startsWith("https://api.cloudflare.com")) { cfApiCalls.push(`${init?.method ?? "GET"} ${url}`); return new Response(JSON.stringify({ success: false }), { status: 500 }); }
      throw new Error(`unexpected network fetch in test: ${url}`);
    }) as typeof fetch;

    const jwtPart = (obj: unknown): string => b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
    const futureExp = Math.floor(Date.now() / 1000) + 3600;
    const tokenFor = async (email: string): Promise<string> => {
      const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
      const payload = jwtPart({ iss: ISS, aud: AUD, exp: futureExp, iat: futureExp - 3600, email, sub: `sub-of-${email}` });
      const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${payload}`)));
      return `${header}.${payload}.${b64urlEncode(sig)}`;
    };

    const storage = new MockStorage();
    const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
    const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(typeof input === "string" ? input : (input as URL).toString(), init)) } as unknown as DurableObjectStub;
    const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
    const env = { SCHEDULER: namespace, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, CF_ACCOUNT_ID: "acct-deny", WORKER_NAME: "downpipe-engine" } as unknown as Env;

    const call = async (email: string): Promise<Response> => handleAdmin(new Request("https://engine.example/admin/keys/install", {
      method: "POST",
      headers: { "cf-access-jwt-assertion": await tokenFor(email), "content-type": "application/json", origin: "https://engine.example" },
      body: JSON.stringify({ token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS_PUBLIC }),
    }), env);

    let denied: Response;
    try {
      // The FIRST Access caller bootstraps to Owner; burn that on an owner email via a harmless GET so
      // the install-attempting email below is a plain viewer, not the bootstrap owner.
      await handleAdmin(new Request("https://engine.example/admin/whoami", { method: "GET", headers: { "cf-access-jwt-assertion": await tokenFor("owner@acme.example") } }), env);
      denied = await call("viewer@acme.example");
    } finally {
      globalThis.fetch = realFetch;
    }

    ok("a non-owner install attempt is refused 403 (forbidden, keys.ceremony)", denied.status === 403);
    const deniedBody = await denied.text();
    ok("the refusal names the required keys.ceremony capability", /forbidden/.test(deniedBody) && /keys\.ceremony/.test(deniedBody));
    ok("the refused install made ZERO Cloudflare API calls (no secret was ever PUT)", cfApiCalls.length === 0);
  }

  console.log("\n-- installEngineSecrets: each required-field guard refuses before any network call --");
  {
    // Non-string inputs are coerced to empty by the leading typeof-guards, so the same required-field
    // checks fire. A missing/blank signer private and a missing/blank break-glass public are both
    // refused with their named reason and ZERO fetch calls (the engine is never left half-keyed).
    const s1 = makeSecretsStub();
    let threw = "";
    try { await installEngineSecrets("acct1", "downpipe-engine", { token: TOKEN, signerPrivate: undefined as unknown as string, breakGlassPublic: BREAK_GLASS_PUBLIC }, s1.fetch); } catch (e) { threw = (e as Error).message; }
    ok("a non-string (missing) signer private is refused as required, no fetch", /signer private is required/.test(threw) && s1.calls.length === 0);

    const s2 = makeSecretsStub();
    threw = "";
    try { await installEngineSecrets("acct1", "downpipe-engine", { token: TOKEN, signerPrivate: "   ", breakGlassPublic: BREAK_GLASS_PUBLIC }, s2.fetch); } catch (e) { threw = (e as Error).message; }
    ok("a whitespace-only signer private is refused as required, no fetch", /signer private is required/.test(threw) && s2.calls.length === 0);

    const s3 = makeSecretsStub();
    threw = "";
    try { await installEngineSecrets("acct1", "downpipe-engine", { token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: 12345 as unknown as string }, s3.fetch); } catch (e) { threw = (e as Error).message; }
    ok("a non-string (missing) break-glass public is refused as required, no fetch", /break-glass public is required/.test(threw) && s3.calls.length === 0);

    // A malformed operational PRIVATE (with a valid operational public, so the pair is complete) fails the
    // identity loader and is refused locally, again before any write.
    const s4 = makeSecretsStub();
    threw = "";
    try { await installEngineSecrets("acct1", "downpipe-engine", { token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS_PUBLIC, operationalPublic: OPERATIONAL_PUBLIC, operationalPrivate: "not-a-valid-identity" }, s4.fetch); } catch (e) { threw = (e as Error).message; }
    ok("a malformed operational private is refused locally with no fetch", /operational private did not parse/.test(threw) && s4.calls.length === 0);

    // Valid keys but a NON-STRING (missing) token: the leading typeof-guard coerces it to empty, every
    // key still parses, then the token guard fires last with no PUT (the token-required branch is reached
    // only after validation passes).
    const s5 = makeSecretsStub();
    threw = "";
    try { await installEngineSecrets("acct1", "downpipe-engine", { token: undefined as unknown as string, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS_PUBLIC }, s5.fetch); } catch (e) { threw = (e as Error).message; }
    ok("valid keys with a non-string (missing) token are refused (token required), no PUT made", /paste the deploy token/.test(threw) && s5.calls.length === 0);
  }

  console.log("\n-- POST /keys/install REFUSES a SILENT re-key when a signer is already present (custody guard) --");
  {
    // A returning owner on an ALREADY-PROVISIONED estate: env carries SIGNER_PRIVATE (+ BREAK_GLASS_PUBLIC),
    // so signerConfigured reads true. An install WITHOUT confirmRekey must be REFUSED (400) and AUDITED (key-
    // install-failed / already-configured), and it must make ZERO Cloudflare API calls, so the signer that
    // anchors every prior run receipt is never overwritten. Mirrors the add-operational already-configured
    // refusal.
    const ADMIN_TOKEN = "keys-install-rekey-refuse-token";
    const env = routeEnv(ADMIN_TOKEN, { CF_ACCOUNT_ID: "acct-rekey-refuse", SIGNER_PRIVATE: "sentinel-existing-signer-must-never-be-overwritten", BREAK_GLASS_PUBLIC: "sentinel-existing-break-glass" });

    const cfCalls: string[] = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.startsWith("https://api.cloudflare.com")) cfCalls.push(`${init?.method ?? "GET"} ${url}`);
      return new Response(JSON.stringify({ success: false }), { status: 500 });
    }) as typeof fetch;

    let status = 0;
    let respBody = "";
    let auditText = "";
    try {
      const resp = await handleAdmin(new Request("https://engine.example/admin/keys/install", {
        method: "POST",
        headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" },
        body: JSON.stringify({ token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS_PUBLIC }),
      }), env);
      status = resp.status;
      respBody = await resp.text();
      const auditResp = await handleAdmin(new Request("https://engine.example/admin/audit?limit=50", { method: "GET", headers: { authorization: `Bearer ${ADMIN_TOKEN}` } }), env);
      auditText = await auditResp.text();
    } finally {
      globalThis.fetch = realFetch;
    }

    ok("a second install with NO confirmRekey is refused 400, not a silent overwrite", status === 400);
    ok("the refusal says a signer is already installed and names the deliberate re-key path", /already installed/.test(respBody) && /re-key/.test(respBody));
    ok("the refusal made ZERO Cloudflare API calls (the existing signer was never overwritten)", cfCalls.length === 0);
    ok("the refusal is AUDITED as key-install-failed, cause already-configured", /key-install-failed/.test(auditText) && /already-configured/.test(auditText));
    ok("the audited refusal carries no token and no private value", !auditText.includes(TOKEN) && !auditText.includes(SIGNER_PRIVATE));
  }

  console.log("\n-- POST /keys/install PROCEEDS with an explicit confirmRekey (the deliberate, warned re-key) --");
  {
    // Same provisioned estate (SIGNER_PRIVATE present), but the body carries confirmRekey:true, which the
    // console sets ONLY from the state-aware re-key card, after showing the signer-continuity warning. The
    // install must proceed and PUT the new key set: the "explicit, warned route" the full re-key keeps.
    const ADMIN_TOKEN = "keys-install-rekey-confirm-token";
    const env = routeEnv(ADMIN_TOKEN, { CF_ACCOUNT_ID: "acct-rekey-confirm", SIGNER_PRIVATE: "sentinel-existing-signer", BREAK_GLASS_PUBLIC: "sentinel-existing-break-glass" });

    const secretsStub = makeSecretsStub();
    const realFetch = globalThis.fetch;
    globalThis.fetch = secretsStub.fetch;
    let status = 0;
    let auditText = "";
    try {
      const resp = await handleAdmin(new Request("https://engine.example/admin/keys/install", {
        method: "POST",
        headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" },
        body: JSON.stringify({ token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS_PUBLIC, confirmRekey: true }),
      }), env);
      status = resp.status;
      const auditResp = await handleAdmin(new Request("https://engine.example/admin/audit?limit=50", { method: "GET", headers: { authorization: `Bearer ${ADMIN_TOKEN}` } }), env);
      auditText = await auditResp.text();
    } finally {
      globalThis.fetch = realFetch;
    }

    ok("a confirmed re-key (confirmRekey:true) proceeds and returns 200", status === 200);
    ok("the confirmed re-key installed the two secrets via the secrets endpoint", secretsStub.puts.length === 2 && secretsStub.puts.map((p) => p.name).sort().join(",") === "BREAK_GLASS_PUBLIC,SIGNER_PRIVATE");
    ok("the confirmed re-key is audited as keys-installed and leaks no token or private value", /keys-installed/.test(auditText) && !auditText.includes(TOKEN) && !auditText.includes(SIGNER_PRIVATE));
  }

  console.log("\n-- POST /keys/install still performs a FIRST install on a signer-less engine (guard does not fire) --");
  {
    // A genuinely fresh engine (no SIGNER_PRIVATE in env): the guard must NOT fire, so the first install
    // proceeds with no confirmRekey flag. This is the legitimate case the guard must never break.
    const ADMIN_TOKEN = "keys-install-first-token";
    const env = routeEnv(ADMIN_TOKEN, { CF_ACCOUNT_ID: "acct-first-install" });

    const secretsStub = makeSecretsStub();
    const realFetch = globalThis.fetch;
    globalThis.fetch = secretsStub.fetch;
    let status = 0;
    try {
      const resp = await handleAdmin(new Request("https://engine.example/admin/keys/install", {
        method: "POST",
        headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" },
        body: JSON.stringify({ token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS_PUBLIC }),
      }), env);
      status = resp.status;
    } finally {
      globalThis.fetch = realFetch;
    }

    ok("a first install on a signer-less engine returns 200 (guard does not fire without a signer)", status === 200);
    ok("the first install set the two secrets", secretsStub.puts.length === 2);
  }

  console.log("\n-- POST /keys/install: a DEMO re-run is NOT refused (the fresh-first-run marker masks the persisted signer) --");
  {
    // The demo subtlety the guard must honour: a demo reset persists SIGNER_PRIVATE but sets the fresh-first-run
    // marker, so GET /admin/status reports signerConfigured:false and the onboarding wizard legitimately
    // re-installs WITHOUT confirmRekey. The guard reads the SAME masked value, so it must let this through; a
    // guard on raw env.SIGNER_PRIVATE would wrongly refuse the demo re-run. This exercises the guard's demo
    // branch end to end (the marker is pre-set on the DO exactly as a reset leaves it).
    const ADMIN_TOKEN = "keys-install-demo-rerun-token";
    const storage = new MockStorage();
    await storage.put("demoFreshFirstRun", true); // the marker POST /demo/reset writes after the storage wipe
    const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
    const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(typeof input === "string" ? input : (input as URL).toString(), init)) } as unknown as DurableObjectStub;
    const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
    const env = {
      SCHEDULER: namespace,
      ADMIN_TOKEN,
      WORKER_NAME: "downpipe-engine",
      CF_ACCOUNT_ID: "acct-demo-rerun",
      DEMO_MODE: "true",
      SIGNER_PRIVATE: "sentinel-persisted-through-demo-reset",
      BREAK_GLASS_PUBLIC: "sentinel-persisted-break-glass",
    } as unknown as Env;

    const secretsStub = makeSecretsStub();
    const realFetch = globalThis.fetch;
    globalThis.fetch = secretsStub.fetch;
    let status = 0;
    try {
      const resp = await handleAdmin(new Request("https://engine.example/admin/keys/install", {
        method: "POST",
        headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" },
        body: JSON.stringify({ token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS_PUBLIC }),
      }), env);
      status = resp.status;
    } finally {
      globalThis.fetch = realFetch;
    }

    ok("a demo re-run install (marker set, no confirmRekey) is NOT refused: it returns 200", status === 200);
    ok("the demo re-run installed the new key set (the mask let a signer-less-looking engine through)", secretsStub.puts.length === 2);
  }

  console.log("\n-- the keys-installed append SURVIVES the Durable Object reset the secret PUTs cause --");
  {
    // THE DEFECT THIS PINS. A POST /admin/keys/install can return 200, genuinely write all four secrets, and
    // leave NO keys-installed row on a contiguous chain (nothing appended, nothing rolled back: the append
    // never arrived). Each Cloudflare secret PUT rolls a NEW WORKER VERSION, and a new version RESETS this
    // Worker's Durable Objects, so the append that follows races the rollout and throws "Durable Object reset
    // because its code was updated" on the stub the isolate already holds.
    //
    // WHY IT IS GRADED HERE RATHER THAN LIVE. It is a RACE, not a deterministic condition, so a live cell that
    // drives one install and sees the row land proves nothing either way. The tolerance is structural and
    // holds or fails in the source, so the reset is INJECTED here and the property is graded deterministically.
    //
    // TO INVERT IT: delete the `afterSecretWrite` argument from the keys-installed auditChecked call in
    // src/admin/router-keys.ts and this case fails with the row absent, which is the defect exactly.
    const ADMIN_TOKEN = "keys-install-do-reset-token";
    const storage = new MockStorage();
    const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
    // resetsLeft audit POSTs THROW the reset error the runtime raises, then the DO recovers. One throw is
    // enough to prove the ladder is wired; the value is deliberately below SELF_DEPLOY_RETRY_MAX_ATTEMPTS so
    // a passing run means the retry worked, not that the budget happened to be large.
    let resetsLeft = 1;
    let auditPosts = 0;
    const stub = {
      fetch: (input: RequestInfo | URL, init?: RequestInit) => {
        const url = typeof input === "string" ? input : (input as URL).toString();
        if (init?.method === "POST" && new URL(url).pathname === "/audit") {
          auditPosts++;
          if (resetsLeft > 0) {
            resetsLeft--;
            // The exact wording the Workers runtime uses, because retryAfterSelfDeploy matches on it: a
            // retry keyed to a different string would be a ladder that never runs.
            throw new Error("Durable Object reset because its code was updated.");
          }
        }
        return dobj.fetch(new Request(url, init));
      },
    } as unknown as DurableObjectStub;
    const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
    const env = { SCHEDULER: namespace, ADMIN_TOKEN, CF_ACCOUNT_ID: "acct-do-reset", WORKER_NAME: "downpipe-engine" } as unknown as Env;

    const secretsStub = makeSecretsStub();
    const realFetch = globalThis.fetch;
    globalThis.fetch = secretsStub.fetch;
    let installStatus = 0;
    let auditText = "";
    try {
      const resp = await handleAdmin(new Request("https://engine.example/admin/keys/install", {
        method: "POST",
        headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" },
        body: JSON.stringify({ token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS_PUBLIC, operationalPublic: OPERATIONAL_PUBLIC, operationalPrivate: OPERATIONAL_PRIVATE }),
      }), env);
      installStatus = resp.status;
      const auditResp = await handleAdmin(new Request("https://engine.example/admin/audit?action=keys-installed&limit=50", {
        method: "GET", headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
      }), env);
      auditText = await auditResp.text();
    } finally {
      globalThis.fetch = realFetch;
    }

    ok("the install still returns 200 through a DO reset (the operator never sees the retry)", installStatus === 200);
    ok("the four secrets were genuinely written (the install landed, as it did live)", secretsStub.puts.length === 4);
    // Anti-vacuity: a stub that was never asked to throw would pass the row assertion while proving nothing.
    ok("the injected reset was actually consumed (the append was retried, not merely attempted once)", resetsLeft === 0 && auditPosts >= 2);
    const events = JSON.parse(auditText) as { events?: Array<{ action?: string; outcome?: string; seq?: number }> };
    const installed = (events.events ?? []).filter((e) => e.action === "keys-installed");
    ok("the keys-installed row LANDED despite the reset, with a numeric seq", installed.length === 1 && typeof installed[0]?.seq === "number");
    ok("the landed row records the SUCCESS outcome, not a failure", installed[0]?.outcome === "success");
    ok("the retry appended exactly ONE row (a reset must not duplicate the ceremony record)", installed.length === 1);
  }

  console.log("\n-- the rollout's OPAQUE message is ridden out too, and a real fault still is not --");
  {
    // WHY THIS EXISTS. The retry predicate must match the OPAQUE form the Workers runtime actually raises
    // during a version-rollout Durable Object reset, not only the NAMED "Durable Object reset because its code
    // was updated" message: a predicate keyed only to the named form still loses the keys-installed row when
    // the runtime raises the opaque form instead.
    //
    // THE CONTROL ARM IS THE POINT. A cell that only drives the failing message cannot tell a fix from a
    // coincidence, so two controls run beside it here, both of which pass under the OLD predicate and the NEW
    // one: the named reset must still be ridden out, and a genuine fault must still be abandoned on attempt
    // one rather than hammered. Only the OPAQUE arm changes verdict across the fix.
    async function driveInstallThrowing(message: string): Promise<{ status: number; puts: number; auditPosts: number; consumed: boolean; rows: number }> {
      const ADMIN_TOKEN = "keys-install-opaque-rollout-token";
      const storage = new MockStorage();
      const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
      let throwsLeft = 1;
      let auditPosts = 0;
      const stub = {
        fetch: (input: RequestInfo | URL, init?: RequestInit) => {
          const url = typeof input === "string" ? input : (input as URL).toString();
          if (init?.method === "POST" && new URL(url).pathname === "/audit") {
            auditPosts++;
            if (throwsLeft > 0) {
              throwsLeft--;
              throw new Error(message);
            }
          }
          return dobj.fetch(new Request(url, init));
        },
      } as unknown as DurableObjectStub;
      const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
      const env = { SCHEDULER: namespace, ADMIN_TOKEN, CF_ACCOUNT_ID: "acct-opaque", WORKER_NAME: "downpipe-engine" } as unknown as Env;
      const secretsStub = makeSecretsStub();
      const realFetch = globalThis.fetch;
      globalThis.fetch = secretsStub.fetch;
      let status = 0;
      let auditText = "";
      try {
        const resp = await handleAdmin(new Request("https://engine.example/admin/keys/install", {
          method: "POST",
          headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" },
          body: JSON.stringify({ token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS_PUBLIC, operationalPublic: OPERATIONAL_PUBLIC, operationalPrivate: OPERATIONAL_PRIVATE }),
        }), env);
        status = resp.status;
        const auditResp = await handleAdmin(new Request("https://engine.example/admin/audit?action=keys-installed&limit=50", {
          method: "GET", headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
        }), env);
        auditText = await auditResp.text();
      } finally {
        globalThis.fetch = realFetch;
      }
      const parsed = JSON.parse(auditText) as { events?: Array<{ action?: string }> };
      return { status, puts: secretsStub.puts.length, auditPosts, consumed: throwsLeft === 0, rows: (parsed.events ?? []).filter((e) => e.action === "keys-installed").length };
    }

    // TREATMENT: the exact string the runtime raised on the request that lost the row live. This arm FAILS on
    // the unpatched build and passes here, which is the whole change.
    const opaque = await driveInstallThrowing("internal error; reference = n3rmrlv4r241rk2ob8u84pfq");
    ok("anti-vacuity: the opaque rollout throw was actually injected and consumed", opaque.consumed);
    ok("the install still returns 200 through the OPAQUE rollout fault", opaque.status === 200);
    ok("the four secrets were genuinely written under the opaque fault", opaque.puts === 4);
    ok("the opaque rollout fault was RETRIED rather than abandoned on attempt one", opaque.auditPosts >= 2);
    ok("the keys-installed row LANDED through the opaque rollout fault", opaque.rows === 1);

    // CONTROL 1, passes under the old predicate and the new one: the named reset must still be ridden out, so
    // the widening did not break the case the ladder was built for.
    const named = await driveInstallThrowing("Durable Object reset because its code was updated.");
    ok("anti-vacuity: the named reset throw was actually injected and consumed", named.consumed);
    ok("CONTROL, unchanged by this fix: the NAMED reset is still retried", named.auditPosts >= 2);
    ok("CONTROL, unchanged by this fix: the named reset still lands its row", named.rows === 1);

    // CONTROL 2, passes under the old predicate and the new one: a real fault must STILL end the loop at
    // attempt one. This is what stops the widening becoming "retry everything", and it is the assertion that
    // fails if somebody replaces the predicate with a constant true.
    const realFault = await driveInstallThrowing("SIGNER_PRIVATE is not valid base64url");
    ok("anti-vacuity: the real-fault throw was actually injected and consumed", realFault.consumed);
    ok("CONTROL, unchanged by this fix: a REAL fault is not retried (exactly one append attempt)", realFault.auditPosts === 1);
    ok("CONTROL, unchanged by this fix: a real fault loses the row rather than being papered over", realFault.rows === 0);
    ok("CONTROL, unchanged by this fix: a real fault still returns 200 (the secrets are written; the audit is best-effort)", realFault.status === 200);

    // ANTI-VACUITY on the source itself: if the predicate stops being a named function, or the measured
    // string stops being the thing it is keyed to, the arms above would still pass against some other
    // mechanism. Read from disk so a rename cannot slip past.
    const auditSrc = await import("node:fs/promises").then((fs) => fs.readFile(new URL("../src/admin/router-audit.ts", import.meta.url), "utf8"));
    ok("the retryable predicate is a NAMED function, not an inline regex the ladder alone knows about", /function isSelfDeployReset\(/.test(auditSrc));
    ok("the ladder asks that predicate rather than testing a literal itself", /if \(!isSelfDeployReset\(msg\)\)/.test(auditSrc));
    ok("the predicate still carries the NAMED reset pattern", /reset because its code was updated/.test(auditSrc));
    ok("the predicate carries the OPAQUE rollout pattern this fix was measured against", /internal error\\s\*\(\?:;/.test(auditSrc) || /DO_OPAQUE_ROLLOUT_FAULT/.test(auditSrc));
    ok("the opaque pattern is ANCHORED, so a longer message that merely mentions an internal error is still a fault", /DO_OPAQUE_ROLLOUT_FAULT = \/\^/.test(auditSrc));
  }

  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nKEYS-INSTALL VECTORS PASS");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
