// Validates the targeted operational-key ADD (POST /keys/add-operational): the minimal upgrade path for
// a break-glass-only engine. The security-critical properties are the point of this test:
//   1. VALIDATE BEFORE WRITE: a malformed operationalPublic / operationalPrivate, or a missing token,
//      returns 400-class having made ZERO fetch calls and set NOTHING.
//   2. GOOD KEYS: exactly two PUTs, in order (OPERATIONAL_PUBLIC then OPERATIONAL_PRIVATE), each with
//      type secret_text, the correct value, and Authorization Bearer <token>.
//   3. NEVER TOUCHES THE SIGNER OR BREAK-GLASS: no PUT to SIGNER_PRIVATE or BREAK_GLASS_PUBLIC ever fires,
//      confirming the custody claim that this route cannot rotate the signer or the break-glass recipient.
//   4. REFUSES (never silently reissues) when an operational key is already present, and the refusal is
//      AUDITED (key-install-failed, cause "already-configured"), not a bare, unaudited 400.
//   5. NO LEAK: no private value and no token appears in any audit detail, response body or console output.
//   6. NON-OWNER REFUSED: a caller without keys.ceremony is denied with NO Cloudflare fetch, and the denial
//      is audited.
//   7. a successful add CLEARS the durable OPERATIONAL_RETIRED marker (best-effort: a failed clear
//      does not fail the add), so a genuine re-enable through this route is clean.
// No real network and no real deploy: a stubbed fetch records the PUTs (and a stubbed JWKS lets the
// non-owner refusal run through the REAL handleAdmin gate). Run: node test/validate-keys-add-operational.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { addOperationalSecrets } from "../src/admin/attach.ts";
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

// ---- Build a VALID operational pair (the exact encodings the in-browser ceremony emits) ----------------
// a recipient public = x25519 public(32) || ML-KEM-1024 ek(1568) = 1600 bytes.
const opKp = x25519.keygen();
const OPERATIONAL_PUBLIC = b64urlEncode(concat(opKp.publicKey, ml_kem1024.keygen(randomBytes(64)).publicKey));
// an operational PRIVATE identity = x25519 scalar(32) || ML-KEM seed(64) = 96 bytes.
const OPERATIONAL_PRIVATE = b64urlEncode(concat(randomBytes(32), randomBytes(64)));
// A second, distinct pair, so a "no leak" check can tell "the wrong pair" from "no pair at all".
const opKp2 = x25519.keygen();
const OPERATIONAL_PUBLIC_2 = b64urlEncode(concat(opKp2.publicKey, ml_kem1024.keygen(randomBytes(64)).publicKey));

// Values that must NEVER appear in any PUT this route makes (the custody claim under test): a fake
// signer private and break-glass public, standing in for "the engine's real, untouched secrets".
const SIGNER_PRIVATE_SENTINEL = "sentinel-signer-private-must-never-be-put";
const BREAK_GLASS_PUBLIC_SENTINEL = "sentinel-break-glass-public-must-never-be-put";

const TOKEN = "cfat-test-edit-workers-token-1234567890";

// A recording fetch stub for the secrets endpoint, identical in shape to validate-keys-install.ts's: every
// PUT to .../secrets succeeds and is recorded (url, the Authorization header, the parsed JSON body). Any
// other call is recorded too, so the test can assert the EXACT set of calls.
interface Put { name: string; text: string; type: string; auth: string; url: string }
function makeSecretsStub(): { fetch: typeof fetch; puts: Put[]; dels: string[]; calls: string[] } {
  const puts: Put[] = [];
  const dels: string[] = [];
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
    // The marker-clear DELETE (best-effort): succeed it here so the happy-path tests below see the
    // clean, real-world case. A dedicated test further down uses a different stub to prove a FAILING
    // clear is swallowed instead of failing the add.
    if (method === "DELETE" && /\/secrets\/OPERATIONAL_RETIRED$/.test(url)) {
      dels.push(url);
      return new Response(JSON.stringify({ success: true }), { status: 200 });
    }
    return new Response(JSON.stringify({ success: false, errors: [{ code: 0, message: "unexpected" }] }), { status: 500 });
  }) as typeof fetch;
  return { fetch: fetchImpl, puts, dels, calls };
}

async function main(): Promise<void> {
  console.log("-- addOperationalSecrets: VALIDATE BEFORE WRITE (a bad key sets nothing, no fetch) --");
  {
    // Malformed operationalPublic -> refused before any network call.
    const s1 = makeSecretsStub();
    let threw = "";
    try { await addOperationalSecrets("acct1", "downpipe-engine", TOKEN, "deadbeef", OPERATIONAL_PRIVATE, s1.fetch); } catch (e) { threw = (e as Error).message; }
    ok("a malformed operationalPublic is refused before any network call", threw !== "" && /operational public did not parse/.test(threw));
    ok("a malformed operationalPublic made ZERO fetch calls", s1.calls.length === 0);
    ok("the refusal reason carries NO private value and NO token", !threw.includes(OPERATIONAL_PRIVATE) && !threw.includes(TOKEN));

    // Malformed operationalPrivate (a valid public, a junk identity) -> refused, ZERO fetch.
    const s2 = makeSecretsStub();
    threw = "";
    try { await addOperationalSecrets("acct1", "downpipe-engine", TOKEN, OPERATIONAL_PUBLIC, "not-a-valid-identity", s2.fetch); } catch (e) { threw = (e as Error).message; }
    ok("a malformed operationalPrivate is refused before any network call", threw !== "" && /operational private did not parse/.test(threw));
    ok("a malformed operationalPrivate made ZERO fetch calls", s2.calls.length === 0);

    // A missing (empty) operationalPublic is refused as required, not as a parse failure.
    const s3 = makeSecretsStub();
    threw = "";
    try { await addOperationalSecrets("acct1", "downpipe-engine", TOKEN, "", OPERATIONAL_PRIVATE, s3.fetch); } catch (e) { threw = (e as Error).message; }
    ok("an empty operationalPublic is refused as required, no fetch", /operational public is required/.test(threw) && s3.calls.length === 0);

    // A missing (empty) operationalPrivate is refused as required, not as a parse failure.
    const s4 = makeSecretsStub();
    threw = "";
    try { await addOperationalSecrets("acct1", "downpipe-engine", TOKEN, OPERATIONAL_PUBLIC, "", s4.fetch); } catch (e) { threw = (e as Error).message; }
    ok("an empty operationalPrivate is refused as required, no fetch", /operational private is required/.test(threw) && s4.calls.length === 0);

    // A missing (empty) token is refused, with both keys valid, and no fetch.
    const s5 = makeSecretsStub();
    threw = "";
    try { await addOperationalSecrets("acct1", "downpipe-engine", "", OPERATIONAL_PUBLIC, OPERATIONAL_PRIVATE, s5.fetch); } catch (e) { threw = (e as Error).message; }
    ok("valid keys with an empty token are refused (token required), no PUT made", /paste the deploy token/.test(threw) && s5.calls.length === 0);
  }

  console.log("\n-- addOperationalSecrets: GOOD KEYS -> exactly two PUTs, in order, correct values --");
  {
    const stub = makeSecretsStub();
    await addOperationalSecrets("acct-xyz", "downpipe-engine", TOKEN, OPERATIONAL_PUBLIC, OPERATIONAL_PRIVATE, stub.fetch);
    const names = stub.puts.map((p) => p.name);
    ok("exactly two secrets are PUT, in order OPERATIONAL_PUBLIC then OPERATIONAL_PRIVATE", names.join(",") === "OPERATIONAL_PUBLIC,OPERATIONAL_PRIVATE");
    const byName = new Map(stub.puts.map((p) => [p.name, p]));
    ok("OPERATIONAL_PUBLIC was PUT with type secret_text and the correct value", byName.get("OPERATIONAL_PUBLIC")?.type === "secret_text" && byName.get("OPERATIONAL_PUBLIC")?.text === OPERATIONAL_PUBLIC);
    ok("OPERATIONAL_PRIVATE was PUT with type secret_text and the correct value", byName.get("OPERATIONAL_PRIVATE")?.type === "secret_text" && byName.get("OPERATIONAL_PRIVATE")?.text === OPERATIONAL_PRIVATE);
    ok("every PUT carried Authorization: Bearer <token>", stub.puts.every((p) => p.auth === `Bearer ${TOKEN}`));
    ok("every PUT hit the dedicated secrets endpoint for the engine's account + script", stub.puts.every((p) => /\/accounts\/acct-xyz\/workers\/scripts\/downpipe-engine\/secrets$/.test(p.url)));
    // The custody claim under test: no OTHER secret name is ever touched by this function.
    ok("NO signer or break-glass secret was set (the function has no way to: it never receives them)", !byName.has("SIGNER_PRIVATE") && !byName.has("BREAK_GLASS_PUBLIC"));
    // After a successful add, the OPERATIONAL_RETIRED marker is cleared (best-effort), and only AFTER
    // both operational PUTs have already landed.
    ok("the add clears the OPERATIONAL_RETIRED marker AFTER both operational PUTs (3 calls, DELETE last)", stub.calls.length === 3 && (stub.calls[2] ?? "").startsWith("DELETE") && /OPERATIONAL_RETIRED$/.test(stub.calls[2] ?? ""));
    ok("the marker clear hit the same account+script secrets endpoint", stub.dels.length === 1 && /\/accounts\/acct-xyz\/workers\/scripts\/downpipe-engine\/secrets\/OPERATIONAL_RETIRED$/.test(stub.dels[0] ?? ""));
  }

  console.log("\n-- addOperationalSecrets: a failed PUT names the Edit Cloudflare Workers scope and stops --");
  {
    const calls: string[] = [];
    const denyStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push(`${init?.method ?? "GET"} ${String(input)}`);
      return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }), { status: 403 });
    }) as typeof fetch;
    let threw = "";
    try { await addOperationalSecrets("acct-xyz", "downpipe-engine", TOKEN, OPERATIONAL_PUBLIC, OPERATIONAL_PRIVATE, denyStub); } catch (e) { threw = (e as Error).message; }
    ok("a failed PUT throws naming the Edit Cloudflare Workers template", /Edit Cloudflare Workers/.test(threw) && /OPERATIONAL_PUBLIC/.test(threw));
    ok("the add STOPS on the first failed PUT (only one PUT attempted)", calls.filter((c) => c.startsWith("PUT")).length === 1);
    ok("no marker-clear DELETE was attempted (the add never got that far)", !calls.some((c) => c.startsWith("DELETE")));
    ok("the failure reason carries no token and no private value", !threw.includes(TOKEN) && !threw.includes(OPERATIONAL_PRIVATE));
  }

  console.log("\n-- addOperationalSecrets: a FAILING marker-clear (best-effort) does NOT fail the add --");
  {
    // Both operational PUTs succeed; the OPERATIONAL_RETIRED delete is then refused by Cloudflare (a real
    // fault, not a 404). The add must still resolve: the caller already got the thing they asked for (a
    // working operational pair), and a housekeeping marker-clear failure must never surface as a failed add.
    const calls: string[] = [];
    const flakyMarkerStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      calls.push(`${method} ${url}`);
      if (method === "PUT" && /\/secrets$/.test(url)) return new Response(JSON.stringify({ success: true }), { status: 200 });
      if (method === "DELETE" && /OPERATIONAL_RETIRED$/.test(url)) return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "denied" }] }), { status: 403 });
      return new Response(JSON.stringify({ success: false }), { status: 500 });
    }) as typeof fetch;
    let threw = "";
    try { await addOperationalSecrets("acct-xyz", "downpipe-engine", TOKEN, OPERATIONAL_PUBLIC, OPERATIONAL_PRIVATE, flakyMarkerStub); } catch (e) { threw = (e as Error).message; }
    ok("the add resolves successfully even though the marker-clear DELETE was refused", threw === "");
    ok("both operational PUTs landed and the (refused) marker DELETE was still attempted", calls.filter((c) => c.startsWith("PUT")).length === 2 && calls.some((c) => c.startsWith("DELETE") && c.includes("OPERATIONAL_RETIRED")));
  }

  console.log("\n-- the route SUCCEEDS on a break-glass-only engine, sets exactly two secrets, and audits it --");
  {
    // env carries SIGNER_PRIVATE + BREAK_GLASS_PUBLIC (a real break-glass-only engine) but NO OPERATIONAL_*,
    // so the route's own precondition passes and the add proceeds. The sentinel signer/break-glass values
    // stand in for "the engine's real, untouched secrets"; if the route ever touched them it would PUT them
    // (the stub records every PUT), which the assertions below would catch.
    const ADMIN_TOKEN = "keys-add-operational-admin-token";
    const storage = new MockStorage();
    const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
    const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(typeof input === "string" ? input : (input as URL).toString(), init)) } as unknown as DurableObjectStub;
    const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
    const env = {
      SCHEDULER: namespace,
      ADMIN_TOKEN,
      CF_ACCOUNT_ID: "acct-add-op",
      WORKER_NAME: "downpipe-engine",
      SIGNER_PRIVATE: SIGNER_PRIVATE_SENTINEL,
      BREAK_GLASS_PUBLIC: BREAK_GLASS_PUBLIC_SENTINEL,
    } as unknown as Env;

    const secretsStub = makeSecretsStub();
    const realFetch = globalThis.fetch;
    globalThis.fetch = secretsStub.fetch;

    let status = 0;
    let respBody = "";
    let auditText = "";
    try {
      const resp = await handleAdmin(new Request("https://engine.example/admin/keys/add-operational", {
        method: "POST",
        headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" },
        body: JSON.stringify({ token: TOKEN, operationalPublic: OPERATIONAL_PUBLIC, operationalPrivate: OPERATIONAL_PRIVATE }),
      }), env);
      status = resp.status;
      respBody = await resp.text();
      const auditResp = await handleAdmin(new Request("https://engine.example/admin/audit?limit=50", { method: "GET", headers: { authorization: `Bearer ${ADMIN_TOKEN}` } }), env);
      auditText = await auditResp.text();
    } finally {
      globalThis.fetch = realFetch;
    }

    ok("the add-operational route returns 200 on a break-glass-only engine", status === 200);
    ok("the response is a bare {ok:true} (no signer, no configured booleans: this is not the full ceremony)", /"ok":true/.test(respBody));
    ok("the response carries no token and no private value", !respBody.includes(TOKEN) && !respBody.includes(OPERATIONAL_PRIVATE));
    ok("the engine set EXACTLY two secrets: OPERATIONAL_PUBLIC and OPERATIONAL_PRIVATE", secretsStub.puts.length === 2 && secretsStub.puts.map((p) => p.name).sort().join(",") === "OPERATIONAL_PRIVATE,OPERATIONAL_PUBLIC");
    ok("the engine's signer and break-glass secrets were NEVER PUT (the custody claim)", !secretsStub.puts.some((p) => p.name === "SIGNER_PRIVATE" || p.name === "BREAK_GLASS_PUBLIC"));
    ok("no PUT carried the sentinel signer or break-glass VALUE either", !secretsStub.puts.some((p) => p.text === SIGNER_PRIVATE_SENTINEL || p.text === BREAK_GLASS_PUBLIC_SENTINEL));
    ok("the AUDIT feed records operational-added but contains NO token and NO private value", /operational-added/.test(auditText) && !auditText.includes(TOKEN) && !auditText.includes(OPERATIONAL_PRIVATE));
    ok("the route also cleared the OPERATIONAL_RETIRED marker (best-effort) via the same secrets endpoint", secretsStub.dels.length === 1 && /OPERATIONAL_RETIRED$/.test(secretsStub.dels[0] ?? ""));
  }

  console.log("\n-- the route REFUSES (audited, no fetch) when an operational key is already present --");
  {
    // env already carries a full two-recipient posture (OPERATIONAL_PUBLIC present). The route must refuse
    // WITHOUT ever calling resolveEngineAccountAndScript or touching Cloudflare, and the refusal must be
    // AUDITED as key-install-failed / cause already-configured, not a bare, unaudited 400.
    const ADMIN_TOKEN = "keys-add-operational-refuse-token";
    const storage = new MockStorage();
    const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
    const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(typeof input === "string" ? input : (input as URL).toString(), init)) } as unknown as DurableObjectStub;
    const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
    const env = {
      SCHEDULER: namespace,
      ADMIN_TOKEN,
      CF_ACCOUNT_ID: "acct-add-op-refuse",
      WORKER_NAME: "downpipe-engine",
      SIGNER_PRIVATE: SIGNER_PRIVATE_SENTINEL,
      BREAK_GLASS_PUBLIC: BREAK_GLASS_PUBLIC_SENTINEL,
      OPERATIONAL_PUBLIC: "already-here-operational-public",
      OPERATIONAL_PRIVATE: "already-here-operational-private",
    } as unknown as Env;

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
      const resp = await handleAdmin(new Request("https://engine.example/admin/keys/add-operational", {
        method: "POST",
        headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" },
        body: JSON.stringify({ token: TOKEN, operationalPublic: OPERATIONAL_PUBLIC_2, operationalPrivate: OPERATIONAL_PRIVATE }),
      }), env);
      status = resp.status;
      respBody = await resp.text();
      const auditResp = await handleAdmin(new Request("https://engine.example/admin/audit?limit=50", { method: "GET", headers: { authorization: `Bearer ${ADMIN_TOKEN}` } }), env);
      auditText = await auditResp.text();
    } finally {
      globalThis.fetch = realFetch;
    }

    ok("an already-configured engine refuses with 400, not a silent reissue", status === 400);
    ok("the refusal names the full re-key ceremony as the alternative, never implies a silent rotate", /already installed/.test(respBody) && /Generate keys/.test(respBody));
    ok("the refusal made ZERO Cloudflare API calls (nothing was read or written)", cfCalls.length === 0);
    ok("the refusal is AUDITED as key-install-failed, cause already-configured", /key-install-failed/.test(auditText) && /already-configured/.test(auditText));
    ok("the audited refusal carries no token and no private value", !auditText.includes(TOKEN) && !auditText.includes(OPERATIONAL_PRIVATE));
  }

  console.log("\n-- a NON-OWNER caller is refused with NO Cloudflare fetch, and the denial is audited --");
  {
    const TEAM = "maelstrom";
    const ISS = `https://${TEAM}.cloudflareaccess.com`;
    const AUD = "keys-add-operational-aud";
    const KID = "keys-add-operational-kid";
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
    const env = { SCHEDULER: namespace, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, CF_ACCOUNT_ID: "acct-add-op-deny", WORKER_NAME: "downpipe-engine" } as unknown as Env;

    const call = async (email: string): Promise<Response> => handleAdmin(new Request("https://engine.example/admin/keys/add-operational", {
      method: "POST",
      headers: { "cf-access-jwt-assertion": await tokenFor(email), "content-type": "application/json", origin: "https://engine.example" },
      body: JSON.stringify({ token: TOKEN, operationalPublic: OPERATIONAL_PUBLIC, operationalPrivate: OPERATIONAL_PRIVATE }),
    }), env);

    let denied: Response;
    let auditText = "";
    try {
      // The FIRST Access caller bootstraps to Owner; burn that on an owner email via a harmless GET so
      // the add-operational-attempting email below is a plain viewer, not the bootstrap owner.
      await handleAdmin(new Request("https://engine.example/admin/whoami", { method: "GET", headers: { "cf-access-jwt-assertion": await tokenFor("owner@acme.example") } }), env);
      denied = await call("viewer@acme.example");
      const ownerToken = await tokenFor("owner@acme.example");
      const auditResp = await handleAdmin(new Request("https://engine.example/admin/audit?limit=50", { method: "GET", headers: { "cf-access-jwt-assertion": ownerToken } }), env);
      auditText = await auditResp.text();
    } finally {
      globalThis.fetch = realFetch;
    }

    ok("a non-owner add-operational attempt is refused 403 (forbidden, keys.ceremony)", denied.status === 403);
    const deniedBody = await denied.text();
    ok("the refusal names the required keys.ceremony capability", /forbidden/.test(deniedBody) && /keys\.ceremony/.test(deniedBody));
    ok("the refused add-operational made ZERO Cloudflare API calls", cfApiCalls.length === 0);
    ok("the denial is audited as operational-added, outcome denied", /operational-added/.test(auditText) && /"outcome":"denied"/.test(auditText));
  }

  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nKEYS-ADD-OPERATIONAL VECTORS PASS");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
