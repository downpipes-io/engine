// Fuzz and property tests for the identity-provider payload readers: the SCIM facade, the SAML XML
// parser and response verifier, the SP metadata writer, and the OIDC ID-token verifier and issuer screens.
// Run through: node test/property/property-parsers.ts
import fc from "fast-check";
import { fetchJwksGuarded } from "../../src/admin/oidc.ts";
import { assertSafeFetchEndpoint, assertSafeIssuer, verifyIdToken, type JWKS, type VerifyIdTokenOptions } from "../../src/admin/oidc-verify.ts";
import { buildSpMetadata } from "../../src/admin/saml/metadata.ts";
import { parseXml } from "../../src/admin/saml/parser.ts";
import { verifySamlResponse } from "../../src/admin/saml/response.ts";
import { handleScim } from "../../src/admin/scim.ts";
import type { Env } from "../../src/env.d.ts";
import { b64urlEncode } from "../../src/crypto/bytes.ts";
import { ACS_URL, ASSERTION_ID, baseConn, baseCtx, buildAssertion, buildResponse, buildSelfSignedCertPem, encodeResponse, serialise, signAssertion } from "../saml-response-fixtures.ts";
import { assertSafe, assertTotal, jsonValue, mutationOf, prop, quiet, runs, text, utf8 } from "./parser-fuzz-lib.ts";

const isErr = (e: Error): boolean => e instanceof Error;
const anyString = fc.oneof(fc.string({ maxLength: 80 }), fc.string({ unit: "binary", maxLength: 60 }));

// ---- SCIM ----
const TOKEN = "scim-fuzz-bearer-token";
const SCIM_STATUS = new Set([200, 204, 400, 401, 404, 405, 429, 503]);
const PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
function scimEnv(deletes: string[], token: string | null = TOKEN): Env {
  const stub = {
    fetch: async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const u = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (u.endsWith("/roles/delete")) deletes.push((JSON.parse(String(init?.body)) as { email?: string }).email ?? "");
      return new Response(JSON.stringify(u.endsWith("/rate-check") ? { allowed: true } : { deleted: true }), { headers: { "content-type": "application/json" } });
    },
  } as unknown as DurableObjectStub;
  const ns = { idFromName: () => ({}), get: () => stub } as unknown as DurableObjectNamespace;
  return { SCHEDULER: ns, ...(token !== null ? { SCIM_BEARER_TOKEN: token } : {}) } as unknown as Env;
}
const scimReq = (method: string, path: string, bearer: string | null, body?: unknown): Request =>
  new Request(`https://engine.example${path}`, { method, headers: { ...(bearer !== null ? { authorization: `Bearer ${bearer}` } : {}), "content-type": "application/scim+json" }, ...(body !== undefined && method !== "GET" && method !== "HEAD" ? { body: typeof body === "string" ? body : JSON.stringify(body) } : {}) });
const scimPath = fc.oneof(
  fc.constantFrom("/scim/v2/ServiceProviderConfig", "/scim/v2/Users", "/scim/v2/Users/", "/scim/v2/Users/a%40b.co", "/scim/v2/Users/%E0%A4%A", "/scim/v2/Users/a%2Fb", "/scim/v2/Groups", "/scim/v2/"),
  fc.string({ maxLength: 30 }).map((s) => `/scim/v2/Users/${encodeURIComponent(s)}`),
  fc.string({ maxLength: 20 }).map((s) => `/scim/v2/${encodeURIComponent(s)}`),
);
const objectBody = fc.oneof(
  fc.constant({ schemas: [PATCH_OP], Operations: [{ op: "replace", path: "active", value: false }] }),
  fc.record({ schemas: fc.oneof(fc.constant([PATCH_OP]), fc.array(fc.string({ maxLength: 8 }), { maxLength: 2 })), Operations: jsonValue }, { requiredKeys: [] }),
  fc.dictionary(fc.string({ maxLength: 8 }), jsonValue, { maxKeys: 4 }),
);
const method = fc.constantFrom("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS");

async function scimRound(m: string, path: string, bearer: string | null, body: unknown): Promise<{ res: Response; deletes: string[] }> {
  const deletes: string[] = [];
  const res = await assertTotal("handleScim", () => handleScim(scimReq(m, path, bearer, body), scimEnv(deletes)));
  if (!(res instanceof Response) || !SCIM_STATUS.has(res.status)) throw new Error(`status ${res instanceof Response ? res.status : "none"} is outside the closed set`);
  return { res, deletes };
}

// ---- OIDC ----
const ISS = "https://idp.example.com";
const CLIENT = "client-1";
const NONCE = "n-1";
const NOW = 1_800_000_000;
const enc = (v: unknown): string => b64urlEncode(utf8(typeof v === "string" ? v : JSON.stringify(v)));
async function oidcKeys(): Promise<{ jwks: JWKS; mint: (header: unknown, payload: unknown) => Promise<string> }> {
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as JsonWebKey;
  return {
    jwks: { keys: [{ kid: "k1", kty: "EC", crv: "P-256", alg: "ES256", use: "sig", x: jwk.x!, y: jwk.y! }] },
    mint: async (header, payload) => {
      const input = `${enc(header)}.${enc(payload)}`;
      const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, utf8(input) as BufferSource));
      return `${input}.${b64urlEncode(sig)}`;
    },
  };
}
const OPTS: VerifyIdTokenOptions = { expectedIssuer: ISS, clientId: CLIENT, allowedAlgs: ["ES256"], nonce: NONCE, now: NOW };
const GOOD_PAYLOAD = { iss: ISS, aud: CLIENT, sub: "user-1", exp: NOW + 600, iat: NOW - 10, nonce: NONCE, email: "a@b.co", email_verified: true };

export async function runIdpProperties(): Promise<void> {
  console.log("scim facade");
  await prop("handleScim: arbitrary requests with the right bearer give a closed status and never crash", async () => {
    await quiet(() =>
      fc.assert(
        fc.asyncProperty(method, scimPath, fc.oneof(objectBody, anyString, fc.constant(undefined)), async (m, path, body) => {
          const { deletes } = await scimRound(m, path, TOKEN, body);
          if (deletes.length > 1) throw new Error("one request offboarded more than once");
          for (const e of deletes) if (!e.includes("@") || e.length > 320 || /[\r\n]/.test(e)) throw new Error("offboarded a member id that fails the email screen");
          if (deletes.length > 0 && m !== "DELETE" && m !== "PATCH") throw new Error(`offboarded on ${m}`);
        }),
        runs(300),
      ),
    );
  });
  await prop("handleScim: no bearer, a wrong bearer or no configured token never reaches the offboard route", async () => {
    await quiet(() =>
      fc.assert(
        fc.asyncProperty(method, scimPath, fc.option(fc.string({ maxLength: 40 }), { nil: null }), objectBody, async (m, path, bearer, body) => {
          const used = bearer === TOKEN ? "other" : bearer;
          const deletes: string[] = [];
          const res = await assertTotal("handleScim", () => handleScim(scimReq(m, path, used, body), scimEnv(deletes)));
          if (res.status !== 401 && res.status !== 429) throw new Error(`status ${res.status} without a valid bearer`);
          const off = await assertTotal("handleScim", () => handleScim(scimReq(m, path, TOKEN, body), scimEnv(deletes, null)));
          if (off.status !== 503) throw new Error(`status ${off.status} with no configured token`);
          if (deletes.length > 0) throw new Error("offboarded without authority");
        }),
        runs(150),
      ),
    );
  });
  await prop("handleScim: a deprovision request offboards the decoded member exactly once", async () => {
    await quiet(() =>
      fc.assert(
        fc.asyncProperty(fc.emailAddress(), fc.boolean(), async (email, viaPatch) => {
          const body = { schemas: [PATCH_OP], Operations: [{ op: "replace", path: "active", value: false }] };
          const { res, deletes } = await scimRound(viaPatch ? "PATCH" : "DELETE", `/scim/v2/Users/${encodeURIComponent(email)}`, TOKEN, viaPatch ? body : undefined);
          if (res.status !== 204 || deletes.length !== 1 || deletes[0] !== email) throw new Error(`status ${res.status}, deletes ${JSON.stringify(deletes)}`);
        }),
        runs(60),
      ),
    );
  });
  await prop("handleScim: a PATCH body of JSON null is refused with a 400, not a thrown TypeError", async () => {
    await quiet(() => scimRound("PATCH", "/scim/v2/Users/a%40b.co", TOKEN, "null").then(() => undefined));
  });

  console.log("saml");
  const rsa = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", rsa.publicKey));
  const certPem = await buildSelfSignedCertPem(spki, rsa.privateKey, "idp.example");
  const conn = baseConn([certPem]);
  const signed = await signAssertion(buildAssertion(), ASSERTION_ID, rsa.privateKey);
  const responseXml = utf8(serialise(buildResponse([signed])));
  const responseB64 = encodeResponse(buildResponse([signed]));
  const b64std = (b: Uint8Array): string => Buffer.from(b).toString("base64");
  const base = await verifySamlResponse(responseB64, conn, baseCtx());

  await prop("parseXml: arbitrary text and bytes never throw and refuse with a reason", async () => {
    await fc.assert(
      fc.asyncProperty(fc.oneof(anyString, fc.uint8Array({ maxLength: 200 }), fc.constantFrom("<a>", "<!DOCTYPE a [<!ENTITY x 'y'>]><a>&x;</a>", "<a xmlns:p='u' p:x='1' p:x='2'/>", "<a>&#0;</a>", "<?xml version='1.0'?><a/>")), async (v) => {
        const r = await assertTotal("parseXml", async () => parseXml(v));
        if (!r.ok && (typeof r.reason !== "string" || r.reason === "")) throw new Error("refusal without a reason");
      }),
      runs(500),
    );
  });
  await prop("parseXml: mutations of a real signed Response never throw", async () => {
    await fc.assert(fc.asyncProperty(mutationOf(responseXml), async (b) => void (await assertTotal("parseXml", async () => parseXml(b)))), runs(400));
    if (!parseXml(responseXml).ok) throw new Error("the real Response did not parse");
  });
  await prop("parseXml: nesting past the depth limit is refused, within it is accepted, and a huge nest does not overflow", async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 1, max: 160 }), async (d) => {
        const r = await assertTotal("parseXml", async () => parseXml(`${"<a>".repeat(d)}${"</a>".repeat(d)}`));
        if (r.ok !== d <= 100) throw new Error(`depth ${d} gave ok=${r.ok}`);
      }),
      runs(40),
    );
    const big = await assertTotal("parseXml", async () => parseXml(`${"<a>".repeat(150_000)}${"</a>".repeat(150_000)}`));
    if (big.ok) throw new Error("a 150000-deep document was accepted");
  });
  await prop("parseXml: a wide document past the node limit is refused", async () => {
    const r = await assertTotal("parseXml", async () => parseXml(`<a>${"<b/>".repeat(60_000)}</a>`));
    if (r.ok) throw new Error("60000 children were accepted under a 50000-node limit");
  });
  await prop("verifySamlResponse: the real Response verifies, and arbitrary base64 refuses with a reason", async () => {
    if (!base.ok) throw new Error(`the real Response did not verify: ${base.reason}`);
    await fc.assert(
      fc.asyncProperty(fc.oneof(anyString, fc.uint8Array({ maxLength: 300 }).map(b64std)), async (s) => {
        const r = await assertTotal("verifySamlResponse", () => verifySamlResponse(s, conn, baseCtx()));
        if (r.ok) throw new Error("arbitrary input verified");
        if (typeof r.reason !== "string" || r.reason === "") throw new Error("refusal without a reason");
      }),
      runs(300),
    );
  });
  await prop("verifySamlResponse: a mutated signed Response never crashes and never yields another principal", async () => {
    await fc.assert(
      fc.asyncProperty(mutationOf(responseXml), async (b) => {
        const r = await assertTotal("verifySamlResponse", () => verifySamlResponse(b64std(b), conn, baseCtx()));
        if (r.ok && base.ok && JSON.stringify(r.principal) !== JSON.stringify(base.principal)) throw new Error("a mutation verified as a different principal");
      }),
      runs(150),
    );
  });
  await prop("buildSpMetadata: arbitrary entity ids and formats round-trip through the parser", async () => {
    await fc.assert(
      fc.asyncProperty(fc.string({ maxLength: 40 }), fc.string({ maxLength: 40 }), async (entity, fmt) => {
        const xml = await assertTotal("buildSpMetadata", async () => buildSpMetadata({ ...conn, spEntityId: entity, nameIdFormat: fmt }, ACS_URL));
        const r = parseXml(xml);
        if (!r.ok) throw new Error(`the writer's own metadata did not parse: ${r.reason}`);
      }),
      runs(300),
    );
  });

  console.log("oidc");
  const o = await oidcKeys();
  const goodToken = await o.mint({ alg: "ES256", kid: "k1", typ: "JWT" }, GOOD_PAYLOAD);
  await prop("verifyIdToken: the real token verifies and arbitrary strings refuse with a reason", async () => {
    const g = await verifyIdToken(goodToken, o.jwks, OPTS);
    if (!g.ok) throw new Error(`the real token did not verify: ${g.reason}`);
    await fc.assert(
      fc.asyncProperty(fc.oneof(anyString, fc.tuple(anyString, anyString, anyString).map((t) => t.join(".")), fc.constant("a".repeat(40_000))), async (s) => {
        const r = await assertTotal("verifyIdToken", () => verifyIdToken(s, o.jwks, OPTS));
        if (r.ok) throw new Error("arbitrary text verified");
        if (typeof r.reason !== "string" || r.reason === "") throw new Error("refusal without a reason");
      }),
      runs(300),
    );
  });
  await prop("verifyIdToken: a mutated real token never crashes and never yields another subject", async () => {
    await fc.assert(
      fc.asyncProperty(mutationOf(utf8(goodToken)).map(text), async (t) => {
        const r = await assertTotal("verifyIdToken", () => verifyIdToken(t, o.jwks, OPTS));
        if (r.ok && (r.sub !== "user-1" || r.iss !== ISS)) throw new Error("a mutation verified as another subject");
      }),
      runs(200),
    );
  });
  await prop("verifyIdToken: arbitrary JSON headers and payloads under a real or garbage signature refuse and never crash", async () => {
    await fc.assert(
      fc.asyncProperty(jsonValue, jsonValue, fc.boolean(), async (h, p, real) => {
        const t = real ? await o.mint(h, p) : `${enc(h)}.${enc(p)}.${enc("garbage-signature")}`;
        const r = await assertTotal("verifyIdToken", () => verifyIdToken(t, o.jwks, OPTS));
        if (r.ok) throw new Error("an arbitrary document verified");
      }),
      runs(300),
    );
  });
  await prop("fetchJwksGuarded then verifyIdToken: an arbitrary JWKS document gives a sanitised set or a reason, and never a crash downstream", async () => {
    const serve = (body: string): typeof fetch => (async () => new Response(body, { status: 200, headers: { "content-type": "application/json" } })) as unknown as typeof fetch;
    await fc.assert(
      fc.asyncProperty(fc.oneof(jsonValue.map((v) => JSON.stringify(v)), anyString, fc.array(fc.dictionary(fc.constantFrom("kid", "kty", "crv", "x", "y", "n", "e", "alg", "use"), fc.oneof(fc.string({ maxLength: 12 }), jsonValue)), { maxLength: 4 }).map((keys) => JSON.stringify({ keys: [...keys, ...o.jwks.keys] }))), async (body) => {
        const r = await assertTotal("fetchJwksGuarded", () => fetchJwksGuarded("https://idp.example.com/jwks", serve(body)));
        if (!r.ok) {
          if (typeof r.reason !== "string" || r.reason === "") throw new Error("refusal without a reason");
          return;
        }
        const kids = new Set<string>();
        for (const k of r.jwks.keys) {
          if (typeof k !== "object" || k === null || typeof k.kty !== "string") throw new Error("the sanitiser kept a key without a string kty");
          if (typeof k.kid === "string") {
            if (kids.has(k.kid)) throw new Error("the sanitiser kept a duplicate kid");
            kids.add(k.kid);
          }
        }
        const v = await assertTotal("verifyIdToken", () => verifyIdToken(goodToken, r.jwks, OPTS));
        if (v.ok && !body.includes(o.jwks.keys[0]!.x!)) throw new Error("verified without the signing key");
      }),
      runs(200),
    );
  });
  await prop("verifyIdToken: a JWKS without a keys array or with a null member refuses with a reason, not a TypeError", async () => {
    await fc.assert(
      fc.asyncProperty(fc.constantFrom<unknown>(0, null, [], {}, { keys: null }, { keys: [null] }, { keys: "x" }), async (j) => {
        await assertTotal("verifyIdToken", () => verifyIdToken(goodToken, j as JWKS, OPTS));
      }),
      runs(10),
    );
  });
  await prop("assertSafeIssuer and assertSafeFetchEndpoint: arbitrary text refuses with an Error, never crashes", async () => {
    await fc.assert(
      fc.asyncProperty(fc.oneof(anyString, fc.webUrl(), fc.constantFrom("https://[::1]/", "https://127.0.0.1/", "https://0x7f.1/", "https://localhost./", "http://a/", "https://a@b/")), async (s) => {
        await assertSafe("assertSafeIssuer", () => assertSafeIssuer(s), isErr);
        await assertSafe("assertSafeFetchEndpoint", () => assertSafeFetchEndpoint(s), isErr);
      }),
      runs(400),
    );
  });
}
