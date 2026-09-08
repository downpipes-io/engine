// Shared harness for the validate-passkey suite (split out of validate-passkey.ts so no single file or
// function is oversized). This module holds the fake-but-REAL authenticator, the tiny CBOR encoder, the
// in-memory DO double, the HTTP-ish drivers over handleAdmin, and the shared ok() pass-counter. The test
// groups (validate-passkey-*.ts) import these and each export a run(); validate-passkey.ts orchestrates
// them in order so `node test/validate-passkey.ts` still executes the full suite.
//
// The verification path under test is the one that ships: these helpers stand up a genuine P-256 (ES256)
// or RSA (RS256) keypair with Web Crypto, build real WebAuthn structures (a CBOR attestationObject with
// fmt "none", authenticatorData carrying the COSE public key, a clientDataJSON echoing the server
// challenge), and SIGN real assertions over (authenticatorData || SHA-256(clientDataJSON)). The REAL
// scheduler DO issues + single-use consumes the challenge, runs the production verifyRegistration/
// verifyAssertion, persists the credential + signCount, and bootstraps the first registrant to Owner.

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { b64urlEncode, b64urlDecode } from "../src/crypto/bytes.ts";
import { passkeySubject } from "../src/admin/identity.ts";
import { MockStorage } from "./mock-storage.ts";
import type { Env } from "../src/env.d.ts";

export { MockStorage };

// ---- The shared pass-counter -------------------------------------------------------------------
// failures is module-global so every test group records into the SAME counter; the orchestrator reads it
// via failureCount() after running all groups, then prints the summary and exits non-zero on any failure.
let failures = 0;
export function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
export function failureCount(): number {
  return failures;
}

// ---- In-memory DO storage (the subset SchedulerDO uses) ---------------------------------------
// The in-memory DurableObjectState storage double (get/put/delete, a sorted prefix list, a no-op
// setAlarm and the countPrefix helper this suite uses to assert nothing leaked) is the shared
// MockStorage from ./mock-storage.ts, re-exported above so the passkey groups keep importing it from
// the harness. The shared list returns keys in lexicographic order, a deterministic superset of the
// insertion-order scan this suite relies on.

// makeScheduler builds a SchedulerDO over MockStorage and a SCHEDULER namespace whose idFromName/get
// both return a stub forwarding fetch() into the DO, so handleAdmin's schedulerStub() resolves to this
// one in-memory DO. The env carries CONSOLE_ORIGIN (the WebAuthn origin) so handlePasskey resolves the
// origin + rp.id; PASSKEY_RP_ID is left unset so the rp.id DEFAULTS to the console host (the WebAuthn-
// correct default), which is what these tests bind and check against.
export const ORIGIN = "https://downpipe-console.example";
export const RP_ID = "downpipe-console.example"; // host of ORIGIN (the default rp.id)
// ADMIN_TOKEN is the deploy-time operator secret. The account-takeover fix makes it the ONLY way to enrol
// the FIRST Owner passkey (the bootstrap path), so the env carries one and the bootstrap registration
// presents it as a Bearer token. Subsequent enrolments use the invite or self-add paths instead.
export const ADMIN_TOKEN = "test-admin-token-deadbeef-deadbeef";

export function makeScheduler(): { env: Env; storage: MockStorage; stub: DurableObjectStub } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  const env = { SCHEDULER: namespace, CONSOLE_ORIGIN: ORIGIN, ADMIN_TOKEN } as unknown as Env;
  return { env, storage, stub };
}

// captureErrors swaps console.error for a collector (without suppressing it) so a test can assert the
// precise reason was logged with an opaque [err:XXXXXXXX category] id and that the raw detail never
// leaks to the client. Returns the captured lines and a restore fn.
export function captureErrors(): { errors: string[]; restore: () => void } {
  const errors: string[] = [];
  const orig = console.error;
  console.error = (...args: unknown[]): void => {
    errors.push(args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" "));
  };
  return { errors, restore: () => { console.error = orig; } };
}

// ---- A minimal CBOR ENCODER for the test (the module only ships a decoder) ---------------------
// We encode exactly the shapes a real authenticator emits: the attestationObject map (text keys) and the
// COSE_Key map (integer keys), plus the byte/text/int primitives those need. This is deliberately a tiny
// encoder; it lets the test build BYTE-FOR-BYTE real WebAuthn structures that the production decoder then
// parses, so the round trip exercises the real CBOR path. Maps are emitted in insertion order.
export type CborInput =
  | { int: number }
  | { bytes: Uint8Array }
  | { text: string }
  | { map: Array<[CborInput, CborInput]> }
  | { array: CborInput[] };

function encHead(major: number, n: number): Uint8Array {
  if (n < 24) return new Uint8Array([(major << 5) | n]);
  if (n < 0x100) return new Uint8Array([(major << 5) | 24, n]);
  if (n < 0x10000) return new Uint8Array([(major << 5) | 25, (n >> 8) & 0xff, n & 0xff]);
  // 32-bit length is enough for every structure here.
  return new Uint8Array([(major << 5) | 26, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
}

export function cat(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

export function cborEncode(v: CborInput): Uint8Array {
  if ("int" in v) {
    if (v.int >= 0) return encHead(0, v.int);
    return encHead(1, -1 - v.int); // negative integer
  }
  if ("bytes" in v) return cat(encHead(2, v.bytes.length), v.bytes);
  if ("text" in v) {
    const b = new TextEncoder().encode(v.text);
    return cat(encHead(3, b.length), b);
  }
  if ("array" in v) {
    const items = v.array.map(cborEncode);
    return cat(encHead(4, v.array.length), ...items);
  }
  // map
  const pairs = v.map.map(([k, val]) => cat(cborEncode(k), cborEncode(val)));
  return cat(encHead(5, v.map.length), ...pairs);
}

// ---- A fake-but-REAL authenticator -------------------------------------------------------------
// Authenticator holds a Web Crypto keypair (ES256 P-256 or RS256 RSA), a credential id, an AAGUID, and a
// running signCount. It can emit a real attestationObject (registration) and a real signed assertion
// (login). The COSE public key is built from the exported JWK, so the bytes the DO stores and re-parses
// are the genuine COSE encoding of this key.
export interface Authenticator {
  alg: "ES256" | "RS256";
  credentialId: Uint8Array;
  aaguid: Uint8Array;
  signCount: number;
  privateKey: CryptoKey;
  cosePublicKey: Uint8Array;
}

export async function makeAuthenticator(alg: "ES256" | "RS256"): Promise<Authenticator> {
  const credentialId = crypto.getRandomValues(new Uint8Array(32));
  const aaguid = crypto.getRandomValues(new Uint8Array(16));
  if (alg === "ES256") {
    const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const jwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { x: string; y: string };
    const x = b64urlDecode(jwk.x);
    const y = b64urlDecode(jwk.y);
    // COSE_Key EC2: { 1:2 (kty EC2), 3:-7 (alg ES256), -1:1 (crv P-256), -2:x, -3:y }.
    const cose = cborEncode({
      map: [
        [{ int: 1 }, { int: 2 }],
        [{ int: 3 }, { int: -7 }],
        [{ int: -1 }, { int: 1 }],
        [{ int: -2 }, { bytes: x }],
        [{ int: -3 }, { bytes: y }],
      ],
    });
    return { alg, credentialId, aaguid, signCount: 0, privateKey: kp.privateKey, cosePublicKey: cose };
  }
  // RS256.
  const kp = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const jwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
  const n = b64urlDecode(jwk.n);
  const e = b64urlDecode(jwk.e);
  // COSE_Key RSA: { 1:3 (kty RSA), 3:-257 (alg RS256), -1:n, -2:e }.
  const cose = cborEncode({
    map: [
      [{ int: 1 }, { int: 3 }],
      [{ int: 3 }, { int: -257 }],
      [{ int: -1 }, { bytes: n }],
      [{ int: -2 }, { bytes: e }],
    ],
  });
  return { alg, credentialId, aaguid, signCount: 0, privateKey: kp.privateKey, cosePublicKey: cose };
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data as Uint8Array<ArrayBuffer>));
}

// buildAuthData assembles authenticator data: rpIdHash(32) || flags(1) || signCount(4) [|| AAGUID(16) ||
// credIdLen(2) || credId || COSE]. attested=true builds the registration shape (attested credential data
// present, AT flag set); attested=false builds the assertion shape (header only). up controls the
// user-present flag.
export async function buildAuthData(
  auth: Authenticator,
  rpId: string,
  // uv is widened to boolean | undefined because callers forward opts.uv verbatim (an undefined requests the
  // default); the body reads `opts.uv ?? true`, so undefined is a meaningful, handled value.
  opts: { attested: boolean; up: boolean; signCount: number; uv?: boolean | undefined; includeAttestedData?: boolean },
): Promise<Uint8Array> {
  const rpIdHash = await sha256(new TextEncoder().encode(rpId));
  let flags = 0;
  if (opts.up) flags |= 0x01; // UP
  // UV (user verified) is now REQUIRED by the verifier (the admin front door), so it defaults to set; a
  // test drives the UV-absent negative control by passing uv:false.
  if (opts.uv ?? true) flags |= 0x04; // UV
  if (opts.attested) flags |= 0x40; // AT
  const sc = new Uint8Array(4);
  new DataView(sc.buffer).setUint32(0, opts.signCount, false);
  // includeAttestedData controls whether the attested-credential-data bytes are appended; it defaults to
  // the AT flag. A test sets the AT flag WITHOUT appending real data (or appends data on an assertion) to
  // drive the "AT set on an assertion is rejected" control: here we set the AT flag but append a minimal
  // attested-credential-data block so the structure parses far enough for the AT check to fire.
  const appendAttested = opts.includeAttestedData ?? opts.attested;
  if (!appendAttested) return cat(rpIdHash, new Uint8Array([flags]), sc);
  const credIdLen = new Uint8Array(2);
  new DataView(credIdLen.buffer).setUint16(0, auth.credentialId.length, false);
  return cat(rpIdHash, new Uint8Array([flags]), sc, auth.aaguid, credIdLen, auth.credentialId, auth.cosePublicKey);
}

// clientDataJSON builds a real clientDataJSON for a ceremony type, echoing the server challenge (b64url)
// and the origin. extra lets a test override individual fields (a wrong origin/type/challenge).
export function clientDataJSON(type: string, challengeB64: string, origin: string): Uint8Array {
  const obj = { type, challenge: challengeB64, origin, crossOrigin: false };
  return new TextEncoder().encode(JSON.stringify(obj));
}

// rawToDer converts a raw r||s ECDSA signature (what Web Crypto's ECDSA sign emits) to the ASN.1 DER
// SEQUENCE{INTEGER r, INTEGER s} a WebAuthn assertion actually carries, so the test feeds the DO the DER
// the production derEcdsaToRaw path expects. It mirrors the inverse of the module's converter: minimal
// encoding, a 0x00 sign byte prepended when the high bit is set.
export function rawToDer(raw: Uint8Array): Uint8Array {
  const r = raw.subarray(0, 32);
  const s = raw.subarray(32, 64);
  const enc = (b: Uint8Array): Uint8Array => {
    // strip leading zeros (but keep at least one byte)
    let i = 0;
    while (i < b.length - 1 && b[i] === 0x00) i++;
    let v = b.subarray(i);
    // prepend 0x00 if the high bit is set (so it reads as a positive INTEGER)
    if ((v[0]! & 0x80) !== 0) v = cat(new Uint8Array([0x00]), v);
    return cat(new Uint8Array([0x02, v.length]), v);
  };
  const rDer = enc(r);
  const sDer = enc(s);
  const body = cat(rDer, sDer);
  return cat(new Uint8Array([0x30, body.length]), body);
}

// signAssertion produces a real WebAuthn assertion for an authenticator: it builds the assertion
// authenticatorData, the clientDataJSON, signs over (authData || SHA-256(clientDataJSON)) with the
// authenticator's private key (DER for ES256, raw PKCS#1 for RS256), and returns the credential JSON the
// finish endpoint expects. opts let a test drive the negative controls (wrong origin/rpId/challenge, a
// chosen signCount, a tamper on the signature, the user-present flag).
export async function signAssertion(
  auth: Authenticator,
  challengeB64: string,
  opts: { origin?: string; rpId?: string; signCount?: number; tamper?: boolean; up?: boolean; uv?: boolean; forceAt?: boolean } = {},
): Promise<{ id: string; rawId: string; type: string; response: { clientDataJSON: string; authenticatorData: string; signature: string } }> {
  const origin = opts.origin ?? ORIGIN;
  const rpId = opts.rpId ?? RP_ID;
  const signCount = opts.signCount ?? auth.signCount + 1;
  const up = opts.up ?? true;
  // forceAt sets the AT (attested-credential-data) flag on an ASSERTION (and appends the attested data),
  // which the hardened verifier rejects: an assertion must carry no attested credential data. uv:false
  // drives the user-verified-absent control.
  const authData = await buildAuthData(auth, rpId, { attested: false, up, signCount, uv: opts.uv, ...(opts.forceAt ? { includeAttestedData: true } : {}) });
  if (opts.forceAt) {
    // Set the AT flag bit on the authData header (byte 32) so the assertion claims attested credential data.
    authData[32] = authData[32]! | 0x40;
  }
  const cd = clientDataJSON("webauthn.get", challengeB64, origin);
  const cdHash = await sha256(cd);
  const signed = cat(authData, cdHash);
  let sig: Uint8Array;
  if (auth.alg === "ES256") {
    const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, auth.privateKey, signed as Uint8Array<ArrayBuffer>));
    sig = rawToDer(raw);
  } else {
    sig = new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, auth.privateKey, signed as Uint8Array<ArrayBuffer>));
  }
  if (opts.tamper) {
    // Flip a bit in the signature so it can no longer verify (but stays structurally valid DER/PKCS#1:
    // we flip a byte in the middle, not the DER framing, so the parser still accepts the shape and the
    // CRYPTO check is what fails, proving the signature is actually verified).
    const mid = Math.floor(sig.length / 2);
    sig = sig.slice();
    sig[mid] = sig[mid]! ^ 0x01;
  }
  return {
    id: b64urlEncode(auth.credentialId),
    rawId: b64urlEncode(auth.credentialId),
    type: "public-key",
    response: { clientDataJSON: b64urlEncode(cd), authenticatorData: b64urlEncode(authData), signature: b64urlEncode(sig) },
  };
}

// buildAttestation produces a real registration credential for an authenticator: a CBOR attestationObject
// with fmt "none", the registration authData (attested credential data present), and the clientDataJSON
// echoing the server challenge. opts let a test drive a wrong origin / wrong rpId / wrong type / absent
// user-present / a corrupted COSE key.
export async function buildAttestation(
  auth: Authenticator,
  challengeB64: string,
  opts: { origin?: string; rpId?: string; type?: string; up?: boolean; uv?: boolean; corruptCose?: boolean } = {},
): Promise<{ id: string; rawId: string; type: string; response: { clientDataJSON: string; attestationObject: string } }> {
  const origin = opts.origin ?? ORIGIN;
  const rpId = opts.rpId ?? RP_ID;
  const type = opts.type ?? "webauthn.create";
  const up = opts.up ?? true;
  if (opts.corruptCose) {
    // Replace the COSE key with a malformed one (a CBOR map missing the kty/alg labels) so the verifier's
    // parseCoseKey rejects it. We mutate a copy of the authenticator's COSE field for this build only.
    auth = { ...auth, cosePublicKey: cborEncode({ map: [[{ int: 99 }, { int: 1 }]] }) };
  }
  // uv defaults to set (the verifier now REQUIRES user verification at registration); a test passes
  // uv:false to drive the UV-absent registration control.
  const authData = await buildAuthData(auth, rpId, { attested: true, up, uv: opts.uv, signCount: auth.signCount });
  const attObj = cborEncode({
    map: [
      [{ text: "fmt" }, { text: "none" }],
      [{ text: "attStmt" }, { map: [] }],
      [{ text: "authData" }, { bytes: authData }],
    ],
  });
  const cd = clientDataJSON(type, challengeB64, origin);
  return {
    id: b64urlEncode(auth.credentialId),
    rawId: b64urlEncode(auth.credentialId),
    type: "public-key",
    response: { clientDataJSON: b64urlEncode(cd), attestationObject: b64urlEncode(attObj) },
  };
}

// ---- HTTP-ish drivers over handleAdmin ---------------------------------------------------------
// post drives an /admin/auth/* route through handleAdmin, the same entry the live Worker calls, so the
// unauthenticated dispatch, the origin/rp.id resolution and the DO forward are all exercised. opts let a
// test set the headers that decide the proven registration path: an Authorization bearer (the ADMIN_TOKEN
// bootstrap / token self-add), a session Cookie (a passkey-session self-add), and the Origin (the CSRF/
// logout check). CF-Connecting-IP is set (so the per-IP auth limiter has a key) unless the test overrides
// it. It returns the parsed JSON body, the status, and the FIRST Set-Cookie header (so a test can carry the
// minted session into a later self-add).
// PasskeyOptions is the WebAuthn creation/request options a begin response carries under publicKey. Only
// the fields these tests read are named (the rest stay open via the index signature); the named fields
// mirror what the begin endpoints return so the assertions are type-checked against the real shape.
export type PasskeyOptions = {
  challenge?: string;
  rp?: { id?: string;[k: string]: unknown };
  user?: { name?: string;[k: string]: unknown };
  pubKeyCredParams?: unknown;
  authenticatorSelection?: { userVerification?: string;[k: string]: unknown };
  allowCredentials?: Array<{ id?: string;[k: string]: unknown }>;
  [k: string]: unknown;
};

// PasskeyBody is the narrow JSON-OBJECT shape the /admin/auth/* responses carry that these tests read.
// Every field is optional because a single endpoint returns only its relevant subset (a begin returns
// publicKey+challengeId, a finish returns ok/role/bootstrapped, an error returns error/reason). This
// replaces the prior `any` so assertions against .json.* are still type-checked.
export type PasskeyBody = {
  ok?: boolean;
  bootstrapped?: boolean;
  role?: string;
  email?: string;
  error?: string;
  reason?: string;
  challengeId?: string;
  recoveryCodes?: string[];
  inviteToken?: string;
  publicKey?: PasskeyOptions;
  [k: string]: unknown;
};

// PasskeyJson is the FULL parse result a JSON decode can yield: the object body, or (for a non-JSON body)
// the raw string, or null. The /admin/auth/* endpoints these tests drive always answer with a JSON object
// (success, the coarse { error } / { ok:false, reason }, and the 429 { error:"rate limited" } are all
// objects), so the post() helpers below expose json as PasskeyBody; challengeFor takes this wider type
// because it is the one site that defensively guards the non-object shapes before reading publicKey.
export type PasskeyJson = PasskeyBody | string | null;

// post returns json typed as the PasskeyBody OBJECT (not the wider PasskeyJson union): every /admin/auth/*
// response these tests drive is a JSON object, so the assertions read .json.<field> directly. The parse is
// unchanged at runtime (a JSON object on every real path here); the rawJson union is still computed and the
// raw string/null fallback is preserved for the (here-unreached) non-JSON case, so behaviour is identical.
// The single narrowing lives here so the call sites need no per-site cast.
export async function post(
  env: Env,
  path: string,
  body: unknown,
  opts: { authorization?: string; cookie?: string; origin?: string; ip?: string | null } = {},
): Promise<{ status: number; json: PasskeyBody; setCookie: string | null; retryAfter: string | null }> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (opts.authorization !== undefined) headers["authorization"] = opts.authorization;
  if (opts.cookie !== undefined) headers["cookie"] = opts.cookie;
  if (opts.origin !== undefined) headers["origin"] = opts.origin;
  // Default a stable per-test source IP so the per-IP auth limiter is exercised on the happy path without
  // tripping; a test that wants the absent-IP fail-open or the limiter trip overrides ip.
  const ip = opts.ip === undefined ? "203.0.113.7" : opts.ip;
  if (ip !== null) headers["CF-Connecting-IP"] = ip;
  const resp = await handleAdmin(new Request(`https://engine.example${path}`, {
    method: "POST",
    body: JSON.stringify(body),
    headers,
  }), env);
  const text = await resp.text();
  let rawJson: PasskeyJson = null;
  try { rawJson = JSON.parse(text) as PasskeyJson; } catch { rawJson = text; }
  // The endpoints under test always answer a JSON object, so expose it as PasskeyBody for the assertions;
  // the parse above is the genuine runtime value (object on every path these tests reach).
  const json = (typeof rawJson === "object" && rawJson !== null ? rawJson : {}) as PasskeyBody;
  // retryAfter exposes the Retry-After response header so a test can verify the rate limiter's
  // Retry-After contract on a 429, not just the coarse body.
  return { status: resp.status, json, setCookie: resp.headers.get("set-cookie"), retryAfter: resp.headers.get("retry-after") };
}

// extractSessionCookie turns a Set-Cookie header value into a Cookie header value (name=value) a later
// request can present, so a test can carry a minted passkey session into a self-add registration.
export function extractSessionCookie(setCookie: string | null): string | null {
  if (setCookie === null) return null;
  const first = setCookie.split(";")[0]!.trim();
  return first.length > 0 ? first : null;
}

// registerBegin / registerFinish / loginBegin / loginFinish are thin helpers over post(). opts carry the
// proven-path inputs: inviteToken (a client body field, the invite path), authorization (the bootstrap /
// token self-add), and cookie (a session self-add). The origin defaults to the configured ORIGIN.
export type RegOpts = { inviteToken?: string; authorization?: string; cookie?: string; origin?: string; ip?: string | null };
export async function registerBegin(env: Env, email: string, opts: RegOpts = {}): Promise<{ status: number; json: PasskeyBody; setCookie: string | null }> {
  const { inviteToken, ...h } = opts;
  return post(env, "/admin/auth/register/begin", { email, ...(inviteToken !== undefined ? { inviteToken } : {}) }, h);
}
export async function registerFinish(env: Env, email: string, credential: unknown, opts: RegOpts = {}): Promise<{ status: number; json: PasskeyBody; setCookie: string | null }> {
  const { inviteToken, ...h } = opts;
  return post(env, "/admin/auth/register/finish", { email, credential, ...(inviteToken !== undefined ? { inviteToken } : {}) }, h);
}
export async function loginBegin(env: Env, email?: string): Promise<{ status: number; json: PasskeyBody; setCookie: string | null }> {
  return post(env, "/admin/auth/login/begin", email !== undefined ? { email } : {});
}
export async function loginFinish(env: Env, challengeId: string, credential: unknown): Promise<{ status: number; json: PasskeyBody; setCookie: string | null }> {
  return post(env, "/admin/auth/login/finish", { challengeId, credential });
}

// bootstrapOpts is the Authorization+Origin a FIRST-Owner (bootstrap) registration needs: the ADMIN_TOKEN
// bearer (proving the operator) and the configured Origin.
export const bootstrapOpts = (): RegOpts => ({ authorization: `Bearer ${ADMIN_TOKEN}`, origin: ORIGIN });

// enrolBootstrapOwner runs the full FIRST-Owner enrolment (begin+finish) over the bootstrap path and
// returns the finish result. Used as the common setup for tests that need an established account before
// exercising invite/self-add/login. It asserts nothing (callers assert what they care about).
export async function enrolBootstrapOwner(env: Env, auth: Authenticator, email: string): Promise<{ status: number; json: PasskeyBody; setCookie: string | null }> {
  const begin = await registerBegin(env, email, bootstrapOpts());
  const att = await buildAttestation(auth, challengeFor(begin));
  return registerFinish(env, email, att, bootstrapOpts());
}

// grantRoleViaToken has the bare-token break-glass Owner grant a role to an email (the DO mints a
// registration invite when that email has no credential yet) and returns the invite token from the 200
// body. It drives POST /admin/roles authenticated by the ADMIN_TOKEN bearer (method:"token" -> owner). The
// EMAIL binding is not configured in these tests, so no email is sent; the token is read straight off the
// role-write response, which is exactly what the invite email would carry.
export async function grantRoleViaToken(env: Env, email: string, role: string): Promise<string> {
  const resp = await handleAdmin(new Request("https://engine.example/admin/roles", {
    method: "POST",
    body: JSON.stringify({ email, role }),
    headers: { "content-type": "application/json", authorization: `Bearer ${ADMIN_TOKEN}`, origin: ORIGIN },
  }), env);
  const j = (await resp.json()) as { inviteToken?: string };
  // The grant to a not-yet-enrolled email always mints an invite token; every caller uses it as one. Assert
  // its presence so the return is string (a missing token is a genuine failure the test should surface).
  if (j.inviteToken === undefined) throw new Error(`grantRoleViaToken: no inviteToken minted for ${email}`);
  return j.inviteToken;
}

// whoamiRole reads the DO's resolved role for a PASSKEY caller's email directly (the same GET /whoami the
// router uses), so a test can assert the bootstrap/bind actually wrote a subject-keyed role entry. The
// role table now keys on the stable subject; a passkey caller's subject is passkeySubject(email)
// ("passkey|<email>"), so the test passes method:passkey + that subject to read back the bound entry
// exactly as the router would for this credential's session.
export async function whoamiRole(stub: DurableObjectStub, email: string): Promise<{ role: string; roleSource: string; isOnlyOwner: boolean }> {
  const params = new URLSearchParams({ method: "passkey", email, subject: passkeySubject(email) });
  const resp = await stub.fetch(`https://scheduler.internal/whoami?${params.toString()}`, { method: "GET" });
  return (await resp.json()) as { role: string; roleSource: string; isOnlyOwner: boolean };
}

// challengeFor extracts the challenge the begin response advertised (the client echoes it back). It
// takes the { status, json } result the post() helpers return and reads json.publicKey.challenge.
export function challengeFor(begin: { status: number; json: PasskeyJson }): string {
  if (begin.json === null || typeof begin.json === "string" || begin.json.publicKey?.challenge === undefined) {
    throw new Error("challengeFor: begin response carried no publicKey.challenge");
  }
  return begin.json.publicKey.challenge;
}

// challengeIdFor extracts the server-issued challengeId a login/begin returns, which the matching
// login/finish must echo back. challengeId is an optional field on the body shape, so this asserts its
// presence (a login/begin that omitted it is a genuine failure to surface, not a value to pass on as
// undefined); callers feed the result straight into loginFinish.
export function challengeIdFor(begin: { status: number; json: PasskeyBody }): string {
  if (begin.json.challengeId === undefined) {
    throw new Error("challengeIdFor: login/begin response carried no challengeId");
  }
  return begin.json.challengeId;
}

// RequiredOptions is the begin-options view optionsFor returns: the option groups a successful
// register/login begin always populates (rp, user, authenticatorSelection, allowCredentials,
// pubKeyCredParams) are present, so a test that has just asserted the begin succeeded can read them
// without re-checking each group. Leaf fields stay optional, matching the open shape.
export type RequiredOptions = PasskeyOptions & {
  rp: NonNullable<PasskeyOptions["rp"]>;
  user: NonNullable<PasskeyOptions["user"]>;
  authenticatorSelection: NonNullable<PasskeyOptions["authenticatorSelection"]>;
  allowCredentials: NonNullable<PasskeyOptions["allowCredentials"]>;
  pubKeyCredParams: unknown;
};

// optionsFor returns the publicKey creation/request options a begin advertised, asserting the options
// block is present (a begin that returned no publicKey is a genuine failure, not a value to read fields
// off of as undefined). It is the typed accessor for the option-shape assertions, symmetric with
// challengeFor/challengeIdFor; callers read .rp.id, .user.name, .allowCredentials and the like off it.
export function optionsFor(begin: { status: number; json: PasskeyBody }): RequiredOptions {
  const pk = begin.json.publicKey;
  if (pk === undefined) {
    throw new Error("optionsFor: begin response carried no publicKey options");
  }
  return pk as RequiredOptions;
}
