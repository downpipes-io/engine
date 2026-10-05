// Prove that a native (OIDC) session ends when the grant that admitted it is removed, driven through the real
// router (handleAdmin) and the real SchedulerDO on MockStorage with the IdP stubbed.
// Run: node test/validate-session-grant-recheck.ts
//
// THE FINDING (ASVS v5.0.0-7.4.1, 7.4.2, 8.2.1). A native sign-in is refused when no role row,
// invite or mapped group grants the principal, but the check ran at sign-in only. A session admitted by a group
// mapping stayed valid after an Owner deleted or changed that mapping: the per-request role read fell back to the
// floor role and the session kept reading the audit log, the member list and the configuration.
//
// Cases: the mapping is deleted; the mapping is moved to another group; the Owner removes a role row (control:
// already ends the session); the connection is deleted (control: already ends it); an unchanged mapping and an
// unrelated mapping change leave the session alive (controls).

import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { roleSubjectKey } from "../src/admin/identity.ts";
import { AUTH_SIGNALS_KEY } from "../src/admin/auth-signals.ts";
import type { Env } from "../src/env.d.ts";
import { MockStorage } from "./mock-storage.ts";
import { dohReply } from "./lib/doh-stub.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ORIGIN = "https://console.acme.example";
const ADMIN_TOKEN = "test-admin-token-subject-keyed";
const SESS = "__Host-downpipes_session";
const OIDC_TXN = "__Host-downpipes_oidc_txn";
const FOUNDER = { subject: "passkey|founder@acme.example", email: "founder@acme.example", role: "owner", grantedBy: "system", grantedAt: "2026-06-13T00:00:00.000Z" };

// ---------------- the stubbed IdPs (two issuers, one per connection) ----------------
interface OidcWho { sub: string; email: string; emailVerified: boolean | undefined; groups: string[] }
const idp = { who: null as OidcWho | null, issuer: "", client: "", nonce: "" };
const ISSUERS: Record<string, string> = { corp: "https://sso.acme.example", corp2: "https://sso2.acme.example" };

const kp = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
const jwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
function b64u(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const enc = (o: unknown) => b64u(new TextEncoder().encode(JSON.stringify(o)));
async function idToken(): Promise<string> {
  const w = idp.who!;
  const now = Math.floor(Date.now() / 1000);
  const h = enc({ alg: "RS256", kid: "k1", typ: "JWT" });
  // email_verified is left OUT of the token when the case says "absent".
  const claims: Record<string, unknown> = { iss: idp.issuer, sub: w.sub, aud: idp.client, nonce: idp.nonce, iat: now, exp: now + 300, email: w.email, groups: w.groups };
  if (w.emailVerified !== undefined) claims.email_verified = w.emailVerified;
  const p = enc(claims);
  const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${h}.${p}`)));
  return `${h}.${p}.${b64u(sig)}`;
}
const json = (o: unknown) => new Response(JSON.stringify(o), { status: 200, headers: { "content-type": "application/json" } });

const realFetch = globalThis.fetch;
process.on("exit", () => {
  globalThis.fetch = realFetch;
});
globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
  const d = dohReply(input);
  if (d) return d;
  const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
  for (const iss of Object.values(ISSUERS)) {
    if (url === `${iss}/jwks`) return json({ keys: [{ kid: "k1", kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", use: "sig" }] });
    if (url === `${iss}/token`) return json({ id_token: await idToken(), access_token: "at", token_type: "Bearer" });
  }
  throw new Error(`unexpected fetch in test: ${url}`);
}) as typeof fetch;

// ---------------- the engine under test ----------------
function makeEnv(): { env: Env; storage: MockStorage } {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = { fetch: (i: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(typeof i === "string" ? i : i instanceof URL ? i.toString() : i.url, init)) } as unknown as DurableObjectStub;
  const ns = { idFromName: () => ({}), get: () => stub } as unknown as DurableObjectNamespace;
  return { env: { SCHEDULER: ns, CONSOLE_ORIGIN: ORIGIN, ADMIN_TOKEN } as unknown as Env, storage };
}
function setCookies(r: Response): string[] {
  const h = r.headers as Headers & { getSetCookie?: () => string[] };
  return typeof h.getSetCookie === "function" ? h.getSetCookie() : r.headers.get("set-cookie") ? [r.headers.get("set-cookie")!] : [];
}
function cookie(r: Response, name: string): string | null {
  for (const c of setCookies(r)) {
    const m = c.match(new RegExp(`^${name}=([^;]*)`));
    if (m && m[1] !== "") return m[1]!;
  }
  return null;
}
async function admin(env: Env, method: string, path: string, body?: unknown): Promise<Response> {
  const headers: Record<string, string> = { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" };
  return handleAdmin(new Request(`${ORIGIN}${path}`, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) }), env);
}
async function get(env: Env, path: string, cookieHeader?: string): Promise<Response> {
  return handleAdmin(new Request(`${ORIGIN}${path}`, { method: "GET", headers: { "CF-Connecting-IP": "198.51.100.9", ...(cookieHeader ? { cookie: cookieHeader } : {}) } }), env);
}
async function alive(env: Env, token: string): Promise<boolean> {
  return (await get(env, "/admin/whoami", `${SESS}=${token}`)).status === 200;
}
async function signIn(env: Env, connId: string, who: OidcWho): Promise<string | null> {
  idp.who = who;
  idp.issuer = ISSUERS[connId]!;
  idp.client = `cid-${connId}`;
  const st = await get(env, `/admin/oidc/start/${connId}`);
  const u = new URL(st.headers.get("location") ?? "about:blank");
  idp.nonce = u.searchParams.get("nonce") ?? "";
  const state = u.searchParams.get("state") ?? "";
  const txn = cookie(st, OIDC_TXN) ?? "";
  const cb = await get(env, `/admin/oidc/callback/${connId}?code=c${Math.random()}&state=${encodeURIComponent(state)}`, `${OIDC_TXN}=${txn}`);
  return cookie(cb, SESS);
}
async function createConn(env: Env, connId: string): Promise<void> {
  const iss = ISSUERS[connId]!;
  const proposal = {
    id: connId, kind: "oidc", label: connId, presetId: "generic-oidc", enabled: true, issuer: iss, clientId: `cid-${connId}`, secretRef: { mode: "do-plaintext" },
    scopes: ["openid", "email", "profile"], idTokenSigAlgs: ["RS256"], pkce: "required", clientAuth: "client_secret_post", requireNonce: true, groupsClaim: "groups",
    authorizationEndpoint: `${iss}/authorize`, tokenEndpoint: `${iss}/token`, jwksUri: `${iss}/jwks`,
  };
  const r = await admin(env, "POST", "/admin/idp/connections", { proposal, secret: "s" });
  if (r.status !== 200) throw new Error(`connection ${connId} not created: ${r.status} ${await r.text()}`);
}

async function signalCount(storage: MockStorage, name: string): Promise<number> {
  const agg = (await storage.get<Record<string, { count: number }>>(AUTH_SIGNALS_KEY)) ?? {};
  return agg[name]?.count ?? 0;
}
async function world(): Promise<{ env: Env; storage: MockStorage }> {
  const w = makeEnv();
  await w.storage.put(roleSubjectKey(FOUNDER.subject), FOUNDER);
  await createConn(w.env, "corp");
  return w;
}
async function mapGroup(env: Env, group: string, role: string): Promise<void> {
  const r = await admin(env, "POST", "/admin/group-roles", { group, role, connId: "corp" });
  if (r.status !== 200) throw new Error(`mapping ${group} failed: ${r.status}`);
}
const member = (sub: string, email: string, groups: string[]): OidcWho => ({ sub, email, emailVerified: true, groups });

console.log("A native session ends when the grant that admitted it is removed\n");

{
  console.log("(a) the group mapping is deleted");
  const { env, storage } = await world();
  await mapGroup(env, "staff", "operator");
  const s = await signIn(env, "corp", member("m1", "m1@acme.example", ["staff"]));
  ok("(a) precondition: the group-mapped member gets a session", s !== null && (await alive(env, s)));
  const before = await signalCount(storage, "session-grant-lapsed");
  const d = await admin(env, "POST", "/admin/group-roles/delete", { group: "staff", connId: "corp" });
  ok("(a) the Owner deletes the mapping (200)", d.status === 200);
  ok("(a) the member's existing session is refused on its next request", s !== null && !(await alive(env, s)));
  ok("(a) the session-grant-lapsed signal is counted", (await signalCount(storage, "session-grant-lapsed")) === before + 1);
  ok("(a) a fresh sign-in is refused too (no grant)", (await signIn(env, "corp", member("m1", "m1@acme.example", ["staff"]))) === null);
}

{
  console.log("\n(b) the mapping is moved to another group");
  const { env } = await world();
  await mapGroup(env, "staff", "operator");
  const s = await signIn(env, "corp", member("m2", "m2@acme.example", ["staff"]));
  ok("(b) precondition: the group-mapped member gets a session", s !== null && (await alive(env, s)));
  await mapGroup(env, "admins", "operator");
  await admin(env, "POST", "/admin/group-roles/delete", { group: "staff", connId: "corp" });
  ok("(b) the member's session is refused once its group maps to nothing", s !== null && !(await alive(env, s)));
}

{
  console.log("\n(c) control: an unchanged mapping, and a change to an unrelated mapping");
  const { env } = await world();
  await mapGroup(env, "staff", "operator");
  await mapGroup(env, "contractors", "viewer");
  const s = await signIn(env, "corp", member("m3", "m3@acme.example", ["staff"]));
  ok("(c) precondition: the member gets a session", s !== null && (await alive(env, s)));
  await admin(env, "POST", "/admin/group-roles/delete", { group: "contractors", connId: "corp" });
  ok("(c) the member's session survives a change to another group's mapping", s !== null && (await alive(env, s)));
  const w = s !== null ? await get(env, "/admin/whoami", `${SESS}=${s}`) : null;
  ok("(c) whoami still reads the mapped role", w !== null && ((await w.json()) as { role?: string }).role === "operator");
}

{
  console.log("\n(d) control: a member admitted by a role row, then removed");
  const { env } = await world();
  await admin(env, "POST", "/admin/roles", { email: "m4@acme.example", role: "operator" });
  const s = await signIn(env, "corp", member("m4", "m4@acme.example", []));
  ok("(d) precondition: the invited member gets a session", s !== null && (await alive(env, s)));
  await mapGroup(env, "unrelated", "viewer");
  await admin(env, "POST", "/admin/group-roles/delete", { group: "unrelated", connId: "corp" });
  ok("(d) a role-row member is untouched by a mapping change", s !== null && (await alive(env, s)));
  const d = await admin(env, "POST", "/admin/roles/delete", { email: "m4@acme.example" });
  ok("(d) the Owner removes the member (200)", d.status === 200);
  ok("(d) the member's session is refused after the removal", s !== null && !(await alive(env, s)));
}

{
  console.log("\n(e) control: the connection is deleted");
  const { env } = await world();
  await mapGroup(env, "staff", "operator");
  const s = await signIn(env, "corp", member("m5", "m5@acme.example", ["staff"]));
  ok("(e) precondition: the member gets a session", s !== null && (await alive(env, s)));
  const d = await admin(env, "POST", "/admin/idp/connections/delete", { connId: "corp" });
  ok("(e) the Owner deletes the connection (200)", d.status === 200);
  ok("(e) the member's session is refused after the connection is gone", s !== null && !(await alive(env, s)));
}

console.log(failures === 0 ? "\nSESSION GRANT RE-CHECK VECTORS PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures);
if (failures > 0) process.exit(1);
