// Prove that a native SSO sign-in with NO grant gets NO session, for every interactive connection kind, driven
// through the real router (handleAdmin) and the real SchedulerDO on MockStorage with every IdP stubbed.
// Run: node test/validate-sso-no-grant.ts
//
// THE FINDING (ASVS v5.0.0-8.2.1 and 6.8.1). The github and gitlab presets have no organisation, team
// or group restriction, so ANY account holder with a verified email completed the sign-in, and a subject with no
// role row resolved to Viewer: the audit log, the member list, the configuration and restore dry-runs. The
// session mint now refuses a principal that no role row, no invite and no mapped group grants.
//
// For each kind (generic OIDC, the gitlab preset, the github preset, generic OAuth2, SAML) this proves:
//   - a STRANGER is refused: 302 to ?oidc=no-access, no session cookie, no role row, no groups snapshot, an
//     authn-failure audit row for the connection, and the sso-no-grant-refused signal counted;
//   - an INVITED email (a pending grant written by the Owner) is admitted with the invited role;
//   - a GROUP-MAPPED account is admitted with the mapped role;
//   - an account with an EXISTING role row is admitted again (the invite bound to a row at first sign-in).
// Plus, on OIDC: an explicit Viewer row admits; an UNVERIFIED email does not claim an invite and is refused.
// Plus the medium half: on an EMPTY role table a stranger is refused, and a group-mapped native account is
// admitted with its mapped role but is NOT made the first Owner. The empty-table world runs for every preset:
// github, generic OIDC (email_verified true, false and absent), gitlab, generic OAuth2, SAML trust-idp, and
// SAML require-flag (flag true and flag false). A pending Owner invite binds only on a strongly verified email.

import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { oidcSubject, ROLE_SUBJECT_PREFIX, roleSubjectKey, samlSubject } from "../src/admin/identity.ts";
import { AUTH_SIGNALS_KEY } from "../src/admin/auth-signals.ts";
import { AUDIT_PREFIX } from "../src/admin/audit.ts";
import { ab } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";
import type { XmlElement } from "../src/admin/saml/xml-node.ts";
import { a, BEARER, buildSelfSignedCertPem, el, encodeResponse, NAMEID_PERSISTENT, SAML_ASSERTION_NS, SAML_PROTOCOL_NS, signAssertion, STATUS_SUCCESS, t } from "./saml-response-fixtures.ts";
import { MockStorage } from "./mock-storage.ts";
import { dohReply } from "./lib/doh-stub.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ORIGIN = "https://console.acme.example";
const ADMIN_TOKEN = "test-admin-token-sso-no-grant";
const SESS = "__Host-downpipes_session";
const OIDC_TXN = "__Host-downpipes_oidc_txn";
const SAML_TXN = "__Host-downpipes_saml_txn";
const NO_ACCESS = `${ORIGIN}/?oidc=no-access`;
const FOUNDER = { subject: "passkey|founder@acme.example", email: "founder@acme.example", role: "owner", grantedBy: "system", grantedAt: "2026-06-13T00:00:00.000Z" };

// ---------------- the stubbed IdPs ----------------
// One mutable identity per protocol. A sign-in sets it, then drives start + callback; the fetch stub answers
// from it. The OIDC stub signs a real RS256 id_token carrying the nonce read back out of the authorize URL.
// emailVerified "absent" leaves the email_verified claim out of the id_token altogether.
interface OidcWho { sub: string; email: string; emailVerified: boolean | "absent"; groups: string[]; groupsClaim: string }
interface GithubWho { id: number; email: string; teams: Array<{ slug: string; organization: { login: string } }>; orgs: Array<{ login: string }> }
interface GenericWho { id: string; email: string; groups: string[] }
const idp = { oidc: null as OidcWho | null, oidcIssuer: "", oidcClient: "", nonce: "", github: null as GithubWho | null, generic: null as GenericWho | null };

const GENERIC_ISSUER = "https://sso.acme.example";
const GITLAB = "https://gitlab.com";
const GEN_AUTH = "https://id.example.net/oauth/authorize";
const GEN_TOKEN = "https://id.example.net/oauth/token";
const GEN_API = "https://api.id.example.net";

const kp = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
const jwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
function b64u(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const enc = (o: unknown) => b64u(new TextEncoder().encode(JSON.stringify(o)));
async function idToken(): Promise<string> {
  const w = idp.oidc!;
  const now = Math.floor(Date.now() / 1000);
  const h = enc({ alg: "RS256", kid: "k1", typ: "JWT" });
  const verified = w.emailVerified === "absent" ? {} : { email_verified: w.emailVerified };
  const p = enc({ iss: idp.oidcIssuer, sub: w.sub, aud: idp.oidcClient, nonce: idp.nonce, iat: now, exp: now + 300, email: w.email, ...verified, [w.groupsClaim]: w.groups });
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
  // Generic OIDC (explicit endpoints) and the gitlab preset (discovery on gitlab.com).
  if (url === `${GENERIC_ISSUER}/jwks` || url === `${GITLAB}/oauth/discovery/keys`) return json({ keys: [{ kid: "k1", kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", use: "sig" }] });
  if (url === `${GENERIC_ISSUER}/token` || url === `${GITLAB}/oauth/token`) return json({ id_token: await idToken(), access_token: "at", token_type: "Bearer" });
  if (url === `${GITLAB}/.well-known/openid-configuration`) {
    return json({
      issuer: GITLAB, authorization_endpoint: `${GITLAB}/oauth/authorize`, token_endpoint: `${GITLAB}/oauth/token`, jwks_uri: `${GITLAB}/oauth/discovery/keys`,
      response_types_supported: ["code"], subject_types_supported: ["public"], id_token_signing_alg_values_supported: ["RS256"],
      code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
    });
  }
  // The github preset (OAuth2, no id_token).
  if (url === "https://github.com/login/oauth/access_token") return json({ access_token: "gho_x", token_type: "bearer", scope: "read:org,user:email" });
  if (url === "https://api.github.com/user") return json({ id: idp.github!.id, login: `user${idp.github!.id}` });
  if (url === "https://api.github.com/user/emails") return json([{ email: idp.github!.email, primary: true, verified: true }]);
  if (url === "https://api.github.com/user/teams") return json(idp.github!.teams);
  if (url === "https://api.github.com/user/orgs") return json(idp.github!.orgs);
  // Generic OAuth2 (the extensibility hatch): a profile that carries the email and its verified flag, and a
  // flat membership list read through groupsPath.
  if (url === GEN_TOKEN) return json({ access_token: "gen_x", token_type: "bearer" });
  if (url === `${GEN_API}/me`) return json({ id: idp.generic!.id, email: idp.generic!.email, verified: true });
  if (url === `${GEN_API}/me/groups`) return json(idp.generic!.groups.map((name) => ({ name })));
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
async function createConn(env: Env, body: unknown, label: string): Promise<void> {
  const r = await admin(env, "POST", "/admin/idp/connections", body);
  const b = (await r.json()) as { ok?: boolean; reason?: string };
  ok(`${label}: the Owner creates the connection`, r.status === 200 && b.ok === true);
  if (b.ok !== true) console.log(`       reason: ${b.reason}`);
}
async function invite(env: Env, email: string, role: string): Promise<void> {
  const r = await admin(env, "POST", "/admin/roles", { email, role });
  ok(`the Owner invites ${email} as ${role}`, r.status === 200);
}
async function mapGroup(env: Env, group: string, role: string, connId: string): Promise<void> {
  const r = await admin(env, "POST", "/admin/group-roles", { group, role, connId });
  ok(`the Owner maps group ${group} to ${role} on ${connId}`, r.status === 200);
}
async function whoami(env: Env, token: string): Promise<{ role?: string; roleSource?: string; method?: string }> {
  const r = await get(env, "/admin/whoami", `${SESS}=${token}`);
  return r.status === 200 ? ((await r.json()) as { role?: string; roleSource?: string; method?: string }) : {};
}

// ---------------- one sign-in per protocol ----------------
interface SignIn { status: number; location: string; token: string | null }
async function oauthSignIn(env: Env, connId: string): Promise<SignIn> {
  const st = await get(env, `/admin/oidc/start/${connId}`);
  const u = new URL(st.headers.get("location") ?? "about:blank");
  idp.nonce = u.searchParams.get("nonce") ?? "";
  const state = u.searchParams.get("state") ?? "";
  const txn = cookie(st, OIDC_TXN) ?? "";
  const cb = await get(env, `/admin/oidc/callback/${connId}?code=c${Math.random()}&state=${encodeURIComponent(state)}`, `${OIDC_TXN}=${txn}`);
  return { status: cb.status, location: cb.headers.get("location") ?? "", token: cookie(cb, SESS) };
}

// SAML: a fresh signing key per test world, the pinned cert on the connection, and a signed assertion per sign-in.
const SAML_CONN = "work-idp";
const SAML_IDP = "https://idp.acme.example/entity";
const SAML_SSO = "https://idp.acme.example/sso";
const SAML_SP = `${ORIGIN}/saml`;
const SAML_ACS = `${ORIGIN}/admin/saml/acs/${SAML_CONN}`;
let samlSeq = 0;
async function inflateRaw(input: Uint8Array): Promise<string> {
  const ds = new DecompressionStream("deflate-raw");
  const w = ds.writable.getWriter();
  void w.write(ab(input));
  void w.close();
  return new Response(ds.readable).text();
}
// extraAttrs adds more Attributes (name, value) to the AttributeStatement, for example the verified flag that
// a require-flag connection reads.
async function samlSignIn(env: Env, nameId: string, email: string, groups: string[], extraAttrs: Array<[string, string]> = []): Promise<SignIn> {
  const st = await get(env, `/admin/saml/start/${SAML_CONN}`);
  const u = new URL(st.headers.get("location") ?? "about:blank");
  const relay = u.searchParams.get("RelayState") ?? "";
  const bin = atob(u.searchParams.get("SAMLRequest") ?? "");
  const xml = await inflateRaw(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
  const reqId = /\bID="([^"]+)"/.exec(xml)?.[1] ?? "";
  const txn = cookie(st, SAML_TXN) ?? "";
  const now = Date.now();
  const iso = (ms: number) => new Date(ms).toISOString();
  const aid = `_assertion_${++samlSeq}`;
  const scd = el("saml:SubjectConfirmationData", [a("Recipient", SAML_ACS), a("NotOnOrAfter", iso(now + 600_000)), a("InResponseTo", reqId)], []);
  const subject = el("saml:Subject", [], [el("saml:NameID", [a("Format", NAMEID_PERSISTENT)], [t(nameId)]), el("saml:SubjectConfirmation", [a("Method", BEARER)], [scd])]);
  const conditions = el("saml:Conditions", [a("NotBefore", iso(now - 300_000)), a("NotOnOrAfter", iso(now + 600_000))], [el("saml:AudienceRestriction", [], [el("saml:Audience", [], [t(SAML_SP)])])]);
  const attrs = el("saml:AttributeStatement", [], [
    el("saml:Attribute", [a("Name", "email")], [el("saml:AttributeValue", [], [t(email)])]),
    el("saml:Attribute", [a("Name", "groups")], groups.map((g) => el("saml:AttributeValue", [], [t(g)]))),
    ...extraAttrs.map(([n, v]) => el("saml:Attribute", [a("Name", n)], [el("saml:AttributeValue", [], [t(v)])])),
  ]);
  const assertion: XmlElement = el("saml:Assertion", [a("xmlns:saml", SAML_ASSERTION_NS), a("ID", aid), a("Version", "2.0"), a("IssueInstant", iso(now - 30_000))], [el("saml:Issuer", [], [t(SAML_IDP)]), subject, conditions, attrs]);
  const signed = await signAssertion(assertion, aid, samlKp!.privateKey);
  const status = el("samlp:Status", [], [el("samlp:StatusCode", [a("Value", STATUS_SUCCESS)], [])]);
  const response = el("samlp:Response", [a("xmlns:samlp", SAML_PROTOCOL_NS), a("ID", `_response_${samlSeq}`), a("Version", "2.0"), a("IssueInstant", iso(now - 30_000)), a("Destination", SAML_ACS), a("InResponseTo", reqId)], [status, signed]);
  const body = `SAMLResponse=${encodeURIComponent(encodeResponse(response))}&RelayState=${encodeURIComponent(relay)}`;
  const r = await handleAdmin(new Request(SAML_ACS, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "CF-Connecting-IP": "198.51.100.9", cookie: `${SAML_TXN}=${txn}` }, body }), env);
  return { status: r.status, location: r.headers.get("location") ?? "", token: cookie(r, SESS) };
}
let samlKp: CryptoKeyPair | null = null;
const SAML_FLAG_ATTR = "email_verified";
async function samlConnection(env: Env, policy: "trust-idp" | "require-flag" = "trust-idp"): Promise<void> {
  samlKp = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", samlKp.publicKey));
  const cert = await buildSelfSignedCertPem(spki, samlKp.privateKey, "idp.acme.example");
  const proposal = {
    id: SAML_CONN, kind: "saml", label: "Work IdP", presetId: "generic-saml", enabled: true, idpEntityId: SAML_IDP, idpSsoUrl: SAML_SSO,
    idpSigningCerts: [cert], spEntityId: SAML_SP, nameIdFormat: NAMEID_PERSISTENT, wantAssertionsSigned: true, allowIdpInitiated: false,
    clockSkewSec: 120, emailVerifiedPolicy: policy, emailAttr: "email", groupsAttr: "groups",
    ...(policy === "require-flag" ? { emailVerifiedAttr: SAML_FLAG_ATTR } : {}),
  };
  await createConn(env, { proposal }, "saml");
}

// ---------------- the shared assertions ----------------
async function signalCount(storage: MockStorage, name: string): Promise<number> {
  const agg = (await storage.get<Record<string, { count: number }>>(AUTH_SIGNALS_KEY)) ?? {};
  return agg[name]?.count ?? 0;
}
async function failureRows(storage: MockStorage, connId: string): Promise<number> {
  const rows = await storage.list<{ action?: string; target?: { kind?: string; connId?: string; ceremony?: string } }>({ prefix: AUDIT_PREFIX });
  return [...rows.values()].filter((e) => e.action === "authn-failure" && e.target?.kind === "authn-attempt" && e.target.connId === connId).length;
}
async function roleRows(storage: MockStorage): Promise<number> {
  return (await storage.list({ prefix: "role:" })).size;
}
async function expectRefused(label: string, storage: MockStorage, connId: string, signIn: () => Promise<SignIn>): Promise<void> {
  const rowsBefore = await roleRows(storage);
  const sigBefore = await signalCount(storage, "sso-no-grant-refused");
  const groupsBefore = (await storage.list({ prefix: "oidcgroups:" })).size;
  const s = await signIn();
  // The Location is pinned to the exact literal the console reads: no reason, provider error, subject or email.
  ok(`${label}: the callback lands on exactly /?oidc=no-access`, s.status === 302 && s.location === NO_ACCESS);
  ok(`${label}: NO session cookie is minted`, s.token === null);
  ok(`${label}: no role row is written`, (await roleRows(storage)) === rowsBefore);
  ok(`${label}: no groups snapshot is written`, (await storage.list({ prefix: "oidcgroups:" })).size === groupsBefore);
  // The authn-failure row is throttled per connection (appendAuthnFailureAudit): the first refusal in a window
  // writes a row at once and later ones ride its attempts count, so the check is that the chain holds one.
  ok(`${label}: the refusal is on the audit chain (authn-failure for this connection)`, (await failureRows(storage, connId)) >= 1);
  ok(`${label}: the sso-no-grant-refused signal is counted`, (await signalCount(storage, "sso-no-grant-refused")) === sigBefore + 1);
}
async function expectAdmitted(label: string, env: Env, want: { role: string; roleSource: string }, signIn: () => Promise<SignIn>): Promise<void> {
  const s = await signIn();
  ok(`${label}: a session cookie is minted`, s.status === 302 && s.token !== null && s.location !== NO_ACCESS);
  const w = s.token !== null ? await whoami(env, s.token) : {};
  ok(`${label}: whoami reads role ${want.role} (${want.roleSource})`, w.role === want.role && w.roleSource === want.roleSource);
}
async function world(): Promise<{ env: Env; storage: MockStorage }> {
  const w = makeEnv();
  await w.storage.put(roleSubjectKey(FOUNDER.subject), FOUNDER);
  return w;
}

console.log("SSO sign-in with no grant gets no session\n");

// ---------------- 1. generic OIDC ----------------
{
  console.log("generic OIDC");
  const { env, storage } = await world();
  idp.oidcIssuer = GENERIC_ISSUER;
  idp.oidcClient = "cid";
  const proposal = {
    id: "corp", kind: "oidc", label: "Corp", presetId: "generic-oidc", enabled: true, issuer: GENERIC_ISSUER, clientId: "cid", secretRef: { mode: "do-plaintext" },
    scopes: ["openid", "email", "profile"], idTokenSigAlgs: ["RS256"], pkce: "required", clientAuth: "client_secret_post", requireNonce: true, groupsClaim: "groups",
    authorizationEndpoint: `${GENERIC_ISSUER}/authorize`, tokenEndpoint: `${GENERIC_ISSUER}/token`, jwksUri: `${GENERIC_ISSUER}/jwks`,
  };
  await createConn(env, { proposal, secret: "s" }, "oidc");
  const as = (who: OidcWho) => () => {
    idp.oidc = who;
    return oauthSignIn(env, "corp");
  };
  const base = { emailVerified: true, groups: [] as string[], groupsClaim: "groups" };
  await expectRefused("oidc stranger", storage, "corp", as({ ...base, sub: "stranger", email: "stranger@gmail.com" }));
  await invite(env, "invitee@acme.example", "operator");
  await expectAdmitted("oidc invited email", env, { role: "operator", roleSource: "email" }, as({ ...base, sub: "invitee", email: "invitee@acme.example" }));
  await expectAdmitted("oidc existing row (the bound invite)", env, { role: "operator", roleSource: "email" }, as({ ...base, sub: "invitee", email: "invitee@acme.example" }));
  await mapGroup(env, "backup-approvers", "approver", "corp");
  await expectAdmitted("oidc group-mapped", env, { role: "approver", roleSource: "group" }, as({ ...base, sub: "grouped", email: "grouped@acme.example", groups: ["backup-approvers"] }));
  await expectRefused("oidc stranger in an UNMAPPED group", storage, "corp", as({ ...base, sub: "other", email: "other@acme.example", groups: ["marketing"] }));
  const viewerSubject = oidcSubject("corp", GENERIC_ISSUER, "viewer-row");
  await storage.put(roleSubjectKey(viewerSubject), { subject: viewerSubject, email: "reader@acme.example", role: "viewer", grantedBy: "founder@acme.example", grantedAt: "2026-06-13T00:00:00.000Z" });
  await expectAdmitted("oidc explicit Viewer row", env, { role: "viewer", roleSource: "default" }, as({ ...base, sub: "viewer-row", email: "reader@acme.example" }));
  await invite(env, "unverified@acme.example", "operator");
  await expectRefused("oidc UNVERIFIED email with a pending invite", storage, "corp", as({ ...base, sub: "unverified", email: "unverified@acme.example", emailVerified: false }));
  ok("oidc unverified: the invite stays pending (not bound off an unverified email)", (await storage.get("role:pending:unverified@acme.example")) !== undefined);
  // The console reads exactly two values of the oidc parameter. Every OTHER failure keeps the generic landing:
  // a callback whose state was never minted lands on /?oidc=failed, never on no-access.
  {
    const st = await get(env, "/admin/oidc/start/corp");
    const cb = await get(env, "/admin/oidc/callback/corp?code=c&state=never-minted", `${OIDC_TXN}=${cookie(st, OIDC_TXN) ?? ""}`);
    ok("oidc forged state: the callback lands on exactly /?oidc=failed, with no session", cb.status === 302 && cb.headers.get("location") === `${ORIGIN}/?oidc=failed` && cookie(cb, SESS) === null);
  }
}

// ---------------- 2. the gitlab preset (OIDC, host gitlab.com) ----------------
{
  console.log("\ngitlab preset (gitlab.com)");
  const { env, storage } = await world();
  idp.oidcIssuer = GITLAB;
  idp.oidcClient = "gl-client";
  await createConn(env, { presetId: "gitlab", vars: { host: "gitlab.com" }, clientId: "gl-client", secret: "gl-secret", enabled: true }, "gitlab");
  const as = (who: OidcWho) => () => {
    idp.oidc = who;
    return oauthSignIn(env, "gitlab");
  };
  const base = { emailVerified: true, groups: [] as string[], groupsClaim: "groups_direct" };
  await expectRefused("gitlab stranger", storage, "gitlab", as({ ...base, sub: "9001", email: "stranger@gmail.com" }));
  await invite(env, "dev@acme.example", "operator");
  await expectAdmitted("gitlab invited email", env, { role: "operator", roleSource: "email" }, as({ ...base, sub: "9002", email: "dev@acme.example" }));
  await expectAdmitted("gitlab existing row", env, { role: "operator", roleSource: "email" }, as({ ...base, sub: "9002", email: "dev@acme.example" }));
  await mapGroup(env, "acme/platform", "approver", "gitlab");
  await expectAdmitted("gitlab group-mapped", env, { role: "approver", roleSource: "group" }, as({ ...base, sub: "9003", email: "lead@acme.example", groups: ["acme/platform"] }));
}

// ---------------- 3. the github preset (OAuth2) ----------------
{
  console.log("\ngithub preset (OAuth2)");
  const { env, storage } = await world();
  await createConn(env, { presetId: "github", vars: {}, clientId: "gh-client", secret: "gh-secret", enabled: true }, "github");
  const as = (who: GithubWho) => () => {
    idp.github = who;
    return oauthSignIn(env, "github");
  };
  await expectRefused("github stranger", storage, "github", as({ id: 99999001, email: "stranger@gmail.com", teams: [], orgs: [] }));
  await expectRefused("github member of another org", storage, "github", as({ id: 99999002, email: "someone@other.example", teams: [], orgs: [{ login: "other-org" }] }));
  await invite(env, "octo@acme.example", "operator");
  await expectAdmitted("github invited email", env, { role: "operator", roleSource: "email" }, as({ id: 101, email: "octo@acme.example", teams: [], orgs: [] }));
  await expectAdmitted("github existing row", env, { role: "operator", roleSource: "email" }, as({ id: 101, email: "octo@acme.example", teams: [], orgs: [] }));
  await mapGroup(env, "acme", "viewer", "github");
  await expectAdmitted("github org-mapped (the org as a Viewer group)", env, { role: "viewer", roleSource: "default" }, as({ id: 102, email: "member@acme.example", teams: [], orgs: [{ login: "acme" }] }));
  await mapGroup(env, "acme/sre", "approver", "github");
  await expectAdmitted("github team-mapped", env, { role: "approver", roleSource: "group" }, as({ id: 103, email: "sre@acme.example", teams: [{ slug: "sre", organization: { login: "acme" } }], orgs: [{ login: "acme" }] }));
}

// ---------------- 4. generic OAuth2 ----------------
{
  console.log("\ngeneric OAuth2");
  const { env, storage } = await world();
  const vars = { authorizeUrl: GEN_AUTH, tokenUrl: GEN_TOKEN, apiBase: GEN_API, profileUrl: `${GEN_API}/me`, subjectPath: "id", emailUrl: `${GEN_API}/me`, emailPath: "email", emailVerifiedPath: "verified", groupsUrl: `${GEN_API}/me/groups`, groupsPath: "name" };
  await createConn(env, { presetId: "generic-oauth2", id: "hatch", vars, clientId: "gen-client", secret: "gen-secret", enabled: true }, "generic-oauth2");
  const as = (who: GenericWho) => () => {
    idp.generic = who;
    return oauthSignIn(env, "hatch");
  };
  await expectRefused("generic-oauth2 stranger", storage, "hatch", as({ id: "u-1", email: "stranger@gmail.com", groups: [] }));
  await invite(env, "ops@acme.example", "operator");
  await expectAdmitted("generic-oauth2 invited email", env, { role: "operator", roleSource: "email" }, as({ id: "u-2", email: "ops@acme.example", groups: [] }));
  await expectAdmitted("generic-oauth2 existing row", env, { role: "operator", roleSource: "email" }, as({ id: "u-2", email: "ops@acme.example", groups: [] }));
  await mapGroup(env, "backup-admins", "approver", "hatch");
  await expectAdmitted("generic-oauth2 group-mapped", env, { role: "approver", roleSource: "group" }, as({ id: "u-3", email: "grp@acme.example", groups: ["backup-admins"] }));
}

// ---------------- 5. SAML ----------------
{
  console.log("\nSAML");
  const { env, storage } = await world();
  await samlConnection(env);
  await expectRefused("saml stranger", storage, SAML_CONN, () => samlSignIn(env, "stranger@acme.example", "stranger@acme.example", []));
  await invite(env, "samluser@acme.example", "operator");
  await expectAdmitted("saml invited email", env, { role: "operator", roleSource: "email" }, () => samlSignIn(env, "samluser@acme.example", "samluser@acme.example", []));
  await expectAdmitted("saml existing row", env, { role: "operator", roleSource: "email" }, () => samlSignIn(env, "samluser@acme.example", "samluser@acme.example", []));
  await mapGroup(env, "administrators", "approver", SAML_CONN);
  await expectAdmitted("saml group-mapped", env, { role: "approver", roleSource: "group" }, () => samlSignIn(env, "grouped@acme.example", "grouped@acme.example", ["administrators"]));
  const rowSubject = samlSubject(SAML_CONN, SAML_IDP, "grouped@acme.example");
  ok("saml group-mapped: no role row is written for a group-only member", (await storage.get(roleSubjectKey(rowSubject))) === undefined);
}

// ---------------- 6. the empty role table (the medium half) ----------------
{
  console.log("\nempty role table (no Owner yet, the break-glass token configured SSO)");
  const { env, storage } = makeEnv();
  await createConn(env, { presetId: "github", vars: {}, clientId: "gh-client", secret: "gh-secret", enabled: true }, "github (empty table)");
  const as = (who: GithubWho) => () => {
    idp.github = who;
    return oauthSignIn(env, "github");
  };
  await expectRefused("empty table: github stranger", storage, "github", as({ id: 99999001, email: "stranger@gmail.com", teams: [], orgs: [] }));
  ok("empty table: the stranger did not become the first Owner (the table is still empty)", (await roleRows(storage)) === 0);
  await mapGroup(env, "acme", "approver", "github");
  await expectAdmitted("empty table: github org-mapped member", env, { role: "approver", roleSource: "group" }, as({ id: 102, email: "member@acme.example", teams: [], orgs: [{ login: "acme" }] }));
  ok("empty table: the group-mapped member did NOT claim the first Owner (no role row written)", (await roleRows(storage)) === 0);
  ok("empty table: the bootstrap-refused-native-idp signal is counted", (await signalCount(storage, "bootstrap-refused-native-idp")) > 0);
  // The supported route to a first Owner over native SSO: the break-glass writes an Owner invite for the
  // operator's own address, and a strongly verified sign-in binds it.
  await invite(env, "founder@acme.example", "owner");
  await expectAdmitted("empty table: the invited Owner signs in and binds the invite", env, { role: "owner", roleSource: "email" }, as({ id: 1, email: "founder@acme.example", teams: [], orgs: [] }));
}

// ---------------- 7. the empty role table, for every other preset ----------------
// Section 6 covers the github preset. This runs the same world for each other kind and email-trust variant:
// a stranger is refused by the no-grant check, a group-mapped member is admitted with its mapped role but is
// NOT made the first Owner, and a pending Owner invite binds only on a strongly verified email. Each refusal
// counts the signal of the step that refused it, so a refusal for another reason cannot pass these checks.
async function bootstrapConsumed(storage: MockStorage): Promise<boolean> {
  return (await storage.get<{ bootstrapConsumed?: boolean }>("orgpolicy"))?.bootstrapConsumed === true;
}
interface EmptyTableCase {
  label: string;
  connId: string;
  create: (env: Env) => Promise<void>;
  stranger: (env: Env) => () => Promise<SignIn>;
  group: string;
  grouped: (env: Env) => () => Promise<SignIn>;
  ownerEmail: string;
  owner: (env: Env) => () => Promise<SignIn>;
  // "binds": the invite binds and the sign-in is admitted as owner. "no-grant": the invite does not bind and
  // the no-grant check refuses, with blockSignal counted. "emailless": the email is dropped before the mint
  // and the emailless check refuses, with blockSignal counted.
  ownerOutcome: "binds" | "no-grant" | "emailless";
  blockSignal?: string;
}
async function emptyTable(c: EmptyTableCase): Promise<void> {
  console.log(`\nempty role table: ${c.label}`);
  const { env, storage } = makeEnv();
  await c.create(env);
  ok(`${c.label}: the role table starts empty`, (await roleRows(storage)) === 0);
  await expectRefused(`${c.label}: stranger`, storage, c.connId, c.stranger(env));
  ok(`${c.label}: the stranger did not become the first Owner (the table is still empty)`, (await roleRows(storage)) === 0 && !(await bootstrapConsumed(storage)));
  const nativeBefore = await signalCount(storage, "bootstrap-refused-native-idp");
  await mapGroup(env, c.group, "approver", c.connId);
  await expectAdmitted(`${c.label}: group-mapped member`, env, { role: "approver", roleSource: "group" }, c.grouped(env));
  ok(`${c.label}: the group-mapped member did NOT claim the first Owner (no role row, latch unset)`, (await roleRows(storage)) === 0 && !(await bootstrapConsumed(storage)));
  ok(`${c.label}: the bootstrap-refused-native-idp signal is counted`, (await signalCount(storage, "bootstrap-refused-native-idp")) > nativeBefore);
  await invite(env, c.ownerEmail, "owner");
  const pendingKey = `role:pending:${c.ownerEmail}`;
  if (c.ownerOutcome === "binds") {
    await expectAdmitted(`${c.label}: the invited Owner signs in and binds the invite`, env, { role: "owner", roleSource: "email" }, c.owner(env));
    ok(`${c.label}: the Owner invite is no longer pending`, (await storage.get(pendingKey)) === undefined);
    return;
  }
  const blockBefore = await signalCount(storage, c.blockSignal!);
  if (c.ownerOutcome === "no-grant") {
    await expectRefused(`${c.label}: the Owner invite that must not bind`, storage, c.connId, c.owner(env));
  } else {
    const s = await c.owner(env)();
    ok(`${c.label}: the Owner invite with the email dropped lands on exactly /?oidc=failed, with no session`, s.status === 302 && s.location === `${ORIGIN}/?oidc=failed` && s.token === null);
  }
  ok(`${c.label}: the ${c.blockSignal} signal is counted (the step that refused it)`, (await signalCount(storage, c.blockSignal!)) === blockBefore + 1);
  ok(`${c.label}: the Owner invite stays pending`, (await storage.get(pendingKey)) !== undefined);
  // The pending invite is the only role: key; no subject-bound row exists.
  ok(`${c.label}: nobody became the first Owner (no subject-bound role row, latch unset)`, (await storage.list({ prefix: ROLE_SUBJECT_PREFIX })).size === 0 && !(await bootstrapConsumed(storage)));
}

const OIDC_PROPOSAL = {
  id: "corp", kind: "oidc", label: "Corp", presetId: "generic-oidc", enabled: true, issuer: GENERIC_ISSUER, clientId: "cid", secretRef: { mode: "do-plaintext" },
  scopes: ["openid", "email", "profile"], idTokenSigAlgs: ["RS256"], pkce: "required", clientAuth: "client_secret_post", requireNonce: true, groupsClaim: "groups",
  authorizationEndpoint: `${GENERIC_ISSUER}/authorize`, tokenEndpoint: `${GENERIC_ISSUER}/token`, jwksUri: `${GENERIC_ISSUER}/jwks`,
};
const oidcAs = (connId: string, who: OidcWho) => (env: Env) => () => {
  idp.oidc = who;
  return oauthSignIn(env, connId);
};
for (const ev of [true, false, "absent"] as const) {
  const base = { emailVerified: ev, groups: [] as string[], groupsClaim: "groups" };
  await emptyTable({
    label: `generic OIDC, email_verified ${String(ev)}`,
    connId: "corp",
    create: async (env) => {
      idp.oidcIssuer = GENERIC_ISSUER;
      idp.oidcClient = "cid";
      await createConn(env, { proposal: OIDC_PROPOSAL, secret: "s" }, `oidc (empty table, email_verified ${String(ev)})`);
    },
    stranger: oidcAs("corp", { ...base, sub: "stranger", email: "stranger@gmail.com" }),
    group: "backup-approvers",
    grouped: oidcAs("corp", { ...base, sub: "grouped", email: "grouped@acme.example", groups: ["backup-approvers"] }),
    ownerEmail: "founder@acme.example",
    owner: oidcAs("corp", { ...base, sub: "founder", email: "founder@acme.example" }),
    // Only the JSON boolean true verifies the email (oidc-verify.ts). false and an absent claim bind no invite.
    ...(ev === true ? { ownerOutcome: "binds" as const } : { ownerOutcome: "no-grant" as const, blockSignal: "email-verified-bind-blocked" }),
  });
}

{
  const base = { emailVerified: true, groups: [] as string[], groupsClaim: "groups_direct" };
  await emptyTable({
    label: "gitlab preset",
    connId: "gitlab",
    create: async (env) => {
      idp.oidcIssuer = GITLAB;
      idp.oidcClient = "gl-client";
      await createConn(env, { presetId: "gitlab", vars: { host: "gitlab.com" }, clientId: "gl-client", secret: "gl-secret", enabled: true }, "gitlab (empty table)");
    },
    stranger: oidcAs("gitlab", { ...base, sub: "9001", email: "stranger@gmail.com" }),
    group: "acme/platform",
    grouped: oidcAs("gitlab", { ...base, sub: "9003", email: "lead@acme.example", groups: ["acme/platform"] }),
    ownerEmail: "founder@acme.example",
    owner: oidcAs("gitlab", { ...base, sub: "9000", email: "founder@acme.example" }),
    ownerOutcome: "binds",
  });
}

{
  const genAs = (who: GenericWho) => (env: Env) => () => {
    idp.generic = who;
    return oauthSignIn(env, "hatch");
  };
  const vars = { authorizeUrl: GEN_AUTH, tokenUrl: GEN_TOKEN, apiBase: GEN_API, profileUrl: `${GEN_API}/me`, subjectPath: "id", emailUrl: `${GEN_API}/me`, emailPath: "email", emailVerifiedPath: "verified", groupsUrl: `${GEN_API}/me/groups`, groupsPath: "name" };
  await emptyTable({
    label: "generic OAuth2",
    connId: "hatch",
    create: (env) => createConn(env, { presetId: "generic-oauth2", id: "hatch", vars, clientId: "gen-client", secret: "gen-secret", enabled: true }, "generic-oauth2 (empty table)"),
    stranger: genAs({ id: "u-1", email: "stranger@gmail.com", groups: [] }),
    group: "backup-admins",
    grouped: genAs({ id: "u-3", email: "grp@acme.example", groups: ["backup-admins"] }),
    ownerEmail: "founder@acme.example",
    owner: genAs({ id: "u-0", email: "founder@acme.example", groups: [] }),
    ownerOutcome: "binds",
  });
}

await emptyTable({
  label: "SAML trust-idp",
  connId: SAML_CONN,
  create: (env) => samlConnection(env, "trust-idp"),
  stranger: (env) => () => samlSignIn(env, "stranger@acme.example", "stranger@acme.example", []),
  group: "administrators",
  grouped: (env) => () => samlSignIn(env, "grouped@acme.example", "grouped@acme.example", ["administrators"]),
  ownerEmail: "founder@acme.example",
  owner: (env) => () => samlSignIn(env, "founder@acme.example", "founder@acme.example", []),
  // trust-idp verifies the email by policy only, so an Owner invite never binds on it (resolveBoundEntry).
  ownerOutcome: "no-grant",
  blockSignal: "owner-bind-refused-weak-email-verification",
});

await emptyTable({
  label: "SAML require-flag, flag true",
  connId: SAML_CONN,
  create: (env) => samlConnection(env, "require-flag"),
  stranger: (env) => () => samlSignIn(env, "stranger@acme.example", "stranger@acme.example", [], [[SAML_FLAG_ATTR, "true"]]),
  group: "administrators",
  grouped: (env) => () => samlSignIn(env, "grouped@acme.example", "grouped@acme.example", ["administrators"], [[SAML_FLAG_ATTR, "true"]]),
  ownerEmail: "founder@acme.example",
  owner: (env) => () => samlSignIn(env, "founder@acme.example", "founder@acme.example", [], [[SAML_FLAG_ATTR, "true"]]),
  ownerOutcome: "binds",
});

await emptyTable({
  label: "SAML require-flag, flag false",
  connId: SAML_CONN,
  create: (env) => samlConnection(env, "require-flag"),
  stranger: (env) => () => samlSignIn(env, "stranger@acme.example", "stranger@acme.example", [], [[SAML_FLAG_ATTR, "true"]]),
  group: "administrators",
  grouped: (env) => () => samlSignIn(env, "grouped@acme.example", "grouped@acme.example", ["administrators"], [[SAML_FLAG_ATTR, "true"]]),
  ownerEmail: "founder@acme.example",
  // The IdP asserts the flag false, so the email is dropped and the mint refuses an emailless principal.
  owner: (env) => () => samlSignIn(env, "founder@acme.example", "founder@acme.example", [], [[SAML_FLAG_ATTR, "false"]]),
  ownerOutcome: "emailless",
  blockSignal: "emailless-assertion",
});

verdictReached(failures);
if (failures === 0) console.log("\nSSO NO-GRANT VECTORS PASS");
else {
  console.log(`\n${failures} FAILURE(S)`);
  process.exitCode = 1;
}
