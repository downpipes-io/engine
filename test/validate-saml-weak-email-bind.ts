// Prove that a WEAKLY verified email binds only a non-privileged invite, driven through the real router
// (handleAdmin) and the real SchedulerDO on MockStorage with a stubbed, signing SAML IdP.
// Run: node test/validate-saml-weak-email-bind.ts
//
// THE RULE (ASVS v5.0.0-8.2.1, v5.0.0-6.8.1).
// A trust-idp SAML connection trusts the email the signed assertion carries, with no verified flag. The
// engine marks that email WEAK (emailVerifiedStrong false). Before this change a weak email refused only an
// Owner invite. Any other pending invite bound to the FIRST subject that asserted the address, so a tenant
// admin at the IdP could take a pending access-admin, approver or restore-operator invite.
// Now a weak email binds only a grant with no people, access, approval or Owner-reserved capability
// (roles.write, access.policy, restore.approve, keys.ceremony, posture.riskaccept).
//
// This proves:
//   - trust-idp: an owner, access-admin, approver or restore-operator invite is refused (no-access), the
//     invite stays pending, and the right signal is counted;
//   - trust-idp: a custom role with roles.write or restore.approve is refused; one with neither binds; a grant
//     whose custom role record is gone is refused (fail closed);
//   - trust-idp: a viewer or operator invite binds (pin);
//   - trust-idp: a legacy role:<email> row gets the same answer as the pending row;
//   - trust-idp: a mapped group still admits at its mapped role, and leaves a privileged invite pending (pin);
//   - require-flag with the flag true: every invite binds, Owner included (pin; unchanged);
//   - PASSKEY SELF-ADD PIN: a SAML session cannot start a passkey registration for its own
//     email or for the Owner's email, and cannot regenerate recovery codes without a step-up.

import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { roleSubjectKey, samlSubject } from "../src/admin/identity.ts";
import { AUTH_SIGNALS_KEY } from "../src/admin/auth-signals.ts";
import { ab } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";
import type { XmlElement } from "../src/admin/saml/xml-node.ts";
import { a, BEARER, buildSelfSignedCertPem, el, encodeResponse, NAMEID_PERSISTENT, SAML_ASSERTION_NS, SAML_PROTOCOL_NS, signAssertion, STATUS_SUCCESS, t } from "./saml-response-fixtures.ts";
import { PASSKEY_CRED_PREFIX, PASSKEY_USER_PREFIX } from "../src/sched/scheduler-do-keys.ts";
import { MockStorage } from "./mock-storage.ts";
import { dohReply } from "./lib/doh-stub.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ORIGIN = "https://console.acme.example";
const ADMIN_TOKEN = "test-admin-token-saml-weak-email";
const SESS = "__Host-downpipes_session";
const SAML_TXN = "__Host-downpipes_saml_txn";
const NO_ACCESS = `${ORIGIN}/?oidc=no-access`;
const FOUNDER = { subject: "passkey|founder@acme.example", email: "founder@acme.example", role: "owner", grantedBy: "system", grantedAt: "2026-06-13T00:00:00.000Z" };
const SIG_OWNER = "owner-bind-refused-weak-email-verification";
const SIG_PRIV = "privileged-bind-refused-weak-email-verification";

const realFetch = globalThis.fetch;
process.on("exit", () => {
  globalThis.fetch = realFetch;
});
globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
  const d = dohReply(input);
  if (d) return d;
  const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
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
async function postAs(env: Env, path: string, token: string, body: unknown): Promise<Response> {
  return handleAdmin(new Request(`${ORIGIN}${path}`, { method: "POST", headers: { "content-type": "application/json", origin: ORIGIN, "CF-Connecting-IP": "198.51.100.9", cookie: `${SESS}=${token}` }, body: JSON.stringify(body) }), env);
}
async function invite(env: Env, email: string, role: string, customRole?: string): Promise<void> {
  const r = await admin(env, "POST", "/admin/roles", { email, role, ...(customRole !== undefined ? { customRole } : {}) });
  ok(`the Owner invites ${email} as ${customRole ?? role}`, r.status === 200);
}
async function customRole(env: Env, name: string, capabilities: string[]): Promise<void> {
  const r = await admin(env, "POST", "/admin/custom-roles", { name, label: name, capabilities, landing: "downpipes" });
  ok(`the Owner creates custom role ${name} (${capabilities.join(", ")})`, r.status === 200);
}
async function mapGroup(env: Env, group: string, role: string, connId: string): Promise<void> {
  const r = await admin(env, "POST", "/admin/group-roles", { group, role, connId });
  ok(`the Owner maps group ${group} to ${role} on ${connId}`, r.status === 200);
}
async function whoami(env: Env, token: string): Promise<{ role?: string; roleSource?: string; method?: string }> {
  const r = await get(env, "/admin/whoami", `${SESS}=${token}`);
  return r.status === 200 ? ((await r.json()) as { role?: string; roleSource?: string; method?: string }) : {};
}

// ---------------- the stubbed SAML IdP ----------------
const TRUST = "trust-conn";
const FLAG = "flag-conn";
const SAML_IDP = "https://idp.acme.example/entity";
const SAML_SSO = "https://idp.acme.example/sso";
const SAML_SP = `${ORIGIN}/saml`;
let samlSeq = 0;
let samlKp: CryptoKeyPair | null = null;
async function inflateRaw(input: Uint8Array): Promise<string> {
  const ds = new DecompressionStream("deflate-raw");
  const w = ds.writable.getWriter();
  void w.write(ab(input));
  void w.close();
  return new Response(ds.readable).text();
}
interface SignIn { status: number; location: string; token: string | null }
interface Who { nameId: string; email: string; groups?: string[]; verifiedFlag?: string }
async function samlSignIn(env: Env, connId: string, who: Who): Promise<SignIn> {
  const acs = `${ORIGIN}/admin/saml/acs/${connId}`;
  const st = await get(env, `/admin/saml/start/${connId}`);
  const u = new URL(st.headers.get("location") ?? "about:blank");
  const relay = u.searchParams.get("RelayState") ?? "";
  const bin = atob(u.searchParams.get("SAMLRequest") ?? "");
  const xml = await inflateRaw(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
  const reqId = /\bID="([^"]+)"/.exec(xml)?.[1] ?? "";
  const txn = cookie(st, SAML_TXN) ?? "";
  const now = Date.now();
  const iso = (ms: number) => new Date(ms).toISOString();
  const aid = `_assertion_${++samlSeq}`;
  const scd = el("saml:SubjectConfirmationData", [a("Recipient", acs), a("NotOnOrAfter", iso(now + 600_000)), a("InResponseTo", reqId)], []);
  const subject = el("saml:Subject", [], [el("saml:NameID", [a("Format", NAMEID_PERSISTENT)], [t(who.nameId)]), el("saml:SubjectConfirmation", [a("Method", BEARER)], [scd])]);
  const conditions = el("saml:Conditions", [a("NotBefore", iso(now - 300_000)), a("NotOnOrAfter", iso(now + 600_000))], [el("saml:AudienceRestriction", [], [el("saml:Audience", [], [t(SAML_SP)])])]);
  const attrList = [
    el("saml:Attribute", [a("Name", "email")], [el("saml:AttributeValue", [], [t(who.email)])]),
    el("saml:Attribute", [a("Name", "groups")], (who.groups ?? []).map((g) => el("saml:AttributeValue", [], [t(g)]))),
  ];
  if (who.verifiedFlag !== undefined) attrList.push(el("saml:Attribute", [a("Name", "email_verified")], [el("saml:AttributeValue", [], [t(who.verifiedFlag)])]));
  const attrs = el("saml:AttributeStatement", [], attrList);
  const assertion: XmlElement = el("saml:Assertion", [a("xmlns:saml", SAML_ASSERTION_NS), a("ID", aid), a("Version", "2.0"), a("IssueInstant", iso(now - 30_000))], [el("saml:Issuer", [], [t(SAML_IDP)]), subject, conditions, attrs]);
  const signed = await signAssertion(assertion, aid, samlKp!.privateKey);
  const status = el("samlp:Status", [], [el("samlp:StatusCode", [a("Value", STATUS_SUCCESS)], [])]);
  const response = el("samlp:Response", [a("xmlns:samlp", SAML_PROTOCOL_NS), a("ID", `_response_${samlSeq}`), a("Version", "2.0"), a("IssueInstant", iso(now - 30_000)), a("Destination", acs), a("InResponseTo", reqId)], [status, signed]);
  const body = `SAMLResponse=${encodeURIComponent(encodeResponse(response))}&RelayState=${encodeURIComponent(relay)}`;
  const r = await handleAdmin(new Request(acs, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "CF-Connecting-IP": "198.51.100.9", cookie: `${SAML_TXN}=${txn}` }, body }), env);
  return { status: r.status, location: r.headers.get("location") ?? "", token: cookie(r, SESS) };
}
async function samlConnections(env: Env): Promise<void> {
  samlKp = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", samlKp.publicKey));
  const cert = await buildSelfSignedCertPem(spki, samlKp.privateKey, "idp.acme.example");
  const common = {
    kind: "saml", presetId: "generic-saml", enabled: true, idpEntityId: SAML_IDP, idpSsoUrl: SAML_SSO,
    idpSigningCerts: [cert], spEntityId: SAML_SP, nameIdFormat: NAMEID_PERSISTENT, wantAssertionsSigned: true, allowIdpInitiated: false,
    clockSkewSec: 120, emailAttr: "email", groupsAttr: "groups",
  };
  const a1 = await admin(env, "POST", "/admin/idp/connections", { proposal: { ...common, id: TRUST, label: "Trust IdP", emailVerifiedPolicy: "trust-idp" } });
  ok("the Owner creates a trust-idp SAML connection", a1.status === 200);
  const a2 = await admin(env, "POST", "/admin/idp/connections", { proposal: { ...common, id: FLAG, label: "Flag IdP", emailVerifiedPolicy: "require-flag", emailVerifiedAttr: "email_verified" } });
  ok("the Owner creates a require-flag SAML connection with emailVerifiedAttr", a2.status === 200);
}

// ---------------- the shared assertions ----------------
async function signalCount(storage: MockStorage, name: string): Promise<number> {
  const agg = (await storage.get<Record<string, { count: number }>>(AUTH_SIGNALS_KEY)) ?? {};
  return agg[name]?.count ?? 0;
}
async function world(): Promise<{ env: Env; storage: MockStorage }> {
  const w = makeEnv();
  await w.storage.put(roleSubjectKey(FOUNDER.subject), FOUNDER);
  await samlConnections(w.env);
  return w;
}
// expectWeakRefused: a trust-idp sign-in that holds only a privileged invite is refused, the invite row stays,
// no subject row is written, and exactly the named signal moves by one.
async function expectWeakRefused(label: string, env: Env, storage: MockStorage, key: string, who: Who, signal: string): Promise<void> {
  const before = { owner: await signalCount(storage, SIG_OWNER), priv: await signalCount(storage, SIG_PRIV) };
  const s = await samlSignIn(env, TRUST, who);
  ok(`${label}: refused, the callback lands on /?oidc=no-access`, s.status === 302 && s.location === NO_ACCESS);
  ok(`${label}: NO session cookie is minted`, s.token === null);
  ok(`${label}: the invite row ${key} is still there`, (await storage.get(key)) !== undefined);
  ok(`${label}: no subject row is written`, (await storage.get(roleSubjectKey(samlSubject(TRUST, SAML_IDP, who.nameId)))) === undefined);
  const after = { owner: await signalCount(storage, SIG_OWNER), priv: await signalCount(storage, SIG_PRIV) };
  const wantOwner = before.owner + (signal === SIG_OWNER ? 1 : 0);
  const wantPriv = before.priv + (signal === SIG_PRIV ? 1 : 0);
  ok(`${label}: the ${signal} signal is counted once (and only that one)`, after.owner === wantOwner && after.priv === wantPriv);
}
async function expectBound(label: string, env: Env, storage: MockStorage, connId: string, key: string, who: Who, wantRole: string): Promise<string | null> {
  const s = await samlSignIn(env, connId, who);
  ok(`${label}: a session cookie is minted`, s.status === 302 && s.token !== null && s.location !== NO_ACCESS);
  const row = await storage.get<{ role?: string }>(roleSubjectKey(samlSubject(connId, SAML_IDP, who.nameId)));
  ok(`${label}: the invite is bound to the subject as ${wantRole}`, row?.role === wantRole);
  ok(`${label}: the invite row ${key} is consumed`, (await storage.get(key)) === undefined);
  return s.token;
}

console.log("A weakly verified SAML email binds only a non-privileged invite\n");

// ---------------- 1. trust-idp: built-in roles on the pending row ----------------
{
  console.log("trust-idp: pending invites for the built-in roles");
  const { env, storage } = await world();
  const barred: Array<[string, string]> = [["owner", SIG_OWNER], ["access-admin", SIG_PRIV], ["approver", SIG_PRIV], ["restore-operator", SIG_PRIV]];
  for (const [role, signal] of barred) {
    const email = `${role}-invitee@acme.example`;
    await invite(env, email, role);
    await expectWeakRefused(`trust-idp ${role} invite`, env, storage, `role:pending:${email}`, { nameId: `weak-${role}`, email }, signal);
  }
  for (const role of ["viewer", "operator"]) {
    const email = `${role}-invitee@acme.example`;
    await invite(env, email, role);
    const before = { owner: await signalCount(storage, SIG_OWNER), priv: await signalCount(storage, SIG_PRIV) };
    const token = await expectBound(`trust-idp ${role} invite`, env, storage, TRUST, `role:pending:${email}`, { nameId: `weak-${role}`, email }, role);
    ok(`trust-idp ${role} invite: whoami reads ${role}`, token !== null && (await whoami(env, token)).role === role);
    ok(`trust-idp ${role} invite: no refusal signal is counted`, (await signalCount(storage, SIG_OWNER)) === before.owner && (await signalCount(storage, SIG_PRIV)) === before.priv);
  }
}

// ---------------- 2. trust-idp: custom roles ----------------
{
  console.log("\ntrust-idp: invites that carry a custom role");
  const { env, storage } = await world();
  await customRole(env, "people-editor", ["downpipe.read", "roles.read", "roles.write"]);
  await customRole(env, "restore-signer", ["downpipe.read", "restore.request", "restore.approve"]);
  await customRole(env, "notify-manager", ["downpipe.read", "notify.config"]);
  await customRole(env, "short-lived", ["downpipe.read"]);
  await invite(env, "people@acme.example", "viewer", "people-editor");
  await expectWeakRefused("trust-idp custom role with roles.write", env, storage, "role:pending:people@acme.example", { nameId: "weak-people", email: "people@acme.example" }, SIG_PRIV);
  await invite(env, "signer@acme.example", "viewer", "restore-signer");
  await expectWeakRefused("trust-idp custom role with restore.approve", env, storage, "role:pending:signer@acme.example", { nameId: "weak-signer", email: "signer@acme.example" }, SIG_PRIV);
  await invite(env, "notify@acme.example", "viewer", "notify-manager");
  await expectBound("trust-idp custom role with neither", env, storage, TRUST, "role:pending:notify@acme.example", { nameId: "weak-notify", email: "notify@acme.example" }, "viewer");
  // A grant whose custom role record is gone. The engine cannot tell what the name will mean when someone
  // re-creates it, so it fails closed: no bind.
  await invite(env, "ghost@acme.example", "viewer", "short-lived");
  await storage.delete("customrole:short-lived");
  ok("the custom role record short-lived is gone", (await storage.get("customrole:short-lived")) === undefined);
  await expectWeakRefused("trust-idp custom role whose record is missing", env, storage, "role:pending:ghost@acme.example", { nameId: "weak-ghost", email: "ghost@acme.example" }, SIG_PRIV);
}

// ---------------- 3. trust-idp: the legacy role:<email> row ----------------
{
  console.log("\ntrust-idp: legacy role:<email> rows");
  const { env, storage } = await world();
  const legacy = (email: string, role: string) => storage.put(`role:${email}`, { email, role, grantedBy: "founder@acme.example", grantedAt: "2026-06-13T00:00:00.000Z" });
  await legacy("legacy-owner@acme.example", "owner");
  await expectWeakRefused("trust-idp legacy owner row", env, storage, "role:legacy-owner@acme.example", { nameId: "legacy-owner", email: "legacy-owner@acme.example" }, SIG_OWNER);
  await legacy("legacy-approver@acme.example", "approver");
  await expectWeakRefused("trust-idp legacy approver row", env, storage, "role:legacy-approver@acme.example", { nameId: "legacy-approver", email: "legacy-approver@acme.example" }, SIG_PRIV);
  await legacy("legacy-admin@acme.example", "access-admin");
  await expectWeakRefused("trust-idp legacy access-admin row", env, storage, "role:legacy-admin@acme.example", { nameId: "legacy-admin", email: "legacy-admin@acme.example" }, SIG_PRIV);
  await legacy("legacy-operator@acme.example", "operator");
  await expectBound("trust-idp legacy operator row", env, storage, TRUST, "role:legacy-operator@acme.example", { nameId: "legacy-operator", email: "legacy-operator@acme.example" }, "operator");
}

// ---------------- 4. trust-idp: a mapped group still admits ----------------
{
  console.log("\ntrust-idp: group mappings");
  const { env, storage } = await world();
  await mapGroup(env, "backup-approvers", "approver", TRUST);
  const s = await samlSignIn(env, TRUST, { nameId: "grouped", email: "grouped@acme.example", groups: ["backup-approvers"] });
  const w = s.token !== null ? await whoami(env, s.token) : {};
  ok("trust-idp group-mapped approver: admitted as approver (group)", s.token !== null && w.role === "approver" && w.roleSource === "group");
  // A person with a pending access-admin invite AND a mapped Viewer group signs in on the group's role; the
  // weak email does not take the invite.
  await mapGroup(env, "staff", "viewer", TRUST);
  await invite(env, "staffer@acme.example", "access-admin");
  const s2 = await samlSignIn(env, TRUST, { nameId: "staffer", email: "staffer@acme.example", groups: ["staff"] });
  const w2 = s2.token !== null ? await whoami(env, s2.token) : {};
  ok("trust-idp group Viewer with a pending access-admin invite: admitted as viewer", s2.token !== null && w2.role === "viewer");
  ok("trust-idp group Viewer with a pending access-admin invite: the invite stays pending", (await storage.get("role:pending:staffer@acme.example")) !== undefined);
  ok("trust-idp group Viewer with a pending access-admin invite: no subject row is written", (await storage.get(roleSubjectKey(samlSubject(TRUST, SAML_IDP, "staffer")))) === undefined);
}

// ---------------- 5. require-flag with the flag true: every invite binds (unchanged) ----------------
{
  console.log("\nrequire-flag with the verified flag: every invite binds");
  const { env, storage } = await world();
  await customRole(env, "people-editor", ["downpipe.read", "roles.read", "roles.write"]);
  for (const role of ["owner", "access-admin", "approver", "restore-operator", "operator"]) {
    const email = `${role}-strong@acme.example`;
    await invite(env, email, role);
    await expectBound(`require-flag ${role} invite`, env, storage, FLAG, `role:pending:${email}`, { nameId: `strong-${role}`, email, verifiedFlag: "true" }, role);
  }
  await invite(env, "people-strong@acme.example", "viewer", "people-editor");
  await expectBound("require-flag custom role with roles.write", env, storage, FLAG, "role:pending:people-strong@acme.example", { nameId: "strong-people", email: "people-strong@acme.example", verifiedFlag: "true" }, "viewer");
  ok("require-flag: no weak-email refusal signal is counted", (await signalCount(storage, SIG_OWNER)) === 0 && (await signalCount(storage, SIG_PRIV)) === 0);
}

// ---------------- 6. PASSKEY SELF-ADD PIN ----------------
// A SAML session must never enrol a passkey through the self-add arm, and must not regenerate recovery codes
// without a step-up. Otherwise an IdP that asserts the Owner's email could mint a passkey|<owner> identity.
// That stays closed only while the self-add arm in scheduler-do-passkey.ts admits only the access and passkey
// methods.
{
  console.log("\nSAML session: passkey self-add and recovery regenerate (pin)");
  const { env, storage } = await world();
  await invite(env, "member@acme.example", "operator");
  const member = await samlSignIn(env, TRUST, { nameId: "member", email: "member@acme.example" });
  ok("a trust-idp SAML member signs in", member.token !== null);
  await mapGroup(env, "staff", "viewer", TRUST);
  const attacker = await samlSignIn(env, TRUST, { nameId: "attacker", email: FOUNDER.email, groups: ["staff"] });
  ok("a trust-idp SAML subject that asserts the Owner's email signs in on its group role only", attacker.token !== null && (await whoami(env, attacker.token)).role === "viewer");
  const credRows = async () => (await storage.list({ prefix: PASSKEY_CRED_PREFIX })).size + (await storage.list({ prefix: PASSKEY_USER_PREFIX })).size;
  const credsBefore = await credRows();
  for (const [label, token, email] of [["member, own email", member.token, "member@acme.example"], ["attacker, the Owner's email", attacker.token, FOUNDER.email]] as const) {
    if (token === null) continue;
    const r = await postAs(env, "/admin/auth/register/begin", token, { email });
    const b = (await r.json()) as { ok?: boolean; reason?: string };
    ok(`SAML session (${label}): passkey register/begin is refused (forbidden)`, b.ok === false && b.reason === "forbidden");
    const f = await postAs(env, "/admin/auth/register/finish", token, { email, credential: { id: "x", rawId: "x", type: "public-key", response: {} } });
    const fb = (await f.json().catch(() => ({}))) as { ok?: boolean };
    ok(`SAML session (${label}): passkey register/finish adds nothing`, fb.ok !== true);
    const g = await postAs(env, "/admin/auth/recovery-codes/regenerate", token, {});
    ok(`SAML session (${label}): recovery-codes/regenerate needs a step-up (401)`, g.status === 401);
  }
  ok("SAML sessions: no passkey credential row is written", (await credRows()) === credsBefore);
}

verdictReached(failures);
if (failures === 0) console.log("\nSAML WEAK-EMAIL BIND VECTORS PASS");
else {
  console.log(`\n${failures} FAILURE(S)`);
  process.exitCode = 1;
}
