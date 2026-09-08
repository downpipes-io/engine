// Prove the OPTIONAL identity-provider group->role mapping, end to end and SERVER-SIDE, with
// in-memory doubles only. No network, no deploy, no cost. Run:
//   node test/validate-group-roles.ts
//
// What this proves (the auth-boundary claims the task pins):
//  - a group mapped to operator lifts a caller IN THAT GROUP to operator (resolved server-side
//    from the verified Access groups, not asserted by the client);
//  - the approver CAP: POST /admin/group-roles with role "owner" is rejected (a clear 400), and a
//    group can NEVER resolve a caller to owner even if a mapping were somehow stored with owner;
//  - an explicit per-email role and a group role COMBINE via max (the stronger of the two wins),
//    and roleSource reports the honest basis (email vs group);
//  - the last-Owner guard is UNAFFECTED by groups (it counts only explicit `role:` owner entries;
//    a group conferring approver to the sole Owner's account does not let them self-demote);
//  - NO groups claim -> UNCHANGED per-email behaviour (group-mapping is purely additive);
//  - the token-fallback path is UNCHANGED (owner, no groups, roleSource owner-token);
//  - the writes are Owner-only and the DO re-resolves Owner from the forwarded email + groups
//    (defence in depth: a non-Owner caller header is refused even bypassing the router);
//  - each change is audited as a redaction-safe group-role-change carrying only the group + role;
//  - an ABUSIVE (but validly-signed) groups claim is BOUNDED (length-capped, per-entry length-capped,
//    deduped, control-char entries dropped) at BOTH the verify-time boundGroups layer AND the DO's
//    OWN layer (parseGroupsParam from the query param, decodeCaller from the caller header), driving
//    the DO path directly so the DO-side bound is what does the capping, not access.ts.
//
// The Access path is driven with a forged-but-correctly-signed RS256 JWT verified against a
// controlled JWKS served by a stubbed global fetch, so authorise() runs its REAL verification and
// resolves a REAL verified identity (with REAL verified groups) at the chosen role, exercising the
// production router + DO code path rather than a shim (the same technique as validate-rbac.ts).

import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { encodeCaller, decodeCaller, type Caller } from "../src/admin/identity.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import type { AuditEvent } from "../src/admin/audit.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

function makeScheduler(): { env: Pick<Env, "SCHEDULER">; storage: MockStorage; stub: DurableObjectStub } {
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
  return { env: { SCHEDULER: namespace }, storage, stub };
}

// ---- Forged Access JWT (real RS256 verification, controlled JWKS) ------------------------
const TEAM = "maelstrom";
const ISS = `https://${TEAM}.cloudflareaccess.com`;
const AUD = "group-roles-test-aud";
const KID = "group-roles-kid-1";

function jwtPart(obj: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}

async function main(): Promise<void> {
  const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const pubJwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
  const jwks = { keys: [{ kid: KID, kty: "RSA", n: pubJwk.n, e: pubJwk.e }] };

  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url === `${ISS}/cdn-cgi/access/certs`) {
      return new Response(JSON.stringify(jwks), { headers: { "content-type": "application/json" } });
    }
    throw new Error(`unexpected network fetch in test: ${url}`);
  }) as typeof fetch;

  const futureExp = Math.floor(Date.now() / 1000) + 3600;
  // tokenFor mints a signed Access JWT for an email, OPTIONALLY carrying a groups claim and/or an idp
  // hint. A token with no groups argument omits the claim entirely (the honest "no groups" case that
  // must leave the per-email behaviour unchanged).
  async function tokenFor(email: string, opts?: { groups?: unknown; idp?: string }): Promise<string> {
    const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
    // Authorisation keys on the stable subject (iss+"|"+sub), so every token carries a sub (a stable
    // per-email value so each distinct email is a distinct subject; group mappings apply on top).
    const claims: Record<string, unknown> = { iss: ISS, aud: AUD, exp: futureExp, iat: futureExp - 3600, email, sub: `sub-of-${email}` };
    if (opts && "groups" in opts) claims["groups"] = opts.groups;
    if (opts?.idp !== undefined) claims["idp"] = opts.idp;
    const body = jwtPart(claims);
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
    return `${header}.${body}.${b64urlEncode(sig)}`;
  }

  const sched = makeScheduler();
  const accessEnv = (): Env =>
    ({
      ...sched.env,
      CF_ACCESS_TEAM_DOMAIN: TEAM,
      CF_ACCESS_AUD: AUD,
    }) as unknown as Env;

  // call drives handleAdmin as a given Access identity, OPTIONALLY presenting verified groups + an
  // idp hint in the signed token.
  async function call(
    email: string,
    method: "GET" | "POST",
    path: string,
    body?: unknown,
    jwtOpts?: { groups?: unknown; idp?: string },
  ): Promise<Response> {
    const assertion = await tokenFor(email, jwtOpts);
    const init: RequestInit = {
      method,
      headers: { "cf-access-jwt-assertion": assertion, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    };
    return handleAdmin(new Request(`https://engine.example${path}`, init), accessEnv());
  }

  type Who = { method: string; email: string | null; role: string; roleSource: string; groups: string[]; identityProvider?: string; isOnlyOwner: boolean };
  async function whoami(email: string, jwtOpts?: { groups?: unknown; idp?: string }): Promise<Who> {
    return (await (await call(email, "GET", "/admin/whoami", undefined, jwtOpts)).json()) as Who;
  }

  const OWNER = "owner@acme.example";
  const ALICE = "alice@acme.example"; // an Access caller with no explicit email grant
  const BOB = "bob@acme.example"; // an Access caller with an explicit email grant, to test combine
  const G_ENG = "engineering"; // an IdP group we will map to operator
  const G_SRE = "sre-oncall"; // an IdP group we will map to approver
  const G_NONE = "marketing"; // an unmapped IdP group

  // Bootstrap OWNER as the first Access caller (-> Owner). No groups on this token.
  {
    const who = await whoami(OWNER);
    ok("bootstrap: first Access caller is Owner", who.role === "owner");
    ok("bootstrap: roleSource is the explicit email grant", who.roleSource === "email");
    ok("bootstrap: bootstrap Owner has no groups applied", Array.isArray(who.groups) && who.groups.length === 0);
    ok("bootstrap: sole Owner is isOnlyOwner", who.isOnlyOwner === true);
  }

  // ---- PROOF 1: NO groups claim -> UNCHANGED per-email behaviour --------------------------
  // A fresh Access caller with NO groups claim and no email grant resolves to viewer/default, exactly
  // as before group-mapping existed. The token carrying no groups is the additive off-switch.
  {
    const who = await whoami(ALICE); // no groups
    ok("no-groups caller defaults to viewer (per-email behaviour unchanged)", who.role === "viewer");
    ok("no-groups caller roleSource is default", who.roleSource === "default");
    ok("no-groups caller reports an empty groups list", who.groups.length === 0);
    // Even PRESENTING groups changes nothing while there is no mapping for them.
    const who2 = await whoami(ALICE, { groups: [G_ENG, G_NONE] });
    ok("groups present but unmapped: still viewer (mapping is empty)", who2.role === "viewer" && who2.roleSource === "default");
    ok("the verified groups are still surfaced honestly to the console", who2.groups.includes(G_ENG) && who2.groups.includes(G_NONE));
  }

  // ---- PROOF 2: a group mapped to operator lifts a caller in that group -------------------
  {
    // Owner maps the engineering group to operator. The mapping write is Owner-only.
    const set = await call(OWNER, "POST", "/admin/group-roles", { group: G_ENG, role: "operator" });
    const entry = (await set.json()) as { group: string; role: string; grantedBy: string };
    ok("Owner maps a group to operator: 200", set.status === 200);
    ok("the mapping records the group + role", entry.group === G_ENG && entry.role === "operator");
    ok("the mapping records the granting Owner", entry.grantedBy === OWNER);

    // GET /group-roles is readable and shows the mapping.
    const list = (await (await call(ALICE, "GET", "/admin/group-roles")).json()) as Array<{ group: string; role: string }>;
    ok("any authenticated role may read the group-role mapping", Array.isArray(list));
    ok("the mapping list shows the engineering->operator entry", list.some((m) => m.group === G_ENG && m.role === "operator"));

    // ALICE, presenting the engineering group, now resolves to operator FROM THE GROUP.
    const who = await whoami(ALICE, { groups: [G_ENG] });
    ok("a caller in the mapped group resolves to operator", who.role === "operator");
    ok("the resolved role's basis is the group", who.roleSource === "group");

    // The lift is real server-side: ALICE (now operator via the group) may create a downpipe, which a
    // viewer could not. This proves the group role drives the actual capability gate, not just whoami.
    const create = await call(ALICE, "POST", "/admin/downpipes", { id: "dp-grp", name: "via group", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_grp", include: [], exclude: [] } }, { groups: [G_ENG] });
    ok("the group-conferred operator can create a downpipe (capability gate honours the group role)", create.status === 200);
    // Without the group claim, the SAME caller is back to viewer and is refused (additive proof).
    const refused = await call(ALICE, "POST", "/admin/downpipes", { id: "dp-x", name: "x", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_x", include: [], exclude: [] } });
    ok("the same caller WITHOUT the group claim is refused (403): mapping is additive per-token", refused.status === 403);
  }

  // ---- PROOF 2b: a CONNECTION-SCOPED group mapping does NOT confer the role to a login that is not
  // through that connection -- closing the cross-IdP group-name collision (a group name mapped for the trusted
  // IdP is not inherited by a SECOND connection asserting the same name). A GLOBAL mapping is unchanged.
  {
    // A mapping scoped to a specific IdP connection (connId) is accepted and records its scope.
    const setScoped = await call(OWNER, "POST", "/admin/group-roles", { group: "scoped-admins", role: "operator", connId: "conn-entra" });
    ok("a connId-scoped group mapping is accepted (200)", setScoped.status === 200);
    const scopedEntry = (await setScoped.json()) as { group?: string; role?: string; connId?: string };
    ok("the scoped mapping records its connId", scopedEntry.connId === "conn-entra");
    ok("the scoped mapping is listed with its connId", ((await (await call(OWNER, "GET", "/admin/group-roles")).json()) as Array<{ group: string; connId?: string }>).some((m) => m.group === "scoped-admins" && m.connId === "conn-entra"));
    // ALICE presenting the SAME group name, but NOT through conn-entra (an Access login has no native connId),
    // does NOT inherit operator -- the scope filters the mapping out. This is the collision that used to leak.
    const scopedWho = await whoami(ALICE, { groups: ["scoped-admins"] });
    ok("a login NOT through the scoped connection does NOT get the scoped role (collision closed)", scopedWho.role === "viewer" && scopedWho.roleSource === "default");
    // Contrast: a GLOBAL mapping for a different group name STILL confers the role to any login (unchanged).
    const setGlobal = await call(OWNER, "POST", "/admin/group-roles", { group: "global-ops", role: "operator" });
    ok("a GLOBAL (unscoped) mapping is accepted (200)", setGlobal.status === 200);
    const globalWho = await whoami(ALICE, { groups: ["global-ops"] });
    ok("a global mapping still confers the role to any login (backward-compatible)", globalWho.role === "operator" && globalWho.roleSource === "group");
    // An invalid connId is rejected at write time.
    const badScope = await call(OWNER, "POST", "/admin/group-roles", { group: "x", role: "operator", connId: "NOT A CONN ID" });
    ok("an invalid connId is rejected (400)", badScope.status === 400);
    // Cleanup so later proofs see a clean mapping table.
    await call(OWNER, "POST", "/admin/group-roles/delete", { group: "scoped-admins" });
    await call(OWNER, "POST", "/admin/group-roles/delete", { group: "global-ops" });
  }

  // ---- PROOF 3: the approver CAP (write-time rejection + resolution-time cap) -------------
  {
    // A) Write-time: mapping a group to owner is an authorisation refusal -> 403.
    const r = await call(OWNER, "POST", "/admin/group-roles", { group: "admins", role: "owner" });
    const b = (await r.json()) as { error?: string };
    ok("mapping a group to owner is rejected (403)", r.status === 403);
    ok("the rejection is the generic forbidden body, leaking no owner reason", b.error === "forbidden" && !/only an Owner|per-email/.test(JSON.stringify(b)));
    // The rejected mapping was NOT stored (it must not leak through).
    const list = (await (await call(OWNER, "GET", "/admin/group-roles")).json()) as Array<{ group: string }>;
    ok("the rejected owner mapping was not stored", !list.some((m) => m.group === "admins"));

    // B) Resolution-time: even if a mapping were SOMEHOW stored with owner (planted directly into
    // storage, bypassing the write path), a caller in that group can NEVER resolve to owner. The cap
    // is re-applied at resolution (capped at approver), so the planted owner mapping resolves to
    // approver at most, never owner.
    sched.storage.rawPut(`grouprole:${"superadmins"}`, { group: "superadmins", role: "owner", grantedBy: "tampered", grantedAt: "2026-06-08T00:00:00.000Z" });
    const who = await whoami("carol@acme.example", { groups: ["superadmins"] });
    ok("a planted owner group mapping NEVER resolves a caller to owner", who.role !== "owner");
    ok("the planted owner mapping is capped to approver at resolution", who.role === "approver" && who.roleSource === "group");
  }

  // ---- PROOF 4: explicit email role and group role COMBINE via max ------------------------
  {
    // Map the SRE group to approver (the higher of the two we will combine).
    await call(OWNER, "POST", "/admin/group-roles", { group: G_SRE, role: "approver" });
    // Give BOB an explicit email grant of operator.
    await call(OWNER, "POST", "/admin/roles", { email: BOB, role: "operator" });

    // BOB with NO groups: just the email grant -> operator, source email.
    const onlyEmail = await whoami(BOB);
    ok("email-only caller resolves to the email role (operator)", onlyEmail.role === "operator" && onlyEmail.roleSource === "email");

    // BOB presenting the SRE group (approver): max(operator, approver) = approver, source group.
    const combinedUp = await whoami(BOB, { groups: [G_SRE] });
    ok("email(operator) + group(approver) combine to the higher (approver)", combinedUp.role === "approver");
    ok("the combine reports the group as the winning basis", combinedUp.roleSource === "group");

    // BOB presenting the engineering group (operator) which EQUALS the email grant: max is operator,
    // and the explicit email grant WINS ties (it is the more specific named authority).
    const combinedTie = await whoami(BOB, { groups: [G_ENG] });
    ok("email(operator) + group(operator) tie resolves to operator", combinedTie.role === "operator");
    ok("an explicit email grant wins a tie (source email)", combinedTie.roleSource === "email");

    // The group never DROPS the email role: a lower group does not reduce a higher email grant.
    await call(OWNER, "POST", "/admin/group-roles", { group: G_NONE, role: "viewer" });
    const notReduced = await whoami(BOB, { groups: [G_NONE] });
    ok("a lower group mapping never reduces a higher email grant", notReduced.role === "operator" && notReduced.roleSource === "email");
  }

  // ---- PROOF 5: the last-Owner guard is UNAFFECTED by groups ------------------------------
  {
    // There is exactly one explicit Owner (OWNER). Map a group to approver and have OWNER present it;
    // OWNER stays owner (the email grant out-ranks the group) and is still the sole counted Owner.
    const who = await whoami(OWNER, { groups: [G_SRE] });
    ok("the Owner presenting an approver group is still owner (email out-ranks group)", who.role === "owner");
    ok("groups do not add a counted Owner: the Owner is still the only one", who.isOnlyOwner === true);

    // Self-demotion of the only Owner is still refused 400 regardless of any group the Owner is in,
    // because the guard counts only explicit `role:` owner entries (a group can never confer owner).
    const demote = await call(OWNER, "POST", "/admin/roles", { email: OWNER, role: "viewer" }, { groups: [G_SRE] });
    const b = (await demote.json()) as { error?: string };
    ok("self-demotion of the sole Owner is still refused 400 (guard unaffected by groups)", demote.status === 400);
    ok("the last-Owner reason is explicit", typeof b.error === "string" && /last Owner/.test(b.error));
    // No mapping created THROUGH THE WRITE PATH carries owner (the write-time cap held on every
    // upsert). The only owner-role row is the "superadmins" entry PROOF 3B planted DIRECTLY into
    // storage to prove the resolution-time cap; the write path could never have produced it, so it is
    // excluded here. Every legitimately-written mapping is viewer/operator/approver.
    const list = (await (await call(OWNER, "GET", "/admin/group-roles")).json()) as Array<{ group: string; role: string }>;
    ok("no WRITTEN group mapping carries owner (the write-time cap held)", list.filter((m) => m.group !== "superadmins").every((m) => m.role !== "owner"));
  }

  // ---- PROOF 6: the token-fallback path is UNCHANGED -------------------------------------
  {
    // No Access env, only ADMIN_TOKEN: the bare-token caller is the all-or-nothing break-glass owner,
    // carries NO groups, and reports roleSource owner-token. Group-mapping never applies to it.
    const tokenEnv = ({ ...sched.env, ADMIN_TOKEN: "shared-break-glass-token" }) as unknown as Env;
    const r = await handleAdmin(
      new Request("https://engine.example/admin/whoami", { method: "GET", headers: { authorization: "Bearer shared-break-glass-token" } }),
      tokenEnv,
    );
    const who = (await r.json()) as Who;
    ok("token fallback authorises (200)", r.status === 200);
    ok("token fallback is method token, no email", who.method === "token" && who.email === null);
    ok("token fallback resolves to owner (break-glass), source owner-token", who.role === "owner" && who.roleSource === "owner-token");
    ok("token fallback carries no groups", who.groups.length === 0);
  }

  // ---- PROOF 7: the writes are Owner-only, with DO re-resolution (defence in depth) -------
  {
    // A non-Owner (ALICE, viewer with no groups) is refused the mapping write at the router (403 JSON).
    const r = await call(ALICE, "POST", "/admin/group-roles", { group: G_ENG, role: "operator" });
    const b = (await r.json()) as { error?: string; required?: string; have?: string };
    ok("a non-Owner is refused the mapping write (403)", r.status === 403);
    // The group->role mapping write gates on the access.policy capability now (contract section 8). The
    // allow/deny for the four existing roles is unchanged (only owner holds access.policy among them);
    // required is the capability rather than the "owner" role string.
    ok("the 403 is the forbidden capability gate naming access.policy", b.error === "forbidden" && b.required === "access.policy");

    // Even a caller whose GROUP confers operator cannot write the mapping (operator < owner), and the
    // DO re-resolves Owner from email + groups, so the cap is not bypassable by group elevation.
    const r2 = await call(ALICE, "POST", "/admin/group-roles", { group: G_NONE, role: "viewer" }, { groups: [G_ENG] });
    ok("a group-elevated operator still cannot write the mapping (owner-only)", r2.status === 403);

    // Defence in depth: call the DO DIRECTLY with a non-Owner caller header (bypassing the router).
    // The DO RE-RESOLVES the role from the forwarded email + groups (no explicit Owner grant, no
    // owner-conferring group) and must refuse the write (fail closed -> 400).
    const operatorCaller: Caller = { method: "access", email: ALICE, subject: `${ISS}|sub-of-${ALICE}`, role: "owner", groups: [G_ENG] }; // a LIE: asserts owner; the DO re-resolves from email+groups
    const direct = await sched.stub.fetch("https://scheduler.internal/group-roles", {
      method: "POST",
      headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(operatorCaller) },
      body: JSON.stringify({ group: "evil", role: "approver" }),
    });
    const db = (await direct.json()) as { error?: string };
    ok("the DO refuses a mapping write from a non-Owner caller even when the header LIES role:owner (re-resolves)", direct.status === 403 && typeof db.error === "string" && /forbidden/.test(db.error));
    // And a write with NO caller header is refused too (fails closed).
    const noCaller = await sched.stub.fetch("https://scheduler.internal/group-roles", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ group: "evil", role: "approver" }),
    });
    ok("the DO refuses a mapping write with no caller header (fail closed)", noCaller.status === 403);
    // The malicious group was never stored.
    const list = (await (await call(OWNER, "GET", "/admin/group-roles")).json()) as Array<{ group: string }>;
    ok("the bypass attempts stored nothing", !list.some((m) => m.group === "evil"));
  }

  // ---- PROOF 8: delete is Owner-only, idempotent, and removes the lift --------------------
  {
    // Remove the engineering->operator mapping; ALICE presenting that group drops back to viewer.
    const del = await call(OWNER, "POST", "/admin/group-roles/delete", { group: G_ENG });
    const b = (await del.json()) as { deleted: boolean };
    ok("Owner deletes a group mapping (deleted:true)", del.status === 200 && b.deleted === true);
    const who = await whoami(ALICE, { groups: [G_ENG] });
    ok("after deletion the group no longer lifts the caller (back to viewer)", who.role === "viewer" && who.roleSource === "default");
    // Deleting an absent mapping is an idempotent no-op success.
    const again = (await (await call(OWNER, "POST", "/admin/group-roles/delete", { group: G_ENG })).json()) as { deleted: boolean };
    ok("deleting an absent mapping is idempotent (deleted:false)", again.deleted === false);
    // A non-Owner cannot delete.
    ok("a non-Owner cannot delete a group mapping (403)", (await call(ALICE, "POST", "/admin/group-roles/delete", { group: G_SRE })).status === 403);
  }

  // ---- PROOF 9: changes are audited as a redaction-safe group-role-change ------------------
  {
    // The successful set/delete above each recorded a group-role-change at the DO commit point. Read
    // the audit log (Owner) and assert the events carry only the group name + role, never a secret.
    const log = (await (await call(OWNER, "GET", "/admin/audit?action=group-role-change&limit=500")).json()) as { events: AuditEvent[] };
    ok("group-role-change events were recorded", log.events.length >= 1);
    ok("every group-role-change targets the grouprole kind (group + role only)", log.events.every((e) => e.target.kind === "grouprole"));
    const setEvent = log.events.find((e) => e.outcome === "success" && e.target.kind === "grouprole" && (e.target as { group: string }).group === G_ENG && (e.target as { role: string }).role === "operator");
    ok("the engineering->operator set is in the trail with the safe group + role", setEvent !== undefined);
    ok("the set event attributes the granting Owner", setEvent?.actorEmail === OWNER && setEvent?.actorMethod === "access");
    // A denied mapping write is also audited (the non-Owner attempt in PROOF 7).
    ok("a denied group-role-change (non-Owner) is recorded", log.events.some((e) => e.outcome === "denied" && e.actorEmail === ALICE));
    // No mapped/serialised event should carry "owner" as a grouprole role (the cap held).
    ok("no group-role-change audit target carries the owner role", log.events.every((e) => e.target.kind !== "grouprole" || (e.target as { role: string }).role !== "owner"));
  }

  // ---- PROOF 10: the verified idp hint is surfaced honestly (when present) ----------------
  {
    // A token carrying an idp hint surfaces it on whoami; a token without one omits it (never faked).
    const withIdp = await whoami("dave@acme.example", { groups: [G_SRE], idp: "okta" });
    ok("whoami surfaces the verified identity provider when the token carries it", withIdp.identityProvider === "okta");
    const withoutIdp = await whoami("erin@acme.example", { groups: [G_SRE] });
    ok("whoami omits identityProvider when the token carries none (never fabricated)", withoutIdp.identityProvider === undefined);
  }

  // ---- PROOF 11: an ABUSIVE groups claim is BOUNDED at the verify layer AND the DO's own layer ---
  // The auth-boundary invariant under test: the DO bounds EVERY groups list it ingests ITSELF (it does
  // not rely on access.ts boundGroups, a different module, having bounded it first), so a forged or
  // pathological-but-validly-signed list cannot hand the single-threaded DO an unbounded list to loop
  // over or persist. We assert the cap at THREE points: (a) the verify-time boundGroups layer (via the
  // end-to-end whoami over a real signed JWT), (b) the DO's parseGroupsParam (driving GET /whoami on
  // the DO stub DIRECTLY with the abusive list as the query param, bypassing access.ts so the DO-side
  // bound is the one doing the work), and (c) the DO's decodeCaller (the caller-header path the
  // group-roles writes use), both as the exported function's own observable AND by driving a DO write
  // with the abusive header so the bound is exercised inside the DO's fetch.
  {
    const LONG = "x".repeat(300); // a single entry over the 256-char cap -> must be dropped
    const CTRL_NUL = "bad\x00group"; // an ASCII NUL control-char entry -> must be dropped
    const CTRL_TAB = "tab\tgroup"; // an ASCII TAB (0x09) control-char entry -> must be dropped
    const DUP = "dup-group"; // appears many times -> must survive exactly once (deduped)
    // Build an abusive list: control-char + over-long + duplicates placed FIRST (so they fall inside
    // the kept window and are genuinely tested for drop/dedupe, not merely truncated away by the cap),
    // then 10,000 distinct entries to blow past the 200 cap.
    const abusive: string[] = [CTRL_NUL, CTRL_TAB, LONG, DUP, DUP, DUP, "  ", ""];
    for (let i = 0; i < 10000; i++) abusive.push(`grp-${i}`);
    abusive.push(DUP); // a late duplicate too, to prove order-preserving first-occurrence dedupe

    const hasControl = (s: string): boolean => {
      for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        if (c < 0x20 || c === 0x7f) return true;
      }
      return false;
    };
    const wellBounded = (label: string, groups: string[]): void => {
      ok(`${label}: list capped to <= 200`, groups.length <= 200);
      ok(`${label}: every entry <= 256 chars`, groups.every((g) => g.length <= 256));
      ok(`${label}: no over-long entry survived`, !groups.includes(LONG));
      ok(`${label}: no control-char entry survived`, groups.every((g) => !hasControl(g)));
      ok(`${label}: no empty/whitespace-only entry survived`, groups.every((g) => g.trim().length > 0));
      ok(`${label}: deduped (the duplicate survives exactly once)`, groups.filter((g) => g === DUP).length <= 1);
      ok(`${label}: the list is deduped overall`, new Set(groups).size === groups.length);
    };

    // (a) Verify-time boundGroups: a real signed JWT carrying the abusive groups claim. whoami surfaces
    // the verified groups; boundGroups must have capped them before they ever reached the DO.
    const whoVerify = await whoami("mallory@acme.example", { groups: abusive });
    wellBounded("boundGroups (verify-time, end-to-end whoami)", whoVerify.groups);

    // (b) DO parseGroupsParam: drive the DO stub's GET /whoami DIRECTLY with the abusive list as the
    // `groups` query param (a JSON array), bypassing access.ts entirely so the DO's OWN parseGroupsParam
    // is the only thing that can bound it. The DO must cap/normalise it and echo a bounded list.
    const params = new URLSearchParams({ email: "mallory@acme.example", subject: `${ISS}|sub-of-mallory@acme.example`, method: "access", groups: JSON.stringify(abusive) });
    const doWhoResp = await sched.stub.fetch(`https://scheduler.internal/whoami?${params.toString()}`, { method: "GET" });
    const doWho = (await doWhoResp.json()) as { groups: string[] };
    ok("the DO GET /whoami accepts the abusive list without choking (200)", doWhoResp.status === 200);
    wellBounded("DO parseGroupsParam (direct DO whoami)", doWho.groups);
    // The DO bound is genuinely the one doing the work here: an UNbounded pass-through would echo > 200.
    ok("DO parseGroupsParam actually capped a 10k+ list to 200", doWho.groups.length === 200);

    // (c1) DO decodeCaller, as the exported function's own observable: a caller header built from the
    // abusive groups must decode to a bounded list (this is the function the DO calls on every write).
    const abusiveCaller: Caller = { method: "access", email: "mallory@acme.example", subject: `${ISS}|sub-of-mallory@acme.example`, role: "viewer", groups: abusive };
    const decoded = decodeCaller(encodeCaller(abusiveCaller));
    ok("decodeCaller returns a payload for an abusive-but-valid caller header", decoded !== null);
    wellBounded("DO decodeCaller (caller header)", decoded?.groups ?? []);
    ok("DO decodeCaller actually capped a 10k+ list to 200", (decoded?.groups.length ?? -1) === 200);

    // (c2) Exercise decodeCaller INSIDE the DO's fetch: drive a /group-roles write directly with the
    // abusive-groups caller header. The DO decodes the caller (bounding the groups) and re-resolves the
    // role; this caller is not an Owner (viewer + no owner-conferring group), so the write fails closed
    // (400) WITHOUT the DO ever looping over an unbounded list. This proves the bound is exercised on
    // the live DO write path, not only via the standalone function.
    const direct = await sched.stub.fetch("https://scheduler.internal/group-roles", {
      method: "POST",
      headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(abusiveCaller) },
      body: JSON.stringify({ group: "abusive-write", role: "operator" }),
    });
    ok("the DO write with an abusive-groups caller header fails closed (non-Owner, 403) without choking", direct.status === 403);
    // The abusive write stored nothing (it was refused before any upsert).
    const list = (await (await call(OWNER, "GET", "/admin/group-roles")).json()) as Array<{ group: string }>;
    ok("the abusive-groups write stored no mapping", !list.some((m) => m.group === "abusive-write"));
  }

  // ---- PROOF 12: access-admin (the access.policy holder) MANAGES the mapping WITHIN AUTHORITY only ---
  // The group->role mapping writes gate on access.policy, which access-admin holds. The DO re-resolves the
  // caller's role from its own tables and reads can(role, "access.policy"). But the HARD no-escalation
  // invariant (requireGrantWithinAuthority) means an access-admin may only map a group to a role whose
  // capability set is a SUBSET of its OWN: access-admin holds neither downpipe.write nor restore.apply, so
  // mapping a group to operator is REFUSED (it would hand a directory of people a capability the assigner
  // lacks). A within-authority mapping (viewer, whose caps it holds) IS honoured (200), the lift is real,
  // AND the owner CAP is UNCHANGED (a group can never be mapped to owner -> 400). So allowing access-admin
  // here never lets it confer owner OR escalate via the mapping. Owner (PROOF 2 / PROOF 4) maps any
  // non-owner role because it holds every capability.
  {
    const ADMIN = "accessadmin-gr@acme.example"; // a fresh access-admin (people + access policy)
    const G_ADMIN = "platform-admins"; // a group the access-admin will map within its authority

    // OWNER appoints the access-admin (an Owner-only initial grant), then the access-admin manages the
    // mapping. ADMIN has an explicit email grant and no groups, so the DO re-resolves it to access-admin.
    await call(OWNER, "POST", "/admin/roles", { email: ADMIN, role: "access-admin" });

    // access-admin mapping a group to a STRONGER role (operator) is REFUSED by the within-authority guard:
    // operator confers downpipe.write, which access-admin does not hold, so it cannot hand it to a group.
    const tooStrong = await call(ADMIN, "POST", "/admin/group-roles", { group: "would-be-operators", role: "operator" });
    const tooStrongBody = (await tooStrong.json()) as { error?: string };
    ok("access-admin CANNOT map a group to operator (refused 403 by the within-authority guard)", tooStrong.status === 403);
    ok("the refusal is the generic forbidden body, leaking no capability name", tooStrongBody.error === "forbidden" && !/downpipe\.write/.test(JSON.stringify(tooStrongBody)) && !/do not hold/.test(JSON.stringify(tooStrongBody)));
    const afterStrong = (await (await call(OWNER, "GET", "/admin/group-roles")).json()) as Array<{ group: string }>;
    ok("the refused operator mapping stored nothing", !afterStrong.some((m) => m.group === "would-be-operators"));

    // access-admin SETS a WITHIN-AUTHORITY mapping. access-admin's only within-authority roles are viewer
    // (a subset of its caps) and access-admin itself (equal caps). We map to access-admin: it is BOTH within
    // authority AND an observable lift (it out-ranks the viewer default, so roleSource reads "group"; a
    // viewer mapping would resolve to the viewer DEFAULT and could not be distinguished from no mapping).
    const set = await call(ADMIN, "POST", "/admin/group-roles", { group: G_ADMIN, role: "access-admin" });
    const setBody = (await set.json()) as { group?: string; role?: string; grantedBy?: string };
    ok("access-admin can set a within-authority group->role mapping (access-admin, 200, DO persists it)", set.status === 200);
    ok("the mapping records the group + role + the granting access-admin", setBody.group === G_ADMIN && setBody.role === "access-admin" && setBody.grantedBy === ADMIN);
    // The lift is real: a caller presenting that group resolves to access-admin from the group.
    const lifted = await whoami("frank@acme.example", { groups: [G_ADMIN] });
    ok("the access-admin-set mapping lifts a caller in that group to access-admin (roleSource group)", lifted.roleSource === "group" && lifted.role === "access-admin");

    // The owner CAP holds EVEN FOR an access-admin caller: mapping a group to owner is rejected (403).
    const capOwner = await call(ADMIN, "POST", "/admin/group-roles", { group: "secret-admins", role: "owner" });
    const capBody = (await capOwner.json()) as { error?: string };
    ok("access-admin mapping a group to owner is still rejected (403)", capOwner.status === 403);
    ok("the owner-cap rejection is the generic forbidden body, leaking no owner reason", capBody.error === "forbidden" && !/only an Owner|per-email/.test(JSON.stringify(capBody)));
    const afterCap = (await (await call(OWNER, "GET", "/admin/group-roles")).json()) as Array<{ group: string }>;
    ok("the rejected owner mapping by the access-admin stored nothing", !afterCap.some((m) => m.group === "secret-admins"));

    // access-admin DELETES the mapping: also honoured (200), and the lift is removed.
    const del = await call(ADMIN, "POST", "/admin/group-roles/delete", { group: G_ADMIN });
    const delBody = (await del.json()) as { deleted: boolean };
    ok("access-admin can delete a group->role mapping (deleted:true)", del.status === 200 && delBody.deleted === true);
    const unlifted = await whoami("frank@acme.example", { groups: [G_ADMIN] });
    ok("after the access-admin deletes the mapping the lift is gone (back to viewer)", unlifted.role === "viewer" && unlifted.roleSource === "default");
  }

  globalThis.fetch = realFetch;
  console.log(failures === 0 ? "\nGROUP->ROLE MAPPING VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
