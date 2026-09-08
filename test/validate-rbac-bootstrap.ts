// validate-rbac PROOFs 1..1e: bootstrap-first-caller-as-Owner, the emailless/subless denials, the
// recycled-subject closure (V10.3.3 / V10.5.2) and the legacy email-keyed migration. Extracted verbatim
// from test/validate-rbac.ts; the assertions, order and
// expected values are unchanged. Proofs 1 and 1a..1c run on the shared scheduler in `ctx`; 1d and 1e
// each stand up their own fresh scheduler exactly as the single-file suite did.

import { handleAdmin } from "../src/admin/router.ts";
import type { Env } from "../src/env.d.ts";
import { type Ctx, ISS, AUD, KID, TEAM, jwtPart, makeScheduler } from "./validate-rbac-harness.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";

export async function runBootstrap(ctx: Ctx): Promise<void> {
  const { ok, signer, call, accessEnv } = ctx;
  const { futureExp, privateKey, tokenForSub } = signer;

  const OWNER = "owner@acme.example";
  const OPERATOR = "operator@acme.example";

  // ---- PROOF 1: bootstrap the first Access caller as Owner -------------------------------
  // The role table is empty, so the first authenticated Access caller's whoami makes them Owner.
  {
    const r = await call(OWNER, "GET", "/admin/whoami");
    const who = (await r.json()) as { method: string; email: string; role: string; isOnlyOwner: boolean; sessionExpiresAt?: number };
    ok("bootstrap: first Access caller whoami is 200", r.status === 200);
    ok("bootstrap: first Access caller is Owner", who.role === "owner");
    ok("bootstrap: whoami echoes the verified email", who.email === OWNER);
    ok("bootstrap: whoami reports method access", who.method === "access");
    ok("bootstrap: whoami carries the session expiry from the JWT exp", who.sessionExpiresAt === futureExp);
    ok("bootstrap: the sole Owner is isOnlyOwner", who.isOnlyOwner === true);
  }

  // A SECOND Access caller now joins; because the table is non-empty they default to viewer
  // (least privilege), proving the bootstrap is one-shot, not "every caller is Owner".
  {
    const r = await call(OPERATOR, "GET", "/admin/whoami");
    const who = (await r.json()) as { role: string; isOnlyOwner: boolean };
    ok("a later caller defaults to viewer (least privilege)", who.role === "viewer");
    ok("a non-owner is not isOnlyOwner", who.isOnlyOwner === false);
  }

  // ---- PROOF 1b: an emailless but validly-signed Access JWT is DENIED --------
  // A Cloudflare Access service token is validly signed for the application audience but carries
  // common_name/sub, not email. Such a token must NEVER be folded into the bare-token Owner
  // break-glass (the prior privilege-escalation bug). It must be denied (401), never resolved to Owner.
  {
    async function tokenForNoEmail(): Promise<string> {
      const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
      const body = jwtPart({ iss: ISS, aud: AUD, exp: futureExp, iat: futureExp - 3600, sub: "svc-token-1", common_name: "ci-automation" });
      const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, new TextEncoder().encode(`${header}.${body}`)));
      return `${header}.${body}.${b64urlEncode(sig)}`;
    }
    const whoReq = new Request("https://engine.example/admin/whoami", { method: "GET", headers: { "cf-access-jwt-assertion": await tokenForNoEmail() } });
    const r = await handleAdmin(whoReq, accessEnv());
    ok("an emailless valid Access JWT is denied (401), not resolved to Owner", r.status === 401);
    // And it cannot escalate: an emailless Access caller must not be able to grant itself any role.
    const grantReq = new Request("https://engine.example/admin/roles", {
      method: "POST",
      headers: { "cf-access-jwt-assertion": await tokenForNoEmail(), "content-type": "application/json" },
      body: JSON.stringify({ email: "attacker@evil.example", role: "owner" }),
    });
    const gr = await handleAdmin(grantReq, accessEnv());
    ok("an emailless Access caller cannot grant a role (denied, never Owner)", gr.status === 401);
  }

  // ---- PROOF 1c (V10.3.3): an email-bearing Access JWT with NO sub is DENIED --------------
  // Authorisation now keys on the stable subject (iss+"|"+sub). A validly-signed assertion that carries
  // an email but no `sub` has no stable identity to authorise on, so it is rejected the SAME way an
  // emailless one is (401), never downgraded to the owner break-glass and never resolved to a role.
  {
    async function tokenForNoSub(email: string): Promise<string> {
      const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
      const body = jwtPart({ iss: ISS, aud: AUD, exp: futureExp, iat: futureExp - 3600, email });
      const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, new TextEncoder().encode(`${header}.${body}`)));
      return `${header}.${body}.${b64urlEncode(sig)}`;
    }
    const r = await handleAdmin(new Request("https://engine.example/admin/whoami", { method: "GET", headers: { "cf-access-jwt-assertion": await tokenForNoSub("nosub@acme.example") } }), accessEnv());
    ok("V10.3.3: an email-bearing Access JWT with no sub is denied (401), not resolved to a role", r.status === 401);
    ok("V10.3.3: the subless rejection is the plaintext sign-in signal (not a downgrade)", (await r.text()) === "unauthorised");
  }

  // ---- PROOF 1d (V10.3.3 / V10.5.2 CLOSURE): a recycled email with a DIFFERENT subject does NOT
  //               inherit a departed member's role -------------------------------------------------
  // THE FINDING THIS CLOSES: with the old email-keyed role table, deleting a member and reassigning their
  // email to a new person would let the NEW person inherit the OLD role (the role row was keyed by the
  // email). With the subject-keyed table, authorisation keys on the immutable (iss, sub): the departed
  // member's grant bound to THEIR subject, so a new Access user reusing the email (a different sub) has no
  // bound entry and matches no pending invite, and resolves to the least-privilege viewer. This is the
  // ASVS V10.3.3 / V10.5.2 closure proof. A FRESH scheduler keeps it self-contained (its own bootstrap).
  {
    const sc = makeScheduler();
    const env = (): Env => ({ ...sc.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD }) as unknown as Env;
    const callSub = async (email: string, sub: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> => {
      const init: RequestInit = {
        method,
        headers: { "cf-access-jwt-assertion": await tokenForSub(email, sub), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      };
      return handleAdmin(new Request(`https://engine.example${path}`, init), env());
    };
    const CL_OWNER = "closure-owner@acme.example";
    const DEPARTED = "shared@acme.example"; // the email that will be recycled
    const SUB_DEPARTED = "sub-departed-alice";
    const SUB_RECYCLED = "sub-recycled-bob"; // a DIFFERENT Access user, SAME email later

    // Bootstrap the owner (first caller in this fresh DO), then grant DEPARTED the approver role (an
    // invite-by-email; it lands as a pending grant since DEPARTED has not authenticated yet).
    await callSub(CL_OWNER, "sub-closure-owner", "GET", "/admin/whoami");
    const grant = await callSub(CL_OWNER, "sub-closure-owner", "POST", "/admin/roles", { email: DEPARTED, role: "approver" });
    ok("closure: owner grants approver to the (soon-departed) email", grant.status === 200);

    // The departed member (sub-departed-alice) authenticates: the pending invite BINDS to their subject and
    // resolves to approver. This is the legitimate holder before the email is recycled.
    const aliceWho = (await (await callSub(DEPARTED, SUB_DEPARTED, "GET", "/admin/whoami")).json()) as { role: string; subject?: string };
    ok("closure: the departed member binds the invite to THEIR subject and is approver", aliceWho.role === "approver");
    ok("closure: whoami returns the stable subject (iss|sub), not the email", aliceWho.subject === `${ISS}|${SUB_DEPARTED}`);

    // VARIANT A (recycle WITHOUT offboarding): while alice's bound approver entry still exists, a DIFFERENT
    // Access user (sub-recycled-bob) signs in with the SAME email. Under the OLD email-keyed code this would
    // resolve to approver (the email matched the row); under the fix it resolves to VIEWER (the subject has
    // no grant), proving the role is bound to the immutable subject, not the recyclable email.
    const bobWho = (await (await callSub(DEPARTED, SUB_RECYCLED, "GET", "/admin/whoami")).json()) as { role: string; subject?: string; isOnlyOwner: boolean };
    ok("CLOSURE A: a different subject reusing the email does NOT inherit approver (resolves viewer)", bobWho.role === "viewer");
    ok("CLOSURE A: the recycled caller's subject is its own (iss|sub-recycled), distinct from the departed", bobWho.subject === `${ISS}|${SUB_RECYCLED}` && bobWho.subject !== aliceWho.subject);

    // And the recycled caller cannot perform an approver-only action: a restore APPLY is refused at the
    // capability gate (it holds only viewer), proving the non-inheritance has real authority teeth, not
    // just a cosmetic role label.
    const bobApply = await callSub(DEPARTED, SUB_RECYCLED, "POST", "/admin/restore", { runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV", confirm: true });
    const bobApplyBody = (await bobApply.json()) as { error?: string; required?: string; have?: string };
    ok("CLOSURE A: the recycled caller is refused restore.apply (viewer authority)", bobApply.status === 403 && bobApplyBody.required === "restore.apply" && bobApplyBody.have === "viewer");

    // VARIANT B (recycle AFTER offboarding): the owner OFFBOARDS the departed member (deletes their bound
    // entry), then yet another Access user (sub-recycled-carol) signs in with the same email. It must also
    // resolve to viewer: offboarding removed the bound grant AND any pending invite, so nothing lingers for
    // a recycled subject to pick up.
    const del = (await (await callSub(CL_OWNER, "sub-closure-owner", "POST", "/admin/roles/delete", { email: DEPARTED })).json()) as { deleted: boolean };
    ok("closure: the owner offboards the departed member (bound entry removed)", del.deleted === true);
    const carolWho = (await (await callSub(DEPARTED, "sub-recycled-carol", "GET", "/admin/whoami")).json()) as { role: string; subject?: string };
    ok("CLOSURE B: after offboarding, a recycled email with a new subject resolves to viewer", carolWho.role === "viewer");
    ok("CLOSURE B: the post-offboard recycled caller has its own subject", carolWho.subject === `${ISS}|sub-recycled-carol`);

    // The owner is untouched throughout (the closure never affected the legitimate Owner's authority).
    const ownerStill = (await (await callSub(CL_OWNER, "sub-closure-owner", "GET", "/admin/whoami")).json()) as { role: string };
    ok("closure: the bootstrap Owner is unaffected by the recycle attempts", ownerStill.role === "owner");
  }

  // ---- PROOF 1e (migration): a LEGACY email-keyed entry is treated as pending and binds on first auth ----
  // Existing tenants have role rows under the OLD `role:<email>` key (no subject). On read these are treated
  // as pending invitations, so an existing grant is NOT lost: the member's role still resolves, and on their
  // first verified request the DO BINDS it to their subject (`role:sub:<subject>`) and removes the legacy
  // row. We seed a legacy row directly into a fresh DO's storage (simulating a pre-upgrade tenant), then
  // prove the member resolves the legacy role AND that the row migrated to the subject key.
  {
    const sc = makeScheduler();
    const env = (): Env => ({ ...sc.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD }) as unknown as Env;
    const callSub = async (email: string, sub: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> => {
      const init: RequestInit = {
        method,
        headers: { "cf-access-jwt-assertion": await tokenForSub(email, sub), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      };
      return handleAdmin(new Request(`https://engine.example${path}`, init), env());
    };
    const LEGACY_EMAIL = "legacy-member@acme.example";
    const LEGACY_SUB = "sub-legacy-member";
    // Seed a pre-rekey owner (so the table is non-empty / no bootstrap fires) AND a LEGACY operator row in
    // the OLD email-keyed shape (no subject), exactly as a pre-upgrade tenant's storage would hold them.
    await sc.storage.put("role:owner-legacy@acme.example", { email: "owner-legacy@acme.example", role: "owner", grantedBy: "bootstrap", grantedAt: "2026-01-01T00:00:00.000Z" });
    await sc.storage.put(`role:${LEGACY_EMAIL}`, { email: LEGACY_EMAIL, role: "operator", grantedBy: "owner-legacy@acme.example", grantedAt: "2026-01-02T00:00:00.000Z" });

    // The legacy member authenticates: the legacy row is read as pending and BINDS to their subject; their
    // role resolves to the legacy operator (the grant was not lost across the upgrade).
    const who = (await (await callSub(LEGACY_EMAIL, LEGACY_SUB, "GET", "/admin/whoami")).json()) as { role: string; subject?: string };
    ok("migration: a legacy email-keyed grant still resolves the role (not lost)", who.role === "operator");
    ok("migration: whoami returns the now-bound stable subject", who.subject === `${ISS}|${LEGACY_SUB}`);
    // The roster (GET /admin/roles) shows the member with the legacy role, now subject-bound.
    const roster = (await (await callSub("owner-legacy@acme.example", "sub-owner-legacy", "GET", "/admin/roles")).json()) as Array<{ email: string; role: string; subject: string }>;
    const row = roster.find((e) => e.email === LEGACY_EMAIL);
    ok("migration: the bound roster row carries the subject (the legacy row migrated)", row?.role === "operator" && row?.subject === `${ISS}|${LEGACY_SUB}`);
    // The legacy email-keyed row is gone (bound to the subject key); a SECOND login is idempotent.
    const who2 = (await (await callSub(LEGACY_EMAIL, LEGACY_SUB, "GET", "/admin/whoami")).json()) as { role: string };
    ok("migration: a second login is idempotent (still operator, no re-bind needed)", who2.role === "operator");
  }
}
