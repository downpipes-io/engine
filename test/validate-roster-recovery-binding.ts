// validate-roster-recovery-binding: the roster-bound consumption gate, driven BOTH DIRECTIONS against a real
// Durable Object through the production router.
//
// WHAT IS BEING PROVED, AND WHY IT NEEDED A LIVE DRIVE. A recovery code is a one-time bearer secret with no
// expiry, deliberately: a break-glass credential that expires on a clock fails during the emergency it exists
// for. Spending one mints an ordinary session (method "passkey", the consumed email's subject), and that
// session reaches the SELF-ADD arm of resolveRegistrationAuthorisation indistinguishably from a session an
// authenticator produced. So a person whose role row was deleted could spend one code and walk away with a
// PERMANENT credential. In one observed case, 71 of 149 identities could sign in with no role row, 67 of
// them by recovery code, against ONE the roster accounts for.
//
// THE DEFECT IS REPRODUCED HERE BEFORE IT IS CLOSED (section B). The removed person's consumption is driven
// first, and the session it mints is asserted to be REAL and to still authorise ordinary reads, because the
// fix must close the enrolment WITHOUT inventing a lockout. Only then is the enrolment shown to be refused.
// A proof that only showed the refusal could not tell a working gate from a broken sign-in.
//
// THE FAIL-OPEN ARMS ARE THE POINT OF SECTIONS C AND D. Binding validity to the roster is only safe if an
// UNREADABLE roster is a non-answer. Two ways it can be unreadable are proved separately: a storage fault,
// and a roster that reads EMPTY (a new or broken account, which a naive membership test would read as
// "everybody has left" and refuse every consumption on).
//
// Sections F and G cover two guards on the offboarding revoke found missing: the step-up gate did not
// cover the route, and a self-targeted revoke was not refused at all.
//
// Run: node test/validate-roster-recovery-binding.ts

import { handleAdmin } from "../src/admin/router.ts";
import { STEPUP_SUBS } from "../src/admin/router-core.ts";
import { SESSION_COOKIE_NAME } from "../src/admin/session.ts";
import { classifyRosterMembership, rosterRefusesEnrolment } from "../src/admin/signin-factors.ts";
import { PASSKEY_CRED_PREFIX, PASSKEY_INVITE_PREFIX } from "../src/sched/scheduler-do-base.ts";
import type { Env } from "../src/env.d.ts";
import { buildContext } from "./validate-owner-action-dualcontrol-harness.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ORIGIN = "https://console.example";

async function main(): Promise<void> {
  const ctx = await buildContext();
  const { sched, OWNER, call, doFetch } = ctx;
  const store = sched.storage;

  // The env the UNAUTHENTICATED sign-in routes run under. CONSOLE_ORIGIN must be set or every passkey
  // ceremony 501s before it reaches an authorisation decision, which would make a refusal proof vacuous.
  const authEnv = (): Env => ({ ...sched.env, CONSOLE_ORIGIN: ORIGIN }) as unknown as Env;

  // Spend a recovery code exactly as the sign-in screen does: an unauthenticated POST to the production
  // route, no cookie, no bearer.
  const spendCode = async (email: string, code: string): Promise<Response> =>
    handleAdmin(
      new Request("https://engine.example/admin/auth/recovery", {
        method: "POST",
        headers: { "content-type": "application/json", origin: ORIGIN },
        body: JSON.stringify({ email, code }),
      }),
      authEnv(),
    );

  // Begin a passkey REGISTRATION carrying a session cookie. This is the self-add path: the one that turns a
  // spent one-time secret into a standing credential. begin is used rather than finish because begin is where
  // authorisation is decided, and finish needs a real authenticator.
  const beginRegister = async (email: string, cookie: string | null): Promise<{ status: number; ok?: boolean; reason?: string }> => {
    const r = await handleAdmin(
      new Request("https://engine.example/admin/auth/register/begin", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          origin: ORIGIN,
          ...(cookie !== null ? { cookie: `${SESSION_COOKIE_NAME}=${cookie}` } : {}),
        },
        body: JSON.stringify({ email, displayName: email }),
      }),
      authEnv(),
    );
    const body = (await r.json()) as { ok?: boolean; reason?: string };
    return { status: r.status, ...body };
  };

  // Mint a fresh recovery set for ANY address by driving the DO route the console's regenerate sits on. The
  // plaintext codes exist only in this response, which is the same property the real route has.
  const mintCodes = async (email: string): Promise<string[]> => {
    const r = await doFetch("/recovery/regenerate", null, { email });
    const body = (await r.json()) as { ok?: boolean; codes?: string[] };
    return body.codes ?? [];
  };

  const cookieOf = (r: Response): string | null => {
    const raw = r.headers.get("set-cookie");
    if (raw === null) return null;
    const m = new RegExp(`${SESSION_COOKIE_NAME}=([^;]+)`).exec(raw);
    return m?.[1] ?? null;
  };

  const STAYER = "stayer-rbr@acme.example";
  const LEAVER = "leaver-rbr@acme.example";
  const GROUPIE = "groupie-rbr@acme.example";

  try {
      ok("A1: a populated roster that does not carry the address refuses", classifyRosterMembership({ read: "ok", rosterSize: 4, targetPresent: false }) === "off-roster");
      ok("A2: a populated roster that carries it admits", classifyRosterMembership({ read: "ok", rosterSize: 4, targetPresent: true }) === "on-roster");
      ok("A3: a FAILED read is unreadable, never a departure", classifyRosterMembership({ read: "failed", rosterSize: 4, targetPresent: false }) === "unreadable");
      ok("A4: an EMPTY roster is unreadable, not 'everybody has left'", classifyRosterMembership({ read: "ok", rosterSize: 0, targetPresent: false }) === "unreadable");
      ok("A5: an uncomputable roster size is unreadable too", classifyRosterMembership({ read: "ok", rosterSize: Number.NaN, targetPresent: false }) === "unreadable");
      // The polarity guard itself. `verdict !== "on-roster"` is the same expression with the opposite safety
      // direction and would read as correct in review, so it is asserted rather than assumed.
      ok("A6: only off-roster refuses; unreadable admits", rosterRefusesEnrolment("off-roster") && !rosterRefusesEnrolment("unreadable") && !rosterRefusesEnrolment("on-roster"));

    // ===========================================================================================
    // SECTION B: THE LIVE DEFECT, REPRODUCED THEN CLOSED. Grant a role, delete it, and spend a
    // recovery code as the removed person.
    // ===========================================================================================
    {
      // A member who STAYS, so the roster is populated. Without this the account would be empty and the gate
      // would correctly stand down, which would make every refusal below vacuous.
      ok("B1: a staying member is granted a role", (await call(OWNER, "POST", "/admin/roles", { email: STAYER, role: "viewer" })).status === 200);
      // And a member who is granted a role and then removed: the offboarded person.
      ok("B2: the leaver is granted a role", (await call(OWNER, "POST", "/admin/roles", { email: LEAVER, role: "viewer" })).status === 200);

      const leaverCodes = await mintCodes(LEAVER);
      const stayerCodes = await mintCodes(STAYER);
      ok("B3: both hold a banked set of recovery codes", leaverCodes.length > 0 && stayerCodes.length > 0);

      ok("B4: the leaver is offboarded", ((await (await call(OWNER, "POST", "/admin/roles/delete", { email: LEAVER })).json()) as { deleted?: boolean }).deleted === true);
      // THE RESIDUE ITSELF, unchanged and deliberately not destroyed: deleteRole touches no factor store, so
      // the banked codes outlive the role row. If this ever flips, deleteRole has started revoking.
      ok("B5: THE RESIDUE: the removed person's recovery codes survive the offboard", ((await (await doFetch(`/recovery/remaining?email=${encodeURIComponent(LEAVER)}`, null, undefined, "GET")).json()) as { remaining: number }).remaining > 0);

      // ---- direction one: the removed person ----
      const spent = await spendCode(LEAVER, leaverCodes[0] ?? "");
      ok("B6: the removed person's code still SIGNS THEM IN (no lockout was invented)", spent.status === 200);
      const leaverCookie = cookieOf(spent);
      ok("B7: and a real session cookie was issued", typeof leaverCookie === "string" && (leaverCookie?.length ?? 0) > 0);
      const spentBody = (await spent.json()) as { role?: string; enrolPasskey?: boolean };
      ok("B8: the session resolves to viewer, conferring nothing the roster does not grant", spentBody.role === "viewer");
      ok("B9: THE FIX, part one: the console is NOT told to enrol a fresh passkey", spentBody.enrolPasskey === false);

      const refused = await beginRegister(LEAVER, leaverCookie);
      ok("B10: THE FIX, part two: the enrolment itself is refused, not merely un-prompted", refused.ok === false && refused.reason === "forbidden");
      ok("B11: and no credential was created for the removed address", store.keysWithPrefix(PASSKEY_CRED_PREFIX).every((k) => (store.rawGet<{ email?: string }>(k)?.email ?? "") !== LEAVER));

      // ---- direction two: a legitimate break-glass on a healthy account ----
      const good = await spendCode(STAYER, stayerCodes[0] ?? "");
      ok("B12: the staying member's break-glass sign-in still works", good.status === 200);
      const stayerCookie = cookieOf(good);
      ok("B13: and they ARE told to enrol a fresh passkey", ((await good.json()) as { enrolPasskey?: boolean }).enrolPasskey === true);
      const allowed = await beginRegister(STAYER, stayerCookie);
      ok("B14: and the enrolment is authorised, so the break-glass is intact end to end", allowed.ok === true);
    }

    // ===========================================================================================
    // SECTION C: the consumption racing a role deletion. THIS SECTION DOES NOT PROVE THE ROSTER GATE,
    // AND SAYING SO IS THE POINT. Something else already closes this race: deleteRole's session-epoch
    // bump. The racer's cookie is dead before the registration is even authorised, so the ceremony
    // never reaches the self-add arm. Labelling the assertion below as a proof of the roster gate would
    // be a check that cannot fail for the reason it claims.
    //
    // What it does establish, which is still worth holding: the race is closed, it is closed EARLIER
    // than the roster gate, and adding the gate did not weaken it.
    // ===========================================================================================
    {
      const RACER = "racer-rbr@acme.example";
      ok("C1: the racer is granted a role", (await call(OWNER, "POST", "/admin/roles", { email: RACER, role: "viewer" })).status === 200);
      const codes = await mintCodes(RACER);
      const spent = await spendCode(RACER, codes[0] ?? "");
      const cookie = cookieOf(spent);
      ok("C2: they consume a code while still on the roster, and are told to enrol", ((await spent.json()) as { enrolPasskey?: boolean }).enrolPasskey === true);

      // The deletion lands after the consumption and before the enrolment.
      ok("C3: the role is deleted in the window between the two requests", ((await (await call(OWNER, "POST", "/admin/roles/delete", { email: RACER })).json()) as { deleted?: boolean }).deleted === true);
      // The MECHANISM, asserted rather than assumed: deleteRole bumps the session epoch, so the cookie minted
      // moments earlier no longer authorises anything at all.
      const stale = await handleAdmin(
        new Request("https://engine.example/admin/whoami", { headers: { cookie: `${SESSION_COOKIE_NAME}=${cookie ?? ""}` } }),
        authEnv(),
      );
      ok("C4: the epoch bump has already killed the session the code minted", stale.status === 401 || stale.status === 403);
      const after = await beginRegister(RACER, cookie);
      ok("C5: so the enrolment is refused, by the epoch bump rather than by the roster gate", after.ok === false && after.reason === "forbidden");
    }

    // ===========================================================================================
    // SECTION D: THE FAIL-OPEN ARMS. Get these backwards and a customer is locked out of their own
    // account during an incident, which is the exact harm this work exists to avoid.
    // ===========================================================================================
    {
      // D-i: the roster read THROWS. The gate must stand down and admit.
      const FALLBACK = "fallback-rbr@acme.example";
      ok("D1: the fallback member is granted a role", (await call(OWNER, "POST", "/admin/roles", { email: FALLBACK, role: "viewer" })).status === 200);
      const codes = await mintCodes(FALLBACK);
      const cookie = cookieOf(await spendCode(FALLBACK, codes[0] ?? ""));

      // Break the roster's OWN two reads for the duration of one registration, and only those. Both are
      // unbounded lists under the `role:` prefix; the bootstrap precondition check that runs earlier in the
      // same ceremony is a list of ONE under the same prefix, so the limit discriminates them.
      //
      // The narrowing is not convenience. Failing every `role:` read takes the whole registration ceremony
      // down at roleTableIsEmpty, well before the roster gate is consulted, and a refusal observed that way
      // would say nothing about the gate's direction. Scoping the fault to the deciding reads is what makes
      // this an actual test of the fail-open arm rather than of the ceremony's pre-existing behaviour under a
      // dead role table.
      const realList = store.list.bind(store);
      let thrown = 0;
      (store as unknown as { list: unknown }).list = async (opts?: { prefix?: string; limit?: number }): Promise<unknown> => {
        if (typeof opts?.prefix === "string" && opts.prefix.startsWith("role:") && opts.limit === undefined) {
          thrown++;
          throw new Error("simulated storage fault on the role table");
        }
        return realList(opts as never);
      };
      const degraded = await beginRegister(FALLBACK, cookie);
      (store as unknown as { list: unknown }).list = realList;
      ok("D2: the roster read really did fail during that registration", thrown > 0);
      ok("D3: FAIL OPEN: an unreadable roster ADMITS the enrolment, it does not refuse it", degraded.ok === true);

      // D-ii: a roster that reads EMPTY. Proved on the verdict rather than through the ceremony, because an
      // empty role table is also the bootstrap precondition and bootstrap returns before self-add is reached,
      // so a ceremony drive could not tell the two apart.
      ok("D4: an empty roster classifies as unreadable, so the gate stands down", classifyRosterMembership({ read: "ok", rosterSize: 0, targetPresent: false }) === "unreadable" && !rosterRefusesEnrolment("unreadable"));
    }

    // ===========================================================================================
    // SECTION E: the scope. An IdP GROUP-MAPPED member legitimately holds authority with NO role
    // row, and the engine holds the mapping but never the membership, so the roster set cannot see
    // them. They must not be caught by this gate.
    // ===========================================================================================
    {
      const before = store.keysWithPrefix(PASSKEY_CRED_PREFIX).length;
      // An Access caller with no role row at all. This is the shape a group-mapped member arrives in.
      const r = await call(GROUPIE, "POST", "/admin/auth/register/begin", { email: GROUPIE, displayName: GROUPIE });
      const body = (await r.json()) as { ok?: boolean; reason?: string };
      ok("E1: an ACCESS caller with no role row is not refused by the roster gate", body.reason !== "forbidden");
      ok("E2: and nothing was created as a side effect of asking", store.keysWithPrefix(PASSKEY_CRED_PREFIX).length === before);
    }
    // ===========================================================================================
    // SECTION H: THE INVITE ARM, the second way past the same gate.
    //
    // Sections A to E stated openly that the invite arm was not gated rather
    // than assuming it closed, and that turned out to be right. resolveRegistrationAuthorisation evaluates the
    // invite arm BEFORE the self-add arm and RETURNS from it, so presenting any valid inviteToken
    // left the function without the roster gate ever being evaluated.
    //
    // An invite is minted at the commit point of setRole, its only producer, and lives under
    // `passkeyInvite:<token>` for seven days. deleteRole removes the bound role row and every
    // pending row and says in its own comment that it does so "so an offboarded person cannot
    // rebind a lingering pending invite on a later login" -- but the registration invite is keyed
    // by TOKEN, and an email-keyed delete cannot reach it even in principle. The SCIM leaver path
    // posts only /roles/delete. So a removed address kept an unauthenticated route to a standing
    // credential, and to a fresh set of never-expiring recovery codes, for up to a week.
    //
    // Driven end to end through the production route, unauthenticated, exactly as the link in the
    // invitation email arrives. H2 is a positive control: the same redemption on a member the
    // roster still carries must keep working, or the refusal below proves only that invites broke.
    // ===========================================================================================
    {
      const INVITED = "invited-rbr@acme.example";
      const OPENROSTER = "invited-failopen-rbr@acme.example";

      // The token is read out of storage rather than out of a response, because the engine never
      // returns it to a caller: it goes straight into the invitation email's registration link.
      const inviteTokenFor = (email: string): string | null => {
        for (const k of store.keysWithPrefix(PASSKEY_INVITE_PREFIX)) {
          if ((store.rawGet<{ email?: string }>(k)?.email ?? "") === email) return k.slice(PASSKEY_INVITE_PREFIX.length);
        }
        return null;
      };

      // Redeem an invite the way the link does: unauthenticated, no cookie, no bearer, the token in
      // the body. begin rather than finish, because begin is where authorisation is decided and the
      // peek there does not burn the invite, so the same token can be driven twice.
      const redeem = async (email: string, token: string): Promise<{ status: number; ok?: boolean; reason?: string }> => {
        const r = await handleAdmin(
          new Request("https://engine.example/admin/auth/register/begin", {
            method: "POST",
            headers: { "content-type": "application/json", origin: ORIGIN },
            body: JSON.stringify({ email, displayName: email, inviteToken: token }),
          }),
          authEnv(),
        );
        const body = (await r.json()) as { ok?: boolean; reason?: string };
        return { status: r.status, ...body };
      };

      ok("H1: granting a role to an unenrolled address is accepted", (await call(OWNER, "POST", "/admin/roles", { email: INVITED, role: "viewer" })).status === 200);
      const token = inviteTokenFor(INVITED) ?? "";
      ok("H2a: and it minted a registration invite bound to that address", token.length > 0);
      ok("H2b: POSITIVE CONTROL: the invite redeems while the roster still accounts for them", (await redeem(INVITED, token)).ok === true);

      ok("H3: the invitee is offboarded before they ever enrolled", ((await (await call(OWNER, "POST", "/admin/roles/delete", { email: INVITED })).json()) as { deleted?: boolean }).deleted === true);
      ok("H4: they are gone from the roster the gate reads", !((await (await call(OWNER, "GET", "/admin/roles")).text()).includes(INVITED)));
      // THE RESIDUE ITSELF. If this ever flips, deleteRole has started sweeping invites and section H
      // is testing a case that can no longer arise, which is worth knowing rather than passing quietly.
      ok("H5: THE RESIDUE: the invite is keyed by token, so the offboard cannot reach it and it survives", inviteTokenFor(INVITED) === token);

      const after = await redeem(INVITED, token);
      ok("H6: THE FIX: redeeming the surviving invite is refused", after.ok === false && after.reason === "forbidden");
      ok("H7: and no credential was created for the removed address", store.keysWithPrefix(PASSKEY_CRED_PREFIX).every((k) => (store.rawGet<{ email?: string }>(k)?.email ?? "") !== INVITED));
      // The fault has to be its own kind. `passkey-invite-invalid` would send support the wrong way:
      // the token is genuine and unexpired, and "ask them to resend the link" is the one answer that
      // cannot work, because a resend mints another invite for an address that is still off-roster.
      const faults = store.rawGet<Record<string, { count?: number }>>("diag:ceremonyfaults") ?? {};
      ok("H8: the refusal is filed as a ROSTER fault, not as a bad link", (faults["passkey-invite-off-roster"]?.count ?? 0) > 0);

      // FAIL OPEN on this arm too, by the same mechanism section D uses on the self-add arm: break
      // only the roster's own two unbounded `role:` list reads for the duration of one redemption.
      // An off-roster invitee whose roster cannot be read must be ADMITTED, or an estate whose role
      // table is failing to populate refuses every invitation it has outstanding.
      ok("H9: a second invitee is granted a role", (await call(OWNER, "POST", "/admin/roles", { email: OPENROSTER, role: "viewer" })).status === 200);
      const token2 = inviteTokenFor(OPENROSTER) ?? "";
      ok("H10: and they too are offboarded with the invite still live", ((await (await call(OWNER, "POST", "/admin/roles/delete", { email: OPENROSTER })).json()) as { deleted?: boolean }).deleted === true && inviteTokenFor(OPENROSTER) === token2);
      const realList2 = store.list.bind(store);
      let thrown2 = 0;
      (store as unknown as { list: unknown }).list = async (opts?: { prefix?: string; limit?: number }): Promise<unknown> => {
        if (typeof opts?.prefix === "string" && opts.prefix.startsWith("role:") && opts.limit === undefined) {
          thrown2++;
          throw new Error("simulated storage fault on the role table");
        }
        return realList2(opts as never);
      };
      const degraded = await redeem(OPENROSTER, token2);
      (store as unknown as { list: unknown }).list = realList2;
      ok("H11: the roster read really did fail during that redemption", thrown2 > 0);
      ok("H12: FAIL OPEN: an unreadable roster ADMITS the redemption of an off-roster invite", degraded.ok === true);
    }

      ok("F1: the one-credential delete is step-up gated", STEPUP_SUBS.has("/passkey/credentials/delete"));
      ok("F2: THE FIX: the every-factor revoke is step-up gated too", STEPUP_SUBS.has("/signin-factors/revoke"));
      // A positive control on the test itself: the Set really can answer false, so F1/F2 are not vacuous.
      ok("F3: and the membership test can still answer no", !STEPUP_SUBS.has("/signin-factors"));

    // ===========================================================================================
    // SECTION G: self-revocation. The route's own comment argued this was refused; it was not.
    // ===========================================================================================
    {
      const r = await call(OWNER, "POST", "/admin/signin-factors/revoke", { email: OWNER });
      ok("G1: revoking your own every sign-in factor is refused", r.status === 400);
      const err = ((await r.json()) as { error?: string }).error ?? "";
      // The sole Owner here is refused by the availability floor, whose sentence names the repair. Either
      // refusal is correct; what must never happen is a 200.
      ok("G2: and the refusal explains itself rather than being a bare error", err.length > 20);
      ok("G3: the Owner's own credentials are untouched", store.keysWithPrefix(PASSKEY_CRED_PREFIX).every((k) => (store.rawGet<{ email?: string }>(k)?.email ?? "") !== OWNER));

      // G1 above passes on the tree WITHOUT the self guard, because the sole Owner is caught by the
      // availability floor first. So the guard itself is proved where the floor cannot reach: a SECOND Owner
      // exists, the tally is fine, and the only thing standing between this caller and a total self-lockout is
      // the self test.
      ok("G4: a second Owner is appointed, so the availability floor no longer bites", (await call(OWNER, "POST", "/admin/roles", { email: ctx.OWNER2, role: "owner" })).status === 200);
      const self = await call(ctx.OWNER2, "POST", "/admin/signin-factors/revoke", { email: ctx.OWNER2 });
      ok("G5: THE FIX: a non-sole Owner revoking their OWN factors is refused", self.status === 400);
      const selfErr = ((await self.json()) as { error?: string }).error ?? "";
      ok("G6: and the refusal names the self-lockout and the two routes that do the legitimate jobs", /your OWN/.test(selfErr) && /regenerate/.test(selfErr));
    }

    // ===========================================================================================
    // SECTION J: THE REGENERATE ROUTE, the third way past the same gate and the shortest of the three.
    //
    // Sections B and H close the CONVERSION of a spent code into a standing passkey, at both arms of
    // resolveRegistrationAuthorisation. But a passkey is not the only standing credential a recovery
    // sign-in can mint. POST /admin/auth/recovery-codes/regenerate mints a FRESH SET of codes that,
    // by the deliberate design this work is built on, never expire, and it reads no roster at all.
    //
    // Its gate is authenticated + carries a verified email + CSRF + step-up, and every one of those is
    // satisfied by the very session the spent code just minted: it is method "passkey" with the
    // consumed email's subject, so it is indistinguishable from an authenticator's session at exactly
    // the point that matters, and handleRegenerate's own comment records that a recovery sign-in is
    // recent enough to clear the step-up. So the removed person spends one code, is refused a passkey
    // by the section B gate, and on the very next request banks a fresh set of the same one-time
    // secret. That is the sentence the section B fix uses for what it closes, reached by a shorter
    // route, and the residue it leaves is worse: an unbounded supply with no expiry.
    //
    // SCOPED TO THE PASSKEY METHOD, for the identical reason the self-add arm is. A member whose
    // authority comes only from an IdP group claim has no role row, arrives as "access"/oidc/saml, and
    // must keep their own regenerate. J5 is that direction, and it goes red under the tempting
    // unscoped fix.
    // ===========================================================================================
    {
      const LEAVER2 = "leaver2-rbr@acme.example";
      // Regenerate exactly as the console does: the production router route, carrying the session
      // cookie the spent code minted, with a same-origin Origin so the CSRF check passes.
      const regenerate = async (cookie: string | null): Promise<{ status: number; codes: string[] | undefined }> => {
        const r = await handleAdmin(
          new Request("https://engine.example/admin/auth/recovery-codes/regenerate", {
            method: "POST",
            headers: { "content-type": "application/json", origin: ORIGIN, ...(cookie !== null ? { cookie: `${SESSION_COOKIE_NAME}=${cookie}` } : {}) },
            body: JSON.stringify({}),
          }),
          authEnv(),
        );
        const body = (await r.json()) as { recoveryCodes?: string[] };
        return { status: r.status, codes: body.recoveryCodes };
      };
      const remainingFor = async (email: string): Promise<number> =>
        ((await (await doFetch(`/recovery/remaining?email=${encodeURIComponent(email)}`, null, undefined, "GET")).json()) as { remaining: number }).remaining;

      ok("J1: the leaver is granted a role and banks a set", (await call(OWNER, "POST", "/admin/roles", { email: LEAVER2, role: "viewer" })).status === 200);
      const banked = await mintCodes(LEAVER2);
      ok("J2: the leaver is offboarded", ((await (await call(OWNER, "POST", "/admin/roles/delete", { email: LEAVER2 })).json()) as { deleted?: boolean }).deleted === true);
      const spent = await spendCode(LEAVER2, banked[0] ?? "");
      const leaverCookie = cookieOf(spent);
      ok("J3: the removed person's code signs them in, as section B requires (no lockout invented)", spent.status === 200 && typeof leaverCookie === "string");
      const beforeRemaining = await remainingFor(LEAVER2);

      const regen = await regenerate(leaverCookie);
      ok("J4: THE CLAIM UNDER TEST: an OFF-ROSTER session cannot mint a fresh set of never-expiring codes", regen.status === 403);
      ok("J4: THE ASSERTION THAT MATTERS: no plaintext set was returned to them", regen.codes === undefined);
      // The write assertion, because a status-only proof passes a build that refuses and mints anyway.
      // A successful regenerate replaces the record with a FULL set, so the count would jump back up.
      ok("J4: and no new set was banked (the count did not go back up)", (await remainingFor(LEAVER2)) <= beforeRemaining);

      // ---- the two directions the refusal must NOT catch ----
      // J5: a member the roster still carries regenerates normally, or this proves only that the route
      // broke. STAYER spent one code in section B and is still on the roster.
      const stayerCodes = await mintCodes(STAYER);
      const stayerSpent = await spendCode(STAYER, stayerCodes[0] ?? "");
      const stayerRegen = await regenerate(cookieOf(stayerSpent));
      ok("J5: NO LOCKOUT: a member the roster still carries regenerates their own set (200)", stayerRegen.status === 200);
      ok("J5: and they really got a fresh plaintext set back", Array.isArray(stayerRegen.codes) && (stayerRegen.codes?.length ?? 0) > 0);

      // J6: the group-mapped shape, the false-positive direction. An Access caller with no role row is
      // exactly how a member whose authority comes from an IdP group claim arrives, and the roster set
      // cannot see them. An unscoped refusal strands them; this must resolve on its own merits.
      const groupieRegen = await handleAdmin(
        new Request("https://engine.example/admin/auth/recovery-codes/regenerate", {
          method: "POST",
          headers: { "content-type": "application/json", origin: ORIGIN, "cf-access-jwt-assertion": "" },
          body: JSON.stringify({}),
        }),
        authEnv(),
      );
      ok("J6: an emailless/unauthenticated caller is refused for its own reason, not the roster's", groupieRegen.status === 401 || groupieRegen.status === 403);
      const groupieScoped = await call(GROUPIE, "POST", "/admin/auth/recovery-codes/regenerate", {});
      ok("J6: NO STRANDING: an ACCESS caller with no role row is NOT refused by the roster gate", groupieScoped.status === 200);
    }
  } finally {
    globalThis.fetch = ctx.realFetch;
  }

  // Both arguments, deliberately: called bare the guard reads failures as undefined and prints its own
  // VERDICT: FAIL beside this file's line, which is the "printed a verdict that means nothing" shape it
  // exists to catch. The check count rides too, so a run that asserted nothing cannot report a pass.
  if (failures > 0) process.exitCode = 1;
  console.log(`\nVERDICT: ${failures === 0 ? "PASS" : "FAIL"} failures=${failures} checks=${checks} entry=${import.meta.url.replace("file://", "")}`);
  if (failures > 0) process.exit(1);
}

await main();
