// validate-cov-sched-scheduler-do-signin-factors: a focused validator for SignInFactorsMixin
// (src/sched/scheduler-do-signin-factors.ts), the union read over the three sign-in stores and the REVOKE
// that clears them.
//
// THE HEADLINE PROOF (SECTION B) IS A REGRESSION TEST FOR A DEFECT THAT WAS DEMONSTRATED LIVE, not a
// hypothetical. On a real estate an operator granted a role, deleted it, and the removed person's registration
// invite still produced an authorisation yes. That happened because deleteRole removes the role row and
// touches none of the three stores a person actually signs in with, and because two of those stores had no
// delete anywhere in the engine to call. Section B walks exactly that sequence and asserts BOTH halves: that
// the way in survives the role deletion (so the test still describes the real system), and that the revoke
// closes it.
//
// It drives the REAL Durable Object through the production router (handleAdmin) for the grant, the offboard
// and the revoke, and seeds the credential and recovery stores directly (those records are otherwise minted
// only by a full WebAuthn ceremony, which needs an authenticator). Every assertion checks a real outcome: an
// HTTP status, a record read back out of storage, an audited effect, or a returned body field.
//
// Run: node test/validate-cov-sched-scheduler-do-signin-factors.ts

import { buildContext } from "./validate-owner-action-dualcontrol-harness.ts";
import { ROLE_SUBJECT_PREFIX, SCIM_OFFBOARD_EMAIL, SCIM_OFFBOARD_SUBJECT } from "../src/admin/identity.ts";
import { PASSKEY_CRED_PREFIX, PASSKEY_INVITE_PREFIX, RECOVERY_PREFIX, SESSION_EPOCH_PREFIX } from "../src/sched/scheduler-do-base.ts";
import type { SignInFactorRow } from "../src/admin/signin-factors.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

interface RevokeBody {
  email: string;
  revoked: { passkeyCredentials: number; recovery: boolean; invitesLive: number; invitesExpired: number };
  sessionsTerminated: boolean;
}

const DAY_MS = 24 * 60 * 60 * 1000;

async function main(): Promise<void> {
  const ctx = await buildContext();
  const { sched, OWNER, call, readLog } = ctx;
  const store = sched.storage;

  const ALICE = "alice-sf@acme.example";
  const BOB = "bob-sf@acme.example";
  const CAROL = "carol-sf@acme.example";
  const STRANGER = "nobody-sf@acme.example";

  // Read one email's row out of the union read. A NAMED email always comes back as a row, so an absent row is
  // itself a failure rather than a silent zero.
  const rowFor = async (email: string): Promise<SignInFactorRow | undefined> => {
    const r = await call(OWNER, "GET", `/admin/signin-factors?email=${encodeURIComponent(email)}`);
    const body = (await r.json()) as { factors?: SignInFactorRow[] };
    return body.factors?.[0];
  };
  const revoke = async (email: unknown): Promise<Response> => call(OWNER, "POST", "/admin/signin-factors/revoke", { email });
  const seedCred = (email: string, id: string): void => {
    store.rawPut(`${PASSKEY_CRED_PREFIX}${id}`, {
      credentialId: id, email, cosePublicKey: "AA", alg: -7, signCount: 0,
      transports: ["internal"], aaguid: "AAAAAAAAAAAAAAAAAAAAAA", createdAt: new Date().toISOString(),
    });
  };
  const seedInvite = (email: string, token: string, expiresAt: number): void => {
    store.rawPut(`${PASSKEY_INVITE_PREFIX}${token}`, { email, createdAt: Date.now(), expiresAt });
  };

  // SCIM-REVOKE: THE UNATTENDED-OWNER SKIP, proven both ways.
  //
  // The guard exists because a connector misfire is indistinguishable from a real departure at the moment it
  // arrives, and recovery codes cannot be re-derived. It DECLINES rather than refuses, deliberately: the SCIM
  // facade issues this revoke BEFORE /roles/delete, so a throw here would abort the whole offboard and leave a
  // departed Owner holding their role, their authority and every factor.
  const scimSkipProof = async (): Promise<void> => {
    const OWNER_EMAIL = "owner-scim-skip@acme.example";
    // The target is an Owner with real factors, so a skip that did nothing would be indistinguishable from a
    // revoke that found nothing. Seeding both means the assertion has something to fail on.
    store.rawPut(`${ROLE_SUBJECT_PREFIX}sub-${OWNER_EMAIL}`, { email: OWNER_EMAIL, role: "owner", subject: `sub-${OWNER_EMAIL}`, grantedAt: new Date().toISOString() });
    seedCred(OWNER_EMAIL, "cred-scim-skip");
    seedInvite(OWNER_EMAIL, "tok-scim-skip", Date.now() + 86_400_000);

    const scimCaller = { method: "token" as const, email: SCIM_OFFBOARD_EMAIL, subject: SCIM_OFFBOARD_SUBJECT, groups: [], sourceIp: null };
    const out = await sched.dobj.revokeSignInFactors({ email: OWNER_EMAIL }, scimCaller);
    ok("SCIM caller + Owner target: the destructive half is DECLINED, not refused", out.declined === "unattended-owner");
    ok("SCIM caller + Owner target: nothing was revoked", out.revoked.passkeyCredentials === 0 && out.revoked.recovery === false && out.revoked.invitesLive === 0);
    ok("SCIM caller + Owner target: no session was terminated", out.sessionsTerminated === false);
    // The teeth: the factors must still BE there. A skip that returned zeros while deleting anyway would pass
    // every assertion above.
    ok("SCIM caller + Owner target: the credential still exists", (await store.rawGet(`${PASSKEY_CRED_PREFIX}cred-scim-skip`)) !== undefined);
    ok("SCIM caller + Owner target: the live invite still exists", (await store.rawGet(`${PASSKEY_INVITE_PREFIX}tok-scim-skip`)) !== undefined);

    // NEGATIVE CONTROL, which is what stops this from being a rule that fires for everyone. A HUMAN owner
    // caller against the same target must NOT be declined: it goes to the ordinary Owner floor instead.
    let humanDeclined = false;
    try {
      const human = await sched.dobj.revokeSignInFactors({ email: OWNER_EMAIL }, { method: "access" as const, email: "real-owner@acme.example", subject: "sub-real-owner", groups: [], sourceIp: null });
      humanDeclined = human.declined === "unattended-owner";
    } catch {
      humanDeclined = false; // a throw is the Owner floor, which is the point: not the skip
    }
    ok("negative control: a HUMAN caller is never declined by the unattended-owner skip", humanDeclined === false);

    // CLEAN UP THE SEED. This proof needs a SECOND Owner to exist, and the later sole-Owner proofs in this file
    // assert the refusal names "the only Owner". Leaving this row behind silently turned that refusal into the
    // dual-control one and failed a check that had nothing to do with this change. Shared fixtures are shared.
    await store.delete(`${ROLE_SUBJECT_PREFIX}sub-${OWNER_EMAIL}`);
    await store.delete(`${PASSKEY_CRED_PREFIX}cred-scim-skip`);
    await store.delete(`${PASSKEY_INVITE_PREFIX}tok-scim-skip`);
  };

  try {
    await scimSkipProof();
    // ===========================================================================================
    // SECTION A: the revoke clears all three stores at once, and the read agrees it did.
    // ===========================================================================================
    {
      seedCred(BOB, "cred-bob-1");
      seedCred(BOB, "cred-bob-2");
      store.rawPut(`${RECOVERY_PREFIX}${BOB}`, { generatedAt: new Date().toISOString(), codes: [{ hash: "x", consumedAt: null }] });
      seedInvite(BOB, "tok-bob-live", Date.now() + 3 * DAY_MS);

      const before = await rowFor(BOB);
      ok("A1: a seeded member reads as able to sign in", before?.signIn === "can-sign-in");
      ok("A2: the read sees both credentials and the live invite", before?.passkey.credentials === 2 && before?.invites.live === 1);

      const r = await revoke(BOB);
      ok("A3: the revoke is accepted (200)", r.status === 200);
      const body = (await r.json()) as RevokeBody;
      ok("A4: it reports both credentials removed", body.revoked.passkeyCredentials === 2);
      ok("A5: it reports the recovery record removed", body.revoked.recovery === true);
      ok("A6: it reports the live invite removed", body.revoked.invitesLive === 1);
      ok("A7: it reports that sessions were terminated", body.sessionsTerminated === true);

      // Storage, not just the response body: the records are actually gone.
      ok("A8: no credential record survives", store.keysWithPrefix(`${PASSKEY_CRED_PREFIX}cred-bob-`).length === 0);
      ok("A9: no recovery record survives", store.rawGet(`${RECOVERY_PREFIX}${BOB}`) === undefined);
      ok("A10: no invite record survives", store.rawGet(`${PASSKEY_INVITE_PREFIX}tok-bob-live`) === undefined);

      const after = await rowFor(BOB);
      ok("A11: the union read now says no factor", after?.signIn === "no-factor");
      ok("A12: and it names no path at all", (after?.paths ?? ["x"]).length === 0);

      const log = await readLog();
      ok("A13: the act is in the tamper-evident trail", log.events.some((e) => e.action === "signin-factor-revoke"));
    }

    // ===========================================================================================
    // SECTION B: THE LIVE DEFECT, REPRODUCED THEN CLOSED. Grant, offboard, and confirm the removed
    // person could still sign in; then revoke and confirm they cannot.
    // ===========================================================================================
    {
      const grant = await call(OWNER, "POST", "/admin/roles", { email: ALICE, role: "viewer" });
      ok("B1: the grant is accepted", grant.status === 200);
      const inviteToken = ((await grant.json()) as { inviteToken?: string }).inviteToken;
      ok("B2: granting a role to an un-enrolled address mints a registration invite", typeof inviteToken === "string" && inviteToken.length > 0);

      const del = await call(OWNER, "POST", "/admin/roles/delete", { email: ALICE });
      ok("B3: the offboard reports the member deleted", ((await del.json()) as { deleted?: boolean }).deleted === true);
      const roster = (await (await call(OWNER, "GET", "/admin/roles")).json()) as Array<{ email: string }>;
      ok("B4: the roster no longer names them", !roster.some((e) => e.email === ALICE));

      // THE DEFECT ITSELF. The role row is gone and the invite is untouched, so the person the operator
      // believes they have offboarded still holds a way in. If this assertion ever flips, deleteRole has
      // started revoking and the argument in revokeSignInFactors needs revisiting deliberately.
      const orphaned = await rowFor(ALICE);
      ok("B5: THE DEFECT: after deleteRole the removed person can still sign in", orphaned?.signIn === "can-sign-in");
      ok("B6: and the surviving way in is the registration invite", (orphaned?.paths ?? []).includes("registration-invite"));
      ok("B7: while the roster no longer accounts for them", orphaned?.hasRoleEntry === false);

      const body = (await (await revoke(ALICE)).json()) as RevokeBody;
      ok("B8: the revoke closes the surviving invite", body.revoked.invitesLive === 1);
      const closed = await rowFor(ALICE);
      ok("B9: THE FIX: the removed person can no longer sign in", closed?.signIn === "no-factor");
      ok("B10: and the invite record is gone from storage", closed?.invites.live === 0 && closed?.invites.expired === 0);
    }

    // ===========================================================================================
    // SECTION C: the epoch bump is scoped to a REAL revocation. Sweeping dead records, or finding
    // nothing at all, must not sign anybody out.
    // ===========================================================================================
    {
      const epochBefore = store.rawGet(`${SESSION_EPOCH_PREFIX}${CAROL}`);
      seedInvite(CAROL, "tok-carol-dead-1", Date.now() - 5 * DAY_MS);
      seedInvite(CAROL, "tok-carol-dead-2", Date.now() - 9 * DAY_MS);

      const body = (await (await revoke(CAROL)).json()) as RevokeBody;
      ok("C1: expired invites are swept for the named email", body.revoked.invitesExpired === 2);
      ok("C2: and they are NOT counted as ways in that were closed", body.revoked.invitesLive === 0);
      ok("C3: sweeping only dead records does not terminate sessions", body.sessionsTerminated === false);
      ok("C4: so the session epoch is left exactly as it was", store.rawGet(`${SESSION_EPOCH_PREFIX}${CAROL}`) === epochBefore);
      ok("C5: the dead records are nonetheless gone", store.keysWithPrefix(`${PASSKEY_INVITE_PREFIX}tok-carol-`).length === 0);

      const none = (await (await revoke(STRANGER)).json()) as RevokeBody;
      ok("C6: revoking an address with nothing is a clean no-op", none.revoked.passkeyCredentials === 0 && none.revoked.recovery === false && none.revoked.invitesLive === 0);
      ok("C7: and it terminates no sessions", none.sessionsTerminated === false);
      ok("C8: an unusable address is refused, never widened to the account", (await revoke("not-an-address")).status === 400);
      ok("C9: a missing address is refused too", (await revoke(undefined)).status === 400);
    }

    // ===========================================================================================
    // SECTION D: the availability guard. Stripping every factor from the only Owner would lock the
    // account out permanently, so it is refused.
    // ===========================================================================================
    {
      const r = await revoke(OWNER);
      ok("D1: revoking the sole Owner's every sign-in factor is refused", r.status === 400);
      const err = ((await r.json()) as { error?: string }).error ?? "";
      ok("D2: and the refusal explains it is the only Owner, not a demotion", /only Owner/i.test(err) && !/demot/i.test(err));
    }

    // ===========================================================================================
    // SECTION E: the dead-guard fix. An email whose ONLY roster presence is an EXPIRED pending
    // invite must not read as accounted for. The guard that was supposed to do this compared a
    // string-union role against null and could never fire.
    // ===========================================================================================
    {
      const LAPSED = "lapsed-sf@acme.example";
      await call(OWNER, "POST", "/admin/roles", { email: LAPSED, role: "viewer", expiresAt: new Date(Date.now() - DAY_MS).toISOString() });
      seedCred(LAPSED, "cred-lapsed-1");
      const row = await rowFor(LAPSED);
      ok("E1: an expired grant does not make leftover residue look accounted for", row?.hasRoleEntry === false);
    }
  } finally {
    globalThis.fetch = ctx.realFetch;
  }

  // Both arguments, deliberately. Called bare, the guard reads failures as undefined and prints its own
  // VERDICT: FAIL line next to this file's VERDICT: PASS, which is the exact "printed a verdict that means
  // nothing" shape it exists to catch. The check count is passed too so a run that asserted nothing cannot
  // report a pass.
  if (failures > 0) process.exitCode = 1;
  console.log(`\nVERDICT: ${failures === 0 ? "PASS" : "FAIL"} failures=${failures} checks=${checks} entry=${import.meta.url.replace("file://", "")}`);
  if (failures > 0) process.exit(1);
}

await main();
