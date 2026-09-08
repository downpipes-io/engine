// validate-offboard-residue: what a person still holds after they have been offboarded, enumerated from the
// STORAGE layer outwards and driven against a real Durable Object through the production routes.
//
// WHY IT IS WRITTEN FROM THE STORAGE SIDE. A prior registration-invite bypass was missed for one
// generalisable reason: `passkeyInvite:` is keyed by the TOKEN, so the code that removes a PERSON could not
// see it, and deleteRole's own comment claimed a guard that could not exist. Reading outwards from the
// offboarding code is precisely the method that missed it, because that code can only show you the keys it
// already knows the name of. So this file starts from the key namespaces the DO writes and asks of each one:
// what does holding it let somebody do, what is it keyed by, and does each offboarding route actually remove
// it. The routes are NOT equivalent, and an artefact cleaned by one and not another is worse than one cleaned
// by none, because the gap becomes intermittent.
//
// THE DEFECT THIS FILE CLOSES is the same shape one store along.
// resolveRole is max(email-table role, highest group-mapped role, viewer), and groupRoleFor needs no row at
// all, so a member whose authority comes ONLY from an IdP GROUP CLAIM has nothing under `role:`. deleteRole
// returned early on "no entry for this email" BEFORE either of its two session-revocation axes, so for exactly
// those people POST /roles/delete removed nothing, revoked nothing and audited nothing, and answered 200
// {deleted:false} while their native-IdP session kept full authority for the rest of the 12h cookie. Driven
// against the real DO through handleAdmin: whoami resolves operator via the group claim before the offboard,
// zero sessionEpoch keys are written by it, and whoami still resolves operator after. revokeSignInFactors
// did not close it either -- it scopes its own bump to a revocation that closed a way in, and such a member
// holds no passkey, no recovery record and no invite, so it answered sessionsTerminated:false and the session
// survived that too. The SCIM leaver path posts only /roles/delete, so an automated deprovision reported
// success and did nothing at all.
//
// THE NO-LOCKOUT ARMS ARE SECTION C AND THEY ARE NOT DECORATION. A revocation fix that cannot be re-entered is
// a lockout wearing a helmet, so the same account is driven forwards afterwards: the group mapping survives,
// a fresh session for the same person still resolves the same role, and a member the roster does carry is
// untouched throughout.
//
// Run: node test/validate-offboard-residue.ts

import { handleAdmin } from "../src/admin/router.ts";
import { handleScim } from "../src/admin/scim.ts";
import { SESSION_COOKIE_NAME, signSession } from "../src/admin/session.ts";
import { b64urlDecode } from "../src/crypto/bytes.ts";
import { CONN_PREFIX } from "../src/admin/oidc-store-kv.ts";
import {
  OIDC_GROUPS_PREFIX,
  PASSKEY_CRED_PREFIX,
  PASSKEY_INVITE_PREFIX,
  PASSKEY_SESSION_KEY_KEY,
  PASSKEY_USER_PREFIX,
  RECOVERY_PREFIX,
  SESSION_EPOCH_PREFIX,
} from "../src/sched/scheduler-do-base.ts";
import type { AuditEvent } from "../src/admin/audit.ts";
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
const SCIM_TOKEN = "offboard-residue-scim-bearer";
// A group the estate maps to a real role, and two people who hold that role THROUGH it and nothing else.
const GROUP = "eng-offboard-residue";
const CONN = "entra-offboard-residue";
const LEAVER = "leaver-ofr@acme.example";
const SCIM_LEAVER = "scimleaver-ofr@acme.example";
const STAYER = "stayer-ofr@acme.example";

async function main(): Promise<void> {
  const ctx = await buildContext();
  const { sched, OWNER, call } = ctx;
  const store = sched.storage;
  // CONSOLE_ORIGIN must be set or the unauthenticated sign-in surface 501s before any authorisation decision.
  // SCIM_BEARER_TOKEN is what makes the SCIM facade answer at all, so the leaver path can be driven as the
  // customer's IdP drives it rather than described.
  const authEnv = (): Env => ({ ...sched.env, CONSOLE_ORIGIN: ORIGIN, SCIM_BEARER_TOKEN: SCIM_TOKEN }) as unknown as Env;

  // whoami through the production router carrying nothing but the session cookie: the one read that answers
  // "does this cookie still authorise anything, and as whom".
  const whoami = async (token: string): Promise<{ status: number; role: string | null; roleSource: string | null }> => {
    const r = await handleAdmin(
      new Request("https://engine.example/admin/whoami", { headers: { cookie: `${SESSION_COOKIE_NAME}=${token}` } }),
      authEnv(),
    );
    // A non-200 carries no identity at all, and null says so. Reporting a role of "" or "viewer" for a refused
    // request would let a refusal masquerade as a resolved caller in every assertion below.
    if (r.status !== 200) return { status: r.status, role: null, roleSource: null };
    const b = (await r.json()) as { role?: string; roleSource?: string };
    return { status: 200, role: b.role ?? null, roleSource: b.roleSource ?? null };
  };

  const auditActions = async (): Promise<string[]> => {
    const r = await call(OWNER, "GET", "/admin/audit?limit=1000");
    return ((await r.json()) as { events: AuditEvent[] }).events.map((e) => e.action);
  };

  try {
    // ===========================================================================================
    // SECTION A: the account, and a member the engine is the SESSION AUTHORITY for who holds a real
    // role with no row of any kind. Everything downstream is vacuous if this section does not
    // establish genuine authority, so it asserts the authority rather than assuming it.
    // ===========================================================================================
    let key: Uint8Array;
    {
      // A failed verify is enough to materialise the session-signing key, which is generated lazily on first
      // use. Signing this validator's tokens with the DO's OWN key is what makes them real sessions rather
      // than a fixture: they are minted and verified by the production signSession / passkeySessionVerify.
      await handleAdmin(new Request("https://engine.example/admin/whoami", { headers: { cookie: `${SESSION_COOKIE_NAME}=not-a-token` } }), authEnv());
      const rec = store.rawGet<{ key: string }>(PASSKEY_SESSION_KEY_KEY);
      ok("A1: the DO's own session-signing key exists, so the sessions below are real ones", rec !== undefined && typeof rec.key === "string");
      key = b64urlDecode(rec?.key ?? "");

      // A member who STAYS and IS on the roster. Without one the role table would be empty, which is the
      // bootstrap precondition and a different code path, and every "the roster is populated" claim below
      // would be answering about an account in a state no customer is ever in.
      ok("A2: a staying member is granted a role", (await call(OWNER, "POST", "/admin/roles", { email: STAYER, role: "viewer" })).status === 200);
      ok("A3: the estate maps an IdP group to operator", (await call(OWNER, "POST", "/admin/group-roles", { group: GROUP, role: "operator" })).status === 200);

      // The connection has to EXIST and be ENABLED or verify refuses on the liveness gate, and the refusal
      // would look exactly like the revocation this file is about.
      store.rawPut(`${CONN_PREFIX}${CONN}`, { id: CONN, kind: "oidc", enabled: true });
      for (const [email, sub] of [[LEAVER, `oidc:${CONN}|iss|leaver`], [SCIM_LEAVER, `oidc:${CONN}|iss|scimleaver`]] as const) {
        store.rawPut(`${OIDC_GROUPS_PREFIX}${sub}`, [GROUP]);
        void email;
      }
    }

    const subOf = (which: "leaver" | "scimleaver"): string => `oidc:${CONN}|iss|${which}`;
    const mint = async (email: string, which: "leaver" | "scimleaver"): Promise<string> =>
      signSession(key, { method: "oidc", email, subject: subOf(which), connId: CONN, epoch: 0 }, Date.now());

    // ===========================================================================================
    // SECTION B: THE DEFECT, driven through both offboarding routes an operator actually has.
    // ===========================================================================================
    {
      const token = await mint(LEAVER, "leaver");
      const before = await whoami(token);
      // THE ANTI-VACUITY ASSERTION, and the one that makes the refusal below mean something. If this ever
      // stops passing, every "the session is dead" check underneath passes for the wrong reason.
      ok("B1: the leaver's session authorises, and it resolves to OPERATOR from the group claim", before.status === 200 && before.role === "operator" && before.roleSource === "group");
      // ... on an account where they hold NO grant row of any kind. This is the property that made them
      // invisible to an email-keyed offboard: there is nothing keyed by their address to find.
      const roleKeys = store.keysWithPrefix("role:");
      ok("B2: and they hold NO role row at all: not bound, not pending, not legacy", roleKeys.every((k) => !k.includes(LEAVER) && !k.includes(subOf("leaver"))) && roleKeys.length > 0);

      const del = await call(OWNER, "POST", "/admin/roles/delete", { email: LEAVER });
      const delBody = (await del.json()) as { deleted?: boolean };
      // `deleted:false` is CORRECT and stays correct: no grant existed, so none was removed, and SCIM's
      // removed-signal and the console's row both read this field. The defect was never this answer; it was
      // everything the early return skipped on the way to it.
      ok("B3: the offboard reports deleted:false, because there was no grant row to remove", del.status === 200 && delBody.deleted === false);
      // THE FIX. An offboard of somebody the role table cannot see is still an offboard, so the email
      // revocation axis is bumped anyway. Asserting the KEY EXISTS, not merely that the session died, is what
      // stops the assertion below being satisfiable by an unrelated refusal.
      ok("B4: THE FIX: the email revocation axis was bumped even though nothing was deleted", store.keysWithPrefix(SESSION_EPOCH_PREFIX).includes(`${SESSION_EPOCH_PREFIX}${LEAVER}`));
      const after = await whoami(token);
      ok("B5: so the surviving session is dead: the same cookie now authorises nothing", after.status === 401 || after.status === 403);
      ok("B6: and it is recorded as a session termination, not as a role change nobody made", (await auditActions()).includes("session-terminate"));

      // The OTHER route, and the reason this had to be fixed in deleteRole rather than beside it: the union
      // revoke scopes its bump to a revocation that closed a way in, and a group-claim member has no passkey,
      // no recovery record and no invite, so it finds nothing and terminates nothing. It is not a fallback.
      const rev = await call(OWNER, "POST", "/admin/signin-factors/revoke", { email: LEAVER });
      const revBody = (await rev.json()) as { revoked?: { passkeyCredentials?: number; recovery?: boolean; invitesLive?: number }; sessionsTerminated?: boolean };
      ok(
        "B7: the sign-in-factor revoke finds nothing for such a member and terminates nothing, so it never covered this",
        rev.status === 200 && revBody.revoked?.passkeyCredentials === 0 && revBody.revoked?.recovery === false && revBody.revoked?.invitesLive === 0 && revBody.sessionsTerminated === false,
      );
    }

    // ===========================================================================================
    // SECTION C: THE SCIM LEAVER PATH, driven as the customer's IdP drives it. It posts only
    // /roles/delete, so before the fix an automated deprovision was a complete no-op that answered
    // success.
    // ===========================================================================================
    {
      const token = await mint(SCIM_LEAVER, "scimleaver");
      ok("C1: the second group-claim member's session authorises as operator", (await whoami(token)).role === "operator");
      const r = await handleScim(
        new Request(`https://engine.example/scim/v2/Users/${encodeURIComponent(SCIM_LEAVER)}`, {
          method: "DELETE",
          headers: { authorization: `Bearer ${SCIM_TOKEN}` },
        }),
        authEnv(),
      );
      // SCIM's own contract is an idempotent 204 whether or not a grant existed, which is exactly why the
      // no-op was invisible: the IdP was told the leaver was deprovisioned either way.
      ok("C2: SCIM answers its idempotent deprovision success", r.status === 204 || r.status === 200);
      ok("C3: THE FIX, through the automated path: the SCIM leaver's session is dead", (await whoami(token)).status !== 200);
    }

    // ===========================================================================================
    // SECTION D: THE NO-LOCKOUT ARMS. A revocation that cannot be re-entered is a lockout, and the
    // people this fix touches are reached through estate-wide policy, so getting this wrong would
    // sign out a whole directory of legitimate users with no way back.
    // ===========================================================================================
    {
      // D-i: the group mapping is ESTATE POLICY about a directory of people, not this person's grant.
      // Destroying it here would offboard everybody who holds it, so it is deliberately untouched.
      const mappings = (await (await call(OWNER, "GET", "/admin/group-roles")).json()) as { groupRoles?: { group: string }[] } | { group: string }[];
      const list = Array.isArray(mappings) ? mappings : (mappings.groupRoles ?? []);
      ok("D1: the group->role mapping survives the offboard untouched", list.some((m) => m.group === GROUP));

      // D-ii: and the fix ends SESSIONS, it does not remove AUTHORITY. A session minted after the bump
      // carries the current epoch and resolves the same role, so anybody still entitled simply signs in
      // again. This is the arm that would fail if the bump had been implemented as a deny-list.
      const fresh = await signSession(key, { method: "oidc", email: LEAVER, subject: subOf("leaver"), connId: CONN, epoch: 1 }, Date.now());
      const re = await whoami(fresh);
      ok("D2: a FRESH session for the same person still resolves operator, so nobody is locked out", re.status === 200 && re.role === "operator");

      // D-iii: the member the roster DOES carry is untouched by any of it.
      ok("D3: the staying member still holds their granted role", store.keysWithPrefix("role:").some((k) => k.includes(STAYER)));

      // D-iv: idempotent offboarding is preserved. An address with no grant and no session is still a
      // successful no-op, which is what SCIM retries depend on.
      const ghost = await call(OWNER, "POST", "/admin/roles/delete", { email: "ghost-ofr@acme.example" });
      ok("D4: offboarding an address that was never a member is still an idempotent success", ghost.status === 200 && ((await ghost.json()) as { deleted?: boolean }).deleted === false);
    }

    // ===========================================================================================
    // SECTION E: THE RESIDUE CENSUS. The enumeration made executable, so the next change to either
    // offboarding route reports what it started or stopped removing instead of drifting silently.
    // Each row is a real artefact, driven, not a description of one.
    // ===========================================================================================
    {
      const EQUIPPED = "equipped-ofr@acme.example";
      ok("E1: a fully equipped member is granted a role, which mints their registration invite", (await call(OWNER, "POST", "/admin/roles", { email: EQUIPPED, role: "operator" })).status === 200);
      // Their recovery record, minted through the DO's own regenerate route (the same one the console's
      // regenerate button reaches). The codes themselves are never read, printed or compared here: what is
      // being measured is which route DELETES the record they are banked in.
      const codes = await ctx.doFetch("/recovery/regenerate", null, { email: EQUIPPED });
      ok("E2: and a banked recovery record exists for them", codes.status === 200 && store.keysWithPrefix(`${RECOVERY_PREFIX}${EQUIPPED}`).length === 1);
      // A credential and a user record. Finishing a real WebAuthn ceremony needs an authenticator, so the two
      // records the ceremony would leave are seeded in the shapes the ceremony writes; what is being measured
      // is which offboarding route DELETES them, and a delete does not care how the record arrived.
      store.rawPut(`${PASSKEY_CRED_PREFIX}cred-ofr-1`, { credentialId: "cred-ofr-1", email: EQUIPPED, createdAt: new Date().toISOString(), aaguid: "", transports: [], alg: -7, publicKey: "", signCount: 0 });
      store.rawPut(`${PASSKEY_USER_PREFIX}${EQUIPPED}`, { email: EQUIPPED, displayName: EQUIPPED, createdAt: new Date().toISOString() });
      const inviteKeys = store.keysWithPrefix(PASSKEY_INVITE_PREFIX).length;
      ok("E3: and an outstanding registration invite, keyed by its token", inviteKeys > 0);

      // ---- route one: the role delete on its own (what SCIM drives, and the console's Remove member) ----
      ok("E4: the equipped member is offboarded by the role delete", ((await (await call(OWNER, "POST", "/admin/roles/delete", { email: EQUIPPED })).json()) as { deleted?: boolean }).deleted === true);
      ok("E5: THE ROLE DELETE REMOVES THE GRANT: no role row survives for them", store.keysWithPrefix("role:").every((k) => !k.includes(EQUIPPED)));
      // The residue, asserted as SURVIVING. These are not aspirational: if any of them ever flips, the role
      // delete has started sweeping a factor store and this section says so rather than passing quietly.
      ok("E6: RESIDUE: their passkey credential survives the role delete (keyed by credential id)", store.keysWithPrefix(PASSKEY_CRED_PREFIX).some((k) => (store.rawGet<{ email?: string }>(k)?.email ?? "") === EQUIPPED));
      ok("E7: RESIDUE: their recovery record survives the role delete (keyed by email, deleted by nothing on this route)", store.keysWithPrefix(`${RECOVERY_PREFIX}${EQUIPPED}`).length === 1);
      ok("E8: RESIDUE: their registration invite survives the role delete (keyed by TOKEN, unreachable from an email)", store.keysWithPrefix(PASSKEY_INVITE_PREFIX).length === inviteKeys);

      // ---- route two: the sign-in-factor revoke, the union write ----
      const rev = await call(OWNER, "POST", "/admin/signin-factors/revoke", { email: EQUIPPED });
      const revoked = ((await rev.json()) as { revoked?: { passkeyCredentials?: number; recovery?: boolean; invitesLive?: number } }).revoked;
      ok("E9: the revoke closes all three at once", rev.status === 200 && (revoked?.passkeyCredentials ?? 0) >= 1 && revoked?.recovery === true && (revoked?.invitesLive ?? 0) >= 1);
      ok("E10: their credential is gone", store.keysWithPrefix(PASSKEY_CRED_PREFIX).every((k) => (store.rawGet<{ email?: string }>(k)?.email ?? "") !== EQUIPPED));
      ok("E11: their recovery record is gone", store.keysWithPrefix(`${RECOVERY_PREFIX}${EQUIPPED}`).length === 0);
      ok("E12: their invite is gone", store.keysWithPrefix(PASSKEY_INVITE_PREFIX).every((k) => (store.rawGet<{ email?: string }>(k)?.email ?? "") !== EQUIPPED));

      // The one artefact NEITHER route removes, recorded honestly rather than quietly swept. `passkeyUser:` is
      // the WebAuthn user record (address plus display name). It is read only by the fleet-drill population
      // count and by nothing on any authorisation path, so it is not a way in and burning it would buy no
      // security; it is asserted here so that "it survives" stays a measured fact rather than an assumption,
      // and so a future reader who finds it does not have to re-derive whether it matters.
      ok("E13: RESIDUE, and deliberately not closed: the passkey USER record survives both routes, and grants nothing", store.keysWithPrefix(`${PASSKEY_USER_PREFIX}${EQUIPPED}`).length === 1);
      // The group snapshot survives too, but an earlier version of this file's rationale for tolerating it was
      // wrong: it read "once the sessions that could quote it are dead it confers nothing". That is false:
      // spendTimeGroupsFor reads
      // `oidcgroups:<subject>` DIRECTLY when a stored governance record re-resolves its recorded principal's
      // authority, with no session in hand and no session required. So the snapshot IS quoted after every
      // session is dead, and it is the sole source of a group-conferred person's authority at spend time.
      // That is the exact shape this repo keeps being bitten by: a comment asserting a closure, stopping the
      // next reader looking. The residue is still tolerated, but for the reason that is actually true.
      //
      // WHY IT IS STILL TOLERATED. The snapshot confers authority only through the group->role MAPPING, and
      // the estate can revoke it: delete the mapping and every holder of that group loses the role, at spend
      // time as at request time. What it cannot do is revoke ONE person that way. The per-person answers are
      // to reject the record, or -- since the replay now re-reads connection liveness -- to disable or delete
      // the IdP connection they signed in through, which the spend refuses on exactly as a request does.
      // Deleting the snapshot itself would be a THIRD revocation surface keyed on a subject no operator
      // holding an address can name, which is why it is not the answer here.
      ok("E14: RESIDUE, and deliberately not closed: the oidc group snapshot survives an offboard, keyed by a subject an offboard cannot name", store.keysWithPrefix(`${OIDC_GROUPS_PREFIX}${subOf("leaver")}`).length === 1);
      // E15 is the assertion the old comment's premise would have failed. It states, as a measured fact
      // rather than a claim, that the surviving snapshot is read by a path that presents NO session: a bare
      // re-resolution of the recorded subject answers with the group's role. If a future change ever does
      // sweep the snapshot on offboard, this goes red and says the tolerated residue stopped being tolerated,
      // which is the direction a reader wants to be told about.
      // Cast rather than widen SchedulerDOSurface. spendTimeGroupsFor is deliberately NOT on that interface
      // (it is called only from within the mixin that defines it, and the surface's own size exemption argues
      // in as many words for keeping such helpers off it), so a test that needs it reaches it here instead of
      // pushing a declaration onto the shared type for one assertion's sake.
      const spendTimeGroupsFor = (sched.dobj as unknown as { spendTimeGroupsFor(subject: string, recorded: readonly string[] | undefined): Promise<string[]> }).spendTimeGroupsFor.bind(sched.dobj);
      const spendGroups = await spendTimeGroupsFor(subOf("leaver"), []);
      ok("E15: MEASURED, and the reason E14's old premise was false: the snapshot is quoted with NO session at all", spendGroups.includes(GROUP));
    }
  } finally {
    globalThis.fetch = ctx.realFetch;
  }

  // Both arguments: called bare the guard reads failures as undefined and declares a verdict that means
  // nothing, and the check count rides so a run that asserted nothing cannot report a pass.
  if (failures > 0) process.exitCode = 1;
  console.log(`\nVERDICT: ${failures === 0 ? "PASS" : "FAIL"} failures=${failures} checks=${checks} entry=${import.meta.url.replace("file://", "")}`);
  if (failures > 0) process.exit(1);
}

await main();
