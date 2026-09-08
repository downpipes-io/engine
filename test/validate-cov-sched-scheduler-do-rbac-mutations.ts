// validate-cov-sched-scheduler-do-rbac-mutations: a focused branch-coverage validator for RbacMutationsMixin
// (src/sched/scheduler-do-rbac-mutations.ts), the RBAC write cluster: setRole / deleteRole, the group->role
// mapping writes (setGroupRole / deleteGroupRole), the composable custom-role writes (addCustomRole /
// deleteCustomRole) and the two list views (listGroupRoles / listCustomRoles). It drives the REAL Durable
// Object through the production router (handleAdmin) for the owner-authored happy paths, the validation
// rejections, the last-Owner and anti-escalation guards, and the bound vs pending grant shapes; and it
// drives the DO stub router-bypassed (encodeCaller) for the bare-token-fallback actor branch and the caller
// source-IP audit attribution. Every assertion checks a real outcome: an HTTP status, a persisted record
// read back, an audited effect, or a returned body field. The change-control gate is OFF (the default), so
// each gated mutation applies inline through the same validated method an approved change would replay.
// No network beyond the harness JWKS shim, no deploy, no cost.
//
// Run: node test/validate-cov-sched-scheduler-do-rbac-mutations.ts

import { buildContext } from "./validate-owner-action-dualcontrol-harness.ts";
import { type Caller } from "../src/admin/identity.ts";
import { PASSKEY_CRED_PREFIX } from "../src/sched/scheduler-do-base.ts";
import type { AuditEvent } from "../src/admin/audit.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
const errOf = async (r: Response): Promise<string> => ((await r.json()) as { error?: string }).error ?? "";

// A far-future RFC-3339 expiry so effectiveRole never reads the grant as expired (deterministic; not clock
// dependent within any realistic run).
const FAR = "2999-01-01T00:00:00.000Z";
const IP = "203.0.113.7"; // TEST-NET-3 documentation address: a distinctive, fixed source IP to assert on.

async function main(): Promise<void> {
  const ctx = await buildContext();
  const { sched, OWNER, OWNER2, subjectOf, call, doFetch, ownerCaller } = ctx;

  // Router-bypass callers. The DO RE-RESOLVES authority from its own tables, so the header role is only a
  // label; the bare-token caller resolves to the break-glass owner, the owner+IP caller to the table owner.
  const tokenCaller: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };
  const ownerIp: Caller = { ...ownerCaller(OWNER), sourceIp: IP };

  const ALICE = "alice-rm@acme.example";
  const BOB = "bob-rm@acme.example";
  const DAVE = "dave-rm@acme.example";
  const FRANK = "frank-rm@acme.example";
  const OWNER3 = "owner3-rm@acme.example";
  const OWNER4 = "owner4-rm@acme.example";
  const PEOPLE = "people-rm@acme.example"; // an access-admin: roles.write + access.policy, NOT downpipe.write

  const roster = async (): Promise<Array<{ email: string; role: string; subject: string }>> =>
    (await (await call(OWNER, "GET", "/admin/roles")).json()) as Array<{ email: string; role: string; subject: string }>;

  try {
    // ===========================================================================================
    // SECTION A: addCustomRole + listCustomRoles (create valid, owner-reserved reject, token createdBy).
    // ===========================================================================================
    {
      const cr = await call(OWNER, "POST", "/admin/custom-roles", { name: "kv-reader", label: "KV reader", capabilities: ["downpipe.read", "restore.dryrun"], landing: "downpipes" });
      ok("addCustomRole: a valid role is created (200)", cr.status === 200);
      const crBody = (await cr.json()) as { name: string; createdBy: string | null; capabilities: string[] };
      ok("addCustomRole: the stored record names the creator (createdBy = owner email)", crBody.name === "kv-reader" && crBody.createdBy === OWNER);

      const crBad = await call(OWNER, "POST", "/admin/custom-roles", { name: "danger", label: "danger", capabilities: ["downpipe.read", "keys.ceremony"], landing: "downpipes" });
      ok("addCustomRole: an owner-reserved capability is rejected (400)", crBad.status === 400 && /owner-reserved/.test(await errOf(crBad)));

      // Bare-token (break-glass) creates a role: createdBy is null (no attributable email), via the DO stub.
      const crTok = await doFetch("/custom-roles", tokenCaller, { name: "tok-role", label: "Token role", capabilities: ["downpipe.read"], landing: "downpipes" });
      ok("addCustomRole: the bare-token break-glass can create a role (200)", crTok.status === 200);
      const crTokBody = (await crTok.json()) as { name: string; createdBy: string | null };
      ok("addCustomRole: a token-authored role records createdBy null", crTokBody.createdBy === null);

      const list = (await (await call(OWNER, "GET", "/admin/custom-roles")).json()) as Array<{ name: string }>;
      ok("listCustomRoles: the catalogue carries both created roles", Array.isArray(list) && list.some((r) => r.name === "kv-reader") && list.some((r) => r.name === "tok-role"));
    }

    // ===========================================================================================
    // SECTION B: setRole happy shapes (pending built-in, pending custom+expiry, bound updates, invite mint).
    // ===========================================================================================
    {
      // (1) Fresh email, built-in role, no expiry -> a PENDING invite is written and a registration invite minted.
      const r1 = await call(OWNER, "POST", "/admin/roles", { email: ALICE, role: "operator" });
      ok("setRole: a fresh email built-in grant is accepted (200)", r1.status === 200);
      const r1b = (await r1.json()) as { email: string; role: string; grantedBy: string; subject?: string; inviteToken?: string };
      ok("setRole: the pending grant carries the email + role + granting owner", r1b.email === ALICE && r1b.role === "operator" && r1b.grantedBy === OWNER);
      ok("setRole: a fresh (un-enrolled) grantee gets a single-use registration invite token", typeof r1b.inviteToken === "string" && r1b.inviteToken.length > 0);
      ok("setRole: a pending grant has no bound subject yet", r1b.subject === undefined || r1b.subject === "");

      // (2) Fresh email, CUSTOM role, with an expiry -> stored role pinned to the viewer floor, customRole named.
      const r2 = await call(OWNER, "POST", "/admin/roles", { email: BOB, customRole: "kv-reader", expiresAt: FAR });
      ok("setRole: a fresh custom-role grant with expiry is accepted (200)", r2.status === 200);
      const r2b = (await r2.json()) as { role: string; customRole?: string; expiresAt?: string };
      ok("setRole: a custom-role grant pins the built-in role to the viewer floor and names the custom role", r2b.role === "viewer" && r2b.customRole === "kv-reader");
      ok("setRole: the time-boxed grant carries the expiresAt it was given", r2b.expiresAt === FAR);

      // (3) Bind ALICE by authenticating (whoami binds the pending invite to her stable subject).
      const aliceWho = (await (await call(ALICE, "GET", "/admin/whoami")).json()) as { role: string };
      ok("setRole: the invitee binds on first auth (whoami resolves the pending operator grant)", aliceWho.role === "operator");

      // (4) Bound update, CUSTOM role, no expiry -> updates the subject-keyed entry IN PLACE.
      const r3 = await call(OWNER, "POST", "/admin/roles", { email: ALICE, customRole: "kv-reader" });
      ok("setRole: a bound member's grant updates in place to a custom role (200)", r3.status === 200);
      const r3b = (await r3.json()) as { subject?: string; role: string; customRole?: string; expiresAt?: string };
      ok("setRole: the in-place update preserves the stable subject and pins to the viewer floor", typeof r3b.subject === "string" && r3b.subject!.length > 0 && r3b.role === "viewer" && r3b.customRole === "kv-reader");
      ok("setRole: the rewritten bound entry carries no expiry when none was given", r3b.expiresAt === undefined);

      // (5) Bound update, BUILT-IN role, WITH expiry -> the other arm of the bound-entry expiry/custom spreads.
      const r4 = await call(OWNER, "POST", "/admin/roles", { email: ALICE, role: "approver", expiresAt: FAR });
      ok("setRole: a bound member's grant updates to a built-in role with an expiry (200)", r4.status === 200);
      const r4b = (await r4.json()) as { subject?: string; role: string; customRole?: string; expiresAt?: string };
      ok("setRole: the bound built-in update stores the role + expiry and drops the custom-role pin", r4b.role === "approver" && r4b.expiresAt === FAR && r4b.customRole === undefined && typeof r4b.subject === "string");

      // (6) An already-ENROLLED email (has a passkey credential): no registration invite is minted.
      sched.storage.rawPut(`${PASSKEY_CRED_PREFIX}cov-cred-dave`, { credentialId: "cov-cred-dave", email: DAVE, cosePublicKey: "AAAA", alg: -7, signCount: 0, transports: [], aaguid: "AA", createdAt: "2026-01-01T00:00:00.000Z" });
      const r5 = await call(OWNER, "POST", "/admin/roles", { email: DAVE, role: "viewer" });
      ok("setRole: granting an already-enrolled email succeeds (200)", r5.status === 200);
      const r5b = (await r5.json()) as { role: string; inviteToken?: string };
      ok("setRole: an enrolled grantee gets NO registration invite (a second key is self-added)", r5b.inviteToken === undefined && r5b.role === "viewer");

      // (7) An empty customRole string falls through to the built-in role (the `&& length > 0` false arm).
      const r6 = await call(OWNER, "POST", "/admin/roles", { email: "x5cov@acme.example", role: "viewer", customRole: "" });
      ok("setRole: an empty customRole string falls back to the built-in role (200, no custom pin)", r6.status === 200 && (await r6.json() as { role: string; customRole?: string }).customRole === undefined);

      // (8) a time-boxed custom-role grant's expiresAt must gate the CAPABILITY
      // overlay, not just the built-in role label (the built-in role is already pinned to the viewer floor
      // for any custom-role grant, so that label alone proves nothing about expiry). A PAST expiry must
      // resolve to the built-in floor with no capability/customRole overlay at all; a FUTURE expiry must
      // surface both, locking in both directions. now = Date.now() at grant time (mutations.ts) and at
      // whoami resolution time are both real wall-clock, so this is deterministic without mocking.
      const PAST_EXPIRY = "2020-01-01T00:00:00.000Z";
      const EXPIRED_GRANTEE = "expired-kv-rm@acme.example";
      const LIVE_GRANTEE = "live-kv-rm@acme.example";
      await call(OWNER, "POST", "/admin/roles", { email: EXPIRED_GRANTEE, customRole: "kv-reader", expiresAt: PAST_EXPIRY });
      await call(OWNER, "POST", "/admin/roles", { email: LIVE_GRANTEE, customRole: "kv-reader", expiresAt: FAR });
      type WhoBody = { role: string; customRole?: { name: string }; capabilities?: string[] };
      const expiredWho = (await (await call(EXPIRED_GRANTEE, "GET", "/admin/whoami")).json()) as WhoBody;
      ok(
        "whoami: an EXPIRED custom-role grant drops the capability overlay (viewer floor, no customRole/capabilities)",
        expiredWho.role === "viewer" && expiredWho.customRole === undefined && expiredWho.capabilities === undefined,
      );
      const liveWho = (await (await call(LIVE_GRANTEE, "GET", "/admin/whoami")).json()) as WhoBody;
      ok(
        "whoami: a LIVE (future-expiry) custom-role grant surfaces its capability overlay",
        liveWho.role === "viewer" && liveWho.customRole?.name === "kv-reader" && Array.isArray(liveWho.capabilities) && liveWho.capabilities.includes("restore.dryrun"),
      );

      // Persistence read-back: the roster reflects the grants above.
      const rs = await roster();
      ok("setRole: the roster reflects the bound + pending grants (alice approver, bob kv-reader)", rs.some((e) => e.email === ALICE && e.role === "approver") && rs.some((e) => e.email === BOB && e.role === "viewer"));
    }

    // ===========================================================================================
    // SECTION C: setRole validation rejections (every throw arm -> 400).
    // ===========================================================================================
    {
      ok("setRole: an unusable email is rejected (400)", (await call(OWNER, "POST", "/admin/roles", { email: "", role: "viewer" })).status === 400);
      ok("setRole: an unknown built-in role is rejected (400)", (await call(OWNER, "POST", "/admin/roles", { email: "x1cov@acme.example", role: "superuser" })).status === 400);
      ok("setRole: assigning a non-existent custom role is rejected (400)", (await call(OWNER, "POST", "/admin/roles", { email: "x2cov@acme.example", customRole: "no-such-role" })).status === 400);
      ok("setRole: a malformed expiresAt is rejected (400)", (await call(OWNER, "POST", "/admin/roles", { email: "x3cov@acme.example", role: "viewer", expiresAt: "not-a-timestamp" })).status === 400);
      ok("setRole: a non-string expiresAt is rejected (400)", (await call(OWNER, "POST", "/admin/roles", { email: "x4cov@acme.example", role: "viewer", expiresAt: 12345 })).status === 400);
    }

    // ===========================================================================================
    // SECTION D: setRole owner gates (last-Owner guard, owner grant/re-grant/demote with two owners,
    //            bare-token actor attribution).
    // ===========================================================================================
    {
      // Demoting the SOLE Owner is refused (last-Owner guard) while OWNER is the only owner.
      const lastOwner = await call(OWNER, "POST", "/admin/roles", { email: OWNER, role: "viewer" });
      ok("setRole: demoting the sole Owner is refused (400, last-Owner guard)", lastOwner.status === 400 && /last Owner/.test(await errOf(lastOwner)));

      // Grant a SECOND owner (pending), then bind it, so there are two effective owners.
      const grantOwner2 = await call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "owner" });
      ok("setRole: an Owner grants a second Owner (200)", grantOwner2.status === 200 && (await grantOwner2.json() as { role: string }).role === "owner");
      const owner2Who = (await (await call(OWNER2, "GET", "/admin/whoami")).json()) as { role: string };
      ok("setRole: the second Owner binds on first auth (resolves to owner)", owner2Who.role === "owner");

      // Re-grant owner to an existing (bound) Owner. With two Owners present, an owner-conferring role-set now
      // AUTO-GATES (autoGateOwnerMint, the puppet-owner-laundering guard), so it QUEUES rather than applying
      // inline. OWNER2 is already a bound Owner, so the (unapproved) re-grant leaves the roster unchanged and
      // the demote below still operates on the bound Owner. (Accepted-and-queued, not refused: the authority is
      // intact; only the inline-vs-queued shape changed.)
      const regrant = await call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "owner" });
      ok("setRole: re-granting owner to an existing Owner auto-gates with two Owners present (202 queued)", regrant.status === 202);

      // Demote ONE of two Owners: allowed, because countOwners != 1 (the guard does not fire).
      const demoteOne = await call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "viewer" });
      ok("setRole: demoting one of two Owners is allowed (200)", demoteOne.status === 200 && (await demoteOne.json() as { role: string }).role === "viewer");

      // Bare-token (break-glass) grant: the actor is recorded as the token-fallback, via the DO stub.
      const tokGrant = await doFetch("/roles", tokenCaller, { email: "tokgrant-rm@acme.example", role: "operator" });
      ok("setRole: a bare-token grant is accepted (200)", tokGrant.status === 200);
      ok("setRole: a token-authored grant records grantedBy = token-fallback", (await tokGrant.json() as { grantedBy: string }).grantedBy === "token-fallback");
    }

    // ===========================================================================================
    // SECTION E: deleteRole (pending removal, bound removal, absent no-op, invalid email, owner guards).
    // ===========================================================================================
    {
      // Remove a PENDING-only member.
      await call(OWNER, "POST", "/admin/roles", { email: FRANK, role: "operator" });
      const delPending = await call(OWNER, "POST", "/admin/roles/delete", { email: FRANK });
      ok("deleteRole: a pending member is removed (deleted:true)", delPending.status === 200 && (await delPending.json() as { deleted: boolean }).deleted === true);

      // Remove a BOUND member (ALICE, an approver) -> deletes the subject-keyed entry + bumps session epochs.
      const delBound = await call(OWNER, "POST", "/admin/roles/delete", { email: ALICE });
      ok("deleteRole: a bound member is removed (deleted:true)", delBound.status === 200 && (await delBound.json() as { deleted: boolean }).deleted === true);
      ok("deleteRole: the removed member is gone from the roster", !(await roster()).some((e) => e.email === ALICE));

      // Removing an ABSENT member is an idempotent no-op success.
      const delAbsent = await call(OWNER, "POST", "/admin/roles/delete", { email: "ghost-rm@acme.example" });
      ok("deleteRole: removing an absent member is a no-op (deleted:false)", delAbsent.status === 200 && (await delAbsent.json() as { deleted: boolean }).deleted === false);

      // An unusable email is rejected.
      ok("deleteRole: an unusable email is rejected (400)", (await call(OWNER, "POST", "/admin/roles/delete", { email: "" })).status === 400);

      // Removing the SOLE Owner is refused (last-Owner guard).
      const delSoleOwner = await call(OWNER, "POST", "/admin/roles/delete", { email: OWNER });
      ok("deleteRole: removing the sole Owner is refused (400, last-Owner guard)", delSoleOwner.status === 400 && /last Owner/.test(await errOf(delSoleOwner)));

      // Removing one of TWO Owners (a bound Owner) is allowed.
      await call(OWNER, "POST", "/admin/roles", { email: OWNER3, role: "owner" });
      await call(OWNER3, "GET", "/admin/whoami"); // bind OWNER3 as a second effective owner
      const delOneOwner = await call(OWNER, "POST", "/admin/roles/delete", { email: OWNER3 });
      ok("deleteRole: removing one of two bound Owners is allowed (deleted:true)", delOneOwner.status === 200 && (await delOneOwner.json() as { deleted: boolean }).deleted === true);
    }

    // ===========================================================================================
    // SECTION F: anti-escalation (an access-admin holds roles.write but cannot touch the owner role nor
    //            grant capabilities it lacks). Real refusals through the production router.
    // ===========================================================================================
    {
      await call(OWNER, "POST", "/admin/roles", { email: PEOPLE, role: "access-admin" });
      const aaGrantOwner = await call(PEOPLE, "POST", "/admin/roles", { email: "victim-rm@acme.example", role: "owner" });
      ok("anti-escalation: an access-admin cannot grant the owner role (403)", aaGrantOwner.status === 403);
      const aaGrantApprover = await call(PEOPLE, "POST", "/admin/roles", { email: "wb-approver-rm@acme.example", role: "approver" });
      ok("anti-escalation: an access-admin cannot grant a role conferring caps it lacks (approver, 403)", aaGrantApprover.status === 403);

      // An access-admin cannot REMOVE an Owner, even with two Owners present (the demote-Owner arm).
      await call(OWNER, "POST", "/admin/roles", { email: OWNER4, role: "owner" });
      await call(OWNER4, "GET", "/admin/whoami"); // a second effective owner so the last-Owner guard does not pre-empt
      const aaDeleteOwner = await call(PEOPLE, "POST", "/admin/roles/delete", { email: OWNER4 });
      ok("anti-escalation: an access-admin cannot remove an Owner (403)", aaDeleteOwner.status === 403);
      ok("anti-escalation: the Owner the access-admin tried to remove is still on the roster", (await roster()).some((e) => e.email === OWNER4 && e.role === "owner"));
    }

    // ===========================================================================================
    // SECTION G: setGroupRole + listGroupRoles + deleteGroupRole.
    // ===========================================================================================
    {
      const g1 = await call(OWNER, "POST", "/admin/group-roles", { group: "eng", role: "operator" });
      ok("setGroupRole: a built-in mapping is stored (200)", g1.status === 200);
      const g1b = (await g1.json()) as { group: string; role: string; grantedBy: string; customRole?: string };
      ok("setGroupRole: the mapping records group + role + granting owner", g1b.group === "eng" && g1b.role === "operator" && g1b.grantedBy === OWNER && g1b.customRole === undefined);

      const g2 = await call(OWNER, "POST", "/admin/group-roles", { group: "kv-team", customRole: "kv-reader" });
      ok("setGroupRole: a custom-role mapping is stored (200)", g2.status === 200);
      const g2b = (await g2.json()) as { role: string; customRole?: string };
      ok("setGroupRole: a custom-role mapping pins the role to the viewer floor and names the custom role", g2b.role === "viewer" && g2b.customRole === "kv-reader");

      const g3 = await call(OWNER, "POST", "/admin/group-roles", { group: "admins", role: "owner" });
      ok("setGroupRole: mapping a group to owner is rejected (403, the owner cap)", g3.status === 403);
      ok("setGroupRole: an unknown custom role is rejected (400)", (await call(OWNER, "POST", "/admin/group-roles", { group: "x-grp", customRole: "no-such-role" })).status === 400);
      ok("setGroupRole: an invalid built-in role is rejected (400)", (await call(OWNER, "POST", "/admin/group-roles", { group: "y-grp", role: "superuser" })).status === 400);
      ok("setGroupRole: an empty group name is rejected (400)", (await call(OWNER, "POST", "/admin/group-roles", { group: "", role: "operator" })).status === 400);

      // Bare-token group mapping: the actor is recorded as token-fallback, via the DO stub.
      const gTok = await doFetch("/group-roles", tokenCaller, { group: "tok-grp", role: "viewer" });
      ok("setGroupRole: a bare-token mapping is accepted (200)", gTok.status === 200);
      ok("setGroupRole: a token-authored mapping records grantedBy = token-fallback", (await gTok.json() as { grantedBy: string }).grantedBy === "token-fallback");

      const lg = (await (await call(OWNER, "GET", "/admin/group-roles")).json()) as Array<{ group: string; role: string }>;
      ok("listGroupRoles: the mapping list reflects the stored entries", Array.isArray(lg) && lg.some((m) => m.group === "eng" && m.role === "operator"));

      const dg1 = await call(OWNER, "POST", "/admin/group-roles/delete", { group: "eng" });
      ok("deleteGroupRole: an existing mapping is removed (deleted:true)", dg1.status === 200 && (await dg1.json() as { deleted: boolean }).deleted === true);
      const dg2 = await call(OWNER, "POST", "/admin/group-roles/delete", { group: "nonexistent-grp" });
      ok("deleteGroupRole: removing an absent mapping is a no-op (deleted:false)", dg2.status === 200 && (await dg2.json() as { deleted: boolean }).deleted === false);
      ok("deleteGroupRole: an empty group name is rejected (400)", (await call(OWNER, "POST", "/admin/group-roles/delete", { group: "" })).status === 400);
    }

    // ===========================================================================================
    // SECTION H: deleteCustomRole (existing, absent no-op, invalid name shapes).
    // ===========================================================================================
    {
      const dc1 = await call(OWNER, "POST", "/admin/custom-roles/delete", { name: "tok-role" });
      ok("deleteCustomRole: an existing role is removed (deleted:true)", dc1.status === 200 && (await dc1.json() as { deleted: boolean }).deleted === true);
      const dc2 = await call(OWNER, "POST", "/admin/custom-roles/delete", { name: "ghost-role" });
      ok("deleteCustomRole: removing an absent role is a no-op (deleted:false)", dc2.status === 200 && (await dc2.json() as { deleted: boolean }).deleted === false);
      ok("deleteCustomRole: an empty name is rejected (400)", (await call(OWNER, "POST", "/admin/custom-roles/delete", { name: "" })).status === 400);
      ok("deleteCustomRole: a missing name is rejected (400)", (await call(OWNER, "POST", "/admin/custom-roles/delete", {})).status === 400);
    }

    // ===========================================================================================
    // SECTION J: bare-token (break-glass) actor attribution across the custom-role and delete audit appends.
    // The break-glass owner has no attributable email, so each of these writes records actorEmail null on its
    // commit-point audit event. Driven router-bypassed with the token caller; every op leaves a real effect.
    // ===========================================================================================
    {
      // A token-authored CUSTOM-role assignment (the custom-role audit append's null-email arm).
      const tcSet = await doFetch("/roles", tokenCaller, { email: "tokcustom-rm@acme.example", customRole: "kv-reader" });
      ok("token: a custom-role grant by the break-glass owner is accepted (200)", tcSet.status === 200 && (await tcSet.json() as { grantedBy: string; customRole?: string }).customRole === "kv-reader");
      // A token-authored member removal (the deleteRole audit append's null-email arm).
      const tcDel = await doFetch("/roles/delete", tokenCaller, { email: "tokcustom-rm@acme.example" });
      ok("token: a member removal by the break-glass owner removes it (deleted:true)", tcDel.status === 200 && (await tcDel.json() as { deleted: boolean }).deleted === true);
      // A token-authored CUSTOM-role group mapping (the setGroupRole custom audit append's null-email arm).
      const tgSet = await doFetch("/group-roles", tokenCaller, { group: "tok-custom-grp", customRole: "kv-reader" });
      ok("token: a custom-role group mapping by the break-glass owner is accepted (200)", tgSet.status === 200 && (await tgSet.json() as { grantedBy: string }).grantedBy === "token-fallback");
      // A token-authored group-mapping removal (the deleteGroupRole audit append's null-email arm).
      const tgDel = await doFetch("/group-roles/delete", tokenCaller, { group: "tok-custom-grp" });
      ok("token: a group-mapping removal by the break-glass owner removes it (deleted:true)", tgDel.status === 200 && (await tgDel.json() as { deleted: boolean }).deleted === true);
      // A token-authored custom-role create then delete (the deleteCustomRole audit append's null-email arm).
      ok("token: a custom-role create by the break-glass owner is accepted (200)", (await doFetch("/custom-roles", tokenCaller, { name: "tok-del-role", label: "Token delete role", capabilities: ["downpipe.read"], landing: "downpipes" })).status === 200);
      const tcrDel = await doFetch("/custom-roles/delete", tokenCaller, { name: "tok-del-role" });
      ok("token: a custom-role removal by the break-glass owner removes it (deleted:true)", tcrDel.status === 200 && (await tcrDel.json() as { deleted: boolean }).deleted === true);

      // The audit chain records these break-glass writes with a token method and a null actor email.
      const tokEvents = (((await (await call(OWNER, "GET", "/admin/audit?limit=2000")).json()) as { events: AuditEvent[] }).events).filter((e) => e.actorMethod === "token" && e.actorEmail === null);
      const tokActions = tokEvents.map((e) => e.action);
      ok("token: a break-glass role removal is audited with a null actor email", tokActions.includes("role-change"));
      ok("token: a break-glass group-mapping removal is audited with a null actor email", tokActions.includes("group-role-change"));
      ok("token: the break-glass custom-role writes are audited with a null actor email", tokActions.filter((a) => a === "custom-role-change").length >= 3);
    }

    // ===========================================================================================
    // SECTION I: source-IP audit attribution. The DO is driven router-bypassed with an owner caller that
    // carries a fixed source IP, exercising the `caller?.sourceIp ?? null` audit field across every mutation
    // family. Each op returns a real effect; the audit chain then carries the IP for each action.
    // ===========================================================================================
    {
      ok("source-ip: addCustomRole with a source IP succeeds (200)", (await doFetch("/custom-roles", ownerIp, { name: "ip-role", label: "IP role", capabilities: ["downpipe.read"], landing: "downpipes" })).status === 200);
      ok("source-ip: setRole (built-in) with a source IP succeeds (200)", (await doFetch("/roles", ownerIp, { email: "ipbuiltin-rm@acme.example", role: "viewer" })).status === 200);
      ok("source-ip: setRole (custom) with a source IP succeeds (200)", (await doFetch("/roles", ownerIp, { email: "ipcustom-rm@acme.example", customRole: "ip-role" })).status === 200);
      ok("source-ip: setGroupRole (built-in) with a source IP succeeds (200)", (await doFetch("/group-roles", ownerIp, { group: "ip-grp", role: "viewer" })).status === 200);
      ok("source-ip: setGroupRole (custom) with a source IP succeeds (200)", (await doFetch("/group-roles", ownerIp, { group: "ip-grp-c", customRole: "ip-role" })).status === 200);
      const delIpRole = await doFetch("/roles/delete", ownerIp, { email: "ipbuiltin-rm@acme.example" });
      ok("source-ip: deleteRole with a source IP removes the member (deleted:true)", delIpRole.status === 200 && (await delIpRole.json() as { deleted: boolean }).deleted === true);
      const delIpGrp = await doFetch("/group-roles/delete", ownerIp, { group: "ip-grp" });
      ok("source-ip: deleteGroupRole with a source IP removes the mapping (deleted:true)", delIpGrp.status === 200 && (await delIpGrp.json() as { deleted: boolean }).deleted === true);
      const delIpCustom = await doFetch("/custom-roles/delete", ownerIp, { name: "ip-role" });
      ok("source-ip: deleteCustomRole with a source IP removes the role (deleted:true)", delIpCustom.status === 200 && (await delIpCustom.json() as { deleted: boolean }).deleted === true);

      const events = ((await (await call(OWNER, "GET", "/admin/audit?limit=2000")).json()) as { events: AuditEvent[] }).events;
      const ipActions = new Set(events.filter((e) => e.sourceIp === IP).map((e) => e.action));
      ok("source-ip: the role-change audit events carry the caller source IP", ipActions.has("role-change"));
      ok("source-ip: the group-role-change audit events carry the caller source IP", ipActions.has("group-role-change"));
      ok("source-ip: the custom-role-change audit events carry the caller source IP", ipActions.has("custom-role-change"));
    }

    // The whole write history is tamper-evident and verifies intact end to end.
    const verify = (await (await call(OWNER, "GET", "/admin/audit/verify")).json()) as { intact: boolean };
    ok("the audit chain verifies intact across the entire RBAC write history", verify.intact === true);
  } finally {
    globalThis.fetch = ctx.realFetch;
  }

  console.log(failures === 0 ? "\nVECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
