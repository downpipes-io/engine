// validate-rbac PROOFs 10 and 10b: the access-admin DO authority for role writes (within-authority
// only, no escalation, no Owner-touching) and the router-trusted `method` axis at the DO. Extracted
// verbatim from test/validate-rbac.ts; the assertions, order and expected values are unchanged. These
// proofs are STATEFUL over the shared scheduler in `ctx` (they follow PROOF 9c and assume the
// OWNER/OWNER2 roster the matrix proofs left) and run in the original order.

import { encodeCaller, type Caller } from "../src/admin/identity.ts";
import { PASSKEY_CRED_PREFIX } from "../src/sched/scheduler-do-base.ts";
import { type Ctx, OWNER, OWNER2 } from "./validate-rbac-harness.ts";

export async function runAccessAdmin(ctx: Ctx): Promise<void> {
  const { ok, signer, sched, call } = ctx;
  const { subjectOf } = signer;

  // ---- PROOF 10: access-admin DO authority for role writes, WITHIN AUTHORITY only --------------
  // The access-admin role holds roles.write + access.policy, so it may MANAGE PEOPLE, but the HARD
  // no-escalation invariant (requireGrantWithinAuthority) means it may only grant a role whose
  // capability set is a SUBSET of its OWN: access-admin holds neither downpipe.write nor restore.apply,
  // so it can NOT grant operator/approver/restore-operator (those confer capabilities it lacks), and it
  // can NEVER mint Owner or demote/remove an existing Owner (requireNotOwnerEscalation). It CAN grant a
  // within-authority role (viewer or access-admin, whose caps it holds). The DO is the authority: it
  // RE-RESOLVES the caller's role from its own tables and recomputes its own capability set, so a router
  // bug or a lying header asserting owner cannot bypass either guard. We prove the full matrix: granting a
  // stronger non-owner role (operator) is refused naming the missing capability; granting a within-authority
  // role works; granting owner is refused; demoting an owner is refused; owner can still grant anything; the
  // last-Owner guard still holds; nothing escalating persists; and the DO re-resolves. bootstrap is proved
  // by PROOF 1 (unchanged).
  {
    const ADMIN = "accessadmin-do@acme.example"; // a fresh access-admin (the people-only role)
    const TARGET = "managed-member@acme.example"; // a throwaway target the access-admin manages
    const NEWOWNER = "would-be-owner@acme.example"; // a target the access-admin tries (and fails) to make Owner

    // OWNER (an Owner) grants the access-admin role. Only an Owner may do this initial grant.
    const grantAdmin = await call(OWNER, "POST", "/admin/roles", { email: ADMIN, role: "access-admin" });
    ok("access-admin: an Owner can appoint an access-admin (200)", grantAdmin.status === 200);
    const adminWho = (await (await call(ADMIN, "GET", "/admin/whoami")).json()) as { role: string };
    ok("access-admin: the appointed caller resolves to access-admin", adminWho.role === "access-admin");

    // 10a) access-admin GRANTING a STRONGER non-owner role is REFUSED by the within-authority guard: the
    // router gate passes (access-admin holds roles.write), so this is the DO's no-escalation guard firing
    // -> 400 naming the capability access-admin does not hold (operator confers downpipe.write). An
    // access-admin must not be able to hand out powers it lacks itself. The approver grant is refused the
    // same way (it also confers downpipe.write / restore.apply). Neither persists.
    const grantOperator = await call(ADMIN, "POST", "/admin/roles", { email: TARGET, role: "operator" });
    const goperBody = (await grantOperator.json()) as { error?: string };
    ok("access-admin CANNOT grant operator (refused 403 by the within-authority guard)", grantOperator.status === 403);
    ok("the refusal is the generic forbidden body, leaking no capability name", goperBody.error === "forbidden" && !/downpipe\.write/.test(JSON.stringify(goperBody)) && !/do not hold/.test(JSON.stringify(goperBody)));
    const grantApprover = await call(ADMIN, "POST", "/admin/roles", { email: TARGET, role: "approver" });
    ok("access-admin CANNOT grant approver either (confers caps it lacks, refused 403)", grantApprover.status === 403);
    // Neither stronger grant persisted: TARGET was never created.
    const roleListAfterStrong = (await (await call(OWNER, "GET", "/admin/roles")).json()) as Array<{ email: string }>;
    ok("the refused stronger grants persisted nothing (TARGET was not created)", !roleListAfterStrong.some((e) => e.email === TARGET));

    // 10a') access-admin GRANTS a WITHIN-AUTHORITY role (access-admin, whose caps it holds exactly): the DO
    // honours roles.write end to end (200), proving the guard blocks only escalation, not legitimate people
    // management. The grant is real (the target resolves to access-admin).
    const grant = await call(ADMIN, "POST", "/admin/roles", { email: TARGET, role: "access-admin" });
    const grantBody = (await grant.json()) as { email?: string; role?: string; grantedBy?: string };
    ok("access-admin CAN grant a within-authority role (access-admin) (200, DO persists it)", grant.status === 200);
    ok("the within-authority grant records the role and the granting access-admin", grantBody.role === "access-admin" && grantBody.grantedBy === ADMIN);
    const targetWho = (await (await call(TARGET, "GET", "/admin/whoami")).json()) as { role: string };
    ok("the within-authority grant takes effect (target resolves to access-admin)", targetWho.role === "access-admin");

    // 10b) access-admin DEMOTES the member to viewer (viewer's caps are a subset of access-admin's, so
    // within authority): also 200 (a within-authority write).
    const revoke = await call(ADMIN, "POST", "/admin/roles", { email: TARGET, role: "viewer" });
    ok("access-admin can demote a member to the within-authority viewer role (200)", revoke.status === 200);
    const revokedWho = (await (await call(TARGET, "GET", "/admin/whoami")).json()) as { role: string };
    ok("the demotion takes effect (target back to viewer)", revokedWho.role === "viewer");
    // And access-admin can DELETE (offboard) a non-owner member.
    const delNonOwner = (await (await call(ADMIN, "POST", "/admin/roles/delete", { email: TARGET })).json()) as { deleted: boolean };
    ok("access-admin can offboard a non-owner member (deleted:true)", delNonOwner.deleted === true);

    // 10c) HARD GUARD: access-admin CANNOT grant the owner role (no self-elevation to break-glass). The
    // router gate passes (access-admin holds roles.write), so this is the DO's finer anti-escalation
    // guard firing -> 403 (an authorisation refusal, 037-03) with a generic forbidden body that does not
    // name the owner-escalation reason.
    const grantOwner = await call(ADMIN, "POST", "/admin/roles", { email: NEWOWNER, role: "owner" });
    const goBody = (await grantOwner.json()) as { error?: string };
    ok("access-admin CANNOT grant owner (refused 403 by the DO escalation guard)", grantOwner.status === 403);
    ok("the refusal is the generic forbidden body, not naming the owner-escalation reason", goBody.error === "forbidden" && !/only an Owner/i.test(JSON.stringify(goBody)));
    // The escalation did NOT persist: NEWOWNER was never created as an Owner (or at all).
    const roleList1 = (await (await call(OWNER, "GET", "/admin/roles")).json()) as Array<{ email: string; role: string }>;
    ok("the refused owner grant persisted nothing (NEWOWNER is not an Owner)", !roleList1.some((e) => e.email === NEWOWNER && e.role === "owner"));
    // And an access-admin cannot elevate ITSELF to owner either (the self-minting attack the guard blocks).
    const selfElevate = await call(ADMIN, "POST", "/admin/roles", { email: ADMIN, role: "owner" });
    ok("access-admin CANNOT elevate itself to owner (refused 403)", selfElevate.status === 403);
    const adminStill = (await (await call(ADMIN, "GET", "/admin/whoami")).json()) as { role: string };
    ok("the self-elevation did not persist (still access-admin)", adminStill.role === "access-admin");

    // 10d) HARD GUARD: access-admin CANNOT demote an existing Owner. OWNER and OWNER2 are both Owners at
    // this point, so demoting OWNER2 would NOT trip the last-Owner guard; the refusal is unambiguously
    // the anti-escalation guard (only an Owner may touch the owner role). Refused 400; OWNER2 unchanged.
    const ownersNow = (await (await call(OWNER, "GET", "/admin/roles")).json()) as Array<{ email: string; role: string }>;
    ok("precondition: two Owners exist so a demotion would not trip the last-Owner guard", ownersNow.filter((e) => e.role === "owner").length >= 2);
    const demoteOwner = await call(ADMIN, "POST", "/admin/roles", { email: OWNER2, role: "approver" });
    const doBody = (await demoteOwner.json()) as { error?: string };
    ok("access-admin CANNOT demote an existing Owner (refused 403)", demoteOwner.status === 403);
    ok("the demote refusal is the generic forbidden body, not naming the owner-escalation reason", doBody.error === "forbidden" && !/only an Owner/i.test(JSON.stringify(doBody)));
    const owner2Who = (await (await call(OWNER2, "GET", "/admin/whoami")).json()) as { role: string };
    ok("the refused demotion did not persist (OWNER2 is still owner)", owner2Who.role === "owner");
    // access-admin also cannot DELETE (offboard) an existing Owner.
    const delOwner = await call(ADMIN, "POST", "/admin/roles/delete", { email: OWNER2 });
    const delOwnerBody = (await delOwner.json()) as { error?: string };
    ok("access-admin CANNOT delete an existing Owner (refused 403)", delOwner.status === 403);
    ok("the delete-owner refusal is the generic forbidden body, not naming the owner-escalation reason", delOwnerBody.error === "forbidden" && !/only an Owner/i.test(JSON.stringify(delOwnerBody)));
    const owner2Still = (await (await call(OWNER2, "GET", "/admin/whoami")).json()) as { role: string };
    ok("the refused owner deletion did not persist (OWNER2 still owner)", owner2Still.role === "owner");

    // 10e) OWNER still can do BOTH owner-touching operations (the guard targets non-owners only). But with two
    // Owners (OWNER + OWNER2) already present, minting a THIRD Owner now AUTO-GATES (autoGateOwnerMint, the
    // puppet-owner-laundering guard): the owner-grant queues (202) and a DISTINCT Owner must approve it before
    // it lands, so a lone compromised owner cannot self-mint the "distinct" checker its own high-blast op needs.
    // The AUTHORITY is unchanged (an Owner may appoint an Owner); only the inline-vs-queued shape changed.
    const ownerGrantsOwner = await call(OWNER, "POST", "/admin/roles", { email: NEWOWNER, role: "owner" });
    ok("an Owner's owner-grant auto-gates with two Owners present (202 queued, not inline)", ownerGrantsOwner.status === 202);
    const ownerMintId = ((await ownerGrantsOwner.json()) as { id?: string }).id ?? "";
    const approveOwnerMint = await call(OWNER2, "POST", `/admin/config/changes/${ownerMintId}/approve`);
    ok("a DISTINCT Owner approves the owner-mint and it lands (200)", approveOwnerMint.status === 200);
    const newOwnerWho = (await (await call(NEWOWNER, "GET", "/admin/whoami")).json()) as { role: string };
    ok("the approved owner grant took effect", newOwnerWho.role === "owner");
    const ownerDemotesOwner = await call(OWNER, "POST", "/admin/roles", { email: NEWOWNER, role: "viewer" });
    ok("an Owner CAN demote another Owner (200, >=1 Owner remains)", ownerDemotesOwner.status === 200);
    const demotedNewOwner = (await (await call(NEWOWNER, "GET", "/admin/whoami")).json()) as { role: string };
    ok("the demotion by an Owner took effect", demotedNewOwner.role === "viewer");

    // 10f) The last-Owner guard STILL HOLDS under capability authority. Reduce to a single Owner, then
    // an Owner self-demotion is refused 400 with the last-Owner reason (distinct from the escalation
    // reason). Demote OWNER2 to approver via OWNER so OWNER is the sole Owner again.
    await call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "approver" });
    const soleNow = (await (await call(OWNER, "GET", "/admin/whoami")).json()) as { isOnlyOwner: boolean };
    ok("precondition: OWNER is the sole Owner again", soleNow.isOnlyOwner === true);
    const lastOwner = await call(OWNER, "POST", "/admin/roles", { email: OWNER, role: "viewer" });
    const loBody = (await lastOwner.json()) as { error?: string };
    ok("the last-Owner guard still refuses the sole Owner's self-demotion (400)", lastOwner.status === 400);
    ok("the last-Owner refusal reason is the availability guard, not the escalation guard", typeof loBody.error === "string" && /last Owner/.test(loBody.error));
    // Restore OWNER2 to owner for cleanliness / any later assertions.
    await call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "owner" });

    // 10g) DEFENCE IN DEPTH: the DO RE-RESOLVES the caller's role from its own tables, so a forged caller
    // header CANNOT bypass the escalation guard by asserting role:owner. Drive the DO /roles route
    // DIRECTLY (bypassing the router) with the access-admin's email but a LYING role:owner header; the DO
    // recomputes the role (access-admin in its table) and refuses the owner grant (400). This is strictly
    // stronger than trusting the header role.
    const lyingAdminCaller: Caller = { method: "access", email: ADMIN, subject: subjectOf(ADMIN), role: "owner", groups: [] }; // a LIE: asserts owner (the DO re-resolves the subject to access-admin)
    const directLie = await sched.stub.fetch("https://scheduler.internal/roles", {
      method: "POST",
      headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(lyingAdminCaller) },
      body: JSON.stringify({ email: NEWOWNER, role: "owner" }),
    });
    const dlBody = (await directLie.json()) as { error?: string };
    ok("the DO refuses an owner grant even when the header LIES role:owner for an access-admin (re-resolves)", directLie.status === 403 && dlBody.error === "forbidden" && !/only an Owner/i.test(JSON.stringify(dlBody)));
    // The lying-header escalation persisted nothing.
    const roleList2 = (await (await call(OWNER, "GET", "/admin/roles")).json()) as Array<{ email: string; role: string }>;
    ok("the lying-header owner grant persisted nothing", !roleList2.some((e) => e.email === NEWOWNER && e.role === "owner"));
    // And the DO honours a TRUTHFUL access-admin header for a WITHIN-AUTHORITY grant directly (capability
    // path, re-resolved): the access-admin may persist a role whose caps it holds even when reached
    // directly (access-admin, an equal-caps grant; operator would be refused as it confers downpipe.write).
    const truthfulAdminCaller: Caller = { method: "access", email: ADMIN, subject: subjectOf(ADMIN), role: "access-admin", groups: [] };
    const directOk = await sched.stub.fetch("https://scheduler.internal/roles", {
      method: "POST",
      headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(truthfulAdminCaller) },
      body: JSON.stringify({ email: TARGET, role: "access-admin" }),
    });
    ok("the DO honours a truthful access-admin header for a within-authority grant directly (200)", directOk.status === 200);
    // Cleanup the throwaway target.
    await call(OWNER, "POST", "/admin/roles/delete", { email: TARGET });
  }

  // ---- PROOF 10b: the caller header's `method` axis is router-trusted ----------------------
  // Defence in depth: roleForCaller short-circuits `method:"token"` to owner-token WITHOUT
  // consulting the tables. That is correct because the caller header is ROUTER-INTERNAL: callerHeaders()
  // in router.ts always sets it from the verified verdict and an inbound x-downpipe-caller is
  // overwritten, never copied, so a client cannot forge `method`. The engine RELIES on this path for its
  // own ENGINE_DRILL_CALLER (index.ts), the internal owner-authority token break-glass. We forge a
  // caller header asserting method:"token" DIRECTLY against the DO (the router-only trust boundary, the
  // same technique PROOF 7 uses to bypass the router) and assert the documented behaviour: it resolves
  // to owner authority, even when the asserted email is non-null. Driven through POST /group-roles, whose
  // DO re-check (requireCapabilityResolved -> roleForCaller, access.policy) is exactly the surface
  // roleForCaller feeds, so the test surface matches the "method is as trusted as the header" claim.
  {
    // A token caller with no email (the canonical break-glass shape, identical to ENGINE_DRILL_CALLER):
    // roleForCaller returns owner-token, which holds access.policy, so the group-role write succeeds and
    // is attributed to the token-fallback actor (no email to attribute).
    const tokenCaller: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };
    const rToken = await sched.stub.fetch("https://scheduler.internal/group-roles", {
      method: "POST",
      headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(tokenCaller) },
      body: JSON.stringify({ group: "r13-token-group", role: "operator" }),
    });
    const tokenBody = (await rToken.json()) as { group?: string; role?: string; grantedBy?: string };
    ok("a method:token caller header resolves to owner authority at the DO (group-role write 200)", rToken.status === 200);
    ok("the token caller maps the group (owner-token holds access.policy)", tokenBody.group === "r13-token-group" && tokenBody.role === "operator");
    ok("a no-email token caller is attributed to the token-fallback actor", tokenBody.grantedBy === "token-fallback");

    // A token caller with a NON-NULL email is STILL owner: the `method` axis short-circuits before the
    // email-keyed lookup, so an asserted email never demotes a token caller (and, because the header is
    // router-only, this combination is never reachable from a client; this pins the documented behaviour).
    // The asserted email is NOT in the role table (it would resolve to viewer via the email path), proving
    // the owner outcome comes from the method short-circuit, not from any table grant.
    const tokenWithEmailCaller: Caller = { method: "token", email: "not-in-table@evil.example", subject: null, role: "owner", groups: [] };
    const rTokenEmail = await sched.stub.fetch("https://scheduler.internal/group-roles", {
      method: "POST",
      headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(tokenWithEmailCaller) },
      body: JSON.stringify({ group: "r13-token-email-group", role: "viewer" }),
    });
    const tokenEmailBody = (await rTokenEmail.json()) as { group?: string; role?: string; grantedBy?: string };
    ok("a method:token caller with a non-null email STILL resolves to owner (method short-circuits)", rTokenEmail.status === 200);
    ok("the token+email caller maps the group (owner authority, not the email-path viewer)", tokenEmailBody.group === "r13-token-email-group" && tokenEmailBody.role === "viewer");
    // A token caller WITH an email is attributed to that email (the actor is the caller's email when present).
    ok("a token caller with an email is attributed to that email", tokenEmailBody.grantedBy === "not-in-table@evil.example");

    // Contrast: the SAME asserted email under method:"access" (not token) resolves via the email-keyed
    // lookup to viewer (no table grant), which LACKS access.policy, so the identical group-role write is
    // refused. This proves the owner outcome above is the `method:"token"` short-circuit, not the header.
    const accessSameEmail: Caller = { method: "access", email: "not-in-table@evil.example", subject: subjectOf("not-in-table@evil.example"), role: "owner", groups: [] }; // a LIE: asserts owner; the subject has no grant -> viewer
    const rAccess = await sched.stub.fetch("https://scheduler.internal/group-roles", {
      method: "POST",
      headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(accessSameEmail) },
      body: JSON.stringify({ group: "r13-access-group", role: "operator" }),
    });
    const accessBody = (await rAccess.json()) as { error?: string };
    ok("the same email under method:access (no grant) is refused (the method axis, not the role, decides)", rAccess.status === 403 && typeof accessBody.error === "string" && /forbidden/.test(accessBody.error));
    // Cleanup the throwaway group mappings the token writes created.
    await sched.stub.fetch("https://scheduler.internal/group-roles/delete", {
      method: "POST",
      headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(tokenCaller) },
      body: JSON.stringify({ group: "r13-token-group" }),
    });
    await sched.stub.fetch("https://scheduler.internal/group-roles/delete", {
      method: "POST",
      headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(tokenCaller) },
      body: JSON.stringify({ group: "r13-token-email-group" }),
    });
  }

  // ---- AUTH-77: requireNotOwnerEscalation on the SESSION/CREDENTIAL kill paths ------------------
  // The role-TABLE escalation guard is proven above (PROOF 10c/10d). AUTH-77 closes the SIBLING surfaces a
  // non-owner with roles.write could otherwise use to lock an Owner OUT: terminating an Owner's sessions
  // (scheduler-do-session.ts terminateUserSessions) and revoking an Owner's passkey credential
  // (scheduler-do-recovery.ts revokePasskeyCredential) are BOTH guarded by requireNotOwnerEscalation
  // (scheduler-do-recovery.ts:331 / scheduler-do-session.ts:256), so an access-admin (roles.write, NOT an
  // Owner) is refused 403 against an Owner target while still permitted against a non-owner. Driven through
  // the production router as an access caller (step-up is exempt for the access method), so the 403 is the
  // DO's owner-escalation guard, not a router gate.
  {
    const ADMIN77 = "accessadmin-77@acme.example"; // a fresh access-admin: holds roles.write, is NOT an Owner
    const NONOWNER = "managed-77@acme.example"; // a throwaway non-owner target (the permitted control)
    await call(OWNER, "POST", "/admin/roles", { email: ADMIN77, role: "access-admin" });
    await call(OWNER, "POST", "/admin/roles", { email: NONOWNER, role: "viewer" });
    const ownerRole = ((await (await call(OWNER, "GET", "/admin/roles")).json()) as Array<{ email: string; role: string }>).find((e) => e.email === OWNER)?.role;
    ok("AUTH-77: precondition - OWNER is an Owner (the protected target)", ownerRole === "owner");

    // (a) terminate-user: the access-admin CAN terminate a NON-owner's sessions (roles.write suffices)...
    const termNonOwner = await call(ADMIN77, "POST", "/admin/sessions/terminate-user", { email: NONOWNER });
    ok("AUTH-77: an access-admin CAN terminate a non-owner member's sessions (200, roles.write)", termNonOwner.status === 200);
    // ...but is REFUSED against an OWNER target (requireNotOwnerEscalation: cannot lock an Owner out -> 403).
    const termOwner = await call(ADMIN77, "POST", "/admin/sessions/terminate-user", { email: OWNER });
    const termOwnerBody = (await termOwner.json()) as { error?: string };
    ok("AUTH-77: an access-admin CANNOT terminate an Owner's sessions (refused 403)", termOwner.status === 403 && termOwnerBody.error === "forbidden");

    // ===== terminate-user ANSWERS ok:true FOR AN ADDRESS NO ROSTER ROW HOLDS. THAT IS DELIBERATE. =====
    //
    // This is pinned here so a future reader does not "fix" it into an outage.
    //
    // Membership is NOT the roster. A member signed in through a GROUP MAPPING holds a live session and has
    // no explicit role entry and no pending invitation, so an existence check against those two tables would
    // refuse exactly the offboarding that most needs to work. scheduler-do-rbac-mutations.ts says so in its
    // own words at the deleteRole no-current arm: "terminateUserSessions is already reachable to the same
    // roles.write holder for any address, with no roster membership required and the same unconditional
    // bump" -- another code path's safety argument RESTS on this behaviour.
    //
    // It is also not an enumeration surface to defend: the route is gated on roles.write, and a caller who
    // holds roles.write can read the whole roster from GET /admin/roles, so a refusal would tell them
    // nothing they cannot already list. The bump is unconditional and idempotent, so an address nobody holds
    // costs one epoch counter and changes nothing.
    const termNobody = await call(ADMIN77, "POST", "/admin/sessions/terminate-user", { email: "nobody-holds-this@acme.example" });
    ok("AUTH-77: terminate-user answers 200 ok:true for an address no roster row holds (DELIBERATE, see the comment)", termNobody.status === 200 && ((await termNobody.json()) as { ok?: boolean }).ok === true);
    // The refusal it must NOT be confused with: an unparseable address is still a hard failure, so "answers
    // ok for anything" is not what is being pinned here.
    const termJunk = await call(ADMIN77, "POST", "/admin/sessions/terminate-user", { email: "not an address" });
    ok("AUTH-77: an UNPARSEABLE address is still refused, so the ok:true above is about membership, not about validation", termJunk.status !== 200);

    // (b) revoke passkey credential: seed a credential for the OWNER target so the guard (which is reached
    // only for an EXISTING credential, not the absent-credential idempotent no-op) actually fires.
    const ownerCredId = "auth77-owner-cred";
    await sched.storage.put(`${PASSKEY_CRED_PREFIX}${ownerCredId}`, { credentialId: ownerCredId, email: OWNER, cosePublicKey: "AA", alg: -7, signCount: 0, transports: [], aaguid: "AA", createdAt: new Date().toISOString() });
    const revOwner = await call(ADMIN77, "POST", "/admin/passkey/credentials/delete", { credentialId: ownerCredId });
    const revOwnerBody = (await revOwner.json()) as { error?: string };
    ok("AUTH-77: an access-admin CANNOT revoke an Owner's passkey credential (refused 403)", revOwner.status === 403 && revOwnerBody.error === "forbidden");
    const survived = await sched.storage.get(`${PASSKEY_CRED_PREFIX}${ownerCredId}`);
    ok("AUTH-77: the refused revoke left the Owner's credential intact (Owner not locked out of the passkey path)", survived !== undefined);

    // Cleanup the throwaways.
    await sched.storage.delete(`${PASSKEY_CRED_PREFIX}${ownerCredId}`);
    await call(OWNER, "POST", "/admin/roles/delete", { email: NONOWNER });
    await call(OWNER, "POST", "/admin/roles/delete", { email: ADMIN77 });
  }
}
