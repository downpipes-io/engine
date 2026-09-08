// The RBAC write cluster: the role, group->role mapping and composable custom-role MUTATIONS, plus
// their list views. A sibling sub-mixin of RbacMixin (the role-resolution primitives) and
// RbacAuthorityMixin (caller authority + the anti-escalation guards); all layer over a base whose
// `this` is SchedulerDOSurface, so each write re-resolves the caller through this.roleForCaller and
// re-checks this.requireGrantWithinAuthority / this.requireNotOwnerEscalation / this.countOwners. A
// leaf the assembly depends on, never the reverse.

import { type AuthMethod, type CustomRole, type CustomRoleProposal, capabilitiesOfCustomRole, isConnId, isRole, type PendingRoleEntry, ROLE_CAPABILITIES, type Role, type RoleEntry, rolePendingKey, roleSubjectKey, validateCustomRole } from "../admin/identity.ts";
import { checkOwnerRemoval, OwnerFloorRefusal, ownerRemovalRefusal, strandRefusal, wouldStrandDualControl } from "../admin/owner-floor.ts";
import { recordAdminRefusal, recordAuthzRefusal, recordGovernanceRefusal } from "./sched-fault-ledger.ts";
import { AuthError, CUSTOM_ROLE_PREFIX, GROUP_ROLE_PREFIX, type GroupRoleEntry, type SchedulerDOCtor } from "./scheduler-do-base.ts";
import { nowMillisISO } from "./scheduler-helpers.ts";

export function RbacMutationsMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // setRole upserts a member's role, BY EMAIL (an Owner/access-admin does not know the subject). Gated on
    // roles.write (DO re-check from the caller's RESOLVED role, so owner OR access-admin may manage people),
    // validated, and last-Owner guarded inside one read-modify-write. HARD GUARD: only an Owner may grant
    // the owner role or demote a current Owner (requireNotOwnerEscalation), so an access-admin cannot mint
    // itself Owner. A guard or validation failure THROWS so the existing fetch() catch returns 400 { error }
    // (the same discipline as validateConfig). The grantedBy actor comes from the forwarded caller; a
    // token-fallback Owner has no email -> "token-fallback".
    //
    // SUBJECT-KEYED STORAGE (ASVS V10.3.3 / V10.5.2): if the email is ALREADY BOUND to a subject (the member
    // has authenticated), the existing `role:sub:<subject>` entry is updated IN PLACE (its subject preserved,
    // so the re-grade stays on the same stable identity). Otherwise the grant is recorded as a PENDING invite
    // `role:pending:<email>`, which BINDS to the invitee's subject on their first verified request. Either
    // way the authority is keyed on the immutable subject once bound, never the recyclable email.
    //
    // CUSTOM ROLE ASSIGNMENT: when req.customRole names an existing custom role, the grant references it
    // (the stored role field is pinned to the "viewer" FLOOR and customRole carries the name); the
    // grant's authority then resolves to the custom role's capability set. A custom role can never be
    // owner and can never hold an owner-reserved capability (the create-time guardrails), so a
    // custom-role assignment is never an owner-touching operation: it cannot grant owner, cannot demote
    // the last Owner, and the anti-escalation/last-Owner guards are unaffected. Assigning a non-existent
    // custom role is rejected (you cannot assign a role that does not exist).
    async setRole(
      req: { email?: string; role?: string; customRole?: string; expiresAt?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<(RoleEntry | PendingRoleEntry) & { inviteToken?: string; inviteState?: "minted" | "already-enrolled" }> {
      const resolved = await this.requireCapabilityResolved(caller, "roles.write");
      const email = this.normaliseEmail(req.email);
      if (!email) throw new Error("email must be a valid lowercased address");
      // A grant references EITHER a built-in role OR a custom role, never both. When customRole is
      // present it wins (role is pinned to the viewer floor); otherwise req.role must be a built-in role.
      const assigningCustom = typeof req.customRole === "string" && req.customRole.length > 0;
      let customRec: CustomRole | undefined;
      if (assigningCustom) {
        customRec = await this.state.storage.get<CustomRole>(`${CUSTOM_ROLE_PREFIX}${req.customRole}`);
        if (customRec === undefined) throw new Error(`unknown custom role: ${req.customRole}`);
      } else if (!isRole(req.role)) {
        throw new Error("role must be viewer/operator/approver/owner (or customRole must name an existing custom role)");
      }
      if (req.expiresAt !== undefined) {
        if (typeof req.expiresAt !== "string" || !Number.isFinite(Date.parse(req.expiresAt))) {
          throw new Error("expiresAt must be an RFC-3339 timestamp");
        }
      }
      const now = Date.now();
      const entries = await this.listRoleEntries();
      const pending = await this.listPendingEntries();
      // The target's CURRENT grant (for the guards and the in-place update), found by email across the bound
      // entries first (an authenticated member) then the pending/legacy invitations (a not-yet-bound one).
      const boundCurrent = entries.find((e) => e.email === email);
      const pendingCurrent = pending.find((p) => p.email === email);
      const current: RoleEntry | PendingRoleEntry | undefined = boundCurrent ?? pendingCurrent;

      // The effective built-in role this write stores: the viewer floor when assigning a custom role,
      // else the requested built-in role. A custom-role assignment is therefore never owner.
      const storedRole: Role = assigningCustom ? "viewer" : (req.role as Role);

      // F3 last-Owner guard, RAISED to a two-Owner floor while dual control is armed (the single-owner
      // dual-control deadlock guard, rule b). This fires on a demotion of a current Owner to a non-owner role
      // (including self-demotion) that would drop the estate below its Owner floor: ONE by default (removing
      // the last Owner, the long-standing G-P0-042 refusal, unchanged) and TWO while Require Approver is on
      // (dual control needs a distinct second Owner to approve, so demoting down to a lone Owner would make
      // every maker=checker change permanently unapprovable). The count is the SAME bound + pending Owner tally
      // as before, read above so there is no race with a concurrent write (the DO serialises its own storage);
      // getRequireConfigApproval is the live gate state. checkOwnerRemoval is FAIL-SAFE (an ambiguous count
      // refuses). Under dual control this method runs at PROPOSE time inside dryRunConfigMutation, so a floor
      // breach is refused at propose (a 400), never queued.
      const newRoleIsOwner = storedRole === "owner";
      const targetIsCurrentOwner = current !== undefined && this.effectiveRole(current, now) === "owner";
      if (targetIsCurrentOwner && !newRoleIsOwner) {
        const verdict = checkOwnerRemoval(this.countOwners(entries, pending, now), await this.getRequireConfigApproval());
        if (!verdict.ok) {
          // G175 + G146: record WHICH guard fired, HERE, where it is known. Both refusals throw a plain Error
          // and answer 400 (never the DO's AuthError funnel), so without this the last-Owner guard was DEAD on
          // this path and a governance refusal coalesced with a shape refusal into one indistinguishable
          // {admin-write, refused-validation} row. The raised dual-control floor is the same guard family, so it
          // reuses the same closed counters (last-owner-guard / {rbac-guardrail, guardrail}); the sentence names
          // which floor fired.
          await recordAuthzRefusal(this.state.storage, "last-owner-guard");
          await recordAdminRefusal(this.state.storage, "rbac-guardrail", "guardrail");
          throw new OwnerFloorRefusal(ownerRemovalRefusal(verdict.reason), verdict.reason);
        }
      }

      // THE STRAND INVARIANT (owner-floor.ts wouldStrandDualControl), third entrance. The floor guard above
      // refuses a mutation that drops the Owner count NOW. A TIME-BOXED Owner grant drops it LATER, with no
      // mutation to refuse, which is that module's own residual edge 2. With dual control armed and the
      // break-glass token retired there is no identity left that can disarm unilaterally, so a grant that can
      // lapse is a grant that can strand the estate. It is refused here, at the last moment anything can act,
      // and both remedies it names are still open (grant without an expiry, or turn Require Approver off).
      // Only an OWNER grant carrying an expiresAt is reached: a time-boxed operator or viewer cannot lapse
      // the Owner count, and a permanent Owner grant is the remedy rather than the fault.
      if (newRoleIsOwner && typeof req.expiresAt === "string" && req.expiresAt !== "") {
        if (
          wouldStrandDualControl("grant-expiring-owner", {
            dualControlOn: await this.getRequireConfigApproval(),
            breakGlassRetired: await this.getBreakGlassTokenRetired(),
            expiringOwnerGrants: 0,
          })
        ) {
          await recordAuthzRefusal(this.state.storage, "last-owner-guard");
          await recordAdminRefusal(this.state.storage, "rbac-guardrail", "guardrail");
          throw new Error(strandRefusal("grant-expiring-owner", 1));
        }
      }

      // HARD anti-escalation guard: only an Owner may GRANT the owner role or DEMOTE a current Owner.
      // An access-admin holds roles.write and reached here, but it must not be able to mint itself (or
      // anyone) Owner, nor strip an existing Owner. Computed from the RESOLVED caller role (the DO's own
      // table lookup), so a non-owner cannot bypass it by asserting owner in the forwarded header.
      this.requireNotOwnerEscalation(resolved.role, newRoleIsOwner, targetIsCurrentOwner && !newRoleIsOwner);

      // No-escalation on the grant itself: the assigned role (custom or built-in) may only confer
      // capabilities the assigner already holds, so neither a self-grant nor a delegation can hand out
      // authority beyond the assigner's own (closes the assign-a-strong-custom-role and the
      // access-admin-grants-approver escalations the create-time guard alone did not).
      const assignedCaps = assigningCustom ? capabilitiesOfCustomRole(customRec!) : ROLE_CAPABILITIES[storedRole];
      this.requireGrantWithinAuthority(resolved, assignedCaps);

      const actor = caller?.email ? caller.email : "token-fallback";
      // Persist the grant. If the email is already BOUND to a subject, update that subject-keyed entry in
      // place (preserving the stable subject and the display email); otherwise write a PENDING invite keyed
      // by email, which binds to a subject on first auth. The returned record is the persisted shape.
      let entry: RoleEntry | PendingRoleEntry;
      if (boundCurrent !== undefined) {
        entry = {
          subject: boundCurrent.subject,
          email,
          role: storedRole,
          grantedBy: actor,
          grantedAt: nowMillisISO(),
          ...(assigningCustom ? { customRole: req.customRole } : {}),
          ...(req.expiresAt !== undefined ? { expiresAt: req.expiresAt } : {}),
        };
        await this.state.storage.put(roleSubjectKey(boundCurrent.subject), entry);
      } else {
        entry = {
          email,
          role: storedRole,
          grantedBy: actor,
          grantedAt: nowMillisISO(),
          ...(assigningCustom ? { customRole: req.customRole } : {}),
          ...(req.expiresAt !== undefined ? { expiresAt: req.expiresAt } : {}),
        };
        await this.state.storage.put(rolePendingKey(email), entry);
        // Clear any legacy `role:<email>` row this pending now supersedes (so resolution does not see two
        // invitations for one email). Best-effort delete; absent is fine.
        await this.state.storage.delete(`role:${email}`);
      }
      // REGISTRATION INVITE (the second proven registration path): granting a role to an email that has
      // NO passkey credential yet is the Owner/access-admin AUTHORISING that email to enrol its first key.
      // Mint a single-use, email-bound, TTL'd invite at this commit point and return its token so the
      // router can embed it in the role-invite email's registration link. The bound email is the canonical
      // email this grant just persisted (never a client claim), so a non-bootstrap register/finish can take
      // the email FROM the invite, not the client field. mintRegistrationInvite returns null when the email
      // already has a credential (no invite needed: a second key is added via the self-add path), so an
      // invite is minted only when enrolment is actually pending.
      const inviteToken = await this.mintRegistrationInvite(email, now);
      // Record the role change in the audit chain as a by-product of the successful write (the
      // commit point, so the log reflects what actually happened). The actor is the granting Owner;
      // the target carries only the member email and the new role, both already the role table's own
      // data, never a secret. A token-fallback Owner has no attributable email (actorEmail null). A
      // custom-role assignment is recorded as a custom-role-change naming the assigned role (the
      // role-table view shows the viewer floor; the custom-role-change is the honest assignment signal).
      if (assigningCustom) {
        await this.appendAudit({
          actorSubject: caller ? caller.subject : null,
          actorEmail: caller?.email ? caller.email : null,
          actorMethod: caller ? caller.method : "access",
          sourceIp: caller?.sourceIp ?? null,
          action: "custom-role-change",
          outcome: "success",
          // engine-src-039-05: record the ASSIGNED custom role's real capability count, not 0. customRec is
          // the role record loaded and existence-checked above (the assignment is rejected when it is absent),
          // so this is the same stored authority count addCustomRole audits at creation, keeping the trail honest.
          target: { kind: "customrole", name: req.customRole as string, capabilityCount: customRec!.capabilities.length },
        });
      } else {
        await this.appendAudit({
          actorSubject: caller ? caller.subject : null,
          actorEmail: caller?.email ? caller.email : null,
          actorMethod: caller ? caller.method : "access",
          sourceIp: caller?.sourceIp ?? null,
          action: "role-change",
          outcome: "success",
          target: { kind: "role", email, role: storedRole },
        });
      }
      // The persisted record stays a clean Role/PendingRoleEntry; the inviteToken (when one was minted) is
      // returned ALONGSIDE it for the router's invite email, not stored on the role row.
      //
      // inviteState (G340) is returned on BOTH arms, and that is the point of it. A grant that comes back with
      // no token has always had two meanings -- the person already has a passkey (no invite is needed, none is
      // minted) and this engine has no invite mint at all -- and the console could not tell them apart, so it
      // fell back to the same "they are emailed if invites are configured" toast for both. One of those states
      // is correct and the other means the new member is authorised and can never sign in. The engine is the
      // only party that knows which, so it now says so, and a response carrying NEITHER field is an engine that
      // predates the mint, which the console records as skew rather than guessing at.
      return inviteToken !== null
        ? { ...entry, inviteToken, inviteState: "minted" as const }
        : { ...entry, inviteState: "already-enrolled" as const };
    }

    // deleteRole removes a member entirely (a distinct, audited offboarding action). Gated on
    // roles.write (DO re-check from the RESOLVED role: owner OR access-admin), last-Owner guarded, and
    // (HARD GUARD) only an Owner may remove a member who is currently an Owner (requireNotOwnerEscalation),
    // so an access-admin cannot strip an Owner. All refusals THROW -> 400. Deleting an absent member is a
    // no-op success (idempotent offboarding), returning { deleted: false }.
    async deleteRole(
      req: { email?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ deleted: boolean }> {
      const resolved = await this.requireCapabilityResolved(caller, "roles.write");
      const email = this.normaliseEmail(req.email);
      if (!email) throw new Error("email must be a valid lowercased address");
      const now = Date.now();
      const entries = await this.listRoleEntries();
      const pending = await this.listPendingEntries();
      // The target by email across the bound entries (an authenticated member) then the pending/legacy
      // invitations (a not-yet-bound one). Offboarding removes whichever exists; an absent member is a no-op.
      const boundCurrent = entries.find((e) => e.email === email);
      const pendingCurrent = pending.find((p) => p.email === email);
      const current: RoleEntry | PendingRoleEntry | undefined = boundCurrent ?? pendingCurrent;
      // AN OFFBOARD OF SOMEBODY THIS TABLE CANNOT SEE IS STILL AN OFFBOARD. resolveRole is max(email-table
      // role, highest group-mapped role, viewer), and groupRoleFor needs no row of any kind, so a member whose
      // authority comes ONLY from an IdP GROUP CLAIM has nothing under `role:`. This bumps the session epoch
      // for that email below even when there is no row to delete, so a group-claim-only member's session
      // fails closed on their next request. revokeSignInFactors does not cover this case: it scopes its own
      // epoch bump to a revocation that closed a way in, and such a member holds no passkey, no recovery
      // record and no invite. The SCIM leaver path posts only /roles/delete, so this keeps an automated
      // deprovision effective even for group-claim-only members.
      //
      // The bump is on the EMAIL axis only, because that is the only axis an operator holding an address can
      // name: the subject of a group-claim member exists solely inside their own signed cookie. It is
      // sufficient, not a compromise -- passkeySessionVerify checks the email epoch for EVERY method, oidc and
      // saml included, before it reaches the subject axis.
      //
      // WHO THIS CAN LOCK OUT: nobody. It ends sessions, it does not remove authority, and it grants this
      // caller nothing new -- terminateUserSessions is already reachable to the same roles.write holder for any
      // address, with no roster membership required and the same unconditional bump. Anybody still entitled
      // signs in again and resolves the same role, because the group mapping is deliberately untouched: a
      // mapping is estate policy about a directory of people, not this person's grant, and destroying it here
      // would offboard everybody who holds it. An Owner can never reach this arm (an owner always has an
      // explicit named grant, and a group can never map to owner), so no availability floor is in play.
      //
      // `deleted` stays FALSE, because nothing was deleted: SCIM's removed-signal and the console's row both
      // read it and neither should be told a grant went away that never existed. The audit entry is the record.
      if (!current) {
        await this.bumpSessionEpoch(email);
        await this.appendAudit({
          actorSubject: caller ? caller.subject : null,
          actorEmail: caller?.email ? caller.email : null,
          actorMethod: caller ? caller.method : "access",
          sourceIp: caller?.sourceIp ?? null,
          // session-terminate, NOT role-change: nobody's role changed, and the offboarding role-change entry
          // asserts a demotion to viewer that did not happen here. The role recorded is the effective role of
          // an absent entry, which matches terminateUserSessions filing the same action for the same shape of
          // target; the group-conferred role is not knowable from an address alone.
          action: "session-terminate",
          outcome: "success",
          target: { kind: "role", email, role: this.effectiveRole(undefined, now) },
        });
        return { deleted: false };
      }
      const targetIsCurrentOwner = this.effectiveRole(current, now) === "owner";
      // F3 offboard guard, RAISED to a two-Owner floor while dual control is armed (rule b, the same invariant
      // as the setRole demotion arm above): refuse removing a current Owner that would drop the estate below
      // its Owner floor (one by default, two while Require Approver is on). Same bound + pending tally and live
      // gate read; checkOwnerRemoval is fail-safe. The SCIM offboard path reaches deleteRole directly (bypassing
      // only the approval queue, never this guard), so an automated deprovision cannot strand the estate either.
      if (targetIsCurrentOwner) {
        const verdict = checkOwnerRemoval(this.countOwners(entries, pending, now), await this.getRequireConfigApproval());
        if (!verdict.ok) {
          // G175 + G146: THE OFFBOARDING GUARD, recorded where WHICH guard fired is known (both refusals throw a
          // plain Error -> 400 and never reach the AuthError funnel). The raised dual-control floor is the same
          // guard family, so it reuses the same closed counters; the sentence names which floor fired.
          await recordAuthzRefusal(this.state.storage, "last-owner-guard");
          await recordAdminRefusal(this.state.storage, "rbac-guardrail", "guardrail");
          throw new OwnerFloorRefusal(ownerRemovalRefusal(verdict.reason), verdict.reason);
        }
      }
      // HARD anti-escalation guard: removing a current Owner is an owner-touching operation, so only an
      // Owner may do it. An access-admin (roles.write) may offboard any non-owner member, but not an Owner.
      this.requireNotOwnerEscalation(resolved.role, false, targetIsCurrentOwner);
      // Remove the member's grant wherever it lives: the bound subject-keyed entry AND any pending/legacy
      // GRANT row for the email (`role:pending:<email>` and the legacy `role:<email>`), so an offboarded
      // person's unbound grant cannot bind to their subject on a later login. `deleted` is true when anything
      // was actually removed.
      //
      // WHAT THIS DOES NOT REACH: a registration invite is stored under `passkeyInvite:<TOKEN>`, keyed by the
      // secret itself, so an email-keyed delete here cannot reach it. Redeeming an outstanding invite after an
      // offboard is refused by the roster gate on the invite arm of resolveRegistrationAuthorisation, and the
      // invite is burned, along with the credentials and the recovery record, only by revokeSignInFactors,
      // which is a separate operator act on purpose. Sweeping outstanding invites at offboard time as well is
      // known, untracked debt. So: this deletes GRANTS, and it deletes nothing else.
      let deleted = false;
      if (boundCurrent !== undefined) {
        deleted = (await this.state.storage.delete(roleSubjectKey(boundCurrent.subject))) || deleted;
      }
      for (const k of this.pendingStorageKeysFor(email)) {
        deleted = (await this.state.storage.delete(k)) || deleted;
      }
      // Offboarding is a distinct, audited role-change. Record the removal as a role change to
      // viewer (the least-privilege resting state of an absent member, matching roleFor's default),
      // so the trail reads "member was removed / dropped to no privilege" without a separate action
      // enum. Only recorded when a member actually existed and was removed.
      if (deleted) {
        // OFFBOARDING TERMINATES SESSIONS (ASVS V7.4.2 / V7.4.1, the L1 must-fix). Removing the role does NOT
        // on its own invalidate a live session: per-request role re-resolution only DOWNGRADES the offboarded
        // member to viewer, leaving the inventory/audit/reports/roster/restore-dryrun read surface live for up
        // to the 12h TTL (adversarially confirmed). Bump the revocation axes so the NEXT request from any of
        // their sessions fails closed at the verify-time gate: the per-email epoch counter, and (for a bound
        // member) the per-subject not-before instant, which also kills any oidc/saml session keyed on the
        // subject. Mirrors terminateUserSessions (7886/7891); the existing verify gate enforces both for free.
        await this.bumpSessionEpoch(email);
        if (boundCurrent !== undefined) await this.bumpSessionEpochSub(boundCurrent.subject, now);
        await this.appendAudit({
          actorSubject: caller ? caller.subject : null,
          actorEmail: caller?.email ? caller.email : null,
          actorMethod: caller ? caller.method : "access",
          sourceIp: caller?.sourceIp ?? null,
          action: "role-change",
          outcome: "success",
          target: { kind: "role", email, role: "viewer" },
        });
      }
      return { deleted };
    }

    // listGroupRoles returns the group->role mapping as-is (readable by any authenticated caller;
    // reading the mapping is not a write). A group name is the customer's own directory data in their
    // own account; the console escapes it on render.
    async listGroupRoles(): Promise<GroupRoleEntry[]> {
      return this.listGroupRoleEntries();
    }

    // setGroupRole upserts an identity-provider group -> role mapping. Gated on the access.policy
    // capability (owner OR access-admin), and the DO RE-RESOLVES the caller's role from its own tables
    // (requireCapabilityResolved), not the asserted header role, so a router bug or an elevated header
    // cannot grant a mapping write. CRITICAL SECURITY CAP (unchanged): a group may map to any role
    // EXCEPT owner; an attempt to map a group to OWNER is rejected with a clear 400, so owner stays an
    // explicit, named, per-email grant and the last-Owner guard (which counts only `role:` owner
    // entries) is never affected by a group. Because a group can never confer owner, allowing
    // access.policy here does NOT let an access-admin escalate to owner via the mapping. A
    // guard/validation failure THROWS so the existing fetch() catch returns 400 { error } (the same
    // discipline as setRole). The change is recorded in the audit chain as a redaction-safe
    // group-role-change carrying only the group name + role (the customer's own data, never a secret).
    async setGroupRole(
      req: { group?: string; role?: string; customRole?: string; connId?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<GroupRoleEntry> {
      const resolved = await this.requireCapabilityResolved(caller, "access.policy");
      const group = this.normaliseGroup(req.group);
      if (!group) throw new Error("group must be a non-empty name up to 256 characters");
      // G2: an optional connId SCOPES this mapping to logins through that ONE IdP connection (closing the
      // cross-IdP group-name collision); absent = GLOBAL (the legacy behaviour, unchanged). Validate it when present.
      const scopeConnId = typeof req.connId === "string" && req.connId.length > 0 ? req.connId : undefined;
      if (scopeConnId !== undefined && !isConnId(scopeConnId)) throw new Error("connId must be a valid connection id");
      // A mapping references EITHER a built-in role OR a custom role. When customRole is present it wins
      // (the stored role field is pinned to the viewer floor); otherwise req.role must be a built-in role.
      // A custom role can never be owner (the create-time guardrail), so the owner cap below is never
      // reachable via a custom-role mapping; mapping a group to a custom role is the equivalent of the
      // per-email custom-role assignment, just keyed on an IdP group.
      const assigningCustom = typeof req.customRole === "string" && req.customRole.length > 0;
      let customRec: CustomRole | undefined;
      if (assigningCustom) {
        customRec = await this.state.storage.get<CustomRole>(`${CUSTOM_ROLE_PREFIX}${req.customRole}`);
        if (customRec === undefined) throw new Error(`unknown custom role: ${req.customRole}`);
      } else if (!isRole(req.role)) {
        throw new Error("role must be viewer/operator/approver/owner (or customRole must name an existing custom role)");
      }
      // THE CAP: a group may NEVER map to owner. owner is an explicit, named, per-email grant (the
      // break-glass owner is a specific person, not a group), so reject it here at the authority
      // boundary with a precise reason. This also keeps the last-Owner guard coherent. (A custom-role
      // mapping pins the built-in role to viewer, so this can only fire on a direct built-in owner map.)
      if (!assigningCustom && req.role === "owner") throw new AuthError("a group cannot be mapped to owner; owner must be an explicit per-email grant");
      const storedRole: Role = assigningCustom ? "viewer" : (req.role as Role);
      // No-escalation on the group mapping itself: same invariant as setRole - the mapped role may only
      // confer capabilities the assigner holds, so an access.policy holder cannot map a group to a role
      // that hands a directory of people a capability the assigner lacks.
      const assignedCaps = assigningCustom ? capabilitiesOfCustomRole(customRec!) : ROLE_CAPABILITIES[storedRole];
      this.requireGrantWithinAuthority(resolved, assignedCaps);
      const actor = caller?.email ? caller.email : "token-fallback";
      const entry: GroupRoleEntry = {
        group,
        role: storedRole,
        grantedBy: actor,
        grantedAt: nowMillisISO(),
        ...(assigningCustom ? { customRole: req.customRole } : {}),
        ...(scopeConnId !== undefined ? { connId: scopeConnId } : {}),
      };
      await this.state.storage.put(`${GROUP_ROLE_PREFIX}${group}`, entry);
      // Record the change as a by-product of the successful write (the commit point). The actor is the
      // granting Owner; the target carries only the group NAME + the role (or the custom-role name), both
      // the mapping's own redaction-safe data, never a secret. A custom-role mapping is recorded as a
      // custom-role-change naming the assigned role.
      if (assigningCustom) {
        await this.appendAudit({
          actorSubject: caller ? caller.subject : null,
          actorEmail: caller?.email ? caller.email : null,
          actorMethod: caller ? caller.method : "access",
          sourceIp: caller?.sourceIp ?? null,
          action: "custom-role-change",
          outcome: "success",
          // engine-src-039-05: record the MAPPED custom role's real capability count, not 0. customRec is the
          // role record loaded and existence-checked above (the mapping is rejected when it is absent), so this
          // matches the count addCustomRole audits at creation, keeping the group-mapping trail honest.
          target: { kind: "customrole", name: req.customRole as string, capabilityCount: customRec!.capabilities.length },
        });
      } else {
        await this.appendAudit({
          actorSubject: caller ? caller.subject : null,
          actorEmail: caller?.email ? caller.email : null,
          actorMethod: caller ? caller.method : "access",
          sourceIp: caller?.sourceIp ?? null,
          action: "group-role-change",
          outcome: "success",
          target: { kind: "grouprole", group, role: storedRole },
        });
      }
      return entry;
    }

    // deleteGroupRole removes a group->role mapping (a distinct, audited action). Gated on access.policy
    // (owner OR access-admin); the DO re-resolves the caller's role from its own tables
    // (requireCapabilityResolved). Deleting an absent mapping is an idempotent no-op success returning
    // { deleted: false }; it records an audit entry only when something was actually removed (mirroring
    // deleteRole). There is no last-Owner concern here because a group can never confer owner, so
    // removing a mapping can never remove the last Owner.
    async deleteGroupRole(
      req: { group?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ deleted: boolean }> {
      await this.requireCapabilityResolved(caller, "access.policy");
      const group = this.normaliseGroup(req.group);
      if (!group) throw new Error("group must be a non-empty name up to 256 characters");
      const deleted = await this.state.storage.delete(`${GROUP_ROLE_PREFIX}${group}`);
      if (deleted) {
        // Record the removal as a group-role change to viewer (the least-privilege resting state of an
        // unmapped group, matching resolveRole's default), so the trail reads "group mapping removed"
        // without a separate action enum. Only recorded when a mapping actually existed.
        await this.appendAudit({
          actorSubject: caller ? caller.subject : null,
          actorEmail: caller?.email ? caller.email : null,
          actorMethod: caller ? caller.method : "access",
          sourceIp: caller?.sourceIp ?? null,
          action: "group-role-change",
          outcome: "success",
          target: { kind: "grouprole", group, role: "viewer" },
        });
      }
      return { deleted };
    }

    // ---- Composable custom roles (OPTIONAL, additive) -------------------------------------
    // A custom role is an account-defined NAMED capability bundle, stored under `customrole:<name>`,
    // reachable only by an explicit email grant or a group mapping that references its name. The CRUD
    // gates on access.policy (the people-and-access-policy capability), the SAME gate as the group
    // mapping (defining who may hold which authority is access policy). The DO re-resolves the caller's
    // effective AUTHORITY from its own tables (requireCapabilityResolved), never trusting the asserted
    // role or a forwarded capability set. The HARD guardrails live in the pure validateCustomRole
    // (identity.ts), which the DO drives against the CREATOR's OWN resolved capability set so a creator
    // can never put a capability they do not hold (no privilege escalation) nor an owner-reserved
    // capability into a custom role, and a surface "edit" must be backed by the matching write capability.

    // listCustomRoles returns the custom-role catalogue as-is (readable by any authenticated caller;
    // reading the catalogue is not a write). The records carry no secret, so it is safe to return to the
    // customer's own console.
    async listCustomRoles(): Promise<CustomRole[]> {
      const map = await this.listCustomRoleRecords();
      return [...map.values()];
    }

    // addCustomRole creates or updates a custom role. Gated on access.policy (DO re-resolves the caller's
    // authority from its own tables). The HARD guardrails are enforced by validateCustomRole against the
    // CREATOR's OWN resolved capability set (the no-escalation check): every capability in the role must
    // be one the creator themselves holds, none may be owner-reserved, and a surface "edit" requires the
    // role to hold the screen's write capability. A guardrail failure THROWS so the existing fetch()
    // catch returns 400 { error } (the same discipline as validateConfig). On success the record is
    // stamped with createdBy (the verified creator email, null for the bare-token break-glass) and
    // createdAt, persisted, and a redaction-safe custom-role-change is appended (the name + capability
    // count only, never the capability list).
    async addCustomRole(
      proposal: CustomRoleProposal,
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<CustomRole> {
      // requireCapabilityResolved returns the caller's RESOLVED effective capability set, which is exactly
      // the set the no-escalation guard intersects the proposed capabilities against: a creator can grant
      // ONLY capabilities they themselves hold, recomputed from the DO's own tables (never a forwarded
      // set). The token-fallback break-glass resolves to owner's full set, so it may compose any
      // non-owner-reserved role (it still cannot put keys.ceremony / posture.riskaccept in, the
      // owner-reserved bar holding even for the owner: those stay the owner's named, non-delegable powers).
      const resolved = await this.requireCapabilityResolved(caller, "access.policy");
      const result = validateCustomRole(proposal, resolved.capabilities);
      if (!result.ok) {
        // G182: an attempted PRIVILEGE ESCALATION through a custom role is now its own counted, dated fact.
        // The two escalation refusals are tagged by the validator itself; an ordinary validation failure (a
        // bad name, a hidden landing screen) is NOT one and records nothing, so the counter cannot be inflated
        // by typos -- a signal that cries wolf devalues every true one, and this signal's whole value is that
        // a non-zero count means someone genuinely tried.
        if (result.escalation !== undefined) await recordGovernanceRefusal(this.state.storage, "role-escalation", result.escalation);
        throw new Error(result.reason);
      }
      const record: CustomRole = {
        ...result.role,
        createdBy: caller?.email ? caller.email : null,
        createdAt: nowMillisISO(),
      };
      await this.state.storage.put(`${CUSTOM_ROLE_PREFIX}${record.name}`, record);
      await this.appendAudit({
        actorSubject: caller ? caller.subject : null,
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "custom-role-change",
        outcome: "success",
        target: { kind: "customrole", name: record.name, capabilityCount: record.capabilities.length },
      });
      return record;
    }

    // deleteCustomRole removes a custom role. Gated on access.policy (DO re-resolves the caller's
    // authority). Deleting an absent role is an idempotent no-op success returning { deleted: false }
    // (mirroring deleteGroupRole); it records an audit entry only when something was actually removed.
    // Any email grant or group mapping still REFERENCING the deleted role falls back to the viewer floor
    // at resolution (resolveAuthority ignores a name that no longer exists), so removing a custom role
    // drops its holders to least privilege rather than failing open. The grants are NOT swept here (the
    // resolution-time fallback is sufficient and avoids an unbounded write), matching the lazy-expiry
    // discipline elsewhere.
    async deleteCustomRole(
      req: { name?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ deleted: boolean }> {
      await this.requireCapabilityResolved(caller, "access.policy");
      if (typeof req.name !== "string" || req.name.length === 0) throw new Error("name must be a non-empty custom-role name");
      const name = req.name.trim().toLowerCase();
      // G301: count the grants that STILL name this role, BEFORE it goes. Every one of them drops to the
      // viewer floor at resolution on its holder's next request, and until now the deletion FACT rode in the
      // pack while its CONSEQUENCE rode nowhere: a member could lose access after a role tidy-up with nothing
      // linking the loss to the tidy-up. Both tables confer the role and a group grant can carry a whole
      // team, so counting only the member table would under-report the blast radius.
      //
      // It is counted HERE, in the DO, and not in the browser, because the browser is not always present:
      // under change control this method runs at APPROVE time, replayed by gatedConfigMutation with no
      // console in the loop, which is exactly the governance-mature account where the linkage matters most.
      // Counts only: never a holder's subject, email or the role's capability list.
      const members = await this.listRoles();
      const groups = await this.listGroupRoles();
      const affectedGrantCount = members.filter((r) => r.customRole === name).length + groups.filter((r) => r.customRole === name).length;
      const deleted = await this.state.storage.delete(`${CUSTOM_ROLE_PREFIX}${name}`);
      if (deleted) {
        // G061: deleting a custom role that still has HOLDERS silently demotes every one of them to their
        // built-in floor. The signal is gated on there BEING holders: its name asserts a blast radius, and a
        // signal that fires on the deletion of a role nobody held asserts a fact the code never established,
        // which sends a support engineer hunting demotions that never happened.
        if (affectedGrantCount > 0) await this.recordAuthSignal("rbac-custom-role-delete-blast-radius");
        await this.appendAudit({
          actorSubject: caller ? caller.subject : null,
          actorEmail: caller?.email ? caller.email : null,
          actorMethod: caller ? caller.method : "access",
          sourceIp: caller?.sourceIp ?? null,
          action: "custom-role-change",
          outcome: "success",
          // A removal is signalled by a 0 capability count (the role no longer bundles anything).
          target: { kind: "customrole", name, capabilityCount: 0, affectedGrantCount },
        });
      }
      return { deleted };
    }
  };
}
