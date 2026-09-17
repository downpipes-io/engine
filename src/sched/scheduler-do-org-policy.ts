// The account-wide ORG-POLICY record and the shared gate state. OrgPolicyMixin owns the single
// ORG_POLICY_KEY record (read once, merge-written so the three flags never race-clobber each other), the
// opt-in requireConfigApproval gate flag, the effectiveOwnerActionGateOn decision both gate sites consult,
// and the one-way bootstrap-consumed + break-glass-token-retired latches (with their owner-gated setter).
// It is the shared leaf the config-change gate (scheduler-do-change-control.ts), the owner-action gate
// (scheduler-do-dual-control.ts), the RBAC bootstrap, the passkey first-Owner enrolment, the auth wiring
// and the status/posture slice all read through `this`. Layered over a base whose `this` is
// SchedulerDOSurface, so countOwners / roleForCaller / appendAudit / recoveryBreakGlassVerdict dispatch
// through `this`. The gate can never deadlock its own off switch, the owner re-check and the
// break-glass-in-place precondition hold, and the ORG_POLICY_KEY shape stays stable. This is a leaf that
// the rest of the assembly depends on, never the reverse.

import type { AuthMethod } from "../admin/identity.ts";
import { isHighBlastAlwaysGated, type OwnerActionKind } from "../admin/owner-action.ts";
import type { PasskeyOwnerEvidence } from "../admin/passkey.ts";
import type { RecoveryBreakGlassReason } from "../admin/recovery.ts";
import { strandRefusal, wouldStrandDualControl } from "../admin/owner-floor.ts";
import { validateEgressAllowlist } from "../notify/types.ts";
import { AuthError, ORG_POLICY_KEY, type OrgPolicy, type SchedulerDOCtor } from "./scheduler-do-base.ts";

export function OrgPolicyMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // ---- OPT-IN dual-control change control for CONFIG mutations (default OFF) -------------------
    // When the org setting requireConfigApproval is OFF (the default), the config-mutation routes apply
    // inline: the gate code below short-circuits to a direct applyConfigMutation, adding no friction. When
    // it is ON, a config mutation is VALIDATED at propose time (dryRunConfigMutation runs the SAME validated
    // method under a storage checkpoint+rollback, so a bad/unauthorised request is rejected NOW, not
    // deferred) and, instead of committing, a PENDING CHANGE is recorded for a SECOND identity to approve
    // (maker != checker, holding the same write capability). On a clean approve the SAME validated method is
    // REPLAYED (one apply code path), which auto-snapshots into config history recording both the proposer
    // and the approver. This reuses the restore dual-control discipline (change-control.ts is the pure logic,
    // this DO is the storage authority) and the config-history diff; it never forks a second divergent write.

    // getRequireConfigApproval reads the gate flag (default OFF when the policy record or the field is
    // absent), so a tenant that never set it gets the no-friction default. It is the single read point the
    // mutation dispatch consults.
    async getRequireConfigApproval(): Promise<boolean> {
      const policy = (await this.state.storage.get<OrgPolicy>(ORG_POLICY_KEY)) ?? null;
      return policy !== null && policy.requireConfigApproval === true;
    }

    // getRequireRestoreApproval reads the RESTORE-apply dual-control flag (default OFF when the policy
    // record or the field is absent). It is the single read point the restore apply path consults, and it is
    // deliberately a SEPARATE flag from requireConfigApproval: the two gates cover different actions (a
    // config mutation versus a write-back over live data) and an estate may reasonably want either without
    // the other. Treating one as the other would misrepresent the restore gate as optional when it is not.
    async getRequireRestoreApproval(): Promise<boolean> {
      const policy = (await this.state.storage.get<OrgPolicy>(ORG_POLICY_KEY)) ?? null;
      return policy !== null && policy.requireRestoreApproval === true;
    }

    // getRequireAllUpdateApproval reads the "gate EVERY engine update" flag (default OFF when the policy
    // record or the field is absent), so a tenant that never set it gets the no-friction default. It is the
    // single read point the update-apply, update-settle, update-ramp and component-apply routes consult
    // before deciding whether the vendor's declared risk class may excuse an apply from the second-owner
    // gate; updateNeedsDualControl in router-core.ts takes the answer as its second argument.
    async getRequireAllUpdateApproval(): Promise<boolean> {
      const policy = (await this.state.storage.get<OrgPolicy>(ORG_POLICY_KEY)) ?? null;
      return policy !== null && policy.requireAllUpdateApproval === true;
    }

    // setRequireAllUpdateApproval is the OWNER-ONLY toggle for that flag. It mirrors setNotifyNewSignInContext
    // in shape (owner re-resolved from the DO's own tables, MERGE-write, config-policy-change audit naming the
    // policy and the direction) and differs from it in what it governs, so the two departures are stated here
    // rather than left to be inferred.
    //
    // NO TWO-OWNER FLOOR ON ARMING, unlike setRequireRestoreApproval, and the reason is that this flag cannot
    // deadlock anyone: it never turns a gate ON. It removes the vendor's risk class as an EXCUSE from a gate
    // that is already on, and the gate's own arm path (setRequireConfigApproval) already carries the
    // two-owner floor, while the high-blast auto-apply engages only at two owners. On a one-owner estate the
    // gate is off, so arming this changes nothing until a second Owner exists, which is the moment the floor
    // would have been satisfied anyway.
    //
    // DISARM IS IMMEDIATE AND NOT ASYMMETRIC, the same deliberate, recorded gap setRequireRestoreApproval
    // carries: an Owner turning it off returns the account to the vendor-declared risk classes, and the
    // asymmetric off switch would need its own owner-action kind and dispatch. It is not claimed anywhere as
    // present. What is present: the master dual-control gate is untouched by this toggle, an apply still
    // requires the apply capability and an operator-supplied deploy credential, and every change is audited.
    async setRequireAllUpdateApproval(
      req: { requireAllUpdateApproval?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ requireAllUpdateApproval: boolean; disarmed: boolean }> {
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may change the update-approval policy");
      if (typeof req.requireAllUpdateApproval !== "boolean") throw new Error("requireAllUpdateApproval must be a boolean");
      const wasOn = await this.getRequireAllUpdateApproval();
      const disarmed = wasOn && req.requireAllUpdateApproval === false;
      await this.writeOrgPolicy({ requireAllUpdateApproval: req.requireAllUpdateApproval });
      await this.appendAudit({
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "config-policy-change",
        outcome: "success",
        // policyName + direction only, the same redaction class as the sibling toggles.
        target: { kind: "access-policy", policyName: "update-approval", newValue: req.requireAllUpdateApproval === true },
      });
      return { requireAllUpdateApproval: req.requireAllUpdateApproval, disarmed };
    }

    // expiringOwnerGrantCount counts the currently-EFFECTIVE Owner grants that carry an expiresAt: the third
    // leg of the strand invariant (owner-floor.ts).
    //
    // IT COUNTS PENDING INVITES TOO. A second Owner who has been invited but has not yet signed in is stored
    // as a PENDING entry, not a bound one, so a guard reading only the bound table would see ZERO expiring
    // grants and allow the whole combination to assemble. An Owner invited with an expiry, where the retire
    // or the arm happens before they have ever authenticated, is the commonest shape this guards against.
    // countOwners counts pending entries for precisely this reason ("an unexpired pending Owner invite binds
    // on first auth, so it is a real way back in"), and the same fact makes it a real way to LOSE one.
    //
    // A grant whose expiresAt does not parse is counted, matching effectiveRole's own fail-open: an
    // unparseable timestamp is a grant nobody can reason about, which is the case this refusal exists for.
    async expiringOwnerGrantCount(): Promise<number> {
      const now = Date.now();
      const expiring = (e: { role?: string; expiresAt?: string }): boolean =>
        this.effectiveRole(e as never, now) === "owner" && typeof e.expiresAt === "string" && e.expiresAt !== "";
      return (await this.listRoleEntries()).filter(expiring).length + (await this.listPendingEntries()).filter(expiring).length;
    }

    // getNotifyNewSignInContext reads the opt-in unusual-location sign-in policy, default OFF when the
    // record or the field is absent, so a tenant that never enabled it keeps the default. It is the single
    // read point the sign-in paths consult before doing the coarse-context comparison.
    async getNotifyNewSignInContext(): Promise<boolean> {
      const policy = (await this.state.storage.get<OrgPolicy>(ORG_POLICY_KEY)) ?? null;
      return policy !== null && policy.notifyNewSignInContext === true;
    }

    // setNotifyNewSignInContext is the OWNER-ONLY toggle for the unusual-location sign-in notify
    // (default OFF; opt-in per account). It mirrors setRequireChangeNumber exactly: the DO re-resolves
    // owner from its own tables, MERGE-writes the org policy, applies immediately (a notify preference is
    // a process control, not a security control, so it is not dual-control-gated) and records the
    // redaction-safe config-policy-change audit event (the boolean rides the response, never the log).
    async setNotifyNewSignInContext(
      req: { notifyNewSignInContext?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ notifyNewSignInContext: boolean }> {
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may change the sign-in-context notify policy");
      if (typeof req.notifyNewSignInContext !== "boolean") throw new Error("notifyNewSignInContext must be a boolean");
      await this.writeOrgPolicy({ notifyNewSignInContext: req.notifyNewSignInContext });
      await this.appendAudit({
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "config-policy-change",
        outcome: "success",
        target: { kind: "access-policy", policyName: "notify-signin-context", newValue: req.notifyNewSignInContext === true }, // name the policy + the direction
      });
      return { notifyNewSignInContext: req.notifyNewSignInContext };
    }

    // effectiveOwnerActionGateOn is the gate decision every owner-action site consults: the gate is ON for a
    // given kind when EITHER the customer turned the opt-in requireConfigApproval toggle ON (governs every
    // gated kind), OR the kind is a HIGH-BLAST data/sign-in op (destination repoint/remove, IdP change) AND a
    // SECOND owner exists. The high-blast auto-apply CANNOT be disarmed below it: with two owners a lone
    // compromised/coerced owner cannot exfiltrate every future backup, destroy proven copies, or take over
    // who can sign in without a second owner approving. With ONE owner the auto-apply does NOT engage (forcing
    // dual control with no one to approve would deadlock the single-owner self-hosted bootstrap); the toggle
    // still governs, and the fresh-auth step-up is the sole control. The owner count uses the SAME bound +
    // pending tally as the last-Owner guard, so a pending Owner invite already counts. The global default-on
    // for ALL gated ops remains opt-in (the toggle).
    //
    // THE BARE-TOKEN BREAK-GLASS IS EXEMPT FROM THE HIGH-BLAST AUTO-APPLY (not from the opt-in toggle). Dual
    // control defends against a compromised ATTRIBUTABLE IDENTITY (a stolen passkey/OIDC cookie session), the
    // realistic compromise vector: it splits an act across two such identities. The bare-token break-glass has
    // NO attributable identity, so it can neither propose nor approve an owner action (recordOwnerAction /
    // canApproveOwnerAction refuse it). Auto-gating a high-blast kind for the break-glass would therefore be a
    // hard deadlock with no escape: there is no toggle to flip off (the auto-apply ignores the toggle), and
    // the second-approver path is closed to it. That breaks the DOCUMENTED first-Owner bootstrap, where the
    // ADMIN_TOKEN break-glass is the only available identity and must be able to wire the FIRST IdP connection
    // (a high-blast idp-conn-create, auto-enabled) before any second attributable owner can exist to approve.
    // The break-glass is the deliberate all-or-nothing override whose sole protection is the SECRECY OF THE
    // TOKEN itself, exactly the precedent requireStepUp sets (it EXEMPTS method === "token" from fresh-auth
    // step-up for the same reason). So the break-glass keeps its all-or-nothing power here; an attributable
    // identity session remains auto-gated for these high-blast ops. The opt-in TOGGLE is unchanged: when an
    // owner has explicitly armed it, the break-glass still cannot propose, but it retains its direct disarm at
    // the route (the dual-control-disable break-glass escape), so that path has no deadlock either.
    async effectiveOwnerActionGateOn(kind: OwnerActionKind, callerMethod: AuthMethod | null): Promise<boolean> {
      if (await this.getRequireConfigApproval()) return true;
      if (!isHighBlastAlwaysGated(kind)) return false;
      if (callerMethod === "token") return false; // bare-token break-glass: all-or-nothing, protected by the token secret (see above)
      const owners = this.countOwners(await this.listRoleEntries(), await this.listPendingEntries(), Date.now());
      return owners >= 2;
    }

    // readOrgPolicy returns the single account-wide policy record (or a default-everything-OFF object when no
    // record exists yet), so the three flags share one read and a write can MERGE rather than clobber. An
    // absent record (or absent field) reads its default OFF, so nothing is gated unless explicitly turned on.
    async readOrgPolicy(): Promise<OrgPolicy> {
      const policy = (await this.state.storage.get<OrgPolicy>(ORG_POLICY_KEY)) ?? null;
      if (policy === null) return { requireConfigApproval: false };
      return policy;
    }

    // writeOrgPolicy persists a MERGED policy: it reads the current record and overlays only the supplied
    // field(s), so setting one flag (e.g. bootstrapConsumed) never silently clears another (e.g.
    // requireConfigApproval or breakGlassTokenRetired). This is the single write point the three flag setters
    // funnel through, so they cannot race-clobber each other within this single-threaded DO.
    async writeOrgPolicy(patch: Partial<OrgPolicy>): Promise<OrgPolicy> {
      const current = await this.readOrgPolicy();
      const next: OrgPolicy = { ...current, ...patch };
      await this.state.storage.put(ORG_POLICY_KEY, next);
      return next;
    }

    // getAttendedCadenceDays reads the estate-wide attended-verification interval in whole days, or 0 when
    // none is set. Zero is the honest reading of absent: no cadence chosen means no obligation.
    async getAttendedCadenceDays(): Promise<number> {
      const raw = (await this.readOrgPolicy()).attendedCadenceDays;
      return typeof raw === "number" && Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : 0;
    }

    // setAttendedCadenceDays APPLIES the interval. OWNER-ONLY, re-resolved from the DO's own tables exactly as
    // setRequireChangeNumber does, so a router bug cannot let a non-owner move it: lengthening a proof interval
    // weakens the estate's stated assurance, so it is an owner decision even though it gates nothing.
    //
    // 0 CLEARS the cadence, and that must stay reachable. An operator who set one has to be able to stop
    // stating a rhythm they no longer keep; forcing them to pick a long interval instead would leave a number
    // in the compliance record that nobody intends to meet.
    //
    // The bound is 0, or 1 to 3650 days. The floor is one day because a sub-day cadence cannot be met by a
    // ceremony that needs a person present, and on split custody a quorum. The ceiling is ten years because
    // beyond that an interval is indistinguishable from "never" while still reading as a stated rhythm.
    //
    // Unlike the boolean policies, whose value is deliberately never written to the immutable log, the new
    // interval IS recorded: an integer number of days is redaction-safe, and lengthening a proof interval is
    // exactly the change a reviewer needs to see.
    async setAttendedCadenceDays(
      req: { attendedCadenceDays?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ attendedCadenceDays: number }> {
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may change the attended-verification cadence");
      const raw = req.attendedCadenceDays;
      if (typeof raw !== "number" || !Number.isFinite(raw) || !Number.isInteger(raw)) {
        throw new Error("attendedCadenceDays must be a whole number of days");
      }
      if (raw < 0 || raw > 3650) throw new Error("attendedCadenceDays must be 0 (no cadence) or between 1 and 3650");
      await this.writeOrgPolicy({ attendedCadenceDays: raw });
      await this.appendAudit({
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "config-policy-change",
        outcome: "success",
        target: { kind: "access-policy", policyName: "attended-cadence", newDays: raw },
      });
      return { attendedCadenceDays: raw };
    }

    // getEgressAllowlist reads the operator-configured outbound egress allowlist: the closed list of
    // external hosts a CUSTOMER-CONFIGURED sink (a notify channel today) may be pointed at, beside
    // the fixed vendor hosts the engine always reaches. Absent reads as the empty list, which
    // screenEgressAllowlist treats as UNRESTRICTED: an account that never sets one reaches any public https
    // host from its notify channels. It is the single read point every config-time and send-time screen
    // consults (addNotifyChannel, and the router's channel-delivery path via GET /config/egress-allowlist).
    async getEgressAllowlist(): Promise<string[]> {
      const raw = (await this.readOrgPolicy()).egressAllowlist;
      return Array.isArray(raw) ? raw : [];
    }

    // setEgressAllowlist serves POST /config/egress-allowlist. OWNER-ONLY, re-resolved here (defence in
    // depth over the router's keys.ceremony gate), mirroring setAttendedCadenceDays: it applies IMMEDIATELY
    // (a positive allowlist is not the direction a compromised owner benefits from disarming solo, so there
    // is no dual-control arm here either) and validateEgressAllowlist bounds the shape (a canonical hostname
    // or a "*.suffix" wildcard, no scheme/port/userinfo/IP literal, at most EGRESS_ALLOWLIST_MAX_ENTRIES
    // entries). An empty submitted list CLEARS the allowlist back to unrestricted (the same "absent or empty
    // means unset" reading getEgressAllowlist gives it), not a configured-but-nothing-permitted state.
    // THROWS -> 400 with the plain reason (a bad entry names itself, bounded, never a secret). The audit
    // event carries only the resulting host COUNT, never a hostname (a hostname is the operator's own
    // configuration, not a secret, but the access-policy audit target is deliberately value-free by design,
    // matching every sibling policy toggle in this file).
    async setEgressAllowlist(
      req: { egressAllowlist?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ egressAllowlist: string[] }> {
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may change the outbound egress allowlist");
      const v = validateEgressAllowlist(req.egressAllowlist ?? []);
      if (!v.ok) throw new Error(v.reason);
      await this.writeOrgPolicy({ egressAllowlist: v.hosts });
      await this.appendAudit({
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "config-policy-change",
        outcome: "success",
        target: { kind: "access-policy", policyName: "egress-allowlist", hostCount: v.hosts.length },
      });
      return { egressAllowlist: v.hosts };
    }

    // getBootstrapConsumed reads the one-way bootstrap latch (default false when absent). Once true, NO
    // bootstrap path may ever create another Owner. It is the single read point both bootstrap paths (the
    // whoami empty-table grant and the passkey first-Owner enrolment) consult before claiming a first Owner.
    async getBootstrapConsumed(): Promise<boolean> {
      return (await this.readOrgPolicy()).bootstrapConsumed === true;
    }

    // markBootstrapConsumed latches bootstrapConsumed true (idempotent: a second call is a harmless re-write)
    // and audits a one-time bootstrap-consumed event ONLY on the transition false -> true, so the trail
    // records exactly when the first Owner was claimed (the break-glass token's single legitimate use). The
    // actor is the claiming caller (the bootstrapping email for the email/passkey path, or the token
    // break-glass when an ADMIN_TOKEN bootstrap minted the first Owner). It MERGE-writes so the config-approval
    // gate and the retire flag are untouched. sourceIp is the coarse provenance for the audit event and both
    // callers thread it: the passkey-enrolment finish forwards it off the request body, and the whoami
    // role-resolution GET path (the ACCESS first-owner bootstrap, the first call a fresh console makes)
    // forwards the router's read of the edge header as a query param. The default stays null for an
    // engine-internal caller that genuinely has no address.
    async markBootstrapConsumed(actorEmail: string | null, actorMethod: AuthMethod, sourceIp: string | null = null): Promise<void> {
      const already = await this.getBootstrapConsumed();
      await this.writeOrgPolicy({ bootstrapConsumed: true });
      if (!already) {
        await this.appendAudit({
          actorEmail,
          actorMethod,
          sourceIp,
          action: "bootstrap-consumed",
          outcome: "success",
          // The field-less access-policy variant is the redaction-safe target: the trail records that the
          // first-Owner bootstrap was consumed, who consumed it, and when, with no value written (matching the
          // config-policy-change discipline of never writing a value to the tamper-evident log).
          target: { kind: "access-policy" },
        });
      }
    }

    // lockoutPreflight computes the DO-owned "is there a second factor / a way back in OTHER than the bare
    // ADMIN_TOKEN" facts the pre-flight guard needs. The retire-break-glass-token path already refuses
    // to dispose of the token unless a way back in exists; the raw ADMIN_TOKEN_DISABLED env flag and a
    // `wrangler secret delete ADMIN_TOKEN` are OUT-OF-BAND (the engine cannot intercept them, by no-custody
    // design), so the only safe guard the engine can offer there is an authoritative pre-flight VERDICT the
    // console consults BEFORE it guides the operator to disable/delete the token. This method reports the three
    // DO-side factors; CF Access (an env fact) is added by the router (POST /policy/require-access), which OR's
    // them into secondFactorPresent and refuses to advise the disable when none is present.
    //  - passkeyOwnerEnrolled: at least one bound OWNER has a registered passkey (a non-token way in for an owner).
    //  - recoveryReady: recovery codes have been generated/acknowledged for an Owner (the recovery-code break-glass).
    //  - secondOwner: a second Owner exists (bound or an unexpired pending invite), so losing one passkey survives.
    // It reads only redaction-safe facts (role table + recovery-ack latch + passkey PRESENCE counts), never a
    // secret or a credential value, and never throws an unexpected fault into the read path.
    // rosterUnreadable is the factor this surface could not otherwise see. Every other figure here is
    // computed from the rows that PARSE, and a row that does not parse is dropped by BOTH readers, so an
    // account whose only Owner grant is corrupted would otherwise answer this route with a body
    // indistinguishable from a healthy account's: same four factors, same `secondOwner: false`, same 200,
    // even while `/roles` reports unreadable rows. The authorisation path fails CLOSED, so nothing is
    // granted that should not be and no stranger is bootstrapped in place of a lost Owner, which bounds this
    // to silent privilege LOSS rather than escalation. But without this count, the one surface built to warn
    // about a lost way back in would say nothing, and a warning surface that cannot distinguish the state it
    // exists to warn about reads as an all-clear. It is a COUNT and never a row, and it is carried BESIDE
    // the four factors rather than folded into one of them, because "there is a second Owner" and "a grant
    // could not be read" have different remedies.
    async lockoutPreflight(): Promise<{ passkeyOwnerEnrolled: boolean; passkeyOwnerEvidence: PasskeyOwnerEvidence; passkeyWitnessSince: string | null; recoveryReady: boolean; recoveryReadyReason: RecoveryBreakGlassReason; secondOwner: boolean; rosterUnreadable: number }> {
      const now = Date.now();
      const [entries, pending] = await Promise.all([this.listRoleEntries(), this.listPendingEntries()]);
      const ownerCount = this.countOwners(entries, pending, now);
      // recoveryReady is PURELY the recovery-code break-glass (kept distinct from secondOwner so the console can
      // render the four named factors separately); the require-access verdict OR's all of them together. It is
      // the LIVE verdict (recoveryBreakGlassVerdict): an Owner re-resolved now, a parseable record, an
      // unconsumed code and a key the codes still verify under. A write-once latch would not do here: it
      // could report a second factor present even on an account whose banked codes no longer verify, which
      // is the false all-clear this pre-flight exists to avoid.
      const verdict = await this.recoveryBreakGlassVerdict();
      const recoveryReady = verdict.ready;
      // passkeyOwnerEnrolled: does any BOUND owner (an entry whose effective role is owner) hold a passkey? A
      // pending (unbound) owner has not authenticated yet, so it cannot have enrolled one - hence bound entries
      // only. The per-email passkey list is read for each owner email; a single hit is enough.
      //
      // LAPSED OWNERS DO NOT COUNT AS BOUND. This uses effectiveRole, not the stored role, matching
      // secondOwner (via countOwners) and recoveryReady (via recoveryBreakGlassVerdict): the same
      // lazy-expiry rule applies to all three factors. This method exists to answer "is there a way back in
      // OTHER than the bare ADMIN_TOKEN" for an operator about to retire or delete that token, and a lapsed
      // Owner's passkey is not a way back in: their next sign-in resolves to viewer, so counting it would let
      // this pre-flight say yes on an account that is about to be locked to a role that cannot administer
      // it. effectiveRole is the single expiry rule (absent expiresAt never expires; an unparseable one
      // fails OPEN, so corrupt data can never manufacture a lockout warning), and it is already called on
      // these same entries by countOwners two lines above, so the lazy-expiry signal here costs nothing
      // extra.
      const ownerEmails = new Set<string>();
      for (const e of entries) if (this.effectiveRole(e, now) === "owner" && e.email) ownerEmails.add(e.email.trim().toLowerCase());
      let passkeyOwnerEnrolled = false;
      // THE USABILITY WITNESS IS REPORTED, NOT GATED. passkeyOwnerEnrolled above remains the only passkey
      // input to secondFactorPresent, because no honest gate can be built from this evidence: even with
      // perfect data a never-asserted passkey is the NORMAL state of a break-glass key that an Owner
      // deliberately keeps in reserve. Gating on absence would tell a healthy account it is unsafe, on the
      // one screen whose value is that it is believed.
      //
      // So the evidence is surfaced instead of consumed. passkeyOwnerEvidence is a closed enum over bound
      // Owners' credentials, and it separates the two things a bare absence conflates:
      //   no-credential      no bound Owner holds a passkey at all (passkeyOwnerEnrolled is false)
      //   demonstrated       at least one has produced a VERIFIED assertion; possession was proven, dated
      //   never-asserted     every one of them was enrolled AFTER the witness opened and none has ever
      //                      asserted; this is a real fact, not an artefact of when record-keeping started
      //   unknown            at least one predates the witness (or the witness never opened), so nothing is
      //                      known about it either way and no verdict may be built on it
      // `unknown` is the answer for every account alive today, and saying so is the point: an inference
      // dressed as a fact is what this row exists to stop.
      let anyDemonstrated = false;
      let anyUnknown = false;
      const witnessSince = await this.getPasskeyWitnessSince();
      const witnessSinceMs = witnessSince === null ? null : Date.parse(witnessSince);
      for (const email of ownerEmails) {
        const creds = await this.listPasskeyCredsForEmail(email);
        if (creds.length > 0) passkeyOwnerEnrolled = true;
        for (const c of creds) {
          if (typeof c.lastAssertedAt === "string" && c.lastAssertedAt.length > 0) { anyDemonstrated = true; continue; }
          // No stamp. Is that informative? Only if this credential was enrolled after the witness opened. An
          // unparseable or absent createdAt is treated as predating it: the conservative reading is that
          // nothing is known, never that a credential is dead.
          const createdMs = Date.parse(c.createdAt ?? "");
          if (witnessSinceMs === null || Number.isNaN(witnessSinceMs) || Number.isNaN(createdMs) || createdMs < witnessSinceMs) anyUnknown = true;
        }
      }
      const passkeyOwnerEvidence: PasskeyOwnerEvidence = !passkeyOwnerEnrolled
        ? "no-credential"
        : anyDemonstrated
          ? "demonstrated"
          : anyUnknown
            ? "unknown"
            : "never-asserted";
      const rosterUnreadable = await this.countUnreadableRoleRows();
      return { passkeyOwnerEnrolled, passkeyOwnerEvidence, passkeyWitnessSince: witnessSince, recoveryReady, recoveryReadyReason: verdict.reason, secondOwner: ownerCount >= 2, rosterUnreadable };
    }

    // getBreakGlassTokenRetired reads the retire latch (default false when absent). When true, the ADMIN_TOKEN
    // bearer fallback is refused exactly as ADMIN_TOKEN_DISABLED refuses it. It is the single read point the
    // router's auth wiring (POST /admin-policy/break-glass-retired) and the DO's own token short-circuits consult.
    async getBreakGlassTokenRetired(): Promise<boolean> {
      return (await this.readOrgPolicy()).breakGlassTokenRetired === true;
    }

    // setBreakGlassTokenRetired serves POST /admin/policy/retire-break-glass-token. OWNER-ONLY and ONE-WAY
    // FROM THE APP: it RE-RESOLVES the caller's role from this DO's own tables (roleForCaller) and requires
    // role === "owner". The retire is also wired into auth.ts so that ONCE retired a bare ADMIN_TOKEN
    // no longer resolves to owner; combined with the owner re-check here, a retired token can NEVER un-retire
    // itself (only a passkey/Access Owner can flip it, or a redeploy resetting the DO). It MERGE-writes (the
    // config-approval gate + the bootstrap latch are untouched) and records a break-glass-token-retired audit
    // event with the actor. THROWS -> 400 on a non-owner (the router gates owner first via keys.ceremony; this
    // is defence in depth). The value is one-way true here: passing false would be honoured (an Owner may
    // un-retire), but the route only ever sends true; an un-retire is a deliberate Owner act, not a token's.
    async setBreakGlassTokenRetired(
      req: { retired?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ breakGlassTokenRetired: boolean }> {
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may retire the break-glass token");
      // The route sends retired:true; a missing/garbled value defaults to true (the retire intent), and an
      // explicit false (an Owner choosing to un-retire) is honoured. A retired token never reaches here as
      // owner, so a bare token can never send false to un-retire itself.
      const retired = req.retired !== false;
      // BREAK-GLASS-IN-PLACE GATE (only when actually RETIRING): disposing of the bootstrap token must never
      // strand the tenant with NO way back in. So a retire is REFUSED unless an ongoing admin break-glass is
      // already in place: EITHER recovery codes have been generated (acknowledged) for at least one Owner, OR a
      // SECOND Owner exists (so losing one Owner's passkey is survivable). Un-retiring (retired === false) is
      // never gated (it only RE-ENABLES a path, never removes one). The router gates owner first; this is the
      // substantive precondition, enforced HERE at the authority so a console that skipped the check cannot
      // strand the tenant. THROWS -> 400 with a clear, actionable reason the console surfaces verbatim.
      if (retired) {
        // The LIVE recovery verdict is used here, not a write-once ack latch. This gate is the one that
        // makes the retire IRREVERSIBLE-ish in practice, so it is exactly where a factor that no longer
        // works must not count: a stale latch could say yes while the banked codes actually answer 401,
        // which would let the account destroy its only working credential.
        const ackd = (await this.recoveryBreakGlassVerdict()).ready;
        // Bound + pending owners, matching the recoveryBreakGlassReady posture computation and the
        // last-Owner guard: an unexpired pending Owner invite binds on first auth, so it is a real way
        // back in and counts toward the second-Owner condition exactly as it does in the posture slice.
        const owners = this.countOwners(await this.listRoleEntries(), await this.listPendingEntries(), Date.now());
        if (!ackd && owners < 2) {
          throw new Error(
            "cannot retire the break-glass token yet: set up a way back in first - have an Owner sign in with a passkey and generate recovery codes (codes for an Owner who has only ever signed in via Access would recover to viewer), or appoint a second Owner. Disposing of the token now would leave no path back in if a passkey is lost.",
          );
        }
        // A SECOND QUESTION, ANSWERED HERE: whether the estate can still ADMINISTER itself, not merely sign
        // in. The gate above asks whether there is a way back IN. This checks whether there is a way back
        // OUT of dual control. The bare token is the only identity that disarms it unilaterally, and this
        // route disposes of that token one way. See owner-floor.ts's wouldStrandDualControl for the
        // three-condition invariant.
        const expiring = await this.expiringOwnerGrantCount();
        if (wouldStrandDualControl("retire-break-glass", { dualControlOn: await this.getRequireConfigApproval(), breakGlassRetired: false, expiringOwnerGrants: expiring })) {
          throw new Error(strandRefusal("retire-break-glass", expiring));
        }
      }
      await this.writeOrgPolicy({ breakGlassTokenRetired: retired });
      await this.appendAudit({
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "break-glass-token-retired",
        outcome: "success",
        // newValue records the direction (true = retired, false = un-retired), so an incident timeline can
        // distinguish the two -- un-retiring (re-arming break-glass) is the single most security-significant
        // direction on this surface. Still no value, no token, no operator text.
        target: { kind: "access-policy", policyName: "break-glass-retired", newValue: retired === true },
      });
      return { breakGlassTokenRetired: retired };
    }
  };
}
