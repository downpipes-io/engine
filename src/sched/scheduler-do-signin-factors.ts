// The SIGN-IN FACTOR union read. See src/admin/signin-factors.ts for the vocabulary and, more importantly,
// for the polarity argument: this read's dangerous failure is the FALSE NEGATIVE, which is the opposite of
// every other recovery-side check in this engine.
//
// It is one mixin rather than an addition to RecoveryMixin because it spans three stores that no existing
// module owns together (`passkeyCred:`, `recovery:` and `passkeyInvite:`), and reshaping the credential
// route to grow a recovery arm would be a second design against one store at a time, which is the
// mistake this exists to stop repeating.

import { isScimOffboardCaller } from "../admin/identity.ts";
import type { AuthMethod, PendingRoleEntry, RoleEntry } from "../admin/identity.ts";
import { checkOwnerRemoval, OwnerFloorRefusal } from "../admin/owner-floor.ts";
import type { PasskeyCred, PasskeyInvite } from "../admin/passkey.ts";
import { isRecoveryRecordShaped, isRecoverySigningKeyUsable, type RecoveryRecord, recoveryKeyProof, remainingCount } from "../admin/recovery.ts";
import { classifyRosterMembership, classifySignIn, type RecoveryKeyContinuity, type RosterVerdict, revocationClosedAWayIn, type SignInFactorRevocation, type SignInFactorRow } from "../admin/signin-factors.ts";
import { recordAdminRefusal, recordAuthzRefusal } from "./sched-fault-ledger.ts";
import { PASSKEY_CRED_PREFIX, PASSKEY_INVITE_PREFIX, PASSKEY_SESSION_KEY_KEY, RECOVERY_PREFIX, RECOVERY_SIGNING_KEY_KEY, type SchedulerDOCtor } from "./scheduler-do-base.ts";

type Caller = { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null;

// callerEmailOf normalises the caller's own address the SAME way the target is normalised, so the
// self-revocation test compares like with like. A caller carrying NO email (the bare-token break-glass) can
// never equal a normalised target, which is correct: that caller has no factors of its own to revoke.
function callerEmailOf(caller: Caller): string | null {
  const raw = caller?.email;
  if (typeof raw !== "string") return null;
  const v = raw.trim().toLowerCase();
  return v.length > 0 ? v : null;
}

export function SignInFactorsMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // recoveryRecordKeyContinuity splits recoveryRecordKeyLive's boolean into the three answers this read
    // needs. That helper folds "refuted" and "unprovable" into one `false` on purpose, because the pre-flight
    // it feeds must treat an unprovable way back in as no way back in before telling an operator to destroy a
    // credential. Here the two must not be folded: "orphaned" is a finished offboarding and "unknown" is one
    // an operator still has to look at.
    //
    // The PROOF arm is the only one that can refute. A keyProof that recomputes unequal under the live key is
    // a demonstration that no banked code verifies. Everything else is inference: the timeline arm can say
    // "live" (the same inference lockoutPreflight already acts on when it reports ready) but it can never say
    // "dead", because a timeline that fails to place a record under the live key is equally consistent with an
    // old record whose provenance was simply never recorded. So the negative timeline answer is "unknown".
    //
    // A keyProof present but unverifiable (the key is too short to import, or importing throws) is "unknown"
    // and not "orphaned": that is a fault in the reader, not evidence about the record.
    async recoveryRecordKeyContinuity(
      record: RecoveryRecord,
      keyRec: { key?: string; createdAt?: string; adoptedFromSessionKey?: boolean; sessionKeyCreatedAt?: string } | undefined,
      sessionRec: { key?: string; createdAt?: string } | undefined,
    ): Promise<RecoveryKeyContinuity> {
      if (typeof record.keyProof === "string" && record.keyProof.length > 0) {
        try {
          const live = await this.recoverySigningKey();
          if (!isRecoverySigningKeyUsable(live)) return "unknown";
          return (await recoveryKeyProof(live)) === record.keyProof ? "live" : "orphaned";
        } catch {
          return "unknown";
        }
      }
      return (await this.recoveryRecordKeyLive(record, keyRec, sessionRec)) ? "live" : "unknown";
    }

    // rosterAccountedEmails is THE construction of "the emails this account's roster accounts for": a row in
    // the bound role table, or an UNEXPIRED pending grant. It is one function because it now has two callers
    // whose answers must never diverge - the union read, which REPORTS the set, and the consumption gate,
    // which REFUSES on it. A reporting read and an enforcing read of the same word are exactly the pair that
    // drifts.
    //
    // GROUP MAPPINGS ARE NOT IN IT, AND CANNOT BE. resolveRole returns max(role row, group-mapped role,
    // viewer), but a group->role grant is resolved from claims an IdP presents at sign-in; the engine holds
    // the mapping and never the membership. So this set is a LOWER BOUND on who is legitimately entitled, and
    // every caller that refuses on it has to be sound under that. The consumption gate is: it applies only to
    // the passkey method, which carries no group claims and can therefore never have been resolved by one.
    //
    // The EXPIRY test on a pending grant is isExpired and deliberately not effectiveRole. effectiveRole is
    // declared returning Role, a closed union of six strings with no null member, so the `=== null` this
    // replaced was always false and the skip never fired; and `!== "viewer"` would be wrong the other way,
    // dropping a legitimate unexpired viewer out of the set.
    rosterAccountedEmails(entries: RoleEntry[], pending: PendingRoleEntry[], now: number): Set<string> {
      const norm = (e: unknown): string => (typeof e === "string" ? e.trim().toLowerCase() : "");
      const known = new Set<string>();
      for (const e of entries) if (e.email) known.add(norm(e.email));
      for (const p of pending) {
        if (!p.email) continue;
        if (this.isExpired(p, now)) continue;
        known.add(norm(p.email));
      }
      return known;
    }

    // rosterMembership answers "does the roster still account for this address?" for a caller that is about to
    // decide whether a bearer secret may still buy STANDING access.
    //
    // IT FAILS OPEN, AND THE try/catch IS THE POINT, not defensive padding. The two role-table reads are
    // storage list calls that can throw, and a throw here would otherwise propagate into a 500 on the
    // enrolment path, which is a refusal wearing a different status code. Binding validity to the roster is
    // only safe if an unreadable roster is a NON-ANSWER, so the fault is caught here, converted to
    // "unreadable", and counted. Nothing about the fault reaches the caller's response.
    //
    // The verdict is computed at the moment of the ACT, not carried from an earlier request, which is what
    // makes a role deletion racing a consumption harmless: the DO serialises its own storage, so the read that
    // decides is either wholly before or wholly after the delete, and being after is the safer of the two.
    async rosterMembership(email: string | null): Promise<RosterVerdict> {
      if (!email) return "unreadable";
      let entries: RoleEntry[];
      let pending: PendingRoleEntry[];
      try {
        [entries, pending] = await Promise.all([this.listRoleEntries(), this.listPendingEntries()]);
      } catch {
        await this.recordAuthSignalThrottled("roster-read-unavailable");
        return "unreadable";
      }
      const known = this.rosterAccountedEmails(entries, pending, Date.now());
      const verdict = classifyRosterMembership({ read: "ok", rosterSize: known.size, targetPresent: known.has(email) });
      // An EMPTY roster on an account that has a caller presenting a credential is the state classifyRosterMembership
      // deliberately reads as unreadable rather than as "everybody has left". Record it: on a healthy estate it
      // should never happen, and if it does the gate is standing down and somebody should know.
      if (verdict === "unreadable" && known.size === 0) await this.recordAuthSignalThrottled("roster-read-empty");
      return verdict;
    }

    // listSignInFactors is the union read: every email that holds a way into this account, and what kind.
    //
    // SCOPE, and the false-empty rule it enforces. `emailParam` absent means the WHOLE ACCOUNT, and there is
    // deliberately no fallback to the caller's own email. That fallback is what produced the false empty on
    // the credential route: a bearer token carries no email, so every ADMIN_TOKEN sweep silently
    // narrowed to "nobody" and read back `200 []`, byte-identical to a clean account. An account-wide default
    // cannot go wrong that way, because the target is always resolved and always the thing the caller asked
    // about.
    //
    // An `?email=` that is PRESENT but does not normalise is refused with a 400, not silently widened to the
    // account and not silently narrowed to the caller. Widening would answer a question nobody asked;
    // narrowing is the original defect. The 400 follows the same reasoning: a new field on a 200
    // leaves every client not yet reading it seeing a list it will misread, and a client cannot mistake a 400
    // for an answer.
    //
    // A NAMED target ALWAYS gets a row, even when all three stores are empty for it. An empty array for a
    // named email would be the false empty in miniature: "no rows" and "this person has nothing" are the same
    // bytes. `signIn: "no-factor"` says the second one out loud.
    //
    // AUTHORITY: roles.write for the account-wide read and for reading anyone but yourself, matching the
    // credential route. Reading your OWN factors needs only an authenticated caller. A caller without the
    // capability is REFUSED, never handed an empty list.
    async listSignInFactors(
      emailParam: string | null,
      caller: Caller,
    ): Promise<{ scope: "account" | "email"; factors: SignInFactorRow[]; witnessSince: string | null; groupRoleMappings: number }> {
      const callerEmail = caller ? this.normaliseEmail(caller.email) : null;
      let target: string | null = null;
      if (emailParam !== null) {
        target = this.normaliseEmail(emailParam);
        if (!target) throw new Error("sign-in factor listing was given an email it cannot use: name a valid address with ?email=, or omit it entirely to read the whole account");
        if (target !== callerEmail) await this.requireCapabilityResolved(caller, "roles.write");
      } else {
        await this.requireCapabilityResolved(caller, "roles.write");
      }

      const now = Date.now();
      const [credMap, recMap, inviteMap, entries, pending, groupRoles] = await Promise.all([
        this.state.storage.list<PasskeyCred>({ prefix: PASSKEY_CRED_PREFIX }),
        this.state.storage.list<unknown>({ prefix: RECOVERY_PREFIX }),
        this.state.storage.list<PasskeyInvite>({ prefix: PASSKEY_INVITE_PREFIX }),
        this.listRoleEntries(),
        this.listPendingEntries(),
        this.listGroupRoleEntries(),
      ]);

      const norm = (e: unknown): string => (typeof e === "string" ? e.trim().toLowerCase() : "");
      // known = the emails the roster accounts for, built by the ONE constructor below, which the consumption
      // gate also calls. Two constructions of "the roster" would be the same shape of defect this campaign has
      // been closing all day: a second component free to drift from the first.
      const known = this.rosterAccountedEmails(entries, pending, now);

      const creds = new Map<string, PasskeyCred[]>();
      for (const c of credMap.values()) {
        const e = norm(c.email);
        if (e.length === 0) continue;
        const list = creds.get(e);
        if (list === undefined) creds.set(e, [c]);
        else list.push(c);
      }
      // Invites are keyed by TOKEN, which is the secret itself, so the key is read and immediately discarded:
      // only the bound email, the live/expired split and the soonest expiry ever leave this loop.
      const invites = new Map<string, { live: number; expired: number; soonest: number | null }>();
      for (const inv of inviteMap.values()) {
        const e = norm(inv?.email);
        if (e.length === 0) continue;
        const slot = invites.get(e) ?? { live: 0, expired: 0, soonest: null };
        const expiresAt = typeof inv.expiresAt === "number" ? inv.expiresAt : 0;
        if (expiresAt > now) {
          slot.live++;
          if (slot.soonest === null || expiresAt < slot.soonest) slot.soonest = expiresAt;
        } else slot.expired++;
        invites.set(e, slot);
      }
      const recoveries = new Map<string, unknown>();
      for (const [key, raw] of recMap.entries()) recoveries.set(key.slice(RECOVERY_PREFIX.length).trim().toLowerCase(), raw);

      // Read both key records ONCE for the whole scan, exactly as recoveryBreakGlassVerdict does. Neither
      // value is returned, logged or compared against anything a caller supplied.
      const keyRec = await this.state.storage.get<{ key?: string; createdAt?: string; adoptedFromSessionKey?: boolean; sessionKeyCreatedAt?: string }>(RECOVERY_SIGNING_KEY_KEY);
      const sessionRec = await this.state.storage.get<{ key?: string; createdAt?: string }>(PASSKEY_SESSION_KEY_KEY);

      // The row set. Account scope is the union of the three stores (an email with nothing anywhere has
      // nothing to report); email scope is exactly the one named address, present or not.
      const subjects = target !== null ? [target] : [...new Set([...creds.keys(), ...recoveries.keys(), ...invites.keys()])].sort();

      const factors: SignInFactorRow[] = [];
      for (const email of subjects) {
        const mine = creds.get(email) ?? [];
        const stamps = mine.map((c) => (typeof c.lastAssertedAt === "string" ? c.lastAssertedAt : "")).filter((s) => s.length > 0);
        stamps.sort();
        const raw = recoveries.get(email);
        const present = raw !== undefined && raw !== null;
        const parseable = present && isRecoveryRecordShaped(raw);
        const record = parseable ? (raw as RecoveryRecord) : null;
        // unconsumedCodes is null, never 0, when the record could not be parsed. 0 reads as "no codes left",
        // which is the reassuring answer about a record nobody could read.
        const unconsumedCodes = record === null ? null : remainingCount(record);
        const keyContinuity: RecoveryKeyContinuity = record === null ? (present ? "unknown" : "none") : await this.recoveryRecordKeyContinuity(record, keyRec, sessionRec);
        const inv = invites.get(email) ?? { live: 0, expired: 0, soonest: null };
        const { verdict, paths } = classifySignIn({
          passkeyCredentials: mine.length,
          recoveryPresent: present,
          recoveryParseable: parseable,
          recoveryUnconsumed: unconsumedCodes,
          recoveryKeyContinuity: keyContinuity,
          liveInvites: inv.live,
        });
        factors.push({
          email,
          hasRoleEntry: known.has(email),
          signIn: verdict,
          paths,
          passkey: {
            credentials: mine.length,
            credentialIds: mine.map((c) => c.credentialId).sort(),
            lastAssertedAt: stamps.length > 0 ? (stamps[stamps.length - 1] ?? null) : null,
          },
          recovery: {
            present,
            parseable,
            unconsumedCodes,
            keyContinuity,
            generatedAt: record !== null && typeof record.generatedAt === "string" ? record.generatedAt : null,
          },
          invites: {
            live: inv.live,
            expired: inv.expired,
            soonestExpiresAt: inv.soonest === null ? null : new Date(inv.soonest).toISOString(),
          },
        });
      }

      // groupRoleMappings is the GROUP-CLAIM CAVEAT, and it is a count rather than a per-row flag because a
      // per-row flag would be a fabrication. A group->role grant is resolved from claims the IdP presents at
      // sign-in; the engine holds the mapping but not the membership, so it cannot say whether THIS email is
      // in that group. What it can say honestly is that such mappings exist, which is what tells an operator
      // that removing a row may not have removed the authority. A zero here is the strong answer: no email in
      // this account can hold a role by group claim at all.
      return { scope: target !== null ? "email" : "account", factors, witnessSince: await this.getPasskeyWitnessSince(), groupRoleMappings: groupRoles.length };
    }

    // revokeSignInFactors is THE OFFBOARDING WRITE: it removes every way the named person can authenticate,
    // across the same three stores the union read above spans, as ONE audited operation.
    //
    // WHY IT HAD TO BE BUILT AT ALL. Two of the three stores had no delete anywhere in this engine. A
    // `recovery:<email>` record was written by enrolment and regeneration and removed by nothing, and
    // `passkeyInvite:` was deleted only as the single-use burn on its own redemption. So the offboarding an
    // operator believes they are performing could not be performed: the ordering was fine, two of its steps had
    // no implementation. A person whose role row was deleted kept a live invite that enrols a fresh credential
    // with no roster check, and kept banked recovery codes that mint a session and return enrolPasskey:true.
    //
    // WHY IT IS KEYED BY EMAIL AND SPANS ALL THREE AT ONCE. An operator holds an address, not a token and not a
    // credential id. Invites are keyed by the TOKEN, which is the secret, so an operator can never name one and
    // an email-keyed delete cannot reach them without a scan -- that is not an implementation detail, it is the
    // reason the invite store was unreachable from an offboard in principle. And a revoke that closed one store
    // at a time is how this defect was built in the first place: the credential route existed, so the account
    // read "no credentials" while two bearer secrets stood. One action over one email, or the same gap again.
    //
    // WHY IT IS NOT FOLDED INTO deleteRole, which is the question a reader will ask first. resolveRole returns
    // max(explicit email-table role, highest group-mapped role, viewer), so an email can hold authority from a
    // role ROW and an IdP GROUP CLAIM simultaneously. For such a member deleteRole removes only the row, which
    // is a DEMOTION to their group-conferred role -- deleteRole audits it as a role change to viewer and calls
    // viewer "the least-privilege resting state". Folding factor destruction into that would mean demoting
    // somebody who remains a legitimate user of the estate also destroys their authenticator and their recovery
    // codes, irreversibly, because recovery codes cannot be re-derived. Deliberate removal should revoke;
    // demotion should not; deleteRole cannot tell which one it is being asked for, and this route is told.
    //
    // AUTHORITY. roles.write, always, with NO self-service arm. Revoking your own every factor is a
    // self-lockout with no legitimate use (rotating your own codes is regenerate, dropping a lost key is the
    // credential route), and the guards below cannot save a caller who is entitled to lock themselves out.
    async revokeSignInFactors(
      req: { email?: unknown },
      caller: Caller,
      // `declined` is present ONLY when the destructive half was deliberately skipped, and it names why. It is
      // absent on every ordinary revoke, so a caller cannot mistake "nothing was there to close" for "we chose
      // not to look".
    ): Promise<{ email: string; revoked: SignInFactorRevocation; sessionsTerminated: boolean; declined?: "unattended-owner" }> {
      const resolved = await this.requireCapabilityResolved(caller, "roles.write");
      const email = this.normaliseEmail(req.email);
      // The same 400 the read gives an unusable ?email=, and for the same reason: a revoke that silently
      // widened to the account, or silently narrowed to the caller, would be catastrophic in a way no response
      // shape could walk back. There is deliberately NO account-wide revoke.
      if (!email) throw new Error("sign-in factor revocation needs a valid address: name the member whose ability to sign in is being removed");

      const now = Date.now();
      const [entries, pending] = await Promise.all([this.listRoleEntries(), this.listPendingEntries()]);
      const boundCurrent = entries.find((e) => e.email === email);
      // The target need NOT be on the roster. That is the WHOLE POINT: the person this route exists for is
      // precisely the one whose role row is already gone and whose bearer secrets outlived it. Unlike
      // deleteRole, an absent member is not an early return here, because absent-from-the-roster is the
      // expected state of a half-finished offboarding.
      const current = boundCurrent ?? pending.find((p) => p.email === email);
      const targetRole = this.effectiveRole(current, now);
      const targetIsOwner = targetRole === "owner";

      // AVAILABILITY GUARD. Removing every sign-in factor from an Owner is strictly more destructive than
      // removing one credential (revokePasskeyCredential's guard) because it leaves NOTHING: no key, no banked
      // code, no pending invite. The floor arithmetic is checkOwnerRemoval, reused because it is the same
      // question about the same tally and it is fail-safe on an uncomputable count, INCLUDING its raised
      // two-Owner floor while dual control is armed. That arm is not padding: with Require Approver on, an
      // Owner stripped of every factor still counts toward the Owner tally but cannot approve, so the remaining
      // Owner cannot even re-invite them without an approver who can no longer sign in. That is a deadlock, and
      // it is reachable only through this route.
      //
      // The SENTENCES are this route's own and are deliberately not ownerRemovalRefusal's. Those name removing
      // or demoting an Owner, and nobody's role changes here; an operator told their revoke was refused because
      // it would demote an Owner would go looking for a demotion that never happened.
      // THE UNATTENDED-OWNER SKIP (connector-misfire mitigation).
      //
      // An unattended connector has no business destroying ANY Owner's recovery codes: it fires on connector
      // bugs as readily as on real departures, and recovery codes cannot be re-derived. The plan proposed a
      // REFUSAL for this, and a refusal is the wrong kind of stop. The Owner branch below refuses by THROWING,
      // and the SCIM facade issues this revoke BEFORE `/roles/delete`, so a throw here means the role delete is
      // never issued at all: the leaver would keep their role row, their authority AND every factor. That is
      // worse than today for exactly the person whose departure matters most.
      //
      // So this DECLINES rather than refuses. The destructive half is skipped and reported; the caller carries
      // on and removes the AUTHORITY, which is the standing-access exposure a prompt deprovision exists to
      // close, while the IRREVERSIBLE half waits for a human who can see what they are destroying. A human
      // caller is unaffected: the floor below still governs them, and this branch cannot widen anything,
      // because declining to delete is not a permission.
      if (targetIsOwner && isScimOffboardCaller(caller)) {
        return {
          email,
          revoked: { passkeyCredentials: 0, recovery: false, invitesLive: 0, invitesExpired: 0 },
          sessionsTerminated: false,
          declined: "unattended-owner",
        };
      }
      if (targetIsOwner) {
        const verdict = checkOwnerRemoval(this.countOwners(entries, pending, now), await this.getRequireConfigApproval());
        if (!verdict.ok) {
          await recordAuthzRefusal(this.state.storage, "last-owner-guard");
          await recordAdminRefusal(this.state.storage, "rbac-guardrail", "guardrail");
          // The SENTENCES stay this route's own, for the reason given above. What changes is that the throw
          // now CARRIES its verdict, so a caller can file the refusal as an Owner-floor refusal without
          // reading a word of the prose. The SCIM facade used to decide that by testing the response text for
          // "would remove the last Owner", which these two sentences do not contain and were never going to.
          throw new OwnerFloorRefusal(
            verdict.reason === "last-owner"
              ? "cannot revoke the sign-in factors of the only Owner: this removes every passkey, recovery code and pending invite at once, so nobody would be able to sign in to this account. Appoint a second Owner first."
              : "dual control (Require Approver) is on, and revoking this Owner's sign-in factors would leave one Owner who can actually sign in. The stripped Owner still counts toward the two-Owner floor but could no longer approve anything, including their own re-invitation. Appoint another Owner, or turn Require Approver off.",
            verdict.reason,
          );
        }
      }
      // HARD anti-escalation guard, matching deleteRole and revokePasskeyCredential: an access-admin holds
      // roles.write and may offboard any non-owner, but only an Owner may strip an Owner.
      this.requireNotOwnerEscalation(resolved.role, false, targetIsOwner);

      // SELF-REVOCATION IS REFUSED: revoking your own every factor is a self-lockout with no legitimate use,
      // because rotating your own codes is regenerate and dropping a lost key is the credential route.
      //
      // ITS SAFETY DIRECTION IS THE EASY ONE: it refuses a DESTRUCTIVE act, so it can lock nobody out.
      //
      // IT SITS AFTER THE OWNER-FLOOR GUARD DELIBERATELY, and both still run before any mutation. A SOLE
      // Owner revoking themselves is refused by both, and the floor's sentence is the more useful of the two
      // because it names the repair ("appoint a second Owner first"); the self sentence would leave them
      // reading advice about a credential route that cannot help. The floor guard does not subsume this one:
      // it fires only for an OWNER target and only when the tally would breach the floor, so a second Owner
      // present, or any non-owner, walked straight past it into a total self-lockout only somebody else could
      // repair.
      if (callerEmailOf(caller) === email) {
        await recordAdminRefusal(this.state.storage, "rbac-guardrail", "guardrail");
        throw new Error(
          "cannot revoke your OWN sign-in factors: this removes every passkey, recovery code and pending invite you hold at once, and only another operator could let you back in. To rotate your recovery codes use regenerate; to drop a lost key remove that credential.",
        );
      }

      // ---- the three deletes ------------------------------------------------------------------------
      // Credentials are deleted directly rather than by looping revokePasskeyCredential. That helper re-runs
      // its own capability resolution and sole-Owner check per credential and audits + bumps the epoch on each,
      // so a loop would emit N audit rows and N epoch bumps for ONE operator act, and its last-credential guard
      // would refuse mid-way through a revoke this route has already authorised as a whole.
      const mine = await this.listPasskeyCredsForEmail(email);
      let passkeyCredentials = 0;
      for (const c of mine) {
        if (await this.state.storage.delete(`${PASSKEY_CRED_PREFIX}${c.credentialId}`)) passkeyCredentials++;
      }
      // The recovery record: one key per email, and the first delete of it that has ever existed.
      const recovery = await this.state.storage.delete(`${RECOVERY_PREFIX}${email}`);
      // Invites: a SCAN is unavoidable because the key is the token. The token is read into a local, used only
      // to build the delete key, and never returned, logged or counted by value.
      const inviteMap = await this.state.storage.list<PasskeyInvite>({ prefix: PASSKEY_INVITE_PREFIX });
      let invitesLive = 0;
      let invitesExpired = 0;
      for (const [key, inv] of inviteMap.entries()) {
        if ((typeof inv?.email === "string" ? inv.email.trim().toLowerCase() : "") !== email) continue;
        const live = typeof inv.expiresAt === "number" && inv.expiresAt > now;
        if (!(await this.state.storage.delete(key))) continue;
        if (live) invitesLive++;
        else invitesExpired++;
      }

      // EXPIRED INVITES ARE SWEPT HERE, and only here. Expiry does NOT imply deletion on its own: a read must
      // not mutate, and the expired COUNT is the only surviving evidence that invitations were minted for this
      // address over and over, which is a real diagnosis (a person who never completed enrolment) that a
      // background sweep would erase before anyone read it. But once an operator has explicitly named this
      // person for removal that diagnosis is spent, and leaving dead records keyed to somebody who has just
      // been offboarded serves nobody. So the sweep is scoped to the named
      // email and attended by definition, never a cron. It is reported as its own count so it can never pad the
      // number that matters, and it deliberately does not count toward "a way in was closed".
      const revoked: SignInFactorRevocation = { passkeyCredentials, recovery, invitesLive, invitesExpired };
      const closedAWayIn = revocationClosedAWayIn(revoked);

      // SESSION TERMINATION IS SCOPED TO A REAL REVOCATION. Bumping the epoch kills every live session for this
      // identity, which is correct for a deliberate removal and wrong as a side effect of anything else. So it
      // fires only when a WAY IN was actually closed: a revoke that found nothing, or one that swept only
      // expired residue, must not sign anybody out. Both axes, as deleteRole does -- the per-email epoch, and
      // for a bound member the per-subject not-before, which is what kills an oidc/saml session keyed on the
      // subject rather than the address.
      if (closedAWayIn) {
        await this.bumpSessionEpoch(email);
        if (boundCurrent !== undefined) await this.bumpSessionEpochSub(boundCurrent.subject, now);
        await this.appendAudit({
          actorSubject: caller ? caller.subject : null,
          actorEmail: caller?.email ? caller.email : null,
          actorMethod: caller ? caller.method : "access",
          sourceIp: caller?.sourceIp ?? null,
          action: "signin-factor-revoke",
          outcome: "success",
          // The role the target HELD at the revocation, not a transition: this action does not change anybody's
          // role, and recording "viewer" here (as an offboarding role-change legitimately does) would assert a
          // demotion that did not happen.
          target: { kind: "role", email, role: targetRole },
        });
      }
      return { email, revoked, sessionsTerminated: closedAWayIn };
    }
  };
}
