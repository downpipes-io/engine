// The RBAC caller-authority cluster: effective-authority resolution for a forwarded caller, the whoami
// bootstrap/bind path, and the anti-escalation + grant-within-authority guards. A sibling sub-mixin of
// RbacMixin (the role-resolution primitives stay there; the role/group/custom-role writes live in
// scheduler-do-rbac-mutations.ts). All layer over a base whose `this` is SchedulerDOSurface, so
// roleForCaller reaches resolveAuthority / resolveBoundEntry / capabilitiesOfCustomRole and the writes
// reach these guards through `this`. A leaf the assembly depends on, never the reverse.

import { type AuthMethod, type Capability, type CustomRole, ROLE_CAPABILITIES, type Role, type RoleEntry, type RoleSource, roleSubjectKey } from "../admin/identity.ts";
import { getIdpConnectionRaw } from "../admin/oidc-store.ts";
import { AuthError, type GroupRoleEntry, type MutationCaller, OIDC_GROUPS_PREFIX, type SchedulerDOCtor } from "./scheduler-do-base.ts";
import { nowMillisISO } from "./scheduler-helpers.ts";

// subjectConnId extracts the IdP connection id a NATIVE-IdP subject was minted through: a native subject is
// "oidc:<connId>|<issuer>|<sub>" or "saml:<connId>|<entityId>|<NameID>" (identity.ts), so the connId is the
// first "|"-separated segment after the method prefix. A passkey / Cloudflare-Access subject (no oidc:/saml:
// prefix) belongs to no native connection, so it returns null and matches only GLOBAL (unscoped) group mappings.
function subjectConnId(subject: string): string | null {
  for (const prefix of ["oidc:", "saml:"]) {
    if (subject.startsWith(prefix)) {
      const rest = subject.slice(prefix.length);
      const bar = rest.indexOf("|");
      const connId = bar > 0 ? rest.slice(0, bar) : rest;
      return connId.length > 0 ? connId : null;
    }
  }
  return null;
}

// scopeGroupMapping (G2) filters the group-role mapping to those that apply to THIS caller's connection before
// role resolution: a GLOBAL mapping (no connId) always applies; a SCOPED mapping applies only when its connId
// matches the connection the caller's subject was minted through. This closes the cross-IdP group-name
// collision (a scoped "admins" for the trusted IdP is not conferred to a second connection asserting the same
// name) without touching the pure resolution functions -- they receive an already-connection-scoped mapping.
// Fast path: when no scoped mapping exists the list is returned unchanged (the legacy all-global behaviour).
function scopeGroupMapping(mapping: GroupRoleEntry[], subject: string): GroupRoleEntry[] {
  if (!mapping.some((m) => m.connId !== undefined)) return mapping;
  const connId = subjectConnId(subject);
  return mapping.filter((m) => m.connId === undefined || m.connId === connId);
}

// isNativeIdpSubject reports whether a subject was minted through one of the engine's OWN IdP connections,
// as opposed to a passkey or Cloudflare-Access subject which belongs to no connection at all. It is the
// companion to subjectConnId above: that function answers WHICH connection, this one answers WHETHER there
// is supposed to be one, and the pair is what lets a malformed native subject (the "oidc:" prefix with no
// readable connection id) fail CLOSED instead of being mistaken for a connectionless passkey caller.
function isNativeIdpSubject(subject: string): boolean {
  return subject.startsWith("oidc:") || subject.startsWith("saml:");
}

export function RbacAuthorityMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // roleForCaller resolves the effective AUTHORITY (built-in role + source, plus any custom-role
    // capability set + record) for a forwarded caller (the DO's own authority computation for the
    // people/access-policy routes). The token-fallback caller is the all-or-nothing break-glass owner
    // (owner-token), resolved without consulting the tables, exactly as the router does. An Access
    // caller's authority is resolved from this DO's own role table + group mapping + custom-role
    // catalogue given the caller's email and verified groups, so the DO NEVER trusts the role asserted in
    // the header (nor a forwarded capability set); it recomputes from its own state. A null caller
    // (absent/malformed header) fails closed to viewer/default (no authority).
    //
    // REPLAY. A caller carrying `replay: true` is a RECORDED identity being re-resolved with no request of
    // theirs in hand (the approval spend's stored maker and checker, the owner action's stored proposer). Such
    // a re-resolution must never BIND: resolveBoundEntry step 2 is a WRITE that turns a pending grant matching
    // the caller's EMAIL into a subject-keyed entry and deletes the pending row, and a recorded email is not a
    // live authentication of the person now behind that address. Without the suppression, an ordinary invite
    // issued at a departed person's re-used address would resurrect their armed approval and consume the
    // new person's grant into the departed subject. The subject axis is untouched, so a replayed identity that is
    // still BOUND resolves exactly as it always did; only the email-matched bind is off.
    //
    // THE FLAG NOW CARRIES A SECOND DIFFERENCE, and both are the same idea: a replay must never resolve to
    // more than a live request from that identity would. A live native-IdP request is refused outright unless
    // its connection still exists and is enabled (scheduler-do-session's authoritative re-read), and a replay
    // presents no session, so it consulted that axis not at all. It does now, via replayConnectionLive below.
    // A live caller passes no flag and reaches neither branch, so every live path stays byte-for-byte
    // unchanged and the two differences between a replay and a request are both written down here.
    async roleForCaller(
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null; replay?: boolean } | null,
    ): Promise<{ role: Role; source: RoleSource; capabilities?: ReadonlySet<Capability>; customRole?: CustomRole }> {
      if (caller === null) return { role: "viewer", source: "default" };
      // SECURITY (ENG-B1): ONLY the bare-token method is the Owner break-glass. An emailless/subjectless
      // Access caller OR a passkey caller must fall through to the SUBJECT-keyed lookup below, where a null
      // subject fails closed to viewer. The passkey method is subject-bearing (passkeySubject(email)), so it
      // resolves its role from the role table EXACTLY like an Access subject and can NEVER reach the
      // owner-token break-glass; only method:"token" does.
      // SECURITY (R13): this branch trusts the ASSERTED `method`, and that is correct PRECISELY BECAUSE
      // `method` is as trusted as the rest of the caller header. The DO's "never trust the asserted role"
      // discipline is about the ROLE axis (recomputed below from the DO's own tables); the caller header
      // ITSELF is router-internal, not a client input: it is built ONLY by callerHeaders() in router.ts
      // and the engine's own ENGINE_DRILL_CALLER in index.ts,
      // from the verified auth verdict and an inbound x-downpipe-caller is overwritten, never copied (see
      // CALLER_HEADER / callerHeaders), so a forged method cannot reach here from a client request. The
      // engine RELIES on this method:"token" -> owner path for its own ENGINE_DRILL_CALLER (index.ts), the
      // internal owner-authority break-glass it forwards to record a scheduled restore test's evidence.
      // It must therefore stay ROUTER-ONLY: keep the caller header out of any client-copyable path.
      //
      // BREAK-GLASS RETIRE is NOT enforced here on purpose. The retire flag disposes of the EXTERNAL ADMIN_TOKEN
      // bearer: auth.ts refuses a retired inbound bare token at the gate (it never reaches any route), and the
      // inbound-token role-resolution point (whoami) re-checks the latch as defence in depth. roleForCaller is
      // ALSO the path the engine's OWN internal ENGINE_DRILL_CALLER (a forged owner header the engine sets on
      // ITSELF, never the ADMIN_TOKEN string) flows through to record scheduled restore-test evidence; gating
      // it here would silently disable that legitimate internal cron after a retire and undermine restore-test
      // recency. The two token callers are indistinguishable at this surface, so the external-disposal control
      // is enforced at the EXTERNAL boundary (auth.ts + whoami), not on the engine's own internal authority.
      if (caller.method === "token") return { role: "owner", source: "owner-token" };
      const subject = this.normaliseSubject(caller.subject);
      if (!subject) return { role: "viewer", source: "default" };
      // CONNECTION LIVENESS, ON A REPLAY ONLY, and it is the second thing a re-resolution cannot get from
      // the record alone. A LIVE request from a native-IdP subject has already passed scheduler-do-session's
      // authoritative liveness re-read before it reaches here: an oidc/saml session is valid only while its
      // connection still EXISTS and is ENABLED, so deleting or disabling a connection kills every session on
      // it on the very next request. A REPLAY presents no session and passed none of that. So a person whose
      // connection had been deleted outright still re-resolved to their full authority, and their armed
      // approval still spent, for as long as the record lived. That is not a stale snapshot: it is the whole
      // connection axis missing from a path that is otherwise deliberately the SAME roleForCaller a request
      // goes through. Checked here rather than inside scopeGroupMapping because the gap is wider than the
      // group mapping: a person carrying a DIRECT role row on a dead connection is refused every request too,
      // and refusing the groups alone would have left that half open.
      if (caller.replay === true && isNativeIdpSubject(subject) && !(await this.replayConnectionLive(subject))) {
        return { role: "viewer", source: "default" };
      }
      const email = this.normaliseEmail(caller.email);
      const now = Date.now();
      const mapping = await this.listGroupRoleEntries();
      const customRoles = await this.listCustomRoleRecords();
      // Resolve (and bind-on-first-auth) the caller's BOUND entry by their stable subject. The email is the
      // bind key for a pending invite; authorisation keys on the subject. A caller whose email equals a
      // departed member's but whose SUBJECT differs has no bound entry and matches no pending invite of the
      // departed member (that grant bound to the departed subject, or was deleted), so it resolves to viewer:
      // the V10.3.3 / V10.5.2 closure (a recycled email never inherits a prior member's role).
      // `undefined` for a live caller keeps resolveBoundEntry's own per-subject default (false for a native-IdP
      // subject, true otherwise); a replay forces it off. Every live path is therefore byte-for-byte unchanged.
      const mine = await this.resolveBoundEntry(subject, email, caller.replay === true ? false : undefined);
      return this.resolveAuthority(mine, caller.groups, scopeGroupMapping(mapping, subject), customRoles, now);
    }

    // replayConnectionLive answers "could this recorded native-IdP principal still authenticate at all?" for
    // a re-resolution that happens with no request of theirs in hand. It is the SAME question, read from the
    // SAME record, that scheduler-do-session asks of every live oidc/saml request: does the connection the
    // subject was minted through still exist, and is it enabled. A pure DO storage read, no IdP network.
    //
    // IT FAILS CLOSED IN BOTH DIRECTIONS THAT MATTER. A native subject carrying no readable connection id is
    // malformed and answers false, because the only ways to reach here are a hand-edited record or a subject
    // format that has changed under us, and conferring authority on either is worse than refusing. A
    // connection that is absent (deleted, which also deletes its paired client secret) or present-and-disabled
    // answers false, which are precisely the two states the request path refuses on.
    //
    // WHAT IT DOES NOT DO IS VOID ANYTHING. Like every other axis of the spend-time binding this is a
    // SUSPENSION: re-enable the connection and the same approval spends with no fresh ceremony, because the
    // subject string is unchanged and this is a live read. A connection DELETED and re-created gets a new
    // connection id and therefore a new subject, so its members' records were already dead on the subject
    // axis and nothing here changes that. The signal is recorded because the approver's remedy differs from
    // every other lapse: "authority lapsed" points them at the role table, and the role grant may be intact.
    async replayConnectionLive(subject: string): Promise<boolean> {
      const connId = subjectConnId(subject);
      if (connId === null) {
        await this.recordAuthSignal("replay-conn-liveness-refused");
        return false;
      }
      const conn = await getIdpConnectionRaw(this.idpKv, connId);
      if (conn === undefined || !conn.enabled) {
        await this.recordAuthSignal("replay-conn-liveness-refused");
        return false;
      }
      return true;
    }

    // capabilitiesOfResolved materialises the effective capability set for a resolved authority: the
    // explicit custom-role capability set when present, otherwise the built-in role's set. This is the DO
    // mirror of callerCan in identity.ts (the router side), so the two enforce authority identically. The
    // owner-token break-glass holds every capability (its built-in role is owner), so a forwarded
    // owner-token resolves to owner's full set.
    capabilitiesOfResolved(resolved: { role: Role; capabilities?: ReadonlySet<Capability> }): ReadonlySet<Capability> {
      return resolved.capabilities ?? ROLE_CAPABILITIES[resolved.role];
    }

    // spendTimeGroupsFor answers "which groups does this STORED subject hold NOW?" for an authority
    // re-resolution that happens long after the person acted and without a request of theirs in hand.
    //
    // For an oidc/saml subject the engine holds its OWN server-side snapshot at `oidcgroups:<subject>` and
    // re-reads it on EVERY request that session makes (scheduler-do-session.ts), so that snapshot -- not the
    // copy recorded when they acted -- is what the engine would grant them right now, and using anything else
    // would re-resolve against a value the engine itself considers stale. A MISSING snapshot resolves to no
    // groups for exactly the same reason: that is what their own next request would resolve to.
    //
    // For every other method the recorded claims are the only thing there is. A Cloudflare-Access caller's
    // groups exist solely inside the inbound Access token and are stored nowhere server-side, so a re-resolution
    // that ignored the recorded copy would strand every approver whose role comes from an Access group mapping,
    // which is a legitimate approver being refused rather than a lapsed one being caught. A passkey caller has
    // no groups at all, so the recorded empty list is already the live answer.
    //
    // The list is bounded by the DO's own boundGroupList, exactly as every other group input is: a stored
    // record is an input like any other and the DO bounds its own inputs. A non-array (a corrupted or
    // hand-edited record) yields no groups, which is the fail-closed direction.
    async spendTimeGroupsFor(subject: string, recordedGroups: readonly string[] | undefined): Promise<string[]> {
      if (subject.startsWith("oidc:") || subject.startsWith("saml:")) {
        const snapshot = await this.state.storage.get<string[]>(`${OIDC_GROUPS_PREFIX}${subject}`);
        return this.boundGroupList(Array.isArray(snapshot) ? snapshot : []);
      }
      return this.boundGroupList(Array.isArray(recordedGroups) ? [...recordedGroups] : []);
    }

    // resolveStoredIdentityAuthority re-resolves the LIVE effective capability set of a principal recorded on a
    // stored governance record, keyed on their IMMUTABLE SUBJECT. It is the shared engine behind the spend-time
    // binding on the restore and prune approval machines (approvalIdentitiesStillAuthorised, approvals.ts) and
    // it is deliberately the SAME roleForCaller every request goes through, so a re-resolution can never grant
    // something a live request would not.
    //
    // method is "access", never the method the person actually authenticated with, for the same reason
    // proposerReplayCaller pins it: the ONLY behaviour `method` drives in roleForCaller is the bare-token
    // owner break-glass branch, and a replayed identity must never be able to reach it. A record with no
    // subject holds nothing (fail closed); the request/approve paths already refuse a subjectless caller, so
    // reaching that branch means the record is malformed and refusing is correct.
    async resolveStoredIdentityAuthority(subject: string | undefined, email: string | undefined, recordedGroups: readonly string[] | undefined): Promise<ReadonlySet<Capability>> {
      if (typeof subject !== "string" || subject.length === 0) return new Set<Capability>();
      const groups = await this.spendTimeGroupsFor(subject, recordedGroups);
      // replay: true, and it is the difference between a suspension and a resurrection. The recorded email is
      // carried for the same reason proposerReplayCaller carries it (it is what the resolution and any audit
      // downstream call the person), but it must NOT be allowed to match a pending grant: an address is not an
      // identity, and the pending grant sitting at a departed maker's re-issued address belongs to whoever the
      // account invited next.
      const resolved = await this.roleForCaller({ method: "access", email: typeof email === "string" ? email : null, subject, groups, replay: true });
      return this.capabilitiesOfResolved(resolved);
    }

    // withResolvedCaps enriches a forwarded mutation caller with its LIVE-resolved effective capability set
    // ONLY when the caller resolves (from the DO's OWN tables, via roleForCaller) to a CUSTOM ROLE, so the
    // gated apply runs as a MutationCaller whose by-role re-checks (callerHolds) honour that custom role's
    // actual authority (F6) instead of refusing it on its "viewer" built-in floor. For a BUILT-IN caller the
    // forwarded caller is returned VERBATIM (same role, no capabilities set): the notify/expiry/webhook/
    // posture by-role re-checks already trust the router-forwarded built-in role (it is router-internal, see
    // CALLER_HEADER), so re-resolving it here would WRONGLY override the asserted role with a tables-only
    // lookup and break the existing trust-the-forwarded-role contract. The custom-role set is the caller's
    // OWN live-resolved authority, so this NEVER widens what they may do; it only stops a legitimate
    // custom-role holder being refused. A null caller stays null. The DO's people/access-policy writes use
    // requireCapabilityResolved (which re-resolves regardless), so they are unaffected either way.
    async withResolvedCaps(caller: MutationCaller | null): Promise<MutationCaller | null> {
      if (caller === null) return null;
      const resolved = await this.roleForCaller(caller);
      // Only a custom-role caller carries a resolved capability set; for a built-in caller leave the
      // forwarded caller untouched (trust the router-internal asserted role, as the by-role checks already do).
      if (resolved.capabilities === undefined) return caller;
      return {
        method: caller.method,
        email: caller.email,
        subject: caller.subject, // carry the stable principal so the apply-time re-resolution keys on it
        role: resolved.role, // the custom-role caller's "viewer" built-in floor; the set is the real authority
        groups: caller.groups,
        capabilities: resolved.capabilities,
        // Carried, not dropped. This function REBUILDS the caller field by field rather than spreading, so a
        // replay caller passing through here would silently lose the flag and the downstream re-checks would
        // resolve it as a live request: a bind-on-first-auth write and an unchecked connection. No live path
        // hands it a replay caller today, and this is what keeps that true if one ever does.
        ...(caller.replay === true ? { replay: true as const } : {}),
      };
    }

    // listRoles returns the people ROSTER (readable by any authenticated caller; reading the table is not a
    // write): the BOUND members (`role:sub:` entries, each with a real subject) AND the PENDING invitations
    // (`role:pending:`/legacy, an invited email that has not authenticated yet), so an Owner/access-admin
    // sees everyone they have granted - including invitees who have not signed in. A pending row is surfaced
    // with subject "" (the honest "not bound yet" placeholder; the console shows the email and an "invited"
    // state). Emails are the customer's own data in their own account; the console escapes them on render. A
    // pending row is included only when no bound entry already covers the same email (a bound member is the
    // authoritative row), so the same person never appears twice.
    async listRoles(): Promise<RoleEntry[]> {
      const bound = await this.listRoleEntries();
      const boundEmails = new Set(bound.map((e) => e.email));
      const pending = await this.listPendingEntries();
      const pendingRows: RoleEntry[] = pending
        .filter((p) => !boundEmails.has(p.email))
        .map((p) => ({
          subject: "",
          email: p.email,
          role: p.role,
          grantedBy: p.grantedBy,
          grantedAt: p.grantedAt,
          ...(p.expiresAt !== undefined ? { expiresAt: p.expiresAt } : {}),
          ...(p.customRole !== undefined ? { customRole: p.customRole } : {}),
        }));
      return [...bound, ...pendingRows];
    }

    // parseGroupsParam reads the OPTIONAL groups query param (a JSON array the router built from the
    // verified Access groups) into a bounded string[]. Anything that is not a JSON array yields [] (the
    // honest "no groups" signal that keeps the per-email path unchanged). The DO bounds the list ITSELF
    // via boundGroupList (trim, drop empty/over-long/control-char, dedupe, cap to GROUPS_MAX) rather
    // than relying on access.ts having bounded it: the DO is its own authority and bounds its own
    // inputs, so a pathological signed token or a tampered param cannot hand it an unbounded list.
    parseGroupsParam(raw: string | null): string[] {
      // An ABSENT/empty param is the legitimate "this caller has no groups" (a passkey caller always, an
      // Access caller with no group claims): it is not a fault and is never recorded.
      if (raw === null || raw.length === 0) return [];
      try {
        const v = JSON.parse(raw) as unknown;
        // G061: a param that PARSED but is not an array is corrupt (a router/DO version skew, a tampered
        // param). It coerces to [] and every group->role mapping in the account silently stops resolving:
        // "all our AD-group users dropped to viewer at once", with a perfectly clean-looking pack.
        if (!Array.isArray(v)) {
          void this.recordAuthSignalThrottled("rbac-groups-param-unparseable");
          return [];
        }
        return this.boundGroupList(v);
      } catch {
        // The same coercion, from a param that is not JSON at all. Count only: never the param.
        void this.recordAuthSignalThrottled("rbac-groups-param-unparseable");
        return [];
      }
    }

    // whoami resolves the caller's role, its honest source, and whether they are the sole Owner.
    // method/email/subject/groups come from the router's verified verdict. BOOTSTRAP: when the role table
    // is EMPTY (no bound, no pending, no legacy) and the caller authenticated via Access/passkey (so there
    // is a stable subject), that first caller becomes the Owner via a SUBJECT-keyed `role:sub:` entry, so a
    // fresh tenant can administer roles (source "email", a named, attributable grant). The token-fallback
    // caller has no subject and never writes an entry; it resolves to owner with source "owner-token". For
    // an established table the bound entry is resolved/bound by subject (resolveBoundEntry: bind-on-first-
    // auth from a pending email invite) and folded with the group mapping. isOnlyOwner counts explicit
    // bound+pending owner entries (a group can never confer owner), so the last-Owner pre-empt is coherent.
    async whoami(
      emailRaw: string | null,
      subjectRaw: string | null,
      method: string | null,
      groupsRaw: string | null,
      // G346: the edge address the ROUTER read, forwarded for the one WRITE this route can perform (the
      // first-Owner bootstrap's attributed audit row). Optional and defaulted so a caller that has no address
      // (a local validator request, an engine-internal probe) is unchanged.
      sourceIpRaw: string | null = null,
    ): Promise<{ role: Role; roleSource: RoleSource; subject?: string; groups: string[]; isOnlyOwner: boolean; customRole?: CustomRole; capabilities?: Capability[]; recoveryRequired?: true }> {
      const now = Date.now();
      const email = this.normaliseEmail(emailRaw);
      const subject = this.normaliseSubject(subjectRaw);
      const groups = this.parseGroupsParam(groupsRaw);
      // Token fallback: the router treats the bare-token break-glass as owner; the DO has no row to
      // report, so it reports owner with isOnlyOwner false (it is not a counted, attributable Owner row).
      // The token path carries no groups (the break-glass has no IdP identity), so source is owner-token.
      // BREAK-GLASS RETIRE, defence in depth at the inbound-token role-resolution point: once the Owner has
      // retired the break-glass token, an inbound bare token must NEVER resolve to owner. auth.ts already
      // refuses a retired bare token at the gate (so it never reaches here on the live path), but re-check the
      // latch HERE too so the DO's own role resolution for a token caller fails closed to least-privilege
      // viewer while retired (a router bypass cannot then surface owner). This is the inbound EXTERNAL token
      // path only (the engine's internal cron uses roleForCaller + /drill-evidence, not whoami), so the
      // legitimate internal drill-evidence recording is unaffected by a retire.
      if (method === "token") {
        if (await this.getBreakGlassTokenRetired()) {
          return { role: "viewer", roleSource: "default", groups: [], isOnlyOwner: false };
        }
        return { role: "owner", roleSource: "owner-token", groups: [], isOnlyOwner: false };
      }
      // SECURITY (ENG-B1 / V10.3.3): an Access/passkey caller with no STABLE subject is NOT the break-glass;
      // fail closed to viewer. The router and authorise reject a subjectless/emailless assertion upstream,
      // so this is defence in depth and never the bootstrap.
      if (!subject) {
        return { role: "viewer", roleSource: "default", groups: [], isOnlyOwner: false };
      }
      // INFRA-1 silence-killer + amnesia-latch deadlock fix. The recovery-required latch and the first-Owner
      // bootstrap key on the SAME condition -- an EMPTY role table -- so the latch's whoami degrade belongs
      // INSIDE the empty-table branch, gated on roleTableIsEmpty(). Two reasons this is the right gate:
      //   * PURPOSE. The latch exists to stop a WIPED DO silently re-bootstrapping first-Owner to whoever
      //     calls first, and that silent re-bootstrap can happen ONLY when the role table is empty. Genuine
      //     fresh-DO amnesia -- a redeploy whose fresh DO lost the config AND the identity while running on an
      //     old bucket that still holds runs -- leaves the role table EMPTY, so the degrade still fires there:
      //     a fresh-DO caller on an old bucket is still reported recovery-required (viewer), never Owner.
      //   * DEADLOCK. The cron latches recovery-required on an empty CONFIG (0 downpipes + 0 destinations)
      //     REGARDLESS of the role table, and the latch clears only through the break-glass reconcile, which
      //     refuses a non-empty role table. So an INTACT Owner who emptied their config (deleted every
      //     downpipe and destination while an env/IaC destination still resolved and the bucket still held
      //     runs) was latched to viewer every session with NO in-product clear -- a real no-recovery lockout.
      //     An intact Owner is not an amnesiac control plane: when the role table is NON-EMPTY the identity
      //     survived, so fall through to resolve authority normally below and NEVER degrade.
      // The bare-token break-glass short-circuited above, so the reconcile path is unaffected. (Read AFTER the
      // token/subjectless early-returns, and now only when the table is empty, so the common established-table
      // path pays no extra storage read.)
      if (await this.roleTableIsEmpty()) {
        const recovery = await this.getControlPlaneRecoveryRequired();
        if (recovery.required) {
          return { role: "viewer", roleSource: "default", subject, groups, isOnlyOwner: false, recoveryRequired: true };
        }
        // BELT-AND-BRACES over the empty-table check: once the FIRST Owner has EVER been claimed
        // (bootstrapConsumed latched true), NO bootstrap may mint another Owner even if the role table later
        // became empty. So an empty table with the latch already set does NOT bootstrap; this caller falls
        // through to the least-privilege viewer default (an Owner must grant them a role), and the break-glass
        // is the documented recovery if every Owner is lost. The last-Owner guard already prevents emptying the
        // table by removing/demoting the sole Owner (requireNotLastOwner in roleSet/roleDelete throws "would
        // remove the last Owner"), so a non-empty table is the norm; this latch closes the residual window
        // (e.g. a hand-edited/cleared store) where an empty table could otherwise re-open the first-Owner grant.
        if (await this.getBootstrapConsumed()) {
          // G061: THE DEADLOCK. The role table is EMPTY and the one-shot bootstrap latch is SPENT, so nobody
          // holds authority and nobody can claim it: every caller resolves to viewer forever and the "email
          // the owner a link" button is permanently inert. Until now this was indistinguishable, in a pack,
          // from "an account whose members are all viewers" -- and the two have completely different remedies
          // (the second is a role grant; this one is the break-glass recovery). Recorded THROTTLED because
          // whoami is on every authenticated request. Count only: no subject, no email.
          void this.recordAuthSignalThrottled("rbac-empty-table-with-latch");
          return { role: "viewer", roleSource: "default", groups, isOnlyOwner: false };
        }
        // First caller bootstrap: a SUBJECT-keyed Owner entry recording the email for display. Race-free in
        // the single-threaded DO. An emailless first caller cannot bootstrap (it has no display identity and
        // the access path requires email upstream), so guard email here too.
        if (email !== null) {
          const entry: RoleEntry = { subject, email, role: "owner", grantedBy: "bootstrap", grantedAt: nowMillisISO() };
          await this.state.storage.put(roleSubjectKey(subject), entry);
          // Latch the one-way bootstrap-consumed flag (and audit the one-time event) the MOMENT this first Owner
          // row is created: from here on the empty-table path above refuses any further bootstrap. The actor is
          // the bootstrapping email via the method that reached whoami (access or passkey; the token break-glass
          // short-circuited above and never writes a row here).
          // The source IP is threaded through on this access first-owner bootstrap call, matching the passkey
          // twin (scheduler-do-passkey.ts markBootstrapConsumed(email, "passkey", sourceIp)).
          const sourceIp = typeof sourceIpRaw === "string" && sourceIpRaw.length > 0 ? sourceIpRaw : null;
          await this.markBootstrapConsumed(email, method === "passkey" ? "passkey" : "access", sourceIp);
          // The bootstrap is an explicit, attributable Owner grant, so the basis is "email".
          return { role: "owner", roleSource: "email", subject, groups, isOnlyOwner: true };
        }
        return { role: "viewer", roleSource: "default", groups: [], isOnlyOwner: false };
      }
      const mapping = await this.listGroupRoleEntries();
      const customRoles = await this.listCustomRoleRecords();
      // Resolve (and bind-on-first-auth) the caller's bound entry by subject, then fold the group mapping +
      // any referenced custom role's capability set ON TOP (additive). When a custom role wins, role is the
      // built-in floor, source is "custom", capabilities is the resolved set and customRole is the winning
      // record for the console to skin/land.
      const mine = await this.resolveBoundEntry(subject, email);
      const resolved = this.resolveAuthority(mine, groups, scopeGroupMapping(mapping, subject), customRoles, now);
      // isOnlyOwner is meaningful only for an explicit owner; a group/custom role can never confer owner, so
      // this is true only when the EFFECTIVE role is owner (which only an explicit grant can reach) and there
      // is exactly one explicit effective Owner across the bound + pending entries.
      const entries = await this.listRoleEntries();
      const pending = await this.listPendingEntries();
      const isOnlyOwner = resolved.role === "owner" && this.countOwners(entries, pending, now) === 1;
      return {
        role: resolved.role,
        roleSource: resolved.source,
        subject,
        groups,
        isOnlyOwner,
        ...(resolved.customRole !== undefined ? { customRole: resolved.customRole } : {}),
        ...(resolved.capabilities !== undefined ? { capabilities: [...resolved.capabilities] } : {}),
      };
    }

    // requireCapabilityResolved is the DO-side authority re-check for the PEOPLE-and-access-policy
    // writes (the role table, the group->role mapping AND the custom-role catalogue). It RE-RESOLVES the
    // caller's effective AUTHORITY from the DO's OWN tables given the forwarded email AND verified groups
    // (roleForCaller), then checks the resolved EFFECTIVE CAPABILITY SET holds the required CAPABILITY
    // (capabilitiesOfResolved -> has(), the same set callerCan reads on the router side). It never trusts
    // the role NOR a forwarded capability set for these routes, so a router bug cannot grant a people
    // write, and (critically) an access-admin elevating the header role, or a forged custom-role
    // capability set, could not slip through: the authority is recomputed from this DO's state. The
    // token-fallback caller resolves to owner-token (the documented break-glass), which holds every
    // capability; an absent/malformed caller resolves to viewer/default and is refused. It THROWS an
    // AuthError on refusal so the fetch() catch maps it to a 403 (the router returns the first-class 403
    // before forwarding, so reaching this throw means the router gate was bypassed and failing closed is
    // correct). It returns the resolved authority (role + the effective capability set) so the caller can
    // apply finer guards (the role table's owner-escalation guard, which needs the resolved built-in
    // role, and validateCustomRole, which needs the creator's own capability set for the no-escalation check).
    async requireCapabilityResolved(
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
      capability: Capability,
    ): Promise<{ role: Role; source: RoleSource; capabilities: ReadonlySet<Capability> }> {
      const resolved = await this.roleForCaller(caller);
      const caps = this.capabilitiesOfResolved(resolved);
      // engine-src-037-03: a capability denial is an authorisation refusal -> AuthError -> 403 (not a 400),
      // and the capability name stays in the message for the internal log only, never echoed to the caller.
      if (!caps.has(capability)) throw new AuthError(`forbidden: ${capability} capability required`);
      return { role: resolved.role, source: resolved.source, capabilities: caps };
    }

    // requireNotOwnerEscalation is the HARD anti-privilege-escalation guard for the role table: a caller
    // may only create OR remove the owner role if THEY are themselves an Owner. An access-admin holds
    // roles.write (so it manages viewer/operator/restore-operator/approver/access-admin), but it must
    // NEVER be able to mint itself (or anyone) Owner, nor demote/remove an existing Owner, because owner
    // is the break-glass-holder role and that would be a self-elevation of the whole account. The two
    // owner-touching operations are: GRANTING owner (the new role is owner) and DEMOTING/REMOVING a
    // current Owner (the target is currently an effective Owner and the new role is not owner). Either
    // requires callerRole === "owner". This is ORTHOGONAL to the last-Owner guard (which protects
    // availability: never remove the SOLE Owner, even an owner cannot); this one protects the authority
    // boundary (only an Owner may touch the owner role at all). callerRole is the RESOLVED role from
    // requireCapabilityResolved (the DO's own table lookup), so a non-owner cannot bypass it by asserting
    // owner in the forwarded header. It THROWS on refusal -> 400 (the router gates roles.write first).
    requireNotOwnerEscalation(callerRole: Role, grantingOwner: boolean, demotingOwner: boolean): void {
      if ((grantingOwner || demotingOwner) && callerRole !== "owner") {
        throw new AuthError("forbidden: only an Owner may grant or remove the owner role");
      }
    }

    // requireGrantWithinAuthority is the HARD no-escalation invariant for GRANTING a role (built-in OR
    // custom) to a person OR a group: an assigner may only confer capabilities they THEMSELVES hold. The
    // create-time guard (validateCustomRole) stops composing a role above your authority, but assignment
    // is the second door: once any strong role exists, a roles.write/access.policy holder must not be
    // able to hand it out (or self-grant it) and thereby confer capabilities beyond their own resolved
    // set. So the assigned role's capability set must be a SUBSET of the assigner's. Computed from the
    // DO's own recomputed caps (capabilitiesOfResolved over the requireCapabilityResolved result), never
    // a forwarded header, so a non-owner cannot bypass it by asserting a stronger role. Owner-as-target
    // is handled separately by requireNotOwnerEscalation; this closes the access-admin-grants-approver and
    // the assign-a-strong-custom-role-to-yourself escalations. THROWS on refusal -> 400.
    requireGrantWithinAuthority(
      resolved: { role: Role; capabilities?: ReadonlySet<Capability> },
      assignedCaps: ReadonlySet<Capability>,
    ): void {
      const assignerCaps = this.capabilitiesOfResolved(resolved);
      for (const cap of assignedCaps) {
        if (!assignerCaps.has(cap)) {
          throw new AuthError(`forbidden: cannot grant a role conferring the ${cap} capability that you do not hold`);
        }
      }
    }
  };
}
