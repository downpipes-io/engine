// The RBAC subsystem (D3: the role model keyed on the STABLE subject, the optional group->role
// mapping, and the composable custom roles). RbacMixin holds the role-resolution PRIMITIVES
// (normalise/list/resolveRole/resolveAuthority/customRoleNamesFor/capGroupRole); the caller-authority
// resolution + whoami + the anti-escalation guards live in the sibling ./scheduler-do-rbac-authority.ts
// (RbacAuthorityMixin), and the role/group/custom-role WRITES + their list views live in
// ./scheduler-do-rbac-mutations.ts (RbacMutationsMixin). All three layer over a base whose `this` is
// SchedulerDOSurface, so the resolution helpers (resolveRole / roleForCaller / resolveAuthority /
// capGroupRole / can-checks) the route guards call keep resolving identically across the files; the
// guards themselves stay with their handlers.

import { type Capability, type CustomRole, capabilitiesOfCustomRole, customRoleReservedCapabilityDrops, isRole, maxRole, OWNER_RESERVED_CAPABILITIES, type PendingRoleEntry, ROLE_CAPABILITIES, ROLE_PENDING_PREFIX, ROLE_RANK, ROLE_SUBJECT_PREFIX, type Role, type RoleEntry, type RoleSource, rolePendingKey, roleSubjectKey } from "../admin/identity.ts";

import { type ClaimBoundary, type ClaimDropTally, claimDropCounter } from "../admin/posture-counters.ts";
import { SESSION_SUBJECT_MAX } from "../admin/session.ts";
import { CUSTOM_ROLE_PREFIX, GROUP_NAME_MAX, GROUP_ROLE_PREFIX, GROUPS_MAX, type GroupRoleEntry, type SchedulerDOCtor } from "./scheduler-do-base.ts";
import { nowMillisISO } from "./scheduler-helpers.ts";

// GROUP_CAP_OWNER_FALLBACK is what a tampered/planted owner group-mapping is clamped DOWN to at
// resolution: approver, the highest cumulative role a group is allowed to express (this preserves the
// historical defence-in-depth behaviour that a planted owner mapping resolves to approver, never owner).
// It was a `private static readonly` on the single SchedulerDO class; as a module const here it holds the
// SAME value and the SAME role, used only by capGroupRole below (a structural move, no behaviour change).
const GROUP_CAP_OWNER_FALLBACK: Role = "approver";

export function RbacMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // ---- RBAC role model (D3) keyed on the STABLE subject (ASVS V10.3.3 / V10.5.2) ---------
    // The role table now keys authorisation on the immutable subject, not the mutable email, so a
    // recycled/reassigned email can never inherit a departed member's role.
    // THAT IS ONE DIRECTION AND THE MIRROR IS NOT CLOSED BY IT, which is worth saying here because the exact
    // sentence above stood in three files. A NEW person at an old address
    // inherits nothing, because their new subject reaches no existing bound row. The reverse is the open one:
    // the OLD SUBJECT CAN CONSUME THE NEW PERSON'S GRANT, because the bind below matches a pending row BY
    // EMAIL (resolveBoundEntry -> pendingStorageKeysFor(email)) and writes it onto whichever subject presented.
    // If a departed member's credential still authenticates, an ordinary invite issued at their re-used address
    // binds to THEM and the new hire is left resolving to viewer with nothing to say why. What closes this on
    // the stored-authority paths is caller.replay, which suppresses bind-on-first-auth and nothing else; a LIVE
    // caller passes nothing and keeps the per-subject default, because bind-on-first-auth is how an invite is
    // ever claimed. So the guard against the mirror is offboarding the credential, not this key choice.
    // Two storage shapes:
    //   - BOUND entries `role:sub:<subject>` (RoleEntry): a member who has authenticated, keyed by their
    //     stable subject (iss+"|"+sub for Access, passkey|<email> for passkey). This is the authority key.
    //   - PENDING entries `role:pending:<email>` (PendingRoleEntry): an Owner/access-admin INVITED an email
    //     before that person ever authenticated. On the invitee's first verified request the DO BINDS it
    //     (creates `role:sub:<subject>` recording the email, deletes the pending row).
    // A LEGACY `role:<email>` entry (from before this re-keying) is read as a PENDING entry so it binds to
    // a subject on next login and is never silently dropped. Resolution, the bootstrap-Owner rule and the
    // last-Owner guard all live here (the DO is the single authority; the router gate is defence in depth).

    // normaliseEmail lowercases and bounds the email so a malformed or oversized value cannot
    // land in a storage key, mirroring validateConfig's discipline for downpipe ids. It returns
    // null for anything that is not a usable key (the caller maps that to a 400). The email is still the
    // pending-invite key and the display identity, so it is still bounded here even though authorisation
    // now keys on the subject.
    normaliseEmail(raw: unknown): string | null {
      if (typeof raw !== "string") return null;
      const e = raw.trim().toLowerCase();
      // A practical bound: non-empty, no whitespace, must look like local@domain, length-capped
      // so it fits comfortably in a DO storage key. This is an authority-boundary sanity check,
      // not full RFC 5322 validation (the IdP already issued the identity).
      if (e.length < 3 || e.length > 320) return null;
      if (/\s/.test(e)) return null;
      if (!/^[^@]+@[^@]+$/.test(e)) return null;
      // Reject any ASCII control character (0x00-0x1F or 0x7F): \s above catches tab/LF/VT/FF/CR but not NUL
      // or the other C0 controls, and an IdP-asserted email is untrusted input that must not carry one into
      // this storage-key fragment, a signed session cookie or an audit-log field (mirrors normaliseSubject's
      // and normaliseGroup's identical discipline below).
      for (let i = 0; i < e.length; i++) {
        const c = e.charCodeAt(i);
        if (c < 0x20 || c === 0x7f) return null;
      }
      return e;
    }

    // normaliseSubject bounds a subject for use as a storage-key fragment (`role:sub:<subject>`): a
    // trimmed, non-empty, length-capped string with no ASCII control characters (mirroring normaliseGroup's
    // discipline). The subject is already shaped by access.ts (iss+"|"+sub) / passkeySubject (passkey|email)
    // at the trust boundary, and the caller header is router-internal, so this is a defensive key-safety
    // bound, not the authenticity check. Returns null for anything unusable (the caller fails closed).
    normaliseSubject(raw: unknown): string | null {
      if (typeof raw !== "string") return null;
      const s = raw.trim();
      // The cap MATCHES the session token's SESSION_SUBJECT_MAX: a native-IdP subject (oidc:<connId>|<issuer>|
      // <sub>) can exceed the old 512 floor, and if the resolution cap were lower than the session cap a long
      // subject would mint a valid session yet resolve to viewer forever (the role:sub:<subject> bind/lookup
      // would silently reject the key). Keeping them equal makes "what the session asserts" and "what the role
      // table keys on" byte-identical for every length the session admits.
      if (s.length < 1 || s.length > SESSION_SUBJECT_MAX) return null;
      for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        if (c < 0x20 || c === 0x7f) return null;
      }
      return s;
    }

    // listRoleEntries reads the whole BOUND role table once (`role:sub:` prefix). The table is small
    // (members, not runs), so an unbounded list is fine and lets the last-Owner guard, resolution and the
    // bootstrap check operate on the full set inside one read-modify-write. A prefix list on "role:sub:"
    // deliberately EXCLUDES the pending and legacy rows (see listPendingEntries). It returns ONLY entries
    // that actually carry a non-empty string subject AND a valid role, so a record that merely happens to
    // live under this prefix without a real subject (the contrived legacy `role:<email>` where the email
    // starts with "sub:") is NOT mistaken for a bound member; listPendingEntries treats such a record as
    // pending instead, keeping the partition exhaustive and disjoint.
    async listRoleEntries(): Promise<RoleEntry[]> {
      const map = await this.state.storage.list<RoleEntry>({ prefix: ROLE_SUBJECT_PREFIX });
      const all = [...map.values()];
      const kept = all.filter((e) => e !== null && typeof e === "object" && typeof e.subject === "string" && e.subject.length > 0 && isRole(e.role));
      // G061: a role row that does not parse is SILENTLY FILTERED OUT of authority resolution, which means that
      // member disappears from the people screen and loses access -- with the engine reporting a perfectly
      // healthy roster. The filter is right (a corrupt row must never confer authority); the silence is not.
      // COUNT only: never the subject, the email or the row.
      if (kept.length < all.length) await this.recordAuthSignalThrottled("rbac-malformed-role-row-dropped");
      return kept;
    }

    // countUnreadableRoleRows is how many stored role records BOTH readers above refuse to parse, counted
    // rather than merely dropped, so a caller can qualify a verdict it would otherwise state unconditionally.
    //
    // WHY THIS EXISTS AS ITS OWN READ. G061 already books the drop as an auth SIGNAL, and a signal is a thing
    // support reads after an incident. The lockout pre-flight is a thing an operator reads BEFORE one, and it
    // was answering byte-identically whether the account's only Owner grant was sound or corrupt: the roster
    // went to `[]`, `whoami` resolved to viewer by default, and the pre-flight still reported the same four
    // factors it reports on a healthy account. A warning surface that cannot distinguish the state it exists
    // to warn about is read as an all-clear, which is worse than having no warning at all.
    //
    // COUNT ONLY: never a subject, an email, a key or a row. It reads the broad `role:` prefix once, the same
    // list listPendingEntries already takes, and applies the same two parse tests the two readers apply, so it
    // cannot disagree with them about what "unreadable" means.
    async countUnreadableRoleRows(): Promise<number> {
      const map = await this.state.storage.list<unknown>({ prefix: "role:" });
      let unreadable = 0;
      for (const [key, raw] of map) {
        if (raw === null || typeof raw !== "object") {
          unreadable++;
          continue;
        }
        const rec = raw as Record<string, unknown>;
        // A bound row must carry a real subject AND a role in the vocabulary. A pending row need not carry a
        // subject, so it is graded on the role alone; an email-less pending row is caught by its own reader.
        if (key.startsWith(ROLE_SUBJECT_PREFIX)) {
          if (!(typeof rec.subject === "string" && rec.subject.length > 0 && isRole(rec.role))) unreadable++;
        } else if (!isRole(rec.role)) {
          unreadable++;
        }
      }
      return unreadable;
    }

    // listPendingEntries reads every UNBOUND grant once: the explicit `role:pending:<email>` rows AND any
    // LEGACY `role:<email>` rows (read as pending so they bind on next login). It lists the broad `role:`
    // prefix and partitions: a key under `role:sub:` is a bound entry (skipped here), a key under
    // `role:pending:` is an explicit pending row, and anything else under `role:` is a legacy email-keyed
    // row migrated to the pending shape (its email taken from the key suffix when the stored value lacks
    // one). The result is the full set of invitations awaiting a subject, used by resolution (to bind), by
    // setRole/deleteRole (to upsert/remove by email), and by countOwners (a pending owner still counts).
    async listPendingEntries(): Promise<PendingRoleEntry[]> {
      const map = await this.state.storage.list<Record<string, unknown>>({ prefix: "role:" });
      const out: PendingRoleEntry[] = [];
      // G061: the pending twin of listRoleEntries' malformed-row filter. A pending row that does not parse is
      // SILENTLY FILTERED OUT, and the person it invited can then never bind: they sign in, resolve to viewer,
      // and the people screen shows the invitation as still outstanding forever. The filter is right (a corrupt
      // row must never confer authority); the silence is not. COUNT only: never the key, the email or the row.
      let dropped = 0;
      for (const [key, raw] of map) {
        if (raw === null || typeof raw !== "object") {
          dropped++;
          continue;
        }
        const rec = raw as Record<string, unknown>;
        if (key.startsWith(ROLE_SUBJECT_PREFIX)) {
          // A `role:sub:` key is a BOUND entry (skip here) ONLY when it carries a real string subject. A
          // record under this prefix WITHOUT a subject is the contrived legacy case (a legacy `role:<email>`
          // whose email happened to start with "sub:"); fall through and treat it as legacy-pending so the
          // partition stays exhaustive (listRoleEntries applies the symmetric filter, so neither side loses it).
          // A bound row is a legitimate skip, NOT a drop, so it is not counted.
          if (typeof rec.subject === "string" && (rec.subject as string).length > 0) continue;
        } else if (key.startsWith(ROLE_PENDING_PREFIX)) {
          // An explicit pending row carries its own email and role.
          const email = typeof rec.email === "string" ? (rec.email as string) : key.slice(ROLE_PENDING_PREFIX.length);
          if (isRole(rec.role)) out.push(this.asPending(email, rec));
          else dropped++;
          continue;
        }
        // A legacy `role:<email>` row (the email is the key suffix). It binds on next login; treat it as
        // pending. Its stored value already has email/role/grantedBy/grantedAt (the pre-rekey RoleEntry
        // shape), so the migration is a faithful read.
        const legacyEmail = key.slice("role:".length);
        if (legacyEmail.length > 0 && isRole(rec.role)) out.push(this.asPending(legacyEmail, rec));
        else dropped++;
      }
      if (dropped > 0) await this.recordAuthSignalThrottled("rbac-malformed-pending-row-dropped");
      return out;
    }

    // asPending coerces a stored pending/legacy record (an untyped object) into a PendingRoleEntry, taking
    // the email from the key when the record omits it (a legacy row may key the email only). It copies only
    // the known, redaction-safe fields; an unknown extra field is dropped.
    asPending(email: string, rec: Record<string, unknown>): PendingRoleEntry {
      // G061: PROVENANCE FABRICATION. A row without a usable grantedBy is read as granted by "unknown", and a
      // row without a usable grantedAt is stamped with the time of THIS READ. Both are substitutions the caller
      // cannot see: the audit answer to "who granted this role, and when?" becomes an engine guess presented as
      // a fact, and the grantedAt guess also drifts forward on every read. Recording it is what keeps the
      // substitution honest. COUNT only: never the row, the email or the substituted value.
      if (typeof rec.grantedBy !== "string" || typeof rec.grantedAt !== "string") {
        void this.recordAuthSignalThrottled("rbac-provenance-fabricated");
      }
      return {
        email,
        role: rec.role as Role,
        grantedBy: typeof rec.grantedBy === "string" ? (rec.grantedBy as string) : "unknown",
        grantedAt: typeof rec.grantedAt === "string" ? (rec.grantedAt as string) : nowMillisISO(),
        ...(typeof rec.expiresAt === "string" ? { expiresAt: rec.expiresAt as string } : {}),
        ...(typeof rec.customRole === "string" ? { customRole: rec.customRole as string } : {}),
      };
    }

    // pendingStorageKeysFor returns every storage key that holds a pending/legacy grant for an email: the
    // canonical `role:pending:<email>` and, defensively, the legacy `role:<email>` (so a bind/delete clears
    // both). The legacy key is `role:<email>`, which must not be confused with `role:sub:`/`role:pending:`;
    // since email contains "@" and never starts with "sub:" or "pending:", the bare key is unambiguous.
    pendingStorageKeysFor(email: string): string[] {
      return [rolePendingKey(email), `role:${email}`];
    }

    // roleTableIsEmpty reports whether there is NO grant of any kind (no bound, no pending, no legacy), the
    // precondition for the first-caller bootstrap. Every grant key (role:sub:, role:pending: and the legacy
    // role:<email>) shares the "role:" prefix, and the sibling grouprole:/customrole: prefixes do not, so a
    // single bounded list of one key answers the yes/no question without reading either full table.
    async roleTableIsEmpty(): Promise<boolean> {
      const any = await this.state.storage.list({ prefix: "role:", limit: 1 });
      return any.size === 0;
    }

    // resolveBoundEntry is the SINGLE place a caller's stable subject is turned into a bound RoleEntry,
    // performing the BIND-ON-FIRST-AUTH migration. Given the caller's subject and verified email:
    //   1. if `role:sub:<subject>` exists, return it (the member is already bound);
    //   2. else, if a pending/legacy grant matches the caller's email, BIND it: write `role:sub:<subject>`
    //      recording the email (display) and the grant's role/customRole/expiry/grantedBy, DELETE the
    //      pending+legacy rows, and return the new bound entry;
    //   3. else, return undefined (no grant -> the caller defaults to viewer at resolution).
    // The bind is a write on resolution, consistent with the lazy-write discipline elsewhere (whoami's
    // bootstrap write, lazy expiry); the DO serialises its own storage so there is no race. It is
    // idempotent: once bound, step 1 returns the entry and nothing is rewritten. A caller with no subject
    // (the token break-glass, or a malformed header) is handled by the callers (they never call this), so
    // subject is required non-null here.
    async resolveBoundEntry(
      subject: string,
      email: string | null,
      // allowEmailBind gates the BIND-ON-FIRST-AUTH (step 2). It DEFAULTS to false for a native-IdP subject
      // (an oidc:/saml: prefix) and true otherwise (passkey|<email> / Access <issuer>|<sub>): a native-IdP
      // email is only trustworthy when the IdP marked it verified, which is checked ONCE at session mint
      // (oidcSessionIssue) where the bind is then FORCED with allowEmailBind=true. A request-time resolution
      // for an oidc/saml caller therefore never auto-binds a pending invite off a possibly-UNVERIFIED
      // IdP-asserted email - the "open-bind" account-takeover the adversarial review flagged. A passkey/Access
      // email is verified at the door, so those keep binding on first request exactly as before (default true).
      allowEmailBind: boolean = !(subject.startsWith("oidc:") || subject.startsWith("saml:")),
      // G3: the STRENGTH of the email verification behind this auth. An OWNER invite is the highest-privilege
      // grant, so it may bind ONLY on a genuinely-verified email (OIDC/OAuth2 email_verified, or a SAML
      // connection with emailVerifiedPolicy "require-flag"). A SAML "trust-idp" connection asserts
      // verified-by-policy with no real flag -- strong enough for lesser roles, NOT to claim owner. Defaults
      // true so every non-native caller (passkey/Access, verified at the door) and every non-owner bind is
      // unchanged; only the native-IdP mint (nativeSessionIssue) passes the computed strength.
      emailVerifiedStrong: boolean = true,
    ): Promise<RoleEntry | undefined> {
      const existing = await this.state.storage.get<RoleEntry>(roleSubjectKey(subject));
      if (existing !== undefined) return existing;
      if (email === null) return undefined;
      if (!allowEmailBind) return undefined;
      // Look the pending/legacy grant up directly by its email-derived key (role:pending:<email>, then the
      // legacy role:<email>) rather than loading and scanning the whole pending table; this turns the
      // bind-on-first-auth from O(N pending) into O(1). asPending coerces the stored row into a typed entry.
      let match: PendingRoleEntry | undefined;
      for (const k of this.pendingStorageKeysFor(email)) {
        const raw = await this.state.storage.get<Record<string, unknown>>(k);
        if (raw !== undefined && raw !== null && isRole(raw.role)) {
          match = this.asPending(email, raw);
          break;
        }
      }
      if (match === undefined) return undefined;
      // G3: refuse to bind a pending OWNER invite off a weakly-verified email (a trust-idp SAML connection). The
      // user still signs in (the caller mints the session regardless); it simply does not INHERIT owner -- the
      // invite stays pending until claimed via a connection that genuinely verifies the email, so a compromised
      // or deliberately-weak second connection cannot bind the highest-privilege role.
      if (match.role === "owner" && !emailVerifiedStrong) {
        // G005: the owner INVITE is refused because this connection does not genuinely verify the address
        // (a trust-idp SAML connection). The user signs in fine and simply does not inherit owner -- so the
        // invite sits in the inbox looking UNCLAIMED forever and nobody can say why. The refusal is correct
        // (a weak connection must not be able to bind the highest privilege); its silence was the bug.
        await this.recordAuthSignal("owner-bind-refused-weak-email-verification");
        return undefined;
      }
      // BIND: the pending invite becomes a subject-keyed entry. The email is recorded for display/audit.
      const bound: RoleEntry = {
        subject,
        email,
        role: match.role,
        grantedBy: match.grantedBy,
        grantedAt: match.grantedAt,
        ...(match.expiresAt !== undefined ? { expiresAt: match.expiresAt } : {}),
        ...(match.customRole !== undefined ? { customRole: match.customRole } : {}),
      };
      await this.state.storage.put(roleSubjectKey(subject), bound);
      for (const k of this.pendingStorageKeysFor(email)) await this.state.storage.delete(k);
      return bound;
    }

    // effectiveRole applies lazy expiry: an entry past its expiresAt resolves to viewer (a
    // time-boxed self-revoke), so an expired just-in-time elevation drops to least privilege
    // without a sweep. The stored entry is left as-is; only the resolved value changes. It accepts a
    // bound RoleEntry OR a pending/legacy PendingRoleEntry (both carry role + expiresAt), so the same
    // lazy-expiry rule applies whether a grant is bound or still pending.
    effectiveRole(entry: RoleEntry | PendingRoleEntry | undefined, now: number): Role {
      if (!entry) return "viewer";
      if (entry.expiresAt) {
        const t = Date.parse(entry.expiresAt);
        // G061: an expiresAt that does not PARSE fails OPEN by convention (malformed data must not itself
        // revoke a grant) -- which means a just-in-time elevation whose timestamp is corrupt NEVER LAPSES. A
        // temporary owner is now a permanent one and nothing anywhere says so. Count the fail-open (a posture
        // signal), and count the demotion too so a lapse is a recorded fact rather than an inference.
        if (!Number.isFinite(t)) {
          void this.recordAuthSignalThrottled("rbac-expiry-unparseable-fail-open");
        } else if (t <= now) {
          void this.recordAuthSignalThrottled("rbac-lazy-expiry-demotion");
          return "viewer";
        }
      }
      return entry.role;
    }

    // isExpired is the SAME lazy-expiry timestamp rule effectiveRole applies to the built-in role axis,
    // extracted so the custom-role overlay (customRoleNamesFor, below) can apply it too: absent expiresAt
    // never expires; an unparseable expiresAt fails OPEN (not expired), matching effectiveRole's own
    // convention so malformed/legacy data cannot itself revoke a grant; otherwise expired means
    // at-or-before `now`. effectiveRole keeps its own inline check (unchanged, still the built-in axis's
    // source of truth); this closes ASVS V8 CR-02, where the custom-role axis had no expiry check at all.
    isExpired(entry: { expiresAt?: string } | undefined, now: number): boolean {
      if (!entry?.expiresAt) return false;
      const t = Date.parse(entry.expiresAt);
      return Number.isFinite(t) && t <= now;
    }

    // countOwners counts members whose EFFECTIVE role is owner across BOTH the bound subject-keyed entries
    // AND the pending/legacy invitations (an invited-but-not-yet-bound owner still counts, so the
    // last-Owner guard cannot be defeated by removing the only bound owner while a pending owner exists, or
    // vice versa). An expired Owner grant does not count (effectiveRole). It counts ONLY explicit role-table
    // entries; a group can never confer owner (the write-time + resolution caps), so the group->role mapping
    // never affects this count and the last-Owner guard stays coherent.
    countOwners(entries: RoleEntry[], pending: PendingRoleEntry[], now: number): number {
      let n = 0;
      for (const e of entries) if (this.effectiveRole(e, now) === "owner") n++;
      for (const p of pending) if (this.effectiveRole(p, now) === "owner") n++;
      return n;
    }

    // ---- Group->role mapping (OPTIONAL, additive) -----------------------------------------
    // THE GROUP CAP (contract section 1): an identity-provider group may confer ANY role EXCEPT owner
    // (so a group can map to viewer/operator/restore-operator/approver/access-admin, but never owner).
    // owner stays an explicit, named, per-email grant (the break-glass owner is a specific person, not
    // a group). This is enforced at write time (setGroupRole rejects owner) AND re-applied at resolution
    // (capGroupRole) so even a mapping that somehow held owner could never resolve a caller to owner.
    // capGroupRole applies the resolution-time cap: a group may confer any role except owner, so only an
    // owner value is clamped (down to GROUP_CAP_OWNER_FALLBACK = approver); every other role passes
    // through unchanged. This is no longer a rank ceiling (the two narrow roles are not on the cumulative
    // ladder, so a rank clamp would wrongly demote a legitimately-mapped access-admin or restore-operator
    // group); it is precisely "reject owner". Defence in depth alongside the write-time rejection.
    capGroupRole(role: Role): Role {
      // G061: this clamp is a TAMPER DETECTOR. A group mapping is not allowed to confer owner (rejected at
      // write time), so a stored mapping that CLAIMS owner means the write-time guard was bypassed or the
      // record was altered underneath us. It is clamped -- and it fired completely silently. Count only (never
      // the group name or the mapping); the clamp itself is unchanged.
      if (role === "owner") {
        void this.recordAuthSignalThrottled("rbac-owner-clamp-fired");
        return GROUP_CAP_OWNER_FALLBACK;
      }
      return role;
    }

    // normaliseGroup bounds a group name for use as a storage key (grouprole:<group>), mirroring
    // normaliseEmail's authority-boundary discipline: a trimmed, non-empty, length-capped string with
    // no control characters. The group name is the customer's own IdP data; this only ensures it is a
    // safe, bounded key. Returns null for anything unusable (the caller maps that to a 400). Group
    // names are matched CASE-SENSITIVELY (an IdP group name is an opaque directory identifier, unlike
    // an email which we treat case-insensitively), so it is trimmed but NOT lowercased.
    normaliseGroup(raw: unknown): string | null {
      if (typeof raw !== "string") return null;
      const g = raw.trim();
      if (g.length < 1 || g.length > GROUP_NAME_MAX) return null;
      // Reject any ASCII control character (0x00-0x1F or 0x7F) so the value is a safe, single-line
      // storage-key fragment. A group name may legitimately contain spaces and unicode, so only the
      // control range is excluded, not punctuation.
      for (let i = 0; i < g.length; i++) {
        const c = g.charCodeAt(i);
        if (c < 0x20 || c === 0x7f) return null;
      }
      return g;
    }

    // boundGroupList is the DO's OWN bounding of a groups list, applied to EVERY groups list the DO
    // ingests regardless of where it came from (the groups query param, or the forwarded caller
    // header decoded by decodeCaller). It keeps only string entries, normalises each through
    // normaliseGroup (trim, drop empty, drop over GROUP_NAME_MAX, drop any ASCII control-char name),
    // dedupes (first occurrence wins, order preserved), and caps the result to GROUPS_MAX. This is the
    // invariant "the DO bounds its own inputs": the DO does not rely on access.ts boundGroups (a
    // different module) having already bounded the list, so a forged/oversized header or a pathological
    // signed token cannot hand the single-threaded DO an unbounded list to loop over or persist. For a
    // normal small list the output is identical to the input order (the live behaviour is unchanged).
    boundGroupList(raw: unknown[], drops?: ClaimDropTally, boundary?: ClaimBoundary): string[] {
      // G061: a groups list longer than GROUPS_MAX is TRUNCATED here, so a role-bearing group past the cap is
      // silently invisible and its holders drop to viewer ("users mapped via AD groups all lost their roles").
      // The existing group-name-dropped signal fires only at NATIVE-IdP sign-in; this is the DO's own bound,
      // which every caller path passes through. Count only: never a group name.
      if (Array.isArray(raw) && raw.length > GROUPS_MAX) void this.recordAuthSignalThrottled("rbac-group-list-truncated");
      const seen = new Set<string>();
      const out: string[] = [];
      // R6: THE CAP IS TESTED AFTER NORMALISE AND DEDUPE, as the OIDC bounder already does (oidc.ts boundGroups).
      // Tested BEFORE them, a list of 200 distinct groups followed by DUPLICATES of those same 200 filed
      // claim-drop-<boundary>-groups-list-capped on a sign-in where nothing was lost: a fault row on a path that
      // is working. A duplicate is not a drop. Work stays bounded (the single-threaded DO must not be handed an
      // unbounded list to loop over, G061): the scan stops at SCAN_MAX entries, and a list longer than that HAS
      // lost the entries past it, so the cap drop is filed on that fact alone.
      const SCAN_MAX = GROUPS_MAX * 4;
      const scanned = Math.min(raw.length, SCAN_MAX);
      if (raw.length > SCAN_MAX && drops !== undefined && boundary !== undefined) drops.add(claimDropCounter(boundary, "groups-list-capped"));
      for (let i = 0; i < scanned; i++) {
        // G271 (R5): when the caller passes a tally, record WHICH bound threw a group away and at WHICH parse
        // boundary. This is the site where a SAML assertion's groups are first bounded (they ride verbatim out of
        // the assertion), so it is the only place the SAML front door's "the mapped group fell past the cap"
        // ticket can be named. The KIND is derived from the same rules normaliseGroup applies; the group NAME is
        // never read out of this function. An unclassified drop (a non-string entry, an empty name) is not a drop
        // of a group the IdP meaningfully asserted, so it tallies nothing.
        const entry = raw[i];
        const g = this.normaliseGroup(entry); // null for non-string / empty / over-long / control-char
        if (g === null) {
          if (drops !== undefined && boundary !== undefined && typeof entry === "string") {
            const t = entry.trim();
            if (t.length > GROUP_NAME_MAX) drops.add(claimDropCounter(boundary, "group-overlength"));
            else if (t.length > 0) drops.add(claimDropCounter(boundary, "group-control-char"));
          }
          continue;
        }
        if (seen.has(g)) continue; // a duplicate is not a drop
        if (out.length >= GROUPS_MAX) {
          // A DISTINCT group the IdP asserted, past the cap: this is the "the user is in the right AD group and
          // gets viewer" state, and the ONE name that says the cap is what threw it away.
          if (drops !== undefined && boundary !== undefined) drops.add(claimDropCounter(boundary, "groups-list-capped"));
          continue;
        }
        seen.add(g);
        out.push(g);
      }
      return out;
    }

    // listGroupRoleEntries reads the whole group->role mapping once. Like the role table it is small
    // (mapped groups, not runs), so an unbounded list is fine and lets resolution fold over the full
    // set in one read.
    async listGroupRoleEntries(): Promise<GroupRoleEntry[]> {
      const map = await this.state.storage.list<GroupRoleEntry>({ prefix: GROUP_ROLE_PREFIX });
      return [...map.values()];
    }

    // groupRoleFor computes the role the caller's groups confer (each clamped by capGroupRole: any role
    // except owner), folding multiple matching groups via maxRole (the rank-ordered combine), or null
    // when no group matches (so resolution can tell "no group conferred anything" from "viewer"). It
    // matches the caller's verified groups against the stored mapping case-sensitively. An empty groups
    // list (Access sent none, or the token path) trivially matches nothing -> null, which is what keeps
    // the per-email behaviour unchanged when there are no groups. NOTE: maxRole folds by ROLE_RANK, which
    // is a total order; for the two narrow roles (not on the cumulative ladder) the fold is still
    // deterministic but coarse (it picks the higher-ranked of two narrow group mappings), which is
    // acceptable because the narrow roles are normally conferred singly and never confer owner.
    groupRoleFor(groups: string[], mapping: GroupRoleEntry[]): Role | null {
      if (groups.length === 0 || mapping.length === 0) return null;
      const want = new Set(groups);
      let best: Role | null = null;
      for (const m of mapping) {
        if (!want.has(m.group)) continue;
        const capped = this.capGroupRole(m.role);
        best = best === null ? capped : maxRole(best, capped);
      }
      return best;
    }

    // resolveRole is the single BUILT-IN role-resolution function: given the caller's email and verified
    // groups, it returns the EFFECTIVE built-in role and its honest SOURCE. The role is
    //   max( explicit email-table role (or viewer), highest group-mapped role (any role except owner), viewer ).
    // Time-boxed expiry on the email table is applied via effectiveRole (an expired email grant reads as
    // viewer, so a group mapping can still lift the caller). The source reflects whichever input
    // conferred the winning role; an explicit email grant WINS ties (it is the more specific, named
    // authority), and "group" is reported only when a group strictly out-ranks the email grant by
    // ROLE_RANK. The combine is by ROLE_RANK (unchanged for the four cumulative roles); the two narrow
    // roles are handled (never crash, deterministic) but a cross-family combine is coarse by design. A
    // caller with neither grant resolves to viewer / "default". This is the BUILT-IN axis only; custom
    // roles are folded ON TOP by resolveAuthority below, which calls this for the built-in floor and then
    // unions in any referenced custom-role capability set.
    resolveRole(
      emailEntry: RoleEntry | undefined,
      groups: string[],
      roleMapping: GroupRoleEntry[],
      now: number,
    ): { role: Role; source: RoleSource } {
      const emailRole = this.effectiveRole(emailEntry, now); // viewer when absent/expired
      const groupRole = this.groupRoleFor(groups, roleMapping); // any role except owner, or null
      // The email grant counts as an explicit source only when it actually lifts the caller above the
      // viewer default (an absent/expired entry resolves to viewer, which is the default, not a grant).
      const emailIsGrant = emailEntry !== undefined && ROLE_RANK[emailRole] > ROLE_RANK.viewer;
      if (groupRole !== null && ROLE_RANK[groupRole] > ROLE_RANK[emailRole]) {
        // A group strictly out-ranks the email grant (or the email is just the viewer default): the
        // group is the basis of the winning role.
        return { role: groupRole, source: "group" };
      }
      if (emailIsGrant) return { role: emailRole, source: "email" };
      // Neither lifted the caller above viewer: least privilege, default basis. (If a group mapped the
      // caller to viewer exactly, that is still the default resting role, so "default" is honest.)
      return { role: "viewer", source: "default" };
    }

    // customRoleNamesFor collects the custom-role NAMES a caller's grants reference: the email grant's
    // customRole (if any AND not expired -- ASVS V8 CR-02: an expired email grant contributes NO
    // custom-role name, exactly like effectiveRole demotes an expired built-in grant to viewer) plus the
    // customRole of every group mapping the caller's verified groups match (GroupRoleEntry carries no
    // expiresAt, so a group-sourced reference is never time-boxed and needs no check). It is the additive
    // overlay on top of the built-in role axis: a name here is folded into the caller's capability set by
    // resolveAuthority. Order is email-first then group order, deduped (a name referenced by both an email
    // grant and a group is folded once). An empty result means the caller is on a pure built-in role (the
    // unchanged path).
    customRoleNamesFor(emailEntry: RoleEntry | undefined, groups: string[], mapping: GroupRoleEntry[], now: number): string[] {
      const names: string[] = [];
      const seen = new Set<string>();
      const add = (n: string | undefined) => {
        if (typeof n === "string" && n.length > 0 && !seen.has(n)) {
          seen.add(n);
          names.push(n);
        }
      };
      // Gate purely on the timestamp (NOT on effectiveRole !== "viewer": setRole pins a custom-role
      // grant's stored `role` to the viewer floor UNCONDITIONALLY, expired or not, so that predicate would
      // always read "viewer" and would disable this overlay entirely -- see isExpired above).
      if (emailEntry !== undefined && !this.isExpired(emailEntry, now)) add(emailEntry.customRole);
      if (groups.length > 0 && mapping.length > 0) {
        const want = new Set(groups);
        for (const m of mapping) if (want.has(m.group)) add(m.customRole);
      }
      return names;
    }

    // resolveAuthority is the SINGLE effective-authority resolution: it returns the built-in role + source
    // (from resolveRole) AND, when any grant references a custom role, the UNION of the built-in role's
    // capability set with each referenced custom role's set, plus the winning custom-role record for the
    // console. A custom role is folded EXACTLY like a built-in (its set is just has()-checked), so a
    // caller granted a custom role is gated by exactly the capabilities the role bundles. When a custom
    // role strictly ADDS authority beyond the built-in floor, source becomes "custom" and capabilities is
    // returned (callerCan reads it). A grant whose customRole names a role that no longer exists is
    // ignored (the holder drops to the built-in floor, never fails open); an EXPIRED email grant's
    // customRole reference is likewise excluded (customRoleNamesFor's own expiry gate, ASVS V8 CR-02), so
    // a time-boxed custom-role grant demotes to the built-in floor exactly like the built-in axis, not
    // just in appearance. Owner-reserved capabilities can
    // never appear (capabilitiesOfCustomRole re-bars them at read time), so a custom role can never reach
    // owner authority. When no custom role applies, the result is exactly the prior built-in resolution
    // (capabilities/customRole absent), so the built-in path is byte-for-byte unchanged.
    resolveAuthority(
      emailEntry: RoleEntry | undefined,
      groups: string[],
      roleMapping: GroupRoleEntry[],
      customRoles: Map<string, CustomRole>,
      now: number,
    ): { role: Role; source: RoleSource; capabilities?: ReadonlySet<Capability>; customRole?: CustomRole } {
      const builtin = this.resolveRole(emailEntry, groups, roleMapping, now);
      const names = this.customRoleNamesFor(emailEntry, groups, roleMapping, now);
      if (names.length === 0) return builtin; // pure built-in: unchanged
      // Fold the built-in floor's capabilities with every referenced custom role's set. The built-in
      // floor is included so a custom role is purely additive (it never REMOVES a capability the built-in
      // grant already conferred), matching the "custom roles are additive" contract.
      const union = new Set<Capability>(ROLE_CAPABILITIES[builtin.role]);
      let winning: CustomRole | undefined;
      let added = false;
      for (const name of names) {
        const rec = customRoles.get(name);
        if (rec === undefined) {
          // G061: a missing-custom-role SIGNAL. The custom role this grant names
          // no longer exists, so the holder SILENTLY drops to their built-in floor (usually viewer) with no
          // error, no audit event and nothing on their people row saying why. The drop is correct (never fail
          // open); its invisibility is the bug. Throttled (this is the per-request authority resolution) and a
          // COUNT only -- never the role name, the subject or the email.
          void this.recordAuthSignalThrottled("rbac-dangling-custom-role-ref");
          continue; // a deleted custom role drops to the built-in floor
        }
        // G312: the clamp inside capabilitiesOfCustomRole drops an owner-reserved capability a stored custom
        // role should be structurally incapable of holding (the write path refuses one). A drop here therefore
        // means the RECORD WAS TAMPERED WITH, and the clamp -- correctly -- makes that invisible. Count it.
        // Throttled: this is the per-request authority resolution. A count only, never the capability or role.
        const reservedDrops = customRoleReservedCapabilityDrops(rec);
        if (reservedDrops > 0) void this.recordAdminCountersThrottled(["stored-custom-role-reserved-capability-dropped"]);
        const caps = capabilitiesOfCustomRole(rec);
        // G312: THE TAMPER SIGNAL NOBODY WAS TOLD ABOUT. validateCustomRole bars an owner-reserved capability
        // at CREATE, and capabilitiesOfCustomRole re-bars it at every READ (defence in depth), so a stored
        // custom role that holds one cannot have got there through the product: the record was edited under
        // the engine. The clamp is correct and stays exactly as it is; what was missing is that it fired at
        // all. Recorded THROTTLED (this is the per-request authority resolution) and as a COUNT only: never
        // the role name, the capability, the subject or the email.
        if (rec.capabilities.some((c) => OWNER_RESERVED_CAPABILITIES.has(c as Capability))) {
          void this.bumpAdminCounterLocalThrottled("stored-custom-role-reserved-capability-dropped");
        }
        for (const c of caps) {
          if (!union.has(c)) {
            union.add(c);
            added = true;
          }
        }
        // The FIRST existing referenced role is the winning record surfaced to the console (email-first,
        // then group order); a second custom role still unions its caps in, but the console shows one
        // primary skin/landing.
        if (winning === undefined) winning = rec;
      }
      // If no referenced custom role exists any more (all deleted), or none added authority beyond the
      // built-in floor, the caller is effectively on the built-in role: report the built-in resolution.
      if (winning === undefined) return builtin;
      return { role: builtin.role, source: added ? "custom" : builtin.source, capabilities: union, customRole: winning };
    }

    // listCustomRoleRecords reads the whole custom-role catalogue once into a name->record map. Like the
    // role and group tables it is small (defined roles, not runs), so an unbounded list is fine and lets
    // resolution fold over the full set in one read. The map key is the canonical role name (the storage
    // key fragment after the prefix), so a referenced name looks up directly.
    async listCustomRoleRecords(): Promise<Map<string, CustomRole>> {
      const map = await this.state.storage.list<CustomRole>({ prefix: CUSTOM_ROLE_PREFIX });
      const out = new Map<string, CustomRole>();
      for (const rec of map.values()) out.set(rec.name, rec);
      return out;
    }
  };
}
