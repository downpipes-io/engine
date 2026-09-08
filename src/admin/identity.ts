// Identity and role types for the engine governance backbone. The
// single load-bearing fact this builds on: authorise() (auth.ts) already verifies the
// Cloudflare Access JWT and then throws the identity away when a caller collapses to a boolean. These
// types thread that already-computed identity through to the router and the scheduler DO, so
// the role becomes a real server-side control rather than a cosmetic client gate.
//
// Node 25 strip-types compatible: no enums, no parameter properties, explicit field
// declarations only. Mirrored read-only in the console (api.ts) so the two sides cannot drift.

import { type ChangeRef, parseChangeRef } from "./change-ref.ts";
import type { Capability, CustomRole } from "./identity-rbac.ts";
import { can } from "./identity-rbac.ts";
// The engine governance backbone is split across sibling modules so each stays a coherent unit under 500
// lines. The core identity + role PRIMITIVES (AuthMethod / isCookieBorneMethod / Role / ROLE_RANK / isRole /
// roleAtLeast / maxRole / canonicalEmail) live in identity-roles.ts; the capability + custom-role layer
// (Capability / ROLE_CAPABILITIES / can / the custom-role machinery) lives in identity-rbac.ts. This module
// keeps the request-scoped Caller, the whoami/verdict shapes, the stable-subject derivations, the role-table
// keys and the caller-header transport, and RE-EXPORTS the moved surface so every importer of identity.ts
// (the router, the scheduler DO, auth.ts, the SAML/OIDC adapters, the validators) keeps working unchanged.
import type { AuthMethod, Role } from "./identity-roles.ts";
import { isRole } from "./identity-roles.ts";

export type { Capability, CustomRole, CustomRoleProposal, Presentation, SurfaceMode } from "./identity-rbac.ts";
export {
  ALL_CAPABILITIES,
  CUSTOM_ROLE_NAME_PATTERN,
  can,
  capabilitiesOfCustomRole,
  customRoleReservedCapabilityDrops,
  isCapability,
  isScreen,
  OWNER_RESERVED_CAPABILITIES,
  ROLE_CAPABILITIES,
  SCREEN_WRITE_CAPABILITY,
  validateCustomRole,
} from "./identity-rbac.ts";
export type { AuthMethod, Role } from "./identity-roles.ts";
export { canonicalEmail, isCookieBorneMethod, isRole, maxRole, ROLE_RANK, roleAtLeast } from "./identity-roles.ts";

// callerCan is the SINGLE authorisation primitive the router and DO use now that a caller may be on a
// custom role: if the caller carries an explicit resolved capability set (a custom-role caller), the
// check is that set's has(); otherwise it falls back to can(caller.role, cap) over the built-in table.
// Built-in callers carry NO capabilities field, so their authorisation is byte-for-byte unchanged (the
// fallback runs). This is the one place the two authority sources (built-in role vs custom-role set)
// converge, so a route's gate cannot read one and a re-check read the other.
export function callerCan(caller: Pick<Caller, "role" | "capabilities">, capability: Capability): boolean {
  if (caller.capabilities !== undefined) return caller.capabilities.has(capability);
  return can(caller.role, capability);
}

// The verdict authorise() returns instead of a bare boolean. The Access path threads the
// email, the STABLE subject (iss+"|"+sub) the role table now keys on, and the JWT exp the verifier
// already computed, plus the OPTIONAL identity-provider groups and idp hint the SIGNED Access payload
// carried (absent when Access sent none, which is what keeps group-mapping additive). The passkey path
// carries a subject too (passkeySubject(email), the engine's own credential principal). A present-but-
// invalid Access assertion still returns { ok: false } and is NEVER downgraded to the token path
// (auth.ts preserves that exactly), and a subjectless Access assertion is rejected the same way an
// emailless one is. The token path carries no email, no subject, no session expiry, and no groups (the
// bare-token break-glass is not attributable to a stable identity, so it stays the owner break-glass).
export type AuthVerdict =
  | { ok: true; method: AuthMethod; email: string | null; subject?: string; exp?: number; groups?: string[]; identityProvider?: string; connId?: string }
  // throttled marks the ONE deny that is not a statement about the credential: the bare-token
  // anti-brute-force limiter, which fires BEFORE tokenEqual and so refuses a correct and an incorrect token
  // identically. Everything else stays a bare { ok: false } so no deny class is oracled back to an attacker.
  | { ok: false; throttled?: true };

// The verified caller, resolved ONCE per request in handleAdmin after a positive verdict: the
// auth method, the verified email (null for the token fallback), the OPTIONAL identity-provider
// groups carried on a verified Access JWT (always an array; [] when Access sent none or on the
// token path), and the role the DO resolved from its own tables given the email AND the groups.
// The token-fallback caller resolves to "owner" (the documented break-glass is all-or-nothing
// because it cannot be attributed) and carries no groups. identityProvider is set only when the
// verified Access token actually carried an idp hint; it is honestly absent otherwise.
export interface Caller {
  method: AuthMethod;
  email: string | null;
  // subject is the STABLE, immutable principal authorisation keys on (ASVS V10.3.3 / V10.5.2): an
  // Access caller's iss+"|"+sub, a passkey caller's passkeySubject(email), or a native-IdP caller's
  // oidcSubject(connId,iss,sub) / samlSubject(connId,entityId,nameId). It is null ONLY for the bare-token
  // break-glass (which is the all-or-nothing owner, resolved without the role table). email is retained for
  // DISPLAY and AUDIT only; the role lookup, the dual-control maker != checker comparison, and the
  // last-Owner count all key on subject, so a recycled/reassigned email can never inherit a departed
  // member's role. A null-subject caller has no stable identity and cannot be a dual-control maker or
  // checker (the token break-glass refusal, unchanged).
  subject: string | null;
  role: Role;
  groups: string[];
  identityProvider?: string;
  // connId is the id of the IdP connection (idpconn:<connId>) a native oidc/saml session was minted
  // through; present only for those methods. It is the axis the per-connection session epoch
  // (idpEpoch:<connId>) keys on (disabling/deleting a connection kills its live sessions) and the honest
  // provider the console shows. Absent for access/passkey/token.
  connId?: string;
  // customRole / capabilities are present ONLY for a caller whose effective authority is a NAMED custom
  // role (an explicit per-email grant or an IdP-group mapping referenced a custom-role name). When they
  // are present, role is pinned to the least-privilege "viewer" FLOOR (so any non-capability read of
  // caller.role stays safe and the owner-escalation guard correctly treats a custom-role caller as a
  // non-owner) and capabilities carries the role's resolved set, which callerCan() reads. For the six
  // built-in roles both are absent and authorisation falls back to can(caller.role, cap) unchanged.
  customRole?: string;
  capabilities?: ReadonlySet<Capability>;
  // sourceIp is the COARSE provenance the audit trail records: where the request came from, read by the
  // router from the edge-injected CF-Connecting-IP header (resolveCaller's caller sets it). It is never a
  // secret and never an authority input (no gate reads it); null when absent (e.g. a local validator
  // request). It is carried on the caller so a forwarded mutating call lets the DO attribute the SAME IP
  // at the commit point that the router would attribute at a denial, closing the "denials have an IP but
  // the matching success does not" gap. SECURITY: the value is the edge header the router reads, never a
  // client-supplied caller-header field (decodeCaller re-reads it from the router-internal header only,
  // and the router overwrites any inbound x-downpipe-caller; see CALLER_HEADER).
  sourceIp?: string | null;
  // change is the OPTIONAL change reference (change-ref.ts) the operator attached to a change-controlled
  // action when the OWNER-OPT-IN requireChangeNumber policy is on: a CR number, or an Emergency Change with
  // a justification. Like sourceIp it is REQUEST-SCOPED, NON-AUTHORITY metadata (no gate reads it, the role
  // is never derived from it); UNLIKE sourceIp it is CLIENT-supplied (the console's X-Downpipes-Change
  // header) rather than edge-injected, the same operator-attested redaction class as the restore reason. The
  // router parses it onto the caller once and encodeCaller carries it to the DO, so the change-control
  // chokepoint (which runs in the DO) can validate it and record the change-recorded audit event. Absent =>
  // no reference was supplied (the policy then refuses the action if one was required for it).
  change?: ChangeRef | null;
}

// SCIM_OFFBOARD_EMAIL / SCIM_OFFBOARD_SUBJECT identify the ONE internal, router-only synthetic Caller the
// SCIM deprovisioning facade (admin/scim.ts) builds for its automated /roles/delete calls. Defined HERE
// (not in scim.ts) because BOTH layers need the same literal: scim.ts stamps it onto the caller header it
// builds, and the scheduler DO's route dispatch (isScimOffboardCaller below, consumed by
// scheduler-do-routing.ts) recognises it to send an automated, IdP-driven revocation straight to the
// validated apply path instead of the human dual-control approval queue.
//
// ASVS V7.4.1/V7.4.2: queuing was tried first (give this caller an attributable email/subject so
// proposeConfigMutation would queue it like a human change) and created a WORSE, previously-impossible
// stuck state: the queue's approve-time replay re-resolves the PROPOSER's authority from their subject
// against the LIVE role table, and no login flow can ever bind "scim-offboard-internal" to a real grant, so
// a queued SCIM removal could be proposed but never approved (a permanently pending change, a misleading
// 409 promising completion that could never arrive, and a cryptic 403 for a fully-privileged approver). The
// gate is the wrong shape for this action regardless: the customer's IdP, not a human downpipes operator,
// already decided this person is gone, and this is a REVOCATION (the SCIM facade has no role-set/
// provisioning path at all -- see scim.ts's own scope comment -- so bypassing the queue here can only ever
// narrow access, never grant it). Making that revocation wait on a human "Approve" click would hold the
// departed member's access open in the meantime, the exact standing-access exposure a prompt deprovision
// exists to close. So this caller now bypasses the queue entirely (see isScimOffboardCaller).
//
// email/subject grant no authority themselves: roleForCaller's method==="token" branch
// (scheduler-do-rbac-authority.ts) resolves this caller to owner from `method` ALONE, before ever
// consulting them; they exist purely so the audit trail names the actor as the automated SCIM connector
// rather than a blank.
export const SCIM_OFFBOARD_EMAIL = "scim-offboard@internal.downpipes";
export const SCIM_OFFBOARD_SUBJECT = "scim-offboard-internal";

// isScimOffboardCaller recognises exactly that one caller: an EXACT match on all three of method/email/
// subject. A near-miss matches neither this predicate nor gets any different treatment than before --
// e.g. the same email/subject under a real access/passkey method (which cannot happen: no login flow
// mints this subject), or the bare ADMIN_TOKEN break-glass (also method:"token", but email/subject are
// always null for it) -- so it falls through to the unchanged, fully-gated human path. This is used ONLY
// to decide whether a role-delete should bypass the human approval queue; it is not an authority check
// (roleForCaller resolves this caller's authority independently, as above), so a true result only changes
// WHETHER the action queues, never WHAT the caller may do. Safe against a forged request: the caller
// header this reads is router-internal (see CALLER_HEADER) and only admin/scim.ts ever mints this exact
// identity, built from the verified SCIM bearer, never from client input.
export function isScimOffboardCaller(caller: { method: AuthMethod; email: string | null; subject: string | null } | null): boolean {
  return caller !== null && caller.method === "token" && caller.email === SCIM_OFFBOARD_EMAIL && caller.subject === SCIM_OFFBOARD_SUBJECT;
}

// RoleSource is the honest BASIS of the resolved role, surfaced to the customer's own console so it
// can explain WHY a caller holds a role without faking it: "owner-token" is the bare-token
// break-glass (all-or-nothing owner); "email" is an explicit per-email grant in the role table;
// "group" is a role conferred only by an identity-provider group mapping (no explicit email grant
// reached it); "default" is the least-privilege resting state (viewer, no grant of either kind).
// When both an email grant and a group mapping apply, the source reflects whichever conferred the
// EFFECTIVE (winning) role; "email" wins ties, since an explicit per-email grant is the more
// specific, named authority.
export type RoleSource = "owner-token" | "email" | "group" | "custom" | "default";

// WhoAmI is the GET /admin/whoami response (D1): the identity the engine already verified, so
// the console can show the real session chip, the honest Access verdict, the active role and
// the session expiry instead of faking any of them. sessionExpiresAt is the Access JWT exp
// (epoch seconds), present only for the access method. isOnlyOwner lets the console pre-empt
// the last-Owner block without a second round trip. roleSource is the honest BASIS of the role
// (owner-token / email / group / default) so the console can explain it; groups is the verified
// identity-provider group list that applied (the customer's own data, fine to return to their own
// console; [] when none). identityProvider is present only when the verified token carried it.
export interface WhoAmI {
  method: AuthMethod;
  email: string | null;
  // subject is the STABLE identity key (iss+"|"+sub for Access, passkeySubject(email) for passkey), so
  // the console mirrors engine logic on the SAME key the engine authorises on. It is honestly absent for
  // the bare-token break-glass (no stable identity). The console displays `email` as the human-legible
  // label and uses `subject` only as the internal key where it mirrors the engine, never as the primary
  // label (it is an opaque id). It is redaction-safe (an opaque identifier, never a secret or value).
  subject?: string;
  role: Role;
  roleSource: RoleSource;
  groups: string[];
  identityProvider?: string;
  // connId is the IdP-connection id for a native oidc/saml session (the console renders the provider label
  // and the "signed in via <connection>" chip from it); absent for access/passkey/token.
  connId?: string;
  sessionExpiresAt?: number;
  isOnlyOwner: boolean;
  // customRole is present only when the caller's effective authority is a NAMED custom role (roleSource
  // "custom"): it carries the resolved record (name/label/capabilities/surface/presentation/landing) so
  // the console can pick the skin, open the landing screen and gate affordances by the same capability
  // set the engine enforces. role is the "viewer" floor in this case (the capability set is the real
  // authority). Absent for the six built-in roles. capabilities is the resolved set as a plain array (a
  // ReadonlySet does not serialise to JSON), so the console can mirror the gates exactly.
  customRole?: CustomRole;
  capabilities?: Capability[];
  // csrfToken is the double-submit CSRF token for a COOKIE-BORNE session (passkey/oidc/saml); absent for the
  // header-authenticated token/access methods (they are not ambient-credential CSRF vectors). The console
  // echoes it in the x-downpipes-csrf header on the session-termination routes, where the engine validates
  // it server-side against the readable __Host-downpipes_csrf cookie (defence in depth on top of the
  // strict-Origin guard). It is issued/refreshed here, on whoami, and set as the readable cookie in the same
  // response. Not a session secret (see session.ts CSRF_COOKIE_NAME); redaction-safe to return to the
  // caller's own console.
  csrfToken?: string;
}

// passkeySubject derives the STABLE principal for a passkey caller from its bound, verified email:
// "passkey|<canonical-email>". A passkey caller carries no Cloudflare Access `sub`, so the engine's own
// credential identity is its subject. It is a DISTINCT namespace from an Access subject (which is the
// team issuer URL "|" the Access uuid), so a passkey subject and an Access subject can never collide.
// The email passed in is already canonical (lowercased/trimmed) at the trust boundary. This is the one
// place the passkey subject is shaped, so auth.ts (the verdict) and the DO passkey bootstrap agree.
export function passkeySubject(email: string): string {
  return `passkey|${email}`;
}

// CONN_ID_PATTERN bounds an IdP-connection id. It is folded into a native subject and used as a DO
// storage-key fragment (idpconn:<id>, idpEpoch:<id>), so it must be a safe single token that can NEVER
// contain the ":" or "|" subject separators (else a crafted connId could forge a colliding subject). 1 to
// 64 chars of lowercase letters, digits and hyphen, not leading/trailing hyphen.
export const CONN_ID_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
export function isConnId(v: unknown): v is string {
  return typeof v === "string" && CONN_ID_PATTERN.test(v);
}

// oidcSubject derives the STABLE principal for a NATIVE OIDC/OAuth2 caller: "oidc:<connId>|<issuer>|<sub>".
// Like passkeySubject it is a DISTINCT, collision-proof namespace: the "oidc:" prefix and the UNCONDITIONAL
// connId fold mean it can never equal an Access subject (the bare "<issuer>|<sub>"), a passkey subject
// ("passkey|<email>"), or another connection's subject, even if two connections share an IdP issuer. connId
// is pattern-bounded (isConnId) so it cannot contain the ":"/"|" separators. issuer is the verified, exact
// token issuer; sub is the IdP's immutable subject claim (for an OAuth2 provider with no id_token the
// adapter passes the provider's immutable id, e.g. "github:<apiBase>:<numericId>"). This is the ONE place
// the OIDC subject is shaped, so the verdict, the DO bootstrap and the role table agree.
export function oidcSubject(connId: string, issuer: string, sub: string): string {
  return `oidc:${connId}|${issuer}|${sub}`;
}

// samlSubject derives the STABLE principal for a NATIVE SAML caller: "saml:<connId>|<idpEntityId>|<NameID>".
// Same disjoint-namespace discipline as oidcSubject: the "saml:" prefix plus the unconditional, pattern-
// bounded connId fold keep it collision-proof against Access/passkey/oidc subjects and across connections.
// The NameID must be a PERSISTENT (or pinned stable-attribute) value, never transient (the SAML adapter
// rejects transient NameIDs), so the subject is stable across logins. This is the ONE place the SAML
// subject is shaped.
export function samlSubject(connId: string, idpEntityId: string, nameId: string): string {
  return `saml:${connId}|${idpEntityId}|${nameId}`;
}

// ROLE_SUBJECT_PREFIX keys a BOUND role entry by the caller's stable subject: `role:sub:<subject>`. This
// is the authorisation key (ASVS V10.3.3 / V10.5.2): the role table is keyed on the immutable subject,
// not the mutable email, so a recycled/reassigned email can never inherit a departed member's role.
export const ROLE_SUBJECT_PREFIX = "role:sub:";

// ROLE_PENDING_PREFIX keys an INVITED-but-not-yet-bound grant by the lowercased email:
// `role:pending:<email>`. An Owner/access-admin invites by EMAIL (they do not know the subject), so the
// grant waits here until the invitee first authenticates, at which point the DO BINDS it to their subject
// (creates `role:sub:<subject>` recording the email, deletes the pending entry). A legacy `role:<email>`
// entry (from before this re-keying) is treated as a pending entry on read, so existing grants bind on
// next login and are never silently dropped.
export const ROLE_PENDING_PREFIX = "role:pending:";

// roleSubjectKey / rolePendingKey build the two storage keys, kept here so the DO and any reader agree
// on the exact strings (mirroring approvalKey / AUDIT_PREFIX).
export function roleSubjectKey(subject: string): string {
  return ROLE_SUBJECT_PREFIX + subject;
}
export function rolePendingKey(email: string): string {
  return ROLE_PENDING_PREFIX + email;
}

// RoleEntry is one row of the BOUND in-account role table held in the scheduler DO, keyed by the caller's
// stable subject (the storage key is `role:sub:${subject}`). subject is the immutable principal authority
// keys on; email is retained for DISPLAY and AUDIT only (the console shows it, the audit records it), never
// for authorisation. grantedBy is the granting Owner's EMAIL (display), or "bootstrap" for the first
// authenticated caller. expiresAt is an optional time-boxed grant; the DO treats an expired grant as viewer.
export interface RoleEntry {
  subject: string;
  email: string;
  role: Role;
  grantedBy: string;
  grantedAt: string;
  expiresAt?: string;
  // customRole, when present, names a custom role this grant confers INSTEAD of the built-in role
  // field (which is pinned to "viewer" as the floor). The grant's authority then becomes the custom
  // role's capability set, resolved from the `customrole:` table at request time (the DO never trusts a
  // forwarded capability set; it recomputes from the name, the same discipline as the group mapping).
  // A grant whose customRole names a role that no longer exists falls back to the viewer floor (a
  // deleted custom role drops its holders to least privilege, never fails open).
  customRole?: string;
}

// PendingRoleEntry is an invited-but-not-yet-bound grant, keyed by the lowercased email
// (`role:pending:${email}`). It carries no subject yet (the invitee has never authenticated). On the
// invitee's first verified request the DO binds it: it reads the role/customRole/expiry/grantedBy here,
// writes a RoleEntry under `role:sub:<subject>` recording both, and deletes this pending row. A legacy
// `role:<email>` entry is read as a PendingRoleEntry (same shape minus the subject), so it binds on next
// login. The fields mirror RoleEntry minus subject, so the bind is a faithful copy.
export interface PendingRoleEntry {
  email: string;
  role: Role;
  grantedBy: string;
  grantedAt: string;
  expiresAt?: string;
  customRole?: string;
}

// The internal header the router uses to forward the resolved Caller to the DO on a request.
// SECURITY: this header is INTERNAL. The router (handleAdmin) sets it on the scheduler.fetch()
// it builds from scratch; a DO fetch never leaves the account, so the DO can trust it FROM THE
// ROUTER ONLY. The DO must never honour this header on a path that an inbound client could
// reach, and the router must never copy an inbound client's headers onto the DO fetch (it does
// not; it forwards only the body). The router always sets this header explicitly, so an
// attacker-supplied value on the inbound request is simply overwritten.
export const CALLER_HEADER = "x-downpipe-caller";

// A compact, transport-safe caller subset carried in the header. Only the fields the DO needs for
// its authority re-check, role resolution and the audit actor; never a secret. groups is carried so
// the DO can RESOLVE the role itself from its own group->role table given the forwarded email AND
// groups (the DO never trusts the forwarded role for the group-roles routes; it recomputes). The
// forwarded role remains the router-resolved value the existing routes' DO re-checks already trust
// FROM THE ROUTER ONLY (see CALLER_HEADER); groups make that resolution auditable end to end.
interface CallerHeaderPayload {
  method: AuthMethod;
  email: string | null;
  // subject is the stable principal (iss+"|"+sub, or passkeySubject(email)); null for the bare-token
  // break-glass. The DO needs it to key the role lookup (`role:sub:<subject>`), to bind a pending email
  // invite on first auth, and as the maker != checker comparison axis. Like the email and groups it is
  // forwarded for the DO's own re-resolution; the DO never derives authority from it directly beyond the
  // table lookup, and the header is router-internal (see CALLER_HEADER), so a client cannot forge it.
  subject: string | null;
  role: Role;
  groups: string[];
  // connId is the IdP-connection id for a native oidc/saml caller (absent otherwise). Forwarded so the DO
  // can record the honest provider in the audit actor; it is NOT an authority input (the DO re-resolves the
  // role from subject + groups), and the header is router-internal (see CALLER_HEADER) so it cannot be forged.
  connId?: string;
  // customRole, when present, is the NAME of the custom role the caller resolved to (role is the
  // viewer floor in that case). The DO re-resolves the capability SET from this name against its own
  // `customrole:` table; it never trusts a forwarded set, so only the name reference crosses the wire,
  // exactly as only the email + groups (not the resolved role) are trusted for the group-roles routes.
  customRole?: string;
  // sourceIp is the coarse audit provenance (where the request came from): the router reads it from the
  // edge CF-Connecting-IP header and carries it here so the DO can stamp the SAME IP on a SUCCESS recorded
  // at the commit point that a router-recorded DENIAL already carries. It is NOT an authority input (the DO
  // re-resolves the role from subject + groups and never reads this) and the header is router-internal (see
  // CALLER_HEADER), so it cannot be forged by a client: the router overwrites any inbound header and SETS
  // this value from the edge header it read. Absent (omitted) when there was no IP, decoded back to null.
  sourceIp?: string | null;
  // change is the OPTIONAL change reference forwarded to the DO so the change-control chokepoint can validate
  // it and record the change-recorded event (see Caller.change). It is non-authority metadata; decodeCaller
  // reconstructs it through parseChangeRef (bounded, control-chars stripped), so a forged/oversized value
  // cannot pass an unbounded reference onward. Omitted when no reference was supplied.
  change?: ChangeRef | null;
}

// CALLER_GROUP_NAME_MAX bounds a single forwarded group name and CALLER_GROUPS_MAX bounds how many
// the decoder will reconstruct from the header. The header is router-set and internal (see
// CALLER_HEADER), but decodeCaller still bounds the list it hands onward so a forged or oversized
// header value cannot pass an unbounded list to the DO: the bound is applied at the point the list
// is reconstructed, independently of any bounding access.ts did, mirroring the DO's own input
// bounding. The values match access.ts/the DO (256 / 200) deliberately and are kept here so this
// module has no cross-module dependency for its own bounding.
const CALLER_GROUP_NAME_MAX = 256;
const CALLER_GROUPS_MAX = 200;

// boundCallerGroups normalises a reconstructed groups list the same way the DO and access.ts do:
// keep only strings, trim, drop empty, drop any over CALLER_GROUP_NAME_MAX, drop any name carrying
// an ASCII control character (0x00-0x1F or 0x7F, matching the DO's normaliseGroup so the two
// normalisers agree), dedupe (first occurrence wins, order preserved), and cap to CALLER_GROUPS_MAX.
// A non-array yields [] (the honest "no groups" default that keeps the request from failing closed
// for an otherwise-valid caller). For a normal small list the output order is unchanged.
//
// IT TALLIES NOTHING, AND IT CANNOT. This bound is a defence-in-depth SECOND bound, and every
// producer of a Caller has already applied the IDENTICAL limits (access.ts boundGroups, oidc.ts boundGroups,
// oauth2.ts addGroup, the DO's boundGroupList: all 200 / 256), so by the time a groups list reaches this
// function there is nothing left for it to drop. The claim-drop tally that used to hang off it could only ever
// be driven by a hand-built header no production producer emits, which is a member a support engineer would
// never see. The bound STAYS (a forged header must never hand the DO an unbounded list); the tally is gone, and
// the drop is counted where it actually happens -- at the IdP boundary that carried the oversized claim.
function boundCallerGroups(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const entry of raw) {
    if (typeof entry !== "string") continue;
    const g = entry.trim();
    if (g.length === 0) continue;
    if (g.length > CALLER_GROUP_NAME_MAX) continue;
    let control = false;
    for (let i = 0; i < g.length; i++) {
      const c = g.charCodeAt(i);
      if (c < 0x20 || c === 0x7f) {
        control = true;
        break;
      }
    }
    if (control) continue;
    if (seen.has(g)) continue;
    if (out.length >= CALLER_GROUPS_MAX) continue;
    seen.add(g);
    out.push(g);
  }
  return out;
}

// base64url(JSON) encode/decode for the caller header. base64url avoids header-unsafe
// characters that a raw JSON value (with quotes/commas) would carry. This is not a security
// boundary (see CALLER_HEADER); it is a faithful, header-safe transport of an already-trusted
// value, so a plain Buffer/btoa round trip is sufficient and Node 25 + Workers both have btoa.
export function encodeCaller(caller: Caller): string {
  const payload: CallerHeaderPayload = {
    method: caller.method,
    email: caller.email,
    subject: caller.subject,
    role: caller.role,
    groups: caller.groups,
    ...(caller.connId !== undefined ? { connId: caller.connId } : {}),
    // Carry ONLY the custom-role NAME (never the resolved capability set): the DO re-resolves the set
    // from its own table, so the wire stays a name reference like the email + groups, never trusted authority.
    ...(caller.customRole !== undefined ? { customRole: caller.customRole } : {}),
    // Carry the coarse source IP so the DO can attribute it on a commit-point SUCCESS. Only included when
    // present (a null/absent IP is simply omitted and decodes back to null); it is non-authoritative
    // provenance, never a secret, and the header is router-internal so a client cannot forge it.
    ...(caller.sourceIp !== undefined && caller.sourceIp !== null ? { sourceIp: caller.sourceIp } : {}),
    // Carry the OPTIONAL change reference so the DO's change-control chokepoint can validate + record it. Only
    // included when present (an absent reference is simply omitted and decodes back to undefined). It is
    // non-authority operator metadata (like sourceIp), never a secret; parseChangeRef re-bounds it on decode.
    ...(caller.change !== undefined && caller.change !== null ? { change: caller.change } : {}),
  };
  const json = JSON.stringify(payload);
  // btoa works over a binary string; the JSON here is ASCII (emails and enums), and a
  // non-ASCII email is handled by escaping to UTF-8 bytes first so btoa never throws.
  const bytes = new TextEncoder().encode(json);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// decodeCaller parses the header the router set. It returns null on any malformed value rather
// than throwing, so the DO falls back to a safe default (treat as no caller -> least
// privilege) instead of 500ing. A null/absent header is the bare-token-or-self path and the
// DO route decides what that means for its specific operation.
export function decodeCaller(header: string | null): CallerHeaderPayload | null {
  if (!header) return null;
  try {
    const b64 = header.replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const obj = JSON.parse(new TextDecoder().decode(bytes)) as unknown;
    if (typeof obj !== "object" || obj === null) return null;
    return parseCallerPayload(obj as Record<string, unknown>);
  } catch {
    return null;
  }
}

// parseCallerPayload extracts and bounds the caller fields from the already-decoded header object. It owns
// the field-level validation (method allowlist, role check, optional-field defaulting and bounding); the
// transport decode (base64url + JSON.parse + object check) stays in decodeCaller. Returns null on any
// malformed required field, so the DO falls back to least privilege.
function parseCallerPayload(rec: Record<string, unknown>): CallerHeaderPayload | null {
  const method = rec.method;
  const email = rec.email;
  const subjectRaw = rec.subject;
  const role = rec.role;
  // The closed AuthMethod set: access | passkey | oidc | saml | token. The four email+subject-bearing
  // methods (access, passkey, oidc, saml) resolve their role from the subject-keyed table and never get
  // the owner-token break-glass; only method:"token" does. Anything else is malformed -> null.
  if (method !== "access" && method !== "passkey" && method !== "oidc" && method !== "saml" && method !== "token") return null;
  if (email !== null && typeof email !== "string") return null;
  // subject is the stable principal; null for the token break-glass, a string otherwise. A missing key
  // (a header from before subject-keying) reads as null, which the DO treats as "no stable identity"
  // (it falls back to the email-bind path on read, never the owner break-glass unless method is token).
  const subject = subjectRaw === null || subjectRaw === undefined ? null : typeof subjectRaw === "string" ? subjectRaw : null;
  if (!isRole(role)) return null;
  // groups is OPTIONAL on the wire (a header from before group-mapping, or the token path, omits
  // it): boundCallerGroups defaults to [] for a missing/non-array field (so the decode does not
  // fail closed for an otherwise-valid caller) and otherwise bounds the list the decoder hands
  // onward (trim, drop empty/over-long/control-char, dedupe, cap 200). This bounds at the point of
  // reconstruction so a forged or oversized header cannot pass the DO an unbounded list, even
  // though the header is router-set and internal (defence in depth, mirroring the DO's own bound).
  const groups = boundCallerGroups(rec.groups);
  // customRole is OPTIONAL (a built-in-role caller, or a header from before custom roles, omits it).
  // It is carried only as a NAME the DO re-resolves; a non-string or empty value is dropped to
  // undefined (the built-in-role path). It is NOT bounds-validated against the name pattern here: the
  // DO re-resolves it against its own `customrole:` table and a name that matches nothing falls back
  // to the viewer floor, so a forged name confers nothing.
  const customRoleRaw = rec.customRole;
  const customRole = typeof customRoleRaw === "string" && customRoleRaw.length > 0 ? customRoleRaw : undefined;
  // connId is OPTIONAL (only a native oidc/saml caller carries it). A non-string/empty value drops to
  // undefined. It is a display/audit field, not an authority input, so it is not pattern-validated here.
  const connIdRaw = rec.connId;
  const connId = typeof connIdRaw === "string" && connIdRaw.length > 0 ? connIdRaw : undefined;
  // sourceIp is OPTIONAL (omitted when there was no IP, or a header from before this field). A non-string
  // or empty value drops to undefined (the DO then records null). It is a coarse provenance field for the
  // audit actor, NOT an authority input, so it is not validated as an IP literal here: even a garbage value
  // only mislabels a provenance string, never confers authority. It is read ONLY from this router-internal
  // header (the router SETS it from the edge CF-Connecting-IP and overwrites any inbound value), so a client
  // cannot inject a forged IP into the trail through an attacker-supplied x-downpipe-caller.
  const sourceIpRaw = rec.sourceIp;
  const sourceIp = typeof sourceIpRaw === "string" && sourceIpRaw.length > 0 ? sourceIpRaw : undefined;
  // change is OPTIONAL (only present when the operator attached a reference to a change-controlled action).
  // parseChangeRef reconstructs a bounded, control-char-stripped reference or null; it is non-authority
  // metadata, so a malformed value only loses the reference (the policy then refuses the action if one was
  // required), never confers authority. Spread in only when a reference reconstructed (null => omitted).
  const change = parseChangeRef(rec.change);
  return { method, email, subject, role, groups, ...(connId !== undefined ? { connId } : {}), ...(customRole !== undefined ? { customRole } : {}), ...(sourceIp !== undefined ? { sourceIp } : {}), ...(change !== null ? { change } : {}) };
}

// FORBIDDEN is the 403 body shape the router returns when a positive auth verdict's role lacks the
// capability a route requires. It is JSON (distinct from the plaintext 401 "unauthorised"), so the
// console discriminates a capability gate from a sign-in failure on the status code + body. required
// is now the Capability the route needs (the gate moved from role-rank to the capability map); have
// is the caller's resolved role, so the console can say "your <role> cannot <capability>".
export interface Forbidden {
  error: "forbidden";
  required: Capability;
  have: Role;
}
