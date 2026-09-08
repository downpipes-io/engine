// The core identity + role PRIMITIVES for the engine governance backbone, split out of identity.ts so each
// module stays a coherent unit under 500 lines. This is the leaf the capability/custom-role layer
// (identity-rbac.ts) and the rest of identity.ts depend on: the auth-method tag, the role union + rank, the
// runtime role guard, the cumulative-role comparisons, and the single display-email canonicalisation. It
// imports nothing from the rest of the identity core (no import cycle). Behaviour is byte-identical to the
// original identity.ts: this code was MOVED verbatim, not changed.
//
// Node 25 strip-types compatible: no enums, no parameter properties, explicit field declarations only.

// How a request authenticated. "access" is a verified Cloudflare Access JWT (higher assurance,
// attributable to an email); "passkey" is the engine's OWN WebAuthn session (a signed, short-TTL cookie a
// successful passkey login issued, attributable to the credential's bound email; the free self-hosted
// front door); "oidc" and "saml" are the engine's OWN NATIVE external-IdP sessions (the SAME signed cookie,
// minted after the engine itself completes an OIDC/OAuth2 authorization-code flow or validates a SAML
// assertion, with NO Cloudflare Access in the path), attributable to the IdP's verified subject; "token" is
// the ADMIN_TOKEN bearer fallback (lower assurance, NOT attributable, so it resolves to the all-or-nothing
// owner break-glass). Precedence at the gate is access (header) > session-cookie (passkey | oidc | saml,
// distinguished by the signed payload's method) > token: a present-but-INVALID Access JWT or session cookie
// is rejected outright and NEVER downgraded to a weaker method (auth.ts preserves this). access, passkey,
// oidc and saml all carry a verified email AND a stable subject and resolve their role from the SAME
// subject-keyed role table; only the bare token is email-less and subject-less and resolves to owner.
// "recovery" is audit-only: it tags break-glass recovery-code events so an audit reader does not
// mistake them for ADMIN_TOKEN-bearer ("token") activity. It is never a session-borne method (a
// recovered session is minted as a passkey-class session), so it does not participate in method
// ranking or the cookie-borne CSRF set below.
export type AuthMethod = "access" | "passkey" | "oidc" | "saml" | "token" | "recovery";

// isHumanActorMethod is true for the methods that authenticate a PERSON in a live, interactive session, and it
// is therefore the set of audit events that SHOULD carry a source IP. "token" is the shared-token
// break-glass, which is deliberately non-attributable and is often invoked from a machine; an engine-observed
// event has no session at all. Counting a missing IP on either of those would raise a fault on a legitimate
// state, and a counter that climbs on a healthy engine is one nobody reads.
export function isHumanActorMethod(method: AuthMethod | "engine" | undefined | null): boolean {
  return method === "access" || method === "passkey" || method === "oidc" || method === "saml" || method === "recovery";
}

// isCookieBorneMethod is true for the three methods that authenticate via the engine's OWN ambient session
// cookie (passkey | oidc | saml). They are exactly the methods that need the strict-Origin CSRF guard on a
// mutating request (an ambient cookie a foreign page could ride); "access" and "token" present an EXPLICIT
// header a foreign page cannot set on a credentialed cross-origin request, so they are exempt. Keeping this
// in one place means every CSRF site widens together when a new cookie-borne method is added.
export function isCookieBorneMethod(method: AuthMethod): boolean {
  return method === "passkey" || method === "oidc" || method === "saml";
}

// The roles. The original FOUR are cumulative (owner >= approver >= operator >= viewer); a new
// member defaults to viewer (least privilege). The IA's "Viewer/Auditor" maps to viewer,
// "Approver/Recovery admin" to approver, "Owner/break-glass holder" to owner. Two NARROW roles are
// added that are deliberately NOT on the cumulative ladder (their powers are a specific subset, not
// a prefix of owner): "restore-operator" is recovery-only (request/apply/approve/drill, no downpipe
// create/edit/delete, no people, no keys) and "access-admin" is people-only (roles + access policy,
// no data, no restore, no keys). Authority is decided by the explicit ROLE_CAPABILITIES map below,
// not by rank; ROLE_RANK survives only as the resolution ordering for the four cumulative roles and
// the group-mapping combine (the two narrow roles still need a rank so maxRole/expiry fold cleanly).
export type Role = "viewer" | "operator" | "restore-operator" | "approver" | "access-admin" | "owner";

// ROLE_RANK orders the roles for ROLE RESOLUTION ONLY (the group-mapping combine via maxRole, the
// lazy-expiry "drops to viewer" comparison, and the group cap). It is NOT the authority check any
// more: per-route authorisation reads ROLE_CAPABILITIES via can(), because the two narrow roles are
// a subset, not a prefix, of owner and a single rank cannot express that. The four cumulative roles
// keep their original ranks (0..3) so their resolution is byte-for-byte unchanged; the two narrow
// roles are placed adjacent to the cumulative role they most resemble for the combine (restore-
// operator just above operator, access-admin just below owner) and owner stays the strict maximum so
// maxRole(owner, anything) === owner and the group cap "anything but owner" is a single comparison.
export const ROLE_RANK: Record<Role, number> = {
  viewer: 0,
  operator: 1,
  "restore-operator": 2,
  approver: 3,
  "access-admin": 4,
  owner: 5,
};

// isRole is the runtime guard the role-write route uses to reject a malformed role string at
// the authority boundary (the DO), matching how validateConfig bounds a downpipe config.
export function isRole(v: unknown): v is Role {
  return (
    v === "viewer" ||
    v === "operator" ||
    v === "restore-operator" ||
    v === "approver" ||
    v === "access-admin" ||
    v === "owner"
  );
}

// roleAtLeast is the ROLE RESOLUTION helper for maxRole/expiry folding only: does `have` meet the
// minimum `need` by cumulative rank, so owner satisfies every comparison. Per-route authorisation uses
// callerCan() over the ROLE_CAPABILITIES capability map; do not use this for gating, as the narrow roles
// (restore-operator, access-admin) are not cumulative.
/** @knipignore Cumulative-role gate primitive; currently unused (route gating keys on capabilities). */
export function roleAtLeast(have: Role, need: Role): boolean {
  return ROLE_RANK[have] >= ROLE_RANK[need];
}

// maxRole combines two roles by taking the higher rank. It is the single place role resolution
// expresses "the caller gets the strongest role any of their sources confers": the explicit
// email-table grant combined with the highest group-mapped role. Cumulative roles make this a
// rank comparison, so it is associative and commutative and folds cleanly over a list.
export function maxRole(a: Role, b: Role): Role {
  return ROLE_RANK[a] >= ROLE_RANK[b] ? a : b;
}

// canonicalEmail is the SINGLE canonicalisation of a verified caller's DISPLAY email, applied ONCE at
// the trust boundary (resolveCaller) so every downstream consumer sees one canonical form. Authorisation
// now keys on the stable SUBJECT, not the email, so the email no longer decides the role lookup or the
// maker != checker comparison; but it is still the displayed/audited identity and the rate-limit and
// invite (`role:pending:<email>`) key, so a single canonical form keeps "Alice@Example.com" and
// "alice@example.com" from presenting two display identities or two pending keys. Normalising here
// (trim + toLowerCase) collapses that: an email is an ASCII-case-insensitive identifier for our
// purposes, so the lowercased, trimmed form is the one canonical email the audit, the pending invite,
// and the rate limiter all see. Returns null for a null/non-string input (the token fallback has no
// email), preserving the bare-token semantics.
export function canonicalEmail(email: string | null): string | null {
  if (email === null) return null;
  const e = email.trim().toLowerCase();
  return e.length > 0 ? e : null;
}
