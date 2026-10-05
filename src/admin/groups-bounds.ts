// Shared bounds for the IdP group lists the engine carries from a login. They are the SAME limits on every
// IdP path (the OIDC path, the OAuth2 path and the Access decision path), so they live here in one place
// rather than being declared independently per file. Declaring them once removes the drift risk: changing a
// bound for one provider must not silently diverge between the three normalisers.

// GROUPS_MAX caps how many group strings the engine will trust from one token, so a pathological or hostile
// (but validly-signed) token cannot make the engine carry an unbounded list into the role resolution. 200 is
// far above any realistic per-user group count.
export const GROUPS_MAX = 200;

// GROUP_NAME_MAX bounds a single group string (after trimming). A group name is the customer's own IdP data,
// not a storage key here, but bounding it keeps the carried list small and keeps a later DO storage key
// (grouprole:<group>) within sane limits.
export const GROUP_NAME_MAX = 256;
