// The storage substrate for the DO-side OIDC store (oidc-store.ts): the injected KvStorage interface, the
// DO-local storage-key prefixes, the per-key builders, and the shared default state TTL. Splitting this off
// keeps oidc-store.ts focused on the connection CRUD + flow orchestration while this module owns the storage
// shape every path is written over. The symbols are re-exported from oidc-store.ts so importers are unchanged.
//
// Node 25 strip-types + Workers compatible: no Node builtins, no enums, explicit fields.

// KvStorage is the get/put/delete/list subset of the DO's DurableObjectStorage this store uses. Injecting it
// (rather than importing the DO's storage) is what makes every path testable with the same in-memory mock
// validate-session.ts uses. put structurally persists the value; list returns a Map of key -> value for a
// prefix (the DO's storage list shape). delete returns whether a key existed (unused by callers, kept faithful).
export interface KvStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
  list<T>(opts?: { prefix?: string }): Promise<Map<string, T>>;
}

// ---- storage-key prefixes ----------------------------------------------------------------------

export const CONN_PREFIX = "idpconn:";
export const SECRET_PREFIX = "idpsecret:";
export const STATE_PREFIX = "oidcstate:";

// DEFAULT_STATE_TTL_MS bounds how long a minted /start state record is valid for its callback. Ten minutes is
// generous for an interactive IdP round trip (the user logs in at the IdP and is redirected back) and short
// enough that an abandoned/leaked state self-expires. The callback passes this; sweepOidcStates uses it to
// prune abandoned records (a user who started a login and never finished leaves a record behind).
export const DEFAULT_STATE_TTL_MS = 600000;

export function connKey(id: string): string {
  return CONN_PREFIX + id;
}
export function secretKey(id: string): string {
  return SECRET_PREFIX + id;
}
export function stateKey(state: string): string {
  return STATE_PREFIX + state;
}
