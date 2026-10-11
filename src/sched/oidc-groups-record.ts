// The per-subject IdP group record, stored at oidcgroups:<subject>.
//
// The record is { email, groups, updatedAt }. It is written at every native-IdP sign-in, so the address and the
// time are the person's last sign-in's. The address lets an offboard by address find the record without a
// separate address-to-subject index. The time lets the scheduler alarm delete a record nobody has refreshed.
//
// A bare group list is a string[] with no address and no time. Every reader accepts it, but an offboard cannot
// name it and the age rule cannot date it. The next authenticated request of the person it belongs to rewrites it
// as a group record with email and updatedAt, using the address in their session. An active person keeps their role.
// The first alarm that sees a bare list stamps it { groups, migratedAt }. The alarm deletes it 14 days later.
// Remove once the migration window has closed: the bare group-list form is read only during it.
// Nobody active owns a list that is still bare after migratedAt plus 14 days.

export const OIDC_GROUPS_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;
export const OIDC_GROUPS_MIGRATION_GRACE_MS = 14 * 24 * 60 * 60 * 1000;

export interface OidcGroupsRecord {
  email: string;
  groups: string[];
  updatedAt: number;
}

// The slice of DurableObjectStorage this module uses, so a validator can drive it with a small double.
export interface OidcGroupsStore {
  list<T>(opts: { prefix: string; startAfter?: string; limit?: number }): Promise<Map<string, T>>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
}

const PAGE = 500;

export function makeOidcGroupsRecord(email: string, groups: readonly string[], nowMs: number): OidcGroupsRecord {
  return { email, groups: [...groups], updatedAt: nowMs };
}

// groupsOf returns the groups of a bare group list or a group record, or undefined for anything else.
// Remove once the migration window has closed: the bare group-list form is read only during it.
export function groupsOf(raw: unknown): string[] | undefined {
  if (Array.isArray(raw)) return raw.filter((g): g is string => typeof g === "string");
  if (raw !== null && typeof raw === "object" && Array.isArray((raw as { groups?: unknown }).groups)) {
    return (raw as { groups: unknown[] }).groups.filter((g): g is string => typeof g === "string");
  }
  return undefined;
}

// hasEmail is true for a group record that carries an email.
export function hasEmail(raw: unknown): raw is OidcGroupsRecord {
  return raw !== null && typeof raw === "object" && !Array.isArray(raw) && typeof (raw as { email?: unknown }).email === "string";
}

// isStale is true for a record the alarm deletes: a group record whose time is more than the retention
// behind the clock, a stamped record more than the grace behind it, or a malformed record. A bare list is not stale
// here, because the alarm stamps it first.
export function isStale(raw: unknown, nowMs: number): boolean {
  if (Array.isArray(raw)) return false;
  if (raw === null || typeof raw !== "object") return true;
  const r = raw as { updatedAt?: unknown; migratedAt?: unknown };
  if (hasEmail(raw)) return typeof r.updatedAt !== "number" || !Number.isFinite(r.updatedAt) || nowMs - r.updatedAt > OIDC_GROUPS_RETENTION_MS;
  return typeof r.migratedAt !== "number" || !Number.isFinite(r.migratedAt) || nowMs - r.migratedAt > OIDC_GROUPS_MIGRATION_GRACE_MS;
}

async function scan(store: OidcGroupsStore, prefix: string, visit: (key: string, raw: unknown) => Promise<void>): Promise<void> {
  let after: string | undefined;
  for (;;) {
    const page = await store.list<unknown>({ prefix, limit: PAGE, ...(after !== undefined ? { startAfter: after } : {}) });
    if (page.size === 0) return;
    for (const [k, v] of page) {
      after = k;
      await visit(k, v);
    }
    if (page.size < PAGE) return;
  }
}

// sweepOidcGroups stamps each bare group list with migratedAt, deletes every stale record, and returns how many
// it deleted.
// Remove once the migration window has closed: the bare group-list form is read only during it.
export async function sweepOidcGroups(store: OidcGroupsStore, prefix: string, nowMs: number): Promise<number> {
  let n = 0;
  await scan(store, prefix, async (k, raw) => {
    if (Array.isArray(raw)) {
      await store.put(k, { groups: groupsOf(raw) ?? [], migratedAt: nowMs });
    } else if (isStale(raw, nowMs) && (await store.delete(k))) n++;
  });
  return n;
}

// deleteOidcGroupsForEmail deletes every record whose stored address is the given one and returns how many.
export async function deleteOidcGroupsForEmail(store: OidcGroupsStore, prefix: string, email: string): Promise<number> {
  let n = 0;
  await scan(store, prefix, async (k, raw) => {
    const stored = raw !== null && typeof raw === "object" && !Array.isArray(raw) ? (raw as { email?: unknown }).email : undefined;
    if (typeof stored === "string" && stored.toLowerCase() === email.toLowerCase() && (await store.delete(k))) n++;
  });
  return n;
}
