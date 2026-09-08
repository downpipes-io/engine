// The versionable governance-config SNAPSHOT layer for config-history.ts. This module defines the
// stable, key-ordered ConfigSnapshot shape (a normalised projection of the live DO records), the raw
// SnapshotInput the DO hands in, the projection snapshotConfig that copies ONLY named, non-secret
// fields into the snapshot (redaction-safe by construction), and serialiseSnapshot, the ONE canonical
// byte form used for both the content hash and the byte-identical de-dupe. Everything here was MOVED
// VERBATIM out of config-history.ts to keep that module a readable size; the behaviour is unchanged.
// config-history.ts imports the snapshot types + serialiseSnapshot from here and re-exports them so its
// callers keep importing them by name from config-history.ts.
//
// SECRETS BY REFERENCE ONLY (the no-value rule, mirroring audit.ts redaction-by-construction and the
// ceremony's by-reference pattern). The only secret-adjacent fields the versionable config carries are
// a Secrets Store source's secret NAME and its env BINDING name (SecretBindingSpec) and the kv/r2/d1
// BINDING names. These are the customer's own non-secret account metadata, already returned verbatim by
// GET /admin/downpipes; they are NOT secret VALUES (the engine never holds a secret's value in its
// config at all - it reads them from the account Secrets Store at run time by binding). snapshotConfig
// copies ONLY this closed, named-metadata set into the snapshot, field by field, so there is no path by
// which a secret value could enter a snapshot even if a caller stuffed one elsewhere in the input. The
// validator asserts this directly (no secret marker can appear in a serialised snapshot).
//
// Node 25 strip-types compatible and Workers-runtime compatible: Web Crypto only, no enums, explicit
// field declarations. TypeScript 6 + exactOptionalPropertyTypes: every optional key is included only
// when it carries a value.

import { canonicalJSON } from "../format/canonjson.ts";
import type { DownpipeConfig } from "../sched/types.ts";

// ---- The versionable config shape (stable, key-ordered) ----------------------------------------
// These are NORMALISED projections of the live DO records: only the fields that define WHAT the
// account's governance posture is, copied field by field (never spread) so an unexpected field on a
// source record can never ride into a snapshot. Arrays are sorted by a stable key (id/email/group/
// name) so a snapshot is byte-identical regardless of storage iteration order, which is what makes the
// content hash and the de-dupe deterministic.

// A downpipe's versionable shape: its identity, schedule, enablement, the restore-test cadence, and the
// source SELECTOR (type + the binding/namespace/bucket names + include/exclude globs + the secret NAMES
// for a secrets source). Every field here is non-secret account metadata already exposed by GET
// /admin/downpipes. No secret VALUE exists in a downpipe config to copy.
export interface ConfigDownpipe {
  id: string;
  name: string;
  cadenceSeconds: number;
  enabled: boolean;
  restoreTestCadenceSeconds: number; // 0 = off; normalised so an absent value reads as the stored default
  source: {
    type: "kv" | "r2" | "secrets" | "d1" | "cf-config" | "workers" | "stream" | "images" | "artifacts";
    binding: string | null;
    namespaceId: string | null;
    bucketName: string | null;
    // secrets are referenced BY NAME ONLY: the source-native secret name + the env binding it is read
    // through. Never a secret value (there is none in the config; the value lives in the account Secrets
    // Store, read at run time by binding). Sorted by name for stability.
    secrets: { name: string; binding: string }[];
    include: string[];
    exclude: string[];
  };
}

// A built-in or custom role grant: the email it is for, the built-in role, and (when the grant confers a
// named custom role) the custom-role name. expiresAt is carried because a time-boxed grant changing is a
// real posture change. grantedBy/grantedAt are provenance, NOT part of the versionable posture (who
// clicked save and exactly when does not change WHAT the access posture is), so they are deliberately
// excluded so a re-grant of the identical role does not churn a new version.
export interface ConfigRoleGrant {
  email: string;
  role: string;
  customRole: string | null;
  expiresAt: string | null;
}

// An identity-provider group -> role mapping: the group name, the built-in role, and the custom-role
// name when the mapping confers one. Same provenance-excluded discipline as ConfigRoleGrant.
export interface ConfigGroupRole {
  group: string;
  role: string;
  customRole: string | null;
  // connId: the IdP connection this mapping is SCOPED to, or null when it is GLOBAL. Captured so config
  // history + the dual-control diff show whether a group-role mapping applies to one connection or all.
  connId: string | null;
}

// A composable custom role definition: its name, label, the SORTED capability list, the per-screen
// surface (sorted by screen), the presentation skin and the landing screen. createdBy/createdAt are
// provenance and excluded (re-saving an identical role must not churn a version).
export interface ConfigCustomRole {
  name: string;
  label: string;
  capabilities: string[];
  surface: { screen: string; mode: string }[];
  presentation: string;
  landing: string;
}

// A notify channel definition: id, kind, label, enablement, and the routing targets. toAddresses ARE the
// customer's own configured destinations (the same data GET /notify/channels returns); they are not a
// secret. The endpoint url (webhook/slack/teams) is DIFFERENT: a Slack/
// Teams/generic-webhook url is itself the bearer credential (it commonly carries a token in its PATH or
// QUERY), so it is redacted to host + presence only (urlHost via the shared
// webhookHost() helper, urlConfigured), never the raw url. A PagerDuty routing key is likewise a
// credential, referenced as a PRESENCE boolean only (routingKeyConfigured), never its value. createdAt is
// provenance and excluded.
export interface ConfigNotifyChannel {
  id: string;
  kind: string;
  name: string;
  enabled: boolean;
  urlConfigured: boolean;
  urlHost: string | null;
  toAddresses: string[];
  routingKeyConfigured: boolean;
}

// A notify rule definition: id, scope, severity floor, the selected events, the target channel ids, the
// digest cadence and enablement. All non-secret routing metadata.
export interface ConfigNotifyRule {
  id: string;
  scope: string; // "global" or "downpipe:<id>", a stable scalar for the diff
  minSeverity: string;
  events: string[]; // the event list, or ["all"] for the "all" sentinel, sorted for stability
  channelIds: string[];
  digest: string; // "off" | "daily" | "weekly"
  enabled: boolean;
}

// A posture risk-acceptance: the check id and the reason. The reason is redaction-safe operator free
// text (the same field the posture surface stores), never a secret. acceptedBy/acceptedAt are provenance
// and excluded.
export interface ConfigRiskAccept {
  checkId: string;
  // kind is the override kind ("risk-accepted" | "attested-pass" | "compensating-control" |
  // "not-applicable"). OPTIONAL so a snapshot persisted before override kinds existed keeps parsing;
  // an absent kind reads as the legacy "risk-accepted" wherever it is compared.
  kind?: string;
  reason: string;
}

// A tracked credential/key expiry item: its stable id, label, kind and the RFC-3339 expiry. All
// redaction-safe operator metadata (the same fields GET /expiry projects); an ExpiryItem has no field
// that could hold a secret. The note/source are provenance-ish display detail and excluded from the
// versionable posture (the id/label/kind/expiry are the reviewable facts; a note edit should not need a
// version), mirroring how grantedBy/grantedAt are excluded from a role grant.
export interface ConfigExpiryItem {
  id: string;
  label: string;
  kind: string;
  // OPTIONAL: a no-expiry credential (one that does not expire by default, or a never-expiring token)
  // omits it; the diff renders an absent expiry as "no expiry".
  expiresAt?: string;
}

// The coverage reference inventory, by resource type, each a sorted list of resource ids (+ optional
// label). It is reference data only (a checklist), never a binding a seal/restore path consults, so it
// carries no secret. Present only when an inventory has been stored.
export interface ConfigCoverageInventory {
  kv: { id: string; name: string | null }[];
  r2: { id: string; name: string | null }[];
  d1: { id: string; name: string | null }[];
  secrets: { id: string; name: string | null }[];
}

// ConfigSnapshot is the whole versionable governance posture, normalised and stable-key-ordered. It is
// the object that is content-hashed (canonical JSON) and de-duped against the head version, and the
// object the diff walks. Every member list is sorted by its stable key. coverage is OPTIONAL (absent
// when no inventory is stored, which is a different, honest state from an empty inventory).
export interface ConfigSnapshot {
  downpipes: ConfigDownpipe[];
  roles: ConfigRoleGrant[];
  groupRoles: ConfigGroupRole[];
  customRoles: ConfigCustomRole[];
  notifyChannels: ConfigNotifyChannel[];
  notifyRules: ConfigNotifyRule[];
  riskAccepts: ConfigRiskAccept[];
  expiryItems: ConfigExpiryItem[];
  coverage?: ConfigCoverageInventory;
}

// ---- The raw inputs the DO hands snapshotConfig ------------------------------------------------
// snapshotConfig takes the live records the DO already holds (the same shapes its list methods return)
// and projects them into the normalised ConfigSnapshot. The input field types are kept loose
// (structural) so the DO can pass its records directly without a converting copy; snapshotConfig reads
// ONLY the named fields it projects, so an extra field on an input is simply ignored (and a secret could
// not ride in on one, since nothing is spread).

export interface SnapshotInput {
  downpipes: DownpipeConfig[];
  roles: Array<{ email: string; role: string; customRole?: string; expiresAt?: string }>;
  groupRoles: Array<{ group: string; role: string; customRole?: string; connId?: string }>;
  customRoles: Array<{
    name: string;
    label: string;
    capabilities: string[];
    surface: Record<string, string>;
    presentation: string;
    landing: string;
  }>;
  notifyChannels: Array<{
    id: string;
    kind: string;
    name: string;
    enabled: boolean;
    url?: string;
    toAddresses?: string[];
    routingKey?: string;
  }>;
  notifyRules: Array<{
    id: string;
    scope: { kind: "global" } | { kind: "downpipe"; downpipeId: string };
    minSeverity: string;
    events: string[] | "all";
    channelIds: string[];
    digest?: string;
    enabled: boolean;
  }>;
  riskAccepts: Array<{ checkId: string; kind?: string; reason: string }>;
  expiryItems: Array<{ id: string; label: string; kind: string; expiresAt?: string }>;
  // coverage is null when no inventory is stored (the honest-unknown state), distinct from an inventory
  // whose groups are all empty (a stored-but-empty inventory).
  coverage: { kv: Array<{ id: string; name?: string }>; r2: Array<{ id: string; name?: string }>; d1: Array<{ id: string; name?: string }>; secrets: Array<{ id: string; name?: string }> } | null;
}

// byKey sorts a copy of a list by a string key extractor, stably and case-sensitively (the keys are
// already canonical lowercased ids/emails/names or exact group/screen names), so the serialised snapshot
// is independent of storage iteration order.
function byKey<T>(list: readonly T[], key: (t: T) => string): T[] {
  return [...list].sort((a, b) => {
    const ka = key(a);
    const kb = key(b);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
}

// sortedStrings returns a sorted copy of a string list (for include/exclude globs, capability lists,
// channel id lists, event lists), so reordering the same set never churns a version or a diff.
function sortedStrings(list: readonly string[]): string[] {
  return [...list].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

// webhookHost extracts ONLY the host (hostname, plus a non-default port) from a notify channel's endpoint
// url, for the redacted snapshot. It deliberately drops the scheme, the path, the query and any userinfo,
// because such a url's secret typically lives in the PATH or QUERY (a Slack/PagerDuty/SIEM token): the host
// is the reviewable "where do alerts go" fact, the rest is not in the version. An unparseable url yields null
// (recorded as configured with no readable host), never the raw string. The hostname is lowercased by the
// URL parser, so the value is stable for the de-dupe and diff.
// EXPORTED because the pending-change inbox needs the SAME reduction, not a second one. A queued
// notify-channel-set stores the submitted channel verbatim, so its params hold the raw url until the change
// is decided; change-control.ts projects that url through THIS function for every caller-facing echo and for
// the at-rest scrub, so what a reviewer sees before the change applies is exactly what the config history
// shows them after it, computed by one piece of code.
export function webhookHost(url: string): string | null {
  try {
    const u = new URL(url);
    return u.port ? `${u.hostname}:${u.port}` : u.hostname;
  } catch {
    return null;
  }
}

// snapshotConfig projects the live DO records into the stable, key-ordered ConfigSnapshot. It copies
// ONLY the named, non-secret fields (never a spread), so the snapshot is redaction-safe by construction:
// a Secrets Store secret is carried by its NAME and BINDING only, a PagerDuty routing key by a PRESENCE
// boolean only, and no secret VALUE has any field to occupy. The result is deterministic for a given
// posture regardless of the order the DO listed its storage, which is what makes the content hash and
// the de-dupe stable.
function projectDownpipe(d: SnapshotInput["downpipes"][number]): ConfigDownpipe {
  return {
    id: d.id,
    name: d.name,
    cadenceSeconds: d.cadenceSeconds,
    enabled: d.enabled,
    // An absent restoreTestCadenceSeconds reads as 0 (off) for the snapshot's purpose; the DO defaults
    // it on create, so a stored config normally carries an explicit value. Normalising to a number keeps
    // the field a stable scalar the diff can compare.
    restoreTestCadenceSeconds: typeof d.restoreTestCadenceSeconds === "number" ? d.restoreTestCadenceSeconds : 0,
    source: {
      type: d.source.type,
      binding: d.source.binding ?? null,
      namespaceId: d.source.namespaceId ?? null,
      bucketName: d.source.bucketName ?? null,
      // SECRETS BY NAME ONLY: copy each secret's source-native name + its env binding name, sorted by
      // name. Never a value (the config has none). This is the same named metadata GET /downpipes returns.
      secrets: byKey(d.source.secrets ?? [], (s) => s.name).map((s) => ({ name: s.name, binding: s.binding })),
      include: sortedStrings(d.source.include ?? []),
      exclude: sortedStrings(d.source.exclude ?? []),
    },
  };
}

function projectRole(r: SnapshotInput["roles"][number]): ConfigRoleGrant {
  return { email: r.email, role: r.role, customRole: r.customRole ?? null, expiresAt: r.expiresAt ?? null };
}

function projectGroupRole(g: SnapshotInput["groupRoles"][number]): ConfigGroupRole {
  return { group: g.group, role: g.role, customRole: g.customRole ?? null, connId: g.connId ?? null };
}

function projectCustomRole(c: SnapshotInput["customRoles"][number]): ConfigCustomRole {
  return {
    name: c.name,
    label: c.label,
    capabilities: sortedStrings(c.capabilities ?? []),
    surface: byKey(
      Object.entries(c.surface ?? {}).map(([screen, mode]) => ({ screen, mode })),
      (e) => e.screen,
    ),
    presentation: c.presentation,
    landing: c.landing,
  };
}

function projectNotifyChannel(c: SnapshotInput["notifyChannels"][number]): ConfigNotifyChannel {
  return {
    id: c.id,
    kind: c.kind,
    name: c.name,
    enabled: c.enabled,
    // The endpoint url is a bearer credential, so it is redacted to
    // host + presence only, via the webhookHost() helper, never the raw url.
    urlConfigured: typeof c.url === "string" && c.url.length > 0,
    urlHost: typeof c.url === "string" ? webhookHost(c.url) : null,
    toAddresses: sortedStrings(c.toAddresses ?? []),
    // A PagerDuty routing key is a credential: record its PRESENCE only, never its value.
    routingKeyConfigured: typeof c.routingKey === "string" && c.routingKey.length > 0,
  };
}

function projectNotifyRule(r: SnapshotInput["notifyRules"][number]): ConfigNotifyRule {
  return {
    id: r.id,
    scope: r.scope.kind === "downpipe" ? `downpipe:${r.scope.downpipeId}` : "global",
    minSeverity: r.minSeverity,
    events: r.events === "all" ? ["all"] : sortedStrings(r.events),
    channelIds: sortedStrings(r.channelIds ?? []),
    digest: typeof r.digest === "string" ? r.digest : "off",
    enabled: r.enabled,
  };
}

function projectExpiryItem(e: SnapshotInput["expiryItems"][number]): ConfigExpiryItem {
  return { id: e.id, label: e.label, kind: e.kind, ...(e.expiresAt !== undefined ? { expiresAt: e.expiresAt } : {}) };
}

function projectCoverage(coverage: NonNullable<SnapshotInput["coverage"]>): NonNullable<ConfigSnapshot["coverage"]> {
  const grp = (list: Array<{ id: string; name?: string }>): { id: string; name: string | null }[] =>
    byKey(list, (x) => x.id).map((x) => ({ id: x.id, name: x.name ?? null }));
  return {
    kv: grp(coverage.kv ?? []),
    r2: grp(coverage.r2 ?? []),
    d1: grp(coverage.d1 ?? []),
    secrets: grp(coverage.secrets ?? []),
  };
}

export function snapshotConfig(input: SnapshotInput): ConfigSnapshot {
  const snapshot: ConfigSnapshot = {
    downpipes: byKey(input.downpipes, (d) => d.id).map(projectDownpipe),
    roles: byKey(input.roles, (r) => r.email).map(projectRole),
    groupRoles: byKey(input.groupRoles, (g) => g.group).map(projectGroupRole),
    customRoles: byKey(input.customRoles, (c) => c.name).map(projectCustomRole),
    notifyChannels: byKey(input.notifyChannels, (c) => c.id).map(projectNotifyChannel),
    notifyRules: byKey(input.notifyRules, (r) => r.id).map(projectNotifyRule),
    riskAccepts: byKey(input.riskAccepts, (a) => a.checkId).map((a) => ({ checkId: a.checkId, ...(a.kind !== undefined ? { kind: a.kind } : {}), reason: a.reason })),
    expiryItems: byKey(input.expiryItems, (e) => e.id).map(projectExpiryItem),
  };
  if (input.coverage !== null) snapshot.coverage = projectCoverage(input.coverage);
  return snapshot;
}

// serialiseSnapshot is the ONE canonical byte form of a snapshot, used for BOTH the content hash and the
// byte-identical de-dupe. canonicalJSON sorts object keys and forbids non-integer/non-safe numbers, so
// the bytes are reproducible across the append, the verify and the validator. The arrays are already
// stable-key-ordered by snapshotConfig (canonicalJSON does NOT reorder arrays, only object keys), so the
// two stability mechanisms compose: object-key order from canonicalJSON, array order from snapshotConfig.
export function serialiseSnapshot(snapshot: ConfigSnapshot): Uint8Array {
  return canonicalJSON(snapshot);
}
