// The plain-English (Australian) config-history DIFF for config-history.ts. diffConfig produces a human
// change list between two ConfigSnapshots (from -> to); summarise condenses that diff into the one-line
// auto-summary stamped on a version. Everything here was MOVED VERBATIM out of config-history.ts to keep
// that module a readable size; the behaviour is unchanged. config-history.ts imports diffConfig/summarise
// from here and re-exports them (plus ChangeKind/ConfigChange/SUMMARY_MAX_CHANGES) so its callers keep
// importing them by name from config-history.ts.
//
// Node 25 strip-types compatible: no enums, explicit field declarations.

import type {
  ConfigCoverageInventory,
  ConfigCustomRole,
  ConfigDownpipe,
  ConfigExpiryItem,
  ConfigGroupRole,
  ConfigRoleGrant,
  ConfigSnapshot,
} from "./config-snapshot.ts";

// ---- Plain-English (Australian) diff -----------------------------------------------------------
// diffConfig produces a human change list between two snapshots (from -> to). It is the operator-facing
// payoff: "schedule daily -> hourly", "alice: operator -> approver", "downpipe kv:sessions added",
// "custom role Board Member: +reports.read", "group platform-eng unmapped". Australian English, no em or
// en dashes (a plain ASCII "->" is used for transitions). It walks each versionable family, comparing the
// two normalised, stable-key-ordered snapshots, and emits an ADD / REMOVE / per-field CHANGE line for
// each difference. It NEVER emits a secret (the snapshots carry none); the lines read only the same
// named metadata the snapshot holds.

// ChangeKind tags a line so a console can group/icon it without re-parsing the text.
export type ChangeKind = "added" | "removed" | "changed";

export interface ConfigChange {
  kind: ChangeKind;
  // area is the versionable family the change is in, so a console can group by it.
  area: "downpipe" | "role" | "group-role" | "custom-role" | "notify-channel" | "notify-rule" | "risk-accept" | "expiry" | "coverage";
  // text is the plain-English (Australian) one-liner.
  text: string;
}

// cadenceLabel renders a cadence in seconds as a friendly word where it maps to a common period, else
// "every N seconds". This is what turns "3600 -> 86400" into "hourly -> daily" in a schedule change line.
function cadenceLabel(seconds: number): string {
  switch (seconds) {
    case 0:
      return "off";
    case 3600:
      return "hourly";
    case 86400:
      return "daily";
    case 604800:
      return "weekly";
    case 2592000:
      return "monthly";
    default:
      if (seconds % 86400 === 0) return `every ${seconds / 86400} days`;
      if (seconds % 3600 === 0) return `every ${seconds / 3600} hours`;
      if (seconds % 60 === 0) return `every ${seconds / 60} minutes`;
      return `every ${seconds} seconds`;
  }
}

// downpipeLabel is the stable short label a downpipe diff line leads with: its source type and binding/
// identity (e.g. "kv:sessions"), falling back to the id. It reads only non-secret config metadata.
function downpipeLabel(d: ConfigDownpipe): string {
  const ident = d.source.binding ?? d.source.namespaceId ?? d.source.bucketName ?? d.id;
  return `${d.source.type}:${ident}`;
}

// indexBy builds a Map keyed by a string extractor for an O(1) presence/lookup across the two snapshots.
function indexBy<T>(list: readonly T[], key: (t: T) => string): Map<string, T> {
  const m = new Map<string, T>();
  for (const t of list) m.set(key(t), t);
  return m;
}

// setDiff returns the items added and removed between two sorted string lists (used for capability
// lists, event lists, channel-id lists, secret-name sets, etc.), so a line can read "+reports.read" and
// "-audit.read".
function setDiff(from: readonly string[], to: readonly string[]): { added: string[]; removed: string[] } {
  const fromSet = new Set(from);
  const toSet = new Set(to);
  const added = to.filter((x) => !fromSet.has(x));
  const removed = from.filter((x) => !toSet.has(x));
  return { added, removed };
}

// joinPlus renders an added/removed capability-style delta as "+a, +b, -c" for a change line suffix.
function joinPlus(added: string[], removed: string[]): string {
  return [...added.map((a) => `+${a}`), ...removed.map((r) => `-${r}`)].join(", ");
}

// Each diff<Family> helper compares the one family between the two snapshots and returns its ConfigChange
// lines (ADD / REMOVE / per-field CHANGE), following the consistent add/remove/change pattern. diffConfig
// concatenates them in the version's family order. diffNotifyWebbook and diffCoverage have unique one-shot
// semantics (a single redacted scalar object / a presence-or-set comparison) and stay slightly different.

function diffDownpipes(from: ConfigSnapshot, to: ConfigSnapshot): ConfigChange[] {
  const changes: ConfigChange[] = [];
  const fromIdx = indexBy(from.downpipes, (d) => d.id);
  const toIdx = indexBy(to.downpipes, (d) => d.id);
  for (const d of to.downpipes) {
    if (!fromIdx.has(d.id)) changes.push({ kind: "added", area: "downpipe", text: `downpipe ${downpipeLabel(d)} added` });
  }
  for (const d of from.downpipes) {
    if (!toIdx.has(d.id)) changes.push({ kind: "removed", area: "downpipe", text: `downpipe ${downpipeLabel(d)} removed` });
  }
  for (const d of to.downpipes) {
    const prev = fromIdx.get(d.id);
    if (prev === undefined) continue;
    const label = downpipeLabel(d);
    if (prev.cadenceSeconds !== d.cadenceSeconds) {
      changes.push({ kind: "changed", area: "downpipe", text: `downpipe ${label} schedule ${cadenceLabel(prev.cadenceSeconds)} -> ${cadenceLabel(d.cadenceSeconds)}` });
    }
    if (prev.enabled !== d.enabled) {
      changes.push({ kind: "changed", area: "downpipe", text: `downpipe ${label} ${d.enabled ? "enabled" : "disabled"}` });
    }
    if (prev.restoreTestCadenceSeconds !== d.restoreTestCadenceSeconds) {
      changes.push({ kind: "changed", area: "downpipe", text: `downpipe ${label} restore test ${cadenceLabel(prev.restoreTestCadenceSeconds)} -> ${cadenceLabel(d.restoreTestCadenceSeconds)}` });
    }
    if (prev.name !== d.name) {
      changes.push({ kind: "changed", area: "downpipe", text: `downpipe ${label} renamed ${prev.name} -> ${d.name}` });
    }
    // Selector changes: include/exclude globs and the secret-name set (by name only).
    const inc = setDiff(prev.source.include, d.source.include);
    if (inc.added.length || inc.removed.length) {
      changes.push({ kind: "changed", area: "downpipe", text: `downpipe ${label} include ${joinPlus(inc.added, inc.removed)}` });
    }
    const exc = setDiff(prev.source.exclude, d.source.exclude);
    if (exc.added.length || exc.removed.length) {
      changes.push({ kind: "changed", area: "downpipe", text: `downpipe ${label} exclude ${joinPlus(exc.added, exc.removed)}` });
    }
    const secDiff = setDiff(prev.source.secrets.map((s) => s.name), d.source.secrets.map((s) => s.name));
    if (secDiff.added.length || secDiff.removed.length) {
      changes.push({ kind: "changed", area: "downpipe", text: `downpipe ${label} secrets ${joinPlus(secDiff.added, secDiff.removed)}` });
    }
  }
  return changes;
}

function diffRoles(from: ConfigSnapshot, to: ConfigSnapshot): ConfigChange[] {
  const changes: ConfigChange[] = [];
  const fromIdx = indexBy(from.roles, (r) => r.email);
  const toIdx = indexBy(to.roles, (r) => r.email);
  const roleName = (r: ConfigRoleGrant): string => (r.customRole ? `custom role ${r.customRole}` : r.role);
  for (const r of to.roles) {
    if (!fromIdx.has(r.email)) changes.push({ kind: "added", area: "role", text: `${r.email}: granted ${roleName(r)}` });
  }
  for (const r of from.roles) {
    if (!toIdx.has(r.email)) changes.push({ kind: "removed", area: "role", text: `${r.email} removed` });
  }
  for (const r of to.roles) {
    const prev = fromIdx.get(r.email);
    if (prev === undefined) continue;
    if (roleName(prev) !== roleName(r)) {
      changes.push({ kind: "changed", area: "role", text: `${r.email}: ${roleName(prev)} -> ${roleName(r)}` });
    }
    if ((prev.expiresAt ?? null) !== (r.expiresAt ?? null)) {
      const was = prev.expiresAt ?? "no expiry";
      const now = r.expiresAt ?? "no expiry";
      changes.push({ kind: "changed", area: "role", text: `${r.email} expiry ${was} -> ${now}` });
    }
  }
  return changes;
}

function diffGroupRoles(from: ConfigSnapshot, to: ConfigSnapshot): ConfigChange[] {
  const changes: ConfigChange[] = [];
  const fromIdx = indexBy(from.groupRoles, (g) => g.group);
  const toIdx = indexBy(to.groupRoles, (g) => g.group);
  const gRole = (g: ConfigGroupRole): string => `${g.customRole ? `custom role ${g.customRole}` : g.role}${g.connId ? ` (scoped to connection ${g.connId})` : ""}`;
  for (const g of to.groupRoles) {
    if (!fromIdx.has(g.group)) changes.push({ kind: "added", area: "group-role", text: `group ${g.group} mapped to ${gRole(g)}` });
  }
  for (const g of from.groupRoles) {
    if (!toIdx.has(g.group)) changes.push({ kind: "removed", area: "group-role", text: `group ${g.group} unmapped` });
  }
  for (const g of to.groupRoles) {
    const prev = fromIdx.get(g.group);
    if (prev === undefined) continue;
    if (gRole(prev) !== gRole(g)) {
      changes.push({ kind: "changed", area: "group-role", text: `group ${g.group}: ${gRole(prev)} -> ${gRole(g)}` });
    }
  }
  return changes;
}

function diffCustomRoles(from: ConfigSnapshot, to: ConfigSnapshot): ConfigChange[] {
  const changes: ConfigChange[] = [];
  const fromIdx = indexBy(from.customRoles, (c) => c.name);
  const toIdx = indexBy(to.customRoles, (c) => c.name);
  // The display name a console shows is the label; the diff leads with it (falling back to the name).
  const disp = (c: ConfigCustomRole): string => c.label || c.name;
  for (const c of to.customRoles) {
    if (!fromIdx.has(c.name)) changes.push({ kind: "added", area: "custom-role", text: `custom role ${disp(c)} created` });
  }
  for (const c of from.customRoles) {
    if (!toIdx.has(c.name)) changes.push({ kind: "removed", area: "custom-role", text: `custom role ${disp(c)} deleted` });
  }
  for (const c of to.customRoles) {
    const prev = fromIdx.get(c.name);
    if (prev === undefined) continue;
    const caps = setDiff(prev.capabilities, c.capabilities);
    if (caps.added.length || caps.removed.length) {
      changes.push({ kind: "changed", area: "custom-role", text: `custom role ${disp(c)}: ${joinPlus(caps.added, caps.removed)}` });
    }
    if (prev.presentation !== c.presentation) {
      changes.push({ kind: "changed", area: "custom-role", text: `custom role ${disp(c)} presentation ${prev.presentation} -> ${c.presentation}` });
    }
    if (prev.landing !== c.landing) {
      changes.push({ kind: "changed", area: "custom-role", text: `custom role ${disp(c)} landing ${prev.landing} -> ${c.landing}` });
    }
    // Surface (per-screen visibility) changes, rendered screen by screen.
    const prevSurface = indexBy(prev.surface, (s) => s.screen);
    const toSurface = indexBy(c.surface, (s) => s.screen);
    for (const s of c.surface) {
      const was = prevSurface.get(s.screen);
      if (was === undefined) changes.push({ kind: "changed", area: "custom-role", text: `custom role ${disp(c)} screen ${s.screen} ${s.mode}` });
      else if (was.mode !== s.mode) changes.push({ kind: "changed", area: "custom-role", text: `custom role ${disp(c)} screen ${s.screen} ${was.mode} -> ${s.mode}` });
    }
    for (const s of prev.surface) {
      if (!toSurface.has(s.screen)) changes.push({ kind: "changed", area: "custom-role", text: `custom role ${disp(c)} screen ${s.screen} reset` });
    }
  }
  return changes;
}

function diffNotifyChannels(from: ConfigSnapshot, to: ConfigSnapshot): ConfigChange[] {
  const changes: ConfigChange[] = [];
  const fromIdx = indexBy(from.notifyChannels, (c) => c.id);
  const toIdx = indexBy(to.notifyChannels, (c) => c.id);
  for (const c of to.notifyChannels) {
    if (!fromIdx.has(c.id)) changes.push({ kind: "added", area: "notify-channel", text: `notify channel ${c.name} (${c.kind}) added` });
  }
  for (const c of from.notifyChannels) {
    if (!toIdx.has(c.id)) changes.push({ kind: "removed", area: "notify-channel", text: `notify channel ${c.name} (${c.kind}) removed` });
  }
  for (const c of to.notifyChannels) {
    const prev = fromIdx.get(c.id);
    if (prev === undefined) continue;
    if (prev.enabled !== c.enabled) changes.push({ kind: "changed", area: "notify-channel", text: `notify channel ${c.name} ${c.enabled ? "enabled" : "disabled"}` });
    // The url is redacted to urlConfigured/urlHost (config-snapshot.ts); compare those, never a raw url.
    if (prev.urlConfigured !== c.urlConfigured || prev.urlHost !== c.urlHost) changes.push({ kind: "changed", area: "notify-channel", text: `notify channel ${c.name} endpoint changed` });
    const addr = setDiff(prev.toAddresses, c.toAddresses);
    if (addr.added.length || addr.removed.length) changes.push({ kind: "changed", area: "notify-channel", text: `notify channel ${c.name} recipients ${joinPlus(addr.added, addr.removed)}` });
    if (prev.routingKeyConfigured !== c.routingKeyConfigured) changes.push({ kind: "changed", area: "notify-channel", text: `notify channel ${c.name} routing key ${c.routingKeyConfigured ? "configured" : "cleared"}` });
  }
  return changes;
}

function diffNotifyRules(from: ConfigSnapshot, to: ConfigSnapshot): ConfigChange[] {
  const changes: ConfigChange[] = [];
  const fromIdx = indexBy(from.notifyRules, (r) => r.id);
  const toIdx = indexBy(to.notifyRules, (r) => r.id);
  for (const r of to.notifyRules) {
    if (!fromIdx.has(r.id)) changes.push({ kind: "added", area: "notify-rule", text: `notify rule (${r.scope}, ${r.minSeverity}+) added` });
  }
  for (const r of from.notifyRules) {
    if (!toIdx.has(r.id)) changes.push({ kind: "removed", area: "notify-rule", text: `notify rule (${r.scope}, ${r.minSeverity}+) removed` });
  }
  for (const r of to.notifyRules) {
    const prev = fromIdx.get(r.id);
    if (prev === undefined) continue;
    if (prev.enabled !== r.enabled) changes.push({ kind: "changed", area: "notify-rule", text: `notify rule ${r.scope} ${r.enabled ? "enabled" : "disabled"}` });
    if (prev.minSeverity !== r.minSeverity) changes.push({ kind: "changed", area: "notify-rule", text: `notify rule ${r.scope} severity ${prev.minSeverity} -> ${r.minSeverity}` });
    if (prev.digest !== r.digest) changes.push({ kind: "changed", area: "notify-rule", text: `notify rule ${r.scope} digest ${prev.digest} -> ${r.digest}` });
    const ev = setDiff(prev.events, r.events);
    if (ev.added.length || ev.removed.length) changes.push({ kind: "changed", area: "notify-rule", text: `notify rule ${r.scope} events ${joinPlus(ev.added, ev.removed)}` });
    const ch = setDiff(prev.channelIds, r.channelIds);
    if (ch.added.length || ch.removed.length) changes.push({ kind: "changed", area: "notify-rule", text: `notify rule ${r.scope} channels ${joinPlus(ch.added, ch.removed)}` });
  }
  return changes;
}

function diffRiskAccepts(from: ConfigSnapshot, to: ConfigSnapshot): ConfigChange[] {
  const changes: ConfigChange[] = [];
  const fromIdx = indexBy(from.riskAccepts, (a) => a.checkId);
  const toIdx = indexBy(to.riskAccepts, (a) => a.checkId);
  // An absent kind is a pre-override-kinds record; it reads as the legacy risk-accepted everywhere.
  const kindOf = (a: { kind?: string }): string => a.kind ?? "risk-accepted";
  for (const a of to.riskAccepts) {
    if (!fromIdx.has(a.checkId)) changes.push({ kind: "added", area: "risk-accept", text: `override (${kindOf(a)}) recorded for ${a.checkId}` });
  }
  for (const a of from.riskAccepts) {
    if (!toIdx.has(a.checkId)) changes.push({ kind: "removed", area: "risk-accept", text: `override (${kindOf(a)}) withdrawn for ${a.checkId}` });
  }
  for (const a of to.riskAccepts) {
    const prev = fromIdx.get(a.checkId);
    if (prev === undefined) continue;
    if (kindOf(prev) !== kindOf(a)) changes.push({ kind: "changed", area: "risk-accept", text: `override kind changed for ${a.checkId} (${kindOf(prev)} -> ${kindOf(a)})` });
    else if (prev.reason !== a.reason) changes.push({ kind: "changed", area: "risk-accept", text: `override reason updated for ${a.checkId}` });
  }
  return changes;
}

function diffExpiryItems(from: ConfigSnapshot, to: ConfigSnapshot): ConfigChange[] {
  const changes: ConfigChange[] = [];
  const fromIdx = indexBy(from.expiryItems ?? [], (e) => e.id);
  const toIdx = indexBy(to.expiryItems ?? [], (e) => e.id);
  const label = (e: ConfigExpiryItem): string => e.label || e.id;
  const expOf = (e: ConfigExpiryItem): string => e.expiresAt ?? "no expiry";
  for (const e of to.expiryItems ?? []) {
    if (!fromIdx.has(e.id)) changes.push({ kind: "added", area: "expiry", text: `tracked expiry ${label(e)} (${e.kind}) added, expires ${expOf(e)}` });
  }
  for (const e of from.expiryItems ?? []) {
    if (!toIdx.has(e.id)) changes.push({ kind: "removed", area: "expiry", text: `tracked expiry ${label(e)} removed` });
  }
  for (const e of to.expiryItems ?? []) {
    const prev = fromIdx.get(e.id);
    if (prev === undefined) continue;
    if (prev.expiresAt !== e.expiresAt) changes.push({ kind: "changed", area: "expiry", text: `tracked expiry ${label(e)} expiry ${expOf(prev)} -> ${expOf(e)}` });
    if (prev.label !== e.label) changes.push({ kind: "changed", area: "expiry", text: `tracked expiry ${prev.label || prev.id} renamed to ${e.label || e.id}` });
    if (prev.kind !== e.kind) changes.push({ kind: "changed", area: "expiry", text: `tracked expiry ${label(e)} kind ${prev.kind} -> ${e.kind}` });
  }
  return changes;
}

function diffCoverage(from: ConfigSnapshot, to: ConfigSnapshot): ConfigChange[] {
  const fromCov = from.coverage;
  const toCov = to.coverage;
  if (fromCov === undefined && toCov !== undefined) {
    return [{ kind: "added", area: "coverage", text: "coverage inventory imported" }];
  }
  if (fromCov !== undefined && toCov === undefined) {
    return [{ kind: "removed", area: "coverage", text: "coverage inventory cleared" }];
  }
  if (fromCov === undefined || toCov === undefined) return [];
  const changes: ConfigChange[] = [];
  const groups: Array<keyof ConfigCoverageInventory> = ["kv", "r2", "d1", "secrets"];
  for (const g of groups) {
    const d = setDiff(fromCov[g].map((x) => x.id), toCov[g].map((x) => x.id));
    if (d.added.length || d.removed.length) {
      changes.push({ kind: "changed", area: "coverage", text: `coverage ${g} ${joinPlus(d.added, d.removed)}` });
    }
  }
  return changes;
}

export function diffConfig(from: ConfigSnapshot, to: ConfigSnapshot): ConfigChange[] {
  return [
    ...diffDownpipes(from, to),
    ...diffRoles(from, to),
    ...diffGroupRoles(from, to),
    ...diffCustomRoles(from, to),
    ...diffNotifyChannels(from, to),
    ...diffNotifyRules(from, to),
    ...diffRiskAccepts(from, to),
    ...diffExpiryItems(from, to),
    ...diffCoverage(from, to),
  ];
}

// summarise builds the short auto-summary stamped on a version from the diff against its parent. It is a
// redaction-safe one-liner: the first few change texts joined with "; ", with a "(+N more)" suffix when
// there are more, or a fixed note when there is no parent (the genesis version) or no detectable change
// (a manual snapshot of an unchanged posture, though the de-dupe normally prevents storing that). The
// cap keeps the summary a single readable line and the stored record small.
export const SUMMARY_MAX_CHANGES = 4;

export function summarise(changes: ConfigChange[], isGenesis: boolean): string {
  if (isGenesis) return "initial configuration snapshot";
  if (changes.length === 0) return "no configuration change";
  const shown = changes.slice(0, SUMMARY_MAX_CHANGES).map((c) => c.text);
  const extra = changes.length - shown.length;
  return shown.join("; ") + (extra > 0 ? ` (+${extra} more)` : "");
}
