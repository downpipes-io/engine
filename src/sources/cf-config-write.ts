// The diff-driven restore WRITE specs for the cf-config source surface registry (cf-config-surfaces.ts).
// zone-settings restores by PATCHing each changed setting; the other high-value IDEMPOTENT surfaces are
// LISTS of items (DNS records, page rules, firewall access rules, ruleset rules), so their diff-driven
// restore is the SAME shape one level up (read current live, match to the snapshot by a stable identity,
// apply only the differences). writeList is the shared engine; the per-surface specs (writeDns, etc.) are
// the only surface-specific write code. Everything here was MOVED VERBATIM out of cf-config-surfaces.ts to
// keep that module a readable size; the behaviour is unchanged. The registry (cf-config-surfaces.ts)
// imports these write functions; this module imports the core types/paginate and the shared helpers, so
// there is no cycle.
//
// Node 25 strip-types compatible: no enums, explicit declarations.

import type { Meter } from "../meter.ts";
import { type CfApi, type CfConfigSurface, type CfScope, type ConfigWriteResult, type Ids, paginate, paginateAdaptive, RULESETS_PER_PAGE } from "./cf-config-core.ts";
import { classifyCfWriteSkip } from "./cf-config-fault.ts";
import { asJson, type ConfigChange, isPlainObject, jsonEqual, naturalKey, stripStamped } from "./cf-config-shared.ts";

// LIST WRITE-BACK (SRC-5) -----------------------------------------------------------------------
// zone-settings restores by PATCHing each changed setting. The other high-value IDEMPOTENT surfaces
// are LISTS of items (DNS records, page rules, firewall access rules, ruleset rules), so their
// diff-driven restore is the SAME shape, one level up: read the CURRENT live list, match items to
// the snapshot by a STABLE identity, and apply only the differences,
//   - a snapshot item with NO live match           -> CREATE  (POST)
//   - a snapshot item whose live match has CHANGED  -> UPDATE  (PUT / PATCH the matched id)
//   - a snapshot item identical to its live match   -> SKIP    (never touched)
// SAFETY CONTRACT (identical to zone-settings):
//   * NEVER a blind wholesale overwrite, we never PUT the whole collection; each item is created or
//     updated on its own, so one item the API rejects skips ITSELF, not the rest.
//   * ADDITIVE by default: a LIVE item the snapshot does NOT mention is LEFT ALONE, we do NOT prune
//     live extras. Deleting live records the backup happens not to contain is destructive and is NOT
//     idempotent-restore semantics, so it is deliberately omitted (a future "mirror exactly" mode
//     would be an explicit opt-in, never the default). pruneExtras stays false here.
//   * Idempotent: re-running a restore converges (unchanged items skip), and matching by NATURAL key
//     (not just the server id, which a fresh zone will not have) means a re-run does not duplicate.
// Each new write() is gated by the surface's restoreTier === "idempotent"; ordered/reprovision
// surfaces (certs, members/roles, service tokens, load balancers) keep NO write, they stay backup +
// diff-preview only, because they need dependency-ordered create / id-remap / write-only re-provision
// that a flat item-by-item apply cannot do safely.

// ListWriteSpec describes how ONE list surface applies: how to identify an item, how to read/create/
// update it, and how to shape the request body. It is the only per-surface code; writeList is shared.
export interface ListWriteSpec {
  // readLive overrides how the writer reads CURRENT live state.
  //
  // By default writeListSpec paginates listPath itself, which assumes the surface's read is the same plain
  // list. When a surface ENRICHES its read (a sub-read, a non-standard envelope, a different page cap) the
  // two views diverge, and the writer then diffs a snapshot of one shape against a live view of another.
  // gateway-lists showed exactly this: its read sub-reads each list's items, the writer's own read did not,
  // so live came back with no `items` at all, every list looked changed on every run, and the nested guard
  // could not see the entries it exists to protect. Neither the round trip nor the diff looked wrong; the
  // restore worked and simply never converged.
  //
  // A surface whose read is enriched must pass the same reader here, so the writer diffs like against like.
  readLive?(api: CfApi, ids: Ids, meter?: Meter): Promise<unknown[]>;
  // nestedCollections names fields on an item that are COLLECTIONS of their own, so an update that sends
  // the whole item replaces them wholesale. Declared per surface rather than inferred: guessing which
  // array field is a collection rather than an ordinary value would refuse restores for the wrong reason.
  nestedCollections?: readonly string[];
  // listPath builds the collection path (read-current + the POST create target).
  listPath(ids: Ids): string;
  // itemPath builds a single item's path (the PUT/PATCH update target) from the item's server id.
  itemPath(ids: Ids, id: string): string;
  // identity returns a STABLE key for an item so live and snapshot items match. It prefers the
  // server id but MUST fall back to a natural key (type+name+content, expression, target+value, ...)
  // so a snapshot whose ids are stale (a fresh zone) still matches and a re-run does not duplicate.
  identity(item: Record<string, unknown>): string;
  // natural returns the surface-specific NATURAL key: the field(s) that NAME this item independent of
  // its (possibly stale) server id and independent of its editable content, so a CHANGED item with a
  // stale id still matches its live counterpart (and is updated, not duplicated) and two DISTINCT
  // items never collide. It MUST be unique per logical item (e.g. DNS type|name, a firewall rule's
  // configuration, a page rule's targets), a too-coarse key would mis-match distinct items.
  natural(item: Record<string, unknown>): string;
  // serverId returns the LIVE item's id for the update path; "" if the item has none (then a changed
  // match cannot be updated in place and is reported skipped rather than blind-recreated).
  serverId(item: Record<string, unknown>): string;
  // createMethod / updateMethod let a surface pick POST vs PUT for create and PUT vs PATCH for update
  // (CF is not uniform: page rules update with PUT, ruleset rules PATCH, firewall access rules PATCH).
  createMethod: "POST" | "PUT";
  updateMethod: "PUT" | "PATCH";
  // body shapes the request payload from the snapshot item (strip server-stamped read-only fields).
  body(item: Record<string, unknown>): unknown;
  // label is the human path prefix used in ConfigChange.path / skipped reasons.
  label: string;
}

// writeList is the shared diff-driven apply for a list surface. It reads the CURRENT live list,
// indexes it by identity (server id AND natural key, so either matches), then for each snapshot item
// decides create / update / skip and, unless dryRun, applies it item by item, fail-open per item.
// It NEVER deletes a live extra (additive default) and NEVER PUTs the whole collection.
// ListOp is one decided create/update before the apply loop. Shared by buildListOps and applyListOps.
type ListOp = { kind: "create" | "update"; id?: string; item: Record<string, unknown>; path: string };

// indexLive builds the live lookups by BOTH server id and natural key, so a snapshot item matches
// whichever it shares. Natural key is the durable one across a fresh zone.
//
// A natural-key COLLISION (two live items sharing one natural key) is NOT safely resolved by keeping the
// first and treating the rest as missing-and-created: that claim holds only while the snapshot's server
// ids are still live. Once they are stale, which is precisely the restore-into-a-rebuilt-account case
// natural() exists to serve, keep-the-first binds a snapshot item to whichever twin Cloudflare happened to
// return first -- for example, two Zero Trust posture rules both named "Disk Encryption", one Windows and
// one macOS: a snapshot with stale ids could have the writer issue PUT .../live-A carrying the macOS
// criteria onto the WINDOWS rule, then create a duplicate, then report success, failing posture for every
// Windows device. Which of the two outcomes you get depends on Cloudflare's list ordering, which is not
// ours to control.
//
// So an ambiguous natural key is now tracked and REFUSED at the match site rather than guessed at. The
// duplicate-server-id case is refused wholesale for the same reason (see writeListSpec).
function indexLive(spec: ListWriteSpec, live: Array<Record<string, unknown>>): { byId: Map<string, Record<string, unknown>>; byNat: Map<string, Record<string, unknown>>; idCollision: boolean; ambiguousNat: Set<string> } {
  const byId = new Map<string, Record<string, unknown>>();
  const byNat = new Map<string, Record<string, unknown>>();
  // Natural keys shared by two or more LIVE items. A snapshot item matching one of these by natural key
  // alone cannot be resolved to a single live counterpart, so it must not be updated.
  const ambiguousNat = new Set<string>();
  // A DUPLICATE SERVER ID means the collection is not a flat set of independently addressable items,
  // and writeList's whole matching model assumes it is. Found live on dlp-entries, which returns the
  // same predefined entry once per profile with an identical id: Map.set would silently keep the LAST,
  // so a snapshot item could be matched against a different parent's copy of itself and updated in the
  // wrong place. That is the one failure mode this engine must never have, so it refuses the surface
  // rather than guessing. The natural-key collision below stays conservative (keep the FIRST, so at
  // worst an item is treated as missing and created), but an id collision has no safe fallback.
  let idCollision = false;
  for (const it of live) {
    if (!isPlainObject(it)) continue;
    const sid = spec.serverId(it);
    if (sid) {
      if (byId.has(sid)) idCollision = true;
      byId.set(sid, it);
    }
    const nat = spec.natural(it);
    if (byNat.has(nat)) ambiguousNat.add(nat);
    else byNat.set(nat, it);
  }
  return { byId, byNat, idCollision, ambiguousNat };
}

// buildListOps diffs each snapshot item against the live index and decides create / update / skip,
// returning the preview changes and the ops to apply. It NEVER deletes a live extra (additive default),
// but it MUST REPORT one.
//
// F9: a LIVE item the snapshot does not contain MUST produce a "remove" change (summariseDiff renders it
// as "N live-only (left in place)"), never silence. Without it, a restore run to recover FROM an attack
// would leave an attacker-added DNS record, page rule, or a firewall rule with mode "whitelist" in place
// and still report success. It matters most on the allow-list surfaces, where the added entry IS the
// attack.
//
// The fix reports, it does not delete. Deleting a live extra by default would be the worse defect: a
// record the customer legitimately added after the backup is not rubbish to be swept up. Pruning, if
// it is ever wanted, is an explicit per-surface opt-in that names every item it would remove.
function buildListOps(spec: ListWriteSpec, liveById: Map<string, Record<string, unknown>>, liveByNat: Map<string, Record<string, unknown>>, snapshot: Array<Record<string, unknown>>, live: Array<Record<string, unknown>>, ambiguousNat: Set<string>): { changes: ConfigChange[]; ops: ListOp[]; skippedAmbiguous: ConfigWriteResult["skipped"] } {
  const changes: ConfigChange[] = [];
  const ops: ListOp[] = [];
  const skippedAmbiguous: ConfigWriteResult["skipped"] = [];
  // Track which live items a snapshot item has already claimed so two snapshot items cannot both
  // match (and double-update) the same live item via the natural key.
  const claimed = new Set<Record<string, unknown>>();
  for (const snap of snapshot) {
    const sid = spec.serverId(snap);
    const byId = sid ? liveById.get(sid) : undefined;
    const nat = spec.natural(snap);
    const byNat = liveByNat.get(nat);
    const idMatch = byId && !claimed.has(byId) ? byId : undefined;
    const natMatch = byNat && !claimed.has(byNat) ? byNat : undefined;
    const path = `${spec.label}/${spec.identity(snap)}`;
    // An AMBIGUOUS natural key can only be trusted when the server id also matched. Falling back to it
    // alone would bind this item to whichever twin the API listed first, which is how a macOS posture
    // rule ends up overwriting the Windows one. Refuse and say so; never guess which twin was meant.
    if (idMatch === undefined && natMatch !== undefined && ambiguousNat.has(nat)) {
      skippedAmbiguous.push({ path, reason: "two or more live items share this item's identifying fields, so the snapshot cannot be matched to one of them; restore this surface out of band", cls: "conflict" });
      continue;
    }
    const match = idMatch ?? natMatch;
    if (match) claimed.add(match);
    if (!match) {
      changes.push({ path, action: "add", from: "", to: asJson(stripStamped(snap)) });
      ops.push({ kind: "create", item: snap, path });
      continue;
    }
    // Compare the writable shape only (server-stamped fields ignored): unchanged -> skip.
    if (jsonEqual(normaliseItem(spec, match), normaliseItem(spec, snap))) continue;
    const lostNested = nestedLiveOnly(spec, match, snap);
    if (lostNested.length > 0) {
      // NAME each entry. Reporting "the list had 5 entries and will have 3" is a count, and a count cannot
      // be reviewed, which is the same reason F9 names removals rather than tallying them.
      for (const { field, entries } of lostNested) {
        for (const e of entries) changes.push({ path: `${path}/${field}/${entryIdentity(e)}`, action: "remove", from: asJson(e), to: "" });
      }
      const total = lostNested.reduce((n, x) => n + x.entries.length, 0);
      skippedAmbiguous.push({
        path,
        reason: `${total} live entr(y/ies) in ${lostNested.map((x) => x.field).join(", ")} are not in the snapshot; updating this item would replace the collection and delete them, and restore is additive. They are named in the diff`,
        cls: "live-only-rules",
      });
      continue;
    }
    const liveId = spec.serverId(match);
    changes.push({ path, action: "change", from: asJson(normaliseItem(spec, match)), to: asJson(normaliseItem(spec, snap)) });
    ops.push({ kind: "update", id: liveId, item: snap, path });
  }
  // F9: every live item no snapshot item claimed is reported as a "remove" change, which summariseDiff
  // renders as "live-only (left in place)". NO op is queued for it, so the additive contract is intact:
  // this is a report, not a deletion. `claimed` holds object references from the same `live` array, so
  // identity membership is exact and an item matched by server id or by natural key is not re-reported.
  for (const it of live) {
    if (!isPlainObject(it) || claimed.has(it)) continue;
    changes.push({ path: `${spec.label}/${spec.identity(it)}`, action: "remove", from: asJson(stripStamped(it)), to: "" });
  }
  return { changes, ops, skippedAmbiguous };
}

// entryIdentity is the identity of ONE ENTRY inside a collection: a rule inside a ruleset, a value inside
// a Gateway list. It has to survive an EDIT, which is why it is not the entry's content: content matching
// makes an edited entry look like a different one, so an ordinary change reads as "the live entry is not
// in the snapshot" and the writer refuses the restore it exists to perform. Two existing tests caught that
// the first time it was written for rulesets.
//
// `value` is in the chain for Gateway list entries, whose whole content IS their value. The final fallback
// is the stripped entry, which is the conservative direction: an entry with no identifying field is
// treated as live-only unless something byte-identical is in the snapshot, so the writer refuses rather
// than deletes.
function entryIdentity(r: unknown): string {
  if (!isPlainObject(r)) return JSON.stringify(r);
  for (const f of ["ref", "id", "description", "value"]) {
    const v = r[f];
    if (typeof v === "string" && v !== "") return `${f}=${v}`;
  }
  return JSON.stringify(stripStamped(r));
}

// normaliseItem is stripStamped, but it also reaches INSIDE a declared nested collection.
//
// IT IS NOT WHAT MAKES A NESTED SURFACE CONVERGE. jsonEqual already skips SKIP_IN_DIFF fields RECURSIVELY
// at every depth, so a Gateway list entry's created_at never affects the comparison; what makes a nested
// surface converge is `readLive`, which must read live the same way the surface's own read does, or live
// would have no `items` key at all and the snapshot's extra key would make every list differ forever.
//
// What this DOES do is keep the request body and the rendered diff clean: without it a restore sends each
// entry's created_at back to Cloudflare and the preview renders timestamps the apply would never change.
// Both are worth having, neither is the convergence fix.
export function normaliseItem(spec: ListWriteSpec, item: Record<string, unknown>): Record<string, unknown> {
  const out = stripStamped(item);
  // Drop whichever field holds this item's OWN server id. stripStamped removes `id`, which covers most
  // collections; device-managed-networks keys on `network_id`, which is equally server-assigned, so a
  // restored object carried a NEW one, never equalled its snapshot, and the writer re-applied it on every
  // run. The spec already knows which value addresses the item, so the field is found by matching that
  // value rather than by guessing at names: every *_id is NOT dropped, because subnet_id on a device IP
  // profile is a reference to another object and is real configuration.
  // serverId is optional here on purpose: generatedWriter also calls this with a partial spec carrying only
  // nestedCollections, to normalise a request BODY. Requiring the function threw "spec.serverId is not a
  // function" for every generated writer at once, which is at least a loud failure rather than a quiet one.
  // Drop the item's OWN address field. Matching BY VALUE instead would delete every field that happens to
  // hold the same string, which is only harmless while the address is always an opaque server id: a uuid
  // does not collide with a url or a description, but a surface addressed by a human-chosen field is not so
  // lucky (a custom page asset whose description equalled its name would have the description silently
  // dropped from the update body). So delete the FIELD the address was resolved from, which the spec knows,
  // rather than every field that looks like it.
  const own = typeof spec.serverId === "function" ? spec.serverId(item) : "";
  if (own !== "") {
    const field = Object.keys(out).find((k) => out[k] === own);
    if (field !== undefined) delete out[field];
  }
  for (const f of spec.nestedCollections ?? []) {
    const arr = out[f];
    if (Array.isArray(arr)) out[f] = arr.map((e) => (isPlainObject(e) ? stripStamped(e) : e));
  }
  return out;
}

// nestedLiveOnly reports the entries a NESTED collection would lose if this item were updated.
//
// writeListSpec never deletes an ITEM: applyListOps only creates and updates, and F9 reports live-only
// items without queueing an op. But an update sends the whole item, so a collection nested INSIDE an item
// is replaced wholesale, and any entry the snapshot lacks is deleted with it. That is B3's shape one level
// down, and it is why the gateway-lists writer was removed rather than repaired when its read was fixed:
// PUT /gateway/lists/{id} carrying four items leaves exactly those four, confirmed against the live API.
//
// Only surfaces that DECLARE a nested collection are checked. Most items have none, and guessing which
// array field is a collection rather than an ordinary value would refuse restores for the wrong reason.
function nestedLiveOnly(
  spec: ListWriteSpec,
  live: Record<string, unknown>,
  snap: Record<string, unknown>,
): Array<{ field: string; entries: unknown[] }> {
  const out: Array<{ field: string; entries: unknown[] }> = [];
  for (const field of spec.nestedCollections ?? []) {
    const liveArr = live[field];
    const snapArr = snap[field];
    // An ABSENT snapshot array is not an empty one. It means the capture did not read that collection, and
    // treating it as empty would report every live entry as a loss and refuse every restore.
    if (!Array.isArray(liveArr) || !Array.isArray(snapArr)) continue;
    const known = new Set(snapArr.map(entryIdentity));
    const lost = liveArr.filter((e) => !known.has(entryIdentity(e)));
    if (lost.length > 0) out.push({ field, entries: lost });
  }
  return out;
}

// applyListOps runs the create/update ops item by item, fail-open per item, returning the applied count
// and the skipped list. It NEVER PUTs the whole collection; one item the API rejects skips ITSELF.
async function applyListOps(spec: ListWriteSpec, api: CfApi, ids: Ids, ops: ListOp[], meter?: Meter): Promise<{ applied: number; skipped: ConfigWriteResult["skipped"] }> {
  const skipped: ConfigWriteResult["skipped"] = [];
  let applied = 0;
  for (const op of ops) {
    try {
      if (op.kind === "update") {
        if (!op.id) { skipped.push({ path: op.path, reason: "changed but the live item has no id to update in place", cls: "no-live-id" }); continue; }
        meter?.spend(1);
        await api.send(spec.updateMethod, spec.itemPath(ids, op.id), spec.body(op.item));
      } else {
        meter?.spend(1);
        await api.send(spec.createMethod, spec.listPath(ids), spec.body(op.item));
      }
      applied++;
    } catch (e) {
      // G191: classify the refusal HERE, at the only site that ever holds the exception. The 120-char text
      // still rides to the operator's live response; the CLASS is what a support pack can carry.
      skipped.push({ path: op.path, reason: (e as Error).message.replace(/^Cloudflare API [A-Z]+ [^:]+:\s*/, "").slice(0, 120), cls: classifyCfWriteSkip(e) });
    }
  }
  return { applied, skipped };
}

// writeListSpec is writeList exposed for the generated table in cf-config-write-generated.ts. Same
// engine, same safety contract; the only difference is that the caller supplies the spec as data.
export async function writeListSpec(
  spec: ListWriteSpec,
  api: CfApi,
  ids: Ids,
  data: unknown,
  opts: { dryRun: boolean },
  meter?: Meter,
): Promise<ConfigWriteResult> {
  // Read current live items (paginated, so a large live list is fully seen, a partial read could
  // wrongly classify an existing item as "missing" and re-create a duplicate).
  // paginateAdaptive, not paginate: Cloudflare's page-size ceiling varies per collection and this one
  // function lists all of them. See its comment for why the ceiling is discovered rather than tabulated.
  const live = (spec.readLive !== undefined
    ? await spec.readLive(api, ids, meter)
    : await paginateAdaptive(api, spec.listPath(ids), meter)) as Array<Record<string, unknown>>;
  const { byId, byNat, idCollision, ambiguousNat } = indexLive(spec, live);
  if (idCollision) {
    // Refuse the whole surface, loudly and without writing. Reported as a skip so it reaches the operator
    // through the same path as every other refusal rather than throwing into a generic restore error.
    return { changes: [], applied: 0, skipped: [{ path: spec.label, reason: "this collection returns duplicate server ids, so an item cannot be matched to its live counterpart safely; restore it out of band", cls: "conflict" }] };
  }
  const snapshot = (Array.isArray(data) ? data : []).filter(isPlainObject) as Array<Record<string, unknown>>;
  const { changes, ops, skippedAmbiguous } = buildListOps(spec, byId, byNat, snapshot, live, ambiguousNat);
  if (opts.dryRun) return { changes, applied: 0, skipped: skippedAmbiguous };
  const { applied, skipped } = await applyListOps(spec, api, ids, ops, meter);
  return { changes, applied, skipped: [...skippedAmbiguous, ...skipped] };
}

// ---- per-surface write specs (the only surface-specific write code) ----
// DNS records: identity = id, natural key = type|name|content; create POST, update PUT (CF DNS
// updates with a full PUT to /dns_records/{id}). proxied/ttl/priority ride in the body.
export function writeDns(api: CfApi, ids: Ids, data: unknown, opts: { dryRun: boolean }, meter?: Meter): Promise<ConfigWriteResult> {
  return writeListSpec({
    listPath: (i) => `/zones/${i.zoneId}/dns_records`,
    itemPath: (i, id) => `/zones/${i.zoneId}/dns_records/${id}`,
    identity: (it) => (typeof it.id === "string" ? it.id : naturalKey(it)),
    serverId: (it) => (typeof it.id === "string" ? it.id : ""),
    // A DNS record is NAMED by type+name (its content/proxied/ttl are the editable parts). For record
    // types where multiple records share a type+name (A/AAAA/MX/TXT round-robin sets), the content is
    // part of the identity too, so a changed-content record correctly reads as a NEW record (additive)
    // rather than silently overwriting a sibling, safer than collapsing a round-robin set.
    natural: (it) => `dns:${JSON.stringify({ type: it.type, name: it.name, content: it.content })}`,
    createMethod: "POST",
    updateMethod: "PUT",
    body: (it) => stripStamped(it),
    label: "dns",
  }, api, ids, data, opts, meter);
}
// Page rules: identity = id, natural key falls back to the targets/actions; create POST, update PUT
// (the Page Rules API replaces a rule with PUT /pagerules/{id}).
export function writePageRules(api: CfApi, ids: Ids, data: unknown, opts: { dryRun: boolean }, meter?: Meter): Promise<ConfigWriteResult> {
  return writeListSpec({
    listPath: (i) => `/zones/${i.zoneId}/pagerules`,
    itemPath: (i, id) => `/zones/${i.zoneId}/pagerules/${id}`,
    identity: (it) => (typeof it.id === "string" ? it.id : naturalKey(it)),
    serverId: (it) => (typeof it.id === "string" ? it.id : ""),
    // A page rule is NAMED by its targets (the URL pattern it matches); its actions/status/priority
    // are editable. So a target-set match with changed actions is an UPDATE, not a duplicate.
    natural: (it) => `pr:${JSON.stringify(it.targets ?? null)}`,
    createMethod: "POST",
    updateMethod: "PUT",
    body: (it) => stripStamped(it),
    label: "page-rules",
  }, api, ids, data, opts, meter);
}
// Account rule lists (the IP / ASN / hostname lists that WAF and Gateway rules reference by name).
// A dangling list reference breaks every rule that points at it, so the list itself is worth restoring
// even though its ITEMS are a separate collection.
//
// The natural key is the NAME. Cloudflare enforces name uniqueness per account for rule lists, so the
// key cannot collide, which is the property `indexLive` depends on. `kind` is deliberately NOT in the key: kind is immutable
// after creation, so a name match with a different kind is a genuine conflict that the API should
// refuse loudly rather than something this writer should paper over by treating it as a new list.
//
// PROVEN by test/live-cf-roundtrip.ts: created, captured, DELETED, restored, and re-run to confirm the
// name key matched rather than duplicating.
export function writeAccountRuleLists(api: CfApi, ids: Ids, data: unknown, opts: { dryRun: boolean }, meter?: Meter): Promise<ConfigWriteResult> {
  return writeListSpec({
    listPath: (i) => `/accounts/${i.accountId}/rules/lists`,
    itemPath: (i, id) => `/accounts/${i.accountId}/rules/lists/${id}`,
    identity: (it) => (typeof it.id === "string" ? it.id : naturalKey(it)),
    serverId: (it) => (typeof it.id === "string" ? it.id : ""),
    natural: (it) => `rulelist:${String(it.name ?? "")}`,
    createMethod: "POST",
    // Cloudflare edits a rule list with PUT /rules/lists/{id}, and the editable part is the description.
    updateMethod: "PUT",
    // `kind` is immutable after creation and `num_items` / `num_referencing_filters` are server-computed,
    // so sending them back is at best noise and at worst a validation refusal on an otherwise fine update.
    body: (it) => {
      const b = stripStamped(it) as Record<string, unknown>;
      delete b.num_items;
      delete b.num_referencing_filters;
      return b;
    },
    label: "account-rule-lists",
  }, api, ids, data, opts, meter);
}
// Firewall access rules (zone or account): identity = id, natural key = mode|configuration; create
// POST, update PATCH (the access-rules API edits with PATCH /firewall/access_rules/rules/{id}).
export function writeFirewallAccessRules(scope: CfScope): NonNullable<CfConfigSurface["write"]> {
  const base = (i: Ids) => (scope === "zone" ? `/zones/${i.zoneId}` : `/accounts/${i.accountId}`);
  return (api, ids, data, opts, meter) =>
    writeListSpec({
      listPath: (i) => `${base(i)}/firewall/access_rules/rules`,
      itemPath: (i, id) => `${base(i)}/firewall/access_rules/rules/${id}`,
      identity: (it) => (typeof it.id === "string" ? it.id : naturalKey(it)),
      serverId: (it) => (typeof it.id === "string" ? it.id : ""),
      // A firewall access rule is NAMED by its configuration {target,value} (e.g. ip=1.2.3.4); its
      // mode (block/challenge/whitelist) and notes are editable. So a same-target rule with a changed
      // mode is an UPDATE, and two rules for different targets never collide.
      natural: (it) => `far:${JSON.stringify(it.configuration ?? null)}`,
      createMethod: "POST",
      updateMethod: "PATCH",
      body: (it) => {
        // An access rule writes { mode, notes, configuration:{target,value} }. Send only those.
        const s = stripStamped(it);
        const out: Record<string, unknown> = {};
        for (const k of ["mode", "notes", "configuration"]) if (s[k] !== undefined) out[k] = s[k];
        return out;
      },
      label: scope === "zone" ? "firewall-access-rules" : "account-firewall-access-rules",
    }, api, ids, data, opts, meter);
}
// WAF / rulesets (zone or account): the snapshot is the ARRAY of expanded rulesets (each with its
// rules). The entrypoint/managed phase rulesets ALREADY EXIST on a zone (they cannot be created), so
// the idempotent write updates each ruleset's RULES in place via PUT /rulesets/{id} (the Rulesets API
// replaces a ruleset's rule list with a single PUT of { rules }, which IS that surface's idempotent
// semantics, not a blind whole-account overwrite; each ruleset is addressed by its own id). A
// snapshot ruleset whose id is not live is reported (CREATE of a phase entrypoint needs the phase, a
// reprovision concern) and skipped rather than blind-created. Live rulesets the snapshot omits are
// left untouched. matched by ruleset id (rulesets carry a stable id) or by phase as the natural key.
// RulesetOp is one decided ruleset rule-list PUT before the apply loop.
type RulesetOp = { id: string; rules: unknown; path: string };

// indexLiveRulesets builds the live ruleset lookups by id and by phase (the durable key across a zone).
function indexLiveRulesets(liveIndex: Array<Record<string, unknown>>): { byId: Map<string, Record<string, unknown>>; byPhase: Map<string, Record<string, unknown>> } {
  const byId = new Map<string, Record<string, unknown>>();
  const byPhase = new Map<string, Record<string, unknown>>();
  for (const rs of liveIndex) {
    if (!isPlainObject(rs)) continue;
    if (typeof rs.id === "string") byId.set(rs.id, rs);
    if (typeof rs.phase === "string") byPhase.set(rs.phase, rs);
  }
  return { byId, byPhase };
}

// diffOneRuleset matches one snapshot ruleset to a live one, expands the live rule list, and decides
// whether it changed. It pushes the preview change and, when applicable, the apply op. A snapshot
// ruleset with no live match is reported as an add but never blind-created (reprovision concern).
async function diffOneRuleset(api: CfApi, rulesBase: string, labelOf: string, snap: Record<string, unknown>, liveById: Map<string, Record<string, unknown>>, liveByPhase: Map<string, Record<string, unknown>>, dryRun: boolean, changes: ConfigChange[], ops: RulesetOp[], skipped: ConfigWriteResult["skipped"], meter?: Meter): Promise<void> {
  const sid = typeof snap.id === "string" ? snap.id : "";
  const phase = typeof snap.phase === "string" ? snap.phase : "";
  const path = `${labelOf}/${phase || sid || "?"}`;
  // Match the snapshot ruleset to a live one by id, else by phase (the durable key across a zone).
  const liveRs = (sid && liveById.get(sid)) || (phase && liveByPhase.get(phase));
  if (!liveRs || typeof liveRs.id !== "string") {
    // No live ruleset for this phase: creating a phase entrypoint is a reprovision concern, not a
    // flat idempotent apply. Report it as an add in the preview, but never blind-create it.
    changes.push({ path, action: "add", from: "", to: asJson({ phase, rules: (snap.rules as unknown[])?.length ?? 0 }) });
    if (!dryRun) skipped.push({ path, reason: "no live ruleset for this phase; create the entrypoint out of band (reprovision)", cls: "no-live-phase" });
    return;
  }
  // The ruleset INDEX entry usually omits the rules; fetch the FULL live ruleset by id so we diff
  // its real rule list (a missing expansion would wrongly read live as empty and re-PUT every
  // ruleset). One metered GET per matched ruleset (unmatched ones cost nothing).
  let liveFull = liveRs;
  if (!Array.isArray(liveRs.rules)) {
    meter?.spend(1);
    const full = (await api.get(`${rulesBase}/${liveRs.id}`)) as Record<string, unknown> | null;
    if (isPlainObject(full)) liveFull = full;
  }
  // Both have rules; diff the rule arrays (server-stamped fields ignored). Unchanged -> skip.
  const snapRules = Array.isArray(snap.rules) ? (snap.rules as unknown[]) : [];
  const liveRules = Array.isArray(liveFull.rules) ? (liveFull.rules as unknown[]) : [];
  const snapCmp = snapRules.map((r) => (isPlainObject(r) ? stripStamped(r) : r));
  const liveCmp = liveRules.map((r) => (isPlainObject(r) ? stripStamped(r) : r));
  if (jsonEqual(liveCmp, snapCmp)) return;

  // REFUSE TO DELETE. PUT /rulesets/{id} replaces the whole rule list, so applying a snapshot to a live
  // ruleset that has rules the snapshot lacks DELETES them. The restore contract is additive: never
  // prune, never wholesale-replace a collection, at any size.
  //
  // The realistic case is not exotic. An engineer adds a WAF rule, a restore runs from an older snapshot,
  // and the rule disappears with the run reporting success. The same shape is how an attacker's added rule
  // would have been silently reverted, which is the one case where deleting is what you wanted; the
  // operator still has to be the one who decides that, out of band.
  //
  // Matching is on IDENTITY, not on content: an EDITED rule has different content on each side, so matching
  // by content would read every ordinary change as "the live rule is not in the snapshot" and refuse every
  // restore it existed to perform. Identity has to survive an edit, which is exactly what content cannot do.
  //
  // Preference order: `ref` (Cloudflare's stable rule reference, unchanged across edits), then `id`, then
  // `description`. The final fallback is the stripped content, which is the conservative direction: a rule
  // with no identifying field at all is treated as live-only unless something byte-identical is in the
  // snapshot, so the writer refuses rather than deletes.
  const snapIds = new Set(snapRules.map(entryIdentity));
  const liveOnly = liveRules.filter((r) => !snapIds.has(entryIdentity(r)));
  if (liveOnly.length > 0) {
    // NAME each one. F9 exists because a restore that quietly does something to a rule the operator
    // cannot see is a product failure even when the write itself is correct. Reporting "3 rules became 2"
    // is exactly that failure: it is a count, and a count cannot be reviewed.
    for (const r of liveOnly) {
      const d = isPlainObject(r) ? (typeof r.description === "string" && r.description !== "" ? r.description : typeof r.expression === "string" ? r.expression : "") : "";
      changes.push({ path: `${path}/${d.slice(0, 60) || "rule"}`, action: "remove", from: asJson(r), to: "" });
    }
    skipped.push({
      path,
      reason: `${liveOnly.length} live rule(s) are not in the snapshot; applying it would delete them, and restore is additive. They are named in the diff. Remove them in Cloudflare first, or re-apply this ruleset out of band`,
      cls: "live-only-rules",
    });
    return;
  }

  changes.push({ path, action: "change", from: asJson({ rules: liveCmp.length }), to: asJson({ rules: snapCmp.length }) });
  ops.push({ id: liveRs.id, rules: snapRules.map((r) => (isPlainObject(r) ? stripStamped(r) : r)), path });
}

// applyRulesetOps PUTs each changed ruleset's rule list, fail-open per ruleset.
//
// The PUT is a wholesale replace of that ruleset's rules, which is only safe because diffOneRuleset has
// already refused any ruleset whose live side carries rules the snapshot does not. Every op that reaches
// here is therefore additive in effect: the live rules are a subset of what is being written.
async function applyRulesetOps(api: CfApi, rulesBase: string, ops: RulesetOp[], skipped: ConfigWriteResult["skipped"], meter?: Meter): Promise<number> {
  let applied = 0;
  for (const op of ops) {
    try {
      meter?.spend(1);
      await api.send("PUT", `${rulesBase}/${op.id}`, { rules: op.rules });
      applied++;
    } catch (e) {
      // G191: classify the refusal HERE, at the only site that ever holds the exception. The 120-char text
      // still rides to the operator's live response; the CLASS is what a support pack can carry.
      skipped.push({ path: op.path, reason: (e as Error).message.replace(/^Cloudflare API [A-Z]+ [^:]+:\s*/, "").slice(0, 120), cls: classifyCfWriteSkip(e) });
    }
  }
  return applied;
}

export function writeRulesets(scope: CfScope): NonNullable<CfConfigSurface["write"]> {
  const base = (i: Ids) => (scope === "zone" ? `/zones/${i.zoneId}` : `/accounts/${i.accountId}`);
  const labelOf = scope === "zone" ? "rulesets" : "account-rulesets";
  return async (api, ids, data, opts, meter) => {
    const rulesBase = `${base(ids)}/rulesets`;
    // Read live rulesets (the index is a list -> paginate) and expand each so we can diff its rules.
    // RULESETS_PER_PAGE, not the registry default: Cloudflare refuses per_page above 50 on the ruleset
    // index, which would otherwise throw on every account and stop the WRITE path of both ruleset surfaces
    // from running at all. expandRulesets (the READ) uses the same page size for the same reason.
    const liveIndex = (await paginate(api, rulesBase, meter, RULESETS_PER_PAGE)) as Array<Record<string, unknown>>;
    const { byId: liveById, byPhase: liveByPhase } = indexLiveRulesets(liveIndex);
    const snapshot = (Array.isArray(data) ? data : []).filter(isPlainObject) as Array<Record<string, unknown>>;
    const changes: ConfigChange[] = [];
    const skipped: ConfigWriteResult["skipped"] = [];
    const ops: RulesetOp[] = [];
    for (const snap of snapshot) {
      await diffOneRuleset(api, rulesBase, labelOf, snap, liveById, liveByPhase, opts.dryRun, changes, ops, skipped, meter);
    }
    const applied = opts.dryRun ? 0 : await applyRulesetOps(api, rulesBase, ops, skipped, meter);
    return { changes, applied, skipped };
  };
}
