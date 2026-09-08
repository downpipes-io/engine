// Shared leaf for the cf-config source surface registry (cf-config-surfaces.ts). It holds the
// ConfigChange shape (one field that differs between the LIVE config and the SNAPSHOT) and the small,
// self-contained JSON comparison/serialisation helpers BOTH the diff-driven restore write path
// (cf-config-write.ts) and the restore diff preview (cf-config-diff.ts) use: the value-equality check
// that ignores server-stamped/volatile fields, the server-stamped field stripper, the natural-key
// builder, and the JSON clipping. Everything here was MOVED VERBATIM out of cf-config-surfaces.ts to keep
// that module a readable size; the behaviour is unchanged. This leaf imports NOTHING local, so the
// surfaces/core/write/diff modules can all depend on it without a cycle.
//
// Node 25 strip-types compatible: no enums, explicit declarations.

// ConfigChange is one field that differs between the LIVE config and the SNAPSHOT, for the restore
// diff preview (the customer sees exactly what a restore would change before confirming). from/to
// are JSON-stringified for stable, redaction-safe display. action is the kind of change.
export interface ConfigChange {
  path: string; // a human path within the surface (e.g. a setting id, a DNS record name)
  action: "change" | "add" | "remove";
  from: string; // current live value (JSON), "" for an add
  to: string; // snapshot value (JSON), "" for a remove
}

// SERVER_STAMPED are read-only fields the API returns but never accepts on write: stripped from the
// request body and ignored when comparing live-vs-snapshot, so they are pure noise, never a "change".
export const SERVER_STAMPED = new Set([
  "id", "created_on", "modified_on", "last_modified", "modified", "uploaded_on", "updated_at",
  // modified_at was MISSING, and Cloudflare uses all three spellings across its API: modified_on on the
  // older zone endpoints, updated_at on some newer ones, modified_at on others again (AI Gateway is one).
  // A read-only timestamp left out of this set is compared like configuration, so it differs the instant
  // anything is written and the diff never converges: the writer re-applies an identical item on every
  // run, forever, and the round trip reports it as a natural-key failure. That is what it looked like on
  // ai-gateway-gateways until the field was diffed directly.
  "modified_at",
  // ...and a FOURTH pair. secondary-dns-acls answers created_time / modified_time, which survived the strip
  // and differed on every read, so the writer re-applied an identical ACL forever and the round trip read it
  // as a natural-key failure. Exactly what modified_at did, one spelling along. Cloudflare has now used
  // _on, _at and _time for the same concept across its API, so this set is a running tally of spellings
  // rather than a closed vocabulary, and the live idempotence sweep is what surfaces the next one.
  "created_time",
  "modified_time",
  "created_at", "zone_id", "zone_name", "account_id", "version", "last_updated", "self", "managed",
  "meta", "scope", "ref",
  // A SERVER-ASSIGNED IDENTIFIER that is not called "id". Enabling RUM on a zone mints a `site_tag`, so a
  // restore's diff carrying it back would have Cloudflare answer 10004 malformedParams to the whole request,
  // failing the write entirely -- including any attempt to undo it, which would leave Web Analytics switched
  // on until it was turned off by hand. The field the endpoint reports and refuses to accept is the
  // dangerous kind: it looks like configuration and behaves like an id.
  "site_tag",
  // READ-ONLY METADATA ABOUT the setting rather than the setting. Cloudflare stamps `editable` on every
  // zone-settings response and correctly ignores any attempt to write it; flipping `editable` back at it
  // makes ten surfaces look unexercisable, so it is stripped here too, keeping read and write in agreement.
  "editable", "read_only", "readonly", "locked", "modifiable",
]);
// stripStamped returns a shallow copy of an item without the server-stamped/read-only fields. The
// comparison and the request body both use it so a restore neither sends nor diffs un-writable fields.
export function stripStamped(item: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(item)) if (!SERVER_STAMPED.has(k)) out[k] = item[k];
  return out;
}
// naturalKey is the DEFAULT natural key: a stable canonical JSON of the item's NAMING fields (the
// ones that do not change when the item is edited), so live and snapshot items match even when the
// snapshot's server id is stale, distinct items never collide, and a CHANGED item still matches its
// counterpart (its naming fields are unchanged; only its editable fields differ). The fields here are
// the union of the naming fields across the supported surfaces; a surface with a sharper key passes
// its own natural(). When NONE of the naming fields are present it falls back to the full stripped
// item (so two genuinely-distinct shapeless items still differ). `configuration` is included whole
// because a firewall access rule is named by its configuration {target,value}, not a top-level field.
export function naturalKey(item: Record<string, unknown>): string {
  const naming: Record<string, unknown> = {};
  for (const k of ["type", "name", "configuration", "target", "expression", "targets", "hostname", "pattern"]) {
    if (item[k] !== undefined) naming[k] = item[k];
  }
  try {
    return Object.keys(naming).length > 0 ? `n:${JSON.stringify(naming, bigIntReplacer)}` : `f:${JSON.stringify(stripStamped(item), bigIntReplacer)}`;
  } catch {
    // JSON.stringify still threw (e.g. a circular structure). Fall back to a CSPRNG id from the
    // Workers crypto rather than Math.random; this degrades the match for this one item but never
    // collides two distinct items onto the same key.
    return `r:${crypto.randomUUID()}`;
  }
}

// JSON replacer that renders BigInt values as a tagged string so a CF API response carrying one does
// not make JSON.stringify throw and drop naturalKey to its random fallback.
function bigIntReplacer(_k: string, v: unknown): unknown {
  return typeof v === "bigint" ? `bigint:${v.toString()}` : v;
}

// Fields the Cloudflare API stamps on read but a restore never writes: diffing them is pure noise.
const VOLATILE_KEYS = new Set([
  "modified_on", "created_on", "last_modified", "modified", "uploaded_on", "updated_at", "created_at", "expires_on",
  // A FIFTH spelling, and the one with no suffix at all. Workers observability saved queries stamp bare
  // `created` and `updated`, so a query PATCHed back to itself differed on `updated` a second later and the
  // writer re-applied it forever. Cloudflare has now used _on, _at, _time and no suffix for the same
  // concept, which is why this reads as a running tally rather than a designed vocabulary. These two sit in
  // VOLATILE_KEYS rather than SERVER_STAMPED deliberately: they are timestamp churn to be ignored in a
  // DIFF, not fields a restore must strip from a request body, and conflating the two would quietly widen
  // what gets removed from every write.
  "created", "updated",
  // NOT a timestamp, and the first member of this set that is not. Zaraz mints a fresh `debugKey` on EVERY
  // read: three consecutive GETs with no write in between return three different values, while
  // `zarazVersion` beside it stays put. So it is server-generated churn in exactly the sense the rest of
  // this set is, and diffing it as configuration means a restore reports a change and rewrites the whole
  // Zaraz config on every single run, forever, on any account that has Zaraz at all.
  //
  // An account with no Zaraz reads an empty surface, so the writer has nothing to disagree with regardless.
  // This sits in VOLATILE_KEYS rather than SERVER_STAMPED for the same reason as `created`/`updated`: it is
  // to be ignored in a DIFF, not stripped from a request body.
  "debugKey",
]);

// SKIP_IN_DIFF is the single set of fields ignored everywhere a live config is compared with a snapshot:
// the structural diff walker (cf-config-diff.ts) and jsonEqual both consult it. It is the union of
// SERVER_STAMPED (read-only fields the API returns but never accepts on write, e.g. id, version, zone_id)
// and VOLATILE_KEYS (timestamps and similar churn). Deriving both the diff and the equality check from one
// set means a SERVER_STAMPED field stripped before the write can never surface in the diff preview as a
// spurious "change" row (e.g. "version: 1 -> 3") that a restore would never apply, keeping the preview and
// the write in agreement.
export const SKIP_IN_DIFF = new Set([...SERVER_STAMPED, ...VOLATILE_KEYS]);

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// jsonEqual is value equality over JSON (no cycles, no functions, both sides come from JSON.parse).
export function jsonEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (!jsonEqual(a[i], b[i])) return false;
    return true;
  }
  if (isPlainObject(a) && isPlainObject(b)) {
    const ka = Object.keys(a).filter((k) => !SKIP_IN_DIFF.has(k));
    const kb = Object.keys(b).filter((k) => !SKIP_IN_DIFF.has(k));
    if (ka.length !== kb.length) return false;
    for (const k of ka) if (!jsonEqual(a[k], b[k])) return false;
    return true;
  }
  return false;
}


function clip(s: string, max = 2000): string {
  return s.length > max ? `${s.slice(0, max)}…` : s;
}
export function asJson(v: unknown): string {
  try { return clip(JSON.stringify(v) ?? "null"); } catch { return "\"<unserialisable>\""; }
}
