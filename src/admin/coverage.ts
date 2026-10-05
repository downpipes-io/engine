// Coverage and gap detection (what is and is not backed up). A small, redaction-safe REFERENCE
// inventory of the account's resources (KV namespaces, R2 buckets, D1 databases, Secrets Store
// secrets) the operator supplies out of band, cross-referenced against the configured downpipes and
// their run/restorability state, so the console can answer the one question a backup posture exists
// to answer: which resources are protected, which are unprotected, and which are backed up but never
// proven recoverable.
//
// REFERENCE DATA ONLY (sacred). The inventory is descriptive metadata the operator pastes (or a
// separate read-only discovery step submits): a resource id and a label per resource, never a
// binding, never a credential, never the resource's data. It is stored DISTINCT from the backup
// bindings (a single DO key, see COVERAGE_INVENTORY_KEY) and is NEVER consulted on any seal/restore
// path. It cannot grant data access: a downpipe still reaches a resource ONLY through its own
// configured, reserved-binding-checked source (buildAdapter), and that path never reads this
// inventory. The inventory's sole job is to let the gap view say "this resource exists" for a
// resource no downpipe covers; it is a checklist, not a key.
//
// NO-CUSTODY + REDACTION (sacred). An inventoried resource carries ONLY an id (the native resource
// identifier, e.g. a KV namespace id or an R2 bucket name, which is the customer's own redaction-safe
// account metadata, not a secret) and an OPTIONAL human label. The type has no field that could carry
// a value, a key, or a credential, and the gap projection surfaces only ids/labels/counts.
//
// HONEST UNKNOWN (sacred). With NO inventory stored, the gap view returns an explicit "unknown" shape
// (hasInventory:false, empty resources, zeroed rollup) and NEVER implies full coverage. The absence of
// an inventory means "we do not know what exists", not "everything is covered": claiming coverage we
// cannot evidence would be the exact dishonesty this feature exists to prevent.
//
// This module is pure logic plus the storage-shape constants, so the DO (storage + the two routes),
// any reader and the validator share one definition of "protected/unprotected/untested", one matching
// rule and one rollup, and none of them can compute those three things two different ways. Node 25
// strip-types compatible: no enums, no parameter properties, explicit declarations.
// exactOptionalPropertyTypes: optional keys are spread in only when they carry a value.

// CoverageResourceType is the set of ID-KEYED resource kinds the coverage inventory reconciles against
// configured downpipes (kv/r2/secrets/d1). It is a SUBSET of the downpipe SourceSpec.type union: the
// account/zone-scoped source types (cf-config, workers) are not id-joined here and are surfaced via the
// sources list, not this gap analysis -- so the inventory gap view honestly answers "are my namespaces,
// buckets, databases and secrets backed up" and does not claim to cover cf-config or Workers. The inventory
// groups resources by this type, and a downpipe's source.type is matched against the same type, so a KV
// inventory entry is only ever matched against a KV source (a bucket named the same as a namespace can never
// be cross-matched).
export type CoverageResourceType = "kv" | "r2" | "secrets" | "d1";

// COVERAGE_RESOURCE_TYPES is the value-level companion to CoverageResourceType (the union is type-only
// and cannot be iterated at runtime). It is the fixed list the inventory validator walks and the gap
// computation iterates, so a new resource type added to the union is added here too (the validator
// asserts the two agree so they cannot drift).
export const COVERAGE_RESOURCE_TYPES: readonly CoverageResourceType[] = ["kv", "r2", "secrets", "d1"];

// InventoryResource is one inventoried resource as it is STORED: a native id and an optional label.
//   id    - the native resource identifier the operator/discovery supplied: a KV namespace id, an R2
//           bucket name, a D1 database id, or a Secrets Store secret name. It is the join key against a
//           downpipe source (see matchKeysForSource). It is the customer's own account metadata, not a
//           secret. For r2 and secrets, the native identifier IS the name, so id and name coincide.
//   name  - an OPTIONAL human label for the console (e.g. "uploads", "production-db"). Honestly absent
//           when the operator supplied only an id; the gap view falls back to the id for display.
// The TYPE carries no binding FIELD, no credential and no value: there is no field that could hold any of
// them. The id is matched against a downpipe source's native identity OR its binding (matchKeysForSource),
// so an operator may legitimately enter a binding NAME as an id - a binding name is non-secret account
// metadata, already exposed via GET /downpipes - and the gap report then simply reflects what the operator
// supplied. That is a value in the id field, never a separate binding field: the type has none.
export interface InventoryResource {
  id: string;
  name?: string;
}

// ResourceInventory is the whole stored reference inventory, grouped by resource type. Each group is a
// (possibly empty) list of InventoryResource. It is stored under a single DO key (COVERAGE_INVENTORY_KEY)
// as reference data, entirely distinct from the dp:/secrets/binding state. An absent inventory (the key
// is unset) is the HONEST UNKNOWN case (see computeCoverage); an inventory with all-empty groups is a
// stored-but-empty inventory (hasInventory:true, nothing to report), which is a different, honest state.
export interface ResourceInventory {
  kv: InventoryResource[];
  r2: InventoryResource[];
  d1: InventoryResource[];
  secrets: InventoryResource[];
}

// CoverageStatus is the per-resource verdict (contract: what is and is not backed up).
//   protected   - a configured downpipe backs this resource up AND that downpipe has a verified run
//                 (at least one successful run) AND its recoverability has been proven (a passed BLIND
//                 restore test or KEYLESS attestation, i.e. a restoreProven record). This is the only
//                 status that asserts the resource is genuinely safe: backed up, runs succeed, and the
//                 archive has been proven recoverable.
//   untested    - a configured downpipe backs this resource up, but it is NOT yet protected: either no
//                 successful run has landed, or recoverability has never been proven. The honest middle
//                 state ("backed up but never restore-proven"): a backup exists, but its recoverability
//                 is unproven, so it must not be presented as safe.
//   unprotected - no configured downpipe covers this resource at all. It exists (the inventory says so)
//                 and nothing is backing it up.
export type CoverageStatus = "protected" | "unprotected" | "untested";

// CoverageResource is one row of the computed gap view: the resource's type, native id and display
// label, its computed status, and (when covered) the id of the downpipe that covers it so the console
// can link to it. downpipeId is honestly absent for an unprotected resource (nothing covers it). It
// carries only redaction-safe fields; no binding, no value, no key can flow through.
export interface CoverageResource {
  type: CoverageResourceType;
  id: string;
  name: string; // the label if supplied, else the id (so a reader always has something to show)
  status: CoverageStatus;
  downpipeId?: string; // the covering downpipe's id, present only when covered (protected/untested)
}

// CoverageRollup is the headline count per status across every inventoried resource, plus the total.
// total === protected + unprotected + untested always (every resource lands in exactly one bucket).
export interface CoverageRollup {
  total: number;
  protected: number;
  unprotected: number;
  untested: number;
}

// CoverageReport is the GET /admin/coverage body. hasInventory is the HONEST-UNKNOWN discriminator:
//   false - no inventory is stored. resources is [], rollup is all-zero, and the report makes NO claim
//           about coverage (the caller must read this as "unknown", never "fully covered").
//   true  - an inventory is stored (it may be empty). resources is the per-resource gap view and rollup
//           is the headline counts. generatedAt is the RFC-3339 millis-Z time the view was computed.
// The shape is identical in both cases (so a consumer parses one type); hasInventory is the flag that
// says whether the numbers MEAN anything.
export interface CoverageReport {
  hasInventory: boolean;
  generatedAt: string;
  rollup: CoverageRollup;
  resources: CoverageResource[];
}

// CoverageDownpipeInput is the per-downpipe slice computeCoverage reads: the id, the source descriptor
// it backs up (the SAME fields buildAdapter reads to reach the resource: type + binding + the native
// namespaceId/bucketName + the secrets list), and the two recovery-state booleans the status ladder
// needs (hasSuccessfulRun, restoreProven). It is built by the DO from the DownpipeState it already
// holds; it carries no binding the matcher could turn into access (the matcher only COMPARES the
// configured identity against the inventory id, it never USES the binding to read anything).
//
// SECURITY NOTE: the source fields here are the downpipe's OWN configured identity (what it already
// backs up), read for COMPARISON only. The inventory never feeds back into a downpipe's source; the
// data direction is one-way (downpipes -> match -> verdict), so a fabricated inventory can only change
// what a resource's STATUS reads as, never what any downpipe actually reaches.
export interface CoverageDownpipeInput {
  id: string;
  source: {
    type: CoverageResourceType;
    binding?: string;
    namespaceId?: string; // kv native id
    bucketName?: string; // r2 native name
    databaseId?: string; // d1 native database id
    secrets?: { name: string }[]; // secrets native names
  };
  hasSuccessfulRun: boolean; // at least one run completed ok
  restoreProven: boolean; // a passed blind-test / keyless-attest (a restoreProven record exists)
}

// COVERAGE_INVENTORY_KEY is the SINGLE DO storage key the reference inventory lives under, deliberately
// distinct from every binding/secret/dp: key so the inventory is structurally separate from anything
// that grants data access. Kept here (the coverage domain) so the DO and any reader agree on the exact
// string, mirroring EXPIRY_PREFIX / POSTURE_SNAPSHOT_KEY.
export const COVERAGE_INVENTORY_KEY = "coverage-inventory";

// COVERAGE_ID_PATTERN bounds an inventoried resource id at the authority boundary so a crafted value
// cannot be stored. It is permissive enough for the native identifiers the cloud uses (KV namespace ids
// and D1 database ids are 32-char hex; R2 bucket names and secret names allow letters, digits, hyphen,
// underscore, dot), but it excludes whitespace and control characters so the stored value is a safe,
// single-line, bounded string. 1 to 256 chars.
export const COVERAGE_ID_PATTERN = /^[A-Za-z0-9._-]{1,256}$/;

// COVERAGE_NAME_MAX bounds the optional human label, matching the downpipe-name discipline (256).
const COVERAGE_NAME_MAX = 256;

// COVERAGE_RESOURCES_PER_TYPE_MAX bounds how many resources of one type the validator will ingest, so a
// pasted-or-discovered inventory cannot hand the single-threaded DO an unbounded list to store and later
// loop over. 5000 is far above any realistic per-account namespace/bucket/db/secret count while capping
// the worst case. A list over the cap is REJECTED (not silently truncated) so the operator knows their
// inventory did not fully land, rather than the gap view silently under-reporting.
const COVERAGE_RESOURCES_PER_TYPE_MAX = 5000;

// isCoverageResourceType is the runtime guard for the resource type at the authority boundary, mirroring
// isExpiryKind / isRole. It is the closed type membership check used when normalising a downpipe source's
// type before matching (a source whose type is not one of the four cannot match any inventory entry).
export function isCoverageResourceType(v: unknown): v is CoverageResourceType {
  return v === "kv" || v === "r2" || v === "secrets" || v === "d1";
}

// EMPTY_INVENTORY is the all-groups-empty inventory. It is the value validateInventory returns for an
// inventory object that simply omits a group (a caller sending only { kv: [...] } gets the other three
// groups as []), and the shape the DO stores. It is NOT the same as "no inventory": a stored
// EMPTY_INVENTORY reads as hasInventory:true with nothing to report, whereas an absent key reads as the
// honest unknown.
function emptyInventory(): ResourceInventory {
  return { kv: [], r2: [], d1: [], secrets: [] };
}

// validateInventory checks a client-supplied inventory at the authority boundary (the DO route), the
// same discipline validateExpiryItem applies to a tracked item. It enforces, per group: an array of
// objects, each with a valid id (COVERAGE_ID_PATTERN) and an OPTIONAL bounded label with no control
// characters; the per-type count cap; and it dedupes by id within a group (first occurrence wins, order
// preserved) so a pasted list with duplicates stores each resource once. A missing group defaults to []
// (a caller may submit only the types they have). It returns the NORMALISED inventory (only the fields
// that belong, exactOptionalPropertyTypes-safe) or a typed rejection the route maps to a 400. It NEVER
// throws and NEVER inspects for secrets (the type cannot carry one); it validates shape and bounds only.
// InventoryReject is the typed rejection: the operator sentence the route 400s with, plus the CLOSED code the
// pack counts under. The two refusals answer completely different tickets -- "the customer believes they
// uploaded an inventory and the gap view is empty forever" (shape) versus "a big account can never store one
// at all" (over-cap, which no amount of re-submitting will fix) -- so they are counted apart. The code is a
// compile-time constant chosen at the refusing branch; no submitted value can reach it.
export type InventoryRejectCode = "coverage-inventory-rejected-shape" | "coverage-inventory-rejected-over-cap";

export function validateInventory(raw: unknown): { ok: true; inventory: ResourceInventory } | { ok: false; reason: string; code: InventoryRejectCode } {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, reason: "inventory must be an object with kv/r2/d1/secrets groups", code: "coverage-inventory-rejected-shape" };
  }
  const obj = raw as Record<string, unknown>;
  const out = emptyInventory();
  for (const type of COVERAGE_RESOURCE_TYPES) {
    const group = obj[type];
    if (group === undefined) continue; // an omitted group is an empty group (the operator has none)
    if (!Array.isArray(group)) {
      return { ok: false, reason: `${type} must be an array of { id, name? } resources`, code: "coverage-inventory-rejected-shape" };
    }
    if (group.length > COVERAGE_RESOURCES_PER_TYPE_MAX) {
      return { ok: false, reason: `${type} must not exceed ${COVERAGE_RESOURCES_PER_TYPE_MAX} resources`, code: "coverage-inventory-rejected-over-cap" };
    }
    const seen = new Set<string>();
    const list: InventoryResource[] = [];
    for (const entry of group) {
      if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
        return { ok: false, reason: `each ${type} resource must be an object with an id`, code: "coverage-inventory-rejected-shape" };
      }
      const rec = entry as Record<string, unknown>;
      const id = rec.id;
      if (typeof id !== "string" || !COVERAGE_ID_PATTERN.test(id)) {
        return { ok: false, reason: `each ${type} resource id must be 1 to 256 chars of [A-Za-z0-9._-]`, code: "coverage-inventory-rejected-shape" };
      }
      let name: string | undefined;
      const rawName = rec.name;
      if (rawName !== undefined) {
        if (typeof rawName !== "string") return { ok: false, reason: `${type} resource name must be a string`, code: "coverage-inventory-rejected-shape" };
        if (rawName.length > COVERAGE_NAME_MAX) return { ok: false, reason: `${type} resource name must not exceed ${COVERAGE_NAME_MAX} characters`, code: "coverage-inventory-rejected-shape" };
        for (let i = 0; i < rawName.length; i++) {
          const c = rawName.charCodeAt(i);
          if (c < 0x20 || c === 0x7f) return { ok: false, reason: `${type} resource name must not contain control characters`, code: "coverage-inventory-rejected-shape" };
        }
        // An empty-after-trim name is treated as absent (no label), so the display falls back to the id.
        const trimmed = rawName.trim();
        if (trimmed.length > 0) name = trimmed;
      }
      if (seen.has(id)) continue; // dedupe within the group; first occurrence wins, order preserved
      seen.add(id);
      list.push({ id, ...(name !== undefined ? { name } : {}) });
    }
    out[type] = list;
  }
  return { ok: true, inventory: out };
}

// matchKeysForSource returns the set of identity strings a downpipe source presents for matching against
// an inventory id of the source's OWN type. The keys mirror buildAdapter's identity resolution EXACTLY,
// so the gap view agrees with what a run would actually back up:
//   kv  -> the native namespaceId if recorded, else the binding (buildAdapter uses namespaceId ?? binding).
//   r2  -> the native bucketName if recorded, else the binding (buildAdapter uses bucketName ?? binding).
//   d1  -> the native databaseId if recorded, else the binding. (D1Source is still constructed with the
//          binding as its record name, so the binding remains a match key; the optional databaseId is an
//          ADDITIONAL key so an inventory keyed by the native database id also matches.)
//   secrets -> each configured secret's native name (a secrets downpipe covers a SET of named secrets).
// Both the recorded native id AND the binding are returned for kv/r2 so an inventory keyed by either the
// native id OR the binding matches (an operator's discovery step reports the native id; a hand-typed
// inventory might use the binding). A source with no usable key returns an empty set (it matches nothing).
//
// This function only READS the source's configured identity to COMPARE it; it never uses any of these
// strings to reach a resource. The inventory is reference data; matching is pure string comparison.
export function matchKeysForSource(source: CoverageDownpipeInput["source"]): { type: CoverageResourceType; keys: Set<string> } {
  const keys = new Set<string>();
  if (source.type === "kv") {
    if (typeof source.namespaceId === "string" && source.namespaceId.length > 0) keys.add(source.namespaceId);
    if (typeof source.binding === "string" && source.binding.length > 0) keys.add(source.binding);
  } else if (source.type === "r2") {
    if (typeof source.bucketName === "string" && source.bucketName.length > 0) keys.add(source.bucketName);
    if (typeof source.binding === "string" && source.binding.length > 0) keys.add(source.binding);
  } else if (source.type === "d1") {
    if (typeof source.databaseId === "string" && source.databaseId.length > 0) keys.add(source.databaseId);
    if (typeof source.binding === "string" && source.binding.length > 0) keys.add(source.binding);
  } else {
    // secrets: each configured secret's native name is a match key (the downpipe covers that named secret).
    if (Array.isArray(source.secrets)) {
      for (const sec of source.secrets) {
        if (sec && typeof sec.name === "string" && sec.name.length > 0) keys.add(sec.name);
      }
    }
  }
  return { type: source.type, keys };
}

// statusForCovered folds a covering downpipe's recovery state into the protected/untested verdict (an
// uncovered resource is handled separately as unprotected). The ladder is deliberate and conservative:
// only a downpipe that has BOTH a successful run AND a proven restore is "protected"; anything less is
// "untested". This is the no-false-pass posture: a backup that exists but whose recoverability is
// unproven is honestly "untested", never presented as safe.
function statusForCovered(dp: CoverageDownpipeInput): CoverageStatus {
  return dp.hasSuccessfulRun && dp.restoreProven ? "protected" : "untested";
}

// computeCoverage is the PURE gap computation (contract: what is and is not backed up). Given the stored
// inventory (or null for the honest-unknown case), the per-downpipe slice, and a clock, it returns the
// CoverageReport: one row per inventoried resource with its computed status, plus the headline rollup.
//
//   inventory === null -> HONEST UNKNOWN: hasInventory:false, no resources, zeroed rollup. The report
//                         makes NO coverage claim (absence of an inventory is "unknown", not "covered").
//   inventory present  -> for each inventoried resource, find the FIRST downpipe whose source is of the
//                         same type and whose match keys include the resource id. Covered -> protected or
//                         untested per statusForCovered; uncovered -> unprotected. Roll up the counts.
//
// It does NO I/O and reads only redaction-safe fields. The matching is pure string comparison of the
// resource id against each same-type downpipe's configured identity (matchKeysForSource); the inventory
// is never used to reach a resource, so a fabricated inventory can only change a STATUS, never grant
// access. Resources are emitted grouped by type in COVERAGE_RESOURCE_TYPES order, preserving each group's
// stored order, so the view is stable for a given inventory.
// CoverageCandidates indexes the cover downpipe per resource type by match key, so a resource lookup is an
// O(1) map get rather than a linear re-scan of every same-type downpipe.
type CoverageCandidates = Map<CoverageResourceType, Map<string, CoverageDownpipeInput>>;

// bucketByType builds the per-type match-key index. For a resource id, the FIRST downpipe (in the supplied
// order) of the same type whose keys include the id is the cover; ties are resolved by that first-wins order
// so the verdict is deterministic. A downpipe that matches on more than one key (kv/r2 match on namespaceId
// OR binding) is inserted under each of its keys, first-wins so an earlier downpipe is never displaced.
function bucketByType(downpipes: CoverageDownpipeInput[]): CoverageCandidates {
  const byType: CoverageCandidates = new Map();
  for (const t of COVERAGE_RESOURCE_TYPES) byType.set(t, new Map());
  for (const dp of downpipes) {
    if (coverageExcludeReason(dp) !== null) continue; // excluded from matching: it can cover nothing
    const { type, keys } = matchKeysForSource(dp.source);
    const index = byType.get(type)!;
    for (const key of keys) if (!index.has(key)) index.set(key, dp);
  }
  return byType;
}

// coverageExcludeReason is the SINGLE decision on whether a downpipe participates in coverage matching at all,
// and WHY it does not. bucketByType is written in terms of it so the exclusion the gap view acts on and the
// exclusion the pack counts are, by construction, the same decision: a second copy of these two conditions
// would be free to drift, and a coverage counter that drifts from the coverage verdict is worse than none.
//
// Both exclusions produce the same visible symptom -- the resource this downpipe protects reads UNPROTECTED,
// on a screen the customer is audited against -- and they were silent. Neither is a legitimate state (an
// api-discovery source type never reaches here: the DO filters those out before building the input), so a
// non-null answer is always a defect. It returns the COUNTER NAME, never the source, the binding or the id.
export function coverageExcludeReason(dp: CoverageDownpipeInput): "coverage-downpipe-excluded-unknown-source-type" | "coverage-downpipe-excluded-no-identity-key" | null {
  if (!isCoverageResourceType(dp.source.type)) return "coverage-downpipe-excluded-unknown-source-type";
  if (matchKeysForSource(dp.source).keys.size === 0) return "coverage-downpipe-excluded-no-identity-key";
  return null;
}

// computeResourceRows walks the inventory in COVERAGE_RESOURCE_TYPES order, finds each resource's cover (if
// any), and returns the emitted rows plus the rolled-up counts.
function computeResourceRows(
  inventory: ResourceInventory,
  byType: CoverageCandidates,
): { resources: CoverageResource[]; rollup: CoverageRollup } {
  const resources: CoverageResource[] = [];
  const rollup: CoverageRollup = { total: 0, protected: 0, unprotected: 0, untested: 0 };
  for (const type of COVERAGE_RESOURCE_TYPES) {
    const candidates = byType.get(type)!;
    for (const res of inventory[type]) {
      // The first same-type downpipe whose configured identity matches this resource id, by O(1) key lookup.
      const cover = candidates.get(res.id);
      const status: CoverageStatus = cover === undefined ? "unprotected" : statusForCovered(cover);
      resources.push({
        type,
        id: res.id,
        name: res.name ?? res.id,
        status,
        ...(cover !== undefined ? { downpipeId: cover.id } : {}),
      });
      rollup.total++;
      if (status === "protected") rollup.protected++;
      else if (status === "unprotected") rollup.unprotected++;
      else rollup.untested++;
    }
  }
  return { resources, rollup };
}

export function computeCoverage(
  inventory: ResourceInventory | null,
  downpipes: CoverageDownpipeInput[],
  now: number,
): CoverageReport {
  // toISOString already yields the canonical millis-Z form (exactly three fractional digits), so this
  // replace is a no-op on the normal path. It is kept as defence against a non-standard toISOString that
  // emits more than three fractional digits, matching the millis-Z intent used by config-history/expiry.
  const generatedAt = new Date(now).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
  if (inventory === null) {
    // HONEST UNKNOWN: no inventory stored. Make no coverage claim.
    return {
      hasInventory: false,
      generatedAt,
      rollup: { total: 0, protected: 0, unprotected: 0, untested: 0 },
      resources: [],
    };
  }
  const { resources, rollup } = computeResourceRows(inventory, bucketByType(downpipes));
  return { hasInventory: true, generatedAt, rollup, resources };
}
