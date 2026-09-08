// Prove coverage and gap detection (what is and is not backed up): the pure projection + matching in
// engine/src/admin/coverage.ts, and the inventory storage + the two routes (POST /coverage/inventory,
// GET /coverage) in the scheduler DO. In-memory doubles only; no network, no deploy, no cost. Run:
//   node test/validate-coverage.ts
//
// Coverage:
//  validateInventory: shape/id/name/bounds checks; missing groups default empty; per-id dedupe; the
//    per-type cap; control-character + oversized rejection; a NON-object/array inventory is refused.
//  computeCoverage (pure gap computation): protected (covered + successful run + restore-proven),
//    untested (covered but not yet both), unprotected (no covering downpipe); the rollup sums; the
//    same-type rule (a bucket named like a namespace is never cross-matched); kv/r2 match by native id
//    OR binding, d1 by native databaseId OR binding, secrets by each native secret name; honest-unknown when inventory is
//    null (hasInventory:false, zeroed rollup, NO implied coverage); a NEGATIVE control where a wrong id
//    leaves a resource unprotected even though a downpipe of the same type exists.
//  DO routes (driving real code end to end): POST /coverage/inventory stores reference data and is
//    re-checked on access.policy (a viewer caller is refused); GET /coverage computes from the stored
//    inventory + real downpipe/run/restore state; honest-unknown before any inventory is stored.
//  INVENTORY NEVER REACHES DATA (the sacred property): storing an inventory naming a resource adds NO
//    binding and NO source to any downpipe; the downpipe set the seal path reads (GET /downpipes) is
//    byte-for-byte unchanged by an inventory write, and a fabricated inventory only changes a STATUS,
//    never what any downpipe actually backs up.

import {
  validateInventory,
  computeCoverage,
  matchKeysForSource,
  isCoverageResourceType,
  COVERAGE_RESOURCE_TYPES,
  COVERAGE_INVENTORY_KEY,
  type ResourceInventory,
  type CoverageDownpipeInput,
  type CoverageReport,
} from "../src/admin/coverage.ts";
import { SchedulerDO, type DownpipeConfig } from "../src/sched/scheduler-do.ts";
import { encodeCaller, type Caller } from "../src/admin/identity.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

function makeScheduler(): { storage: MockStorage; stub: SchedulerDO } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  return { storage, stub: new SchedulerDO(state) };
}

// The bare-token break-glass resolves to owner (holds access.policy + posture.read), so it can both
// store an inventory and read the gap view. A viewer holds posture.read but NOT access.policy, so a
// viewer caller header lets us prove the DO's defence-in-depth re-check refuses an unauthorised
// inventory write while still allowing the read.
const OWNER_CALLER: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };
const OWNER_HEADER = encodeCaller(OWNER_CALLER);
const VIEWER_CALLER: Caller = { method: "access", email: "v@example.au", subject: "subject-v@example.au", role: "viewer", groups: [] };
const VIEWER_HEADER = encodeCaller(VIEWER_CALLER);
// An operator holds posture.read (so it may READ the gap view) but NOT access.policy, so the DO's
// defence-in-depth re-check must still refuse it the inventory WRITE, exactly like a viewer.
const OPERATOR_CALLER: Caller = { method: "access", email: "op@example.au", subject: "subject-op@example.au", role: "operator", groups: [] };
const OPERATOR_HEADER = encodeCaller(OPERATOR_CALLER);

function fetchDO(dobj: SchedulerDO, method: string, path: string, body?: unknown, header?: string): Promise<Response> {
  const url = `https://scheduler.internal${path}`;
  const headers: Record<string, string> = {
    ...(body !== undefined ? { "content-type": "application/json" } : {}),
    ...(header !== undefined ? { "x-downpipe-caller": header } : {}),
  };
  const init: RequestInit = { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) };
  return dobj.fetch(new Request(url, init));
}

// A minimal valid downpipe config for a given source. The cadence floor is 60s; restore tests off (0)
// keeps the upsert simple. The source binding is a non-reserved [A-Za-z0-9_] name.
function kvConfig(id: string, binding: string, namespaceId?: string): DownpipeConfig {
  return {
    id,
    name: id,
    cadenceSeconds: 3600,
    enabled: true,
    restoreTestCadenceSeconds: 0,
    source: { type: "kv", binding, include: [], exclude: [], ...(namespaceId !== undefined ? { namespaceId } : {}) },
  };
}
function r2Config(id: string, binding: string, bucketName?: string): DownpipeConfig {
  return {
    id,
    name: id,
    cadenceSeconds: 3600,
    enabled: true,
    restoreTestCadenceSeconds: 0,
    source: { type: "r2", binding, include: [], exclude: [], ...(bucketName !== undefined ? { bucketName } : {}) },
  };
}
function d1Config(id: string, binding: string): DownpipeConfig {
  return {
    id,
    name: id,
    cadenceSeconds: 3600,
    enabled: true,
    restoreTestCadenceSeconds: 0,
    source: { type: "d1", binding, include: [], exclude: [] },
  };
}
function secretsConfig(id: string, secretNames: string[]): DownpipeConfig {
  return {
    id,
    name: id,
    cadenceSeconds: 3600,
    enabled: true,
    restoreTestCadenceSeconds: 0,
    source: { type: "secrets", secrets: secretNames.map((n, i) => ({ name: n, binding: `SECRET_${i}` })), include: [], exclude: [] },
  };
}

// addDownpipe drives the real DO upsert (validateConfig). markRunOk drives the real trigger -> complete
// flow so the downpipe genuinely has an "ok" history row. markRestoreProven drives the real
// restore-proven route so the downpipe carries an affirmative recoverability proof.
async function addDownpipe(dobj: SchedulerDO, config: DownpipeConfig): Promise<void> {
  const resp = await fetchDO(dobj, "POST", "/downpipes", config, OWNER_HEADER);
  if (resp.status !== 200) throw new Error(`addDownpipe ${config.id} failed: ${resp.status} ${await resp.text()}`);
}
async function markRunOk(dobj: SchedulerDO, id: string): Promise<void> {
  const tr = await fetchDO(dobj, "POST", "/trigger", { id }, OWNER_HEADER);
  const trig = (await tr.json()) as { runId: string; index: number };
  const cr = await fetchDO(dobj, "POST", "/complete", { id, runId: trig.runId, index: trig.index, status: "ok" });
  if (cr.status !== 200) throw new Error(`complete ${id} failed: ${cr.status}`);
}
async function markRestoreProven(dobj: SchedulerDO, id: string): Promise<void> {
  const resp = await fetchDO(dobj, "POST", "/restore-proven", { downpipeId: id, method: "blind-test", runId: "run-" + id }, OWNER_HEADER);
  const body = (await resp.json()) as { ok: boolean };
  if (!body.ok) throw new Error(`restore-proven ${id} failed`);
}

// ---- validateInventory: shape, id, name, bounds, dedupe -----------------------------------
function testValidateInventory(): void {
  {
    const good = validateInventory({
      kv: [{ id: "ns-aaa", name: "uploads" }, { id: "ns-bbb" }],
      r2: [{ id: "media-bucket" }],
      d1: [{ id: "db-001", name: "app" }],
      secrets: [{ id: "API_KEY" }],
    });
    ok("validate: a well-formed inventory is accepted", good.ok === true);
    if (good.ok) {
      ok("validate: kv group preserved", good.inventory.kv.length === 2);
      ok("validate: label kept when supplied", good.inventory.kv[0]?.name === "uploads");
      ok("validate: label honestly absent when omitted", good.inventory.kv[1]?.name === undefined);
      ok("validate: r2/d1/secrets groups preserved", good.inventory.r2.length === 1 && good.inventory.d1.length === 1 && good.inventory.secrets.length === 1);
    }

    // A missing group defaults to empty (the operator may submit only the types they have).
    const partial = validateInventory({ kv: [{ id: "only-kv" }] });
    ok("validate: omitted groups default to empty", partial.ok === true && partial.inventory.r2.length === 0 && partial.inventory.d1.length === 0 && partial.inventory.secrets.length === 0);

    // Dedupe within a group: a pasted list with a repeated id stores the resource once (first wins).
    const dup = validateInventory({ kv: [{ id: "ns-x", name: "first" }, { id: "ns-x", name: "second" }] });
    ok("validate: duplicate id deduped (first wins)", dup.ok === true && dup.inventory.kv.length === 1 && dup.inventory.kv[0]?.name === "first");

    // NEGATIVE controls: a malformed inventory is refused, never silently accepted.
    ok("validate: a non-object inventory is refused", validateInventory(null).ok === false && validateInventory(42).ok === false && validateInventory([]).ok === false);
    ok("validate: a non-array group is refused", validateInventory({ kv: { id: "x" } }).ok === false);
    ok("validate: a resource without an id is refused", validateInventory({ kv: [{ name: "no-id" }] }).ok === false);
    ok("validate: an id with whitespace is refused", validateInventory({ kv: [{ id: "bad id" }] }).ok === false);
    ok("validate: an id with a control char is refused", validateInventory({ kv: [{ id: "bad\x07id" }] }).ok === false);
    ok("validate: an over-long id is refused", validateInventory({ kv: [{ id: "a".repeat(257) }] }).ok === false);
    ok("validate: a name with a control char is refused", validateInventory({ kv: [{ id: "ns", name: "bad\x01name" }] }).ok === false);
    ok("validate: an over-long name is refused", validateInventory({ kv: [{ id: "ns", name: "a".repeat(257) }] }).ok === false);
    ok("validate: an over-cap group is refused", validateInventory({ kv: Array.from({ length: 5001 }, (_, i) => ({ id: "ns-" + i })) }).ok === false);
    // An empty-after-trim name is treated as absent (no label).
    const blankName = validateInventory({ kv: [{ id: "ns", name: "   " }] });
    ok("validate: blank name treated as absent", blankName.ok === true && blankName.inventory.kv[0]?.name === undefined);
  }
}

// ---- COVERAGE_RESOURCE_TYPES agrees with isCoverageResourceType ----------------------------
function testResourceTypeGuard(): void {
  ok("types: the value list matches the type guard", COVERAGE_RESOURCE_TYPES.every((t) => isCoverageResourceType(t)) && COVERAGE_RESOURCE_TYPES.length === 4);
  ok("types: an unknown type is rejected by the guard", !isCoverageResourceType("queue") && !isCoverageResourceType(""));
}

// ---- matchKeysForSource: mirrors buildAdapter's identity resolution ------------------------
function testMatchKeys(): void {
  {
    // kv: native id preferred, binding also a key (so an inventory keyed by either matches).
    const kv = matchKeysForSource({ type: "kv", binding: "KV_UP", namespaceId: "ns-aaa" });
    ok("match: kv presents the native namespaceId", kv.type === "kv" && kv.keys.has("ns-aaa"));
    ok("match: kv also presents the binding", kv.keys.has("KV_UP"));
    // r2: native bucketName + binding.
    const r2 = matchKeysForSource({ type: "r2", binding: "R2_MED", bucketName: "media-bucket" });
    ok("match: r2 presents the native bucketName and binding", r2.keys.has("media-bucket") && r2.keys.has("R2_MED"));
    // d1: binding when no native id recorded; native databaseId + binding when it is.
    const d1 = matchKeysForSource({ type: "d1", binding: "D1_APP" });
    ok("match: d1 with no databaseId presents the binding only", d1.keys.size === 1 && d1.keys.has("D1_APP"));
    const d1id = matchKeysForSource({ type: "d1", binding: "D1_APP", databaseId: "db-uuid-123" });
    ok("match: d1 presents the native databaseId and binding", d1id.keys.has("db-uuid-123") && d1id.keys.has("D1_APP") && d1id.keys.size === 2);
    // secrets: each native secret name.
    const sec = matchKeysForSource({ type: "secrets", secrets: [{ name: "API_KEY" }, { name: "DB_PW" }] });
    ok("match: secrets present each native secret name", sec.keys.has("API_KEY") && sec.keys.has("DB_PW") && sec.keys.size === 2);
    // A source with no usable identity matches nothing.
    const empty = matchKeysForSource({ type: "kv" });
    ok("match: a source with no identity matches nothing", empty.keys.size === 0);
  }
}

// ---- computeCoverage (pure): the three statuses + rollup -----------------------------------
function testComputeCoverageStatuses(): void {
  {
    const inventory: ResourceInventory = {
      kv: [{ id: "ns-protected" }, { id: "ns-untested" }, { id: "ns-orphan" }],
      r2: [{ id: "bucket-by-binding" }],
      d1: [],
      secrets: [{ id: "API_KEY" }, { id: "UNUSED_SECRET" }],
    };
    const downpipes: CoverageDownpipeInput[] = [
      // covers ns-protected by native id, has a run AND a proof -> protected
      { id: "dp-prot", source: { type: "kv", binding: "KV_A", namespaceId: "ns-protected" }, hasSuccessfulRun: true, restoreProven: true },
      // covers ns-untested by native id, has a run but NO proof -> untested
      { id: "dp-untested", source: { type: "kv", binding: "KV_B", namespaceId: "ns-untested" }, hasSuccessfulRun: true, restoreProven: false },
      // covers bucket-by-binding by its BINDING (no bucketName recorded) -> r2 matched by binding
      { id: "dp-r2", source: { type: "r2", binding: "bucket-by-binding" }, hasSuccessfulRun: true, restoreProven: true },
      // covers API_KEY (a secrets downpipe) but has neither a run nor a proof -> untested
      { id: "dp-sec", source: { type: "secrets", secrets: [{ name: "API_KEY" }] }, hasSuccessfulRun: false, restoreProven: false },
    ];
    const report = computeCoverage(inventory, downpipes, Date.parse("2026-06-09T00:00:00.000Z"));
    const byId = new Map(report.resources.map((r) => [r.id, r]));

    ok("compute: hasInventory true when an inventory is present", report.hasInventory === true);
    ok("compute: protected resource (run + proof)", byId.get("ns-protected")?.status === "protected");
    ok("compute: protected links the covering downpipe", byId.get("ns-protected")?.downpipeId === "dp-prot");
    ok("compute: untested resource (run, no proof)", byId.get("ns-untested")?.status === "untested");
    ok("compute: unprotected resource (no covering downpipe)", byId.get("ns-orphan")?.status === "unprotected");
    ok("compute: unprotected carries no downpipeId", byId.get("ns-orphan")?.downpipeId === undefined);
    ok("compute: r2 matched by binding is protected", byId.get("bucket-by-binding")?.status === "protected");
    ok("compute: a secret covered but unproven is untested", byId.get("API_KEY")?.status === "untested");
    ok("compute: an uncovered secret is unprotected", byId.get("UNUSED_SECRET")?.status === "unprotected");

    // Rollup sums: 6 resources = 2 protected (ns-protected, bucket-by-binding) + 2 untested
    // (ns-untested, API_KEY) + 2 unprotected (ns-orphan, UNUSED_SECRET).
    ok("rollup: total counts every resource", report.rollup.total === 6);
    ok("rollup: protected count", report.rollup.protected === 2);
    ok("rollup: untested count", report.rollup.untested === 2);
    ok("rollup: unprotected count", report.rollup.unprotected === 2);
    ok("rollup: the three buckets sum to the total", report.rollup.protected + report.rollup.untested + report.rollup.unprotected === report.rollup.total);
  }
}

// ---- computeCoverage: the SAME-TYPE rule (no cross-type matching) --------------------------
function testComputeCoverageMatchingRules(): void {
  {
    // A bucket named exactly like a namespace must NOT be matched by a KV downpipe (and vice versa):
    // matching is scoped to the resource's own type. Here a KV downpipe is configured with a binding
    // "collide", and the inventory has an R2 resource id "collide": the R2 resource stays unprotected.
    const inventory: ResourceInventory = { kv: [], r2: [{ id: "collide" }], d1: [], secrets: [] };
    const downpipes: CoverageDownpipeInput[] = [
      { id: "dp-kv", source: { type: "kv", binding: "collide" }, hasSuccessfulRun: true, restoreProven: true },
    ];
    const report = computeCoverage(inventory, downpipes, Date.now());
    ok("same-type: a kv downpipe never covers an r2 resource with a colliding name", report.resources[0]?.status === "unprotected");
  }

  // ---- computeCoverage: a NEGATIVE control (wrong id leaves it unprotected) -------------------
  {
    // A kv downpipe exists, but its identity does not match the inventoried resource id, so the
    // resource is unprotected EVEN THOUGH a downpipe of the same type exists. This drives the matcher,
    // not just the absence path: the existence of a same-type downpipe must not falsely cover.
    const inventory: ResourceInventory = { kv: [{ id: "ns-real" }], r2: [], d1: [], secrets: [] };
    const downpipes: CoverageDownpipeInput[] = [
      { id: "dp-other", source: { type: "kv", binding: "KV_X", namespaceId: "ns-different" }, hasSuccessfulRun: true, restoreProven: true },
    ];
    const report = computeCoverage(inventory, downpipes, Date.now());
    ok("negative: a same-type downpipe with a non-matching id does NOT cover the resource", report.resources[0]?.status === "unprotected");
  }

  // ---- computeCoverage: id matching is EXACT and CASE-SENSITIVE -------------------------------
  {
    // The match is byte-exact string equality (Set.has), never case-folded: a downpipe whose identity is
    // "kv_uploads" must NOT cover an inventoried resource id "KV_uploads" (a different cloud resource).
    // Folding case here would silently report an unrelated resource as protected, the exact dishonesty the
    // feature exists to prevent. A resource whose id EXACTLY matches a downpipe identity IS covered, so the
    // same fixture proves the positive (exact) and negative (case-variant) sides together.
    const inventory: ResourceInventory = { kv: [{ id: "KV_uploads" }, { id: "kv_uploads" }], r2: [], d1: [], secrets: [] };
    const downpipes: CoverageDownpipeInput[] = [
      { id: "dp-lower", source: { type: "kv", binding: "kv_uploads" }, hasSuccessfulRun: true, restoreProven: true },
    ];
    const report = computeCoverage(inventory, downpipes, Date.now());
    const byId = new Map(report.resources.map((r) => [r.id, r]));
    ok("case: an EXACT id match is covered (kv_uploads -> protected)", byId.get("kv_uploads")?.status === "protected" && byId.get("kv_uploads")?.downpipeId === "dp-lower");
    ok("case: a CASE-VARIANT id is NOT matched (KV_uploads stays unprotected)", byId.get("KV_uploads")?.status === "unprotected" && byId.get("KV_uploads")?.downpipeId === undefined);
  }
}

// ---- computeCoverage: HONEST UNKNOWN when there is no inventory -----------------------------
function testHonestUnknown(): void {
  {
    // The whole point: a null inventory must NOT imply full coverage. Even with healthy, proven
    // downpipes present, the report is the honest-unknown shape: hasInventory false, no resources, a
    // zeroed rollup. It claims nothing.
    const downpipes: CoverageDownpipeInput[] = [
      { id: "dp-prot", source: { type: "kv", binding: "KV_A", namespaceId: "ns-protected" }, hasSuccessfulRun: true, restoreProven: true },
    ];
    const report = computeCoverage(null, downpipes, Date.now());
    ok("unknown: hasInventory is false with no inventory", report.hasInventory === false);
    ok("unknown: no resources are claimed", report.resources.length === 0);
    ok("unknown: the rollup is zeroed (NOT a fabricated full-coverage)", report.rollup.total === 0 && report.rollup.protected === 0 && report.rollup.untested === 0 && report.rollup.unprotected === 0);
    ok("unknown: a generatedAt is still stamped (the read succeeded)", typeof report.generatedAt === "string" && report.generatedAt.endsWith("Z"));
  }
}

// ============================================================================================
// DO routes: driving real code end to end (storage + the two routes + the access.policy re-check)
// ============================================================================================

// ---- GET /coverage BEFORE any inventory: honest unknown ------------------------------------
async function testRouteUnknownBeforeInventory(): Promise<void> {
  {
    const { stub } = makeScheduler();
    // Even with a healthy, proven downpipe configured, the gap view is honest-unknown until an
    // inventory is stored: the engine cannot enumerate the account's resources by itself.
    await addDownpipe(stub, kvConfig("dp-1", "KV_A", "ns-aaa"));
    await markRunOk(stub, "dp-1");
    await markRestoreProven(stub, "dp-1");
    const resp = await fetchDO(stub, "GET", "/coverage", undefined, OWNER_HEADER);
    const report = (await resp.json()) as CoverageReport;
    ok("route: GET /coverage 200 before any inventory", resp.status === 200);
    ok("route: honest-unknown before any inventory (hasInventory false)", report.hasInventory === false);
    ok("route: no coverage implied before any inventory", report.resources.length === 0 && report.rollup.total === 0);
  }
}

// ---- POST /coverage/inventory re-checks access.policy (a viewer is refused) ----------------
async function testRouteInventoryAccessPolicy(): Promise<void> {
  {
    const { stub, storage } = makeScheduler();
    const denied = await fetchDO(stub, "POST", "/coverage/inventory", { kv: [{ id: "ns-aaa" }] }, VIEWER_HEADER);
    ok("route: a viewer (no access.policy) is refused the inventory write", denied.status === 403);
    ok("route: a refused write stores NO inventory", !storage.has(COVERAGE_INVENTORY_KEY));
    // An OPERATOR also lacks access.policy (a data role, not a people/policy role), so the DO re-check
    // refuses it the inventory write too, even though it holds posture.read for the read side.
    const deniedOp = await fetchDO(stub, "POST", "/coverage/inventory", { kv: [{ id: "ns-aaa" }] }, OPERATOR_HEADER);
    ok("route: an operator (no access.policy) is refused the inventory write", deniedOp.status === 403);
    ok("route: the operator-refused write stores NO inventory either", !storage.has(COVERAGE_INVENTORY_KEY));
    // The owner (access.policy via the token break-glass) may store it.
    const allowed = await fetchDO(stub, "POST", "/coverage/inventory", { kv: [{ id: "ns-aaa", name: "uploads" }] }, OWNER_HEADER);
    ok("route: the owner may store the inventory", allowed.status === 200);
    ok("route: the inventory is now stored under its own key", storage.has(COVERAGE_INVENTORY_KEY));
    const stored = storage.rawGet<ResourceInventory>(COVERAGE_INVENTORY_KEY);
    ok("route: the stored inventory carries only the supplied reference data", stored !== undefined && stored.kv.length === 1 && stored.kv[0]?.id === "ns-aaa");
  }
}

// ---- POST /coverage/inventory rejects a malformed body with a 400 --------------------------
async function testRouteMalformedInventory(): Promise<void> {
  const { stub, storage } = makeScheduler();
  const bad = await fetchDO(stub, "POST", "/coverage/inventory", { kv: [{ name: "no-id" }] }, OWNER_HEADER);
  ok("route: a malformed inventory is a 400", bad.status === 400);
  ok("route: a malformed write stores nothing", !storage.has(COVERAGE_INVENTORY_KEY));
}

// ---- GET /coverage computes from stored inventory + real downpipe/run/restore state --------
async function testRouteComputeFromStored(): Promise<void> {
  {
    const { stub } = makeScheduler();
    // Real downpipes via the real upsert; one fully protected (run + proof), one untested (run, no
    // proof), one never run (untested), plus an inventoried resource no downpipe covers (unprotected).
    await addDownpipe(stub, kvConfig("dp-prot", "KV_A", "ns-protected"));
    await markRunOk(stub, "dp-prot");
    await markRestoreProven(stub, "dp-prot");

    await addDownpipe(stub, r2Config("dp-untested", "R2_B", "bucket-untested"));
    await markRunOk(stub, "dp-untested"); // a run, but no restore proof

    await addDownpipe(stub, d1Config("dp-d1", "D1_APP")); // never run, never proven

    // Store the inventory (owner). It names the three covered resources plus two orphans.
    const inv = {
      kv: [{ id: "ns-protected", name: "uploads" }, { id: "ns-orphan-kv" }],
      r2: [{ id: "bucket-untested" }],
      d1: [{ id: "D1_APP", name: "app-db" }],
      secrets: [{ id: "ORPHAN_SECRET" }],
    };
    const store = await fetchDO(stub, "POST", "/coverage/inventory", inv, OWNER_HEADER);
    ok("route: store the full inventory", store.status === 200);

    const resp = await fetchDO(stub, "GET", "/coverage", undefined, OWNER_HEADER);
    const report = (await resp.json()) as CoverageReport;
    const byId = new Map(report.resources.map((r) => [r.id, r]));
    ok("route: hasInventory true after storing", report.hasInventory === true);
    ok("route: ns-protected is protected (run + proof, real state)", byId.get("ns-protected")?.status === "protected" && byId.get("ns-protected")?.downpipeId === "dp-prot");
    ok("route: ns-protected shows its label", byId.get("ns-protected")?.name === "uploads");
    ok("route: ns-orphan-kv is unprotected", byId.get("ns-orphan-kv")?.status === "unprotected");
    ok("route: bucket-untested is untested (run, no proof, real state)", byId.get("bucket-untested")?.status === "untested");
    ok("route: D1_APP is untested (never run, matched by binding)", byId.get("D1_APP")?.status === "untested" && byId.get("D1_APP")?.downpipeId === "dp-d1");
    ok("route: ORPHAN_SECRET is unprotected", byId.get("ORPHAN_SECRET")?.status === "unprotected");
    ok("route: rollup totals 5 resources", report.rollup.total === 5);
    ok("route: rollup 1 protected / 2 untested / 2 unprotected", report.rollup.protected === 1 && report.rollup.untested === 2 && report.rollup.unprotected === 2);

    // A viewer (posture.read but no access.policy) may READ the gap view (it is the customer's own view).
    const viewerRead = await fetchDO(stub, "GET", "/coverage", undefined, VIEWER_HEADER);
    ok("route: a viewer may read the gap view", viewerRead.status === 200);
  }
}

// ---- THE SACRED PROPERTY: an inventory NEVER reaches data ----------------------------------
async function testSacredProperty(): Promise<void> {
  {
    const { stub } = makeScheduler();
    // Configure exactly one downpipe. Capture the downpipe set the SEAL PATH reads (GET /downpipes).
    await addDownpipe(stub, kvConfig("dp-only", "KV_ONLY", "ns-only"));
    const before = await (await fetchDO(stub, "GET", "/downpipes")).json() as Array<{ config: { id: string; source: unknown } }>;

    // Now store an inventory that NAMES resources the downpipe does not back up (a different namespace,
    // a bucket, a secret). If the inventory could grant access, this is exactly where a new source/
    // binding would leak in.
    await fetchDO(stub, "POST", "/coverage/inventory", {
      kv: [{ id: "ns-only" }, { id: "ns-someone-elses" }],
      r2: [{ id: "secret-bucket" }],
      secrets: [{ id: "ROOT_TOKEN" }],
    }, OWNER_HEADER);

    // The downpipe set the seal path reads is BYTE-FOR-BYTE unchanged: no source was added, no binding
    // was added, the single downpipe still backs up only what it was configured to.
    const after = await (await fetchDO(stub, "GET", "/downpipes")).json() as Array<{ config: { id: string; source: unknown } }>;
    ok("sacred: the inventory write adds NO downpipe", after.length === before.length && after.length === 1);
    ok("sacred: the single downpipe is unchanged by the inventory", JSON.stringify(after) === JSON.stringify(before));
    ok("sacred: the inventory only changes a STATUS, never a source", after[0]?.config.id === "dp-only");

    // The gap view reflects the inventory (ns-someone-elses / secret-bucket / ROOT_TOKEN are
    // unprotected: named but NOT backed up), which is the whole honest point: the engine knows they
    // exist and reports they are NOT covered, rather than silently reaching them.
    const report = await (await fetchDO(stub, "GET", "/coverage", undefined, OWNER_HEADER)).json() as CoverageReport;
    const byId = new Map(report.resources.map((r) => [r.id, r]));
    ok("sacred: a named-but-unbacked resource reads unprotected (not reached)", byId.get("ns-someone-elses")?.status === "unprotected" && byId.get("secret-bucket")?.status === "unprotected" && byId.get("ROOT_TOKEN")?.status === "unprotected");
    ok("sacred: the downpipe's own resource still reads (covered)", byId.get("ns-only")?.downpipeId === "dp-only");
  }
}

// ---- An empty stored inventory is a distinct, honest state (not 'unknown') -----------------
async function testEmptyInventoryState(): Promise<void> {
  const { stub } = makeScheduler();
  await fetchDO(stub, "POST", "/coverage/inventory", {}, OWNER_HEADER); // stores an all-empty inventory
  const report = await (await fetchDO(stub, "GET", "/coverage", undefined, OWNER_HEADER)).json() as CoverageReport;
  ok("empty: a stored empty inventory reads hasInventory true (NOT unknown)", report.hasInventory === true);
  ok("empty: a stored empty inventory has nothing to report", report.resources.length === 0 && report.rollup.total === 0);
}

async function main(): Promise<void> {
  testValidateInventory();
  testResourceTypeGuard();
  testMatchKeys();
  testComputeCoverageStatuses();
  testComputeCoverageMatchingRules();
  testHonestUnknown();
  await testRouteUnknownBeforeInventory();
  await testRouteInventoryAccessPolicy();
  await testRouteMalformedInventory();
  await testRouteComputeFromStored();
  await testSacredProperty();
  await testEmptyInventoryState();

  console.log(failures === 0 ? "\nvalidate-coverage: ALL PASS" : `\nvalidate-coverage: ${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
