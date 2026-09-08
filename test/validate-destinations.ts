// Validates the multi-destination collection in the scheduler DO (src/sched/scheduler-do.ts): the
// lazy MIGRATION of the legacy single destConfig into the collection as "default", redaction-safe
// listing, per-id resolution for per-downpipe routing (an unknown id resolves to null, never a wrong
// bucket), and destinationForRun mapping a runId to its downpipe's destination via the history ring.
// The DO is driven over its internal HTTP surface with a mock storage; no network. Run: node test/validate-destinations.ts.

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { encodeCaller, type Caller } from "../src/admin/identity.ts";
import { boundDestPruneMap, DEST_PRUNE_MAP_MAX, type DestPruneState, foldRetentionRecordIntoDestPrune } from "../src/cron/retention-dest-prune.ts";
import type { RetentionPassRecord } from "../src/cron/retention-record.ts";

// An owner-token caller (roleForCaller short-circuits method:"token" to owner), for the owner-gated
// destination-removal route.
const OWNER: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };
// A non-owner caller (operator) to prove the owner gate fires at the DO surface, not only the router.
const OPERATOR: Caller = { method: "passkey", email: "op@example.com", subject: "op", role: "operator", groups: [] };

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

function makeDO(seed: Record<string, unknown>): SchedulerDO {
  const storage = new MockStorage();
  for (const [k, v] of Object.entries(seed)) storage.seed(k, v);
  return new SchedulerDO({ storage } as unknown as DurableObjectState);
}
function get(dobj: SchedulerDO, path: string): Promise<Response> {
  return dobj.fetch(new Request(`https://scheduler.internal${path}`, { method: "GET" }));
}

const LEGACY = {
  endpoint: "https://acct.r2.cloudflarestorage.com",
  bucket: "archive-one",
  region: "auto",
  accessKeyId: "AKID_ONE",
  secretAccessKey: "SECRET_ONE",
  setAt: 1,
  setBy: "owner@example.com",
  verifiedAt: 1,
  deleteProbe: "ok" as const,
};

async function testLegacyMigration(): Promise<void> {
  console.log("-- legacy single destConfig MIGRATES to the collection as 'default' --");
  {
    const dobj = makeDO({ destConfig: LEGACY });
    const cfg = (await (await get(dobj, "/dest-config")).json()) as { config: { bucket?: string; secretAccessKey?: string } | null };
    ok("GET /dest-config resolves the migrated default (the run path's credential source)", cfg.config?.bucket === "archive-one" && cfg.config?.secretAccessKey === "SECRET_ONE");
    const list = (await (await get(dobj, "/destinations")).json()) as { destinations: Array<{ id?: string; bucket?: string; isDefault?: boolean; secretAccessKey?: unknown }>; defaultId: string | null };
    ok("GET /destinations lists exactly the migrated default", list.destinations.length === 1 && list.destinations[0]!.id === "default" && list.destinations[0]!.isDefault === true);
    ok("the default's bucket survived migration", list.destinations[0]!.bucket === "archive-one");
    ok("defaultId points at the migrated entry", list.defaultId === "default");
    ok("the list view is REDACTION-SAFE (no secret access key)", (list.destinations[0] as Record<string, unknown>).secretAccessKey === undefined);
  }
}

async function testPerIdResolution(): Promise<void> {
  console.log("-- per-id resolution: a known id resolves, an UNKNOWN id is null (never a wrong bucket) --");
  {
    const collection = {
      list: [
        { ...LEGACY, id: "default", label: "Archive one" },
        { ...LEGACY, id: "dest-two", label: "Archive two", bucket: "archive-two", accessKeyId: "AKID_TWO", secretAccessKey: "SECRET_TWO" },
      ],
      defaultId: "default",
    };
    const dobj = makeDO({ destinations: collection });
    const def = (await (await get(dobj, "/dest-config")).json()) as { config: { bucket?: string } | null };
    ok("no id resolves the DEFAULT", def.config?.bucket === "archive-one");
    const two = (await (await get(dobj, "/dest-config?id=dest-two")).json()) as { config: { bucket?: string } | null };
    ok("an explicit id resolves THAT destination", two.config?.bucket === "archive-two");
    const missing = (await (await get(dobj, "/dest-config?id=dest-nope")).json()) as { config: unknown };
    ok("an UNKNOWN id resolves to null (a dangling pin fails loud, never falls back to a wrong bucket)", missing.config === null);
  }
}

async function testDestinationForRun(): Promise<void> {
  console.log("-- destinationForRun maps a runId to its downpipe's destination via the history ring --");
  {
    const collection = { list: [{ ...LEGACY, id: "default", label: "one" }, { ...LEGACY, id: "dest-two", label: "two", bucket: "archive-two" }], defaultId: "default" };
    const dobj = makeDO({
      destinations: collection,
      "dp:pinned": { config: { id: "pinned", name: "Pinned", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_X", include: [], exclude: [] }, destinationId: "dest-two" }, nextRunAt: 0, lastRunId: "run-2", inFlight: false },
      "dp:plain": { config: { id: "plain", name: "Plain", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_Y", include: [], exclude: [] } }, nextRunAt: 0, lastRunId: "run-1", inFlight: false },
      "dp:fan": { config: { id: "fan", name: "Fan", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_Z", include: [], exclude: [] }, destinationIds: ["dest-two", "default"] }, nextRunAt: 0, lastRunId: "run-3", inFlight: false },
      "hist:pinned": [{ runId: "run-2", index: 2, startedAt: "2026-06-13T00:00:00.000Z", status: "ok" }],
      "hist:plain": [{ runId: "run-1", index: 1, startedAt: "2026-06-13T00:00:00.000Z", status: "ok" }],
      "hist:fan": [{ runId: "run-3", index: 3, startedAt: "2026-06-13T00:00:00.000Z", status: "ok" }],
    });
    const pinned = (await (await get(dobj, "/downpipes/dest-for-run?runId=run-2")).json()) as { destinationId: string | null };
    ok("a run from a PINNED downpipe resolves to its pinned destination", pinned.destinationId === "dest-two");
    const plain = (await (await get(dobj, "/downpipes/dest-for-run?runId=run-1")).json()) as { destinationId: string | null };
    ok("a run from an UNPINNED downpipe resolves to null (the default)", plain.destinationId === null);
    const unknown = (await (await get(dobj, "/downpipes/dest-for-run?runId=run-404")).json()) as { destinationId: string | null };
    ok("a run in NO history ring resolves to null (the default)", unknown.destinationId === null);
    // dests-for-run returns the FULL set (primary + replicas) for the replica-fallback restore path.
    const fan = (await (await get(dobj, "/downpipes/dests-for-run?runId=run-3")).json()) as { destinationIds: string[] };
    ok("a fan-out run lists primary + replicas in order (restore can fall back to a replica)", JSON.stringify(fan.destinationIds) === JSON.stringify(["dest-two", "default"]));
    const fanPrimary = (await (await get(dobj, "/downpipes/dest-for-run?runId=run-3")).json()) as { destinationId: string | null };
    ok("a fan-out run's primary (dest-for-run) is the first destination", fanPrimary.destinationId === "dest-two");
    const plainList = (await (await get(dobj, "/downpipes/dests-for-run?runId=run-1")).json()) as { destinationIds: string[] };
    ok("an unpinned run lists no destinations (follows the default)", plainList.destinationIds.length === 0);
  }
  // The BATCHED findRunRing must resolve a run to the right destination across MANY
  // downpipes (the ring keys are read in one batched storage.get, not one get per downpipe), and a
  // LEGACY ring row (no recorded origin) must still fall back to the downpipe's configured primary.
  console.log("-- batched resolution across many downpipes + legacy-origin fallback --");
  {
    const collection = { list: [{ ...LEGACY, id: "default", label: "d" }, { ...LEGACY, id: "dest-two", label: "two", bucket: "two" }, { ...LEGACY, id: "dest-three", label: "three", bucket: "three" }], defaultId: "default" };
    const seed: Record<string, unknown> = { destinations: collection };
    // Seed a fleet so the batched read crosses more than one downpipe; the target run lives on the LAST one.
    for (let i = 0; i < 20; i++) {
      const id = `dp_${String(i).padStart(2, "0")}`;
      seed[`dp:${id}`] = { config: { id, name: id, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV", include: [], exclude: [] }, destinationIds: ["dest-three", "default"] }, nextRunAt: 0, lastRunId: null, inFlight: false };
      seed[`hist:${id}`] = [{ runId: `r-${id}`, index: i, startedAt: "2026-06-13T00:00:00.000Z", status: "ok", destinationId: "dest-three" }];
    }
    // A downpipe pinned to dest-two whose ring row is LEGACY (no destinationId) -> falls back to the pin.
    seed["dp:legacy"] = { config: { id: "legacy", name: "Legacy", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_L", include: [], exclude: [] }, destinationId: "dest-two" }, nextRunAt: 0, lastRunId: "run-legacy", inFlight: false };
    seed["hist:legacy"] = [{ runId: "run-legacy", index: 99, startedAt: "2026-06-13T00:00:00.000Z", status: "ok" }];
    const dobj = makeDO(seed);
    const far = (await (await get(dobj, "/downpipes/dest-for-run?runId=r-dp_19")).json()) as { destinationId: string | null };
    ok("a run on a downpipe deep in the fleet resolves via the batched read", far.destinationId === "dest-three");
    const farList = (await (await get(dobj, "/downpipes/dests-for-run?runId=r-dp_19")).json()) as { destinationIds: string[] };
    ok("its fan-out list is origin-first then replicas, unchanged by batching", JSON.stringify(farList.destinationIds) === JSON.stringify(["dest-three", "default"]));
    const legacy = (await (await get(dobj, "/downpipes/dest-for-run?runId=run-legacy")).json()) as { destinationId: string | null };
    ok("a LEGACY ring row (no origin) falls back to the configured primary", legacy.destinationId === "dest-two");
  }
}

async function testRemovalGuard(): Promise<void> {
  console.log("-- removing a destination is GUARDED against orphaning runs it is the only proven copy of --");
  {
    const post = (dobj: SchedulerDO, body: unknown, caller: Caller = OWNER) =>
      dobj.fetch(new Request("https://scheduler.internal/destinations/remove", {
        method: "POST",
        headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(caller) },
        body: JSON.stringify(body),
      }));
    const dests = { list: [{ ...LEGACY, id: "default", label: "Default" }, { ...LEGACY, id: "dest-two", label: "Two", bucket: "two" }], defaultId: "default" };
    // A downpipe that NO LONGER fans out to dest-two (so the existing pin-guard does not fire), but whose
    // history shows run-5 SEALED to dest-two (failover, or a prior config). dest-two is its only origin.
    const dpDroppedTwo = { config: { id: "fan", name: "Fan", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV", include: [], exclude: [] }, destinationIds: ["default"] }, nextRunAt: 0, lastRunId: "run-5", inFlight: false };
    const histOriginTwo = [{ runId: "run-5", index: 5, startedAt: "2026-06-15T00:00:00.000Z", status: "ok", destinationId: "dest-two" }];

    // (a) UNCOVERED: no other destination is caught up to run-5 -> removal REFUSED.
    {
      const dobj = makeDO({ destinations: dests, "dp:fan": dpDroppedTwo, "hist:fan": histOriginTwo });
      const res = await post(dobj, { id: "dest-two" });
      const body = (await res.json()) as { error?: string; destinations?: unknown };
      ok("removing the only proven copy of a run is REFUSED (400)", res.status === 400 && /only proven copy/i.test(body.error ?? ""));
      const still = (await (await get(dobj, "/destinations")).json()) as { destinations: Array<{ id?: string }> };
      ok("the destination is NOT removed when the guard refuses", still.destinations.some((d) => d.id === "dest-two"));
    }

    // (b) COVERED: another destination PROVES it holds the run's window (holdsFrom 1 <= run-5 <= holdsIndex
    // 5) -> removal ALLOWED. holdsFrom is required by the membership bound (a covering copy must prove its
    // floor, not just its top, so a replica that only observed from a higher ring floor cannot falsely cover).
    {
      const dobj = makeDO({
        destinations: dests,
        "dp:fan": dpDroppedTwo,
        "hist:fan": histOriginTwo,
        "repl:fan": { default: { holdsRunId: "run-5", holdsIndex: 5, holdsFrom: 1, lastOk: true, lastAttemptAt: 1 } },
      });
      const res = await post(dobj, { id: "dest-two" });
      const body = (await res.json()) as { destinations?: Array<{ id?: string }> };
      ok("removal is ALLOWED once another destination is proven caught up past the run", res.status === 200 && !(body.destinations ?? []).some((d) => d.id === "dest-two"));
    }

    // (c) FORCE: an owner can drop the copies deliberately even while uncovered.
    {
      const dobj = makeDO({ destinations: dests, "dp:fan": dpDroppedTwo, "hist:fan": histOriginTwo });
      const res = await post(dobj, { id: "dest-two", force: true });
      const body = (await res.json()) as { destinations?: Array<{ id?: string }> };
      ok("force overrides the orphan guard (deliberate drop)", res.status === 200 && !(body.destinations ?? []).some((d) => d.id === "dest-two"));
    }

    // (d) the existing PIN guard still fires first when a downpipe CURRENTLY uses the destination.
    {
      const dpPinsTwo = { ...dpDroppedTwo, config: { ...dpDroppedTwo.config, destinationIds: ["dest-two", "default"] } };
      const dobj = makeDO({ destinations: dests, "dp:fan": dpPinsTwo, "hist:fan": histOriginTwo });
      const res = await post(dobj, { id: "dest-two" });
      const body = (await res.json()) as { error?: string };
      ok("a destination a downpipe still PINS is refused by the in-use guard", res.status === 400 && /in use by/i.test(body.error ?? ""));
    }

    // (e) the role gate fires at the DO surface: a non-owner (operator) removal is refused (403), and
    // the destination survives. This proves the owner gate is enforced inside the DO, not only the router.
    {
      const dobj = makeDO({ destinations: dests, "dp:fan": dpDroppedTwo, "hist:fan": histOriginTwo });
      const res = await post(dobj, { id: "dest-two", force: true }, OPERATOR);
      ok("a non-owner (operator) removal is refused (403) by the DO role gate", res.status === 403);
      const still = (await (await get(dobj, "/destinations")).json()) as { destinations: Array<{ id?: string }> };
      ok("the destination survives a non-owner removal attempt", still.destinations.some((d) => d.id === "dest-two"));
    }

    // ---- THE DEFAULT-ROUTED BLIND SPOT -----------------------------------------------------
    // An UNPINNED downpipe (the console wizard leaves downpipes unpinned, the common case) seals to whatever
    // the current default is and records NO origin id (destinationId undefined). The guard must not match only
    // destinationId === id, or a default-routed run counts as ZERO coverage and the last proven
    // copy's destination becomes removable (200 instead of the 400 orphan refusal). An unpinned downpipe has no
    // pin, so the in-use guard never fires first: the orphan guard is the only thing standing in the way.
    const dpUnpinned = { config: { id: "plain", name: "Plain", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV", include: [], exclude: [] } }, nextRunAt: 0, lastRunId: "run-1", inFlight: false };
    const histDefaultRouted = [{ runId: "run-1", index: 1, startedAt: "2026-06-15T00:00:00.000Z", status: "ok" }];
    const soleDefault = { list: [{ ...LEGACY, id: "default", label: "Default" }], defaultId: "default" };

    // (f) the GUARD FIRES: removing the SOLE console default that holds default-routed (unpinned) runs is
    // REFUSED (400).
    {
      const dobj = makeDO({ destinations: soleDefault, "dp:plain": dpUnpinned, "hist:plain": histDefaultRouted });
      const res = await post(dobj, { id: "default" });
      const body = (await res.json()) as { error?: string };
      ok("removing the SOLE default that holds default-routed (unpinned) runs is REFUSED (400)", res.status === 400 && /only proven copy/i.test(body.error ?? ""));
      const still = (await (await get(dobj, "/destinations")).json()) as { destinations: Array<{ id?: string }> };
      ok("the sole default is NOT removed when the default-routed orphan guard refuses", still.destinations.some((d) => d.id === "default"));
    }

    // (g) NO OVER-REFUSAL: removing a NON-default destination is unaffected by default-routed runs (they are
    // attributed to the current default, never to the destination being removed), so a legitimate multi-
    // destination remove still passes (200). This is the check the isDefault gate protects.
    {
      const dobj = makeDO({ destinations: dests, "dp:plain": dpUnpinned, "hist:plain": histDefaultRouted });
      const res = await post(dobj, { id: "dest-two" });
      const body = (await res.json()) as { destinations?: Array<{ id?: string }> };
      ok("removing a NON-default destination is ALLOWED though default-routed runs exist (not over-refused)", res.status === 200 && !(body.destinations ?? []).some((d) => d.id === "dest-two"));
    }

    // (h) the fix narrows to UNCOVERED default-routed runs, it does not blanket-refuse every default remove:
    // when another destination PROVES it holds the default-routed run's window (holdsFrom 1 <= run-1 <=
    // holdsIndex 1) the default remove is ALLOWED (200), promoting the survivor.
    {
      const dobj = makeDO({
        destinations: dests,
        "dp:plain": dpUnpinned,
        "hist:plain": histDefaultRouted,
        "repl:plain": { "dest-two": { holdsRunId: "run-1", holdsIndex: 1, holdsFrom: 1, lastOk: true, lastAttemptAt: 1 } },
      });
      const res = await post(dobj, { id: "default" });
      const body = (await res.json()) as { destinations?: Array<{ id?: string }> };
      ok("removing the default is ALLOWED once another destination is proven caught up past the default-routed run", res.status === 200 && !(body.destinations ?? []).some((d) => d.id === "default"));
    }

    // (i) FORCE overrides the default-routed refusal (a deliberate drop). This force:true path is
    // the one the console's type-to-confirm gate guards, and it must be reachable for default-routed runs too.
    {
      const dobj = makeDO({ destinations: soleDefault, "dp:plain": dpUnpinned, "hist:plain": histDefaultRouted });
      const res = await post(dobj, { id: "default", force: true });
      const body = (await res.json()) as { destinations?: Array<{ id?: string }> };
      ok("force overrides the default-routed orphan guard (the type-to-confirm force path is reachable)", res.status === 200 && !(body.destinations ?? []).some((d) => d.id === "default"));
    }
  }
}

// ---- the per-destination retention-prune sidecar (fold + DestStatusView join) -----------------

// dpRow builds one pass-record downpipe row with zero counts unless overridden.
function dpRow(id: string, destKey: string, outcome: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { id, destKey, outcome, supersededRuns: 0, runTreeObjects: 0, orphanSegs: 0, retainedRuns: 0, ...extra };
}

// passRecord builds a minimal POST /retention-record body around the given downpipe rows.
function passRecord(at: number, downpipes: Array<Record<string, unknown>>, attended = false): Record<string, unknown> {
  return { at, ...(attended ? { attended: true } : {}), downpipesWithRetention: downpipes.length, downpipesPaused: 0, replicationUnreadable: false, auditWriteFailures: 0, destinations: [], downpipes };
}

function postRecord(dobj: SchedulerDO, body: Record<string, unknown>): Promise<Response> {
  return dobj.fetch(new Request("https://scheduler.internal/retention-record", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }));
}

async function testPruneSidecarFold(): Promise<void> {
  console.log("-- fold (pure): destination-grain aggregation, the two halves, closed vocabularies --");
  {
    const rec = passRecord(1000, [
      dpRow("dp1", "", "applied", { supersededRuns: 2, runTreeObjects: 5, orphanSegs: 2, retainedRuns: 1 }),
      dpRow("dp2", "", "no-op", { retainedRuns: 3 }),
      dpRow("dp3", "dest-two", "dry-run", { supersededRuns: 1, runTreeObjects: 3, retainedRuns: 1 }),
    ]) as unknown as RetentionPassRecord;
    const m = foldRetentionRecordIntoDestPrune({}, rec, "default");
    ok("the default slot '' resolves onto the console default's id (no ghost '' row beside it)", m.default !== undefined && m[""] === undefined);
    ok("counts SUM across one destination's applied downpipes (reclaimed = run-tree + orphans)", m.default?.lastApplied?.reclaimed === 7 && m.default?.lastApplied?.supersededRuns === 2);
    ok("severity: applied outranks a sibling no-op at destination grain", m.default?.lastOutcome.outcome === "applied");
    ok("a dry-run destination carries the outcome half only (no reclaim ever applied)", m["dest-two"]?.lastOutcome.outcome === "dry-run" && m["dest-two"]?.lastApplied === undefined);
  }
  {
    // The two-halves invariant: a later deferral (or error) never erases the last reclaim.
    const applied = foldRetentionRecordIntoDestPrune({}, passRecord(1000, [dpRow("dp1", "d1", "applied", { supersededRuns: 2, runTreeObjects: 4, orphanSegs: 1 })]) as unknown as RetentionPassRecord, "");
    const deferred = foldRetentionRecordIntoDestPrune(applied, passRecord(2000, [dpRow("dp1", "d1", "deferred", { deferralClass: "retained-run-unreadable" })]) as unknown as RetentionPassRecord, "");
    ok("a deferral advances lastOutcome (deferred @2000, with its closed class)", deferred.d1?.lastOutcome.outcome === "deferred" && deferred.d1?.lastOutcome.at === 2000 && deferred.d1?.lastOutcome.deferClass === "retained-run-unreadable");
    ok("...and NEVER erases lastApplied (the reclaim half survives at its own timestamp)", deferred.d1?.lastApplied?.at === 1000 && deferred.d1?.lastApplied?.reclaimed === 5);
    // One downpipe errors while a sibling applies in the SAME pass: the outcome half warns, the reclaim
    // half still advances (the sibling's applied result is never overwritten by the error).
    const mixed = foldRetentionRecordIntoDestPrune({}, passRecord(3000, [
      dpRow("dpA", "d2", "applied", { supersededRuns: 1, runTreeObjects: 2, orphanSegs: 0 }),
      dpRow("dpB", "d2", "error", { errorClass: "dest-write-failed", wormBlocked: true }),
    ]) as unknown as RetentionPassRecord, "");
    ok("error outranks applied at destination grain, and wormBlocked rides the outcome half", mixed.d2?.lastOutcome.outcome === "error" && mixed.d2?.lastOutcome.wormBlocked === true);
    ok("the sibling's applied result still advances lastApplied in the same pass", mixed.d2?.lastApplied?.reclaimed === 2 && mixed.d2?.lastApplied?.supersededRuns === 1);
  }
  {
    // Closed vocabularies at the fold: a drifted outcome drops the row; a drifted defer class coarsens
    // to "other"; a row with NO destKey (an older caller) is skipped, never guessed.
    const hostile = foldRetentionRecordIntoDestPrune({}, passRecord(1000, [
      // d4 carries ONLY the hostile outcome: a working vocabulary check leaves NO row at all, so this
      // cannot be masked by a well-formed sibling winning the severity coarsening.
      dpRow("dp1", "d4", "exfiltrate"),
      dpRow("dp2", "d3", "deferred", { deferralClass: "hostile-class" }),
      { id: "dp3", outcome: "applied", supersededRuns: 9, runTreeObjects: 9, orphanSegs: 9, retainedRuns: 0 },
    ]) as unknown as RetentionPassRecord, "");
    ok("an out-of-vocabulary outcome row is DROPPED whole (no row, never the raw token)", hostile.d4 === undefined);
    ok("a drifted defer class coarsens to `other`, never the raw token", hostile.d3?.lastOutcome.deferClass === "other");
    ok("a row with no destKey cannot be attributed and is skipped (no row under its id or '')", hostile.dp3 === undefined && hostile[""] === undefined);
  }
  {
    // The bound: only the DEST_PRUNE_MAP_MAX freshest rows survive, oldest evicted first.
    const big: Record<string, DestPruneState> = {};
    for (let i = 0; i < DEST_PRUNE_MAP_MAX + 8; i++) big[`d${i}`] = { lastOutcome: { at: i, outcome: "no-op" } };
    const { map, evicted } = boundDestPruneMap(big);
    ok(`the sidecar map is bounded to the ${DEST_PRUNE_MAP_MAX} freshest rows (8 evicted, oldest first)`, Object.keys(map).length === DEST_PRUNE_MAP_MAX && evicted === 8 && map.d0 === undefined && map[`d${DEST_PRUNE_MAP_MAX + 7}`] !== undefined);
  }
}

async function testPruneSidecarJoin(): Promise<void> {
  console.log("-- join: POST /retention-record folds at the DO write boundary and DestStatusView carries lastPrune --");
  const dests = { list: [{ ...LEGACY, id: "default", label: "Default" }, { ...LEGACY, id: "dest-two", label: "Two", bucket: "two" }], defaultId: "default" };
  {
    const dobj = makeDO({ destinations: dests });
    await postRecord(dobj, passRecord(1000, [
      dpRow("dp1", "", "applied", { supersededRuns: 2, runTreeObjects: 5, orphanSegs: 2, retainedRuns: 1 }),
      dpRow("dp3", "dest-two", "dry-run", { supersededRuns: 1, runTreeObjects: 3, retainedRuns: 1 }),
    ]));
    const list = (await (await get(dobj, "/destinations")).json()) as { destinations: Array<{ id?: string; lastPrune?: DestPruneState }> };
    const def = list.destinations.find((d) => d.id === "default");
    const two = list.destinations.find((d) => d.id === "dest-two");
    ok("GET /destinations joins the default's sidecar row (applied, reclaimed 7)", def?.lastPrune?.lastOutcome.outcome === "applied" && def?.lastPrune?.lastApplied?.reclaimed === 7);
    ok("GET /destinations joins dest-two's row (dry-run, no reclaim half)", two?.lastPrune?.lastOutcome.outcome === "dry-run" && two?.lastPrune?.lastApplied === undefined);
    await postRecord(dobj, passRecord(2000, [dpRow("dp1", "", "deferred", { deferralClass: "retained-run-unreadable" })]));
    const after = (await (await get(dobj, "/dest-status")).json()) as { lastPrune?: DestPruneState };
    ok("a later deferral advances the default's outcome half via /dest-status", after.lastPrune?.lastOutcome.outcome === "deferred" && after.lastPrune?.lastOutcome.at === 2000);
    ok("the deferral did NOT erase the default's last reclaim (lastApplied @1000 survives)", after.lastPrune?.lastApplied?.at === 1000 && after.lastPrune?.lastApplied?.reclaimed === 7);
  }
  {
    // The env-configured fallback: an estate with NO console destination still surfaces its prune
    // telemetry through the singular /dest-status view (the default slot "" is kept, not resolved away),
    // and an ATTENDED record folds without superseding the latest CRON pass slot.
    const dobj = makeDO({});
    await postRecord(dobj, passRecord(1000, [dpRow("dp1", "", "applied", { supersededRuns: 1, runTreeObjects: 3, orphanSegs: 1, retainedRuns: 1 })], true));
    const slot = (await (await get(dobj, "/retention-state")).json()) as { record: unknown };
    ok("an attended record never supersedes the latest CRON pass slot (retention-state stays null)", slot.record === null);
    const status = (await (await get(dobj, "/dest-status")).json()) as { present: boolean; lastPrune?: DestPruneState };
    ok("an env-only estate's /dest-status still carries lastPrune (present:false, row from slot '')", status.present === false && status.lastPrune?.lastOutcome.outcome === "applied" && status.lastPrune?.lastApplied?.reclaimed === 4);
    await postRecord(dobj, passRecord(2000, [dpRow("dp1", "", "no-op", { retainedRuns: 1 })]));
    const slot2 = (await (await get(dobj, "/retention-state")).json()) as { record: { at?: number } | null };
    ok("a CRON record still lands in the latest-pass slot as before", slot2.record?.at === 2000);
  }
}

async function main(): Promise<void> {
  await testLegacyMigration();
  await testPerIdResolution();
  await testDestinationForRun();
  await testRemovalGuard();
  await testPruneSidecarFold();
  await testPruneSidecarJoin();

  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nMULTI-DESTINATION VECTORS PASS");
}

void main();
