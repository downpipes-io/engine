// The per-destination RUNLOG anti-rollback floor: the in-account counterpart of the offline reader's
// --min-runlog-index pin.
//
// WHAT IT CATCHES. Each destination holds its own signed _RECOVERY/RUNLOG. A bucket-write adversary can put
// back an OLDER copy of that document with its own valid signature. That copy is internally consistent, so
// the chain-anomaly check passes it. Only a number held OUTSIDE the bucket can show the log went backwards.
// The offline reader takes that number from the recovery sheet (--min-runlog-index). In-account, this module
// keeps it: the highest RUNLOG index the engine CONFIRMED it appended to each destination. The restore,
// drill, verify and attest opens pass it as minRunlogIndex, and checkRunlogFreshness refuses a RUNLOG whose
// maximum index is below it (format/freshness.ts). The comparison is the reader's own: the whole
// document's maximum index against the pin, 0 or absent meaning no pin.
//
// WHY PER DESTINATION, AND WHY CONFIRMED. The account-global runlogCounter is the wrong pin. It is allocated
// at trigger, so an in-flight run raises it before any RUNLOG holds that index. A failed run consumes an
// index and appends nothing. And a second destination can hold a higher index than this one ever will. Each
// of those would refuse a healthy restore. So the floor rises only on evidence that THIS destination's RUNLOG
// holds the index: an ok completion (the seal appends the RUNLOG entry as its last write, seal/pipeline.ts,
// seal/slice.ts, seal/fanout.ts), or a replicate-pass record (the index is in the replica's RUNLOG, or was
// appended to it this pass, seal/replicate.ts). A retention prune does not lower a RUNLOG's maximum index:
// it marks entries superseded and keeps them (seal/prune.ts applyPrune).
//
// THE KEY IS THE DESTINATION THE READ WILL OPEN. floorKeyFor mirrors how the worker resolves a destination
// (getDestConfigById, then fetchDestConfig): an id names that stored destination, no id names the default,
// and a dangling id or the synthetic deploy record resolves to the env-backed destination (DEST_R2 or
// DEST_*), keyed "". So the floor read for an open is always the floor of the bucket the open reads.
//
// WHEN A DESTINATION CHANGES, ITS FLOOR RESETS. A floor describes one bucket. When an id is repointed to a
// different endpoint or bucket, or removed, its floor drops to a tombstone { index: 0, resetAt }. A new or
// migrated bucket then carries no pin until a run or a replication confirms an append to it. That is the
// same state as before this module existed, never a false refusal. A re-added destination gets a new id and
// starts clean. The tombstone's resetAt also stops a run that began BEFORE the repoint, and completes after
// it, from raising the new bucket's floor with an index only the old bucket holds.
//
// RESIDUAL, stated. The DO cannot see the env: a redeploy that points DEST_R2 or DEST_* at another bucket
// keeps the "" floor. The RUNLOG writers then refuse the new bucket (seal/pipeline.ts verifyRunlogForWrite), so
// no run lands there until an Owner resets the floor through the attended route (resetRunlogFloor below).
// Also, the floor is not in the control-plane export, so a rebuilt DO starts with no floors, which is the
// pre-existing (unpinned) behaviour.

import type { DestinationCollection, StoredDestination } from "./scheduler-do-base.ts";

export const RUNLOG_FLOOR_KEY = "runlogFloor";
// The last time the DEFAULT resolution changed (a different destination became the default, or the first
// console destination replaced the env default). A default-routed run records no destination id, so a run
// that began before this instant may have sealed to the previous default: it does not raise a floor.
export const RUNLOG_FLOOR_DEFAULT_MOVED_KEY = "runlogFloorDefaultMovedAt";
// The env-backed destination (DEST_R2 or DEST_*), which has no stored id.
export const ENV_FLOOR_KEY = "";
// A bound on the map. Entries are per destination id, so real entries are few; the bound only reaps old
// tombstones on an estate that has added and removed many destinations.
export const RUNLOG_FLOOR_MAP_MAX = 256;

export interface RunlogFloorEntry {
  index: number; // the highest RUNLOG index confirmed appended to this destination; 0 = none since resetAt
  resetAt?: number; // epoch ms the destination was repointed or removed
}

type FloorMap = Record<string, RunlogFloorEntry>;

interface FloorStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
}

// floorKeyFor names the destination an open of `id` reads: the stored destination's own id, or ENV_FLOOR_KEY
// for the env-backed one. It mirrors getDestConfigById (id, else the default) and fetchDestConfig (the
// synthetic deploy record and a missing record both resolve to the env).
export function floorKeyFor(coll: DestinationCollection, id: string | null | undefined): string {
  if (coll.list.length === 0) return ENV_FLOOR_KEY;
  const rec = id ? coll.list.find((d) => d.id === id) : coll.list.find((d) => d.id === coll.defaultId);
  if (!rec || rec.source === "deploy") return ENV_FLOOR_KEY;
  return rec.id;
}

// locationOf is what makes two records the same bucket: the endpoint and the bucket (the container, on
// Azure). A credential rotation or a label edit keeps the location, so it keeps the floor.
function locationOf(d: StoredDestination): string {
  return `${d.endpoint}\n${d.bucket}`;
}

async function readMap(storage: FloorStorage): Promise<FloorMap> {
  const m = await storage.get<FloorMap>(RUNLOG_FLOOR_KEY);
  return m && typeof m === "object" ? m : {};
}

// readRunlogFloor returns the floor for one destination key, or undefined when none is confirmed (no pin).
export async function readRunlogFloor(storage: FloorStorage, key: string): Promise<number | undefined> {
  const e = (await readMap(storage))[key];
  return e !== undefined && Number.isInteger(e.index) && e.index > 0 ? e.index : undefined;
}

// raiseRunlogFloor records that `index` is confirmed in destination `key`'s RUNLOG. Forward-only. startedAtMs,
// when known, is when the run that appended it began: a destination repointed after that instant keeps its
// reset floor, because the append went to the bucket it pointed at before.
export async function raiseRunlogFloor(storage: FloorStorage, key: string, index: number, startedAtMs?: number): Promise<void> {
  if (!Number.isInteger(index) || index <= 0) return;
  const map = await readMap(storage);
  const e = map[key];
  if (e?.resetAt !== undefined && startedAtMs !== undefined && e.resetAt >= startedAtMs) return;
  if (e !== undefined && e.index >= index) return;
  map[key] = { index, ...(e?.resetAt !== undefined ? { resetAt: e.resetAt } : {}) };
  await storage.put(RUNLOG_FLOOR_KEY, map);
}

// recordCompletionFloor raises the floor for an ok completion. destinationId is the origin the seal reported;
// absent means a default-routed run, which is skipped when the default moved after the run began. An id that
// no longer names a stored destination (removed while the run was in flight) raises nothing: floorKeyFor
// would map it to the env-backed destination, which never received this append.
export async function recordCompletionFloor(storage: FloorStorage, coll: DestinationCollection, destinationId: string | undefined, index: number, startedAt: string): Promise<void> {
  const parsed = Date.parse(startedAt);
  const startedAtMs = Number.isFinite(parsed) ? parsed : undefined;
  if (destinationId !== undefined && !coll.list.some((d) => d.id === destinationId)) return;
  if (destinationId === undefined) {
    const moved = await storage.get<number>(RUNLOG_FLOOR_DEFAULT_MOVED_KEY);
    if (typeof moved === "number" && (startedAtMs === undefined || moved >= startedAtMs)) return;
  }
  await raiseRunlogFloor(storage, floorKeyFor(coll, destinationId), index, startedAtMs);
}

// recordReplicaFloor raises a replica's floor from a replicate-pass ok record. The same dangling-id rule as
// recordCompletionFloor applies.
export async function recordReplicaFloor(storage: FloorStorage, coll: DestinationCollection, destinationId: string, index: number): Promise<void> {
  if (!coll.list.some((d) => d.id === destinationId)) return;
  await raiseRunlogFloor(storage, floorKeyFor(coll, destinationId), index);
}

// noteDestinationsChanged is called on every save of the destination collection. It resets the floor of
// each destination that was removed or repointed to another location, and stamps a default move.
export async function noteDestinationsChanged(storage: FloorStorage, before: DestinationCollection | undefined, after: DestinationCollection, now: number): Promise<void> {
  const prior: DestinationCollection = before && Array.isArray(before.list) ? before : { list: [], defaultId: "" };
  const reset: string[] = [];
  for (const d of prior.list) {
    if (d.source === "deploy") continue; // the env-backed destination: the DO cannot see it move
    const next = after.list.find((a) => a.id === d.id);
    if (!next || next.source === "deploy" || locationOf(next) !== locationOf(d)) reset.push(d.id);
  }
  if (floorKeyFor(prior, undefined) !== floorKeyFor(after, undefined)) await storage.put(RUNLOG_FLOOR_DEFAULT_MOVED_KEY, now);
  if (reset.length === 0) return;
  const map = await readMap(storage);
  for (const id of reset) map[id] = { index: 0, resetAt: now };
  const keys = Object.keys(map);
  if (keys.length > RUNLOG_FLOOR_MAP_MAX) {
    // Reap the OLDEST tombstones first. A live floor (index > 0) is never reaped.
    const tombstones = keys.filter((k) => map[k]!.index === 0).sort((a, b) => (map[a]!.resetAt ?? 0) - (map[b]!.resetAt ?? 0));
    for (const k of tombstones.slice(0, keys.length - RUNLOG_FLOOR_MAP_MAX)) delete map[k];
  }
  await storage.put(RUNLOG_FLOOR_KEY, map);
}

// resetRunlogFloor is the Owner's attended reset (admin/router-runlog.ts POST /runlog/floor/reset), the way out
// of the redeploy residual above: an env destination repointed to another bucket keeps the "" floor, and the
// RUNLOG writers then refuse that bucket. It moves the floor DOWN to `to` (the highest index of the RUNLOG the
// Owner was shown, 0 when absent), stamped resetAt like a repoint, so a run that began before the reset cannot
// raise it with an index only the old bucket holds. expect is the floor the Owner was shown: a floor that moved
// since is "moved" and nothing changes. Never called by the engine on its own.
export async function resetRunlogFloor(storage: FloorStorage, key: string, expect: number | undefined, to: number, now: number): Promise<"reset" | "moved"> {
  const current = await readRunlogFloor(storage, key);
  if (current !== expect) return "moved";
  const map = await readMap(storage);
  map[key] = { index: Number.isInteger(to) && to > 0 ? to : 0, resetAt: now };
  await storage.put(RUNLOG_FLOOR_KEY, map);
  return "reset";
}
