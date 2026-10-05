// Destination-id resolvers for a downpipe config (primary / replicas / all). These are pure free
// functions kept apart from scheduler-do.ts (the SchedulerDO class stays lean)
// so the class file shrinks without any behaviour change: every call site is unchanged because
// scheduler-do.ts imports these back and re-exports them under the same names. They take only the
// inline { destinationId?, destinationIds? } shape, so this module is a clean leaf (no imports) that
// scheduler-do.ts depends on, never the reverse (keeps madge at 0 cycles).

// primaryDestinationId is the destination a downpipe SEALS to: the first non-blank destinationIds
// entry (fan-out) else the legacy single destinationId else undefined (=> the default). It drops
// blanks so a malformed list can never resolve to "".
export function primaryDestinationId(c: { destinationId?: string; destinationIds?: string[] }): string | undefined {
  const first = (c.destinationIds ?? []).find((x) => typeof x === "string" && x.trim() !== "");
  return first ?? c.destinationId;
}

// replicaDestinationIds are the EXTRA destinations a finalised run is replicated to (every
// destinationIds entry after the primary), de-duplicated and with the primary removed so a run never
// double-writes or self-replicates. Empty for a single-destination downpipe (the common case).
export function replicaDestinationIds(c: { destinationId?: string; destinationIds?: string[] }): string[] {
  const primary = primaryDestinationId(c);
  const seen = new Set<string>();
  const out: string[] = [];
  for (const id of c.destinationIds ?? []) {
    if (typeof id !== "string" || id.trim() === "" || id === primary || seen.has(id)) continue;
    seen.add(id);
    out.push(id);
  }
  return out;
}

// allDestinationIds is the full set a downpipe touches (primary + replicas), used by the delete guard.
export function allDestinationIds(c: { destinationId?: string; destinationIds?: string[] }): string[] {
  const p = primaryDestinationId(c);
  return [...(p !== undefined ? [p] : []), ...replicaDestinationIds(c)];
}

// gapBelowSeed reports whether a seal completion at `index` on `destinationId` would claim a run the
// destination does not hold if it raised the destination's holdsIndex from `provenTop` to `index`: true when
// the ring has an ok run of this downpipe strictly between the two that did not seal to this destination.
// A row with no recorded origin counts as a gap, because the destination it sealed to cannot be read back.
// Pure; the caller (recordReplicationState) keeps holdsIndex where it is when this is true.
export function gapBelowSeed(ring: readonly { index: number; status: string; runId?: string; destinationId?: string }[], destinationId: string, provenTop: number, index: number): boolean {
  return ring.some((e) => e.status === "ok" && !!e.runId && e.index > provenTop && e.index < index && e.destinationId !== destinationId);
}

// heldAboveWindow is the stored form of a destination's holdsAbove list (DestReplState): the valid,
// distinct, non-negative integer run indexes strictly ABOVE its contiguous window top `holdsIndex`,
// ascending, at most `cap` of them (the newest are kept). Anything else in `raw` is dropped, so a malformed
// record can only make the list shorter, which is the direction that keeps more runs "at risk" in the
// removal guard. Pure.
export function heldAboveWindow(raw: unknown, holdsIndex: number, cap: number): number[] {
  if (!Array.isArray(raw)) return [];
  const set = new Set<number>();
  for (const x of raw) if (typeof x === "number" && Number.isInteger(x) && x >= 0 && x > holdsIndex) set.add(x);
  return [...set].sort((p, q) => p - q).slice(-cap);
}

// setHeldAbove stores heldAboveWindow(raw) on a replication record, above its (possibly just raised) window
// top, or removes the field when nothing is left. The caller passes the replicate pass's fresh list on an ok
// record from that pass (it read the destination's RUNLOG), else the stored list, which is then only trimmed.
export function setHeldAbove(st: { holdsIndex: number; holdsAbove?: number[] }, raw: unknown, cap: number): void {
  const above = heldAboveWindow(raw, st.holdsIndex, cap);
  if (above.length > 0) st.holdsAbove = above;
  else delete st.holdsAbove;
}

// nextReplAnchors is THE SINGLE producer of a downpipe's replication ANCHOR map: for each destination
// the downpipe is CONFIGURED to fan out to, the value of the downpipe's monotone sealed-run counter
// (DownpipeState.sealedRuns) at the moment that destination ENTERED the fan-out list.
//
// WHY IT EXISTS. "This destination has never reported a replication heartbeat" is, on its own, the state of a
// destination configured five minutes ago AND the state of a destination that has held no copy since March.
// One is the healthiest thing in the product and the other is the 3-2-1 promise silently unmet, and an alarm
// that cannot tell them apart fires on the customer who did nothing wrong. The anchor is the missing
// discriminator, and it is a COUNT, never a timestamp of a customer event: sealedRuns - anchor = how many
// backups have SUCCEEDED since this destination was configured and still produced no copy. Zero is the new
// destination. Two is a fault.
//
// It is DELIBERATELY idempotent and preserving: an existing anchor is carried through UNCHANGED, so an
// unrelated config edit (a rename, a cadence change) can never reset the clock on a destination that has been
// failing for months. A destination NEW to the list anchors at the CURRENT counter (it is owed nothing yet). A
// destination DROPPED from the list loses its anchor (re-adding it correctly starts the count again).
//
// The same function serves both call sites (the config upsert, and the lazy backfill on run completion for a
// record written before this shipped), so the two cannot drift. The backfill anchors a legacy destination at
// the CURRENT head, which UNDERSTATES how long it has been failing: conservative on purpose, the signal is
// silent for two more successful runs rather than asserting a history it did not observe.
export function nextReplAnchors(
  prior: Record<string, number> | undefined,
  configured: readonly string[],
  sealedRuns: number,
): Record<string, number> | undefined {
  if (configured.length === 0) return undefined;
  const head = Number.isFinite(sealedRuns) && sealedRuns > 0 ? Math.floor(sealedRuns) : 0;
  const out: Record<string, number> = {};
  for (const id of configured) {
    const p = prior?.[id];
    out[id] = typeof p === "number" && Number.isFinite(p) && p >= 0 ? Math.min(Math.floor(p), head) : head;
  }
  return out;
}

// replNeverReportedSince is the READ side of the anchor: given the never-reported destination ids, the
// anchor map and the downpipe's sealed-run counter, it returns the LARGEST number of successful backups that
// have completed since ANY of them was configured (`maxSince`), and how many of them carry NO anchor at all
// (`unanchored` -- a record written before the anchor shipped, whose age cannot yet be established).
//
// maxSince is undefined when NOTHING is anchored: an honest absence, not a zero. A zero MEANS something here
// ("no backup has succeeded since it was configured, so it is owed no copy yet") and must never be forged.
export function replNeverReportedSince(
  neverReportedIds: readonly string[],
  anchors: Record<string, number> | undefined,
  sealedRuns: number,
): { maxSince?: number; unanchored: number } {
  const head = Number.isFinite(sealedRuns) && sealedRuns > 0 ? Math.floor(sealedRuns) : 0;
  let maxSince: number | undefined;
  let unanchored = 0;
  for (const id of neverReportedIds) {
    const a = anchors?.[id];
    if (typeof a !== "number" || !Number.isFinite(a) || a < 0) {
      unanchored++;
      continue;
    }
    const since = Math.max(0, head - Math.floor(a));
    if (maxSince === undefined || since > maxSince) maxSince = since;
  }
  return { ...(maxSince !== undefined ? { maxSince } : {}), unanchored };
}

// retentionWidensPrune says whether a downpipe upsert lets the cron retention pass delete more than the
// stored config lets it delete. addDownpipe asks for restore.apply when it does, which is the capability
// the attended prune route needs (router-retention-prune.ts). It lives here because the replica rule
// below reads the destination list. Only a config with enforce true can delete, so an edit that ends
// with enforce off or absent never widens. With enforce on, the edit widens when:
//  - enforce was not on before (an arm, or a create with enforce on);
//  - a stored keepRuns or keepDays bound goes down or is removed (a run is kept if EITHER bound keeps it,
//    so adding a bound keeps more and is not a widening);
//  - a stored replica is no longer a replica (the replica-coverage hold in seal/prune.ts keeps a run on the
//    primary until every configured replica holds it, so removing one frees runs the hold kept).
// It reads a config that validateConfig has already accepted. Pure; exported for the validator.
interface RetentionScope {
  destinationId?: string;
  destinationIds?: string[];
  retention?: { keepRuns?: number; keepDays?: number; enforce?: boolean };
}
export function retentionWidensPrune(prior: RetentionScope | undefined, next: RetentionScope): boolean {
  const r = next.retention;
  if (r?.enforce !== true) return false;
  const p = prior?.retention;
  if (prior === undefined || p?.enforce !== true) return true;
  for (const bound of ["keepRuns", "keepDays"] as const) {
    const was = p[bound];
    const now = r[bound];
    if (was !== undefined && (now === undefined || now < was)) return true;
  }
  const replicas = new Set(replicaDestinationIds(next));
  return replicaDestinationIds(prior).some((id) => !replicas.has(id));
}

// RETENTION_ARMED_ALONE_HEADER is set by the DO on an upsert response when a widening edit applied with no
// second approver (the bare token, or no other holder of restore.approve). The router reads it and raises
// the retention-armed-alone alert. The value is the number of downpipes armed alone.
export const RETENTION_ARMED_ALONE_HEADER = "x-downpipe-retention-armed-alone";
