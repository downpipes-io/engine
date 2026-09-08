// Destination-id resolvers for a downpipe config (primary / replicas / all). These are pure free
// functions with no imports, so scheduler-do.ts can depend on them without a cycle.

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

// nextReplAnchors (G299) is THE SINGLE producer of a downpipe's replication ANCHOR map: for each destination
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

// replNeverReportedSince (G299) is the READ side of the anchor: given the never-reported destination ids, the
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
