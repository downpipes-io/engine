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

// latestSuccessfulRun returns the newest OK entry in a downpipe's run-history ring (index-ascending,
// newest-last), skipping over any failed/abandoned/in-flight entries above it, or undefined when no run
// in the ring has ever succeeded. This is DELIBERATELY NOT the same rule reconcileReplicationAlerts uses
// for its own proven-copy accounting (scheduler-do-sre-alerting.ts): that detector stops at the newest
// RESOLVED run and treats a non-ok newest run as nothing to reason about this tick, because it is
// answering "is replication keeping up right now". redundant-copies answers a different question --
// "does a backed-up source currently exist in two places" -- and a run that failed after a prior run
// succeeded does not erase the two proven copies of that last successful run. Pure.
export function latestSuccessfulRun<T extends { status: string }>(ring: readonly T[]): T | undefined {
  for (let i = ring.length - 1; i >= 0; i--) {
    const h = ring[i];
    if (h !== undefined && h.status === "ok") return h;
  }
  return undefined;
}

// REPL_VISIT_FALLBACK_MS bounds how long a non-origin destination gets the benefit of the doubt when the
// replication pass has not visited it since the downpipe's newest successful run finished. Posture is read
// on every GET /posture and every 6-hourly cron pass; the replication pass itself defers whole downpipes
// (and individual destinations within a downpipe) for budget, often for several ticks running, with no
// change at all to that destination's own state. Grading a destination on a run the pass has not reached
// yet, the instant that run lands, turned a healthy estate's read into a pass/fail flap at every seal (see
// gradedRunFor). After this bound with still no visit, the gap is real, not a deferral, and the check stops
// giving credit it cannot back up.
export const REPL_VISIT_FALLBACK_MS = 6 * 60 * 60 * 1000;

// runFinishedAtMs is the wall-clock moment a run-history entry finished: its recorded start plus its
// measured duration, when known. durationMs is absent only on a legacy row recorded before it was tracked;
// such a row's start is read as its finish too, which can only UNDERSTATE how long ago it finished -- the
// conservative direction, since it never gives a destination MORE time to be visited before the fallback
// bound applies.
export function runFinishedAtMs(entry: { startedAt: string; durationMs?: number }): number {
  const started = Date.parse(entry.startedAt);
  return started + (typeof entry.durationMs === "number" && entry.durationMs >= 0 ? entry.durationMs : 0);
}

// gradedRunFor picks which of a downpipe's successful runs (ascending by index, oldest first) ONE
// non-origin destination is graded against this tick: the newest run the replication pass has actually
// VISITED this destination for since that run finished (lastAttemptAt >= the run's finish). A fresh run the
// pass has not reached yet therefore cannot fail a destination that is still proven current on the run
// before it -- the destination is graded on that older, already-visited run instead, so a deferred tick (or
// one simply not yet due) reads no differently from a quiet one. Once the NEWEST run is older than
// REPL_VISIT_FALLBACK_MS with still no visit recorded on this destination, it is graded on that newest run
// regardless: a destination the pass has not reached in that long is a real gap. Returns undefined when
// neither holds -- the newest run is both unvisited and still within the fallback bound -- meaning there is
// nothing fair to grade this destination on yet. Pure.
export function gradedRunFor<T extends { index: number; startedAt: string; durationMs?: number }>(runs: readonly T[], lastAttemptAt: number, now: number): T | undefined {
  for (let i = runs.length - 1; i >= 0; i--) {
    const run = runs[i];
    if (run !== undefined && lastAttemptAt >= runFinishedAtMs(run)) return run;
  }
  const newest = runs[runs.length - 1];
  if (newest !== undefined && now - runFinishedAtMs(newest) > REPL_VISIT_FALLBACK_MS) return newest;
  return undefined;
}

// DestinationRedundancyGap is one non-origin destination assessRedundancy found NOT (yet, truthfully)
// holding the run it was graded on: lastOk is its most recent replication attempt's outcome (the
// reachability heartbeat), heldRuns/totalRuns are how many of the downpipe's retained successful runs it
// currently holds, of how many exist, for a plain "catching up" readout. Redaction-safe: an id, a
// boolean and two counts, never a key, endpoint or credential.
export interface DestinationRedundancyGap {
  destinationId: string;
  lastOk: boolean;
  heldRuns: number;
  totalRuns: number;
}

// assessRedundancy is the proven half of "N of M copies", read against the run EACH destination is fairly
// graded on (gradedRunFor) rather than a single downpipe-wide run: the origin of the downpipe's newest
// successful run always counts (the seal wrote it there); every other configured destination counts only
// when its holdsIndex is at or past the index of the run IT is graded on. A destination gradedRunFor could
// not yet fairly judge (a fresh run, not yet visited, still within the fallback bound) never counts toward
// PROVEN, but it IS still reported in `gaps`: an unvisited destination that counted toward neither side AND
// stayed unnamed would leave a downpipe failing with no explanation at all, which reads just as wrongly as
// a vacuous pass -- the operator is owed a reason either way. lastOk defaults to true (catching up, not
// failing) for a destination with no replication record at all: the absence of a repl row is "not yet
// attempted", never evidence of a failed attempt, so it must not read the same as a destination whose last
// real attempt actually failed. `runs` is the downpipe's successful runs, ascending by index (oldest
// first), exactly the shape the run-history ring already carries. Pure; no I/O.
export function assessRedundancy<T extends { index: number; startedAt: string; durationMs?: number }>(
  allDests: readonly string[],
  origin: string | undefined,
  runs: readonly T[],
  repl: Readonly<Record<string, { holdsIndex: number; lastOk?: boolean; lastAttemptAt?: number } | undefined>>,
  now: number,
): { provenCopies: number; gaps: DestinationRedundancyGap[] } {
  const totalRuns = runs.length;
  const originCounts = origin !== undefined && allDests.includes(origin);
  let provenCopies = originCounts ? 1 : 0;
  const gaps: DestinationRedundancyGap[] = [];
  for (const destId of allDests) {
    if (originCounts && destId === origin) continue;
    const st = repl[destId];
    const graded = gradedRunFor(runs, st?.lastAttemptAt ?? 0, now);
    const holdsIndex = st?.holdsIndex ?? -1;
    if (graded !== undefined && holdsIndex >= graded.index) {
      provenCopies++;
      continue;
    }
    const heldRuns = runs.filter((r) => r.index <= holdsIndex).length;
    gaps.push({ destinationId: destId, lastOk: st?.lastOk ?? true, heldRuns, totalRuns });
  }
  return { provenCopies, gaps };
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

// FAILED_DESTINATION_BASES is the closed set naming how a FAILED run's destination id is known: attempted (the
// destination the seal selected and wrote to), pinned (the downpipe's pinned id, the run failed before one
// resolved), default (the default id that was being resolved). The pack adds "unknown" for a row with none.
export const FAILED_DESTINATION_BASES = ["attempted", "pinned", "default"] as const;
export type FailedDestinationBasis = (typeof FAILED_DESTINATION_BASES)[number];
const DESTINATION_ID_SHAPE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

// failedDestinationOf re-gates an untrusted (id, basis) pair posted on a failed completion: both must pass, or
// the run records no attribution. The id keeps only the shape of a destination id (dest-81ddfcc4, deploy), so a
// URL, a bucket name or free text can never ride onto the row or into the pack.
export function failedDestinationOf(id: unknown, basis: unknown): { id: string; basis: FailedDestinationBasis } | undefined {
  if (typeof id !== "string" || !DESTINATION_ID_SHAPE.test(id)) return undefined;
  if (typeof basis !== "string" || !(FAILED_DESTINATION_BASES as readonly string[]).includes(basis)) return undefined;
  return { id, basis: basis as FailedDestinationBasis };
}

// destinationIdOf gates a posted destination id to the same shape (undefined when it is not one).
export function destinationIdOf(id: unknown): string | undefined {
  return typeof id === "string" && DESTINATION_ID_SHAPE.test(id) ? id : undefined;
}
