import type { RunHistoryEntry } from "../sched/types.ts";
import type { PointInTimeRun } from "./restore-types.ts";

// Point-in-time / by-timestamp run resolution. Today a restore takes a specific runId;
// this resolves "the run to restore from AS OF timestamp T" = the LATEST SUCCESSFUL run that completed
// AT-OR-BEFORE T, from the bounded per-downpipe run-history ring. The resolved runId then flows through
// the existing restore/drill path unchanged. It is a PURE function over the redaction-safe history ring
// (run id + status + a completion time + an index), so it is unit-tested directly and carries no secret.
//
// HONEST RETAINED-WINDOW SEMANTICS (the load-bearing claim): you can only restore to a point COVERED BY
// the retained runs. The ring is bounded (RING_CAP), so a T older than the oldest retained successful run
// cannot be served, there is no archive entry to resolve to, and resolveRunAt says so plainly via the
// retainedFrom/retainedTo bounds rather than silently returning the oldest run (which would misrepresent
// the recovery point). A T after the newest run resolves to that newest run (the latest recovery point).

// completionMs derives the run's COMPLETION instant in epoch ms. The history row records startedAt (the
// trigger time) and an optional durationMs (the wall-clock of runBackup); the recovery point is when the
// run COMPLETED, which is startedAt + durationMs. A legacy row without durationMs falls back to startedAt
// (the run completed at or after it; using startedAt is the conservative under-estimate, so an at-or-before
// query never over-claims a fresher recovery point than the row can prove). Returns null when startedAt is
// unparseable (the row cannot be placed on the timeline and is excluded from resolution).
export function completionMs(entry: RunHistoryEntry): number | null {
  const started = Date.parse(entry.startedAt);
  if (!Number.isFinite(started)) return null;
  const dur = typeof entry.durationMs === "number" && Number.isFinite(entry.durationMs) && entry.durationMs >= 0 ? entry.durationMs : 0;
  return started + dur;
}

// toIso renders an epoch-ms instant as the codebase's RFC-3339 UTC-millis form (trailing sub-ms trimmed),
// matching the manifest/RUNLOG/history time format so a resolved completedAt reads identically to the
// timestamps a console already shows.
function toIso(ms: number): string {
  return new Date(ms).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}

// resolveRunAt resolves the run to restore from as of T (atMs, epoch ms) for ONE downpipe, from its run-
// history ring. The rule is AT-OR-BEFORE: the latest SUCCESSFUL ("ok") run whose completion instant is
// <= atMs. Only successful runs are eligible (a failed/abandoned/in-flight run sealed no recoverable
// archive, so it is never a recovery point). It returns:
//   found:true  { runId, completedAt, index } for the resolved run, when a successful run completed at or
//               before T within the retained ring.
//   found:false { reason, retainedFrom?, retainedTo? } when none qualifies. retainedFrom/retainedTo are the
//               completedAt bounds of the SUCCESSFUL runs the ring currently holds (absent when the ring
//               holds no successful run at all), so a console can state the honest recoverable window. The
//               reason distinguishes "T precedes the retained window" (there ARE retained runs, all newer
//               than T) from "no successful run retained" (the ring holds none).
// It NEVER throws and reads only the ring's redaction-safe fields.
export function resolveRunAt(downpipeId: string, ring: RunHistoryEntry[], atMs: number): PointInTimeRun {
  // The successful, timeline-placeable runs, each with its completion instant. A row that is not "ok" or
  // whose startedAt is unparseable is excluded (it is not a recoverable point).
  //
  // A SUCCESSFUL run whose startedAt is corrupt is silently dropped here, so a run that genuinely
  // COVERS the requested instant reads as "no run exists" and the customer is told their point-in-time
  // restore is impossible -- a data-loss-grade wrong answer produced by a timestamp bug. The exclusion is
  // now COUNTED and reported on the result: a found:false carrying excludedCorruptRuns > 0 means "we found
  // no run at or before T, AND we threw away N successful runs we could not place on the timeline", which
  // is a completely different conversation from an honest empty window. Counts only, never a raw timestamp.
  const ok: Array<{ entry: RunHistoryEntry; at: number }> = [];
  let excludedCorruptRuns = 0;
  for (const entry of ring) {
    if (entry.status !== "ok") continue;
    const at = completionMs(entry);
    if (at === null) {
      excludedCorruptRuns++;
      continue;
    }
    ok.push({ entry, at });
  }
  // The retained recoverable window (completedAt bounds across ALL retained successful runs), used in the
  // honest miss message. Computed independently of atMs so it is reported whether or not T resolves.
  let retainedFrom: number | undefined;
  let retainedTo: number | undefined;
  for (const { at } of ok) {
    if (retainedFrom === undefined || at < retainedFrom) retainedFrom = at;
    if (retainedTo === undefined || at > retainedTo) retainedTo = at;
  }
  const windowBounds = {
    ...(retainedFrom !== undefined ? { retainedFrom: toIso(retainedFrom) } : {}),
    ...(retainedTo !== undefined ? { retainedTo: toIso(retainedTo) } : {}),
    // Carried on BOTH outcomes: on a miss it is the reason the miss may be wrong, and on a hit it warns that
    // a FRESHER recovery point may exist in a row we could not place (so the resolved run may be older than
    // the true best answer). Omitted entirely when the ring is clean (the overwhelmingly common case).
    ...(excludedCorruptRuns > 0 ? { excludedCorruptRuns } : {}),
  };

  // Pick the LATEST successful run completed at-or-before T (the maximum completion instant <= atMs). A
  // tie on completion instant resolves to the higher run index (the later run), so the resolution is
  // deterministic regardless of ring order.
  let best: { entry: RunHistoryEntry; at: number } | null = null;
  for (const cand of ok) {
    if (cand.at > atMs) continue;
    if (best === null || cand.at > best.at || (cand.at === best.at && cand.entry.index > best.entry.index)) {
      best = cand;
    }
  }

  if (best === null) {
    // No successful run at or before T. Distinguish the two honest cases for the console.
    const reason = ok.length === 0
      ? "no successful run retained for this downpipe"
      : "no run completed at or before that time within the retained window";
    return { downpipeId, found: false, reason, ...windowBounds };
  }
  return {
    downpipeId,
    found: true,
    runId: best.entry.runId,
    completedAt: toIso(best.at),
    index: best.entry.index,
    ...windowBounds,
  };
}
