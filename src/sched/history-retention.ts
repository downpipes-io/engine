// history-retention: the time-based retention policy for the per-downpipe run-history ring
// (ASVS V14.1.2 first increment; docs/security/data-classification.md section 2.14).
//
// THE GAP THIS CLOSES. The run-history ring (key `hist:<downpipeId>`, scheduler-do-scheduling.ts) is
// already bounded by COUNT: RING_CAP (scheduler-do-limits.ts) keeps only the most recent 50 entries per
// downpipe. A count bound is not a retention policy in the ASVS sense, because it never trips for a
// low-traffic downpipe -- a downpipe that runs once a month keeps its FIRST run's metadata for as long
// as the account exists, with no age-based floor at all. This module adds the missing AGE bound: an
// entry older than RUN_HISTORY_MAX_AGE_MS is purged regardless of how many entries the ring holds.
//
// PURE. No storage, no DO, no cron, no env. purgeRunHistoryEntries is the single chokepoint the
// cron-driven pass (cron/history-retention-pass.ts) and the DO route it calls
// (scheduler-do-routing.ts POST /history-retention-pass) both rely on, so the policy is defined once
// and the DO never has to re-derive it. Nothing here reads an environment binding: the engine Durable
// Object receives no env, and this module carries the retention window as a plain constant, not an
// env-derived fact.

import type { RunHistoryEntry } from "./types.ts";

// RUN_HISTORY_MAX_AGE_DAYS is the retention window for one run-history entry, independent of the
// RING_CAP count bound. 400 days covers a full year of periodic (monthly/quarterly) compliance review
// plus slack for a late audit, while still giving the ring a real ceiling instead of none. It is a
// separate constant from AUDIT_CAP (admin/audit.ts): the audit chain is capped by COUNT for a different
// reason (a tamper-evident hash chain), and tying the two together would make an unrelated future change
// to one silently move the other.
export const RUN_HISTORY_MAX_AGE_DAYS = 400;
export const RUN_HISTORY_MAX_AGE_MS = RUN_HISTORY_MAX_AGE_DAYS * 24 * 60 * 60 * 1000;

// ageMs reads startedAt (RFC-3339, the same format the manifest/RUNLOG use) and returns how old the
// entry is, or null when the timestamp will not parse. A malformed or absent timestamp is NEVER treated
// as expired: the retention window failing to prove itself elapsed must default to RETAINING the row,
// not deleting it, matching every other fail-safe direction the retention/prune subsystem takes
// (seal/prune.ts's own abstain-on-unreadable discipline).
function ageMs(entry: RunHistoryEntry, nowMs: number): number | null {
  const t = Date.parse(entry.startedAt);
  return Number.isFinite(t) ? nowMs - t : null;
}

export interface RunHistoryPurgeResult {
  readonly kept: readonly RunHistoryEntry[];
  readonly purged: number;
}

/**
 * purgeRunHistoryEntries partitions one downpipe's ring into the rows the retention window keeps and a
 * count of how many it purged. Order is preserved among the kept rows (a stable filter, not a resort).
 *
 * An `in-flight` row is NEVER purged, whatever its age: it carries no completion time yet, and the
 * scheduler's own heartbeat/complete paths (scheduler-do-scheduling.ts) key off this ring by runId, so
 * removing a row the scheduler still expects to update would silently orphan a run in progress.
 *
 * @param ring - the downpipe's stored ring, newest-appended last (the on-disk order).
 * @param nowMs - the current time, injected so the function is deterministic and testable.
 * @param maxAgeMs - the retention window; an entry strictly older than this is purged.
 * @returns the retained rows (same relative order) and how many were purged.
 */
export function purgeRunHistoryEntries(ring: readonly RunHistoryEntry[], nowMs: number, maxAgeMs: number): RunHistoryPurgeResult {
  const kept: RunHistoryEntry[] = [];
  let purged = 0;
  for (const entry of ring) {
    const age = entry.status === "in-flight" ? null : ageMs(entry, nowMs);
    if (age !== null && age > maxAgeMs) {
      purged++;
      continue;
    }
    kept.push(entry);
  }
  return { kept, purged };
}
