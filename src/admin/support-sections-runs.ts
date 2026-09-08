// Support-pack section gatherers: the runs / scheduler / infra / updates / deploy-status
// domain (run history, scheduler-liveness signals, drive budget yields, the update
// lifecycle, the deploy-identity baseline, and the DO-owned status facts). Moved verbatim
// out of support.ts, which assembles the bundle from these gatherers; each keeps its
// original redaction contract (see the per-function comments). Behaviour is unchanged.

import type { Env } from "../env.d.ts";
import { MARKER_ATTRIBUTION_ID_MAX_LEN, MARKER_ATTRIBUTION_MAX_PER_KIND, MARKER_KEYS } from "../seal/marker.ts";
import { doURL } from "../do-url.ts";
import type { BuildStatusOptions } from "./status.ts";
import { clampNonNegInt, gateClosed, UNKNOWN_CODE } from "./support-shared.ts";
import { checkUpdates, compareSemver } from "./updates.ts";
// UNKNOWN_CODE is used by the update-availability classifiers below (G258/G317).

// STATE_REFUSED_CLASSES mirrors the closed StateRefusedClass vocabulary (sched/types.ts, G095/G210). The
// scheduler-signals projection forwards a refusal class ONLY when it is a member, and support.ts re-uses the
// same set to join a refusal onto its downpipes[] row -- so an out-of-vocab class can reach neither surface.
export const STATE_REFUSED_CLASSES: ReadonlySet<string> = new Set(["schema-newer", "schema-version-malformed"]);

// PREV_RUN_ID_STATUSES mirrors the closed vocabulary run-chain.ts's annotatePredecessorChain
// emits ("none" | "retained" | "pruned" | "unknown"). fetchRunHistory gates prevRunIdStatus against it
// (defence in depth, the same discipline STATE_REFUSED_CLASSES applies above), so an out-of-vocab value
// from a future or hostile DO response is DROPPED rather than riding into the pack unreviewed.
const PREV_RUN_ID_STATUSES: ReadonlySet<string> = new Set(["none", "retained", "pruned", "unknown"]);

// fetchRunHistory shapes the per-downpipe recent run rows: coarse outcomes + redaction-safe throughput
// and observability fields (status, the enumerated error vocabulary, counts, durations, the silent-loss
// and which-destination signals); never a record name or value. At most the 10 most recent rows per
// downpipe. v:2 restores the rich fields the diagnosis layer needs (recordsSkipped/recordsIncomplete =
// silent-data-loss, with incompleteByMarker = WHICH incompleteness kinds; opCounts = throttle pressure;
// destinationId/downDestinationIds = which destination).
// boundedIncompleteIds re-clamps a run row's per-kind attribution at the PACK BOUNDARY (defence in depth): it
// keeps only the closed MARKER_KEYS, drops non-array/empty kinds, and re-applies the SAME per-kind count cap +
// per-id length clamp the seal writer enforces, so even a malformed / oversized DO row can never push an
// unbounded or malformed structure into the pack. Redaction-safe by construction (the ids are the closed/
// product-token surface ids the seal already gated; this only bounds their shape). Returns undefined when
// nothing survives, so the row simply omits the field.
function boundedIncompleteIds(raw: Record<string, string[]> | undefined): Record<string, string[]> | undefined {
  if (raw === undefined || typeof raw !== "object" || raw === null) return undefined;
  const out: Record<string, string[]> = {};
  for (const k of MARKER_KEYS) {
    const arr = raw[k];
    if (!Array.isArray(arr) || arr.length === 0) continue;
    const ids: string[] = [];
    for (const id of arr) {
      if (typeof id !== "string") continue;
      ids.push(id.slice(0, MARKER_ATTRIBUTION_ID_MAX_LEN));
      if (ids.length >= MARKER_ATTRIBUTION_MAX_PER_KIND) break;
    }
    if (ids.length > 0) out[k] = ids;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

// unknownMarkerKinds counts the incompleteness KINDS on a run row that fall OUTSIDE the closed MARKER_KEYS
// vocabulary (G317). boundedIncompleteIds drops them (correctly: the pack must never carry an unknown key's
// ids), but dropping them SILENTLY is itself the bug -- after a version skew between the seal writer and the
// pack builder, a whole new incompleteness kind vanishes and the run reads cleanly incomplete-by-nothing. The
// COUNT rides instead: the drift is visible, the raw key never is.
function unknownMarkerKinds(raw: Record<string, string[]> | undefined): number {
  if (raw === undefined || typeof raw !== "object" || raw === null) return 0;
  const known: ReadonlySet<string> = new Set<string>(MARKER_KEYS);
  return Object.keys(raw).filter((k) => !known.has(k)).length;
}


// CAUSE_DIGEST_SHAPE gates the verify verdict's one-way correlation handle: engine-computed hex, nothing else.
// A raw reader message posted into this field fails the gate and is dropped, which is the point -- the digest
// exists precisely so the TEXT (which can embed a shard id or an object key) never has to ride.
const CAUSE_DIGEST_SHAPE = /^[0-9a-f]{8,16}$/;
function projectSealVerification(v: { status: string; tier: string; sampled: number; at: number; reason?: string; tier0Cause?: string; via?: string; attempts?: number; recovered?: boolean; causeDigest?: string; failingOrdinal?: number; verifiedBeforeFail?: number }): Record<string, unknown> {
  const int = (n: unknown): number | undefined => (typeof n === "number" && Number.isFinite(n) && n >= 0 ? Math.min(Number.MAX_SAFE_INTEGER, Math.floor(n)) : undefined);
  return {
    status: String(v.status).slice(0, 32),
    tier: String(v.tier).slice(0, 32),
    sampled: int(v.sampled) ?? 0,
    at: int(v.at) ?? 0,
    ...(typeof v.reason === "string" ? { reason: v.reason.slice(0, 64) } : {}),
    ...(typeof v.tier0Cause === "string" ? { tier0Cause: v.tier0Cause.slice(0, 64) } : {}),
    // via: HOW the decrypt tier reached the master. Without it a break-glass-only estate's "full" verdict
    // reads identically to a two-recipient estate's, and support would conclude the same thing had been
    // checked. "recipient" means a wrap was decapsulated and therefore proven to open; "master" means the
    // bytes decrypt and no wrap was touched.
    ...(typeof v.via === "string" ? { via: v.via.slice(0, 16) } : {}),
    ...(int(v.attempts) !== undefined ? { attempts: int(v.attempts) } : {}),
    ...(v.recovered !== undefined ? { recovered: v.recovered === true } : {}),
    ...(typeof v.causeDigest === "string" && CAUSE_DIGEST_SHAPE.test(v.causeDigest) ? { causeDigest: v.causeDigest } : {}),
    ...(int(v.failingOrdinal) !== undefined ? { failingOrdinal: int(v.failingOrdinal) } : {}),
    ...(int(v.verifiedBeforeFail) !== undefined ? { verifiedBeforeFail: int(v.verifiedBeforeFail) } : {}),
  };
}

export async function fetchRunHistory(scheduler: DurableObjectStub): Promise<Record<string, unknown[]>> {
  const histResp = await scheduler.fetch(doURL("/history"), { method: "GET" });
  const { byDownpipe } = (await histResp.json()) as {
    byDownpipe: Record<
      string,
      Array<{
        runId: string;
        index: number;
        startedAt: string;
        status: string;
        recordCount?: number;
        bytes?: number;
        error?: string;
        causeDigest?: string;
        durationMs?: number;
        recordsSkipped?: number;
        recordsVanished?: number;
        recordsIncomplete?: number;
        incompleteByMarker?: Record<string, number>;
        incompleteIds?: Record<string, string[]>;
        opCounts?: Record<string, number>;
        archiveBytesWritten?: number;
        segmentsWritten?: number;
        destinationId?: string;
        downDestinationIds?: string[];
        // tier0Cause (mode tier0-only-reason-unknown): WHY a verified Tier-0 row skipped the decrypt sample.
        // attempts/recovered (mode runlog-sig-stale-window): a verdict that self-healed after a read-after-
        // write retry is the always-on at-seal signal of a transient RUNLOG body-vs-sig staleness window.
        sealVerification?: { status: string; tier: string; sampled: number; at: number; reason?: string; tier0Cause?: string; via?: string; attempts?: number; recovered?: boolean; causeDigest?: string; failingOrdinal?: number; verifiedBeforeFail?: number };
        multipartAbortFailed?: boolean;
        // prevRunId / prevRunIdStatus: the run-chain pointer + the DO's own honest verdict on it
        // (run-chain.ts annotatePredecessorChain), so a downloaded pack lets an auditor reconstruct the
        // predecessor chain offline too, not only via a live GET /admin/history call.
        prevRunId?: string | null;
        prevRunIdStatus?: string;
      }>
    >;
  };
  const runs: Record<string, unknown[]> = {};
  for (const [id, rows] of Object.entries(byDownpipe ?? {})) {
    // The ring is NEWEST-FIRST. The pack carries the 10 most recent rows, PLUS the smart-retained boundary row
    // (G342): the OLDEST FAILING row still in the ring -- the first status flip, whose error / causeDigest /
    // counts are the ONSET of the fault and routinely differ from the identical-looking recent failures. On an
    // hourly pipe that broke three days ago the 10-row recency window shows only the tail, so the onset (and
    // therefore what changed that day) was unrecoverable remotely. Mirrors the configEvents keystone pattern:
    // recency window + always-retained keystone. At most ONE extra row per downpipe, and none for a healthy one.
    const windowed = rows.slice(0, 10);
    const oldestFailingIdx = rows.map((r) => r.status).lastIndexOf("failed");
    const selected = oldestFailingIdx >= 10 ? [...windowed, rows[oldestFailingIdx]!] : windowed;
    runs[id] = selected.map((r) => ({
      runId: r.runId,
      index: r.index,
      startedAt: r.startedAt,
      status: r.status,
      ...(r.recordCount !== undefined ? { recordCount: r.recordCount } : {}),
      ...(r.bytes !== undefined ? { bytes: r.bytes } : {}),
      ...(r.durationMs !== undefined ? { durationMs: r.durationMs } : {}),
      ...(r.error !== undefined ? { error: r.error } : {}),
      // The 12-hex correlation digest of a FAILED run, byte-identical to the Logpush `[cause <hex>]` line for
      // the same fault. Redaction-safe (a one-way SHA-384 prefix of an already-coarse error, never raw text);
      // revives the diagnostics-bot's existing causeDigest consumer so it can join a log line to this row.
      ...(r.causeDigest !== undefined ? { causeDigest: r.causeDigest } : {}),
      // v:2 rich signals, all redaction-safe (counts, an op tally, opaque destination ids; never a value/name).
      ...(r.recordsSkipped !== undefined ? { recordsSkipped: r.recordsSkipped } : {}),
      // WS-P2: in-scope objects that vanished (were deleted) mid-crawl between list and value read (redaction-
      // safe integer count; the churn signal for a live source shifting under the backup).
      ...(r.recordsVanished !== undefined ? { recordsVanished: r.recordsVanished } : {}),
      ...(r.recordsIncomplete !== undefined ? { recordsIncomplete: r.recordsIncomplete } : {}),
      // The PER-MARKER breakdown (WHICH incompleteness kinds the run sealed): the diagnostics-bot consumes it
      // separately from the aggregate recordsIncomplete. Redaction-safe (marker key identity + integer counts).
      ...(r.incompleteByMarker !== undefined ? { incompleteByMarker: r.incompleteByMarker } : {}),
      // WS-P1 per-kind ATTRIBUTION: WHICH surface/object each incompleteness kind hit this run (redaction-safe
      // closed/product-token ids -- cf-config surface ids today). Re-clamped at the boundary; omitted when empty.
      ...((): Record<string, unknown> => { const b = boundedIncompleteIds(r.incompleteIds); return b !== undefined ? { incompleteIds: b } : {}; })(),
      // droppedUnknownCount (G317): incompleteness KINDS on this row outside the closed MARKER_KEYS vocabulary.
      // Non-zero means the seal writer has drifted ahead of the pack's allowlist -- evidence the pack would
      // otherwise have dropped in silence. A count only; the unknown key itself never rides.
      ...((): Record<string, unknown> => { const n = unknownMarkerKinds(r.incompleteIds); return n > 0 ? { droppedUnknownCount: n } : {}; })(),
      ...(r.opCounts !== undefined ? { opCounts: r.opCounts } : {}),
      ...(r.archiveBytesWritten !== undefined ? { archiveBytesWritten: r.archiveBytesWritten } : {}),
      ...(r.segmentsWritten !== undefined ? { segmentsWritten: r.segmentsWritten } : {}),
      ...(r.destinationId !== undefined ? { destinationId: r.destinationId } : {}),
      ...(r.downDestinationIds !== undefined ? { downDestinationIds: r.downDestinationIds } : {}),
      // Verify-at-seal verdict per run (ENG-RST-01): redaction-safe status/tier/sampled/at + coarse reason,
      // now with the three fields a SUSPECT verdict on a 50,000-record run actually needs (G067). The verdict
      // was previously spread verbatim from the DO row; it is projected FIELD BY FIELD here, so a future DO
      // field cannot ride into the pack unreviewed. failingOrdinal is the record INDEX the decrypt died on
      // (never a key); verifiedBeforeFail is how many verified CLEAN first (`sampled` is zeroed on failure, so
      // a suspect verdict otherwise looks like it verified nothing); and causeDigest is a one-way correlation
      // handle -- shape-gated to hex -- so two recurring reader faults can be joined WITHOUT the raw text,
      // which can embed a shard id or an object key, ever riding.
      ...(r.sealVerification !== undefined ? { sealVerification: projectSealVerification(r.sealVerification) } : {}),
      // multipart-abort-stranded-parts: a FAILED multipart upload's best-effort abort ALSO failed on this
      // run's destination, stranding invisible part-storage. A BOOLEAN only (never a key/id/value); carried
      // only when true, so a clean run row is byte-identical to before.
      ...(r.multipartAbortFailed === true ? { multipartAbortFailed: true } : {}),
      // The predecessor chain pointer (a run id or null for a genuine first run, never an
      // absent-reads-as-empty-string coercion) + the DO's own honest verdict on it, so a downloaded pack
      // lets an auditor reconstruct a downpipe's run chain offline, not only via a live admin read.
      // prevRunIdStatus is gated to the closed vocabulary (defence in depth); an out-of-vocab value is
      // dropped rather than riding into the pack, matching STATE_REFUSED_CLASSES above.
      ...(r.prevRunId !== undefined ? { prevRunId: r.prevRunId } : {}),
      ...(typeof r.prevRunIdStatus === "string" && PREV_RUN_ID_STATUSES.has(r.prevRunIdStatus) ? { prevRunIdStatus: r.prevRunIdStatus } : {}),
    }));
  }
  return runs;
}

// fetchDriveBudgetYield pulls the cumulative cron seal-loop budget-yield record (failover-probe-budget-
// exhaustion): the cron records a yield when the shared per-invocation subrequest budget ran low before every
// due downpipe was dispatched, so undispatched downpipes were carried to the next tick. It has no per-run home
// (the yield happens before a run is allocated), so without this the "the fleet is too large for the per-tick
// budget; N downpipes were starved" fault is only a log line. Redaction-safe (a cumulative count + a timestamp
// + a clamped last-carried int). Best-effort: {} on failure OR when the loop has never yielded (honest absence).
export async function fetchDriveBudgetYield(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  try {
    const r = await scheduler.fetch(doURL("/drive-budget-yield"), { method: "GET" });
    const j = (await r.json()) as { count?: unknown; lastAt?: unknown; lastCarried?: unknown } | null;
    if (j === null || typeof j !== "object") return {};
    return {
      ...(typeof j.count === "number" && Number.isFinite(j.count) ? { count: Math.max(0, Math.min(1_000_000_000, Math.floor(j.count))) } : {}),
      ...(typeof j.lastAt === "number" && Number.isFinite(j.lastAt) ? { lastAt: j.lastAt } : {}),
      ...(typeof j.lastCarried === "number" && Number.isFinite(j.lastCarried) ? { lastCarried: Math.max(0, Math.min(1_000_000, Math.floor(j.lastCarried))) } : {}),
    };
  } catch {
    // A read fault is NOT honest absence (no yields recorded). Flag it so the two are distinguishable (G031).
    return { driveBudgetUnavailable: true };
  }
}

// fetchStatusBaseline pulls the deploy-identity marker recorded at the last status-snapshot baseline (engine-
// version-change-baseline-suppressed / same-version-redeploy-double-blind): the engine version + Cloudflare
// deploy id + time observed when the baseline was (re-)established. A snapshot RESET (a wiped/first-poll
// control plane) re-stamps it with a fresh `at`, so comparing `at` across two packs reveals a reset a same-
// version redeploy would otherwise hide, and cfVersionId names which deploy. Redaction-safe (a version string
// + a deploy id + a timestamp). Best-effort: {} on failure OR before the first observation (honest absence).
export async function fetchStatusBaseline(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  try {
    const j = (await (await scheduler.fetch(doURL("/status-baseline"), { method: "GET" })).json()) as { version?: unknown; cfVersionId?: unknown; at?: unknown } | null;
    if (j === null || typeof j !== "object") return {};
    return {
      ...(typeof j.version === "string" ? { version: j.version.slice(0, 64) } : {}),
      ...(typeof j.cfVersionId === "string" ? { cfVersionId: j.cfVersionId.slice(0, 128) } : {}),
      ...(typeof j.at === "number" && Number.isFinite(j.at) ? { at: j.at } : {}),
    };
  } catch {
    return {};
  }
}

// fetchSchedulerSignals pulls the redaction-safe SCHEDULER-LIVENESS aggregate (RUNS-SCHEDULER + INFRA
// new-logging) into the pack: the per-cron-tick OUTCOME ring (the false-green detector -- a tick that
// dispatched 0 of N due, overdrew its subrequest budget, crashed a pass, or missed ticks), the due-index
// parity snapshot (SCHED due-index-drift / rebuild-partial-or-too-big), and the runlog counter vs the max
// run-history index (SCHED runlog-counter-reset, derived as counter < maxHistoryIndex). Every field is a
// COUNT / flag / clamped timestamp -- no id, name or value -- so it is redaction-safe by construction.
export async function fetchSchedulerSignals(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  {
    const r = await scheduler.fetch(doURL("/scheduler-signals"), { method: "GET" });
    const j = (await r.json()) as { ticks?: unknown; dueIndex?: unknown; runlog?: unknown; listCaps?: unknown; storageFaults?: unknown; schedHealth?: unknown; stateRefusals?: unknown };
    const out: Record<string, unknown> = {};
    // The per-tick outcome ring: capped to the most-recent 64 (the DO already bounds it; re-cap + re-clamp
    // defensively) and reduced to the closed count/flag fields. `overBudget` is the subrequest-overdraw flag.
    if (Array.isArray(j.ticks) && j.ticks.length > 0) {
      out.ticks = j.ticks.slice(-64).map((t) => {
        const row = (typeof t === "object" && t !== null ? t : {}) as Record<string, unknown>;
        return {
          at: clampNonNegInt(row.at),
          intervalMs: clampNonNegInt(row.intervalMs),
          due: clampNonNegInt(row.due),
          dispatched: clampNonNegInt(row.dispatched),
          coalesced: clampNonNegInt(row.coalesced),
          carried: clampNonNegInt(row.carried),
          sealErrors: clampNonNegInt(row.sealErrors),
          passErrors: clampNonNegInt(row.passErrors),
          budgetCap: clampNonNegInt(row.budgetCap),
          budgetSpent: clampNonNegInt(row.budgetSpent),
          budgetRemaining: clampNonNegInt(row.budgetRemaining),
          overBudget: row.overBudget === true,
        };
      });
    }
    // The due-index parity snapshot (the last O(N) reconcile's counts): index entries the DO held vs the
    // entries dp: truth requires + the fleet total. `matched` is the healthy steady state; a mismatch is a
    // drifted/partial index (or a first-deploy build). Omitted when no reconcile has stamped one yet.
    if (j.dueIndex && typeof j.dueIndex === "object" && Object.keys(j.dueIndex).length > 0) {
      const d = j.dueIndex as Record<string, unknown>;
      out.dueIndex = {
        ...(typeof d.at === "number" ? { at: clampNonNegInt(d.at) } : {}),
        indexEntriesBeforeRebuild: clampNonNegInt(d.indexEntriesBeforeRebuild),
        indexEntriesRequired: clampNonNegInt(d.indexEntriesRequired),
        dpTotal: clampNonNegInt(d.dpTotal),
        matched: d.matched === true,
      };
    }
    // The runlog counter vs the highest run index any history ring records. `reset` (counter < maxHistoryIndex)
    // is the runlog-counter-reset signal: a wiped/reset counter re-allocates indices that collide with runs
    // already recorded, breaking the monotonic join key.
    if (j.runlog && typeof j.runlog === "object") {
      const rl = j.runlog as Record<string, unknown>;
      const counter = clampNonNegInt(rl.counter);
      const maxHistoryIndex = clampNonNegInt(rl.maxHistoryIndex);
      out.runlog = { counter, maxHistoryIndex, reset: counter < maxHistoryIndex };
    }
    // listCaps (INFRA do-list-pagination-cap): the DO's per-list page size + paging guard + the live history-ring
    // count, so a fleet approaching pageSize*maxPages (silent read truncation) is visible. Ints only.
    if (j.listCaps && typeof j.listCaps === "object") {
      const lc = j.listCaps as Record<string, unknown>;
      out.listCaps = { pageSize: clampNonNegInt(lc.pageSize), maxPages: clampNonNegInt(lc.maxPages), historyRings: clampNonNegInt(lc.historyRings) };
    }
    // storageFaults (SCHED persist-state-storage-fault / INFRA do-value-size-limit): the DISTINCT persist-state
    // storage-fault counter, isolating the persist/storage-fault subset (putFailed) and the DO-value-too-large
    // subset (valueTooLarge) from the generic tick sealErrors/passErrors. Projected ONLY when a fault has been
    // recorded (total > 0), so a healthy engine omits it entirely. Ints + a closed lastKind enum (an out-of-vocab
    // value is DROPPED, defence-in-depth redaction) + a clamped timestamp -- no id/name/value rides (no-custody).
    if (j.storageFaults && typeof j.storageFaults === "object") {
      const sf = j.storageFaults as Record<string, unknown>;
      const total = clampNonNegInt(sf.total);
      if (total > 0) {
        out.storageFaults = {
          total,
          valueTooLarge: clampNonNegInt(sf.valueTooLarge),
          putFailed: clampNonNegInt(sf.putFailed),
          lastAt: clampNonNegInt(sf.lastAt),
          ...(sf.lastKind === "value-too-large" || sf.lastKind === "put-failed" ? { lastKind: sf.lastKind } : {}),
          // lastDownpipeId (G040): WHICH downpipe's dp: record was being persisted when the put threw. A
          // climbing valueTooLarge count that names no downpipe cannot be acted on; this attributes it. The
          // customer's own downpipe label (the class downpipes[]/sealFaults already carry), re-clamped here.
          ...(typeof sf.lastDownpipeId === "string" && sf.lastDownpipeId !== "" ? { lastDownpipeId: sf.lastDownpipeId.slice(0, 128) } : {}),
        };
      }
    }
    // schedHealth (G040): the scheduler HOUSEKEEPING faults that are otherwise fully silent -- a best-effort
    // alarm() sweep that throws (DO storage grows unbounded), a listAllByPrefix that EXHAUSTED its paging guard
    // (downpipes past the cap are never enumerated, so they read as nonexistent to due() and simply stop being
    // scheduled), and a due-index parity stamp that failed to write. parityStampStale is DERIVED in the DO: the
    // last parity-stamp WRITE failed at/after the dueIndex snapshot above, so that snapshot must NOT be read as a
    // fresh parity measurement. Projected only when something actually fired (a healthy engine omits it).
    // Counts + clamped timestamps + a boolean (no-custody).
    if (j.schedHealth && typeof j.schedHealth === "object") {
      const sh = j.schedHealth as Record<string, unknown>;
      const counter = (v: unknown): { count: number; lastAt: number } => {
        const c = (typeof v === "object" && v !== null ? v : {}) as Record<string, unknown>;
        return { count: clampNonNegInt(c.count), lastAt: clampNonNegInt(c.lastAt) };
      };
      const sweepFaults = counter(sh.sweepFaults);
      const listTruncations = counter(sh.listTruncations);
      const parityStampFailures = counter(sh.parityStampFailures);
      const anyFired = sweepFaults.count > 0 || listTruncations.count > 0 || parityStampFailures.count > 0;
      if (anyFired || sh.parityStampStale === true) {
        out.schedHealth = { sweepFaults, listTruncations, parityStampFailures, parityStampStale: sh.parityStampStale === true };
      }
    }
    // stateRefusals (G095/G210): the downpipes whose persisted dp: record this engine REFUSED to read at the
    // load-bearing due()/trigger() reads -- an engine ROLLED BACK onto new-shape state (schema-newer), or a
    // corrupt/hand-edited version stamp (schema-version-malformed). Each is a downpipe that silently STOPPED
    // producing runs: it is skipped before a run row is ever created, so the pack shows only growing staleness
    // with no failed run to explain it. The class is gated on the closed vocabulary (an out-of-vocab value is
    // DROPPED, defence in depth); the record's CONTENTS never ride, only the two version ints, a count and a
    // clamped timestamp, keyed by the customer's own downpipe label. Projected only when something was refused.
    if (j.stateRefusals && typeof j.stateRefusals === "object") {
      const sr = j.stateRefusals as { total?: unknown; truncated?: unknown; downpipes?: unknown };
      const rows = (Array.isArray(sr.downpipes) ? sr.downpipes : []).slice(0, 25).flatMap((row) => {
        const rr = (typeof row === "object" && row !== null ? row : {}) as Record<string, unknown>;
        if (typeof rr.downpipeId !== "string" || rr.downpipeId === "") return [];
        if (!STATE_REFUSED_CLASSES.has(rr.class as string)) return [];
        return [{
          downpipeId: rr.downpipeId.slice(0, 128),
          class: rr.class as string,
          at: clampNonNegInt(rr.at),
          count: clampNonNegInt(rr.count),
          storedVersion: clampNonNegInt(rr.storedVersion),
          supportedVersion: clampNonNegInt(rr.supportedVersion),
        }];
      });
      if (rows.length > 0) out.stateRefusals = { total: clampNonNegInt(sr.total), truncated: sr.truncated === true, downpipes: rows };
    }
    return out;
  }
}

// UPDATE_REASON_CLASSES: the CLOSED cause vocabulary that replaces the update lifecycle's free-text `reason` in
// the pack. Each member names a DIFFERENT remedy, which is the whole reason the class exists rather than a
// truncated sentence.
export const UPDATE_REASON_CLASSES = [
  "upload-failed", // the new version could not be uploaded: the engine is unchanged, nothing was applied
  "promote-failed", // uploaded but promotion failed: the prior version is still serving
  "ramp-start-failed", // the gradual ramp would not start: still 100% on the prior version
  "rollback-failed", // THE BAD ONE: the new version failed AND the rollback failed, so the customer is serving a version they did not want
  "verify-failed", // the bundle or the canary did not verify
  "account-not-marked", // the config-level gate refused: the engine's own Cloudflare account is not marked
  "other", // the residual: counted, never dropped, never text
] as const;
export type UpdateReasonClass = (typeof UPDATE_REASON_CLASSES)[number];

// updateReasonClass is a CLASSIFIER, in the strict sense this codebase means it: it may READ the engine's
// sentence to SELECT a closed member, and it RETURNS that member. The text itself never crosses the boundary.
//
// It exists because the sentence is no longer safe to project. The update paths build it as
// `...the previously-live version is still serving...: ${msg(e)}`, so it now carries the raw Cloudflare
// deploy-driver error, which can embed a URL, an account id or a script name. A clamp is not a
// redaction: it bounds the length of the leak, not its content.
// A SUCCESSFUL update names no cause. Classifying one would fabricate a fault out of a healthy state:
// a support engineer must never be sent to investigate a clean apply. Only a non-success outcome is
// classified at all.
const UPDATE_SUCCESS_OUTCOMES: ReadonlySet<string> = new Set(["applied", "applied-unconfirmed", "no-op", "up-to-date", "confirmed"]);

function updateReasonClass(reason: unknown, outcome: unknown): UpdateReasonClass | undefined {
  const r = typeof reason === "string" ? reason.toLowerCase() : "";
  const o = typeof outcome === "string" ? outcome.toLowerCase() : "";
  if (r === "" && o === "") return undefined; // honest absence: nothing has happened
  if (UPDATE_SUCCESS_OUTCOMES.has(o)) return undefined; // a clean update HAS no cause: do not invent one
  // The OUTCOME is authoritative where it is explicit: it is already a closed engine enum, and it is the one
  // field the rollback paths were widened to tell the truth in.
  if (o.includes("rollback-failed")) return "rollback-failed";
  if (r.includes("could not be uploaded")) return "upload-failed";
  if (r.includes("promotion failed") || r.includes("did not land as the live version")) return "promote-failed";
  if (r.includes("ramp could not be started")) return "ramp-start-failed";
  if (r.includes("rollback") && r.includes("failed")) return "rollback-failed";
  if (r.includes("did not verify") || r.includes("did not pass verification")) return "verify-failed";
  if (r.includes("account") && r.includes("mark")) return "account-not-marked";
  return "other";
}

// SETTLE_STEP_DETAIL_CLASSES + READBACK_DETAIL_CLASSES: the CLOSED vocabularies that replace the LAST TWO raw
// platform strings the update lifecycle put in the pack.
//
// The `reason` sentence was classified when it was found to be carrying the raw Cloudflare deploy error. These
// two survived that pass behind a 160-char clamp, in the same object literal, and a clamp is not a redaction:
// it bounds the LENGTH of a leak, not its content.
//
//   settleTrace[].detail  update-gate.ts's canary-flight step writes the CanaryLiveness verdict on the happy
//                         path, but its catch arm interpolates the raw fetch/Workers exception (which carries
//                         the canary URL and hostname). The single likeliest populator of that arm is exactly
//                         the incident this section exists for: a failed rollback with an ailing canary.
//   readback.detail       update-apply.ts's readBackUploaded returns `detail: msg(e)` on a thrown read-back,
//                         which is the raw Cloudflare API message (URL, account id, script name) -- the same
//                         class of leak that was taken out of `reason`.
//
// Both are CLASSIFIERS: they may READ the engine's own sentence to SELECT a closed member, and they RETURN
// that member. The sentence stays on the operator's own API response, where their console renders it, and it
// never crosses the pack boundary. The step LABELS (canary-flight, self-check, the retry suffixes) are
// engine-authored constants and stay as they are.
export const SETTLE_STEP_DETAIL_CLASSES = [
  "alive", // the canary flight came back ALIVE: every byte of the probe archive round-tripped
  "dead", // the flight came back DEAD: data evidence of a regression, never retried
  "ailing", // the flight came back AILING: it RAN, and could not prove health in the window
  // G275: THREE members have now been deleted from this vocabulary for the SAME reason, and the reason is the
  // whole point of the exercise: a closed-set member with no reachable production producer tells a support
  // engineer the evidence was looked for and not found, which is worse than an honest absence.
  //
  //   "flight-errored" -- could only be written when gate.flyNow() THREW. probeSettleVerdict's ONE production
  //   call site (router-updates.ts) always passes makeHealthGate, whose flyNow wraps its own scheduler fetch,
  //   and runCanaryCycle never throws by construction. Zero producers.
  //
  //   "pending" -- the settle's detail is `f.status` only when the flight MEASURED something, and a measured
  //   flight is alive, dead or ailing: runCanaryCycle returns "pending" from exactly ONE exit (resolveDestination's
  //   catch, canary/cycle.ts), which records a single "skip" aspect and is therefore, by definition, unmeasured.
  //   So (status "pending", measured true) is unreachable through the only gate the route builds, and the row it
  //   promised ("the flight had not resolved when it was read") is a state the gate cannot be in: flight() runs a
  //   full SYNCHRONOUS cycle (write, seal, read, restore) and returns a completed verdict. Zero producers.
  //
  //   "disabled" -- runCanaryCycle never returns it at all. Zero producers.
  //
  // The defensive catch in probeSettleVerdict stays; if it ever did fire, its detail coarsens to "other"
  // (counted, never dropped) rather than to a class that lies.
  "unmeasured", // the flight ATTEMPTED NOTHING: it resolved no destination, so no probe ran, and this is the "the engine cannot reach its own destination" fact. A flight that RAN reports alive, dead or ailing, never this
  "selfcheck-passed", // the fallback self-check: the new version boots, answers and reports the expected version
  "selfcheck-failed", // the fallback self-check did not pass
  "other", // the residual: counted, never dropped, never text
] as const;
export type SettleStepDetailClass = (typeof SETTLE_STEP_DETAIL_CLASSES)[number];

function settleStepDetailClass(detail: unknown): SettleStepDetailClass | undefined {
  if (typeof detail !== "string" || detail === "") return undefined;
  const d = detail.toLowerCase();
  // alive / dead / ailing are the three liveness verdicts a MEASURED flight can report, and they are the only
  // bare-liveness details the production settle can author (see the vocabulary note above). "pending" and
  // "disabled" are CanaryLiveness members the settle route can never write here, so they are not admitted: were
  // one ever to arrive from a non-production gate it coarsens to "other" rather than to a class with no producer.
  if (d === "alive" || d === "dead" || d === "ailing") return d;
  // Tested BEFORE the residual: this is the one detail probeSettleVerdict authors that is not a bare liveness.
  if (d.includes("measured nothing")) return "unmeasured";
  if (d.includes("did not pass its self-check")) return "selfcheck-failed";
  if (d.includes("boots, answers and reports")) return "selfcheck-passed";
  return "other";
}

const SETTLE_STEP_SHAPE = /^(?:canary-flight|self-check)(?:-retry-\d{1,2})?$/;

// settleStep ALLOWLISTS the step label. probeSettleVerdict authors exactly four shapes ("canary-flight",
// "canary-flight-retry-N", "self-check", "self-check-retry-N"), so anything else is not an engine label and is
// DROPPED rather than clamped. A clamp would have admitted whatever a future caller put there.
function settleStep(step: unknown): string | undefined {
  if (typeof step !== "string") return undefined;
  return SETTLE_STEP_SHAPE.test(step) ? step : undefined;
}

export const READBACK_DETAIL_CLASSES = [
  "driver-unsupported", // the deploy driver cannot read a version's module back, so the digest cross-check could not be attempted at all. A capability fact, not a fault
  "digest-differs", // the platform returned bytes whose digest is NOT the signed channel's. Incident-grade, and already carried by verdict "mismatch"
  "readback-errored", // the read-back call THREW (the raw platform message went to the log, never here): the cross-check was attempted and could not complete
  "other", // the residual: counted, never dropped, never text
] as const;
export type ReadbackDetailClass = (typeof READBACK_DETAIL_CLASSES)[number];

// readbackDetailClass is a CLASSIFIER in this codebase's strict sense: it READS the engine's sentence only to
// SELECT a closed member, and returns the member. The text never crosses.
//
// It reads the VERDICT as well as the sentence, because the two arms that share verdict "unavailable" cannot be
// told apart from the text alone -- and the whole point is that one of those two texts is NOT ours to trust.
// The discrimination is therefore STRUCTURAL: readBackUploaded emits a detail on exactly three paths, and only
// the driver-unsupported one authors a sentence under an "unavailable" verdict. So an "unavailable" carrying any
// OTHER detail is the catch arm by construction, which is what gives readback-errored a real producer rather
// than a text match against a message an attacker or a platform could shape.
function readbackDetailClass(detail: unknown, verdict: unknown): ReadbackDetailClass | undefined {
  if (typeof detail !== "string" || detail === "") return undefined;
  const d = detail.toLowerCase();
  if (d.includes("does not support version read-back")) return "driver-unsupported";
  if (d.includes("digest differs")) return "digest-differs";
  if (verdict === "unavailable") return "readback-errored";
  return "other";
}

// fetchUpdateStatus surfaces the SAFE-APPLY UPDATE LIFECYCLE (UPD new-logging) + the engine-account-marked
// state into the pack: the pending-verification record, the last completed outcome + reason CLASS + canary
// verdict, the rollback-needed latch, the anti-rollback high-water mark, and whether the engine's own Cloudflare
// account is marked (the config-level gate the apply/settle/rollback paths refuse on). Version strings are
// ENGINE ids (not customer data; already carried as engine.version), bounded defensively. The free-text reason
// is NOT projected: see updateReasonClass above. Timestamps clamped. No secret, no token, no platform message.
export async function fetchUpdateStatus(env: Env, scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  {
    const clampStr = (v: unknown, n: number): string | undefined => (typeof v === "string" ? v.slice(0, n) : undefined);
    const out: Record<string, unknown> = {};
    const r = await scheduler.fetch(doURL("/update-status"), { method: "GET" });
    const j = (await r.json()) as {
      pending?: { fromVersion?: unknown; toVersion?: unknown; recommendedVersion?: unknown; riskClass?: unknown; promotedAt?: unknown } | null;
      last?: { outcome?: unknown; recommendedVersion?: unknown; fromVersion?: unknown; toVersion?: unknown; canaryVerdict?: unknown; selfCheckOk?: unknown; settleTrace?: unknown; at?: unknown; reason?: unknown; confirmationPending?: unknown; readback?: { verdict?: unknown; deployedSha384?: unknown; detail?: unknown } | null } | null;
      lastConsole?: { outcome?: unknown; reason?: unknown; at?: unknown; component?: unknown; confirmedLive?: unknown; toVersion?: unknown } | null;
      history?: Array<{ outcome?: unknown; toVersion?: unknown; at?: unknown; component?: unknown; canaryVerdict?: unknown }>;
      rollbackNeeded?: { recommendedVersion?: unknown; toVersion?: unknown; canaryVerdict?: unknown; at?: unknown } | null;
      settledHighWaterMark?: unknown;
    };
    // READBACK_VERDICT_SET (G160/G306): the closed apply-time release-digest cross-check verdict.
    const READBACK_VERDICT_SET: ReadonlySet<string> = new Set(["verified", "mismatch", "unavailable"]);
    if (j.pending && typeof j.pending === "object") {
      const p = j.pending;
      out.pending = {
        ...(clampStr(p.fromVersion, 64) !== undefined ? { fromVersion: clampStr(p.fromVersion, 64) } : {}),
        ...(clampStr(p.toVersion, 64) !== undefined ? { toVersion: clampStr(p.toVersion, 64) } : {}),
        ...(clampStr(p.recommendedVersion, 64) !== undefined ? { recommendedVersion: clampStr(p.recommendedVersion, 64) } : {}),
        ...(clampStr(p.riskClass, 32) !== undefined ? { riskClass: clampStr(p.riskClass, 32) } : {}),
        ...(typeof p.promotedAt === "number" && Number.isFinite(p.promotedAt) ? { promotedAt: Math.floor(p.promotedAt) } : {}),
      };
    }
    if (j.last && typeof j.last === "object") {
      const l = j.last;
      // G219: the two DERIVED booleans. `outcome` now carries the honest closed values (rollback-failed,
      // rollback-failed-still-split, applied-unconfirmed), but every downstream reader -- the console badge,
      // the notify rules, the diagnostics bot's update-failed-or-rollback-needed signal -- was written against
      // the OLD vocabulary, in which those states were spelled "rolled-back" and "applied". A reader that has
      // not been taught the new members would read "rollback-failed" as simply unknown and fall through to its
      // default, which is the same silence it had before. These booleans are the unambiguous, version-skew-proof
      // statement of the two facts that actually matter, and they cannot be misread by an older consumer:
      //
      //   stillServingBadVersion  the rollback did NOT land. The customer is running the build they tried to
      //                           escape (or, on a ramp, a live traffic split is still routing to it).
      //   applyUnconfirmed        the promote was accepted and the live version could never be CONFIRMED, so
      //                           "applied" would be claiming a proof that was never obtained.
      const outcome = typeof l.outcome === "string" ? l.outcome : "";
      const stillServingBadVersion = outcome === "rollback-failed" || outcome === "rollback-failed-still-split";
      out.last = {
        ...(clampStr(l.outcome, 48) !== undefined ? { outcome: clampStr(l.outcome, 48) } : {}),
        ...(stillServingBadVersion ? { stillServingBadVersion: true } : {}),
        ...(outcome === "rollback-failed-still-split" ? { trafficStillSplit: true } : {}),
        ...(outcome === "applied-unconfirmed" ? { applyUnconfirmed: true } : {}),
        ...(clampStr(l.recommendedVersion, 64) !== undefined ? { recommendedVersion: clampStr(l.recommendedVersion, 64) } : {}),
        ...(clampStr(l.fromVersion, 64) !== undefined ? { fromVersion: clampStr(l.fromVersion, 64) } : {}),
        ...(clampStr(l.toVersion, 64) !== undefined ? { toVersion: clampStr(l.toVersion, 64) } : {}),
        ...(clampStr(l.canaryVerdict, 32) !== undefined ? { canaryVerdict: clampStr(l.canaryVerdict, 32) } : {}),
        // selfCheckOk + settleTrace ( observability): the DECISION TRACE a rollback/keep-pending
        // is diagnosed from -- was it a dead canary (data failure) or a swap-window flake the hourly canary
        // will confirm. settleTrace is the per-attempt retry story, bounded (<=8 entries).
        //
        // G275 DE-LEAK: `detail` is NOT PROJECTED. probeSettleVerdict's flight arm (update-gate.ts) builds
        // `the canary flight errored: ${e.message}` from a RAW THROWN fetch error, so a Cloudflare/network
        // message -- which can embed a URL, a hostname or a script name -- must never ride into the sealed
        // bundle. A CLAMP IS NOT A REDACTION: it bounds the LENGTH of the leak, not its content. The step
        // and the closed detailClass (SETTLE_STEP_DETAIL_CLASSES) carry the whole diagnosis; the operator still
        // reads the full sentence in their OWN console (it is on the API response) and in a tail.
        ...(typeof l.selfCheckOk === "boolean" ? { selfCheckOk: l.selfCheckOk } : {}),
        ...(Array.isArray(l.settleTrace)
          ? {
              settleTrace: l.settleTrace.slice(0, 8).map((a) => {
                const e = a as { step?: unknown; ok?: unknown; detail?: unknown };
                return {
                  ...(settleStep(e.step) !== undefined ? { step: settleStep(e.step) } : {}),
                  ...(typeof e.ok === "boolean" ? { ok: e.ok } : {}),
                  // detail is NOT projected: its catch arm carries the raw canary-flight exception (URL and
                  // hostname included). The closed class carries the fact instead.
                  ...(settleStepDetailClass(e.detail) !== undefined ? { detailClass: settleStepDetailClass(e.detail) } : {}),
                };
              }),
            }
          : {}),
        ...(typeof l.at === "number" && Number.isFinite(l.at) ? { at: Math.floor(l.at) } : {}),
        // reason is NOT projected: the update paths interpolate the raw deploy-driver error into it
        // (update-rollback.ts, update-apply.ts, update-ramp.ts, update-orchestrate.ts all build
        // `...: ${msg(e)}`), so a Cloudflare API message, which can embed a URL, an account id or a script
        // name, must never ride into the sealed bundle. A clamp is not a redaction: it bounds the length of
        // the leak, not its content.
        //
        // The operator still sees the full sentence in their OWN console (it is returned on the API response and
        // rendered there). What the customer SENDS US is the closed class below, which is what a diagnosis needs.
        ...(updateReasonClass(l.reason, l.outcome) !== undefined ? { reasonClass: updateReasonClass(l.reason, l.outcome) } : {}),
        // confirmationPending (G167): the update applied via self-check and is awaiting the hourly canary's
        // live confirmation -- an "applied but not yet confirmed" that a rollback story hinges on.
        ...(typeof l.confirmationPending === "boolean" ? { confirmationPending: l.confirmationPending } : {}),
        // readback (G160/G306): the apply-time release-digest cross-check. A `mismatch` is incident-grade
        // (the deployed artefact is not the signed release) yet the pack read HEALTHY without it. Closed
        // verdict enum + the public deployed sha384 (a digest, never a secret) + a closed detail CLASS.
        //
        // G275 DE-LEAK (second arm): `detail` is NOT PROJECTED. Two of readback's three detail producers
        // are engine-authored; the third (update-apply.ts readBackUploaded's catch arm) is `detail: msg(e)`,
        // the RAW THROWN error from a fetch to the Cloudflare API, so a platform message carrying a URL, an
        // account id or a script name must never ride into the sealed bundle. A clamp bounds the LENGTH of
        // a leak, it does not redact it. The closed class below carries the whole diagnosis; the operator
        // still reads the full sentence in their OWN console (it is on the API response) and in a tail.
        ...(l.readback && typeof l.readback === "object"
          ? {
              readback: {
                ...(typeof l.readback.verdict === "string" && READBACK_VERDICT_SET.has(l.readback.verdict) ? { verdict: l.readback.verdict } : {}),
                ...(typeof l.readback.deployedSha384 === "string" ? { deployedSha384: l.readback.deployedSha384.slice(0, 96) } : {}),
                // detail is NOT projected: on a thrown read-back it is the raw Cloudflare API message (URL,
                // account id, script name), the same leak that was taken out of `reason`.
                ...(readbackDetailClass(l.readback.detail, l.readback.verdict) !== undefined ? { detailClass: readbackDetailClass(l.readback.detail, l.readback.verdict) } : {}),
              },
            }
          : {}),
      };
    }
    // lastConsole (G160/G167): the CONSOLE component's last self-apply outcome (the engine `last` above is the
    // ENGINE component; a console update has its own lifecycle). confirmedLive = the browser confirmed the new
    // console actually served. Redaction-safe: closed outcome + closed reason CLASS + booleans + version + times.
    if (j.lastConsole && typeof j.lastConsole === "object") {
      const c = j.lastConsole;
      out.lastConsole = {
        ...(clampStr(c.outcome, 48) !== undefined ? { outcome: clampStr(c.outcome, 48) } : {}),
        // Same reason as `last` above: update-orchestrate.ts interpolates the raw deploy-driver error into this
        // sentence, so the free text is replaced by its closed class.
        ...(updateReasonClass(c.reason, c.outcome) !== undefined ? { reasonClass: updateReasonClass(c.reason, c.outcome) } : {}),
        ...(clampStr(c.toVersion, 64) !== undefined ? { toVersion: clampStr(c.toVersion, 64) } : {}),
        ...(typeof c.confirmedLive === "boolean" ? { confirmedLive: c.confirmedLive } : {}),
        ...(typeof c.at === "number" && Number.isFinite(c.at) ? { at: Math.floor(c.at) } : {}),
        ...(clampStr(c.component, 32) !== undefined ? { component: clampStr(c.component, 32) } : {}),
      };
    }
    // history (G167): the bounded update outcome ring (already capped DO-side at UPDATE_HISTORY_CAP), so a
    // rollback that scrolled off `last` after a later update is still visible. Coarse per-entry projection.
    if (Array.isArray(j.history) && j.history.length > 0) {
      out.history = j.history.slice(-16).map((h) => ({
        ...(clampStr(h.outcome, 48) !== undefined ? { outcome: clampStr(h.outcome, 48) } : {}),
        ...(clampStr(h.toVersion, 64) !== undefined ? { toVersion: clampStr(h.toVersion, 64) } : {}),
        ...(clampStr(h.canaryVerdict, 32) !== undefined ? { canaryVerdict: clampStr(h.canaryVerdict, 32) } : {}),
        ...(clampStr(h.component, 32) !== undefined ? { component: clampStr(h.component, 32) } : {}),
        ...(typeof h.at === "number" && Number.isFinite(h.at) ? { at: Math.floor(h.at) } : {}),
      }));
    }
    if (j.rollbackNeeded && typeof j.rollbackNeeded === "object") {
      const rb = j.rollbackNeeded;
      out.rollbackNeeded = {
        ...(clampStr(rb.recommendedVersion, 64) !== undefined ? { recommendedVersion: clampStr(rb.recommendedVersion, 64) } : {}),
        ...(clampStr(rb.toVersion, 64) !== undefined ? { toVersion: clampStr(rb.toVersion, 64) } : {}),
        ...(clampStr(rb.canaryVerdict, 32) !== undefined ? { canaryVerdict: clampStr(rb.canaryVerdict, 32) } : {}),
        ...(typeof rb.at === "number" && Number.isFinite(rb.at) ? { at: Math.floor(rb.at) } : {}),
      };
    }
    if (clampStr(j.settledHighWaterMark, 64) !== undefined) out.settledHighWaterMark = clampStr(j.settledHighWaterMark, 64);
    // engineAccountMarked (UPD engine-account-unmarked-blocks-update): the CONFIG-LEVEL gate the update paths
    // refuse on -- the CF_ACCOUNT_ID deploy var, else the discovery config's marked engineAccountId. A false
    // here means every self-apply update/settle/rollback is blocked until the owner marks the account. (The
    // engine's live single-account-scan fallback needs a CF API call the offline pack does not make; this is
    // the offline config-level answer, which is what the operator sets.) A boolean only, never the account id.
    let marked = typeof env.CF_ACCOUNT_ID === "string" && env.CF_ACCOUNT_ID.trim() !== "";
    if (!marked) {
      const cr = await scheduler.fetch(doURL("/sources/discovery-config"), { method: "GET" });
      const cfg = ((await cr.json()) as { config?: { engineAccountId?: string | null } | null }).config ?? null;
      marked = typeof cfg?.engineAccountId === "string" && cfg.engineAccountId !== "";
    }
    out.engineAccountMarked = marked;
    // available (G258): the UPDATE-AVAILABILITY GATING VERDICTS. The pack carried version strings and the
    // DO-side lifecycle, but nothing about WHY the console offers no update at all -- "why is there no Update
    // now button", "the release notes disappeared", "the console never offers me updates". Each blocking verdict
    // had to be inferred or dug out of live engine state. They are all already computed by checkUpdates (the
    // same call the console's update screen makes); this projects them, coarsened:
    //   channelIssue    : the CLOSED class of why the channel did not verify (never the engine's sentence, and
    //                     never the channel URL) -- not-configured / url-invalid / not-https / signer-key-invalid
    //                     / fetch-failed / signature-invalid.
    //   channelBaseValid: the configured channel url parses AND is https (the https gate that silently blocks).
    //   versionParseOk  : the running + recommended version stamps are both comparable semver (an unparseable
    //                     stamp makes compatible:false with no visible cause).
    //   compatBlocked   : the CLOSED compat class -- the release declares a minEngineVersion NEWER than this
    //                     engine (min-engine-version), or one this engine cannot even parse and therefore
    //                     REFUSES to apply onto (min-engine-version-unparseable).
    // Best-effort and time-boxed by the platform's own subrequest budget: an unconfigured channel makes NO
    // network call at all (checkUpdates short-circuits), and any fault degrades to an omitted block rather than
    // failing the whole updates section, which carries DO state the channel has nothing to do with.
    try {
      out.available = await updateAvailability(env);
    } catch {
      // Honest absence: the availability probe could not run. The DO-side lifecycle above still rides.
    }
    return out;
  }
}

// CHANNEL_ISSUE_CLASSES is the CLOSED vocabulary of why the signed update channel did not verify (G258).
const CHANNEL_ISSUE_CLASSES: ReadonlySet<string> = new Set(["not-configured", "url-invalid", "not-https", "signer-key-invalid", "fetch-failed", "signature-invalid"]);
// COMPAT_BLOCK_CLASSES is the CLOSED vocabulary of why an available release cannot be applied to THIS engine.
const COMPAT_BLOCK_CLASSES: ReadonlySet<string> = new Set(["min-engine-version", "min-engine-version-unparseable"]);

// classifyChannelIssue READS the engine-authored refusal sentence ONLY to SELECT a closed enum member and
// RETURNS that enum (the classifyCoarseError idiom): the sentence itself is discarded and never stored, so
// even if a future refusal path interpolated the channel URL it could not ride into the pack through here.
export function classifyChannelIssue(reason: unknown): string {
  const s = typeof reason === "string" ? reason : "";
  if (s.includes("not configured")) return "not-configured";
  if (s.includes("not a valid URL")) return "url-invalid";
  if (s.includes("must use https")) return "not-https";
  if (s.includes("pinned update-signer key")) return "signer-key-invalid";
  if (s.includes("could not fetch")) return "fetch-failed";
  if (s.includes("did not verify")) return "signature-invalid";
  return UNKNOWN_CODE; // a NEW refusal path the pack has not learned: visible as drift, never as free text
}

// classifyCompatBlock names WHY a recommended release is incompatible with the running engine, or null when it
// is applicable. It re-derives the verdict from the SAME compareSemver the apply gate uses (isEngineCompatible
// REFUSES an uncomparable floor rather than assuming it fits), so the pack and the gate cannot disagree.
export function classifyCompatBlock(runningVersion: string, minEngineVersion: string | undefined): string | null {
  if (minEngineVersion === undefined || minEngineVersion === "") return null;
  const cmp = compareSemver(runningVersion, minEngineVersion);
  if (cmp === null) return "min-engine-version-unparseable";
  return cmp < 0 ? "min-engine-version" : null;
}

// updateAvailability projects checkUpdates into the closed, redaction-safe availability verdicts (G258). It
// carries booleans, closed classes and the engine/release VERSION ids (already carried as engine.version), and
// never the channelBase URL, the artefact url, the sha384 or the human release notes.
async function updateAvailability(env: Env): Promise<Record<string, unknown>> {
  const s = await checkUpdates(env);
  const compatBlocked = s.verified ? classifyCompatBlock(s.currentVersion, s.minEngineVersion) : null;
  const rawBase = typeof env.UPDATE_CHANNEL_URL === "string" ? env.UPDATE_CHANNEL_URL : "";
  let channelBaseValid = false;
  try {
    channelBaseValid = rawBase !== "" && new URL(rawBase).protocol === "https:";
  } catch {
    channelBaseValid = false;
  }
  return {
    configured: s.configured === true,
    verified: s.verified === true,
    channelBaseValid,
    ...(s.recommendedVersion !== undefined ? { recommendedVersion: s.recommendedVersion.slice(0, 64) } : {}),
    ...(typeof s.updateAvailable === "boolean" ? { updateAvailable: s.updateAvailable } : {}),
    ...(typeof s.compatible === "boolean" ? { compatible: s.compatible } : {}),
    ...(compatBlocked !== null && COMPAT_BLOCK_CLASSES.has(compatBlocked) ? { compatBlocked } : {}),
    ...(gateClosed(s.riskClass, new Set(["routine", "migration", "breaking"])) !== undefined ? { riskClass: gateClosed(s.riskClass, new Set(["routine", "migration", "breaking"])) } : {}),
    // versionParseOk: both stamps comparable. Meaningless (and so omitted) before a recommendation exists.
    ...(s.recommendedVersion !== undefined ? { versionParseOk: compareSemver(s.currentVersion, s.recommendedVersion) !== null } : {}),
    ...(s.verified !== true ? { channelIssue: gateClosed(classifyChannelIssue(s.reason), CHANNEL_ISSUE_CLASSES) ?? UNKNOWN_CODE } : {}),
  };
}

// fetchStatusDoOpts pulls the DO-owned status facts the pack's StatusReport needs but that live in the
// scheduler DO (not env), so buildStatus lights up the same break-glass-disposal / expiry / credential-
// lifecycle findings the console's GET /admin/status route shows. It MIRRORS that handler's DO reads
// (router-status.ts) MINUS the caller-scoped ones: recoveryCodesRemaining is per verified caller EMAIL and a
// self-service bundle has no caller, so it is honestly ABSENT here (never fabricated). Each read is presence-
// safe: a DO hiccup leaves that fact honestly absent rather than a fabricated 0/false, so the status never
// fails, and consoleDestSet drives the pack's statusSource ("live" vs "env-fallback", gap-B6: a failed dest
// read leaves it absent -> the pack honestly reports env-fallback). Only counts / booleans / the dest KIND
// cross the wire; never a binding name, endpoint, region, credential or code.
export async function fetchStatusDoOpts(scheduler: DurableObjectStub): Promise<BuildStatusOptions> {
  const opts: BuildStatusOptions = {};
  try {
    const r = await scheduler.fetch(doURL("/expiry/warnings"), { method: "GET" });
    const { expiryWarnings, cleanupPending } = (await r.json()) as { expiryWarnings?: number; cleanupPending?: number };
    if (typeof expiryWarnings === "number" && Number.isFinite(expiryWarnings)) opts.expiryWarnings = expiryWarnings;
    if (typeof cleanupPending === "number" && Number.isFinite(cleanupPending)) opts.cleanupPending = cleanupPending;
  } catch {
    // Presence-safe: leave expiryWarnings/cleanupPending absent so the status never fails on the expiry read.
  }
  try {
    const r = await scheduler.fetch(doURL("/policy/break-glass-disposal"), { method: "GET" });
    const d = (await r.json()) as { bootstrapConsumed?: boolean; breakGlassTokenRetired?: boolean };
    if (typeof d.bootstrapConsumed === "boolean") opts.bootstrapConsumed = d.bootstrapConsumed;
    if (typeof d.breakGlassTokenRetired === "boolean") opts.breakGlassTokenRetired = d.breakGlassTokenRetired;
  } catch {
    // Presence-safe: leave the two break-glass-disposal latches absent so the status never fails on this read.
  }
  try {
    const r = await scheduler.fetch(doURL("/dest-status"), { method: "GET" });
    const { present, endpointHost, source } = (await r.json()) as { present?: boolean; endpointHost?: string; source?: string };
    // DEST-REPLACE-REASSIGN: source:"deploy" (ensureDeployDestSeeded) is present:true with no
    // real credential; see the identical guard's citation in router-status.ts.
    if (typeof present === "boolean") opts.consoleDestSet = present && source !== "deploy";
    if (typeof endpointHost === "string") opts.consoleDestHost = endpointHost;
  } catch {
    // Presence-safe: leave consoleDestSet absent so the status honestly reports statusSource "env-fallback".
  }
  return opts;
}
