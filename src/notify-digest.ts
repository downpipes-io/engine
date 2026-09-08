// DIGEST FLUSH (contract section 2: "an optional digest mode (a daily or weekly summary email) for
// the success stream so success notifications do not become noise"). The routing layer (notify-routing.ts)
// DEFERS each success-class emission a digest rule selected (resolveDelivery -> ResolvedDelivery.digested),
// recording one redaction-safe pending entry per (channel, occurrence) in the DO under the notify-digest:
// prefix. This module is the FLUSH: the pure logic that, given the pending entries and the CURRENT
// epoch-millis (the DO has no wall clock, so the cron driver passes it in), groups the entries per channel,
// decides which channels' windows have ELAPSED, and rolls each due channel's batch up into ONE
// redaction-safe summary per channel for delivery via the existing channel adapters. Everything here was
// MOVED VERBATIM out of notify.ts to keep that module a readable size; the behaviour is unchanged.
// notify.ts re-exports every symbol from here so its existing callers keep importing them by name from
// notify.ts.
//
// REDACTION (sacred). A pending digest entry and the rolled-up summary carry ONLY the same safe
// surface every other notification carries: the event/severity enums, the downpipe id/name, RFC-3339
// times, and a one-line detail. The summary is a COUNT per event type plus the set of downpipe NAMES
// touched; it never reads a secret, key, value, selector, credential or fingerprint. FAIL-OPEN
// (sacred). The flush is observability layered on the success stream: it runs AFTER the run loop in
// the cron and the whole path is guarded so a digest problem never blocks a backup or the cron.
//
// This module imports only the channel-facing types + DigestPeriod from the leaf ./notify/types.ts; it
// imports NOTHING from notify.ts or notify-routing.ts, so there is no cycle.

import type { ChannelKind, DigestPeriod, NotifyEmission, NotifyEvent, Severity } from "./notify/types.ts";

// ---- notify-digest render health (G223) -----------------------------------------------------------------
//
// Every guard in this module fails CONSERVATIVELY on an unparseable timestamp: the digest does not flush, or
// the entry is dropped from the window. That is the right behaviour (a guessed flush could spam a customer's
// pager), but it was INVISIBLE -- "our digest just stopped arriving" had no evidence behind it at all. This
// module is a PURE leaf with no env and no scheduler stub, so it tallies isolate-locally (the
// sources/source-fault-ledger.ts idiom) and the DO's digest path drains it and files the count against the
// admin-counter aggregate. A COUNT only: the offending timestamp is never retained.
let timestampParseFailures = 0;
function noteTimestampParseFailure(): void {
  timestampParseFailures += 1;
}

/**
 * drainNotifyDigestFaults returns and CLEARS the isolate-local digest-render tally, so the counts are
 * attributable to the flush that just ran and cannot leak into the next one.
 *
 * @returns how many timestamps could not be parsed since the last drain.
 */
export function drainNotifyDigestFaults(): { timestampParseFailures: number } {
  const out = { timestampParseFailures };
  timestampParseFailures = 0;
  return out;
}

// DIGEST_WINDOW_MS is the elapsed-time budget per cadence before a channel's batch is flushed. The
// window is measured from the OLDEST pending entry for the channel (the first deferred occurrence in
// the current batch), so a daily digest flushes about a day after the first deferred success and a
// weekly one about a week after, regardless of when the cron happens to tick (the cron is ~*/15, so
// the actual flush lands at the first tick PAST the window, which is the correct "at least N elapsed"
// semantic). Exact day/week in ms; no calendar alignment (the contract specifies an elapsed window,
// not a wall-clock 00:00 boundary, which keeps it computable in the clockless DO from nowMs alone).
export const DIGEST_WINDOW_MS: Record<DigestPeriod, number> = {
  daily: 24 * 60 * 60 * 1000,
  weekly: 7 * 24 * 60 * 60 * 1000,
};

// PendingDigestEntry is one deferred success-class occurrence, stored under `notify-digest:${seq}` in
// the DO and returned to the cron by /notify/digest-due. It is the redaction-safe join of the
// emission and the channel it was deferred for, PLUS the cadence (period) the deferring rule chose,
// so the flush knows which window to apply per channel without re-reading the rules. seq is the
// opaque monotonic order key (also the storage-key suffix). It carries no secret: every field is the
// same safe surface a NotifyHistoryEntry carries.
export interface PendingDigestEntry {
  seq: number; // monotonic order; storage key suffix `notify-digest:${padded(seq)}`
  channelId: string;
  channelKind: ChannelKind;
  period: DigestPeriod; // the cadence the deferring rule chose (daily/weekly)
  event: NotifyEvent;
  severity: Severity;
  downpipeId: string | null;
  downpipeName: string | null; // the safe downpipe label, for the roll-up's names list (null = account-level)
  detail: string; // redaction-safe one-liner (downpipe name + state), as deferred
  at: string; // RFC-3339 UTC millis the occurrence was deferred
}

// DigestSummary is the rolled-up, redaction-safe body for ONE channel's due batch: how many of each
// event type accumulated, the distinct downpipe names touched (sorted, deduped, NEVER an id-as-secret
// and never a value), the count of account-level occurrences (downpipeId null, e.g. role-change), the
// total occurrence count, and the window the batch covers (the oldest..newest deferred times). It is
// the structured form the per-channel detail string is rendered from; a console or an adapter can use
// the structure or the rendered line. It carries NO secret.
export interface DigestSummary {
  total: number; // total deferred occurrences in the batch
  byEvent: Partial<Record<NotifyEvent, number>>; // count per event type (only events present)
  downpipeNames: string[]; // distinct downpipe names touched, sorted (redaction-safe labels)
  accountLevelCount: number; // occurrences with no downpipe (downpipeId null)
  fromAt: string; // oldest deferred time in the batch (RFC-3339)
  toAt: string; // newest deferred time in the batch (RFC-3339)
}

// DigestBatch is one channel's due batch the cron delivers: the channel id/kind, the period, the
// rolled-up summary, the rendered redaction-safe detail line, and the seqs of the pending entries the
// batch consumed (so the cron can POST /notify/digest-sent {ids} to clear EXACTLY what it delivered,
// transactionally, with no race against entries deferred after the due-read).
export interface DigestBatch {
  channelId: string;
  channelKind: ChannelKind;
  period: DigestPeriod;
  summary: DigestSummary;
  detail: string; // the rendered one-line roll-up (redaction-safe)
  seqs: number[]; // the pending-entry seqs this batch consumed (cleared on digest-sent)
}

// digestWindowElapsed reports whether a channel's batch is due to flush: the elapsed time from the
// OLDEST deferred entry to nowMs has reached the cadence window. The DO has no wall clock, so nowMs is
// PASSED IN by the cron driver (contract). A non-finite or future oldestAtMs (clock skew) is treated
// as NOT elapsed (conservative: never flush a batch whose age cannot be trusted). This is the single
// definition of "due" the DO route uses, so the cron and the DO cannot disagree on the window.
export function digestWindowElapsed(period: DigestPeriod, oldestAtMs: number, nowMs: number): boolean {
  if (!Number.isFinite(oldestAtMs) || !Number.isFinite(nowMs)) {
    // G223: the CONSERVATIVE suppression. An unparseable window bound means the digest does NOT flush -- an
    // alert the customer expected is never sent. Suppressing conservatively is right (a guessed flush could
    // spam), but it must be VISIBLE, so this is counted, never the timestamp itself.
    noteTimestampParseFailure();
    return false;
  }
  const elapsed = nowMs - oldestAtMs;
  if (elapsed < 0) return false; // future oldest (skew): not due
  return elapsed >= DIGEST_WINDOW_MS[period];
}

// summariseDigest builds the redaction-safe roll-up for ONE channel's batch of pending entries. It
// counts occurrences per event type, collects the DISTINCT downpipe names (sorted, deduped, taken
// from the entry's own safe downpipeName label; an entry with a null downpipe is counted as
// account-level rather than given a fake name), and records the oldest..newest deferred window. It
// reads ONLY the safe fields on each entry (event/downpipeName/at); there is no path here that can
// reach a secret. The caller passes entries that all share one channelId.
export function summariseDigest(entries: PendingDigestEntry[]): DigestSummary {
  const byEvent: Partial<Record<NotifyEvent, number>> = {};
  const names = new Set<string>();
  let accountLevelCount = 0;
  // Track the oldest/newest by INSTANT (Date.parse epoch-millis), not by lexical string order: a
  // lexical < / > on RFC-3339 strings is wrong for mixed precision/offset (e.g. a "+10:00" offset
  // sorts after a "Z" string yet is an EARLIER instant), which could pick the wrong fromAt/toAt. We
  // compare on the parsed instant but EMIT the chosen entry's own original `at` string (so the window
  // labels stay in the producers' canonical form). A non-finite parse is ignored for the comparison
  // (a malformed `at` cannot win the min/max), so the chosen ends are always real, comparable instants.
  let fromAt = "";
  let toAt = "";
  let fromMs = Number.POSITIVE_INFINITY;
  let toMs = Number.NEGATIVE_INFINITY;
  for (const e of entries) {
    byEvent[e.event] = (byEvent[e.event] ?? 0) + 1;
    if (e.downpipeName !== null && e.downpipeName.length > 0) names.add(e.downpipeName);
    else if (e.downpipeId === null) accountLevelCount++;
    const t = Date.parse(e.at);
    if (!Number.isFinite(t)) {
      noteTimestampParseFailure(); // G223: this entry is silently EXCLUDED from the digest's oldest/newest span
      continue;
    }
    if (fromAt === "" || t < fromMs) {
      fromMs = t;
      fromAt = e.at;
    }
    if (toAt === "" || t > toMs) {
      toMs = t;
      toAt = e.at;
    }
  }
  return {
    total: entries.length,
    byEvent,
    downpipeNames: [...names].sort(),
    accountLevelCount,
    fromAt,
    toAt,
  };
}

// renderDigestDetail turns a DigestSummary into ONE redaction-safe line: the total, the per-event
// counts, and the touched downpipe names (capped so a huge fan-out cannot make an unbounded line).
// It is the `detail` carried on the digest NotifyEmission and the NotifyHistoryEntry. It names ONLY
// safe labels and integer counts; it can never carry a secret. The wording is plain (no emoji here;
// the per-channel adapter adds its own severity glyph from the emission severity, which for a
// success-class digest is info).
const DIGEST_NAMES_IN_LINE = 8;
export function renderDigestDetail(summary: DigestSummary): string {
  const parts: string[] = [];
  // Per-event counts in a stable order (the digestible-event subset, via EVENT_ORDER).
  for (const ev of EVENT_ORDER) {
    const c = summary.byEvent[ev];
    if (c !== undefined && c > 0) parts.push(`${c} ${ev}`);
  }
  const head = `Digest: ${summary.total} update${summary.total === 1 ? "" : "s"}`;
  const counts = parts.length > 0 ? ` (${parts.join(", ")})` : "";
  let tail = "";
  if (summary.downpipeNames.length > 0) {
    const shown = summary.downpipeNames.slice(0, DIGEST_NAMES_IN_LINE);
    const more = summary.downpipeNames.length - shown.length;
    tail = ` across ${shown.join(", ")}${more > 0 ? ` and ${more} more` : ""}`;
  }
  const acct = summary.accountLevelCount > 0 ? `; ${summary.accountLevelCount} account-level` : "";
  return `${head}${counts}${tail}${acct}`;
}

// EVENT_ORDER fixes a stable display order for the per-event counts in a digest line. It lists every
// NotifyEvent that can carry a count in byEvent so none is silently dropped from the summary line.
// canary-dead and update-rollback-needed are immediate-only (never digested) but are listed so a
// stray count would still render; canary-recovered is success-class and genuinely digestible. Kept
// local (not exported) since it is presentation only.
const EVENT_ORDER: readonly NotifyEvent[] = [
  "backup-success",
  "backup-failure",
  "backup-stale",
  "restore-test-pass",
  "restore-test-fail",
  "restore-applied",
  "credential-expiry",
  "posture-regression",
  "role-change",
  "canary-dead",
  "canary-recovered",
  "update-rollback-needed",
];

// digestEmissionFor builds the NotifyEmission the cron hands to deliverToChannel for a due batch. The
// digest is a SUCCESS-class roll-up, so it is always info severity; the event is reported as the
// MODAL (most frequent) event in the batch purely for the adapter's labelling (the detail carries the
// full per-event breakdown). downpipeId/downpipeName are null because a digest spans many downpipes
// (the names are in the detail); recovered is never set (a digest is not a PagerDuty resolve). The
// `at` is the flush time, passed in. It carries ONLY the redaction-safe summary line.
export function digestEmissionFor(summary: DigestSummary, atISO: string): NotifyEmission {
  // Pick the modal event for the adapter label; default to backup-success if the batch is somehow
  // empty of counts (it never is when total > 0, but be explicit for the type).
  let modal: NotifyEvent = "backup-success";
  let best = -1;
  for (const ev of EVENT_ORDER) {
    const c = summary.byEvent[ev] ?? 0;
    if (c > best) {
      best = c;
      modal = ev;
    }
  }
  return {
    event: modal,
    severity: "info",
    downpipeId: null,
    downpipeName: null,
    detail: renderDigestDetail(summary),
    at: atISO,
  };
}

// groupDigestDue is the PURE core of the digest-due route: given ALL pending digest entries and the
// current epoch-millis (passed in by the cron; the DO has no wall clock), it groups entries by
// channel, and for each channel decides whether the batch is DUE (the elapsed time from the channel's
// OLDEST entry to nowMs has reached the channel's window). The channel's window is the SHORTEST cadence
// among its entries (daily beats weekly), so a daily digest is never delayed behind a weekly one that
// happens to share the channel. For each due channel it builds the rolled-up DigestBatch (the summary,
// the rendered detail, and the exact seqs to clear). It is deterministic and storage-free, so the DO
// and the validator exercise the identical decision. A channel whose window has not elapsed is left
// pending (not returned), so its entries accumulate until a later tick.
//
// Determinism: channels are emitted sorted by channelId, and each batch's seqs are sorted ascending,
// so the output order does not depend on Map iteration order.
export function groupDigestDue(entries: PendingDigestEntry[], nowMs: number): DigestBatch[] {
  // Group by channelId.
  const byChannel = new Map<string, PendingDigestEntry[]>();
  for (const e of entries) {
    const arr = byChannel.get(e.channelId);
    if (arr) arr.push(e);
    else byChannel.set(e.channelId, [e]);
  }
  const batches: DigestBatch[] = [];
  for (const channelId of [...byChannel.keys()].sort()) {
    const group = byChannel.get(channelId)!;
    // The channel's effective window is the SHORTEST cadence among its entries.
    let period: DigestPeriod = "weekly";
    let oldestMs = Number.POSITIVE_INFINITY;
    for (const e of group) {
      if (e.period === "daily") period = "daily";
      const t = Date.parse(e.at);
      if (!Number.isFinite(t)) noteTimestampParseFailure(); // G223: silently excluded from the summary's window
      if (Number.isFinite(t) && t < oldestMs) oldestMs = t;
    }
    if (!digestWindowElapsed(period, oldestMs, nowMs)) continue; // not due yet; keep accumulating
    const summary = summariseDigest(group);
    const seqs = group.map((e) => e.seq).sort((a, b) => a - b);
    // channelKind is uniform within a channel (it is the channel's own kind); take the first.
    const channelKind = group[0]!.channelKind;
    batches.push({
      channelId,
      channelKind,
      period,
      summary,
      detail: renderDigestDetail(summary),
      seqs,
    });
  }
  return batches;
}
