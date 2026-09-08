// SRE alerting: the stale/failure DETECTION core. This is the on-call persona; without an open
// console, a stalled or failing backup is invisible, so the engine pushes a transition-based alert
// to the customer's OWN sink. WHERE it goes is the notify-channel model (a channel plus a rule);
// this module decides WHETHER a downpipe is in an alertable state and shapes the alert line.
//
// The channel-adapter + routing layer (the event/severity model, validateChannel/validateRule,
// resolveDelivery, deliverToChannel/deliverEmission) lives in ./notify-routing.ts, and the daily/weekly
// digest flush in ./notify-digest.ts; both were MOVED VERBATIM out of this module to keep it a readable
// size. This file re-exports every symbol from both siblings (plus the channel-facing leaf
// ./notify/types.ts) so its existing callers keep importing them by name from notify.ts.
//
// NO-CUSTODY boundary (sacred). A CUSTOMER-configured channel points at the CUSTOMER's own
// endpoint, so the payload MAY carry the customer's own downpipe id/name/status/freshness (their
// data, to their sink). It must NEVER carry key material, record values, selectors-as-secrets, a
// fingerprint, or any vendor-bound reconnaissance. The alert is built ONLY from the run-history
// ring (ids, names, enums, RFC-3339 times), which is the same redaction-safe surface the console
// already reads; there is no path here that can reach a secret, a destination credential, or a
// plaintext value. This is DISTINCT from the vendor beacon, which is content-free; this is the
// customer's own operational data going to the customer's own endpoint.
//
// Fail-open (sacred). An alert is observability, never a control. Detection and delivery are
// best-effort: no configured channel, an invalid stored url, a non-2xx response, a network throw or a
// timeout must NEVER block, delay past a bound, or fail a backup. Every entry point here returns a
// value rather than throwing, and deliverPayload (the one guarded fetch, in ./notify/types.ts) is
// non-throwing by construction.
//
// This module is pure logic, so the DO (storage) and the cron driver (index.ts) share one definition
// of "stale", one alert shape, and one url validator, and none of them can compute those three
// things two different ways. Node 25 strip-types compatible: no enums, no parameter properties,
// explicit declarations. exactOptionalPropertyTypes: optional keys are spread in only when they
// carry a value.

import type { DownpipeConfig } from "./sched/types.ts";

// ALERT_COOLDOWN_MS bounds how often the SAME downpipe in the SAME state may re-alert. Detection is
// transition-based (a NEWLY stale/failed downpipe alerts), but a downpipe that stays stale would
// re-qualify on every */15 reconciliation tick; the cooldown plus the stored last-alerted state
// means a persistent condition alerts once, not every fifteen minutes, so the customer's on-call
// channel is not spammed. One hour is a sensible floor for a re-nudge on a still-broken pipe.
export const ALERT_COOLDOWN_MS = 60 * 60 * 1000;

// STALE_CADENCE_MULTIPLE is how many cadence intervals past the last SUCCESSFUL run a downpipe may
// go before it is considered stale. A backup on an N-second cadence is expected roughly every N
// seconds; allowing a generous multiple absorbs jitter (JITTER_FRACTION), a single coalesced or
// retried run, and cron-tick coarseness (the cron reconciles every ~15 min, so a sub-15-min cadence
// cannot be policed faster than that anyway) WITHOUT crying stale on the first slightly-late run.
// Three intervals means "we have missed about two expected runs", a real staleness signal.
export const STALE_CADENCE_MULTIPLE = 3;

// AlertState is the closed set of conditions worth alerting on. "failed" is the stronger, more
// specific signal (the most recent resolved run errored); "stale" is the absence signal (no recent
// SUCCESSFUL run for too long, whatever the cause, including a run that never started). A healthy
// downpipe has neither and is represented by null at the call sites.
export type AlertState = "failed" | "stale";

// MIN_RUN is the minimal run-history shape the detector reads: a resolved status, the start time,
// and the run id. It is a structural subset of the DO's RunHistoryEntry, declared here so this
// module does not depend on the DO's full ring type and so a caller can pass exactly the safe,
// redaction-safe fields (no counts, no bytes, nothing beyond ids/enums/times are needed to decide
// stale/failed). The ring is newest-LAST in DO storage; the detector is given it in that order.
export interface MinRun {
  runId: string;
  startedAt: string; // RFC-3339 UTC millis
  status: "in-flight" | "ok" | "failed";
  // recordsIncomplete (R1-1): how many records this run sealed as incompleteness sentinels (markers,
  // not the real bytes). It is redaction-safe (a plain count, no name/secret) and is the ONE extra
  // fact the backup-success notification carries so a backup with markers reads "completed with N
  // items not fully captured", not a clean ok. Absent/0 means a fully-captured run.
  recordsIncomplete?: number;
}

// DownpipeAlert is one alert line in the payload. It carries ONLY the customer's own redaction-safe
// operational facts: the downpipe id and name (their config), the computed state enum, and the last
// run's id + start time (freshness). No counts of records, no bytes, no selectors, no binding names,
// no key material; an on-call responder needs to know which pipe, in what state, and how stale, and
// nothing here can express more than that. lastRunAt/lastRunId are present only when a run exists.
export interface DownpipeAlert {
  id: string;
  name: string;
  state: AlertState;
  lastRunAt?: string;
  lastRunId?: string;
}

// DetectionInput is everything the detector needs for ONE downpipe, assembled by the DO from state
// it already holds: the config (for id/name/cadence/enabled), the run-history ring (newest-last),
// and the time this state was last alerted on (from the per-downpipe cooldown record, or undefined
// if never). Keeping detection a pure function of these inputs makes it directly unit-testable and
// guarantees the cron and the DO agree on the verdict.
export interface DetectionInput {
  config: Pick<DownpipeConfig, "id" | "name" | "cadenceSeconds" | "enabled">;
  history: MinRun[]; // newest-LAST, as stored by the DO
  lastAlertedState?: AlertState; // the state we last alerted this downpipe on, if any
  lastAlertedAt?: number; // epoch ms of that last alert, if any
}

// classify decides a downpipe's current alertable state from its run history, or null if healthy.
// Rules, in order:
//  - A disabled downpipe is never alerted (the operator deliberately paused it; silence is correct).
//  - With NO resolved run yet, the downpipe is not alerted: a freshly-created pipe that has not had
//    its first run is "pending", not "failed" or "stale"; alerting on it would be a false positive
//    during onboarding. (Staleness is measured from the last SUCCESS, and there is none to measure.)
//  - failed: the most recent RESOLVED run (ignoring an in-flight row, which is a run in progress, not
//    a failure) has status "failed". This is the precise, strong signal and takes precedence.
//  - stale: the last SUCCESSFUL run started longer ago than STALE_CADENCE_MULTIPLE cadence intervals.
//    Measured from the last success (not the last attempt) so a pipe that keeps failing reads failed,
//    and a pipe whose runs simply stopped happening reads stale. An in-flight run does not reset
//    staleness (it has not succeeded yet).
//  - otherwise healthy (null).
// It reads only ids/enums/times; it cannot surface a value.
export function classify(input: DetectionInput, now: number): AlertState | null {
  if (!input.config.enabled) return null;
  // The most recent RESOLVED run (ok or failed); an in-flight row is a run still going, not an
  // outcome, so it is skipped when deciding failed-ness. The ring is newest-last, so scan backwards.
  let lastResolved: MinRun | undefined;
  let lastSuccessAt: number | undefined;
  for (let i = input.history.length - 1; i >= 0; i--) {
    const h = input.history[i];
    if (h === undefined) continue; // noUncheckedIndexedAccess: the ring is dense, but be explicit
    if (h.status === "in-flight") continue;
    if (lastResolved === undefined) lastResolved = h;
    if (h.status === "ok") {
      const t = Date.parse(h.startedAt);
      if (Number.isFinite(t)) lastSuccessAt = t;
      break; // the newest success found; both facts we need are now known
    }
  }
  // No resolved run at all (only in-flight, or an empty ring): pending, not alertable.
  if (lastResolved === undefined) return null;
  // failed takes precedence: the latest outcome errored.
  if (lastResolved.status === "failed") return "failed";
  // The latest outcome is ok; check staleness of the last success against the cadence budget.
  if (lastSuccessAt === undefined) return null; // resolved-ok with an unparseable time: do not cry wolf
  const budgetMs = input.config.cadenceSeconds * 1000 * STALE_CADENCE_MULTIPLE;
  if (now - lastSuccessAt > budgetMs) return "stale";
  return null;
}

// shouldAlert applies the transition + cooldown gate on top of classify, so the DO records an alert
// only for a NEWLY stale/failed downpipe (or one whose alertable state changed, e.g. stale -> failed),
// and re-nudges a persistently broken pipe at most once per ALERT_COOLDOWN_MS rather than every tick.
// Returns the state to alert (and to record as last-alerted), or null to stay silent. A healthy
// downpipe (classify -> null) clears nothing here; the DO clears the cooldown record on recovery so a
// future relapse alerts immediately (see clearOnRecovery).
export function shouldAlert(input: DetectionInput, now: number): AlertState | null {
  const state = classify(input, now);
  if (state === null) return null;
  // A different alertable state than last time is always worth alerting (e.g. it was stale and is now
  // failing, or vice versa): the on-call signal changed.
  if (input.lastAlertedState !== state) return state;
  // Same state as last alert: only re-alert once the cooldown has elapsed (a persistent condition
  // gets a periodic nudge, not a per-tick storm). A missing/old timestamp is treated as elapsed.
  if (input.lastAlertedAt === undefined) return state;
  if (now - input.lastAlertedAt >= ALERT_COOLDOWN_MS) return state;
  return null;
}

// buildAlert renders one DownpipeAlert from a downpipe's config + history + decided state, carrying
// ONLY the redaction-safe fields. lastRunAt/lastRunId come from the most recent RESOLVED run (the run
// the responder will look at); they are omitted (exactOptionalPropertyTypes-safe spreads) when there
// is no resolved run. It never reads counts, bytes, selectors, or bindings.
export function buildAlert(config: Pick<DownpipeConfig, "id" | "name">, history: MinRun[], state: AlertState): DownpipeAlert {
  let last: MinRun | undefined;
  for (let i = history.length - 1; i >= 0; i--) {
    const h = history[i];
    if (h === undefined) continue;
    if (h.status === "in-flight") continue;
    last = h;
    break;
  }
  return {
    id: config.id,
    name: config.name,
    state,
    ...(last !== undefined ? { lastRunAt: last.startedAt, lastRunId: last.runId } : {}),
  };
}

// isInternalSinkHost (the SSRF default-deny classifier), isAllowedWebhookUrl (the webhook url
// authority-boundary validator), WEBHOOK_TIMEOUT_MS and deliverPayload all live in the leaf
// ./notify/types.ts (which breaks the notify.ts<->notify/channels/* cycle). Re-exported so callers that
// import them by name from notify.ts keep working.
export { deliverPayload, isAllowedWebhookUrl, isInternalSinkHost, WEBHOOK_TIMEOUT_MS } from "./notify/types.ts";

// =============================================================================================
// NOTIFICATION CHANNELS, EVENTS, ROUTING, DELIVERY and the DIGEST flush (contract section 2)
// =============================================================================================
//
// The channel-adapter + routing layer and the daily/weekly digest flush were MOVED VERBATIM out of
// this module into ./notify-routing.ts and ./notify-digest.ts (to keep this file a readable size).
// The channel-facing types (ChannelKind, NotifyChannel, NotifyEmission, NotifyEvent, Severity) and the
// cosmetic severityEmoji helper, plus DigestPeriod, live in the leaf ./notify/types.ts. Everything is
// re-exported here so existing callers keep importing it by name from notify.ts; the behaviour is
// unchanged.

// Channel-facing types + cosmetic helper + the success-class digest cadence, from the leaf.
export type { AckOutcome, ChannelDeliveryResult, ChannelKind, DeliveryFailCode, DigestPeriod, NotifyChannel, NotifyEmission, NotifyEvent, Severity, SinkScreenVerdict } from "./notify/types.ts";
export { ACK_OUTCOMES, classifyHttpDeliveryStatus, classifyNetworkFailure, classifyReplication, DELIVERY_FAIL_CODES, isRunEvictionRisk, NOTIFY_EVENT_NAMES, SINK_SCREEN_VERDICTS, sanitiseEmailPlatformCode, screenSinkHost, severityEmoji } from "./notify/types.ts";
// The daily/weekly digest flush layer, from ./notify-digest.ts.
export type { DigestBatch, DigestSummary, PendingDigestEntry } from "./notify-digest.ts";
export {
  DIGEST_WINDOW_MS,
  digestEmissionFor,
  digestWindowElapsed,
  groupDigestDue,
  renderDigestDetail,
  summariseDigest,
} from "./notify-digest.ts";
// The channels/events/routing/delivery layer, from ./notify-routing.ts.
export type { DeliveryRecord, NotifyHistoryEntry, NotifyRule, ResolvedDelivery } from "./notify-routing.ts";
export {
  deliverEmission,
  routeEngineNotification,
  deliverToChannel,
  isNotifyEvent,
  isSeverity,
  isSuccessClass,
  NOTIFY_CHANNEL_PREFIX,
  NOTIFY_HISTORY_CAP,
  NOTIFY_HISTORY_PREFIX,
  NOTIFY_RULE_PREFIX,
  redactChannelSecretForRead,
  resolveDelivery,
  ruleSelects,
  severityAtLeast,
  severityOf,
  validateChannel,
  validateRule,
} from "./notify-routing.ts";
