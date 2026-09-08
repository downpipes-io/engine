// NOTIFICATION CHANNELS, EVENTS, ROUTING and per-channel DELIVERY (contract section 2). This is the
// channel-adapter + routing layer that sits on top of the SRE-alert detection core in notify.ts: it adds
// the event + severity model (severityOf), the rule shape + authority-boundary validators
// (validateChannel / validateRule), the pure routing resolution (ruleSelects / resolveDelivery: global
// + per-downpipe override, dedupe, minSeverity, success-class digest deferral) and the fully-guarded
// per-channel fan-out (deliverToChannel / deliverEmission). Everything here was MOVED VERBATIM out of
// notify.ts to keep that module a readable size; the behaviour is unchanged. notify.ts re-exports every
// symbol from here so its existing callers keep importing them by name from notify.ts.
//
// REDACTION (sacred). Every shape here carries ONLY the customer's own redaction-safe operational
// facts: a downpipe id/name, an event/severity enum, RFC-3339 times, and a one-line `detail` that is
// the downpipe name + state, NEVER a secret, key, value, selector, credential or fingerprint. The
// provider payloads (Slack text, PagerDuty summary, the webhook body) are built only from those
// fields. FAIL-OPEN (sacred). Delivery is best-effort: deliverPayload (url channels) and sendEmail
// (email channels) never throw; the orchestrator wraps each delivery so one channel's failure never
// blocks another channel, a backup, or the cron.
//
// This module imports the channel-facing types + the SSRF-screened url validator from the leaf
// ./notify/types.ts and the per-kind adapters from ./notify/channels/*; it imports NOTHING from
// notify.ts, so there is no cycle (notify.ts depends on this module, not the reverse).

// isWrappedSecret is the PURE shape check (no crypto) config-secret.ts documents as safe to call from
// anywhere, including this routing leaf: it lets validateChannel accept EITHER a plaintext apiKey (the
// CONFIG_WRAP_KEY-absent back-compat floor) OR an already-sealed WrappedSecret envelope (what the router
// forwards once it has wrapped a jsm/servicenow secret), without this module doing any crypto itself --
// mirroring how scheduler-do-siem-push.ts's buildPushRecord accepts the same two shapes for the push auth
// header secret.
import { isWrappedSecret, type WrappedSecret } from "./admin/config-secret.ts";
import { doURL } from "./do-url.ts";
import { log } from "./log.ts";
import type { Env } from "./env.d.ts";
import * as emailChannel from "./notify/channels/email.ts";
import * as jsmChannel from "./notify/channels/jsm.ts";
import * as pagerdutyChannel from "./notify/channels/pagerduty.ts";
import * as servicenowChannel from "./notify/channels/servicenow.ts";
import * as slackChannel from "./notify/channels/slack.ts";
import * as teamsChannel from "./notify/channels/teams.ts";
import * as webhookChannel from "./notify/channels/webhook.ts";
import {
  type AckOutcome,
  type ChannelDeliveryResult,
  type ChannelKind,
  type DeliveryFailCode,
  type DigestPeriod,
  isAllowedWebhookUrl,
  NOTIFY_EVENT_NAMES,
  type NotifyChannel,
  type NotifyEmission,
  type NotifyEvent,
  type Severity,
  type SinkScreenVerdict,
  type WebhookRejectCode,
} from "./notify/types.ts";

// NotifyRule is one routing rule, stored under `notify-rule:${id}`. scope is global or per-downpipe;
// a per-downpipe rule overrides the global default for the same event class on that downpipe.
// minSeverity gates by severity; events selects which events (or "all"); channelIds names the
// channels to deliver to; digest (default off) batches the SUCCESS-class events instead of sending
// per occurrence; enabled toggles the rule.
export interface NotifyRule {
  id: string; // storage key `notify-rule:${id}`
  scope: { kind: "global" } | { kind: "downpipe"; downpipeId: string };
  minSeverity: Severity; // deliver events at or above this
  events: NotifyEvent[] | "all"; // which events this rule selects
  channelIds: string[]; // deliver to these channels
  digest?: "off" | "daily" | "weekly"; // batch success-class events (default off)
  enabled: boolean;
}

// NotifyHistoryEntry is one delivery record in the capped ring (`notify-history:${padded(seq)}`,
// cap 1000). It is redaction-safe: detail is the downpipe name + state one-liner, never a secret.
// delivered records the best-effort delivery outcome (the channel accepted the send), so the console
// can show a delivery history; channelKind lets it render the provider icon without a channel lookup.
export interface NotifyHistoryEntry {
  seq: number; // storage key `notify-history:${padded(seq)}`; capped ring (cap 1000)
  ts: string;
  event: NotifyEvent;
  severity: Severity;
  downpipeId: string | null;
  channelId: string;
  channelKind: ChannelKind;
  delivered: boolean;
  detail: string; // redaction-safe one-liner (downpipe name + state; never a secret)
  // The CLOSED delivery-failure code + (email only) the shape-gated platform code, present only on a
  // FAILED delivery (delivered:false), so "an alert never reached me" can be diagnosed without the raw
  // response (NOTIF needs-new-logging). recovered rides for a PagerDuty resolve emission so the pack can
  // correlate a resolve with its trigger (pagerduty-resolve-dedupkey). All redaction-safe.
  deliveryCode?: DeliveryFailCode;
  platformCode?: string;
  recovered?: boolean;
  // The send-time sink-screen verdict for a url-bearing channel (NOTIF: dns-rebinding-gap). Unlike
  // deliveryCode (only on a failure), this rides on EVERY url-channel delivery -- a DELIVERED `hostname`
  // sink is exactly the rebind-exposed one, so the verdict is a positive observation, not a failure signal.
  sinkScreen?: SinkScreenVerdict;
  // A manual channel test-send from the console (POST /notify/test). It rides the history ring so a
  // channel verification leaves a durable trace ("tested, and it delivered"), but it is NOT a routed
  // engine event: rules and digests never see it, and a reader that predates the flag reads the entry
  // as the info-severity delivery it was. Absent on every real event.
  test?: true;
  // unconfirmed (item 10, HARDENING.md): true on a delivered:true entry whose sink only
  // ASYNC-ACCEPTED the request (JSM/Opsgenie's Alert API 202) without a positively-confirmed outcome, so
  // "delivered" here is never silently conflated with a confirmed success. Absent (the common case) for
  // every synchronous channel.
  unconfirmed?: boolean;
  // ackOutcome (gap G033) is the CLOSED verdict of the async confirmation step, splitting the flat
  // `unconfirmed` flag into "the provider POSITIVELY reported the async create FAILED" (async-create-failed:
  // the alert never existed, a real non-delivery hiding inside a delivered:true row) and "we simply could not
  // confirm" (confirmation-unavailable). Produced by the jsm adapter and carried on the DeliveryRecord; the
  // DO's /notify/record validates it against ACK_OUTCOMES before it lands here. Absent for every synchronous
  // channel and for a delivery that was never async-accepted.
  ackOutcome?: AckOutcome;
  // G020: on an email-recipients-invalid failure, the POSITION of the offending entry in the channel's address
  // list. ONE typo'd address kills delivery to EVERY recipient of that channel (the send is a single call), and
  // support could not name the bad entry -- the customer had to eyeball the list and guess. An index is an
  // integer, never an address, so it names the field without naming a person.
  recipientIndex?: number;
}

// NOTIFY_HISTORY_CAP is the ring cap (contract section 2.1: cap 1000). The DO rolls the oldest
// entries off once the retained count exceeds it, the same discipline as the run-history RING_CAP.
export const NOTIFY_HISTORY_CAP = 1000;

// Storage-key prefixes for the DO. Kept here (the notify domain) so the DO and any reader agree on
// the exact strings, mirroring AUDIT_PREFIX.
export const NOTIFY_CHANNEL_PREFIX = "notify-channel:";
export const NOTIFY_RULE_PREFIX = "notify-rule:";
export const NOTIFY_HISTORY_PREFIX = "notify-history:";

// severityOf is the FIXED event -> severity mapping (contract section 2.1). backup-failure,
// restore-test-fail and a critical-check posture-regression are critical; backup-stale,
// credential-expiry and a high posture-regression are warning; the success-class is info. The
// posture-regression severity depends on the failing check, so the caller may OVERRIDE it by passing
// an explicit severity to the emit; this function is the default when none is supplied.
export function severityOf(event: NotifyEvent): Severity {
  switch (event) {
    case "backup-failure":
    case "restore-test-fail":
    case "recovery-code-abuse":
      // Repeated recovery-code failures are someone guessing a high-value admin credential: page now.
      return "critical";
    case "canary-dead":
      // A bit strayed from the exact known data: the canary is dead, evacuate the coalmine. Page now.
      return "critical";
    case "update-rollback-needed":
      // A promoted-but-unsettled engine version is failing the hourly canary and only a human-supplied
      // deploy token can revert it: page now so the owner opens the console and rolls back in one click.
      return "critical";
    case "backup-stale":
    case "source-detached":
    case "backup-volume-regression":
      // A source binding went missing: warn so an operator re-attaches it before more runs fail. Never
      // digested (a protection gap must be prompt), and edge-triggered in the DO so it pages once. A volume
      // regression (retention held the last FULL backup because newer runs shrank/emptied) is the same
      // class: no data lost, but warn promptly so a human checks whether the source emptied; edge-triggered.
      return "warning";
    case "credential-expiry":
    case "recovery-code-used":
    case "dual-control-disabled":
    case "update-available":
    case "auth-credential-change":
    case "dest-change":
    case "sign-in-new-context":
    case "replication-degraded":
    case "run-at-risk-eviction":
      // Proven redundancy fell below the configured copy count, or a run is about to age out of the ring
      // while a replica still lacks it: warn so an operator can act before the window closes. Both default
      // to warning; the DO MAY override run-at-risk-eviction to critical via an explicit emit severity when
      // eviction would leave only a single proven copy (the last-copy case), the same override mechanism
      // posture-regression uses below. Neither is digested (a redundancy warning must be prompt).
      // A successful recovery-code sign-in is a break-glass admin event; warn so a human sees it promptly
      // (it is never digested - a break-glass sign-in must be prompt, not batched). Disarming dual control is
      // the same class: a governance control was dropped; warn promptly, never digest. A new engine version
      // is informational-but-actionable: warn (one-shot per version, never digested).
      return "warning";
    case "posture-regression":
      // Default to warning (the "high" case); a critical-check regression is emitted with an explicit
      // critical severity by the posture path. This default keeps a regression at least a warning.
      return "warning";
    case "backup-success":
    case "restore-test-pass":
    case "restore-applied":
    case "role-change":
    case "canary-recovered":
      return "info";
  }
}

// SUCCESS_CLASS_EVENTS is the set of info-severity events eligible for DIGEST batching (contract
// section 2.3: success-class events with digest set are batched, not sent per occurrence). The
// failure/warning stream is never digested (an on-call alert must be prompt).
const SUCCESS_CLASS_EVENTS: ReadonlySet<NotifyEvent> = new Set<NotifyEvent>([
  "backup-success",
  "restore-test-pass",
  "restore-applied",
  "role-change",
  "canary-recovered",
]);

// isSuccessClass reports whether an event is digestible success-class.
export function isSuccessClass(event: NotifyEvent): boolean {
  return SUCCESS_CLASS_EVENTS.has(event);
}

// SEVERITY_RANK orders severities for the minSeverity comparison (deliver when event severity >= the
// rule's minSeverity).
const SEVERITY_RANK: Record<Severity, number> = { info: 0, warning: 1, critical: 2 };

// severityAtLeast reports whether an event's severity meets a rule's minSeverity.
export function severityAtLeast(have: Severity, need: Severity): boolean {
  return SEVERITY_RANK[have] >= SEVERITY_RANK[need];
}

// validateChannel checks a client-supplied NotifyChannel at the authority boundary (the DO route),
// the same discipline validateConfig applies to a downpipe and isAllowedWebhookUrl to a webhook url.
// It enforces: a valid kind; a 1..256-char name; and EXACTLY the transport field the kind requires,
// validated:
//  - webhook | slack: a url that passes isAllowedWebhookUrl (https, no userinfo, not workers.dev);
//  - teams: EITHER a url (connector, isAllowedWebhookUrl) OR toAddresses (email-to-channel); one of
//    the two must be present (the connector vs email-to-channel choice the blueprint offers);
//  - pagerduty: a non-empty, bounded routingKey;
//  - email: a non-empty toAddresses of custom-domain addresses (validated via the email module).
// It returns a normalised channel (id/createdAt/enabled defaulted by the caller) carrying ONLY the
// field its kind uses (exactOptionalPropertyTypes-safe: a foreign transport field is dropped, never
// stored), or a typed rejection the route maps to a 400. The id and createdAt are assigned by the DO,
// not trusted from the client, so this validates the kind/name/transport shape only.
// ValidatedChannel is the normalised channel body validateChannel returns (id/createdAt/enabled
// defaulted by the caller).
type ValidatedChannel = Pick<NotifyChannel, "kind" | "name"> &
  Partial<Pick<NotifyChannel, "url" | "routingKey" | "toAddresses" | "allowInternalSink" | "apiKey" | "username">>;
// ChannelResult's failure now carries the CLOSED webhook-reject code alongside the operator-facing SENTENCE
// (G235/G251). The sentence is what the operator reads and what the pack can never record (it quotes the
// submitted URL's shape and is free text); the code is the SAME decision as a closed enum member, so the DO
// can count it. "I can't save my SIEM/webhook channel" is a common ticket where the customer is stuck in a
// validation loop the pack was completely blind to -- every rejection was a 400 to the browser and nothing
// else. A count per code answers it in one line: they keep pasting an http:// URL, or their sink is on a
// private address and they have not ticked the internal-sink override. Additive: every existing consumer
// reads `reason` and is unchanged.
type ChannelResult = { ok: true; channel: ValidatedChannel } | { ok: false; reason: string; code?: WebhookRejectCode };
type RecipientsValidator = (addrs: unknown) => { ok: true; to: string[] } | { ok: false; reason: string };

// PAGERDUTY_ROUTING_KEY bound: a generous ceiling so a malformed value cannot land oversized; a
// real Events API v2 routing key is 32 chars, but other integrations use longer tokens.
const ROUTING_KEY_MAX = 256;
// API_KEY_MAX / USERNAME_MAX bound the jsm/servicenow credential fields: a generous ceiling (a GenieKey
// token or a ServiceNow password/username is far shorter) so a malformed value cannot land oversized.
// API_KEY_MAX applies only to a PLAINTEXT apiKey; an already-sealed WrappedSecret (a fixed-shape
// {v,iv,ct} envelope the router forwards) is exempt, its length being ciphertext + base64 overhead.
const API_KEY_MAX = 512;
const USERNAME_MAX = 256;

// SecretParseResult is the outcome of parsing a jsm/servicenow apiKey field: KEEP-SECRET (an absent/
// empty submission means "no change; the DO splices in the prior stored value"), a plaintext string, or
// an already-sealed envelope (forwarded pre-wrapped by the router). validateChannel never wraps/unwraps
// -- it only shape-checks -- so the crypto stays entirely in config-secret.ts / the router.
type SecretParseResult = { ok: true; value: string | WrappedSecret | undefined } | { ok: false; reason: string };

// parseChannelSecret shape-checks a jsm/servicenow apiKey submission. Absent/null/empty-OR-WHITESPACE is
// ALLOWED (not a shape error): it is the KEEP-SECRET signal on an edit, and the DO-level splice
// (addNotifyChannel) is what rejects a FIRST-ever create with no secret to keep (mirroring buildPushRecord's
// own KEEP-SECRET discipline). A well-formed WrappedSecret envelope passes through unchanged; otherwise the
// value must be a non-empty, bounded plaintext string.
function parseChannelSecret(raw: unknown): SecretParseResult {
  // A trimmed-empty string (absent, "", or whitespace-only "   ") is the KEEP-SECRET / no-value signal, NOT
  // a credential. This MUST agree with wrapNotifyChannelSecret in the router, which strips a trimmed-empty
  // apiKey rather than forwarding it, so a whitespace-only value can never reach here as plaintext and get
  // stored UNWRAPPED.
  if (raw === undefined || raw === null || (typeof raw === "string" && raw.trim() === "")) return { ok: true, value: undefined };
  if (isWrappedSecret(raw)) return { ok: true, value: raw };
  if (typeof raw === "string" && raw.length <= API_KEY_MAX) return { ok: true, value: raw };
  return { ok: false, reason: "apiKey must be a non-empty, bounded string (or an already-sealed secret) when supplied" };
}

/**
 * channelPlaintextSecretRejection is the API_KEY_MAX bound evaluated where the PLAINTEXT still exists.
 *
 * parseChannelSecret runs INSIDE the Durable Object, and the router seals a jsm/servicenow apiKey before the
 * DO ever sees it (wrapNotifyChannelSecret). A sealed value takes the isWrappedSecret arm and returns before
 * the length test, so with CONFIG_WRAP_KEY set -- the ordinary deployment -- the 512-character bound is
 * never evaluated by parseChannelSecret at all, and an oversized token would be stored as ciphertext without
 * this separate check. This function re-applies the same bound where the plaintext is still visible, so the
 * accept/reject decision does not depend on whether CONFIG_WRAP_KEY happens to be set.
 *
 * It reads the SAME API_KEY_MAX and the same trimmed-empty KEEP-SECRET rule as parseChannelSecret, so the
 * pre-seal check and the post-seal check cannot drift. Two values are deliberately NOT rejected here, and
 * the non-string test is what exempts both: a NON-STRING apiKey is left in place so parseChannelSecret still
 * refuses it with its own reason, and an ALREADY-SEALED WrappedSecret is an OBJECT, so it takes the same
 * arm and is exempt from a length rule that is about plaintext.
 *
 * @param body - the submitted channel body (untrusted).
 * @returns an operator-facing reason, or null when there is nothing to refuse.
 */
export function channelPlaintextSecretRejection(body: { kind?: unknown; apiKey?: unknown }): string | null {
  if (body.kind !== "jsm" && body.kind !== "servicenow") return null;
  const raw = body.apiKey;
  if (typeof raw !== "string" || raw.trim() === "") return null;
  if (raw.length <= API_KEY_MAX) return null;
  return `apiKey must be a non-empty, bounded string (at most ${API_KEY_MAX} characters) when supplied`;
}

// redactChannelSecretForRead is the READ projection for the operator-facing channel list (GET
// /notify/channels): it strips the sealed apiKey (the jsm/servicenow bearer/basic credential) and replaces
// it with a presence-only boolean, so a notify.config holder sees THAT a credential is configured without
// ever reading its value -- even on the CONFIG_WRAP_KEY-absent floor where the stored apiKey is plaintext.
// The url/routingKey/username stay (they are the customer's own sink locator + a non-secret integration
// account name, already echoed like a webhook url), but the apiKey is the sealed secret and must never
// round-trip out of a read. The single-channel INTERNAL read (getNotifyChannel, used by the test-send
// delivery path) is deliberately NOT redacted: it needs the real apiKey to authenticate the send.
export function redactChannelSecretForRead(channel: NotifyChannel): Omit<NotifyChannel, "apiKey"> & { apiKeyPresent?: boolean } {
  const out: NotifyChannel & { apiKeyPresent?: boolean } = { ...channel };
  if (out.apiKey !== undefined) out.apiKeyPresent = true;
  delete out.apiKey;
  return out;
}

// validateUrlKind validates a url-bearing channel (webhook/slack) and stores allowInternalSink only
// when true (exactOptionalPropertyTypes-safe).
function validateUrlKind(kind: "webhook" | "slack", name: string, url: unknown, allowInternalSink: boolean): ChannelResult {
  const v = isAllowedWebhookUrl(url, { allowInternalSink });
  if (!v.ok) return { ok: false, reason: v.reason, code: v.code };
  return { ok: true, channel: { kind, name, url: v.url, ...(allowInternalSink ? { allowInternalSink: true } : {}) } };
}

// validateTeamsKind validates a Teams channel: connector url OR email-to-channel address(es). Prefer
// the url (the blueprint default); fall back to toAddresses. Exactly one path is stored.
function validateTeamsKind(name: string, c: Record<string, unknown>, allowInternalSink: boolean, recipientsValidator: RecipientsValidator): ChannelResult {
  if (c.url !== undefined && c.url !== null && c.url !== "") {
    const v = isAllowedWebhookUrl(c.url, { allowInternalSink });
    if (!v.ok) return { ok: false, reason: v.reason, code: v.code };
    return { ok: true, channel: { kind: "teams", name, url: v.url, ...(allowInternalSink ? { allowInternalSink: true } : {}) } };
  }
  const v = recipientsValidator(c.toAddresses);
  if (!v.ok) return { ok: false, reason: `teams channel needs a connector url or toAddresses: ${v.reason}` };
  return { ok: true, channel: { kind: "teams", name, toAddresses: v.to } };
}

// validatePagerdutyKind validates a PagerDuty channel's bounded, non-empty routingKey.
function validatePagerdutyKind(name: string, routingKey: unknown): ChannelResult {
  if (typeof routingKey !== "string" || routingKey.trim().length < 1 || routingKey.length > ROUTING_KEY_MAX) {
    return { ok: false, reason: "pagerduty channel needs a routingKey" };
  }
  return { ok: true, channel: { kind: "pagerduty", name, routingKey: routingKey.trim() } };
}

// validateEmailKind validates an email channel's custom-domain recipient list.
function validateEmailKind(name: string, toAddresses: unknown, recipientsValidator: RecipientsValidator): ChannelResult {
  const v = recipientsValidator(toAddresses);
  if (!v.ok) return { ok: false, reason: v.reason };
  return { ok: true, channel: { kind: "email", name, toAddresses: v.to } };
}

// validateJsmKind validates a Jira Service Management / Opsgenie channel: a customer alert-create url
// (SSRF-screened like webhook/slack) plus an OPTIONAL apiKey (the GenieKey token). apiKey is optional
// HERE only in the KEEP-SECRET sense (parseChannelSecret); the DO's addNotifyChannel is what enforces a
// first-ever create actually has one.
function validateJsmKind(name: string, url: unknown, apiKeyRaw: unknown, allowInternalSink: boolean): ChannelResult {
  const v = isAllowedWebhookUrl(url, { allowInternalSink });
  if (!v.ok) return { ok: false, reason: v.reason, code: v.code };
  const sec = parseChannelSecret(apiKeyRaw);
  if (!sec.ok) return { ok: false, reason: `jsm channel ${sec.reason}` };
  return {
    ok: true,
    channel: { kind: "jsm", name, url: v.url, ...(sec.value !== undefined ? { apiKey: sec.value } : {}), ...(allowInternalSink ? { allowInternalSink: true } : {}) },
  };
}

// validateServicenowKind validates a ServiceNow Event Management channel: a customer em_event table url
// (SSRF-screened), a required (always-resupplied, non-secret) Basic-auth username, and an OPTIONAL
// apiKey (the Basic-auth password) under the same KEEP-SECRET discipline as jsm's token.
function validateServicenowKind(name: string, url: unknown, usernameRaw: unknown, apiKeyRaw: unknown, allowInternalSink: boolean): ChannelResult {
  const v = isAllowedWebhookUrl(url, { allowInternalSink });
  if (!v.ok) return { ok: false, reason: v.reason, code: v.code };
  if (typeof usernameRaw !== "string" || usernameRaw.trim().length < 1 || usernameRaw.length > USERNAME_MAX) {
    return { ok: false, reason: "servicenow channel needs a username" };
  }
  const sec = parseChannelSecret(apiKeyRaw);
  if (!sec.ok) return { ok: false, reason: `servicenow channel ${sec.reason}` };
  return {
    ok: true,
    channel: {
      kind: "servicenow",
      name,
      url: v.url,
      username: usernameRaw.trim(),
      ...(sec.value !== undefined ? { apiKey: sec.value } : {}),
      ...(allowInternalSink ? { allowInternalSink: true } : {}),
    },
  };
}

export function validateChannel(raw: unknown, recipientsValidator: RecipientsValidator): ChannelResult {
  if (typeof raw !== "object" || raw === null) return { ok: false, reason: "channel must be an object" };
  const c = raw as Record<string, unknown>;
  const kind = c.kind;
  if (kind !== "email" && kind !== "webhook" && kind !== "slack" && kind !== "pagerduty" && kind !== "teams" && kind !== "jsm" && kind !== "servicenow") {
    return { ok: false, reason: "kind must be email/webhook/slack/pagerduty/teams/jsm/servicenow" };
  }
  const name = c.name;
  if (typeof name !== "string" || name.trim().length < 1 || name.length > 256) {
    return { ok: false, reason: "name must be 1 to 256 characters" };
  }
  const trimmedName = name.trim();
  // allowInternalSink: the per-channel SSRF override (finding E8). Only a literal boolean true opts in;
  // anything else (absent, false, a truthy non-boolean) leaves the default-deny in force. It is stored
  // ONLY when true and ONLY on a url-bearing kind, so a foreign value never lands and an email/pagerduty
  // channel never carries a meaningless flag (exactOptionalPropertyTypes-safe).
  if (c.allowInternalSink !== undefined && typeof c.allowInternalSink !== "boolean") {
    return { ok: false, reason: "allowInternalSink must be a boolean" };
  }
  const allowInternalSink = c.allowInternalSink === true;
  if (kind === "webhook" || kind === "slack") return validateUrlKind(kind, trimmedName, c.url, allowInternalSink);
  if (kind === "teams") return validateTeamsKind(trimmedName, c, allowInternalSink, recipientsValidator);
  if (kind === "pagerduty") return validatePagerdutyKind(trimmedName, c.routingKey);
  if (kind === "jsm") return validateJsmKind(trimmedName, c.url, c.apiKey, allowInternalSink);
  if (kind === "servicenow") return validateServicenowKind(trimmedName, c.url, c.username, c.apiKey, allowInternalSink);
  return validateEmailKind(trimmedName, c.toAddresses, recipientsValidator);
}

// NOTIFY_EVENTS is the closed rule-vocabulary set validateRule checks an events array against. It is
// built DIRECTLY from NOTIFY_EVENT_NAMES (the single source of truth the NotifyEvent union is derived
// from), so it can never drift from the union: every event a rule may name is exactly the set of
// notifiable events, and a new event added to the canonical list is nameable in a rule automatically.
const NOTIFY_EVENTS: ReadonlySet<NotifyEvent> = new Set<NotifyEvent>(NOTIFY_EVENT_NAMES);

// isNotifyEvent / isSeverity are runtime guards mirroring isRole's authority-boundary discipline.
export function isNotifyEvent(v: unknown): v is NotifyEvent {
  return typeof v === "string" && NOTIFY_EVENTS.has(v as NotifyEvent);
}
export function isSeverity(v: unknown): v is Severity {
  return v === "info" || v === "warning" || v === "critical";
}

// CHANNEL_IDS_MAX / EVENTS_MAX bound the per-rule lists so a malformed rule cannot store an
// unbounded array; both are far above any realistic configuration.
const CHANNEL_IDS_MAX = 100;
const EVENTS_MAX = 50;

// validateRule checks a client-supplied NotifyRule at the authority boundary. It enforces: a valid
// scope (global, or downpipe with a bounded downpipeId); a valid minSeverity; events that is "all"
// or a non-empty bounded array of valid NotifyEvents; a non-empty bounded channelIds array of
// bounded id strings; an OPTIONAL digest in off/daily/weekly; and a boolean enabled. It returns the
// normalised rule body (id assigned by the DO) carrying digest only when set, or a typed rejection.
// parseScope validates a rule's scope (global, or downpipe with a bounded downpipeId).
function parseScope(scopeRaw: unknown): { ok: true; scope: NotifyRule["scope"] } | { ok: false; reason: string } {
  if (typeof scopeRaw !== "object" || scopeRaw === null) return { ok: false, reason: "scope is required" };
  const sc = scopeRaw as Record<string, unknown>;
  if (sc.kind === "global") return { ok: true, scope: { kind: "global" } };
  if (sc.kind === "downpipe") {
    const id = sc.downpipeId;
    if (typeof id !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(id)) {
      return { ok: false, reason: "downpipe scope needs a valid downpipeId" };
    }
    return { ok: true, scope: { kind: "downpipe", downpipeId: id } };
  }
  return { ok: false, reason: "scope.kind must be global or downpipe" };
}

// parseEvents validates a rule's events ("all" or a non-empty bounded, deduped list of valid events).
function parseEvents(raw: unknown): { ok: true; events: NotifyEvent[] | "all" } | { ok: false; reason: string } {
  if (raw === "all") return { ok: true, events: "all" };
  if (!Array.isArray(raw)) return { ok: false, reason: "events must be 'all' or a list of events" };
  if (raw.length < 1 || raw.length > EVENTS_MAX) return { ok: false, reason: "events must be 'all' or a non-empty list" };
  const out: NotifyEvent[] = [];
  const seen = new Set<NotifyEvent>();
  for (const e of raw) {
    if (!isNotifyEvent(e)) return { ok: false, reason: `unknown event: ${String(e)}` };
    if (seen.has(e)) continue;
    seen.add(e);
    out.push(e);
  }
  return { ok: true, events: out };
}

// parseChannelIds validates a rule's channelIds (a non-empty bounded, deduped list of bounded ids).
function parseChannelIds(raw: unknown): { ok: true; channelIds: string[] } | { ok: false; reason: string } {
  if (!Array.isArray(raw) || raw.length < 1 || raw.length > CHANNEL_IDS_MAX) {
    return { ok: false, reason: "channelIds must be a non-empty list" };
  }
  const channelIds: string[] = [];
  const seen = new Set<string>();
  for (const id of raw) {
    if (typeof id !== "string" || id.length < 1 || id.length > 64) return { ok: false, reason: "each channelId must be a 1 to 64 char string" };
    if (seen.has(id)) continue;
    seen.add(id);
    channelIds.push(id);
  }
  return { ok: true, channelIds };
}

export function validateRule(
  raw: unknown,
): { ok: true; rule: Omit<NotifyRule, "id"> } | { ok: false; reason: string } {
  if (typeof raw !== "object" || raw === null) return { ok: false, reason: "rule must be an object" };
  const r = raw as Record<string, unknown>;
  const sc = parseScope(r.scope);
  if (!sc.ok) return sc;
  if (!isSeverity(r.minSeverity)) return { ok: false, reason: "minSeverity must be info/warning/critical" };
  const ev = parseEvents(r.events);
  if (!ev.ok) return ev;
  const ch = parseChannelIds(r.channelIds);
  if (!ch.ok) return ch;
  // digest (optional)
  let digest: "off" | "daily" | "weekly" | undefined;
  if (r.digest !== undefined) {
    if (r.digest !== "off" && r.digest !== "daily" && r.digest !== "weekly") {
      return { ok: false, reason: "digest must be off/daily/weekly" };
    }
    digest = r.digest;
  }
  if (typeof r.enabled !== "boolean") return { ok: false, reason: "enabled must be a boolean" };
  const rule: Omit<NotifyRule, "id"> = {
    scope: sc.scope,
    minSeverity: r.minSeverity,
    events: ev.events,
    channelIds: ch.channelIds,
    enabled: r.enabled,
    ...(digest !== undefined ? { digest } : {}),
  };
  return { ok: true, rule };
}

// ruleSelects reports whether a rule selects an event of a given severity for a given downpipe. It is
// the pure core of routing resolution (contract section 2.3), unit-testable without storage:
//  - the rule must be enabled;
//  - its scope must match: a global rule matches any event; a downpipe rule matches only events for
//    that downpipe (an account-level event with downpipeId null is matched only by a global rule);
//  - the event severity must be >= the rule's minSeverity;
//  - the rule's events must include the event (or be "all").
export function ruleSelects(rule: NotifyRule, event: NotifyEvent, severity: Severity, downpipeId: string | null): boolean {
  if (!rule.enabled) return false;
  if (rule.scope.kind === "downpipe") {
    if (downpipeId === null || rule.scope.downpipeId !== downpipeId) return false;
  }
  if (!severityAtLeast(severity, rule.minSeverity)) return false;
  if (rule.events === "all") return true;
  return rule.events.includes(event);
}

// ResolvedDelivery is the routing outcome for one emission: the deduped set of enabled channels to
// deliver to NOW, and the deduped set of channels for which the emission was DEFERRED to a digest
// (success-class events on a rule whose digest is daily/weekly). The DO records a pending-digest
// entry for the deferred set and delivers immediately to the now set. digestPeriods carries the
// cadence per deferred channel so the DO can stamp each pending entry with the window it belongs to;
// when two digest rules name the SAME channel at different cadences, the SHORTEST (most frequent)
// wins, so a daily digest is never held back behind a weekly one.
export interface ResolvedDelivery {
  now: NotifyChannel[]; // deliver immediately, deduped by channel id
  digested: NotifyChannel[]; // success-class events deferred to a daily/weekly digest, deduped
  digestPeriods: Record<string, DigestPeriod>; // channelId -> the (shortest) cadence to batch it under
}

// resolveDelivery is routing resolution (contract section 2.3), a PURE function over the stored rules
// and channels. For an emission (event + severity + downpipeId):
//  - gather every matching enabled rule (ruleSelects): the global rules plus the per-downpipe rules
//    for this downpipe. A per-downpipe rule OVERRIDES the global default for the same event class on
//    that downpipe: when ANY downpipe-scoped rule selects this event, the global rules are NOT also
//    applied for it (the per-downpipe configuration wins), so an operator can redirect or silence a
//    downpipe's stream without the global default doubling it up. With no downpipe rule for the event,
//    the global rules apply (the default).
//  - from the winning rules, select each rule's channels; a SUCCESS-CLASS event on a rule whose
//    digest is daily/weekly is DEFERRED (added to `digested`), every other selection is immediate
//    (added to `now`).
//  - dedupe channels by id across rules (a channel named by two matching rules is delivered once);
//    the immediate set wins over the digested set for the same channel (if one rule would deliver now
//    and another would digest the same channel, deliver now).
// Only enabled channels that actually exist are returned; an unknown/disabled channelId is skipped.
// partitionMatchingRules returns the winning rules for an emission. It gathers every matching enabled
// rule (ruleSelects) and applies the per-downpipe override: if any downpipe-scoped rule selected this
// event, the global rules do not also apply for it (the per-downpipe configuration is the override of
// the global default); otherwise the matching global rules apply.
function partitionMatchingRules(emission: { event: NotifyEvent; severity: Severity; downpipeId: string | null }, rules: NotifyRule[]): NotifyRule[] {
  const matchingDownpipe: NotifyRule[] = [];
  const matchingGlobal: NotifyRule[] = [];
  for (const rule of rules) {
    if (!ruleSelects(rule, emission.event, emission.severity, emission.downpipeId)) continue;
    if (rule.scope.kind === "downpipe") matchingDownpipe.push(rule);
    else matchingGlobal.push(rule);
  }
  return matchingDownpipe.length > 0 ? matchingDownpipe : matchingGlobal;
}

// buildResolvedDelivery partitions the winning rules' channels into now vs digested (dedup by id;
// immediate wins over digest for the same channel) and accumulates the shortest digest cadence per
// deferred channel (daily beats weekly). Only enabled channels that exist are returned.
function buildResolvedDelivery(event: NotifyEvent, winning: NotifyRule[], byId: Map<string, NotifyChannel>): ResolvedDelivery {
  const nowIds = new Set<string>();
  const digestIds = new Set<string>();
  // digestPeriodFor records, per deferred channel, the SHORTEST cadence any digest rule chose for it
  // (daily beats weekly). This is what the flush stamps onto the pending entry; the shortest window
  // means a channel that any rule wants flushed daily is flushed daily, never delayed to a weekly rung.
  const digestPeriodFor = new Map<string, DigestPeriod>();
  const digestThisEvent = isSuccessClass(event);
  for (const rule of winning) {
    const deferred = digestThisEvent && rule.digest !== undefined && rule.digest !== "off";
    for (const id of rule.channelIds) {
      if (deferred) {
        digestIds.add(id);
        // rule.digest is "daily" | "weekly" here (deferred excludes undefined/"off").
        const period = rule.digest as DigestPeriod;
        const prior = digestPeriodFor.get(id);
        // Keep the shorter window: daily (the shorter) wins over a prior weekly.
        if (prior === undefined || (prior === "weekly" && period === "daily")) digestPeriodFor.set(id, period);
      } else {
        nowIds.add(id);
      }
    }
  }
  const now: NotifyChannel[] = [];
  const digested: NotifyChannel[] = [];
  const digestPeriods: Record<string, DigestPeriod> = {};
  for (const id of nowIds) {
    const ch = byId.get(id);
    if (ch?.enabled) now.push(ch);
  }
  for (const id of digestIds) {
    if (nowIds.has(id)) continue; // immediate wins over digest for the same channel
    const ch = byId.get(id);
    if (ch?.enabled) {
      digested.push(ch);
      const p = digestPeriodFor.get(id);
      if (p !== undefined) digestPeriods[id] = p;
    }
  }
  return { now, digested, digestPeriods };
}

export function resolveDelivery(
  emission: { event: NotifyEvent; severity: Severity; downpipeId: string | null },
  rules: NotifyRule[],
  channels: NotifyChannel[],
): ResolvedDelivery {
  const byId = new Map<string, NotifyChannel>();
  for (const ch of channels) byId.set(ch.id, ch);
  const winning = partitionMatchingRules(emission, rules);
  return buildResolvedDelivery(emission.event, winning, byId);
}

// deliverToChannel dispatches ONE emission to ONE channel by kind, fully guarded so NOTHING can
// throw into the caller (the DO's emit path or the cron). It selects the per-kind adapter's deliver
// (each itself fail-open) and returns the best-effort delivery boolean. The extra try/catch is
// belt-and-braces: every adapter already swallows its own errors (deliverPayload / sendEmail never
// throw), but a future change to a formatter or dispatch cannot regress the fail-open guarantee. An
// email/teams-via-email delivery needs env (for the send_email binding); url/routingKey channels do
// not, but env is threaded uniformly so the dispatch is one signature.
export async function deliverToChannel(env: Env, channel: NotifyChannel, emission: NotifyEmission): Promise<ChannelDeliveryResult> {
  try {
    switch (channel.kind) {
      case "webhook":
        return await webhookChannel.deliver(channel, emission);
      case "slack":
        return await slackChannel.deliver(channel, emission);
      case "pagerduty":
        return await pagerdutyChannel.deliver(channel, emission);
      case "teams":
        return await teamsChannel.deliver(env, channel, emission);
      case "email":
        return await emailChannel.deliver(env, channel, emission);
      case "jsm":
        return await jsmChannel.deliver(env, channel, emission);
      case "servicenow":
        return await servicenowChannel.deliver(env, channel, emission);
    }
  } catch {
    // A thrown delivery path must never escape into a backup or the cron; degrade to not-delivered.
    //
    // G020: every adapter already swallows its own transport errors (deliverPayload and sendEmail never
    // throw), so a throw that reaches HERE is by construction an engine fault -- never a customer-side
    // transport class -- and adapter-exception says exactly that. The path is otherwise unchanged: still
    // fail-open, still not-delivered, still no message recorded.
    return { ok: false, code: "adapter-exception" };
  }
}

// DeliveryRecord is one channel's delivery outcome the DO turns into a NotifyHistoryEntry. It is the
// redaction-safe join of the emission + the channel + the result: the channel id/kind, whether the
// send was accepted, and the emission's event/severity/downpipeId/detail (all already safe).
export interface DeliveryRecord {
  channelId: string;
  channelKind: ChannelKind;
  delivered: boolean;
  // The closed delivery-failure code + (email) shape-gated platform code, present only on a failed
  // delivery; recovered marks a PagerDuty resolve emission. Carried through /notify/record into the history.
  code?: DeliveryFailCode;
  platformCode?: string;
  recovered?: boolean;
  // The send-time sink-screen verdict for a url-bearing channel (NOTIF: dns-rebinding-gap), carried on
  // success AND failure (a delivered `hostname` sink is the rebind-exposed class). Dropped for email/pagerduty.
  sinkScreen?: SinkScreenVerdict;
  // unconfirmed (item 10): JSM/Opsgenie's async-accepted (202) outcome, carried through into the history
  // entry so a bare 202 is never recorded as an indistinguishable plain "delivered".
  unconfirmed?: boolean;
  // ackOutcome (gap G033): the CLOSED async-confirmation verdict, carried through /notify/record into the
  // history entry so a POSITIVELY-FAILED async create (async-create-failed) is never indistinguishable from a
  // confirmation we could not obtain (confirmation-unavailable).
  ackOutcome?: AckOutcome;
  // G020: which recipient in the channel's address list was rejected (an integer POSITION, never the address).
  recipientIndex?: number;
}

// deliverEmission is the single, fully-guarded fan-out the DO's emit path calls. Given an emission
// and the already-resolved set of NOW channels (from resolveDelivery), it delivers to each in turn
// (sequentially: an account's channel count is small and the single-threaded DO context favours
// simple, bounded work over parallel fan-out), guarding each so one channel's failure never aborts
// the rest. It NEVER throws. It returns one DeliveryRecord per attempted channel so the caller can
// append a redaction-safe history entry per delivery. The digested set is NOT delivered here (it is
// deferred to a digest); the caller records the deferral separately.
export async function deliverEmission(env: Env, emission: NotifyEmission, channels: NotifyChannel[]): Promise<DeliveryRecord[]> {
  const records: DeliveryRecord[] = [];
  for (const ch of channels) {
    const r = await deliverToChannel(env, ch, emission);
    records.push({
      channelId: ch.id,
      channelKind: ch.kind,
      delivered: r.ok,
      // On a FAILURE, carry the closed WHY (and the email platform code). On a recovered emission, mark it so
      // a PagerDuty resolve is visible in the history (the dedup-key correlation with its earlier trigger).
      ...(!r.ok && r.code !== undefined ? { code: r.code } : {}),
      ...(!r.ok && r.platformCode !== undefined ? { platformCode: r.platformCode } : {}),
      ...(emission.recovered === true ? { recovered: true } : {}),
      // The send-time sink-screen verdict rides on SUCCESS and failure alike (a delivered `hostname` sink is
      // the rebind-exposed one). Only url channels set it; email/pagerduty leave it undefined (omitted).
      ...(r.sinkScreen !== undefined ? { sinkScreen: r.sinkScreen } : {}),
      // unconfirmed (item 10) rides on a delivered:true JSM/Opsgenie async-accepted (202) outcome.
      ...(r.unconfirmed === true ? { unconfirmed: true } : {}),
      // ackOutcome (gap G033): the closed async-confirmation verdict alongside it, so a POSITIVELY-failed
      // async create is distinguishable from an unobtainable confirmation.
      ...(r.ackOutcome !== undefined ? { ackOutcome: r.ackOutcome } : {}),
      // G020: the failing recipient's INDEX, on a failure only. The address stopped inside sendEmail.
      ...(!r.ok && r.recipientIndex !== undefined ? { recipientIndex: r.recipientIndex } : {}),
    });
  }
  return records;
}


// routeEngineNotification is the two-phase DO + Worker split every engine-side notification takes: the DO
// resolves which channels this emission routes to right now (rules, severity, digest batching), this side
// delivers through the channel adapters, which are the half that holds env, and posts the per-channel
// outcomes back so the DO records the redaction-safe history.
//
// It is FULLY FAIL-OPEN, and that is the property worth stating rather than assuming. Every caller reaches
// it AFTER the operation it is reporting has already completed, so a routing or delivery hiccup must
// degrade to "not delivered" and never escape into a seal path or a restore. deliverEmission does not
// throw and the whole body is wrapped.
//
// It is shared rather than copied because the failure handling here is the load-bearing part: it
// distinguishes "no channel was configured" (an honest nothing-to-deliver, not a lost alert) from a
// routing throw, and it AWAITS the history write so support can tell "the alert never went out" from "it
// went out and only its record was lost". A second copy would drift on exactly those distinctions.
//
// label names the calling path and appears only in log lines, never in a delivered notification.
export async function routeEngineNotification(
  env: Env,
  scheduler: DurableObjectStub,
  emission: NotifyEmission,
  label: string,
): Promise<{ delivered: boolean; routingFailed?: boolean; historyWriteFailed?: boolean }> {
  try {
    const resolveResp = await scheduler.fetch(doURL("/notify/resolve"), {
      method: "POST",
      body: JSON.stringify({ emission }),
      headers: { "content-type": "application/json" },
    });
    const { now } = (await resolveResp.json()) as { now: NotifyChannel[]; digestedCount: number; emission: NotifyEmission | null };
    // No channel resolved immediately is NOT a routing failure: the operator configured no immediate
    // channel, or it was digested. Reporting that as a lost alert would be a false alarm.
    if (now.length === 0) return { delivered: false };
    const records = await deliverEmission(env, emission, now);
    let historyWriteFailed = false;
    try {
      const rec = await scheduler.fetch(doURL("/notify/record"), {
        method: "POST",
        body: JSON.stringify({ emission, records }),
        headers: { "content-type": "application/json" },
      });
      if (!rec.ok) historyWriteFailed = true;
    } catch (e) {
      historyWriteFailed = true;
      log("error", `${label} notify history record failed (non-critical): ${(e as Error).message}`);
    }
    return { delivered: records.some((r) => r.delivered), ...(historyWriteFailed ? { historyWriteFailed: true } : {}) };
  } catch (e) {
    log("error", `${label} notification routing skipped (non-critical): ${(e as Error).message}`);
    return { delivered: false, routingFailed: true };
  }
}
