// The PagerDuty channel adapter (contract section 2.2). PagerDuty is the Events API v2: a POST to a
// FIXED provider endpoint with the channel's routing key and a PagerDuty-specific envelope. It
// supports trigger and resolve, so a RECOVERED failure/stale condition can auto-resolve the incident
// (emission.recovered drives event_action: "resolve"). The payload carries only the redaction-safe
// surface (a summary built from the downpipe name + state, the severity, a source label); never a
// secret, key, value or fingerprint. FAIL-OPEN: deliver never throws (deliverPayload swallows all).
//
// The routing key is the customer's own credential to their own PagerDuty service; the engine stores
// it as their config (a NotifyChannel.routingKey) and sends it to the fixed endpoint, never logs it.

import type { ChannelDeliveryResult, NotifyChannel, NotifyEmission, Severity } from "../types.ts";
import { deliverPayload } from "../types.ts";

// PAGERDUTY_EVENTS_URL is the fixed Events API v2 enqueue endpoint. It is a constant provider URL,
// NOT a customer-supplied url, so it is not subject to (and does not need) isAllowedWebhookUrl; the
// per-channel secret is the routing key in the body.
export const PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue";

// PagerDutyPayload is the Events API v2 envelope. event_action is trigger (a new/continuing
// condition) or resolve (a recovered condition). dedup_key lets PagerDuty correlate a trigger with
// its later resolve; it is derived from the downpipe id + event so a recovery resolves the matching
// incident. payload.severity maps our scale to PagerDuty's (info/warning/critical are shared; we map
// directly). source is a redaction-safe label (the downpipe name or "downpipe"). component carries
// the event enum.
export interface PagerDutyPayload {
  routing_key: string;
  event_action: "trigger" | "resolve";
  dedup_key?: string;
  payload: {
    summary: string;
    severity: Severity;
    source: string;
    component?: string;
  };
}

// pagerdutyDedupKey derives a stable correlation key from the downpipe id + event so a resolve cancels
// the matching trigger. For an account-level event (downpipeId null) it keys on the event alone.
function pagerdutyDedupKey(emission: NotifyEmission): string {
  return emission.downpipeId !== null ? `downpipe:${emission.downpipeId}:${emission.event}` : `account:${emission.event}`;
}

// format renders the Events API v2 envelope from the emission's safe surface. A recovered emission
// sends event_action "resolve" (auto-resolving the incident); otherwise "trigger". The summary is
// the redaction-safe one-line detail (downpipe name + state), capped to PagerDuty's 1024-char limit.
export function format(channel: NotifyChannel, emission: NotifyEmission): PagerDutyPayload {
  const action: "trigger" | "resolve" = emission.recovered === true ? "resolve" : "trigger";
  const summary = emission.detail.length > 1024 ? emission.detail.slice(0, 1024) : emission.detail;
  return {
    routing_key: channel.routingKey ?? "",
    event_action: action,
    dedup_key: pagerdutyDedupKey(emission),
    payload: {
      summary,
      severity: emission.severity,
      source: emission.downpipeName ?? "downpipe",
      component: emission.event,
    },
  };
}

// deliver POSTs the envelope to the fixed Events API v2 endpoint, fail-open. A channel with no
// routing key (impossible after validateChannel) is a non-delivery.
export async function deliver(channel: NotifyChannel, emission: NotifyEmission): Promise<ChannelDeliveryResult> {
  // G280: PagerDuty has a FIXED endpoint, so a PagerDuty channel can only ever be missing its CREDENTIAL
  // (the routing key). Naming the absent field class is the whole fix ticket.
  if (!channel.routingKey) return { ok: false, code: "no-credential" };
  // PAGERDUTY_EVENTS_URL is a FIXED provider endpoint chosen by the adapter, not a customer url, so it
  // is exempt from the send-time internal-sink screen (allowInternal=true); the per-channel secret is
  // the routing key in the body, validated separately. The closed failure code (4xx = a bad routing key,
  // 5xx = PagerDuty erroring) rides back so a "pages never arrive" can be diagnosed. A recovered emission
  // sends event_action:"resolve" (whether the resolve reached PagerDuty rides on the delivered/recovered
  // pair in the history, which the pack surfaces for the dedup-key correlation).
  const r = await deliverPayload(PAGERDUTY_EVENTS_URL, format(channel, emission), true);
  return { ok: r.ok, ...(r.code !== undefined ? { code: r.code } : {}) };
}
