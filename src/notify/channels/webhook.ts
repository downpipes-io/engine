// The generic webhook channel adapter (contract section 2.2). It formats a NotifyEmission into the
// versioned `downpipe-event-v1` body and delivers it via the shared fail-open deliverPayload
// (https-validated url at store time, 5s timeout, errors swallowed). This is the channel a customer
// points at their own SIEM/automation; the body
// carries ONLY the customer's own redaction-safe operational facts (event/severity enums, the
// downpipe id/name, a one-line detail, the emit time), never a secret, key, value or fingerprint.
//
// Fail-open + redaction are inherited: format adds no field beyond the emission's safe surface (the
// dedupKey is built from the downpipe id and the event enum, or the event enum alone), and
// deliver never throws (deliverPayload swallows all errors into { ok:false }).

import type { ChannelDeliveryResult, NotifyChannel, NotifyEmission } from "../types.ts";
import { deliverPayload, incidentDedupKey } from "../types.ts";

// WebhookPayloadV1 is the versioned generic webhook body. The `kind` lets a receiver pin the schema.
// downpipe is OMITTED for an account-level event (downpipeId null), exactOptionalPropertyTypes-safe.
// dedupKey and recovered are additive fields (from engine 0.3.7) and the kind stays v1. A receiver that
// ignores unknown keys keeps working. A receiver that rejects unknown keys (an exact key-set check) rejects
// every 0.3.7 body, and the engine records a success if that receiver still answers 2xx, so
// UPGRADING.md and the webhook docs page tell such a receiver to accept the two keys. The v1 contract is
// that the body can gain optional fields and a receiver ignores keys it does not know; a removed or
// renamed field is a new kind. The two fields let a webhook-based incident tool (incident.io, Grafana
// OnCall, Splunk On-Call) correlate a trigger with its later close, as the PagerDuty, JSM and ServiceNow
// adapters do natively.
export interface WebhookPayloadV1 {
  kind: "downpipe-event-v1";
  at: string;
  event: string;
  severity: string;
  downpipe?: { id: string; name: string | null };
  detail: string;
  dedupKey: string;
  recovered?: true;
}

// format renders the v1 body from the emission's redaction-safe fields only. dedupKey is the shared
// incidentDedupKey (types.ts), the key the PagerDuty, JSM and ServiceNow adapters send. recovered is
// present, and true, only on the auto-resolve close of one of the four recovering events (backup-failure,
// backup-stale, replication-degraded, run-at-risk-eviction). It is omitted otherwise, so a receiver maps
// "recovered present" to resolve and anything else to trigger. canary-recovered is its own event, not a
// recovered close: it carries no recovered and its key is account:canary-recovered, not the canary-dead key.
export function format(emission: NotifyEmission): WebhookPayloadV1 {
  return {
    kind: "downpipe-event-v1",
    at: emission.at,
    event: emission.event,
    severity: emission.severity,
    ...(emission.downpipeId !== null ? { downpipe: { id: emission.downpipeId, name: emission.downpipeName } } : {}),
    detail: emission.detail,
    dedupKey: incidentDedupKey(emission),
    ...(emission.recovered === true ? { recovered: true as const } : {}),
  };
}

// deliver POSTs the formatted body to the channel's validated url. It is fail-open: a channel with no
// url (impossible after validateChannel, but defensive) is a non-delivery, and deliverPayload never
// throws. Returns the best-effort delivery outcome. egressAllowlist (ASVS V13.2.4) is the account's
// current configured allowlist; absent permits every host (screenEgressAllowlist's unset behaviour).
export async function deliver(channel: NotifyChannel, emission: NotifyEmission, egressAllowlist?: readonly string[]): Promise<ChannelDeliveryResult> {
  if (!channel.url) return { ok: false, code: "no-transport" };
  // SSRF defence in depth: deliverPayload re-screens the host at send time. Pass the channel's
  // explicit internal-sink opt-in (default false) so an internal target is refused unless the
  // operator deliberately allowed it. The closed failure code (redirect / 4xx / 5xx / SSRF / timeout)
  // rides back so the delivery history can say WHY, never the raw response.
  const r = await deliverPayload(channel.url, format(emission), channel.allowInternalSink === true, undefined, undefined, egressAllowlist);
  // Carry the send-time sink-screen verdict (NOTIF: dns-rebinding-gap) so the history can OBSERVE whether
  // this customer sink was a literal IP (fully screened) or an un-pinnable hostname (the residual rebind gap).
  return { ok: r.ok, ...(r.code !== undefined ? { code: r.code } : {}), ...(r.sinkScreen !== undefined ? { sinkScreen: r.sinkScreen } : {}), ...(r.resolvedScreen !== undefined ? { resolvedScreen: r.resolvedScreen } : {}) };
}
