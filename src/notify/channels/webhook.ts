// The generic webhook channel adapter (contract section 2.2). It formats a NotifyEmission into the
// versioned `downpipe-event-v1` body and delivers it via the shared fail-open deliverPayload
// (https-validated url at store time, 5s timeout, errors swallowed). This is the channel a customer
// points at their own SIEM/automation; the body
// carries ONLY the customer's own redaction-safe operational facts (event/severity enums, the
// downpipe id/name, a one-line detail, the emit time), never a secret, key, value or fingerprint.
//
// Fail-open + redaction are inherited: format adds no field beyond the emission's safe surface, and
// deliver never throws (deliverPayload swallows all errors into { ok:false }).

import type { ChannelDeliveryResult, NotifyChannel, NotifyEmission } from "../types.ts";
import { deliverPayload } from "../types.ts";

// WebhookPayloadV1 is the versioned generic webhook body. The `kind` lets a receiver pin the schema.
// downpipe is OMITTED for an account-level event (downpipeId null), exactOptionalPropertyTypes-safe.
export interface WebhookPayloadV1 {
  kind: "downpipe-event-v1";
  at: string;
  event: string;
  severity: string;
  downpipe?: { id: string; name: string | null };
  detail: string;
}

// format renders the v1 body from the emission's redaction-safe fields only.
export function format(emission: NotifyEmission): WebhookPayloadV1 {
  return {
    kind: "downpipe-event-v1",
    at: emission.at,
    event: emission.event,
    severity: emission.severity,
    ...(emission.downpipeId !== null ? { downpipe: { id: emission.downpipeId, name: emission.downpipeName } } : {}),
    detail: emission.detail,
  };
}

// deliver POSTs the formatted body to the channel's validated url. It is fail-open: a channel with no
// url (impossible after validateChannel, but defensive) is a non-delivery, and deliverPayload never
// throws. Returns the best-effort delivery outcome.
export async function deliver(channel: NotifyChannel, emission: NotifyEmission): Promise<ChannelDeliveryResult> {
  if (!channel.url) return { ok: false, code: "no-transport" };
  // SSRF defence in depth: deliverPayload re-screens the host at send time. Pass the channel's
  // explicit internal-sink opt-in (default false) so an internal target is refused unless the
  // operator deliberately allowed it. The closed failure code (redirect / 4xx / 5xx / SSRF / timeout)
  // rides back so the delivery history can say WHY, never the raw response.
  const r = await deliverPayload(channel.url, format(emission), channel.allowInternalSink === true);
  // Carry the send-time sink-screen verdict (NOTIF: dns-rebinding-gap) so the history can OBSERVE whether
  // this customer sink was a literal IP (fully screened) or an un-pinnable hostname (the residual rebind gap).
  return { ok: r.ok, ...(r.code !== undefined ? { code: r.code } : {}), ...(r.sinkScreen !== undefined ? { sinkScreen: r.sinkScreen } : {}) };
}
