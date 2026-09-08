// The Slack channel adapter (contract section 2.2). A Slack incoming-webhook is a url that accepts a
// Slack-specific JSON body; this adapter formats a NotifyEmission into `{ text, blocks? }` and
// delivers it via the shared fail-open deliverPayload. The text is a severity glyph plus the
// redaction-safe one-line detail; the optional blocks add a section with the event and severity.
// REDACTION: the body is built only from the emission's safe surface (enums, downpipe name, detail,
// time); it never carries a secret, key, value or fingerprint. FAIL-OPEN: deliver never throws.

import type { ChannelDeliveryResult, NotifyChannel, NotifyEmission } from "../types.ts";
import { deliverPayload, severityEmoji } from "../types.ts";

// SlackPayload is the minimal Slack incoming-webhook body. text is the fallback/notification line;
// blocks is an optional richer layout. Both carry only the redaction-safe surface.
export interface SlackPayload {
  text: string;
  blocks?: Array<{ type: "section"; text: { type: "mrkdwn"; text: string } }>;
}

// format renders the Slack body: a glyph + the detail as text, and a single mrkdwn section block
// naming the event and severity. mrkdwn here uses only the emission's own safe strings.
export function format(emission: NotifyEmission): SlackPayload {
  const text = `${severityEmoji(emission.severity)} ${emission.detail}`;
  return {
    text,
    blocks: [
      {
        type: "section",
        text: { type: "mrkdwn", text: `*${emission.event}* (${emission.severity})\n${emission.detail}` },
      },
    ],
  };
}

// deliver POSTs the Slack body to the channel's validated url, fail-open.
export async function deliver(channel: NotifyChannel, emission: NotifyEmission): Promise<ChannelDeliveryResult> {
  if (!channel.url) return { ok: false, code: "no-transport" };
  // SSRF defence in depth: re-screen the host at send time, honouring the per-channel opt-in.
  const r = await deliverPayload(channel.url, format(emission), channel.allowInternalSink === true);
  // Carry the send-time sink-screen verdict (NOTIF: dns-rebinding-gap) so the history OBSERVES the sink class.
  return { ok: r.ok, ...(r.code !== undefined ? { code: r.code } : {}), ...(r.sinkScreen !== undefined ? { sinkScreen: r.sinkScreen } : {}) };
}
