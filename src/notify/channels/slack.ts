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

// escapeSlack applies the three entity escapes Slack's message API requires in text and mrkdwn (ASVS
// V1.3.3). Without them a detail string is ACTIVE SYNTAX: `<!channel>` pings the whole channel and
// `<https://evil.example|Open the restore console>` renders as a labelled link. The detail is not a safe
// string: it is built from the downpipe NAME, which config-validate bounds by length only, so an operator
// with downpipe.write could put either of those into every alert this channel carries. Event and severity
// are closed vocabularies and are left as they are.
export function escapeSlack(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// format renders the Slack body: a glyph + the detail as text, and a single mrkdwn section block
// naming the event and severity. The detail is escaped in both places; see escapeSlack.
export function format(emission: NotifyEmission): SlackPayload {
  const detail = escapeSlack(emission.detail);
  const text = `${severityEmoji(emission.severity)} ${detail}`;
  return {
    text,
    blocks: [
      {
        type: "section",
        text: { type: "mrkdwn", text: `*${emission.event}* (${emission.severity})\n${detail}` },
      },
    ],
  };
}

// deliver POSTs the Slack body to the channel's validated url, fail-open. egressAllowlist (ASVS V13.2.4)
// is the account's current configured allowlist; absent permits every host.
export async function deliver(channel: NotifyChannel, emission: NotifyEmission, egressAllowlist?: readonly string[]): Promise<ChannelDeliveryResult> {
  if (!channel.url) return { ok: false, code: "no-transport" };
  // SSRF defence in depth: re-screen the host at send time, honouring the per-channel opt-in.
  const r = await deliverPayload(channel.url, format(emission), channel.allowInternalSink === true, undefined, undefined, egressAllowlist);
  // Carry the send-time sink-screen verdict (NOTIF: dns-rebinding-gap) so the history OBSERVES the sink class.
  return { ok: r.ok, ...(r.code !== undefined ? { code: r.code } : {}), ...(r.sinkScreen !== undefined ? { sinkScreen: r.sinkScreen } : {}), ...(r.resolvedScreen !== undefined ? { resolvedScreen: r.resolvedScreen } : {}) };
}
