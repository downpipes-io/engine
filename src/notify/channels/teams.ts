// The Microsoft Teams channel adapter (contract section 2.2). Teams supports two transports: an
// incoming-webhook CONNECTOR (a url that accepts a MessageCard body) OR email-to-channel (send to the
// channel's email address via the engine's outbound email). This adapter dispatches on which the
// channel was configured with: a url -> the connector card via the shared fail-open deliverPayload; a
// toAddresses -> the email channel adapter (which uses src/email.ts). REDACTION: both bodies are
// built only from the emission's safe surface (event/severity enums, the downpipe name + state
// one-liner, the time); never a secret, key, value or fingerprint. FAIL-OPEN: deliver never throws.

import type { Env } from "../../env.d.ts";
import type { ChannelDeliveryResult, NotifyChannel, NotifyEmission } from "../types.ts";
import { deliverPayload, severityEmoji } from "../types.ts";
import { deliver as deliverEmail } from "./email.ts";

// TeamsCard is the minimal legacy MessageCard the connector accepts. themeColor is derived from
// severity (a cosmetic hex, no data); title and text carry the redaction-safe surface only.
export interface TeamsCard {
  "@type": "MessageCard";
  "@context": "http://schema.org/extensions";
  themeColor: string;
  summary: string;
  title: string;
  text: string;
}

// Connector card accent hex strings, one per severity. Cosmetic only.
const COLOUR_CRITICAL = "D93F3F";
const COLOUR_WARNING = "E8A317";
const COLOUR_INFO = "2EB67D";

// themeColour maps severity to a connector card accent hex string. Cosmetic only.
function themeColour(severity: NotifyEmission["severity"]): string {
  switch (severity) {
    case "critical":
      return COLOUR_CRITICAL;
    case "warning":
      return COLOUR_WARNING;
    case "info":
      return COLOUR_INFO;
  }
}

// formatCard renders the connector MessageCard from the emission's safe surface.
export function formatCard(emission: NotifyEmission): TeamsCard {
  return {
    "@type": "MessageCard",
    "@context": "http://schema.org/extensions",
    themeColor: themeColour(emission.severity),
    summary: `${emission.event} (${emission.severity})`,
    title: `${severityEmoji(emission.severity)} ${emission.event} (${emission.severity})`,
    text: emission.detail,
  };
}

// deliver dispatches on the configured transport: a connector url POSTs the MessageCard (fail-open
// via deliverPayload); otherwise, when toAddresses is set, it sends an email to the channel address
// (reusing the email adapter, itself fail-open via src/email.ts). A channel with neither is a
// non-delivery (impossible after validateChannel, but defensive).
export async function deliver(env: Env, channel: NotifyChannel, emission: NotifyEmission): Promise<ChannelDeliveryResult> {
  if (channel.url) {
    // SSRF defence in depth: re-screen the connector host at send time, honouring the per-channel opt-in.
    const r = await deliverPayload(channel.url, formatCard(emission), channel.allowInternalSink === true);
    // Carry the send-time sink-screen verdict (NOTIF: dns-rebinding-gap) so the history OBSERVES the sink class.
    return { ok: r.ok, ...(r.code !== undefined ? { code: r.code } : {}), ...(r.sinkScreen !== undefined ? { sinkScreen: r.sinkScreen } : {}) };
  }
  if (channel.toAddresses && channel.toAddresses.length > 0) {
    return deliverEmail(env, channel, emission);
  }
  // G280: a Teams channel carries EITHER a connector url OR an address list, and neither is present. The
  // url is the primary transport for this kind, so its absence is the actionable statement.
  return { ok: false, code: "no-url" };
}
