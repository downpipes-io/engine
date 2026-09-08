// The email channel adapter (contract section 2.2). It formats a NotifyEmission into a redaction-safe
// EmailMessage (subject, a plain-text part, and a branded HTML part from the same redaction-safe surface) and delivers it via the
// fail-open sendEmail (src/email.ts), which is honestly { ok:false, reason:"email-not-configured" }
// when the send_email binding is absent. REDACTION: the subject/body are built ONLY from the
// emission's safe surface (event/severity enums, the downpipe name + state one-liner, the time);
// never a secret, key, value or fingerprint. FAIL-OPEN: deliver never throws (sendEmail swallows all).

import { type EmailMessage, sendEmail } from "../../email.ts";
import type { Env } from "../../env.d.ts";
import type { ChannelDeliveryResult, DeliveryFailCode, NotifyChannel, NotifyEmission } from "../types.ts";
import { emailPlatformCodeOf } from "../types.ts";
import { renderEngineEmailHtml } from "../../email-theme.ts";

// emailReasonToCode maps the fail-open sendEmail reason vocabulary to the CLOSED DeliveryFailCode so the
// delivery history says WHY an email alert did not go out (unconfigured binding vs a bad EMAIL_FROM vs the
// platform rejecting the send). It reads the engine's OWN closed reason vocabulary (email.ts EmailResult),
// never a platform message, and returns an enum member.
//
// G236: a subject that failed the send primitive's bounds, a body that failed them (both ENGINE-side
// formatting bugs) and the Email Service refusing the send outright (a CUSTOMER-side onboarding gap: an
// un-onboarded sending domain, an unverified sender) are different tickets with opposite fixes, so each arm
// is named here; the residual email-rejected remains for any reason outside the vocabulary, so a future
// reason can never fall out of the closed set.
export function emailReasonToCode(reason: string | undefined): DeliveryFailCode {
  switch (reason) {
    case "email-not-configured":
      return "email-not-configured";
    // G020: EMAIL_FROM never set and EMAIL_FROM set-but-wrong are different tickets (an onboarding gap vs a
    // malformed sender address), so they are different codes.
    case "email-from-not-configured":
      return "email-from-not-configured";
    case "email-from-invalid":
      return "email-from-invalid";
    case "email-recipients-invalid":
      return "email-recipients-invalid";
    case "email-subject-invalid":
      return "email-subject-invalid";
    case "email-body-invalid":
      return "email-body-invalid";
    case "email-send-failed":
      return "email-platform-rejected";
    default:
      return "email-rejected"; // residual: a reason outside the closed vocabulary
  }
}

// SUBJECT_PREFIX tags the alert so it is filterable in an inbox. It is a fixed, non-sensitive label.
const SUBJECT_PREFIX = "[downpipe]";

// format renders the EmailMessage for an emission and a set of recipient addresses. The subject is a
// prefix + severity + event; the text body is the redaction-safe detail plus the event/severity/time
// lines. The html body is the SAME safe surface rendered into the branded card (email-theme.ts); it
// carries no secret, key, fingerprint or link, and every value is escaped where it enters markup.
export function format(toAddresses: string[], emission: NotifyEmission): EmailMessage {
  const subject = `${SUBJECT_PREFIX} ${emission.severity}: ${emission.event}`;
  const text =
    `${emission.detail}\n\n` +
    `Event: ${emission.event}\n` +
    `Severity: ${emission.severity}\n` +
    (emission.downpipeName !== null ? `Downpipe: ${emission.downpipeName}\n` : "") +
    `Time: ${emission.at}\n`;
  // The html part is the SAME redaction-safe surface as the text: the detail line, then the
  // event/severity/(downpipe/)time facts. It emits no CTA and no link, so nothing sensitive rides it.
  const facts = [
    `Event: ${emission.event}`,
    `Severity: ${emission.severity}`,
    ...(emission.downpipeName !== null ? [`Downpipe: ${emission.downpipeName}`] : []),
    `Time: ${emission.at}`,
  ].join("\n");
  const html = renderEngineEmailHtml({ subject, heading: `${emission.severity}: ${emission.event}`, paragraphs: [emission.detail, facts] });
  return { to: toAddresses, subject, text, html };
}

// deliver sends the formatted message via the engine's fail-open email primitive. A channel with no
// toAddresses (impossible after validateChannel) is a non-delivery. The result is the best-effort
// outcome: ok reflects whether the binding accepted the send (false when email is unconfigured).
export async function deliver(env: Env, channel: NotifyChannel, emission: NotifyEmission): Promise<ChannelDeliveryResult> {
  const to = channel.toAddresses;
  // G280: the channel HAS a transport (email); what it lacks is an ADDRESS LIST. no-transport said only
  // "something about this channel is missing" and the customer could not be told which field to fill.
  if (!to || to.length === 0) return { ok: false, code: "no-recipients" };
  const r = await sendEmail(env, format(to, emission));
  if (r.ok) return { ok: true };
  // Carry the closed reason code AND the platform code (E_SENDER_DOMAIN_NOT_AVAILABLE, ...) -- the one
  // diagnostic that names an email-send onboarding gap. emailPlatformCodeOf is the redaction chokepoint: a
  // documented E_UPPER_SNAKE code passes through, and a NON-CONFORMING code is still recorded as the
  // engine-owned E_OTHER placeholder (G236: the fact that the platform sent a code is itself evidence), so
  // the raw platform string never leaves the classifier.
  const platformCode = emailPlatformCodeOf(r.code);
  // G020: carry the failing recipient's INDEX onto the history row. The address never leaves sendEmail.
  return {
    ok: false,
    code: emailReasonToCode(r.reason),
    ...(platformCode !== undefined ? { platformCode } : {}),
    ...(r.recipientIndex !== undefined ? { recipientIndex: r.recipientIndex } : {}),
  };
}
