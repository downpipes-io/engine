// Outbound email (contract section 3). A single fail-open send primitive the rest of the engine
// uses for operator-facing mail: notification channels of kind "email" (section 2), credential and
// key expiry alerts (section 4). It is the email counterpart of deliverPayload: one guarded
// send, never a control.
//
// NO-CUSTODY + REDACTION boundary (sacred, mirrored from notify.ts). An email is observability sent
// to a recipient the customer configured (their own on-call inbox, their own Teams channel address).
// The body is built by the caller from the SAME redaction-safe surface the webhook alert uses (a
// downpipe id/name + a state enum + RFC-3339 times); this module is content-neutral and adds no
// field of its own beyond the configured sender. It must NEVER be handed, and never forwards, a key,
// a record value, a destination credential, a selector-as-secret, or a fingerprint. Callers pass
// already-safe subject/text/html; this module does not inspect or transform them and does not log
// them (a thrown send logs only a coarse reason, never the message).
//
// THE ONE SANCTIONED EXCEPTION to "never a key" is the custody-share route (admin/router-custody.ts,
// POST /custody/send-share). It deliberately carries a SINGLE Shamir share of the customer's split
// break-glass key. A share below the reconstruction threshold is information-theoretically NULL (it
// reveals nothing about the key), it is sent by the customer's own choice, one share per request, over
// their own domain, never logged and never stored, and the ciphertext (the envelope over identity.key)
// is kept strictly OFF the engine, so even every emailed share together cannot decrypt. That is a
// bounded, customer-initiated key-custody flow, not observability, and it is the ONLY place a
// key-adjacent value may cross this boundary; every other caller stays redaction-safe.
//
// FAIL-OPEN (sacred). sendEmail NEVER throws and never blocks a backup, a cron tick, or a route. An
// absent EMAIL binding, an unconfigured/invalid EMAIL_FROM, a malformed recipient, or a thrown
// send() all degrade to a returned { ok: false, reason } with a short enumerated reason. The
// notification router and the expiry path treat email exactly like the webhook: best-effort, the
// condition persists in state, the next eligible tick retries.
//
// LIVE-SEND GATING (cost honesty). The Cloudflare send_email binding requires Workers Paid plus
// destination-address/domain onboarding, which is gated and not exercised by any validator (the
// validators pass an in-memory double for env.EMAIL). At the code level this is a guarded call to
// env.EMAIL.send(); nothing here incurs a cost until the binding is bound and the domain onboarded.
//
// Node 25 strip-types compatible: no enums, no parameter properties, explicit declarations only.
// exactOptionalPropertyTypes: optional keys (html, reason) are set only when they carry a value.

import type { Env } from "./env.d.ts";
import { log } from "./log.ts";
// The platform-code shape gate + the engine-owned placeholder live in the notify leaf (notify/types.ts, which
// imports nothing but a type). They are single-sourced from there rather than re-spelled here, so the gate the
// log applies is the SAME one the notify history and the support pack re-apply, and the three cannot drift.
import { EMAIL_PLATFORM_CODE_OTHER, sanitiseEmailPlatformCode } from "./notify/types.ts";

// EmailMessage is the redaction-safe message the caller assembles. `to` is one or more recipient
// addresses (validated here at the boundary); subject/text are required; html is an OPTIONAL richer
// body. There is deliberately no header/attachment/raw field: the only thing that crosses to the
// binding is a small, plain message the caller has already made safe.
export interface EmailMessage {
  to: string[];
  subject: string;
  text: string;
  html?: string;
}

// EmailResult is the advisory outcome. ok:true means the binding accepted the send (best-effort: the
// binding's own delivery is asynchronous and not observable here). ok:false carries a short
// enumerated reason the caller MAY surface or record (never a stack, never a recipient value). The
// closed reason vocabulary keeps callers from string-matching an internal message. code carries the
// PLATFORM's error code when the Email Service rejected the send (E_SENDER_DOMAIN_NOT_AVAILABLE,
// E_SENDER_NOT_VERIFIED, ...): it is the one diagnostic an operator needs to fix onboarding, safe to
// surface on AUTHENTICATED routes only (the no-oracle anonymous routes never see it).
export interface EmailResult {
  ok: boolean;
  reason?: string;
  code?: string;
  // G020: on an email-recipients-invalid failure, the POSITION of the offending entry in the channel's address
  // list. It is an integer, never an address, and it is what lets support say "your third recipient is the
  // problem" instead of "one of your five addresses is wrong, find it".
  recipientIndex?: number;
}

// MAX_RECIPIENTS bounds a single send so a malformed or hostile `to` cannot drive an unbounded
// loop/payload on the single send call; 50 is far above any operator alert fan-out (an alert goes to
// an on-call list, not a mailing list) while capping the worst case. The notification router sends
// per channel, so a channel's address list is the natural unit and stays small.
const MAX_RECIPIENTS = 50;

// MAX_ADDRESS_LEN bounds one address; 320 is the practical RFC 5321 local@domain ceiling, matching
// the DO's normaliseEmail bound, so an oversized value cannot land in a send payload.
const MAX_ADDRESS_LEN = 320;

// isCustomDomainAddress validates a sender or recipient address at the authority boundary, the same
// discipline isAllowedWebhookUrl applies to a webhook url. The house rule is custom domains only:
// the sender (EMAIL_FROM) must be a real address on a custom domain, never a *.workers.dev host. It
// enforces: a non-empty trimmed string within the length bound; exactly one "@"; a non-empty local
// part with no whitespace; a domain with at least one dot (a bare hostname is not a deliverable
// address) and no whitespace; and the domain is NOT workers.dev or a subdomain of it. This is a
// boundary sanity check (the address class an operator configures), not full RFC 5322 validation.
export function isCustomDomainAddress(raw: unknown): { ok: true; address: string } | { ok: false; reason: string } {
  if (typeof raw !== "string") return { ok: false, reason: "address must be a string" };
  const addr = raw.trim();
  if (addr.length === 0) return { ok: false, reason: "address is required" };
  if (addr.length > MAX_ADDRESS_LEN) return { ok: false, reason: "address is too long" };
  if (/\s/.test(addr)) return { ok: false, reason: "address must not contain whitespace" };
  const at = addr.indexOf("@");
  if (at <= 0 || at !== addr.lastIndexOf("@") || at === addr.length - 1) {
    return { ok: false, reason: "address must be a single local@domain" };
  }
  const domain = addr.slice(at + 1).toLowerCase();
  // A deliverable address needs a dotted domain; reject a bare hostname (no dot) and any leading/
  // trailing dot (an empty label). This also rejects "user@localhost", which is not a custom domain.
  if (!domain.includes(".") || domain.startsWith(".") || domain.endsWith(".")) {
    return { ok: false, reason: "address domain must be a dotted custom domain" };
  }
  // House rule: never a workers.dev sender/recipient; customers use a custom domain.
  if (domain === "workers.dev" || domain.endsWith(".workers.dev")) {
    return { ok: false, reason: "workers.dev addresses are not allowed; use a custom domain" };
  }
  return { ok: true, address: addr };
}

// validateRecipients normalises and bounds the `to` list: every entry must be a custom-domain
// address, the list must be non-empty and within MAX_RECIPIENTS, and duplicates are dropped (first
// occurrence wins, order preserved). Returns the cleaned list or a short reason. Used by sendEmail
// AND re-exported for the email channel adapter / route validation so the same rule applies wherever
// addresses are accepted.
//
// G020: the rejection now also carries the recipientIndex -- the POSITION in the list of the entry that failed,
// never the address. One typo'd address in a five-recipient channel kills delivery to ALL FIVE (the send is one
// call), and support could not name the bad entry: the customer had to eyeball five addresses and guess. An
// index is enough to point straight at it, and it is not customer data.
export function validateRecipients(raw: unknown): { ok: true; to: string[] } | { ok: false; reason: string; recipientIndex?: number } {
  if (!Array.isArray(raw) || raw.length === 0) return { ok: false, reason: "at least one recipient is required" };
  if (raw.length > MAX_RECIPIENTS) return { ok: false, reason: `at most ${MAX_RECIPIENTS} recipients are allowed` };
  const seen = new Set<string>();
  const out: string[] = [];
  for (let i = 0; i < raw.length; i++) {
    const v = isCustomDomainAddress(raw[i]);
    if (!v.ok) return { ok: false, reason: `recipient invalid: ${v.reason}`, recipientIndex: i };
    const key = v.address.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(v.address);
  }
  if (out.length === 0) return { ok: false, reason: "at least one recipient is required" };
  return { ok: true, to: out };
}

// EMAIL_SUBJECT_MAX / EMAIL_BODY_MAX bound the message so a caller bug cannot hand the binding an
// unbounded payload. These are generous (a subject line; a multi-paragraph alert body) and exist
// only as a backstop; the redaction-safe bodies the engine builds are far smaller.
const EMAIL_SUBJECT_MAX = 998; // RFC 5322 line-length ceiling for a header
const EMAIL_BODY_MAX = 256 * 1024; // 256 KiB is ample for any operator alert/digest body

// sendEmail is the single fail-open send. It validates the sender and recipients at the boundary,
// then, when the EMAIL binding is present, hands a small message to env.EMAIL.send() inside a
// try/catch so a thrown or rejected send becomes { ok:false, reason:"email-send-failed" } and never
// escapes. With no binding it returns { ok:false, reason:"email-not-configured" } (the honest
// unconfigured state). With no/invalid EMAIL_FROM it returns reason:"email-from-not-configured" /
// "email-from-invalid". It logs only a coarse reason on failure, NEVER the recipients, subject, or
// body (no message content reaches console).
//
// The message shape handed to the binding follows the Cloudflare send_email contract loosely: a
// from/to/subject and a text (and html when present) body. The binding type is intentionally
// `send(message: unknown)` in env.d.ts so this module does not couple to a specific email-message
// library; a real deployment binds the platform's EmailMessage. The validator passes a double whose
// send() records or resolves, so this path is exercised without a live send.
// The small, plain message handed to the binding. Only the configured sender, the validated
// recipients, and the caller's already-safe subject/body cross this boundary; no header,
// attachment, or raw field exists to smuggle anything else.
interface EmailPayload {
  from: string;
  to: string[];
  subject: string;
  text: string;
  html?: string;
}

// validateEmailMessage runs the sender, recipient, subject and body checks in sequence and returns
// either the plain payload to hand to the binding or a distinct fail-open EmailResult so the operator
// can tell which field is misconfigured. It does NOT touch the binding; sendEmail owns the send.
function validateEmailMessage(env: Env, msg: EmailMessage): { ok: true; payload: EmailPayload } | { ok: false; reason: string; recipientIndex?: number } {
  const fromRaw = env.EMAIL_FROM;
  if (typeof fromRaw !== "string" || fromRaw.trim().length === 0) {
    return { ok: false, reason: "email-from-not-configured" };
  }
  const fromV = isCustomDomainAddress(fromRaw);
  if (!fromV.ok) {
    // A configured-but-invalid sender (e.g. a workers.dev or bare-hostname EMAIL_FROM) is a
    // misconfiguration, surfaced as a distinct reason so the operator can fix it; still fail-open.
    return { ok: false, reason: "email-from-invalid" };
  }
  const toV = validateRecipients(msg.to);
  // G020: carry the failing entry's INDEX through, so the channel adapter can record it on the history row.
  // The address itself stops here and goes no further.
  if (!toV.ok) return { ok: false, reason: "email-recipients-invalid", ...(toV.recipientIndex !== undefined ? { recipientIndex: toV.recipientIndex } : {}) };
  if (typeof msg.subject !== "string" || msg.subject.length === 0 || msg.subject.length > EMAIL_SUBJECT_MAX) {
    return { ok: false, reason: "email-subject-invalid" };
  }
  if (typeof msg.text !== "string" || msg.text.length === 0 || msg.text.length > EMAIL_BODY_MAX) {
    return { ok: false, reason: "email-body-invalid" };
  }
  if (msg.html !== undefined && (typeof msg.html !== "string" || msg.html.length > EMAIL_BODY_MAX)) {
    return { ok: false, reason: "email-body-invalid" };
  }
  return {
    ok: true,
    payload: {
      from: fromV.address,
      to: toV.to,
      subject: msg.subject,
      text: msg.text,
      ...(msg.html !== undefined ? { html: msg.html } : {}),
    },
  };
}

export async function sendEmail(env: Env, msg: EmailMessage): Promise<EmailResult> {
  try {
    const binding = env.EMAIL;
    if (!binding || typeof binding.send !== "function") {
      // Honest unconfigured state: no send_email binding bound (the common case until a tenant is on
      // Workers Paid with a domain onboarded). Fail-open: the caller treats this exactly like a
      // best-effort non-delivery.
      return { ok: false, reason: "email-not-configured" };
    }
    const validated = validateEmailMessage(env, msg);
    if (!validated.ok) return validated;
    await binding.send(validated.payload);
    return { ok: true };
  } catch (e) {
    // Any failure (a rejected send, an edge restriction, a binding that threw) is swallowed: email is
    // observability, never a control. Log the platform error CODE alongside the coarse message (the
    // code names the onboarding gap, e.g. E_SENDER_DOMAIN_NOT_AVAILABLE when the sending domain is
    // not onboarded to Email Service); NEVER the message content/recipients.
    const code = typeof (e as { code?: unknown }).code === "string" ? (e as { code: string }).code : undefined;
    // The LOG is a durable sink (the customer's Workers Logs), so only the SHAPE-GATED code may be written to
    // it. `code` is whatever the platform put on the exception: the documented E_UPPER_SNAKE token in the
    // happy case, but nothing bounds it, and a chatty platform can put a full sentence there carrying the
    // RECIPIENT ADDRESS or an internal host. Logging it raw would leak exactly what this module promises never
    // to log (see the redaction note above). A non-conforming code is logged as the engine-owned E_OTHER
    // placeholder, so the FACT that the platform gave a reason survives while its text does not.
    const logged = sanitiseEmailPlatformCode(code) ?? (code !== undefined && code.length > 0 ? EMAIL_PLATFORM_CODE_OTHER : undefined);
    log("error", `sendEmail failed (best-effort, fail-open)${logged ? ` [${logged}]` : ""}: see platform error code above`);
    // The RAW code is still RETURNED (in memory, never recorded here): the email channel adapter's
    // emailPlatformCodeOf is the single recording chokepoint, and it needs to see a non-conforming code in
    // order to record the E_OTHER placeholder rather than silently dropping the fact (gap G236).
    return { ok: false, reason: "email-send-failed", ...(code ? { code } : {}) };
  }
}
