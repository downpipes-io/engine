// router-custody.ts -- the custody-ceremony routes. Currently one route: emailing a single Shamir share
// of the split break-glass key to a custodian (the alternative is a download the operator hands over).
//
// SECURITY. A browser cannot send email, so an emailed share must
// transit the engine (which holds the EMAIL binding) on its way out. This is SAFE because of ciphertext
// separation (S1): the engine emails ONLY shares of the 256-bit wrapping key; the ciphertext (the
// AES-256-GCM envelope over identity.key) is NEVER sent to the engine and stays a customer-held download,
// so an attacker who captured every emailed share (a compromised engine, or every custodian inbox)
// reconstructs the wrapping key but STILL cannot decrypt identity.key without the ciphertext. A single
// share below the threshold reveals nothing at all (Shamir, information-theoretic). This route therefore
// handles ONE share per request, is owner-gated + rate-limited, NEVER logs or stores the share value or the
// custodian address, and emails over the customer's own outbound email on their own domain (no custody:
// Maelstrom receives nothing). The share is emailed BODY-ONLY (no attachment; the engine email primitive
// has no attachment surface by design). The email tells the custodian to save the share offline or in a
// password manager and then delete the email.

import type { RouterCtx } from "./router-helpers.ts";
import { jsonResponse, jsonError, gate, rateLimited, recordAudit } from "./router-core.ts";
import { sendEmail, isCustomDomainAddress } from "../email.ts";
import { b64urlDecode } from "../crypto/bytes.ts";
import { log } from "../log.ts";
import { DEFAULT_FOOTER_NOTE, renderEngineEmailHtml } from "../email-theme.ts";

// SHARE_BYTES is the byte length of one Shamir share (console/src/lib/shamir.ts): a 1-byte non-zero index
// plus 32 payload bytes. The route validates a posted share decodes to exactly this, so a malformed or
// oversized value never reaches the email body.
export const SHARE_BYTES = 33;
const CUSTODIAN_LABEL_MAX = 120;

// NO LOCAL escapeHtml. The custodian label is the one operator-controlled string that enters the HTML
// body, and it is now escaped where it enters markup by email-theme.ts, which uses the engine's single
// util/html.ts helper. The copy that used to live here was a second definition of the same escape set,
// which is exactly the shape util/html.ts exists to prevent: two escape sets drift, one cannot. The
// share itself is base64url (a closed alphabet) and every other field is a bounded integer.

// normaliseLabel strips the optional custodian label (an operator display string) of control characters and
// trims it, WITHOUT bounding its length. It is the shared cleaning step, so the refusal below and the value
// that reaches the email body can never disagree about what the label is.
//
// The strip runs BEFORE the trim so that a label whose only surrounding "whitespace" is a control character
// still trims, and length is measured on this result. cleanLabel used to slice to CUSTODIAN_LABEL_MAX first
// and strip afterwards, which quietly shortened a legal 120-character label carrying any control character
// to 119 or fewer. That is the same cap-before-clean shape found on the change-number normaliser, and it was
// found here the same way: by the control that proves a legal value at exactly the boundary is still accepted.
function normaliseLabel(raw: unknown): string {
  if (typeof raw !== "string") return "";
  let out = "";
  for (const ch of raw) {
    const c = ch.codePointAt(0) ?? 0;
    if (c >= 0x20 && c !== 0x7f) out += ch;
  }
  return out.trim();
}

// custodianLabelRejection is the SUBMIT-TIME twin of cleanLabel, in the same family as the destination
// surface's assumeRolePolicyRejection and wormPolicyRejection: it answers WHY a submitted custodian label is
// unusable, so the route refuses instead of shortening.
//
// WHY THIS ONE REFUSES RATHER THAN TRUNCATING, decided rather than omitted. The label is IDENTITY: it is
// printed on the share email as the name of the person the custodian is meant to be, and the custodian reads
// it. A truncated name is not a rejected one. It looks valid, it is sent without complaint, and it fails the
// only job it has, which is to say who holds this share. The bound is not a new rule either: 120 is the
// console field's own bound, enforced inline and again at Send, so every console caller is already refused
// before a request is built. What the engine's silence covered was the OTHER callers, anything holding an
// operator session or the break-glass token, for whom a long name was quietly cut and nobody was told.
//
// The strip and the trim are deliberately NOT refusals. They do not change WHO is named, and the strip is the
// header-injection defence for the email body, which must keep running unconditionally whatever else changes.
//
// @param raw - the submitted custodianLabel (untrusted, any shape).
// @returns an operator-facing reason, or null when there is nothing to refuse.
export function custodianLabelRejection(raw: unknown): string | null {
  if (normaliseLabel(raw).length <= CUSTODIAN_LABEL_MAX) return null;
  return `the custodian name must be ${CUSTODIAN_LABEL_MAX} characters or fewer; it is printed on the share email as the custodian's own name, so a longer one is refused rather than shortened`;
}

// cleanLabel bounds and strips the optional custodian label (an operator display string) of control
// characters, so it is safe to place in the plain-text body and, once escaped, the HTML body. Returns ""
// for an absent/blank label.
//
// The bound stays here as defence in depth for any caller that has not been through custodianLabelRejection.
// On the send route the two agree exactly: a label that is accepted is at most CUSTODIAN_LABEL_MAX after
// cleaning, so the slice is a no-op and what is accepted is emailed equal to its cleaned form.
export function cleanLabel(raw: unknown): string {
  return normaliseLabel(raw).slice(0, CUSTODIAN_LABEL_MAX);
}

// SHARE_EMAIL_STEPS is the custodian instruction list, single-sourced so the two message parts cannot
// drift: the ordered list in the HTML part and the numbered lines in the text part are the same array.
const SHARE_EMAIL_STEPS: readonly string[] = [
  "Save this share offline, or in a password manager such as Bitwarden.",
  "Then delete this email.",
  "Keep it to yourself and do not forward it. It stays safe only while it is held apart from the other shares.",
];

// TEXT_WRAP is the conventional plain-text mail column. The text part used to be emitted as unwrapped
// logical lines, one of them 175 characters, so a client that does not soft-wrap showed a custodian a
// sentence they had to scroll sideways to read. The share itself is never wrapped: it is one token and a
// break inserted into it would be indistinguishable from part of the value.
const TEXT_WRAP = 72;

// wrapProse greedily wraps one sentence at TEXT_WRAP, never breaking inside a word.
function wrapProse(line: string): string {
  const words = line.split(" ").filter((w) => w.length > 0);
  const out: string[] = [];
  let current = "";
  for (const word of words) {
    if (current.length === 0) current = word;
    else if (current.length + 1 + word.length <= TEXT_WRAP) current = `${current} ${word}`;
    else {
      out.push(current);
      current = word;
    }
  }
  if (current.length > 0) out.push(current);
  return out.join("\n");
}

// buildShareEmail renders the plain-text and HTML bodies for one share. The custodian instructions are the
// point: save it offline or in a password manager, then delete the email; a share alone reveals nothing;
// keep it apart from the other shares. n/m are the total and threshold; label is the (already-cleaned)
// custodian display string; shareB64 is the share itself. Neither this function nor its caller logs any of
// it.
//
// THE HTML PART IS RENDERED BY THE ENGINE'S OWN THEME (email-theme.ts) rather than a local copy, so it
// never carries a vendor sign-off on mail the vendor does not send: the whole custody design turns on
// Maelstrom receiving nothing, and a recovery-share email signed by the vendor would invite a custodian to
// read vendor involvement into a key ceremony the vendor has no part in. The footer is the theme's neutral
// automated-message line, the palette matches the rest of the product's mail, and the layout is responsive
// (fits a phone viewport, supports dark-scheme clients).
export function buildShareEmail(shareB64: string, n: number, m: number, label: string): { subject: string; text: string; html: string } {
  const who = label ? ` for ${label}` : "";
  const subject = "Keep this downpipes recovery share safe";
  const opening = `You have been given one share${who} of a downpipes recovery key.`;
  const reassurance = `On its own this share reveals nothing. Any ${m} of the ${n} shares together reconstruct the key if recovery is ever needed, so no single person holds enough to recover on their own.`;
  const stepsHeading = "What to do now";
  const text = [
    wrapProse(opening),
    "",
    wrapProse(reassurance),
    "",
    "Your share:",
    shareB64,
    "",
    `${stepsHeading}:`,
    // The steps are numbered here from the SAME array the ordered list renders, so a step added to one
    // part can never be missing from the other.
    ...SHARE_EMAIL_STEPS.map((item, i) => wrapProse(`${i + 1}. ${item}`)),
    "",
    DEFAULT_FOOTER_NOTE,
  ].join("\n");
  const html = renderEngineEmailHtml({
    subject,
    preheader: "One share of a recovery key. Save it offline, then delete this email.",
    heading: "Keep this recovery share safe",
    paragraphs: [opening, reassurance],
    code: { value: shareB64, label: "Your share" },
    steps: { heading: stepsHeading, items: [...SHARE_EMAIL_STEPS] },
  });
  return { subject, text, html };
}

// handleCustody dispatches the custody-ceremony group. Returns the route's Response, or null when no case
// here matched (the hub falls to the next spoke).
export async function handleCustody(ctx: RouterCtx): Promise<Response | null> {
  const { req, scheduler, caller, sub, sourceIp } = ctx;
  switch (`${req.method} ${sub}`) {
    // POST /custody/send-share emails ONE Shamir share to a custodian. Owner-gated (keys.ceremony, the
    // custody-ceremony bar), rate-limited. The share value + custodian address NEVER reach the log or
    // storage; only the redaction-safe counts (threshold-of-total) are audited. The ciphertext never
    // touches this route, so captured shares stay useless (S1). Body-only, no attachment.
    case "POST /custody/send-share": {
      const body = (await req.json().catch(() => ({}))) as { toEmail?: unknown; custodianLabel?: unknown; shareB64?: unknown; n?: unknown; m?: unknown };
      const denied = gate(caller, "keys.ceremony");
      if (denied) {
        // A refused attempt: record who tried, with placeholder counts (no share, no address ever recorded).
        await recordAudit(scheduler, caller, sourceIp, "custody-share-emailed", "denied", { kind: "custody-share", n: 0, m: 0 });
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;

      const addr = isCustomDomainAddress(body.toEmail);
      if (!addr.ok) return jsonError(`custodian email invalid: ${addr.reason}`, 400);

      const n = typeof body.n === "number" && Number.isInteger(body.n) ? body.n : 0;
      const m = typeof body.m === "number" && Number.isInteger(body.m) ? body.m : 0;
      if (!(n >= 2 && n <= 255 && m >= 2 && m <= n)) {
        return jsonError("share threshold invalid: need 2 <= threshold <= total <= 255", 400);
      }
      const shareB64 = typeof body.shareB64 === "string" ? body.shareB64 : "";
      // The share must decode to exactly SHARE_BYTES; a malformed or oversized value never reaches the email.
      let shareBytes: Uint8Array;
      try {
        shareBytes = b64urlDecode(shareB64);
      } catch {
        return jsonError("share is not valid base64url", 400);
      }
      if (shareBytes.length !== SHARE_BYTES) {
        return jsonError(`share must be ${SHARE_BYTES} bytes`, 400);
      }
      // Refuse an over-length custodian name rather than shortening it. This sits where the label is first
      // read, so a request whose SHARE is also wrong still answers about the share: the refusal is pinned to
      // the label, not to the request.
      const labelReason = custodianLabelRejection(body.custodianLabel);
      if (labelReason !== null) return jsonError(labelReason, 400);
      const label = cleanLabel(body.custodianLabel);

      const mail = buildShareEmail(shareB64, n, m, label);
      const result = await sendEmail(ctx.env, { to: [addr.address], subject: mail.subject, text: mail.text, html: mail.html });
      if (!result.ok) {
        // Fail honestly with the coarse reason (e.g. email-not-configured on a tenant without the EMAIL
        // binding). Never log the share or the address; the reason names the config gap only.
        log("info", `custody-share email not sent: ${result.reason ?? "unknown"} (share + address never logged)`);
        return jsonResponse({ sent: false, reason: result.reason ?? "email-send-failed", ...(result.code ? { code: result.code } : {}) });
      }
      // Success: audit the redaction-safe counts only. The share, the address and the label never enter the
      // trail (the closed custody-share target cannot hold them).
      await recordAudit(scheduler, caller, sourceIp, "custody-share-emailed", "success", { kind: "custody-share", n, m });
      log("info", `custody-share emailed (${m} of ${n}) (share + address never logged)`);
      return jsonResponse({ sent: true });
    }
    default:
      return null;
  }
}
