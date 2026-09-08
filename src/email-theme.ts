// The engine's transactional-email HTML theme: one renderer that wraps an operator-facing message (an
// alert, a digest, a sign-in link, the delivery test) in the same branded card the control-plane
// licensing pack uses, so a self-hosted engine's own mail reads as Downpipes. It is the HTML companion
// to the plain-text bodies the callers still build; sendEmail carries both parts, and a client that
// shows only the text part loses nothing.
//
// Written for hostile email clients, mirroring control-plane lib/email-blocks.ts: table-based layout,
// every load-bearing style inline (the single <style> block is progressive enhancement only, a
// dark-scheme tweak and a narrow-screen tweak), a 560px centred card, an MSO conditional-comment ghost
// table for the Word renderer's missing max-width, and no image, script, webfont or remote resource of
// any kind (a remote load is a tracking surface, and this mail goes to a customer's own team).
//
// NO VENDOR IDENTITY. This mail is sent BY a customer's self-hosted engine TO their own team, so it must
// never carry the licensing pack's vendor sign-off. The footer is the
// downpipes wordmark and one neutral automated-message line only.
//
// Pure module: no env, no binding, no clock read. Every interpolated value is escaped by escapeHtml at
// the point it enters markup.

import { escapeHtml } from "./util/html.ts";

const FONT_STACK = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";

// The palette is the brand indigo on the console ink ramp, identical to the control-plane email theme so
// the two surfaces match. a-500 #3b66f0 drives the wordmark, inline links and the accent rule; the
// deeper a-600 #2952d8 is the CTA fill only, so the white label clears WCAG AA; the neutrals are ink-ramp
// steps. The <style> block below restates the tuned dark version for clients that honour it.
const PAGE_BG = "#eef1f5";
const CARD_BG = "#fcfdfe";
const TEXT_COLOUR = "#232831";
const HEADING_COLOUR = "#14171d";
const MUTED_COLOUR = "#5b6575";
const BORDER_COLOUR = "#e4e8ee";
const FOOTER_BG = "#f6f8fa";
const ACCENT = "#3b66f0";
const BUTTON_BG = "#2952d8";
const ACCENT_CONTRAST = "#ffffff";
const TRUST_ACCENT = "#4fd0bf";
// The recessed code well, the same n-100 / n-200 pair the control-plane pack sets its claim code in.
const CODE_BG = "#eef1f5";
const CODE_BORDER = "#d8dee6";

// No webfont, ever: a font download is a remote load, and this mail promises none.
const MONO_STACK = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace";

const PROSE_FONT = `font-family:${FONT_STACK};font-size:15px;line-height:24px;`;
const SMALL_FONT = `font-family:${FONT_STACK};font-size:13px;line-height:20px;`;

// The neutral footer line every engine email ends with, in place of the licensing pack's vendor
// sign-off. A caller may override it, but every current caller takes this default.
export const DEFAULT_FOOTER_NOTE = "This is an automated message from your Downpipes engine.";

// Progressive enhancement ONLY: a client that strips this <style> block still renders correctly from the
// inline styles alone. The dark-scheme rules restate the palette for clients that honour
// prefers-color-scheme (Gmail does not, so the inline light values are the base most readers see); the
// narrow-screen rule relaxes padding on small viewports.
const ENHANCEMENT_STYLE = [
  "<style>",
  "@media (max-width: 600px) {",
  "  .dp-outer-pad { padding: 16px 8px !important; }",
  "  .dp-inner-pad { padding-left: 20px !important; padding-right: 20px !important; }",
  "}",
  "@media (prefers-color-scheme: dark) {",
  "  .dp-body { background-color: #1b1e23 !important; }",
  "  .dp-card { background-color: #23272e !important; border-color: #343a43 !important; }",
  "  .dp-text, .dp-heading { color: #e6e9ed !important; }",
  "  .dp-muted { color: #9aa3ad !important; }",
  "  .dp-code-box { background-color: #282d35 !important; border-color: #454d58 !important; }",
  "  .dp-footer { background-color: #1f2329 !important; border-top-color: #343a43 !important; }",
  "  .dp-accent { color: #84a4ff !important; }",
  "  .dp-link { color: #a8c0ff !important; }",
  "  .dp-btn { background-color: #2952d8 !important; }",
  "  .dp-rule { background-color: #84a4ff !important; }",
  "}",
  "</style>",
].join("\n");

// linkifyHtml escapes prose and turns bare http(s) URLs into underlined accent links, trimming trailing
// punctuation out of the target; interior newlines become <br>. Mirrors the control-plane helper so the
// two mail surfaces linkify identically. Every piece, URL included, passes through escapeHtml, so no
// substituted value can inject markup.
function linkifyHtml(text: string): string {
  const pieces = text.split(/(https?:\/\/[^\s]+)/g);
  const html = pieces
    .map((piece, i) => {
      if (i % 2 === 0) return escapeHtml(piece);
      const trimmed = piece.replace(/[).,;:!?\]}'"]+$/, "");
      const trailer = piece.slice(trimmed.length);
      return `<a href="${escapeHtml(trimmed)}" class="dp-link" style="color:${ACCENT};text-decoration:underline;">${escapeHtml(trimmed)}</a>${escapeHtml(trailer)}`;
    })
    .join("");
  return html.replace(/\n/g, "<br>");
}

// row wraps one block's HTML in the card's standard content row; padding does all the spacing (the Word
// renderer ignores table margins, so nothing here relies on them).
function row(innerHtml: string, bottomPadding: number, topPadding = 0): string {
  return `<tr><td class="dp-inner-pad" style="padding:${topPadding}px 36px ${bottomPadding}px 36px;">${innerHtml}</td></tr>`;
}

/** One call-to-action button, a sign-in or set-up link. The URL is always present in the plain-text
 * part as well, so a text-only client never loses it. */
export interface EngineEmailCta {
  label: string;
  url: string;
}

/** One monospace value set in its own recessed well: a recovery share, a fingerprint. Never a link and
 * never a credential the vendor holds; the ONE caller today is the custody share route, whose value is a
 * single Shamir share the customer chose to email over their own domain. */
export interface EngineEmailCode {
  value: string;
  label?: string;
}

/** A numbered instruction list with its own small heading. Separate from `paragraphs` because a list is
 * a list: rendered as a real ordered list, it survives a client that strips every style, whereas a run of
 * numbered sentences inside one paragraph reads as prose the moment the wrapping changes. */
export interface EngineEmailSteps {
  heading?: string;
  items: string[];
}

/** {@link renderEngineEmailHtml}'s input: a heading, one or more prose paragraphs, an optional monospace
 * value, an optional numbered list, an optional CTA button, and optional subject / preheader /
 * footer-note overrides. The optional blocks render in that fixed order after the paragraphs. */
export interface EngineEmailInput {
  heading: string;
  paragraphs: string[];
  code?: EngineEmailCode;
  steps?: EngineEmailSteps;
  subject?: string;
  preheader?: string;
  cta?: EngineEmailCta;
  footerNote?: string;
}

// The code well and the list, mirroring control-plane lib/email-blocks.ts's own codeHtml/stepsHtml so a
// share email and a licence email set the same value the same way. overflow-wrap:anywhere is what keeps a
// long unbroken token inside the 560px card instead of stretching it; margin:0 on the <li> is there
// because a bare list item otherwise carries the UA stylesheet's own margin on top of this padding, which
// the Word renderer applies too and which doubles the gap between steps.
function codeHtml(code: EngineEmailCode): string {
  const caption = code.label === undefined ? "" : `<div class="dp-muted" style="${SMALL_FONT}font-weight:600;letter-spacing:0.4px;color:${MUTED_COLOUR};text-align:center;padding-bottom:8px;">${escapeHtml(code.label)}</div>`;
  const box =
    `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">` +
    `<tr><td class="dp-code-box" align="center" style="background-color:${CODE_BG};border:1px solid ${CODE_BORDER};border-radius:8px;padding:16px 20px;">` +
    `<span class="dp-code-value dp-text" style="font-family:${MONO_STACK};font-size:14px;line-height:24px;font-weight:600;color:${HEADING_COLOUR};overflow-wrap:anywhere;">${escapeHtml(code.value)}</span>` +
    `</td></tr></table>`;
  return row(`${caption}${box}`, 22);
}

function stepsHtml(steps: EngineEmailSteps): string {
  const heading =
    steps.heading === undefined
      ? ""
      : `<div class="dp-text" style="${PROSE_FONT}font-weight:600;color:${HEADING_COLOUR};padding-bottom:6px;">${escapeHtml(steps.heading)}</div>`;
  const lis = steps.items.map((item) => `<li class="dp-text" style="${PROSE_FONT}color:${TEXT_COLOUR};margin:0;padding:0 0 6px 4px;">${linkifyHtml(item)}</li>`).join("");
  return row(`${heading}<ol style="margin:0;padding:0 0 0 22px;">${lis}</ol>`, 12);
}

// The CTA button carries its padding on the coloured <td> (the Word renderer supports padding there, not
// reliably on an inline anchor) and display:block on the anchor so the whole cell is clickable and the
// pill survives Outlook.
function ctaHtml(cta: EngineEmailCta): string {
  const button =
    `<table role="presentation" cellpadding="0" cellspacing="0" border="0">` +
    `<tr><td class="dp-btn" bgcolor="${BUTTON_BG}" style="background-color:${BUTTON_BG};border-radius:6px;padding:11px 22px;">` +
    `<a href="${escapeHtml(cta.url)}" style="display:block;font-family:${FONT_STACK};font-size:14px;line-height:16px;font-weight:600;color:${ACCENT_CONTRAST};text-decoration:none;">${escapeHtml(cta.label)}</a>` +
    `</td></tr></table>`;
  return row(button, 20);
}

/**
 * Renders an engine operator email to the designed HTML part: the branded 560px card with the indigo
 * accent rule and the downpipes wordmark, the heading, the prose paragraphs, an optional CTA button, and
 * the neutral footer (wordmark plus one automated-message line, never a vendor sign-off). Every
 * load-bearing style is inline; the single <style> block is progressive enhancement only. No image,
 * script or remote resource of any kind. Every substituted value is escaped where it enters markup.
 *
 * @param input - the heading, paragraphs, and optional CTA / subject / preheader / footer note.
 * @returns a complete `<!doctype html>` document for the EmailMessage.html field.
 */
export function renderEngineEmailHtml(input: EngineEmailInput): string {
  const titleSource = input.subject ?? input.heading;
  const preheaderSource = input.preheader ?? input.paragraphs[0] ?? input.heading;
  const preheader = escapeHtml(preheaderSource.replace(/\s+/g, " ").trim().slice(0, 140));
  // Pad the hidden preview so the client's snippet does not run on into the body copy.
  const preheaderPad = "&#160;&#8204;".repeat(40);
  const footerNote = input.footerNote ?? DEFAULT_FOOTER_NOTE;

  const bodyRows: string[] = [];
  bodyRows.push(row(`<h1 class="dp-heading" style="margin:0;font-family:${FONT_STACK};font-size:21px;line-height:30px;font-weight:600;color:${HEADING_COLOUR};">${escapeHtml(input.heading)}</h1>`, 12));
  for (const paragraph of input.paragraphs) {
    bodyRows.push(row(`<div class="dp-text" style="${PROSE_FONT}color:${TEXT_COLOUR};">${linkifyHtml(paragraph)}</div>`, 16));
  }
  if (input.code !== undefined) bodyRows.push(codeHtml(input.code));
  if (input.steps !== undefined) bodyRows.push(stepsHtml(input.steps));
  if (input.cta !== undefined) bodyRows.push(ctaHtml(input.cta));

  return [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<meta name="color-scheme" content="light dark">',
    '<meta name="supported-color-schemes" content="light dark">',
    `<title>${escapeHtml(titleSource)}</title>`,
    ENHANCEMENT_STYLE,
    "</head>",
    `<body class="dp-body" style="margin:0;padding:0;background-color:${PAGE_BG};">`,
    `<div style="display:none;max-height:0;max-width:0;overflow:hidden;opacity:0;mso-hide:all;font-size:1px;line-height:1px;color:${PAGE_BG};">${preheader}${preheaderPad}</div>`,
    `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="dp-body" style="background-color:${PAGE_BG};">`,
    `<tr><td align="center" class="dp-outer-pad" style="padding:32px 16px;">`,
    // MSO (Word, behind Outlook desktop) reads table markup but ignores max-width, so this ghost table
    // caps the card at 560px there; every other client sees a plain comment and renders the real card.
    `<!--[if mso]><table role="presentation" width="560" align="center" cellpadding="0" cellspacing="0" border="0"><tr><td><![endif]-->`,
    `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="dp-card" style="width:100%;max-width:560px;background-color:${CARD_BG};border:1px solid ${BORDER_COLOUR};border-radius:10px;overflow:hidden;">`,
    `<tr><td class="dp-rule" bgcolor="${ACCENT}" style="height:3px;background-color:${ACCENT};background-image:linear-gradient(100deg,${ACCENT} 0%,${TRUST_ACCENT} 100%);font-size:0;line-height:0;">&#160;</td></tr>`,
    row(`<div class="dp-accent" style="font-family:${FONT_STACK};font-size:15px;line-height:20px;font-weight:700;letter-spacing:0.4px;color:${ACCENT};">downpipes</div>`, 18, 24),
    ...bodyRows,
    `<tr><td class="dp-footer dp-inner-pad" style="padding:18px 36px 22px 36px;background-color:${FOOTER_BG};border-top:1px solid ${BORDER_COLOUR};">` +
      `<div class="dp-accent" style="${SMALL_FONT}font-weight:700;letter-spacing:0.4px;color:${ACCENT};">downpipes</div>` +
      `<div class="dp-muted" style="font-family:${FONT_STACK};font-size:12px;line-height:18px;color:${MUTED_COLOUR};padding-top:6px;">${escapeHtml(footerNote)}</div>` +
      "</td></tr>",
    "</table>",
    "<!--[if mso]></td></tr></table><![endif]-->",
    "</td></tr></table>",
    "</body></html>",
  ].join("\n");
}
